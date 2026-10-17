package server

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/DevCop95/obliteratus/internal/elevate"
)

// allModules returns a server with every gated module unlocked and a payload
// path that does not exist, so the tests below exercise the handler bodies and
// their argument validation rather than the fail-closed gate (which
// middleware_test.go already covers).
func allModules(t *testing.T) *httptest.Server {
	t.Helper()
	s := newTestServer(t, Config{
		EnableCollect: true,
		EnablePersist: true,
		EnableEvasion: true,
		EnableLateral: true,
		EnableInject:  true,
		PayloadPath:   filepath.Join(t.TempDir(), "absent.bin"),
	})
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)
	return ts
}

// authedPost sends an authenticated POST and returns the status and body.
func authedPost(t *testing.T, ts *httptest.Server, path, body string) (int, string) {
	t.Helper()
	req := do("POST", ts.URL+path, "", map[string]string{
		"X-Signal-Token": testToken,
		"Content-Type":   "application/json",
	}, strings.NewReader(body))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

// authedGet sends an authenticated GET and returns the status and body.
func authedGet(t *testing.T, ts *httptest.Server, path string) (int, string) {
	t.Helper()
	req := do("GET", ts.URL+path, "", map[string]string{"X-Signal-Token": testToken}, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

// TestHandlersRejectMalformedBody drives every JSON-decoding handler with a
// body it must refuse. These paths used to be untested: a handler that returns
// 500 (or, worse, succeeds) on garbage input is how a console endpoint turns
// into an unexpected primitive. All cases must answer 400 before touching the
// system.
func TestHandlersRejectMalformedBody(t *testing.T) {
	ts := allModules(t)
	cases := []struct{ path, body string }{
		{"/v1/sys/cmd", `{}`},
		{"/v1/sys/cmd", `not json at all`},
		{"/v1/sys/cmd", `{"c":"   "}`}, // whitespace-only command
		{"/v1/op/roast-asrep", `{}`},
		{"/v1/op/roast-asrep", `{"user":"svc"}`}, // missing domain
		{"/v1/op/roast-asrep", `not json`},
		{"/v1/op/roast-tgs", `{}`},
		{"/v1/op/roast-tgs", `{"user":"u","domain":"d","hash":"h"}`}, // no spns
		{"/v1/op/roast-tgs", `not json`},
		{"/v1/op/spn-enum", `{}`},
		{"/v1/op/spn-enum", `{"domain":"d"}`}, // missing user
		{"/v1/op/spn-enum", `not json`},
		{"/v1/op/lsass-wipe", `{}`},
		{"/v1/op/lsass-wipe", `not json`},
		{"/v1/op/persist-add", `not json`},
		{"/v1/op/persist-del", `not json`},
		{"/v1/op/lateral-winrm", `{"host":"","command":""}`},
		{"/v1/op/lateral-winrm", `{"host":"10.0.0.5","command":""}`},
		{"/v1/op/lateral-winrm", `not json`},
		{"/v1/op/lateral-scm", `{}`},
		{"/v1/op/lateral-scm", `{"host":"","command":"whoami"}`},
		{"/v1/op/lateral-scm", `not json`},
		{"/v1/op/d4", `{"pid":0}`},
		{"/v1/op/d4", `{"pid":-1}`},
		{"/v1/op/d4", `not json`},
	}
	for _, tc := range cases {
		status, body := authedPost(t, ts, tc.path, tc.body)
		if status != http.StatusBadRequest {
			t.Errorf("POST %s with %s: status = %d, want 400 (body %q)",
				tc.path, tc.body, status, body)
		}
	}
}

// TestPrivilegedHandlersRequireElevation documents both branches of the admin
// gate. CI runs elevated (windows-latest) and unelevated (ubuntu-latest), so
// each branch is asserted where it applies and skipped where it cannot be
// exercised safely.
func TestPrivilegedHandlersRequireElevation(t *testing.T) {
	ts := allModules(t)
	elevated := elevate.IsAdmin()

	if !elevated {
		for _, path := range []string{"/v1/sys/sam", "/v1/op/lsass"} {
			status, body := authedPost(t, ts, path, `{"pid":0}`)
			if status != http.StatusForbidden {
				t.Errorf("POST %s unelevated: status = %d, want 403", path, status)
			}
			if !strings.Contains(body, "elevated") {
				t.Errorf("POST %s: body %q must name the elevation requirement", path, body)
			}
		}
		return
	}

	// Elevated: argument validation runs before any dump is attempted, so an
	// invalid PID is refused without acquiring LSASS.
	if status, body := authedPost(t, ts, "/v1/op/lsass", `{"pid":0}`); status != http.StatusBadRequest {
		t.Errorf("POST /v1/op/lsass elevated with pid=0: status = %d, want 400 (body %q)", status, body)
	}
	// /v1/sys/sam takes no body and would start a real hive export, so the
	// elevated success path is left to the live verification matrix rather
	// than triggered from a unit test.
}

// TestLSASSWipeConfinesToToolDumps is the security-critical assertion for the
// wipe endpoint: without the confinement check it is an arbitrary
// truncate-and-delete primitive for the token holder.
func TestLSASSWipeConfinesToToolDumps(t *testing.T) {
	ts := allModules(t)

	if status, _ := authedPost(t, ts, "/v1/op/lsass-wipe", `{"path":"   "}`); status != http.StatusBadRequest {
		t.Errorf("blank path: status = %d, want 400", status)
	}

	for _, path := range []string{
		`C:\Windows\System32\config\SAM`,
		`C:\Windows\Temp\evil.dmp`,
		`C:\Windows\System32\drivers\etc\hosts`,
		filepath.Join(filepath.Clean(os.TempDir()), "not-a-dump.dmp"),
		filepath.Join(filepath.Clean(os.TempDir()), "..", "escape.dmp"),
	} {
		body := `{"path":` + strconv.Quote(path) + `}`
		status, resp := authedPost(t, ts, "/v1/op/lsass-wipe", body)
		if status != http.StatusUnprocessableEntity {
			t.Errorf("wipe %q: status = %d, want 422 (body %q)", path, status, resp)
		}
	}
}

// TestLSASSWipeRemovesDump covers the accepted case end to end: a file that
// matches the tool's own dump naming convention inside the temp directory is
// actually deleted.
func TestLSASSWipeRemovesDump(t *testing.T) {
	ts := allModules(t)
	dump := filepath.Join(filepath.Clean(os.TempDir()), "obl-lsass-4242-20260101-010101.dmp")
	if err := os.WriteFile(dump, []byte("not a real minidump"), 0o600); err != nil {
		t.Skipf("cannot create temp dump: %v", err)
	}
	t.Cleanup(func() { _ = os.Remove(dump) })

	status, body := authedPost(t, ts, "/v1/op/lsass-wipe", `{"path":`+strconv.Quote(dump)+`}`)
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %q)", status, body)
	}
	if _, err := os.Stat(dump); !os.IsNotExist(err) {
		t.Errorf("dump still present after wipe (stat err = %v)", err)
	}
}

// TestPersistRejectsInvalidSpec checks that a bad persistence spec is refused
// with 422 and, importantly, that it never reaches the registry/Task
// Scheduler/WMI backends.
func TestPersistRejectsInvalidSpec(t *testing.T) {
	ts := allModules(t)
	cases := []struct{ path, body string }{
		{"/v1/op/persist-add", `{"type":"bogus","name":"x","cmd":"y"}`},
		{"/v1/op/persist-add", `{"type":"run","name":"","cmd":"y"}`},
		{"/v1/op/persist-add", `{"type":"run","name":"x","cmd":""}`},
		{"/v1/op/persist-del", `{"type":"bogus","name":"x"}`},
		{"/v1/op/persist-del", `{"type":"run","name":""}`},
	}
	for _, tc := range cases {
		status, body := authedPost(t, ts, tc.path, tc.body)
		if status != http.StatusUnprocessableEntity {
			t.Errorf("POST %s with %s: status = %d, want 422 (body %q)",
				tc.path, tc.body, status, body)
		}
	}
}

// TestInjectPayloadErrors covers the two payload-resolution failures that sit
// between the module gate and the injection routine itself.
func TestInjectPayloadErrors(t *testing.T) {
	// 1. Configured payload path does not exist → 404.
	ts := allModules(t)
	status, body := authedPost(t, ts, "/v1/op/d4", `{"pid":1234}`)
	if status != http.StatusNotFound {
		t.Errorf("missing payload: status = %d, want 404 (body %q)", status, body)
	}
	if !strings.Contains(body, "payload not found") {
		t.Errorf("missing payload: body %q should explain the missing file", body)
	}

	// 2. Packed payload with no --payload-key → 422, and it must not be
	//    handed to the injection routine half-unpacked.
	packed := filepath.Join(t.TempDir(), "packed.bin")
	if err := os.WriteFile(packed, append([]byte("OBLP\x01"), []byte("ciphertext")...), 0o600); err != nil {
		t.Skipf("cannot create packed payload: %v", err)
	}
	s := newTestServer(t, Config{EnableInject: true, PayloadPath: packed})
	ts2 := httptest.NewServer(s.Handler())
	defer ts2.Close()

	status, body = authedPost(t, ts2, "/v1/op/d4", `{"pid":1234}`)
	if status != http.StatusUnprocessableEntity {
		t.Errorf("packed without key: status = %d, want 422 (body %q)", status, body)
	}
	if !strings.Contains(body, "payload-key") {
		t.Errorf("packed without key: body %q should mention --payload-key", body)
	}

	// 3. Plain payload but an impossible PID → the injection routine fails and
	//    the handler reports it rather than answering OK.
	plain := filepath.Join(t.TempDir(), "plain.bin")
	if err := os.WriteFile(plain, []byte("\x90\x90\x90\xc3"), 0o600); err != nil {
		t.Skipf("cannot create payload: %v", err)
	}
	s2 := newTestServer(t, Config{EnableInject: true, PayloadPath: plain})
	ts3 := httptest.NewServer(s2.Handler())
	defer ts3.Close()

	status, body = authedPost(t, ts3, "/v1/op/d4", `{"pid":999999}`)
	if status != http.StatusUnprocessableEntity {
		t.Errorf("impossible pid: status = %d, want 422 (body %q)", status, body)
	}
}

// TestAuditEndpoints covers the always-available defensive API: the JSON
// report and the CSV export, including the download header.
func TestAuditEndpoints(t *testing.T) {
	ts := allModules(t)

	status, body := authedPost(t, ts, "/v1/audit/report", "")
	if status != http.StatusOK {
		t.Fatalf("report: status = %d, want 200 (body %q)", status, body)
	}
	var rep struct {
		Tool     string `json:"tool"`
		Version  string `json:"version"`
		Findings []struct {
			ID string `json:"id"`
		} `json:"findings"`
	}
	if err := json.Unmarshal([]byte(body), &rep); err != nil {
		t.Fatalf("report is not valid JSON: %v", err)
	}
	if len(rep.Findings) == 0 {
		t.Error("report carries no findings; the audit should always emit its 12 checks")
	}

	req := do("POST", ts.URL+"/v1/audit/csv", "", map[string]string{"X-Signal-Token": testToken}, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("csv: status = %d, want 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "text/csv") {
		t.Errorf("csv Content-Type = %q, want text/csv", ct)
	}
	if cd := resp.Header.Get("Content-Disposition"); !strings.Contains(cd, "attachment") {
		t.Errorf("csv Content-Disposition = %q, want an attachment", cd)
	}
}

// TestHexEndpoint covers both branches: no payload configured (empty body) and
// a payload whose first bytes are hex-encoded for the viewer.
func TestHexEndpoint(t *testing.T) {
	// No payload file → 200 with an empty body, never a 500.
	ts := allModules(t)
	status, body := authedGet(t, ts, "/v1/sys/hex")
	if status != http.StatusOK {
		t.Errorf("no payload: status = %d, want 200", status)
	}
	if body != "" {
		t.Errorf("no payload: body = %q, want empty", body)
	}

	// With a payload → the first bytes, hex-encoded, truncated at 256.
	payload := filepath.Join(t.TempDir(), "p.bin")
	if err := os.WriteFile(payload, []byte{0xde, 0xad, 0xbe, 0xef}, 0o600); err != nil {
		t.Skipf("cannot create payload: %v", err)
	}
	s := newTestServer(t, Config{PayloadPath: payload})
	ts2 := httptest.NewServer(s.Handler())
	defer ts2.Close()

	status, body = authedGet(t, ts2, "/v1/sys/hex")
	if status != http.StatusOK {
		t.Fatalf("with payload: status = %d, want 200", status)
	}
	if body != "deadbeef" {
		t.Errorf("hex = %q, want deadbeef", body)
	}
}

// TestProcessesEndpoint covers the process table the dashboard polls.
func TestProcessesEndpoint(t *testing.T) {
	ts := allModules(t)
	status, body := authedGet(t, ts, "/v1/sys/b2")
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200", status)
	}
	var procs []json.RawMessage
	if err := json.Unmarshal([]byte(body), &procs); err != nil {
		t.Fatalf("process table is not a JSON array: %v (body %.120s)", err, body)
	}
}

// TestCommandEndpoint covers the operator console: an empty command is refused
// and a real one returns its output.
func TestCommandEndpoint(t *testing.T) {
	ts := allModules(t)

	status, body := authedPost(t, ts, "/v1/sys/cmd", `{"c":""}`)
	if status != http.StatusBadRequest {
		t.Errorf("empty command: status = %d, want 400 (body %q)", status, body)
	}

	status, body = authedPost(t, ts, "/v1/sys/cmd", `{"c":"echo obl-probe"}`)
	if status != http.StatusOK {
		t.Fatalf("echo: status = %d, want 200 (body %q)", status, body)
	}
	if !strings.Contains(body, "obl-probe") {
		t.Errorf("echo output = %q, want it to contain obl-probe", body)
	}
}
