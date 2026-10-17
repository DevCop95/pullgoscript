package server

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testToken = "test-token-0123456789abcdef"

// newTestServer builds a server around the shared test token. It takes
// testing.TB so fuzz targets (*testing.F) can use it too.
func newTestServer(tb testing.TB, cfg Config) *Server {
	tb.Helper()
	cfg.Token = testToken
	if cfg.Version == "" {
		cfg.Version = "test"
	}
	return New(cfg)
}

// do builds an authenticated request against an httptest server URL.
func do(method, url, host string, header map[string]string, body io.Reader) *http.Request {
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		panic(err)
	}
	if host != "" {
		req.Host = host
	}
	for k, v := range header {
		req.Header.Set(k, v)
	}
	return req
}

func TestValidHost(t *testing.T) {
	cases := map[string]bool{
		"127.0.0.1:8080":          true,
		"localhost:8080":          true,
		"[::1]:8080":              true,
		"127.0.0.1":               true,
		"LOCALHOST":               true,
		"evil.com:8080":           false,
		"192.168.1.10":            false,
		"":                        false,
		"127.0.0.1.evil.com:8080": false,
	}
	for host, want := range cases {
		if got := validHost(host); got != want {
			t.Errorf("validHost(%q) = %v, want %v", host, got, want)
		}
	}
}

func TestGuardRejectsMissingToken(t *testing.T) {
	s := newTestServer(t, Config{})
	ts := httptest.NewServer(s.Handler())
	defer ts.Close()

	req := do("GET", ts.URL+"/v1/sys/st", "", nil, nil) // no token header
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
}

func TestGuardRejectsWrongToken(t *testing.T) {
	s := newTestServer(t, Config{})
	ts := httptest.NewServer(s.Handler())
	defer ts.Close()

	req := do("GET", ts.URL+"/v1/sys/st", "", map[string]string{"X-Signal-Token": "nope"}, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
}

func TestGuardRejectsForeignHost(t *testing.T) {
	// DNS rebinding simulation: request carries the right token but arrives
	// with a Host header that is not loopback.
	s := newTestServer(t, Config{})
	ts := httptest.NewServer(s.Handler())
	defer ts.Close()

	req := do("GET", ts.URL+"/v1/sys/st", "attacker.example",
		map[string]string{"X-Signal-Token": testToken}, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (host check must run before token check)", resp.StatusCode)
	}
}

func TestGuardAcceptsValidRequest(t *testing.T) {
	s := newTestServer(t, Config{})
	ts := httptest.NewServer(s.Handler())
	defer ts.Close()

	req := do("GET", ts.URL+"/v1/sys/st", "", map[string]string{"X-Signal-Token": testToken}, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if got := string(body); got != "USER" && got != "ADMIN" {
		t.Fatalf("status body = %q, want USER or ADMIN", got)
	}
}

func TestWrongMethodIsRejected(t *testing.T) {
	s := newTestServer(t, Config{})
	ts := httptest.NewServer(s.Handler())
	defer ts.Close()

	// /v1/sys/cmd is POST-only; a GET (e.g. from a plain <img> tag) must not
	// reach the handler even with a token.
	for _, path := range []string{"/v1/sys/cmd", "/v1/sys/sam"} {
		req := do("GET", ts.URL+path, "", map[string]string{"X-Signal-Token": testToken}, nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusMethodNotAllowed {
			t.Fatalf("GET %s: status = %d, want 405", path, resp.StatusCode)
		}
	}
}

func TestIndexInjectsToken(t *testing.T) {
	s := newTestServer(t, Config{})
	req := httptest.NewRequest("GET", "/", nil)
	req.Host = "127.0.0.1:8080"
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, `window.apiToken = "`+testToken+`"`) {
		t.Fatal("served HTML does not carry the run token")
	}
	if strings.Contains(body, "SIGNAL_\" + location.port") {
		t.Fatal("placeholder token was not replaced")
	}
}

func TestSecurityHeadersPresent(t *testing.T) {
	s := newTestServer(t, Config{})
	req := httptest.NewRequest("GET", "/", nil)
	req.Host = "127.0.0.1:8080"
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)

	for header, want := range map[string]string{
		"X-Content-Type-Options": "nosniff",
		"X-Frame-Options":        "DENY",
		"Referrer-Policy":        "no-referrer",
		"Cache-Control":          "no-store",
	} {
		if got := rec.Header().Get(header); got != want {
			t.Errorf("%s = %q, want %q", header, got, want)
		}
	}
	if csp := rec.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "default-src 'self'") {
		t.Errorf("Content-Security-Policy = %q, want default-src 'self'", csp)
	}
}

func TestDisabledModuleFailsClosed(t *testing.T) {
	// Default config: collect + inject locked.
	s := newTestServer(t, Config{})
	ts := httptest.NewServer(s.Handler())
	defer ts.Close()

	for _, tc := range []struct{ method, path, flag string }{
		{"POST", "/v1/op/a7", "--enable-collect"},
		{"POST", "/v1/op/cookies", "--enable-collect"},
		{"POST", "/v1/sys/sam", "--enable-collect"},
		{"POST", "/v1/op/roast-asrep", "--enable-collect"},
		{"POST", "/v1/op/roast-tgs", "--enable-collect"},
		{"POST", "/v1/op/spn-enum", "--enable-collect"},
		{"POST", "/v1/op/lsass", "--enable-collect"},
		{"POST", "/v1/op/lsass-wipe", "--enable-collect"},
		{"GET", "/v1/sys/persist", "--enable-persist"},
		{"POST", "/v1/op/persist-add", "--enable-persist"},
		{"POST", "/v1/op/persist-del", "--enable-persist"},
		{"POST", "/v1/op/etw", "--enable-evasion"},
		{"POST", "/v1/op/amsi", "--enable-evasion"},
		{"POST", "/v1/op/lateral-winrm", "--enable-lateral"},
		{"POST", "/v1/op/lateral-scm", "--enable-lateral"},
		{"GET", "/v1/sys/nexus", "--enable-collect"},
		{"POST", "/v1/op/d4", "--enable-inject"},
	} {
		req := do(tc.method, ts.URL+tc.path, "",
			map[string]string{"X-Signal-Token": testToken}, strings.NewReader("{}"))
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		var payload map[string]string
		_ = json.NewDecoder(resp.Body).Decode(&payload)
		resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("%s %s: status = %d, want 403", tc.method, tc.path, resp.StatusCode)
		}
		if !strings.Contains(payload["hint"], tc.flag) {
			t.Errorf("%s %s: hint %q does not mention %s", tc.method, tc.path, payload["hint"], tc.flag)
		}
	}
}

func TestValidLSASSDumpPath(t *testing.T) {
	tmp := filepath.Clean(os.TempDir())
	good := filepath.Join(tmp, "obl-lsass-640-20260101-120000.dmp")
	// Create the file so the Lstat/symlink check has something to stat.
	if err := os.WriteFile(good, []byte("x"), 0o600); err != nil {
		t.Skipf("cannot create temp dump: %v", err)
	}
	defer os.Remove(good)

	cases := map[string]bool{
		good: true,
		filepath.Join(tmp, "obl-lsass-1-20260101-000000.dmp"):       false, // does not exist
		filepath.Join(tmp, "evil.dmp"):                              false, // wrong name
		filepath.Join(tmp, "obl-lsass-x-20260101-120000.dmp"):       false, // pid not numeric
		`C:\Windows\System32\config\SAM`:                            false, // outside temp
		filepath.Join(tmp, "..", "obl-lsass-1-20260101-120000.dmp"): false, // traversal out of temp
		"": false,
	}
	for path, want := range cases {
		if got := validLSASSDumpPath(path); got != want {
			t.Errorf("validLSASSDumpPath(%q) = %v, want %v", path, got, want)
		}
	}
}

func TestAllowedOrigin(t *testing.T) {
	s := newTestServer(t, Config{Addr: "127.0.0.1:8080"})
	for origin, want := range map[string]bool{
		"http://127.0.0.1:8080": true,
		"http://localhost:8080": true,
		"http://localhost:9999": true, // different port still loopback; token still required
		"http://evil.com":       false,
		"https://evil.com":      false,
		"http://attacker.test":  false,
		"":                      true, // non-browser client; token is the gate
	} {
		if got := s.allowedOrigin(origin); got != want {
			t.Errorf("allowedOrigin(%q) = %v, want %v", origin, got, want)
		}
	}
}

func TestRefusesNonLoopbackBind(t *testing.T) {
	s := newTestServer(t, Config{Addr: "0.0.0.0:0"})
	err := s.ListenAndServe()
	if err == nil {
		t.Fatal("ListenAndServe on 0.0.0.0 must be refused")
	}
	if !strings.Contains(err.Error(), "non-loopback") {
		t.Fatalf("error = %v, want mention of non-loopback", err)
	}
}

func TestHealthEndpoint(t *testing.T) {
	s := newTestServer(t, Config{})
	ts := httptest.NewServer(s.Handler())
	defer ts.Close()
	resp, err := http.Get(ts.URL + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
}
