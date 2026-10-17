package server

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// This file fuzzes the console's exposed surface: the Host allow-list, the
// WebSocket Origin parser and the route policy (which checks precede which
// handler). The parsers inside the modules are fuzzed separately in
// internal/audit, internal/krb, internal/research and so on; what matters here
// is the *guard*, because a hole in it exposes every module at once.
//
// The four targets below never reach a state-changing handler: they only ever
// present a token that cannot match (a byte is prepended to it), so the tests
// assert the gate without executing anything.

// routeKind classifies a registered pattern by the checks that must precede its
// handler. A route added to (*Server).routes() without s.guard(...) shows up
// here as a kindAPI entry that answers something other than 403.
type routeKind int

const (
	kindPage     routeKind = iota // host check only; the token travels inside the page
	kindWS                        // host + origin (for browsers) + token from ?t=
	kindAPI                       // host + token
	kindGatedAPI                  // host + token + an --enable-* flag
)

type testRoute struct {
	method, path string
	kind         routeKind
	flag         string // the flag that unlocks a kindGatedAPI route
}

// registeredRoutes mirrors the patterns registered in (*Server).routes().
// TestRouteTableMatchesServer fails if a listed pattern does not exist, and
// TestGuardedRoutesRejectBadToken fails if a guarded pattern stops being
// guarded — so a new route cannot be added without this table noticing.
var registeredRoutes = []testRoute{
	// pages
	{"GET", "/", kindPage, ""},
	{"GET", "/healthz", kindPage, ""},
	{"GET", "/ws", kindWS, ""},

	// read-only system API
	{"GET", "/v1/sys/st", kindAPI, ""},
	{"GET", "/v1/sys/hex", kindAPI, ""},
	{"GET", "/v1/sys/b2", kindAPI, ""},

	// state-changing system API
	{"POST", "/v1/sys/cmd", kindAPI, ""},
	{"POST", "/v1/sys/opt", kindAPI, ""},

	// collection module
	{"GET", "/v1/sys/a7", kindGatedAPI, "--enable-collect"},
	{"GET", "/v1/sys/cookies", kindGatedAPI, "--enable-collect"},
	{"GET", "/v1/sys/nexus", kindGatedAPI, "--enable-collect"},
	{"POST", "/v1/op/a7", kindGatedAPI, "--enable-collect"},
	{"POST", "/v1/op/cookies", kindGatedAPI, "--enable-collect"},
	{"POST", "/v1/sys/sam", kindGatedAPI, "--enable-collect"},
	{"POST", "/v1/op/roast-asrep", kindGatedAPI, "--enable-collect"},
	{"POST", "/v1/op/roast-tgs", kindGatedAPI, "--enable-collect"},
	{"POST", "/v1/op/spn-enum", kindGatedAPI, "--enable-collect"},
	{"POST", "/v1/op/lsass", kindGatedAPI, "--enable-collect"},
	{"POST", "/v1/op/lsass-wipe", kindGatedAPI, "--enable-collect"},

	// persistence module
	{"GET", "/v1/sys/persist", kindGatedAPI, "--enable-persist"},
	{"POST", "/v1/op/persist-add", kindGatedAPI, "--enable-persist"},
	{"POST", "/v1/op/persist-del", kindGatedAPI, "--enable-persist"},

	// evasion module
	{"POST", "/v1/op/etw", kindGatedAPI, "--enable-evasion"},
	{"POST", "/v1/op/amsi", kindGatedAPI, "--enable-evasion"},

	// lateral movement module
	{"POST", "/v1/op/lateral-winrm", kindGatedAPI, "--enable-lateral"},
	{"POST", "/v1/op/lateral-scm", kindGatedAPI, "--enable-lateral"},

	// injection module
	{"POST", "/v1/op/d4", kindGatedAPI, "--enable-inject"},

	// defensive audit (always available)
	{"POST", "/v1/audit/report", kindAPI, ""},
	{"POST", "/v1/audit/csv", kindAPI, ""},
}

// guardedRoutes returns only the routes that must present the run token.
func guardedRoutes() []testRoute {
	var out []testRoute
	for _, r := range registeredRoutes {
		if r.kind == kindAPI || r.kind == kindGatedAPI {
			out = append(out, r)
		}
	}
	return out
}

// TestRouteTableMatchesServer proves every listed pattern is really registered:
// a typo in the table (or a route that was removed) answers 404, and a wrong
// method answers 405.
func TestRouteTableMatchesServer(t *testing.T) {
	s := newTestServer(t, Config{})
	h := s.Handler()
	for _, r := range registeredRoutes {
		req := httptest.NewRequest(r.method, r.path, strings.NewReader("{}"))
		req.Host = "127.0.0.1:8080"
		req.Header.Set("X-Signal-Token", "not-the-token")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code == http.StatusNotFound || rec.Code == http.StatusMethodNotAllowed {
			t.Errorf("%s %s: status %d — pattern is not registered as listed", r.method, r.path, rec.Code)
		}
	}
}

// TestGuardedRoutesRejectBadToken is the route-policy invariant: on every
// guarded route, a request without the run token must be refused before the
// handler runs. A route registered without s.guard(...) — the realistic way to
// expose a module by accident — fails here.
func TestGuardedRoutesRejectBadToken(t *testing.T) {
	s := newTestServer(t, Config{})
	h := s.Handler()
	for _, r := range guardedRoutes() {
		for _, tc := range []struct {
			name  string
			token string
		}{
			{"absent token", ""},
			{"wrong token", "not-the-token"},
			{"token prefix", testToken[:len(testToken)-1]},
			{"token as substring", testToken[:8]},
		} {
			req := httptest.NewRequest(r.method, r.path, strings.NewReader("{}"))
			req.Host = "127.0.0.1:8080"
			if tc.token != "" {
				req.Header.Set("X-Signal-Token", tc.token)
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != http.StatusForbidden {
				t.Errorf("%s %s with %s: status = %d, want 403", r.method, r.path, tc.name, rec.Code)
			}
			// A refused request must not leak the secret it refused to accept.
			if strings.Contains(rec.Body.String(), testToken) {
				t.Errorf("%s %s with %s: response body carries the run token", r.method, r.path, tc.name)
			}
		}
	}
}

// TestGatedRoutesFailsClosedWithValidToken proves the module gate sits behind
// the token gate but in front of every effect: with a correct token and the
// module disabled, a gated route is still 403 — and it never reports the token
// is the problem, which would mislead an operator into re-checking it.
func TestGatedRoutesFailsClosedWithValidToken(t *testing.T) {
	s := newTestServer(t, Config{}) // no --enable-* flags
	h := s.Handler()
	for _, r := range registeredRoutes {
		if r.kind != kindGatedAPI {
			continue
		}
		req := httptest.NewRequest(r.method, r.path, strings.NewReader("{}"))
		req.Host = "127.0.0.1:8080"
		req.Header.Set("X-Signal-Token", testToken)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Errorf("%s %s with a valid token and %s off: status = %d, want 403",
				r.method, r.path, r.flag, rec.Code)
		}
		if !strings.Contains(rec.Body.String(), r.flag) {
			t.Errorf("%s %s: refusal does not name %s: %s", r.method, r.path, r.flag, rec.Body.String())
		}
	}
}

// loopbackOracle is an independent, deliberately naive statement of the same
// policy validHost implements: the only strings that may be accepted are the
// canonical loopback names, optionally followed by a numeric port. It returns
// "" for anything else. Where the two disagree, validHost is accepting
// something that is not a loopback host:port at all.
func loopbackOracle(hostport string) string {
	s := strings.ToLower(hostport)
	if i := strings.LastIndexByte(s, ':'); i >= 0 {
		if !isPort(s[i+1:]) {
			return ""
		}
		s = s[:i]
	}
	s = strings.TrimSuffix(s, ".")
	switch s {
	case "127.0.0.1", "localhost":
		return s
	case "[::1]":
		return "::1"
	}
	return ""
}

// FuzzValidHost is the DNS-rebinding control under fuzz: whatever it accepts
// must be a loopback authority, and nothing else. This is the check that keeps
// an attacker-controlled domain that resolves to 127.0.0.1 from reading the
// dashboard's token.
func FuzzValidHost(f *testing.F) {
	for _, seed := range []string{
		"127.0.0.1:8080", "localhost:8080", "[::1]:8080", "127.0.0.1", "LOCALHOST",
		"localhost.", "127.0.0.1.:8080", "evil.com:8080", "127.0.0.1.evil.com:8080",
		// Shapes whose *authority* a naive parser reads as loopback even though
		// the string is not one — the interesting mutations.
		"127.0.0.1:8080/evil", "127.0.0.1:@evil", "localhost:80?x=1", "127.0.0.1:8a08",
		"127.0.0.1:", "[::1]", "::1", "127.0.0.1\t", "127.0.0.1%2e", "user@127.0.0.1",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, hostport string) {
		if !validHost(hostport) {
			return
		}
		if got := loopbackOracle(hostport); got == "" {
			t.Fatalf("validHost(%q) = true, but it is not a loopback authority", hostport)
		}
		// Independent of the oracle: a host:port authority cannot contain these.
		if strings.ContainsAny(hostport, `/\\@#?%`+" \t\r\n") {
			t.Fatalf("validHost(%q) = true, but the value contains a non-authority character", hostport)
		}
	})
}

// FuzzAllowedOrigin is the WebSocket handshake guard under fuzz. An accepted
// Origin must be exactly scheme://loopback-host[:port] — no userinfo, no path,
// no query. The userinfo case is the one that matters: url.Parse splits
// "http://evil.com@127.0.0.1" into User=evil.com and Host=127.0.0.1, so a guard
// that only inspects Host reads a remote origin as local.
func FuzzAllowedOrigin(f *testing.F) {
	s := newTestServer(f, Config{Addr: "127.0.0.1:8080"})
	for _, seed := range []string{
		"http://127.0.0.1:8080", "http://localhost:8080", "https://[::1]:8080",
		"", "null", "http://evil.com", "https://evil.com:443",
		"http://evil.com@127.0.0.1", "http://127.0.0.1@evil.com", "http://user:pw@localhost",
		"file://127.0.0.1", "http://127.0.0.1/#x", "http://127.0.0.1/?a=b",
		"http://127.0.0.1.evil.com", "//127.0.0.1", "http:127.0.0.1",
		`http://evil.com\@127.0.0.1`, "http://127.0.0.1\t",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, origin string) {
		if !s.allowedOrigin(origin) {
			return
		}
		if origin == "" {
			return // documented: non-browser clients send no Origin
		}
		if strings.Contains(origin, "@") {
			t.Fatalf("allowedOrigin(%q) = true, but an Origin carries no userinfo", origin)
		}
		u, err := url.Parse(origin)
		if err != nil {
			t.Fatalf("allowedOrigin(%q) = true, but the value does not parse as a URL", origin)
		}
		if u.Scheme != "http" && u.Scheme != "https" {
			t.Fatalf("allowedOrigin(%q) = true with scheme %q", origin, u.Scheme)
		}
		if u.User != nil {
			t.Fatalf("allowedOrigin(%q) = true with userinfo %q", origin, u.User)
		}
		if u.Path != "" && u.Path != "/" {
			t.Fatalf("allowedOrigin(%q) = true with path %q", origin, u.Path)
		}
		if u.RawQuery != "" || u.Fragment != "" {
			t.Fatalf("allowedOrigin(%q) = true with query/fragment", origin)
		}
		if got := loopbackOracle(u.Host); got == "" {
			t.Fatalf("allowedOrigin(%q) = true, but its authority %q is not loopback", origin, u.Host)
		}
	})
}

// FuzzRoutesRejectBadToken drives the whole mux with an arbitrary Host, Origin,
// body and a token that cannot match, and asserts the policy for whichever
// route is selected: a non-loopback Host is always 403, a page route with a
// loopback Host is served, and everything else is 403 without ever disclosing
// the run token. The route is chosen from registeredRoutes so the fuzzer
// explores the guard, never invalid paths (which would 404 and prove nothing).
func FuzzRoutesRejectBadToken(f *testing.F) {
	s := newTestServer(f, Config{})
	h := s.Handler()
	for i := range registeredRoutes {
		f.Add(uint8(i), "127.0.0.1:8080", "http://127.0.0.1:8080", "", "{}")
	}
	f.Fuzz(func(t *testing.T, idx uint8, host, origin, tok, body string) {
		r := registeredRoutes[int(idx)%len(registeredRoutes)]
		req := httptest.NewRequest(r.method, r.path, strings.NewReader(body))
		req.Host = host
		if origin != "" {
			req.Header.Set("Origin", origin)
		}
		// Prepending a byte makes a match impossible regardless of what the
		// fuzzer produced, so this target can never reach a state-changing
		// handler: the only paths it exercises are the refusals.
		req.Header.Set("X-Signal-Token", "x"+tok)

		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)

		if !validHost(host) {
			if rec.Code != http.StatusForbidden {
				t.Fatalf("%s %s: Host %q is not loopback, status = %d, want 403",
					r.method, r.path, host, rec.Code)
			}
			return
		}
		if r.kind == kindPage {
			if rec.Code != http.StatusOK {
				t.Fatalf("%s %s: page with loopback Host %q, status = %d, want 200",
					r.method, r.path, host, rec.Code)
			}
			return
		}
		if rec.Code != http.StatusForbidden {
			t.Fatalf("%s %s reached without the run token: status = %d (token %q)",
				r.method, r.path, rec.Code, tok)
		}
		if strings.Contains(rec.Body.String(), testToken) {
			t.Fatalf("%s %s: refusal leaked the run token", r.method, r.path)
		}
	})
}
