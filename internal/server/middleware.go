package server

import (
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/DevCop95/obliteratus/internal/token"
)

// loopbackHosts are the only Host values accepted. Everything the dashboard
// does is local, so a Host header from any other name means either DNS
// rebinding (attacker DNS answer pointing at 127.0.0.1) or a proxy probing us.
var loopbackHosts = map[string]bool{
	"127.0.0.1": true,
	"localhost": true,
	"::1":       true,
}

// validHost reports whether the request targeted a loopback Host header.
//
// Strictness matters more than permissiveness here: this is the control that
// stops a DNS-rebinding page (`Host: attacker.example` resolving to 127.0.0.1)
// from reading the token out of the dashboard. Anything that is not a bare
// loopback host, a loopback host with a numeric port, or a bracketed IPv6
// loopback with a numeric port is refused.
//
// Note that net.SplitHostPort validates the *shape* of an address, not its
// contents, and it is more permissive than it looks: for "127.0.0.1:8080/evil"
// it returns host "127.0.0.1" with port "8080/evil", and for "127.0.0.1:8a08"
// and "127.0.0.1:" it returns no error at all. The stdlib HTTP server only
// rejects the first shape — a Host containing "/" never reaches a handler (400
// before this code runs) — so for a non-numeric or empty port this explicit
// isPort check is the only control, not a belt over the stdlib's braces. That
// was verified against the live listener, not assumed.
//
// None of the three is a live bypass: a rebinding page cannot make a browser
// send a loopback-looking Host, it supplies its own hostname. But the guard is
// asserted here rather than left to the stdlib, and those exact host strings
// are pinned in the fuzz seed corpus (FuzzValidHost), so the check cannot
// quietly become permissive again.
func validHost(hostport string) bool {
	host := hostport
	if h, p, err := net.SplitHostPort(hostport); err == nil {
		if !isPort(p) {
			return false
		}
		host = h
	} else if strings.ContainsAny(hostport, ":[]") {
		// A port separator or bracket we could not parse: refuse instead of
		// guessing which parser the caller intended.
		return false
	}
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if host == "" {
		return false
	}
	return loopbackHosts[host]
}

// isPort reports whether p is a non-empty run of ASCII digits.
func isPort(p string) bool {
	if p == "" {
		return false
	}
	for i := 0; i < len(p); i++ {
		if p[i] < '0' || p[i] > '9' {
			return false
		}
	}
	return true
}

// guard is the API middleware: loopback Host + constant-time token check.
// Cross-origin pages cannot satisfy it — the custom X-Signal-Token header
// forces a CORS preflight, which we never approve, so a hostile page's fetch
// dies before the request is ever sent (this is what protects state-changing
// routes such as /v1/sys/cmd from CSRF).
func (s *Server) guard(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		setSecurityHeaders(w, s.connectSrc)
		if !validHost(r.Host) {
			http.Error(w, "forbidden: host", http.StatusForbidden)
			return
		}
		if !token.Equal(s.token, r.Header.Get("X-Signal-Token")) {
			http.Error(w, "forbidden: token", http.StatusForbidden)
			return
		}
		next(w, r)
	}
}

// guardPage guards HTML-ish routes that cannot carry a token on first load
// (there is no token to send yet). Host validation is still mandatory: it is
// what keeps a rebinding domain from reading the token out of the page.
func (s *Server) guardPage(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		setSecurityHeaders(w, s.connectSrc)
		if !validHost(r.Host) {
			http.Error(w, "forbidden: host", http.StatusForbidden)
			return
		}
		next(w, r)
	}
}

// setSecurityHeaders applies baseline hardening headers to every response.
func setSecurityHeaders(w http.ResponseWriter, connectSrc string) {
	h := w.Header()
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Cache-Control", "no-store")
	// The dashboard is fully self-contained apart from Google Fonts; scripts
	// must come from the origin itself. 'unsafe-inline' is required by the
	// legacy dashboard markup (inline handlers) and does not weaken the
	// connect-src boundary below.
	h.Set("Content-Security-Policy",
		"default-src 'self'; "+
			"script-src 'self' 'unsafe-inline'; "+
			"style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "+
			"font-src https://fonts.gstatic.com; "+
			"img-src 'self' data:; "+
			"connect-src 'self' "+connectSrc+"; "+
			"frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
}

// allowedOrigin validates the Origin header of a WebSocket handshake.
// Browsers always attach Origin to cross-origin WS requests, so a page on
// evil.com cannot complete the handshake even if it somehow knew the token
// (it still needs the token too — both checks must pass).
//
// The check is deliberately stricter than "url.Parse succeeded and the host
// looks loopback". Go's url.Parse puts the *userinfo* in u.User and the host in
// u.Host, so "http://evil.com@127.0.0.1" parses with u.Host == "127.0.0.1" and
// would read as loopback. A browser never sends userinfo in Origin, which is
// why this was not exploitable, but accepting a non-loopback origin because of
// a parsing quirk is the kind of thing that stops being theoretical the moment
// the check is reused. So: an Origin must be exactly scheme://host[:port].
func (s *Server) allowedOrigin(origin string) bool {
	if origin == "" {
		// Non-browser clients (curl, a test) send no Origin; they are held to
		// the token check alone, which browsers on other origins cannot pass.
		return true
	}
	u, err := url.Parse(origin)
	if err != nil {
		return false
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return false
	}
	if u.User != nil || u.Opaque != "" || u.RawQuery != "" || u.Fragment != "" {
		return false
	}
	if u.Path != "" && u.Path != "/" {
		return false
	}
	return validHost(u.Host)
}
