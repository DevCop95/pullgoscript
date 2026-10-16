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
func validHost(hostport string) bool {
	host := hostport
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		host = h
	}
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	return loopbackHosts[host]
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
	return validHost(u.Host)
}
