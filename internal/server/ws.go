package server

import (
	"encoding/json"
	"log"
	"net/http"
	"sync"

	"github.com/DevCop95/obliteratus/internal/token"
	"github.com/gorilla/websocket"
)

// hub tracks authenticated dashboard sockets and fans out JSON events.
type hub struct {
	mu      sync.Mutex
	clients map[*websocket.Conn]bool
}

func newHub() *hub { return &hub{clients: make(map[*websocket.Conn]bool)} }

func (h *hub) add(c *websocket.Conn) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.clients[c] = true
}

func (h *hub) remove(c *websocket.Conn) {
	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.clients, c)
}

// broadcastJSON sends v to every connected dashboard socket. Write errors are
// dropped here — a dead socket is reaped by its read loop.
func (h *hub) broadcastJSON(v interface{}) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for c := range h.clients {
		_ = c.WriteJSON(v)
	}
}

// broadcastLog streams one operator-console line ("[ts] msg").
func (h *hub) broadcastLog(msg, level string) {
	h.broadcastJSON(map[string]string{"m": msg, "l": level})
}

// upgrader is configured per-server so CheckOrigin can enforce both the
// loopback origin and (via query token in the handler) the per-run token.
func (s *Server) newUpgrader() websocket.Upgrader {
	return websocket.Upgrader{
		ReadBufferSize:  1024,
		WriteBufferSize: 1024,
		// The v1 implementation returned true unconditionally, letting any
		// web page open this socket and drive the console. Now: Origin must
		// be loopback AND the caller must present the token (checked in
		// handleWS before we even upgrade).
		CheckOrigin: func(r *http.Request) bool {
			return s.allowedOrigin(r.Header.Get("Origin"))
		},
	}
}

// handleWS completes the WebSocket handshake for the dashboard.
//
// Browser JS cannot attach custom headers to a WebSocket, so the token
// travels as a query parameter (?t=). Both checks are required:
//   - Origin must be this loopback listener (blocks cross-site WS hijack);
//   - token must match (blocks a page that passed the origin check by being
//     served from loopback but lacking the secret).
func (s *Server) handleWS(w http.ResponseWriter, r *http.Request) {
	setSecurityHeaders(w, s.connectSrc)
	if !validHost(r.Host) {
		http.Error(w, "forbidden: host", http.StatusForbidden)
		return
	}
	if !s.allowedOrigin(r.Header.Get("Origin")) {
		http.Error(w, "forbidden: origin", http.StatusForbidden)
		return
	}
	if !token.Equal(s.token, r.URL.Query().Get("t")) {
		http.Error(w, "forbidden: token", http.StatusForbidden)
		return
	}
	up := s.newUpgrader()
	conn, err := up.Upgrade(w, r, nil)
	if err != nil {
		return // Upgrade already wrote the error response
	}
	s.hub.add(conn)
	defer func() {
		s.hub.remove(conn)
		conn.Close()
	}()
	// Read loop only exists to detect disconnects; the dashboard never sends
	// frames after the handshake.
	for {
		if _, _, err := conn.NextReader(); err != nil {
			return
		}
	}
}

// logLine broadcasts a console line and also records it server-side.
func (s *Server) logLine(msg, level string) {
	log.Printf("[%s] %s", level, msg)
	s.hub.broadcastLog(msg, level)
}

// sendJSON writes v as the JSON response with the given status.
func sendJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
