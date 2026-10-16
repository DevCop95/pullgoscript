package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// TestWebSocketRequiresTokenAndOrigin exercises the full WS handshake in both
// directions: a legit loopback client with the token connects; a hostile
// origin (even with the token) is rejected.
func TestWebSocketRequiresTokenAndOrigin(t *testing.T) {
	s := newTestServer(t, Config{})
	ts := httptest.NewServer(s.Handler())
	defer ts.Close()
	wsURL := "ws" + strings.TrimPrefix(ts.URL, "http")

	// 1. No token → rejected before upgrade.
	d := websocket.Dialer{HandshakeTimeout: 3 * time.Second}
	_, resp, err := d.Dial(wsURL+"/ws", nil)
	if err == nil {
		t.Fatal("dial without token succeeded, want rejection")
	}
	if resp == nil || resp.StatusCode != http.StatusForbidden {
		t.Fatalf("no-token handshake status = %v, want 403", resp)
	}

	// 2. Token but hostile Origin → rejected.
	header := http.Header{}
	header.Set("Origin", "https://evil.example")
	_, resp, err = d.Dial(wsURL+"/ws?t="+testToken, header)
	if err == nil {
		t.Fatal("dial with hostile origin succeeded, want rejection")
	}
	if resp == nil || resp.StatusCode != http.StatusForbidden {
		t.Fatalf("hostile-origin handshake status = %v, want 403", resp)
	}

	// 3. Token + loopback origin → accepted.
	header = http.Header{}
	header.Set("Origin", ts.URL) // httptest serves from 127.0.0.1
	conn, resp, err := d.Dial(wsURL+"/ws?t="+testToken, header)
	if err != nil {
		if resp != nil {
			t.Fatalf("legit handshake failed: %v (status %d)", err, resp.StatusCode)
		}
		t.Fatalf("legit handshake failed: %v", err)
	}
	defer conn.Close()

	// 4. Broadcast reaches the authenticated client.
	s.hub.broadcastLog("hello", "INFO")
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	var msg map[string]string
	if err := conn.ReadJSON(&msg); err != nil {
		t.Fatalf("read broadcast: %v", err)
	}
	if msg["m"] != "hello" || msg["l"] != "INFO" {
		t.Fatalf("broadcast = %v, want {m:hello l:INFO}", msg)
	}
}
