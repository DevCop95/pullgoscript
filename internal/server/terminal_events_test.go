package server

import (
	"errors"
	"testing"

	"github.com/DevCop95/obliteratus/internal/audit"
)

// TestSAMTerminalEvents locks in the contract that fixed the opaque SAM
// failure: a dump error must surface as sam_error and must NOT be followed by
// a bare sam_done (which the dashboard renders as the misleading "no SAM
// material" empty state).
func TestSAMTerminalEvents(t *testing.T) {
	accounts := []audit.SAMAccount{{RID: 500, User: "Administrator"}}

	t.Run("error yields only sam_error", func(t *testing.T) {
		evs := samTerminalEvents(nil, errors.New("reg save: access denied"))
		if len(evs) != 1 {
			t.Fatalf("got %d events, want 1: %v", len(evs), evs)
		}
		m := evs[0].(map[string]interface{})
		if m["type"] != "sam_error" {
			t.Fatalf("type = %v, want sam_error", m["type"])
		}
		if m["error"] != "reg save: access denied" {
			t.Fatalf("error = %v, want the real cause", m["error"])
		}
		for _, ev := range evs {
			if ev.(map[string]interface{})["type"] == "sam_done" {
				t.Fatal("sam_done must not follow a failure")
			}
		}
	})

	t.Run("success with accounts yields chunk then done", func(t *testing.T) {
		evs := samTerminalEvents(accounts, nil)
		if len(evs) != 2 {
			t.Fatalf("got %d events, want 2: %v", len(evs), evs)
		}
		if evs[0].(map[string]interface{})["type"] != "sam_chunk" {
			t.Fatalf("first event = %v, want sam_chunk", evs[0])
		}
		if evs[1].(map[string]interface{})["type"] != "sam_done" {
			t.Fatalf("last event = %v, want sam_done", evs[1])
		}
	})

	t.Run("success with no accounts yields only done", func(t *testing.T) {
		evs := samTerminalEvents(nil, nil)
		if len(evs) != 1 {
			t.Fatalf("got %d events, want 1: %v", len(evs), evs)
		}
		if evs[0].(map[string]interface{})["type"] != "sam_done" {
			t.Fatalf("event = %v, want sam_done", evs[0])
		}
	})
}

// TestLSASSTerminalEvents locks in that a failed dump reports lsass_error
// instead of staying silent (the old behaviour left the dashboard hanging).
func TestLSASSTerminalEvents(t *testing.T) {
	t.Run("error yields only lsass_error", func(t *testing.T) {
		evs := lsassTerminalEvents("", 0, errors.New("OpenProcess: access denied"))
		if len(evs) != 1 {
			t.Fatalf("got %d events, want 1: %v", len(evs), evs)
		}
		m := evs[0].(map[string]interface{})
		if m["type"] != "lsass_error" {
			t.Fatalf("type = %v, want lsass_error", m["type"])
		}
		if m["error"] != "OpenProcess: access denied" {
			t.Fatalf("error = %v, want the real cause", m["error"])
		}
	})

	t.Run("success yields lsass_done with path and size", func(t *testing.T) {
		evs := lsassTerminalEvents(`C:\Temp\obl-lsass-660-20260101-120000.dmp`, 4096, nil)
		if len(evs) != 1 {
			t.Fatalf("got %d events, want 1: %v", len(evs), evs)
		}
		m := evs[0].(map[string]interface{})
		if m["type"] != "lsass_done" {
			t.Fatalf("type = %v, want lsass_done", m["type"])
		}
		if m["size"] != int64(4096) {
			t.Fatalf("size = %v, want 4096", m["size"])
		}
	})
}
