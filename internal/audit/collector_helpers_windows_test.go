//go:build windows

package audit

// Unit tests for the browser-collection helpers that need no live browser:
// the path builders, the log truncator, the XOR/AEAD primitives and the copy
// helper. The end-to-end collection path needs a real profile and a SYSTEM
// token, but these are the pieces where a bug is silent and cheap to prevent.

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBrowserRootPaths(t *testing.T) {
	root := `C:\Users\test\AppData\Local`
	t.Setenv("LOCALAPPDATA", root)
	cases := map[string]string{
		"Chrome": filepath.Join(root, "Google", "Chrome", "User Data"),
		"Brave":  filepath.Join(root, "BraveSoftware", "Brave-Browser", "User Data"),
		"Edge":   filepath.Join(root, "Microsoft", "Edge", "User Data"),
		// An unknown name must fall back to Chrome rather than produce an
		// empty path that would make the collector walk the whole drive.
		"Unknown": filepath.Join(root, "Google", "Chrome", "User Data"),
	}
	for browser, want := range cases {
		if got := browserRoot(browser); got != want {
			t.Errorf("browserRoot(%q) = %q, want %q", browser, got, want)
		}
	}
	if got, want := localStatePath("Edge"), filepath.Join(cases["Edge"], "Local State"); got != want {
		t.Errorf("localStatePath(Edge) = %q, want %q", got, want)
	}
}

func TestTruncateForLog(t *testing.T) {
	if got := truncateForLog([]byte("  hello\n")); got != "hello" {
		t.Errorf("truncateForLog(short) = %q, want hello", got)
	}
	long := strings.Repeat("A", 500)
	got := truncateForLog([]byte(long))
	if len(got) != 120 {
		t.Errorf("truncateForLog(500 chars) = %d chars, want 120", len(got))
	}
	if truncateForLog(nil) != "" {
		t.Error("truncateForLog(nil) should be empty")
	}
}

func TestXorBytesRoundTrip(t *testing.T) {
	key := []byte{0x0f, 0x1e, 0x2d}
	a := []byte("the quick brown fox")
	if got := xorBytes(xorBytes(a, key), key); !bytes.Equal(got, a) {
		t.Errorf("xorBytes is not self-inverse: %q -> %q", a, got)
	}
	// A single-byte key repeats; a longer key wraps.
	if got := xorBytes([]byte{0x00, 0x00, 0x00}, []byte{0xff}); !bytes.Equal(got, []byte{0xff, 0xff, 0xff}) {
		t.Errorf("xorBytes with a 1-byte key = %x", got)
	}
	// An empty key must fail closed, not divide by zero.
	if got := xorBytes(a, nil); got != nil {
		t.Errorf("xorBytes with an empty key = %x, want nil", got)
	}
}

func TestAESGCMOpen(t *testing.T) {
	key := bytes.Repeat([]byte{0x11}, 32)
	iv := bytes.Repeat([]byte{0x22}, 12)
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("aes.NewCipher: %v", err)
	}
	gcm, err := cipher.NewGCMWithNonceSize(block, 12)
	if err != nil {
		t.Fatalf("cipher.NewGCMWithNonceSize: %v", err)
	}
	plain := []byte("app-bound encryption master key blob")
	sealed := gcm.Seal(nil, iv, plain, nil)

	got, err := aesGCMOpen(key, iv, sealed)
	if err != nil {
		t.Fatalf("aesGCMOpen: %v", err)
	}
	if !bytes.Equal(got, plain) {
		t.Errorf("aesGCMOpen round-trip = %q, want %q", got, plain)
	}

	bad := []struct {
		name        string
		key, iv, ct []byte
	}{
		{"short key", key[:16], iv, sealed},
		{"short iv", key, iv[:8], sealed},
		{"short ct", key, iv, sealed[:15]},
		{"wrong key", bytes.Repeat([]byte{0x33}, 32), iv, sealed},
		{"tampered ct", key, iv, flip(sealed)},
	}
	for _, c := range bad {
		if _, err := aesGCMOpen(c.key, c.iv, c.ct); err == nil {
			t.Errorf("%s: aesGCMOpen accepted a bad input", c.name)
		}
	}
}

// flip returns b with its last byte toggled (breaks the GCM tag).
func flip(b []byte) []byte {
	out := append([]byte{}, b...)
	out[len(out)-1] ^= 0xff
	return out
}

func TestForceCopy(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src.db")
	dst := filepath.Join(dir, "copy.db")
	want := []byte("sqlite header and rows")
	if err := os.WriteFile(src, want, 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := forceCopy(src, dst); err != nil {
		t.Fatalf("forceCopy: %v", err)
	}
	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatalf("read copy: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("copy = %q, want %q", got, want)
	}
	if err := forceCopy(filepath.Join(dir, "missing.db"), dst); err == nil {
		t.Error("forceCopy with a missing source: want error, got nil")
	}
}
