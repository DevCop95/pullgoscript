package persist

import (
	"strings"
	"testing"
)

// FuzzSanitizeName pins the invariant that makes the persist HTTP API safe:
// whatever a caller puts in the JSON "name" field, the string that ends up as a
// registry value name, a Startup folder filename or a PowerShell argument can
// only contain [A-Za-z0-9._-] and is at most 64 bytes. The table test next door
// covers the cases we thought of; this covers the ones we did not.
func FuzzSanitizeName(f *testing.F) {
	for _, s := range []string{
		"obl-update",
		"a.b_c9",
		`..\evil`,
		"../../etc/passwd",
		`evil"; Remove-Item C:\ -Recurse #`,
		"a b",
		"$(calc).exe",
		"a`nb",
		strings.Repeat("x", 200),
		"héllo",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, name string) {
		got := sanitizeName(name)
		if len(got) > 64 {
			t.Fatalf("sanitizeName(%q) is %d bytes, want at most 64", name, len(got))
		}
		for i := 0; i < len(got); i++ {
			c := got[i]
			switch {
			case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9',
				c == '-', c == '_', c == '.':
			default:
				t.Fatalf("sanitizeName(%q) = %q contains %q, outside [A-Za-z0-9._-]", name, got, c)
			}
		}
		// Idempotent: a name that round-trips through the API must not drift.
		if again := sanitizeName(got); again != got {
			t.Fatalf("sanitizeName is not idempotent: %q -> %q -> %q", name, got, again)
		}
	})
}
