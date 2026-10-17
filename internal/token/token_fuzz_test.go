package token

import "testing"

// FuzzEqual pins the comparison to exact equality. The interesting mutations
// are the near-misses: a prefix, a suffix, a case-variant or a truncation of
// the real token. A guard that accepted any of those would be a complete
// authentication bypass, because every console endpoint trusts this one call.
// Constant-time behaviour cannot be fuzzed; correctness of the verdict can.
func FuzzEqual(f *testing.F) {
	f.Add("a", "a")
	f.Add("", "")
	f.Add("abc", "ab")
	f.Add("abc", "abcd")
	f.Add("ABC", "abc")
	f.Add("abc", "abc\x00")
	f.Add("\x00", "")
	f.Add("deadbeef", "ecafbeef")
	f.Fuzz(func(t *testing.T, a, b string) {
		if got, want := Equal(a, b), a == b; got != want {
			t.Fatalf("Equal(%q, %q) = %v, want %v", a, b, got, want)
		}
	})
}
