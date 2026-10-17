package obfuscate

// Fuzz target for the string obfuscator.
//
// There is no parser here, so this pins an invariant rather than hunting a
// crash: Mask and S are exact inverses for every input, and S must never panic
// on arbitrary bytes (it runs on embedded literals at process start). A
// round-trip break means a masked literal in .rodata decodes to the wrong
// value — a silent, hard-to-trace runtime failure.

import "testing"

func FuzzMaskRoundTrip(f *testing.F) {
	f.Add("AmsiScanBuffer")
	f.Add("")
	f.Add("\x00\xff\x1b\x7f") // arbitrary bytes: S is byte-wise, not UTF-8 aware

	f.Fuzz(func(t *testing.T, s string) {
		if got := S(Mask(s)); got != s {
			t.Fatalf("S(Mask(%q)) = %q, round-trip broken", s, got)
		}
	})
}
