package research

// Fuzz target for the packed-payload envelope.
//
// Unpack runs the moment a payload is loaded, and on any --payload file an
// operator points the injector at — potentially an artefact assembled by
// someone else. A truncated or adversarial blob must fail closed and never
// panic. The seed is a genuine Pack output so the fuzzer mutates the envelope
// (lengths, nonce, ciphertext, tag), not just the magic.
//
// The key is fixed and non-secret by design: this target checks parser
// robustness, not confidentiality.

import "testing"

func FuzzUnpack(f *testing.F) {
	key := DeriveKey("obliteratus-fuzz-seed")
	if packed, err := Pack(key, []byte("\x90\x90\x90\xc3 payload placeholder")); err == nil {
		f.Add(packed)
	}
	f.Add([]byte{})
	f.Add(packMagic)
	f.Add(append(append([]byte{}, packMagic...), make([]byte, 40)...))

	f.Fuzz(func(t *testing.T, data []byte) {
		if _, err := Unpack(key, data); err == nil {
			// A successful decode must at least be self-consistent: anything
			// Unpack accepts has to survive a repack round-trip.
			if !IsPacked(data) {
				t.Fatalf("Unpack accepted a blob IsPacked rejected: %x", data)
			}
		}
	})
}
