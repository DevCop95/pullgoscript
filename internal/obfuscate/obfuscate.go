// Package obfuscate is a build-time string obfuscator: sensitive literals are
// stored as masked byte slices and decoded in memory at use, so they never
// appear in the compiled binary's string table. That raises the cost of a
// `strings`/`grep` sweep or a static YARA signature on the payload.
//
// This is OBFUSCATION, NOT ENCRYPTION: the mask key ships in the binary and a
// determined analyst recovers it in minutes. It is a signature-lowering
// measure for the operator's own tooling, nothing more — never use it to
// protect an actual secret.
//
// Mask is the inverse of S and is meant to be run by a generator (see the
// masked literals in the research package, and cmd/oblpack's sibling usage):
//
//	obfuscate.S(obfuscate.Mask("AmsiScanBuffer")) == "AmsiScanBuffer"
package obfuscate

// pepperMask is the fixed constant the pepper itself is stored against, so the
// mask key is not a plaintext string in the binary either (a single grep for
// the product name must not identify the tool).
func pepperMask(i int) byte { return byte(i*17 + 3) }

// pepperEnc is "obl1t3r4tu5" XOR pepperMask, byte by byte. Stored encoded so
// the key does not sit in .rodata as contiguous printable ASCII.
var pepperEnc = []byte{0x6c, 0x76, 0x49, 0x07, 0x33, 0x6b, 0x1b, 0x4e, 0xff, 0xe9, 0x98}

// pepper is mixed into every position so the mask is not a single repeating
// byte (a one-byte XOR is defeated by a trivial frequency count).
var pepper = func() []byte {
	out := make([]byte, len(pepperEnc))
	for i := range pepperEnc {
		out[i] = pepperEnc[i] ^ pepperMask(i)
	}
	return out
}()

// maskByte computes the mask for position i.
func maskByte(i int) byte {
	return pepper[i%len(pepper)] ^ byte(i*31+7)
}

// Mask encodes plain into the masked form embedded in the binary.
func Mask(plain string) []byte {
	out := make([]byte, len(plain))
	for i := 0; i < len(plain); i++ {
		out[i] = plain[i] ^ maskByte(i)
	}
	return out
}

// S decodes a masked literal produced by Mask back to its plaintext.
func S(masked []byte) string {
	out := make([]byte, len(masked))
	for i := range masked {
		out[i] = masked[i] ^ maskByte(i)
	}
	return string(out)
}
