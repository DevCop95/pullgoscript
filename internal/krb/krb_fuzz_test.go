package krb

// Fuzz target for the KDC response parser.
//
// parseRep decodes what arrives on the wire from a host answering on port 88 —
// a domain controller we hope is honest, or whatever a hostile network planted
// in its place. That is untrusted input, and a panic here aborts the roast path
// mid-engagement, so the exhaustive decoder needs proof it rejects garbage
// without dying. The seed reuses the known-good KRB-ERROR vector from the unit
// tests so the fuzzer mutates a decodable structure.

import "testing"

func FuzzParseRep(f *testing.F) {
	// KRB-ERROR ::= [APPLICATION 30] with error-code [6] = 25, plus pvno and
	// msg-type, i.e. the same shape TestParseKRBError pins.
	f.Add(app(30, append(ctx(0, derInt(5)), append(ctx(1, derInt(30)), ctx(6, derInt(25))...)...)))
	// AS-REP ::= [APPLICATION 11] with pvno/msg-type and an EncryptedData [6].
	ed := ctx(6, derSeq(derInt(23), derOctet([]byte{0xde, 0xad, 0xbe, 0xef})))
	asrep := append(ctx(0, derInt(5)), ctx(1, derInt(11))...)
	asrep = append(asrep, ed...)
	f.Add(app(11, asrep))
	f.Add([]byte{})
	f.Add([]byte{0x7e}) // APPLICATION 30 tag, no length
	f.Add([]byte{0x6b}) // APPLICATION 11 tag, no length

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _, _, _ = parseRep(data)
	})
}
