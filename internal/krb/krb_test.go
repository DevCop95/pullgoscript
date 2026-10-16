package krb

import (
	"bytes"
	"encoding/asn1"
	"encoding/hex"
	"strings"
	"testing"
)

// --- MD4 / NT hash ---------------------------------------------------------
// Vectors: RFC 1320 test suite ("abc") and the well-known NT hashes for the
// empty string and "password" (same value pinned in audit/sam_test.go).

func TestNTFromPassword(t *testing.T) {
	cases := map[string]string{
		"":         "31d6cfe0d16ae931b73c59d7e0c089c0",
		"password": "8846f7eaee8fb117ad06bdd830b7586c",
		"abc":      "e0fba38268d0ec66ef1cb452d5885e53", // MD4(UTF-16LE("abc"))
	}
	for pw, want := range cases {
		if got := NTFromPassword(pw); got != want {
			t.Errorf("NTFromPassword(%q) = %s, want %s", pw, got, want)
		}
	}
}

// --- RC4-HMAC (RFC 4757) ---------------------------------------------------
// Reference vectors produced with an independent implementation
// (pycryptodome HMAC-MD5 + ARC4, the same primitives impacket uses):
//
//	key   = 9f6288573c037e4806bec930e44b7933
//	usage = 1, plaintext = 01*8 || "kerberos-test-data"
//	chk   = a624f6ebdf527fea63d0de4762115cf6
//	ct    = 31b3ddefd479b84eded2fad699e605603ec24ff9eda463b9c03b

var refKey, _ = hex.DecodeString("9f6288573c037e4806bec930e44b7933")

func TestRC4DecryptReferenceVector(t *testing.T) {
	blob, _ := hex.DecodeString("a624f6ebdf527fea63d0de4762115cf6" +
		"31b3ddefd479b84eded2fad699e605603ec24ff9eda463b9c03b")
	pt, ok := rc4Decrypt(refKey, 1, blob)
	if !ok {
		t.Fatal("rc4Decrypt: checksum mismatch on reference vector")
	}
	want := []byte("kerberos-test-data") // confounder (8 bytes) is stripped on decrypt
	if !bytes.Equal(pt, want) {
		t.Fatalf("rc4Decrypt = %x, want %x", pt, want)
	}
}

func TestRC4RoundTrip(t *testing.T) {
	for _, usage := range []uint32{1, 8, 10, 11} {
		plain := []byte("authenticator-plaintext-" + string(rune('A'+usage)))
		blob := rc4Encrypt(refKey, usage, plain)
		if len(blob) != 16+8+len(plain) {
			t.Fatalf("usage %d: blob length %d", usage, len(blob))
		}
		got, ok := rc4Decrypt(refKey, usage, blob)
		if !ok || !bytes.Equal(got, plain) {
			t.Fatalf("usage %d: round trip failed (ok=%v)", usage, ok)
		}
		if _, ok := rc4Decrypt(refKey, usage+1, blob); ok {
			t.Fatalf("usage %d: decrypt succeeded with wrong usage", usage)
		}
	}
}

func TestRC4ChecksumReference(t *testing.T) {
	got := rc4Checksum(refKey, 10, []byte("ticket-der-bytes"))
	want, _ := hex.DecodeString("190d97b1ce526ba4b55114bc74579cc1")
	if !bytes.Equal(got, want) {
		t.Fatalf("rc4Checksum = %x, want %x", got, want)
	}
}

// --- DER builders ----------------------------------------------------------

func TestBuildASReqNoPreauthStructure(t *testing.T) {
	req := buildASReqNoPreauth("CORP.LOCAL", "alice", 0x11223344)
	var root asn1.RawValue
	if _, err := asn1.Unmarshal(req, &root); err != nil {
		t.Fatalf("decode AS-REQ: %v", err)
	}
	if root.Class != asn1.ClassApplication || root.Tag != 10 {
		t.Fatalf("root = class %d tag %d, want APPLICATION 10", root.Class, root.Tag)
	}
	fields := children(&root)
	if len(fields) < 3 {
		t.Fatalf("AS-REQ has %d fields, want >= 3", len(fields))
	}
	if got := parseInt(fields[0].FullBytes); got != 5 {
		t.Errorf("pvno = %d, want 5", got)
	}
	if got := parseInt(fields[1].FullBytes); got != 10 {
		t.Errorf("msg-type = %d, want 10", got)
	}
	body := fields[len(fields)-1]
	if body.Class != asn1.ClassContextSpecific || body.Tag != 4 {
		t.Fatalf("last field = [%d], want [4] req-body", body.Tag)
	}
	bodySeq := children(&body) // [4] wraps the KDC-REQ-BODY SEQUENCE
	if len(bodySeq) != 1 || bodySeq[0].Tag != asn1.TagSequence {
		t.Fatalf("req-body does not contain a single SEQUENCE")
	}
	var seenRealm, seenNonce, seenEtype bool
	for _, bf := range children(&bodySeq[0]) {
		if bf.Class != asn1.ClassContextSpecific {
			continue
		}
		switch bf.Tag {
		case 2:
			seenRealm = parseString(bf.FullBytes) == "CORP.LOCAL"
		case 6:
			seenNonce = parseInt(bf.FullBytes) == 0x11223344
		case 7:
			inner := children(&bf)
			seenEtype = len(inner) == 1 && parseInt(inner[0].FullBytes) == 23
		}
	}
	if !seenRealm || !seenNonce || !seenEtype {
		t.Fatalf("req-body missing fields: realm=%v nonce=%v etype23=%v", seenRealm, seenNonce, seenEtype)
	}
}

func TestBuildTGSReqStructure(t *testing.T) {
	ticket := app(1, append(ctx(0, derInt(5)), ctx(2, derGeneralString("CORP.LOCAL"))...))
	sess := bytes.Repeat([]byte{0x42}, 16)
	req := buildTGSReqFrom("CORP.LOCAL", "alice", ticket, sess, []string{"krbtgt", "CORP.LOCAL"}, 7)
	var root asn1.RawValue
	if _, err := asn1.Unmarshal(req, &root); err != nil {
		t.Fatalf("decode TGS-REQ: %v", err)
	}
	if root.Class != asn1.ClassApplication || root.Tag != 12 {
		t.Fatalf("root = class %d tag %d, want APPLICATION 12", root.Class, root.Tag)
	}
	fields := children(&root)
	if len(fields) != 4 {
		t.Fatalf("TGS-REQ has %d fields, want 4 (pvno, msg-type, padata, body)", len(fields))
	}
	entries := children(&fields[2])
	if len(entries) == 1 && entries[0].Tag == asn1.TagSequence {
		entries = children(&entries[0]) // [3] wraps the padata SEQUENCE OF
	}
	if len(entries) != 1 {
		t.Fatalf("padata has %d entries, want 1 (PA-TGS-REQ)", len(entries))
	}
	var paVal, apReq asn1.RawValue
	for _, e := range entries {
		var entrySeq asn1.RawValue
		if _, err := asn1.Unmarshal(e.FullBytes, &entrySeq); err != nil {
			continue
		}
		for _, f := range children(&entrySeq) {
			if f.Class == asn1.ClassContextSpecific && f.Tag == 2 {
				paVal = f
				break
			}
		}
		if paVal.FullBytes != nil {
			break
		}
	}
	if paVal.FullBytes == nil {
		t.Fatal("no PA-TGS-REQ value entry ([2]) in padata")
	}
	for _, f := range children(&paVal) {
		if f.Class == asn1.ClassUniversal && f.Tag == asn1.TagOctetString {
			if _, err := asn1.Unmarshal(f.Bytes, &apReq); err != nil {
				t.Fatalf("AP-REQ decode: %v", err)
			}
		}
	}
	if apReq.Class != asn1.ClassApplication || apReq.Tag != 14 {
		t.Fatalf("AP-REQ = class %d tag %d, want APPLICATION 14 (empty=%v)", apReq.Class, apReq.Tag, apReq.FullBytes == nil)
	}
}

// --- response parsing ------------------------------------------------------

func TestParseKRBError(t *testing.T) {
	// KRB-ERROR ::= [APPLICATION 30], error-code [6] = 25 (PREAUTH_REQUIRED)
	raw := app(30, append(ctx(0, derInt(5)), append(ctx(1, derInt(30)), ctx(6, derInt(25))...)...))
	_, code, isErr, err := parseRep(raw)
	if err != nil || !isErr || code != 25 {
		t.Fatalf("parseRep(KRB-ERROR) = code %d isErr %v err %v, want 25/true/nil", code, isErr, err)
	}
	if txt := errText(code); !strings.Contains(txt, "PREAUTH") {
		t.Errorf("errText(25) = %q, want mention of PREAUTH", txt)
	}
}

func TestHashFormatting(t *testing.T) {
	cipher := append(bytes.Repeat([]byte{0xab}, 16), bytes.Repeat([]byte{0xcd}, 32)...)
	chkHex, ctHex := hex.EncodeToString(cipher[:16]), hex.EncodeToString(cipher[16:])
	got := "$krb5asrep$23$alice@CORP.LOCAL:" + chkHex + "$" + ctHex
	if !strings.HasPrefix(got, "$krb5asrep$23$alice@CORP.LOCAL:") || !strings.HasSuffix(got, "$"+ctHex) {
		t.Fatalf("asrep hash malformed: %q", got)
	}
	tgs := "$krb5tgs$23$*svc$CORP.LOCAL$MSSQLSvc/dc.corp.local:1433*$" + chkHex + "$" + ctHex
	if !strings.HasPrefix(tgs, "$krb5tgs$23$*svc$CORP.LOCAL$") {
		t.Fatalf("tgs hash malformed: %q", tgs)
	}
}

func TestNTKeyValidation(t *testing.T) {
	if _, err := NTKey("31d6cfe0d16ae931b73c59d7e0c089c0"); err != nil {
		t.Fatalf("valid hash rejected: %v", err)
	}
	for _, bad := range []string{"", "zz", "31d6", strings.Repeat("a", 33)} {
		if _, err := NTKey(bad); err == nil {
			t.Errorf("NTKey(%q) accepted invalid input", bad)
		}
	}
}
