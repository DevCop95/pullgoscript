package krb

import (
	"encoding/asn1"
	"testing"
)

func TestDomainToBaseDN(t *testing.T) {
	if got := domainToBaseDN("CORP.EXAMPLE.COM"); got != "DC=corp,DC=example,DC=com" {
		t.Fatalf("baseDN = %q", got)
	}
}

func TestLDAPBindStructure(t *testing.T) {
	req := ldapBind(1, "cn=roast,dc=corp,dc=local", "s3cret")
	var root asn1.RawValue
	if _, err := asn1.Unmarshal(req, &root); err != nil {
		t.Fatalf("decode bind: %v", err)
	}
	if root.Tag != asn1.TagSequence {
		t.Fatalf("root tag = %d, want SEQUENCE", root.Tag)
	}
	fields := children(&root)
	if len(fields) != 2 {
		t.Fatalf("LDAPMessage has %d fields, want 2", len(fields))
	}
	if parseInt(fields[0].FullBytes) != 1 {
		t.Errorf("messageID = %d, want 1", parseInt(fields[0].FullBytes))
	}
	var op asn1.RawValue
	if _, err := asn1.Unmarshal(fields[1].FullBytes, &op); err != nil {
		t.Fatalf("op decode: %v", err)
	}
	if op.Class != asn1.ClassApplication || op.Tag != 0 {
		t.Fatalf("op = class %d tag %d, want APPLICATION 0 (bind)", op.Class, op.Tag)
	}
	kids := children(&op)
	if len(kids) != 3 || parseInt(kids[0].FullBytes) != 3 {
		t.Fatalf("bind body malformed")
	}
}

func TestLDAPSearchStructure(t *testing.T) {
	req := ldapSearch(2, "dc=corp,dc=local")
	var root asn1.RawValue
	if _, err := asn1.Unmarshal(req, &root); err != nil {
		t.Fatalf("decode search: %v", err)
	}
	fields := children(&root)
	if len(fields) != 2 {
		t.Fatalf("LDAPMessage has %d fields, want 2", len(fields))
	}
	var op asn1.RawValue
	if _, err := asn1.Unmarshal(fields[1].FullBytes, &op); err != nil {
		t.Fatalf("op decode: %v", err)
	}
	if op.Class != asn1.ClassApplication || op.Tag != 3 {
		t.Fatalf("op = class %d tag %d, want APPLICATION 3 (search)", op.Class, op.Tag)
	}
	kids := children(&op)
	if len(kids) != 8 {
		t.Fatalf("search req has %d fields, want 8 (RFC 4511 4.5.1)", len(kids))
	}
	if parseLDAPString(kids[0].FullBytes) != "dc=corp,dc=local" {
		t.Errorf("baseObject = %q", parseLDAPString(kids[0].FullBytes))
	}
}

func TestBindOKSynthetic(t *testing.T) {
	// BindResponse ::= [APPLICATION 1] SEQUENCE { resultCode [0] ENUM }
	var okBuf, badBuf reqBuf
	okBuf.add(der(0x80, []byte{0}))
	okBuf.add(derOctet(nil))
	okBuf.add(der(0x80, nil))
	badBuf.add(der(0x80, []byte{49}))
	badBuf.add(derOctet(nil))
	badBuf.add(der(0x80, nil))
	if !bindOK(der(0x61, okBuf.buf)) {
		t.Error("bindOK rejected a synthetic success response")
	}
	if bindOK(der(0x61, badBuf.buf)) {
		t.Error("bindOK accepted resultCode 49")
	}
}

func TestSearchDoneSynthetic(t *testing.T) {
	var doneBuf reqBuf
	doneBuf.add(der(0x80, []byte{0}))
	doneBuf.add(derOctet(nil))
	doneBuf.add(der(0x80, nil))
	done := der(0x65, doneBuf.buf)
	entry := der(0x64, append(derOctet([]byte("dc=x")), ctx(3, derSeq())...))
	stream := append(entry, done...)
	if !searchDone(stream) {
		t.Error("searchDone missed the trailing APPLICATION 5")
	}
	if searchDone(entry) {
		t.Error("searchDone claimed done without terminator")
	}
}

func TestEtypeAllowed(t *testing.T) {
	for _, c := range []struct {
		in   string
		want bool
	}{
		{"", true},        // attribute absent → default allows RC4
		{"4", true},       // RC4-only
		{"31", true},      // everything incl. RC4
		{"24", false},     // AES-only (bit 0x4 off)
		{"garbage", true}, // unparseable → try anyway
	} {
		if got := etypeAllowed(c.in); got != c.want {
			t.Errorf("etypeAllowed(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}
