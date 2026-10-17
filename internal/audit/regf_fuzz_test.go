package audit

// Fuzz target for the regf hive parser.
//
// regf.go consumes files produced by `reg save` — and, on a hostile host, a
// file an attacker can influence. The run that parses it holds an elevated
// token, so a panic here is not a test failure: it is a crash in the middle of
// a credential-extraction operation. Every offset the parser trusts is
// bounds-checked; this target exists to prove that under mutation and to keep
// it true through refactors.
//
// The seeds include a structurally valid hive (a root nk, plus a variant with
// an lf subkey list) so the fuzzer starts past the header check and into the
// key/subkey walk instead of bouncing off the signature every time.

import (
	"encoding/binary"
	"testing"
)

// putCell writes one hive cell at a hive-relative offset: a negative 4-byte
// size header (the "allocated" marker) followed by a body that starts with the
// two-byte cell signature. fill may set further fields on the body.
func putCell(buf []byte, off, bodyLen int, sig string, fill func([]byte)) {
	p := regfHeaderSize + off
	binary.LittleEndian.PutUint32(buf[p:p+4], uint32(int32(-(bodyLen + 4))))
	body := buf[p+4 : p+4+bodyLen]
	copy(body[0:2], sig)
	if fill != nil {
		fill(body)
	}
}

// buildHive assembles the smallest hive loadHive accepts with a root nk, and
// (when withChild) an "lf" subkey list pointing at one child nk. Offsets match
// the fields parseNK reads.
func buildHive(withChild bool) []byte {
	buf := make([]byte, regfHeaderSize+0x200)
	copy(buf[0:4], "regf")
	binary.LittleEndian.PutUint32(buf[0x24:0x28], 0) // root nk at cell 0

	putCell(buf, 0x00, nkMinSize, "nk", func(c []byte) {
		if withChild {
			binary.LittleEndian.PutUint32(c[0x14:0x18], 1)    // numSubkeys
			binary.LittleEndian.PutUint32(c[0x1C:0x20], 0x50) // subkey list at cell 0x50
		}
		binary.LittleEndian.PutUint32(c[0x24:0x28], 0)          // numValues
		binary.LittleEndian.PutUint32(c[0x28:0x2C], 0xFFFFFFFF) // no value list
	})
	if !withChild {
		return buf
	}
	// cell 0x50: "lf" list, count 1, entry -> cell 0x60.
	putCell(buf, 0x50, 12, "lf", func(c []byte) {
		binary.LittleEndian.PutUint16(c[2:4], 1)
		binary.LittleEndian.PutUint32(c[4:8], 0x60)
	})
	// cell 0x60: the child nk.
	putCell(buf, 0x60, nkMinSize, "nk", nil)
	return buf
}

// walkHive recurses over parsed subkeys with a hard depth cap: the parser
// already guards ri nesting, but a crafted self-referential hive must not turn
// the fuzzer into an unbounded loop either.
func walkHive(n *nk, depth int) {
	if depth > 6 {
		return
	}
	_, _ = n.className()
	_, _, _ = n.value("")
	subs, err := n.subkeys()
	if err != nil {
		return
	}
	for _, s := range subs {
		walkHive(s, depth+1)
	}
}

func FuzzRegf(f *testing.F) {
	f.Add(buildHive(false))
	f.Add(buildHive(true))
	f.Add([]byte("regf"))
	f.Add([]byte{})
	f.Add(make([]byte, regfHeaderSize))

	f.Fuzz(func(t *testing.T, data []byte) {
		h, err := loadHive(data)
		if err != nil {
			return
		}
		root, err := h.root()
		if err != nil {
			return
		}
		walkHive(root, 0)
		// Exercise the separate targeted-lookup paths too.
		_, _ = h.openKey("SAM")
		_, _ = root.subkey("ControlSet001")
	})
}
