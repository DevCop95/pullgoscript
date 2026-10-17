package audit

// Parser tests for the regf hive reader. regf.go is platform-neutral, so these
// run on every runner — the fuzz target (regf_fuzz_test.go) hunts for panics
// under mutation; these pin the actual semantics on a hand-built hive: cell
// offsets, the resident-value encoding, subkey-list resolution, key class
// names and the LSA class hex decode.
//
// The synthetic hives are built with putCell/putRawCell rather than checked in
// as binary fixtures, so the byte layout each test depends on is visible in
// the test itself.

import (
	"encoding/binary"
	"testing"
)

// putRawCell writes a hive cell with a negative size header and no signature
// (value lists and data cells have none).
func putRawCell(buf []byte, off, bodyLen int, fill func([]byte)) {
	p := regfHeaderSize + off
	binary.LittleEndian.PutUint32(buf[p:p+4], uint32(int32(-(bodyLen + 4))))
	body := buf[p+4 : p+4+bodyLen]
	if fill != nil {
		fill(body)
	}
}

// emptyHive returns a header-sized buffer with the regf signature and root
// pointer already written; tests then lay out cells with putCell/putRawCell.
func emptyHive() []byte {
	buf := make([]byte, regfHeaderSize+0x400)
	copy(buf[0:4], "regf")
	binary.LittleEndian.PutUint32(buf[0x24:0x28], 0) // root nk at cell 0
	return buf
}

func TestLoadHiveRejectsMalformedInput(t *testing.T) {
	cases := map[string][]byte{
		"nil":       nil,
		"empty":     {},
		"short":     []byte("regf"),
		"no magic":  make([]byte, regfHeaderSize),
		"bad magic": append([]byte("REGX"), make([]byte, regfHeaderSize)...),
	}
	for name, in := range cases {
		if _, err := loadHive(in); err == nil {
			t.Errorf("%s: loadHive accepted a malformed hive", name)
		}
	}
}

func TestLoadHiveAcceptsBareHeader(t *testing.T) {
	// A well-formed signature and length is all loadHive itself checks; the
	// cell layout is validated lazily by root().
	if _, err := loadHive(emptyHive()); err != nil {
		t.Fatalf("loadHive(valid header) = %v, want nil", err)
	}
}

func TestRootParsesKeyNode(t *testing.T) {
	buf := emptyHive()
	putCell(buf, 0x00, nkMinSize, "nk", func(c []byte) {
		binary.LittleEndian.PutUint32(c[0x14:0x18], 2)          // numSubkeys
		binary.LittleEndian.PutUint32(c[0x24:0x28], 3)          // numValues
		binary.LittleEndian.PutUint32(c[0x28:0x2C], 0xFFFFFFFF) // no value list
	})

	h, err := loadHive(buf)
	if err != nil {
		t.Fatalf("loadHive: %v", err)
	}
	root, err := h.root()
	if err != nil {
		t.Fatalf("root: %v", err)
	}
	if root.numSubkeys != 2 || root.numValues != 3 {
		t.Errorf("root = %d subkeys / %d values, want 2/3", root.numSubkeys, root.numValues)
	}
	// subkeyOffsets short-circuits to (nil, nil) when subkeyList is
	// 0xFFFFFFFF or numSubkeys is 0; here numSubkeys is non-zero but the list
	// offset is 0, which must produce an error rather than a panic.
	if _, err := root.subkeys(); err == nil {
		t.Error("subkeys() with a bogus list offset: want error, got nil")
	}
}

func TestRootRejectsNonKeyCell(t *testing.T) {
	buf := emptyHive()
	putCell(buf, 0x00, nkMinSize, "vk", nil) // wrong signature
	h, _ := loadHive(buf)
	if _, err := h.root(); err == nil {
		t.Error("root() on a vk cell: want error, got nil")
	}
}

func TestRootRejectsOutOfRangeOffset(t *testing.T) {
	buf := emptyHive()
	binary.LittleEndian.PutUint32(buf[0x24:0x28], 0xFFFFFF00) // past the end
	h, _ := loadHive(buf)
	if _, err := h.root(); err == nil {
		t.Error("root() with an out-of-range offset: want error, got nil")
	}
}

// TestValueResidentAndMissing covers the value list -> vk chain, including the
// resident encoding where the data lives inside the offset field.
func TestValueResidentAndMissing(t *testing.T) {
	buf := emptyHive()
	putCell(buf, 0x00, nkMinSize, "nk", func(c []byte) {
		binary.LittleEndian.PutUint32(c[0x24:0x28], 1)    // numValues
		binary.LittleEndian.PutUint32(c[0x28:0x2C], 0x50) // value list at cell 0x50
	})
	putRawCell(buf, 0x50, 4, func(c []byte) {
		binary.LittleEndian.PutUint32(c[0:4], 0x60) // one vk at cell 0x60
	})
	putCell(buf, 0x60, vkMinSize+4, "vk", func(c []byte) {
		binary.LittleEndian.PutUint16(c[0x02:0x04], 4)          // nameLen
		binary.LittleEndian.PutUint32(c[0x04:0x08], 0x80000003) // resident, 3 bytes
		copy(c[0x08:0x0B], "abc")                               // resident data
		binary.LittleEndian.PutUint32(c[0x0C:0x10], 1)          // REG_SZ
		copy(c[vkMinSize:vkMinSize+4], "Test")
	})

	h, err := loadHive(buf)
	if err != nil {
		t.Fatalf("loadHive: %v", err)
	}
	root, err := h.root()
	if err != nil {
		t.Fatalf("root: %v", err)
	}
	data, typ, err := root.value("Test")
	if err != nil {
		t.Fatalf("value(Test): %v", err)
	}
	if string(data) != "abc" || typ != 1 {
		t.Errorf("value(Test) = %q/%d, want \"abc\"/1", data, typ)
	}
	// Value names are case-insensitive, as in the live registry.
	if _, _, err := root.value("tEsT"); err != nil {
		t.Errorf("value lookup should be case-insensitive: %v", err)
	}
	if _, _, err := root.value("Missing"); err == nil {
		t.Error("value(Missing): want error, got nil")
	}
}

func TestSubkeyListAndPathWalk(t *testing.T) {
	buf := emptyHive()
	putCell(buf, 0x00, nkMinSize, "nk", func(c []byte) {
		binary.LittleEndian.PutUint32(c[0x14:0x18], 1)          // numSubkeys
		binary.LittleEndian.PutUint32(c[0x1C:0x20], 0x50)       // subkey list
		binary.LittleEndian.PutUint32(c[0x28:0x2C], 0xFFFFFFFF) // no values
	})
	putCell(buf, 0x50, 12, "lf", func(c []byte) {
		binary.LittleEndian.PutUint16(c[2:4], 1)
		binary.LittleEndian.PutUint32(c[4:8], 0x60)
	})
	// Child key named "SAM" (ASCII-compressed: nk flag bit 0x20).
	putCell(buf, 0x60, nkMinSize+3, "nk", func(c []byte) {
		binary.LittleEndian.PutUint16(c[0x02:0x04], nkFlagASCIIName)
		binary.LittleEndian.PutUint16(c[0x48:0x4A], 3) // nameLen
		copy(c[nkMinSize:nkMinSize+3], "SAM")
	})

	h, err := loadHive(buf)
	if err != nil {
		t.Fatalf("loadHive: %v", err)
	}
	root, err := h.root()
	if err != nil {
		t.Fatalf("root: %v", err)
	}
	subs, err := root.subkeys()
	if err != nil {
		t.Fatalf("subkeys: %v", err)
	}
	if len(subs) != 1 || subs[0].name != "SAM" {
		t.Fatalf("subkeys = %d entries (%q), want 1 (\"SAM\")", len(subs), names(subs))
	}
	child, err := root.subkey("sam") // case-insensitive
	if err != nil {
		t.Fatalf("subkey(sam): %v", err)
	}
	if child.name != "SAM" {
		t.Errorf("subkey(sam).name = %q, want SAM", child.name)
	}
	if _, err := root.subkey("nope"); err == nil {
		t.Error("subkey(nope): want error, got nil")
	}
	if got, err := h.openKey("SAM"); err != nil || got.name != "SAM" {
		t.Errorf("openKey(SAM) = %v/%q, want nil/SAM", err, got.name)
	}
	if _, err := h.openKey("SAM\\Deeper"); err == nil {
		t.Error("openKey(SAM\\Deeper): want error, got nil")
	}
}

// TestClassNameHexRoundTrip mirrors how the boot key components are read: an
// nk pointing at a class cell holding an 8-char hex string.
func TestClassNameHexRoundTrip(t *testing.T) {
	buf := emptyHive()
	putCell(buf, 0x00, nkMinSize, "nk", func(c []byte) {
		binary.LittleEndian.PutUint32(c[0x30:0x34], 0x50) // classOff
		binary.LittleEndian.PutUint16(c[0x4A:0x4C], 8)    // classLen
		binary.LittleEndian.PutUint32(c[0x28:0x2C], 0xFFFFFFFF)
	})
	putRawCell(buf, 0x50, 8, func(c []byte) { copy(c, "a1b2c3d4") })

	h, err := loadHive(buf)
	if err != nil {
		t.Fatalf("loadHive: %v", err)
	}
	root, err := h.root()
	if err != nil {
		t.Fatalf("root: %v", err)
	}
	class, err := root.className()
	if err != nil {
		t.Fatalf("className: %v", err)
	}
	if class != "a1b2c3d4" {
		t.Fatalf("className = %q, want a1b2c3d4", class)
	}
	got, err := hexClass(class)
	if err != nil {
		t.Fatalf("hexClass(%q): %v", class, err)
	}
	want := []byte{0xa1, 0xb2, 0xc3, 0xd4}
	if len(got) != 4 || got[0] != want[0] || got[3] != want[3] {
		t.Errorf("hexClass = %x, want %x", got, want)
	}
}

func TestClassNameEmptyWhenAbsent(t *testing.T) {
	buf := emptyHive()
	putCell(buf, 0x00, nkMinSize, "nk", nil)
	h, _ := loadHive(buf)
	root, err := h.root()
	if err != nil {
		t.Fatalf("root: %v", err)
	}
	if got, err := root.className(); err != nil || got != "" {
		t.Errorf("className with no class = %q/%v, want \"\"/nil", got, err)
	}
}

func TestHexClassValidation(t *testing.T) {
	bad := []string{"", "abc", "abcdefghi", "zzzzzzzz", "a1b2c3d"}
	for _, s := range bad {
		if _, err := hexClass(s); err == nil {
			t.Errorf("hexClass(%q) = nil error, want rejection", s)
		}
	}
	got, err := hexClass("  A1B2C3D4  ") // trimmed, upper case accepted
	if err != nil {
		t.Fatalf("hexClass(hex with padding): %v", err)
	}
	if len(got) != 4 || got[0] != 0xa1 {
		t.Errorf("hexClass = %x, want a1b2c3d4", got)
	}
}

func names(ns []*nk) string {
	out := ""
	for i, n := range ns {
		if i > 0 {
			out += ","
		}
		out += n.name
	}
	return out
}
