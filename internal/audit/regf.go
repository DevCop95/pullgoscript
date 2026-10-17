package audit

// Offline parser for the Windows registry hive (regf) on-disk format.
//
// lsadump::sam needs to read two hives — SYSTEM (boot key material in the
// class names of the LSA keys) and SAM (account hashes). Both can be exported
// with `reg save` from an elevated token; this parser then walks the saved
// files without touching the live registry API, so no SYSTEM impersonation
// and no COM are involved. Only the small subset of the format the dump
// needs is implemented: key nodes (nk), subkey lists (lf/lh/li/ri), value
// lists (vk) and key class names. Every offset is bounds-checked — the
// parser must not panic on a truncated or hostile file.

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
	"unicode/utf16"
)

const (
	regfHeaderSize  = 0x1000 // hive bins start right after the 4 KiB header
	nkMinSize       = 0x4C   // fixed part of a key node incl. name/class lens
	vkMinSize       = 0x14   // fixed part of a value key before the name
	nkFlagASCIIName = 0x20   // key name stored as compressed ASCII, not UTF-16
	maxSubkeyDepth  = 8      // "ri" index recursion guard
)

// regfHive is an in-memory registry hive file.
type regfHive struct {
	data []byte
}

// loadHive reads a saved hive file and validates the regf header.
func loadHive(data []byte) (*regfHive, error) {
	if len(data) < regfHeaderSize {
		return nil, fmt.Errorf("regf: file too small (%d bytes)", len(data))
	}
	if string(data[0:4]) != "regf" {
		return nil, fmt.Errorf("regf: bad signature %q", data[0:4])
	}
	return &regfHive{data: data}, nil
}

// cell returns the payload of the cell at the given hive-relative offset.
// Offsets in the file are relative to the start of the hive bins (0x1000).
// The leading 4-byte signed size marks the cell allocated (negative) or
// free (positive); its absolute value includes the size field itself.
func (h *regfHive) cell(off uint32) ([]byte, error) {
	p := int(off) + regfHeaderSize
	if p < regfHeaderSize || p+4 > len(h.data) {
		return nil, fmt.Errorf("regf: cell offset 0x%x out of range", off)
	}
	size := int32(binary.LittleEndian.Uint32(h.data[p:])) //#nosec G115 -- cell size is a signed 32-bit field per the regf on-disk format
	if size < 0 {
		size = -size
	}
	if size < 4 || p+int(size) > len(h.data) {
		return nil, fmt.Errorf("regf: cell at 0x%x has invalid size %d", off, size)
	}
	return h.data[p+4 : p+int(size)], nil
}

// nk is a parsed key node.
type nk struct {
	hive       *regfHive
	name       string
	classOff   uint32
	classLen   uint16
	subkeyList uint32
	numSubkeys uint32
	valueList  uint32
	numValues  uint32
}

// parseNK decodes a key node cell at the given hive offset.
func (h *regfHive) parseNK(off uint32) (*nk, error) {
	c, err := h.cell(off)
	if err != nil {
		return nil, err
	}
	if len(c) < nkMinSize || string(c[0:2]) != "nk" {
		return nil, fmt.Errorf("regf: no nk cell at 0x%x", off)
	}
	flags := binary.LittleEndian.Uint16(c[2:4])
	nameLen := int(binary.LittleEndian.Uint16(c[0x48:0x4A]))
	classLen := binary.LittleEndian.Uint16(c[0x4A:0x4C])
	if nkMinSize+nameLen > len(c) {
		return nil, fmt.Errorf("regf: nk name at 0x%x overruns cell", off)
	}
	var name string
	raw := c[nkMinSize : nkMinSize+nameLen]
	name = decodeName(raw, flags&nkFlagASCIIName != 0)
	return &nk{
		hive:       h,
		name:       name,
		classOff:   binary.LittleEndian.Uint32(c[0x30:0x34]),
		classLen:   classLen,
		subkeyList: binary.LittleEndian.Uint32(c[0x1C:0x20]),
		numSubkeys: binary.LittleEndian.Uint32(c[0x14:0x18]),
		valueList:  binary.LittleEndian.Uint32(c[0x28:0x2C]),
		numValues:  binary.LittleEndian.Uint32(c[0x24:0x28]),
	}, nil
}

// root returns the hive's root key node.
func (h *regfHive) root() (*nk, error) {
	if len(h.data) < 0x28 {
		return nil, fmt.Errorf("regf: header truncated")
	}
	off := binary.LittleEndian.Uint32(h.data[0x24:0x28])
	return h.parseNK(off)
}

// className returns the key's class name (UTF-16 in the hive, null-trimmed).
// The boot key components (JD/Skew1/GBG/Data) are stored this way.
func (n *nk) className() (string, error) {
	if n.classLen == 0 {
		return "", nil
	}
	c, err := n.hive.cell(n.classOff)
	if err != nil {
		return "", err
	}
	if int(n.classLen) > len(c) {
		return "", fmt.Errorf("regf: class name overruns cell")
	}
	raw := c[:n.classLen]
	s := strings.TrimRight(decodeUTF16LE(raw), "\x00")
	// classLen may be counted in characters on some hives — retry at double
	// width when the first decode produced nothing usable.
	if !printableASCII(s) && int(n.classLen)*2 <= len(c) {
		if s2 := strings.TrimRight(decodeUTF16LE(c[:int(n.classLen)*2]), "\x00"); printableASCII(s2) {
			s = s2
		}
	}
	if !printableASCII(s) {
		s = strings.TrimRight(string(raw), "\x00")
	}
	return s, nil
}

// subkey returns the child key with the given name (case-insensitive).
func (n *nk) subkey(name string) (*nk, error) {
	offs, err := n.subkeyOffsets()
	if err != nil {
		return nil, err
	}
	for _, off := range offs {
		child, err := n.hive.parseNK(off)
		if err != nil {
			continue
		}
		if strings.EqualFold(child.name, name) {
			return child, nil
		}
	}
	return nil, fmt.Errorf("regf: subkey %q not found under %q", name, n.name)
}

// subkeys returns all child keys.
func (n *nk) subkeys() ([]*nk, error) {
	offs, err := n.subkeyOffsets()
	if err != nil {
		return nil, err
	}
	out := make([]*nk, 0, len(offs))
	for _, off := range offs {
		if child, err := n.hive.parseNK(off); err == nil {
			out = append(out, child)
		}
	}
	return out, nil
}

// subkeyOffsets resolves the subkey list (lf/lh/li, possibly indexed by ri)
// into raw key-node offsets.
func (n *nk) subkeyOffsets() ([]uint32, error) {
	if n.numSubkeys == 0 || n.subkeyList == 0xFFFFFFFF {
		return nil, nil
	}
	return n.hive.listOffsets(n.subkeyList, maxSubkeyDepth)
}

// listOffsets walks a subkey list cell, expanding "ri" index lists.
func (h *regfHive) listOffsets(off uint32, depth int) ([]uint32, error) {
	if depth <= 0 {
		return nil, fmt.Errorf("regf: subkey index nesting too deep")
	}
	c, err := h.cell(off)
	if err != nil {
		return nil, err
	}
	if len(c) < 4 {
		return nil, fmt.Errorf("regf: subkey list at 0x%x truncated", off)
	}
	sig := string(c[0:2])
	count := int(binary.LittleEndian.Uint16(c[2:4]))
	var offs []uint32
	switch sig {
	case "lf", "lh":
		// Both are 4-byte key-node offset + 4-byte name material (a hint for
		// lf, a hash for lh) per entry. Verified against a real SYSTEM hive:
		// every resolved offset must land on an nk cell.
		if len(c) < 4+count*8 {
			return nil, fmt.Errorf("regf: %s list at 0x%x truncated", sig, off)
		}
		for i := 0; i < count; i++ {
			offs = append(offs, binary.LittleEndian.Uint32(c[4+i*8:]))
		}
	case "li":
		if len(c) < 4+count*4 {
			return nil, fmt.Errorf("regf: li list at 0x%x truncated", off)
		}
		for i := 0; i < count; i++ {
			offs = append(offs, binary.LittleEndian.Uint32(c[4+i*4:]))
		}
	case "ri":
		if len(c) < 4+count*4 {
			return nil, fmt.Errorf("regf: ri list at 0x%x truncated", off)
		}
		for i := 0; i < count; i++ {
			sub, err := h.listOffsets(binary.LittleEndian.Uint32(c[4+i*4:]), depth-1)
			if err != nil {
				return nil, err
			}
			offs = append(offs, sub...)
		}
	default:
		return nil, fmt.Errorf("regf: unknown subkey list signature %q", sig)
	}
	return offs, nil
}

// value returns the data and type of the named value ("" = default value).
// The value count lives in the key node; a value-list cell is then just the
// 4-byte offsets back to back (verified against a real SYSTEM hive — the
// count-prefixed flavour seen on older hives is also accepted).
func (n *nk) value(name string) ([]byte, uint32, error) {
	if n.numValues == 0 || n.valueList == 0xFFFFFFFF {
		return nil, 0, fmt.Errorf("regf: key %q has no values", n.name)
	}
	list, err := n.hive.cell(n.valueList)
	if err != nil {
		return nil, 0, err
	}
	count := int(n.numValues)
	var offs []uint32
	if len(list) >= 4 && binary.LittleEndian.Uint32(list[0:4]) == uint32(count) { //#nosec G115 -- count is the key node's numValues, a uint32 field; conversion is exact
		// count-prefixed variant
		if 4+count*4 > len(list) {
			return nil, 0, fmt.Errorf("regf: value list of %q truncated", n.name)
		}
		list = list[4:]
	} else if count*4 > len(list) {
		return nil, 0, fmt.Errorf("regf: value list of %q truncated", n.name)
	}
	offs = make([]uint32, count)
	for i := 0; i < count; i++ {
		offs[i] = binary.LittleEndian.Uint32(list[i*4:])
	}
	for _, off := range offs {
		data, typ, vkName, err := n.hive.parseVK(off)
		if err != nil {
			continue
		}
		if strings.EqualFold(vkName, name) {
			return data, typ, nil
		}
	}
	return nil, 0, fmt.Errorf("regf: value %q not found in %q", name, n.name)
}

// parseVK decodes a value key cell: name, type and (resident or pointed-to)
// data.
func (h *regfHive) parseVK(off uint32) (data []byte, typ uint32, name string, err error) {
	c, err := h.cell(off)
	if err != nil {
		return nil, 0, "", err
	}
	if len(c) < vkMinSize || string(c[0:2]) != "vk" {
		return nil, 0, "", fmt.Errorf("regf: no vk cell at 0x%x", off)
	}
	nameLen := int(binary.LittleEndian.Uint16(c[2:4]))
	dataLen := binary.LittleEndian.Uint32(c[4:8])
	dataOff := binary.LittleEndian.Uint32(c[8:12])
	typ = binary.LittleEndian.Uint32(c[12:16])
	flags := binary.LittleEndian.Uint16(c[16:18])
	if vkMinSize+nameLen > len(c) {
		return nil, 0, "", fmt.Errorf("regf: vk name at 0x%x overruns cell", off)
	}
	name = decodeName(c[vkMinSize:vkMinSize+nameLen], flags&1 != 0)
	// High bit set → the value is resident in the offset field itself.
	if dataLen&0x80000000 != 0 {
		inline := dataLen & 0x7FFFFFFF
		if inline > 4 {
			return nil, 0, "", fmt.Errorf("regf: resident value at 0x%x too large", off)
		}
		return c[8 : 8+inline], typ, name, nil
	}
	if dataLen == 0 {
		return nil, typ, name, nil
	}
	dc, err := h.cell(dataOff)
	if err != nil {
		return nil, 0, "", err
	}
	if int(dataLen) > len(dc) {
		return nil, 0, "", fmt.Errorf("regf: value data at 0x%x overruns cell", dataOff)
	}
	return dc[:dataLen], typ, name, nil
}

// openKey walks a backslash-separated path from the root key.
func (h *regfHive) openKey(path string) (*nk, error) {
	cur, err := h.root()
	if err != nil {
		return nil, err
	}
	for _, part := range strings.Split(path, `\`) {
		if part == "" {
			continue
		}
		cur, err = cur.subkey(part)
		if err != nil {
			return nil, fmt.Errorf("regf: %s: %w", path, err)
		}
	}
	return cur, nil
}

// decodeUTF16LE decodes UTF-16LE bytes, replacing invalid sequences.
func decodeUTF16LE(b []byte) string {
	if len(b)%2 != 0 {
		b = b[:len(b)-1]
	}
	u := make([]uint16, len(b)/2)
	for i := range u {
		u[i] = binary.LittleEndian.Uint16(b[i*2:])
	}
	return string(utf16.Decode(u))
}

// printableASCII reports whether s is a non-empty run of printable ASCII —
// the shape every name we care about (key paths, value names, hex classes)
// has in practice.
func printableASCII(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < 0x20 || r > 0x7E {
			return false
		}
	}
	return true
}

// decodeName picks between the ASCII and UTF-16 interpretations of a raw
// name, preferring whatever the flag says but falling back when the flag and
// the bytes disagree (hives in the wild contain both encodings under
// either flag).
func decodeName(raw []byte, asciiFlag bool) string {
	a, u := string(raw), decodeUTF16LE(raw)
	aOK, uOK := printableASCII(a), printableASCII(u)
	if asciiFlag {
		if aOK {
			return a
		}
		if uOK {
			return u
		}
		return a
	}
	if uOK {
		return u
	}
	if aOK {
		return a
	}
	return u
}

// hexClass decodes an LSA class name (an 8-char hex string) into 4 bytes.
func hexClass(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if len(s) != 8 {
		return nil, fmt.Errorf("regf: LSA class %q is not 8 hex chars", s)
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("regf: LSA class %q: %w", s, err)
	}
	return b, nil
}
