//go:build windows

package audit

// Reference vectors for the lsadump::sam crypto chain, generated with the
// independent impacket 0.13.1 implementation (impacket.crypto.transformKey,
// Cryptodome ARC4/AES/DES) on this machine. They pin the exact byte layout
// of [MS-SAMR] 2.2.11 so a refactor cannot silently break hash extraction.

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func hx(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

func TestDeriveDESKeys(t *testing.T) {
	cases := []struct {
		rid    uint32
		k1, k2 string
	}{
		{500, "f40040000ea00400", "007a00200006d002"},
		{1001, "e880c0000e480c00", "007440600006a406"},
	}
	for _, c := range cases {
		k1, k2 := deriveDESKeys(c.rid)
		if !bytes.Equal(k1, hx(t, c.k1)) || !bytes.Equal(k2, hx(t, c.k2)) {
			t.Errorf("deriveDESKeys(%d) = %x/%x, want %s/%s", c.rid, k1, k2, c.k1, c.k2)
		}
	}
}

func TestRCK4Vector(t *testing.T) {
	got := rc4Crypt([]byte("0123456789abcdef"), []byte("The quick brown fox"))
	want := hx(t, "d00025798c3bc9fb62d638ecafe43d65848250")
	if !bytes.Equal(got, want) {
		t.Errorf("rc4Crypt = %x, want %x", got, want)
	}
	// RC4 is symmetric: applying it twice restores the input.
	if rt := rc4Crypt([]byte("0123456789abcdef"), got); !bytes.Equal(rt, []byte("The quick brown fox")) {
		t.Errorf("rc4 round trip = %x", rt)
	}
}

func TestHashedBootKeyRC4(t *testing.T) {
	bootKey := hx(t, "000102030405060708090a0b0c0d0e0f")
	salt := hx(t, "101112131415161718191a1b1c1d1e1f")
	stored := hx(t, "e8880b6b2bdc7c2392fc273792ac5aa56bff5ddfabdad92c408d6447f1bb1ddb")
	want := hx(t, "202122232425262728292a2b2c2d2e2fe308304cb7d3063a4a2f8652d3bc6b6b")

	hbk, err := hashedBootKeyRC4(bootKey, salt, stored)
	if err != nil {
		t.Fatalf("hashedBootKeyRC4: %v", err)
	}
	if !bytes.Equal(hbk, want) {
		t.Errorf("hashedBootKeyRC4 = %x, want %x", hbk, want)
	}

	// Corrupting the checksum field must be detected, not silently accepted.
	bad := append([]byte(nil), stored...)
	bad[31] ^= 0xFF
	if _, err := hashedBootKeyRC4(bootKey, salt, bad); err == nil {
		t.Error("hashedBootKeyRC4 accepted a bad checksum")
	}
}

func TestHashedBootKeyAES(t *testing.T) {
	bootKey := hx(t, "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf")
	salt := hx(t, "b0b1b2b3b4b5b6b7b8b9babbbcbdbebf")
	data := hx(t, "c7ffa87770fcdcecd2ec2b35d67699f55ac74546bbd2987b5ad5bd6faa022c95")
	want := hx(t, "c0c1c2c3c4c5c6c7c8c9cacbcccdcecfc0c1c2c3c4c5c6c7c8c9cacbcccdcecf")

	if got := hashedBootKeyAES(bootKey, data, salt); !bytes.Equal(got, want) {
		t.Errorf("hashedBootKeyAES = %x, want %x", got, want)
	}
}

func TestDecryptHashOldStyle(t *testing.T) {
	hbk := hx(t, "202122232425262728292a2b2c2d2e2fe308304cb7d3063a4a2f8652d3bc6b6b")
	blob := hx(t, "0100010043d5d2d9822dccff8f3c4613f465c0e7")
	want := hx(t, "29f1ab2d35aa039513df3d9239782708")

	got, err := decryptHash(hbk, 500, blob, false, ntConst)
	if err != nil {
		t.Fatalf("decryptHash(old): %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("decryptHash(old) = %x, want %x", got, want)
	}
	if blob[2] != 1 {
		t.Errorf("old-style revision byte changed: %x", blob[2])
	}
}

func TestDecryptHashNewStyle(t *testing.T) {
	hbk := hx(t, "c0c1c2c3c4c5c6c7c8c9cacbcccdcecfc0c1c2c3c4c5c6c7c8c9cacbcccdcecf")
	blob := hx(t, "0200020000000000d0d1d2d3d4d5d6d7d8d9dadbdcdddedf7eb14db5cff0a29f14101e515e4d1ae6")
	want := hx(t, "2d139f495b19ad9709c8c902fcb29bc2")

	got, err := decryptHash(hbk, 500, blob, true, ntConst)
	if err != nil {
		t.Fatalf("decryptHash(new): %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("decryptHash(new) = %x, want %x", got, want)
	}
	if blob[2] == 1 {
		t.Error("new-style blob misdetected as old style")
	}
}

func TestUnscrambleBootKey(t *testing.T) {
	transform := [16]int{8, 5, 4, 2, 11, 9, 13, 3, 0, 6, 1, 12, 14, 10, 15, 7}
	// Build the pre-image of 000102...0f under the transform.
	scrambled := make([]byte, 16)
	for i, tr := range transform {
		scrambled[tr] = byte(i)
	}
	out, err := unscrambleBootKey(scrambled)
	if err != nil {
		t.Fatalf("unscrambleBootKey: %v", err)
	}
	for i, b := range out {
		if b != byte(i) {
			t.Fatalf("unscrambleBootKey = %x, want 000102...0f", out)
		}
	}
	if _, err := unscrambleBootKey(make([]byte, 8)); err == nil {
		t.Error("unscrambleBootKey accepted a short input")
	}
}
