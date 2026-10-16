package research

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func randomKey(t *testing.T) []byte {
	t.Helper()
	k := make([]byte, packKeyLen)
	if _, err := rand.Read(k); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return k
}

func TestPackRoundTrip(t *testing.T) {
	key := randomKey(t)
	plain := []byte("\xfc\x48\x83\xe4\xf0 shellcode bytes \x00\x01\x02")
	packed, err := Pack(key, plain)
	if err != nil {
		t.Fatalf("Pack: %v", err)
	}
	if !IsPacked(packed) {
		t.Fatal("IsPacked = false for a freshly packed payload")
	}
	if bytes.Contains(packed, plain) {
		t.Fatal("packed payload leaks the plaintext")
	}
	got, err := Unpack(key, packed)
	if err != nil {
		t.Fatalf("Unpack: %v", err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatalf("round trip mismatch: %q", got)
	}
}

func TestUnpackWrongKeyFailsClosed(t *testing.T) {
	packed, err := Pack(randomKey(t), []byte("payload"))
	if err != nil {
		t.Fatalf("Pack: %v", err)
	}
	if _, err := Unpack(randomKey(t), packed); err == nil {
		t.Fatal("Unpack accepted a wrong key")
	}
}

func TestUnpackTamperedFailsClosed(t *testing.T) {
	key := randomKey(t)
	packed, err := Pack(key, []byte("payload-data"))
	if err != nil {
		t.Fatalf("Pack: %v", err)
	}
	packed[len(packed)-1] ^= 0xFF // flip a tag byte
	if _, err := Unpack(key, packed); err == nil {
		t.Fatal("Unpack accepted a tampered payload")
	}
}

func TestPackRejectsBadInput(t *testing.T) {
	if _, err := Pack([]byte("short"), []byte("x")); err == nil {
		t.Error("Pack accepted a short key")
	}
	if _, err := Pack(randomKey(t), nil); err == nil {
		t.Error("Pack accepted an empty payload")
	}
	if _, err := Unpack(randomKey(t), []byte("not-packed")); err == nil {
		t.Error("Unpack accepted an unpacked buffer")
	}
}

func TestDeriveKeyStable(t *testing.T) {
	a := DeriveKey("passphrase")
	b := DeriveKey("passphrase")
	if len(a) != packKeyLen || !bytes.Equal(a, b) {
		t.Fatalf("DeriveKey not stable/32 bytes: len=%d", len(a))
	}
	if bytes.Equal(DeriveKey("a"), DeriveKey("b")) {
		t.Fatal("DeriveKey collided")
	}
}
