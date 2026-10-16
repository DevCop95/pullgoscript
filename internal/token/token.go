// Package token generates and verifies the ephemeral API token that shields
// every OBLITERATUS endpoint.
//
// The token is 32 bytes of crypto/rand data rendered as hex. It is regenerated
// on every process start, so a token captured in a previous run (or derived
// from a predictable value such as the PID, which was the pre-v2 behaviour) is
// useless.
package token

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
)

// Size is the number of random bytes used for a token.
const Size = 32

// New returns a fresh, unpredictable token. The token is unique per run:
//
//	token, err := token.New()
//	if err != nil { ... }
//	// token ~= "9f3c... (64 hex chars)"
func New() (string, error) {
	b := make([]byte, Size)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("token: entropy source failure: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// Equal reports whether a and b are the same token. Comparison is
// constant-time so response timing cannot be used to brute-force the token
// byte by byte.
func Equal(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
