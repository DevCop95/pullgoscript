package token

import "testing"

func TestNewReturns64HexChars(t *testing.T) {
	tok, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if len(tok) != Size*2 {
		t.Fatalf("len = %d, want %d", len(tok), Size*2)
	}
	if _, err := decodeHex(tok); err != nil {
		t.Fatalf("token is not hex: %v", err)
	}
}

func TestNewIsUnique(t *testing.T) {
	a, _ := New()
	b, _ := New()
	if a == b {
		t.Fatal("two consecutive tokens are identical; entropy source is broken")
	}
}

func TestEqual(t *testing.T) {
	a, _ := New()
	if !Equal(a, a) {
		t.Error("Equal(a, a) = false, want true")
	}
	if Equal(a, a+"x") {
		t.Error("Equal(a, a+\"x\") = true, want false")
	}
	if Equal("", "") == false {
		// Empty strings match; callers must reject empties before comparing.
		t.Error("Equal(\"\", \"\") = false, want true (documented behaviour)")
	}
}

// decodeHex is a tiny helper so the test fails loudly on non-hex tokens.
func decodeHex(s string) ([]byte, error) {
	if len(s)%2 != 0 {
		return nil, errOdd
	}
	out := make([]byte, len(s)/2)
	for i := 0; i < len(s); i += 2 {
		hi, ok1 := hexVal(s[i])
		lo, ok2 := hexVal(s[i+1])
		if !ok1 || !ok2 {
			return nil, errChar
		}
		out[i/2] = hi<<4 | lo
	}
	return out, nil
}

type decodeError string

func (e decodeError) Error() string { return string(e) }

const (
	errOdd  decodeError = "odd length"
	errChar decodeError = "invalid hex character"
)

func hexVal(c byte) (byte, bool) {
	switch {
	case '0' <= c && c <= '9':
		return c - '0', true
	case 'a' <= c && c <= 'f':
		return c - 'a' + 10, true
	case 'A' <= c && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}
