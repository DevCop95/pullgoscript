package obfuscate

import "testing"

func TestMaskRoundTrip(t *testing.T) {
	for _, s := range []string{"", "a", "AmsiScanBuffer", "ntdll.dll", "EtwEventWrite", "x86_64-pc-windows"} {
		if got := S(Mask(s)); got != s {
			t.Errorf("round trip %q → %q", s, got)
		}
	}
}

func TestMaskHidesPlaintext(t *testing.T) {
	const secret = "AmsiScanBuffer"
	masked := Mask(secret)
	if string(masked) == secret {
		t.Fatal("Mask did not change the string")
	}
	if string(masked) == "" || len(masked) != len(secret) {
		t.Fatalf("masked length = %d, want %d", len(masked), len(secret))
	}
}
