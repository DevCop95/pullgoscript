package lateral

import "testing"

// insecureTLS is the opt-in escape hatch for a lab WinRM listener with a
// self-signed certificate. The invariant worth pinning: certificate
// verification is only ever skipped when the operator asked for it. A
// regression that returned an insecure config by default would be silent.
func TestInsecureTLSIsOptIn(t *testing.T) {
	if cfg := insecureTLS(false); cfg != nil {
		t.Errorf("insecureTLS(false) = %+v, want nil so Go's default verification applies", cfg)
	}
	cfg := insecureTLS(true)
	if cfg == nil {
		t.Fatal("insecureTLS(true) = nil, want a config with InsecureSkipVerify")
	}
	if !cfg.InsecureSkipVerify {
		t.Error("insecureTLS(true).InsecureSkipVerify = false, want true")
	}
}
