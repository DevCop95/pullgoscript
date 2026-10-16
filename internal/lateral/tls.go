package lateral

import "crypto/tls"

// insecureTLS returns a TLS config that skips certificate verification when
// insecure is set — the explicit, opt-in escape hatch for a lab WinRM listener
// with a self-signed certificate. Without the flag, Go's default verification
// applies (nil config).
func insecureTLS(insecure bool) *tls.Config {
	if !insecure {
		return nil
	}
	// #nosec G402 -- InsecureSkipVerify is a deliberate, operator-requested
	// lab convenience, never the default.
	return &tls.Config{InsecureSkipVerify: true}
}
