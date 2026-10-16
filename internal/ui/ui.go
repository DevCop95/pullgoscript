// Package ui embeds the dashboard so the binary is self-contained: no
// src/web directory needs to ship next to the executable, and the "404
// facade" HTML can never be served from a stale on-disk copy.
package ui

import (
	_ "embed"
	"fmt"
	"strings"
)

//go:embed web/index.html
var indexHTML string

// tokenPlaceholder is what the static HTML declares before the server
// injects the per-run token. Keeping the placeholder as a valid JS expression
// means opening the raw file from disk still parses.
const tokenPlaceholder = `window.apiToken = "SIGNAL_" + location.port;`

// Render returns the dashboard HTML with this run's API token substituted in.
//
// This is safe even though the token ends up in the page body: browsers give
// the page to same-origin JS only. A hostile site can make the browser
// REQUEST http://127.0.0.1:8080/ but the same-origin policy stops it from
// reading the response body, so it never learns the token. (The server also
// rejects requests whose Host header is not loopback, which stops DNS
// rebinding from even getting that far.)
func Render(token string) string {
	injected := fmt.Sprintf("window.apiToken = %q;", token)
	if !strings.Contains(indexHTML, tokenPlaceholder) {
		// Defensive: if the placeholder ever drifts, fail closed instead of
		// serving a dashboard with an empty token.
		return strings.Replace(indexHTML, "</head>",
			"<script>window.apiToken="+fmt.Sprintf("%q", token)+";</script></head>", 1)
	}
	return strings.Replace(indexHTML, tokenPlaceholder, injected, 1)
}

// Raw returns the unmodified embedded HTML (used by tests).
func Raw() string { return indexHTML }
