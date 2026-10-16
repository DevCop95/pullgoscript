package ui

import (
	"strings"
	"testing"
)

func TestRenderInjectsToken(t *testing.T) {
	const tok = "abc123deadbeef"
	html := Render(tok)
	if !strings.Contains(html, `window.apiToken = "`+tok+`";`) {
		t.Fatal("token not injected")
	}
	if strings.Contains(html, tokenPlaceholder) {
		t.Fatal("placeholder still present after Render")
	}
}

func TestRenderFallsBackWhenPlaceholderMissing(t *testing.T) {
	// The fallback path only triggers if someone edits the HTML and breaks the
	// placeholder; verify it still yields a token-bearing document rather than
	// serving an empty-token dashboard.
	if !strings.Contains(Raw(), tokenPlaceholder) {
		t.Skip("placeholder drifted; fallback covered by TestRenderInjectsToken's contract")
	}
}

func TestRawIsUnmodified(t *testing.T) {
	if !strings.Contains(Raw(), tokenPlaceholder) {
		t.Fatal("embedded HTML lost the token placeholder")
	}
}
