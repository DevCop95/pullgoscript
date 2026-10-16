// Package lateral implements the two classic Windows lateral-movement
// execution paths of T1021:
//
//	WinRMExec — remote command execution over the WS-Management (WSMan) SOAP
//	            protocol on 5985/5986 (T1021.006). Pure Go: the envelopes are
//	            hand-built and the responses parsed with encoding/xml, so the
//	            module adds no dependency beyond the standard library.
//	SCMExec   — remote execution by creating and starting a service on the
//	            target's Service Control Manager (T1021.002 / T1569.002). Uses
//	            the in-process SCM API (golang.org/x/sys/windows/svc/mgr) with
//	            an optional network logon for the supplied credentials.
//
// Both are deliberately credential-driven: the caller passes the account the
// engagement is authorised with. Recovered cleartext is never logged — only
// progress lines and the command output the operator asked for.
//
// This module is OFF unless the operator starts obliteratus with
// --enable-lateral; the HTTP routes are what enforce that.
package lateral

import (
	"encoding/xml"
	"strings"
)

// Emitter receives progress lines (msg, level); may be nil.
type Emitter func(msg, level string)

func emit(em Emitter, msg, level string) {
	if em != nil {
		em(msg, level)
	}
}

// Creds is an account to authenticate with on the remote host.
type Creds struct {
	User     string // "DOMAIN\\user", "user@domain" or a local account
	Password string
}

// splitUser separates an account into (domain, name). The domain is empty when
// the caller passed a bare name.
func splitUser(user string) (domain, name string) {
	user = strings.TrimSpace(user)
	// Backslash first: DOMAIN\\name is the canonical down-level form and must
	// not be mistaken for user@domain.
	if i := strings.IndexByte(user, '\\'); i >= 0 {
		return user[:i], user[i+1:]
	}
	if i := strings.LastIndexByte(user, '@'); i >= 0 {
		return user[i+1:], user[:i]
	}
	return "", user
}

// xmlEscape renders s safe for element content (command lines routinely carry
// &, <, > and quotes).
func xmlEscape(s string) string {
	var b strings.Builder
	_ = xml.EscapeText(&b, []byte(s))
	return b.String()
}

// sanitizeName keeps a value to the character class legal in both a service
// name and a registry value name, so one API cannot be abused to smuggle path
// separators or traversal sequences into the target.
func sanitizeName(name string) string {
	name = strings.TrimSpace(name)
	if len(name) > 64 {
		name = name[:64]
	}
	var b strings.Builder
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-' || r == '_' || r == '.':
			b.WriteRune(r)
		}
	}
	return b.String()
}
