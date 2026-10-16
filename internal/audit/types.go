package audit

// This file holds the platform-neutral types shared by the Windows
// collectors, the non-Windows build stubs and the HTTP server layer.

// Emitter receives progress lines destined for the operator console. It may
// be nil.
type Emitter func(msg, level string)

// emit is a nil-safe helper around an Emitter.
func emit(e Emitter, msg, level string) {
	if e != nil {
		e(msg, level)
	}
}

// Entry is one recovered saved credential. JSON field names are the short
// forms the dashboard already consumes (b/u/s/p).
type Entry struct {
	B string `json:"b"` // browser
	U string `json:"u"` // origin URL
	S string `json:"s"` // username
	P string `json:"p"` // secret
}

// Cookie is one recovered cookie jar entry (b/h/n/v in the dashboard).
type Cookie struct {
	B string `json:"b"` // browser
	H string `json:"h"` // host
	N string `json:"n"` // name
	V string `json:"v"` // value
}

// Node is the Identity Nexus view of one origin (u/p/c in the dashboard).
type Node struct {
	U string `json:"u"` // username
	P string `json:"p"` // password marker
	C string `json:"c"` // session marker
}

// SAMAccount is one local account recovered by the lsadump::sam module
// (RID/user/lm/nt in the dashboard).
type SAMAccount struct {
	RID  uint32 `json:"rid"`  // relative ID
	User string `json:"user"` // account name
	LM   string `json:"lm"`   // LM hash hex (empty-hash constant if not stored)
	NT   string `json:"nt"`   // NT hash hex
}

// SupportedChromiumBrowsers lists the Chromium families the collector walks,
// in report order.
var SupportedChromiumBrowsers = []string{"Chrome", "Edge", "Brave"}
