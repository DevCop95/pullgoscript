// Package elevate contains optional, explicit UAC self-elevation.
//
// Elevation is opt-in (--elevate). OBLITERATUS v1 force-elevated on every
// start, which made a "just show me the audit" run pop a UAC prompt — bad
// defaults for a defensive tool.
package elevate

import "errors"

// ErrUnsupported is returned by platforms without a UAC equivalent.
var ErrUnsupported = errors.New("elevate: not supported on this platform")
