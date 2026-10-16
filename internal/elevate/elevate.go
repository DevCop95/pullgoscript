// Package elevate contains optional, explicit UAC self-elevation.
//
// Elevation is opt-in (--elevate) or forced by a module that cannot function
// without an elevated token (--enable-collect: SeBackupPrivilege for the SAM
// hives, SeDebugPrivilege for LSASS). OBLITERATUS v1 force-elevated on every
// start, which made a "just show me the audit" run pop a UAC prompt — bad
// defaults for a defensive tool. v2 keeps those defaults, but a module that
// simply cannot work unelevated now elevates up front instead of failing
// opaquely the first time an operator uses it.
package elevate

import "errors"

// ErrUnsupported is returned by platforms without a UAC equivalent.
var ErrUnsupported = errors.New("elevate: not supported on this platform")
