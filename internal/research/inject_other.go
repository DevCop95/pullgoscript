//go:build !windows || !amd64

// Package research exposes the indirect-syscall injection primitives on
// supported platforms only (windows/amd64). Elsewhere Inject reports the
// limitation so callers degrade gracefully instead of failing to build.
package research

import "errors"

// Inject reports that this platform is unsupported.
func Inject(pid int, payload []byte) error {
	return errors.New("inject: only supported on windows/amd64")
}
