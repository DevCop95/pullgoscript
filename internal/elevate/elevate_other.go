//go:build !windows

package elevate

// IsAdmin always reports false off Windows.
func IsAdmin() bool { return false }

// RelaunchElevated reports the platform limitation.
func RelaunchElevated() error { return ErrUnsupported }

// RunElevated is a no-op off Windows.
func RunElevated() {}
