//go:build !windows

package research

import "fmt"

// PatchETW is a no-op off Windows: there is no ntdll to neuter.
func PatchETW() (uintptr, error) {
	return 0, fmt.Errorf("etw: unsupported on this platform")
}
