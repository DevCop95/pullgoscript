//go:build !windows

package research

import "fmt"

// PatchAMSI is unreachable off Windows: amsi.dll only exists there.
func PatchAMSI() (uintptr, error) {
	return 0, fmt.Errorf("amsi: unsupported on this platform")
}
