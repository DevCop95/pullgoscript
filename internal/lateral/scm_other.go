//go:build !windows

package lateral

import "fmt"

// SCMExec is unreachable off Windows: the Service Control Manager API is
// Windows-only.
func SCMExec(string, Creds, string, string, Emitter) error {
	return fmt.Errorf("scm: unsupported on this platform")
}
