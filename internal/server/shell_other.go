//go:build !windows

package server

import "os/exec"

// runShell executes one operator-console command through the platform shell
// (the dashboard itself only runs on Windows; this keeps the package buildable
// for CI on Linux).
func runShell(command string) ([]byte, error) {
	return exec.Command("sh", "-c", command).CombinedOutput()
}
