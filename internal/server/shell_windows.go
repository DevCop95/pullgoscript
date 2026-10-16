//go:build windows

package server

import (
	"os/exec"
	"syscall"
)

// runShell executes one operator-console command through cmd.exe. The child
// window stays hidden so no console flashes on the operator's desktop.
func runShell(command string) ([]byte, error) {
	cmd := exec.Command("cmd", "/c", "chcp 65001 > nul && "+command)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	return cmd.CombinedOutput()
}
