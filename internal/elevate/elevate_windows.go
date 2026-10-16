//go:build windows

package elevate

import (
	"log"
	"os"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// IsAdmin reports whether the current process token is elevated.
func IsAdmin() bool {
	var token windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &token); err != nil {
		return false
	}
	defer token.Close()
	return token.IsElevated()
}

// RelaunchElevated re-executes the current binary through the UAC consent
// prompt ("runas") and, on success, terminates the unelevated parent.
// It returns an error instead of exiting so callers control lifecycle.
func RelaunchElevated() error {
	if IsAdmin() {
		return nil
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	// Quote arguments that contain spaces so the elevated child sees the same
	// argv as the parent (the v1 implementation joined args unquoted, which
	// silently corrupted flags such as --payload "C:\path with space\x.bin").
	args := make([]string, 0, len(os.Args[1:])+1)
	for _, a := range os.Args[1:] {
		if strings.ContainsAny(a, " \t") {
			a = `"` + a + `"`
		}
		args = append(args, a)
	}
	args = append(args, MarkerArg)
	cwd, _ := os.Getwd()

	shell32 := syscall.NewLazyDLL("shell32.dll")
	shellExecute := shell32.NewProc("ShellExecuteW")
	ret, _, _ := shellExecute.Call(
		0,
		uintptr(unsafe.Pointer(windows.StringToUTF16Ptr("runas"))),
		uintptr(unsafe.Pointer(windows.StringToUTF16Ptr(exe))),
		uintptr(unsafe.Pointer(windows.StringToUTF16Ptr(strings.Join(args, " ")))),
		uintptr(unsafe.Pointer(windows.StringToUTF16Ptr(cwd))),
		1, // SW_SHOWNORMAL
	)
	if ret <= 32 {
		return errCancelled
	}
	return nil
}

// ExitParent terminates the current (now superseded) unelevated process.
func ExitParent() { os.Exit(0) }

// RunElevated is the convenience wrapper used by main: relaunch or exit.
func RunElevated() {
	if IsAdmin() {
		return
	}
	if err := RelaunchElevated(); err != nil {
		log.Println("[!] UAC elevation failed or was cancelled:", err)
		os.Exit(1)
	}
	os.Exit(0)
}

type elevateError string

func (e elevateError) Error() string { return string(e) }

const errCancelled elevateError = "UAC consent declined or ShellExecuteW failed"
