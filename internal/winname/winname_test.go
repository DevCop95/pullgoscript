package winname

import "testing"

// TestDecodedNames pins every masked literal to its plaintext. If a literal is
// corrupted (a bad byte, a table regenerated with a different mask), the build
// fails here instead of resolving a wrong export at runtime.
//
// The plaintext lives only in this test file, which is not part of the shipped
// binary.
func TestDecodedNames(t *testing.T) {
	for _, tc := range []struct {
		name string
		got  string
		want string
	}{
		{"LibKernel32", LibKernel32, "kernel32.dll"},
		{"LibNtdll", LibNtdll, "ntdll.dll"},
		{"LibAmsi", LibAmsi, "amsi.dll"},
		{"LibDbghelp", LibDbghelp, "dbghelp.dll"},
		{"ReadProcMem", ReadProcMem, "ReadProcessMemory"},
		{"WriteProcMem", WriteProcMem, "WriteProcessMemory"},
		{"VirtProtect", VirtProtect, "VirtualProtect"},
		{"FlushICache", FlushICache, "FlushInstructionCache"},
		{"OpenProc", OpenProc, "OpenProcess"},
		{"CloseH", CloseH, "CloseHandle"},
		{"CreateFile", CreateFile, "CreateFileW"},
		{"MiniDump", MiniDump, "MiniDumpWriteDump"},
		{"EtwWrite", EtwWrite, "EtwEventWrite"},
		{"AmsiScan", AmsiScan, "AmsiScanBuffer"},
		{"NtAllocVM", NtAllocVM, "NtAllocateVirtualMemory"},
		{"NtWriteVM", NtWriteVM, "NtWriteVirtualMemory"},
		{"NtProtectVM", NtProtectVM, "NtProtectVirtualMemory"},
		{"NtCreateTh", NtCreateTh, "NtCreateThreadEx"},
		{"NtClose", NtClose, "NtClose"},
	} {
		if tc.got != tc.want {
			t.Errorf("%s decodes to %q, want %q", tc.name, tc.got, tc.want)
		}
	}
}
