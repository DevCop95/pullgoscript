//go:build !windows

package audit

import "fmt"

// RunChecks reports the platform limitation off Windows: OBLITERATUS audits
// Windows security controls through the Windows registry and SCM.
func RunChecks(elevated bool) []Finding {
	return []Finding{{
		ID:          "MK-PLATFORM",
		Title:       "Audit requires Windows",
		Severity:    Info,
		Status:      StatusUnknown,
		Evidence:    "this binary was executed on a non-Windows OS",
		Remediation: "run the audit on the Windows host you want to assess",
	}}
}

// BuildReport wraps the non-Windows stub in a report.
func BuildReport(version string, elevated bool, modules map[string]bool) *Report {
	r := NewReport(version, elevated, modules)
	for _, f := range RunChecks(elevated) {
		r.Add(f)
	}
	r.Finalize()
	return r
}

// CollectCredentials is a no-op off Windows.
func CollectCredentials([]string, Emitter) []Entry { return nil }

// CollectCookies is a no-op off Windows.
func CollectCookies([]string, Emitter) []Cookie { return nil }

// ABEHelper is unreachable off Windows (the SYSTEM unwrap helper).
func ABEHelper(string, string) int { return 1 }

// Nexus returns an empty correlation map off Windows.
func Nexus(Emitter) map[string]Node { return map[string]Node{} }

// DumpSAM returns no accounts off Windows: the SAM hive only exists there.
func DumpSAM(Emitter) ([]SAMAccount, error) { return nil, nil }

// DumpLSASS is unreachable off Windows.
func DumpLSASS(int, string, Emitter) (string, int64, error) {
	return "", 0, fmt.Errorf("lsass: unsupported on this platform")
}
