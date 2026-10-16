//go:build windows

package audit

import (
	"strings"
	"testing"
)

// TestRunChecksShape validates the audit contract on a real Windows host:
// findings exist, IDs are stable and unique, severities/statuses are from the
// known set, and every failing control carries a remediation.
func TestRunChecksShape(t *testing.T) {
	findings := RunChecks(false)
	if len(findings) < 10 {
		t.Fatalf("only %d findings, expected the full playbook (>=10)", len(findings))
	}

	seen := map[string]bool{}
	validSev := map[Severity]bool{Critical: true, High: true, Medium: true, Low: true, Info: true}
	validStatus := map[Status]bool{StatusPass: true, StatusFail: true, StatusUnknown: true}

	for _, f := range findings {
		if !strings.HasPrefix(f.ID, "MK-") {
			t.Errorf("finding %q: ID must start with MK-", f.ID)
		}
		if seen[f.ID] {
			t.Errorf("duplicate finding ID %q", f.ID)
		}
		seen[f.ID] = true
		if !validSev[f.Severity] {
			t.Errorf("%s: invalid severity %v", f.ID, f.Severity)
		}
		if !validStatus[f.Status] {
			t.Errorf("%s: invalid status %q", f.ID, f.Status)
		}
		if f.Title == "" {
			t.Errorf("%s: empty title", f.ID)
		}
		if f.Evidence == "" {
			t.Errorf("%s: empty evidence — a check that observed nothing must say so", f.ID)
		}
		if f.Status == StatusFail && f.Severity <= High && f.Remediation == "" {
			t.Errorf("%s: failing CRITICAL/HIGH check without remediation", f.ID)
		}
	}

	// The core Mimikatz checks must always be present (their Status may be
	// unknown on exotic SKUs, but the check itself must run).
	for _, required := range []string{
		"MK-WDIGEST", "MK-LSASS-PPL", "MK-CREDGUARD", "MK-SEDEBUG",
		"MK-AUTOLOGON-PASS", "MK-PSLOG", "MK-AV", "MK-LAPS",
	} {
		if !seen[required] {
			t.Errorf("required check %s missing", required)
		}
	}
}

// TestBuildReportIsFinalized ensures summaries are computed before consumers
// (API/CLI) read them.
func TestBuildReportIsFinalized(t *testing.T) {
	rep := BuildReport("test", false, map[string]bool{"collect": false})
	if rep.Tool != "obliteratus" || rep.Version != "test" {
		t.Fatalf("meta = %s/%s", rep.Tool, rep.Version)
	}
	if len(rep.Findings) == 0 {
		t.Fatal("no findings")
	}
	total := 0
	for _, n := range rep.Summary {
		total += n
	}
	if total != len(rep.Findings) {
		t.Fatalf("summary total %d != findings %d", total, len(rep.Findings))
	}
	// Sorted descending by severity index.
	for i := 1; i < len(rep.Findings); i++ {
		if rep.Findings[i].Severity < rep.Findings[i-1].Severity {
			t.Fatalf("findings not sorted by severity at %d", i)
		}
	}
}

// TestSeDebugCheckIsHonest makes sure the privilege probe returns a definite
// present/absent answer rather than silently passing.
func TestSeDebugCheckIsHonest(t *testing.T) {
	f := checkSeDebug(false)
	if f.Status == StatusPass && f.Evidence == "" {
		t.Fatal("pass without evidence")
	}
	if !strings.Contains(f.Evidence, "SeDebugPrivilege") {
		t.Fatalf("evidence = %q, want mention of SeDebugPrivilege", f.Evidence)
	}
}
