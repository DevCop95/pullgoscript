// Package audit implements the OBLITERATUS assessment engine.
//
// The core deliverable is a Mimikatz-shaped attack-surface audit: every
// credential-theft technique in the Mimikatz playbook (sekurlsa, winlogon,
// lsadump, misc) is mapped to a concrete, checkable Windows configuration
// state, and the tool reports whether this host would survive it.
//
// Offensive collectors (browser credential/cookie extraction) live in the same
// package but are only reachable when the operator starts the tool with
// --enable-collect, an explicit acknowledgement that the run is part of an
// authorised engagement.
package audit

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Severity ranks a finding by how directly it enables credential theft.
type Severity int

const (
	Critical Severity = iota
	High
	Medium
	Low
	Info
)

// String returns the human label used in reports and the UI.
func (s Severity) String() string {
	switch s {
	case Critical:
		return "CRITICAL"
	case High:
		return "HIGH"
	case Medium:
		return "MEDIUM"
	case Low:
		return "LOW"
	case Info:
		return "INFO"
	}
	return "UNKNOWN"
}

// MarshalJSON emits the severity as a string so API consumers never have to
// map integers.
func (s Severity) MarshalJSON() ([]byte, error) { return json.Marshal(s.String()) }

// UnmarshalJSON parses the string form back into a Severity.
func (s *Severity) UnmarshalJSON(b []byte) error {
	var str string
	if err := json.Unmarshal(b, &str); err != nil {
		return err
	}
	*s = ParseSeverity(str)
	return nil
}

// ParseSeverity maps a label (case-insensitive) to a Severity; unknown labels
// become Info.
func ParseSeverity(v string) Severity {
	switch strings.ToUpper(strings.TrimSpace(v)) {
	case "CRITICAL":
		return Critical
	case "HIGH":
		return High
	case "MEDIUM":
		return Medium
	case "LOW":
		return Low
	default:
		return Info
	}
}

// Status is the outcome of a single check.
type Status string

const (
	// StatusPass means the hardened behaviour is in place.
	StatusPass Status = "pass"
	// StatusFail means the host is exposed to the mapped technique.
	StatusFail Status = "fail"
	// StatusUnknown means the check could not run (missing privilege, missing
	// asset, unsupported OS). Unknown never counts as a pass.
	StatusUnknown Status = "unknown"
)

// Finding is one result of the audit.
type Finding struct {
	// ID is stable, e.g. "MK-WDIGEST". Consumers may key on it.
	ID string `json:"id"`
	// Title is a one-line description of the control.
	Title string `json:"title"`
	// Severity ranks the impact if the control is absent.
	Severity Severity `json:"severity"`
	// Status is pass/fail/unknown.
	Status Status `json:"status"`
	// Evidence is the concrete observed state (registry value, service state…).
	Evidence string `json:"evidence"`
	// Remediation is the concrete fix for a failing check.
	Remediation string `json:"remediation"`
	// Technique is the MITRE ATT&CK ID the control maps to.
	Technique string `json:"technique,omitempty"`
	// Module names the Mimikatz command that would exercise this surface
	// (e.g. "sekurlsa::wdigest").
	Module string `json:"module,omitempty"`
}

// Report is the full result of an audit run.
type Report struct {
	Tool        string          `json:"tool"`
	Version     string          `json:"version"`
	Hostname    string          `json:"hostname"`
	GeneratedAt time.Time       `json:"generated_at"`
	Elevated    bool            `json:"elevated"`
	Modules     map[string]bool `json:"modules"`
	Findings    []Finding       `json:"findings"`
	Summary     map[string]int  `json:"summary"`
}

// NewReport creates an empty report skeleton.
func NewReport(version string, elevated bool, modules map[string]bool) *Report {
	host, _ := hostname()
	return &Report{
		Tool:        "obliteratus",
		Version:     version,
		Hostname:    host,
		GeneratedAt: time.Now().UTC(),
		Elevated:    elevated,
		Modules:     modules,
		Findings:    []Finding{},
		Summary:     map[string]int{},
	}
}

// Add appends a finding to the report.
func (r *Report) Add(f Finding) { r.Findings = append(r.Findings, f) }

// Finalize sorts findings by severity (then ID) and computes the summary
// counters. It is idempotent.
func (r *Report) Finalize() {
	sort.SliceStable(r.Findings, func(i, j int) bool {
		if r.Findings[i].Severity != r.Findings[j].Severity {
			return r.Findings[i].Severity < r.Findings[j].Severity
		}
		return r.Findings[i].ID < r.Findings[j].ID
	})
	summary := map[string]int{}
	for _, s := range []Severity{Critical, High, Medium, Low, Info} {
		summary[s.String()] = 0
	}
	for _, f := range r.Findings {
		summary[f.Severity.String()]++
	}
	r.Summary = summary
}

// WorstSeverity returns the highest severity among failing findings (Info when
// everything passes).
func (r *Report) WorstSeverity() Severity {
	worst := Info
	for _, f := range r.Findings {
		if f.Status == StatusFail && f.Severity < worst {
			worst = f.Severity
		}
	}
	return worst
}

// Failing returns only findings whose Status is fail.
func (r *Report) Failing() []Finding {
	var out []Finding
	for _, f := range r.Findings {
		if f.Status == StatusFail {
			out = append(out, f)
		}
	}
	return out
}

// CSV renders the report as RFC4180 CSV (header + one row per finding).
func (r *Report) CSV() string {
	var b strings.Builder
	w := csv.NewWriter(&b)
	_ = w.Write([]string{"id", "severity", "status", "title", "technique", "module", "evidence", "remediation"})
	for _, f := range r.Findings {
		_ = w.Write([]string{
			f.ID,
			f.Severity.String(),
			string(f.Status),
			f.Title,
			f.Technique,
			f.Module,
			f.Evidence,
			f.Remediation,
		})
	}
	w.Flush()
	return b.String()
}

// String renders a compact human summary (used by the CLI).
func (r *Report) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "OBLITERATUS audit — %s @ %s (elevated=%v)\n",
		r.GeneratedAt.Format(time.RFC3339), r.Hostname, r.Elevated)
	for _, f := range r.Findings {
		fmt.Fprintf(&b, "  [%s] %-9s %-18s %s\n", f.Severity, f.Status, f.ID, f.Title)
	}
	fmt.Fprintf(&b, "summary: %v\n", r.Summary)
	return b.String()
}
