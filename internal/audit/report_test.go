package audit

import (
	"encoding/csv"
	"encoding/json"
	"strings"
	"testing"
)

func TestFinalizeSortsAndCounts(t *testing.T) {
	r := NewReport("test", false, map[string]bool{"collect": false})
	r.Add(Finding{ID: "MK-B", Severity: High, Status: StatusFail})
	r.Add(Finding{ID: "MK-A", Severity: Critical, Status: StatusFail})
	r.Add(Finding{ID: "MK-C", Severity: Info, Status: StatusPass})
	r.Add(Finding{ID: "MK-D", Severity: High, Status: StatusUnknown})
	r.Finalize()

	wantOrder := []string{"MK-A", "MK-B", "MK-D", "MK-C"}
	for i, id := range wantOrder {
		if r.Findings[i].ID != id {
			t.Fatalf("order[%d] = %s, want %s (findings: %+v)", i, r.Findings[i].ID, id, r.Findings)
		}
	}
	if r.Summary["CRITICAL"] != 1 || r.Summary["HIGH"] != 2 || r.Summary["INFO"] != 1 {
		t.Fatalf("summary = %v", r.Summary)
	}
	if len(r.Summary) != 5 {
		t.Fatalf("summary must always carry all five severities, got %d", len(r.Summary))
	}
}

func TestWorstSeverityIgnoresPassAndUnknown(t *testing.T) {
	r := NewReport("test", false, nil)
	r.Add(Finding{ID: "1", Severity: High, Status: StatusPass})
	r.Add(Finding{ID: "2", Severity: Critical, Status: StatusUnknown})
	if got := r.WorstSeverity(); got != Info {
		t.Fatalf("WorstSeverity = %v, want Info (nothing actually failing)", got)
	}
	r.Add(Finding{ID: "3", Severity: Medium, Status: StatusFail})
	if got := r.WorstSeverity(); got != Medium {
		t.Fatalf("WorstSeverity = %v, want Medium", got)
	}
	r.Add(Finding{ID: "4", Severity: High, Status: StatusFail})
	if got := r.WorstSeverity(); got != High {
		t.Fatalf("WorstSeverity = %v, want High", got)
	}
}

func TestFailing(t *testing.T) {
	r := NewReport("test", false, nil)
	r.Add(Finding{ID: "a", Status: StatusFail})
	r.Add(Finding{ID: "b", Status: StatusPass})
	r.Add(Finding{ID: "c", Status: StatusFail})
	got := r.Failing()
	if len(got) != 2 || got[0].ID != "a" || got[1].ID != "c" {
		t.Fatalf("Failing() = %+v", got)
	}
}

func TestCSVQuotesSpecialCharacters(t *testing.T) {
	r := NewReport("test", false, nil)
	r.Add(Finding{
		ID:          "MK-TEST",
		Severity:    Critical,
		Status:      StatusFail,
		Title:       `Value was "1", expected 0`,
		Evidence:    "line1\nline2, with comma",
		Remediation: "see https://example.com/a,b",
	})
	csvOut := r.CSV()
	if !strings.Contains(csvOut, `""1""`) {
		t.Errorf("embedded quotes not escaped: %s", csvOut)
	}
	if !strings.Contains(csvOut, `"line1
line2, with comma"`) {
		t.Errorf("newline/comma not quoted: %s", csvOut)
	}
	// Round-trip through the same parser the consumers use.
	records, err := csv.NewReader(strings.NewReader(csvOut)).ReadAll()
	if err != nil {
		t.Fatalf("CSV does not parse back: %v\n%s", err, csvOut)
	}
	if len(records) != 2 {
		t.Fatalf("expected header + 1 record, got %d", len(records))
	}
	row := records[1]
	if row[0] != "MK-TEST" || row[1] != "CRITICAL" || row[2] != "fail" {
		t.Errorf("record fields = %v", row)
	}
	if row[6] != "line1\nline2, with comma" {
		t.Errorf("evidence round trip = %q", row[6])
	}
}

func TestSeverityJSONRoundTrip(t *testing.T) {
	for _, s := range []Severity{Critical, High, Medium, Low, Info} {
		b, err := json.Marshal(s)
		if err != nil {
			t.Fatalf("marshal %v: %v", s, err)
		}
		var back Severity
		if err := json.Unmarshal(b, &back); err != nil {
			t.Fatalf("unmarshal %s: %v", b, err)
		}
		if back != s {
			t.Errorf("round trip %v -> %v", s, back)
		}
	}
	if got := ParseSeverity("medium"); got != Medium {
		t.Errorf("ParseSeverity(medium) = %v", got)
	}
	if got := ParseSeverity("garbage"); got != Info {
		t.Errorf("ParseSeverity(garbage) = %v, want Info", got)
	}
}

func TestReportJSONShape(t *testing.T) {
	r := NewReport("1.2.3", true, map[string]bool{"collect": false})
	r.Add(Finding{ID: "MK-X", Severity: Low, Status: StatusPass})
	r.Finalize()

	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	var decoded struct {
		Tool     string         `json:"tool"`
		Summary  map[string]int `json:"summary"`
		Findings []struct {
			ID       string `json:"id"`
			Severity string `json:"severity"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(b, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Tool != "obliteratus" || decoded.Findings[0].Severity != "LOW" {
		t.Fatalf("decoded = %+v", decoded)
	}
	if decoded.Summary["LOW"] != 1 {
		t.Fatalf("summary in JSON = %v", decoded.Summary)
	}
}
