//go:build windows

package persist

import (
	"strings"
	"testing"
	"time"
)

func TestPsQuote(t *testing.T) {
	got := psQuote(`C:\x.exe /c "a'b"`)
	if !strings.HasPrefix(got, "'") || !strings.HasSuffix(got, "'") {
		t.Fatalf("psQuote not single-quoted: %q", got)
	}
	if !strings.Contains(got, "''") {
		t.Fatalf("psQuote did not double the embedded quote: %q", got)
	}
}

// TestParseTasksCSV uses a fixture captured from real `schtasks /Query /FO CSV
// /V /NH` output, not a hand-written one. An earlier fixture was fabricated
// with the TaskName in column 0 and the action in column 7, which is exactly
// the assumption the parser had wrong — so the test passed while the module
// reported zero scheduled tasks on every host. Real output puts HostName in
// column 0, TaskName in 1, Author in 7 and "Task To Run" in 8.
func TestParseTasksCSV(t *testing.T) {
	out := []byte(
		// A real task whose action contains quotes: schtasks writes
		// `""C:\...exe" /c""` without doubling the inner quotes, which is
		// non-conforming CSV and used to abort the whole parse.
		`"DEV101","\BraveSoftwareUpdateTaskMachineCore{ABC}","10/16/2026 4:37:40 PM","Ready","Interactive/Background","10/15/2026 4:37:41 PM","0","N/A",""C:\Program Files (x86)\BraveSoftware\Update\BraveUpdate.exe" /c"","N/A"` + "\r\n" +
			// Built-in OS task: must be filtered out.
			`"DEV101","\Microsoft\Windows\Foo","N/A","Ready","Interactive","N/A","0","SYSTEM","%windir%\foo.exe","N/A"` + "\r\n" +
			// Our foothold.
			`"DEV101","\OBL_nightly","N/A","Ready","Interactive","N/A","0","DEV101\Admin","cmd.exe /c beacon.exe","N/A"` + "\r\n" +
			// Truncated row: skipped, and must not discard the rows around it.
			`"DEV101","\Truncated"` + "\r\n")

	entries := parseTasksCSV(out)
	if len(entries) != 2 {
		t.Fatalf("parseTasksCSV returned %d entries, want 2 (Microsoft filtered, truncated skipped): %+v", len(entries), entries)
	}
	for _, e := range entries {
		if e.Type != TypeTask || e.Hive != "TaskScheduler" {
			t.Errorf("entry %+v: type/hive wrong", e)
		}
		// Regression: column 0 is the host name, never the task name.
		if e.Name == "DEV101" {
			t.Errorf("entry %+v: host name leaked into the task name", e)
		}
		if e.Command == "N/A" || e.Command == "SYSTEM" || e.Command == "DEV101\\Admin" {
			t.Errorf("entry %+v: metadata column leaked into the command", e)
		}
	}
	byName := map[string]string{}
	for _, e := range entries {
		byName[e.Name] = e.Command
	}
	if got, ok := byName["OBL_nightly"]; !ok || got != "cmd.exe /c beacon.exe" {
		t.Errorf("OBL_nightly = %q (present=%v), want %q", got, ok, "cmd.exe /c beacon.exe")
	}
	brave, ok := byName["BraveSoftwareUpdateTaskMachineCore{ABC}"]
	if !ok {
		t.Fatalf("the malformed-quote row was dropped; entries = %+v", entries)
	}
	if !strings.Contains(brave, "BraveUpdate.exe") {
		t.Errorf("malformed-quote command = %q, want it to contain BraveUpdate.exe", brave)
	}
}

// TestParseTasksCSVDeduplicates covers the `/V` behaviour that emits one row per
// trigger: the same task must not be listed once per trigger.
func TestParseTasksCSVDeduplicates(t *testing.T) {
	row := func(run string) string {
		return `"DEV101","\OblMultiTrigger","N/A","Ready","Interactive","N/A","0","DEV101\Admin","` + run + `","N/A"` + "\r\n"
	}
	out := []byte(row("cmd.exe /c one") + row("cmd.exe /c one") + row("cmd.exe /c one") +
		`"DEV101","\OblOther","N/A","Ready","Interactive","N/A","0","DEV101\Admin","cmd.exe /c two","N/A"` + "\r\n")

	entries := parseTasksCSV(out)
	if len(entries) != 2 {
		t.Fatalf("parseTasksCSV returned %d entries, want 2 (3 trigger rows collapse to 1): %+v", len(entries), entries)
	}
}

func TestParseWMIConsumers(t *testing.T) {
	out := []byte("OBL_foo|cmd.exe /c calc\r\n\r\nEvilThing|powershell -enc AAAA\r\n")
	entries := parseWMIConsumers(out)
	if len(entries) != 2 {
		t.Fatalf("parseWMIConsumers returned %d entries, want 2", len(entries))
	}
	if entries[0].Name != "OBL_foo" || entries[0].Type != TypeWMI || entries[0].Hive != "WMI" {
		t.Fatalf("entry[0] = %+v", entries[0])
	}
	if entries[1].Command != "powershell -enc AAAA" {
		t.Fatalf("entry[1].Command = %q", entries[1].Command)
	}
}

// TestWMIRemoveScriptQuotesWQL pins the fix for a silent failure: the WQL value
// must be quoted inside the query. Emitting `("Name=" + 'x')` yields the
// invalid query `Name=x`, which matches nothing while the script still prints
// OK — the consumer and filter survived removal and the API reported success.
func TestWMIRemoveScriptQuotesWQL(t *testing.T) {
	s := wmiRemoveScript("OBL_x")
	if !strings.Contains(s, `-Filter ("Name='" + 'OBL_x' + "'")`) {
		t.Fatalf("WQL value is not quoted inside the query:\n%s", s)
	}
	if strings.Contains(s, `-Filter ("Name=" + 'OBL_x')`) {
		t.Fatal("script builds an unquoted WQL value (Name=x is invalid WQL)")
	}
}

func TestWMIRemoveCandidates(t *testing.T) {
	if got := wmiRemoveCandidates("x"); len(got) != 2 || got[0] != "x" || got[1] != wmiNamePrefix+"x" {
		t.Fatalf("wmiRemoveCandidates(%q) = %v, want [x %sx]", "x", got, wmiNamePrefix)
	}
	// Already prefixed: no duplicate candidate.
	if got := wmiRemoveCandidates(wmiNamePrefix + "x"); len(got) != 1 || got[0] != wmiNamePrefix+"x" {
		t.Fatalf("wmiRemoveCandidates(prefixed) = %v, want a single entry", got)
	}
}

// TestRunHiddenTimesOut pins the liveness bound. Before it, a wedged schtasks
// or WMI call held the HTTP handler forever, because exec.Command waits with
// no deadline.
//
// The sleep has to be a real child process: `timeout /t` is unusable here
// because it refuses to run without a console, which is exactly how runHidden
// spawns its children. `ping -n 10` occupies the child for ~9s, so a 300ms
// budget leaves a wide margin between "the context fired" and "the child would
// have finished anyway".
func TestRunHiddenTimesOut(t *testing.T) {
	prev := runHiddenBudget
	runHiddenBudget = 300 * time.Millisecond
	defer func() { runHiddenBudget = prev }()

	start := time.Now()
	_, err := runHidden("ping", "-n", "10", "127.0.0.1")
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("runHidden returned a nil error for a child that outlived the budget")
	}
	if !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("want an explicit timeout error, got %v", err)
	}
	if elapsed > 4*time.Second {
		t.Fatalf("runHidden returned after %s: the context was not enforced", elapsed)
	}
}
