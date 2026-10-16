package persist

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSanitizeName(t *testing.T) {
	for in, want := range map[string]string{
		"":                      "",
		"   ":                   "",
		"obl-update":            "obl-update",
		"a.b_c9":                "a.b_c9",
		`..\evil`:               "..evil",
		"a b":                   "ab",
		"HKLM\\Run\\owned":      "HKLMRunowned",
		strings.Repeat("x", 80): strings.Repeat("x", 64),
	} {
		if got := sanitizeName(in); got != want {
			t.Errorf("sanitizeName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestShimContent(t *testing.T) {
	c := shimContent(`C:\tools\agent.exe --start`)
	if !strings.Contains(c, `C:\tools\agent.exe --start`) {
		t.Error("shim does not carry the command")
	}
}

func TestStartupDirUsesAppData(t *testing.T) {
	dir, err := startupDir()
	if err != nil {
		t.Fatalf("startupDir: %v", err)
	}
	if want := filepath.Join(os.Getenv("APPDATA"), `Microsoft\Windows\Start Menu\Programs\Startup`); dir != want {
		t.Fatalf("startupDir = %q, want %q", dir, want)
	}
}

func TestSpecNormalizedType(t *testing.T) {
	if got := (Spec{}).normalizedType(); got != TypeRun {
		t.Errorf("empty type = %q, want run", got)
	}
	if got := (Spec{Type: "  WMI "}).normalizedType(); got != TypeWMI {
		t.Errorf("WMI type = %q, want wmi", got)
	}
}

func TestAddRemoveValidation(t *testing.T) {
	if err := Add(Spec{Name: "", Command: "x"}); err == nil {
		t.Error("Add accepted an empty name")
	}
	if err := Add(Spec{Name: "x", Command: "  "}); err == nil {
		t.Error("Add accepted an empty command")
	}
	if err := Add(Spec{Type: "bogus", Name: "x", Command: "y"}); err == nil {
		t.Error("Add accepted an unknown type")
	}
	if err := Remove(Spec{Name: ""}); err == nil {
		t.Error("Remove accepted an empty name")
	}
	if err := Remove(Spec{Type: "bogus", Name: "x"}); err == nil {
		t.Error("Remove accepted an unknown type")
	}
}

func TestPsQuote(t *testing.T) {
	got := psQuote(`C:\x.exe /c "a'b"`)
	if !strings.HasPrefix(got, "'") || !strings.HasSuffix(got, "'") {
		t.Fatalf("psQuote not single-quoted: %q", got)
	}
	if !strings.Contains(got, "''") {
		t.Fatalf("psQuote did not double the embedded quote: %q", got)
	}
}

func TestParseTasksCSV(t *testing.T) {
	out := []byte(`"\OBL_nightly","N/A","Ready","Interactive","N/A","0","CORP\a","cmd.exe /c beacon.exe","N/A"` + "\r\n" +
		`"\Microsoft\Windows\Foo","N/A","Ready","Interactive","N/A","0","SYSTEM","%windir%\foo.exe","N/A"` + "\r\n")
	entries := parseTasksCSV(out)
	if len(entries) != 1 {
		t.Fatalf("parseTasksCSV returned %d entries, want 1 (Microsoft task filtered)", len(entries))
	}
	if entries[0].Name != "OBL_nightly" || entries[0].Type != TypeTask {
		t.Fatalf("entry = %+v", entries[0])
	}
	if entries[0].Command != "cmd.exe /c beacon.exe" {
		t.Fatalf("command = %q", entries[0].Command)
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
