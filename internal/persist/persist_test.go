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

// TestAddRemoveValidation exercises the validation that runs before the
// platform backend is chosen, so it is meaningful on every OS.
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
