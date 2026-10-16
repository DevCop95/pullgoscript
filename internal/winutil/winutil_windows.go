//go:build windows

package winutil

import (
	"encoding/csv"
	"os/exec"
	"strings"
	"syscall"

	"golang.org/x/sys/windows/registry"
)

// Processes enumerates running processes via tasklist (CSV output). The
// child window is hidden so a console never flashes on the operator desktop.
func Processes() []Process {
	cmd := exec.Command("tasklist", "/V", "/FO", "CSV", "/NH")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, err := cmd.Output()
	if err != nil {
		return nil
	}
	rows, err := csv.NewReader(strings.NewReader(string(out))).ReadAll()
	if err != nil {
		return nil
	}
	var procs []Process
	for _, r := range rows {
		// tasklist /V columns: name, pid, session#, session name, mem, status, user...
		if len(r) >= 7 {
			procs = append(procs, Process{PID: r[1], Name: r[0], User: r[6], Mem: r[4]})
		}
	}
	return procs
}

// ApplyTelemetryTweaks hardens Windows telemetry/privacy settings and stops
// the DiagTrack service. Each line is a self-describing result for the UI log
// ("SUCCESS: x" / "FAIL: x (Access Denied)"). Requires elevation.
func ApplyTelemetryTweaks() []string {
	var results []string
	tweaks := []struct {
		path  string
		name  string
		value uint32
	}{
		{`SOFTWARE\Policies\Microsoft\Windows\DataCollection`, "AllowTelemetry", 0},
		{`SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting`, "Disabled", 1},
		{`SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced`, "Start_TrackProgs", 0},
	}
	for _, t := range tweaks {
		k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, t.path, registry.SET_VALUE|registry.QUERY_VALUE)
		if err == nil {
			err = k.SetDWordValue(t.name, t.value)
			k.Close()
		}
		if err != nil {
			results = append(results, "FAIL: "+t.name+" (Access Denied)")
		} else {
			results = append(results, "SUCCESS: "+t.name)
		}
	}
	// Stop and disable the Connected User Experiences telemetry service.
	_ = exec.Command("sc", "stop", "DiagTrack").Run()
	_ = exec.Command("sc", "config", "DiagTrack", "start=disabled").Run()
	results = append(results, "SUCCESS: DiagTrack_OFF")
	return results
}
