//go:build windows

package audit

import (
	"errors"
	"fmt"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// RunChecks executes the full Mimikatz attack-surface audit and returns the
// findings in severity order (already Finalized by BuildReport).
//
// Every check is designed to degrade to StatusUnknown (never to a false pass)
// when the required privilege or asset is missing.
func RunChecks(elevated bool) []Finding {
	checks := []func() Finding{
		checkWDigest,
		checkLsassPPL,
		checkCredentialGuard,
		func() Finding { return checkSeDebug(elevated) },
		checkAutologonPassword,
		checkAutologon,
		checkPowerShellLogging,
		checkDefender,
		checkSysmon,
		checkLAPS,
		checkCachedLogons,
		func() Finding { return checkRunContext(elevated) },
	}
	var findings []Finding
	for _, c := range checks {
		findings = append(findings, c())
	}
	return findings
}

// BuildReport runs RunChecks and wraps the result in a finalized Report.
func BuildReport(version string, elevated bool, modules map[string]bool) *Report {
	r := NewReport(version, elevated, modules)
	for _, f := range RunChecks(elevated) {
		r.Add(f)
	}
	r.Finalize()
	return r
}

// ---------------------------------------------------------------------------
// registry helpers
// ---------------------------------------------------------------------------

// regDWORD returns (value, present, error).
func regDWORD(root registry.Key, path, name string) (uint32, bool, error) {
	k, err := registry.OpenKey(root, path, registry.QUERY_VALUE)
	if err != nil {
		return 0, false, err
	}
	defer k.Close()
	v, _, err := k.GetIntegerValue(name)
	if err != nil {
		if errors.Is(err, registry.ErrNotExist) {
			return 0, false, nil
		}
		return 0, false, err
	}
	return uint32(v), true, nil //#nosec G115 -- REG_DWORD is 32-bit by definition; values above 4 GiB cannot occur
}

// regSZ returns (value, present, error).
func regSZ(root registry.Key, path, name string) (string, bool, error) {
	k, err := registry.OpenKey(root, path, registry.QUERY_VALUE)
	if err != nil {
		return "", false, err
	}
	defer k.Close()
	v, _, err := k.GetStringValue(name)
	if err != nil {
		if errors.Is(err, registry.ErrNotExist) {
			return "", false, nil
		}
		return "", false, err
	}
	return v, true, nil
}

// regKeyExists reports whether a key can be opened for read.
func regKeyExists(root registry.Key, path string) bool {
	k, err := registry.OpenKey(root, path, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	k.Close()
	return true
}

// ---------------------------------------------------------------------------
// checks
// ---------------------------------------------------------------------------

// checkWDigest covers `sekurlsa::wdigest` — the classic plaintext-credential
// cache in LSASS (CVE-2010-... era technique, still decisive today).
func checkWDigest() Finding {
	const path = `SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest`
	f := Finding{
		ID:          "MK-WDIGEST",
		Title:       "WDigest does not cache plaintext credentials",
		Severity:    Critical,
		Technique:   "T1003.001",
		Module:      "sekurlsa::wdigest",
		Remediation: `Set HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential = 0 (DWORD) and reboot.`,
	}
	v, present, err := regDWORD(registry.LOCAL_MACHINE, path, "UseLogonCredential")
	switch {
	case err != nil:
		f.Status, f.Evidence = StatusUnknown, "registry unreadable: "+err.Error()
	case present && v == 1:
		f.Status = StatusFail
		f.Evidence = "UseLogonCredential=1 — cleartext passwords sit in LSASS memory after logon."
	case present:
		f.Status = StatusPass
		f.Evidence = fmt.Sprintf("UseLogonCredential=%d", v)
	default:
		f.Status = StatusPass
		f.Evidence = "UseLogonCredential not set (defaults to 0)."
	}
	return f
}

// checkLsassPPL covers LSASS running as a Protected Process Light, which is
// the primary control against `sekurlsa::logonpasswords`.
func checkLsassPPL() Finding {
	const path = `SYSTEM\CurrentControlSet\Control\Lsa`
	f := Finding{
		ID:          "MK-LSASS-PPL",
		Title:       "LSASS runs as a protected process (PPL)",
		Severity:    High,
		Technique:   "T1003.001",
		Module:      "sekurlsa::logonpasswords",
		Remediation: `Set HKLM\SYSTEM\CurrentControlSet\Control\Lsa\RunAsPPL = 1 (DWORD) and reboot. Enable UEFI Secure Boot to allow RunAsPPL=2.`,
	}
	v, present, err := regDWORD(registry.LOCAL_MACHINE, path, "RunAsPPL")
	switch {
	case err != nil:
		f.Status, f.Evidence = StatusUnknown, "registry unreadable: "+err.Error()
	case present && v > 0:
		f.Status = StatusPass
		f.Evidence = fmt.Sprintf("RunAsPPL=%d — non-protected processes cannot open LSASS.", v)
	default:
		f.Status = StatusFail
		f.Evidence = "RunAsPPL absent/0 — LSASS accepts PROCESS_VM_READ from any token with SeDebugPrivilege."
	}
	return f
}

// checkCredentialGuard covers hardware-isolated credential storage
// (`sekurlsa` cannot reach NTLM/hash material when VBS + LSA config are on).
func checkCredentialGuard() Finding {
	const (
		lsaPath = `SYSTEM\CurrentControlSet\Control\Lsa`
		dgPath  = `SYSTEM\CurrentControlSet\Control\DeviceGuard`
	)
	f := Finding{
		ID:          "MK-CREDGUARD",
		Title:       "Credential Guard / virtualization-based security enabled",
		Severity:    High,
		Technique:   "T1003.001",
		Module:      "sekurlsa::logonpasswords",
		Remediation: "Enable Credential Guard (GPO: Computer Configuration > Administrative Templates > System > Device Guard > Turn On Virtualization Based Security) with LsaCfgFlags = 1.",
	}
	lcfg, lcfgPresent, lerr := regDWORD(registry.LOCAL_MACHINE, lsaPath, "LsaCfgFlags")
	vbs, vbsPresent, verr := regDWORD(registry.LOCAL_MACHINE, dgPath, "EnableVirtualizationBasedSecurity")
	switch {
	case lerr != nil || verr != nil:
		f.Status, f.Evidence = StatusUnknown, "registry unreadable (Device Guard / Lsa keys)"
	case lcfgPresent && lcfg > 0:
		f.Status = StatusPass
		f.Evidence = fmt.Sprintf("LsaCfgFlags=%d, EnableVirtualizationBasedSecurity=%d", lcfg, vbs)
	case vbsPresent && vbs > 0:
		f.Status = StatusPass
		f.Evidence = fmt.Sprintf("VBS enabled (EnableVirtualizationBasedSecurity=%d) — verify LsaCfgFlags manually.", vbs)
	default:
		f.Status = StatusFail
		f.Evidence = "Credential Guard not configured — domain NTLM/hash material is recoverable from LSASS."
	}
	return f
}

// checkSeDebug reports whether this very token could open LSASS. Enabled
// SeDebugPrivilege plus a non-PPL LSASS is the full `sekurlsa` precondition.
func checkSeDebug(elevated bool) Finding {
	f := Finding{
		ID:          "MK-SEDEBUG",
		Title:       "SeDebugPrivilege not enabled in the current token",
		Severity:    High,
		Technique:   "T1134.001",
		Module:      "privilege::debug",
		Remediation: "Run OBLITERATUS unelevated for audits; on workstations, drop local-admin rights for daily accounts (LSASS PPL is the compensating control for admins).",
	}
	present, enabled, err := tokenSeDebug()
	switch {
	case err != nil:
		f.Status, f.Evidence = StatusUnknown, "token query failed: "+err.Error()
	case !present:
		f.Status = StatusPass
		f.Evidence = "SeDebugPrivilege not present in token."
	case enabled:
		f.Status = StatusFail
		f.Evidence = fmt.Sprintf("SeDebugPrivilege ENABLED (elevated=%v) — LSASS is openable unless it runs as PPL (see MK-LSASS-PPL).", elevated)
	default:
		f.Status = StatusPass
		f.Evidence = "SeDebugPrivilege present but disabled."
	}
	return f
}

// tokenSeDebug inspects the current process token for SeDebugPrivilege.
func tokenSeDebug() (present, enabled bool, err error) {
	var token windows.Token
	if err = windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &token); err != nil {
		return false, false, err
	}
	defer token.Close()

	var needed uint32
	_ = windows.GetTokenInformation(token, windows.TokenPrivileges, nil, 0, &needed)
	if needed == 0 {
		return false, false, errors.New("TokenPrivileges length 0")
	}
	buf := make([]byte, needed)
	if err = windows.GetTokenInformation(token, windows.TokenPrivileges, &buf[0], needed, &needed); err != nil {
		return false, false, err
	}
	tp := (*windows.Tokenprivileges)(unsafe.Pointer(&buf[0]))

	var debugLUID windows.LUID
	if err = windows.LookupPrivilegeValue(nil, windows.StringToUTF16Ptr("SeDebugPrivilege"), &debugLUID); err != nil {
		return false, false, err
	}
	for _, p := range tp.AllPrivileges() {
		if p.Luid == debugLUID {
			return true, p.Attributes&windows.SE_PRIVILEGE_ENABLED != 0, nil
		}
	}
	return false, false, nil
}

// checkAutologonPassword flags cleartext autologon passwords in the registry
// (`cmdkey /list` + mimikatz-equivalent offline read; also T1552.001).
func checkAutologonPassword() Finding {
	const path = `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`
	f := Finding{
		ID:          "MK-AUTOLOGON-PASS",
		Title:       "No cleartext password stored in Winlogon",
		Severity:    Critical,
		Technique:   "T1552.001",
		Module:      "winlogon (DefaultPassword)",
		Remediation: `Delete HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\DefaultPassword and set AutoAdminLogon=0.`,
	}
	v, present, err := regSZ(registry.LOCAL_MACHINE, path, "DefaultPassword")
	switch {
	case err != nil:
		f.Status, f.Evidence = StatusUnknown, "registry unreadable: "+err.Error()
	case present && strings.TrimSpace(v) != "":
		f.Status = StatusFail
		f.Evidence = "Winlogon\\DefaultPassword is set and readable by any local user."
	default:
		f.Status = StatusPass
		f.Evidence = "Winlogon\\DefaultPassword absent."
	}
	return f
}

// checkAutologon flags automatic logon enabled at all (password then lives in
// LSA secrets, dumpable offline from the registry hive).
func checkAutologon() Finding {
	const path = `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`
	f := Finding{
		ID:          "MK-AUTOLOGON",
		Title:       "Automatic logon disabled",
		Severity:    Medium,
		Technique:   "T1003.004",
		Module:      "lsadump::secrets",
		Remediation: `Set HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\AutoAdminLogon = 0.`,
	}
	v, present, err := regSZ(registry.LOCAL_MACHINE, path, "AutoAdminLogon")
	switch {
	case err != nil:
		f.Status, f.Evidence = StatusUnknown, "registry unreadable: "+err.Error()
	case present && v == "1":
		f.Status = StatusFail
		f.Evidence = "AutoAdminLogon=1 — the account secret is recoverable from the SAM/LSA hive offline."
	default:
		f.Status = StatusPass
		f.Evidence = fmt.Sprintf("AutoAdminLogon=%q (default off).", v)
	}
	return f
}

// checkPowerShellLogging verifies that script/module transcription exists —
// without it, an attacker's PowerShell-based credential access (and our own
// tooling) leaves no telemetry.
func checkPowerShellLogging() Finding {
	f := Finding{
		ID:          "MK-PSLOG",
		Title:       "PowerShell Script Block Logging enabled",
		Severity:    Medium,
		Technique:   "T1059.001",
		Module:      "misc (detection gap)",
		Remediation: `Enable Computer Configuration > Administrative Templates > Windows Components > Windows PowerShell: Turn on Script Block Logging, Module Logging and Transcription.`,
	}
	sb, sbPresent, _ := regDWORD(registry.LOCAL_MACHINE, `SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging`, "EnableScriptBlockLogging")
	ml, mlPresent, _ := regDWORD(registry.LOCAL_MACHINE, `SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging`, "EnableModuleLogging")
	tr, trPresent, _ := regDWORD(registry.LOCAL_MACHINE, `SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription`, "EnableTranscripting")
	enabled := 0
	for _, x := range [][2]interface{}{
		{sbPresent, sb}, {mlPresent, ml}, {trPresent, tr},
	} {
		if x[0].(bool) && x[1].(uint32) != 0 {
			enabled++
		}
	}
	f.Evidence = fmt.Sprintf("scriptblock=%d module=%d transcript=%d", sb, ml, tr)
	if enabled == 0 {
		f.Status = StatusFail
		f.Evidence += " — no PowerShell telemetry sources configured."
	} else {
		f.Status = StatusPass
	}
	return f
}

// checkDefender verifies endpoint protection is installed, enabled and has
// not been tampered with.
//
// Implementation note: we deliberately do NOT query the SCM. Defender's
// service ACL denies OpenService even to elevated admins (by design), which
// would force every healthy host into status "unknown". Reading
// SYSTEM\CurrentControlSet\Services\WinDefend\Start is locale-independent,
// works without privilege, and still answers "is it configured to run?".
func checkDefender() Finding {
	f := Finding{
		ID:          "MK-AV",
		Title:       "Endpoint protection installed and enabled",
		Severity:    High,
		Technique:   "T1562.001",
		Module:      "misc (defense evasion)",
		Remediation: "Re-enable Defender real-time protection (or verify third-party AV/EDR policy) and investigate how it was switched off.",
	}
	if v, present, err := regDWORD(registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Windows Defender\Real-Time Protection`, "DisableRealtimeMonitoring"); err == nil && present && v == 1 {
		f.Status = StatusFail
		f.Evidence = "DisableRealtimeMonitoring=1 — real-time scanning has been switched off."
		return f
	}
	start, present, err := serviceStart("WinDefend")
	switch {
	case err != nil:
		f.Status, f.Evidence = StatusUnknown, "registry unreadable: "+err.Error()
	case !present:
		// No Defender service: either a third-party AV replaced it (fine) or
		// the host runs bare (not fine) — this probe cannot tell which.
		f.Status = StatusUnknown
		f.Evidence = "WinDefend service key absent — verify third-party AV/EDR manually (this check cannot see it)."
	case start == 4:
		f.Status = StatusFail
		f.Evidence = "WinDefend Start=4 (SERVICE_DISABLED)."
	default:
		f.Status = StatusPass
		f.Evidence = fmt.Sprintf("WinDefend Start=%d (%s); no DisableRealtimeMonitoring tamper flag.", start, serviceStartName(start))
	}
	return f
}

// checkSysmon verifies host-based telemetry exists for LSASS access attempts.
func checkSysmon() Finding {
	f := Finding{
		ID:          "MK-SYSMON",
		Title:       "Sysmon (or equivalent EDR telemetry) installed",
		Severity:    Low,
		Module:      "misc (detection gap)",
		Remediation: "Deploy Sysmon with a config that logs process access to lsass.exe (Event ID 10) plus process creation (Event ID 1).",
	}
	disabled := ""
	for _, name := range []string{"Sysmon", "SysmonDrv", "Sense"} {
		start, present, err := serviceStart(name)
		if err != nil || !present {
			continue
		}
		if start == 4 {
			disabled = fmt.Sprintf(" (%s disabled)", name)
			continue
		}
		f.Status = StatusPass
		f.Evidence = fmt.Sprintf("service %s installed, Start=%d.", name, start)
		return f
	}
	f.Status = StatusFail
	f.Evidence = "No enabled Sysmon/MDE Sense service found — LSASS access attempts are not logged." + disabled
	return f
}

// serviceStart reads the start type of a service from its SCM registry key:
// 2=auto, 3=demand, 4=disabled.
func serviceStart(name string) (uint32, bool, error) {
	return regDWORD(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Services\`+name, "Start")
}

// serviceStartName maps a service Start value to its symbolic name.
func serviceStartName(v uint32) string {
	switch v {
	case 0:
		return "SERVICE_BOOT_START"
	case 1:
		return "SERVICE_SYSTEM_START"
	case 2:
		return "SERVICE_AUTO_START"
	case 3:
		return "SERVICE_DEMAND_START"
	default:
		return fmt.Sprintf("start=%d", v)
	}
}

// checkLAPS verifies a managed local-administrator password (password reuse
// across hosts turns one workstation compromise into domain-wide admin).
func checkLAPS() Finding {
	f := Finding{
		ID:          "MK-LAPS",
		Title:       "Managed local admin password (LAPS) in use",
		Severity:    Medium,
		Technique:   "T1078.002",
		Module:      "lsadump::dcsync (adjacent)",
		Remediation: "Deploy Windows LAPS (GPO: LAPS > Backup directory + Password Encryption) or legacy LAPS with AdmPwdEnabled=1.",
	}
	type probe struct {
		path  string
		name  string
		min   uint32
		label string
	}
	probes := []probe{
		{`SOFTWARE\Microsoft\Policies\Laps`, "BackupDirectory", 1, "Windows LAPS policy BackupDirectory"},
		{`SOFTWARE\Policies\Microsoft\Services\LAPS`, "AdmPwdEnabled", 1, "legacy LAPS AdmPwdEnabled"},
	}
	for _, p := range probes {
		if v, present, err := regDWORD(registry.LOCAL_MACHINE, p.path, p.name); err == nil && present && v >= p.min {
			f.Status = StatusPass
			f.Evidence = fmt.Sprintf("%s = %d.", p.label, v)
			return f
		}
	}
	if regKeyExists(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\LAPS\State`) {
		f.Status = StatusPass
		f.Evidence = "Legacy LAPS state key present (password rotation active)."
		return f
	}
	f.Status = StatusFail
	f.Evidence = "No LAPS policy/state detected — the local Administrator password is likely static and shared across hosts."
	return f
}

// checkCachedLogons reports how many cached domain credentials exist (offline
// domain logon cache; dumpable from the registry hive by lsadump::cache).
func checkCachedLogons() Finding {
	const path = `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`
	f := Finding{
		ID:          "MK-CACHEDLOGONS",
		Title:       "Cached domain logon count reviewed",
		Severity:    Info,
		Technique:   "T1003.005",
		Module:      "lsadump::cache",
		Remediation: "Lower CachedLogonsCount (GPO: Interactive logon: Number of previous logons to cache) if offline domain logon is not required.",
	}
	// CachedLogonsCount is REG_SZ on real hosts — try DWORD first (defensive)
	// then fall back to the string form.
	if v, present, err := regDWORD(registry.LOCAL_MACHINE, path, "CachedLogonsCount"); err == nil && present {
		f.Status = StatusPass
		f.Evidence = fmt.Sprintf("CachedLogonsCount=%d — each cached entry is a NT-hash-equivalent offline.", v)
		return f
	}
	if v, present, err := regSZ(registry.LOCAL_MACHINE, path, "CachedLogonsCount"); err == nil && present {
		f.Status = StatusPass
		f.Evidence = fmt.Sprintf("CachedLogonsCount=%s (REG_SZ) — each cached entry is a NT-hash-equivalent offline.", v)
		return f
	}
	f.Status = StatusPass
	f.Evidence = "CachedLogonsCount not set (default 10 on workstations)."
	return f
}

// checkRunContext documents the privilege level this audit ran at — unknown
// checks must be re-run elevated to be trusted.
func checkRunContext(elevated bool) Finding {
	f := Finding{
		ID:          "MK-CONTEXT",
		Title:       "Audit execution context",
		Severity:    Info,
		Status:      StatusPass,
		Remediation: "Re-run with --elevate if any check returned 'unknown'.",
	}
	if elevated {
		f.Evidence = "running elevated"
	} else {
		f.Evidence = "running WITHOUT elevation — some checks may return 'unknown'"
	}
	return f
}
