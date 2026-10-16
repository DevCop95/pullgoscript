// Command obliteratus is the OBLITERATUS Windows credential-exposure
// auditor and local red-team dashboard.
//
// Two modes:
//
//	--audit    headless Mimikatz attack-surface audit (prints a report and
//	           exits; exit code 1 when a CRITICAL/HIGH control is failing)
//	default    local dashboard on 127.0.0.1 with an ephemeral token
//
// Offensive modules are OFF unless explicitly unlocked:
//
//	--enable-collect   browser credential/cookie collection (authorised use)
//	--enable-persist   persistence manager T1547/T1053/T1546 (authorised use)
//	--enable-evasion   self-telemetry evasion: neuter ETW/AMSI in this process
//	--enable-lateral   lateral movement: WinRM + SCM remote execution
//	--enable-inject    Halo's Gate process-injection research module
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/DevCop95/obliteratus/internal/audit"
	"github.com/DevCop95/obliteratus/internal/elevate"
	"github.com/DevCop95/obliteratus/internal/server"
	"github.com/DevCop95/obliteratus/internal/token"
)

// version is the release identifier shown in /v1/sys/st and audit reports.
const version = "2.0.0"

func main() {
	// Hidden internal mode: the collector re-launches this binary as SYSTEM
	// (one-shot scheduled task) to unwrap the Chromium App-Bound master key.
	// Reached only via runABESystemTask; never advertised in -h.
	if len(os.Args) >= 4 && os.Args[1] == "-abe-helper" {
		os.Exit(audit.ABEHelper(os.Args[2], os.Args[3]))
	}

	var (
		addr        = flag.String("addr", server.DefaultAddr, "listen address (must be loopback)")
		collect     = flag.Bool("enable-collect", false, "UNLOCK credential/cookie collection (authorised engagements only)")
		persist     = flag.Bool("enable-persist", false, "UNLOCK the persistence manager (authorised engagements only)")
		evasion     = flag.Bool("enable-evasion", false, "UNLOCK self-telemetry evasion (authorised engagements only)")
		lateral     = flag.Bool("enable-lateral", false, "UNLOCK lateral movement (WinRM + SCM, authorised engagements only)")
		inject      = flag.Bool("enable-inject", false, "UNLOCK the process-injection research module")
		elevateFlag = flag.Bool("elevate", false, "re-launch this process elevated via UAC")
		auditOnly   = flag.Bool("audit", false, "run the Mimikatz attack-surface audit headlessly and exit")
		jsonOut     = flag.Bool("json", false, "with --audit: emit the report as JSON")
		csvOut      = flag.Bool("csv", false, "with --audit: emit the report as CSV")
		payload     = flag.String("payload", "payloads/research_signal.bin", "payload file for the injection module")
		payloadKey  = flag.String("payload-key", "", "passphrase to unpack a packed payload (see cmd/oblpack)")
		showVersion = flag.Bool("version", false, "print version and exit")
	)
	flag.Parse()

	if *showVersion {
		fmt.Printf("obliteratus %s\n", version)
		return
	}

	elevated := elevate.IsAdmin()
	modules := map[string]bool{
		"collect": *collect,
		"inject":  *inject,
		"persist": *persist,
		"evasion": *evasion,
		"lateral": *lateral,
		"console": true,
	}

	// ------------------------------------------------------------------ audit
	if *auditOnly {
		rep := audit.BuildReport(version, elevated, modules)
		switch {
		case *jsonOut:
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			_ = enc.Encode(rep)
		case *csvOut:
			fmt.Print(rep.CSV())
		default:
			fmt.Print(rep.String())
		}
		// Contract for CI/scripting: exit 1 only when a CRITICAL or HIGH
		// control is actually failing (warnings/info never fail the run).
		if rep.WorstSeverity() <= audit.High {
			os.Exit(1)
		}
		return
	}

	// --------------------------------------------------------------- elevation
	if *elevateFlag {
		elevate.RunElevated() // returns only when already elevated
	}

	// ---------------------------------------------------------------- server
	tok, err := token.New()
	if err != nil {
		log.Fatalf("[!] cannot generate API token: %v", err)
	}

	srv := server.New(server.Config{
		Token:         tok,
		Version:       version,
		Addr:          *addr,
		EnableCollect: *collect,
		EnablePersist: *persist,
		EnableEvasion: *evasion,
		EnableLateral: *lateral,
		EnableInject:  *inject,
		PayloadPath:   *payload,
		PayloadKey:    *payloadKey,
		Elevated:      elevated,
	})

	if *collect {
		log.Printf("[!] credential collection UNLOCKED (--enable-collect): authorised targets only")
	}
	if *persist {
		log.Printf("[!] persistence module UNLOCKED (--enable-persist): authorised targets only")
	}
	if *evasion {
		log.Printf("[!] evasion module UNLOCKED (--enable-evasion): authorised targets only")
	}
	if *lateral {
		log.Printf("[!] lateral movement UNLOCKED (--enable-lateral): authorised targets only")
	}
	if *inject {
		log.Printf("[!] injection module UNLOCKED (--enable-inject): authorised targets only")
	}

	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("[!] server stopped: %v", err)
	}
}
