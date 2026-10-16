// Package winutil wraps the small set of Windows system operations the
// dashboard needs: process enumeration and privacy/telemetry hardening.
package winutil

// Process is a row of the process table shown in the UI.
type Process struct {
	PID  string `json:"pid"`
	Name string `json:"name"`
	User string `json:"user"`
	Mem  string `json:"mem"`
}
