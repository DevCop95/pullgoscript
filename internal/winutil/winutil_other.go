//go:build !windows

package winutil

// Processes returns an empty table off Windows.
func Processes() []Process { return nil }

// ApplyTelemetryTweaks reports the platform limitation off Windows.
func ApplyTelemetryTweaks() []string {
	return []string{"FAIL: Windows-only operation"}
}
