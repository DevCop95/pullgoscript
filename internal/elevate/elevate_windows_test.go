//go:build windows

package elevate

import (
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

// The error type carries the only message the operator sees when UAC is
// declined, and MarkerArg is the handshake that tells the elevated child it was
// launched by RelaunchElevated rather than by hand. Both are cheap to pin.
func TestElevateErrorAndMarker(t *testing.T) {
	if errCancelled.Error() == "" {
		t.Error("errCancelled must carry a message for the operator")
	}
	var err error = elevateError("boom")
	if err.Error() != "boom" {
		t.Errorf("elevateError(\"boom\").Error() = %q", err.Error())
	}
	if !strings.Contains(MarkerArg, "elevation") {
		t.Errorf("MarkerArg = %q, want the documented -elevation-attempted handshake", MarkerArg)
	}
	// StripMarker must recognise exactly what RelaunchElevated appends.
	if _, ok := StripMarker([]string{"obl.exe", MarkerArg}); !ok {
		t.Error("StripMarker did not recognise the marker RelaunchElevated appends")
	}
}

// TestIsAdminAgreesWithToken exercises IsAdmin without elevating anything; on a
// non-elevated CI runner it must report false, on an elevated shell true.
func TestIsAdminAgreesWithToken(t *testing.T) {
	got := IsAdmin()

	var token windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &token); err != nil {
		t.Skipf("cannot open own process token: %v", err)
	}
	defer token.Close()
	if want := token.IsElevated(); got != want {
		t.Errorf("IsAdmin() = %v, want %v (token says %v)", got, want, want)
	}
}
