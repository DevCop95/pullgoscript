package audit

import "os"

// WipeFile zeros and removes a secrets-bearing file (best effort — a
// journaling filesystem keeps old blocks around until reuse).
//
// This lives outside the windows-only LSASS file on purpose. The delete uses
// no Windows API, and the dashboard's lsass-wipe handler already confines the
// path to an `obl-lsass-*.dmp` directly inside the temp directory before
// calling it, so the operation is safe on any OS. Keeping a single portable
// implementation avoids the failure mode the cross-platform test caught: on a
// non-Windows build the old stub returned nil, so the endpoint answered
// "dump wiped" while the file was still on disk.
func WipeFile(path string) error {
	if f, err := os.OpenFile(path, os.O_WRONLY, 0); err == nil {
		_ = f.Truncate(0)
		_ = f.Close()
	}
	return os.Remove(path)
}
