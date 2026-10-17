package audit

// WipeFile is deliberately portable (see wipe.go): it is the delete half of the
// lsass-dump cleanup and the cross-platform test below is what caught the old
// Windows-only stub silently reporting "wiped" on a non-Windows build.

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWipeFileRemovesFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "obl-lsass-4242.dmp")
	if err := os.WriteFile(p, []byte("pretend this is a credential dump"), 0o600); err != nil {
		t.Fatalf("seed file: %v", err)
	}
	if err := WipeFile(p); err != nil {
		t.Fatalf("WipeFile: %v", err)
	}
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Fatalf("file still present after WipeFile: stat err = %v", err)
	}
}

func TestWipeFileTruncatesBeforeUnlink(t *testing.T) {
	// A hard link pins the inode: after WipeFile, the other name must observe a
	// zero-length file rather than the original bytes. This is the assertion
	// the old stub failed — it never touched the contents.
	dir := t.TempDir()
	p := filepath.Join(dir, "obl-lsass-1.dmp")
	link := filepath.Join(dir, "pinned.bin")
	secret := []byte("SEKRIT-DUMP-BYTES")
	if err := os.WriteFile(p, secret, 0o600); err != nil {
		t.Fatalf("seed file: %v", err)
	}
	if err := os.Link(p, link); err != nil {
		t.Skipf("hard links unavailable: %v", err)
	}
	if err := WipeFile(p); err != nil {
		t.Fatalf("WipeFile: %v", err)
	}
	got, err := os.ReadFile(link)
	if err != nil {
		t.Fatalf("read linked copy: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("linked copy still holds %d bytes after WipeFile, want 0", len(got))
	}
}

func TestWipeFileMissingFileErrors(t *testing.T) {
	if err := WipeFile(filepath.Join(t.TempDir(), "does-not-exist.dmp")); err == nil {
		t.Error("WipeFile on a missing file: want error, got nil")
	}
}
