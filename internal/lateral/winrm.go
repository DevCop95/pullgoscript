package lateral

// WS-Management (WinRM) command execution, hand-rolled.
//
// WinRM is a SOAP-over-HTTP protocol: the client opens a shell resource, sends
// a command line, then repeatedly pulls the output stream until the command
// reports Done. The four operations we need map to four envelopes:
//
//	Create  (ws-transfer/Create)  → opens a cmd shell, returns a ShellId
//	Command (shell/Command)       → queues cmd.exe, returns a CommandId
//	Receive (shell/Receive)       → pulls base64 stdout/stderr, returns state
//	Delete  (ws-transfer/Delete)  → tears the shell down
//
// Authentication here is HTTP Basic, which a lab DC accepts once WinRM is
// configured with AllowUnencrypted + Basic (documented in the module hint).
// That matches the LDAP simple-bind module's stance: this is an in-lab tool,
// not a production-stealth implant. For TLS, pass UseTLS (5986) — Insecure
// skips certificate verification for the self-signed lab listener.

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// WinRM namespace URI constants (DMTF WS-Management + the Microsoft shell
// extension).
const (
	nsSoap   = "http://www.w3.org/2003/05/soap-envelope"
	nsAddr   = "http://schemas.xmlsoap.org/ws/2004/08/addressing"
	nsWsman  = "http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd"
	nsShell  = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell"
	nsXfer   = "http://schemas.xmlsoap.org/ws/2004/09/transfer"
	nsPolicy = "http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd"

	actCreate   = nsXfer + "/Create"
	actDelete   = nsXfer + "/Delete"
	actCommand  = nsShell + "/Command"
	actReceive  = nsShell + "/Receive"
	resourceURI = nsShell + "/cmd"

	maxEnvelope = 153600
)

// WinRMOpts configures one WinRM execution.
type WinRMOpts struct {
	Host     string // "10.0.0.5", "dc.corp.local" or "host:port"
	User     string // DOMAIN\user / user@domain
	Password string
	UseTLS   bool // 5986 + https
	Insecure bool // skip TLS verification (self-signed lab listener)
}

// endpoint renders the WSMan URL for the target, defaulting the port by scheme
// and splitting any explicit port the operator supplied.
func (o WinRMOpts) endpoint() string {
	host := strings.TrimSpace(o.Host)
	scheme, port := "http", "5985"
	if o.UseTLS {
		scheme, port = "https", "5986"
	}
	if h, p, err := net.SplitHostPort(host); err == nil {
		host, port = h, p
	}
	return fmt.Sprintf("%s://%s/wsman", scheme, net.JoinHostPort(host, port))
}

// winrmClient holds the HTTP transport, endpoint and one rendered Basic header
// for the whole session (WinRM keeps the connection alive across the four
// calls, so the credential is computed once).
type winrmClient struct {
	http *http.Client
	url  string
	auth string
}

// WinRMExec runs command on the remote host over WinRM and returns the
// combined stdout (stderr is appended only when stdout is empty, so a tool
// that writes its whole result to stderr is still visible). em may be nil.
func WinRMExec(o WinRMOpts, command string, em Emitter) (string, error) {
	if strings.TrimSpace(o.Host) == "" {
		return "", fmt.Errorf("winrm: host is required")
	}
	if strings.TrimSpace(o.User) == "" {
		return "", fmt.Errorf("winrm: user is required (Basic auth cannot be anonymous)")
	}
	if strings.TrimSpace(command) == "" {
		return "", fmt.Errorf("winrm: command is required")
	}

	c := &winrmClient{
		url:  o.endpoint(),
		auth: "Basic " + base64.StdEncoding.EncodeToString([]byte(o.User+":"+o.Password)),
		http: &http.Client{
			Timeout: 60 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig:       insecureTLS(o.Insecure),
				DisableKeepAlives:     false,
				ResponseHeaderTimeout: 45 * time.Second,
			},
		},
	}

	emit(em, "WINRM: opening shell on "+c.url+" as "+o.User, "INFO")
	shellID, err := c.create(em)
	if err != nil {
		return "", err
	}
	defer func() { _ = c.delete(shellID, em) }()

	emit(em, "WINRM: queuing command ("+strconv.Itoa(len(command))+" bytes)", "INFO")
	commandID, err := c.command(shellID, command)
	if err != nil {
		return "", err
	}

	out, err := c.receiveAll(shellID, commandID, em)
	if err != nil {
		return "", err
	}
	emit(em, "WINRM: command completed on "+o.Host, "SUCCESS")
	return out, nil
}

// create performs the ws-transfer Create that allocates a shell.
func (c *winrmClient) create(em Emitter) (string, error) {
	body := `<rsp:Shell><rsp:InputStreams>stdin</rsp:InputStreams>` +
		`<rsp:OutputStreams>stdout stderr</rsp:OutputStreams></rsp:Shell>`
	resp, err := c.do(actCreate, nil, body)
	if err != nil {
		return "", err
	}
	if resp.shellID == "" {
		return "", faultOr(resp, "winrm: Create returned no ShellId")
	}
	return resp.shellID, nil
}

// command queues the command line inside an existing shell.
func (c *winrmClient) command(shellID, command string) (string, error) {
	// CommandLine carries the whole thing to cmd.exe; /c makes it run and
	// exit. The command is escaped, not shell-quoted — the operator supplies
	// exactly what cmd.exe should receive.
	body := `<rsp:CommandLine><rsp:Command>cmd.exe /c ` + xmlEscape(command) + `</rsp:Command></rsp:CommandLine>`
	resp, err := c.do(actCommand, [][2]string{{"ShellId", shellID}}, body)
	if err != nil {
		return "", err
	}
	if resp.commandID == "" {
		return "", faultOr(resp, "winrm: Command returned no CommandId")
	}
	return resp.commandID, nil
}

// receiveAll pulls stdout/stderr until the command state is Done.
func (c *winrmClient) receiveAll(shellID, commandID string, em Emitter) (string, error) {
	var out, errOut bytes.Buffer
	for i := 0; i < 500; i++ { // hard ceiling: 500×~512 KiB envelope budget
		body := `<rsp:Receive><rsp:DesiredStream CommandId="` + xmlEscape(commandID) +
			`">stdout stderr</rsp:DesiredStream></rsp:Receive>`
		resp, err := c.do(actReceive, [][2]string{{"ShellId", shellID}}, body)
		if err != nil {
			return "", err
		}
		out.Write(resp.stdout)
		errOut.Write(resp.stderr)
		if resp.done {
			if len(out.Bytes()) == 0 {
				out.Write(errOut.Bytes())
			}
			return strings.TrimRight(out.String(), "\r\n"), nil
		}
	}
	return "", fmt.Errorf("winrm: receive loop did not reach Done (500 iterations)")
}

// delete tears the shell down; failures are non-fatal (the shell is reaped by
// the server when the TCP session closes).
func (c *winrmClient) delete(shellID string, em Emitter) error {
	_, err := c.do(actDelete, [][2]string{{"ShellId", shellID}}, "")
	return err
}

// do sends one envelope and decodes the response.
func (c *winrmClient) do(action string, selectors [][2]string, body string) (*winrmResponse, error) {
	env := winrmEnvelope(action, c.url, newMessageID(), selectors, body)
	req, err := http.NewRequest(http.MethodPost, c.url, strings.NewReader(env))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/soap+xml;charset=UTF-8")
	req.Header.Set("Authorization", c.auth)
	// WinRM expects these; the shell resource also negotiates them.
	req.Header.Set("User-Agent", "Microsoft WinRM Client")
	req.Header.Set("Connection", "Keep-Alive")

	res, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("winrm: transport: %w", err)
	}
	defer res.Body.Close()
	data, err := io.ReadAll(io.LimitReader(res.Body, 8<<20))
	if err != nil {
		return nil, fmt.Errorf("winrm: read response: %w", err)
	}
	if res.StatusCode != http.StatusOK {
		r, perr := parseWinRM(data)
		if perr == nil && r.fault != "" {
			return nil, fmt.Errorf("winrm: HTTP %d: %s", res.StatusCode, r.fault)
		}
		return nil, fmt.Errorf("winrm: HTTP %d from %s", res.StatusCode, c.url)
	}
	r, err := parseWinRM(data)
	if err != nil {
		return nil, err
	}
	if r.fault != "" {
		return nil, fmt.Errorf("winrm: %s", r.fault)
	}
	return r, nil
}

// winrmEnvelope renders one SOAP request. SelectorSet is omitted when empty
// (Create carries none; everything else carries ShellId, plus CommandId inside
// the body for Receive).
func winrmEnvelope(action, endpoint, msgID string, selectors [][2]string, body string) string {
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>`)
	b.WriteString(`<s:Envelope xmlns:s="` + nsSoap + `" xmlns:a="` + nsAddr +
		`" xmlns:w="` + nsWsman + `" xmlns:rsp="` + nsShell + `" xmlns:p="` + nsPolicy + `">`)
	b.WriteString(`<s:Header>`)
	b.WriteString(`<a:To s:mustUnderstand="true">` + xmlEscape(endpoint) + `</a:To>`)
	b.WriteString(`<w:ResourceURI s:mustUnderstand="true">` + resourceURI + `</w:ResourceURI>`)
	b.WriteString(`<a:ReplyTo><a:Address s:mustUnderstand="true">` + nsAddr + `/role/anonymous</a:Address></a:ReplyTo>`)
	b.WriteString(`<a:Action s:mustUnderstand="true">` + action + `</a:Action>`)
	b.WriteString(`<w:MaxEnvelopeSize s:mustUnderstand="true">` + strconv.Itoa(maxEnvelope) + `</w:MaxEnvelopeSize>`)
	b.WriteString(`<a:MessageID>uuid:` + msgID + `</a:MessageID>`)
	b.WriteString(`<w:Locale s:mustUnderstand="false" xml:lang="en-US"/>`)
	b.WriteString(`<p:DataLocale s:mustUnderstand="false" xml:lang="en-US"/>`)
	b.WriteString(`<w:OperationTimeout>PT60S</w:OperationTimeout>`)
	if len(selectors) > 0 {
		b.WriteString(`<w:SelectorSet>`)
		for _, s := range selectors {
			b.WriteString(`<w:Selector Name="` + s[0] + `">` + xmlEscape(s[1]) + `</w:Selector>`)
		}
		b.WriteString(`</w:SelectorSet>`)
	}
	b.WriteString(`</s:Header><s:Body>`)
	b.WriteString(body)
	b.WriteString(`</s:Body></s:Envelope>`)
	return b.String()
}

// newMessageID returns a random RFC-4122-shaped GUID string for the WSMan
// MessageID header (the format WinRM expects after the "uuid:" prefix).
func newMessageID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return strconv.FormatInt(time.Now().UnixNano(), 16)
	}
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant 10
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// winrmResponse is the slice of a WSMan reply this module cares about.
type winrmResponse struct {
	shellID   string
	commandID string
	stdout    []byte
	stderr    []byte
	done      bool
	exitCode  int
	fault     string
}

// parseWinRM walks the response token stream and extracts the ShellId /
// CommandId selectors, the base64 Stream payloads, the CommandState/ExitCode
// and any SOAP fault. A token walk (rather than struct unmarshalling) is used
// because the responses mix several namespaces with variant prefixes.
func parseWinRM(data []byte) (*winrmResponse, error) {
	resp := &winrmResponse{exitCode: -1}
	dec := xml.NewDecoder(bytes.NewReader(data))

	var (
		buf        strings.Builder
		kind       string // "selector" | "stream" | "exitcode" | "fault"
		selName    string
		stName     string
		faultDepth int
	)
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("winrm: decode response: %w", err)
		}
		switch e := tok.(type) {
		case xml.StartElement:
			buf.Reset()
			kind = ""
			switch strings.ToLower(e.Name.Local) {
			case "selector":
				selName = attrOf(e, "Name")
				if selName == "ShellId" || selName == "CommandId" {
					kind = "selector"
				}
			case "stream":
				stName = strings.ToLower(attrOf(e, "Name"))
				kind = "stream"
			case "commandstate":
				if strings.HasSuffix(attrOf(e, "State"), "/Done") {
					resp.done = true
				}
			case "exitcode":
				kind = "exitcode"
			case "fault":
				faultDepth++
				kind = "fault"
			case "text", "reason", "faultstring":
				// SOAP 1.2 carries the message in Fault/Reason/Text; SOAP 1.1
				// in Fault/faultstring.
				if faultDepth > 0 {
					kind = "fault"
				}
			}
		case xml.CharData:
			if kind != "" {
				buf.Write([]byte(e))
			}
		case xml.EndElement:
			v := strings.TrimSpace(buf.String())
			switch kind {
			case "selector":
				if selName == "ShellId" {
					resp.shellID = v
				} else if selName == "CommandId" {
					resp.commandID = v
				}
			case "stream":
				if raw, err := base64DecodeLoose(v); err == nil {
					switch stName {
					case "stdout":
						resp.stdout = append(resp.stdout, raw...)
					case "stderr":
						resp.stderr = append(resp.stderr, raw...)
					}
				}
			case "exitcode":
				if n, err := strconv.Atoi(v); err == nil {
					resp.exitCode = n
				}
			case "fault":
				if resp.fault == "" {
					resp.fault = v
				} else if v != "" && !strings.Contains(resp.fault, v) {
					resp.fault += " " + v
				}
			}
			kind = ""
			if faultDepth > 0 && strings.ToLower(e.Name.Local) == "fault" {
				faultDepth--
			}
		}
	}
	return resp, nil
}

func attrOf(e xml.StartElement, name string) string {
	for _, a := range e.Attr {
		if a.Name.Local == name {
			return a.Value
		}
	}
	return ""
}

// base64DecodeLoose decodes base64 that may carry embedded whitespace (WinRM
// wraps long streams).
func base64DecodeLoose(s string) ([]byte, error) {
	if !strings.ContainsAny(s, " \t\r\n") {
		return base64.StdEncoding.DecodeString(s)
	}
	clean := strings.Map(func(r rune) rune {
		switch r {
		case ' ', '\t', '\r', '\n':
			return -1
		}
		return r
	}, s)
	return base64.StdEncoding.DecodeString(clean)
}

// faultOr returns the parsed SOAP fault when present, else fallback.
func faultOr(resp *winrmResponse, fallback string) error {
	if resp.fault != "" {
		return fmt.Errorf("winrm: %s", resp.fault)
	}
	return fmt.Errorf("%s", fallback)
}
