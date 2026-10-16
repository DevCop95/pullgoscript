package lateral

import (
	"strings"
	"testing"
)

func TestSplitUser(t *testing.T) {
	cases := []struct {
		in         string
		wantDomain string
		wantName   string
	}{
		{`CORP\alice`, "CORP", "alice"},
		{"alice@corp.local", "corp.local", "alice"},
		{"bob", "", "bob"},
		{`CORP\svc$`, "CORP", "svc$"},
		{"  CORP\\alice  ", "CORP", "alice"},
	}
	for _, c := range cases {
		d, n := splitUser(c.in)
		if d != c.wantDomain || n != c.wantName {
			t.Errorf("splitUser(%q) = (%q,%q), want (%q,%q)", c.in, d, n, c.wantDomain, c.wantName)
		}
	}
}

func TestSanitizeName(t *testing.T) {
	for in, want := range map[string]string{
		"":                      "",
		"OblSvc":                "OblSvc",
		`a\b/c`:                 "abc",
		"a b.c-d_e":             "ab.c-d_e",
		strings.Repeat("x", 80): strings.Repeat("x", 64),
	} {
		if got := sanitizeName(in); got != want {
			t.Errorf("sanitizeName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestXMLEscape(t *testing.T) {
	got := xmlEscape(`a & b <c> "d" 'e'`)
	want := `a &amp; b &lt;c&gt; &#34;d&#34; &#39;e&#39;`
	if got != want {
		t.Fatalf("xmlEscape = %q, want %q", got, want)
	}
}

func TestWinRMEnvelopeStructure(t *testing.T) {
	env := winrmEnvelope(actCommand, "http://10.0.0.5:5985/wsman", "abc", [][2]string{{"ShellId", "S1"}}, "<rsp:CommandLine/>")
	for _, want := range []string{
		"<a:Action s:mustUnderstand=\"true\">" + actCommand + "</a:Action>",
		"<w:ResourceURI s:mustUnderstand=\"true\">" + resourceURI + "</w:ResourceURI>",
		"<a:MessageID>uuid:abc</a:MessageID>",
		"<w:Selector Name=\"ShellId\">S1</w:Selector>",
		"<rsp:CommandLine/>",
		"<a:To s:mustUnderstand=\"true\">http://10.0.0.5:5985/wsman</a:To>",
	} {
		if !strings.Contains(env, want) {
			t.Errorf("envelope missing %q\n%s", want, env)
		}
	}
}

func TestWinRMEndpoint(t *testing.T) {
	cases := []struct {
		o    WinRMOpts
		want string
	}{
		{WinRMOpts{Host: "10.0.0.5"}, "http://10.0.0.5:5985/wsman"},
		{WinRMOpts{Host: "dc.corp.local", UseTLS: true}, "https://dc.corp.local:5986/wsman"},
		{WinRMOpts{Host: "10.0.0.5:5999"}, "http://10.0.0.5:5999/wsman"},
		{WinRMOpts{Host: "10.0.0.5:8443", UseTLS: true}, "https://10.0.0.5:8443/wsman"},
	}
	for _, c := range cases {
		if got := c.o.endpoint(); got != c.want {
			t.Errorf("endpoint(%+v) = %q, want %q", c.o, got, c.want)
		}
	}
}

func TestParseWinRMCreate(t *testing.T) {
	raw := []byte(`<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="` + nsSoap + `" xmlns:w="` + nsWsman + `" xmlns:rsp="` + nsShell + `">
<s:Header><w:SelectorSet><w:Selector Name="ShellId">11111111-2222-3333-4444-555555555555</w:Selector></w:SelectorSet></s:Header>
<s:Body><rsp:Shell/></s:Body></s:Envelope>`)
	r, err := parseWinRM(raw)
	if err != nil {
		t.Fatalf("parseWinRM: %v", err)
	}
	if r.shellID != "11111111-2222-3333-4444-555555555555" {
		t.Fatalf("shellID = %q", r.shellID)
	}
}

func TestParseWinRMReceiveDone(t *testing.T) {
	raw := []byte(`<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="` + nsSoap + `" xmlns:rsp="` + nsShell + `">
<s:Body><rsp:ReceiveResponse>
<rsp:Stream Name="stdout" CommandId="C1">SGVsbG8sIHdvcmxkCg==</rsp:Stream>
<rsp:Stream Name="stderr" CommandId="C1"></rsp:Stream>
<rsp:CommandState CommandId="C1" State="` + nsShell + `/CommandState/Done"><rsp:ExitCode>0</rsp:ExitCode></rsp:CommandState>
</rsp:ReceiveResponse></s:Body></s:Envelope>`)
	r, err := parseWinRM(raw)
	if err != nil {
		t.Fatalf("parseWinRM: %v", err)
	}
	if !r.done {
		t.Fatal("done = false, want true")
	}
	if string(r.stdout) != "Hello, world\n" {
		t.Fatalf("stdout = %q", r.stdout)
	}
	if r.exitCode != 0 {
		t.Fatalf("exitCode = %d, want 0", r.exitCode)
	}
}

func TestParseWinRMFault(t *testing.T) {
	raw := []byte(`<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="` + nsSoap + `">
<s:Body><s:Fault><s:Reason><s:Text xml:lang="en-US">access denied</s:Text></s:Reason></s:Fault></s:Body></s:Envelope>`)
	r, err := parseWinRM(raw)
	if err != nil {
		t.Fatalf("parseWinRM: %v", err)
	}
	if !strings.Contains(r.fault, "access denied") {
		t.Fatalf("fault = %q, want to contain 'access denied'", r.fault)
	}
}

func TestBase64DecodeLoose(t *testing.T) {
	got, err := base64DecodeLoose("SGVs\n bG8=\t")
	if err != nil {
		t.Fatalf("base64DecodeLoose: %v", err)
	}
	if string(got) != "Hello" {
		t.Fatalf("decoded = %q, want Hello", got)
	}
}

func TestNewMessageIDShape(t *testing.T) {
	id := newMessageID()
	if strings.Count(id, "-") != 4 || len(id) != 36 {
		t.Fatalf("message id %q is not GUID-shaped", id)
	}
	if newMessageID() == id {
		t.Fatal("message ids are not unique")
	}
}
