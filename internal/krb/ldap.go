// LDAP SPN enumeration (T1018 / T1558.003 support).
//
// THIS USES A SIMPLE BIND OVER CLEAR TEXT: the account password travels the
// wire unencrypted, so this helper is for authorised in-lab engagements only
// (a lab DC with LDAPS off). In production domains, prefer enumerating from
// any domain-joined host with .NET DirectorySearcher or read-only LDAPS —
// the operator who needs that already has those tools. Here the goal is only
// to keep obliteratus a single dependency-free binary in the lab.
//
// Flow: dial host:389, BindRequest (version 3, DN of user, simple password),
// then a whole-subtree search under DC=...,DC=... for (servicePrincipalName=*)
// asking for sAMAccountName, servicePrincipalName and
// msDS-SupportedEncryptionTypes. SPNs whose encryption list does NOT include
// etype 23 (RC4) are skipped — they are not roastable with this module.
package krb

import (
	"encoding/asn1"
	"fmt"
	"net"
	"strings"
	"time"
)

const (
	ldapSearchSPN  = "servicePrincipalName"
	rc4AllowedMask = 0x4 // msDS-SupportedEncryptionTypes bit for RC4-HMAC
)

// SPNEntry is one service account usable as a kerberoast target.
type SPNEntry struct {
	Account string
	SPN     string
	RC4     bool // RC4 allowed (else the TGS-REP will be non-RC4)
}

// domainToBaseDN turns CORP.EXAMPLE.COM into DC=corp,DC=example,DC=com.
func domainToBaseDN(domain string) string {
	parts := strings.Split(strings.ToUpper(domain), ".")
	dns := make([]string, len(parts))
	for i, p := range parts {
		dns[i] = "DC=" + strings.ToLower(p)
	}
	return strings.Join(dns, ",")
}

// ldapMsg wraps payload in LDAPMessage ::= SEQUENCE { messageID, op }.
func ldapMsg(id int32, op []byte) []byte { return derSeq(derInt(int64(id)), op) }

func ldapBind(id int32, dn, password string) []byte {
	var body []byte
	body = append(body, derInt(3)...)
	body = append(body, derOctet([]byte(dn))...)
	body = append(body, der(0x80, []byte(password))...)
	return ldapMsg(id, der(0x60, body))
}

// ldapSearch builds the SearchRequest (APPLICATION 3): whole-subtree, a
// present filter [7] on servicePrincipalName, and the attribute list the
// roaster needs. BER and DER differ only in definite/indefinite lengths —
// we always emit definite forms, which every server accepts.
func ldapSearch(id int32, baseDN string) []byte {
	filter := der(0x87, []byte(ldapSearchSPN))
	var attrs []byte
	for _, a := range []string{"sAMAccountName", "servicePrincipalName", "msDS-SupportedEncryptionTypes", "pwdLastSet"} {
		attrs = append(attrs, derOctet([]byte(a))...)
	}
	req := reqBuf{}
	req.add(derOctet([]byte(baseDN)))
	req.add(der(0x0A, []byte{2})) // scope: wholeSubtree
	req.add(der(0x0A, []byte{0})) // derefAliases: never
	req.add(derInt(0))            // sizeLimit: none requested
	req.add(derInt(0))            // timeLimit: none requested
	req.add(derBool(false))
	req.add(filter)
	req.add(derSeq(attrs))
	return ldapMsg(id, der(0x63, req.buf)) // APPLICATION 3, constructed
}

// reqBuf is a tiny concatenation accumulator (Go has no + for []byte).
type reqBuf struct{ buf []byte }

func (r *reqBuf) add(b []byte) { r.buf = append(r.buf, b...) }

func parseLDAPString(b []byte) string {
	var v asn1.RawValue
	if _, err := asn1.Unmarshal(b, &v); err != nil {
		return ""
	}
	return string(v.Bytes)
}

// walkLDAPEntries yields the attribute maps of every SearchResultEntry in a
// raw TCP stream (a session is a run of LDAPMessage TLVs framed back to back).
func walkLDAPEntries(resp []byte) []map[string][]string {
	var out []map[string][]string
	rest := resp
	for len(rest) > 0 {
		var msg asn1.RawValue
		left, err := asn1.Unmarshal(rest, &msg)
		if err != nil || len(left) == len(rest) {
			break
		}
		rest = left
		if msg.Class != asn1.ClassApplication || msg.Tag != 4 {
			continue // not a SearchResultEntry
		}
		entry := map[string][]string{}
		for _, f := range children(&msg) {
			if f.Class != asn1.ClassContextSpecific || f.Tag != 3 || !f.IsCompound {
				continue
			}
			var attrs asn1.RawValue
			if _, err := asn1.Unmarshal(f.Bytes, &attrs); err != nil {
				continue
			}
			for _, a := range children(&attrs) {
				inner := children(&a)
				if len(inner) != 2 {
					continue
				}
				name := parseLDAPString(inner[0].FullBytes)
				var vals []string
				var set asn1.RawValue
				if _, err := asn1.Unmarshal(inner[1].FullBytes, &set); err == nil {
					for _, v := range children(&set) {
						if v.Tag == asn1.TagOctetString && !v.IsCompound {
							vals = append(vals, string(v.Bytes))
						}
					}
				}
				if name != "" {
					entry[name] = vals
				}
			}
		}
		out = append(out, entry)
	}
	return out
}

// etypeAllowed reports whether the msDS-SupportedEncryptionTypes bitmask
// permits RC4. An absent attribute means the server default (RC4 allowed).
// Unparseable content degrades to allowed so the roaster can try anyway.
func etypeAllowed(raw string) bool {
	if raw == "" {
		return true
	}
	var v int
	if _, err := fmt.Sscanf(raw, "%d", &v); err != nil {
		return true
	}
	return v&rc4AllowedMask != 0
}

// EnumSPNs binds to the DC and returns every servicePrincipalName in the
// domain. user may be "svc-roast" or a DN; password is the account password.
// WARNING: simple bind over clear text (see the package comment above).
func EnumSPNs(host, domain, user, password string, em Emitter) ([]SPNEntry, error) {
	dialTo := net.JoinHostPort(host, "389")
	emit(em, "LDAP: binding to "+dialTo+" as "+user, "INFO")
	conn, err := net.DialTimeout("tcp", dialTo, 5*time.Second)
	if err != nil {
		return nil, fmt.Errorf("ldap: dial %s: %w", dialTo, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))

	dn := user
	if !strings.Contains(user, "=") && !strings.Contains(user, "@") {
		dn = user + "@" + strings.ToLower(domain)
	}
	if _, err := conn.Write(ldapBind(1, dn, password)); err != nil {
		return nil, fmt.Errorf("ldap: bind write: %w", err)
	}
	bindResp := make([]byte, 4096)
	n, err := conn.Read(bindResp)
	if err != nil {
		return nil, fmt.Errorf("ldap: bind read: %w", err)
	}
	if !bindOK(bindResp[:n]) {
		return nil, fmt.Errorf("ldap: bind rejected (wrong credentials or DN form)")
	}

	base := domainToBaseDN(domain)
	emit(em, "LDAP: searching "+base+" for (servicePrincipalName=*)", "INFO")
	if _, err := conn.Write(ldapSearch(2, base)); err != nil {
		return nil, fmt.Errorf("ldap: search write: %w", err)
	}
	var resp []byte
	buf := make([]byte, 65536)
	for {
		n, err := conn.Read(buf)
		if n > 0 {
			resp = append(resp, buf[:n]...)
		}
		if err != nil || searchDone(resp) || len(resp) > 1<<22 {
			break
		}
	}

	var out []SPNEntry
	for _, e := range walkLDAPEntries(resp) {
		acct := ""
		if v, ok := e["sAMAccountName"]; ok && len(v) > 0 {
			acct = v[0]
		}
		if strings.HasSuffix(strings.ToLower(acct), "$") {
			continue // machine accounts roast fine but need their own keys — out of v1 scope
		}
		rc4 := true
		if v, ok := e["msDS-SupportedEncryptionTypes"]; ok && len(v) > 0 {
			rc4 = etypeAllowed(v[0])
		}
		for _, spn := range e["servicePrincipalName"] {
			if spn == "" {
				continue
			}
			out = append(out, SPNEntry{Account: acct, SPN: spn, RC4: rc4})
		}
	}
	emit(em, fmt.Sprintf("LDAP: %d SPN(s) enumerated", len(out)), "SUCCESS")
	return out, nil
}

// bindOK checks the BindResponse resultCode ([APPLICATION 1] → result [0]
// IMPLICIT ENUMERATED, context primitive tag 0). 0 = success.
func bindOK(data []byte) bool {
	var root asn1.RawValue
	if _, err := asn1.Unmarshal(data, &root); err != nil {
		return false
	}
	if root.Class != asn1.ClassApplication || root.Tag != 1 {
		return false
	}
	kids := children(&root)
	if len(kids) < 1 {
		return false
	}
	r := kids[0]
	if r.Class != asn1.ClassContextSpecific || r.Tag != 0 || r.IsCompound {
		return false
	}
	var code int
	for _, b := range r.Bytes {
		code = code<<8 | int(b)
	}
	return code == 0
}

// searchDone scans a raw stream for a SearchResultDone (APPLICATION 5).
func searchDone(data []byte) bool {
	rest := data
	for len(rest) > 0 {
		var m asn1.RawValue
		left, err := asn1.Unmarshal(rest, &m)
		if err != nil || len(left) == len(rest) {
			return false
		}
		if m.Class == asn1.ClassApplication && m.Tag == 5 {
			return true
		}
		rest = left
	}
	return false
}
