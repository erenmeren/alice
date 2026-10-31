package wintest

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/md5" //nolint:gosec,staticcheck // NTLMv2 is defined over MD4 and HMAC-MD5 (MS-NLMP 3.3.2); test-only emulator
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
	"unicode/utf16"

	"golang.org/x/crypto/md4" //nolint:gosec,staticcheck // NTLMv2 is defined over MD4 and HMAC-MD5 (MS-NLMP 3.3.2); test-only emulator
)

// NTLMAccount is the one account the emulated WinRM listener accepts (R71 Ruling 20). The domain a client
// may send is empty, ".", Computer or Domain (case-insensitive).
type NTLMAccount struct{ User, Password, Domain, Computer string }

type ntlmConfig struct{ basicOnly bool }

// NTLMOption changes the emulated listener's authentication.
type NTLMOption func(*ntlmConfig)

// OfferBasicOnly makes the 401 offer only Basic (a listener with Negotiate off), for the client's refusal test.
// Basic is still never accepted.
func OfferBasicOnly() NTLMOption { return func(c *ntlmConfig) { c.basicOnly = true } }

// ntlmConn is one TLS connection's sign-in: Windows binds the NTLM logon to the connection.
type ntlmConn struct {
	authenticated bool
	challenge     []byte // the pending server challenge; used once
	targetInfo    []byte
}

type ntlmConnKey struct{}

const (
	ntlmSignature = "NTLMSSP\x00"
	// UNICODE, REQUEST_TARGET, NTLM, ALWAYS_SIGN, TARGET_TYPE_SERVER, EXTENDED_SESSIONSECURITY, TARGET_INFO, 128, 56:
	// no LM_KEY and no KEY_EXCH (go-ntlmssp refuses both).
	ntlmChallengeFlags = 1<<0 | 1<<2 | 1<<9 | 1<<15 | 1<<17 | 1<<19 | 1<<23 | 1<<29 | 1<<31
	// minNTv2Response is NTProofStr (16) and the fixed part of temp (28) and its trailing reserved field (4);
	// an NTLMv1 response is 24 bytes.
	minNTv2Response = 48
	windowsEpoch    = 116444736000000000 // 1601-01-01 to 1970-01-01 in 100 ns
)

// NTLMServer wraps next in the server side of NTLMv2 over HTTP, connection-bound like Windows: connContext must
// be the http.Server's ConnContext, so each TLS connection signs in once and later requests on it are served
// without a new exchange. Basic is never accepted. clock is the model's clock (the challenge's timestamp).
func NTLMServer(acct NTLMAccount, clock func() time.Time, next http.Handler, opts ...NTLMOption) (h http.Handler, connContext func(context.Context, net.Conn) context.Context) {
	var cfg ntlmConfig
	for _, o := range opts {
		o(&cfg)
	}
	offer := func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		if !cfg.basicOnly {
			w.Header().Add("WWW-Authenticate", "Negotiate")
		}
		w.Header().Add("WWW-Authenticate", `Basic realm="WSMAN"`)
		w.WriteHeader(http.StatusUnauthorized)
	}
	h = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		st, ok := r.Context().Value(ntlmConnKey{}).(*ntlmConn)
		if !ok {
			st = &ntlmConn{} // no connection context: every request is a new connection
		}
		auth := r.Header.Get("Authorization")
		if auth == "" && st.authenticated {
			next.ServeHTTP(w, r)
			return
		}
		scheme, token, _ := strings.Cut(auth, " ")
		if scheme != "Negotiate" && scheme != "NTLM" {
			offer(w, r)
			return
		}
		st.authenticated = false
		msg, err := base64.StdEncoding.DecodeString(token)
		if err != nil || len(msg) < 12 || string(msg[:8]) != ntlmSignature {
			offer(w, r)
			return
		}
		switch binary.LittleEndian.Uint32(msg[8:]) {
		case 1:
			st.challenge = make([]byte, 8)
			_, _ = rand.Read(st.challenge)
			st.targetInfo = targetInfo(acct, clock())
			_, _ = io.Copy(io.Discard, r.Body)
			w.Header().Set("WWW-Authenticate", scheme+" "+base64.StdEncoding.EncodeToString(challengeMessage(acct.Computer, st.challenge, st.targetInfo)))
			w.WriteHeader(http.StatusUnauthorized)
			return
		case 3:
			ch, ti := st.challenge, st.targetInfo
			st.challenge, st.targetInfo = nil, nil
			if ch != nil && verifyAuthenticate(acct, msg, ch, ti) {
				st.authenticated = true
				next.ServeHTTP(w, r)
				return
			}
		}
		offer(w, r)
	})
	connContext = func(ctx context.Context, _ net.Conn) context.Context {
		return context.WithValue(ctx, ntlmConnKey{}, &ntlmConn{})
	}
	return h, connContext
}

func utf16le(s string) []byte {
	u := utf16.Encode([]rune(s))
	b := make([]byte, 2*len(u))
	for i, c := range u {
		binary.LittleEndian.PutUint16(b[2*i:], c)
	}
	return b
}

func av(b *bytes.Buffer, id uint16, value []byte) {
	_ = binary.Write(b, binary.LittleEndian, id)
	_ = binary.Write(b, binary.LittleEndian, uint16(len(value))) //nolint:gosec // names and a timestamp
	b.Write(value)
}

// targetInfo is the challenge's AV pairs: the NetBIOS and DNS names of the computer and its domain (the
// computer's own name in a workgroup), the timestamp, EOL.
func targetInfo(acct NTLMAccount, now time.Time) []byte {
	domain := acct.Domain
	if domain == "" {
		domain = acct.Computer
	}
	ts := make([]byte, 8)
	binary.LittleEndian.PutUint64(ts, uint64(now.UnixNano()/100+windowsEpoch)) //nolint:gosec // after 1601
	var b bytes.Buffer
	av(&b, 2, utf16le(domain))
	av(&b, 1, utf16le(acct.Computer))
	av(&b, 4, utf16le(domain))
	av(&b, 3, utf16le(acct.Computer))
	av(&b, 7, ts)
	av(&b, 0, nil)
	return b.Bytes()
}

// challengeMessage is a type 2 (MS-NLMP 2.2.1.2) without the version field.
func challengeMessage(computer string, challenge, info []byte) []byte {
	name := utf16le(computer)
	const fixed = 48
	b := make([]byte, fixed, fixed+len(name)+len(info))
	copy(b, ntlmSignature)
	binary.LittleEndian.PutUint32(b[8:], 2)
	putField(b[12:], len(name), fixed)
	binary.LittleEndian.PutUint32(b[20:], ntlmChallengeFlags)
	copy(b[24:32], challenge)
	putField(b[40:], len(info), fixed+len(name))
	return append(append(b, name...), info...)
}

func putField(b []byte, n, off int) {
	binary.LittleEndian.PutUint16(b, uint16(n))       //nolint:gosec // short names
	binary.LittleEndian.PutUint16(b[2:], uint16(n))   //nolint:gosec // short names
	binary.LittleEndian.PutUint32(b[4:], uint32(off)) //nolint:gosec // inside the message
}

// field reads the variable field whose descriptor is at off; nil when it lies outside msg.
func field(msg []byte, off int) []byte {
	// Compared in uint64 before any conversion: a uint32 offset wraps as a 32-bit int (A2).
	n := uint64(binary.LittleEndian.Uint16(msg[off:]))
	start := uint64(binary.LittleEndian.Uint32(msg[off+4:]))
	if start > uint64(len(msg)) || n > uint64(len(msg))-start {
		return nil
	}
	return msg[start : start+n]
}

func fromUTF16(b []byte) (string, bool) {
	if len(b)%2 != 0 {
		return "", false
	}
	u := make([]uint16, len(b)/2)
	for i := range u {
		u[i] = binary.LittleEndian.Uint16(b[2*i:])
	}
	return string(utf16.Decode(u)), true
}

// verifyAuthenticate checks a type 3 (MS-NLMP 3.3.2): an NTLMv2 response over this connection's challenge and the
// target info it issued, for the account's user, a domain the account accepts and the account's password.
func verifyAuthenticate(acct NTLMAccount, msg, challenge, info []byte) bool {
	if len(msg) < 64 {
		return false
	}
	nt := field(msg, 20)
	if len(nt) < minNTv2Response {
		return false
	}
	proof, temp := nt[:16], nt[16:]
	if len(temp) != 28+len(info)+4 || temp[0] != 1 || temp[1] != 1 || !bytes.Equal(temp[28:28+len(info)], info) {
		return false
	}
	user, okU := fromUTF16(field(msg, 36))
	domain, okD := fromUTF16(field(msg, 28))
	if !okU || !okD || !strings.EqualFold(user, acct.User) {
		return false
	}
	if domain != "" && domain != "." && !strings.EqualFold(domain, acct.Computer) && (acct.Domain == "" || !strings.EqualFold(domain, acct.Domain)) {
		return false
	}
	return hmac.Equal(proof, hmacMD5(ntowfv2(acct.Password, user, domain), challenge, temp))
}

// ntowfv2 is HMAC-MD5(MD4(UTF-16LE(password)), UTF-16LE(upper(user) || domain)). The account rule is ASCII, so the
// user is upper-cased byte by byte.
func ntowfv2(password, user, domain string) []byte {
	h := md4.New() //nolint:gosec // NTLMv2 is defined over MD4 (MS-NLMP 3.3.2); test-only emulator
	h.Write(utf16le(password))
	up := []byte(user)
	for i, c := range up {
		if 'a' <= c && c <= 'z' {
			up[i] = c - 'a' + 'A'
		}
	}
	return hmacMD5(h.Sum(nil), utf16le(string(up)+domain))
}

func hmacMD5(key []byte, data ...[]byte) []byte {
	m := hmac.New(md5.New, key)
	for _, d := range data {
		m.Write(d)
	}
	return m.Sum(nil)
}
