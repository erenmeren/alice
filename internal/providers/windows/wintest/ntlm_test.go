package wintest

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	ntlmssp "github.com/Azure/go-ntlmssp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// MS-NLMP §4.2.4: the NTLMv2 example's NTOWFv2 and NTProofStr.
func TestNTLMv2Vector(t *testing.T) {
	key := ntowfv2("Password", "User", "Domain")
	assert.Equal(t, "0c868a403bfd7a93a3001ef22ef02e3f", hex.EncodeToString(key))
	unhex := func(s string) []byte {
		b, err := hex.DecodeString(s)
		require.NoError(t, err)
		return b
	}
	avPairs := unhex("02000c0044006f006d00610069006e0001000c005300650072007600650072000000000000000000")
	// temp: 0x0101, reserved, the timestamp (zero), the client challenge, reserved, the AV pairs, reserved.
	temp := append(unhex("0101000000000000"+"0000000000000000"+"aaaaaaaaaaaaaaaa"+"00000000"), avPairs...)
	assert.Equal(t, "68cd0ab851e51c96aabc927bebef6a1c", hex.EncodeToString(hmacMD5(key, unhex("0123456789abcdef"), temp)))
}

func testPassword(t *testing.T) string {
	t.Helper()
	b := make([]byte, 12)
	_, err := rand.Read(b)
	require.NoError(t, err)
	return hex.EncodeToString(b)
}

type ntlmEnv struct {
	url      string
	acct     NTLMAccount
	requests atomic.Int32 // every request the server got
	served   atomic.Int32 // requests that reached the protected handler
	client   func() *http.Client
}

func newNTLMEnv(t *testing.T, opts ...NTLMOption) *ntlmEnv {
	t.Helper()
	e := &ntlmEnv{acct: NTLMAccount{User: "alice", Password: testPassword(t), Domain: "CORP", Computer: "HOST"}}
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		e.served.Add(1)
		_, _ = io.Copy(io.Discard, r.Body)
		_, _ = w.Write([]byte("ok"))
	})
	h, cc := NTLMServer(e.acct, time.Now, next, opts...)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		e.requests.Add(1)
		h.ServeHTTP(w, r)
	}))
	srv.Config.ConnContext = cc
	srv.StartTLS()
	t.Cleanup(srv.Close)
	e.url = srv.URL + "/wsman"
	// Each client is one connection: a new client is a new connection.
	e.client = func() *http.Client {
		tr := srv.Client().Transport.(*http.Transport).Clone()
		tr.MaxConnsPerHost = 1
		t.Cleanup(tr.CloseIdleConnections)
		return &http.Client{Transport: tr}
	}
	return e
}

// answer is a response's status and header (its body is read and closed).
type answer struct {
	status int
	header http.Header
}

func (e *ntlmEnv) do(t *testing.T, c *http.Client, auth string) answer {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, e.url, strings.NewReader("<body/>"))
	require.NoError(t, err)
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	resp, err := c.Do(req)
	require.NoError(t, err)
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	return answer{resp.StatusCode, resp.Header}
}

// negotiated runs the client side of go-ntlmssp over c.
func negotiated(t *testing.T, e *ntlmEnv, c *http.Client, user, password string) answer {
	t.Helper()
	nc := &http.Client{Transport: ntlmssp.Negotiator{RoundTripper: c.Transport}}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, e.url, bytes.NewReader([]byte("<body/>")))
	require.NoError(t, err)
	req.SetBasicAuth(user, password)
	resp, err := nc.Do(req)
	require.NoError(t, err)
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	return answer{resp.StatusCode, resp.Header}
}

func TestNTLMServerAccepts(t *testing.T) {
	e := newNTLMEnv(t)
	for _, user := range []string{"alice", "ALICE", `HOST\alice`, `CORP\alice`, `corp\alice`, `.\alice`} {
		t.Run(user, func(t *testing.T) {
			c := e.client()
			before := e.requests.Load()
			assert.Equal(t, http.StatusOK, negotiated(t, e, c, user, e.acct.Password).status)
			assert.Equal(t, int32(3), e.requests.Load()-before, "anonymous, type 1, type 3")
			// The connection stays authenticated: the next request is served without a new exchange.
			assert.Equal(t, http.StatusOK, negotiated(t, e, c, user, e.acct.Password).status)
			assert.Equal(t, int32(4), e.requests.Load()-before)
		})
	}
}

// challenge sends a type 1 on c and returns the server's type 2.
func challenge(t *testing.T, e *ntlmEnv, c *http.Client) []byte {
	t.Helper()
	neg, err := ntlmssp.NewNegotiateMessage("", "")
	require.NoError(t, err)
	a := e.do(t, c, "Negotiate "+base64.StdEncoding.EncodeToString(neg))
	require.Equal(t, http.StatusUnauthorized, a.status)
	scheme, tok, ok := strings.Cut(a.header.Get("WWW-Authenticate"), " ")
	require.True(t, ok)
	require.Equal(t, "Negotiate", scheme)
	b, err := base64.StdEncoding.DecodeString(tok)
	require.NoError(t, err)
	return b
}

func neg(b []byte) string { return "Negotiate " + base64.StdEncoding.EncodeToString(b) }

func assertOffer(t *testing.T, a answer) {
	t.Helper()
	assert.Equal(t, http.StatusUnauthorized, a.status)
	assert.Equal(t, []string{"Negotiate", `Basic realm="WSMAN"`}, a.header.Values("WWW-Authenticate"))
}

// v1Authenticate is a type 3 with a 24-byte (NTLMv1) NT response.
func v1Authenticate(user string) []byte {
	u := utf16le(user)
	nt := make([]byte, 24)
	b := make([]byte, 64)
	copy(b, "NTLMSSP\x00")
	binary.LittleEndian.PutUint32(b[8:], 3)
	put := func(off int, data []byte) {
		binary.LittleEndian.PutUint16(b[off:], uint16(len(data)))
		binary.LittleEndian.PutUint16(b[off+2:], uint16(len(data)))
		binary.LittleEndian.PutUint32(b[off+4:], uint32(len(b)))
		b = append(b, data...)
	}
	put(20, nt)
	put(36, u)
	return b
}

func TestNTLMServerRefuses(t *testing.T) {
	e := newNTLMEnv(t)

	t.Run("anonymous", func(t *testing.T) {
		assertOffer(t, e.do(t, e.client(), ""))
	})
	t.Run("Basic with the right password", func(t *testing.T) {
		basic := "Basic " + base64.StdEncoding.EncodeToString([]byte("alice:"+e.acct.Password))
		assertOffer(t, e.do(t, e.client(), basic))
	})
	t.Run("wrong password", func(t *testing.T) {
		assertOffer(t, negotiated(t, e, e.client(), "alice", testPassword(t)))
	})
	t.Run("wrong user", func(t *testing.T) {
		assertOffer(t, negotiated(t, e, e.client(), "bob", e.acct.Password))
	})
	t.Run("unknown domain", func(t *testing.T) {
		assertOffer(t, negotiated(t, e, e.client(), `OTHER\alice`, e.acct.Password))
	})
	t.Run("replayed type 3", func(t *testing.T) {
		c := e.client()
		auth, err := ntlmssp.NewAuthenticateMessage(challenge(t, e, c), "alice", e.acct.Password, nil)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, e.do(t, c, neg(auth)).status)
		// On a new connection (no type 1 before it), and a second time on the same one.
		assertOffer(t, e.do(t, e.client(), neg(auth)))
		assertOffer(t, e.do(t, c, neg(auth)))
		// The second type 3 also ended the connection's sign-in.
		assertOffer(t, e.do(t, c, ""))
	})
	t.Run("NTLMv1 response", func(t *testing.T) {
		c := e.client()
		challenge(t, e, c)
		assertOffer(t, e.do(t, c, neg(v1Authenticate("alice"))))
	})
	t.Run("another target info", func(t *testing.T) {
		c := e.client()
		ch := challenge(t, e, c)
		other := challenge(t, e, e.client()) // another connection's challenge carries another timestamp
		copy(other[24:32], ch[24:32])        // with this connection's server challenge
		auth, err := ntlmssp.NewAuthenticateMessage(other, "alice", e.acct.Password, nil)
		require.NoError(t, err)
		if bytes.Equal(other, ch) {
			t.Skip("both challenges were issued in the same 100 ns")
		}
		assertOffer(t, e.do(t, c, neg(auth)))
	})
	t.Run("malformed messages", func(t *testing.T) {
		for _, auth := range []string{
			"Negotiate !!", "NTLM " + base64.StdEncoding.EncodeToString([]byte("NTLMSSP\x00\x02\x00\x00\x00")),
			"Negotiate " + base64.StdEncoding.EncodeToString([]byte("XXXXXXXX\x01\x00\x00\x00")),
			neg([]byte("NTLMSSP\x00")), neg(append([]byte("NTLMSSP\x00\x03\x00\x00\x00"), make([]byte, 20)...)), "Kerberos x",
		} {
			c := e.client()
			challenge(t, e, c)
			assertOffer(t, e.do(t, c, auth))
		}
		// A type 3 whose fields point outside the message.
		c := e.client()
		challenge(t, e, c)
		bad := v1Authenticate("alice")
		binary.LittleEndian.PutUint32(bad[24:], 1<<20)
		assertOffer(t, e.do(t, c, neg(bad)))
		// An offset above the message that wraps when converted to a 32-bit int (A2): refused, never a panic.
		c = e.client()
		challenge(t, e, c)
		bad = v1Authenticate("alice")
		binary.LittleEndian.PutUint32(bad[24:], 0xFFFFFFFF)
		assertOffer(t, e.do(t, c, neg(bad)))
		// An odd-length user name is not UTF-16.
		c = e.client()
		ch := challenge(t, e, c)
		auth, err := ntlmssp.NewAuthenticateMessage(ch, "alice", e.acct.Password, nil)
		require.NoError(t, err)
		binary.LittleEndian.PutUint16(auth[36:], 3)
		assertOffer(t, e.do(t, c, neg(auth)))
	})
	assert.Equal(t, int32(1), e.served.Load(), "only the replay test's one accepted request was served")

	t.Run("Basic only", func(t *testing.T) {
		b := newNTLMEnv(t, OfferBasicOnly())
		a := b.do(t, b.client(), "")
		assert.Equal(t, http.StatusUnauthorized, a.status)
		assert.Equal(t, []string{`Basic realm="WSMAN"`}, a.header.Values("WWW-Authenticate"))
	})
}

// A server without the connection context never authenticates anyone: the state is per connection.
func TestNTLMServerNeedsTheConnContext(t *testing.T) {
	acct := NTLMAccount{User: "alice", Password: testPassword(t), Computer: "HOST"}
	h, cc := NTLMServer(acct, time.Now, http.NotFoundHandler())
	srv := httptest.NewUnstartedServer(h)
	srv.StartTLS()
	t.Cleanup(srv.Close)
	e := &ntlmEnv{url: srv.URL, acct: acct, client: srv.Client}
	assertOffer(t, negotiated(t, e, srv.Client(), "alice", acct.Password))
	assert.NotNil(t, cc(context.Background(), (net.Conn)(nil)).Value(ntlmConnKey{}))
}
