package fakefleet

import (
	"crypto/tls"
	"encoding/json"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAccessLogRecordsEveryConnectionAndOnlyThose(t *testing.T) {
	f := sharedFleet(t)
	s := f.Server(KindValid)
	r := handshake(t, s.Addr(), "logged.fleet.test", nil)
	require.NoError(t, r.err)
	require.NoError(t, f.WaitIdle(ctx(t)))

	log := f.Log()
	require.Len(t, log, 1, "one connection, one entry; the other servers were not dialed")
	a := log[0]
	assert.Equal(t, KindValid, a.Kind)
	assert.Equal(t, s.Addr(), a.Local)
	assert.Equal(t, r.local, a.Remote, "the client's own address")
	assert.Equal(t, "logged.fleet.test", a.SNI)
	assert.True(t, a.Handshake)
	assert.True(t, a.Closed)
	assert.False(t, a.Overflow)
	assert.Positive(t, a.BytesRead)
	assert.Positive(t, a.BytesWritten)
	assert.Zero(t, a.AppBytes)
	assert.False(t, a.Start.IsZero())
	assert.False(t, a.End.Before(a.Start))
	assert.Equal(t, log, s.Log())
	for _, other := range f.Servers() {
		if other.Kind() != KindValid {
			assert.Empty(t, other.Log(), "%s was not dialed", other.Kind())
			assert.Zero(t, other.Accepted(), "%s", other.Kind())
		}
	}
	assert.Equal(t, int64(1), s.Accepted())
	assert.Zero(t, f.AppBytesAfterHandshake())

	f.ClearLog()
	assert.Empty(t, f.Log())
	assert.Zero(t, s.Accepted(), "ClearLog resets the counters")
}

// The hard counter: bytes an application sends after the handshake are counted, per entry and in total.
func TestApplicationBytesAfterTheHandshakeAreCounted(t *testing.T) {
	f := sharedFleet(t)
	for _, k := range []Kind{KindValid, KindTLS12} {
		c, err := tls.Dial("tcp", f.Addr(k), probeConfig(""))
		require.NoError(t, err)
		_, err = c.Write([]byte("GET / HTTP/1.0\r\n\r\n"))
		require.NoError(t, err)
		require.NoError(t, c.Close())
	}
	require.NoError(t, f.WaitIdle(ctx(t)))
	assert.Equal(t, int64(36), f.AppBytesAfterHandshake())
	for _, k := range []Kind{KindValid, KindTLS12} {
		log := f.Server(k).Log()
		require.Len(t, log, 1)
		assert.Equal(t, int64(18), log[0].AppBytes, "%s", k)
	}
}

// The server never writes after the handshake: a client that waits to read gets nothing until it gives up.
func TestTheFakeWritesNothingAfterTheHandshake(t *testing.T) {
	f := sharedFleet(t)
	for _, k := range []Kind{KindTLS12, KindTLS13, KindValid} {
		c, err := tls.Dial("tcp", f.Addr(k), probeConfig(""))
		require.NoError(t, err, k)
		// TLS 1.3 would send session tickets after the handshake; the fake disables them.
		require.NoError(t, c.SetReadDeadline(time.Now().Add(100*time.Millisecond)))
		n, err := c.Read(make([]byte, 1))
		assert.Zero(t, n, k)
		var ne net.Error
		require.ErrorAs(t, err, &ne, k)
		assert.True(t, ne.Timeout(), k)
		require.NoError(t, c.NetConn().Close()) // no close_notify either
	}
	require.NoError(t, f.WaitIdle(ctx(t)))
	for _, a := range f.Log() {
		assert.True(t, a.Handshake, a.Kind)
		assert.Zero(t, a.AppBytes, a.Kind)
	}
}

func TestWaitIdleSeesConnectionsNotYetAccepted(t *testing.T) {
	f := newFleet(t, Options{Kinds: []Kind{KindSlowLoris}, Now: testNow, SlowLorisInterval: time.Hour})
	addr := f.Addr(KindSlowLoris)
	for i := 0; i < 20; i++ {
		c, err := net.Dial("tcp", addr)
		require.NoError(t, err)
		require.NoError(t, c.Close())
	}
	require.NoError(t, f.WaitIdle(ctx(t)))
	assert.Len(t, f.Log(), 20, "every connection made before WaitIdle is in the log, none of its own")
	assert.Equal(t, int64(20), f.Server(KindSlowLoris).Accepted())
}

func TestWaitIdleHonoursTheContext(t *testing.T) {
	f := newFleet(t, Options{Kinds: []Kind{KindSlowLoris}, Now: testNow, SlowLorisInterval: time.Hour})
	c, err := net.Dial("tcp", f.Addr(KindSlowLoris))
	require.NoError(t, err)
	defer func() { _ = c.Close() }()
	_, err = c.Write(goClientHello(t))
	require.NoError(t, err)
	short, cancel := contextWithTimeout(50 * time.Millisecond)
	defer cancel()
	assert.ErrorIs(t, f.WaitIdle(short), short.Err())
}

func TestCloseEndsOpenConnectionsAndIsIdempotent(t *testing.T) {
	f, err := New(Options{Kinds: []Kind{KindSlowLoris, KindValid}, Now: testNow, SlowLorisInterval: time.Hour})
	require.NoError(t, err)
	c, err := net.Dial("tcp", f.Addr(KindSlowLoris))
	require.NoError(t, err)
	defer func() { _ = c.Close() }()
	_, err = c.Write(goClientHello(t))
	require.NoError(t, err)
	// Dial returns once the kernel queues the connection; Close before Accept would drop it unlogged.
	require.Eventually(t, func() bool { return f.Server(KindSlowLoris).Accepted() == 1 }, 10*time.Second, time.Millisecond)
	done := make(chan error, 1)
	go func() { done <- f.Close() }()
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(10 * time.Second):
		t.Fatal("Close waited for the slow client")
	}
	require.NoError(t, f.Close())
	require.NoError(t, c.SetReadDeadline(time.Now().Add(5*time.Second)))
	_, err = io.ReadAll(c)
	if err != nil { // a reset when Close came before the hello was read
		assert.ErrorIs(t, err, syscall.ECONNRESET, "the fake closed the connection")
	}
	_, err = net.DialTimeout("tcp", f.Addr(KindValid), time.Second)
	assert.Error(t, err, "nothing listens after Close")
	assert.NoError(t, f.WaitIdle(ctx(t)), "a closed fleet is idle")
	require.Len(t, f.Log(), 1)
	assert.True(t, f.Log()[0].Closed)
}

func TestConnectionsOverTheLimitAreClosedAndLogged(t *testing.T) {
	f := newFleet(t, Options{Kinds: []Kind{KindSlowLoris}, Now: testNow, SlowLorisInterval: time.Hour, MaxConns: 1})
	held, err := net.Dial("tcp", f.Addr(KindSlowLoris))
	require.NoError(t, err)
	defer func() { _ = held.Close() }()
	_, err = held.Write(goClientHello(t))
	require.NoError(t, err)
	// Connections are accepted in order and counted at accept, so the next one is over the limit.
	over, err := net.Dial("tcp", f.Addr(KindSlowLoris))
	require.NoError(t, err)
	require.NoError(t, over.SetReadDeadline(time.Now().Add(5*time.Second)))
	b, err := io.ReadAll(over)
	assert.NoError(t, err)
	assert.Empty(t, b, "closed at once")
	_ = over.Close()
	log := f.Log()
	require.Len(t, log, 2)
	assert.False(t, log[0].Overflow)
	assert.True(t, log[1].Overflow)
}

// The chain servers send megabytes per connection: they take at most MaxChainConns at a time each.
func TestChainServersHaveTheirOwnSmallLimit(t *testing.T) {
	f := newFleet(t, Options{Kinds: []Kind{KindGiantChain, KindHugeChain, KindValid}, Now: testNow, MaxChainConns: 1, MaxConns: 4})
	for _, k := range []Kind{KindGiantChain, KindHugeChain} {
		held, err := net.Dial("tcp", f.Addr(k))
		require.NoError(t, err)
		defer func() { _ = held.Close() }()
		_, err = held.Write(goClientHello(t)) // the server writes into a client that does not read
		require.NoError(t, err)
		over, err := net.Dial("tcp", f.Addr(k))
		require.NoError(t, err)
		require.NoError(t, over.SetReadDeadline(time.Now().Add(5*time.Second)))
		b, err := io.ReadAll(over)
		assert.NoError(t, err, k)
		assert.Empty(t, b, "%s: closed at once", k)
		_ = over.Close()
		log := f.Server(k).Log()
		require.Len(t, log, 2, k)
		assert.False(t, log[0].Overflow, k)
		assert.True(t, log[1].Overflow, k)
	}
	// The other kinds keep MaxConns.
	for i := 0; i < 2; i++ {
		require.NoError(t, handshake(t, f.Addr(KindValid), "", nil).err)
	}
	for _, a := range f.Server(KindValid).Log() {
		assert.False(t, a.Overflow)
	}
	assert.Equal(t, 8, Options{}.withDefaults(t).MaxChainConns, "the default")
}

func TestLogIsBounded(t *testing.T) {
	f := newFleet(t, Options{Kinds: []Kind{KindPlainText}, Now: testNow, MaxLog: 2})
	for i := 0; i < 4; i++ {
		readBanner(t, f.Addr(KindPlainText))
	}
	require.NoError(t, f.WaitIdle(ctx(t)))
	assert.Len(t, f.Log(), 2)
	assert.Equal(t, int64(2), f.Dropped())
	assert.Equal(t, int64(4), f.Server(KindPlainText).Accepted(), "the counter stays exact")
}

func TestOptionsAreValidated(t *testing.T) {
	for name, o := range map[string]Options{
		"unknown kind":                 {Kinds: []Kind{"bogus"}},
		"duplicate kind":               {Kinds: []Kind{KindValid, KindValid}},
		"listen for a kind not served": {Kinds: []Kind{KindValid}, Listen: map[Kind]string{KindTLS12: "127.0.0.1:0"}},
		"bad listen":                   {Kinds: []Kind{KindValid}, Listen: map[Kind]string{KindValid: "127.0.0.1:notaport"}},
		"bad domain":                   {Kinds: []Kind{KindValid}, Domain: "-bad-.test"},
		"too many SNI":                 {Kinds: []Kind{KindManySNI}, ManySNINames: 5000},
		"huge chain 1":                 {Kinds: []Kind{KindHugeChain}, HugeChainCerts: 1},
		"giant budget":                 {Kinds: []Kind{KindGiantChain}, GiantBytes: -1},
	} {
		_, err := New(o)
		assert.Error(t, err, name)
	}
	// An address in use fails New and leaves nothing listening.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = ln.Close() }()
	_, err = New(Options{Kinds: []Kind{KindValid, KindTLS12}, Listen: map[Kind]string{KindTLS12: ln.Addr().String()}})
	assert.ErrorContains(t, err, "tls12")
}

func TestListenAddressesAndDefaults(t *testing.T) {
	f := newFleet(t, Options{Kinds: []Kind{KindValid}, Listen: map[Kind]string{KindValid: "127.0.0.1:0"}})
	assert.Equal(t, []Kind{KindValid}, []Kind{f.Servers()[0].Kind()})
	assert.Equal(t, "valid.fleet.test", f.Server(KindValid).Host(), "the default domain")
	assert.Equal(t, DefaultDomain, f.Domain())
	assert.Equal(t, f.CA().RootPEM, f.RootPEM())
	r := handshake(t, f.Addr(KindValid), "", nil)
	require.NoError(t, r.err)
	assert.WithinDuration(t, time.Now(), leafOf(t, r).NotBefore, 2*time.Hour, "Now defaults to the real time")
}

func TestControlHandler(t *testing.T) {
	f := sharedFleet(t)
	srv := httptest.NewServer(f.ControlHandler())
	defer srv.Close()
	get := func(path string) (int, string) {
		resp, err := http.Get(srv.URL + path) //nolint:gosec,noctx // a test server
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()
		b, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		return resp.StatusCode, string(b)
	}
	post := func(path string) int {
		resp, err := http.Post(srv.URL+path, "text/plain", nil) //nolint:gosec,noctx // a test server
		require.NoError(t, err)
		_ = resp.Body.Close()
		return resp.StatusCode
	}

	code, body := get("/ping")
	assert.Equal(t, http.StatusOK, code)
	assert.JSONEq(t, `{"ok":true}`, body)

	code, body = get("/fleet")
	require.Equal(t, http.StatusOK, code)
	var info Info
	require.NoError(t, json.Unmarshal([]byte(body), &info))
	assert.Equal(t, "fleet.test", info.Domain)
	require.Len(t, info.Servers, len(AllKinds))
	assert.Equal(t, KindValid, info.Servers[0].Kind)
	assert.Equal(t, f.Addr(KindValid), info.Servers[0].Addr)
	assert.Equal(t, "valid.fleet.test", info.Servers[0].Host)
	assert.Len(t, info.Servers[0].ChainSHA256, 2)
	for _, s := range info.Servers {
		if s.Kind == KindManySNI {
			assert.Equal(t, 256, s.SNINames)
		}
	}

	code, body = get("/ca")
	require.Equal(t, http.StatusOK, code)
	blk, _ := pem.Decode([]byte(body))
	require.NotNil(t, blk)
	assert.Equal(t, f.Root().Raw, blk.Bytes)

	require.NoError(t, handshake(t, f.Addr(KindTLS13), "ctl.fleet.test", nil).err)
	code, body = get("/log?settle=1")
	require.Equal(t, http.StatusOK, code)
	var log []Access
	require.NoError(t, json.Unmarshal([]byte(body), &log))
	require.Len(t, log, 1)
	assert.Equal(t, "ctl.fleet.test", log[0].SNI)
	assert.Contains(t, body, `"bytes_written"`)

	code, body = get("/counters")
	require.Equal(t, http.StatusOK, code)
	var counters Counters
	require.NoError(t, json.Unmarshal([]byte(body), &counters))
	assert.Equal(t, int64(1), counters.Accepted[KindTLS13])
	assert.Zero(t, counters.AppBytesAfterHandshake)

	assert.Equal(t, http.StatusOK, post("/log/clear"))
	_, body = get("/log")
	assert.Equal(t, "[]", strings.TrimSpace(body))

	assert.Equal(t, http.StatusMethodNotAllowed, post("/ping"))
	code, _ = get("/log/clear")
	assert.Equal(t, http.StatusMethodNotAllowed, code)
	code, _ = get("/nope")
	assert.Equal(t, http.StatusNotFound, code)
}

// The valid server's own certificate and key: an e2e journey stores exactly the certificate the fleet presents in
// Alice's inventory, so a discovered certificate shows as known to Alice.
func TestControlHandlerValidPair(t *testing.T) {
	f := sharedFleet(t)
	srv := httptest.NewServer(f.ControlHandler())
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/valid-pair") //nolint:gosec,noctx // a test server
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var pair struct {
		CertificatePEM string `json:"certificate_pem"`
		PrivateKeyPEM  string `json:"private_key_pem"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&pair))
	_, err = tls.X509KeyPair([]byte(pair.CertificatePEM), []byte(pair.PrivateKeyPEM))
	require.NoError(t, err, "the key belongs to the leaf")
	var chain [][]byte
	for rest := []byte(pair.CertificatePEM); ; {
		var blk *pem.Block
		if blk, rest = pem.Decode(rest); blk == nil {
			break
		}
		chain = append(chain, blk.Bytes)
	}
	assert.Equal(t, f.Server(KindValid).Chain(), chain, "the chain the valid server presents, leaf first")

	other, err := New(Options{Kinds: []Kind{KindPlainText}})
	require.NoError(t, err)
	defer func() { _ = other.Close() }()
	rec := httptest.NewRecorder()
	other.ControlHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/valid-pair", nil))
	assert.Equal(t, http.StatusNotFound, rec.Code, "a fleet without the valid server has no pair")
}
