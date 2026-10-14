package tlsprobe

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/certs"
	"alice/internal/platform/netaddr"
	"alice/internal/testutil/fakefleet"
	"alice/internal/testutil/pki"
	"alice/internal/testutil/scanpolicy"
)

var testNow = time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)

var (
	fleetOnce sync.Once
	fleet     *fakefleet.Fleet
	fleetErr  error
	fleetMu   sync.Mutex // tests that read the fleet's log or counters hold it
)

func TestMain(m *testing.M) {
	code := m.Run()
	if fleet != nil {
		_ = fleet.Close()
	}
	os.Exit(code)
}

// sharedFleet is the fleet of every kind, built once per test binary. The test holds it for its
// whole run: on return, every connection has finished and no client sent an application byte.
func sharedFleet(t *testing.T) *fakefleet.Fleet {
	t.Helper()
	fleetOnce.Do(func() {
		fleet, fleetErr = fakefleet.New(fakefleet.Options{Now: testNow, IdleTimeout: 10 * time.Second,
			SlowLorisInterval: 10 * time.Millisecond, GiantBytes: 1 << 20})
	})
	require.NoError(t, fleetErr)
	fleetMu.Lock()
	require.NoError(t, fleet.WaitIdle(testCtx(t)))
	fleet.ClearLog()
	t.Cleanup(func() {
		defer fleetMu.Unlock()
		require.NoError(t, fleet.WaitIdle(testCtx(t)))
		assert.Zero(t, fleet.AppBytesAfterHandshake(), "the probe sent application bytes after a handshake")
		for _, a := range fleet.Log() {
			assert.Zero(t, a.AppBytes, "%s: application bytes after the handshake", a.Kind)
		}
	})
	return fleet
}

func testCtx(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)
	return ctx
}

// counting is a test dialer: netaddr.ScanDialContext with a permissive scan policy (the production
// path, with a 3 s connect timeout), counting the bytes the probe reads and writes.
type counting struct {
	policy  netaddr.ScanPolicy
	read    atomic.Int64
	written atomic.Int64
	dials   atomic.Int64
}

func newCounting(except ...netip.Prefix) *counting {
	return &counting{policy: scanpolicy.Permissive(except...)}
}

func (c *counting) dial(ctx context.Context, network, address string) (net.Conn, error) {
	c.dials.Add(1)
	conn, err := netaddr.ScanDialContext(ctx, c.policy, &net.Dialer{Timeout: 3 * time.Second}, network, address)
	if err != nil {
		return nil, err
	}
	return &countedConn{Conn: conn, c: c}, nil
}

type countedConn struct {
	net.Conn
	c *counting
}

func (cc *countedConn) Read(p []byte) (int, error) {
	n, err := cc.Conn.Read(p)
	cc.c.read.Add(int64(n))
	return n, err
}

func (cc *countedConn) Write(p []byte) (int, error) {
	n, err := cc.Conn.Write(p)
	cc.c.written.Add(int64(n))
	return n, err
}

func capture(t *testing.T, addr, sni string) (Result, *counting, error) {
	t.Helper()
	d := newCounting()
	r, err := CapturePresentedChain(testCtx(t), d.dial, addr, sni)
	return r, d, err
}

func requireCode(t *testing.T, err error, want Code) {
	t.Helper()
	require.Error(t, err)
	code, ok := CodeOf(err)
	require.True(t, ok, "not a probe error: %v", err)
	assert.Equal(t, want, code)
	assert.Equal(t, "tlsprobe: "+string(want), err.Error(), "the error carries the code only")
}

func TestCapturesEveryPresentedChainAsPresented(t *testing.T) {
	f := sharedFleet(t)
	for _, k := range []fakefleet.Kind{fakefleet.KindValid, fakefleet.KindExpired, fakefleet.KindNotYetValid, fakefleet.KindSelfSigned,
		fakefleet.KindWrongOrder, fakefleet.KindMissingIntermediate, fakefleet.KindSHA1, fakefleet.KindManySNI} {
		s := f.Server(k)
		r, _, err := capture(t, s.Addr(), s.Host())
		require.NoError(t, err, k)
		assert.Equal(t, s.Chain(), r.Certificates, "%s: the chain as presented, in its order", k)
		assert.Equal(t, s.Host(), r.SNI, k)
		assert.Equal(t, "TLS 1.3", r.TLSVersion, k)
		assert.NotEmpty(t, r.CipherSuite, k)
		_, err = ParsePresentedChain(r.Certificates)
		require.NoError(t, err, k)
	}
	require.NoError(t, f.WaitIdle(testCtx(t)))
	for _, a := range f.Log() {
		assert.True(t, a.Handshake, "%s: the handshake completed", a.Kind)
		assert.True(t, a.Closed, a.Kind)
		assert.Equal(t, f.Server(a.Kind).Host(), a.SNI, "%s: the SNI sent", a.Kind)
	}
}

func TestWhatTheChainsSay(t *testing.T) {
	f := sharedFleet(t)
	parse := func(k fakefleet.Kind) Chain {
		r, _, err := capture(t, f.Addr(k), "")
		require.NoError(t, err, k)
		c, err := ParsePresentedChain(r.Certificates)
		require.NoError(t, err, k)
		return c
	}
	valid := parse(fakefleet.KindValid)
	require.Len(t, valid.Certificates, 2)
	assert.False(t, valid.Leaf().SelfSigned)
	assert.False(t, valid.Leaf().IsCA)
	assert.True(t, valid.Certificates[1].IsCA)
	assert.Equal(t, f.CA().Intermediate.Subject.CommonName, valid.Leaf().IssuerCN)

	assert.True(t, parse(fakefleet.KindExpired).Leaf().NotAfter.Before(testNow))
	assert.True(t, parse(fakefleet.KindNotYetValid).Leaf().NotBefore.After(testNow))
	self := parse(fakefleet.KindSelfSigned)
	require.Len(t, self.Certificates, 1)
	assert.True(t, self.Leaf().SelfSigned)

	wrong := parse(fakefleet.KindWrongOrder)
	require.Len(t, wrong.Certificates, 3)
	assert.Equal(t, f.Root().Raw, wrong.Certificates[1].Raw, "the root second, as presented")
	assert.True(t, wrong.Certificates[1].SelfSigned)
	assert.Equal(t, f.CA().Intermediate.Raw, wrong.Certificates[2].Raw)

	assert.Len(t, parse(fakefleet.KindMissingIntermediate).Certificates, 1)
	sha1 := parse(fakefleet.KindSHA1)
	assert.Equal(t, "SHA1-RSA", sha1.Leaf().SignatureAlgorithm, "a SHA-1 signed leaf is captured")
	assert.Equal(t, "rsa", sha1.Certificates[1].KeyAlgorithm)
}

func TestSNIVariants(t *testing.T) {
	f := sharedFleet(t)
	s := f.Server(fakefleet.KindSNI)
	seen := map[string]bool{}
	for _, name := range s.SNINames() {
		r, _, err := capture(t, s.Addr(), name)
		require.NoError(t, err)
		assert.Equal(t, s.ChainFor(name)[0], r.Certificates[0], "a different leaf for %s", name)
		assert.Equal(t, name, r.SNI)
		seen[string(r.Certificates[0])] = true
	}
	for _, sni := range []string{"", "127.0.0.1", "::1", "[::1]", "fe80::1%eth0", "unknown.fleet.test"} {
		r, _, err := capture(t, s.Addr(), sni)
		require.NoError(t, err, sni)
		assert.Equal(t, s.Chain()[0], r.Certificates[0], "the default certificate for %q", sni)
		seen[string(r.Certificates[0])] = true
		if sni != "unknown.fleet.test" {
			assert.Empty(t, r.SNI, "no SNI is sent for %q", sni)
		}
	}
	assert.Len(t, seen, 3)
	require.NoError(t, f.WaitIdle(testCtx(t)))
	var sent []string
	for _, a := range f.Log() {
		sent = append(sent, a.SNI)
	}
	assert.Equal(t, []string{"alpha.sni.fleet.test", "beta.sni.fleet.test", "", "", "", "", "", "unknown.fleet.test"}, sent,
		"the server saw no SNI for an empty name or an IP literal")
}

func TestServerNameFor(t *testing.T) {
	for in, want := range map[string]string{"": "", "127.0.0.1": "", "::1": "", "[::1]": "", "fe80::1%eth0": "", "[fe80::1%25eth0]": "",
		"::ffff:10.0.0.1": "", "example.com": "example.com", "example.com.": "example.com", "a.b..": "a.b", "[x]": "[x]", "%": "%"} {
		assert.Equal(t, want, serverNameFor(in), in)
	}
}

func TestVersionsAndSuites(t *testing.T) {
	f := sharedFleet(t)
	for k, want := range map[fakefleet.Kind]string{fakefleet.KindTLS10: "TLS 1.0", fakefleet.KindTLS12: "TLS 1.2", fakefleet.KindTLS13: "TLS 1.3"} {
		r, _, err := capture(t, f.Addr(k), "")
		require.NoError(t, err, k)
		assert.Equal(t, want, r.TLSVersion, k)
		assert.Equal(t, f.Server(k).Chain(), r.Certificates, k)
	}
	// RSA key exchange only: works because the suites are listed explicitly.
	r, _, err := capture(t, f.Addr(fakefleet.KindRSAKeyExchange), "")
	require.NoError(t, err)
	assert.Equal(t, "TLS 1.2", r.TLSVersion)
	assert.True(t, strings.HasPrefix(r.CipherSuite, "TLS_RSA_WITH_"), r.CipherSuite)
}

func TestFailuresOfTheFleet(t *testing.T) {
	f := sharedFleet(t)
	for k, want := range map[fakefleet.Kind]Code{fakefleet.KindPlainText: CodeNoTLS, fakefleet.KindReset: CodeReset,
		fakefleet.KindMalformed: CodeMalformed} {
		r, _, err := capture(t, f.Addr(k), "")
		requireCode(t, err, want)
		assert.Zero(t, r, k)
	}
}

func TestChainLimitsOfTheFleet(t *testing.T) {
	f := sharedFleet(t)
	for _, k := range []fakefleet.Kind{fakefleet.KindGiantChain, fakefleet.KindHugeChain} {
		_, d, err := capture(t, f.Addr(k), "")
		requireCode(t, err, CodeChainTooLarge)
		assert.LessOrEqual(t, d.read.Load(), int64(MaxHandshakeBytes), "%s: never more than the cap is read", k)
	}
}

func TestSlowLorisHitsTheHandshakeCap(t *testing.T) {
	f := sharedFleet(t)
	shortenHandshake(t, 100*time.Millisecond)
	_, _, err := capture(t, f.Addr(fakefleet.KindSlowLoris), "")
	requireCode(t, err, CodeTimeout)
	require.NoError(t, f.WaitIdle(testCtx(t)))
	log := f.Server(fakefleet.KindSlowLoris).Log()
	require.Len(t, log, 1)
	assert.False(t, log[0].Handshake)
	assert.True(t, log[0].Closed, "the probe left")
}

// shortenHandshake sets the handshake cap for one test (tests that use it do not run in parallel).
func shortenHandshake(t *testing.T, d time.Duration) {
	t.Helper()
	old := handshakeTimeout
	handshakeTimeout = d
	t.Cleanup(func() { handshakeTimeout = old })
}

func TestHandshakeDeadline(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	assert.Equal(t, now.Add(5*time.Second), handshakeDeadline(context.Background(), now, 5*time.Second))
	ctx, cancel := context.WithDeadline(context.Background(), now.Add(time.Second))
	defer cancel()
	assert.Equal(t, now.Add(time.Second), handshakeDeadline(ctx, now, 5*time.Second), "an earlier context deadline wins")
	ctx2, cancel2 := context.WithDeadline(context.Background(), now.Add(time.Minute))
	defer cancel2()
	assert.Equal(t, now.Add(5*time.Second), handshakeDeadline(ctx2, now, 5*time.Second))
}

func TestRefusedPort(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := ln.Addr().String()
	require.NoError(t, ln.Close())
	_, _, err = capture(t, addr, "")
	requireCode(t, err, CodeRefused)
}

func TestPolicyRefusal(t *testing.T) {
	f := sharedFleet(t)
	d := newCounting(netip.MustParsePrefix("127.0.0.0/8"))
	_, err := CapturePresentedChain(testCtx(t), d.dial, f.Addr(fakefleet.KindValid), "")
	requireCode(t, err, CodePolicy)
	require.NoError(t, f.WaitIdle(testCtx(t)))
	assert.Zero(t, f.Server(fakefleet.KindValid).Accepted(), "the refused address was never dialed")

	direct := func(context.Context, string, string) (net.Conn, error) {
		return nil, fmt.Errorf("scan: %w", netaddr.ErrScanRefused)
	}
	_, err = CapturePresentedChain(testCtx(t), direct, "192.0.2.1:443", "")
	requireCode(t, err, CodePolicy)
	_, err = CapturePresentedChain(testCtx(t), nil, "192.0.2.1:443", "")
	requireCode(t, err, CodePolicy)
}

func TestContextErrorsPassThrough(t *testing.T) {
	f := sharedFleet(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	called := false
	_, err := CapturePresentedChain(ctx, func(context.Context, string, string) (net.Conn, error) {
		called = true
		return nil, errors.New("unreachable")
	}, f.Addr(fakefleet.KindValid), "")
	assert.ErrorIs(t, err, context.Canceled)
	assert.False(t, called, "a cancelled context dials nothing")

	// Cancelled while the dialer runs.
	ctx, cancel = context.WithCancel(context.Background())
	_, err = CapturePresentedChain(ctx, func(context.Context, string, string) (net.Conn, error) {
		cancel()
		return nil, syscall.ECONNREFUSED
	}, f.Addr(fakefleet.KindValid), "")
	assert.ErrorIs(t, err, context.Canceled)
	_, ok := CodeOf(err)
	assert.False(t, ok)

	// Cancelled during the handshake: the slow-loris server's first byte cancels it.
	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()
	d := newCounting()
	_, err = CapturePresentedChain(ctx, func(c context.Context, n, a string) (net.Conn, error) {
		conn, err := d.dial(c, n, a)
		if err != nil {
			return nil, err
		}
		return &cancelOnRead{Conn: conn, cancel: cancel}, nil
	}, f.Addr(fakefleet.KindSlowLoris), "")
	assert.ErrorIs(t, err, context.Canceled)

	// A context deadline before the handshake cap is the context's error, not a timeout code.
	ctx, cancel2 := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel2()
	_, err = CapturePresentedChain(ctx, d.dial, f.Addr(fakefleet.KindSlowLoris), "")
	assert.ErrorIs(t, err, context.DeadlineExceeded)
}

type cancelOnRead struct {
	net.Conn
	cancel context.CancelFunc
}

func (c *cancelOnRead) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.cancel()
	}
	return n, err
}

// ---- servers the fleet has no kind for ----

// rawServer accepts one connection, reads the ClientHello and runs then.
func rawServer(t *testing.T, then func(net.Conn)) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	done := make(chan struct{})
	go func() {
		defer close(done)
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = c.Close() }()
		_ = c.SetDeadline(time.Now().Add(10 * time.Second))
		hdr := make([]byte, 5)
		if _, err := io.ReadFull(c, hdr); err != nil {
			return
		}
		if _, err := io.ReadFull(c, make([]byte, int(hdr[3])<<8|int(hdr[4]))); err != nil {
			return
		}
		then(c)
	}()
	t.Cleanup(func() { _ = ln.Close(); <-done })
	return ln.Addr().String()
}

func TestAlertsAndClosesAreNotMalformed(t *testing.T) {
	for _, alert := range []byte{40, 42, 43, 70, 80, 112} { // handshake_failure, bad_certificate, unsupported_certificate, protocol_version, internal_error, unrecognized_name
		addr := rawServer(t, func(c net.Conn) { _, _ = c.Write([]byte{21, 3, 3, 0, 2, 2, alert}) })
		_, _, err := capture(t, addr, "")
		requireCode(t, err, CodeNoTLS)
	}
	addr := rawServer(t, func(net.Conn) {}) // closes after the hello
	_, _, err := capture(t, addr, "")
	requireCode(t, err, CodeReset)
	addr = rawServer(t, func(c net.Conn) { _, _ = c.Write([]byte{22, 3, 3, 0, 4, 99, 0, 0, 0}) }) // an unknown handshake message
	_, _, err = capture(t, addr, "")
	requireCode(t, err, CodeNoTLS)
}

// tlsServer serves chain (with the leaf's key) once and counts application bytes after the handshake.
func tlsServer(t *testing.T, chain [][]byte, key any) (string, *atomic.Int64) {
	t.Helper()
	var app atomic.Int64
	cfg := &tls.Config{Certificates: []tls.Certificate{{Certificate: chain, PrivateKey: key}}, SessionTicketsDisabled: true}
	addr := rawlessServer(t, func(c net.Conn) {
		tc := tls.Server(c, cfg)
		if tc.Handshake() != nil {
			return
		}
		n, _ := io.Copy(io.Discard, io.LimitReader(tc, 1<<20))
		app.Add(n)
	})
	return addr, &app
}

func rawlessServer(t *testing.T, serve func(net.Conn)) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	done := make(chan struct{})
	go func() {
		defer close(done)
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = c.Close() }()
		_ = c.SetDeadline(time.Now().Add(10 * time.Second))
		serve(c)
	}()
	t.Cleanup(func() { _ = ln.Close(); <-done })
	return ln.Addr().String()
}

// paddedCert is a self-signed certificate grown with SAN names to at least size bytes of DER.
func paddedCert(t *testing.T, key *pki.Leaf, size int) []byte {
	t.Helper()
	var names []string
	for i := 0; i < size/30+1; i++ {
		names = append(names, fmt.Sprintf("pad-%05d.padding.example.test", i))
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(int64(size)), Subject: pkix.Name{CommonName: "padded"},
		NotBefore: testNow.Add(-time.Hour), NotAfter: testNow.Add(time.Hour), DNSNames: names}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Key.Public(), key.Key)
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(der), size)
	return der
}

func TestChainLimits(t *testing.T) {
	var apps []*atomic.Int64
	t.Cleanup(func() { // registered first, so it runs after every server has finished
		for _, a := range apps {
			assert.Zero(t, a.Load(), "application bytes after the handshake")
		}
	})
	ca := pki.NewCA("Limits", pki.ECDSA256, testNow)
	leaf := ca.Issue(pki.Opts{CommonName: "limits.test", SANs: []string{"limits.test"}}, testNow)
	three := [][]byte{leaf.Cert.Raw, ca.Intermediate.Raw, ca.Root.Raw}

	addr, app := tlsServer(t, three, leaf.Key)
	r, _, err := capture(t, addr, "limits.test")
	require.NoError(t, err)
	assert.Equal(t, three, r.Certificates, "leaf, intermediate, root: in the order presented")

	eleven := [][]byte{leaf.Cert.Raw}
	for range MaxCertificates {
		eleven = append(eleven, ca.Intermediate.Raw)
	}
	addr2, app2 := tlsServer(t, eleven, leaf.Key)
	_, _, err = capture(t, addr2, "")
	requireCode(t, err, CodeChainTooLarge)

	oversized := paddedCert(t, &leaf, MaxCertificateSize+1)
	addr3, app3 := tlsServer(t, [][]byte{leaf.Cert.Raw, oversized}, leaf.Key)
	_, _, err = capture(t, addr3, "")
	requireCode(t, err, CodeChainTooLarge)

	piece := paddedCert(t, &leaf, 14<<10)
	require.LessOrEqual(t, len(piece), MaxCertificateSize)
	total := [][]byte{leaf.Cert.Raw, piece, piece, piece, piece, piece}
	addr4, app4 := tlsServer(t, total, leaf.Key)
	_, d, err := capture(t, addr4, "")
	requireCode(t, err, CodeChainTooLarge)
	assert.LessOrEqual(t, d.read.Load(), int64(MaxHandshakeBytes))

	// Exactly at the limits: ten certificates, 64 KiB together.
	atLimit := [][]byte{leaf.Cert.Raw}
	for range MaxCertificates - 1 {
		atLimit = append(atLimit, ca.Intermediate.Raw)
	}
	addr5, app5 := tlsServer(t, atLimit, leaf.Key)
	r, _, err = capture(t, addr5, "")
	require.NoError(t, err)
	assert.Len(t, r.Certificates, MaxCertificates)
	apps = append(apps, app, app2, app3, app4, app5)
}

// TestOversizedFlightIsCutAtTheCap: a Certificate message under Go's own 256 KiB limit but over
// MaxHandshakeBytes is cut by the probe's byte limit, at the cap.
func TestOversizedFlightIsCutAtTheCap(t *testing.T) {
	const claimed = 200 << 10
	addr := rawServer(t, func(c net.Conn) {
		sh := []byte{2, 0, 0, 38, 3, 3}
		sh = append(sh, make([]byte, 32)...)
		sh = append(sh, 0, 0xc0, 0x2b, 0) // no session id, ECDHE-ECDSA-AES128-GCM-SHA256, no compression
		n := claimed
		sh = append(sh, 11, byte(n>>16), byte(n>>8), byte(n))
		if _, err := c.Write(append([]byte{22, 3, 3, byte(len(sh) >> 8), byte(len(sh))}, sh...)); err != nil {
			return
		}
		rec := append([]byte{22, 3, 3, 0x40, 0}, make([]byte, 16384)...)
		for sent := 0; sent < claimed; sent += 16384 {
			if _, err := c.Write(rec); err != nil {
				return
			}
		}
	})
	_, d, err := capture(t, addr, "")
	requireCode(t, err, CodeChainTooLarge)
	assert.Equal(t, int64(MaxHandshakeBytes), d.read.Load(), "exactly the cap was read, nothing more")
}

func TestChainWithinLimits(t *testing.T) {
	c := make([]byte, MaxCertificateSize)
	assert.True(t, chainWithinLimits(nil))
	assert.True(t, chainWithinLimits([][]byte{c, c, c, c}), "exactly 64 KiB")
	assert.False(t, chainWithinLimits([][]byte{c, c, c, c, {1}}))
	assert.False(t, chainWithinLimits([][]byte{make([]byte, MaxCertificateSize+1)}))
	assert.False(t, chainWithinLimits(make([][]byte, MaxCertificates+1)))
	assert.True(t, chainWithinLimits(make([][]byte, MaxCertificates)))
}

// TestGoErrorTextsArePinned pins the two crypto/tls error texts the classification depends on
// (Go 1.27.2 reports neither with a typed error). A Go upgrade that changes either fails here.
func TestGoErrorTextsArePinned(t *testing.T) {
	f := sharedFleet(t)
	plain := func(k fakefleet.Kind) error {
		c, err := net.DialTimeout("tcp", f.Addr(k), 3*time.Second)
		require.NoError(t, err)
		defer func() { _ = c.Close() }()
		require.NoError(t, c.SetDeadline(time.Now().Add(5*time.Second)))
		cfg := &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS10} //nolint:gosec // G402: a test reading Go's error text
		return tls.Client(c, cfg).Handshake()
	}
	err := plain(fakefleet.KindMalformed)
	require.Error(t, err)
	assert.True(t, strings.HasPrefix(err.Error(), goCertificateParseFailure), "Go's text for an unparseable certificate: %q", err)
	assert.Equal(t, CodeMalformed, codeFor(err, true))

	err = plain(fakefleet.KindGiantChain)
	require.Error(t, err)
	assert.True(t, strings.HasPrefix(err.Error(), goHandshakeTooLarge) && strings.Contains(err.Error(), goHandshakeTooLargeMiddle),
		"Go's text for an oversized handshake message: %q", err)
	assert.Equal(t, CodeChainTooLarge, codeFor(err, true))
	assert.False(t, errors.Is(err, errChainTooLarge), "the giant chain is refused by Go's own limit (header), not ours")
}

func TestCodeFor(t *testing.T) {
	op := func(e error) error {
		return &net.OpError{Op: "dial", Net: "tcp", Err: os.NewSyscallError("connect", e)}
	}
	for _, tc := range []struct {
		err       error
		handshake bool
		want      Code
	}{
		{fmt.Errorf("x: %w", netaddr.ErrScanRefused), false, CodePolicy},
		{op(syscall.ECONNREFUSED), false, CodeRefused},
		{op(syscall.ENETUNREACH), false, CodeRefused},
		{op(syscall.EHOSTUNREACH), false, CodeRefused},
		{errors.New("something else"), false, CodeRefused},
		{op(syscall.ETIMEDOUT), false, CodeTimeout}, // the kernel gave up connecting
		{&net.OpError{Op: "dial", Err: os.ErrDeadlineExceeded}, false, CodeTimeout},
		{os.ErrDeadlineExceeded, true, CodeTimeout},
		{op(syscall.ECONNRESET), true, CodeReset},
		{op(syscall.EPIPE), true, CodeReset},
		{op(syscall.ECONNABORTED), true, CodeReset},
		{io.EOF, true, CodeReset},
		{io.ErrUnexpectedEOF, true, CodeReset},
		{tls.RecordHeaderError{Msg: "first record does not look like a TLS handshake"}, true, CodeNoTLS},
		{&net.OpError{Op: "remote error", Err: errors.New("tls: bad certificate")}, true, CodeNoTLS},
		{errors.New("tls: server sent certificate containing RSA key larger than 8192 bits"), true, CodeNoTLS},
		{errors.New("x509: negative serial number"), true, CodeNoTLS},
		{errors.New("tls: failed to parse certificate from server: x509: negative serial number"), true, CodeMalformed},
		{errors.New("tls: failed to parse certificate from server: x509: negative serial number"), false, CodeRefused},
		{fmt.Errorf("wrapped: %w", errors.New("tls: failed to parse certificate from server: x509: x")), true, CodeNoTLS},
		{errors.New("tls: handshake message of length 16777215 bytes exceeds maximum of 262144 bytes"), true, CodeChainTooLarge},
		{errors.New("tls: handshake message of length 3"), true, CodeNoTLS},
		{fmt.Errorf("read: %w", errChainTooLarge), true, CodeChainTooLarge},
	} {
		assert.Equal(t, tc.want, codeFor(tc.err, tc.handshake), "%v (handshake %v)", tc.err, tc.handshake)
	}
	code, ok := CodeOf(fmt.Errorf("x: %w", &Error{Code: CodeReset}))
	assert.True(t, ok)
	assert.Equal(t, CodeReset, code)
	_, ok = CodeOf(errors.New("x"))
	assert.False(t, ok)
	assert.Len(t, Codes, 7)
}

func TestLimitedConnStopsAtTheCap(t *testing.T) {
	a, b := net.Pipe()
	defer func() { _ = a.Close(); _ = b.Close() }()
	go func() { _, _ = b.Write(make([]byte, 100)) }()
	lc := &limitedConn{Conn: a, left: 10}
	buf := make([]byte, 64)
	n, err := lc.Read(buf)
	require.NoError(t, err)
	assert.Equal(t, 10, n, "a read never goes past the cap")
	_, err = lc.Read(buf)
	assert.ErrorIs(t, err, errChainTooLarge)
}

// The fingerprint, serial, key and self-signed definitions are internal/certs' (certificates.
// fingerprint_sha256 is what "unmanaged" joins on).
func TestDefinitionsMatchTheInventory(t *testing.T) {
	f := sharedFleet(t)
	for _, k := range []fakefleet.Kind{fakefleet.KindValid, fakefleet.KindSelfSigned, fakefleet.KindSHA1, fakefleet.KindRSAKeyExchange,
		fakefleet.KindWrongOrder} {
		for _, der := range f.Server(k).Chain() {
			c, err := ParsePresentedChain([][]byte{der})
			require.NoError(t, err, k)
			p, err := certs.ParseChainPEM(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
			require.NoError(t, err, k)
			got := c.Leaf()
			assert.Equal(t, p.Fingerprint, got.FingerprintSHA256, k)
			assert.Equal(t, p.Serial, got.Serial, k)
			assert.Equal(t, p.Algorithm, got.KeyAlgorithm, k)
			assert.Equal(t, p.Bits, got.KeyBits, k)
			assert.Equal(t, p.SelfSigned, got.SelfSigned, k)
			assert.Equal(t, p.SubjectCN, got.SubjectCN, k)
			var sans []string
			sans = append(append(sans, got.DNSNames...), got.IPAddresses...)
			assert.Equal(t, p.SANs, sans, k)
		}
	}
}

// A connection whose deadline cannot be set is closed without a handshake.
func TestDeadlineFailureEndsTheProbe(t *testing.T) {
	a, b := net.Pipe()
	require.NoError(t, b.Close())
	_, err := CapturePresentedChain(testCtx(t), func(context.Context, string, string) (net.Conn, error) {
		require.NoError(t, a.Close())
		return a, nil
	}, "192.0.2.1:443", "")
	requireCode(t, err, CodeNoTLS)
}
