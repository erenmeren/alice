package fakefleet

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"io"
	"math/big"
	"net"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func verify(f *Fleet, leaf *x509.Certificate, host string, inters ...*x509.Certificate) error {
	roots := x509.NewCertPool()
	roots.AddCert(f.Root())
	pool := x509.NewCertPool()
	for _, c := range inters {
		pool.AddCert(c)
	}
	_, err := leaf.Verify(x509.VerifyOptions{DNSName: host, Roots: roots, Intermediates: pool, CurrentTime: testNow})
	return err
}

func TestValidServerPresentsLeafAndIntermediate(t *testing.T) {
	f := sharedFleet(t)
	s := f.Server(KindValid)
	r := handshake(t, s.Addr(), s.Host(), nil)
	leaf := leafOf(t, r)
	require.Len(t, r.state.PeerCertificates, 2)
	assert.Equal(t, uint16(tls.VersionTLS13), r.state.Version, "a modern server negotiates TLS 1.3")
	assert.Equal(t, "valid.fleet.test", s.Host())
	assert.Equal(t, s.Host(), leaf.Subject.CommonName)
	assert.Equal(t, f.CA().Intermediate.Raw, r.state.PeerCertificates[1].Raw)
	assert.NoError(t, verify(f, leaf, s.Host(), r.state.PeerCertificates[1]))
	assert.Equal(t, s.Chain(), [][]byte{leaf.Raw, f.CA().Intermediate.Raw}, "Chain is what the server presents")
}

func TestValidityKinds(t *testing.T) {
	f := sharedFleet(t)
	expired := leafOf(t, handshake(t, f.Addr(KindExpired), "", nil))
	assert.True(t, expired.NotAfter.Before(testNow))
	var invalid x509.CertificateInvalidError
	require.ErrorAs(t, verify(f, expired, f.Server(KindExpired).Host(), f.CA().Intermediate), &invalid)
	assert.Equal(t, x509.Expired, invalid.Reason)

	future := leafOf(t, handshake(t, f.Addr(KindNotYetValid), "", nil))
	assert.True(t, future.NotBefore.After(testNow))
	require.ErrorAs(t, verify(f, future, f.Server(KindNotYetValid).Host(), f.CA().Intermediate), &invalid)
	assert.Equal(t, x509.Expired, invalid.Reason, "Go reports a not-yet-valid certificate as Expired too")
}

func TestSelfSignedServer(t *testing.T) {
	f := sharedFleet(t)
	r := handshake(t, f.Addr(KindSelfSigned), "", nil)
	leaf := leafOf(t, r)
	require.Len(t, r.state.PeerCertificates, 1)
	assert.Equal(t, leaf.Subject.String(), leaf.Issuer.String())
	assert.NoError(t, leaf.CheckSignature(leaf.SignatureAlgorithm, leaf.RawTBSCertificate, leaf.Signature), "signed by its own key")
	assert.Error(t, verify(f, leaf, f.Server(KindSelfSigned).Host()))
}

func TestWrongOrderAndMissingIntermediate(t *testing.T) {
	f := sharedFleet(t)
	r := handshake(t, f.Addr(KindWrongOrder), "", nil)
	leafOf(t, r)
	require.Len(t, r.state.PeerCertificates, 3)
	assert.Equal(t, f.Root().Raw, r.state.PeerCertificates[1].Raw, "the root comes before the intermediate")
	assert.Equal(t, f.CA().Intermediate.Raw, r.state.PeerCertificates[2].Raw)

	r = handshake(t, f.Addr(KindMissingIntermediate), "", nil)
	leaf := leafOf(t, r)
	require.Len(t, r.state.PeerCertificates, 1)
	host := f.Server(KindMissingIntermediate).Host()
	var unknown x509.UnknownAuthorityError
	assert.ErrorAs(t, verify(f, leaf, host), &unknown, "the chain cannot be built from what the server sends")
	assert.NoError(t, verify(f, leaf, host, f.CA().Intermediate), "it is a good leaf with the intermediate supplied")
}

func TestSNIDependentCertificates(t *testing.T) {
	f := sharedFleet(t)
	s := f.Server(KindSNI)
	require.Equal(t, []string{"alpha.sni.fleet.test", "beta.sni.fleet.test"}, s.SNINames())
	seen := map[string]bool{}
	for _, name := range s.SNINames() {
		leaf := leafOf(t, handshake(t, s.Addr(), name, nil))
		assert.Equal(t, name, leaf.Subject.CommonName)
		assert.Equal(t, s.ChainFor(name)[0], leaf.Raw)
		seen[leaf.SerialNumber.String()] = true
	}
	upper := leafOf(t, handshake(t, s.Addr(), "ALPHA.sni.fleet.test", nil))
	assert.Equal(t, "alpha.sni.fleet.test", upper.Subject.CommonName, "names are matched without case")
	for _, sni := range []string{"", "unknown.fleet.test"} {
		leaf := leafOf(t, handshake(t, s.Addr(), sni, nil))
		assert.Equal(t, s.Host(), leaf.Subject.CommonName, "the default certificate for %q", sni)
		assert.Equal(t, s.Chain()[0], leaf.Raw)
		seen[leaf.SerialNumber.String()] = true
	}
	assert.Len(t, seen, 3, "three different certificates")
	assert.Nil(t, s.ChainFor("unknown.fleet.test"))
}

func TestManySNINames(t *testing.T) {
	f := sharedFleet(t)
	s := f.Server(KindManySNI)
	names := s.SNINames()
	require.Len(t, names, 256)
	assert.Equal(t, "sni-000.many-sni.fleet.test", names[0])
	assert.Equal(t, "sni-255.many-sni.fleet.test", names[255])
	fps := map[string]bool{}
	for _, n := range names {
		fps[string(s.ChainFor(n)[0])] = true
	}
	assert.Len(t, fps, 256, "every name has its own certificate")
	for _, n := range []string{names[0], names[17], names[255]} {
		leaf := leafOf(t, handshake(t, s.Addr(), n, nil))
		assert.Equal(t, s.ChainFor(n)[0], leaf.Raw)
		assert.Equal(t, []string{n}, leaf.DNSNames)
	}
	assert.Equal(t, s.Host(), leafOf(t, handshake(t, s.Addr(), "", nil)).Subject.CommonName)
}

func TestVersionOnlyServers(t *testing.T) {
	f := sharedFleet(t)
	for _, tc := range []struct {
		kind    Kind
		version uint16
	}{{KindTLS10, tls.VersionTLS10}, {KindTLS12, tls.VersionTLS12}, {KindTLS13, tls.VersionTLS13}} {
		r := handshake(t, f.Addr(tc.kind), "", nil)
		require.NoError(t, r.err, tc.kind)
		assert.Equal(t, tc.version, r.state.Version, tc.kind)
		// A client that does not offer the version fails.
		r = handshake(t, f.Addr(tc.kind), "", func(c *tls.Config) {
			if tc.version == tls.VersionTLS13 {
				c.MaxVersion = tls.VersionTLS12
			} else {
				c.MinVersion = tc.version + 1
			}
		})
		assert.Error(t, r.err, tc.kind)
	}
	// Go's default client (TLS 1.2 minimum) cannot talk to the TLS 1.0 server.
	r := handshake(t, f.Addr(KindTLS10), "", func(c *tls.Config) { c.MinVersion = 0 })
	assert.ErrorContains(t, r.err, "protocol version")
}

// Amendment A6: the outcome of the RSA key exchange server under Go's crypto/tls is recorded here.
func TestRSAKeyExchangeOnlyServer(t *testing.T) {
	f := sharedFleet(t)
	r := handshake(t, f.Addr(KindRSAKeyExchange), "", nil)
	leaf := leafOf(t, r)
	assert.Equal(t, x509.RSA, leaf.PublicKeyAlgorithm)
	assert.Equal(t, uint16(tls.VersionTLS12), r.state.Version)
	assert.True(t, strings.HasPrefix(tls.CipherSuiteName(r.state.CipherSuite), "TLS_RSA_WITH_"),
		"a client that lists the RSA suites explicitly gets one: %s", tls.CipherSuiteName(r.state.CipherSuite))
	// Go's default suite list has no RSA key exchange (since Go 1.22): the default client fails.
	r = handshake(t, f.Addr(KindRSAKeyExchange), "", func(c *tls.Config) { c.CipherSuites = nil })
	assert.ErrorContains(t, r.err, "handshake failure")
}

// Amendment A6: a SHA-1-signed leaf is presented and parsed; only verification refuses it.
func TestSHA1SignedServer(t *testing.T) {
	f := sharedFleet(t)
	r := handshake(t, f.Addr(KindSHA1), "", nil)
	leaf := leafOf(t, r)
	require.Len(t, r.state.PeerCertificates, 2)
	assert.Equal(t, x509.SHA1WithRSA, leaf.SignatureAlgorithm)
	inter := r.state.PeerCertificates[1]
	assert.Equal(t, x509.RSA, inter.PublicKeyAlgorithm, "a legacy RSA intermediate signs it")
	var insecure x509.InsecureAlgorithmError
	assert.ErrorAs(t, leaf.CheckSignatureFrom(inter), &insecure, "Go refuses SHA-1 signatures when verifying")
	assert.NoError(t, inter.CheckSignatureFrom(f.Root()))
}

// The malformed server presents a leaf with a negative serial number. Go's client refuses to parse it
// (so it never reaches VerifyPeerCertificate); the DER is on the wire, which the test reads from the
// cleartext TLS 1.2 Certificate message.
func TestMalformedCertificateServer(t *testing.T) {
	f := sharedFleet(t)
	s := f.Server(KindMalformed)
	var rawSeen [][]byte
	r := handshake(t, s.Addr(), "", func(c *tls.Config) {
		c.VerifyPeerCertificate = func(raw [][]byte, _ [][]*x509.Certificate) error {
			rawSeen = raw
			return nil
		}
	})
	assert.ErrorContains(t, r.err, "failed to parse certificate")
	assert.Nil(t, rawSeen, "Go's client parses before VerifyPeerCertificate: the callback never runs")

	chain := certificateMessage(t, s.Addr())
	require.Len(t, chain, 2)
	assert.Equal(t, s.Chain(), chain, "the raw DER is served as it is")
	_, err := x509.ParseCertificate(chain[0])
	assert.ErrorContains(t, err, "negative serial number")
	assert.Equal(t, 0, negativeSerial(t, chain[0]).Cmp(big.NewInt(-4242)))
}

func TestHugeChainServer(t *testing.T) {
	f := sharedFleet(t)
	s := f.Server(KindHugeChain)
	r := handshake(t, s.Addr(), "", nil)
	assert.ErrorContains(t, r.err, "exceeds maximum", "Go's client refuses a certificate message over its limit")
	chain := certificateMessage(t, s.Addr())
	require.Len(t, chain, 10000, "the server really sends ten thousand certificates")
	assert.Equal(t, s.Chain()[0], chain[0])
	assert.Equal(t, f.CA().Intermediate.Raw, chain[9999])
}

func TestGiantChainServerIsBoundedOnItsSide(t *testing.T) {
	f := sharedFleet(t)
	s := f.Server(KindGiantChain)
	r := handshake(t, s.Addr(), "", nil)
	assert.ErrorContains(t, r.err, "exceeds maximum", "the claimed size is refused at the header")

	// A client that reads everything gets the claim and at most GiantBytes of body, then EOF.
	got, err := readAll(t, s.Addr(), goClientHello(t), 10*time.Second)
	require.NoError(t, err)
	recs := records(t, got)
	require.NotEmpty(t, recs)
	hs := bytes.Join(handshakePayloads(recs), nil)
	require.GreaterOrEqual(t, len(hs), 4)
	assert.Equal(t, byte(2), hs[0], "a ServerHello first")
	shLen := int(hs[1])<<16 | int(hs[2])<<8 | int(hs[3])
	cert := hs[4+shLen:]
	assert.Equal(t, []byte{11, 0xff, 0xff, 0xff}, cert[:4], "a Certificate message claiming the protocol maximum")
	assert.Equal(t, int64(1<<20), int64(len(cert)-4), "exactly GiantBytes of body")
	require.NoError(t, f.WaitIdle(ctx(t)))
	for _, a := range s.Log() {
		assert.LessOrEqual(t, a.BytesWritten, int64(1<<20+64*1024), "the fake never writes past its budget")
	}
}

func TestSlowLorisTricklesUntilTheClientLeaves(t *testing.T) {
	f := sharedFleet(t)
	s := f.Server(KindSlowLoris)
	c, err := net.Dial("tcp", s.Addr())
	require.NoError(t, err)
	_, err = c.Write(goClientHello(t))
	require.NoError(t, err)
	buf := make([]byte, 1)
	for i := 0; i < 3; i++ {
		require.NoError(t, c.SetReadDeadline(time.Now().Add(5*time.Second)))
		n, err := c.Read(buf)
		require.NoError(t, err)
		assert.Equal(t, 1, n, "one byte at a time")
	}
	require.NoError(t, c.Close())

	cl, err := net.Dial("tcp", s.Addr())
	require.NoError(t, err)
	require.NoError(t, cl.SetDeadline(time.Now().Add(200*time.Millisecond)))
	err = tls.Client(cl, probeConfig("")).Handshake()
	var ne net.Error
	require.ErrorAs(t, err, &ne)
	assert.True(t, ne.Timeout(), "the handshake never completes: %v", err)
	_ = cl.Close()

	require.NoError(t, f.WaitIdle(ctx(t)))
	log := s.Log()
	require.Len(t, log, 2)
	for _, a := range log {
		assert.True(t, a.Closed, "the fake stopped when the client left")
		assert.False(t, a.Handshake)
	}
	assert.GreaterOrEqual(t, log[0].BytesWritten, int64(3))
}

func TestResetServer(t *testing.T) {
	f := sharedFleet(t)
	r := handshake(t, f.Addr(KindReset), "reset.fleet.test", nil)
	assert.True(t, errors.Is(r.err, syscall.ECONNRESET), "a reset: %v", r.err)
	require.NoError(t, f.WaitIdle(ctx(t)))
	log := f.Server(KindReset).Log()
	require.Len(t, log, 1)
	assert.Equal(t, "reset.fleet.test", log[0].SNI, "the hello is read before the reset")
	assert.Zero(t, log[0].BytesWritten)
}

func TestPlainTextServer(t *testing.T) {
	f := sharedFleet(t)
	r := handshake(t, f.Addr(KindPlainText), "", nil)
	assert.ErrorContains(t, r.err, "does not look like a TLS handshake")
	assert.Equal(t, PlainTextBanner, readBanner(t, f.Addr(KindPlainText)))

	// The server keeps the connection until the client leaves, then logs what it read; no reset.
	c, err := net.Dial("tcp", f.Addr(KindPlainText))
	require.NoError(t, err)
	_, err = c.Write([]byte("EHLO probe\r\n"))
	require.NoError(t, err)
	b := make([]byte, len(PlainTextBanner))
	require.NoError(t, c.SetReadDeadline(time.Now().Add(5*time.Second)))
	_, err = io.ReadFull(c, b)
	require.NoError(t, err)
	require.NoError(t, c.(*net.TCPConn).CloseWrite())
	rest, err := io.ReadAll(c)
	assert.NoError(t, err, "the fake closes cleanly after the client: no reset")
	assert.Empty(t, rest)
	_ = c.Close()
	require.NoError(t, f.WaitIdle(ctx(t)))
	log := f.Server(KindPlainText).Log()
	require.NotEmpty(t, log)
	last := log[len(log)-1]
	assert.Equal(t, int64(len("EHLO probe\r\n")), last.BytesRead)
	assert.Equal(t, int64(len(PlainTextBanner)), last.BytesWritten)
}

func TestEveryKindIsDistinctAndListed(t *testing.T) {
	f := sharedFleet(t)
	require.Len(t, f.Servers(), len(AllKinds))
	addrs := map[string]bool{}
	for i, s := range f.Servers() {
		assert.Equal(t, AllKinds[i], s.Kind())
		assert.Equal(t, s, f.Server(s.Kind()))
		assert.False(t, addrs[s.Addr()])
		addrs[s.Addr()] = true
		host, _, err := net.SplitHostPort(s.Addr())
		require.NoError(t, err)
		assert.Equal(t, "127.0.0.1", host)
		_, inPorts := DefaultPorts[s.Kind()]
		assert.True(t, inPorts, "%s has a default port", s.Kind())
	}
	assert.Nil(t, f.Server("nope"))
	assert.Empty(t, f.Addr("nope"))
	assert.Len(t, DefaultPorts, len(AllKinds))
	ports := map[int]bool{}
	for _, p := range DefaultPorts {
		assert.False(t, ports[p], "port %d twice", p)
		ports[p] = true
	}
}

// ---- wire helpers ----

// goClientHello is the first flight of a real Go client (TLS 1.0 to 1.3), captured from a pipe.
func goClientHello(t *testing.T) []byte {
	t.Helper()
	a, b := net.Pipe()
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_ = tls.Client(a, probeConfig("hello.fleet.test")).Handshake()
	}()
	hdr := make([]byte, 5)
	_, err := io.ReadFull(b, hdr)
	require.NoError(t, err)
	body := make([]byte, binary.BigEndian.Uint16(hdr[3:]))
	_, err = io.ReadFull(b, body)
	require.NoError(t, err)
	_ = b.Close()
	_ = a.Close()
	wg.Wait()
	return append(hdr, body...)
}

type wireRecord struct {
	typ  byte
	body []byte
}

func records(t *testing.T, b []byte) []wireRecord {
	t.Helper()
	var out []wireRecord
	for len(b) >= 5 {
		n := int(binary.BigEndian.Uint16(b[3:]))
		if len(b) < 5+n {
			break
		}
		out = append(out, wireRecord{typ: b[0], body: b[5 : 5+n]})
		b = b[5+n:]
	}
	return out
}

func handshakePayloads(recs []wireRecord) [][]byte {
	var out [][]byte
	for _, r := range recs {
		if r.typ == 22 {
			out = append(out, r.body)
		}
	}
	return out
}

// certificateMessage reads the cleartext TLS 1.2 Certificate message a server sends to a TLS 1.2 client.
func certificateMessage(t *testing.T, addr string) [][]byte {
	t.Helper()
	c, err := net.DialTimeout("tcp", addr, 5*time.Second)
	require.NoError(t, err)
	defer func() { _ = c.Close() }()
	require.NoError(t, c.SetDeadline(time.Now().Add(10*time.Second)))
	var wire bytes.Buffer
	tc := tls.Client(&teeConn{Conn: c, w: &wire}, func() *tls.Config {
		cfg := probeConfig("")
		cfg.MaxVersion = tls.VersionTLS12
		return cfg
	}())
	_ = tc.Handshake() // fails: the test reads the rest of the flight itself
	rest, _ := io.ReadAll(c)
	wire.Write(rest)
	hs := bytes.Join(handshakePayloads(records(t, wire.Bytes())), nil)
	for len(hs) >= 4 {
		n := int(hs[1])<<16 | int(hs[2])<<8 | int(hs[3])
		require.GreaterOrEqual(t, len(hs), 4+n, "a complete handshake message")
		if hs[0] == 11 {
			body := hs[4 : 4+n]
			total := int(body[0])<<16 | int(body[1])<<8 | int(body[2])
			body = body[3:]
			require.Len(t, body, total)
			var chain [][]byte
			for len(body) > 0 {
				l := int(body[0])<<16 | int(body[1])<<8 | int(body[2])
				chain = append(chain, body[3:3+l])
				body = body[3+l:]
			}
			return chain
		}
		hs = hs[4+n:]
	}
	t.Fatal("no Certificate message")
	return nil
}

type teeConn struct {
	net.Conn
	w io.Writer
}

func (c *teeConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	_, _ = c.w.Write(p[:n])
	return n, err
}

// negativeSerial reads the serial number of a DER certificate that x509 refuses to parse.
func negativeSerial(t *testing.T, der []byte) *big.Int {
	t.Helper()
	// Certificate SEQUENCE > TBSCertificate SEQUENCE > [0] version > INTEGER serial.
	skipHeader := func(b []byte) []byte {
		if b[1]&0x80 == 0 {
			return b[2:]
		}
		return b[2+int(b[1]&0x7f):]
	}
	tbs := skipHeader(skipHeader(der))
	require.Equal(t, byte(0xa0), tbs[0])
	tbs = tbs[2+int(tbs[1]):]
	require.Equal(t, byte(0x02), tbs[0])
	v := tbs[2 : 2+int(tbs[1])]
	n := new(big.Int).SetBytes(v)
	if v[0]&0x80 != 0 {
		n.Sub(n, new(big.Int).Lsh(big.NewInt(1), uint(8*len(v))))
	}
	return n
}
