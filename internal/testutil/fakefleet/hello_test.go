package fakefleet

import (
	"bytes"
	"crypto/tls"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReadHelloParsesAGoClientHello(t *testing.T) {
	raw := goClientHello(t)
	got, h := readHello(bytes.NewReader(raw))
	assert.Equal(t, raw, got)
	assert.Equal(t, "hello.fleet.test", h.serverName)
	assert.Contains(t, h.suites, tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256)
	assert.Contains(t, h.suites, tls.TLS_RSA_WITH_AES_128_CBC_SHA, "the probe configuration offers the RSA suites")
}

func TestReadHelloIsBestEffort(t *testing.T) {
	raw := goClientHello(t)
	for name, in := range map[string][]byte{
		"empty":             nil,
		"short header":      {22, 3},
		"not a handshake":   []byte("GET / HTTP/1.1\r\n"),
		"oversized record":  {22, 3, 1, 0xff, 0xff},
		"truncated body":    raw[:len(raw)-10],
		"not a ClientHello": {22, 3, 1, 0, 4, 2, 0, 0, 0},
		"no extensions":     {22, 3, 1, 0, 45, 1, 0, 0, 41, 3, 3, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 0, 0, 2, 0xc0, 0x2f, 1, 0},
	} {
		got, h := readHello(bytes.NewReader(in))
		assert.True(t, bytes.HasPrefix(in, got), name)
		assert.Empty(t, h.serverName, name)
		if name == "no extensions" {
			assert.Equal(t, []uint16{0xc02f}, h.suites)
		}
	}
	// Bad lengths inside the message are refused, not trusted.
	for _, h := range []clientHello{
		parseClientHello([]byte{1, 0, 0, 39, 3, 3}),
		parseClientHello(append(append([]byte{1, 0, 0, 41, 3, 3}, make([]byte, 33)...), 0, 1, 0xc0, 1, 0)),
	} {
		assert.Empty(t, h.suites)
	}
	body := append(append([]byte{3, 3}, make([]byte, 33)...), 0, 2, 0xc0, 0x2f, 1, 0)
	for name, ext := range map[string][]byte{
		"short extension":   {0, 5, 0, 0, 0},
		"bad SNI list":      {0, 6, 0, 0, 0, 2, 0, 9},
		"bad SNI entry":     {0, 7, 0, 0, 0, 3, 0, 1, 0, 9},
		"non-host SNI only": {0, 10, 0, 0, 0, 6, 0, 4, 1, 0, 1, 'x'},
	} {
		msg := append(append([]byte{}, body...), ext...)
		h := parseClientHello(append([]byte{1, 0, byte(len(msg) >> 8), byte(len(msg))}, msg...))
		assert.Equal(t, []uint16{0xc02f}, h.suites, name)
		assert.Empty(t, h.serverName, name)
	}
}

// The giant server needs a TLS 1.2 suite it knows; a TLS 1.3-only client gets the connection closed.
func TestGiantChainClosesWithoutACommonSuite(t *testing.T) {
	f := sharedFleet(t)
	r := handshake(t, f.Addr(KindGiantChain), "", func(c *tls.Config) { c.MinVersion = tls.VersionTLS13 })
	assert.Error(t, r.err)
	require.NoError(t, f.WaitIdle(ctx(t)))
	log := f.Server(KindGiantChain).Log()
	require.Len(t, log, 1)
	assert.Zero(t, log[0].BytesWritten)
	_, ok := pickTLS12Suite([]uint16{tls.TLS_AES_128_GCM_SHA256})
	assert.False(t, ok)
}

// The container binds the unspecified address; WaitIdle reaches such a listener over loopback, IPv4 and IPv6.
func TestWaitIdleOnUnspecifiedAndIPv6Binds(t *testing.T) {
	for _, bind := range []string{"0.0.0.0", "::", "::1"} {
		f, err := New(Options{Kinds: []Kind{KindPlainText}, Bind: bind, Now: testNow})
		if err != nil && bind != "0.0.0.0" {
			t.Logf("no IPv6 here: %v", err)
			continue
		}
		require.NoError(t, err)
		host, port, err := net.SplitHostPort(f.Addr(KindPlainText))
		require.NoError(t, err)
		if ip := net.ParseIP(host); ip.IsUnspecified() {
			host = "127.0.0.1"
			if ip.To4() == nil {
				host = "::1"
			}
		}
		readBanner(t, net.JoinHostPort(host, port))
		require.NoError(t, f.WaitIdle(ctx(t)), bind)
		require.Len(t, f.Log(), 1, bind)
		assert.Equal(t, net.JoinHostPort(host, port), f.Log()[0].Local, "the address the client reached, not the listen address")
		require.NoError(t, f.Close())
	}
}

func TestValidDomain(t *testing.T) {
	for d, ok := range map[string]bool{
		"fleet.test": true, "fleet.alice-e2e.test": true, "a": true,
		"": false, "Fleet.test": false, "a..b": false, "-a.test": false, "a-.test": false, "a_b.test": false,
		string(bytes.Repeat([]byte("a"), 64)) + ".test": false, string(bytes.Repeat([]byte("a."), 101)) + "test": false,
	} {
		assert.Equal(t, ok, validDomain(d), d)
	}
}

func TestChainAccessorsCopy(t *testing.T) {
	f := sharedFleet(t)
	s := f.Server(KindValid)
	c := s.Chain()
	c[0][0] ^= 0xff
	assert.NotEqual(t, c[0], s.Chain()[0], "the caller cannot change what is served")
	assert.Nil(t, f.Server(KindReset).Chain(), "a raw server presents no chain")
	assert.Nil(t, s.SNINames())
}
