package nginx

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/platform/netaddr"
	"alice/internal/platform/netaddr/netaddrtest"
	"alice/internal/providers/linuxssh/helperproto"
	"alice/internal/testutil/pki"
)

// tlsServer serves leaf (TLS minVersion or later) on a local port until the test ends; it answers
// every handshake and closes.
func tlsServer(t *testing.T, leaf pki.Leaf, minVersion uint16) int {
	t.Helper()
	pair, err := tls.X509KeyPair(leaf.FullchainPEM, leaf.KeyPEM)
	require.NoError(t, err)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: max(minVersion, tls.VersionTLS12)})
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	go serveAndClose(ln)
	return ln.Addr().(*net.TCPAddr).Port
}

func serveAndClose(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go func() {
			if tc, ok := c.(*tls.Conn); ok {
				_ = tc.Handshake()
			}
			_ = c.Close()
		}()
	}
}

func TestTLSProberAgainstALocalServer(t *testing.T) {
	ca := pki.NewCA("Probe", pki.ECDSA256, unitNow)
	leaf := ca.Issue(pki.Opts{CommonName: "www.example.test", SANs: []string{"www.example.test"}}, unitNow)
	port := tlsServer(t, leaf, tls.VersionTLS12)
	p := TLSProber{}
	got, err := p.Probe(context.Background(), "127.0.0.1", port, "www.example.test", helperproto.ProbeAny)
	require.NoError(t, err)
	assert.Equal(t, pki.Fingerprint(leaf.Cert), got.LeafSHA256)
	assert.Equal(t, 2, got.ChainLength, "leaf and intermediate")
	assert.Equal(t, leaf.Cert.NotAfter.UTC(), got.NotAfter)

	got, err = p.Probe(context.Background(), "127.0.0.1", port, "", helperproto.ProbeECDSA)
	require.NoError(t, err, "no SNI, the typed TLS 1.2 probe")
	assert.Equal(t, pki.Fingerprint(leaf.Cert), got.LeafSHA256)

	_, err = p.Probe(context.Background(), "127.0.0.1", port, "www.example.test", helperproto.ProbeRSA)
	assert.ErrorIs(t, err, ErrProbeFailed, "an ECDSA-only server has nothing for an RSA probe")

	// D15: a TLS 1.3-only website answers the default probe.
	only13 := tlsServer(t, leaf, tls.VersionTLS13)
	got, err = p.Probe(context.Background(), "127.0.0.1", only13, "www.example.test", helperproto.ProbeAny)
	require.NoError(t, err)
	assert.Equal(t, pki.Fingerprint(leaf.Cert), got.LeafSHA256)
	_, err = p.Probe(context.Background(), "127.0.0.1", only13, "www.example.test", helperproto.ProbeECDSA)
	assert.ErrorIs(t, err, ErrProbeFailed, "the typed probe is TLS 1.2 only")

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	closed := ln.Addr().(*net.TCPAddr).Port
	require.NoError(t, ln.Close())
	_, err = p.Probe(context.Background(), "127.0.0.1", closed, "", helperproto.ProbeAny)
	assert.ErrorIs(t, err, ErrProbeUnreachable)
	assert.NotErrorIs(t, err, ErrProbeFailed)

	plain, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = plain.Close() })
	go serveAndClose(plain)
	_, err = p.Probe(context.Background(), "127.0.0.1", plain.Addr().(*net.TCPAddr).Port, "", helperproto.ProbeAny)
	assert.ErrorIs(t, err, ErrProbeFailed)
	assert.NotErrorIs(t, err, ErrProbeUnreachable)
}

// A server that accepts and never answers the handshake: the probe gives up at its bound.
func TestTLSProberIsBounded(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	held := make(chan net.Conn, 4)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			held <- c
		}
	}()
	t.Cleanup(func() {
		for {
			select {
			case c := <-held:
				_ = c.Close()
			default:
				return
			}
		}
	})
	port := ln.Addr().(*net.TCPAddr).Port
	start := time.Now()
	_, err = TLSProber{HandshakeTimeout: 100 * time.Millisecond}.Probe(context.Background(), "127.0.0.1", port, "", helperproto.ProbeAny)
	assert.ErrorIs(t, err, ErrProbeFailed)
	assert.Less(t, time.Since(start), 5*time.Second)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = TLSProber{}.Probe(ctx, "127.0.0.1", port, "", helperproto.ProbeAny)
	assert.ErrorIs(t, err, context.Canceled)

	_, err = TLSProber{}.Probe(context.Background(), "127.0.0.1", 0, "", helperproto.ProbeAny)
	assert.ErrorIs(t, err, ErrProbeUnreachable, "port 0")
	_, err = TLSProber{}.Probe(context.Background(), "127.0.0.1", port, "", "dsa")
	assert.True(t, errors.Is(err, ErrProbeFailed), "an unknown key type is refused before dialling")
}

// AUD-25 (a): Alice's own TLS probe checks the address it connects to with the target rule. A
// refusal is its own error (ErrProbeNotAllowed), not ErrProbeUnreachable, and nothing reaches the
// website: the test server on 127.0.0.1 would answer a connection to 0.0.0.0.
func TestTLSProberRefusesAnAddressAliceNeverConnectsTo(t *testing.T) {
	ca := pki.NewCA("Probe", pki.ECDSA256, unitNow)
	leaf := ca.Issue(pki.Opts{CommonName: "www.example.test", SANs: []string{"www.example.test"}}, unitNow)
	port := tlsServer(t, leaf, tls.VersionTLS12)
	var rebound atomic.Bool
	p := TLSProber{resolver: netaddrtest.Resolver(func(name string) []netip.Addr {
		switch {
		case name != "www.example.test":
			return nil
		case rebound.Load():
			return []netip.Addr{netip.MustParseAddr("0.0.0.0")}
		}
		return []netip.Addr{netip.MustParseAddr("127.0.0.1")}
	})}
	got, err := p.Probe(context.Background(), "www.example.test", port, "www.example.test", helperproto.ProbeAny)
	require.NoError(t, err)
	assert.Equal(t, pki.Fingerprint(leaf.Cert), got.LeafSHA256)

	rebound.Store(true)
	_, err = p.Probe(context.Background(), "www.example.test", port, "www.example.test", helperproto.ProbeAny)
	assert.ErrorIs(t, err, ErrProbeNotAllowed)
	assert.ErrorIs(t, err, netaddr.ErrNotAllowed)
	assert.NotErrorIs(t, err, ErrProbeUnreachable)
	assert.NotErrorIs(t, err, ErrProbeFailed)

	for _, host := range []string{"169.254.169.254", "0.0.0.0", "::ffff:169.254.169.254"} {
		_, err = TLSProber{}.Probe(context.Background(), host, port, "", helperproto.ProbeAny)
		assert.ErrorIs(t, err, ErrProbeNotAllowed, host)
	}
}
