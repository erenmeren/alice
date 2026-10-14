package fakefleet

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

var testNow = time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)

// fleets are shared per option set inside one test binary: key generation dominates the cost, and
// every test that dials reads only its own server's log (or clears it first under its own lock).
var (
	sharedMu sync.Mutex
	shared   *Fleet
)

// sharedFleet returns the fleet of every kind with test-sized options. Tests that use it hold
// lockShared for their whole run so the access log they read is theirs.
func sharedFleet(t *testing.T) *Fleet {
	t.Helper()
	sharedMu.Lock()
	t.Cleanup(sharedMu.Unlock)
	if shared == nil {
		f, err := New(testOptions())
		require.NoError(t, err)
		shared = f
	}
	require.NoError(t, shared.WaitIdle(ctx(t)))
	shared.ClearLog()
	return shared
}

func testOptions() Options {
	return Options{
		Now:               testNow,
		Domain:            "fleet.test",
		IdleTimeout:       10 * time.Second,
		SlowLorisInterval: 10 * time.Millisecond,
		GiantBytes:        1 << 20,
	}
}

func newFleet(t *testing.T, o Options) *Fleet {
	t.Helper()
	f, err := New(o)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, f.Close()) })
	return f
}

func contextWithTimeout(d time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), d)
}

func ctx(t *testing.T) context.Context {
	t.Helper()
	c, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	return c
}

// probeConfig is the configuration a discovery probe uses: every suite Go knows, TLS 1.0 and up, no
// verification (the test reads what was presented).
func probeConfig(sni string) *tls.Config {
	var suites []uint16
	for _, s := range tls.CipherSuites() {
		suites = append(suites, s.ID)
	}
	for _, s := range tls.InsecureCipherSuites() {
		suites = append(suites, s.ID)
	}
	return &tls.Config{ServerName: sni, InsecureSkipVerify: true, MinVersion: tls.VersionTLS10, CipherSuites: suites} //nolint:gosec // G402: the test reads the presented chain
}

type result struct {
	state tls.ConnectionState
	err   error
	local string
}

// handshake dials addr, runs a TLS handshake and closes the connection without sending anything else.
func handshake(t *testing.T, addr, sni string, mod func(*tls.Config)) result {
	t.Helper()
	cfg := probeConfig(sni)
	if mod != nil {
		mod(cfg)
	}
	c, err := net.DialTimeout("tcp", addr, 5*time.Second)
	require.NoError(t, err)
	defer func() { _ = c.Close() }()
	require.NoError(t, c.SetDeadline(time.Now().Add(5*time.Second)))
	tc := tls.Client(c, cfg)
	err = tc.Handshake()
	return result{state: tc.ConnectionState(), err: err, local: c.LocalAddr().String()}
}

func leafOf(t *testing.T, r result) *x509.Certificate {
	t.Helper()
	require.NoError(t, r.err)
	require.NotEmpty(t, r.state.PeerCertificates)
	return r.state.PeerCertificates[0]
}

// readAll reads a plain TCP connection to addr after writing first, until EOF or the deadline.
func readAll(t *testing.T, addr string, first []byte, deadline time.Duration) ([]byte, error) {
	t.Helper()
	c, err := net.DialTimeout("tcp", addr, 5*time.Second)
	require.NoError(t, err)
	defer func() { _ = c.Close() }()
	require.NoError(t, c.SetDeadline(time.Now().Add(deadline)))
	if first != nil {
		_, err = c.Write(first)
		require.NoError(t, err)
	}
	return io.ReadAll(c)
}
