package tlsverify

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/platform/clock"
	"alice/internal/platform/netaddr"
	"alice/internal/platform/netaddr/netaddrtest"
	"alice/internal/providers"
	"alice/internal/providers/linuxssh/helperproto"
	"alice/internal/testutil/pki"
)

var unitNow = time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC)

// instantClock is a fixed now whose waits end at once; it counts them.
type instantClock struct {
	now   time.Time
	waits atomic.Int64
}

func (c *instantClock) Now() time.Time { return c.now }
func (c *instantClock) After(time.Duration) <-chan time.Time {
	c.waits.Add(1)
	ch := make(chan time.Time, 1)
	ch <- c.now
	return ch
}
func (c *instantClock) NewTicker(time.Duration) clock.Ticker { return nil }

// site is what one emulated endpoint serves: the leaf's SHA-256 and the chain (DER, leaf first).
type site struct {
	leaf  string
	ders  [][]byte
	chain int // 0 = len(ders)
}

func (s site) probe() Probe {
	n := s.chain
	if n == 0 {
		n = len(s.ders)
	}
	return Probe{LeafSHA256: s.leaf, ChainLength: n, Chain: s.ders}
}

// fakeProber is Alice's own probe: answer decides per call (n counts from 1); calls are "host port sni keyType".
type fakeProber struct {
	mu     sync.Mutex
	calls  []string
	answer func(n int, host string, port int, sni, keyType string) (Probe, error)
}

func (f *fakeProber) Probe(_ context.Context, host string, port int, sni, keyType string) (Probe, error) {
	f.mu.Lock()
	f.calls = append(f.calls, fmt.Sprintf("%s %d %s %s", host, port, sni, keyType))
	n := len(f.calls)
	f.mu.Unlock()
	return f.answer(n, host, port, sni, keyType)
}

func (f *fakeProber) probes() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...)
}

// serving answers every probe with the site of its port (none: refused).
func serving(sites map[int]site) *fakeProber {
	return &fakeProber{answer: func(_ int, _ string, port int, _, _ string) (Probe, error) {
		s, ok := sites[port]
		if !ok {
			return Probe{}, fmt.Errorf("%w: refused", ErrProbeUnreachable)
		}
		return s.probe(), nil
	}}
}

func down() *fakeProber {
	return &fakeProber{answer: func(int, string, int, string, string) (Probe, error) {
		return Probe{}, fmt.Errorf("%w: refused", ErrProbeUnreachable)
	}}
}

// fakeServer is the target's own probe; calls are "addr port sni keyType".
type fakeServer struct {
	mu     sync.Mutex
	calls  []string
	answer func(ep Endpoint, keyType string) (Served, bool, error)
}

func (f *fakeServer) probe(_ context.Context, ep Endpoint, keyType string) (Served, bool, error) {
	f.mu.Lock()
	f.calls = append(f.calls, fmt.Sprintf("%s %d %s %s", ep.Addr, ep.Port, ep.SNI, keyType))
	f.mu.Unlock()
	return f.answer(ep, keyType)
}

func (f *fakeServer) probes() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...)
}

func serverServing(sites map[int]site) *fakeServer {
	return &fakeServer{answer: func(ep Endpoint, _ string) (Served, bool, error) {
		s, ok := sites[ep.Port]
		if !ok {
			return Served{}, false, nil
		}
		p := s.probe()
		return Served{Leaf: p.LeafSHA256, Chain: p.ChainLength, DERs: p.Chain}, true, nil
	}}
}

// fixture is a CA, a leaf of www.example.test and the site that serves it with its intermediate.
type fixture struct {
	ca   *pki.CA
	leaf pki.Leaf
	fp   string
	site site
	clk  *instantClock
}

func newFixture() *fixture {
	ca := pki.NewCA("Verify", pki.ECDSA256, unitNow)
	leaf := ca.Issue(pki.Opts{CommonName: "www.example.test", SANs: []string{"www.example.test"}}, unitNow)
	return &fixture{ca: ca, leaf: leaf, fp: pki.Fingerprint(leaf.Cert), site: site{leaf: pki.Fingerprint(leaf.Cert), ders: [][]byte{leaf.Cert.Raw, ca.Intermediate.Raw}},
		clk: &instantClock{now: unitNow}}
}

func (f *fixture) opts() Options {
	return Options{Attempts: 5, RetryWait: time.Millisecond, Clock: f.clk}
}

func (f *fixture) trustFor(known bool) *providers.TrustPolicy {
	roots := x509.NewCertPool()
	if known {
		roots.AddCert(f.ca.Root)
	}
	p := providers.TrustPolicyFor([]*x509.Certificate{f.leaf.Cert, f.ca.Intermediate}, roots, providers.TrustStoreSystem, unitNow)
	return &p
}

var www = []Endpoint{{Port: 443, SNI: "www.example.test", Addr: "127.0.0.1"}}

const host = "web.example.test"

// The judgement of internal/providers/nginx's verification tests that needs no SSH session, against Verify with a fake
// Alice probe and a fake server probe.
func TestVerifyTableFromNginx(t *testing.T) {
	f := newFixture()
	other := strings.Repeat("c", 64)
	ctx := context.Background()

	t.Run("skipped", func(t *testing.T) {
		vr, err := Verify(ctx, host, nil, providers.VerifyRequest{Fingerprint: f.fp, Trust: f.trustFor(true), Verify: providers.VerifyOptions{Skip: true}}, down(), nil, f.opts())
		require.NoError(t, err)
		assert.Equal(t, providers.VerifyResult{OK: true, Mode: "skipped", Level: providers.LevelInstalled}, vr)
	})
	t.Run("nothing to probe", func(t *testing.T) {
		vr, err := Verify(ctx, host, nil, providers.VerifyRequest{Verify: providers.VerifyOptions{Port: 8443}}, down(), nil, f.opts())
		require.NoError(t, err)
		assert.Equal(t, providers.VerifyResult{Reason: ReasonVerifyUnreachable, Params: map[string]string{"port": "8443"}, Failure: providers.VerifyFailureNetwork}, vr)
		vr, err = Verify(ctx, host, nil, providers.VerifyRequest{}, down(), nil, f.opts())
		require.NoError(t, err)
		assert.Equal(t, map[string]string{"port": "443"}, vr.Params, "the default port")
	})
	t.Run("a cancelled context", func(t *testing.T) {
		cctx, cancel := context.WithCancel(ctx)
		cancel()
		_, err := Verify(cctx, host, www, providers.VerifyRequest{Fingerprint: f.fp}, serving(map[int]site{443: f.site}), nil, f.opts())
		var pe *providers.Error
		require.ErrorAs(t, err, &pe)
		assert.Equal(t, "ssh.timeout", pe.Code)
		assert.ErrorIs(t, err, context.Canceled)
	})
	t.Run("what is served", func(t *testing.T) {
		p := serving(map[int]site{443: f.site})
		vr, err := Verify(ctx, host, www, providers.VerifyRequest{}, p, nil, f.opts())
		require.NoError(t, err)
		assert.True(t, vr.OK)
		assert.Equal(t, f.fp, vr.Served)
		assert.Equal(t, 2, vr.ServedChainLength)
		assert.Equal(t, "remote", vr.Mode)
		assert.Equal(t, providers.LevelNone, vr.Level, "a query is never a pass")
		assert.Equal(t, []string{host + " 443 www.example.test any"}, p.probes(), "Alice probes the target's address with SNI, any key type")

		vr, err = Verify(ctx, host, www, providers.VerifyRequest{Fingerprint: strings.Repeat("a", 64), PreviousFingerprint: f.fp}, p, nil, f.opts())
		require.NoError(t, err)
		assert.False(t, vr.OK)
		assert.Equal(t, ReasonVerifyFailed, vr.Reason)
		assert.Equal(t, f.fp, vr.Served)
		assert.Equal(t, map[string]string{"port": "443"}, vr.Params)
		assert.Equal(t, providers.VerifyFailureCertificate, vr.Failure)

		vr, err = Verify(ctx, host, www, providers.VerifyRequest{Fingerprint: strings.Repeat("a", 64), PreviousFingerprint: strings.Repeat("b", 64)}, p, nil, f.opts())
		require.NoError(t, err)
		assert.Equal(t, ReasonVerifyOther, vr.Reason)

		vr, err = Verify(ctx, host, www, providers.VerifyRequest{Fingerprint: f.fp, ChainLength: 3}, p, nil, f.opts())
		require.NoError(t, err)
		assert.Equal(t, ReasonVerifyChain, vr.Reason)
		assert.Equal(t, 2, vr.ServedChainLength)
		assert.Equal(t, map[string]string{"port": "443"}, vr.Params)

		vr, err = Verify(ctx, host, www, providers.VerifyRequest{Fingerprint: f.fp, ChainLength: 2}, p, nil, f.opts())
		require.NoError(t, err)
		assert.True(t, vr.OK)
		assert.Equal(t, providers.LevelServed, vr.Level)
		assert.Equal(t, providers.Trust{}, vr.Trust)
	})
	t.Run("unreachable either way", func(t *testing.T) {
		vr, err := Verify(ctx, host, www, providers.VerifyRequest{Fingerprint: f.fp}, down(), serverServing(nil).probe, f.opts())
		require.NoError(t, err)
		assert.False(t, vr.OK)
		assert.Equal(t, ReasonVerifyUnreachable, vr.Reason)
		assert.Equal(t, map[string]string{"port": "443"}, vr.Params)
		assert.Equal(t, providers.VerifyFailureNetwork, vr.Failure)
	})
	t.Run("retried until the expected leaf is served", func(t *testing.T) {
		p := serving(map[int]site{443: {leaf: other, chain: 1}})
		vr, err := Verify(ctx, host, www, providers.VerifyRequest{Fingerprint: f.fp, KeyType: "ecdsa"}, p, nil, f.opts())
		require.NoError(t, err)
		assert.Equal(t, ReasonVerifyOther, vr.Reason)
		assert.Len(t, p.probes(), 2*5, "five attempts, each an any-probe and an ecdsa-probe")

		clk := &instantClock{now: unitNow}
		flip := &fakeProber{answer: func(n int, _ string, _ int, _, _ string) (Probe, error) {
			if n <= 2 {
				return Probe{LeafSHA256: strings.Repeat("d", 64), ChainLength: 1}, nil
			}
			return f.site.probe(), nil
		}}
		vr, err = Verify(ctx, host, www, providers.VerifyRequest{Fingerprint: f.fp}, flip, nil, Options{Attempts: 5, RetryWait: time.Second, Clock: clk})
		require.NoError(t, err)
		assert.True(t, vr.OK)
		assert.Len(t, flip.probes(), 3, "matched at the third attempt")
		assert.Equal(t, int64(2), clk.waits.Load(), "a wait between attempts, none after the match")
	})
	t.Run("a dual-certificate server asked for the deployed key type", func(t *testing.T) {
		var kinds []string
		dual := &fakeProber{answer: func(_ int, _ string, _ int, _, keyType string) (Probe, error) {
			kinds = append(kinds, keyType)
			if keyType == helperproto.ProbeAny {
				return Probe{LeafSHA256: other, ChainLength: 2}, nil
			}
			return f.site.probe(), nil
		}}
		vr, err := Verify(ctx, host, www, providers.VerifyRequest{Fingerprint: f.fp, KeyType: "ecdsa"}, dual, nil, f.opts())
		require.NoError(t, err)
		assert.True(t, vr.OK)
		assert.Equal(t, []string{"any", "ecdsa"}, kinds, "one attempt: the any-probe, then the typed one")

		kinds = nil
		vr, err = Verify(ctx, host, www, providers.VerifyRequest{Fingerprint: f.fp, PreviousFingerprint: other}, dual, nil, f.opts())
		require.NoError(t, err)
		assert.Equal(t, ReasonVerifyFailed, vr.Reason)
		assert.Equal(t, other, vr.Served)
		assert.NotContains(t, kinds, "ecdsa", "no key type: no second probe")

		// A typed probe that fails or still shows another leaf does not decide.
		for _, typed := range []func() (Probe, error){
			func() (Probe, error) { return Probe{}, fmt.Errorf("%w: no suite", ErrProbeFailed) },
			func() (Probe, error) { return Probe{LeafSHA256: other, ChainLength: 2}, nil },
		} {
			p := &fakeProber{answer: func(_ int, _ string, _ int, _, keyType string) (Probe, error) {
				if keyType == helperproto.ProbeAny {
					return Probe{LeafSHA256: other, ChainLength: 2}, nil
				}
				return typed()
			}}
			vr, err = Verify(ctx, host, www, providers.VerifyRequest{Fingerprint: f.fp, KeyType: "rsa"}, p, nil, f.opts())
			require.NoError(t, err)
			assert.Equal(t, ReasonVerifyOther, vr.Reason)
		}
	})
	t.Run("cancelled while waiting between attempts", func(t *testing.T) {
		cctx, cancel := context.WithCancel(ctx)
		p := &fakeProber{answer: func(int, string, int, string, string) (Probe, error) {
			defer cancel()
			return Probe{LeafSHA256: other, ChainLength: 2}, nil
		}}
		_, err := Verify(cctx, host, www, providers.VerifyRequest{Fingerprint: f.fp}, p, nil, Options{Attempts: 5, RetryWait: 30 * time.Second, Clock: clock.Real{}})
		assert.ErrorIs(t, err, context.Canceled)
		var pe *providers.Error
		require.ErrorAs(t, err, &pe)
		assert.Equal(t, "ssh.timeout", pe.Code)
	})
	t.Run("cancelled during Alice's probe", func(t *testing.T) {
		cctx, cancel := context.WithCancel(ctx)
		p := &fakeProber{answer: func(int, string, int, string, string) (Probe, error) {
			cancel()
			return Probe{}, fmt.Errorf("%w: %w", ErrProbeUnreachable, context.Canceled)
		}}
		_, err := Verify(cctx, host, www, providers.VerifyRequest{Fingerprint: f.fp}, p, serverServing(map[int]site{443: f.site}).probe, f.opts())
		assert.ErrorIs(t, err, context.Canceled)
	})
	t.Run("the server probe fails: an error, not a result", func(t *testing.T) {
		boom := errors.New("ssh connection lost")
		srv := &fakeServer{answer: func(Endpoint, string) (Served, bool, error) { return Served{}, false, boom }}
		_, err := Verify(ctx, host, www, providers.VerifyRequest{Fingerprint: f.fp}, down(), srv.probe, f.opts())
		assert.ErrorIs(t, err, boom)

		// The same during the typed probe.
		n := 0
		srv = &fakeServer{answer: func(Endpoint, string) (Served, bool, error) {
			n++
			if n == 1 {
				return Served{Leaf: other, Chain: 1}, true, nil
			}
			return Served{}, false, boom
		}}
		_, err = Verify(ctx, host, www, providers.VerifyRequest{Fingerprint: f.fp, KeyType: "ecdsa"}, down(), srv.probe, f.opts())
		assert.ErrorIs(t, err, boom)
	})
	t.Run("a server answer Alice cannot use counts as not reached", func(t *testing.T) {
		for _, tc := range []struct {
			name string
			sv   Served
			ok   bool
		}{
			{"the chain bound", Served{Leaf: f.fp, Chain: helperproto.MaxProbeChainCerts}, true},
			{"beyond the chain bound", Served{Leaf: f.fp, Chain: helperproto.MaxProbeChainCerts + 1}, false},
			{"no certificate", Served{Leaf: f.fp, Chain: 0}, false},
			{"not a SHA-256", Served{Leaf: "xyz", Chain: 1}, false},
			{"the absent marker", Served{Leaf: helperproto.AbsentSHA256, Chain: 1}, false},
		} {
			srv := &fakeServer{answer: func(Endpoint, string) (Served, bool, error) { return tc.sv, true, nil }}
			vr, err := Verify(ctx, host, www, providers.VerifyRequest{Fingerprint: f.fp}, down(), srv.probe, f.opts())
			require.NoError(t, err)
			assert.Equal(t, tc.ok, vr.OK, tc.name)
		}
		// Alice's answer is held to the same rule.
		for _, pr := range []Probe{{LeafSHA256: "xyz", ChainLength: 1}, {LeafSHA256: f.fp}} {
			p := &fakeProber{answer: func(int, string, int, string, string) (Probe, error) { return pr, nil }}
			vr, err := Verify(ctx, host, www, providers.VerifyRequest{Fingerprint: f.fp}, p, nil, f.opts())
			require.NoError(t, err)
			assert.Equal(t, ReasonVerifyUnreachable, vr.Reason, "%+v", pr)
		}
	})
	t.Run("every endpoint is compared; a query only needs every handshake", func(t *testing.T) {
		eps := []Endpoint{{Port: 443, SNI: "www.example.test", Addr: "127.0.0.1"}, {Port: 8443, SNI: "www.example.test", Addr: "127.0.0.1"}}
		p := serving(map[int]site{443: f.site, 8443: {leaf: other, chain: 1}})
		vr, err := Verify(ctx, host, eps, providers.VerifyRequest{}, p, nil, f.opts())
		require.NoError(t, err)
		assert.True(t, vr.OK, "a query: every endpoint answered")
		assert.Equal(t, f.fp, vr.Served, "the first endpoint's leaf")
		vr, err = Verify(ctx, host, eps, providers.VerifyRequest{Fingerprint: f.fp, KeyType: "ecdsa"}, p, nil, f.opts())
		require.NoError(t, err)
		assert.False(t, vr.OK)
		assert.Equal(t, ReasonVerifyOther, vr.Reason)
		assert.Equal(t, map[string]string{"port": "8443"}, vr.Params)
		assert.Equal(t, other, vr.Served)

		// A query of a second endpoint nobody reaches.
		vr, err = Verify(ctx, host, eps, providers.VerifyRequest{}, serving(map[int]site{443: f.site}), nil, f.opts())
		require.NoError(t, err)
		assert.Equal(t, ReasonVerifyUnreachable, vr.Reason)
		assert.Equal(t, map[string]string{"port": "8443"}, vr.Params)
	})
	t.Run("trust", func(t *testing.T) {
		p := serving(map[int]site{443: f.site})
		vr, err := Verify(ctx, host, www, providers.VerifyRequest{Fingerprint: f.fp, ChainLength: 2, Trust: f.trustFor(true)}, p, nil, f.opts())
		require.NoError(t, err)
		assert.True(t, vr.OK)
		assert.Equal(t, providers.LevelTrusted, vr.Level)
		assert.Equal(t, providers.Trust{Status: providers.TrustTrusted, Store: providers.TrustStoreSystem, Enforced: true}, vr.Trust)

		vr, err = Verify(ctx, host, www, providers.VerifyRequest{Fingerprint: f.fp, ChainLength: 2, Trust: f.trustFor(false)}, p, nil, f.opts())
		require.NoError(t, err)
		assert.True(t, vr.OK, "an unknown anchor is a warning")
		assert.Equal(t, providers.LevelServed, vr.Level)
		assert.Equal(t, providers.Trust{Status: providers.TrustUntrusted, Error: providers.TrustErrUnknownAuthority, Port: 443, Store: providers.TrustStoreSystem}, vr.Trust)

		// A query is never judged for trust.
		vr, err = Verify(ctx, host, www, providers.VerifyRequest{Trust: f.trustFor(true)}, p, nil, f.opts())
		require.NoError(t, err)
		assert.Equal(t, providers.Trust{}, vr.Trust)

		policy := f.trustFor(true)
		policy.Roots = x509.NewCertPool()
		p = serving(map[int]site{443: f.site})
		vr, err = Verify(ctx, host, www, providers.VerifyRequest{Fingerprint: f.fp, ChainLength: 2, Trust: policy}, p, nil, f.opts())
		require.NoError(t, err)
		assert.False(t, vr.OK)
		assert.Equal(t, ReasonVerifyUntrusted, vr.Reason)
		assert.Equal(t, providers.VerifyFailureTrust, vr.Failure)
		assert.Equal(t, map[string]string{"port": "443", "trust_error": providers.TrustErrUnknownAuthority}, vr.Params)
		assert.Equal(t, providers.Trust{Status: providers.TrustUntrusted, Error: providers.TrustErrUnknownAuthority, Port: 443,
			Store: providers.TrustStoreSystem, Enforced: true}, vr.Trust)
		assert.Equal(t, providers.LevelNone, vr.Level)
		assert.Len(t, p.probes(), 5, "measured again on every attempt")

		// A name the leaf does not cover is a warning even with a known anchor.
		shop := []Endpoint{{Port: 443, SNI: "shop.example.test", Addr: "127.0.0.1"}}
		vr, err = Verify(ctx, host, shop, providers.VerifyRequest{Fingerprint: f.fp, ChainLength: 2, Trust: f.trustFor(true)}, p, nil, f.opts())
		require.NoError(t, err)
		assert.True(t, vr.OK, "%+v", vr)
		assert.Equal(t, providers.Trust{Status: providers.TrustUntrusted, Error: providers.TrustErrNameMismatch, Port: 443,
			Store: providers.TrustStoreSystem, Enforced: true}, vr.Trust)

		otherCA := pki.NewCA("Other", pki.ECDSA256, unitNow)
		for want, ders := range map[string][][]byte{
			providers.TrustErrIncompleteChain:   {f.leaf.Cert.Raw},
			providers.TrustErrWrongIntermediate: {f.leaf.Cert.Raw, otherCA.Intermediate.Raw},
		} {
			p := serving(map[int]site{443: {leaf: f.fp, ders: ders}})
			vr, err := Verify(ctx, host, www, providers.VerifyRequest{Fingerprint: f.fp, Trust: f.trustFor(true)}, p, nil, f.opts())
			require.NoError(t, err)
			assert.Equal(t, ReasonVerifyUntrusted, vr.Reason, want)
			assert.Equal(t, map[string]string{"port": "443", "trust_error": want}, vr.Params)
		}

		// The first warning stays; an answer without its chain is unchecked.
		eps := []Endpoint{{Port: 443, SNI: "shop.example.test", Addr: "127.0.0.1"}, {Port: 8443, SNI: "www.example.test", Addr: "127.0.0.1"},
			{Port: 9443, SNI: "www.example.test", Addr: "127.0.0.1"}}
		p = serving(map[int]site{443: f.site, 8443: f.site, 9443: {leaf: f.fp, chain: 2}})
		vr, err = Verify(ctx, host, eps, providers.VerifyRequest{Fingerprint: f.fp, Trust: f.trustFor(false)}, p, nil, f.opts())
		require.NoError(t, err)
		assert.True(t, vr.OK)
		assert.Equal(t, providers.Trust{Status: providers.TrustUntrusted, Error: providers.TrustErrUnknownAuthority, Port: 443, Store: providers.TrustStoreSystem}, vr.Trust,
			"the first endpoint's warning; neither a later one nor an unchecked answer replaces it")
		p = serving(map[int]site{443: f.site, 8443: {leaf: f.fp, chain: 2}, 9443: f.site})
		vr, err = Verify(ctx, host, eps[1:], providers.VerifyRequest{Fingerprint: f.fp, Trust: f.trustFor(true)}, p, nil, f.opts())
		require.NoError(t, err)
		assert.True(t, vr.OK)
		assert.Equal(t, providers.TrustUnchecked, vr.Trust.Status)
		assert.Equal(t, providers.LevelServed, vr.Level)
	})
	t.Run("trust from the server probe", func(t *testing.T) {
		vr, err := Verify(ctx, host, www, providers.VerifyRequest{Fingerprint: f.fp, ChainLength: 2, Trust: f.trustFor(true)}, down(),
			serverServing(map[int]site{443: f.site}).probe, f.opts())
		require.NoError(t, err)
		assert.True(t, vr.OK)
		assert.Equal(t, "local", vr.Mode)
		assert.Equal(t, providers.LevelTrusted, vr.Level)

		// An older helper's answer has no chain; one whose chain disagrees with its length is not checked either.
		for _, ders := range [][][]byte{nil, {f.leaf.Cert.Raw}} {
			srv := &fakeServer{answer: func(Endpoint, string) (Served, bool, error) {
				return Served{Leaf: f.fp, Chain: 2, DERs: ders}, true, nil
			}}
			policy := f.trustFor(true)
			policy.Roots = x509.NewCertPool()
			vr, err = Verify(ctx, host, www, providers.VerifyRequest{Fingerprint: f.fp, ChainLength: 2, Trust: policy}, down(), srv.probe, f.opts())
			require.NoError(t, err)
			assert.True(t, vr.OK, "nothing to check is no failure")
			assert.Equal(t, providers.LevelServed, vr.Level)
			assert.Equal(t, providers.TrustUnchecked, vr.Trust.Status)
		}
	})
}

// Alice's probe that cannot complete a handshake hands the endpoint to the server probe; an endpoint whose listen Alice
// does not reach (ProbeFromAlice false) is probed by the server only; without a server probe it is not reached.
func TestServerProbeWhenAliceCannot(t *testing.T) {
	f := newFixture()
	ctx := context.Background()

	t.Run("Alice is refused a connection: the server decides, Alice is not asked again", func(t *testing.T) {
		p := down()
		srv := serverServing(map[int]site{443: f.site})
		vr, err := Verify(ctx, host, www, providers.VerifyRequest{Fingerprint: f.fp, ChainLength: 2}, p, srv.probe, f.opts())
		require.NoError(t, err)
		assert.True(t, vr.OK)
		assert.Equal(t, "local", vr.Mode)
		assert.Equal(t, providers.LevelServed, vr.Level)
		assert.Equal(t, []string{"127.0.0.1 443 www.example.test any"}, srv.probes())

		p = down()
		srv = serverServing(map[int]site{443: {leaf: strings.Repeat("c", 64), chain: 1}})
		vr, err = Verify(ctx, host, www, providers.VerifyRequest{Fingerprint: f.fp}, p, srv.probe, f.opts())
		require.NoError(t, err)
		assert.Equal(t, ReasonVerifyOther, vr.Reason)
		assert.Equal(t, "local", vr.Mode)
		assert.Len(t, p.probes(), 1, "a refused connection is not tried again from Alice")
		assert.Len(t, srv.probes(), 5)
	})
	t.Run("a failed handshake from Alice is tried from the server, and from Alice again", func(t *testing.T) {
		p := &fakeProber{answer: func(n int, _ string, _ int, _, _ string) (Probe, error) {
			return Probe{}, fmt.Errorf("%w: alert", ErrProbeFailed)
		}}
		srv := serverServing(nil)
		vr, err := Verify(ctx, host, www, providers.VerifyRequest{Fingerprint: f.fp}, p, srv.probe, f.opts())
		require.NoError(t, err)
		assert.Equal(t, ReasonVerifyUnreachable, vr.Reason)
		assert.Len(t, p.probes(), 5)
		assert.Len(t, srv.probes(), 5)

		vr, err = Verify(ctx, host, www, providers.VerifyRequest{Fingerprint: f.fp}, p, serverServing(map[int]site{443: f.site}).probe, f.opts())
		require.NoError(t, err)
		assert.True(t, vr.OK)
		assert.Equal(t, "local", vr.Mode)
	})
	t.Run("one timeout is measured again from Alice", func(t *testing.T) {
		p := &fakeProber{answer: func(n int, _ string, _ int, _, _ string) (Probe, error) {
			if n == 1 {
				return Probe{}, fmt.Errorf("%w: %w", ErrProbeUnreachable, os.ErrDeadlineExceeded)
			}
			return f.site.probe(), nil
		}}
		vr, err := Verify(ctx, host, www, providers.VerifyRequest{Fingerprint: f.fp}, p, serverServing(nil).probe, f.opts())
		require.NoError(t, err)
		assert.True(t, vr.OK, "%+v", vr)
		assert.Equal(t, "remote", vr.Mode)
		assert.Len(t, p.probes(), 2, "the second attempt reached the website")

		p = &fakeProber{answer: func(n int, _ string, _ int, _, _ string) (Probe, error) {
			if n == 1 {
				return Probe{}, fmt.Errorf("%w: %w", ErrProbeUnreachable, timeoutErr{})
			}
			return f.site.probe(), nil
		}}
		vr, err = Verify(ctx, host, www, providers.VerifyRequest{Fingerprint: f.fp}, p, nil, f.opts())
		require.NoError(t, err)
		assert.True(t, vr.OK, "a net.Error timeout too")
	})
	t.Run("Alice refuses the address: logged once, the server decides", func(t *testing.T) {
		p := &fakeProber{answer: func(int, string, int, string, string) (Probe, error) {
			return Probe{}, fmt.Errorf("%w: %w", ErrProbeNotAllowed, netaddr.ErrNotAllowed)
		}}
		var logs bytes.Buffer
		o := f.opts()
		o.Log = slog.New(slog.NewTextHandler(&logs, nil))
		vr, err := Verify(ctx, host, www, providers.VerifyRequest{Fingerprint: f.fp, ChainLength: 2}, p, serverServing(map[int]site{443: f.site}).probe, o)
		require.NoError(t, err)
		assert.True(t, vr.OK)
		assert.Equal(t, "local", vr.Mode)
		assert.Len(t, p.probes(), 1, "Alice's probe is not repeated once refused")
		assert.Equal(t, 1, strings.Count(logs.String(), "level=WARN"), logs.String())
		assert.Contains(t, logs.String(), "reason=ssh.address_not_allowed port=443 sni=www.example.test")

		// Without a logger nothing breaks.
		vr, err = Verify(ctx, host, www, providers.VerifyRequest{Fingerprint: f.fp}, p, serverServing(map[int]site{443: f.site}).probe, f.opts())
		require.NoError(t, err)
		assert.True(t, vr.OK)
	})
	t.Run("a listen Alice does not reach: only the server probe", func(t *testing.T) {
		p := serving(map[int]site{443: {leaf: strings.Repeat("c", 64), chain: 1}})
		srv := serverServing(map[int]site{443: f.site})
		eps := []Endpoint{{Port: 443, SNI: "www.example.test", Addr: "10.0.0.5", Listen: "10.0.0.5"}}
		vr, err := Verify(ctx, host, eps, providers.VerifyRequest{Fingerprint: f.fp}, p, srv.probe, f.opts())
		require.NoError(t, err)
		assert.True(t, vr.OK, "%+v", vr)
		assert.Equal(t, "local", vr.Mode)
		assert.Empty(t, p.probes(), "Alice's probe of the target's address does not stand for 10.0.0.5")
		assert.Equal(t, []string{"10.0.0.5 443 www.example.test any"}, srv.probes())

		// Alice connects to that very address: her probe stands for it.
		p = serving(map[int]site{443: f.site})
		vr, err = Verify(ctx, "10.0.0.5", eps, providers.VerifyRequest{Fingerprint: f.fp}, p, srv.probe, f.opts())
		require.NoError(t, err)
		assert.True(t, vr.OK)
		assert.Equal(t, "remote", vr.Mode)
		assert.Equal(t, []string{"10.0.0.5 443 www.example.test any"}, p.probes())
	})
	t.Run("no server probe", func(t *testing.T) {
		eps := []Endpoint{{Port: 443, SNI: "www.example.test", Addr: "10.0.0.5", Listen: "10.0.0.5"}}
		p := serving(map[int]site{443: f.site})
		vr, err := Verify(ctx, host, eps, providers.VerifyRequest{Fingerprint: f.fp}, p, nil, f.opts())
		require.NoError(t, err)
		assert.Equal(t, ReasonVerifyUnreachable, vr.Reason)
		assert.Equal(t, providers.VerifyFailureNetwork, vr.Failure)
		assert.Empty(t, p.probes())

		vr, err = Verify(ctx, host, www, providers.VerifyRequest{Fingerprint: f.fp}, down(), nil, f.opts())
		require.NoError(t, err)
		assert.Equal(t, ReasonVerifyUnreachable, vr.Reason)
	})
	t.Run("ProbeOnce", func(t *testing.T) {
		localOnly := false
		sv, ok, err := ProbeOnce(ctx, host, www[0], helperproto.ProbeAny, &localOnly, down(), nil, f.opts())
		require.NoError(t, err)
		assert.False(t, ok)
		assert.Equal(t, Served{}, sv)
		assert.True(t, localOnly, "a refused connection: the server only from now on")
	})
}

type timeoutErr struct{}

func (timeoutErr) Error() string   { return "i/o timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }

var _ net.Error = timeoutErr{}

// Options' zero values: five attempts two seconds apart on the real clock, logs discarded.
func TestOptionsDefaults(t *testing.T) {
	o := Options{}.withDefaults()
	assert.Equal(t, 5, o.Attempts)
	assert.Equal(t, 2*time.Second, o.RetryWait)
	assert.Equal(t, clock.Real{}, o.Clock)
	assert.NotNil(t, o.Log)
	set := Options{Attempts: 2, RetryWait: time.Millisecond, Clock: &instantClock{}}.withDefaults()
	assert.Equal(t, 2, set.Attempts)
	assert.Equal(t, time.Millisecond, set.RetryWait)
}

func TestSNIForTable(t *testing.T) {
	for _, tc := range []struct {
		names, sans []string
		want        string
	}{
		{[]string{"www.example.test", "example.test"}, nil, "www.example.test"},
		{[]string{"_"}, []string{"a.example.test"}, "a.example.test"},
		{[]string{""}, []string{"*.example.test"}, "alice-check.example.test"},
		{[]string{"*.example.test"}, nil, "alice-check.example.test"},
		{[]string{".example.test"}, nil, "example.test"},
		{[]string{"~^www\\d+\\.example\\.test$", "WWW.Example.TEST"}, nil, "www.example.test"},
		{[]string{"www.*"}, []string{"b.example.test"}, "b.example.test"},
		{[]string{"_"}, []string{"10.0.0.5"}, ""},
		{[]string{"10.0.0.5", "::1"}, []string{"2001:db8::1"}, ""},
		{[]string{"bad name", "-x.example.test"}, nil, ""},
		{nil, nil, ""},
	} {
		assert.Equal(t, tc.want, SNIFor(tc.names, tc.sans), "%v %v", tc.names, tc.sans)
	}
}

func TestProbeFromAlice(t *testing.T) {
	for _, tc := range []struct {
		listen, host string
		want         bool
	}{
		{"", "web.example.test", true},
		{"10.0.0.5", "10.0.0.5", true},
		{"2001:db8::1", "2001:DB8::1", true},
		{"::ffff:10.0.0.5", "10.0.0.5", true},
		{"web.example.test", "WEB.example.test", true},
		{"10.0.0.5", "web.example.test", false},
		{"127.0.0.1", "192.0.2.10", false},
		{"::1", "::1", true},
		{"10.0.0.5", "10.0.0.6", false},
		{"fe80::1%eth0", "fe80::1", false},
	} {
		assert.Equal(t, tc.want, ProbeFromAlice(Endpoint{Listen: tc.listen}, tc.host), "%+v", tc)
	}
}

// tlsServer serves leaf (TLS minVersion or later) on a local port until the test ends; it answers every handshake and
// closes. resumed counts handshakes the server resumed from a session ticket.
func tlsServer(t *testing.T, leaf pki.Leaf, minVersion uint16, resumed *atomic.Int64) int {
	t.Helper()
	pair, err := tls.X509KeyPair(leaf.FullchainPEM, leaf.KeyPEM)
	require.NoError(t, err)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: max(minVersion, tls.VersionTLS12)})
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				if tc, ok := c.(*tls.Conn); ok && tc.Handshake() == nil && resumed != nil && tc.ConnectionState().DidResume {
					resumed.Add(1)
				}
				_ = c.Close()
			}()
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

// Every probe is a fresh handshake (Ruling 15): no client session cache, no session tickets, so the first handshake
// after a bind is answered from the binding as it is now.
func TestProbeIsAFreshHandshake(t *testing.T) {
	for _, kt := range []string{helperproto.ProbeAny, helperproto.ProbeRSA, helperproto.ProbeECDSA} {
		c := TLSProber{}.config("www.example.test", kt)
		assert.Nil(t, c.ClientSessionCache, kt)
		assert.True(t, c.SessionTicketsDisabled, kt)
		assert.True(t, c.InsecureSkipVerify, "the chain is judged afterwards, never during the handshake")
		assert.Equal(t, "www.example.test", c.ServerName)
	}
	ca := pki.NewCA("Probe", pki.ECDSA256, time.Now())
	leaf := ca.Issue(pki.Opts{CommonName: "www.example.test", SANs: []string{"www.example.test"}}, time.Now())
	var resumed atomic.Int64
	port := tlsServer(t, leaf, tls.VersionTLS12, &resumed)
	for range 3 {
		got, err := TLSProber{}.Probe(context.Background(), "127.0.0.1", port, "www.example.test", helperproto.ProbeAny)
		require.NoError(t, err)
		assert.Equal(t, pki.Fingerprint(leaf.Cert), got.LeafSHA256)
	}
	time.Sleep(20 * time.Millisecond)
	assert.Zero(t, resumed.Load(), "no handshake resumed a session")
}

func TestTLSProberAgainstALocalServer(t *testing.T) {
	ca := pki.NewCA("Probe", pki.ECDSA256, time.Now())
	leaf := ca.Issue(pki.Opts{CommonName: "www.example.test", SANs: []string{"www.example.test"}}, time.Now())
	port := tlsServer(t, leaf, tls.VersionTLS12, nil)
	p := TLSProber{}
	got, err := p.Probe(context.Background(), "127.0.0.1", port, "www.example.test", helperproto.ProbeAny)
	require.NoError(t, err)
	assert.Equal(t, pki.Fingerprint(leaf.Cert), got.LeafSHA256)
	assert.Equal(t, 2, got.ChainLength, "leaf and intermediate")
	assert.Equal(t, leaf.Cert.NotAfter.UTC(), got.NotAfter)
	assert.Equal(t, [][]byte{leaf.Cert.Raw, ca.Intermediate.Raw}, got.Chain)

	got, err = p.Probe(context.Background(), "127.0.0.1", port, "", helperproto.ProbeECDSA)
	require.NoError(t, err, "no SNI, the typed TLS 1.2 probe")
	assert.Equal(t, pki.Fingerprint(leaf.Cert), got.LeafSHA256)

	_, err = p.Probe(context.Background(), "127.0.0.1", port, "www.example.test", helperproto.ProbeRSA)
	assert.ErrorIs(t, err, ErrProbeFailed, "an ECDSA-only server has nothing for an RSA probe")

	only13 := tlsServer(t, leaf, tls.VersionTLS13, nil)
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
	go func() {
		for {
			c, err := plain.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
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
	assert.ErrorIs(t, err, ErrProbeFailed, "an unknown key type is refused before dialling")
}

// AUD-25 (a): the probe checks the address it connects to with the target rule; a refusal is ErrProbeNotAllowed.
func TestTLSProberRefusesAnAddressAliceNeverConnectsTo(t *testing.T) {
	ca := pki.NewCA("Probe", pki.ECDSA256, time.Now())
	leaf := ca.Issue(pki.Opts{CommonName: "www.example.test", SANs: []string{"www.example.test"}}, time.Now())
	port := tlsServer(t, leaf, tls.VersionTLS12, nil)
	var rebound atomic.Bool
	p := TLSProber{Resolver: netaddrtest.Resolver(func(name string) []netip.Addr {
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
	for _, h := range []string{"169.254.169.254", "0.0.0.0", "::ffff:169.254.169.254"} {
		_, err = TLSProber{}.Probe(context.Background(), h, port, "", helperproto.ProbeAny)
		assert.ErrorIs(t, err, ErrProbeNotAllowed, h)
	}
}
