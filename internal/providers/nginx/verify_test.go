package nginx

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/platform/clock"
	"alice/internal/providers"
	"alice/internal/providers/linuxssh/helperproto"
	"alice/internal/providers/linuxssh/linuxsshtest"
	"alice/internal/providers/webserver"
	"alice/internal/testutil/pki"
)

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

func TestEndpoints(t *testing.T) {
	loc := providers.CertLocation{Servers: []providers.CertServer{
		{Names: []string{"a.example.test"}, Listens: []providers.CertListen{{Port: 443}, {Addr: "::", Port: 443}, {Addr: "10.0.0.5", Port: 8443}}},
		{Names: []string{"a.example.test"}, Listens: []providers.CertListen{{Port: 443}}},
		{Names: []string{"_"}, Listens: []providers.CertListen{{Port: 443, DefaultServer: true}}},
	}}
	assert.Equal(t, []Endpoint{
		{Port: 443, SNI: "a.example.test", Addr: "127.0.0.1"},
		{Port: 8443, SNI: "a.example.test", Addr: "10.0.0.5", Listen: "10.0.0.5"},
		{Port: 443, SNI: "b.example.test", Addr: "127.0.0.1"},
	}, Endpoints(loc, providers.VerifyOptions{}, []string{"b.example.test"}), "deduplicated by port, name and listen address (any address is one)")
	assert.Equal(t, []Endpoint{{Port: 9443, SNI: "check.example.test", Addr: "127.0.0.1"}, {Port: 9443, SNI: "check.example.test", Addr: "10.0.0.5", Listen: "10.0.0.5"}},
		Endpoints(loc, providers.VerifyOptions{Port: 9443, SNI: "check.example.test"}, nil), "an override maps the listens of each address to one endpoint")
	two := providers.CertLocation{Servers: []providers.CertServer{{Names: []string{"a.example.test"},
		Listens: []providers.CertListen{{Addr: "10.0.0.5", Port: 443}, {Addr: "10.0.0.6", Port: 443}, {Addr: "*", Port: 443}, {Addr: "0.0.0.0", Port: 443}}}}}
	assert.Equal(t, []Endpoint{{Port: 443, SNI: "a.example.test", Addr: "10.0.0.5", Listen: "10.0.0.5"}, {Port: 443, SNI: "a.example.test", Addr: "10.0.0.6", Listen: "10.0.0.6"},
		{Port: 443, SNI: "a.example.test", Addr: "127.0.0.1"}}, Endpoints(two, providers.VerifyOptions{}, nil), "one endpoint per specific address")
	many := providers.CertLocation{}
	for i := 0; i < 30; i++ {
		many.Servers = append(many.Servers, providers.CertServer{Names: []string{fmt.Sprintf("s%d.example.test", i)}, Listens: []providers.CertListen{{Port: 443}}})
	}
	assert.Len(t, Endpoints(many, providers.VerifyOptions{}, nil), 10)
	v6 := providers.CertLocation{Servers: []providers.CertServer{{Listens: []providers.CertListen{{Addr: "::", Port: 443}}}}}
	assert.Equal(t, []Endpoint{{Port: 443, Addr: "::1"}}, Endpoints(v6, providers.VerifyOptions{}, nil), "IPv6 any: the IPv6 loopback, no name")
}

func TestLocalAddr(t *testing.T) {
	for in, want := range map[string]string{
		"": "127.0.0.1", "0.0.0.0": "127.0.0.1", "*": "127.0.0.1", "::": "::1", "10.0.0.5": "10.0.0.5",
		"2001:DB8::1": "2001:db8::1", "localhost": "127.0.0.1", "fe80::1%eth0": "127.0.0.1", "::ffff:10.0.0.1": "::ffff:10.0.0.1",
	} {
		assert.Equal(t, want, localAddr(in), in)
	}
}

func TestVerifyFallsBackToTheServerProbe(t *testing.T) {
	e := newEnv(t)
	e.prober.set(true, false)
	s := e.open(t)
	vr, err := s.VerifyDeployment(context.Background(), providers.VerifyRequest{Location: e.location(t), Fingerprint: pki.Fingerprint(e.leaf.Cert), ChainLength: 2})
	require.NoError(t, err)
	assert.True(t, vr.OK)
	assert.Equal(t, "local", vr.Mode)
	assert.Contains(t, strings.Join(e.srv.Commands(), "\n"),
		"/usr/local/libexec/alice-helper tls-probe --addr '127.0.0.1' --port '443' --sni 'www.example.test' --key-type 'any'")
	assert.NotContains(t, strings.Join(e.srv.Commands(), "\n"), "sudo -n /usr/local/libexec/alice-helper tls-probe", "tls-probe runs without sudo")

	// A failed handshake from Alice (not a refused connection) is tried from the server too.
	e = newEnv(t)
	e.prober.set(false, true)
	vr, err = e.open(t).VerifyDeployment(context.Background(), providers.VerifyRequest{Location: e.location(t), Fingerprint: pki.Fingerprint(e.leaf.Cert)})
	require.NoError(t, err)
	assert.True(t, vr.OK)
	assert.Equal(t, "local", vr.Mode)
}

// AUD-25 (a): when the target's name now resolves to an address Alice never connects to, Alice's
// own probe is refused (ErrProbeNotAllowed) and never tried again for that endpoint; the server-side
// probe, which runs on the server, decides. The SSH connection that follows shows the refusal on the
// target (ssh.address_not_allowed).
func TestVerifyFallsBackToTheServerProbeWhenAlicesProbeIsRefused(t *testing.T) {
	e := newEnv(t)
	e.prober.mu.Lock()
	e.prober.notAllowed = true
	e.prober.mu.Unlock()
	loc := e.location(t)
	var logs bytes.Buffer
	s, err := e.prov.Open(context.Background(), e.ref, e.cred, providers.Env{Clock: clock.Real{}, HostKeys: e.hk,
		Log: slog.New(slog.NewTextHandler(&logs, nil))})
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })
	vr, err := s.VerifyDeployment(context.Background(), providers.VerifyRequest{Location: loc, Fingerprint: pki.Fingerprint(e.leaf.Cert), ChainLength: 2})
	require.NoError(t, err)
	assert.True(t, vr.OK)
	assert.Equal(t, "local", vr.Mode)
	assert.Len(t, e.prober.probes(), 1, "Alice's probe is not repeated once refused")
	// The refusal is visible: one warning naming the reason and the endpoint, nothing else.
	assert.Equal(t, 1, strings.Count(logs.String(), "level=WARN"), logs.String())
	assert.Contains(t, logs.String(), "reason=ssh.address_not_allowed port=443 sni=www.example.test")
	assert.Contains(t, strings.Join(e.srv.Commands(), "\n"), "/usr/local/libexec/alice-helper tls-probe --addr '127.0.0.1' --port '443'")
}

func TestVerifyReportsWhatIsServed(t *testing.T) {
	e := newEnv(t)
	s := e.open(t)
	cur := pki.Fingerprint(e.leaf.Cert)
	vr, err := s.VerifyDeployment(context.Background(), providers.VerifyRequest{Location: e.location(t)})
	require.NoError(t, err)
	assert.True(t, vr.OK)
	assert.Equal(t, cur, vr.Served)
	assert.Equal(t, 2, vr.ServedChainLength)
	assert.Equal(t, "remote", vr.Mode)
	assert.Equal(t, []string{"127.0.0.1 443 www.example.test any"}, e.prober.probes(), "Alice probes the target's address with SNI, any key type")

	vr, err = s.VerifyDeployment(context.Background(), providers.VerifyRequest{Location: e.location(t), Fingerprint: strings.Repeat("a", 64), PreviousFingerprint: cur})
	require.NoError(t, err)
	assert.False(t, vr.OK)
	assert.Equal(t, "deployment.verify_failed", vr.Reason)
	assert.Equal(t, cur, vr.Served)
	assert.Equal(t, map[string]string{"port": "443"}, vr.Params)
	vr, err = s.VerifyDeployment(context.Background(), providers.VerifyRequest{Location: e.location(t), Fingerprint: strings.Repeat("a", 64), PreviousFingerprint: strings.Repeat("b", 64)})
	require.NoError(t, err)
	assert.Equal(t, "deployment.verify_other", vr.Reason)

	// §12.8 item 5: the expected leaf with another chain length is a failure of its own.
	vr, err = s.VerifyDeployment(context.Background(), providers.VerifyRequest{Location: e.location(t), Fingerprint: cur, ChainLength: 3})
	require.NoError(t, err)
	assert.False(t, vr.OK)
	assert.Equal(t, "deployment.verify_chain", vr.Reason)
	assert.Equal(t, 2, vr.ServedChainLength)
	assert.Equal(t, map[string]string{"port": "443"}, vr.Params)

	e.prober.set(true, false)
	e.emu.LocalProbeFails(true)
	vr, err = s.VerifyDeployment(context.Background(), providers.VerifyRequest{Location: e.location(t), Fingerprint: cur})
	require.NoError(t, err)
	assert.False(t, vr.OK)
	assert.Equal(t, "deployment.verify_unreachable", vr.Reason)
	assert.Equal(t, map[string]string{"port": "443"}, vr.Params)

	vr, err = s.VerifyDeployment(context.Background(), providers.VerifyRequest{Location: e.location(t), Fingerprint: cur, Verify: providers.VerifyOptions{Skip: true}})
	require.NoError(t, err)
	assert.Equal(t, providers.VerifyResult{OK: true, Mode: "skipped"}, vr)

	vr, err = s.VerifyDeployment(context.Background(), providers.VerifyRequest{Verify: providers.VerifyOptions{Port: 8443}})
	require.NoError(t, err)
	assert.Equal(t, providers.VerifyResult{Reason: "deployment.verify_unreachable", Params: map[string]string{"port": "8443"}}, vr, "nothing to probe")
}

// An endpoint whose leaf is not the expected one yet is probed again (a graceful reload's old
// workers), up to Attempts times; the first match ends it.
func TestVerifyRetriesUntilTheExpectedLeafIsServed(t *testing.T) {
	e := newEnv(t)
	cur := pki.Fingerprint(e.leaf.Cert)
	other := strings.Repeat("c", 64)
	e.emu.ServeOther(443, other)
	vr, err := e.open(t).VerifyDeployment(context.Background(), providers.VerifyRequest{Location: e.location(t), Fingerprint: cur, KeyType: "ecdsa"})
	require.NoError(t, err)
	assert.Equal(t, "deployment.verify_other", vr.Reason)
	assert.Len(t, e.prober.probes(), 2*5, "five attempts, each an any-probe and an ecdsa-probe")

	e = newEnv(t)
	flip := &flipProber{emuProber: e.prober, wrongFor: 2}
	e.prov.prober = flip
	vr, err = e.open(t).VerifyDeployment(context.Background(), providers.VerifyRequest{Location: e.location(t), Fingerprint: pki.Fingerprint(e.leaf.Cert)})
	require.NoError(t, err)
	assert.True(t, vr.OK)
	assert.Equal(t, 3, flip.n, "matched at the third attempt")
}

// flipProber answers a wrong leaf for the first wrongFor probes.
type flipProber struct {
	*emuProber
	wrongFor, n int
}

func (f *flipProber) Probe(ctx context.Context, host string, port int, sni, keyType string) (Probe, error) {
	f.n++
	if f.n <= f.wrongFor {
		return Probe{LeafSHA256: strings.Repeat("d", 64), ChainLength: 1}, nil
	}
	return f.emuProber.Probe(ctx, host, port, sni, keyType)
}

// Spec §12.8 item 4: a dual-certificate server answers the any-probe with its other pair; the
// second probe, of the deployed key type, shows the deployed one and decides.
func TestVerifyAsksADualCertificateServerForTheDeployedKeyType(t *testing.T) {
	e := newEnv(t)
	cur := pki.Fingerprint(e.leaf.Cert)
	rsaLeaf := strings.Repeat("e", 64)
	dual := &dualProber{emuProber: e.prober, any: rsaLeaf}
	e.prov.prober = dual
	vr, err := e.open(t).VerifyDeployment(context.Background(), providers.VerifyRequest{Location: e.location(t), Fingerprint: cur, KeyType: "ecdsa"})
	require.NoError(t, err)
	assert.True(t, vr.OK)
	assert.Equal(t, []string{"any", "ecdsa"}, dual.kinds, "one attempt: the any-probe, then the typed one")

	// Without a key type there is no second probe: the other pair is what the website serves.
	dual.kinds = nil
	vr, err = e.open(t).VerifyDeployment(context.Background(), providers.VerifyRequest{Location: e.location(t), Fingerprint: cur, PreviousFingerprint: rsaLeaf})
	require.NoError(t, err)
	assert.Equal(t, "deployment.verify_failed", vr.Reason)
	assert.Equal(t, rsaLeaf, vr.Served)
	assert.NotContains(t, dual.kinds, "ecdsa")
}

// dualProber serves leaf any to the any-probe and the emulated site's leaf to a typed probe.
type dualProber struct {
	*emuProber
	any   string
	kinds []string
}

func (d *dualProber) Probe(ctx context.Context, host string, port int, sni, keyType string) (Probe, error) {
	d.kinds = append(d.kinds, keyType)
	if keyType == helperproto.ProbeAny {
		return Probe{LeafSHA256: d.any, ChainLength: 2}, nil
	}
	return d.emuProber.Probe(ctx, host, port, sni, helperproto.ProbeAny)
}

func TestVerifyHonoursTheContextAndAClosedSession(t *testing.T) {
	e := newEnv(t)
	s := e.open(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := s.VerifyDeployment(ctx, providers.VerifyRequest{Location: e.location(t)})
	pe := providerErr(t, err)
	assert.Equal(t, "ssh.timeout", pe.Code)
	assert.ErrorIs(t, err, context.Canceled)

	// Cancelled while waiting between attempts.
	e = newEnv(t)
	e.emu.ServeOther(443, strings.Repeat("c", 64))
	e.prov.retryWait = 30 * time.Second
	ctx, cancel = context.WithCancel(context.Background())
	e.prov.prober = &cancelProber{emuProber: e.prober, cancel: cancel}
	_, err = e.open(t).VerifyDeployment(ctx, providers.VerifyRequest{Location: e.location(t), Fingerprint: pki.Fingerprint(e.leaf.Cert)})
	assert.ErrorIs(t, err, context.Canceled)

	// The SSH connection fails during a server-side probe: an error, not a result.
	e = newEnv(t)
	e.prober.set(true, false)
	loc := e.location(t)
	s = e.open(t)
	hangUpOn(e, helperproto.SubTLSProbe)
	_, err = s.VerifyDeployment(context.Background(), providers.VerifyRequest{Location: loc, Fingerprint: pki.Fingerprint(e.leaf.Cert)})
	require.Error(t, err)
	assert.Contains(t, []string{"ssh.protocol_error", "ssh.unreachable"}, providerErr(t, err).Code)

	e = newEnv(t)
	s = e.open(t)
	require.NoError(t, s.Close())
	_, err = s.VerifyDeployment(context.Background(), providers.VerifyRequest{})
	assert.Equal(t, "ssh.unreachable", providerErr(t, err).Code)
}

// cancelProber cancels the context after its first probe (answered by the emulator).
type cancelProber struct {
	*emuProber
	cancel func()
}

func (c *cancelProber) Probe(ctx context.Context, host string, port int, sni, keyType string) (Probe, error) {
	defer c.cancel()
	return c.emuProber.Probe(ctx, host, port, sni, keyType)
}

// A server-side probe that answers something Alice cannot use counts as not reached.
func TestVerifyDistrustsTheServerProbe(t *testing.T) {
	e := newEnv(t)
	e.prober.set(true, false)
	s := e.session(t)
	sv, ok, err := s.probeOnce(context.Background(), Endpoint{Port: 70000, Addr: "127.0.0.1"}, helperproto.ProbeAny, new(bool))
	require.NoError(t, err)
	assert.False(t, ok, "a port the helper cannot take")
	assert.Equal(t, served{}, sv)
}

// Important 1: Alice's own probe stands for an endpoint only when it reaches that listen: a
// wildcard listen, or one on the address Alice connects to. A listen on another specific address
// (or on loopback) is checked by the server-side probe against that address.
func TestVerifyProbesWhereTheListenIs(t *testing.T) {
	t.Run("specific address answered by another block on the target's address", func(t *testing.T) {
		e := newEnv(t, withSiteAddr("10.0.0.5"))
		e.addCatchAll(t)
		loc := e.location(t)
		vr, err := e.open(t).VerifyDeployment(context.Background(), providers.VerifyRequest{Location: loc, Fingerprint: pki.Fingerprint(e.leaf.Cert)})
		require.NoError(t, err)
		assert.True(t, vr.OK, "%+v", vr)
		assert.Equal(t, "local", vr.Mode)
		assert.Empty(t, e.prober.probes(), "Alice's probe of the target's address does not stand for 10.0.0.5")
		assert.Contains(t, strings.Join(e.srv.Commands(), "\n"), "tls-probe --addr '10.0.0.5' --port '443' --sni 'www.example.test'")
	})
	t.Run("loopback-only listen", func(t *testing.T) {
		e := newEnv(t, withSiteAddr("127.0.0.1"))
		e.addCatchAll(t)
		loc := e.location(t)
		s := e.session(t)
		s.host = "192.0.2.10" // Alice reaches the server at its public address
		vr, err := s.VerifyDeployment(context.Background(), providers.VerifyRequest{Location: loc, Fingerprint: pki.Fingerprint(e.leaf.Cert)})
		require.NoError(t, err)
		assert.True(t, vr.OK, "%+v", vr)
		assert.Equal(t, "local", vr.Mode)
		assert.Empty(t, e.prober.probes())
	})
	t.Run("a listen on the address Alice connects to", func(t *testing.T) {
		e := newEnv(t, withSiteAddr("127.0.0.1"))
		e.addCatchAll(t)
		vr, err := e.open(t).VerifyDeployment(context.Background(), providers.VerifyRequest{Location: e.location(t), Fingerprint: pki.Fingerprint(e.leaf.Cert)})
		require.NoError(t, err)
		assert.True(t, vr.OK, "%+v", vr)
		assert.Equal(t, "remote", vr.Mode)
		assert.Equal(t, []string{"127.0.0.1 443 www.example.test any"}, e.prober.probes())
	})
	t.Run("wildcard listen", func(t *testing.T) {
		e := newEnv(t)
		e.addCatchAll(t)
		s := e.session(t)
		s.host = "192.0.2.10"
		vr, err := s.VerifyDeployment(context.Background(), providers.VerifyRequest{Location: e.location(t), Fingerprint: pki.Fingerprint(e.leaf.Cert)})
		require.NoError(t, err)
		assert.True(t, vr.OK, "%+v", vr)
		assert.Equal(t, "remote", vr.Mode)
		assert.Equal(t, []string{"192.0.2.10 443 www.example.test any"}, e.prober.probes())
	})
	t.Run("two blocks on different addresses, same port and name", func(t *testing.T) {
		e := newEnv(t, withSiteAddr("10.0.0.5"))
		e.addCatchAll(t)
		b := e.ca.Issue(pki.Opts{CommonName: "www.example.test", SANs: []string{"www.example.test"}}, e.now)
		e.emu.AddSite(linuxsshtest.NginxSite{Names: []string{"www.example.test"}, Port: 443, Addr: "10.0.0.6", CertPath: "/etc/nginx/ssl/b.crt",
			KeyPath: "/etc/nginx/ssl/b.key"}, b.FullchainPEM, b.KeyPEM)
		s := e.open(t)
		res, err := s.Discover(context.Background(), providers.DiscoverRequest{Certificates: true})
		require.NoError(t, err)
		byPath := locationsByPath(res)
		for path, leaf := range map[string]pki.Leaf{wwwCert: e.leaf, "/etc/nginx/ssl/b.crt": b} {
			vr, err := s.VerifyDeployment(context.Background(), providers.VerifyRequest{Location: byPath[path].Location, Fingerprint: pki.Fingerprint(leaf.Cert)})
			require.NoError(t, err)
			assert.True(t, vr.OK, "%s: %+v", path, vr)
		}
		assert.Empty(t, e.prober.probes())
	})
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
		{"::1", "::1", true}, // Alice runs on the server itself: it connects there
		{"10.0.0.5", "10.0.0.6", false},
	} {
		assert.Equal(t, tc.want, probeFromAlice(Endpoint{Listen: tc.listen}, tc.host), "%+v", tc)
	}
}

// Minor 4: an empty Fingerprint is a query of what the first endpoint serves, not a verification;
// the deploy engine's pre-check passes the currently deployed fingerprint (and key type) so that
// every endpoint is compared and the typed probe applies.
func TestVerifyQueryIsNotAVerification(t *testing.T) {
	e := newEnv(t)
	e.emu.ServeOther(8443, strings.Repeat("c", 64))
	loc := providers.CertLocation{Servers: []providers.CertServer{
		{Names: []string{"www.example.test"}, Listens: []providers.CertListen{{Port: 443}, {Port: 8443}}},
	}}
	s := e.open(t)
	vr, err := s.VerifyDeployment(context.Background(), providers.VerifyRequest{Location: loc})
	require.NoError(t, err)
	assert.True(t, vr.OK, "a query: every endpoint answered")
	assert.Equal(t, pki.Fingerprint(e.leaf.Cert), vr.Served, "the first endpoint's leaf")
	vr, err = s.VerifyDeployment(context.Background(), providers.VerifyRequest{Location: loc, Fingerprint: pki.Fingerprint(e.leaf.Cert), KeyType: "ecdsa"})
	require.NoError(t, err)
	assert.False(t, vr.OK)
	assert.Equal(t, "deployment.verify_other", vr.Reason)
	assert.Equal(t, map[string]string{"port": "8443"}, vr.Params, "every endpoint is compared")
}

// A server-side probe that reports a chain longer than webserver.MaxChainCerts is not an answer
// Alice can use: the endpoint is not reached.
func TestVerifyRefusesAProbeWithTooLongAChain(t *testing.T) {
	for _, tc := range []struct {
		chain int
		ok    bool
	}{{webserver.MaxChainCerts, true}, {webserver.MaxChainCerts + 1, false}} {
		e := newEnv(t)
		e.prober.set(true, false)
		h := e.emu.Handler()
		leaf := pki.Fingerprint(e.leaf.Cert)
		e.srv.SetHandler(func(cmd string, stdin []byte) linuxsshtest.Response {
			if strings.Contains(cmd, " tls-probe ") {
				return linuxsshtest.Response{Stdout: []byte(fmt.Sprintf(`{"ok":true,"leaf_sha256":%q,"chain_length":%d,"not_after":"2030-01-01T00:00:00Z"}`, leaf, tc.chain))}
			}
			return h(cmd, stdin)
		})
		vr, err := e.open(t).VerifyDeployment(context.Background(), providers.VerifyRequest{Location: e.location(t), Fingerprint: leaf})
		require.NoError(t, err)
		assert.Equal(t, tc.ok, vr.OK, "chain length %d", tc.chain)
	}
}
