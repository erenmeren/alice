package nginx

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/providers"
	"alice/internal/providers/linuxssh/helperproto"
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
		{Port: 8443, SNI: "a.example.test", Addr: "10.0.0.5"},
		{Port: 443, SNI: "b.example.test", Addr: "127.0.0.1"},
	}, Endpoints(loc, providers.VerifyOptions{}, []string{"b.example.test"}), "deduplicated by port and name")
	assert.Equal(t, []Endpoint{{Port: 9443, SNI: "check.example.test", Addr: "127.0.0.1"}},
		Endpoints(loc, providers.VerifyOptions{Port: 9443, SNI: "check.example.test"}, nil), "an override maps every listen to one endpoint")
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
