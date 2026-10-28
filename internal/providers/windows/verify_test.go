package windows

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/providers"
	"alice/internal/providers/linuxssh/linuxsshtest"
	"alice/internal/providers/providertest"
	"alice/internal/providers/tlsverify"
	"alice/internal/providers/windows/winproto"
	"alice/internal/providers/windows/wintest"
	"alice/internal/testutil/pki"
)

func ipportLoc(ip string, servers ...providers.CertServer) providers.CertLocation {
	return providers.CertLocation{Kind: providers.LocationWinSSLBinding, Supported: true,
		Locator: providers.Locator{"type": "ipport", "ip": ip, "port": 443, "app_id": winproto.AppIDIIS}, Servers: servers}
}

func site(names ...string) providers.CertServer {
	return providers.CertServer{Names: append([]string{}, names...), Listens: []providers.CertListen{{Addr: "*", Port: 443}}, Section: "Web"}
}

// W2 Ruling 15: the endpoints of a Windows location come from its locator, the IIS host headers and
// the certificate's SANs; the Administrator's port, SNI and probe address apply.
func TestWindowsEndpoints(t *testing.T) {
	sans := []string{"shop.example.test", "www.example.test"}
	sni := providers.CertLocation{Kind: providers.LocationWinSSLBinding,
		Locator: providers.Locator{"type": "hostnameport", "host": "www.example.test", "port": float64(8443), "app_id": winproto.AppIDIIS}}
	wild := providers.CertLocation{Kind: providers.LocationWinSSLBinding,
		Locator: providers.Locator{"type": "hostnameport", "host": "*.example.test", "port": int64(443), "app_id": winproto.AppIDIIS}}
	for _, tc := range []struct {
		name string
		loc  providers.CertLocation
		v    providers.VerifyOptions
		want []tlsverify.Endpoint
	}{
		{"hostnameport: SNI is the host", sni, providers.VerifyOptions{}, []tlsverify.Endpoint{{Port: 8443, SNI: "www.example.test", Addr: "127.0.0.1"}}},
		{"hostnameport with a wildcard host", wild, providers.VerifyOptions{}, []tlsverify.Endpoint{{Port: 443, SNI: "alice-check.example.test", Addr: "127.0.0.1"}}},
		{"ipport wildcard with two IIS host headers: two endpoints", ipportLoc("0.0.0.0", site("a.example.test"), site("B.example.test"), site("a.example.test")),
			providers.VerifyOptions{}, []tlsverify.Endpoint{{Port: 443, SNI: "a.example.test", Addr: "127.0.0.1"}, {Port: 443, SNI: "b.example.test", Addr: "127.0.0.1"}}},
		{"ipport wildcard without a host header: SNI from the SANs", ipportLoc("0.0.0.0", site()), providers.VerifyOptions{},
			[]tlsverify.Endpoint{{Port: 443, SNI: "shop.example.test", Addr: "127.0.0.1"}}},
		{"ipport wildcard without a site: SNI from the SANs", ipportLoc("0.0.0.0"), providers.VerifyOptions{},
			[]tlsverify.Endpoint{{Port: 443, SNI: "shop.example.test", Addr: "127.0.0.1"}}},
		{"ipport [::]: the helper probes ::1", ipportLoc("::"), providers.VerifyOptions{},
			[]tlsverify.Endpoint{{Port: 443, SNI: "shop.example.test", Addr: "::1"}}},
		{"ipport 10.0.0.5: listens on that address only", ipportLoc("10.0.0.5", site()), providers.VerifyOptions{},
			[]tlsverify.Endpoint{{Port: 443, SNI: "shop.example.test", Addr: "10.0.0.5", Listen: "10.0.0.5"}}},
		{"the Administrator's port and SNI", ipportLoc("0.0.0.0", site("a.example.test"), site("b.example.test")), providers.VerifyOptions{Port: 9443, SNI: "override.example.test"},
			[]tlsverify.Endpoint{{Port: 9443, SNI: "override.example.test", Addr: "127.0.0.1"}}},
		{"the Administrator's probe address stands for a specific listen", ipportLoc("10.0.0.5"), providers.VerifyOptions{Address: "lb.example.test"},
			[]tlsverify.Endpoint{{Port: 443, SNI: "shop.example.test", Addr: "10.0.0.5"}}},
		{"a ccs locator has none", providers.CertLocation{Locator: providers.Locator{"type": "ccs", "port": 443, "app_id": winproto.AppIDIIS}}, providers.VerifyOptions{}, nil},
		{"a non-canonical address has none", ipportLoc("::ffff:10.0.0.5"), providers.VerifyOptions{}, nil},
		{"a port of another type has none", providers.CertLocation{Locator: providers.Locator{"type": "ipport", "ip": "0.0.0.0", "port": "443", "app_id": winproto.AppIDIIS}}, providers.VerifyOptions{}, nil},
		{"a fractional port has none", providers.CertLocation{Locator: providers.Locator{"type": "ipport", "ip": "0.0.0.0", "port": 443.5, "app_id": winproto.AppIDIIS}}, providers.VerifyOptions{}, nil},
		{"an int64 port out of range has none", providers.CertLocation{Locator: providers.Locator{"type": "ipport", "ip": "0.0.0.0", "port": int64(1 << 20), "app_id": winproto.AppIDIIS}}, providers.VerifyOptions{}, nil},
	} {
		assert.Equal(t, tc.want, Endpoints(tc.loc, tc.v, sans), tc.name)
	}

	// At most maxEndpoints.
	var servers []providers.CertServer
	for i := range maxEndpoints + 3 {
		servers = append(servers, site(string(rune('a'+i))+".example.test"))
	}
	assert.Len(t, Endpoints(ipportLoc("0.0.0.0", servers...), providers.VerifyOptions{}, sans), maxEndpoints)

	// unverifiable names the first endpoint's port, else the Administrator's, else 443.
	assert.Equal(t, "8443", unverifiable(sni, providers.VerifyOptions{}, nil).Params["port"])
	assert.Equal(t, "7443", unverifiable(providers.CertLocation{}, providers.VerifyOptions{Port: 7443}, nil).Params["port"])
	assert.Equal(t, "443", unverifiable(providers.CertLocation{}, providers.VerifyOptions{}, nil).Params["port"])
}

// venv is an emulated host whose IIS binding ipport <ip>:443 names cert, with its listeners served.
func venv(t *testing.T, ip string) (*env, pki.Leaf) {
	t.Helper()
	now := time.Now()
	m := wintest.NewModel()
	ca := pki.NewCA("Verify", pki.ECDSA256, now)
	m.AddIntermediate(ca.IntermediatePEM)
	l := ca.Issue(pki.Opts{CommonName: wHost, SANs: []string{wHost}}, now)
	sha1 := m.AddCertificate("My", l.CertPEM, l.KeyPEM, wintest.CertOptions{})
	m.AddBinding(winproto.SSLBinding{Type: winproto.BindingIPPort, IP: ip, Port: 443, AppID: winproto.AppIDIIS, CertSHA1: sha1, Store: "My"})
	e := newEnvWith(t, m)
	serve(t, m)
	return e, l
}

// W2 Ruling 15: a binding on a specific address Alice does not connect to is probed by the helper only
// (tls-probe --addr <ip>, a connection of its own); a wildcard binding Alice cannot reach falls back to
// the helper.
func TestVerifyUsesTheHelperWhenAliceCannotReach(t *testing.T) {
	e, l := venv(t, "10.0.0.5")
	s := e.open(t)
	req := providers.VerifyRequest{Location: ipportLoc("10.0.0.5"), Fingerprint: derSHA256(l.Cert.Raw), ChainLength: 2, SANs: []string{wHost}, KeyType: "ecdsa"}
	conns := e.srv.Connections()
	vr, err := s.VerifyDeployment(context.Background(), req)
	require.NoError(t, err)
	assert.True(t, vr.OK, "%+v", vr)
	assert.Equal(t, "local", vr.Mode)
	assert.Equal(t, providers.LevelServed, vr.Level)
	assert.Empty(t, e.probe.seen(), "Alice's own probe does not stand for 10.0.0.5")
	var probes []string
	for _, c := range e.srv.Commands() {
		if strings.HasPrefix(c, winproto.SubTLSProbe) {
			probes = append(probes, c)
		}
	}
	assert.Equal(t, []string{"tls-probe --addr 10.0.0.5 --port 443 --sni www.example.test --key-type any"}, probes)
	assert.Equal(t, conns+1, e.srv.Connections(), "one fresh connection per probe")

	// A wildcard binding: Alice first; when she cannot connect, the helper.
	e, l = venv(t, "0.0.0.0")
	s = e.open(t)
	req.Location, req.Fingerprint = ipportLoc("0.0.0.0", site()), derSHA256(l.Cert.Raw)
	vr, err = s.VerifyDeployment(context.Background(), req)
	require.NoError(t, err)
	assert.True(t, vr.OK)
	assert.Equal(t, "remote", vr.Mode)
	assert.Equal(t, []string{"127.0.0.1:443 www.example.test any"}, e.probe.seen())
	e.probe.setDown(true)
	vr, err = s.VerifyDeployment(context.Background(), req)
	require.NoError(t, err)
	assert.True(t, vr.OK)
	assert.Equal(t, "local", vr.Mode)

	// The helper's probe fails too: unreachable, a result, not an error.
	w := &wenv{env: e, stdins: map[string][][]byte{}}
	w.script(winproto.SubTLSProbe, func([]byte) linuxsshtest.Response { return refusalResponse(4, winproto.CodeProbeFailed) })
	vr, err = s.VerifyDeployment(context.Background(), req)
	require.NoError(t, err)
	assert.False(t, vr.OK)
	assert.Equal(t, "deployment.verify_unreachable", vr.Reason)

	// The Administrator's probe address: Alice's probe connects there.
	e.probe.setDown(false)
	req.Verify.Address = "192.0.2.10"
	vr, err = s.VerifyDeployment(context.Background(), req)
	require.NoError(t, err)
	assert.True(t, vr.OK)
	seen := e.probe.seen()
	assert.Equal(t, "192.0.2.10:443 www.example.test any", seen[len(seen)-1])

	// The SSH connection of the helper's probe fails: an error.
	e.probe.setDown(true)
	req.Verify.Address = ""
	e.srv.DisablePublicKeyAuth()
	_, err = s.VerifyDeployment(context.Background(), req)
	require.Error(t, err)

	// A skipped verification probes nothing; a cancelled context is an error.
	vr, err = s.VerifyDeployment(context.Background(), providers.VerifyRequest{Location: req.Location, Verify: providers.VerifyOptions{Skip: true}})
	require.NoError(t, err)
	assert.Equal(t, providers.LevelInstalled, vr.Level)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = s.VerifyDeployment(ctx, req)
	assert.Equal(t, "ssh.timeout", providerErr(t, err).Code)
}

// The server probe refuses an endpoint it cannot express before anything is dialled.
func TestServerProbeRefusesWhatTheHelperCannotTake(t *testing.T) {
	e, _ := venv(t, "0.0.0.0")
	s := e.open(t).(*session)
	conns := e.srv.Connections()
	for _, ep := range []tlsverify.Endpoint{{Port: 0, Addr: "127.0.0.1"}, {Port: 443, Addr: "not-an-ip"}, {Port: 443, Addr: "127.0.0.1", SNI: "bad sni"}} {
		_, reached, err := s.serverProbe(context.Background(), ep, "any")
		assert.NoError(t, err)
		assert.False(t, reached)
	}
	_, reached, err := s.serverProbe(context.Background(), tlsverify.Endpoint{Port: 443, Addr: "127.0.0.1"}, "any")
	assert.NoError(t, err)
	assert.True(t, reached, "no SNI is the helper's _")
	assert.Equal(t, conns+1, e.srv.Connections())
}

// R61 Task 11: inventory hands the provider the locator as stored (providers.ParseLocator: a number is a json.Number),
// not as discovered (an int): the provider reads the port of both forms and refuses a number that is not a port.
func TestLocatorOfTheStoredLocator(t *testing.T) {
	stored, err := providers.ParseLocator([]byte(`{"app_id":"` + winproto.AppIDIIS + `","host":"www.example.test","port":443,"type":"hostnameport"}`))
	require.NoError(t, err)
	loc := providers.CertLocation{Kind: providers.LocationWinSSLBinding, Locator: stored}
	l, ok := locatorOf(loc)
	require.True(t, ok)
	assert.Equal(t, winproto.Locator{Type: winproto.BindingHostnamePort, Host: "www.example.test", Port: 443, AppID: winproto.AppIDIIS}, l)
	assert.Len(t, Endpoints(loc, providers.VerifyOptions{}, nil), 1)
	for _, n := range []string{"0", "65536", "-1", "4.5", "99999999999999999999"} {
		bad := providers.Locator{"type": "hostnameport", "host": "www.example.test", "port": json.Number(n), "app_id": winproto.AppIDIIS}
		_, ok := locatorOf(providers.CertLocation{Kind: providers.LocationWinSSLBinding, Locator: bad})
		assert.False(t, ok, n)
	}
}

func ccsLoc(servers ...providers.CertServer) providers.CertLocation {
	return providers.CertLocation{Kind: providers.LocationWinCCSFile, Supported: true, CertPath: `C:\CCS\www.example.test.pfx`,
		Locator: providers.Locator{"type": winproto.LocatorCCSFile, "path": `C:\CCS`, "host": "www.example.test"}, Servers: servers}
}

func ccsBinding(host, ip string, port int) providers.CertServer {
	return providers.CertServer{Names: []string{host}, Listens: []providers.CertListen{{Addr: ip, Port: port}}, Section: "Web"}
}

// W5 Ruling 20: a CCS file's endpoints are its linked IIS bindings, each with its port and its host header as SNI
// (a "*." host becomes alice-check.); the Administrator's port, SNI and probe address apply.
func TestCCSEndpoints(t *testing.T) {
	sans := []string{"www.example.test"}
	two := ccsLoc(ccsBinding("www.example.test", "*", 443), ccsBinding("shop.example.test", "*", 8443), ccsBinding("www.example.test", "*", 443))
	for _, tc := range []struct {
		name string
		loc  providers.CertLocation
		v    providers.VerifyOptions
		want []tlsverify.Endpoint
	}{
		{"two linked bindings: two SNI endpoints", two, providers.VerifyOptions{},
			[]tlsverify.Endpoint{{Port: 443, SNI: "www.example.test", Addr: "127.0.0.1"}, {Port: 8443, SNI: "shop.example.test", Addr: "127.0.0.1"}}},
		{"a wildcard host header", ccsLoc(ccsBinding("*.example.test", "*", 443)), providers.VerifyOptions{},
			[]tlsverify.Endpoint{{Port: 443, SNI: "alice-check.example.test", Addr: "127.0.0.1"}}},
		{"a binding on one address listens there only", ccsLoc(ccsBinding("www.example.test", "10.0.0.5", 443)), providers.VerifyOptions{},
			[]tlsverify.Endpoint{{Port: 443, SNI: "www.example.test", Addr: "10.0.0.5", Listen: "10.0.0.5"}}},
		{"a binding on [::]: the helper probes ::1", ccsLoc(ccsBinding("www.example.test", "::", 443)), providers.VerifyOptions{},
			[]tlsverify.Endpoint{{Port: 443, SNI: "www.example.test", Addr: "::1"}}},
		{"an address Alice cannot read has none", ccsLoc(ccsBinding("www.example.test", "not-an-ip", 443)), providers.VerifyOptions{}, nil},
		{"the Administrator's port and SNI", two, providers.VerifyOptions{Port: 9443, SNI: "override.example.test"},
			[]tlsverify.Endpoint{{Port: 9443, SNI: "override.example.test", Addr: "127.0.0.1"}}},
		{"the Administrator's probe address stands for a specific listen", ccsLoc(ccsBinding("www.example.test", "10.0.0.5", 443)),
			providers.VerifyOptions{Address: "lb.example.test"}, []tlsverify.Endpoint{{Port: 443, SNI: "www.example.test", Addr: "10.0.0.5"}}},
		{"unlinked: none", ccsLoc(), providers.VerifyOptions{}, nil},
		{"a locator Alice does not deploy to has none", providers.CertLocation{Kind: providers.LocationWinCCSFile,
			Locator: providers.Locator{"type": winproto.LocatorCCSFile, "path": `\\files\ccs`, "host": "www.example.test"},
			Servers: []providers.CertServer{ccsBinding("www.example.test", "*", 443)}}, providers.VerifyOptions{}, nil},
	} {
		assert.Equal(t, tc.want, Endpoints(tc.loc, tc.v, sans), tc.name)
	}
	var servers []providers.CertServer
	for i := range maxEndpoints + 3 {
		servers = append(servers, ccsBinding(string(rune('a'+i))+".example.test", "*", 443))
	}
	assert.Len(t, Endpoints(ccsLoc(servers...), providers.VerifyOptions{}, sans), maxEndpoints)
}

// Review Focus 3, W5 Ruling 8: a file no IIS binding uses is verified by the helper's read-back only: the
// verification is skipped (level 1) with the param ccs_unlinked on the verify step, and nothing is probed.
func TestCCSUnlinkedIsReadBackOnly(t *testing.T) {
	c := newCEnv(t)
	c.cloc.Servers = nil
	s := c.csession(t)
	vr, err := s.VerifyDeployment(context.Background(), providers.VerifyRequest{Location: c.cloc, Fingerprint: derSHA256(c.old.Cert.Raw)})
	require.NoError(t, err)
	assert.Equal(t, providers.VerifyResult{OK: true, Mode: "skipped", Level: providers.LevelInstalled, Params: map[string]string{"ccs_unlinked": "true"}}, vr)

	nl := c.issue()
	req := c.ccsReq(nl)
	log := &paramsLog{stepLog: &stepLog{}, name: providers.StepNameVerify}
	out, err := s.DeployCertificate(context.Background(), req, log)
	providertest.CheckDeployOutcome(t, out, err)
	require.NoError(t, err)
	assert.Equal(t, providers.DeployCommitted, out.Result)
	assert.Equal(t, "skipped", out.Verified)
	assert.Equal(t, []string{"import_chain:ok", "write_file:ok", "verify:skipped"}, stepWords(out.Steps))
	assert.Equal(t, "true", log.params["ccs_unlinked"])
	assert.Empty(t, c.probe.seen(), "nothing is probed")
	assert.Zero(t, c.countSent(winproto.SubTLSProbe))
	assert.Equal(t, derSHA256(nl.Cert.Raw), c.file(t), "the helper read the file back")
}

// paramsLog records into its stepLog and keeps the params of the named step's final status.
type paramsLog struct {
	*stepLog
	name   string
	params map[string]string
}

func (p *paramsLog) Step(name string, status providers.StepStatus, params map[string]string) {
	p.stepLog.Step(name, status, params)
	if name == p.name && status != providers.StepStarted {
		p.params = params
	}
}

// W6 Ruling 16: the listener's one endpoint: the locator's port, SNI from the SANs, the helper's probe of the
// loopback, on every address; the Administrator's port and SNI replace them. A locator Alice does not deploy to has none.
func TestRDPEndpoints(t *testing.T) {
	loc := rdpLoc(3390, map[string]any{})
	assert.Equal(t, []tlsverify.Endpoint{{Port: 3390, SNI: "rdp.example.test", Addr: "127.0.0.1"}},
		Endpoints(loc, providers.VerifyOptions{}, []string{"rdp.example.test"}))
	assert.Equal(t, []tlsverify.Endpoint{{Port: 13389, SNI: "admin.example.test", Addr: "127.0.0.1"}},
		Endpoints(loc, providers.VerifyOptions{Port: 13389, SNI: "admin.example.test", Address: "192.0.2.7"}, []string{"rdp.example.test"}))
	stored := rdpLoc(0, map[string]any{})
	stored.Locator["port"] = json.Number("3389") // the locator as inventory stored it
	assert.Equal(t, []tlsverify.Endpoint{{Port: 3389, SNI: "rdp.example.test", Addr: "127.0.0.1"}},
		Endpoints(stored, providers.VerifyOptions{}, []string{"rdp.example.test"}))
	for _, bad := range []providers.Locator{
		{"type": winproto.LocatorRDP, "listener": "RDP-Other", "port": 3389},
		{"type": winproto.BindingIPPort, "listener": winproto.RDPListenerName, "port": 3389},
		{"type": winproto.LocatorRDP, "listener": winproto.RDPListenerName, "port": 0},
	} {
		l := rdpLoc(3389, map[string]any{})
		l.Locator = bad
		assert.Empty(t, Endpoints(l, providers.VerifyOptions{}, []string{"rdp.example.test"}), "%v", bad)
	}
}

// Review Focus 4 and W6 Ruling 16: Alice cannot reach the listener's port (a firewall that admits administrators
// only): the helper's tls-probe --rdp of 127.0.0.1 decides; it is the plain probe's command line with --rdp last.
func TestRDPVerifyFallsBackToTheHelper(t *testing.T) {
	r := newREnv(t)
	r.rprobe.setDown(true)
	s := r.open(t)
	req := r.rdpReq(r.issue())
	out, err := s.DeployCertificate(context.Background(), req, nil)
	providertest.CheckDeployOutcome(t, out, err)
	require.NoError(t, err)
	assert.Equal(t, providers.DeployCommitted, out.Result)
	assert.Equal(t, "local", out.Verified, "the helper's probe decided")
	var probes []string
	for _, c := range r.srv.Commands() {
		if strings.HasPrefix(c, winproto.SubTLSProbe) {
			probes = append(probes, c)
		}
	}
	require.NotEmpty(t, probes)
	for _, p := range probes {
		assert.Equal(t, "tls-probe --addr 127.0.0.1 --port 3389 --sni www.example.test --key-type any --rdp", p)
	}
	assert.NotEmpty(t, r.rprobe.seen(), "Alice tried first")
	assert.Empty(t, r.probe.seen(), "never the plain TLS probe")

	// The listener does not take the change: the helper's probe sees the self-signed certificate, and it is put back.
	r = newREnv(t)
	r.rprobe.setDown(true)
	r.model.ServeStaleRDP(true)
	out, err = r.open(t).DeployCertificate(context.Background(), r.rdpReq(r.issue()), nil)
	providertest.CheckDeployOutcome(t, out, err)
	require.NoError(t, err)
	assert.Equal(t, providers.DeployRolledBack, out.Result)
	assert.Equal(t, "deployment.verify_failed", out.Reason)
	assert.Empty(t, r.model.RDPThumbprint())
}
