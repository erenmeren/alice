package windows

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/providers"
	"alice/internal/providers/linuxssh/helperproto"
	"alice/internal/providers/linuxssh/linuxsshtest"
	"alice/internal/providers/providertest"
	"alice/internal/providers/windows/winproto"
	"alice/internal/providers/windows/wintest"
	"alice/internal/testutil/pki"
)

// rdpPort is the emulated listener's port (the model serves it on a random local port, Model.Endpoint).
const rdpPort = 3389

// renv is wenv's host whose RDP-Tcp listener is on (SecurityLayer 2, NLA on) without SSLCertificateSHA1Hash, so it
// serves the single certificate of Remote Desktop, self (W6 Ruling 4).
type renv struct {
	*wenv
	self     pki.Leaf
	selfSHA1 string
	rloc     providers.CertLocation
}

func newREnv(t *testing.T) *renv { return newREnvOf(t, nil) }

// newREnvOf is newREnv whose Remote Desktop store holds self (nil: one made now).
func newREnvOf(t *testing.T, own *pki.Leaf) *renv {
	t.Helper()
	w := newWEnv(t)
	self := pki.SelfSigned("win-rdp01", pki.ECDSA256, time.Now())
	if own != nil {
		self = *own
	}
	sha1 := w.model.AddCertificate(winproto.RDPStoreSelfSigned, self.CertPEM, self.KeyPEM, wintest.CertOptions{})
	w.model.SetRDP(wintest.RDPConfig{Present: true, Enabled: true, NLA: true, Port: rdpPort, SecurityLayer: 2})
	serve(t, w.model) // a second Serve: the listener's port is new
	return &renv{wenv: w, self: self, selfSHA1: sha1, rloc: rdpLoc(rdpPort, map[string]any{"store": winproto.RDPStoreSelfSigned,
		"cert_sha1": sha1, "self_signed": true})}
}

func rdpLoc(port int, details map[string]any) providers.CertLocation {
	return providers.CertLocation{Kind: providers.LocationWinRDP, CertPath: winproto.RDPCanonical, Supported: true,
		Locator: providers.Locator{"type": winproto.LocatorRDP, "listener": winproto.RDPListenerName, "port": port},
		Servers: []providers.CertServer{}, Details: details}
}

// rdpReq is a deployment of nl to the listener, which serves the self-signed certificate now.
func (r *renv) rdpReq(nl pki.Leaf) providers.DeployRequest {
	return providers.DeployRequest{OperationID: uuid.New(), Location: r.rloc, ExpectCertSHA256: derSHA256(r.self.Cert.Raw),
		CertificatePEM: nl.FullchainPEM, PrivateKeyPEM: providers.NewSecret(append([]byte(nil), nl.KeyPEM...)),
		Fingerprint: derSHA256(nl.Cert.Raw), SANs: []string{wHost}, KeyType: "ecdsa", OldFingerprint: derSHA256(r.self.Cert.Raw),
		OldSANs: []string{"win-rdp01"}, ChainLength: 2}
}

// rdpServed is the leaf the listener serves after the RDP negotiation ("" when the handshake fails).
func (r *renv) rdpServed() string {
	p := &modelProber{m: r.model, rdp: true}
	got, err := p.Probe(context.Background(), "127.0.0.1", rdpPort, "", helperproto.ProbeAny)
	if err != nil {
		return ""
	}
	return got.LeafSHA256
}

// versionAs makes the emulated helper answer version v.
func versionAs(e *env, v string) {
	inner := e.model.Handler()
	e.srv.SetHandler(func(cmd string, stdin []byte) linuxsshtest.Response {
		if cmd == winproto.SubVersion {
			b, _ := json.Marshal(winproto.VersionResponse{OK: true, Helper: v, Protocol: 1})
			return linuxsshtest.Response{Stdout: append(b, '\n')}
		}
		return inner(cmd, stdin)
	})
}

func rdpLocations(certs []providers.DiscoveredCertificate) []providers.DiscoveredCertificate {
	var out []providers.DiscoveredCertificate
	for _, c := range certs {
		if c.Location.Kind == providers.LocationWinRDP {
			out = append(out, c)
		}
	}
	return out
}

// Review Focus 5 and W6 Ruling 2: a 1.1.0 helper is never sent an RDP subcommand or tls-probe --rdp. Discovery reads
// the bindings and the CCS files as in W5 and warns win_rdp_helper_outdated; a deployment to the listener is refused
// before anything is sent; its verification probes from Alice only.
func TestRDPNeedsHelper120(t *testing.T) {
	m, err := wintest.Demo(time.Now())
	require.NoError(t, err)
	e := newEnvWith(t, m)
	versionAs(e, "1.1.0")
	cred := &ccsCred{fakeCred: e.cred, pw: m.CCSPassword()}
	sess, err := e.prov.Open(context.Background(), e.ref, cred, providers.Env{})
	require.NoError(t, err)
	res, err := sess.Discover(context.Background(), providers.DiscoverRequest{Certificates: true})
	require.NoError(t, err)
	assert.Equal(t, []string{"version", "iis-dump", "ccs-dump"}, e.srv.Commands())
	assert.Contains(t, codes(res.Warnings), winproto.WarnRDPHelperOutdated)
	assert.NotNil(t, warningParams(res.Warnings, winproto.WarnRDPHelperOutdated), "a server warning")
	assert.Empty(t, rdpLocations(res.Certificates))
	assert.NotEmpty(t, ccsLocations(res.Certificates), "the CCS files as in W5")

	ca := pki.NewCA("Outdated", pki.ECDSA256, time.Now())
	nl := ca.Issue(pki.Opts{CommonName: "win-demo01", SANs: []string{"win-demo01"}}, time.Now())
	loc := rdpLoc(3389, map[string]any{})
	req := providers.DeployRequest{OperationID: uuid.New(), Location: loc, ExpectCertSHA256: strings.Repeat("ab", 32),
		CertificatePEM: nl.FullchainPEM, PrivateKeyPEM: providers.NewSecret(append([]byte(nil), nl.KeyPEM...)), KeyType: "ecdsa"}
	out, derr := sess.DeployCertificate(context.Background(), req, nil)
	providertest.CheckDeployOutcome(t, out, derr)
	pe := providerErr(t, derr)
	assert.Equal(t, ReasonHelperOutdated, pe.Code)
	assert.Equal(t, map[string]string{"helper_version": "1.1.0", "required_version": "1.2.0"}, pe.Params)
	assert.Equal(t, providers.DeployNoChange, out.Result)
	assert.Equal(t, []string{"version", "iis-dump", "ccs-dump"}, e.srv.Commands(), "nothing sent for the RDP deployment")

	e.rprobe.setDown(true)
	vr, err := sess.VerifyDeployment(context.Background(), providers.VerifyRequest{Location: loc, Fingerprint: derSHA256(nl.Cert.Raw),
		SANs: []string{"win-demo01"}, KeyType: "ecdsa"})
	require.NoError(t, err)
	assert.False(t, vr.OK)
	assert.Equal(t, reasonVerifyUnreachable, vr.Reason)
	assert.Equal(t, []string{"version", "iis-dump", "ccs-dump"}, e.srv.Commands(), "no tls-probe --rdp to a 1.1.0 helper")
	assert.NotEmpty(t, e.rprobe.seen(), "Alice tried her own RDP probe")
	assert.Empty(t, e.probe.seen(), "never the plain TLS probe")
}

// Review Focus 5: without an RDP-Tcp key, discovery is W5's: the same binding and CCS locations, no win_rdp location
// and no RDP warning; only rdp-dump is added to what is sent.
func TestDiscoverWithoutRDPIsW5(t *testing.T) {
	run := func(version string) (providers.DiscoveryResult, []string) {
		m, err := wintest.Demo(time.Now())
		require.NoError(t, err)
		m.SetRDP(wintest.RDPConfig{})
		e := newEnvWith(t, m)
		if version != "" {
			versionAs(e, version)
		}
		sess, err := e.prov.Open(context.Background(), e.ref, &ccsCred{fakeCred: e.cred, pw: m.CCSPassword()}, providers.Env{})
		require.NoError(t, err)
		res, err := sess.Discover(context.Background(), providers.DiscoverRequest{Certificates: true})
		require.NoError(t, err)
		return res, e.srv.Commands()
	}
	w6, cmds := run("")
	assert.Equal(t, []string{"version", "iis-dump", "ccs-dump", "rdp-dump"}, cmds)
	w5, _ := run("1.1.0")
	assert.Empty(t, rdpLocations(w6.Certificates))
	require.Equal(t, len(w5.Certificates), len(w6.Certificates))
	for i := range w5.Certificates {
		// Each run's demo host issues its own certificates: everything but their hashes is compared.
		a, b := w5.Certificates[i].Location, w6.Certificates[i].Location
		for _, k := range []string{"cert_sha1", "file_sha256", "file_size"} {
			delete(a.Details, k)
			delete(b.Details, k)
		}
		assert.Equal(t, a, b, a.CertPath)
		assert.Equal(t, w5.Certificates[i].FileSHA256 == "", w6.Certificates[i].FileSHA256 == "", a.CertPath)
	}
	assert.Equal(t, slices.DeleteFunc(codes(w5.Warnings), func(c string) bool { return c == winproto.WarnRDPHelperOutdated }), codes(w6.Warnings))
	for _, c := range codes(w6.Warnings) {
		assert.NotContains(t, c, "rdp")
	}
}

// rdpStoreCert is a certificate of store as rdp-dump sends it, with a usable key.
func rdpStoreCert(t *testing.T, store string, l pki.Leaf, chain ...[]byte) *winproto.StoreCertificate {
	t.Helper()
	yes := true
	c := &winproto.StoreCertificate{Store: store, SHA1: sha1Hex(l.Cert.Raw), SHA256: derSHA256(l.Cert.Raw),
		DER: base64.StdEncoding.EncodeToString(l.Cert.Raw), Chain: []string{}, HasKey: true, KeyUsableBySystem: &yes,
		KeyProvider: "Microsoft Software Key Storage Provider", NotAfter: l.Cert.NotAfter.UTC().Format(time.RFC3339)}
	for _, der := range chain {
		c.Chain = append(c.Chain, base64.StdEncoding.EncodeToString(der))
	}
	return c
}

// Review Focus 3 and W6 Rulings 3-5: the listener's location from rdp-dump.
func TestConvertRDP(t *testing.T) {
	now := time.Now()
	ca := pki.NewCA("RDP convert", pki.ECDSA256, now)
	self := pki.SelfSigned("win-rdp01", pki.ECDSA256, now)
	named := ca.Issue(pki.Opts{CommonName: "rdp.example.test", SANs: []string{"rdp.example.test"}}, now)
	on := func(mod func(*winproto.RDPDumpResponse)) winproto.RDPDumpResponse {
		d := winproto.RDPDumpResponse{OK: true, Present: true, Enabled: true, NLA: true, Port: 3389, SecurityLayer: 2,
			Certificate: rdpStoreCert(t, winproto.RDPStoreSelfSigned, self), SelfSignedCount: 1}
		if mod != nil {
			mod(&d)
		}
		return d
	}
	valueSet := func(d *winproto.RDPDumpResponse) {
		d.ValueSet, d.SelfSignedCount = true, 0
		d.Certificate = rdpStoreCert(t, "MY", named, ca.Intermediate.Raw)
	}
	for _, tc := range []struct {
		name        string
		d           winproto.RDPDumpResponse
		unsupported string
		problem     string
		keyProblem  string
		token       []byte // the leaf of the token, nil: none
		chain       int
		selfSigned  bool
		store       string
		warnings    []string
	}{
		{name: "the value absent, one self-signed certificate: deployable", d: on(nil), token: self.Cert.Raw, chain: 1, selfSigned: true,
			store: winproto.RDPStoreSelfSigned},
		{name: "the value names a certificate of My", d: on(valueSet), token: named.Cert.Raw, chain: 2, store: "MY"},
		{name: "no self-signed certificate", d: on(func(d *winproto.RDPDumpResponse) { d.Certificate, d.SelfSignedCount = nil, 0 }),
			unsupported: winproto.UnsupportedRDPCertUnknown},
		{name: "two self-signed certificates", d: on(func(d *winproto.RDPDumpResponse) { d.Certificate, d.SelfSignedCount = nil, 2 }),
			unsupported: winproto.UnsupportedRDPCertUnknown},
		{name: "Remote Desktop off", d: on(func(d *winproto.RDPDumpResponse) { d.Enabled = false }), unsupported: winproto.UnsupportedRDPDisabled,
			token: self.Cert.Raw, chain: 1, selfSigned: true, store: winproto.RDPStoreSelfSigned},
		{name: "security layer 0", d: on(func(d *winproto.RDPDumpResponse) { d.SecurityLayer = 0 }), unsupported: winproto.UnsupportedRDPNoTLS,
			token: self.Cert.Raw, chain: 1, selfSigned: true, store: winproto.RDPStoreSelfSigned},
		{name: "the value names a certificate not in My", d: on(func(d *winproto.RDPDumpResponse) { d.ValueSet, d.Certificate, d.SelfSignedCount = true, nil, 0 }),
			unsupported: providers.UnsupportedFile, problem: ProblemCertMissing},
		{name: "the named certificate has no key", d: on(func(d *winproto.RDPDumpResponse) { valueSet(d); d.Certificate.HasKey = false }),
			unsupported: providers.UnsupportedFile, keyProblem: ProblemKeyMissing, token: named.Cert.Raw, chain: 2, store: "MY"},
		{name: "a certificate template: autoenrolment warned", d: on(func(d *winproto.RDPDumpResponse) { d.CertTemplate = "RemoteDesktop" }),
			token: self.Cert.Raw, chain: 1, selfSigned: true, store: winproto.RDPStoreSelfSigned, warnings: []string{winproto.WarnRDPAutoenroll}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			certs, warns := convertRDP(tc.d)
			assert.Empty(t, warns)
			require.Len(t, certs, 1)
			c := certs[0]
			checkStorable(t, c)
			l := c.Location
			assert.Equal(t, providers.LocationWinRDP, l.Kind)
			assert.Equal(t, winproto.RDPCanonical, l.CertPath)
			assert.Equal(t, providers.Locator{"type": winproto.LocatorRDP, "listener": winproto.RDPListenerName, "port": 3389}, l.Locator)
			assert.Equal(t, tc.unsupported, l.Unsupported)
			assert.Equal(t, tc.problem, l.Problem)
			assert.Equal(t, tc.keyProblem, l.KeyProblem)
			assert.Equal(t, tc.warnings, l.Warnings)
			assert.Equal(t, tc.d.Enabled, l.Details["enabled"])
			assert.Equal(t, tc.d.NLA, l.Details["nla"])
			assert.Equal(t, tc.d.SecurityLayer, l.Details["security_layer"])
			assert.Equal(t, tc.d.CertTemplate, l.Details["cert_template"])
			assert.Equal(t, tc.selfSigned, l.Details["self_signed"])
			if tc.token == nil {
				assert.Empty(t, c.FileSHA256)
				assert.Nil(t, c.PEMChain)
				return
			}
			assert.Equal(t, derSHA256(tc.token), c.FileSHA256, "the token is the leaf DER's SHA-256 (Ruling 4)")
			assert.Len(t, pemBlocks(c.PEMChain), tc.chain)
			assert.Equal(t, tc.token, pemBlocks(c.PEMChain)[0])
			assert.Equal(t, tc.store, l.Details["store"])
			assert.Equal(t, sha1Hex(tc.token), l.Details["cert_sha1"])
		})
	}
	t.Run("no RDP-Tcp key: no location", func(t *testing.T) {
		certs, warns := convertRDP(winproto.RDPDumpResponse{OK: true})
		assert.Empty(t, certs)
		assert.Empty(t, warns)
	})
	t.Run("a port Alice cannot use: left out, nothing marked missing", func(t *testing.T) {
		certs, warns := convertRDP(on(func(d *winproto.RDPDumpResponse) { d.Port = 0 }))
		assert.Empty(t, certs)
		assert.Equal(t, []string{providers.WarnListTruncated, providers.WarnLocationsDropped}, codes(warns))
	})
	t.Run("a failed rdp-dump keeps the bindings: locations_dropped", func(t *testing.T) {
		r := newREnv(t)
		r.script(winproto.SubRDPDump, func([]byte) linuxsshtest.Response { return refusalResponse(winproto.ExitFailed, winproto.CodeIOError) })
		res, err := r.open(t).Discover(context.Background(), providers.DiscoverRequest{Certificates: true})
		require.NoError(t, err)
		assert.Empty(t, rdpLocations(res.Certificates))
		assert.Contains(t, byPath(res.Certificates), "http.sys/hostnameport/"+wHost+":443")
		assert.Equal(t, []string{providers.WarnListTruncated, providers.WarnLocationsDropped}, codes(res.Warnings))
	})
	t.Run("discovered on the emulator", func(t *testing.T) {
		r := newREnv(t)
		res, err := r.open(t).Discover(context.Background(), providers.DiscoverRequest{Certificates: true})
		require.NoError(t, err)
		got := rdpLocations(res.Certificates)
		require.Len(t, got, 1)
		assert.True(t, got[0].Location.Supported, got[0].Location.Unsupported)
		assert.Equal(t, derSHA256(r.self.Cert.Raw), got[0].FileSHA256)
		assert.Equal(t, r.selfSHA1, got[0].Location.Details["cert_sha1"])
	})
}

// Design §8: discovery's rdp-dump and a deployment's rdp-deploy each run on a fresh connection of their own.
func TestEachRDPCallUsesItsOwnConnection(t *testing.T) {
	r := newREnv(t)
	s := r.open(t)
	assert.Equal(t, 1, r.srv.Connections())
	r.waitNoOpenConnections(t)
	_, err := s.Discover(context.Background(), providers.DiscoverRequest{Certificates: true})
	require.NoError(t, err, "a reused connection would answer rdp-dump as iis-dump")
	assert.Equal(t, 3, r.srv.Connections())
	req := r.rdpReq(r.issue())
	req.Verify.Skip = true
	out, err := s.DeployCertificate(context.Background(), req, nil)
	require.NoError(t, err, "a reused connection would answer rdp-deploy as version")
	assert.Equal(t, providers.DeployCommitted, out.Result)
	assert.Equal(t, 4, r.srv.Connections(), "one connection per helper call")
	assert.Equal(t, []string{"version", "iis-dump", "rdp-dump", "rdp-deploy --op " + req.OperationID.String()}, r.srv.Commands())
	r.waitNoOpenConnections(t)
}

// The shape table of an RDP deployment (W6 Ruling 9; mirror of TestCCSDeployOutcomeTable): one row per refusal code of
// rdp-deploy with its reason, and committed, unchanged, the helper's own restore, the inline rollback and uncertain.
// Every return passes providers.CheckDeployReturn.
func TestRDPDeployOutcomeTable(t *testing.T) {
	type want struct {
		result                    providers.DeployResult
		phase, failed, cause, cls string
		verified                  string
		steps                     []string
		reason                    string
		errCode                   string
		retryable                 bool
		serves                    string // "old", "new" or "" (not checked)
		noDeploySent              bool
		restores                  int
		answered                  bool // the backup is the helper's answer
	}
	refused := func(reason string, retryable bool) want {
		return want{result: providers.DeployNoChange, reason: reason, errCode: reason, retryable: retryable, serves: "old"}
	}
	written := []string{"import_chain:ok", "import_certificate:ok", "grant_key_read:ok", "set_listener:ok"}
	for _, tc := range []struct {
		name  string
		setup func(t *testing.T, r *renv, nl pki.Leaf, req *providers.DeployRequest)
		want  want
	}{
		{"committed, level 3", func(_ *testing.T, r *renv, _ pki.Leaf, req *providers.DeployRequest) {
			req.Trust = &providers.TrustPolicy{Roots: rootPool(r.ca), Store: providers.TrustStoreSystem, Enforce: true}
		}, want{result: providers.DeployCommitted, phase: "committed", verified: "remote", steps: append(written, "verify:ok"), serves: "new", answered: true}},
		{"unchanged: the listener names the certificate already", func(t *testing.T, r *renv, nl pki.Leaf, req *providers.DeployRequest) {
			first := r.rdpReq(nl)
			first.Verify.Skip = true
			out, err := r.open(t).DeployCertificate(context.Background(), first, nil)
			require.NoError(t, err)
			require.Equal(t, providers.DeployCommitted, out.Result)
			req.ExpectCertSHA256, req.OldFingerprint = req.Fingerprint, req.Fingerprint
		}, want{result: providers.DeployUnchanged, phase: "unchanged", verified: "remote",
			steps: []string{"import_chain:ok", "import_certificate:ok", "grant_key_read:ok", "verify:ok"}, serves: "new"}},
		{"BINDING_NOT_FOUND: no RDP-Tcp key", func(_ *testing.T, r *renv, _ pki.Leaf, _ *providers.DeployRequest) {
			r.model.SetRDP(wintest.RDPConfig{})
		}, want{result: providers.DeployNoChange, reason: ReasonBindingNotFound, errCode: ReasonBindingNotFound}},
		{"RDP_DISABLED", func(_ *testing.T, r *renv, _ pki.Leaf, _ *providers.DeployRequest) {
			r.model.SetRDP(wintest.RDPConfig{Present: true, Port: rdpPort, SecurityLayer: 2})
		}, want{result: providers.DeployNoChange, reason: ReasonRDPDisabled, errCode: ReasonRDPDisabled}},
		{"RDP_TLS_OFF", func(_ *testing.T, r *renv, _ pki.Leaf, _ *providers.DeployRequest) {
			r.model.SetRDP(wintest.RDPConfig{Present: true, Enabled: true, Port: rdpPort, SecurityLayer: 0})
		}, want{result: providers.DeployNoChange, reason: ReasonRDPTLSOff, errCode: ReasonRDPTLSOff}},
		{"HASH_MISMATCH: the listener serves another certificate than the token", func(_ *testing.T, _ *renv, _ pki.Leaf, req *providers.DeployRequest) {
			req.ExpectCertSHA256 = strings.Repeat("ab", 32)
		}, refused(ReasonBindingChanged, true)},
		{"UNKNOWN_SUBCOMMAND (the backstop): helper_outdated", func(_ *testing.T, r *renv, _ pki.Leaf, _ *providers.DeployRequest) {
			r.script(winproto.SubRDPDeploy, func([]byte) linuxsshtest.Response {
				return refusalResponse(winproto.ExitRefused, winproto.CodeUnknownSubcommand)
			})
		}, refused(ReasonHelperOutdated, false)},
		{"a locator Alice does not deploy to", func(_ *testing.T, _ *renv, _ pki.Leaf, req *providers.DeployRequest) {
			req.Location.Locator = providers.Locator{"type": winproto.LocatorRDP, "listener": "RDP-Other", "port": rdpPort}
		}, want{result: providers.DeployNoChange, reason: ReasonLocationUnsupported, errCode: ReasonLocationUnsupported, serves: "old", noDeploySent: true}},

		{"key_acl: the grant failed, restored by the helper", func(_ *testing.T, r *renv, _ pki.Leaf, _ *providers.DeployRequest) { r.model.FailKeyACL(true) },
			want{result: providers.DeployRolledBack, phase: "restored", failed: "grant_key_read", cause: "grant_key_read", cls: "key_acl", verified: "remote",
				steps: []string{"import_chain:ok", "import_certificate:ok", "grant_key_read:failed", "verify_old:ok"}, reason: ReasonRDPKeyACLFailed,
				serves: "old", answered: true}},
		{"verification failed: the value is deleted again", func(_ *testing.T, r *renv, _ pki.Leaf, _ *providers.DeployRequest) { r.model.ServeStaleRDP(true) },
			want{result: providers.DeployRolledBack, phase: "restored", failed: "verify", cause: "verify", verified: "remote",
				steps: append(written, "verify:failed", "restore:ok", "verify_old:ok"), reason: "deployment.verify_failed", serves: "old", restores: 1, answered: true}},
		{"verification failed, the previous certificate compromised: forbidden", func(_ *testing.T, r *renv, _ pki.Leaf, req *providers.DeployRequest) {
			r.model.ServeStaleRDP(true)
			req.RecheckGuard = func(context.Context) (providers.RollbackGuard, error) {
				return providers.RollbackGuard{Required: true, ForbiddenLeaf: []string{derSHA256(r.self.Cert.Raw)}}, nil
			}
		}, want{result: providers.DeployRollbackFailed, phase: "restore_forbidden", failed: "restore", cause: "verify", cls: "forbidden",
			steps: append(written, "verify:failed", "restore:failed"), reason: providers.ReasonRollbackForbidden, restores: 1, answered: true}},
		{"OUTCOME_UNKNOWN: uncertain", func(_ *testing.T, r *renv, _ pki.Leaf, _ *providers.DeployRequest) {
			r.script(winproto.SubRDPDeploy, func([]byte) linuxsshtest.Response {
				return refusalResponse(winproto.ExitFailed, winproto.CodeOutcomeUnknown)
			})
		}, want{result: providers.DeployUncertain, errCode: "ssh.protocol_error", serves: "old"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newREnv(t)
			nl := r.issue()
			req := r.rdpReq(nl)
			tc.setup(t, r, nl, &req)
			before := r.countSent(winproto.SubRDPDeploy)
			s := r.open(t)
			out, err := s.DeployCertificate(context.Background(), req, &stepLog{})
			providertest.CheckDeployOutcome(t, out, err)
			w := tc.want
			assert.Equal(t, w.result, out.Result, "%+v %v", out, err)
			assert.Equal(t, w.phase, out.Phase)
			assert.Equal(t, w.failed, out.FailedStep)
			assert.Equal(t, w.cause, out.CauseStep)
			assert.Equal(t, w.cls, out.Error)
			assert.Equal(t, w.verified, out.Verified)
			if w.steps != nil {
				assert.Equal(t, w.steps, stepWords(out.Steps))
			}
			assert.Equal(t, w.reason, out.Reason)
			if w.errCode == "" {
				assert.NoError(t, err)
			} else {
				pe := providerErr(t, err)
				assert.Equal(t, w.errCode, pe.Code)
				assert.Equal(t, w.retryable, pe.Retryable)
			}
			want := providers.BackupRef{OperationID: req.OperationID, Store: winproto.RDPStoreSelfSigned, PreviousSHA1: r.selfSHA1,
				PreviousSHA256: req.ExpectCertSHA256}
			if w.result != providers.DeployUnchanged {
				assert.Equal(t, want, out.Backup, "the previous certificate's store (W6 Ruling 19)")
			}
			r.model.ServeStaleRDP(false)
			switch w.serves {
			case "old":
				assert.Equal(t, derSHA256(r.self.Cert.Raw), r.rdpServed())
				assert.Empty(t, r.model.RDPThumbprint(), "the value is absent")
				assert.False(t, r.model.KeyReadableByNetworkService("My", sha1Hex(nl.Cert.Raw)), "no grant is left")
			case "new":
				assert.Equal(t, req.Fingerprint, r.rdpServed())
				assert.Equal(t, sha1Hex(nl.Cert.Raw), r.model.RDPThumbprint())
				assert.True(t, r.model.KeyReadableByNetworkService("My", sha1Hex(nl.Cert.Raw)))
			}
			if w.noDeploySent {
				assert.Equal(t, before, r.countSent(winproto.SubRDPDeploy))
			}
			assert.Equal(t, w.restores, r.countSent(winproto.SubIISRestore))
			assert.Zero(t, r.countSent(winproto.SubIISDeploy), "the listener is never sent iis-deploy")
		})
	}
}

// W6 Ruling 10 (as the Task 2 ruling carries it): a restore that could not take the NETWORK SERVICE grant back is
// the param rdp_key_acl_left on the restore step (the grant step when the helper never reached a restore), logged
// before the deployment ends.
func TestRDPKeyACLLeftIsReported(t *testing.T) {
	flag := func(r *renv, sub string) {
		inner := r.model.Handler()
		r.record(func(cmd string, stdin []byte) linuxsshtest.Response {
			res := inner(cmd, stdin)
			if s, _, _ := strings.Cut(cmd, " "); s != sub || res.Exit != 0 {
				return res
			}
			var m map[string]any
			require.NoError(t, json.Unmarshal(res.Stdout, &m))
			m["rdp_key_acl_left"] = true
			b, _ := json.Marshal(m)
			return linuxsshtest.Response{Stdout: append(b, '\n')}
		})
	}
	t.Run("the inline rollback", func(t *testing.T) {
		r := newREnv(t)
		r.model.ServeStaleRDP(true)
		flag(r, winproto.SubIISRestore)
		log := &recLog{params: map[string]map[string]string{}}
		out, err := r.open(t).DeployCertificate(context.Background(), r.rdpReq(r.issue()), log)
		providertest.CheckDeployOutcome(t, out, err)
		require.NoError(t, err)
		assert.Equal(t, providers.DeployRolledBack, out.Result)
		assert.Equal(t, "true", log.params["restore"][rdpKeyACLLeftParam])
		assert.Empty(t, log.params["set_listener"][rdpKeyACLLeftParam])
	})
	t.Run("the grant failed and its undo too", func(t *testing.T) {
		r := newREnv(t)
		r.model.FailKeyACL(true)
		flag(r, winproto.SubRDPDeploy)
		log := &recLog{params: map[string]map[string]string{}}
		out, err := r.open(t).DeployCertificate(context.Background(), r.rdpReq(r.issue()), log)
		providertest.CheckDeployOutcome(t, out, err)
		require.NoError(t, err)
		assert.Equal(t, "true", log.params["grant_key_read"][rdpKeyACLLeftParam])
	})
	t.Run("RollbackDeployment", func(t *testing.T) {
		r := newREnv(t)
		s := r.open(t)
		req := r.rdpReq(r.issue())
		req.Verify.Skip = true
		out, err := s.DeployCertificate(context.Background(), req, nil)
		require.NoError(t, err)
		require.Equal(t, providers.DeployCommitted, out.Result)
		flag(r, winproto.SubIISRestore)
		log := &recLog{params: map[string]map[string]string{}}
		rb, err := s.RollbackDeployment(context.Background(), providers.RollbackRequest{OperationID: req.OperationID, Location: r.rloc,
			Verify: providers.VerifyOptions{Skip: true}, Backup: out.Backup}, log)
		providertest.CheckRollbackOutcome(t, rb, err)
		require.NoError(t, err)
		assert.Equal(t, providers.DeployRolledBack, rb.Result)
		assert.Equal(t, "true", log.params["restore"][rdpKeyACLLeftParam])
		assert.Empty(t, r.model.RDPThumbprint(), "the value is deleted again")
	})
	t.Run("a revoke that worked carries nothing", func(t *testing.T) {
		r := newREnv(t)
		r.model.ServeStaleRDP(true)
		log := &recLog{params: map[string]map[string]string{}}
		_, err := r.open(t).DeployCertificate(context.Background(), r.rdpReq(r.issue()), log)
		require.NoError(t, err)
		assert.Empty(t, log.params["restore"][rdpKeyACLLeftParam])
	})
}

// W6 Ruling 8 (WN-24): rdp-deploy's input holds exactly the five members (no locator, no store), it is built in one
// allocation and cleared after the send, and the command line is exactly "rdp-deploy --op <id>".
func TestRDPInputHasNoLocator(t *testing.T) {
	r := newREnv(t)
	var buffers [][]byte
	inputHook = func(b []byte) { buffers = append(buffers, b) }
	t.Cleanup(func() { inputHook = nil })
	req := r.rdpReq(r.issue())
	req.Guard = providers.RollbackGuard{ForbiddenLeaf: []string{strings.Repeat("cd", 32)}}
	req.Verify.Skip = true
	out, err := r.open(t).DeployCertificate(context.Background(), req, nil)
	require.NoError(t, err)
	assert.Equal(t, providers.DeployCommitted, out.Result)
	require.Len(t, buffers, 1)
	assert.Equal(t, make([]byte, len(buffers[0])), buffers[0], "the input buffer is cleared after the send")
	assert.Equal(t, []string{"version", "rdp-deploy --op " + req.OperationID.String()}, r.srv.Commands())

	sent := r.stdinsOf(winproto.SubRDPDeploy)
	require.Len(t, sent, 1)
	var members map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(sent[0], &members))
	keys := make([]string, 0, len(members))
	for k := range members {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	assert.Equal(t, []string{"chain_pem", "expect_sha256", "forbidden_leaf_sha256", "forbidden_spki_sha256", "key_pem"}, keys)
	dec := json.NewDecoder(bytes.NewReader(sent[0]))
	dec.DisallowUnknownFields()
	var in winproto.RDPDeployInput
	require.NoError(t, dec.Decode(&in))
	assert.Equal(t, req.ExpectCertSHA256, in.ExpectSHA256)
	assert.Equal(t, string(req.CertificatePEM), in.ChainPEM)
	assert.Equal(t, []string{}, in.ForbiddenSPKI)
	assert.Equal(t, req.Guard.ForbiddenLeaf, in.ForbiddenLeaf)
	for _, c := range r.srv.Commands() {
		assert.NotContains(t, c, "PRIVATE KEY")
	}

	raw, ok := rdpDeployInput(req.ExpectCertSHA256, req.CertificatePEM, req.PrivateKeyPEM.Bytes(), req.Guard)
	require.True(t, ok)
	assert.Equal(t, cap(raw), len(raw), "one allocation of the final size")
	_, ok = rdpDeployInput(req.ExpectCertSHA256, []byte("é"), req.PrivateKeyPEM.Bytes(), req.Guard)
	assert.False(t, ok, "a chain outside ASCII")
}
