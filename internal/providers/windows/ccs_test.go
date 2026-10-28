package windows

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/providers"
	"alice/internal/providers/linuxssh/linuxsshtest"
	"alice/internal/providers/providertest"
	"alice/internal/providers/windows/winproto"
	"alice/internal/providers/windows/wintest"
	"alice/internal/secrets"
	"alice/internal/testutil/pki"
)

// ccsCred is the platform credential source of a Windows server with a CCS password (providers.CCSPasswordSource);
// pw "" answers as inventory does for a server without one (its ErrNotFound wrapping providers.ErrNoCCSPassword); a
// non-nil err is answered instead (a database failure, an unusable credential).
type ccsCred struct {
	*fakeCred
	pw    string
	err   error
	asked []uuid.UUID
}

func (c *ccsCred) CCSPassword(_ context.Context, target uuid.UUID) (secrets.Plaintext, func(), error) {
	c.asked = append(c.asked, target)
	switch {
	case c.err != nil:
		return secrets.Plaintext{}, nil, c.err
	case c.pw == "":
		return secrets.Plaintext{}, nil, fmt.Errorf("%w: %w", errors.New("inventory: not found"), providers.ErrNoCCSPassword)
	}
	pt := secrets.NewPlaintext([]byte(c.pw))
	return pt, pt.Zero, nil
}

const (
	ccsFolder = `C:\CCS`
	ccsHost   = "ccs.example.test"
	ccsPath   = ccsFolder + `\` + ccsHost + ".pfx"
)

// cenv is wenv's host whose IIS also has the Centralized Certificate Store on at C:\CCS: the file
// ccs.example.test.pfx holds the CCS "old" certificate under the store's password, the http.sys record ccs:443
// and the site "CCS Site" (https *:443:ccs.example.test, sslFlags 3) serve it.
type cenv struct {
	*wenv
	old  pki.Leaf // the CCS file's certificate (wenv's binding keeps its own)
	pw   string
	ccs  *ccsCred
	cloc providers.CertLocation
}

func ccsPassword() string { return "ccs-" + rand.Text() }

func newCEnv(t *testing.T) *cenv { return newCEnvOf(t, nil) }

// newCEnvOf is newCEnv whose CCS file holds old (nil: a certificate issued now).
func newCEnvOf(t *testing.T, old *pki.Leaf) *cenv {
	t.Helper()
	w := newWEnv(t)
	pw := ccsPassword()
	m := w.model
	c := &cenv{wenv: w, pw: pw, ccs: &ccsCred{fakeCred: w.cred, pw: pw}}
	if c.old = c.issue(); old != nil {
		c.old = *old
	}
	m.SetCCS(true, ccsFolder)
	m.SetCCSPassword(pw)
	m.PutCCSFile(ccsHost+".pfx", c.old.Cert, []*x509.Certificate{w.ca.Intermediate}, c.old.Key, pw)
	m.AddBinding(winproto.SSLBinding{Type: winproto.BindingCCS, IP: "0.0.0.0", Port: 443, AppID: winproto.AppIDIIS})
	m.AddSite(winproto.Site{Name: "CCS Site", ID: 3, State: "Started", Bindings: []winproto.SiteBinding{
		{Protocol: "https", Information: "*:443:" + ccsHost, SSLFlags: 3}}})
	c.cloc = providers.CertLocation{Kind: providers.LocationWinCCSFile, CertPath: ccsPath, Supported: true,
		Locator: providers.Locator{"type": winproto.LocatorCCSFile, "path": ccsFolder, "host": ccsHost},
		Servers: []providers.CertServer{{Names: []string{ccsHost}, Listens: []providers.CertListen{{Addr: "*", Port: 443}}, Section: "CCS Site"}},
		Details: map[string]any{"ccs_path": ccsFolder, "file_name": ccsHost + ".pfx"}}
	return c
}

// csession opens a session with the CCS credential source.
func (c *cenv) csession(t *testing.T) *session {
	t.Helper()
	s, err := c.prov.Open(context.Background(), c.ref, c.ccs, providers.Env{})
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })
	return s.(*session)
}

func (c *cenv) issue() pki.Leaf {
	return c.ca.Issue(pki.Opts{CommonName: ccsHost, SANs: []string{ccsHost}}, time.Now())
}

// ccsReq is a deployment of nl to the CCS file, which holds the CCS old certificate now.
func (c *cenv) ccsReq(nl pki.Leaf) providers.DeployRequest {
	return providers.DeployRequest{OperationID: uuid.New(), Location: c.cloc, ExpectCertSHA256: derSHA256(c.old.Cert.Raw),
		CertificatePEM: nl.FullchainPEM, PrivateKeyPEM: providers.NewSecret(append([]byte(nil), nl.KeyPEM...)),
		Fingerprint: derSHA256(nl.Cert.Raw), SANs: []string{ccsHost}, KeyType: "ecdsa", OldFingerprint: derSHA256(c.old.Cert.Raw),
		OldSANs: []string{ccsHost}, ChainLength: 2}
}

// file is the leaf the CCS file holds now ("" when there is none or it does not open).
func (c *cenv) file(t *testing.T) string {
	t.Helper()
	data, ok := c.model.CCSFile(ccsHost + ".pfx")
	if !ok {
		return ""
	}
	leaf, _, _, err := pki.OpenPFXKey(data, []byte(c.pw))
	if err != nil {
		return ""
	}
	return derSHA256(leaf)
}

// ccsServed is the leaf a handshake with SNI www.example.test shows.
func (c *cenv) ccsServed() string {
	s, _, _ := c.model.Served("127.0.0.1", 443, ccsHost)
	return s
}

// backup is the name of the operation's backup in the folder ("" when there is none).
func (c *cenv) backup() string {
	for _, n := range c.model.CCSNames() {
		if strings.HasSuffix(n, ".bak") {
			return n
		}
	}
	return ""
}

// version10 makes the emulated helper answer version 1.0.0 (W4's released helper).
func version10(e *env) {
	inner := e.model.Handler()
	e.srv.SetHandler(func(cmd string, stdin []byte) linuxsshtest.Response {
		if cmd == winproto.SubVersion {
			b, _ := json.Marshal(winproto.VersionResponse{OK: true, Helper: "1.0.0", Protocol: 1})
			return linuxsshtest.Response{Stdout: append(b, '\n')}
		}
		return inner(cmd, stdin)
	})
}

func ccsLocations(certs []providers.DiscoveredCertificate) map[string]providers.DiscoveredCertificate {
	out := map[string]providers.DiscoveredCertificate{}
	for _, c := range certs {
		if c.Location.Kind == providers.LocationWinCCSFile {
			out[c.Location.CertPath] = c
		}
	}
	return out
}

func warningParams(ws []providers.Warning, code string) map[string]string {
	for _, w := range ws {
		if w.Code == code {
			return w.Params
		}
	}
	return nil
}

// Review Focus 5: a 1.0.0 helper is never sent a CCS subcommand. Discovery reads the bindings as in W4 and warns
// win_ccs_helper_outdated; a deployment to a CCS file is refused before anything is sent; a binding still deploys.
func TestCCSNeedsHelper110(t *testing.T) {
	m, err := wintest.Demo(time.Now())
	require.NoError(t, err)
	e := newEnvWith(t, m)
	version10(e)
	cred := &ccsCred{fakeCred: e.cred, pw: m.CCSPassword()}
	sess, err := e.prov.Open(context.Background(), e.ref, cred, providers.Env{})
	require.NoError(t, err)
	res, err := sess.Discover(context.Background(), providers.DiscoverRequest{Certificates: true})
	require.NoError(t, err)
	assert.Equal(t, []string{"version", "iis-dump"}, e.srv.Commands())
	assert.Equal(t, []string{winproto.WarnCCSEnabled, WarnCCSHelperOutdated, winproto.WarnRDPHelperOutdated}, codes(res.Warnings))
	assert.Empty(t, ccsLocations(res.Certificates))
	assert.Len(t, res.Certificates, 4, "the W4 bindings")

	ca := pki.NewCA("Outdated", pki.ECDSA256, time.Now())
	nl := ca.Issue(pki.Opts{CommonName: "ccs.example.test", SANs: []string{"ccs.example.test"}}, time.Now())
	loc := providers.CertLocation{Kind: providers.LocationWinCCSFile, CertPath: `C:\CCS\ccs.example.test.pfx`, Supported: true,
		Locator: providers.Locator{"type": winproto.LocatorCCSFile, "path": `C:\CCS`, "host": "ccs.example.test"}}
	req := providers.DeployRequest{OperationID: uuid.New(), Location: loc, ExpectCertSHA256: strings.Repeat("ab", 32),
		CertificatePEM: nl.FullchainPEM, PrivateKeyPEM: providers.NewSecret(append([]byte(nil), nl.KeyPEM...)), KeyType: "ecdsa"}
	out, derr := sess.DeployCertificate(context.Background(), req, nil)
	providertest.CheckDeployOutcome(t, out, derr)
	pe := providerErr(t, derr)
	assert.Equal(t, ReasonHelperOutdated, pe.Code)
	assert.Equal(t, map[string]string{"helper_version": "1.0.0", "required_version": "1.1.0"}, pe.Params)
	assert.Equal(t, providers.DeployNoChange, out.Result)
	assert.Equal(t, []string{"version", "iis-dump"}, e.srv.Commands(), "nothing sent for the CCS deployment")
	assert.Empty(t, cred.asked, "the password is not even read for a helper that cannot take it")

	// A binding of the same 1.0.0 helper still deploys (W4).
	byP := byPath(res.Certificates)
	web := byP["http.sys/hostnameport/www.win.example.test:443"]
	wl := ca.Issue(pki.Opts{CommonName: "www.win.example.test", SANs: []string{"www.win.example.test"}}, time.Now())
	breq := providers.DeployRequest{OperationID: uuid.New(), Location: web.Location, ExpectCertSHA256: web.FileSHA256,
		CertificatePEM: wl.FullchainPEM, PrivateKeyPEM: providers.NewSecret(append([]byte(nil), wl.KeyPEM...)), KeyType: "ecdsa",
		Verify: providers.VerifyOptions{Skip: true}}
	out, derr = sess.DeployCertificate(context.Background(), breq, nil)
	providertest.CheckDeployOutcome(t, out, derr)
	require.NoError(t, derr)
	assert.Equal(t, providers.DeployCommitted, out.Result)
}

// Review Focus 5: a server without a CCS password (no source, or none set) discovers exactly W4's locations, sends no
// ccs-dump and warns win_ccs_password_missing.
func TestDiscoverWithoutPasswordIsW4(t *testing.T) {
	for _, tc := range []struct {
		name string
		cred func(e *env) providers.CredentialSource
	}{
		{"a source that holds no CCS password", func(e *env) providers.CredentialSource { return e.cred }},
		{"a server whose password was never set", func(e *env) providers.CredentialSource { return &ccsCred{fakeCred: e.cred} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, err := wintest.Demo(time.Now())
			require.NoError(t, err)
			e := newEnvWith(t, m)
			sess, err := e.prov.Open(context.Background(), e.ref, tc.cred(e), providers.Env{})
			require.NoError(t, err)
			res, err := sess.Discover(context.Background(), providers.DiscoverRequest{Certificates: true})
			require.NoError(t, err)
			assert.Equal(t, []string{"version", "iis-dump", "rdp-dump"}, e.srv.Commands())
			assert.Equal(t, []string{winproto.WarnCCSEnabled, WarnCCSPasswordMissing}, codes(res.Warnings))
			var paths []string
			for _, c := range res.Certificates {
				paths = append(paths, c.Location.CertPath)
			}
			assert.Equal(t, []string{"http.sys/ccs/443", "http.sys/hostnameport/www.win.example.test:443", "http.sys/ipport/0.0.0.0:5986",
				"http.sys/ipport/0.0.0.0:8443", winproto.RDPCanonical}, paths)
			assert.Equal(t, UnsupportedCCS, byPath(res.Certificates)["http.sys/ccs/443"].Location.Unsupported, "the old win_ccs reason")
		})
	}
}

// W5 Rulings 5-8, 12 and 18 on the demo host: the linked file has its site as server, the unlinked one warns
// win_ccs_unlinked, an IIS CCS binding without a file is cert_missing, a file the password does not open is
// ccs_password_mismatch with the server warning, and a failed ccs-dump keeps the bindings with locations_dropped.
func TestDiscoverCCSLinks(t *testing.T) {
	now := time.Now()
	m, err := wintest.Demo(now)
	require.NoError(t, err)
	m.AddSite(winproto.Site{Name: "Lost", ID: 4, State: "Started", Bindings: []winproto.SiteBinding{
		{Protocol: "https", Information: "*:443:lost.example.test", SSLFlags: 3}}})
	ca := pki.NewCA("Third party", pki.ECDSA256, now)
	other := ca.Issue(pki.Opts{CommonName: "other.example.test", SANs: []string{"other.example.test"}}, now)
	m.PutCCSFile("other.example.test.pfx", other.Cert, nil, other.Key, ccsPassword())
	m.PutRawCCSFile("not a host.pfx", []byte("x"))
	e := newEnvWith(t, m)
	cred := &ccsCred{fakeCred: e.cred, pw: m.CCSPassword()}
	sess, err := e.prov.Open(context.Background(), e.ref, cred, providers.Env{})
	require.NoError(t, err)
	res, err := sess.Discover(context.Background(), providers.DiscoverRequest{Certificates: true})
	require.NoError(t, err)
	assert.Equal(t, []string{"version", "iis-dump", "ccs-dump", "rdp-dump"}, e.srv.Commands())
	assert.Equal(t, []uuid.UUID{testTarget}, cred.asked, "the provider asks for its own target's password only")
	assert.Equal(t, []string{winproto.WarnCCSEnabled, WarnCCSPasswordMismatch, winproto.WarnCCSFilesIgnored}, codes(res.Warnings))
	assert.Equal(t, map[string]string{"count": "1"}, warningParams(res.Warnings, WarnCCSPasswordMismatch))
	assert.Equal(t, map[string]string{"count": "1"}, warningParams(res.Warnings, winproto.WarnCCSFilesIgnored))
	for _, c := range res.Certificates {
		checkStorable(t, c)
	}
	got := ccsLocations(res.Certificates)
	require.Len(t, got, 4, "%v", got)

	linked := got[`C:\CCS\ccs.example.test.pfx`]
	assert.True(t, linked.Location.Supported, "%+v", linked.Location)
	assert.Equal(t, providers.Locator{"type": "ccs_file", "path": `C:\CCS`, "host": "ccs.example.test"}, linked.Location.Locator)
	assert.Equal(t, []providers.CertServer{{Names: []string{"ccs.example.test"}, Listens: []providers.CertListen{{Addr: "*", Port: 443}},
		Section: "CCS Site"}}, linked.Location.Servers)
	assert.Empty(t, linked.Location.Warnings)
	blocks := pemBlocks(linked.PEMChain)
	require.Len(t, blocks, 2, "leaf and intermediate")
	assert.Equal(t, derSHA256(blocks[0]), linked.FileSHA256, "the token is the leaf's DER SHA-256 (W5 Ruling 13)")
	data, ok := m.CCSFile("ccs.example.test.pfx")
	require.True(t, ok)
	assert.Equal(t, derSHA256(data), linked.Location.Details["file_sha256"], "the bytes' hash is a detail")
	assert.Equal(t, `C:\CCS`, linked.Location.Details["ccs_path"])
	assert.Equal(t, "ccs.example.test.pfx", linked.Location.Details["file_name"])
	assert.EqualValues(t, len(data), linked.Location.Details["file_size"])
	assert.NotEmpty(t, linked.Location.Details["modified_at"])

	unlinked := got[`C:\CCS\_.unlinked.test.pfx`]
	assert.True(t, unlinked.Location.Supported, "an unlinked file is deployable (Ruling 8)")
	assert.Equal(t, "*.unlinked.test", unlinked.Location.Locator["host"])
	assert.Empty(t, unlinked.Location.Servers)
	assert.Equal(t, []string{WarnCCSUnlinked}, unlinked.Location.Warnings)

	lost := got[`C:\CCS\lost.example.test.pfx`]
	assert.False(t, lost.Location.Supported)
	assert.Equal(t, ProblemCertMissing, lost.Location.Problem, "no file is created (Ruling 7)")
	assert.Equal(t, providers.UnsupportedFile, lost.Location.Unsupported)
	assert.Equal(t, "Lost", lost.Location.Servers[0].Section)
	assert.Nil(t, lost.PEMChain)

	mismatch := got[`C:\CCS\other.example.test.pfx`]
	assert.False(t, mismatch.Location.Supported)
	assert.Equal(t, winproto.CCSProblemPasswordMismatch, mismatch.Location.Problem, "never deployed over (Ruling 12)")
	assert.Empty(t, mismatch.FileSHA256)

	// A failed ccs-dump keeps the iis-dump result and marks nothing missing (Ruling 18).
	for _, tc := range []struct {
		name string
		r    linuxsshtest.Response
	}{
		{"an undecodable answer", linuxsshtest.Response{Stdout: []byte("{not json\n")}},
		{"a refusal", refusalResponse(winproto.ExitFailed, winproto.CodeIOError)},
		{"an answer over the output bound (Task 2's concern)", linuxsshtest.Response{Stdout: bytes.Repeat([]byte(" "), winproto.DumpOutput+1)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			inner := m.Handler()
			e.srv.SetHandler(func(cmd string, stdin []byte) linuxsshtest.Response {
				if cmd == winproto.SubCCSDump {
					return tc.r
				}
				return inner(cmd, stdin)
			})
			res, err := sess.Discover(context.Background(), providers.DiscoverRequest{Certificates: true})
			require.NoError(t, err)
			assert.Empty(t, ccsLocations(res.Certificates))
			assert.Len(t, res.Certificates, 5, "the bindings and the RDP listener are kept")
			assert.Equal(t, []string{winproto.WarnCCSEnabled, providers.WarnListTruncated, providers.WarnLocationsDropped}, codes(res.Warnings))
		})
	}

	// A password that could not be read says nothing about the files (fix round 1): no ccs-dump is sent, the bindings
	// are kept and nothing is marked missing; only ErrNoCCSPassword is win_ccs_password_missing.
	e.srv.SetHandler(m.Handler())
	for _, tc := range []struct {
		name string
		pw   string
		err  error
	}{
		{"a database failure", "", errors.New("inventory: read the CCS password: connection refused")},
		{"an unusable credential", "", fmt.Errorf("inventory: cannot be decrypted: %w", providers.ErrCCSPasswordUnusable)},
		{"a password the helper would refuse", "short", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cred.pw, cred.err = tc.pw, tc.err
			t.Cleanup(func() { cred.pw, cred.err = m.CCSPassword(), nil })
			before := len(e.srv.Commands())
			res, err := sess.Discover(context.Background(), providers.DiscoverRequest{Certificates: true})
			require.NoError(t, err)
			assert.Equal(t, []string{"iis-dump", "rdp-dump"}, e.srv.Commands()[before:], "no ccs-dump")
			assert.Empty(t, ccsLocations(res.Certificates))
			assert.Len(t, res.Certificates, 5, "the bindings and the RDP listener are kept")
			assert.Equal(t, []string{winproto.WarnCCSEnabled, providers.WarnListTruncated, providers.WarnLocationsDropped}, codes(res.Warnings))
		})
	}

	// The end of the context during ccs-dump is the discovery's error, not a failed ccs-dump.
	ctx, cancel := context.WithCancel(context.Background())
	inner := m.Handler()
	e.srv.SetHandler(func(cmd string, stdin []byte) linuxsshtest.Response {
		if cmd == winproto.SubCCSDump {
			cancel()
			return linuxsshtest.Response{Delay: 200 * time.Millisecond}
		}
		return inner(cmd, stdin)
	})
	_, err = sess.Discover(ctx, providers.DiscoverRequest{Certificates: true})
	require.Error(t, err)
}

// W5 Ruling 3: a CCS folder Alice does not manage, as iis-dump reads it, gives its server warning and no ccs-dump.
func TestDiscoverCCSFolderNotManaged(t *testing.T) {
	for path, want := range map[string]string{`\\files\ccs`: winproto.WarnCCSRemote, `CCS`: winproto.WarnCCSPathUnsupported} {
		c := newCEnv(t)
		c.model.SetCCS(true, path)
		res, err := c.csession(t).Discover(context.Background(), providers.DiscoverRequest{Certificates: true})
		require.NoError(t, err)
		assert.Contains(t, codes(res.Warnings), want, path)
		assert.Empty(t, ccsLocations(res.Certificates), path)
		assert.Zero(t, c.countSent(winproto.SubCCSDump), path)
		assert.Empty(t, c.ccs.asked, "the password is not read")
	}
}

// Design §8: discovery's ccs-dump and a CCS deployment's ccs-deploy each run on a fresh connection of their own.
func TestEachCCSCallUsesItsOwnConnection(t *testing.T) {
	c := newCEnv(t)
	s := c.csession(t)
	assert.Equal(t, 1, c.srv.Connections())
	c.waitNoOpenConnections(t)
	_, err := s.Discover(context.Background(), providers.DiscoverRequest{Certificates: true})
	require.NoError(t, err, "a reused connection would answer ccs-dump as iis-dump")
	assert.Equal(t, 4, c.srv.Connections())
	req := c.ccsReq(c.issue())
	req.Verify.Skip = true
	out, err := s.DeployCertificate(context.Background(), req, nil)
	require.NoError(t, err, "a reused connection would answer ccs-deploy as version")
	assert.Equal(t, providers.DeployCommitted, out.Result)
	assert.Equal(t, 5, c.srv.Connections(), "one connection per helper call")
	assert.Equal(t, []string{"version", "iis-dump", "ccs-dump", "rdp-dump", "ccs-deploy --op " + req.OperationID.String()}, c.srv.Commands())
	c.waitNoOpenConnections(t)
}

// Review Focus 2: the CCS password reaches the helper on standard input only; the input buffers are cleared after
// the send, and nothing Alice keeps or logs holds it.
func TestCCSPasswordIsNeverOutsideStdin(t *testing.T) {
	c := newCEnv(t)
	var logs bytes.Buffer
	sess, err := c.prov.Open(context.Background(), c.ref, c.ccs, providers.Env{Log: slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))})
	require.NoError(t, err)
	var buffers [][]byte
	inputHook = func(b []byte) { buffers = append(buffers, b) }
	t.Cleanup(func() { inputHook = nil })
	res, derr := sess.Discover(context.Background(), providers.DiscoverRequest{Certificates: true})
	require.NoError(t, derr)
	c.model.ServeStaleCCS(true) // the verification fails and the inline restore runs too
	req := c.ccsReq(c.issue())
	log := &stepLog{}
	out, derr := sess.DeployCertificate(context.Background(), req, log)
	providertest.CheckDeployOutcome(t, out, derr)
	assert.Equal(t, providers.DeployRolledBack, out.Result)

	require.Len(t, buffers, 2, "ccs-dump's and ccs-deploy's inputs")
	for _, b := range buffers {
		assert.NotEmpty(t, b)
		assert.Equal(t, make([]byte, len(b)), b, "the input buffer is cleared after the send")
	}
	for _, cmd := range c.srv.Commands() {
		assert.NotContains(t, cmd, c.pw, "the password is never on a command line")
		assert.Contains(t, []string{"version", "iis-dump", "ccs-dump", "rdp-dump", "ccs-deploy --op " + req.OperationID.String(), "iis-restore --op " + req.OperationID.String(),
			"tls-probe --addr 127.0.0.1 --port 443 --sni ccs.example.test --key-type ecdsa"}, cmd)
	}
	assert.Contains(t, string(c.stdinsOf(winproto.SubCCSDump)[0]), c.pw, "ccs-dump's password is on stdin")
	assert.Contains(t, string(c.stdinsOf(winproto.SubCCSDeploy)[0]), c.pw, "ccs-deploy's password is on stdin")
	assert.NotContains(t, string(c.stdinsOf(winproto.SubIISRestore)[0]), c.pw, "a restore needs no password")
	for _, text := range []string{logs.String(), strings.Join(log.lines(), "\n"), fmt.Sprintf("%+v", out), fmt.Sprint(derr), fmt.Sprintf("%#v", res)} {
		assert.NotContains(t, text, c.pw)
	}
	providertest.CheckNoSecrets(t, []string{c.pw}, out, derr)
	for _, op := range []string{req.OperationID.String()} {
		j, ok := c.model.Journal(op)
		require.True(t, ok)
		assert.NotContains(t, string(j), c.pw)
	}

	// The input is the protocol's JSON, built in one allocation of its final size.
	cl, ok := ccsLocatorOf(c.cloc)
	require.True(t, ok)
	in, ok := ccsDeployInput(cl, req.ExpectCertSHA256, req.CertificatePEM, req.PrivateKeyPEM.Bytes(), []byte(c.pw), req.Guard)
	require.True(t, ok)
	assert.Equal(t, cap(in), len(in))
	var d winproto.CCSDeployInput
	require.NoError(t, json.Unmarshal(in, &d))
	assert.Equal(t, winproto.CCSDeployInput{Path: ccsFolder, Host: ccsHost, ExpectSHA256: req.ExpectCertSHA256, ChainPEM: string(req.CertificatePEM),
		KeyPEM: string(req.PrivateKeyPEM.Bytes()), Password: c.pw, ForbiddenSPKI: []string{}, ForbiddenLeaf: []string{}}, d)
	_, ok = ccsDeployInput(cl, req.ExpectCertSHA256, req.CertificatePEM, req.PrivateKeyPEM.Bytes(), []byte("é"), req.Guard)
	assert.False(t, ok, "a password outside ASCII")
	in, ok = ccsDumpInput([]byte(`a"b\c-0123456789`))
	require.True(t, ok)
	assert.Equal(t, cap(in), len(in))
	var di winproto.CCSDumpInput
	require.NoError(t, json.Unmarshal(in, &di))
	assert.Equal(t, `a"b\c-0123456789`, di.Password)
	for _, bad := range []string{"short", strings.Repeat("ä", winproto.MinCCSPassword), "with a space in it"} {
		_, ok = ccsDumpInput([]byte(bad))
		assert.False(t, ok, "a password the helper would refuse is not sent: %q", bad)
	}
}

// Fix round 1: a deployment's refusal when the password could not be read, by the source's error.
func TestCCSPasswordRefusal(t *testing.T) {
	ctx := context.Background()
	done, cancel := context.WithCancel(ctx)
	cancel()
	for _, tc := range []struct {
		ctx       context.Context
		err       error
		code      string
		retryable bool
	}{
		{ctx, fmt.Errorf("inventory: not found: %w", providers.ErrNoCCSPassword), ReasonCCSPasswordMissing, false},
		{done, context.Canceled, "ssh.timeout", true},
		{ctx, providers.ErrCCSPasswordUnusable, reasonUnexpected, false},
		{ctx, errors.New("connection refused"), ReasonIOError, true},
	} {
		e := ccsPasswordRefusal(tc.ctx, tc.err)
		assert.Equal(t, tc.code, e.Code, "%v", tc.err)
		assert.Equal(t, tc.retryable, e.Retryable, "%v", tc.err)
	}
}

// The shape table of a CCS deployment (W5 Ruling 14; mirror of TestDeployOutcomeTable): one row per refusal code of
// ccs-deploy with its reason, and committed, unchanged, the helper's own restore, the inline rollback (to the backup,
// forbidden, the backup gone) and uncertain. Every return passes providers.CheckDeployReturn.
func TestCCSDeployOutcomeTable(t *testing.T) {
	type want struct {
		result                    providers.DeployResult
		phase, failed, cause, cls string
		verified                  string
		steps                     []string
		reason                    string
		errCode                   string
		retryable                 bool
		file                      string // "old", "new" or "" (not checked)
		noDeploySent              bool
		restores                  int
	}
	refused := func(reason string, retryable bool) want {
		return want{result: providers.DeployNoChange, reason: reason, errCode: reason, retryable: retryable, file: "old"}
	}
	notSent := func(reason string) want {
		return want{result: providers.DeployNoChange, reason: reason, errCode: reason, file: "old", noDeploySent: true}
	}
	written := []string{"import_chain:ok", "write_file:ok"}
	for _, tc := range []struct {
		name  string
		setup func(t *testing.T, c *cenv, nl pki.Leaf, r *providers.DeployRequest)
		want  want
	}{
		{"committed, level 3", func(_ *testing.T, c *cenv, _ pki.Leaf, r *providers.DeployRequest) {
			r.Trust = &providers.TrustPolicy{Roots: rootPool(c.ca), Store: providers.TrustStoreSystem, Enforce: true}
		}, want{result: providers.DeployCommitted, phase: "committed", verified: "remote", steps: append(written, "verify:ok"), file: "new"}},
		{"unchanged: the file holds the certificate and chain already", func(_ *testing.T, c *cenv, nl pki.Leaf, r *providers.DeployRequest) {
			c.model.PutCCSFile(ccsHost+".pfx", nl.Cert, []*x509.Certificate{c.ca.Intermediate}, nl.Key, c.pw)
			r.ExpectCertSHA256 = r.Fingerprint
		}, want{result: providers.DeployUnchanged, phase: "unchanged", verified: "remote", steps: []string{"verify:ok"}, file: "new"}},
		{"CCS_DISABLED", func(_ *testing.T, c *cenv, _ pki.Leaf, _ *providers.DeployRequest) { c.model.SetCCS(false, ccsFolder) },
			refused(ReasonCCSDisabled, false)},
		{"CCS_PATH_CHANGED", func(_ *testing.T, c *cenv, _ pki.Leaf, _ *providers.DeployRequest) { c.model.SetCCS(true, `D:\Other`) },
			want{result: providers.DeployNoChange, reason: ReasonCCSPathChanged, errCode: ReasonCCSPathChanged}},
		{"CCS_PATH_UNSUPPORTED: the folder became a reparse point", func(_ *testing.T, c *cenv, _ pki.Leaf, _ *providers.DeployRequest) {
			c.model.SetCCSReparse(ccsFolder, true)
		}, refused(ReasonLocationUnsupported, false)},
		{"CCS_PASSWORD_MISMATCH: Alice's password does not open the file", func(_ *testing.T, c *cenv, _ pki.Leaf, _ *providers.DeployRequest) {
			c.ccs.pw = ccsPassword()
		}, refused(ReasonCCSPasswordMismatch, false)},
		{"CCS_FILE_NOT_FOUND", func(_ *testing.T, c *cenv, _ pki.Leaf, r *providers.DeployRequest) {
			r.Location.Locator = providers.Locator{"type": winproto.LocatorCCSFile, "path": ccsFolder, "host": "gone.example.test"}
		}, refused(ReasonCCSFileNotFound, false)},
		{"HASH_MISMATCH: the file holds another certificate than the token", func(_ *testing.T, _ *cenv, _ pki.Leaf, r *providers.DeployRequest) {
			r.ExpectCertSHA256 = strings.Repeat("ab", 32)
		}, refused(ReasonBindingChanged, true)},
		{"no password: refused before sending", func(_ *testing.T, c *cenv, _ pki.Leaf, _ *providers.DeployRequest) { c.ccs.pw = "" },
			notSent(ReasonCCSPasswordMissing)},
		{"a password that is not ASCII: refused before sending", func(_ *testing.T, c *cenv, _ pki.Leaf, _ *providers.DeployRequest) {
			c.ccs.pw = strings.Repeat("ä", winproto.MinCCSPassword)
		}, notSent(reasonInvalidCertificate)},
		{"the password could not be read (the database): retryable, refused before sending", func(_ *testing.T, c *cenv, _ pki.Leaf, _ *providers.DeployRequest) {
			c.ccs.err = errors.New("inventory: read the CCS password: connection refused")
		}, want{result: providers.DeployNoChange, reason: ReasonIOError, errCode: ReasonIOError, retryable: true, file: "old", noDeploySent: true}},
		{"the stored password is unusable: final, refused before sending", func(_ *testing.T, c *cenv, _ pki.Leaf, _ *providers.DeployRequest) {
			c.ccs.err = fmt.Errorf("inventory: the credential belongs to another target: %w", providers.ErrCCSPasswordUnusable)
		}, notSent(reasonUnexpected)},
		{"a locator Alice does not deploy to", func(_ *testing.T, _ *cenv, _ pki.Leaf, r *providers.DeployRequest) {
			r.Location.Locator = providers.Locator{"type": winproto.LocatorCCSFile, "path": `\\files\ccs`, "host": ccsHost}
		}, notSent(ReasonLocationUnsupported)},

		{"restored by the helper: the replace failed", func(_ *testing.T, c *cenv, _ pki.Leaf, _ *providers.DeployRequest) { c.model.FailReplace(true) },
			want{result: providers.DeployRolledBack, phase: "restored", failed: "write_file", cause: "write_file", cls: "io_error", verified: "remote",
				steps: []string{"import_chain:ok", "write_file:failed", "verify_old:ok"}, reason: ReasonIOError, file: "old"}},
		{"verification failed: the backup is restored", func(_ *testing.T, c *cenv, _ pki.Leaf, _ *providers.DeployRequest) { c.model.ServeStaleCCS(true) },
			want{result: providers.DeployRolledBack, phase: "restored", failed: "verify", cause: "verify", verified: "remote",
				steps: append(written, "verify:failed", "restore:ok", "verify_old:ok"), reason: "deployment.verify_failed", file: "old", restores: 1}},
		{"the ccs record refresh failed: IIS keeps the old file, the probe fails, the backup is restored", func(_ *testing.T, c *cenv, _ pki.Leaf, _ *providers.DeployRequest) {
			c.model.FailCCSRefresh(true)
		}, want{result: providers.DeployRolledBack, phase: "restored", failed: "verify", cause: "verify", verified: "remote",
			steps: append(written, "verify:failed", "restore:ok", "verify_old:ok"), reason: "deployment.verify_failed", file: "old", restores: 1}},
		{"verification failed, the backup gone: rollback_failed, nothing written", func(t *testing.T, c *cenv, _ pki.Leaf, _ *providers.DeployRequest) {
			c.model.ServeStaleCCS(true)
			inner := c.model.Handler()
			c.record(func(cmd string, stdin []byte) linuxsshtest.Response {
				if strings.HasPrefix(cmd, winproto.SubIISRestore) {
					require.NoError(t, c.model.Host().RemoveCCS(context.Background(), ccsFolder, c.backup()))
				}
				return inner(cmd, stdin)
			})
		}, want{result: providers.DeployRollbackFailed, failed: "restore", cause: "verify", cls: "backup_missing",
			steps: append(written, "verify:failed"), reason: ReasonBackupMissing, file: "new", restores: 1}},
		{"verification failed, the previous certificate compromised: forbidden", func(_ *testing.T, c *cenv, _ pki.Leaf, r *providers.DeployRequest) {
			c.model.ServeStaleCCS(true)
			r.RecheckGuard = func(context.Context) (providers.RollbackGuard, error) {
				return providers.RollbackGuard{Required: true, ForbiddenLeaf: []string{derSHA256(c.old.Cert.Raw)}}, nil
			}
		}, want{result: providers.DeployRollbackFailed, phase: "restore_forbidden", failed: "restore", cause: "verify", cls: "forbidden",
			steps: append(written, "verify:failed", "restore:failed"), reason: providers.ReasonRollbackForbidden, file: "new", restores: 1}},
		{"OUTCOME_UNKNOWN: uncertain", func(_ *testing.T, c *cenv, _ pki.Leaf, _ *providers.DeployRequest) {
			c.script(winproto.SubCCSDeploy, func([]byte) linuxsshtest.Response {
				return refusalResponse(winproto.ExitFailed, winproto.CodeOutcomeUnknown)
			})
		}, want{result: providers.DeployUncertain, errCode: "ssh.protocol_error", file: "old"}},
		{"an answer naming a store: uncertain", func(_ *testing.T, c *cenv, nl pki.Leaf, r *providers.DeployRequest) {
			c.script(winproto.SubCCSDeploy, func([]byte) linuxsshtest.Response {
				return deployResponse(winproto.DeployResponse{Phase: winproto.PhaseCommitted, NewSHA1: sha1Hex(nl.Cert.Raw), NewSHA256: r.Fingerprint,
					PreviousSHA1: c.oldSHA1, PreviousSHA256: r.ExpectCertSHA256, Store: "My", Steps: []winproto.Step{}})
			})
		}, want{result: providers.DeployUncertain, errCode: "ssh.protocol_error", file: "old"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := newCEnv(t)
			nl := c.issue()
			req := c.ccsReq(nl)
			tc.setup(t, c, nl, &req)
			s := c.csession(t)
			log := &stepLog{}
			out, err := s.DeployCertificate(context.Background(), req, log)
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
			assert.Equal(t, providers.BackupRef{OperationID: req.OperationID, PreviousSHA256: req.ExpectCertSHA256}, out.Backup,
				"a CCS file's backup is the journal's (W5 Ruling 21)")
			switch w.file {
			case "old":
				assert.Equal(t, derSHA256(c.old.Cert.Raw), c.file(t))
			case "new":
				assert.Equal(t, req.Fingerprint, c.file(t))
			}
			if w.noDeploySent {
				assert.Zero(t, c.countSent(winproto.SubCCSDeploy))
			}
			assert.Equal(t, w.restores, c.countSent(winproto.SubIISRestore))
			assert.Zero(t, c.countSent(winproto.SubIISDeploy), "a CCS file is never sent iis-deploy")
		})
	}
}

// recLog keeps the params of each step's final status, by step name.
type recLog struct{ params map[string]map[string]string }

func (r *recLog) Step(name string, status providers.StepStatus, params map[string]string) {
	if status != providers.StepStarted {
		r.params[name] = params
	}
}

// F15 route (a): a failed refresh of the http.sys ccs records after the replace or the restore is the param
// ccs_refresh_failed on the write_file or the restore step; it decides nothing by itself (the verification does).
func TestCCSRefreshFailedIsReported(t *testing.T) {
	t.Run("deploy and inline rollback", func(t *testing.T) {
		c := newCEnv(t)
		c.model.FailCCSRefresh(true)
		log := &recLog{params: map[string]map[string]string{}}
		out, err := c.csession(t).DeployCertificate(context.Background(), c.ccsReq(c.issue()), log)
		providertest.CheckDeployOutcome(t, out, err)
		require.NoError(t, err)
		assert.Equal(t, providers.DeployRolledBack, out.Result)
		assert.Equal(t, "true", log.params["write_file"][ccsRefreshFailedParam])
		assert.Equal(t, "true", log.params["restore"][ccsRefreshFailedParam])
		assert.Empty(t, log.params["import_chain"][ccsRefreshFailedParam])
	})
	t.Run("a committed file, then a rollback", func(t *testing.T) {
		c := newCEnv(t)
		s := c.csession(t)
		req := c.ccsReq(c.issue())
		req.Verify.Skip = true
		c.model.FailCCSRefresh(true)
		log := &recLog{params: map[string]map[string]string{}}
		out, err := s.DeployCertificate(context.Background(), req, log)
		providertest.CheckDeployOutcome(t, out, err)
		require.NoError(t, err)
		assert.Equal(t, providers.DeployCommitted, out.Result, "a failed refresh never rolls back by itself")
		assert.Equal(t, "true", log.params["write_file"][ccsRefreshFailedParam])
		log = &recLog{params: map[string]map[string]string{}}
		rb, err := s.RollbackDeployment(context.Background(), providers.RollbackRequest{OperationID: req.OperationID, Location: c.cloc,
			Verify: providers.VerifyOptions{Skip: true}, Backup: out.Backup}, log)
		providertest.CheckRollbackOutcome(t, rb, err)
		require.NoError(t, err)
		assert.Equal(t, providers.DeployRolledBack, rb.Result)
		assert.Equal(t, "true", log.params["restore"][ccsRefreshFailedParam])
	})
	t.Run("a refresh that worked carries nothing", func(t *testing.T) {
		c := newCEnv(t)
		log := &recLog{params: map[string]map[string]string{}}
		out, err := c.csession(t).DeployCertificate(context.Background(), c.ccsReq(c.issue()), log)
		require.NoError(t, err)
		assert.Equal(t, providers.DeployCommitted, out.Result)
		assert.Empty(t, log.params["write_file"][ccsRefreshFailedParam])
	})
}

// A CCS rollback goes through iis-restore on the CCS journal (W5 Ruling 15): restored to the backup's bytes, and
// refused with nothing written once the backup is gone (pruned after 7 days) or the folder became a reparse point.
func TestCCSRollbackDeployment(t *testing.T) {
	commit := func(t *testing.T) (*cenv, *session, providers.RollbackRequest) {
		c := newCEnv(t)
		s := c.csession(t)
		req := c.ccsReq(c.issue())
		req.Verify.Skip = true
		out, err := s.DeployCertificate(context.Background(), req, nil)
		require.NoError(t, err)
		require.Equal(t, providers.DeployCommitted, out.Result)
		return c, s, providers.RollbackRequest{OperationID: req.OperationID, Location: c.cloc, OldFingerprint: derSHA256(c.old.Cert.Raw),
			OldSANs: []string{ccsHost}, KeyType: "ecdsa", Backup: out.Backup}
	}
	t.Run("restored", func(t *testing.T) {
		c, s, rr := commit(t)
		out, err := s.RollbackDeployment(context.Background(), rr, nil)
		providertest.CheckRollbackOutcome(t, out, err)
		require.NoError(t, err)
		assert.Equal(t, providers.DeployRolledBack, out.Result)
		assert.Equal(t, "remote", out.Verified)
		assert.Equal(t, derSHA256(c.old.Cert.Raw), c.file(t))
		assert.Equal(t, derSHA256(c.old.Cert.Raw), c.ccsServed())
		st, err := s.DeploymentStatus(context.Background(), rr.OperationID)
		require.NoError(t, err)
		assert.Equal(t, providers.PhaseRestored, st.Phase)
	})
	t.Run("the backup pruned: BACKUP_MISSING, the file untouched", func(t *testing.T) {
		c, s, rr := commit(t)
		require.NoError(t, c.model.Host().RemoveCCS(context.Background(), ccsFolder, c.backup()))
		out, err := s.RollbackDeployment(context.Background(), rr, nil)
		providertest.CheckRollbackOutcome(t, out, err)
		require.NoError(t, err)
		assert.Equal(t, providers.DeployRollbackFailed, out.Result)
		assert.Equal(t, ReasonBackupMissing, out.Reason)
		assert.Equal(t, winproto.ErrBackupMissing, out.Error)
		assert.Equal(t, map[string]string{}, out.Params, "no store or thumbprint names a CCS file's backup")
		assert.NotEqual(t, derSHA256(c.old.Cert.Raw), c.file(t), "nothing written")
	})
	t.Run("the folder became a reparse point: refused", func(t *testing.T) {
		c, s, rr := commit(t)
		c.model.SetCCSReparse(ccsFolder, true)
		out, err := s.RollbackDeployment(context.Background(), rr, nil)
		providertest.CheckRollbackOutcome(t, out, err)
		assert.Equal(t, providers.DeployNoChange, out.Result)
		assert.Equal(t, ReasonLocationUnsupported, providerErr(t, err).Code)
	})
}

// ccsDump is a ccs-dump answer of the folder C:\CCS.
func ccsDump(files ...winproto.CCSFile) winproto.CCSDumpResponse {
	return winproto.CCSDumpResponse{OK: true, Enabled: true, Local: true, Path: ccsFolder, Files: files}
}

func ccsFileOf(name string, l pki.Leaf, chain ...*x509.Certificate) winproto.CCSFile {
	f := winproto.CCSFile{Name: name, FileSHA256: strings.Repeat("cd", 32), ModifiedAt: "2026-10-27T09:00:00Z", Size: 1234,
		LeafDER: base64.StdEncoding.EncodeToString(l.Cert.Raw), Chain: []string{}}
	for _, c := range chain {
		f.Chain = append(f.Chain, base64.StdEncoding.EncodeToString(c.Raw))
	}
	return f
}

func ccsSite(name, info string, flags int) winproto.Site {
	return winproto.Site{Name: name, Bindings: []winproto.SiteBinding{{Protocol: "https", Information: info, SSLFlags: flags}}}
}

// W5 Rulings 5-8, 12 and 18 on hand-made answers: the file problems, the links (F17's order), the names Alice
// ignores, the bounds and the folder warnings.
func TestConvertCCS(t *testing.T) {
	f := newDump(t)
	leaf := func(cn string) pki.Leaf { return f.ca.Issue(pki.Opts{CommonName: cn, SANs: []string{cn}}, f.now) }
	www, wild := leaf("www.example.test"), leaf("*.example.test")
	f.d.Sites = []winproto.Site{
		ccsSite("Web", "*:443:WWW.example.test", 3),
		ccsSite("Admin", "*:9443:www.example.test", 3),
		ccsSite("Admin", "*:9443:www.example.test", 3), // the same binding twice: one server
		ccsSite("Shop", "10.0.0.5:8443:shop.example.test", 2),
		ccsSite("Deep", "*:443:a.b.example.test", 3), // W5-13: _.example.test.pfx serves a.b.example.test too
		ccsSite("Apex", "*:443:example.test", 3),     // but never its own parent
		ccsSite("Plain", "*:443:plain.example.test", 1),
		ccsSite("NoHost", "*:443:", 2),
	}
	bad := ccsFileOf("not-a-cert.example.test.pfx", www)
	bad.LeafDER = "!!"
	long := ccsFileOf("long.example.test.pfx", www)
	long.Chain = make([]string, winproto.MaxChainCerts+1)
	broken := ccsFileOf("broken.example.test.pfx", www, f.ca.Intermediate)
	broken.Chain = append(broken.Chain, "!!")
	odd := ccsFileOf("odd.example.test.pfx", www)
	odd.FileSHA256, odd.ModifiedAt, odd.Size = "nothex", "yesterday", -5
	c := ccsDump(ccsFileOf("www.example.test.pfx", www, f.ca.Intermediate), ccsFileOf("_.example.test.pfx", wild),
		winproto.CCSFile{Name: "mismatch.example.test.pfx", Problem: winproto.CCSProblemPasswordMismatch},
		winproto.CCSFile{Name: "notpfx.example.test.pfx", Problem: winproto.CCSProblemNotPFX},
		winproto.CCSFile{Name: "nokey.example.test.pfx", Problem: winproto.CCSProblemNoKey},
		winproto.CCSFile{Name: "big.example.test.pfx", Problem: winproto.CCSProblemTooLarge},
		winproto.CCSFile{Name: "strange.example.test.pfx", Problem: "melted"},
		bad, long, broken, odd,
		ccsFileOf("not a host.pfx", www))
	c.Ignored = 2
	certs, warns := convertCCS(f.d, c)
	for _, dc := range certs {
		checkStorable(t, dc)
	}
	got := byPath(certs)
	assert.Equal(t, []string{WarnCCSPasswordMismatch, winproto.WarnCCSFilesIgnored}, codes(warns))
	assert.Equal(t, map[string]string{"count": "3"}, warningParams(warns, winproto.WarnCCSFilesIgnored))
	assert.Equal(t, map[string]string{"count": "1"}, warningParams(warns, WarnCCSPasswordMismatch))

	w := got[`C:\CCS\www.example.test.pfx`]
	assert.True(t, w.Location.Supported)
	assert.Equal(t, []providers.CertServer{{Names: []string{"www.example.test"}, Listens: []providers.CertListen{{Addr: "*", Port: 9443}}, Section: "Admin"},
		{Names: []string{"www.example.test"}, Listens: []providers.CertListen{{Addr: "*", Port: 443}}, Section: "Web"}},
		w.Location.Servers, "the exact file first, sorted by site")
	assert.Len(t, pemBlocks(w.PEMChain), 2)
	assert.Equal(t, derSHA256(www.Cert.Raw), w.FileSHA256)

	wl := got[`C:\CCS\_.example.test.pfx`]
	assert.Equal(t, "*.example.test", wl.Location.Locator["host"])
	assert.Equal(t, []providers.CertServer{
		{Names: []string{"a.b.example.test"}, Listens: []providers.CertListen{{Addr: "*", Port: 443}}, Section: "Deep"},
		{Names: []string{"shop.example.test"}, Listens: []providers.CertListen{{Addr: "10.0.0.5", Port: 8443}}, Section: "Shop"}},
		wl.Location.Servers, "the wildcard file serves a suffix at any depth (W5-13)")
	assert.NotContains(t, got, `C:\CCS\a.b.example.test.pfx`, "linked: no cert_missing location")
	assert.Equal(t, ProblemCertMissing, got[`C:\CCS\example.test.pfx`].Location.Problem, "the wildcard's own parent: no file serves it")

	for path, want := range map[string]string{
		`C:\CCS\mismatch.example.test.pfx`:   winproto.CCSProblemPasswordMismatch,
		`C:\CCS\notpfx.example.test.pfx`:     providers.CertProblemNotACertificate,
		`C:\CCS\big.example.test.pfx`:        providers.CertProblemTooLarge,
		`C:\CCS\strange.example.test.pfx`:    providers.CertProblemUnknown,
		`C:\CCS\not-a-cert.example.test.pfx`: providers.CertProblemNotACertificate,
		`C:\CCS\long.example.test.pfx`:       providers.CertProblemTooLarge,
	} {
		l := got[path].Location
		assert.Equal(t, want, l.Problem, path)
		assert.False(t, l.Supported, path)
		assert.Equal(t, providers.UnsupportedFile, l.Unsupported, path)
		assert.Nil(t, got[path].PEMChain, path)
		assert.Equal(t, []string{WarnCCSUnlinked}, l.Warnings, path)
	}
	nokey := got[`C:\CCS\nokey.example.test.pfx`].Location
	assert.Equal(t, ProblemKeyMissing, nokey.KeyProblem)
	assert.False(t, nokey.Supported)
	assert.Equal(t, []string{WarnCCSUnlinked, providers.WarnCertificateBlockDropped}, got[`C:\CCS\broken.example.test.pfx`].Location.Warnings)
	assert.Len(t, pemBlocks(got[`C:\CCS\broken.example.test.pfx`].PEMChain), 2)
	assert.Equal(t, map[string]any{"ccs_path": ccsFolder, "file_name": "odd.example.test.pfx", "file_sha256": "", "file_size": int64(0), "modified_at": ""},
		got[`C:\CCS\odd.example.test.pfx`].Location.Details)
	assert.Len(t, certs, 12, "www, the wildcard, 9 files with a problem or odd details and a.b missing; the host-less name left out")
	for _, dc := range certs {
		assert.NotEqual(t, "plain.example.test", dc.Location.Locator["host"], "an SNI binding without CCS links to no file")
	}

	// A truncated folder proves no missing file: the cert_missing locations are left out (W2 Ruling 18).
	c = ccsDump(ccsFileOf("www.example.test.pfx", www))
	c.Truncated = true
	certs, warns = convertCCS(f.d, c)
	assert.Len(t, certs, 1)
	assert.Equal(t, []string{providers.WarnListTruncated, providers.WarnLocationsDropped}, codes(warns))
	// So does a file Alice leaves out: the same host twice.
	certs, warns = convertCCS(f.d, ccsDump(ccsFileOf("www.example.test.pfx", www), ccsFileOf("WWW.EXAMPLE.TEST.pfx", www)))
	assert.Len(t, certs, 1)
	assert.Equal(t, []string{providers.WarnListTruncated, providers.WarnLocationsDropped}, codes(warns))

	// The folder: turned off between the calls, remote, unsupported or a reparse point.
	for _, tc := range []struct {
		name string
		c    winproto.CCSDumpResponse
		want []string
	}{
		{"disabled", winproto.CCSDumpResponse{OK: true}, []string{}},
		{"a UNC folder", winproto.CCSDumpResponse{OK: true, Enabled: true, Path: `\\files\ccs`}, []string{winproto.WarnCCSRemote}},
		{"a device path", winproto.CCSDumpResponse{OK: true, Enabled: true, Path: `\\?\C:\CCS`}, []string{winproto.WarnCCSPathUnsupported}},
		{"a reparse-point folder", winproto.CCSDumpResponse{OK: true, Enabled: true, Path: ccsFolder}, []string{winproto.WarnCCSPathUnsupported}},
		{"local but not a path Alice manages", winproto.CCSDumpResponse{OK: true, Enabled: true, Local: true, Path: `C:\..\x`}, []string{winproto.WarnCCSPathUnsupported}},
	} {
		certs, warns := convertCCS(f.d, tc.c)
		assert.Empty(t, certs, tc.name)
		assert.Equal(t, tc.want, codes(warns), tc.name)
	}

	// More files than MaxCCSFiles: the rest is dropped.
	many := ccsDump()
	for i := range winproto.MaxCCSFiles + 1 {
		many.Files = append(many.Files, winproto.CCSFile{Name: fmt.Sprintf("h%d.example.test.pfx", i), Problem: winproto.CCSProblemNotPFX})
	}
	certs, warns = convertCCS(winproto.IISDumpResponse{}, many)
	assert.Len(t, certs, winproto.MaxCCSFiles)
	assert.Equal(t, []string{providers.WarnListTruncated, providers.WarnLocationsDropped}, codes(warns))
}

// Final review I1 (Review Focus 3, WN-21): an https binding convertCCS cannot read may be a CCS binding of any file, so
// a file whose only binding is unreadable is not proven unlinked: every file location is cut (list_truncated, never
// win_ccs_unlinked) and the server warnings say locations_dropped; a binding read without a file stays cert_missing (the
// file list is whole). The verification of such a location probes (no endpoint known: unreachable, the house rule)
// instead of answering skipped.
func TestConvertCCSUnreadableBindingIsNotUnlinked(t *testing.T) {
	f := newDump(t)
	www := f.ca.Issue(pki.Opts{CommonName: "www.example.test", SANs: []string{"www.example.test"}}, f.now)
	f.d.Sites = []winproto.Site{ccsSite("Bad", "*:x:www.example.test", 3), ccsSite("Gone", "*:443:gone.example.test", 3)}
	certs, warns := convertCCS(f.d, ccsDump(ccsFileOf("www.example.test.pfx", www)))
	got := byPath(certs)
	require.Len(t, certs, 2)
	assert.Equal(t, ProblemCertMissing, got[`C:\CCS\gone.example.test.pfx`].Location.Problem, "the file list is whole: missing is proven")
	loc := got[`C:\CCS\www.example.test.pfx`].Location
	assert.Empty(t, loc.Servers)
	assert.Equal(t, []string{providers.WarnListTruncated}, loc.Warnings, "cut, not win_ccs_unlinked")
	assert.Equal(t, []string{providers.WarnListTruncated, providers.WarnLocationsDropped}, codes(warns))
	assert.False(t, unlinkedCCS(loc), "a cut location is never read-back only")

	// The helper's own cut of the iis-dump (truncated, or the list_truncated warning): the same, and no cert_missing.
	for _, cut := range []func(d *winproto.IISDumpResponse){
		func(d *winproto.IISDumpResponse) { d.Truncated = true },
		func(d *winproto.IISDumpResponse) { d.Warnings = []string{winproto.WarnListTruncated} },
	} {
		d := newDump(t).d
		d.Sites = []winproto.Site{ccsSite("Gone", "*:443:gone.example.test", 3)}
		cut(&d)
		certs, warns := convertCCS(d, ccsDump(ccsFileOf("www.example.test.pfx", www)))
		require.Len(t, certs, 1, "no cert_missing location under the helper's cut")
		assert.Equal(t, []string{providers.WarnListTruncated}, certs[0].Location.Warnings, "cut, not win_ccs_unlinked")
		assert.Equal(t, []string{providers.WarnListTruncated, providers.WarnLocationsDropped}, codes(warns))
		assert.False(t, unlinkedCCS(certs[0].Location))
	}

	c := newCEnv(t)
	c.cloc.Servers, c.cloc.Warnings = []providers.CertServer{}, []string{providers.WarnListTruncated}
	vr, err := c.csession(t).VerifyDeployment(context.Background(), providers.VerifyRequest{Location: c.cloc, Fingerprint: derSHA256(c.old.Cert.Raw)})
	require.NoError(t, err)
	assert.False(t, vr.OK, "no skip: the probe has no endpoint")
	assert.Equal(t, reasonVerifyUnreachable, vr.Reason)
	assert.Empty(t, vr.Params[ccsUnlinkedParam])
}

// Final review M1 (F17 measured: an explicit http.sys hostnameport record for host:port wins over CCS): a CCS binding
// that such a record shadows is not linked to its file, and the file's location says win_ccs_shadowed, so a deployment
// to it never probes a host IIS serves from the hostnameport record (it would roll back every time). A shadowed
// binding without a file is no cert_missing location either.
func TestConvertCCSHostnamePortShadows(t *testing.T) {
	f := newDump(t)
	leaf := func(cn string) pki.Leaf { return f.ca.Issue(pki.Opts{CommonName: cn, SANs: []string{cn}}, f.now) }
	www, shop := leaf("www.example.test"), leaf("shop.example.test")
	f.d.Bindings = []winproto.SSLBinding{
		{Type: winproto.BindingHostnamePort, Host: "WWW.example.test", Port: 443, AppID: winproto.AppIDIIS},
		{Type: winproto.BindingHostnamePort, Host: "shop.example.test", Port: 443, AppID: winproto.AppIDIIS},
		{Type: winproto.BindingHostnamePort, Host: "gone.example.test", Port: 443, AppID: winproto.AppIDIIS},
	}
	f.d.Sites = []winproto.Site{
		ccsSite("Web", "*:443:www.example.test", 3),
		ccsSite("Admin", "*:9443:www.example.test", 3), // another port: not shadowed
		ccsSite("Shop", "*:443:shop.example.test", 3),
		ccsSite("Gone", "*:443:gone.example.test", 3),
	}
	certs, warns := convertCCS(f.d, ccsDump(ccsFileOf("www.example.test.pfx", www), ccsFileOf("shop.example.test.pfx", shop)))
	assert.Empty(t, codes(warns))
	got := byPath(certs)
	require.Len(t, certs, 2, "no cert_missing location for the shadowed gone.example.test")
	w := got[`C:\CCS\www.example.test.pfx`].Location
	assert.Equal(t, []providers.CertServer{{Names: []string{"www.example.test"}, Listens: []providers.CertListen{{Addr: "*", Port: 9443}}, Section: "Admin"}},
		w.Servers, "the shadowed binding on 443 is not linked")
	assert.Equal(t, []string{WarnCCSShadowed}, w.Warnings)
	s := got[`C:\CCS\shop.example.test.pfx`].Location
	assert.Empty(t, s.Servers)
	assert.Equal(t, []string{WarnCCSUnlinked, WarnCCSShadowed}, s.Warnings, "no binding left: read-back only")
	assert.True(t, unlinkedCCS(s))
}

// F17 (Ruling 6 as amended by ruling W5-13): the file IIS serves a host from: the exact file, then the nearest
// wildcard file of a suffix at any depth that keeps two labels, never the wildcard's own parent.
func TestCCSFileFor(t *testing.T) {
	files := map[string]bool{"www.example.test": true, "*.example.test": true, "*.b.example.test": true, "a.b.example.test": true}
	has := func(h string) bool { return files[h] }
	for host, want := range map[string]string{
		"www.example.test":   "www.example.test",
		"shop.example.test":  "*.example.test",
		"a.b.example.test":   "a.b.example.test", // the exact file wins over every wildcard
		"x.b.example.test":   "*.b.example.test", // the nearest wildcard first
		"x.c.example.test":   "*.example.test",   // two labels down
		"x.y.c.example.test": "*.example.test",   // three
		"b.example.test":     "*.example.test",
		"example.test":       "", // the wildcard's own parent
		"test":               "",
		"*.example.test":     "*.example.test",
		"x.other.test":       "",
		"localhost":          "",
	} {
		got, ok := ccsFileFor(host, has)
		assert.Equal(t, want, got, host)
		assert.Equal(t, want != "", ok, host)
	}
}

// The F18 and F15 hook points: a CCS file's served chain is compared with the PFX's own chain (the helper builds
// none), a binding's with the chain Windows built; a pickup wait stretches a CCS file's verification attempts.
func TestCCSChainAndPickupHooks(t *testing.T) {
	for _, tc := range []struct {
		kind            providers.LocationKind
		deployed, built int
		compare         int
		extra           map[string]string
	}{
		{providers.LocationWinCCSFile, 2, 0, 2, nil},
		{providers.LocationWinCCSFile, 2, 3, 2, nil},
		{providers.LocationWinSSLBinding, 2, 3, 3, map[string]string{"chain_differs": "true", "deployed_chain": "2", "built_chain": "3"}},
		{providers.LocationWinSSLBinding, 2, 2, 2, nil},
		{providers.LocationWinSSLBinding, 2, 0, 2, nil},
	} {
		compare, extra := comparedChain(tc.kind, tc.deployed, tc.built)
		assert.Equal(t, tc.compare, compare, "%+v", tc)
		assert.Equal(t, tc.extra, extra, "%+v", tc)
	}
	assert.Equal(t, 5, pickupAttempts(0, 5, 2*time.Second), "no pickup wait: W2's attempts")
	assert.Equal(t, 31, pickupAttempts(time.Minute, 5, 2*time.Second), "the attempts span the wait")
	assert.Equal(t, 5, pickupAttempts(time.Second, 5, 2*time.Second), "never fewer than W2's")
}
