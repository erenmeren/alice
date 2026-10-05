package linuxssh

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

	"alice/internal/i18n"
	"alice/internal/platform/clock"
	"alice/internal/providers"
	"alice/internal/providers/linuxssh/helperproto"
	"alice/internal/providers/linuxssh/linuxsshtest"
	"alice/internal/providers/providertest"
	"alice/internal/testutil/pki"
	"alice/locales"
)

const (
	rootFile   = "/root/.ssh/authorized_keys"
	deployFile = "/home/deploy/.ssh/authorized_keys"
	aliceFile  = "/var/lib/alice-svc/.ssh/authorized_keys"
)

// absentFiles are the default second AuthorizedKeysFile of every user; they do not exist, so a
// discovery reads them completely (no keys).
var absentFiles = []string{rootFile + "2", deployFile + "2", aliceFile + "2"}

// provEnv is a provider wired to a fake SSH server answering like alice-helper.
type provEnv struct {
	srv  *linuxsshtest.Server
	emu  *linuxsshtest.Emulator
	cred *fakeCred
	hk   *memHostKeys
	pool *Pool
	prov *Provider
	ref  providers.TargetRef
}

func newProvEnv(t *testing.T) *provEnv {
	t.Helper()
	emu := linuxsshtest.NewEmulator()
	srv := linuxsshtest.NewServer(t, emu.Handler())
	cred := newFakeCred(t)
	srv.Authorize(cred.signer.PublicKey())
	hk := &memHostKeys{}
	hk.pin(srv.HostKey())
	pool := NewPool(&Dialer{Clock: clock.Real{}, HostKeys: hk}, MaxConnections, MaxConnectionsPerTarget, IdleTimeout)
	t.Cleanup(pool.Close)
	host, port := srv.Addr()
	return &provEnv{
		srv: srv, emu: emu, cred: cred, hk: hk, pool: pool, prov: New(Options{Pool: pool, AllowUnverifiedHelper: true}),
		ref: providers.TargetRef{ID: testTarget, Name: "web-01", Kind: providers.KindLinuxSSH,
			Config: providers.TargetConfig{"host": host, "port": port, "username": "alice-svc"}},
	}
}

func (e *provEnv) open(t *testing.T) providers.Session {
	t.Helper()
	s, err := e.prov.Open(context.Background(), e.ref, e.cred, providers.Env{Clock: clock.Real{}, HostKeys: e.hk})
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// keyLine returns an authorized_keys line for a fresh key ("ed25519" or "rsa1024") and its fingerprint.
func keyLine(t testing.TB, kind, options, comment string) (string, string) {
	t.Helper()
	var pub ssh.PublicKey
	switch kind {
	case "ed25519":
		p, _, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)
		pub, err = ssh.NewPublicKey(p)
		require.NoError(t, err)
	case "rsa1024":
		k, err := rsa.GenerateKey(rand.Reader, 1024)
		require.NoError(t, err)
		pub, err = ssh.NewPublicKey(&k.PublicKey)
		require.NoError(t, err)
	default:
		t.Fatalf("unknown key kind %q", kind)
	}
	line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub))) + " " + comment
	if options != "" {
		line = options + " " + line
	}
	return line, ssh.FingerprintSHA256(pub)
}

func hasWarning(ws []providers.Warning, code, path string) bool {
	for _, w := range ws {
		if w.Code == code && (path == "" || w.Params["path"] == path) {
			return true
		}
	}
	return false
}

func TestProviderDescribesItself(t *testing.T) {
	e := newProvEnv(t)
	p := e.prov
	assert.Equal(t, providers.KindLinuxSSH, p.Kind())
	assert.Equal(t, "provider.linuxssh.name", p.DisplayNameKey())
	assert.Equal(t, []providers.Capability{providers.CapAuthorizedKeys, providers.CapDiscoverSSHKeys, providers.CapKeyLogin, providers.CapTestConnection}, p.Capabilities().Sorted())
	assert.Empty(t, p.CredentialSchema().Fields, "targets use the platform key; no per-target secret")
	path, protocol := p.HelperInfo()
	assert.Equal(t, helperproto.HelperPath, path)
	assert.Equal(t, helperproto.Protocol, protocol)
	providertest.CheckProvider(t, p)
}

// Spec §6.5 item 5: the shared conformance suite against the provider over a real SSH session.
// The private key is the secret that must never appear in any result or error.
func TestProviderConformance(t *testing.T) {
	e := newProvEnv(t)
	k, _ := keyLine(t, "ed25519", "", "deploy@laptop")
	e.emu.SetFile(deployFile, []byte(k+"\n"))
	providertest.CheckSession(t, providertest.SessionHarness{
		Capabilities: e.prov.Capabilities(),
		Open: func(ctx context.Context) (providers.Session, error) {
			return e.prov.Open(ctx, e.ref, e.cred, providers.Env{})
		},
		Secrets: secretsOf(t, e.cred),
	})
}

// secretsOf renders the credential's private key the ways it could leak.
func secretsOf(t *testing.T, c *fakeCred) []string {
	t.Helper()
	block, err := ssh.MarshalPrivateKey(c.priv, "")
	require.NoError(t, err)
	seed := c.priv.Seed()
	return []string{
		string(pem.EncodeToMemory(block)),
		base64.StdEncoding.EncodeToString(block.Bytes)[:64],
		base64.StdEncoding.EncodeToString(seed),
		hex.EncodeToString(seed),
		string(seed),
	}
}

// canaryCred fails to hand out its key with an error that carries a secret.
type canaryCred struct{ canary string }

func (c canaryCred) SSHSigner(context.Context) (ssh.Signer, func(), error) {
	return nil, nil, errors.New("decrypt failed for key " + c.canary)
}

// A secret in a credential error never reaches the error's message, JSON or log line.
func TestCredentialErrorsDoNotLeakSecrets(t *testing.T) {
	e := newProvEnv(t)
	const canary = "CANARY-PRIVATE-KEY-0b6d1c"
	_, err := e.prov.Open(context.Background(), e.ref, canaryCred{canary: canary}, providers.Env{})
	assert.Equal(t, "internal.unexpected", providerCode(t, err).Code)
	providertest.CheckNoSecrets(t, []string{canary}, err)
}

func TestSchemaTextsAreTranslated(t *testing.T) {
	cat, err := i18n.Load(locales.FS)
	require.NoError(t, err)
	p := New(Options{})
	keys := []string{p.DisplayNameKey()}
	for _, f := range p.ConfigSchema().Fields {
		keys = append(keys, f.LabelKey, f.HelpKey)
	}
	for _, lang := range []string{"en", "tr"} {
		for _, k := range keys {
			assert.NotEqual(t, k, cat.T(lang, k, nil), "missing %s in %s", k, lang)
		}
	}
}

func TestValidateConfig(t *testing.T) {
	p := newProvEnv(t).prov
	assert.Empty(t, p.ValidateConfig(providers.TargetConfig{"host": "web-01", "port": 22, "username": "alice-svc"}))
	errs := p.ValidateConfig(providers.TargetConfig{"port": 70000})
	fields := []string{}
	for _, e := range errs {
		fields = append(fields, e.Field)
	}
	assert.ElementsMatch(t, []string{"host", "port"}, fields)
}

func TestSetupSnippetsForBothProfiles(t *testing.T) {
	p := newProvEnv(t).prov
	line := AuthorizedKeysLine("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGVtdWxhdGVk alice-platform", "")
	snips := p.SetupSnippets(line)
	require.Len(t, snips, 2)
	for _, profile := range []string{"linux", "nginx"} {
		s := snips[profile]
		assert.Equal(t, profile, s.Profile)
		want, err := Sudoers(profile)
		require.NoError(t, err)
		assert.Equal(t, want, s.Sudoers)
		script, err := SetupScript(profile, line, true)
		require.NoError(t, err)
		assert.Equal(t, script, s.Script)
	}
}

func TestTestConnectionReport(t *testing.T) {
	e := newProvEnv(t)
	s := e.open(t)
	rep, err := s.TestConnection(context.Background())
	require.NoError(t, err)
	assert.Equal(t, ssh.FingerprintSHA256(e.srv.HostKey()), rep.HostKey.Fingerprint)
	assert.Equal(t, helperproto.Version, rep.HelperVersion)
	assert.Equal(t, helperproto.Protocol, rep.HelperProtocol)
	assert.Equal(t, providers.OSRelease{ID: "ubuntu", VersionID: "22.04", PrettyName: "Ubuntu 22.04.4 LTS"}, rep.OS)
	assert.Empty(t, rep.Warnings)
	assert.Equal(t, []string{
		"/usr/local/libexec/alice-helper version",
		"cat /etc/os-release",
		"sudo -n /usr/local/libexec/alice-helper sshd-dump",
	}, e.srv.Commands())
}

func TestTestConnectionWarnsWhenSSHDCannotBeRead(t *testing.T) {
	e := newProvEnv(t)
	e.emu.SetSSHD("")
	rep, err := e.open(t).TestConnection(context.Background())
	require.NoError(t, err)
	assert.True(t, hasWarning(rep.Warnings, "sshd_unreadable", ""))
}

// A-4 (R37 item 21): Env.FreshConnection (the explicit connection test) dials a new connection
// although an idle one exists; without it the idle connection is reused.
func TestOpenWithFreshConnectionDials(t *testing.T) {
	e := newProvEnv(t)
	ctx := context.Background()
	env := providers.Env{Clock: clock.Real{}, HostKeys: e.hk}
	s1, err := e.prov.Open(ctx, e.ref, e.cred, env)
	require.NoError(t, err)
	c1 := connOf(t, s1)
	require.NoError(t, s1.Close())
	dials := e.srv.Connections()

	s2, err := e.prov.Open(ctx, e.ref, e.cred, env)
	require.NoError(t, err)
	assert.Same(t, c1, connOf(t, s2), "reused without FreshConnection")
	require.NoError(t, s2.Close())
	assert.Equal(t, dials, e.srv.Connections())

	env.FreshConnection = true
	s3, err := e.prov.Open(ctx, e.ref, e.cred, env)
	require.NoError(t, err)
	defer func() { _ = s3.Close() }()
	assert.NotSame(t, c1, connOf(t, s3))
	assert.Equal(t, dials+1, e.srv.Connections())
}

// A-16: the provider forgets a deleted target's pooled connections.
func TestProviderForgetsADeletedTarget(t *testing.T) {
	e := newProvEnv(t)
	s := e.open(t)
	c := connOf(t, s)
	require.NoError(t, s.Close())
	require.True(t, c.Healthy(), "kept idle")
	var cc providers.ConnectionCache = e.prov
	cc.ForgetTarget(testTarget)
	assert.False(t, c.Healthy())
}

func TestOpenHelperMissing(t *testing.T) {
	e := newProvEnv(t)
	e.emu.SetHelperMissing(true)
	_, err := e.prov.Open(context.Background(), e.ref, e.cred, providers.Env{})
	assert.Equal(t, "ssh.helper_missing", providerCode(t, err).Code)
}

func TestOpenHelperOutdated(t *testing.T) {
	e := newProvEnv(t)
	// 1 answers without an owner; 2 has no --content-sha256; 3 refuses incomplete content only; 4 has
	// no nginx-fence (an interrupted deployment could never be fenced, AUD-05); 5 skips accounts with
	// a dot or a capital in their name without a word and calls the list complete (AUD-03).
	for _, old := range []int{0, 1, 2, 3, 4, 5} {
		e.emu.SetProtocol(old)
		_, err := e.prov.Open(context.Background(), e.ref, e.cred, providers.Env{})
		pe := providerCode(t, err)
		assert.Equal(t, "ssh.helper_outdated", pe.Code)
		assert.Equal(t, strconv.Itoa(old), pe.Params["helper_protocol"])
		assert.Equal(t, "6", pe.Params["required_protocol"])
	}
}

func TestOpenRefusesAnInvalidStoredConfig(t *testing.T) {
	e := newProvEnv(t)
	e.ref.Config = providers.TargetConfig{"host": ""}
	_, err := e.prov.Open(context.Background(), e.ref, e.cred, providers.Env{})
	assert.Equal(t, "target.invalid_config", providerCode(t, err).Code)
	assert.Empty(t, e.srv.Commands(), "nothing connects")
}

func TestDiscoverListsKeysWithUsersAndFlags(t *testing.T) {
	e := newProvEnv(t)
	rootFrom, rootFromFP := keyLine(t, "ed25519", `from="10.0.0.0/8"`, "root@bastion")
	rootBare, rootBareFP := keyLine(t, "ed25519", "", "root@laptop")
	deployKey, deployFP := keyLine(t, "ed25519", "", "deploy@laptop")
	weak, weakFP := keyLine(t, "rsa1024", "", "ci@old")
	platform := "no-agent-forwarding " + strings.TrimSpace(string(ssh.MarshalAuthorizedKey(e.cred.signer.PublicKey()))) + " alice-platform"
	e.emu.SetFile(rootFile, []byte(rootFrom+"\n"+rootBare+"\n"))
	e.emu.SetFile(deployFile, []byte("# deploy keys\n"+deployKey+"\n"+weak+"\n"+deployKey+"\nthis is not a key\n"))
	e.emu.SetFile(aliceFile, []byte(platform+"\n"))

	res, err := e.open(t).Discover(context.Background(), providers.DiscoverRequest{SSHKeys: true})
	require.NoError(t, err)

	assert.False(t, res.Partial)
	assert.ElementsMatch(t, append([]string{rootFile, deployFile, aliceFile}, absentFiles...), res.ReadFiles)
	assert.True(t, res.SSHD.Read)
	assert.False(t, res.SSHD.KeysManagedElsewhere)
	assert.Equal(t, []string{".ssh/authorized_keys", ".ssh/authorized_keys2"}, res.SSHD.AuthorizedKeysFile)
	require.Len(t, res.HostKeys, 1)
	assert.Equal(t, "ssh-ed25519", res.HostKeys[0].KeyType)

	type found struct {
		user, path string
		line       int
		fp         string
	}
	var got []found
	byLine := map[found]providers.DiscoveredSSHKey{}
	for _, k := range res.SSHKeys {
		f := found{k.OSUser, k.FilePath, k.LineNo, k.Fingerprint}
		got = append(got, f)
		byLine[f] = k
	}
	platformFP := ssh.FingerprintSHA256(e.cred.signer.PublicKey())
	want := []found{
		{"root", rootFile, 1, rootFromFP},
		{"root", rootFile, 2, rootBareFP},
		{"deploy", deployFile, 2, deployFP},
		{"deploy", deployFile, 3, weakFP},
		{"deploy", deployFile, 4, deployFP},
		{"alice-svc", aliceFile, 1, platformFP},
	}
	assert.ElementsMatch(t, want, got)
	assert.NotContains(t, byLine[want[0]].Flags, providers.FlagRootWithoutFrom)
	assert.Equal(t, `from="10.0.0.0/8"`, byLine[want[0]].Options)
	assert.Contains(t, byLine[want[1]].Flags, providers.FlagRootWithoutFrom)
	assert.Contains(t, byLine[want[2]].Flags, providers.FlagDuplicate)
	assert.Contains(t, byLine[want[3]].Flags, providers.FlagWeak)
	assert.Equal(t, 1024, byLine[want[3]].Bits)
	assert.Equal(t, "ci@old", byLine[want[3]].Comment)
	assert.Contains(t, byLine[want[4]].Flags, providers.FlagDuplicate)

	assert.Equal(t, []providers.UnreadableLine{{OSUser: "deploy", FilePath: deployFile, LineNo: 5}}, res.UnreadableLines)
	assert.True(t, hasWarning(res.Warnings, "unreadable_line", deployFile))
	for _, w := range res.Warnings {
		if w.Code == "unreadable_line" {
			assert.Equal(t, "1", w.Params["count"])
		}
	}
}

func TestDiscoverReportsKeyFiles(t *testing.T) {
	e := newProvEnv(t)
	res, err := e.open(t).Discover(context.Background(), providers.DiscoverRequest{SSHKeys: true})
	require.NoError(t, err)
	want := []providers.UserKeyFiles{
		{OSUser: "root", Files: []string{"/root/.ssh/authorized_keys", "/root/.ssh/authorized_keys2"}},
		{OSUser: "alice-svc", Files: []string{"/var/lib/alice-svc/.ssh/authorized_keys", "/var/lib/alice-svc/.ssh/authorized_keys2"}},
		{OSUser: "deploy", Files: []string{"/home/deploy/.ssh/authorized_keys", "/home/deploy/.ssh/authorized_keys2"}},
	}
	assert.Equal(t, want, res.KeyFiles, "the connection account is included, in the helper's order")

	res, err = e.open(t).Discover(context.Background(), providers.DiscoverRequest{})
	require.NoError(t, err)
	assert.Nil(t, res.KeyFiles, "the SSH half was not asked for")

	// nine candidate files: the first eight are kept
	f := newProvEnv(t)
	var pats []string
	for i := 1; i <= 9; i++ {
		pats = append(pats, "/etc/ssh/k"+strconv.Itoa(i)+"/%u")
	}
	f.emu.SetSSHD(strings.Replace(linuxsshtest.DefaultSSHD, "authorizedkeysfile .ssh/authorized_keys .ssh/authorized_keys2",
		"authorizedkeysfile "+strings.Join(pats, " "), 1))
	res, err = f.open(t).Discover(context.Background(), providers.DiscoverRequest{SSHKeys: true})
	require.NoError(t, err)
	require.NotEmpty(t, res.KeyFiles)
	assert.Len(t, res.KeyFiles[0].Files, 8)
	assert.Equal(t, "/etc/ssh/k8/root", res.KeyFiles[0].Files[7])

	// an account whose sshd settings could not be read is left out: its files may be wrong
	g := newProvEnv(t)
	g.emu.SetUserSSHD("deploy", "")
	res, err = g.open(t).Discover(context.Background(), providers.DiscoverRequest{SSHKeys: true})
	require.NoError(t, err)
	for _, u := range res.KeyFiles {
		assert.NotEqual(t, "deploy", u.OSUser)
	}
	assert.Len(t, res.KeyFiles, 2)

	// at most 200 users
	h := newProvEnv(t)
	for i := 0; i < 210; i++ {
		h.emu.AddUser("u"+strconv.Itoa(i), 2000+i, "/home/u"+strconv.Itoa(i))
	}
	h.emu.SetMaxUsers(250)
	res, err = h.open(t).Discover(context.Background(), providers.DiscoverRequest{SSHKeys: true})
	require.NoError(t, err)
	assert.LessOrEqual(t, len(res.KeyFiles), 200)
}

func TestDiscoverWithoutKeysReadsOnlyHostAndSSHD(t *testing.T) {
	e := newProvEnv(t)
	e.emu.SetFile(rootFile, []byte("x\n"))
	res, err := e.open(t).Discover(context.Background(), providers.DiscoverRequest{SSHKeys: false})
	require.NoError(t, err)
	assert.Empty(t, res.SSHKeys)
	for _, c := range e.srv.Commands() {
		assert.NotContains(t, c, "authkeys", "no key file is read")
	}
}

// F-35: with AuthorizedKeysCommand the file keys are still listed, but the host is marked as
// managed elsewhere.
func TestDiscoverDetectsAuthorizedKeysCommand(t *testing.T) {
	e := newProvEnv(t)
	e.emu.SetSSHD(strings.Replace(linuxsshtest.DefaultSSHD, "authorizedkeyscommand none",
		"authorizedkeyscommand /usr/bin/sss_ssh_authorizedkeys", 1))
	k, _ := keyLine(t, "ed25519", "", "deploy@laptop")
	e.emu.SetFile(deployFile, []byte(k+"\n"))
	res, err := e.open(t).Discover(context.Background(), providers.DiscoverRequest{SSHKeys: true})
	require.NoError(t, err)
	assert.True(t, res.SSHD.KeysManagedElsewhere)
	assert.Equal(t, "/usr/bin/sss_ssh_authorizedkeys", res.SSHD.AuthorizedKeysCommand)
	assert.True(t, hasWarning(res.Warnings, "keys_managed_elsewhere", ""))
	assert.Len(t, res.SSHKeys, 1)
}

func TestDiscoverReportsCertificatesAndDisabledPubkey(t *testing.T) {
	e := newProvEnv(t)
	cfg := strings.Replace(linuxsshtest.DefaultSSHD, "pubkeyauthentication yes", "pubkeyauthentication no", 1) +
		"trustedusercakeys /etc/ssh/ca.pub\n"
	e.emu.SetSSHD(cfg)
	res, err := e.open(t).Discover(context.Background(), providers.DiscoverRequest{SSHKeys: true})
	require.NoError(t, err)
	assert.True(t, res.SSHD.CertificatesInUse)
	assert.True(t, hasWarning(res.Warnings, "certificates_in_use", ""))
	assert.True(t, hasWarning(res.Warnings, "pubkey_disabled", ""))
}

func TestDiscoverIsPartialWhenAFileCannotBeRead(t *testing.T) {
	e := newProvEnv(t)
	rk, rootFP := keyLine(t, "ed25519", `from="10.0.0.0/8"`, "root@bastion")
	dk, _ := keyLine(t, "ed25519", "", "deploy@laptop")
	e.emu.SetFile(rootFile, []byte(rk+"\n"))
	e.emu.SetFile(deployFile, []byte(dk+"\n"))
	e.emu.FailRead(deployFile)
	res, err := e.open(t).Discover(context.Background(), providers.DiscoverRequest{SSHKeys: true})
	require.NoError(t, err)
	assert.True(t, res.Partial)
	assert.True(t, hasWarning(res.Warnings, "file_unreadable", deployFile))
	assert.ElementsMatch(t, append([]string{rootFile, aliceFile}, absentFiles...), res.ReadFiles,
		"the unreadable file is not read; the others (aliceFile does not exist) are")
	require.Len(t, res.SSHKeys, 1)
	assert.Equal(t, rootFP, res.SSHKeys[0].Fingerprint)
}

func TestDiscoverFallsBackToDefaultsWhenSSHDFails(t *testing.T) {
	e := newProvEnv(t)
	e.emu.SetSSHD("")
	k, _ := keyLine(t, "ed25519", "", "deploy@laptop")
	e.emu.SetFile("/home/deploy/.ssh/authorized_keys2", []byte(k+"\n"))
	res, err := e.open(t).Discover(context.Background(), providers.DiscoverRequest{SSHKeys: true})
	require.NoError(t, err)
	assert.False(t, res.SSHD.Read)
	assert.Equal(t, "none", res.SSHD.AuthorizedKeysCommand)
	assert.True(t, hasWarning(res.Warnings, "sshd_unreadable", ""))
	require.Len(t, res.SSHKeys, 1)
	assert.Equal(t, "/home/deploy/.ssh/authorized_keys2", res.SSHKeys[0].FilePath)
}

// D13: a file the helper refuses (hard link, foreign owner, leaving its directory) is reported with
// its user and path and never read; an oversized file is reported and not read; a pattern whose
// expansion the helper refuses only adds the helper's unnamed warning; a user with a home outside
// the helper vocabulary is never listed (AUD-03: it is reported by uid instead).
func TestDiscoverSkipsUnsupportedAndOversizedFiles(t *testing.T) {
	e := newProvEnv(t)
	e.emu.SetSSHD(strings.Replace(linuxsshtest.DefaultSSHD, "authorizedkeysfile .ssh/authorized_keys .ssh/authorized_keys2",
		"authorizedkeysfile .ssh/authorized_keys .ssh/authorized_keys2 .ssh/clé", 1))
	e.emu.AddUser("cagla", 1002, "/home/çağla")
	k, _ := keyLine(t, "ed25519", "", "cagla@laptop")
	e.emu.SetFile("/home/çağla/.ssh/authorized_keys", []byte(k+"\n"))
	rk, _ := keyLine(t, "ed25519", `from="10.0.0.0/8"`, "root@bastion")
	e.emu.SetFile(rootFile, []byte(rk+"\n"))
	e.emu.SetUnsupported(rootFile)
	e.emu.SetFile(deployFile, bytes.Repeat([]byte("#"), helperproto.MaxAuthorizedKeysSize+1))
	res, err := e.open(t).Discover(context.Background(), providers.DiscoverRequest{SSHKeys: true})
	require.NoError(t, err)

	var named, unnamed int
	for _, w := range res.Warnings {
		if w.Code != "unsupported_path" {
			continue
		}
		if w.Params["path"] == "" {
			unnamed++
			continue
		}
		named++
		assert.Equal(t, map[string]string{"user": "root", "path": rootFile}, w.Params)
	}
	assert.Equal(t, 1, named, "the refused file is named with its user")
	assert.Equal(t, 1, unnamed, "the refused expansion is the helper's global warning")
	assert.True(t, hasWarning(res.Warnings, "file_too_large", deployFile))
	assert.Empty(t, res.SSHKeys)
	assert.False(t, res.Partial, "skipped files are reported, not a failed scan")
	assert.Contains(t, res.Warnings, providers.Warning{Code: helperproto.WarnAccountHomeUnsupported, Params: map[string]string{"uid": "1002"}})
	assert.NotContains(t, res.ReadFiles, rootFile)
	assert.NotContains(t, res.ReadFiles, deployFile)
	for _, c := range e.srv.Commands() {
		assert.NotContains(t, c, "çağla", "an unsupported path never reaches a command line")
		assert.NotContains(t, c, "authkeys-read '"+deployFile+"'", "an oversized file is not read")
		assert.NotContains(t, c, "authkeys-read '"+rootFile+"'", "a refused file is not read")
	}
}

// Per-user sshd results (Match blocks): a user whose "sshd -T -C" failed and a user whose keys
// also come from an AuthorizedKeysCommand are named in warnings; the host-level summary stays.
func TestDiscoverReportsPerUserSSHDProblems(t *testing.T) {
	e := newProvEnv(t)
	e.emu.SetUserSSHD("deploy", "")
	e.emu.SetUserSSHD("root", strings.Replace(linuxsshtest.DefaultSSHD, "authorizedkeyscommand none",
		"authorizedkeyscommand /usr/bin/sss_ssh_authorizedkeys", 1))
	dk, _ := keyLine(t, "ed25519", "", "deploy@laptop")
	e.emu.SetFile(deployFile, []byte(dk+"\n"))
	res, err := e.open(t).Discover(context.Background(), providers.DiscoverRequest{SSHKeys: true})
	require.NoError(t, err)
	assert.True(t, res.SSHD.Read)
	assert.False(t, res.SSHD.KeysManagedElsewhere, "only root's keys come from a program")
	assert.Contains(t, res.Warnings, providers.Warning{Code: "sshd_unreadable", Params: map[string]string{"user": "deploy"}})
	assert.Contains(t, res.Warnings, providers.Warning{Code: "keys_managed_elsewhere", Params: map[string]string{"user": "root"}})
	n := 0
	for _, w := range res.Warnings {
		if w.Code == "sshd_unreadable" {
			n++
		}
	}
	assert.Equal(t, 1, n, "the helper's global sshd_unreadable is not repeated")
	assert.Len(t, res.SSHKeys, 1, "the files of both users are still listed")
}

// A discovery cancelled between files fails as a whole: it is never a partial success.
func TestDiscoverFailsWhenCancelledMidway(t *testing.T) {
	e := newProvEnv(t)
	for _, f := range []string{rootFile, deployFile, aliceFile} {
		k, _ := keyLine(t, "ed25519", `from="10.0.0.0/8"`, "x@y")
		e.emu.SetFile(f, []byte(k+"\n"))
		e.emu.FailRead(f) // AUD-22: not inlined, so the discovery reads it (and is cancelled there)
	}
	s := e.open(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	inner := e.emu.Handler()
	e.srv.SetHandler(func(cmd string, stdin []byte) linuxsshtest.Response {
		if strings.Contains(cmd, "authkeys-read") {
			cancel()
			return linuxsshtest.Response{Delay: 10 * time.Second}
		}
		return inner(cmd, stdin)
	})
	start := time.Now()
	_, err := s.Discover(ctx, providers.DiscoverRequest{SSHKeys: true})
	assert.Less(t, time.Since(start), 5*time.Second)
	pe := providerCode(t, err)
	assert.Equal(t, "ssh.timeout", pe.Code)
	assert.ErrorIs(t, err, context.Canceled)
}

// The emulator answers write refusals like the helper, and each helper code maps to its reason.
func TestHelperWriteRefusalsMapToReasons(t *testing.T) {
	e := newProvEnv(t)
	e.emu.SetUserSSHD("deploy", "")
	e.emu.SetUserSSHD("root", strings.Replace(linuxsshtest.DefaultSSHD, "authorizedkeyscommand none",
		"authorizedkeyscommand /usr/bin/sss_ssh_authorizedkeys", 1))
	e.emu.SetFile(aliceFile, []byte("x\n"))
	e.emu.SetUnsupported(aliceFile)
	conn, rel, err := e.pool.Acquire(context.Background(), testTarget, Config{Host: e.ref.Config["host"].(string),
		Port: e.ref.Config["port"].(int), Username: "alice-svc"}, e.cred)
	require.NoError(t, err)
	defer rel(true)
	for _, tc := range []struct {
		path, expect, reason, helper string
	}{
		{deployFile, helperproto.AbsentSHA256, "ssh.helper_refused", helperproto.CodeSSHDFailed},
		{rootFile, helperproto.AbsentSHA256, "ssh.keys_managed_elsewhere", helperproto.CodeAuthorizedKeysCommand},
		{aliceFile, helperproto.AbsentSHA256, "ssh.helper_refused", helperproto.CodeUnsafeFile},
		{"/etc/shadow", helperproto.AbsentSHA256, "ssh.helper_refused", helperproto.CodePathNotAllowed},
	} {
		cmd, err := CmdAuthKeysWrite(tc.path, tc.expect, testOp, []byte("k\n"))
		require.NoError(t, err)
		_, err = runHelper[helperproto.AuthKeysWriteResponse](context.Background(), conn, cmd)
		pe := providerCode(t, err)
		assert.Equal(t, tc.reason, pe.Code, tc.path)
		assert.Equal(t, tc.helper, pe.Params["helper_code"], tc.path)
	}
	assert.Empty(t, e.emu.Writes())
}

func TestDiscoverWarnsAboutStrictModes(t *testing.T) {
	e := newProvEnv(t)
	k, _ := keyLine(t, "ed25519", `from="10.0.0.0/8"`, "root@bastion")
	e.emu.SetFile(rootFile, []byte(k+"\n"))
	e.emu.SetInsecure(rootFile)
	res, err := e.open(t).Discover(context.Background(), providers.DiscoverRequest{SSHKeys: true})
	require.NoError(t, err)
	assert.True(t, hasWarning(res.Warnings, "strict_modes", rootFile))
	assert.Len(t, res.SSHKeys, 1, "the file is still read and listed")
}

// ListAuthorizedKeys belongs to the authorized_keys capability and equals discovery.
func TestListAuthorizedKeysEqualsDiscovery(t *testing.T) {
	e := newProvEnv(t)
	k, fp := keyLine(t, "ed25519", "", "deploy@laptop")
	e.emu.SetFile(deployFile, []byte(k+"\n"))
	keys, err := e.open(t).ListAuthorizedKeys(context.Background())
	require.NoError(t, err)
	require.Len(t, keys, 1)
	assert.Equal(t, fp, keys[0].Fingerprint)
}

func TestSessionCloseReturnsTheConnection(t *testing.T) {
	e := newProvEnv(t)
	s, err := e.prov.Open(context.Background(), e.ref, e.cred, providers.Env{})
	require.NoError(t, err)
	attempts := e.srv.AuthAttempts()
	require.NoError(t, s.Close())
	require.NoError(t, s.Close(), "closing twice is harmless")
	s2, err := e.prov.Open(context.Background(), e.ref, e.cred, providers.Env{})
	require.NoError(t, err)
	defer func() { _ = s2.Close() }()
	assert.Equal(t, attempts, e.srv.AuthAttempts(), "the idle connection was reused")
}

// A closed session runs nothing: its connection may already serve another session.
func TestSessionMethodsAfterCloseFail(t *testing.T) {
	e := newProvEnv(t)
	s, err := e.prov.Open(context.Background(), e.ref, e.cred, providers.Env{})
	require.NoError(t, err)
	require.NoError(t, s.Close())
	n := len(e.srv.Commands())
	_, err = s.TestConnection(context.Background())
	assert.Equal(t, "ssh.unreachable", providerCode(t, err).Code)
	_, err = s.Discover(context.Background(), providers.DiscoverRequest{SSHKeys: true})
	assert.Equal(t, "ssh.unreachable", providerCode(t, err).Code)
	assert.Len(t, e.srv.Commands(), n, "nothing ran")
}

func TestFileWarningSeparatesSizeFromParseFailures(t *testing.T) {
	assert.Equal(t, "file_too_large", fileWarning(ErrAuthorizedKeysTooLarge))
	assert.Equal(t, "file_too_large", fileWarning(fmt.Errorf("wrapped: %w", ErrAuthorizedKeysTooLarge)))
	assert.Equal(t, "file_unparseable", fileWarning(errors.New("something else")))
}

var errNoKey = errors.New("no platform key")

type sentinelCred struct{}

func (sentinelCred) SSHSigner(context.Context) (ssh.Signer, func(), error) {
	return nil, nil, fmt.Errorf("vault /secret/CANARY-path: %w", errNoKey)
}

// The credential error's text is hidden, but callers can still recognise it.
func TestCredentialErrorKeepsErrorsIs(t *testing.T) {
	e := newProvEnv(t)
	_, err := e.prov.Open(context.Background(), e.ref, sentinelCred{}, providers.Env{})
	assert.Equal(t, "internal.unexpected", providerCode(t, err).Code)
	assert.ErrorIs(t, err, errNoKey)
	providertest.CheckNoSecrets(t, []string{"CANARY-path"}, err)
}

// Outside a development build the provider offers no setup script without the helper checksums:
// the guide fails instead of telling an administrator to install an unchecked helper as root.
func TestSetupSnippetsNeedTheHelperChecksumsInARelease(t *testing.T) {
	line := AuthorizedKeysLine("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGVtdWxhdGVk alice-platform", "")
	for _, s := range New(Options{}).SetupSnippets(line) {
		assert.Empty(t, s.Script, s.Profile)
	}
	withHelperSums(t, strings.Repeat("a1", 32), strings.Repeat("b2", 32))
	for _, s := range New(Options{}).SetupSnippets(line) {
		assert.Contains(t, s.Script, "sha256sum -c", s.Profile)
	}
}

// Carry 3: Discover names the listed accounts with uid 0 so inventory's pre-check can protect the
// last key of every one of them, not only of "root".
func TestDiscoverReportsUID0Users(t *testing.T) {
	e := newProvEnv(t)
	e.emu.AddUser("toor", 0, "/var/toor")
	s, err := e.prov.Open(context.Background(), e.ref, e.cred, providers.Env{})
	require.NoError(t, err)
	defer func() { _ = s.Close() }()
	res, err := s.Discover(context.Background(), providers.DiscoverRequest{SSHKeys: true})
	require.NoError(t, err)
	assert.Equal(t, []string{"root", "toor"}, res.UID0Users)
}

// Carry 1: Discover passes the helper's account list on; inventory decides with it.
func TestDiscoverReportsTheAccountList(t *testing.T) {
	e := newProvEnv(t)
	e.emu.SetAccounts([]string{"alice-svc", "deploy", "root"}, true)
	s := e.open(t)
	res, err := s.Discover(context.Background(), providers.DiscoverRequest{SSHKeys: true})
	require.NoError(t, err)
	assert.Equal(t, []string{"alice-svc", "deploy", "root"}, res.Accounts)
	assert.True(t, res.AccountsComplete)

	e.emu.SetAccounts([]string{"root", "Bad Name", "deploy"}, true)
	res, err = s.Discover(context.Background(), providers.DiscoverRequest{SSHKeys: true})
	require.NoError(t, err)
	assert.Equal(t, []string{"deploy", "root"}, res.Accounts, "invalid names are dropped")
	assert.False(t, res.AccountsComplete, "a list with an invalid entry is not trusted as complete")

	e.emu.SetAccounts([]string{"root"}, false)
	res, err = s.Discover(context.Background(), providers.DiscoverRequest{SSHKeys: true})
	require.NoError(t, err)
	assert.Equal(t, []string{"root"}, res.Accounts)
	assert.False(t, res.AccountsComplete, "the helper said the list is not complete")

	many := []string{"root"}
	for i := 0; i < helperproto.MaxAccountNames+3; i++ {
		many = append(many, "u"+strconv.Itoa(i))
	}
	e.emu.SetAccounts(many, true)
	res, err = s.Discover(context.Background(), providers.DiscoverRequest{SSHKeys: true})
	require.NoError(t, err)
	assert.Len(t, res.Accounts, helperproto.MaxAccountNames)
	assert.False(t, res.AccountsComplete, "a list cut at the bound is not complete")

	res, err = s.Discover(context.Background(), providers.DiscoverRequest{})
	require.NoError(t, err)
	assert.Nil(t, res.Accounts, "without SSH keys no list is read")
	assert.False(t, res.AccountsComplete)
}

// The emulator, like the real helper, lists every account (users, daemon, nobody) when nothing is
// set, and an absent accounts_complete is unknown.
func TestDiscoverAccountsDefaultsAndUnknown(t *testing.T) {
	e := newProvEnv(t)
	s := e.open(t)
	res, err := s.Discover(context.Background(), providers.DiscoverRequest{SSHKeys: true})
	require.NoError(t, err)
	assert.Contains(t, res.Accounts, "root")
	assert.Contains(t, res.Accounts, "nobody")
	assert.True(t, res.AccountsComplete)
	assert.True(t, sort.StringsAreSorted(res.Accounts))
}

// Alice does not trust accounts_complete blindly (a broken or hostile helper), and the emulator
// follows the real helper: too many users or skipped directory users make the list incomplete.
func TestDiscoverAccountsCompletenessIsChecked(t *testing.T) {
	e := newProvEnv(t)
	s := e.open(t)
	discover := func() providers.DiscoveryResult {
		res, err := s.Discover(context.Background(), providers.DiscoverRequest{SSHKeys: true})
		require.NoError(t, err)
		return res
	}
	e.emu.SetAccounts([]string{}, true)
	assert.False(t, discover().AccountsComplete, "an empty list is not a passwd file")
	e.emu.SetAccounts([]string{"deploy", "alice-svc"}, true)
	assert.False(t, discover().AccountsComplete, "no root: not trusted")
	e.emu.SetAccounts([]string{"root"}, true)
	assert.True(t, discover().AccountsComplete)

	// The real helper's listing limit: the emulator reports incomplete with too_many_users.
	e2 := newProvEnv(t)
	e2.emu.SetMaxUsers(1)
	res, err := e2.open(t).Discover(context.Background(), providers.DiscoverRequest{SSHKeys: true})
	require.NoError(t, err)
	assert.False(t, res.AccountsComplete)
	assert.Contains(t, res.Accounts, "root")
	var seen bool
	for _, w := range res.Warnings {
		seen = seen || w.Code == helperproto.WarnTooManyUsers
	}
	assert.True(t, seen, "the emulator warns too_many_users")

	// A helper that says complete while it warned of skipped users.
	e3 := newProvEnv(t)
	e3.srv.SetHandler(func(cmd string, stdin []byte) linuxsshtest.Response {
		r := e3.emu.Handler()(cmd, stdin)
		if strings.Contains(cmd, " authkeys-list") {
			require.Contains(t, string(r.Stdout), `"warnings":[]`, "the list has no warnings to begin with")
			r.Stdout = bytes.Replace(r.Stdout, []byte(`"warnings":[]`), []byte(`"warnings":["directory_users_not_listed"]`), 1)
		}
		return r
	})
	res, err = e3.open(t).Discover(context.Background(), providers.DiscoverRequest{SSHKeys: true})
	require.NoError(t, err)
	assert.False(t, res.AccountsComplete, "directory users not listed: incomplete whatever the helper says")
}

func TestConnOf(t *testing.T) {
	e := newProvEnv(t)
	s, err := e.prov.Open(context.Background(), e.ref, e.cred, providers.Env{Clock: clock.Real{}, HostKeys: e.hk})
	require.NoError(t, err)
	c, ok := ConnOf(s)
	require.True(t, ok)
	res, err := c.Run(context.Background(), CmdVersion())
	require.NoError(t, err)
	assert.Contains(t, string(res.Stdout), `"protocol":6`)
	require.NoError(t, s.Close())
	_, ok = ConnOf(s)
	assert.False(t, ok, "a closed session's connection may serve another session")
	_, ok = ConnOf(providers.UnsupportedSession{})
	assert.False(t, ok)
	_, ok = ConnOf(nil)
	assert.False(t, ok)
}

// A failed deployment run reports neither the key nor the payload in its error or answer. The runs
// go through the emulated Nginx (the helper's own refusals, a restored and a restore_failed outcome,
// a killed helper that prints nothing, a dropped connection), and through scripted handlers for what
// no helper prints: a malformed answer that even echoes the payload, and a cancelled run.
func TestFailedDeployRunDoesNotLeakTheKey(t *testing.T) {
	const crt, key = "/etc/nginx/ssl/www.crt", "/etc/nginx/ssl/www.key"
	ca := pki.NewCA("Leak", pki.ECDSA256, time.Now())
	oldLeaf, newLeaf := ca.Issue(pki.Opts{CommonName: "www.example.test"}, time.Now()), ca.Issue(pki.Opts{CommonName: "www.example.test"}, time.Now())
	raw, err := json.Marshal(helperproto.NginxDeployInput{CertPEM: string(newLeaf.FullchainPEM), KeyPEM: string(newLeaf.KeyPEM)})
	require.NoError(t, err)
	body := strings.Split(string(newLeaf.KeyPEM), "\n")[1] // a line of the key's base64
	needles := []string{body, hex.EncodeToString([]byte(body)), base64.StdEncoding.EncodeToString([]byte(body))}
	sum := sha256.Sum256(oldLeaf.FullchainPEM)
	oldSHA := hex.EncodeToString(sum[:])
	newEnv := func(t *testing.T) *provEnv {
		e := newProvEnv(t)
		e.emu.EnableNginx("1.22.1")
		e.emu.AddSite(linuxsshtest.NginxSite{Names: []string{"www.example.test"}, Port: 443, CertPath: crt, KeyPath: key}, oldLeaf.FullchainPEM, oldLeaf.KeyPEM)
		return e
	}
	check := func(name string, res Result, resp helperproto.NginxDeployResponse, err error) {
		t.Helper()
		all := fmt.Sprintf("%v %+v %+v %#v", err, err, resp, resp) + string(res.Stdout)
		if j, jerr := json.Marshal(resp); jerr == nil {
			all += string(j)
		}
		if err != nil {
			var pe *providers.Error
			require.True(t, errors.As(err, &pe), name)
			all += fmt.Sprintf("%#v %v %v", pe.Params, pe.Unwrap(), pe)
			if j, jerr := json.Marshal(pe); jerr == nil {
				all += string(j)
			}
		}
		for _, n := range needles {
			assert.NotContains(t, all, n, name)
		}
	}
	run := func(t *testing.T, e *provEnv, expect string, ctx context.Context) (Result, helperproto.NginxDeployResponse, error) {
		c, ok := ConnOf(e.open(t))
		require.True(t, ok)
		cmd, err := CmdNginxDeploy(testOp, crt, key, expect, raw)
		require.NoError(t, err)
		defer cmd.WipeInput()
		res, err := c.Run(ctx, cmd)
		if err != nil {
			return res, helperproto.NginxDeployResponse{}, err
		}
		resp, err := DecodeHelper[helperproto.NginxDeployResponse](res, cmd.Subcommand())
		return res, resp, err
	}
	code := func(err error) (string, string) {
		var pe *providers.Error
		require.True(t, errors.As(err, &pe))
		return pe.Code, pe.Params["helper_code"]
	}

	// Real refusals of the helper (nothing changed).
	for name, tc := range map[string]struct {
		setup  func(e *linuxsshtest.Emulator)
		expect string
		code   string
	}{
		"hash mismatch": {func(*linuxsshtest.Emulator) {}, strings.Repeat("ab", 32), helperproto.CodeHashMismatch},
		"busy":          {func(e *linuxsshtest.Emulator) { e.HoldLock(true) }, oldSHA, helperproto.CodeBusy},
		"no space":      {func(e *linuxsshtest.Emulator) { e.SetFreeBytes(1) }, oldSHA, helperproto.CodeNoSpace},
		"config":        {func(e *linuxsshtest.Emulator) { e.SetConfigInvalid(helperproto.ConfigErrSyntax) }, oldSHA, helperproto.CodeConfigInvalid},
	} {
		e := newEnv(t)
		tc.setup(e.emu)
		res, resp, err := run(t, e, tc.expect, context.Background())
		require.Error(t, err, name)
		check(name, res, resp, err)
		_, hc := code(err)
		assert.Equal(t, tc.code, hc, name)
		assert.Zero(t, e.emu.Reloads(), name)
	}

	// A restored outcome and a restore_failed one are answers, not errors.
	for name, tc := range map[string]struct {
		setup func(e *linuxsshtest.Emulator)
		phase string
	}{
		"restored":       {func(e *linuxsshtest.Emulator) { e.FailConfigTest(1) }, helperproto.PhaseRestored},
		"restore_failed": {func(e *linuxsshtest.Emulator) { e.FailConfigTest(2) }, helperproto.PhaseRestoreFailed},
	} {
		e := newEnv(t)
		tc.setup(e.emu)
		res, resp, err := run(t, e, oldSHA, context.Background())
		require.NoError(t, err, name)
		assert.Equal(t, tc.phase, resp.Phase, name)
		check(name, res, resp, err)
	}

	// A killed helper prints nothing (a protocol error: the outcome is unknown); so does a dropped
	// connection (the transport fails). Neither carries the payload.
	e := newEnv(t)
	e.emu.KillAt(helperproto.StepWriteKey)
	res, resp, err := run(t, e, oldSHA, context.Background())
	require.Error(t, err)
	assert.Empty(t, res.Stdout)
	c, _ := code(err)
	assert.Equal(t, "ssh.protocol_error", c)
	check("killed", res, resp, err)
	// A killed helper that ends by status 137 without a signal is "helper_missing" to DecodeHelper:
	// never a helper refusal (the Nginx provider treats it as uncertain).
	e = newEnv(t)
	e.emu.KillAtWithExit137(helperproto.StepWriteKey)
	res, resp, err = run(t, e, oldSHA, context.Background())
	require.Error(t, err)
	assert.Empty(t, res.Stdout)
	c, hc := code(err)
	assert.Equal(t, "ssh.helper_missing", c)
	assert.Empty(t, hc, "no helper code: the helper never answered")
	check("killed with exit 137", res, resp, err)
	e = newEnv(t)
	e.emu.HangupAfter(helperproto.StepWriteCert)
	res, resp, err = run(t, e, oldSHA, context.Background())
	require.Error(t, err)
	c, _ = code(err)
	assert.Contains(t, []string{"ssh.unreachable", "ssh.protocol_error"}, c, "a transport failure or a session without an exit status: never a helper refusal")
	check("hangup", res, resp, err)
	assert.Equal(t, helperproto.PhaseCommitted, e.emu.NginxPhase(testOp.String()), "the helper finished on its own")

	// The key went only to the helper's stdin.
	e = newEnv(t)
	_, _, err = run(t, e, oldSHA, context.Background())
	require.NoError(t, err)
	assert.Equal(t, [][]byte{raw}, e.emu.DeployStdins())
	for _, cmdLine := range e.srv.Commands() {
		for _, n := range needles {
			assert.NotContains(t, cmdLine, n)
		}
	}

	// Scripted answers no helper prints: a malformed answer that echoes the payload, a cancelled run.
	scripted := func(t *testing.T, h func(cmd string, stdin []byte) linuxsshtest.Response, ctx context.Context) (Result, helperproto.NginxDeployResponse, error) {
		e := newEnv(t)
		e.srv.SetHandler(func(cmd string, stdin []byte) linuxsshtest.Response {
			if strings.Contains(cmd, " nginx-deploy ") {
				return h(cmd, stdin)
			}
			return e.emu.Handler()(cmd, stdin)
		})
		return run(t, e, oldSHA, ctx)
	}
	for _, exit := range []int{0, 3} {
		res, resp, err := scripted(t, func(_ string, stdin []byte) linuxsshtest.Response {
			return linuxsshtest.Response{Stdout: append([]byte("not json "), stdin...), Exit: exit}
		}, context.Background())
		name := "malformed answer exit " + strconv.Itoa(exit)
		require.Error(t, err, name)
		c, _ := code(err)
		assert.Equal(t, "ssh.protocol_error", c)
		check(name, Result{}, resp, err)
		_ = res
	}
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	_, resp, err = scripted(t, func(string, []byte) linuxsshtest.Response {
		<-ctx.Done()
		return linuxsshtest.Response{}
	}, ctx)
	require.Error(t, err)
	c, _ = code(err)
	assert.Equal(t, "ssh.timeout", c)
	check("timeout", Result{}, resp, err)
}

// The Nginx subcommands and tls-probe reach the emulated helper through the lines the constructors
// build (sudo for the privileged ones, none for tls-probe), and answer as the helper would on a
// server without Nginx: dump and test NGINX_NOT_FOUND, the deploy its content check, the status
// "none", the probe PROBE_FAILED (nothing listens).
func TestEmulatorParsesProtocol4Lines(t *testing.T) {
	e := newProvEnv(t)
	s := e.open(t)
	c, ok := ConnOf(s)
	require.True(t, ok)
	probe, err := CmdTLSProbe("127.0.0.1", 443, "a.b", "any")
	require.NoError(t, err)
	deploy, err := CmdNginxDeploy(testOp, "/etc/nginx/a.crt", "/etc/nginx/a.key", strings.Repeat("ab", 32), []byte("{}"))
	require.NoError(t, err)
	status, err := CmdNginxStatus(testOp)
	require.NoError(t, err)
	restore, err := CmdNginxRestore(testOp)
	require.NoError(t, err)
	for _, tc := range []struct {
		cmd  HelperCommand
		want string
	}{
		{probe, helperproto.CodeProbeFailed}, {deploy, helperproto.CodeBadContent}, {restore, helperproto.CodeUnknownOp},
		{CmdNginxDump(), helperproto.CodeNginxNotFound}, {CmdNginxTest(), helperproto.CodeNginxNotFound},
	} {
		res, err := c.Run(context.Background(), tc.cmd)
		require.NoError(t, err)
		_, err = DecodeHelper[helperproto.NginxStatusResponse](res, tc.cmd.Subcommand())
		pe := providerCode(t, err)
		assert.Equal(t, tc.want, pe.Params["helper_code"], tc.cmd.Subcommand())
	}
	res, err := c.Run(context.Background(), status)
	require.NoError(t, err)
	st, err := DecodeHelper[helperproto.NginxStatusResponse](res, status.Subcommand())
	require.NoError(t, err)
	assert.Equal(t, helperproto.PhaseNone, st.Phase)

	// The probe is unprivileged: sudo would refuse it (sudoers does not list it), so the emulator does too.
	res, err = c.Run(context.Background(), HelperCommand{sub: helperproto.SubTLSProbe, sudo: true, timeout: DefaultCommandTimeout, maxOutput: smallOutput,
		tokens: []string{"--addr", "'127.0.0.1'", "--port", "'443'", "--sni", "'_'", "--key-type", "'any'"}})
	require.NoError(t, err)
	assert.Equal(t, 1, res.ExitCode)
}

// hostileList answers authkeys-list with `files` readable files and `unsupported` refused ones for
// root, and every authkeys-read with keysPerFile keys (adapted from the audit's PoC, AUD-04(a)).
func hostileList(t *testing.T, e *provEnv, users, files, unsupported, keysPerFile int) *atomic.Int64 {
	t.Helper()
	var content strings.Builder
	for range keysPerFile {
		line, _ := keyLine(t, "ed25519", "", "k")
		content.WriteString(line + "\n")
	}
	body := []byte(content.String())
	sum := sha256.Sum256(body)
	list := helperproto.AuthKeysListResponse{OK: true, AuthorizedKeysCommand: "none", Warnings: []string{}, Accounts: []string{"root"}, AccountsComplete: true}
	for n := range users {
		u := helperproto.UserFiles{User: "root", UID: 0, Home: "/root", AuthorizedKeysCommand: "none"}
		if n > 0 {
			u.User, u.UID, u.Home = fmt.Sprintf("u%d", n), 1000+n, fmt.Sprintf("/home/u%d", n)
		}
		for i := range files {
			u.Files = append(u.Files, helperproto.FileInfo{Path: fmt.Sprintf("%s/.ssh/k%d", u.Home, i), Exists: true, StrictModesOK: true})
		}
		for i := range unsupported {
			u.Files = append(u.Files, helperproto.FileInfo{Path: fmt.Sprintf("%s/.ssh/u%d", u.Home, i), Exists: true, Unsupported: true})
		}
		list.Users = append(list.Users, u)
	}
	listJSON, err := json.Marshal(list)
	require.NoError(t, err)
	var reads atomic.Int64
	emu := e.emu.Handler()
	e.srv.SetHandler(func(cmd string, stdin []byte) linuxsshtest.Response {
		switch {
		case strings.Contains(cmd, " authkeys-list"):
			return linuxsshtest.Response{Stdout: listJSON}
		case strings.Contains(cmd, " authkeys-read "):
			reads.Add(1)
			path := strings.Trim(cmd[strings.LastIndex(cmd, " ")+1:], "'")
			out, _ := json.Marshal(helperproto.AuthKeysReadResponse{OK: true, Path: path, SHA256: hex.EncodeToString(sum[:]),
				ContentB64: base64.StdEncoding.EncodeToString(body), Owner: "root"})
			return linuxsshtest.Response{Stdout: out}
		}
		return emu(cmd, stdin)
	})
	return &reads
}

// AUD-04(a): a hostile helper decides nothing about the size of a discovery: users, files read,
// keys and warnings are bounded; a cut result is partial (missing marking only for the files read)
// and says list_truncated.
func TestDiscoverIsBounded(t *testing.T) {
	e := newProvEnv(t)
	reads := hostileList(t, e, 1, 3000, 5000, 20)
	res, err := e.open(t).Discover(context.Background(), providers.DiscoverRequest{SSHKeys: true})
	require.NoError(t, err)
	assert.LessOrEqual(t, reads.Load(), int64(maxDiscoverFiles))
	assert.LessOrEqual(t, len(res.SSHKeys), maxDiscoverKeys)
	assert.LessOrEqual(t, len(res.Warnings), maxDiscoverWarnings)
	assert.LessOrEqual(t, len(res.ReadFiles), maxDiscoverFiles)
	assert.True(t, res.Partial)
	assert.Contains(t, warnCodes(res.Warnings), providers.WarnListTruncated)
	for _, k := range res.SSHKeys {
		assert.Contains(t, res.ReadFiles, k.FilePath, "a file is read completely, or not at all")
	}
}

func TestDiscoverBoundsTheUsers(t *testing.T) {
	e := newProvEnv(t)
	hostileList(t, e, maxDiscoverUsers+20, 1, 0, 1)
	res, err := e.open(t).Discover(context.Background(), providers.DiscoverRequest{SSHKeys: true})
	require.NoError(t, err)
	assert.Len(t, res.ReadFiles, maxDiscoverUsers)
	assert.True(t, res.Partial)
	assert.False(t, res.AccountsComplete)
	assert.Contains(t, warnCodes(res.Warnings), providers.WarnListTruncated)
}

func TestDiscoverStopsReadingAfterItsTimeBudget(t *testing.T) {
	old := discoverBudget
	discoverBudget = 0
	defer func() { discoverBudget = old }()
	e := newProvEnv(t)
	reads := hostileList(t, e, 1, 50, 0, 1)
	res, err := e.open(t).Discover(context.Background(), providers.DiscoverRequest{SSHKeys: true})
	require.NoError(t, err)
	assert.LessOrEqual(t, reads.Load(), int64(1))
	assert.True(t, res.Partial)
	assert.Contains(t, warnCodes(res.Warnings), providers.WarnListTruncated)
}

func warnCodes(ws []providers.Warning) []string {
	var out []string
	for _, w := range ws {
		out = append(out, w.Code)
	}
	return out
}

// T3-m5: the real provider (behind the emulator) runs the same key script as the fake key world.
func TestKeyLifecycleConforms(t *testing.T) {
	providertest.CheckKeyLifecycle(t, providertest.KeyLifecycleHarness{New: func(tb testing.TB) providertest.KeyLifecycleEnv {
		e := newProvEnv(tb.(*testing.T))
		e.emu.AddUser("backup", 1002, "/home/backup")
		e.srv.SetLoginCheck(e.emu.AcceptsLogin)
		join := func(lines []string) []byte {
			if len(lines) == 0 {
				return nil
			}
			return []byte(strings.Join(lines, "\n") + "\n")
		}
		return providertest.KeyLifecycleEnv{
			Open: func(ctx context.Context) (providers.Session, error) {
				return e.prov.Open(ctx, e.ref, e.cred, providers.Env{})
			},
			OwnFile: func(u string) string {
				switch u {
				case "root":
					return "/root/.ssh/authorized_keys"
				case "alice-svc":
					return "/var/lib/alice-svc/.ssh/authorized_keys"
				}
				return "/home/" + u + "/.ssh/authorized_keys"
			},
			Seed: func(_, f string, lines ...string) { e.emu.SetFile(f, join(lines)) },
			SeedShared: func(f string, lines ...string) {
				e.emu.SetSSHD(strings.Replace(linuxsshtest.DefaultSSHD, "authorizedkeysfile .ssh/authorized_keys .ssh/authorized_keys2",
					"authorizedkeysfile "+f, 1))
				e.emu.SetFile(f, join(lines))
			},
			Lines: func(f string) []string {
				b, _ := e.emu.File(f)
				return strings.Split(strings.TrimSuffix(string(b), "\n"), "\n")
			},
		}
	}})
}

// T4-I2: the candidate key files are filtered as discovery filters key locations: a path the
// helper marked unsupported or that fails ValidPath is never offered.
func TestKeyFilesDropWhatDiscoveryRefuses(t *testing.T) {
	good := "/home/deploy/.ssh/authorized_keys"
	users := []helperproto.UserFiles{{User: "deploy", Files: []helperproto.FileInfo{
		{Path: good},
		{Path: "/home/other/.ssh/authorized_keys", Unsupported: true},
		{Path: "relative/authorized_keys"},
		{Path: "/home/deploy/../root/.ssh/authorized_keys"},
		{Path: "/home/deploy/.ssh/a b"},
		{Path: "/home/deploy/.ssh/\x1b[31m"},
		{Path: "/home/deploy/.ssh/\xff\xfe"},
		{Path: "/" + strings.Repeat("a", 5000)},
		{Path: ""},
		{Path: "/home/deploy/.ssh/authorized_keys2"},
	}}, {User: "onlybad", Files: []helperproto.FileInfo{{Path: "../x"}}}}
	got := keyFiles(users)
	assert.Equal(t, []providers.UserKeyFiles{
		{OSUser: "deploy", Files: []string{good, "/home/deploy/.ssh/authorized_keys2"}},
		{OSUser: "onlybad", Files: []string{}},
	}, got, "the user stays, with fewer files")

	// the eight-file cap counts only files that are kept
	var many []helperproto.FileInfo
	for i := 0; i < 5; i++ {
		many = append(many, helperproto.FileInfo{Path: "bad"})
	}
	for i := 0; i < 10; i++ {
		many = append(many, helperproto.FileInfo{Path: "/k/" + strconv.Itoa(i)})
	}
	got = keyFiles([]helperproto.UserFiles{{User: "u", Files: many}})
	require.Len(t, got, 1)
	assert.Len(t, got[0].Files, 8)
	assert.Equal(t, "/k/7", got[0].Files[7])

	// through the provider: a file the helper reports as unsupported is not a candidate
	e := newProvEnv(t)
	e.emu.SetUnsupported("/home/deploy/.ssh/authorized_keys2")
	res, err := e.open(t).Discover(context.Background(), providers.DiscoverRequest{SSHKeys: true})
	require.NoError(t, err)
	for _, u := range res.KeyFiles {
		assert.NotContains(t, u.Files, "/home/deploy/.ssh/authorized_keys2")
	}
	assert.True(t, hasWarning(res.Warnings, helperproto.WarnUnsupportedPath, "/home/deploy/.ssh/authorized_keys2"))
}
