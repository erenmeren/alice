package inventory_test

import (
	"crypto/sha1" //nolint:gosec // G505: a Windows thumbprint is an identifier
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"

	"alice/internal/i18n"
	"alice/internal/inventory"
	"alice/internal/providers"
	"alice/internal/providers/fake"
	"alice/internal/providers/windows"
	"alice/internal/providers/windows/winproto"
	"alice/internal/testutil/pki"
	"alice/locales"
)

// The inventory may not import the Windows provider (archtest), so it mirrors windows.ValidUser (R60 Ruling 1); the
// provider checks the stored name again (ValidateConfig, ParseConfig). Both must agree. The table is Task 8's
// (TestParseConfigTakesDomainAccounts) plus the edges of each length.
func TestWindowsUserRuleEqualsTheProviders(t *testing.T) {
	cases := []string{"alice", `CORP\alice-svc`, `A1\b.c-d_e`, "a", strings.Repeat("d", 15) + `\` + strings.Repeat("n", 20),
		`corp\`, `\alice`, `a\b\c`, "alice@corp.example", strings.Repeat("d", 16) + `\alice`, strings.Repeat("n", 21), "ali ce",
		"al'ice", "", "-alice", `CORP\-alice`, "alice\n", `CORP/alice`, "älice", "alice-svc", "Alice.Svc_1", "1", `C-1\x`, `-C\x`,
		`C_1\x`, "a.", ".a", "a\x00", " alice", "alice ", `CORP\\alice`, strings.Repeat("n", 20), `İ\alice`, "ALICE"}
	for _, s := range cases {
		assert.Equal(t, windows.ValidUser(s), inventory.ValidWindowsUser(s), "%q", s)
	}
	assert.Equal(t, windows.DefaultUser, inventory.WindowsDefaultUser)
}

// R60 Ruling 11: IsServer keeps "SSH keys"; Windows is an SSH target with certificate locations, not a web server.
func TestTypePredicates(t *testing.T) {
	cases := []struct {
		typ                    string
		ssh, server, certs, ws bool
	}{
		{"linux", true, true, false, false},
		{"nginx", true, true, true, true},
		{"apache", true, true, true, true},
		{"haproxy", true, true, true, true},
		{"windows", true, false, true, false},
		{"azure_key_vault", false, false, false, false},
		{"", false, false, false, false},
		{"WINDOWS", false, false, false, false},
	}
	for _, c := range cases {
		assert.Equal(t, c.ssh, inventory.IsSSHTarget(c.typ), "IsSSHTarget %q", c.typ)
		assert.Equal(t, c.server, inventory.IsServer(c.typ), "IsServer %q", c.typ)
		assert.Equal(t, c.certs, inventory.HasCertificateLocations(c.typ), "HasCertificateLocations %q", c.typ)
		assert.Equal(t, c.ws, inventory.IsWebServer(c.typ), "IsWebServer %q", c.typ)
	}
	assert.Equal(t, providers.TargetTypeWindows, inventory.TypeWindows)
	assert.NotContains(t, inventory.WebServerTypes(), inventory.TypeWindows, "Windows does not deploy in W1")
}

// R60 Ruling 10: http.sys bindings exist without IIS, so an IIS result is usable without Found; a web server's is not.
func TestConfigUsableForIIS(t *testing.T) {
	assert.True(t, inventory.ConfigUsable(&providers.WebServerFacts{Software: "iis", ConfigValid: true}))
	assert.True(t, inventory.ConfigUsable(&providers.WebServerFacts{Software: "iis", Found: true, ConfigValid: true}))
	assert.False(t, inventory.ConfigUsable(&providers.WebServerFacts{Software: "iis"}), "not valid")
	assert.False(t, inventory.ConfigUsable(&providers.WebServerFacts{Software: "iis", ConfigValid: true, ConfigError: "parse"}))
	assert.False(t, inventory.ConfigUsable(&providers.WebServerFacts{Software: "IIS", ConfigValid: true}), "the provider's exact name")
	assert.False(t, inventory.ConfigUsable(&providers.WebServerFacts{Software: "nginx", ConfigValid: true}))
	assert.False(t, inventory.ConfigUsable(&providers.WebServerFacts{ConfigValid: true}))
	assert.True(t, inventory.ConfigUsable(&providers.WebServerFacts{Software: "nginx", Found: true, ConfigValid: true}))
	assert.False(t, inventory.ConfigUsable(nil))
}

// The inventory's copy of the Windows problem that removes a location's certificate is the provider's.
func TestCertMissingMirrorsTheProvider(t *testing.T) {
	assert.Equal(t, windows.ProblemCertMissing, inventory.ProblemCertMissing)
}

// The inventory builds the Windows key line itself (it may not import the provider); it must be exactly the line the
// Windows setup script accepts (R60 Task 10), with and without from=.
func TestWindowsKeyLineEqualsTheProvidersLine(t *testing.T) {
	const key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGVtdWxhdGVk alice-platform"
	for _, from := range []string{"", "192.0.2.10", "2001:db8::9"} {
		assert.Equal(t, windows.AuthorizedKeysLine(key, from), inventory.WindowsAuthorizedKeysLine(key, from), "from=%q", from)
	}
}

// W2 Ruling 20: deployTypes offers every type whose registered provider deploys, Windows included; a Windows provider
// with W1's capabilities (discovery only) is not offered, nor is a web server whose provider does not deploy.
func TestDeployTypesFollowTheCapability(t *testing.T) {
	registry := func(ps ...providers.Provider) *providers.Registry {
		reg := providers.NewRegistry()
		for _, p := range ps {
			reg.Register(p)
		}
		reg.Freeze()
		return reg
	}
	deploys := []providers.Capability{providers.CapTestConnection, providers.CapDiscoverCerts, providers.CapDeployCertificate,
		providers.CapVerifyDeployment}
	w1 := []providers.Capability{providers.CapTestConnection, providers.CapDiscoverCerts}

	svc := inventory.New(inventory.Config{Registry: registry(fake.New(providers.KindNginx, deploys...), windows.New(windows.Options{}))})
	assert.Equal(t, []string{"nginx", "windows"}, svc.DeployTypes(), "the real Windows provider deploys (W2)")

	svc = inventory.New(inventory.Config{Registry: registry(fake.New(providers.KindNginx, deploys...), fake.New(providers.KindWindows, w1...))})
	assert.Equal(t, []string{"nginx"}, svc.DeployTypes(), "W1's capabilities do not deploy")

	svc = inventory.New(inventory.Config{Registry: registry(fake.New(providers.KindApache, w1...), fake.New(providers.KindHAProxy, deploys...),
		fake.New(providers.KindWindows, deploys...))})
	assert.Equal(t, []string{"haproxy", "windows"}, svc.DeployTypes())

	svc = inventory.New(inventory.Config{Registry: registry()})
	assert.Empty(t, svc.DeployTypes())
}

// W2 Ruling 6: windows.busy and windows.io_error name a real cause (the helper's lock, its disk) and are recorded as
// they are while a deployment is recovered, as nginx.busy is; only a lost or unreadable answer reads "interrupted".
func TestWindowsCausesStayInTheRecord(t *testing.T) {
	for _, code := range []string{"windows.busy", "windows.io_error"} {
		err := providers.NewError(code, true, nil, nil)
		got := inventory.DeployOutcomeRecord(providers.DeployOutcome{Result: providers.DeployUncertain}, err, false)
		assert.False(t, got.Terminal, code)
		assert.Equal(t, code, got.Finish.ErrorCode, "deploy, %s", code)
		rb := inventory.RollbackOutcomeRecord(providers.RollbackOutcome{Result: providers.DeployNoChange, Reason: code}, err, "deployment.verify_failed")
		assert.False(t, rb.Terminal, code)
		assert.Equal(t, code, rb.Finish.ErrorCode, "rollback, %s", code)
	}
	// A killed Windows helper answers no JSON at exit 255, which the provider names windows.helper_missing: as Linux's
	// ssh.helper_missing, nothing true of a deployment being recovered.
	lost := inventory.DeployOutcomeRecord(providers.DeployOutcome{Result: providers.DeployUncertain},
		providers.NewError("windows.helper_missing", false, nil, map[string]string{"subcommand": "iis-deploy"}), false)
	assert.Equal(t, "deployment.interrupted", lost.Finish.ErrorCode)
}

// The Task 8 addendum: a rollback of a Windows deployment carries the rollback info the start record wrote (the
// previous certificate's store and thumbprints); a file's rollback request carries none (the Linux helper reads its
// own backup by operation).
func TestRollbackRequestCarriesTheWindowsBackup(t *testing.T) {
	op := uuid.New()
	ref := &providers.BackupRef{OperationID: op, Store: "My", PreviousSHA1: strings.Repeat("ab", 20), PreviousSHA256: strings.Repeat("cd", 32)}
	win := inventory.Material{Deployment: inventory.Deployment{ID: op, OperationID: &op, Backup: ref},
		Location: providers.CertLocation{Kind: providers.LocationWinSSLBinding, CertPath: "http.sys/ipport/0.0.0.0:443"}}
	g := providers.RollbackGuard{}
	rb := win.RollbackRequest(g)
	assert.Equal(t, *ref, rb.Backup)
	assert.Equal(t, op, rb.OperationID)

	none := win
	none.Deployment.Backup = nil
	assert.Equal(t, providers.BackupRef{}, none.RollbackRequest(g).Backup, "nothing recorded: the provider falls back to the details")

	file := inventory.Material{Deployment: inventory.Deployment{ID: op, OperationID: &op,
		Backup: &providers.BackupRef{OperationID: op, Dir: inventory.BackupRoot + "/" + op.String()}},
		Location: providers.CertLocation{CertPath: "/etc/nginx/ssl/www.crt", KeyPath: "/etc/nginx/ssl/www.key"}}
	assert.Equal(t, providers.BackupRef{}, file.RollbackRequest(g).Backup, "a file's request is as before")
}

// The inventory's rules for the store and thumbprint it writes into rollback_info are the protocol's (it may not
// import the provider's packages).
func TestBackupRulesEqualTheProtocols(t *testing.T) {
	for _, s := range []string{"My", "MY", "WebHosting", "my store", "a.b_c-d", "", strings.Repeat("s", 64), strings.Repeat("s", 65), `My\x`,
		"My\n", "Mý", "<x>", "My\x00"} {
		assert.Equal(t, winproto.ValidStore(s), inventory.ValidBackupStore(s), "%q", s)
	}
	for _, s := range []string{strings.Repeat("ab", 20), strings.Repeat("AB", 20), strings.Repeat("a", 39), strings.Repeat("a", 41), "",
		strings.Repeat("g", 40), strings.Repeat("a", 40) + "\n"} {
		assert.Equal(t, winproto.ValidSHA1(s), inventory.ValidBackupSHA1(s), "%q", s)
	}
}

// R61 Task 11: after a deployment the location's compare-and-swap token is what its provider compares the next send
// against: the SHA-256 of the file's bytes for a file (the helper writes the PEM sent verbatim), the SHA-256 of the
// leaf's DER for an http.sys binding (what iis-deploy's expect_sha256 names). With the file's rule a second Windows
// deployment was refused HASH_MISMATCH.
func TestTheTokenAfterADeploymentIsTheProvidersForm(t *testing.T) {
	now := time.Now()
	ca := pki.NewCA("Token", pki.ECDSA256, now)
	leaf := ca.Issue(pki.Opts{CommonName: "www.example.test", SANs: []string{"www.example.test"}}, now)
	file := sha256.Sum256(leaf.FullchainPEM)
	assert.Equal(t, hex.EncodeToString(file[:]), inventory.NewCertSHA256(providers.LocationServerFile, leaf.FullchainPEM))
	assert.Equal(t, hex.EncodeToString(file[:]), inventory.NewCertSHA256("", leaf.FullchainPEM), "a file's material has no kind")
	assert.Equal(t, pki.Fingerprint(leaf.Cert), inventory.NewCertSHA256(providers.LocationWinSSLBinding, leaf.FullchainPEM))
	assert.Empty(t, inventory.NewCertSHA256(providers.LocationWinSSLBinding, []byte("not PEM")), "no leaf: no token")
}

// R61 Task 14 review: the thumbprint a Windows location records after a deployment names the certificate the token
// names, or nothing: a chain whose first certificate is not the deployed leaf never pairs a wrong SHA-1 with the token.
func TestTheRecordedThumbprintIsTheTokensCertificate(t *testing.T) {
	now := time.Now()
	ca := pki.NewCA("Thumb", pki.ECDSA256, now)
	leaf := ca.Issue(pki.Opts{CommonName: "www.example.test", SANs: []string{"www.example.test"}}, now)
	sum := sha1.Sum(leaf.Cert.Raw) //nolint:gosec // G401: a Windows thumbprint is an identifier
	token := pki.Fingerprint(leaf.Cert)
	assert.Equal(t, hex.EncodeToString(sum[:]), inventory.LeafThumbprint(leaf.FullchainPEM, token))
	assert.Empty(t, inventory.LeafThumbprint(leaf.FullchainPEM, pki.Fingerprint(ca.Intermediate)), "another token: nothing")
	assert.Empty(t, inventory.LeafThumbprint(append(append([]byte(nil), ca.IntermediatePEM...), leaf.FullchainPEM...), token),
		"a chain whose first certificate is not the leaf: nothing")
	assert.Empty(t, inventory.LeafThumbprint(leaf.FullchainPEM, ""), "no token: nothing")
	assert.Empty(t, inventory.LeafThumbprint([]byte("not PEM"), token))
}

// The inventory may not import winproto (archtest), so it mirrors winproto.ValidCCSPassword (W5 Ruling 10); the helper
// and BuildPFX need exactly that alphabet. Both must agree on the edges of length and alphabet.
func TestCCSPasswordRuleEqualsTheHelpers(t *testing.T) {
	cases := []string{"", strings.Repeat("a", 11), strings.Repeat("a", 12), strings.Repeat("~", 128), strings.Repeat("!", 129),
		"abcdefgh ijkl", "abcdefgh\tijkl", "abcdefghijk\u00e9", "abcdefghijk\x00", "abcdefghijk\x7f", "abcdefghijk\x20",
		"!\"#$%&'()*+,-./0123456789:;<=>?@AZ[\\]^_`az{|}~", "Ccs-0123456789"}
	for _, s := range cases {
		assert.Equal(t, winproto.ValidCCSPassword([]byte(s)), inventory.ValidCCSPassword([]byte(s)), "%q", s)
	}
}

// Every e-mail template the inventory lists, the Windows and CCS texts of R61, R62 and W5 among them, has an English and a
// Turkish subject and body in the catalogue, and no list names a template twice.
func TestListedTemplatesHaveTexts(t *testing.T) {
	cat, err := i18n.Load(locales.FS)
	if !assert.NoError(t, err) {
		return
	}
	seen := map[string]bool{}
	for _, list := range [][]string{inventory.Templates(), inventory.WindowsDeploymentTemplates(), inventory.WindowsCCSDeploymentTemplates(),
		inventory.IncidentTemplates(), inventory.RevocationTemplates(), inventory.DriftTemplates(), inventory.WindowsDriftTemplates()} {
		assert.NotEmpty(t, list)
		for _, tpl := range list {
			assert.False(t, seen[tpl], "%s is listed twice", tpl)
			seen[tpl] = true
			for _, lang := range []string{"en", "tr"} {
				for _, part := range []string{"subject", "body"} {
					key := "email." + tpl + "." + part
					assert.NotEqual(t, key, cat.T(lang, key, nil), "%s %s", lang, key)
				}
			}
		}
	}
}
