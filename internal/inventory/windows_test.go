package inventory_test

import (
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"

	"alice/internal/inventory"
	"alice/internal/providers"
	"alice/internal/providers/fake"
	"alice/internal/providers/windows"
	"alice/internal/providers/windows/winproto"
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
