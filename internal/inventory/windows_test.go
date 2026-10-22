package inventory_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"alice/internal/inventory"
	"alice/internal/providers"
	"alice/internal/providers/windows"
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
