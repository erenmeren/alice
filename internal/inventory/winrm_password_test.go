package inventory_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"alice/internal/inventory"
	"alice/internal/providers"
	"alice/internal/providers/windows"
)

// R71 Ruling 7: the WinRM password follows the CCS rule (W5 Ruling 10): 12 to 128 characters of printable ASCII without
// a space.
func TestWinRMPasswordRuleIsTheCCSRule(t *testing.T) {
	for _, s := range []string{strings.Repeat("a", 11), strings.Repeat("a", 129), "abcdefgh ijkl", "abcdefghijk\x7f", "abcdefghijké", ""} {
		assert.False(t, inventory.ValidWinRMPassword([]byte(s)), "%q", s)
		assert.Equal(t, inventory.ValidCCSPassword([]byte(s)), inventory.ValidWinRMPassword([]byte(s)), "%q", s)
	}
	for _, s := range []string{strings.Repeat("a", 12), strings.Repeat("~", 128), "!\"#$%&'()*+,-./0123456789:;<=>?@AZ[\\]^_`az{|}~"} {
		assert.True(t, inventory.ValidWinRMPassword([]byte(s)), "%q", s)
	}
}

// R71 Ruling 6: the inventory mirrors the provider's account rule under each transport (it may not import the provider);
// the two must agree, .\<SAM name> under winrm only.
func TestWindowsUserRuleByTransportEqualsTheProviders(t *testing.T) {
	cases := []string{"alice", `.\alice`, `HOST\alice`, `CORP\alice-svc`, "alice@corp.example", `.\`, `..\alice`, `.\CORP\alice`,
		`.\` + strings.Repeat("n", 20), `.\` + strings.Repeat("n", 21), `.\-alice`, `./alice`, `\alice`, `.alice`}
	for _, tr := range []string{windows.TransportSSH, windows.TransportWinRM} {
		for _, u := range cases {
			_, errs := windows.ParseConfig(providers.TargetConfig{"host": "iis-01", "transport": tr, "username": u})
			assert.Equal(t, len(errs) == 0, inventory.ValidWindowsUserFor(tr, u), "%s %q", tr, u)
		}
	}
	assert.Equal(t, windows.TransportSSH, inventory.TransportSSH)
	assert.Equal(t, windows.TransportWinRM, inventory.TransportWinRM)
	assert.Equal(t, windows.DefaultWinRMPort, inventory.DefaultWinRMPort)
}
