//go:build integration

package inventory_test

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/inventory"
	"alice/internal/providers"
	"alice/internal/providers/fake"
	"alice/internal/providers/windows"
)

// withGuideProviders registers the fake Linux guide provider and the real Windows provider (R60 Task 10).
func withGuideProviders(g *guideProvider, allowUnverified bool) harnessOption {
	return func(c *inventory.Config) {
		reg := providers.NewRegistry()
		reg.Register(g)
		reg.Register(windows.New(windows.Options{AllowUnverifiedHelper: allowUnverified}))
		reg.Freeze()
		c.Registry = reg
	}
}

// The real guide with the Windows provider registered has the windows profile: the PowerShell script with the
// Windows key line (restrict), next to the Linux profiles, which keep their own line.
func TestSetupGuideHasTheWindowsProfile(t *testing.T) {
	g := &guideProvider{Provider: fake.New(providers.KindLinuxSSH)}
	h := newHarness(t, withSeed, withGuideProviders(g, true))
	pk, err := h.svc.EnsurePlatformKey(h.ctx)
	require.NoError(t, err)

	for _, from := range []string{"", "192.0.2.10", "2001:DB8::9"} {
		guide, err := h.svc.SetupGuide(h.ctx, from)
		require.NoError(t, err, from)
		require.Len(t, guide.Profiles, 3, "linux, nginx and windows")
		w := guide.Profiles["windows"]
		assert.Equal(t, "windows", w.Profile)
		assert.Empty(t, w.Sudoers)
		require.NotEmpty(t, w.Script)
		canonical := from
		if from != "" {
			canonical = netip.MustParseAddr(from).String()
		}
		line := windows.AuthorizedKeysLine(pk.PublicKey, canonical)
		require.True(t, strings.HasPrefix(line, "restrict"))
		assert.Contains(t, w.Script, "$AuthorizedKey = '"+line+"'\n", "the Windows script carries the Windows line")
		assert.Equal(t, guide.AuthorizedKeysLine, g.line, "the Linux profiles keep the Linux line")
		assert.Contains(t, guide.Profiles["linux"].Script, guide.AuthorizedKeysLine)
		assert.NotContains(t, w.Script, guide.AuthorizedKeysLine)
	}
}

// Ruling 15: a non-development build without the Windows helper checksums has no Windows script, and the guide
// is all or nothing.
func TestSetupGuideWithoutTheWindowsChecksumsHasNoScript(t *testing.T) {
	if windows.HelperChecksumsKnown() {
		t.Skip("this test binary was linked with the Windows helper checksums")
	}
	g := &guideProvider{Provider: fake.New(providers.KindLinuxSSH)}
	h := newHarness(t, withSeed, withGuideProviders(g, false))
	_, err := h.svc.EnsurePlatformKey(h.ctx)
	require.NoError(t, err)
	_, err = h.svc.SetupGuide(h.ctx, "")
	require.ErrorIs(t, err, inventory.ErrNoSetupScript)
}
