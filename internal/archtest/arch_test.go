package archtest

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// Allowed internal imports per package. A key or entry ending in "/..." covers
// the package and everything below it; other entries are exact. A package may
// always import packages inside its own rule subtree.
var rules = map[string][]string{
	"alice/internal/platform/...":  {},
	"alice/internal/version/...":   {},
	"alice/internal/webui/...":     {},
	"alice/internal/archtest/...":  {},
	"alice/internal/i18n/...":      {platform},
	"alice/internal/rbac/...":      {platform},
	"alice/internal/secrets/...":   {platform},
	"alice/internal/audit/...":     {platform},
	"alice/internal/license/...":   {platform, "alice/internal/secrets/...", "alice/internal/audit/..."},
	"alice/internal/notify/...":    {platform, "alice/internal/i18n/...", "alice/internal/secrets/..."},
	"alice/internal/auth/...":      {platform, "alice/internal/rbac/...", "alice/internal/secrets/...", "alice/internal/audit/...", "alice/internal/notify/..."},
	"alice/internal/certs/...":     {platform, "alice/internal/secrets/..."},
	"alice/internal/providers":     {platform, "alice/internal/secrets/..."},
	"alice/internal/providers/...": {platform, "alice/internal/providers", "alice/internal/providers/linuxssh/..."},
	// The test world of the linuxssh provider runs the real nginx configuration parser, so that an
	// emulated nginx-dump parses configuration text the way the helper does.
	"alice/internal/providers/linuxssh/linuxsshtest": {platform, "alice/internal/providers/linuxssh/...", "alice/internal/providers/nginx/nginxconf"},
	"alice/internal/inventory/...":                   {platform, "alice/internal/secrets/...", "alice/internal/audit/...", "alice/internal/license/...", "alice/internal/rbac/...", "alice/internal/providers", "alice/internal/certs/..."},
	"alice/internal/jobs/...":                        {platform, "alice/internal/audit/...", "alice/internal/license/...", "alice/internal/inventory/...", "alice/internal/providers", "alice/internal/notify/..."},
	"alice/internal/setup/...":                       {platform, "alice/internal/auth/...", "alice/internal/secrets/...", "alice/internal/audit/...", "alice/internal/rbac/..."},
	"alice/internal/api/...": {platform, "alice/internal/i18n/...", "alice/internal/version/...", "alice/internal/rbac/...",
		"alice/internal/secrets/...", "alice/internal/audit/...", "alice/internal/license/...", "alice/internal/notify/...",
		"alice/internal/auth/...", "alice/internal/setup/...", "alice/internal/inventory/...", "alice/internal/jobs/...", "alice/internal/providers"},
	// Test helpers (build tag integration) start PostgreSQL and apply the embedded migrations.
	"alice/internal/testutil/...": {platform, "alice/migrations"},
}

const platform = "alice/internal/platform/..."

// denied lists imports that are forbidden even though a broader allow entry
// covers them. Providers are pure adapters and have no database access (§5.4 rule 2).
var denied = map[string][]string{
	"alice/internal/certs/...":                       {"alice/internal/platform/db/..."},
	"alice/internal/providers":                       {"alice/internal/platform/db/..."},
	"alice/internal/providers/...":                   {"alice/internal/platform/db/..."},
	"alice/internal/providers/linuxssh/linuxsshtest": {"alice/internal/platform/db/..."},
}

// allowed decides whether package pkg may import imp. It is a pure function so
// the rules can be tested with positive and negative cases.
func allowed(pkg, imp string) error {
	if !strings.HasPrefix(imp, "alice/") {
		return nil // standard library and third-party packages are not governed here
	}
	if strings.HasPrefix(pkg, "alice/cmd/") {
		return nil // the composition root may import everything
	}
	key, ok := ruleFor(pkg)
	if !ok {
		return fmt.Errorf("%s has no import rule; add it to internal/archtest", pkg)
	}
	for _, d := range denied[key] {
		if covers(d, imp) {
			return fmt.Errorf("%s must not import %s (denied by rule %q)", pkg, imp, key)
		}
	}
	// A package may import its own subpackages. Provider implementations are
	// siblings, so for them "own" means their own subtree, not the whole rule subtree.
	if key == "alice/internal/providers/..." {
		if imp == pkg || strings.HasPrefix(imp, pkg+"/") {
			return nil
		}
	} else if covers(key, imp) {
		return nil
	}
	for _, a := range rules[key] {
		if covers(a, imp) {
			return nil
		}
	}
	return fmt.Errorf("%s must not import %s (rule %q)", pkg, imp, key)
}

func covers(pattern, pkg string) bool {
	if base, ok := strings.CutSuffix(pattern, "/..."); ok {
		return pkg == base || strings.HasPrefix(pkg, base+"/")
	}
	return pkg == pattern
}

// ruleFor returns the most specific rule key: exact keys win, then the longest subtree.
func ruleFor(pkg string) (string, bool) {
	if _, ok := rules[pkg]; ok {
		return pkg, true
	}
	best := ""
	for k := range rules {
		if covers(k, pkg) && len(k) > len(best) {
			best = k
		}
	}
	return best, best != ""
}

type goPackage struct {
	ImportPath string
	Imports    []string
}

func TestImportRules(t *testing.T) {
	root := moduleRoot(t)
	cmd := exec.Command("go", "list", "-json", "./internal/...")
	cmd.Dir = root
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	require.NoError(t, err, stderr.String())

	dec := json.NewDecoder(bytes.NewReader(out))
	for {
		var p goPackage
		if err := dec.Decode(&p); errors.Is(err, io.EOF) {
			break
		} else {
			require.NoError(t, err)
		}
		for _, imp := range p.Imports {
			if err := allowed(p.ImportPath, imp); err != nil {
				t.Error(err)
			}
		}
	}
}

func TestAllowed(t *testing.T) {
	const (
		nginx   = "alice/internal/providers/nginx"
		azurekv = "alice/internal/providers/azurekv"

		linuxsshtest = "alice/internal/providers/linuxssh/linuxsshtest"
	)
	tests := []struct {
		name, pkg, imp string
		ok             bool
	}{
		{"provider sibling denied", nginx, azurekv, false},
		{"azurekv to azureid allowed", azurekv, "alice/internal/platform/azureid", true},
		{"azurekv to platform/netaddr allowed", azurekv, "alice/internal/platform/netaddr", true},
		{"azurekv to the interface package allowed", azurekv, "alice/internal/providers", true},
		{"azurekv to certs denied", azurekv, "alice/internal/certs", false},
		{"azurekv to secrets denied", azurekv, "alice/internal/secrets", false},
		{"azurekv to the nginx provider denied", azurekv, nginx, false},
		{"azurekv to platform/db denied", azurekv, "alice/internal/platform/db", false},
		{"fakekv to the interface package denied", "alice/internal/testutil/fakekv", "alice/internal/providers", false},
		{"fakekv to azureid allowed", "alice/internal/testutil/fakekv", "alice/internal/platform/azureid", true},
		{"azureid to anything of Alice denied", "alice/internal/platform/azureid", "alice/internal/providers", false},
		{"provider to platform/db denied", nginx, "alice/internal/platform/db", false},
		{"provider interface pkg to platform/db denied", "alice/internal/providers", "alice/internal/platform/db", false},
		{"provider to platform/clock allowed", nginx, "alice/internal/platform/clock", true},
		{"provider to interface package allowed", nginx, "alice/internal/providers", true},
		{"provider to linuxssh allowed", nginx, "alice/internal/providers/linuxssh", true},
		{"provider to own subpackage allowed", nginx, nginx + "/internal", true},
		{"nginxconf to helperproto allowed", nginx + "/nginxconf", "alice/internal/providers/linuxssh/helperproto", true},
		{"linuxsshtest to nginxconf allowed", linuxsshtest, "alice/internal/providers/nginx/nginxconf", true},
		{"linuxsshtest to the nginx provider denied", linuxsshtest, nginx, false},
		{"linuxsshtest to platform/db denied", linuxsshtest, "alice/internal/platform/db", false},
		{"nginxconf to platform/db denied", nginx + "/nginxconf", "alice/internal/platform/db", false},
		{"platform to i18n denied", "alice/internal/platform/clock", "alice/internal/i18n", false},
		{"platform to platform allowed", "alice/internal/platform/db", "alice/internal/platform/clock", true},
		{"api to provider impl denied", "alice/internal/api", nginx, false},
		{"api to provider interface allowed", "alice/internal/api", "alice/internal/providers", true},
		{"api to platform/db allowed", "alice/internal/api", "alice/internal/platform/db", true},
		{"cmd to provider impl allowed", "alice/cmd/alice", nginx, true},
		{"third-party import ignored", nginx, "github.com/x/y", true},
		{"unknown package rejected", "alice/internal/mystery", "alice/internal/version", false},
		{"setup to auth allowed", "alice/internal/setup", "alice/internal/auth", true},
		{"setup to api denied", "alice/internal/setup", "alice/internal/api", false},
		{"api to setup allowed", "alice/internal/api", "alice/internal/setup", true},
		{"auth to setup denied", "alice/internal/auth", "alice/internal/setup", false},
		{"testutil to migrations allowed", "alice/internal/testutil/pgtest", "alice/migrations", true},
		{"certs to secrets allowed", "alice/internal/certs", "alice/internal/secrets", true},
		{"certs to platform/db denied", "alice/internal/certs", "alice/internal/platform/db", false},
		{"testutil to auth denied", "alice/internal/testutil/pgtest", "alice/internal/auth", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := allowed(tc.pkg, tc.imp)
			if tc.ok {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}
		})
	}
}

func TestRuleMatching(t *testing.T) {
	k, _ := ruleFor("alice/internal/providers")
	require.Equal(t, "alice/internal/providers", k)
	k, _ = ruleFor("alice/internal/providers/nginx")
	require.Equal(t, "alice/internal/providers/...", k)
	k, _ = ruleFor("alice/internal/platform/db")
	require.Equal(t, "alice/internal/platform/...", k)
	_, ok := ruleFor("alice/internal/platformx")
	require.False(t, ok)
}

func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	require.NoError(t, err)
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		require.NotEqual(t, parent, dir, "go.mod not found")
		dir = parent
	}
}
