package archtest

import (
	"bytes"
	"encoding/json"
	"errors"
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
	"alice/internal/providers":     {platform, "alice/internal/secrets/..."},
	"alice/internal/providers/...": {platform, "alice/internal/providers", "alice/internal/providers/linuxssh/..."},
	"alice/internal/inventory/...": {platform, "alice/internal/secrets/...", "alice/internal/audit/...", "alice/internal/license/...", "alice/internal/rbac/...", "alice/internal/providers"},
	"alice/internal/jobs/...":      {platform, "alice/internal/audit/...", "alice/internal/license/...", "alice/internal/inventory/...", "alice/internal/providers", "alice/internal/notify/..."},
	"alice/internal/api/...": {platform, "alice/internal/i18n/...", "alice/internal/version/...", "alice/internal/rbac/...",
		"alice/internal/secrets/...", "alice/internal/audit/...", "alice/internal/license/...", "alice/internal/notify/...",
		"alice/internal/auth/...", "alice/internal/inventory/...", "alice/internal/jobs/...", "alice/internal/providers"},
}

const platform = "alice/internal/platform/..."

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
		key, ok := ruleFor(p.ImportPath)
		if !ok {
			t.Errorf("%s has no import rule; add it to internal/archtest", p.ImportPath)
			continue
		}
		for _, imp := range p.Imports {
			if !strings.HasPrefix(imp, "alice/") || covers(key, imp) {
				continue
			}
			allowed := false
			for _, a := range rules[key] {
				if covers(a, imp) {
					allowed = true
					break
				}
			}
			if !allowed {
				t.Errorf("%s must not import %s (rule %q)", p.ImportPath, imp, key)
			}
		}
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
