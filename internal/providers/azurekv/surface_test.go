package azurekv

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAzureSDKSurface keeps the SDK's reach where the design wants it (SEC-065, A-14, rulings S1,
// S2, S4): no ambient credential, no environment, CLI, device-code, browser, workload-identity or
// pipelines source, no persistent cache, no log listener, no switch that weakens the challenge
// check, and the three credential constructors in one file.
func TestAzureSDKSurface(t *testing.T) {
	root := moduleRoot(t)
	forbidden := []string{
		"NewDefaultAzureCredential", "NewEnvironmentCredential", "NewAzureCLICredential", "NewAzureDeveloperCLICredential",
		"NewAzurePowerShellCredential", "NewDeviceCodeCredential", "NewInteractiveBrowserCredential", "NewWorkloadIdentityCredential",
		"NewAzurePipelinesCredential", "NewChainedTokenCredential", "NewUsernamePasswordCredential", "NewOnBehalfOfCredential",
		"NewClientAssertionCredential", "azidentity/cache", "log.SetListener", "AdditionallyAllowedTenants",
		"InsecureAllowCredentialWithHTTP", "ProxyFromEnvironment",
	}
	forbiddenRE := []*regexp.Regexp{
		regexp.MustCompile(`DisableChallengeResourceVerification\s*(:|=)\s*(true|[a-zA-Z])`),
		regexp.MustCompile(`DisableChallengeResourceVerification:\s*true`),
	}
	cacheRE := regexp.MustCompile(`\bCache\s*:`)
	constructors := []string{"NewClientSecretCredential", "NewClientCertificateCredential", "NewManagedIdentityCredential"}
	self := filepath.Join(root, "internal", "providers", "azurekv", "surface_test.go")
	identity := filepath.Join(root, "internal", "providers", "azurekv", "identity.go")
	azurekvDir := filepath.Join(root, "internal", "providers", "azurekv") + string(filepath.Separator)

	n := 0
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "node_modules", "vendor", ".claude", ".superpowers", "dist":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || path == self {
			return nil
		}
		b, err := os.ReadFile(path) //nolint:gosec // G304: walking this repository's own sources
		if err != nil {
			return err
		}
		n++
		src := string(b)
		rel, _ := filepath.Rel(root, path)
		for _, f := range forbidden {
			if strings.Contains(src, f) && !strings.HasSuffix(path, "_test.go") {
				assert.Fail(t, "forbidden SDK surface", "%s uses %s", rel, f)
			}
		}
		for _, re := range forbiddenRE {
			if re.MatchString(src) && !strings.Contains(src, "DisableChallengeResourceVerification to true") {
				assert.Fail(t, "challenge verification is never switched off", rel)
			}
		}
		if strings.Contains(src, "azidentity") && cacheRE.MatchString(src) && !strings.HasSuffix(path, "_test.go") {
			assert.Fail(t, "a token cache option next to azidentity", rel)
		}
		for _, c := range constructors {
			if strings.Contains(src, c) && path != identity && !strings.HasSuffix(path, "_test.go") {
				assert.Fail(t, "a credential constructor outside identity.go", "%s uses %s", rel, c)
			}
		}
		if strings.HasPrefix(path, azurekvDir) && !strings.HasSuffix(path, "_test.go") {
			for _, f := range []string{"http.DefaultClient", "http.DefaultTransport", "http.Get(", "http.Post(", "InsecureSkipVerify"} {
				assert.NotContains(t, src, f, rel)
			}
			if path != identity {
				assert.NotContains(t, src, "azcore.ClientOptions{", "client options are built in identity.go only: "+rel)
			}
		}
		return nil
	})
	require.NoError(t, err)
	assert.Greater(t, n, 100, "the walk saw the repository")
	b, err := os.ReadFile(identity) //nolint:gosec // G304: this package's own source
	require.NoError(t, err)
	for _, c := range constructors {
		assert.Contains(t, string(b), c+"(", "identity.go builds "+c)
	}
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
		require.NotEqual(t, dir, parent, "go.mod not found")
		dir = parent
	}
}
