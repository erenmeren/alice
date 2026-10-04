package azurekv

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAzureSDKSurface keeps the SDK's reach where the design wants it (SEC-065, A-14, rulings S1,
// S2, S4): no ambient credential, no environment, CLI, device-code, browser, workload-identity or
// pipelines source, no persistent cache, no log listener, no switch that weakens the challenge
// check, no direct MSAL use, and the credential constructors in one file. The rules are read from
// the syntax tree (imports and identifiers), so aliases, parentheses and odd spellings of a value
// do not evade them; comments and strings are not code and are ignored.
func TestAzureSDKSurface(t *testing.T) {
	root := moduleRoot(t)
	n := 0
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "node_modules", "vendor", ".claude", ".superpowers", "dist", "testdata":
				return filepath.SkipDir
			}
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)
		if !strings.HasSuffix(path, ".go") || rel == "internal/providers/azurekv/surface_test.go" {
			return nil
		}
		b, err := os.ReadFile(path) //nolint:gosec // G304: walking this repository's own sources
		if err != nil {
			return err
		}
		n++
		for _, f := range scanSource(rel, string(b)) {
			assert.Fail(t, "SDK surface", "%s: %s", rel, f)
		}
		return nil
	})
	require.NoError(t, err)
	assert.Greater(t, n, 100, "the walk saw the repository")
}

const (
	azidentityPath = "github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	azcoreLogPath  = "github.com/Azure/azure-sdk-for-go/sdk/azcore/log"
	msalPath       = "github.com/AzureAD/microsoft-authentication-library-for-go"
	azurekvDir     = "internal/providers/azurekv/"
)

// azidentityFiles are the only non-test files that may import azidentity: identity.go builds the
// credentials, errors.go reads the SDK's error type to classify it.
var azidentityFiles = map[string]bool{azurekvDir + "identity.go": true, azurekvDir + "errors.go": true}

var (
	// forbiddenAnywhere: identifiers no Go file of the repository may use, whatever the value.
	forbiddenAnywhere = map[string]bool{
		"SetListener": true, "DisableChallengeResourceVerification": true, "InsecureAllowCredentialWithHTTP": true,
	}
	// forbiddenInCode: identifiers no non-test file may use.
	forbiddenInCode = map[string]bool{
		"NewDefaultAzureCredential": true, "NewEnvironmentCredential": true, "NewAzureCLICredential": true,
		"NewAzureDeveloperCLICredential": true, "NewAzurePowerShellCredential": true, "NewDeviceCodeCredential": true,
		"NewInteractiveBrowserCredential": true, "NewWorkloadIdentityCredential": true, "NewAzurePipelinesCredential": true,
		"NewChainedTokenCredential": true, "NewUsernamePasswordCredential": true, "NewOnBehalfOfCredential": true,
		"NewClientAssertionCredential": true, "AdditionallyAllowedTenants": true, "ProxyFromEnvironment": true,
	}
	constructors = map[string]bool{"NewClientSecretCredential": true, "NewClientCertificateCredential": true, "NewManagedIdentityCredential": true}
)

// scanSource returns what the file at rel (slash form, from the module root) breaks.
func scanSource(rel, src string) []string {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, rel, src, parser.SkipObjectResolution)
	if err != nil {
		return []string{"does not parse: " + err.Error()}
	}
	var out []string
	add := func(s string) { out = append(out, s) }
	isTest := strings.HasSuffix(rel, "_test.go")
	inKV := strings.HasPrefix(rel, azurekvDir) && !isTest
	imports := map[string]string{} // local name -> path
	importsIdentity := false
	for _, im := range f.Imports {
		p, _ := strconv.Unquote(im.Path.Value)
		name := p[strings.LastIndex(p, "/")+1:]
		if im.Name != nil {
			name = im.Name.Name
		}
		imports[name] = p
		if p == azidentityPath {
			importsIdentity = true
		}
		if isTest {
			continue
		}
		switch {
		case p == azcoreLogPath || strings.HasPrefix(p, azcoreLogPath+"/"):
			add("imports azcore/log: the SDK log listener is never used")
		case strings.HasPrefix(p, msalPath):
			add("imports MSAL directly: only azidentity talks to it")
		case strings.HasPrefix(p, azidentityPath+"/"):
			add("imports an azidentity subpackage (token cache): " + p)
		case p == azidentityPath && !azidentityFiles[rel]:
			add("imports azidentity outside identity.go and errors.go")
		}
	}
	ast.Inspect(f, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.Ident:
			if forbiddenAnywhere[x.Name] {
				add("uses " + x.Name)
			}
			if !isTest && forbiddenInCode[x.Name] {
				add("uses " + x.Name)
			}
			if !isTest && constructors[x.Name] && rel != azurekvDir+"identity.go" {
				add("builds a credential outside identity.go: " + x.Name)
			}
			if inKV && x.Name == "InsecureSkipVerify" {
				add("uses InsecureSkipVerify")
			}
		case *ast.KeyValueExpr:
			if k, ok := x.Key.(*ast.Ident); ok && k.Name == "Cache" && !isTest && (importsIdentity || inKV) {
				add("sets Cache on credential options")
			}
		case *ast.AssignStmt:
			for _, l := range x.Lhs {
				if s, ok := l.(*ast.SelectorExpr); ok && s.Sel.Name == "Cache" && !isTest && (importsIdentity || inKV) {
					add("assigns Cache on credential options")
				}
			}
		case *ast.SelectorExpr:
			if id, ok := x.X.(*ast.Ident); ok && inKV && imports[id.Name] == "net/http" {
				switch x.Sel.Name {
				case "DefaultClient", "DefaultTransport", "Get", "Post", "PostForm", "Head":
					add("uses the default HTTP client: http." + x.Sel.Name)
				}
			}
		case *ast.CompositeLit:
			s, ok := x.Type.(*ast.SelectorExpr)
			if !ok || !inKV {
				break
			}
			id, ok := s.X.(*ast.Ident)
			if !ok {
				break
			}
			if imports[id.Name] == "net/http" && s.Sel.Name == "Transport" && rel != azurekvDir+"transport.go" {
				add("builds an http.Transport outside transport.go")
			}
			if strings.HasSuffix(imports[id.Name], "/azcore") && s.Sel.Name == "ClientOptions" && rel != azurekvDir+"identity.go" {
				add("builds azcore.ClientOptions outside identity.go")
			}
		}
		return true
	})
	return out
}

func TestSurfaceRulesCatchEvasions(t *testing.T) {
	kv := azurekvDir + "x.go"
	cases := []struct {
		name, path, src, want string
	}{
		{"aliased log import", kv, `package p
import l "github.com/Azure/azure-sdk-for-go/sdk/azcore/log"
func f() { l.SetListener(nil) }`, "azcore/log"},
		{"listener identifier through an unrelated import", "x/y.go", `package p
func f(l interface{ SetListener(any) }) { l.SetListener(nil) }`, "SetListener"},
		{"dot import of the log package", "x/y.go", `package p
import . "github.com/Azure/azure-sdk-for-go/sdk/azcore/log"`, "azcore/log"},
		{"verification off by negation", "x/y.go", `package p
func f(o *struct{ DisableChallengeResourceVerification bool }) { o.DisableChallengeResourceVerification = !false }`, "DisableChallengeResourceVerification"},
		{"verification off in parentheses", "x/y.go", `package p
func f(o *struct{ DisableChallengeResourceVerification bool }) { o.DisableChallengeResourceVerification = (true) }`, "DisableChallengeResourceVerification"},
		{"verification off by comparison", "x/y.go", `package p
func f(o *struct{ DisableChallengeResourceVerification bool }) { o.DisableChallengeResourceVerification = 1 == 1 }`, "DisableChallengeResourceVerification"},
		{"verification off in a literal", "x/y.go", `package p
var o = struct{ DisableChallengeResourceVerification bool }{DisableChallengeResourceVerification: true}`, "DisableChallengeResourceVerification"},
		{"cache assigned", kv, `package p
import "github.com/Azure/azure-sdk-for-go/sdk/azidentity"
var _ azidentity.ClientSecretCredentialOptions
func f(o *azidentity.ClientSecretCredentialOptions, c any) { o.Cache = c }`, "Cache"},
		{"cache in a literal", kv, `package p
import "github.com/Azure/azure-sdk-for-go/sdk/azidentity"
var _ = azidentity.ClientSecretCredentialOptions{Cache: nil}`, "Cache"},
		{"token cache package", kv, `package p
import "github.com/Azure/azure-sdk-for-go/sdk/azidentity/cache"`, "subpackage"},
		{"direct MSAL import", kv, `package p
import m "github.com/AzureAD/microsoft-authentication-library-for-go/apps/confidential"
var _ = m.New`, "MSAL"},
		{"azidentity outside its files", kv, `package p
import "github.com/Azure/azure-sdk-for-go/sdk/azidentity"
var _ = azidentity.ClientID("")`, "outside identity.go and errors.go"},
		{"environment credential", "x/y.go", `package p
import "github.com/Azure/azure-sdk-for-go/sdk/azidentity"
var _, _ = azidentity.NewDefaultAzureCredential(nil)`, "NewDefaultAzureCredential"},
		{"constructor outside identity.go", "x/y.go", `package p
import a "github.com/Azure/azure-sdk-for-go/sdk/azidentity"
var _, _ = a.NewClientSecretCredential("", "", "", nil)`, "outside identity.go"},
		{"proxy from the environment", "x/y.go", `package p
import "net/http"
var _ = http.ProxyFromEnvironment`, "ProxyFromEnvironment"},
		{"default transport under an alias", kv, `package p
import h "net/http"
var _ = h.DefaultTransport`, "default HTTP client"},
		{"a transport built outside transport.go", kv, `package p
import "net/http"
var _ = &http.Transport{}`, "http.Transport outside transport.go"},
		{"client options built outside identity.go", kv, `package p
import "github.com/Azure/azure-sdk-for-go/sdk/azcore"
var _ = azcore.ClientOptions{}`, "ClientOptions outside identity.go"},
		{"skip verify in this package", kv, `package p
import "crypto/tls"
var _ = tls.Config{InsecureSkipVerify: true}`, "InsecureSkipVerify"},
		{"unparsable file", "x/y.go", `package p func`, "does not parse"},
	}
	for _, tc := range cases {
		got := scanSource(tc.path, tc.src)
		joined := strings.Join(got, "; ")
		assert.Contains(t, joined, tc.want, tc.name)
	}
	// Clean code, and the places that legitimately hold the surface.
	assert.Empty(t, scanSource(azurekvDir+"identity.go", `package p
import "github.com/Azure/azure-sdk-for-go/sdk/azidentity"
var _, _ = azidentity.NewClientSecretCredential("", "", "", nil)`))
	assert.Empty(t, scanSource(azurekvDir+"errors.go", `package p
import "github.com/Azure/azure-sdk-for-go/sdk/azidentity"
var _ *azidentity.AuthenticationFailedError`))
	assert.Empty(t, scanSource("x/y_test.go", `package p
import "github.com/Azure/azure-sdk-for-go/sdk/azidentity"
var _, _ = azidentity.NewClientSecretCredential("", "", "", nil)`), "tests may build credentials")
	assert.Empty(t, scanSource(azurekvDir+"x.go", `package p
// DisableChallengeResourceVerification = true, SetListener, http.DefaultTransport: in a comment only
var s = "azcore/log DisableChallengeResourceVerification"`), "comments and strings are not code")
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
