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
	pkcs12Path     = "software.sslmate.com/src/go-pkcs12"
	sdkPrefix      = "github.com/Azure/azure-sdk-for-go/sdk/"
	azcorePath     = sdkPrefix + "azcore"
	azcorePolicy   = azcorePath + "/policy"
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
		if im.Name != nil && im.Name.Name == "." && !isTest && (p == "net/http" || strings.HasPrefix(p, sdkPrefix)) {
			add("dot-imports " + p)
		}
		if inKV && p == pkcs12Path {
			add("imports go-pkcs12: the provider never decodes a PFX (the caller states the leaf's thumbprint)")
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
	// Syntax facts the identifier rules need: which selectors are called, which name a parameter's
	// type, and which SDK option literals are the guarded argument of a NewClient call in kvapi.go.
	callFuns := map[*ast.SelectorExpr]bool{}
	paramTypes := map[*ast.SelectorExpr]bool{}
	guardedLits := map[*ast.SelectorExpr]bool{}
	ast.Inspect(f, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.CallExpr:
			if sel, ok := x.Fun.(*ast.SelectorExpr); ok {
				callFuns[sel] = true
			}
		}
		return true
	})
	for _, decl := range f.Decls {
		params := map[string]bool{}
		if x, ok := decl.(*ast.FuncDecl); ok && x.Type.Params != nil {
			for _, fld := range x.Type.Params.List {
				for _, nm := range fld.Names {
					params[nm.Name] = true
				}
				ast.Inspect(fld.Type, func(m ast.Node) bool {
					if sel, ok := m.(*ast.SelectorExpr); ok {
						paramTypes[sel] = true
					}
					return true
				})
			}
		}
		ast.Inspect(decl, func(m ast.Node) bool {
			c, ok := m.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := c.Fun.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "NewClient" {
				return true
			}
			if id, ok := sel.X.(*ast.Ident); !ok || !strings.HasPrefix(imports[id.Name], sdkPrefix) || rel != azurekvDir+"kvapi.go" {
				return true
			}
			// the options argument must be &X.ClientOptions{ClientOptions: <a parameter>}
			if len(c.Args) >= 3 {
				if lit := guardedOptions(c.Args[len(c.Args)-1], params); lit != nil {
					guardedLits[lit] = true
					return true
				}
			}
			add("builds an SDK client without options from the guarded constructor (a nil, local or unrelated options value)")
			return true
		})
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
			id, ok := x.X.(*ast.Ident)
			if !ok {
				break
			}
			p := imports[id.Name]
			if inKV && p == "net/http" {
				switch x.Sel.Name {
				case "DefaultClient", "DefaultTransport", "Get", "Post", "PostForm", "Head":
					add("uses the default HTTP client: http." + x.Sel.Name)
				case "Client", "Transport":
					if rel != azurekvDir+"transport.go" {
						add("references http." + x.Sel.Name + " outside transport.go")
					}
				}
			}
			if isTest {
				break
			}
			isSDK := strings.HasPrefix(p, sdkPrefix)
			switch {
			case isSDK && x.Sel.Name == "NewClient":
				switch {
				case rel != azurekvDir+"kvapi.go":
					add("builds an SDK client outside kvapi.go: " + id.Name + ".NewClient")
				case !callFuns[x]:
					add("uses an SDK client constructor as a value: " + id.Name + ".NewClient")
				}
			case x.Sel.Name == "ClientOptions" && (p == azcorePath || p == azcorePolicy):
				// identity.go builds the guarded options; kvapi.go only names the type of its parameter.
				if rel != azurekvDir+"identity.go" && (rel != azurekvDir+"kvapi.go" || !paramTypes[x]) {
					add("references " + id.Name + ".ClientOptions outside identity.go")
				}
			case x.Sel.Name == "ClientOptions" && isSDK:
				if rel != azurekvDir+"kvapi.go" || !guardedLits[x] {
					add("references " + id.Name + ".ClientOptions outside the guarded client construction of kvapi.go")
				}
			case x.Sel.Name == "NewPipeline" && strings.HasSuffix(p, "/azcore/runtime"):
				add("builds an SDK pipeline: " + id.Name + ".NewPipeline")
			}
		case *ast.CallExpr:
			if fn, ok := x.Fun.(*ast.Ident); ok && fn.Name == "newSDKAPI" && !isTest && inKV {
				if len(x.Args) < 3 || !isCallTo(x.Args[2], "clientOptions") {
					add("newSDKAPI is not given the options of clientOptions(...)")
				}
			}
		}
		return true
	})
	return out
}

// guardedOptions returns the type selector of &X.ClientOptions{ClientOptions: <param>}, or nil.
func guardedOptions(e ast.Expr, params map[string]bool) *ast.SelectorExpr {
	u, ok := e.(*ast.UnaryExpr)
	if !ok || u.Op != token.AND {
		return nil
	}
	lit, ok := u.X.(*ast.CompositeLit)
	if !ok || len(lit.Elts) != 1 {
		return nil
	}
	sel, ok := lit.Type.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "ClientOptions" {
		return nil
	}
	kv, ok := lit.Elts[0].(*ast.KeyValueExpr)
	if !ok {
		return nil
	}
	if k, ok := kv.Key.(*ast.Ident); !ok || k.Name != "ClientOptions" {
		return nil
	}
	if v, ok := kv.Value.(*ast.Ident); !ok || !params[v.Name] {
		return nil
	}
	return sel
}

func isCallTo(e ast.Expr, name string) bool {
	c, ok := e.(*ast.CallExpr)
	if !ok {
		return false
	}
	id, ok := c.Fun.(*ast.Ident)
	return ok && id.Name == name
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
		{"policy client options anywhere", "x/y.go", `package p
import "github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
var _ = &policy.ClientOptions{}`, "ClientOptions outside identity.go"},
		{"policy client options under an alias, in another file of the package", kv, `package p
import p "github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
var _ = p.ClientOptions{}`, "ClientOptions outside identity.go"},
		{"an SDK client outside kvapi.go", kv, `package p
import "github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azcertificates"
var _, _ = azcertificates.NewClient("u", nil, nil)`, "outside kvapi.go"},
		{"an SDK client in another package", "internal/x/y.go", `package p
import k "github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
var _, _ = k.NewClient("u", nil, &k.ClientOptions{})`, "outside kvapi.go"},
		{"an SDK client without options in kvapi.go", azurekvDir + "kvapi.go", `package p
import "github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"
var _, _ = azsecrets.NewClient("u", nil, nil)`, "without options from the guarded constructor"},
		{"var of http.Client", kv, `package p
import "net/http"
var c http.Client`, "http.Client outside transport.go"},
		{"http.Client as a struct field", kv, `package p
import "net/http"
type t struct{ c *http.Client }`, "http.Client outside transport.go"},
		{"a slice of http.Transport", kv, `package p
import "net/http"
var _ = []http.Transport{{}}`, "http.Transport outside transport.go"},
		{"a client constructor as a value", "x/y.go", `package p
import "github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azcertificates"
var mk = azcertificates.NewClient`, "outside kvapi.go"},
		{"a client constructor as a value in kvapi.go", azurekvDir + "kvapi.go", `package p
import "github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azcertificates"
var mk = azcertificates.NewClient`, "as a value"},
		{"a var of azcore.ClientOptions", kv, `package p
import "github.com/Azure/azure-sdk-for-go/sdk/azcore"
var o azcore.ClientOptions`, "ClientOptions outside identity.go"},
		{"azcore.ClientOptions as a var in kvapi.go", azurekvDir + "kvapi.go", `package p
import "github.com/Azure/azure-sdk-for-go/sdk/azcore"
func f() { var o azcore.ClientOptions; _ = o }`, "ClientOptions outside identity.go"},
		{"SDK client options as a var elsewhere", "x/y.go", `package p
import "github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azcertificates"
var o azcertificates.ClientOptions`, "guarded client construction"},
		{"SDK client options as a var in kvapi.go", azurekvDir + "kvapi.go", `package p
import "github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
var o azkeys.ClientOptions`, "guarded client construction"},
		{"a pipeline built by hand", kv, `package p
import "github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
var _ = runtime.NewPipeline`, "NewPipeline"},
		{"a pipeline through an alias in another package", "x/y.go", `package p
import r "github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
var _ = r.NewPipeline`, "NewPipeline"},
		{"the SDK options built elsewhere in kvapi.go", azurekvDir + "kvapi.go", `package p
import "github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azcertificates"
func f(opts int) { o := &azcertificates.ClientOptions{}; _, _ = azcertificates.NewClient("u", nil, o) }`, "guarded"},
		{"a nil options variable in kvapi.go", azurekvDir + "kvapi.go", `package p
import "github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
func f() { var o *azkeys.ClientOptions; _, _ = azkeys.NewClient("u", nil, o) }`, "without options from the guarded constructor"},
		{"options with another value than the parameter", azurekvDir + "kvapi.go", `package p
import "github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
func f(opts int) { _, _ = azkeys.NewClient("u", nil, &azkeys.ClientOptions{ClientOptions: other}) }`, "without options from the guarded constructor"},
		{"newSDKAPI given other options", azurekvDir + "provider.go", `package p
func f() { _, _ = newSDKAPI(v, c, opts, r) }`, "newSDKAPI"},
		{"a dot import of net/http", kv, `package p
import . "net/http"
var _ = Client{}`, "dot-imports"},
		{"an http.Client literal in the package", kv, `package p
import "net/http"
var _ = &http.Client{}`, "http.Client outside transport.go"},
		{"new(http.Transport) in the package", kv, `package p
import h "net/http"
var _ = new(h.Transport)`, "http.Transport outside transport.go"},
		{"new(http.Client) in the package", kv, `package p
import "net/http"
var _ = new(http.Client)`, "http.Client outside transport.go"},
		{"skip verify in this package", kv, `package p
import "crypto/tls"
var _ = tls.Config{InsecureSkipVerify: true}`, "InsecureSkipVerify"},
		{"the provider decoding a PFX", kv, `package p
import "software.sslmate.com/src/go-pkcs12"
var _ = pkcs12.DecodeChain`, "go-pkcs12"},
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
	assert.Empty(t, scanSource(azurekvDir+"kvapi.go", `package p
import (
	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azcertificates"
)
func newSDKAPI(opts azcore.ClientOptions) { _, _ = azcertificates.NewClient("u", nil, &azcertificates.ClientOptions{ClientOptions: opts}) }`), "kvapi.go builds the clients from the guarded options")
	assert.Empty(t, scanSource(azurekvDir+"provider.go", `package p
func f() { _, _ = newSDKAPI(v, c, clientOptions(t), r) }`))
	assert.Empty(t, scanSource(azurekvDir+"transport.go", `package p
import "net/http"
var _ = &http.Client{}
var _ = new(http.Transport)`), "transport.go builds the HTTP clients")
	assert.Empty(t, scanSource(azurekvDir+"identity.go", `package p
import "github.com/Azure/azure-sdk-for-go/sdk/azcore"
var _ = azcore.ClientOptions{}`), "identity.go builds the options")
	assert.Empty(t, scanSource(azurekvDir+"x_test.go", `package p
import "software.sslmate.com/src/go-pkcs12"
var _ = pkcs12.Modern`), "tests build PFX files")
	assert.Empty(t, scanSource("internal/certs/x.go", `package p
import "software.sslmate.com/src/go-pkcs12"
var _ = pkcs12.Modern`), "only azurekv is held to it")
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
