package archtest

import (
	"go/ast"
	"go/parser"
	"go/token"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The Azure provider's dial seam (Phase 5, SEC-065, A-14): the one way a harness maps the provider's
// connections to a test listener. It lives in one file that exists only with the integration tag,
// takes fixed listener addresses (never a dial function), and is called only from test files. The
// release build of the package exports nothing that names a dial, an address mapping or a fixed
// listener, so no harness (and no environment variable) can redirect a production connection.

const (
	azureDir   = "internal/providers/azurekv/"
	seamFile   = azureDir + "seam_integration.go"
	seamSymbol = "WithFixedAddresses"
)

var dialName = regexp.MustCompile(`(?i)dial|addr|fixed|listener`)

// exportedDialNames returns the exported names of a file that speak of dialling or addresses:
// top-level declarations, methods and fields of struct types.
func exportedDialNames(f *ast.File) []string {
	var out []string
	add := func(name string) {
		if ast.IsExported(name) && dialName.MatchString(name) {
			out = append(out, name)
		}
	}
	for _, d := range f.Decls {
		switch x := d.(type) {
		case *ast.FuncDecl:
			add(x.Name.Name)
		case *ast.GenDecl:
			for _, s := range x.Specs {
				switch sp := s.(type) {
				case *ast.ValueSpec:
					for _, n := range sp.Names {
						add(n.Name)
					}
				case *ast.TypeSpec:
					add(sp.Name.Name)
					if st, ok := sp.Type.(*ast.StructType); ok {
						for _, fl := range st.Fields.List {
							for _, n := range fl.Names {
								add(n.Name)
							}
						}
					}
				}
			}
		}
	}
	return out
}

// callsSymbol reports whether a file mentions the seam function by selector or by name.
func callsSymbol(f *ast.File, name string) bool {
	found := false
	ast.Inspect(f, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.SelectorExpr:
			found = found || x.Sel.Name == name
		case *ast.CallExpr:
			if id, ok := x.Fun.(*ast.Ident); ok {
				found = found || id.Name == name
			}
		}
		return !found
	})
	return found
}

func TestAzureDialSeamIsIntegrationOnly(t *testing.T) {
	var seam *goFile
	for _, f := range sourceFiles(t) {
		f := f
		if !strings.HasPrefix(f.rel, azureDir) || strings.Count(f.rel, "/") != 3 || f.test {
			continue
		}
		if f.rel == seamFile {
			seam = &f
			continue
		}
		// Every other file of the package: in the release build, and exporting no dial symbol.
		if inBuild(f.expr) {
			assert.Empty(t, exportedDialNames(f.file), "%s is in the release build and exports a dial or address symbol", f.rel)
		}
		assert.False(t, callsSymbol(f.file, seamSymbol), "%s calls %s", f.rel, seamSymbol)
	}
	require.NotNil(t, seam, "%s is missing", seamFile)
	assert.True(t, requires(seam.expr, "integration"), "%s must carry a //go:build line that requires the integration tag", seamFile)
	assert.False(t, inBuild(seam.expr), "%s is in the release build", seamFile)
	assert.False(t, inBuild(seam.expr, "e2e", "testlicense"), "%s is in the e2e build", seamFile)
	assert.ElementsMatch(t, []string{seamSymbol, "FixedAddresses", "ErrFixedAddresses", "ErrFixedAddressesNeedRoots"},
		exportedDialNames(seam.file), "the seam exports one function over fixed addresses and nothing else")
	assert.Contains(t, seam.src, "o.RootCAs == nil", "the seam refuses a missing root pool")
}

// Only test files call the seam: no non-test file of the repository (the e2e-tagged ones of cmd/alice
// included) names it outside its own file.
func TestAzureDialSeamIsCalledOnlyFromTests(t *testing.T) {
	calls := 0
	for _, f := range sourceFiles(t) {
		if f.rel == seamFile || !callsSymbol(f.file, seamSymbol) {
			continue
		}
		calls++
		assert.True(t, f.test, "%s calls %s outside a test file", f.rel, seamSymbol)
	}
	assert.Positive(t, calls, "no test calls %s; the check would prove nothing", seamSymbol)
}

func TestAzureDialSeamRulesCatchEvasions(t *testing.T) {
	parse := func(src string) *ast.File {
		f, err := parser.ParseFile(token.NewFileSet(), "x.go", "package p\n"+src, 0)
		require.NoError(t, err)
		return f
	}
	assert.Equal(t, []string{"DialAddr"}, exportedDialNames(parse("type Options struct{ DialAddr func(string) string }")))
	assert.Equal(t, []string{"WithFixedAddresses"}, exportedDialNames(parse("func WithFixedAddresses() {}")))
	assert.Equal(t, []string{"SetDialer"}, exportedDialNames(parse("type P struct{}\nfunc (P) SetDialer() {}")))
	assert.Empty(t, exportedDialNames(parse("type Options struct{ RootCAs func() }\nfunc dialAddr() {}")))
	assert.True(t, callsSymbol(parse("func f() { azurekv.WithFixedAddresses() }"), seamSymbol))
	assert.False(t, callsSymbol(parse("func f() { azurekv.New() }"), seamSymbol))
}
