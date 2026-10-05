package archtest

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The zeroing observer of the API (internal/api, onSecretBytes) sees every slice a secret field or a decoded PFX
// was copied into, so a test can check that each one was zeroed. Production code must never set it: a function
// assigned there would receive every client secret, private key and PFX the API decodes. Only _test.go files may
// assign it; it is declared without a value.

const (
	observerDir  = "internal/api/"
	observerName = "onSecretBytes"
)

// writesObserver returns where a file writes the observer: an assignment to it (by name or as a selector), its
// address taken (&onSecretBytes lets a write happen elsewhere), or a declaration that gives it a value.
func writesObserver(f *ast.File, name string) []string {
	var out []string
	named := func(e ast.Expr) bool {
		switch x := ast.Unparen(e).(type) {
		case *ast.Ident:
			return x.Name == name
		case *ast.SelectorExpr:
			return x.Sel.Name == name
		}
		return false
	}
	ast.Inspect(f, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.AssignStmt:
			for _, l := range x.Lhs {
				if named(l) {
					out = append(out, "assignment")
				}
			}
		case *ast.UnaryExpr:
			if x.Op == token.AND && named(x.X) {
				out = append(out, "address")
			}
		case *ast.ValueSpec:
			for i, id := range x.Names {
				if id.Name == name && i < len(x.Values) {
					out = append(out, "initial value")
				}
			}
		}
		return true
	})
	return out
}

func TestZeroingObserverIsSetOnlyByTests(t *testing.T) {
	declared, testWrites := false, 0
	for _, f := range sourceFiles(t) {
		w := writesObserver(f.file, observerName)
		if f.test {
			testWrites += len(w)
			continue
		}
		assert.Empty(t, w, "%s writes %s outside a test file", f.rel, observerName)
		if len(f.rel) > len(observerDir) && f.rel[:len(observerDir)] == observerDir {
			for _, d := range f.file.Decls {
				if g, ok := d.(*ast.GenDecl); ok && g.Tok == token.VAR {
					for _, s := range g.Specs {
						for _, id := range s.(*ast.ValueSpec).Names {
							declared = declared || id.Name == observerName
						}
					}
				}
			}
		}
	}
	require.True(t, declared, "%s is no longer declared in %s: move this check with it", observerName, observerDir)
	assert.Positive(t, testWrites, "no test sets %s; the check would prove nothing", observerName)
}

func TestZeroingObserverRuleCatchesEvasions(t *testing.T) {
	parse := func(src string) *ast.File {
		f, err := parser.ParseFile(token.NewFileSet(), "x.go", "package p\n"+src, 0)
		require.NoError(t, err)
		return f
	}
	assert.Equal(t, []string{"assignment"}, writesObserver(parse("func f() { onSecretBytes = func([]byte) {} }"), observerName))
	assert.Equal(t, []string{"assignment"}, writesObserver(parse("func f() { (onSecretBytes) = nil }"), observerName))
	assert.Equal(t, []string{"assignment"}, writesObserver(parse("func f() { api.onSecretBytes = nil }"), observerName))
	assert.Equal(t, []string{"assignment"}, writesObserver(parse("func f() { var x int; x, onSecretBytes = 1, nil; _ = x }"), observerName))
	assert.Equal(t, []string{"address"}, writesObserver(parse("func f() { p := &onSecretBytes; *p = nil }"), observerName))
	assert.Equal(t, []string{"initial value"}, writesObserver(parse("var onSecretBytes = func([]byte) {}"), observerName))
	assert.Equal(t, []string{"initial value"}, writesObserver(parse("func init() {}\nvar a, onSecretBytes = 1, func([]byte) {}"), observerName))
	assert.Empty(t, writesObserver(parse("var onSecretBytes func([]byte)\nfunc f(b []byte) { if onSecretBytes != nil { onSecretBytes(b) } }"), observerName))
}
