package archtest

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
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
// address taken (&onSecretBytes lets a write happen elsewhere), a for-range that assigns it, or a declaration that
// gives it a value. A //go:linkname alias is found in the source text (linknamesObserver).
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
		case *ast.RangeStmt:
			if x.Tok == token.ASSIGN && ((x.Key != nil && named(x.Key)) || (x.Value != nil && named(x.Value))) {
				out = append(out, "range assignment")
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

// linknamesObserver returns "linkname" when src has a //go:linkname directive whose target is the observer: a pull
// linkname to a non-standard package still links, and gives another package a variable that aliases it.
func linknamesObserver(src, name string) []string {
	var out []string
	for _, line := range strings.Split(src, "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) >= 3 && fields[0] == "//go:linkname" && (fields[2] == name || strings.HasSuffix(fields[2], "."+name)) {
			out = append(out, "linkname")
		}
	}
	return out
}

func TestZeroingObserverIsSetOnlyByTests(t *testing.T) {
	declared, testWrites := false, 0
	for _, f := range sourceFiles(t) {
		w := append(writesObserver(f.file, observerName), linknamesObserver(f.src, observerName)...)
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
	assert.Equal(t, []string{"range assignment"}, writesObserver(parse("func f(fs []func([]byte)) { for _, onSecretBytes = range fs {} }"), observerName))
	assert.Equal(t, []string{"range assignment"}, writesObserver(parse("func f(m map[func([]byte)]int) { for onSecretBytes = range m {} }"), observerName))
	assert.Empty(t, writesObserver(parse("func f(fs []func([]byte)) { for _, onSecretBytes := range fs { _ = onSecretBytes } }"), observerName),
		"a new variable of the same name declared by the loop writes nothing")
	assert.Equal(t, []string{"linkname"}, linknamesObserver("package p\n\nimport _ \"unsafe\"\n\n//go:linkname hook alice/internal/api.onSecretBytes\nvar hook func([]byte)\n", observerName))
	assert.Equal(t, []string{"linkname"}, linknamesObserver("//go:linkname   hook\talice/internal/api.onSecretBytes", observerName))
	assert.Empty(t, linknamesObserver("// onSecretBytes is mentioned in a comment; go:linkname is elsewhere\n", observerName))
	assert.Empty(t, writesObserver(parse("var onSecretBytes func([]byte)\nfunc f(b []byte) { if onSecretBytes != nil { onSecretBytes(b) } }"), observerName))
}
