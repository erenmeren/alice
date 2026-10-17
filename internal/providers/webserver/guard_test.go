package webserver

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/providers"
)

// constStrings returns name -> value of the string constants of a Go file; a value written as a
// selector (nginxconf.ReasonConfigFileWritable = helperproto.WarnConfigFileWritable) is resolved
// through lookup.
func constStrings(t *testing.T, file string, lookup map[string]string) map[string]string {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), file, nil, 0)
	require.NoError(t, err)
	out := map[string]string{}
	for _, d := range f.Decls {
		gd, ok := d.(*ast.GenDecl)
		if !ok || gd.Tok != token.CONST {
			continue
		}
		for _, sp := range gd.Specs {
			vs := sp.(*ast.ValueSpec)
			for i, n := range vs.Names {
				switch v := vs.Values[i].(type) {
				case *ast.BasicLit:
					if v.Kind == token.STRING {
						u, err := strconv.Unquote(v.Value)
						require.NoError(t, err)
						out[n.Name] = u
					}
				case *ast.SelectorExpr:
					if val, ok := lookup[v.Sel.Name]; ok {
						out[n.Name] = val
					}
				}
			}
		}
	}
	return out
}

func withPrefix(m map[string]string, prefix string) []string {
	var out []string
	for name, v := range m {
		if strings.HasPrefix(name, prefix) {
			out = append(out, v)
		}
	}
	slices.Sort(out)
	return out
}

func sorted(in []string) []string { return slices.Sorted(slices.Values(in)) }

// The vocabularies this package maps are copies of the helper's and the parser's: a value added
// there without a mapping here must fail a test, not become "unknown" silently (moved from the
// nginx provider with the dump conversion).
func TestMappedVocabulariesEqualTheirSources(t *testing.T) {
	helper := constStrings(t, "../linuxssh/helperproto/helperproto.go", nil)
	conf := constStrings(t, "../nginx/nginxconf/nginxconf.go", helper)
	reasons := withPrefix(conf, "Reason")
	// apacheconf.Reason* join the union once that package exists; until then its only reason
	// outside nginx's vocabulary, conditional, is named here.
	if _, err := os.Stat("../apacheconf/apacheconf.go"); err == nil {
		reasons = sorted(append(reasons, withPrefix(constStrings(t, "../apacheconf/apacheconf.go", helper), "Reason")...))
		reasons = slices.Compact(reasons)
	} else {
		reasons = sorted(append(reasons, providers.UnsupportedConditional))
	}
	assert.Equal(t, reasons, sorted(pairReasons), "nginxconf.Reason* and apacheconf.Reason* -> pairReasons")
	assert.Equal(t, withPrefix(helper, "ConfigErr"), sorted(configErrors), "helperproto.ConfigErr* -> configErrors")
	assert.Equal(t, withPrefix(helper, "ConfigReason"), sorted(configReasons), "helperproto.ConfigReason* -> configReasons")
	assert.Equal(t, withPrefix(helper, "File"), sorted(fileProblems), "helperproto.File* -> fileProblems")
	assert.NotContains(t, fileProblems, providers.CertProblemUnknown, "unknown is what an unmapped problem becomes")
	assert.NotContains(t, pairReasons, providers.UnsupportedUnknown, "unknown is what an unmapped reason becomes, not a helper value")
}
