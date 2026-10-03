package nginx

import (
	"go/ast"
	"go/parser"
	"go/token"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/providers"
	"alice/internal/providers/nginx/nginxconf"
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

func withPrefix(m map[string]string, prefixes ...string) []string {
	var out []string
	for name, v := range m {
		for _, p := range prefixes {
			if strings.HasPrefix(name, p) {
				out = append(out, v)
			}
		}
	}
	slices.Sort(out)
	return out
}

func sorted(in []string) []string { return slices.Sorted(slices.Values(in)) }

func sources(t *testing.T) (helper, conf map[string]string) {
	t.Helper()
	helper = constStrings(t, "../linuxssh/helperproto/helperproto.go", nil)
	conf = constStrings(t, "nginxconf/nginxconf.go", helper)
	return helper, conf
}

// The vocabularies this package maps are copies of the helper's and the parser's: a value added
// there without a mapping here must fail a test, not become "unknown" silently.
func TestMappedVocabulariesEqualTheirSources(t *testing.T) {
	helper, conf := sources(t)
	assert.Equal(t, withPrefix(conf, "Reason"), sorted(pairReasons), "nginxconf.Reason* -> pairReasons")
	assert.Equal(t, withPrefix(helper, "ConfigErr"), sorted(configErrors), "helperproto.ConfigErr* -> configErrors")
	assert.Equal(t, withPrefix(helper, "ConfigReason"), sorted(configReasons), "helperproto.ConfigReason* -> configReasons")
	assert.Equal(t, withPrefix(helper, "File"), sorted(fileProblems), "helperproto.File* -> fileProblems")
	assert.NotContains(t, fileProblems, providers.CertProblemUnknown, "unknown is what an unmapped problem becomes")
	assert.NotContains(t, pairReasons, providers.UnsupportedUnknown, "unknown is what an unmapped reason becomes, not a helper value")
}

// Every reason of the parser is carried through the real emulator and parser, with the raw text
// that makes the parser arrive at it; a reason without raw text here fails.
func TestEveryParserReasonIsCoveredByTheDiscoverTest(t *testing.T) {
	_, conf := sources(t)
	for _, reason := range withPrefix(conf, "Reason") {
		_, ok := unsupportedRaws[reason]
		assert.True(t, ok, "no emulator raw text for the reason %q: extend unsupportedRaws", reason)
	}
	assert.Len(t, unsupportedRaws, len(withPrefix(conf, "Reason")), "no stale entry")
	assert.Equal(t, nginxconf.ReasonVariable, providers.UnsupportedVariable)
}
