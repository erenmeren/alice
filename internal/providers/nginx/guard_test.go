package nginx

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
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

// goSources lists the repository's non-test Go files (relative, slash-separated): the files git
// knows (tracked, or untracked and not ignored), so a git-ignored tree and other worktrees under
// .claude/ (D17) are not read; without git, a walk that skips every directory whose name starts
// with "." and node_modules and bin. Either way no path with a component starting with "." counts.
func goSources(t *testing.T, root string) []string {
	t.Helper()
	var files []string
	cmd := exec.Command("git", "ls-files", "-co", "--exclude-standard", "--", "*.go")
	cmd.Dir = root
	if out, err := cmd.Output(); err == nil {
		files = strings.Split(strings.TrimSpace(string(out)), "\n")
	} else {
		err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() && p != root && (strings.HasPrefix(d.Name(), ".") || d.Name() == "node_modules" || d.Name() == "bin") {
				return filepath.SkipDir
			}
			if !d.IsDir() && filepath.Ext(p) == ".go" {
				rel, err := filepath.Rel(root, p)
				if err != nil {
					return err
				}
				files = append(files, filepath.ToSlash(rel))
			}
			return nil
		})
		require.NoError(t, err)
	}
	var out []string
	for _, f := range files {
		if f == "" || strings.HasSuffix(f, "_test.go") || slices.ContainsFunc(strings.Split(f, "/"), func(c string) bool { return strings.HasPrefix(c, ".") }) {
			continue
		}
		out = append(out, f)
	}
	return out
}

// Global constraint: helperproto.ProbeTLSConfig is the only certificate check Alice skips; both
// probes (TLSProber here, the helper's tls-probe) use it. Phase 7 adds exactly one more place, the pinned mail
// server certificate of internal/notify (pinnedTLS), whose VerifyConnection accepts only the pinned leaf. Phase 8 adds
// the last one, alice selfcheck's probe of its own listener (cmd/alice/selfcheck.go, C9), whose VerifyConnection
// accepts only the leaf of keys/tls.crt. Network discovery adds the last one, internal/discovery/tlsprobe/probe.go,
// which records the presented chain of any scanned endpoint and trusts nothing it sees.
func TestOnlyProbeTLSConfigSkipsVerification(t *testing.T) {
	root, err := filepath.Abs("../../..")
	require.NoError(t, err)
	needle := "InsecureSkip" + "Verify"
	files := goSources(t, root)
	require.Contains(t, files, "internal/providers/nginx/probe.go", "the walk sees this package")
	var found []string
	for _, f := range files {
		b, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(f))) //nolint:gosec // G304: reading the repository's own sources in a test
		if err != nil && os.IsNotExist(err) {
			continue // listed by git but deleted in the working tree
		}
		require.NoError(t, err)
		if strings.Contains(string(b), needle) {
			found = append(found, f)
		}
	}
	// internal/vconsole/store/tls.go (the vendor's own tool, not the product) only reads the field, to refuse a database
	// connection that does not verify the server certificate; it skips nothing. R59 G2 adds internal/providers/tlspin, whose
	// VerifyConnection accepts only the pinned SubjectPublicKeyInfo. R65 adds internal/providers/httpcheck, whose
	// VerifyConnection accepts only the deployed leaf.
	assert.Equal(t, []string{"cmd/alice/selfcheck.go", "internal/discovery/tlsprobe/probe.go", "internal/notify/pin.go", "internal/providers/httpcheck/httpcheck.go", "internal/providers/linuxssh/helperproto/helperproto.go",
		"internal/providers/tlspin/tlspin.go", "internal/vconsole/store/tls.go"}, found)
	tp, err := os.ReadFile(filepath.Join(root, "internal", "providers", "tlspin", "tlspin.go")) //nolint:gosec // G304: a fixed source file of the repository
	require.NoError(t, err)
	assert.Equal(t, 1, strings.Count(string(tp), needle), "tlspin skips the chain check in one place only")
	assert.Contains(t, string(tp), "cfg.VerifyConnection = v.verify", "tlspin checks the pinned identity itself")
	assert.Contains(t, string(tp), "subtle.ConstantTimeCompare(", "tlspin compares the pin")
	self, err := os.ReadFile(filepath.Join(root, "cmd", "alice", "selfcheck.go")) //nolint:gosec // G304: a fixed source file of the repository
	require.NoError(t, err)
	assert.Equal(t, 1, strings.Count(string(self), needle+":"), "selfcheck skips the chain check in one place only")
	assert.Contains(t, string(self), "VerifyConnection:", "selfcheck compares the presented leaf with keys/tls.crt")
	assert.Contains(t, string(self), "bytes.Equal(cs.PeerCertificates[0].Raw, want)")
	pin, err := os.ReadFile(filepath.Join(root, "internal", "notify", "pin.go")) //nolint:gosec // G304: a fixed source file of the repository
	require.NoError(t, err)
	assert.Equal(t, 1, strings.Count(string(pin), needle), "notify skips the chain check in one place only")
	from := strings.Index(string(pin), "func pinnedTLS(")
	require.Positive(t, from, "notify/pin.go defines pinnedTLS")
	fn := string(pin)[from:]
	end := strings.Index(fn, "\n}\n")
	require.Positive(t, end, "pinnedTLS ends")
	fn = fn[:end]
	assert.Contains(t, fn, needle, "the one place is pinnedTLS")
	assert.Contains(t, fn, "VerifyConnection:", "pinnedTLS checks the pinned leaf itself")
	assert.Contains(t, fn, "subtle.ConstantTimeCompare(", "pinnedTLS compares the pin")
	for _, f := range []string{"../tlsverify/tlsverify.go", "../../../cmd/alice-helper/probe.go"} {
		b, err := os.ReadFile(f) //nolint:gosec // G304: a fixed source file of the repository
		require.NoError(t, err)
		assert.Contains(t, string(b), "helperproto.ProbeTLSConfig(", "%s builds its TLS client from ProbeTLSConfig", f)
	}
}

// D17: other worktrees (.claude/worktrees/*) and other dot-directories are never read.
func TestGoSourcesSkipsDotDirectories(t *testing.T) {
	root := t.TempDir() // outside any git repository: the walk
	for _, f := range []string{"a/b.go", ".claude/worktrees/x/internal/c.go", "bin/d.go", "a/e_test.go", "node_modules/f.go", "a/.hidden/g.go"} {
		p := filepath.Join(root, filepath.FromSlash(f))
		require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o750))
		require.NoError(t, os.WriteFile(p, []byte("package x\n"), 0o600))
	}
	assert.Equal(t, []string{"a/b.go"}, goSources(t, root))
}
