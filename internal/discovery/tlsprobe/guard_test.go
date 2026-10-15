package tlsprobe

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The guard of the one TLS verification bypass (plan 2026-10-13-network-discovery, Global
// Constraints and amendment A6). The rules read the syntax tree, so comments and strings are not code
// and aliases or odd spellings do not evade them. The identifier is built at run time so this file
// does not match itself (it is a test file, which the walk skips anyway).
var skipVerify = "Insecure" + "SkipVerify"

const (
	probeFile  = "internal/discovery/tlsprobe/probe.go"
	probeDir   = "internal/discovery/tlsprobe/"
	probeFunc  = "CapturePresentedChain"
	nolintG402 = "//nolint:gosec // G402: discovery records the presented chain and trusts nothing"
)

// allowedSkipVerify are the only non-test Go files that may name the field, each exactly once: the
// probe, and the three production sites that existed before discovery (each compares the served
// leaf with a pinned certificate in VerifyConnection or by hand and trusts nothing else).
var allowedSkipVerify = map[string]int{
	probeFile:                1,
	"internal/notify/pin.go": 1,
	"internal/providers/linuxssh/helperproto/helperproto.go": 1,
	"cmd/alice/selfcheck.go":                                 1,
	// The vendor console (not part of the product) only reads the field, to refuse a database connection that
	// would not verify the server certificate; it skips nothing.
	"cmd/vendor-console/run.go": 1,
}

// rootSkips are the directories, by exact root-relative path, that hold other projects' Go files
// (dependencies) rather than this module's. Everywhere else only what the go tool itself ignores is
// skipped (skipDir), so a package Go compiles is never left out, whatever its directory is called.
var rootSkips = map[string]bool{"web/node_modules": true, "docs/vendor": true, "alice-design/dist": true}

// skipDir reports whether the walk leaves out the directory at rel (slash form, relative to the
// module root): what the go tool ignores (a name starting with "." or "_", and testdata, which also
// covers .git, .claude with its agent worktrees, and .superpowers) and the rootSkips.
func skipDir(rel string) bool {
	base := path.Base(rel)
	return strings.HasPrefix(base, ".") || strings.HasPrefix(base, "_") || base == "testdata" || rootSkips[rel]
}

// skipVerifySites walks the tree at root and counts InsecureSkipVerify identifiers per non-test Go
// file (root-relative slash path). It also returns how many files it read and every parse failure.
func skipVerifySites(root string) (found map[string]int, scanned int, problems []string, err error) {
	found = map[string]int{}
	err = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			if rel != "." && skipDir(rel) {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(rel, ".go") || strings.HasSuffix(rel, "_test.go") {
			return nil
		}
		b, err := os.ReadFile(p) //nolint:gosec // G304: walking this repository's own sources
		if err != nil {
			return err
		}
		scanned++
		n, perr := countSkipVerify(rel, string(b))
		if perr != nil {
			problems = append(problems, rel+" does not parse: "+perr.Error())
		}
		if n > 0 {
			found[rel] = n
		}
		return nil
	})
	return found, scanned, problems, err
}

func TestInsecureSkipVerifyOnlyInTheAllowedSites(t *testing.T) {
	found, scanned, problems, err := skipVerifySites(moduleRoot(t))
	require.NoError(t, err)
	assert.Empty(t, problems)
	assert.Greater(t, scanned, 300, "the walk saw the repository")
	assert.Equal(t, allowedSkipVerify, found, "%s may appear only in %s (in %s) and the three pinned production sites, once each",
		skipVerify, probeFile, probeFunc)
}

func TestSkipDir(t *testing.T) {
	for rel, want := range map[string]bool{
		".git": true, ".claude": true, ".claude/worktrees/agent-x/internal": true, ".superpowers": true, "_old": true,
		"internal/x/_scratch": true, ".claude/worktrees": true, "web/node_modules/x/y": true, "internal/certs/testdata": true, "testdata": true,
		"web/node_modules": true, "docs/vendor": true, "alice-design/dist": true,
		"internal": false, "internal/a/dist": false, "dist": false, "vendor": false, "node_modules": false,
		"web/src/node_modules": false, "internal/x/worktrees": false, "worktrees": false, "cmd/alice": false,
	} {
		assert.Equal(t, want, excluded(rel), rel)
	}
}

// excluded reports whether the walk leaves out rel: it or one of its ancestors is skipped.
func excluded(rel string) bool {
	for p := rel; p != "." && p != "/"; p = path.Dir(p) {
		if skipDir(p) {
			return true
		}
	}
	return false
}

// TestTheWalkOnAFixtureTree runs the walk over a temporary tree: the allowed sites alone pass; a
// violating file in another package, in a directory named dist, or a missing allowed site fails;
// skipped directories and test files do not count.
func TestTheWalkOnAFixtureTree(t *testing.T) {
	root := t.TempDir()
	write := func(rel, src string) {
		t.Helper()
		p := filepath.Join(root, filepath.FromSlash(rel))
		require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o750))
		require.NoError(t, os.WriteFile(p, []byte(src), 0o600))
	}
	site := `package p
import "crypto/tls"
var _ = &tls.Config{` + skipVerify + `: true}
`
	for rel := range allowedSkipVerify {
		write(rel, site)
	}
	ignored := []string{".claude/worktrees/agent-x/internal/notify/pin.go", "web/node_modules/pkg/x.go", "docs/vendor/x/x.go",
		"alice-design/dist/x.go", "internal/certs/testdata/x.go", "internal/_old/x.go", "internal/other/x_test.go"}
	for _, rel := range ignored {
		write(rel, site)
	}
	write("internal/other/clean.go", "package other\n")
	found, scanned, problems, err := skipVerifySites(root)
	require.NoError(t, err)
	assert.Empty(t, problems)
	assert.Equal(t, allowedSkipVerify, found, "the allowed sites alone pass; skipped trees and tests do not count")
	assert.Equal(t, len(allowedSkipVerify)+1, scanned)

	write("internal/a/dist/x.go", site) // Go compiles it: a directory called dist is not skipped
	found, _, _, err = skipVerifySites(root)
	require.NoError(t, err)
	assert.NotEqual(t, allowedSkipVerify, found)
	assert.Equal(t, 1, found["internal/a/dist/x.go"])
	require.NoError(t, os.Remove(filepath.Join(root, "internal", "a", "dist", "x.go")))

	write("internal/other/bad.go", site) // a violation in another package
	found, _, _, err = skipVerifySites(root)
	require.NoError(t, err)
	assert.NotEqual(t, allowedSkipVerify, found)
	require.NoError(t, os.Remove(filepath.Join(root, "internal", "other", "bad.go")))

	write("internal/notify/pin.go", "package notify\n") // an allowed site gone: the list must shrink
	found, _, _, err = skipVerifySites(root)
	require.NoError(t, err)
	assert.NotEqual(t, allowedSkipVerify, found)
	assert.NotContains(t, found, "internal/notify/pin.go")

	write("internal/notify/pin.go", site+"var _ = &tls.Config{"+skipVerify+": true}\n") // twice in one allowed file
	write("internal/broken/x.go", "package")
	found, _, problems, err = skipVerifySites(root)
	require.NoError(t, err)
	assert.Equal(t, 2, found["internal/notify/pin.go"])
	assert.Len(t, problems, 1, "a file that does not parse is reported")
}

// TestCountSkipVerifyForms: every spelling of the field counts; comments and strings do not.
func TestCountSkipVerifyForms(t *testing.T) {
	for name, src := range map[string]string{
		"struct-literal key": `package p; import "crypto/tls"; var _ = tls.Config{` + skipVerify + `: true}`,
		"aliased import":     `package p; import t2 "crypto/tls"; var _ = &t2.Config{` + skipVerify + `: true}`,
		"dot import":         `package p; import . "crypto/tls"; var _ = Config{` + skipVerify + `: true}`,
		"assignment":         `package p; import "crypto/tls"; func f(c *tls.Config) { c.` + skipVerify + ` = true }`,
		"read":               `package p; import "crypto/tls"; func f(c *tls.Config) bool { return c.` + skipVerify + ` }`,
		"embedded struct":    `package p; import "crypto/tls"; type w struct{ *tls.Config }; func f(x w) { x.` + skipVerify + ` = true }`,
	} {
		n, err := countSkipVerify("x.go", src)
		require.NoError(t, err, name)
		assert.Equal(t, 1, n, name)
	}
}

// countSkipVerify counts the identifiers named InsecureSkipVerify (a struct literal key, a selector,
// anything) in one Go file.
func countSkipVerify(rel, src string) (int, error) {
	f, err := parser.ParseFile(token.NewFileSet(), rel, src, parser.SkipObjectResolution)
	if err != nil {
		return 0, err
	}
	n := 0
	ast.Inspect(f, func(x ast.Node) bool {
		if id, ok := x.(*ast.Ident); ok && id.Name == skipVerify {
			n++
		}
		return true
	})
	return n, nil
}

// TestTheBypassIsOneLineOfCapturePresentedChain: in probe.go the field is set to the literal true
// inside CapturePresentedChain, on a line that carries the agreed nolint justification.
func TestTheBypassIsOneLineOfCapturePresentedChain(t *testing.T) {
	src := readProbeSource(t, "probe.go")
	assert.Empty(t, bypassProblems(src))
}

func bypassProblems(src string) []string {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, probeFile, src, parser.ParseComments|parser.SkipObjectResolution)
	if err != nil {
		return []string{"does not parse: " + err.Error()}
	}
	lines := strings.Split(src, "\n")
	var out []string
	sites := 0
	ast.Inspect(f, func(n ast.Node) bool {
		kv, ok := n.(*ast.KeyValueExpr)
		if !ok {
			return true
		}
		if k, ok := kv.Key.(*ast.Ident); !ok || k.Name != skipVerify {
			return true
		}
		sites++
		if v, ok := kv.Value.(*ast.Ident); !ok || v.Name != "true" {
			out = append(out, "the field is set to something other than the literal true")
		}
		if fn := enclosingFunc(f, kv.Pos()); fn != probeFunc {
			out = append(out, "the field is set in "+strconv.Quote(fn)+", not in "+probeFunc)
		}
		line := lines[fset.Position(kv.Pos()).Line-1]
		if !strings.HasSuffix(strings.TrimSpace(line), nolintG402) {
			out = append(out, "the line does not carry "+nolintG402)
		}
		return true
	})
	if sites != 1 {
		out = append(out, "the field is set "+strconv.Itoa(sites)+" times as a literal key, not once")
	}
	return out
}

func enclosingFunc(f *ast.File, pos token.Pos) string {
	for _, d := range f.Decls {
		if fd, ok := d.(*ast.FuncDecl); ok && fd.Pos() <= pos && pos < fd.End() {
			return fd.Name.Name
		}
	}
	return ""
}

// TestProbePackageSurface: the package never sends application bytes, never dials by itself and
// never hands out a TLS configuration.
func TestProbePackageSurface(t *testing.T) {
	files, err := filepath.Glob("*.go")
	require.NoError(t, err)
	n := 0
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		n++
		for _, p := range surfaceProblems(name, readProbeSource(t, name)) {
			t.Errorf("%s: %s", name, p)
		}
	}
	assert.GreaterOrEqual(t, n, 2, "probe.go and parse.go were read")
}

// forbiddenImports: no application protocol client and no proxy. A path ending in "/" forbids its
// subtree.
var forbiddenImports = []string{"net/http", "net/http/", "net/smtp", "net/textproto", "net/rpc", "net/rpc/", "net/mail",
	"net/url", "golang.org/x/net/", "reflect", "unsafe", "os/exec"}

// forbiddenMethods: no write of any kind. The package has no .Write( call at all (the handshake's
// own messages are written by crypto/tls inside HandshakeContext).
var forbiddenMethods = map[string]bool{"Write": true, "WriteString": true, "WriteTo": true, "ReadFrom": true,
	"CloseWrite": true, "WriteMsgTCP": true}

// forbiddenFuncs: package functions that write.
var forbiddenFuncs = map[string]map[string]bool{
	"io":  {"Copy": true, "CopyN": true, "CopyBuffer": true, "WriteString": true},
	"fmt": {"Fprint": true, "Fprintf": true, "Fprintln": true},
}

// tlsConnUses are the only methods called on the tls.Client connection: no Close (it sends
// close_notify), no Write, no Read.
var tlsConnUses = map[string]bool{"HandshakeContext": true, "ConnectionState": true}

// allowedTLSFuncs are the crypto/tls functions the package calls: the client constructor and the
// name tables. Never tls.Dial, tls.Server or tls.Listen.
var allowedTLSFuncs = map[string]bool{"Client": true, "CipherSuites": true, "InsecureCipherSuites": true,
	"VersionName": true, "CipherSuiteName": true}

func surfaceProblems(rel, src string) []string {
	f, err := parser.ParseFile(token.NewFileSet(), rel, src, parser.SkipObjectResolution)
	if err != nil {
		return []string{"does not parse: " + err.Error()}
	}
	var out []string
	add := func(s string) { out = append(out, s) }
	pkgs := map[string]string{} // local name -> import path
	for _, im := range f.Imports {
		p, _ := strconv.Unquote(im.Path.Value)
		name := p[strings.LastIndex(p, "/")+1:]
		if im.Name != nil {
			name = im.Name.Name
			if name == "." || name == "_" {
				add("imports " + p + " as " + name)
			}
		}
		pkgs[name] = p
		for _, fb := range forbiddenImports {
			if p == fb || (strings.HasSuffix(fb, "/") && strings.HasPrefix(p, fb)) {
				add("imports " + p)
			}
		}
	}
	isPkg := func(e ast.Expr, path string) bool {
		id, ok := e.(*ast.Ident)
		return ok && pkgs[id.Name] == path
	}
	isTLSConfig := func(e ast.Expr) bool {
		sel, ok := e.(*ast.SelectorExpr)
		return ok && sel.Sel.Name == "Config" && isPkg(sel.X, "crypto/tls")
	}
	mentionsTLSConfig := func(n ast.Node) bool {
		found := false
		if n == nil {
			return false
		}
		ast.Inspect(n, func(x ast.Node) bool {
			if e, ok := x.(ast.Expr); ok && isTLSConfig(e) {
				found = true
			}
			return !found
		})
		return found
	}
	// The exported surface and the package-level state never hold a *tls.Config.
	for _, d := range f.Decls {
		switch x := d.(type) {
		case *ast.FuncDecl:
			if x.Name.IsExported() && mentionsTLSConfig(x.Type) {
				add("exported " + x.Name.Name + " has a tls.Config in its signature")
			}
		case *ast.GenDecl:
			for _, s := range x.Specs {
				switch sp := s.(type) {
				case *ast.ValueSpec:
					if mentionsTLSConfig(sp) {
						add("a package-level variable holds a tls.Config")
					}
				case *ast.TypeSpec:
					if mentionsTLSConfig(sp.Type) {
						add("type " + sp.Name.Name + " holds a tls.Config")
					}
				}
			}
		}
	}
	// The tls.Client(...) result: it may only be bound to one name (an assignment or a var
	// declaration) or have HandshakeContext or ConnectionState called on it directly.
	isTLSClient := func(e ast.Expr) bool {
		call, ok := e.(*ast.CallExpr)
		if !ok {
			return false
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		return ok && isPkg(sel.X, "crypto/tls") && sel.Sel.Name == "Client"
	}
	tlsConns := map[string]bool{}
	allowedIdents := map[*ast.Ident]bool{}
	bind := func(id *ast.Ident) {
		tlsConns[id.Name] = true
		allowedIdents[id] = true
	}
	const escapes = "the TLS connection escapes: tls.Client(...) is used other than by binding it to one name or calling HandshakeContext or ConnectionState"
	var stack []ast.Node
	ast.Inspect(f, func(n ast.Node) bool {
		if n == nil {
			stack = stack[:len(stack)-1]
			return true
		}
		if e, ok := n.(ast.Expr); ok && isTLSClient(e) {
			switch p := stack[len(stack)-1].(type) {
			case *ast.AssignStmt:
				if id, ok := p.Lhs[0].(*ast.Ident); ok && len(p.Lhs) == 1 && len(p.Rhs) == 1 {
					bind(id)
				} else {
					add(escapes)
				}
			case *ast.ValueSpec:
				if len(p.Names) == 1 && len(p.Values) == 1 {
					bind(p.Names[0])
				} else {
					add(escapes)
				}
			case *ast.SelectorExpr:
				if !tlsConnUses[p.Sel.Name] {
					add("calls ." + p.Sel.Name + " on the TLS connection")
				}
			default:
				add(escapes)
			}
		}
		stack = append(stack, n)
		return true
	})
	configLits := 0
	ast.Inspect(f, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.CompositeLit:
			if isTLSConfig(x.Type) {
				configLits++
				if fn := enclosingFunc(f, x.Pos()); fn != probeFunc {
					add("a tls.Config is built in " + strconv.Quote(fn) + ", not in " + probeFunc)
				}
			}
		case *ast.CallExpr:
			sel, ok := x.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if forbiddenMethods[sel.Sel.Name] {
				add("calls ." + sel.Sel.Name + "(")
			}
			if id, ok := sel.X.(*ast.Ident); ok {
				if fs := forbiddenFuncs[pkgs[id.Name]]; fs[sel.Sel.Name] {
					add("calls " + pkgs[id.Name] + "." + sel.Sel.Name)
				}
			}
			if isPkg(sel.X, "crypto/tls") && !allowedTLSFuncs[sel.Sel.Name] {
				add("calls tls." + sel.Sel.Name)
			}
		case *ast.SelectorExpr:
			id, ok := x.X.(*ast.Ident)
			if !ok {
				return true
			}
			if tlsConns[id.Name] {
				allowedIdents[id] = true
				if !tlsConnUses[x.Sel.Name] {
					add("calls ." + x.Sel.Name + " on the TLS connection")
				}
			}
			if pkgs[id.Name] != "" {
				name := x.Sel.Name
				if strings.Contains(name, "Dial") || strings.Contains(name, "Listen") || strings.Contains(name, "Proxy") ||
					name == "ScanControl" {
					add("uses " + pkgs[id.Name] + "." + name + ": the probe dials only through the caller's DialFunc")
				}
			}
		}
		return true
	})
	// The TLS connection never escapes: every other use of its name (an argument, a return value, an
	// assignment) is refused.
	ast.Inspect(f, func(n ast.Node) bool {
		if id, ok := n.(*ast.Ident); ok && tlsConns[id.Name] && !allowedIdents[id] {
			add("the TLS connection is used other than by calling HandshakeContext or ConnectionState")
		}
		return true
	})
	if strings.HasSuffix(rel, "probe.go") && configLits != 1 {
		add("probe.go builds " + strconv.Itoa(configLits) + " tls.Config values, not one")
	}
	if !strings.HasSuffix(rel, "probe.go") && configLits != 0 {
		add("a tls.Config outside probe.go")
	}
	return out
}

// TestGuardRulesCatchViolations proves each rule fires on a small source that breaks it, and stays
// quiet on comments, strings and the allowed forms.
func TestGuardRulesCatchViolations(t *testing.T) {
	bad := map[string]string{
		"imports net/http":               `package p; import _ "net/http"`,
		"imports net/smtp":               `package p; import "net/smtp"; var _ = smtp.SendMail`,
		"imports net/textproto":          `package p; import "net/textproto"; var _ textproto.MIMEHeader`,
		"imports golang.org/x/net/proxy": `package p; import "golang.org/x/net/proxy"; var _ = proxy.Direct`,
		"calls .Write(":                  `package p; import "net"; func f(c net.Conn) { _, _ = c.Write(nil) }`,
		"calls .WriteString(":            `package p; import "bufio"; func f(w *bufio.Writer) { _, _ = w.WriteString("") }`,
		"calls io.Copy":                  `package p; import ("io"; "net"); func f(c net.Conn, r io.Reader) { _, _ = io.Copy(c, r) }`,
		"calls fmt.Fprintf":              `package p; import ("fmt"; "net"); func f(c net.Conn) { fmt.Fprintf(c, "x") }`,
		"uses net.Dialer":                `package p; import "net"; var d net.Dialer`,
		"uses net.Dial:":                 `package p; import "net"; func f() { _, _ = net.Dial("tcp", "x") }`,
		"uses net.DialTimeout":           `package p; import "net"; func f() { _, _ = net.DialTimeout("tcp", "x", 0) }`,
		"uses crypto/tls.Dial":           `package p; import "crypto/tls"; func f() { _, _ = tls.Dial("tcp", "x", nil) }`,
		"uses alice/internal/platform/netaddr.ScanDialContext": `package p; import "alice/internal/platform/netaddr"; var _ = netaddr.ScanDialContext`,
		"exported New has a tls.Config":                        `package p; import "crypto/tls"; func New() *tls.Config { return nil }`,
		"a package-level variable holds a tls.Config":          `package p; import "crypto/tls"; var cfg *tls.Config`,
		"type Holder holds a tls.Config":                       `package p; import "crypto/tls"; type Holder struct{ C *tls.Config }`,
		"a tls.Config is built in \"helper\"":                  `package p; import "crypto/tls"; func helper() { _ = &tls.Config{} }`,
		"calls .Close on the TLS connection":                   `package p; import ("crypto/tls"; "net"); func f(c net.Conn) { tc := tls.Client(c, nil); _ = tc.Close() }`,
		"the TLS connection is used other":                     `package p; import ("crypto/tls"; "net"); func g(net.Conn) {}; func f(c net.Conn) { tc := tls.Client(c, nil); g(tc) }`,
		"calls tls.Server":                                     `package p; import ("crypto/tls"; "net"); func f(c net.Conn) { _ = tls.Server(c, nil) }`,
		"imports net as .":                                     `package p; import . "net"; var _ Conn`,
	}
	for want, src := range bad {
		got := strings.Join(surfaceProblems("internal/discovery/tlsprobe/x.go", src), "\n")
		assert.Contains(t, got, want, "source %q", src)
	}
	// The same rules through aliased imports, and every way the TLS connection could be reached.
	const conn = `package p; import ("crypto/tls"; "net"); func g(any) {}; `
	for _, tc := range []struct{ want, src string }{
		{"exported New has a tls.Config", `package p; import t2 "crypto/tls"; func New() *t2.Config { return nil }`},
		{"a tls.Config is built in \"f\"", `package p; import t2 "crypto/tls"; func f() { _ = t2.Config{} }`},
		{"uses net.Dial", `package p; import n "net"; func f() { _, _ = n.Dial("tcp", "x") }`},
		{"imports net/http", `package p; import h "net/http"; var _ = h.Get`},
		{"calls .Close on the TLS connection", `package p; import ("net"; t2 "crypto/tls"); func f(c net.Conn) { tc := t2.Client(c, nil); _ = tc.Close() }`},
		{"calls .Close on the TLS connection", conn + `func f(c net.Conn) { var tc = tls.Client(c, nil); _ = tc.Close() }`},
		{"calls .Close on the TLS connection", conn + `func f(c net.Conn) { _ = tls.Client(c, nil).Close() }`},
		{"calls .Write on the TLS connection", conn + `func f(c net.Conn) { _, _ = tls.Client(c, nil).Write(nil) }`},
		{"calls .Read on the TLS connection", conn + `func f(c net.Conn) { var tc *tls.Conn; tc = tls.Client(c, nil); _, _ = tc.Read(nil) }`},
		{"the TLS connection escapes", conn + `func f(c net.Conn) { g(tls.Client(c, nil)) }`},
		{"the TLS connection escapes", conn + `func f(c net.Conn) *tls.Conn { return tls.Client(c, nil) }`},
		{"the TLS connection escapes", conn + `func f(c net.Conn) { a, b := tls.Client(c, nil), 1; _, _ = a, b }`},
		{"the TLS connection escapes", conn + `type h struct{ c *tls.Conn }; func f(c net.Conn, x *h) { x.c = tls.Client(c, nil) }`},
		{"the TLS connection escapes", conn + `func f(c net.Conn) { _ = (tls.Client(c, nil)).Close() }`},
		{"the TLS connection is used other", conn + `func f(c net.Conn) { var tc = tls.Client(c, nil); g(tc) }`},
	} {
		got := strings.Join(surfaceProblems("internal/discovery/tlsprobe/x.go", tc.src), "\n")
		assert.Contains(t, got, tc.want, "source %q", tc.src)
	}
	assert.Empty(t, surfaceProblems("internal/discovery/tlsprobe/x.go", `package p
import ("context"; "crypto/tls"; "net")
func f(ctx context.Context, c net.Conn) {
	tc := tls.Client(c, nil)
	_ = tc.HandshakeContext(ctx)
	_ = tc.ConnectionState()
	var tc2 = tls.Client(c, nil)
	_ = tc2.ConnectionState()
	_ = tls.Client(c, nil).HandshakeContext(ctx)
}`), "the allowed uses pass")
	assert.Empty(t, surfaceProblems("internal/discovery/tlsprobe/x.go", `package p
import ("crypto/tls"; "net")
// c.Write(nil), net.Dial, tls.Config, net/http: comments are not code
var s = "net.Dialer c.Write( tls.Config"
func capture(c net.Conn) { _ = c.Close(); _ = tls.VersionName(0) }`))

	bypass := map[string]string{
		"not in CapturePresentedChain": `package p; import "crypto/tls"; func other() { _ = &tls.Config{` + skipVerify + `: true, ` + "\n" + `} }`,
		"literal true":                 `package p; import "crypto/tls"; var b = true; func CapturePresentedChain() { _ = &tls.Config{` + skipVerify + `: b, ` + nolintG402 + "\n" + `} }`,
		"does not carry":               `package p; import "crypto/tls"; func CapturePresentedChain() { _ = &tls.Config{` + skipVerify + `: true, // G402` + "\n" + `} }`,
		"0 times":                      `package p; func CapturePresentedChain() {}`,
		"0 times as a literal key":     `package p; import "crypto/tls"; func CapturePresentedChain(c *tls.Config) { c.` + skipVerify + ` = true ` + nolintG402 + "\n" + `}`,
		"2 times": `package p; import "crypto/tls"; func CapturePresentedChain() { _ = &tls.Config{` + skipVerify + `: true, ` + nolintG402 + "\n" +
			`}; _ = &tls.Config{` + skipVerify + `: true, ` + nolintG402 + "\n" + `} }`,
	}
	for want, src := range bypass {
		assert.Contains(t, strings.Join(bypassProblems(src), "\n"), want, "source %q", src)
	}
	assert.Empty(t, bypassProblems(`package p; import "crypto/tls"; func CapturePresentedChain() { _ = &tls.Config{`+skipVerify+`: true, `+nolintG402+"\n"+`} }`))

	n, err := countSkipVerify("x.go", `package p; import "crypto/tls"; func f(c *tls.Config) { c.`+skipVerify+` = true }
// `+skipVerify+` in a comment
var s = "`+skipVerify+`"`)
	require.NoError(t, err)
	assert.Equal(t, 1, n, "a selector assignment counts; comments and strings do not")
	_, err = countSkipVerify("x.go", "package")
	assert.Error(t, err)
}

// TestResultCarriesNoVerdict: nothing the package returns says "verified", "trusted" or "valid".
func TestResultCarriesNoVerdict(t *testing.T) {
	for _, typ := range []reflect.Type{reflect.TypeFor[Result](), reflect.TypeFor[Chain](), reflect.TypeFor[Certificate]()} {
		for i := range typ.NumField() {
			assert.NotRegexp(t, `(?i)verif|trust|valid|ok`, typ.Field(i).Name, typ.Name())
		}
	}
}

func readProbeSource(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(name) //nolint:gosec // G304: this package's own sources
	require.NoError(t, err)
	return string(b)
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
