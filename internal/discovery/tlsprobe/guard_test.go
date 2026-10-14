package tlsprobe

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
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
}

// skippedDirs are not this repository's sources: VCS data, dependencies, agent worktrees and
// working files, fuzz corpora.
var skippedDirs = map[string]bool{".git": true, "node_modules": true, "vendor": true, ".claude": true,
	".superpowers": true, "worktrees": true, ".worktrees": true, "dist": true, "testdata": true}

func TestInsecureSkipVerifyOnlyInTheAllowedSites(t *testing.T) {
	root := moduleRoot(t)
	found := map[string]int{}
	scanned := 0
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if skippedDirs[d.Name()] && path != root {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		b, err := os.ReadFile(path) //nolint:gosec // G304: walking this repository's own sources
		if err != nil {
			return err
		}
		scanned++
		n, perr := countSkipVerify(rel, string(b))
		if perr != nil {
			t.Errorf("%s does not parse: %v", rel, perr)
		}
		if n > 0 {
			found[rel] = n
		}
		return nil
	})
	require.NoError(t, err)
	assert.Greater(t, scanned, 300, "the walk saw the repository")
	assert.Equal(t, allowedSkipVerify, found, "%s may appear only in %s (in %s) and the three pinned production sites, once each",
		skipVerify, probeFile, probeFunc)
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
	// Calls and selectors.
	tlsConns := map[string]bool{}
	ast.Inspect(f, func(n ast.Node) bool {
		as, ok := n.(*ast.AssignStmt)
		if !ok || len(as.Rhs) != 1 {
			return true
		}
		if call, ok := as.Rhs[0].(*ast.CallExpr); ok {
			if sel, ok := call.Fun.(*ast.SelectorExpr); ok && isPkg(sel.X, "crypto/tls") && sel.Sel.Name == "Client" {
				for _, l := range as.Lhs {
					if id, ok := l.(*ast.Ident); ok {
						tlsConns[id.Name] = true
					}
				}
			}
		}
		return true
	})
	configLits := 0
	allowedIdents := map[*ast.Ident]bool{}
	ast.Inspect(f, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.AssignStmt:
			if call, ok := x.Rhs[0].(*ast.CallExpr); ok && len(x.Rhs) == 1 {
				if sel, ok := call.Fun.(*ast.SelectorExpr); ok && isPkg(sel.X, "crypto/tls") && sel.Sel.Name == "Client" {
					for _, l := range x.Lhs {
						if id, ok := l.(*ast.Ident); ok {
							allowedIdents[id] = true
						}
					}
				}
			}
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
