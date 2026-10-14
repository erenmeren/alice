package discovery

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// The egress guard of the scanner (ledger carry C2, Review Focus 1): discovery's own code (not its tests; tlsprobe has
// its own guard, which forbids every dial) opens connections in exactly one place, scan.dialer in scanner.go, with a
// plain net.Dialer through netaddr.ScanDialContext. No HTTP client or transport, no proxy or SOCKS dialer, no other
// net.Dial*, net.Listen*, tls.Dial*, netaddr.DialContext or ScanControl, no Dial/Proxy/Control hook set on anything.
// AST-based: comments and strings are not code.

// dialSite is the one function allowed to build a dialer.
const dialSite = "scanner.go:dialer"

var forbiddenImports = []string{"net/http", "net/url", "net/smtp", "net/rpc", "net/textproto", "net/mail", "crypto/tls",
	"golang.org/x/net/proxy", "golang.org/x/net/http", "golang.org/x/net/http2", "syscall", "os/exec", "unsafe", "reflect"}

// egressProblems checks one file (name relative to the package directory).
func egressProblems(name string, src []byte) []string {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, name, src, parser.SkipObjectResolution)
	if err != nil {
		return []string{name + ": " + err.Error()}
	}
	var out []string
	bad := func(n ast.Node, what string) {
		out = append(out, name+":"+strconv.Itoa(fset.Position(n.Pos()).Line)+": "+what)
	}
	pkgs := map[string]string{} // local name -> import path
	for _, imp := range f.Imports {
		path, _ := strconv.Unquote(imp.Path.Value)
		for _, fb := range forbiddenImports {
			if path == fb || strings.HasPrefix(path, fb+"/") {
				bad(imp, "imports "+path)
			}
		}
		local := path[strings.LastIndex(path, "/")+1:]
		if imp.Name != nil {
			if imp.Name.Name == "." || imp.Name.Name == "_" {
				bad(imp, "dot or blank import of "+path)
			}
			local = imp.Name.Name
		}
		pkgs[local] = path
	}
	for _, decl := range f.Decls {
		fn := ""
		if fd, ok := decl.(*ast.FuncDecl); ok {
			fn = fd.Name.Name
		}
		site := name + ":" + fn
		ast.Inspect(decl, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.SelectorExpr:
				id, ok := n.X.(*ast.Ident)
				if !ok {
					return true
				}
				switch path, sel := pkgs[id.Name], n.Sel.Name; {
				case path == "net" && (strings.HasPrefix(sel, "Dial") && sel != "Dialer" || strings.HasPrefix(sel, "Listen")):
					bad(n, "uses net."+sel)
				case path == "net" && sel == "Dialer" && site != dialSite:
					bad(n, "builds a net.Dialer outside "+dialSite)
				case path == "alice/internal/platform/netaddr" && sel == "ScanDialContext" && site != dialSite:
					bad(n, "dials outside "+dialSite)
				case path == "alice/internal/platform/netaddr" && (sel == "DialContext" || sel == "ScanControl"):
					bad(n, "uses netaddr."+sel)
				}
			case *ast.CallExpr:
				if s, ok := n.Fun.(*ast.SelectorExpr); ok && slices.Contains([]string{"Dial", "DialContext", "DialTLS", "DialTLSContext", "DialTCP", "DialUDP"}, s.Sel.Name) {
					bad(n, "calls ."+s.Sel.Name)
				}
			case *ast.KeyValueExpr:
				if k, ok := n.Key.(*ast.Ident); ok && slices.Contains([]string{"Dial", "DialContext", "Proxy", "Control", "ControlContext", "Transport"}, k.Name) {
					bad(n, "sets "+k.Name)
				}
			}
			return true
		})
	}
	return out
}

// countSites counts the uses of net.Dialer and netaddr.ScanDialContext inside the dial site.
func countSites(src []byte) (dialers, dials int) {
	f, err := parser.ParseFile(token.NewFileSet(), "scanner.go", src, parser.SkipObjectResolution)
	if err != nil {
		return -1, -1
	}
	for _, decl := range f.Decls {
		if fd, ok := decl.(*ast.FuncDecl); ok && fd.Name.Name == "dialer" {
			ast.Inspect(fd, func(n ast.Node) bool {
				if s, ok := n.(*ast.SelectorExpr); ok {
					if id, ok := s.X.(*ast.Ident); ok {
						switch id.Name + "." + s.Sel.Name {
						case "net.Dialer":
							dialers++
						case "netaddr.ScanDialContext":
							dials++
						}
					}
				}
				return true
			})
		}
	}
	return dialers, dials
}

func TestDiscoveryDialsOnlyThroughTheScanPolicy(t *testing.T) {
	files, err := filepath.Glob("*.go")
	require.NoError(t, err)
	seen := 0
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		src, err := os.ReadFile(name)
		require.NoError(t, err)
		require.Empty(t, egressProblems(name, src))
		seen++
	}
	require.GreaterOrEqual(t, seen, 6, "scope, expand, store, scanner, ingest, retention, link")
	src, err := os.ReadFile("scanner.go")
	require.NoError(t, err)
	dialers, dials := countSites(src)
	require.Equal(t, [2]int{1, 1}, [2]int{dialers, dials}, "one net.Dialer and one ScanDialContext, in scan.dialer")
}

// TestEgressGuardCatchesViolations: each rule fires on a small source, and comments and strings do not.
func TestEgressGuardCatchesViolations(t *testing.T) {
	for want, src := range map[string]string{
		"imports net/http":                        `package p; import "net/http"; var _ = http.Get`,
		"imports net/http/httputil":               `package p; import "net/http/httputil"; var _ = httputil.DumpRequest`,
		"imports golang.org/x/net/proxy":          `package p; import "golang.org/x/net/proxy"; var _ = proxy.SOCKS5`,
		"imports crypto/tls":                      `package p; import "crypto/tls"; var _ = tls.Dial`,
		"dot or blank import":                     `package p; import _ "net/http/pprof"`,
		"uses net.Dial":                           `package p; import "net"; var _ = net.Dial`,
		"uses net.DialTimeout":                    `package p; import n "net"; var _ = n.DialTimeout`,
		"uses net.Listen":                         `package p; import "net"; var _ = net.Listen`,
		"builds a net.Dialer outside":             `package p; import "net"; func dialer() any { return &net.Dialer{} }`,
		"dials outside":                           `package p; import "alice/internal/platform/netaddr"; func f() { _ = netaddr.ScanDialContext }`,
		"uses netaddr.DialContext":                `package p; import "alice/internal/platform/netaddr"; var _ = netaddr.DialContext`,
		"uses netaddr.ScanControl":                `package p; import x "alice/internal/platform/netaddr"; var _ = x.ScanControl`,
		"calls .DialContext":                      `package p; func f(d interface{ DialContext() }) { d.DialContext() }`,
		"sets Dial":                               `package p; import "net"; var _ = net.Resolver{Dial: nil}`,
		"sets Proxy":                              `package p; type T struct{ Proxy any }; var _ = T{Proxy: nil}`,
		"sets Control":                            `package p; type T struct{ Control any }; var _ = T{Control: nil}`,
		"expected 'package', found 'EOF'":         ``,
		"builds a net.Dialer outside scanner.go:": `package p; import "net"; type s struct{}; func (s) other() any { return &net.Dialer{} }`,
	} {
		got := strings.Join(egressProblems("x.go", []byte(src)), "\n")
		require.Contains(t, got, want, src)
	}
	clean := "package p\nimport \"net\"\n// net.Dial(\"tcp\") and http.Get in a comment\nvar _ = \"net.Dial\"\nvar _ net.Conn\nvar _ = net.DefaultResolver\n"
	require.Empty(t, egressProblems("x.go", []byte(clean)))
	ok := "package p\nimport (\"net\"; \"alice/internal/platform/netaddr\")\nfunc dialer() { _ = &net.Dialer{}; _ = netaddr.ScanDialContext }\n"
	require.Empty(t, egressProblems("scanner.go", []byte(ok)))
	require.Equal(t, [2]int{1, 1}, func() [2]int { a, b := countSites([]byte(ok)); return [2]int{a, b} }())
	require.Equal(t, [2]int{-1, -1}, func() [2]int { a, b := countSites(nil); return [2]int{a, b} }())
}
