package archtest

import (
	"bytes"
	"go/ast"
	"go/build/constraint"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Build-tag checks (AUD-23). Test-only code reaches a binary only through a build tag:
//   - a file named *_e2e* or *_testlicense* carries a //go:build line that requires its tag;
//   - a *_release* file is in the release build and leaves it when the test tags are set;
//   - the names make release-symcheck looks for, and the test license key label make
//     image-check looks for, live only in files that require their tag (so those binary checks
//     guard what they claim to);
//   - no file of the release build imports a test-only package, and the release binaries link
//     none (go list -deps), while the e2e build does (positive control).
// make release-symcheck and make image-check check the built binaries; this test checks the source.

// testOnlyImports may never be imported by a file of the release build.
var testOnlyImports = []string{
	"testing",
	"github.com/stretchr/testify/...",
	"github.com/testcontainers/...",
	"alice/internal/license/licensetest",
	"alice/internal/testutil/...",
	"alice/internal/providers/linuxssh/linuxsshtest",
	"alice/internal/providers/providertest",
	"alice/internal/vconsole/sign/openpgp/openpgptest",
}

// testOnlyDirs are test helper packages: their own files are untagged on purpose and reach no
// release binary (TestReleaseBinariesLinkNoTestPackages).
//
// cmd/alice-fakeazure is a test tool, not a package of the product: it imports internal/testutil/fakekv, is
// built into the e2e fake Azure image only and is no release binary (TestReleaseBinariesLinkNoTestPackages
// lists the binaries that ship). cmd/alice-fakesmtp and cmd/alice-fakeidp are the same kind of tool for the
// mail and OpenID Connect fakes (internal/testutil/fakesmtp and fakeidp); cmd/alice-fakeacme is the one of
// the fake ACME CA (internal/testutil/fakeacme); cmd/alice-fakefleet is the one of the fake TLS fleet of the
// network discovery journeys (internal/testutil/fakefleet, listed by name too: plan 2026-10-13-network-discovery A9).
var testOnlyDirs = []string{"internal/license/licensetest", "internal/testutil", "internal/providers/linuxssh/linuxsshtest",
	"internal/providers/providertest", "cmd/alice-fakeazure", "cmd/alice-fakesmtp", "cmd/alice-fakeidp", "cmd/alice-fakeacme",
	"internal/testutil/fakefleet", "cmd/alice-fakefleet",
	"internal/vconsole/sign/openpgp/openpgptest"}

// testTags maps the file-name marker of test-only code to the build tag it must require.
var testTags = map[string]string{"_e2e": "e2e", "_testlicense": "testlicense"}

// releaseTags are the tags true in a release build (CGO_ENABLED=0, Linux; the image and make build).
var releaseTags = map[string]bool{"linux": true, "unix": true, "amd64": true, "gc": true}

type goFile struct {
	rel  string
	test bool
	expr constraint.Expr // nil: no //go:build line
	file *ast.File
	src  string
}

func sourceFiles(t *testing.T) []goFile {
	t.Helper()
	root := moduleRoot(t)
	var out []goFile
	fset := token.NewFileSet()
	for _, top := range []string{"cmd", "internal"} {
		err := filepath.WalkDir(filepath.Join(root, top), func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				if d.Name() == "testdata" || d.Name() == "node_modules" {
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(path, ".go") {
				return nil
			}
			raw, err := os.ReadFile(path) //nolint:gosec // walking the repository
			if err != nil {
				return err
			}
			f, err := parser.ParseFile(fset, path, raw, parser.SkipObjectResolution)
			if err != nil {
				return err
			}
			rel, _ := filepath.Rel(root, path)
			out = append(out, goFile{rel: filepath.ToSlash(rel), test: strings.HasSuffix(path, "_test.go"),
				expr: buildExpr(t, path, raw), file: f, src: string(raw)})
			return nil
		})
		require.NoError(t, err)
	}
	require.NotEmpty(t, out)
	return out
}

// buildExpr returns the //go:build expression of a file (lines before the package clause).
func buildExpr(t *testing.T, path string, raw []byte) constraint.Expr {
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "package ") {
			break
		}
		if constraint.IsGoBuild(line) {
			e, err := constraint.Parse(line)
			require.NoError(t, err, path)
			return e
		}
	}
	return nil
}

func tagsOf(e constraint.Expr, into map[string]bool) {
	switch x := e.(type) {
	case *constraint.TagExpr:
		into[x.Tag] = true
	case *constraint.NotExpr:
		tagsOf(x.X, into)
	case *constraint.AndExpr:
		tagsOf(x.X, into)
		tagsOf(x.Y, into)
	case *constraint.OrExpr:
		tagsOf(x.X, into)
		tagsOf(x.Y, into)
	}
}

// requires reports whether e is false whenever tag is unset, whatever its other tags are.
func requires(e constraint.Expr, tag string) bool {
	if e == nil {
		return false
	}
	set := map[string]bool{}
	tagsOf(e, set)
	delete(set, tag)
	others := make([]string, 0, len(set))
	for k := range set {
		others = append(others, k)
	}
	for mask := 0; mask < 1<<len(others); mask++ {
		on := map[string]bool{}
		for i, k := range others {
			on[k] = mask&(1<<i) != 0
		}
		if e.Eval(func(t string) bool { return on[t] }) {
			return false
		}
	}
	return true
}

// inBuild reports whether a file with expression e is compiled with the release tags plus extra.
func inBuild(e constraint.Expr, extra ...string) bool {
	if e == nil {
		return true
	}
	return e.Eval(func(t string) bool {
		return releaseTags[t] || slices.Contains(extra, t) || strings.HasPrefix(t, "go1.")
	})
}

func inTestOnlyDir(rel string) bool {
	for _, d := range testOnlyDirs {
		if strings.HasPrefix(rel, d+"/") {
			return true
		}
	}
	return false
}

func TestTestOnlyFilesRequireTheirTag(t *testing.T) {
	seen := map[string]int{}
	for _, f := range sourceFiles(t) {
		base := filepath.Base(f.rel)
		for marker, tag := range testTags {
			if !strings.Contains(base, marker) {
				continue
			}
			seen[marker]++
			assert.True(t, requires(f.expr, tag), "%s must carry a //go:build line that requires %q", f.rel, tag)
		}
	}
	for marker := range testTags {
		assert.Positive(t, seen[marker], "no file named *%s* found; the check would prove nothing", marker)
	}
}

func TestReleaseVariantsLeaveTheTestBuilds(t *testing.T) {
	n := 0
	for _, f := range sourceFiles(t) {
		if f.test || !strings.Contains(filepath.Base(f.rel), "_release") {
			continue
		}
		n++
		assert.True(t, inBuild(f.expr), "%s is not in the release build", f.rel)
		assert.False(t, inBuild(f.expr, "e2e", "testlicense"), "%s stays in the e2e/test-license build: its test variant would collide", f.rel)
	}
	assert.Positive(t, n, "no *_release* file found")
}

// makeVar returns the value of a Makefile variable defined with :=.
func makeVar(t *testing.T, name string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(moduleRoot(t), "Makefile"))
	require.NoError(t, err)
	m := regexp.MustCompile(`(?m)^` + name + `\s*:=\s*(.*)$`).FindStringSubmatch(string(raw))
	require.NotNil(t, m, "Makefile defines no %s", name)
	v := m[1]
	if i := strings.Index(v, " #"); i >= 0 {
		v = v[:i]
	}
	return strings.TrimSpace(v)
}

// The names release-symcheck looks for in the binary are declared only in files that require e2e:
// otherwise their absence from the release binary would prove nothing about the e2e code.
func TestGuardedSymbolsAreE2EOnly(t *testing.T) {
	re := regexp.MustCompile(`^main\\\.\(([A-Za-z0-9_|]+)\)\$\$$`)
	m := re.FindStringSubmatch(makeVar(t, "E2E_SYMBOLS"))
	require.NotNil(t, m, "E2E_SYMBOLS has an unexpected form")
	names := strings.Split(m[1], "|")
	declared := map[string][]goFile{}
	for _, f := range sourceFiles(t) {
		if f.test || !strings.HasPrefix(f.rel, "cmd/alice/") || strings.Count(f.rel, "/") != 2 {
			continue
		}
		for _, name := range topLevelNames(f.file) {
			declared[name] = append(declared[name], f)
		}
	}
	for _, name := range names {
		files := declared[name]
		if assert.NotEmpty(t, files, "E2E_SYMBOLS names %s, which cmd/alice does not declare; update it", name) {
			for _, f := range files {
				assert.True(t, requires(f.expr, "e2e"), "%s declares %s without requiring the e2e tag", f.rel, name)
			}
		}
	}
}

func topLevelNames(f *ast.File) []string {
	var out []string
	for _, d := range f.Decls {
		switch x := d.(type) {
		case *ast.FuncDecl:
			if x.Recv == nil {
				out = append(out, x.Name.Name)
			}
		case *ast.GenDecl:
			for _, s := range x.Specs {
				switch sp := s.(type) {
				case *ast.ValueSpec:
					for _, n := range sp.Names {
						out = append(out, n.Name)
					}
				case *ast.TypeSpec:
					out = append(out, sp.Name.Name)
				}
			}
		}
	}
	return out
}

// The test license key label make image-check refuses in the binary appears only in files that
// require testlicense (or in test-only packages, which no release binary links), and equals the
// Makefile's TEST_LICENSE_LABEL.
func TestTestLicenseLabelIsTestOnly(t *testing.T) {
	label := makeVar(t, "TEST_LICENSE_LABEL")
	require.NotEmpty(t, label)
	quoted := strconv.Quote(label)
	n := 0
	for _, f := range sourceFiles(t) {
		if f.test || inTestOnlyDir(f.rel) || !strings.Contains(f.src, quoted) {
			continue
		}
		n++
		assert.True(t, requires(f.expr, "testlicense"), "%s holds the test license key label without requiring testlicense", f.rel)
	}
	assert.Positive(t, n, "no source file holds %s; TEST_LICENSE_LABEL is stale", quoted)
}

// The e2e route make image-check refuses in the binary is registered in a file that requires e2e.
func TestTestRouteMarkerIsE2EOnly(t *testing.T) {
	marker := makeVar(t, "TEST_ROUTE_MARKER")
	n := 0
	for _, f := range sourceFiles(t) {
		if f.test || !strings.Contains(f.src, `HandleFunc("GET `+marker+`"`) && !strings.Contains(f.src, `HandleFunc("POST `+marker+`"`) {
			continue
		}
		n++
		assert.True(t, requires(f.expr, "e2e"), "%s registers %s without requiring the e2e tag", f.rel, marker)
	}
	assert.Positive(t, n, "no file registers %s; TEST_ROUTE_MARKER is stale", marker)
}

// testRoutePattern is a net/http route pattern of a test-only endpoint: a method, then a /test path.
var testRoutePattern = regexp.MustCompile(`^(GET|HEAD|POST|PUT|PATCH|DELETE|OPTIONS|CONNECT|TRACE) +([^/\s]*)/test(/|$)`)

// testRoutesOutsideE2E lists every route pattern of a test endpoint ("POST /test/…") written as a string
// literal in a non-test file that does not require the e2e tag ("file: pattern").
func testRoutesOutsideE2E(files []goFile) []string {
	var out []string
	for _, f := range files {
		if f.test || requires(f.expr, "e2e") {
			continue
		}
		ast.Inspect(f.file, func(n ast.Node) bool {
			lit, ok := n.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			if v, err := strconv.Unquote(lit.Value); err == nil && testRoutePattern.MatchString(v) {
				out = append(out, f.rel+": "+v)
			}
			return true
		})
	}
	return out
}

// Every /test route, not only TEST_ROUTE_MARKER, is registered in a file that requires the e2e tag: a
// new test endpoint in a release file fails here before any binary is built.
func TestEveryTestRouteIsE2EOnly(t *testing.T) {
	files := sourceFiles(t)
	assert.Empty(t, testRoutesOutsideE2E(files), "test routes outside the e2e build")
	n := 0
	for _, f := range files {
		if !f.test && strings.Contains(f.src, `"POST /test/rotation/overlap"`) {
			n++
		}
	}
	assert.Equal(t, 1, n, "the rule sees the e2e routes (positive control)")

	// Red case: the same registration in a file without the tag, or with a tag that does not require e2e.
	parse := func(src string) goFile {
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, "x.go", src, parser.ParseComments)
		require.NoError(t, err)
		return goFile{rel: "cmd/alice/x.go", expr: buildExpr(t, "x.go", []byte(src)), file: file, src: src}
	}
	body := "package main\n\nfunc f(m interface{ HandleFunc(string, any) }) { m.HandleFunc(\"POST /test/rotation/overlap\", nil) }\n"
	assert.Equal(t, []string{"cmd/alice/x.go: POST /test/rotation/overlap"}, testRoutesOutsideE2E([]goFile{parse(body)}))
	assert.Len(t, testRoutesOutsideE2E([]goFile{parse("//go:build e2e || testlicense\n\n" + body)}), 1)
	assert.Empty(t, testRoutesOutsideE2E([]goFile{parse("//go:build e2e\n\n" + body)}))
	assert.Empty(t, testRoutesOutsideE2E([]goFile{parse(strings.Replace(body, "POST /test/", "POST /api/v1/test/", 1))}),
		"an API path that merely contains /test is not a test route")
}

// The directory the e2e build reads the fake Azure service's CA from (the Makefile's E2E_AZURE_MARKER, which
// release-symcheck and make image-check look for in the binaries) is named only in files that require e2e
// (test files and the test tool excepted), and the e2e source does name it.
func TestAzureMarkerIsE2EOnly(t *testing.T) {
	marker := makeVar(t, "E2E_AZURE_MARKER")
	require.NotEmpty(t, marker)
	n := 0
	for _, f := range sourceFiles(t) {
		if f.test || inTestOnlyDir(f.rel) || !strings.Contains(f.src, marker) {
			continue
		}
		n++
		assert.True(t, requires(f.expr, "e2e"), "%s holds %s without requiring the e2e tag", f.rel, marker)
	}
	assert.Positive(t, n, "no source file holds %s; E2E_AZURE_MARKER is stale", marker)
}

// The directory the e2e build reads the fake ACME CA's TLS CA from (the Makefile's E2E_ACME_MARKER) is named
// only in files that require e2e, like the Azure one, and the e2e source does name it.
func TestAcmeMarkerIsE2EOnly(t *testing.T) {
	marker := makeVar(t, "E2E_ACME_MARKER")
	require.NotEmpty(t, marker)
	n := 0
	for _, f := range sourceFiles(t) {
		if f.test || inTestOnlyDir(f.rel) || !strings.Contains(f.src, marker) {
			continue
		}
		n++
		assert.True(t, requires(f.expr, "e2e"), "%s holds %s without requiring the e2e tag", f.rel, marker)
	}
	assert.Positive(t, n, "no source file holds %s; E2E_ACME_MARKER is stale", marker)
}

func TestReleaseFilesImportNoTestCode(t *testing.T) {
	for _, f := range sourceFiles(t) {
		if f.test || inTestOnlyDir(f.rel) || !inBuild(f.expr) {
			continue
		}
		for _, imp := range f.file.Imports {
			path, _ := strconv.Unquote(imp.Path.Value)
			for _, bad := range testOnlyImports {
				assert.False(t, covers(bad, path), "%s is in the release build and imports %s", f.rel, path)
			}
		}
	}
}

// TestOnlyTheDirectoryPackageImportsTheLDAPClient: the LDAP client library (and its BER codec) is used by the
// directory sign-in package alone; every other file that imports it is a test or a test helper (plan
// 2026-10-15-ldap-directory-signin, "No LDAP code outside internal/auth/...").
func TestOnlyTheDirectoryPackageImportsTheLDAPClient(t *testing.T) {
	ldapImports := []string{"github.com/go-ldap/...", "github.com/go-asn1-ber/..."}
	found := false
	for _, f := range sourceFiles(t) {
		for _, imp := range f.file.Imports {
			path, _ := strconv.Unquote(imp.Path.Value)
			if !covers(ldapImports[0], path) && !covers(ldapImports[1], path) {
				continue
			}
			found = true
			if f.test || inTestOnlyDir(f.rel) {
				continue
			}
			dir := filepath.ToSlash(filepath.Dir(f.rel))
			assert.Equal(t, "internal/auth/ldap", dir, "%s imports %s", f.rel, path)
		}
	}
	assert.True(t, found, "positive control: the directory package imports the client")
}

func goListDeps(t *testing.T, tags string, pkgs ...string) []string {
	t.Helper()
	args := []string{"list", "-deps"}
	if tags != "" {
		args = append(args, "-tags", tags)
	}
	cmd := exec.Command("go", append(args, pkgs...)...) //nolint:gosec // fixed arguments
	cmd.Dir = moduleRoot(t)
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	require.NoError(t, err, stderr.String())
	return strings.Fields(string(out))
}

func TestReleaseBinariesLinkNoTestPackages(t *testing.T) {
	for _, dep := range goListDeps(t, "", "./cmd/alice", "./cmd/alice-helper", "./cmd/licensectl", "./cmd/vendor-console", "./cmd/vendor-web") {
		for _, bad := range testOnlyImports {
			assert.False(t, covers(bad, dep), "a release binary links %s", dep)
		}
	}
	// Positive control: the e2e build does link a test-only package, so the check can see one.
	assert.Contains(t, goListDeps(t, "e2e testlicense", "./cmd/alice"), "alice/internal/license/licensetest")
	// The fake Azure service is never linked into Alice, in any build that ships or runs as the e2e image:
	// the e2e build trusts its CA from a file and needs no code of it (the fake is its own binary).
	for _, tags := range []string{"", "e2e testlicense"} {
		assert.NotContains(t, goListDeps(t, tags, "./cmd/alice"), "alice/internal/testutil/fakekv", "tags %q", tags)
	}
	assert.Contains(t, goListDeps(t, "", "./cmd/alice-fakeazure"), "alice/internal/testutil/fakekv", "the fake tool is where the fake is linked")
	// The mail and identity provider fakes are their own binaries too: no build of Alice links them.
	for _, tags := range []string{"", "e2e testlicense"} {
		deps := goListDeps(t, tags, "./cmd/alice")
		assert.NotContains(t, deps, "alice/internal/testutil/fakesmtp", "tags %q", tags)
		assert.NotContains(t, deps, "alice/internal/testutil/fakeidp", "tags %q", tags)
		assert.NotContains(t, deps, "alice/internal/testutil/fakeacme", "tags %q", tags)
		assert.NotContains(t, deps, "alice/internal/testutil/fakefleet", "tags %q", tags)
		// The OpenLDAP container helper of the directory sign-in tests (integration builds only).
		assert.NotContains(t, deps, "alice/internal/testutil/fakeldap", "tags %q", tags)
		assert.NotContains(t, goListDeps(t, strings.TrimSpace(tags+" integration"), "./cmd/alice"), "alice/internal/testutil/fakeldap", "tags %q", tags)
	}
	for _, bin := range []string{"./cmd/alice-helper", "./cmd/licensectl"} {
		assert.NotContains(t, goListDeps(t, "", bin), "alice/internal/testutil/fakefleet", bin)
	}
	assert.Contains(t, goListDeps(t, "", "./cmd/alice-fakefleet"), "alice/internal/testutil/fakefleet", "the fake fleet tool is where the fleet is linked")
	assert.Contains(t, goListDeps(t, "", "./cmd/alice-fakesmtp"), "alice/internal/testutil/fakesmtp")
	assert.Contains(t, goListDeps(t, "", "./cmd/alice-fakeidp"), "alice/internal/testutil/fakeidp")
	assert.Contains(t, goListDeps(t, "", "./cmd/alice-fakeacme"), "alice/internal/testutil/fakeacme", "the fake ACME tool is where the fake is linked")
}

func TestRequires(t *testing.T) {
	parse := func(s string) constraint.Expr {
		e, err := constraint.Parse("//go:build " + s)
		require.NoError(t, err)
		return e
	}
	assert.True(t, requires(parse("e2e"), "e2e"))
	assert.True(t, requires(parse("integration && e2e"), "e2e"))
	assert.True(t, requires(parse("testlicense && !e2e"), "testlicense"))
	assert.False(t, requires(parse("e2e || testlicense"), "e2e"), "true with testlicense alone")
	assert.False(t, requires(parse("!e2e"), "e2e"))
	assert.False(t, requires(parse("linux"), "e2e"))
	assert.False(t, requires(nil, "e2e"))
	assert.True(t, inBuild(nil))
	assert.True(t, inBuild(parse("!e2e && !testlicense")))
	assert.False(t, inBuild(parse("!e2e"), "e2e"))
	assert.False(t, inBuild(parse("integration")))
}

// S-10: no build of Alice that ships links a debug or metrics endpoint: net/http/pprof and expvar register
// /debug/pprof/ and /debug/vars when imported, and no metrics library is linked (Alice serves no /metrics).
// cmd/alice TestS10ReleaseServerHasNoDebugOrMetricsEndpoints requests the paths from the release server.
func TestS10ReleaseLinksNoDebugOrMetricsEndpoints(t *testing.T) {
	for _, tags := range []string{"", "e2e testlicense"} {
		deps := goListDeps(t, tags, "./cmd/alice", "./cmd/alice-helper")
		require.Contains(t, deps, "net/http", "positive control: the list holds the standard library (tags %q)", tags)
		for _, dep := range deps {
			assert.False(t, dep == "net/http/pprof" || dep == "expvar" || strings.Contains(dep, "prometheus") ||
				strings.Contains(dep, "opentelemetry"), "tags %q: Alice links %s", tags, dep)
		}
	}
}
