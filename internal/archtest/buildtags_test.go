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
}

// testOnlyDirs are test helper packages: their own files are untagged on purpose and reach no
// release binary (TestReleaseBinariesLinkNoTestPackages).
//
// cmd/alice-fakeazure is a test tool, not a package of the product: it imports internal/testutil/fakekv, is
// built into the e2e fake Azure image only and is no release binary (TestReleaseBinariesLinkNoTestPackages
// lists the binaries that ship).
var testOnlyDirs = []string{"internal/license/licensetest", "internal/testutil", "internal/providers/linuxssh/linuxsshtest",
	"internal/providers/providertest", "cmd/alice-fakeazure"}

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
	for _, dep := range goListDeps(t, "", "./cmd/alice", "./cmd/alice-helper", "./cmd/licensectl") {
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
