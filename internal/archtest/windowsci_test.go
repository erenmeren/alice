package archtest

import (
	"bytes"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.yaml.in/yaml/v3"
)

// The Windows workflow runs only when a change touches what the Windows tests build (W4, R63, Ruling 6).
// deploy/dev/windows-ci.sh decides it from .github/windows-paths.txt ("changed") and turns the
// legs' results into the one required check ("gate", Ruling 4). These tests drive the script itself,
// so CI and the guard share one matcher.

const (
	windowsCIScript = "deploy/dev/windows-ci.sh"
	windowsPaths    = ".github/windows-paths.txt"
)

// windowsFixedEntries must be in the watched list whatever the Go dependencies are (Ruling 6).
var windowsFixedEntries = []string{
	".github/workflows/windows.yml", ".github/windows-paths.txt", "deploy/dev/windows-ci.sh",
	"go.mod", "go.sum", "Makefile", "docs/windows-host-preparation.md",
}

// runWindowsCI runs the script with args and stdin from the module root; it returns the exit code
// and the combined output.
func runWindowsCI(t *testing.T, stdin string, args ...string) (int, string) {
	t.Helper()
	cmd := exec.Command("bash", append([]string{windowsCIScript}, args...)...) //nolint:gosec // fixed script, test arguments
	cmd.Dir = moduleRoot(t)
	cmd.Stdin = strings.NewReader(stdin)
	out, err := cmd.CombinedOutput()
	if err == nil {
		return 0, string(out)
	}
	var exit *exec.ExitError
	require.True(t, errors.As(err, &exit), "%s: %v", windowsCIScript, err)
	return exit.ExitCode(), string(out)
}

// changedWith runs "changed" over a temporary list holding entries.
func changedWith(t *testing.T, entries, names string) (int, string) {
	t.Helper()
	list := filepath.Join(t.TempDir(), "paths.txt")
	require.NoError(t, os.WriteFile(list, []byte(entries), 0o600))
	return runWindowsCI(t, names, "changed", list)
}

// nul joins names the way git diff --name-only -z prints them: each name ended by a NUL byte.
func nul(names ...string) string {
	var b strings.Builder
	for _, n := range names {
		b.WriteString(n)
		b.WriteByte(0)
	}
	return b.String()
}

func TestWindowsChangedScript(t *testing.T) {
	const list = "# watched\n\na/**\n  # indented comment\nb/*\nc.txt\n"
	cases := []struct {
		name  string
		input string
		code  int
	}{
		{"below a dir/** entry", nul("a/x/y.go"), 0},
		{"directly in a dir/* entry", nul("b/z.go"), 0},
		{"below a dir/* entry", nul("b/sub/z.go"), 1},
		{"an exact entry", nul("c.txt"), 0},
		{"a longer name than an exact entry", nul("c.txt.bak"), 1},
		{"a sibling with the same prefix", nul("ab/x"), 1},
		{"the dir of a dir/** entry itself", nul("a"), 1},
		{"the dir of a dir/* entry itself", nul("b"), 1},
		{"a comment line is no entry", nul("# watched"), 1},
		{"empty input", "", 1},
		{"one match among others", nul("web/x.ts", "b/sub/z.go", "b/ok.go"), 0},
		{"a last name without its NUL", nul("web/x.ts") + "c.txt", 0},
		// -z names arrive raw: git's quoting of these ("a/\303\251.go") would match nothing.
		{"a non-ASCII name below a dir/** entry", nul("web/x.ts", "a/été.go"), 0},
		{"a name with a quote and a space below a dir/** entry", nul("a/say \"hi\".go"), 0},
		{"a name with a newline directly in a dir/* entry", nul("b/x\ny"), 0}, // one file directly in b
		{"newline-separated names are one name", "web/x.ts\nc.txt\n", 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			code, out := changedWith(t, list, c.input)
			assert.Equal(t, c.code, code, out)
		})
	}
	t.Run("prints the first matching name", func(t *testing.T) {
		code, out := changedWith(t, list, nul("web/x.ts", "b/ok.go", "a/q"))
		require.Equal(t, 0, code, out)
		assert.Equal(t, "b/ok.go", strings.TrimSpace(out))
	})
	for _, bad := range []string{"a/**/b", "/abs/**", "a/../b", "..", "a b/**", "a/*/b", "**", "a/**x", "*.go", "a/"} {
		t.Run("entry of another form "+bad, func(t *testing.T) {
			code, out := changedWith(t, "c.txt\n"+bad+"\n", nul("c.txt"))
			assert.Equal(t, 2, code, out)
		})
	}
	t.Run("usage", func(t *testing.T) {
		code, out := runWindowsCI(t, "", "changed")
		assert.Equal(t, 2, code, out)
		code, out = runWindowsCI(t, "", "changed", filepath.Join(t.TempDir(), "missing"))
		assert.Equal(t, 2, code, out)
		code, out = runWindowsCI(t, "")
		assert.Equal(t, 2, code, out)
		code, out = runWindowsCI(t, "", "nonsense")
		assert.Equal(t, 2, code, out)
	})
}

func TestWindowsGateDecision(t *testing.T) {
	cases := []struct {
		args []string
		code int
	}{
		{[]string{"success", "false", "skipped", "skipped"}, 0},
		{[]string{"success", "true", "success", "success"}, 0},
		{[]string{"success", "true", "success", "failure"}, 1},
		{[]string{"success", "true", "success", "cancelled"}, 1},
		{[]string{"success", "true", "skipped", "skipped"}, 1},
		{[]string{"success", "true", "failure", "success"}, 1},
		{[]string{"failure", "false", "skipped", "skipped"}, 1},
		{[]string{"failure", "", "skipped", "skipped"}, 1},      // a failed changes job outputs no windows value
		{[]string{"success", "false", "success", "success"}, 1}, // the legs ran although nothing changed: a wrong changes output
		{[]string{"cancelled", "true", "skipped", "skipped"}, 1},
		{[]string{"success", "maybe", "skipped", "skipped"}, 2},
		{[]string{"success", "", "skipped", "skipped"}, 2},
		{[]string{"success", "true", "success"}, 2},
		{[]string{"done", "true", "success", "success"}, 2},
		{[]string{"success", "true", "success", "passed"}, 2},
	}
	for _, c := range cases {
		t.Run(strings.Join(c.args, ","), func(t *testing.T) {
			code, out := runWindowsCI(t, "", append([]string{"gate"}, c.args...)...)
			assert.Equal(t, c.code, code, out)
			if c.code != 2 {
				assert.Equal(t, 1, strings.Count(strings.TrimSpace(out), "\n")+1, "one line saying why: %q", out)
			}
		})
	}
}

// windowsTestDeps lists the in-repo package directories (relative to the module root) that the Windows
// tests build: go list -deps -test for GOOS=windows over the helper and the provider, with tags.
func windowsTestDeps(t *testing.T, tags string) []string {
	t.Helper()
	args := []string{"list", "-deps", "-test", "-f", "{{if not .Standard}}{{.ImportPath}}{{end}}"}
	if tags != "" {
		args = append(args, "-tags", tags)
	}
	args = append(args, "./cmd/alice-winhelper/...", "./internal/providers/windows/...")
	cmd := exec.Command("go", args...) //nolint:gosec // fixed arguments
	cmd.Dir = moduleRoot(t)
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=windows")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	require.NoError(t, err, stderr.String())
	var dirs []string
	for _, line := range strings.Split(string(out), "\n") {
		pkg, _, _ := strings.Cut(strings.TrimSpace(line), " ") // "alice/x [alice/x.test]" is alice/x built for its tests
		if strings.HasSuffix(pkg, ".test") {
			continue // the generated test main
		}
		pkg = strings.TrimSuffix(pkg, "_test") // an external test package lives in the directory of the package it tests
		if dir, ok := strings.CutPrefix(pkg, "alice/"); ok && !slices.Contains(dirs, dir) {
			dirs = append(dirs, dir)
		}
	}
	return dirs
}

func trackedFiles(t *testing.T) string {
	t.Helper()
	cmd := exec.Command("git", "ls-files", "-z") // raw names, each ended by a NUL: the script's input
	cmd.Dir = moduleRoot(t)
	out, err := cmd.Output()
	require.NoError(t, err)
	return string(out)
}

func TestWindowsWorkflowWatchesEveryDependency(t *testing.T) {
	root := moduleRoot(t)
	raw, err := os.ReadFile(filepath.Join(root, windowsPaths)) //nolint:gosec // repository file
	require.NoError(t, err)
	var entries []string
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			entries = append(entries, line)
		}
	}

	t.Run("every package the Windows tests build", func(t *testing.T) {
		var all []string
		for _, tags := range []string{"", "alicetest"} {
			for _, d := range windowsTestDeps(t, tags) {
				if !slices.Contains(all, d) {
					all = append(all, d)
				}
			}
		}
		require.Contains(t, all, "internal/providers/windows/winproto", "positive control: the protocol package is a dependency")
		var missing []string
		for _, d := range all {
			// A directory is watched when a file directly inside it is.
			if code, out := runWindowsCI(t, nul(d+"/doc.go"), "changed", windowsPaths); code != 0 {
				require.Equal(t, 1, code, out)
				missing = append(missing, d)
			}
		}
		slices.Sort(missing)
		assert.Empty(t, missing, "%s does not watch these package directories", windowsPaths)
	})

	t.Run("every fixed entry", func(t *testing.T) {
		for _, f := range windowsFixedEntries {
			assert.Contains(t, entries, f)
		}
	})

	t.Run("no stale entry", func(t *testing.T) {
		files := trackedFiles(t)
		for _, e := range entries {
			code, out := changedWith(t, e+"\n", files)
			assert.Equal(t, 0, code, "entry %q matches no tracked file: %s", e, out)
		}
	})
}

const windowsWorkflow = ".github/workflows/windows.yml"

// loadWorkflow decodes a workflow file into maps.
func loadWorkflow(t *testing.T, path string) map[string]any {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(moduleRoot(t), path)) //nolint:gosec // repository file
	require.NoError(t, err)
	var doc map[string]any
	require.NoError(t, yaml.Unmarshal(raw, &doc))
	// A YAML 1.1 reader decodes the key on as true; go.yaml.in/yaml/v3 keeps the string. Accept both.
	if _, ok := doc["on"]; !ok {
		if v, ok := doc["true"]; ok {
			doc["on"] = v
		}
	}
	return doc
}

// ymap returns m[key] as a mapping, failing the test when it is not one.
func ymap(t *testing.T, m map[string]any, key string) map[string]any {
	t.Helper()
	v, ok := m[key].(map[string]any)
	require.True(t, ok, "%q is not a mapping: %#v", key, m[key])
	return v
}

// ysteps returns the steps of a job.
func ysteps(t *testing.T, job map[string]any) []map[string]any {
	t.Helper()
	list, ok := job["steps"].([]any)
	require.True(t, ok, "steps is not a list")
	steps := make([]map[string]any, 0, len(list))
	for _, s := range list {
		m, ok := s.(map[string]any)
		require.True(t, ok)
		steps = append(steps, m)
	}
	return steps
}

// ystrings returns v as a list of strings (a single string is a list of one).
func ystrings(v any) []string {
	switch x := v.(type) {
	case string:
		return []string{x}
	case []any:
		out := make([]string, 0, len(x))
		for _, e := range x {
			s, _ := e.(string)
			out = append(out, s)
		}
		return out
	}
	return nil
}

// jobRun joins the run texts of a job's steps.
func jobRun(t *testing.T, job map[string]any) string {
	t.Helper()
	var b strings.Builder
	for _, s := range ysteps(t, job) {
		if r, ok := s["run"].(string); ok {
			b.WriteString(r)
			b.WriteByte('\n')
		}
	}
	return b.String()
}

// stepEnvText returns the env: of the job's step with that exact name as YAML text; the step must exist.
func stepEnvText(t *testing.T, job map[string]any, name string) string {
	t.Helper()
	for _, s := range ysteps(t, job) {
		if s["name"] == name {
			return yamlText(s["env"])
		}
	}
	require.Failf(t, "no step", "no step named %q", name)
	return ""
}

// checkoutWith returns the with: of the job's one actions/checkout step.
func checkoutWith(t *testing.T, job map[string]any) map[string]any {
	t.Helper()
	var with map[string]any
	found := 0
	for _, s := range ysteps(t, job) {
		if uses, _ := s["uses"].(string); strings.HasPrefix(uses, "actions/checkout@") {
			found++
			with, _ = s["with"].(map[string]any)
		}
	}
	require.Equal(t, 1, found, "one actions/checkout step")
	return with
}

// collapseCode drops shell comment lines and joins the rest with single spaces.
func collapseCode(script string) string {
	var words []string
	for _, line := range strings.Split(script, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		words = append(words, strings.Fields(line)...)
	}
	return strings.Join(words, " ")
}

func yamlText(v any) string {
	out, err := yaml.Marshal(v)
	if err != nil {
		return ""
	}
	return string(out)
}

// The one required check (Rulings 4, 5, 8, 12): every trigger starts the workflow, the changes job
// decides whether the legs run, and windows-required turns the results into one verdict.
func TestWindowsWorkflowGate(t *testing.T) {
	doc := loadWorkflow(t, windowsWorkflow)
	on := ymap(t, doc, "on")

	for _, ev := range []string{"push", "pull_request"} {
		require.Contains(t, on, ev)
		trig, _ := on[ev].(map[string]any) // pull_request may carry no settings
		assert.NotContains(t, trig, "paths", "%s runs on every change; the changes job decides (Ruling 5)", ev)
		assert.NotContains(t, trig, "paths-ignore", ev)
	}
	push, _ := on["push"].(map[string]any)
	assert.Equal(t, []string{"**"}, ystrings(push["branches"]), "push runs for every branch")
	assert.NotContains(t, push, "tags", "a tag push runs through release.yml's call only")
	require.Contains(t, on, "schedule")
	assert.Contains(t, yamlText(on["schedule"]), "41 2 * * *", "the nightly run (Ruling 9)")
	require.Contains(t, on, "workflow_dispatch")
	call, _ := on["workflow_call"].(map[string]any)
	inputs, _ := call["inputs"].(map[string]any)
	all, _ := inputs["all"].(map[string]any)
	assert.Equal(t, "boolean", all["type"], "workflow_call input all (Ruling 12)")
	assert.Equal(t, false, all["default"])

	assert.Equal(t, map[string]any{"contents": "read"}, doc["permissions"])
	conc := ymap(t, doc, "concurrency")
	group, _ := conc["group"].(string)
	assert.True(t, strings.HasPrefix(group, "windows-"), "a literal prefix, never github.workflow (Ruling 8): %q", group)
	assert.NotContains(t, group, "github.workflow")
	// A default-branch push gets a group of its own per commit: GitHub keeps one pending run per group
	// and cancels it when a newer one queues, whatever cancel-in-progress says, so a shared group
	// would drop a queued push whose before the next push then diffs from.
	assert.Contains(t, group, "github.event.repository.default_branch", "a default-branch push has its own group")
	assert.Contains(t, group, "format('main-{0}', github.sha)", "one group per default-branch commit")
	assert.Contains(t, group, "'nightly'", "the nightly run keeps its group")
	cancel, _ := conc["cancel-in-progress"].(string)
	assert.Contains(t, cancel, "refs/tags/", "a release call is never cancelled")
	assert.Contains(t, cancel, "github.event.repository.default_branch", "a push to the default branch is never cancelled")

	jobs := ymap(t, doc, "jobs")
	for _, j := range []string{"changes", "linux-build", "helper", "windows-required"} {
		require.Contains(t, jobs, j)
	}

	changes := ymap(t, jobs, "changes")
	run := jobRun(t, changes)
	for _, want := range []string{
		"git diff --no-renames --name-only -z",
		"windows-ci.sh changed .github/windows-paths.txt",
		`default=${DEFAULT_BRANCH:-main}`,
		`git merge-base "origin/$default" HEAD`,
		`if [[ $REF == "refs/heads/$default" ]]; then`,
		// On the default branch an unusable before runs the legs; the merge base there is HEAD itself.
		`base=$BEFORE if [[ -z $base || $base =~ ^0+$ ]] || ! git cat-file -e "$base^{commit}" 2>/dev/null; then answer true`,
	} {
		// Compared with white space collapsed: comments aside, indentation and line breaks do not matter.
		assert.Contains(t, collapseCode(run), want, "the changes step (Ruling 5, amended)")
	}
	assert.NotContains(t, run, "origin/main", "the default branch comes through env:, main only as its fallback")
	assert.Contains(t, stepEnvText(t, changes, "Decide whether the Windows legs run"), "github.event.repository.default_branch")
	outputs, _ := changes["outputs"].(map[string]any)
	assert.Contains(t, outputs, "windows")
	assert.Equal(t, 0, checkoutWith(t, changes)["fetch-depth"], "changes needs the history and origin/<default>")
	for _, j := range []string{"changes", "linux-build", "helper", "windows-required"} {
		assert.Equal(t, false, checkoutWith(t, ymap(t, jobs, j))["persist-credentials"], "%s keeps no token in the clone", j)
	}

	gate := ymap(t, jobs, "windows-required")
	assert.Equal(t, "windows-required", gate["name"], "the context name branch protection requires")
	assert.Equal(t, "always()", gate["if"])
	needs := ystrings(gate["needs"])
	slices.Sort(needs)
	assert.Equal(t, []string{"changes", "helper", "linux-build"}, needs)
	assert.Contains(t, jobRun(t, gate), `deploy/dev/windows-ci.sh gate "$CHANGES" "$WINDOWS" "$LINUX_BUILD" "$HELPER"`,
		"windows passes as is: the script refuses an empty value after a successful changes job")
	gateEnv := stepEnvText(t, gate, "Decide")
	for _, want := range []string{"needs.changes.result", "needs.changes.outputs.windows", "needs.linux-build.result", "needs.helper.result"} {
		assert.Contains(t, gateEnv, want, "the gate step's env")
	}

	compareEnv := stepEnvText(t, ymap(t, jobs, "helper"), "Compare with the Linux build")
	for _, want := range []string{"needs.linux-build.outputs.amd64", "needs.linux-build.outputs.arm64"} {
		assert.Contains(t, compareEnv, want, "the F13 comparison (Ruling 10)")
	}

	for _, j := range []string{"linux-build", "helper"} {
		cond, _ := ymap(t, jobs, j)["if"].(string)
		assert.Contains(t, cond, "needs.changes.outputs.windows", "%s runs only when changes says so", j)
	}

	for name := range jobs {
		for _, s := range ysteps(t, ymap(t, jobs, name)) {
			if r, ok := s["run"].(string); ok {
				assert.NotContains(t, r, "${{", "job %s step %v: values reach run text through env: only", name, s["name"])
			}
		}
	}
}

var (
	requiredListRE = regexp.MustCompile(`(?s)\$required = @\((.*?)\n\s*\)`)
	quotedNameRE   = regexp.MustCompile(`'(Test\w+)'`)
)

// Ruling 7: the workflow's $required list names exactly the real and fidelity tests.
func TestWindowsWorkflowRequiresEveryRealTest(t *testing.T) {
	root := moduleRoot(t)
	doc := loadWorkflow(t, windowsWorkflow)
	helper := ymap(t, ymap(t, doc, "jobs"), "helper")
	m := requiredListRE.FindStringSubmatch(jobRun(t, helper))
	require.NotNil(t, m, "the helper job has no $required = @(...) list")
	var required []string
	for _, q := range quotedNameRE.FindAllStringSubmatch(m[1], -1) {
		required = append(required, q[1])
	}
	require.NotEmpty(t, required)

	files, err := filepath.Glob(filepath.Join(root, "cmd", "alice-winhelper", "*_test.go"))
	require.NoError(t, err)
	require.NoError(t, filepath.WalkDir(filepath.Join(root, "internal", "providers", "windows"), func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() && strings.HasSuffix(p, "_test.go") {
			files = append(files, p)
		}
		return err
	}))
	var found []string
	fset := token.NewFileSet()
	for _, f := range files {
		file, err := parser.ParseFile(fset, f, nil, parser.SkipObjectResolution)
		require.NoError(t, err)
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if ok && fn.Recv == nil && (strings.HasPrefix(fn.Name.Name, "TestReal") || strings.HasPrefix(fn.Name.Name, "TestFidelity")) {
				found = append(found, fn.Name.Name)
			}
		}
	}
	require.Contains(t, found, "TestRealRunnerIsClean", "positive control")

	var missing, stale []string
	for _, n := range found {
		if !slices.Contains(required, n) {
			missing = append(missing, n)
		}
	}
	for _, n := range required {
		if !slices.Contains(found, n) {
			stale = append(stale, n)
		}
	}
	slices.Sort(missing)
	slices.Sort(stale)
	assert.Empty(t, missing, "real tests missing from $required in %s", windowsWorkflow)
	assert.Empty(t, stale, "names in $required in %s that are no test", windowsWorkflow)
	assert.Len(t, slices.Compact(slices.Sorted(slices.Values(required))), len(required), "a name is listed twice")
}

// Ruling 10: one set of build flags for alice-helper.exe in the Makefile, the reproducibility check
// and the Windows legs, so the runners test the bytes the release ships.
func TestWindowsHelperBuildFlagsAgree(t *testing.T) {
	root := moduleRoot(t)
	common := []string{"-trimpath", "-buildvcs=false", `-ldflags "-s -w"`}
	archLevel := map[string]string{"amd64": "GOAMD64=v1", "arm64": "GOARM64=v8.0"}

	// checkLines requires one build line per architecture with the common flags and its GOARCH level.
	checkLines := func(t *testing.T, where string, lines []string) {
		t.Helper()
		for arch, level := range archLevel {
			var hit []string
			for _, l := range lines {
				if strings.Contains(l, "GOARCH="+arch) {
					hit = append(hit, l)
				}
			}
			require.Len(t, hit, 1, "%s: one Windows build line for %s", where, arch)
			for _, f := range append([]string{level}, common...) {
				assert.Contains(t, hit[0], f, "%s %s", where, arch)
			}
		}
	}

	t.Run("Makefile winhelper", func(t *testing.T) {
		raw, err := os.ReadFile(filepath.Join(root, "Makefile")) //nolint:gosec // repository file
		require.NoError(t, err)
		_, recipe, ok := strings.Cut(string(raw), "\nwinhelper:")
		require.True(t, ok, "no winhelper target")
		recipe, _, _ = strings.Cut(recipe, "\n\n")
		var builds []string
		for _, l := range strings.Split(recipe, "\n") {
			if strings.Contains(l, "go build") {
				assert.Contains(t, l, "CGO_ENABLED=0")
				assert.Contains(t, l, "GOOS=windows")
				builds = append(builds, l)
			}
		}
		checkLines(t, "Makefile", builds)
	})

	t.Run("reproducible-check.sh", func(t *testing.T) {
		raw, err := os.ReadFile(filepath.Join(root, "deploy", "dev", "reproducible-check.sh")) //nolint:gosec // repository file
		require.NoError(t, err)
		text := string(raw)
		assert.Contains(t, text, "export CGO_ENABLED=0", "the builds of build_copy inherit it")
		var builds []string
		for _, l := range strings.Split(text, "\n") {
			if strings.Contains(l, "GOOS=windows") && strings.Contains(l, "go build") {
				builds = append(builds, l)
			}
		}
		checkLines(t, "reproducible-check.sh", builds)
	})

	// The image builds the helpers whose checksums its alice embeds: one loop over both architectures,
	// both levels on the one line (Go reads only GO$GOARCH).
	t.Run("deploy/Dockerfile", func(t *testing.T) {
		raw, err := os.ReadFile(filepath.Join(root, "deploy", "Dockerfile")) //nolint:gosec // repository file
		require.NoError(t, err)
		text := string(raw)
		var builds []string
		for _, l := range strings.Split(text, "\n") {
			if strings.Contains(l, "GOOS=windows") && strings.Contains(l, "go build") {
				builds = append(builds, l)
			}
		}
		require.Len(t, builds, 1, "one Windows helper build line in the Dockerfile")
		for _, f := range append([]string{"CGO_ENABLED=0", "GOARCH=$arch", "GOAMD64=v1", "GOARM64=v8.0"}, common...) {
			assert.Contains(t, builds[0], f)
		}
		assert.Contains(t, text, "RUN for arch in amd64 arm64; do \\\n      CGO_ENABLED=0 GOOS=windows", "the loop covers both architectures")
	})

	t.Run("windows.yml", func(t *testing.T) {
		doc := loadWorkflow(t, windowsWorkflow)
		var build map[string]any
		for _, s := range ysteps(t, ymap(t, ymap(t, doc, "jobs"), "helper")) {
			if r, _ := s["run"].(string); strings.Contains(r, "go build") {
				require.Nil(t, build, "one build step")
				build = s
			}
		}
		require.NotNil(t, build, "no build step in the helper job")
		env, _ := build["env"].(map[string]any)
		assert.Equal(t, "0", env["CGO_ENABLED"])
		assert.Equal(t, "windows", env["GOOS"])
		assert.Equal(t, "v1", env["GOAMD64"], "amd64 level")
		assert.Equal(t, "v8.0", env["GOARM64"], "arm64 level")
		run, _ := build["run"].(string)
		for _, f := range common {
			assert.Contains(t, run, f)
		}
		for arch := range archLevel {
			assert.Contains(t, run, "'"+arch+"'")
		}
	})
}

// R63 Ruling 12: a version tag stages the release only after the real-Windows check: release.yml calls
// windows.yml with all: true (every leg runs, whatever the change) and stage needs that job.
func TestReleaseWorkflowWaitsForWindows(t *testing.T) {
	doc := loadWorkflow(t, ".github/workflows/release.yml")
	jobs := ymap(t, doc, "jobs")
	win := ymap(t, jobs, "windows")
	assert.Equal(t, "./.github/workflows/windows.yml", win["uses"])
	with := ymap(t, win, "with")
	assert.Equal(t, true, with["all"], "the release call runs every Windows leg")
	assert.Equal(t, map[string]any{"contents": "read"}, win["permissions"])
	stage := ymap(t, jobs, "stage")
	needs := ystrings(stage["needs"])
	assert.Contains(t, needs, "windows", "stage waits for the real-Windows check")
	for _, j := range []string{"gates", "zap-full", "fuzz"} {
		assert.Contains(t, needs, j)
	}
}
