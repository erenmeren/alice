package archtest

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

func TestWindowsChangedScript(t *testing.T) {
	const list = "# watched\n\na/**\n  # indented comment\nb/*\nc.txt\n"
	cases := []struct {
		name  string
		input string
		code  int
	}{
		{"below a dir/** entry", "a/x/y.go\n", 0},
		{"directly in a dir/* entry", "b/z.go\n", 0},
		{"below a dir/* entry", "b/sub/z.go\n", 1},
		{"an exact entry", "c.txt\n", 0},
		{"a longer name than an exact entry", "c.txt.bak\n", 1},
		{"a sibling with the same prefix", "ab/x\n", 1},
		{"the dir of a dir/** entry itself", "a\n", 1},
		{"the dir of a dir/* entry itself", "b\n", 1},
		{"a comment line is no entry", "# watched\n", 1},
		{"empty input", "", 1},
		{"one match among others", "web/x.ts\nb/sub/z.go\nb/ok.go\n", 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			code, out := changedWith(t, list, c.input)
			assert.Equal(t, c.code, code, out)
		})
	}
	t.Run("prints the first matching name", func(t *testing.T) {
		code, out := changedWith(t, list, "web/x.ts\nb/ok.go\na/q\n")
		require.Equal(t, 0, code, out)
		assert.Equal(t, "b/ok.go", strings.TrimSpace(out))
	})
	for _, bad := range []string{"a/**/b", "/abs/**", "a/../b", "..", "a b/**", "a/*/b", "**", "a/**x", "*.go", "a/"} {
		t.Run("entry of another form "+bad, func(t *testing.T) {
			code, out := changedWith(t, "c.txt\n"+bad+"\n", "c.txt\n")
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
		args string
		code int
	}{
		{"success false skipped skipped", 0},
		{"success true success success", 0},
		{"success true success failure", 1},
		{"success true success cancelled", 1},
		{"success true skipped skipped", 1},
		{"success true failure success", 1},
		{"failure false skipped skipped", 1},
		{"success false success success", 1}, // the legs ran although nothing changed: a wrong changes output
		{"cancelled true skipped skipped", 1},
		{"success maybe skipped skipped", 2},
		{"success true success", 2},
		{"done true success success", 2},
		{"success true success passed", 2},
	}
	for _, c := range cases {
		t.Run(c.args, func(t *testing.T) {
			code, out := runWindowsCI(t, "", append([]string{"gate"}, strings.Fields(c.args)...)...)
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
	cmd := exec.Command("git", "ls-files")
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
			if code, out := runWindowsCI(t, d+"/doc.go\n", "changed", windowsPaths); code != 0 {
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
