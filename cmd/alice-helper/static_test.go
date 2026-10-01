//go:build linux

package main

import (
	"debug/elf"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestHelperIsStatic builds the helper the way `make helper` does and proves it is a static binary
// (no program interpreter, no shared libraries) that links only the allowed modules (R21).
func TestHelperIsStatic(t *testing.T) {
	if testing.Short() {
		t.Skip("builds the helper binary")
	}
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("the go command is not on PATH")
	}
	out := filepath.Join(t.TempDir(), "alice-helper")
	build := exec.Command(goBin, "build", "-trimpath", "-ldflags", "-s -w", "-o", out, ".")
	build.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux")
	msg, err := build.CombinedOutput()
	require.NoError(t, err, string(msg))

	f, err := elf.Open(out)
	require.NoError(t, err)
	defer func() { _ = f.Close() }()
	for _, p := range f.Progs {
		assert.NotEqual(t, elf.PT_INTERP, p.Type, "a static binary has no program interpreter")
	}
	libs, err := f.ImportedLibraries()
	require.NoError(t, err)
	assert.Empty(t, libs, "a static binary needs no shared library")

	mods, err := exec.Command(goBin, "version", "-m", out).CombinedOutput()
	require.NoError(t, err, string(mods))
	assert.Contains(t, string(mods), "\tmod\talice")
	assert.Contains(t, string(mods), "build\tCGO_ENABLED=0", "the build info records a cgo-free build")
	deps := 0
	for _, line := range strings.Split(string(mods), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == "dep" {
			deps++
			assert.Contains(t, []string{"golang.org/x/crypto", "golang.org/x/sys"}, fields[1], "unexpected module in alice-helper")
		}
	}
	assert.Positive(t, deps, "the build info lists golang.org/x/crypto")

	// The arm64 build is just as static.
	arm := filepath.Join(t.TempDir(), "alice-helper-arm64")
	buildArm := exec.Command(goBin, "build", "-trimpath", "-ldflags", "-s -w", "-o", arm, ".")
	buildArm.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH=arm64")
	msg, err = buildArm.CombinedOutput()
	require.NoError(t, err, string(msg))
	af, err := elf.Open(arm)
	require.NoError(t, err)
	defer func() { _ = af.Close() }()
	assert.Equal(t, elf.EM_AARCH64, af.Machine)
	for _, p := range af.Progs {
		assert.NotEqual(t, elf.PT_INTERP, p.Type)
	}
	armLibs, err := af.ImportedLibraries()
	require.NoError(t, err)
	assert.Empty(t, armLibs, "no DT_NEEDED entries")
}
