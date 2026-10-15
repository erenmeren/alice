package main

import (
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestVendorToolsCrossCompile keeps the signing program buildable for Windows and macOS: the spec
// requires Linux, Windows and macOS, and a Unix-only call in a shared package would otherwise
// break those builds without any test noticing.
func TestVendorToolsCrossCompile(t *testing.T) {
	if testing.Short() {
		t.Skip("cross-compiles the vendor commands")
	}
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("the go command is not on PATH")
	}
	for _, target := range []struct{ goos, goarch string }{
		{"windows", "amd64"}, {"darwin", "amd64"}, {"darwin", "arm64"},
	} {
		t.Run(target.goos+"-"+target.goarch, func(t *testing.T) {
			for _, pkg := range []string{"alice/cmd/vendor-console", "alice/cmd/licensectl", "alice/cmd/vendor-web"} {
				out := t.TempDir() + "/bin"
				build := exec.Command(goBin, "build", "-o", out, pkg)
				build.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS="+target.goos, "GOARCH="+target.goarch)
				timer := time.AfterFunc(8*time.Minute, func() { _ = build.Process.Kill() })
				msg, err := build.CombinedOutput()
				timer.Stop()
				require.NoError(t, err, "%s for %s/%s: %s", pkg, target.goos, target.goarch, msg)
			}
		})
	}
}

// goEnv runs the go command with extra environment and returns its combined output.
func goEnv(t *testing.T, env []string, args ...string) string {
	t.Helper()
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("the go command is not on PATH")
	}
	cmd := exec.Command(goBin, args...)
	cmd.Env = append(os.Environ(), env...)
	timer := time.AfterFunc(8*time.Minute, func() { _ = cmd.Process.Kill() })
	out, err := cmd.CombinedOutput()
	timer.Stop()
	require.NoError(t, err, "go %s: %s", strings.Join(args, " "), out)
	return string(out)
}

// On Windows the PC/SC library (WinSCard) is reached without cgo, so the YubiKey build is a
// plain cross build there.
func TestVendorConsoleYubiKeyBuildCrossCompilesForWindows(t *testing.T) {
	if testing.Short() {
		t.Skip("cross-compiles the vendor console")
	}
	goEnv(t, []string{"CGO_ENABLED=0", "GOOS=windows", "GOARCH=amd64"},
		"build", "-tags", "yubikey", "-o", t.TempDir()+"/vendor-console.exe", "alice/cmd/vendor-console")
}

// The build without the yubikey tag links the pcsc stub only: no PC/SC library code. The tagged
// build does link it.
func TestUntaggedBuildCarriesNoPCSCLibrary(t *testing.T) {
	if testing.Short() {
		t.Skip("lists the dependencies of the vendor console")
	}
	const scard = "github.com/ebfe/scard"
	untagged := goEnv(t, []string{"CGO_ENABLED=0"}, "list", "-deps", "alice/cmd/vendor-console")
	assert.NotContains(t, untagged, scard)
	assert.Contains(t, untagged, "alice/internal/vconsole/sign/pcsc", "the stub package is linked")
	tagged := goEnv(t, []string{"CGO_ENABLED=1"}, "list", "-deps", "-tags", "yubikey", "alice/cmd/vendor-console")
	assert.Contains(t, tagged, scard)
}
