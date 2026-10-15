package main

import (
	"os"
	"os/exec"
	"testing"
	"time"

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
