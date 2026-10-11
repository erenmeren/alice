package main

import (
	"archive/tar"
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// runImageCheck runs deploy/dev/check-image.sh against a fake docker and a fake go: docker serves a
// release image whose binary holds the helper checksums when withSums is set, go reports hostGo as
// its own version and binGo as the version that built the binary. It returns the output and the
// exit status.
func runImageCheck(t *testing.T, hostGo, binGo string, withSums, ci bool) (string, int) {
	t.Helper()
	for _, tool := range []string{"bash", "tar", "awk", "grep", "find", "sort", "tr"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not available: %v", tool, err)
		}
	}
	dir := t.TempDir()
	const sumAMD, sumARM = "aaaa1111amd64sum", "bbbb2222arm64sum"

	binary := "\x7fELF fake alice"
	if withSums {
		binary += " " + sumAMD + " " + sumARM
	}
	var rootfs bytes.Buffer
	tw := tar.NewWriter(&rootfs)
	add := func(name string, mode int64, body string, typ byte) {
		require.NoError(t, tw.WriteHeader(&tar.Header{Name: name, Mode: mode, Size: int64(len(body)), Typeflag: typ, Uid: 10001, Gid: 10001}))
		_, err := tw.Write([]byte(body))
		require.NoError(t, err)
	}
	add("etc/update-motd.d/10-uname", 0o755, "#!/bin/sh\nuname\n", tar.TypeReg)
	add("opt/alice/keys/", 0o750, "", tar.TypeDir)
	add("opt/alice/state/", 0o700, "", tar.TypeDir)
	add("opt/alice/backups/", 0o700, "", tar.TypeDir)
	add("usr/local/bin/alice", 0o755, binary, tar.TypeReg)
	require.NoError(t, tw.Close())
	require.NoError(t, os.WriteFile(filepath.Join(dir, "rootfs.tar"), rootfs.Bytes(), 0o600))

	fakeDocker := `#!/usr/bin/env bash
case "$1 $2" in
  "image inspect")
    case "$4" in
      *User*) echo "10001:10001" ;;
      *Entrypoint*) echo '["/usr/local/bin/alice"]' ;;
      *Cmd*) echo '["serve"]' ;;
      *Healthcheck*) echo '["CMD","/usr/local/bin/alice","healthcheck"]' ;;
      *ExposedPorts*) echo '{"8443/tcp":{}}' ;;
      *Volumes*) echo null ;;
      *Env*) echo PATH=/usr/bin ;;
    esac ;;
  create*) echo fakeid ;;
  export*) cat "$FAKE_DIR/rootfs.tar" ;;
  rm*) ;;
  run*)
    case "${*: -1}" in
      version) echo "alice 1.0.0 (abc)" ;;
      keys) echo "vk-prod-1" ;;
      help) echo "  healthcheck  check a running server" ;;
      healthcheck) exit 1 ;;
    esac ;;
esac
`
	fakeGo := `#!/usr/bin/env bash
case "$1" in
  env) echo "$FAKE_HOST_GO" ;;
  version) printf '%s: %s\n\tbuild\tCGO_ENABLED=0\n' "$3" "$FAKE_BIN_GO" ;;
esac
`
	require.NoError(t, os.WriteFile(filepath.Join(dir, "docker"), []byte(fakeDocker), 0o700)) //nolint:gosec // a test script
	require.NoError(t, os.WriteFile(filepath.Join(dir, "go"), []byte(fakeGo), 0o700))         //nolint:gosec // a test script

	cmd := exec.Command("bash", "../../deploy/dev/check-image.sh", "ci")
	env := []string{}
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, "CI=") {
			env = append(env, kv)
		}
	}
	if ci {
		env = append(env, "CI=true")
	}
	cmd.Env = append(env,
		"PATH="+dir+string(os.PathListSeparator)+os.Getenv("PATH"),
		"FAKE_DIR="+dir, "FAKE_HOST_GO="+hostGo, "FAKE_BIN_GO="+binGo,
		"TEST_LICENSE_LABEL=test-license-label", "TEST_ROUTE_MARKER=/test/clock", "E2E_AZURE_MARKER=/run/alice-e2e-azure",
		"HELPER_SHA256_AMD64="+sumAMD, "HELPER_SHA256_ARM64="+sumARM,
	)
	out, err := cmd.CombinedOutput()
	status := 0
	if err != nil {
		var exitErr *exec.ExitError
		require.ErrorAs(t, err, &exitErr, string(out))
		status = exitErr.ExitCode()
	}
	return string(out), status
}

// The helper checksums are compared only when the host's Go built them with the same version as
// the image's binary; otherwise the two checks are skipped with a message, never failed.
func TestImageCheckComparesHelperChecksumsOnlyWithTheSameGo(t *testing.T) {
	out, status := runImageCheck(t, "go1.27.1", "go1.27.1", true, false)
	assert.Equal(t, 0, status, out)
	assert.Contains(t, out, "ok:   binary holds the amd64 helper checksum of make helper")
	assert.Contains(t, out, "ok:   binary holds the arm64 helper checksum of make helper")
	assert.NotContains(t, out, "skip:")
	assert.Contains(t, out, "image-check: ok (alice:ci)")

	out, status = runImageCheck(t, "go1.27.1", "go1.27.1", false, false)
	assert.Equal(t, 1, status, out)
	assert.Contains(t, out, "FAIL: binary holds the amd64 helper checksum of make helper")

	out, status = runImageCheck(t, "go1.27.2", "go1.27.1", false, false)
	assert.Equal(t, 0, status, out)
	assert.Contains(t, out, "skip: binary holds the helper checksums of make helper (host Go go1.27.2, image binary built with go1.27.1;")
	assert.NotContains(t, out, "helper checksum of make helper")
	assert.Equal(t, 0, strings.Count(out, "FAIL:"), out)

	// In CI both Go versions must match: a difference fails instead of skipping.
	out, status = runImageCheck(t, "go1.27.2", "go1.27.1", true, true)
	assert.Equal(t, 1, status, out)
	assert.Contains(t, out, "FAIL: host Go go1.27.2 differs from the Go that built the image's binary (go1.27.1); in CI they must match")
	assert.NotContains(t, out, "skip:")
	out, status = runImageCheck(t, "go1.27.1", "go1.27.1", true, true)
	assert.Equal(t, 0, status, out)
}
