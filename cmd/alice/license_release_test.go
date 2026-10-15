//go:build !e2e && !testlicense

package main

import (
	"bytes"
	"log/slog"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/license"
	"alice/internal/license/licensetest"
)

// Spec §22.6 / §26.4: the binary customers run refuses test-signed licenses.
func TestReleaseBinaryRefusesTestSignedLicenses(t *testing.T) {
	assert.False(t, license.TestKeyTrusted)
	now := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	raw := licensetest.Sign(licensetest.Payload(license.NewInstallationID(), now, now.AddDate(1, 0, 0), 10))
	_, err := license.Check(raw, license.EmbeddedKeys())
	assert.ErrorIs(t, err, license.ErrUnknownKey)
}

// The release build of alice links no test signer, no vendor signing code, no testify and
// no terminal library (licensectl-only).
func TestReleaseBinaryLinksNoTestOrVendorCode(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps", ".").Output()
	require.NoError(t, err)
	deps := strings.Fields(string(out))
	require.Contains(t, deps, "alice/internal/license")
	for _, forbidden := range []string{
		"alice/internal/license/licensetest", "alice/internal/license/issuer",
		"alice/internal/vconsole/audit", "alice/internal/vconsole/issue", "alice/internal/vconsole/sign",
		"alice/internal/vconsole/store", "alice/internal/vconsole/migrations",
		"github.com/stretchr/testify/assert", "golang.org/x/term",
	} {
		assert.NotContains(t, deps, forbidden)
	}
}

// A release build has no version suffix and logs no test-build warning (neither the e2e
// nor the test license one).
func TestReleaseBuildIsUnmarkedAndDoesNotWarn(t *testing.T) {
	var out, errOut bytes.Buffer
	require.Equal(t, 0, run([]string{"version"}, env(nil), nil, &out, &errOut))
	assert.Contains(t, out.String(), "alice dev (")
	assert.NotContains(t, out.String(), "e2e")
	assert.NotContains(t, out.String(), "testlicense")
	assert.Equal(t, "dev", buildVersion().Version)

	var logs bytes.Buffer
	warnIfTestBuild(slog.New(slog.NewTextHandler(&logs, nil)), testHandler(testDeps{}))
	assert.Empty(t, logs.String())
}
