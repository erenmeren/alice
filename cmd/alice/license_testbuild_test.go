//go:build testlicense && !e2e

package main

import (
	"bytes"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/license"
)

// A build that trusts the test license key without being the e2e build announces itself:
// a version mark and a startup warning (it must never hold real data).
func TestTestLicenseBuildIsMarkedAndWarns(t *testing.T) {
	require.True(t, license.TestKeyTrusted)
	var out, errOut bytes.Buffer
	require.Equal(t, 0, run([]string{"version"}, env(nil), nil, &out, &errOut))
	assert.Contains(t, out.String(), "alice dev+testlicense (")
	assert.Equal(t, "dev+testlicense", buildVersion().Version)

	var logs bytes.Buffer
	warnIfTestBuild(slog.New(slog.NewTextHandler(&logs, nil)), testHandler(testDeps{}))
	assert.Contains(t, logs.String(), "test license key trusted")
	assert.Contains(t, logs.String(), "never use for real data")
	assert.Contains(t, logs.String(), "level=WARN")
}
