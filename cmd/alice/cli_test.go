package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/license"
)

func TestCLIUsageErrors(t *testing.T) {
	cases := map[string][]string{
		"setup-token without --reset": {"setup-token"},
		"setup-token with extra args": {"setup-token", "--reset", "now"},
		"audit without subcommand":    {"audit"},
		"audit unknown subcommand":    {"audit", "delete"},
		"admin without subcommand":    {"admin"},
		"reset-mfa without username":  {"admin", "reset-mfa"},
		"reset-mfa empty username":    {"admin", "reset-mfa", ""},
		"admin unknown subcommand":    {"admin", "delete-user", "bob"},
		"unlock without username":     {"admin", "unlock"},
		"unlock empty username":       {"admin", "unlock", ""},
		"unlock with extra args":      {"admin", "unlock", "bob", "now"},
		"license without subcommand":  {"license"},
		"license unknown subcommand":  {"license", "delete"},
		"license status extra args":   {"license", "status", "now"},
	}
	for name, args := range cases {
		t.Run(name, func(t *testing.T) {
			var out, errOut bytes.Buffer
			assert.Equal(t, 2, run(args, env(nil), nil, &out, &errOut))
			assert.Contains(t, errOut.String(), "usage: alice")
			assert.Empty(t, out.String())
		})
	}
}

func TestCLICommandsNeedDatabaseURL(t *testing.T) {
	for _, args := range [][]string{{"setup-token", "--reset"}, {"audit", "verify"}, {"admin", "reset-mfa", "bob"}, {"admin", "unlock", "bob"}, {"license", "status"}} {
		var out, errOut bytes.Buffer
		assert.Equal(t, 1, run(args, env(nil), nil, &out, &errOut), args)
		assert.Contains(t, errOut.String(), "ALICE_DATABASE_URL", args)
	}
}

func TestHelpListsOperatorCommands(t *testing.T) {
	var out, errOut bytes.Buffer
	assert.Equal(t, 0, run([]string{"help"}, env(nil), nil, &out, &errOut))
	for _, s := range []string{"setup-token --reset", "audit verify", "admin reset-mfa <username>", "admin unlock <username>"} {
		assert.Contains(t, out.String(), s)
	}
}

func TestLicenseKeysCommand(t *testing.T) {
	var out, errOut bytes.Buffer
	require.Equal(t, 0, run([]string{"license", "keys"}, env(nil), nil, &out, &errOut))
	keys := license.EmbeddedKeys()
	if keys.Len() == 0 {
		assert.Contains(t, out.String(), "No license verification key is embedded in this build")
	}
	for _, k := range keys.Keys() {
		assert.Contains(t, out.String(), k.ID)
		assert.Contains(t, out.String(), license.Fingerprint(k.Key))
	}
	assert.Equal(t, license.TestKeyTrusted, strings.Contains(out.String(), "WARNING: test build"))
	assert.Equal(t, 2, run([]string{"license"}, env(nil), nil, &out, &errOut))
	assert.Equal(t, 2, run([]string{"license", "delete"}, env(nil), nil, &out, &errOut))
}
