package main

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
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
	}
	for name, args := range cases {
		t.Run(name, func(t *testing.T) {
			var out, errOut bytes.Buffer
			assert.Equal(t, 2, run(args, env(nil), &out, &errOut))
			assert.Contains(t, errOut.String(), "usage: alice")
			assert.Empty(t, out.String())
		})
	}
}

func TestCLICommandsNeedDatabaseURL(t *testing.T) {
	for _, args := range [][]string{{"setup-token", "--reset"}, {"audit", "verify"}, {"admin", "reset-mfa", "bob"}, {"admin", "unlock", "bob"}} {
		var out, errOut bytes.Buffer
		assert.Equal(t, 1, run(args, env(nil), &out, &errOut), args)
		assert.Contains(t, errOut.String(), "ALICE_DATABASE_URL", args)
	}
}

func TestHelpListsOperatorCommands(t *testing.T) {
	var out, errOut bytes.Buffer
	assert.Equal(t, 0, run([]string{"help"}, env(nil), &out, &errOut))
	for _, s := range []string{"setup-token --reset", "audit verify", "admin reset-mfa <username>", "admin unlock <username>"} {
		assert.Contains(t, out.String(), s)
	}
}
