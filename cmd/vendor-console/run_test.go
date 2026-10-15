package main

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"

	"alice/internal/platform/clock"
)

func runArgs(args ...string) (int, string, string) {
	var out, errOut bytes.Buffer
	code := run(args, func(string) string { return "" }, &out, &errOut, nil, clock.Real{})
	return code, out.String(), errOut.String()
}

func TestNoArgumentsPrintsUsage(t *testing.T) {
	code, _, stderr := runArgs()
	assert.Equal(t, 2, code)
	assert.Contains(t, stderr, "Usage: vendor-console")
}

func TestUnknownCommandIsRefused(t *testing.T) {
	code, _, stderr := runArgs("frobnicate")
	assert.Equal(t, 2, code)
	assert.Contains(t, stderr, "frobnicate")
}

func TestCommandsThatNeedTheDatabaseSayHowToSetIt(t *testing.T) {
	for _, args := range [][]string{{"migrate"}, {"request", "list"}, {"audit-verify"}} {
		code, _, stderr := runArgs(args...)
		assert.Equal(t, 1, code, args)
		assert.Contains(t, stderr, "VENDOR_DATABASE_URL", args)
	}
}

func TestIssueNeedsItsFlags(t *testing.T) {
	code, _, stderr := runArgs("issue", "--request", "1")
	assert.Equal(t, 2, code)
	assert.Contains(t, stderr, "--hash")
}

func TestUsageListsTheWebUserCommands(t *testing.T) {
	_, _, stderr := runArgs()
	assert.Contains(t, stderr, "web-user add NAME")
	assert.Contains(t, stderr, "web-user list")
}

func TestWebUserCommandsNeedAName(t *testing.T) {
	for _, sub := range []string{"add", "invite", "disable", "enable"} {
		code, _, stderr := runArgs("web-user", sub)
		assert.Equal(t, 2, code, sub)
		assert.Contains(t, stderr, "NAME", sub)
	}
	code, _, _ := runArgs("web-user")
	assert.Equal(t, 2, code)
	code, _, _ = runArgs("web-user", "frob")
	assert.Equal(t, 2, code)
}
