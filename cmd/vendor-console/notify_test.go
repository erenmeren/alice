package main

import (
	"bytes"
	"os/exec"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/platform/clock"
)

func runEnv(env map[string]string, args ...string) (int, string, string) {
	var out, errOut bytes.Buffer
	code := run(args, func(k string) string { return env[k] }, &out, &errOut, nil, clock.Real{})
	return code, out.String(), errOut.String()
}

func TestUsageListsTheNotifyAndSettingsCommands(t *testing.T) {
	_, _, stderr := runArgs()
	for _, want := range []string{"notify run [--dry-run]", "settings set KEY VALUE", "settings show",
		"web-user add NAME [--owner]"} {
		assert.Contains(t, stderr, want)
	}
}

// Nothing of the e-mail machinery is left in the command line: no command, no variable, no flag.
func TestUsageNamesNoMailCommand(t *testing.T) {
	_, _, stderr := runArgs()
	for _, gone := range []string{"smtp", "mail", "owner_email", "set-email", "notify failed", "notify retry", "--base-url"} {
		assert.NotRegexp(t, "(?i)"+regexp.QuoteMeta(gone), stderr)
	}
}

func TestSettingsValuesAreCheckedBeforeTheDatabase(t *testing.T) {
	for _, args := range [][]string{
		{"settings", "set", "timezone", "Nowhere/City"},
		{"settings", "set", "timezone", "Local"},
		{"settings", "set", "timezone", ""},
		{"settings", "set", "last_summary_at", "2026-10-01T00:00:00Z"},
		{"settings", "set", "owner_email", "boss@example.com"},
		{"settings", "set", "timezone"},
		{"settings", "set"},
		{"settings", "show", "extra"},
	} {
		code, _, stderr := runArgs(args...)
		assert.Equal(t, 2, code, "%q", args)
		assert.NotContains(t, stderr, "VENDOR_DATABASE_URL", "%q is refused before connecting", args)
	}
}

func TestAnUnknownSettingNamesTheAllowedKeys(t *testing.T) {
	for _, key := range []string{"owner_email", "last_summary_at", "frob"} {
		code, _, stderr := runArgs("settings", "set", key, "x")
		assert.Equal(t, 2, code, key)
		assert.Contains(t, stderr, `unknown setting "`+key+`"`)
		assert.Contains(t, stderr, "(allowed keys: timezone)", key)
	}
}

func TestRemovedCommandsAreUnknown(t *testing.T) {
	for _, args := range [][]string{
		{"web-user", "set-email", "ayse", "ayse@example.com"},
		{"notify", "failed"},
		{"notify", "retry", "3"},
	} {
		code, _, stderr := runArgs(args...)
		assert.Equal(t, 2, code, "%q", args)
		assert.Contains(t, stderr, "unknown command", "%q", args)
	}
}

func TestUnknownSettingsCommandsAreRefused(t *testing.T) {
	for _, args := range [][]string{{"settings"}, {"settings", "frob"}, {"notify"}, {"notify", "frob"}} {
		code, _, _ := runArgs(args...)
		assert.Equal(t, 2, code, args)
	}
}

// notify run needs only the database: the SMTP variables are gone and are ignored when set.
func TestNotifyRunGoesStraightToTheDatabase(t *testing.T) {
	for _, args := range [][]string{{"notify", "run"}, {"notify", "run", "--dry-run"}} {
		code, _, stderr := runEnv(map[string]string{"VENDOR_SMTP_ADDR": "smtp.example.com:587"}, args...)
		assert.Equal(t, 1, code, args)
		assert.Contains(t, stderr, "VENDOR_DATABASE_URL", args)
		assert.NotRegexp(t, "(?i)smtp", stderr, args)
	}
}

func TestNotifyRunRefusesExtraArgumentsAndTheOldFlag(t *testing.T) {
	for _, args := range [][]string{
		{"notify", "run", "extra"},
		{"notify", "run", "--base-url", "https://licenses.example.com"},
		{"notify", "run", "--dry-run", "extra"},
	} {
		code, _, stderr := runArgs(args...)
		assert.Equal(t, 2, code, "%q", args)
		assert.NotContains(t, stderr, "VENDOR_DATABASE_URL", "%q is refused before connecting", args)
	}
}

func TestWebUserAddTakesOnlyTheOwnerFlag(t *testing.T) {
	for _, args := range [][]string{
		{"web-user", "add", "--owner"},
		{"web-user", "add", "--role", "owner", "ayse"},
		{"web-user", "add", "ayse", "bo"},
		{"web-user", "add", "ayse", "--owner", "--owner"},
		{"web-user", "add", "ayse", "--owner=false"},
		{"web-user", "invite", "--owner", "ayse"},
	} {
		code, _, stderr := runArgs(args...)
		assert.Equal(t, 2, code, "%q", args)
		assert.NotContains(t, stderr, "VENDOR_DATABASE_URL", "%q is refused before connecting", args)
	}
	for _, args := range [][]string{{"web-user", "add", "ayse", "--owner"}, {"web-user", "add", "--owner", "ayse"},
		{"web-user", "add", "ayse"}} {
		code, _, stderr := runArgs(args...)
		assert.Equal(t, 1, code, "%q", args)
		assert.Contains(t, stderr, "VENDOR_DATABASE_URL", "%q", args)
	}
}

func TestTheConsoleLinksNoSMTPClient(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps", "alice/cmd/vendor-console").CombinedOutput()
	require.NoError(t, err, string(out))
	for _, dep := range strings.Fields(string(out)) {
		assert.NotEqual(t, "net/smtp", dep)
		assert.NotContains(t, dep, "alice/internal/vconsole/mail")
	}
}
