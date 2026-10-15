package main

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"

	"alice/internal/platform/clock"
)

func runEnv(env map[string]string, args ...string) (int, string, string) {
	var out, errOut bytes.Buffer
	code := run(args, func(k string) string { return env[k] }, &out, &errOut, nil, clock.Real{})
	return code, out.String(), errOut.String()
}

func TestUsageListsTheNotifyAndSettingsCommands(t *testing.T) {
	_, _, stderr := runArgs()
	for _, want := range []string{"notify run", "settings set KEY VALUE", "settings show", "web-user set-email NAME EMAIL",
		"VENDOR_SMTP_ADDR"} {
		assert.Contains(t, stderr, want)
	}
}

func TestSettingsValuesAreCheckedBeforeTheDatabase(t *testing.T) {
	for _, args := range [][]string{
		{"settings", "set", "owner_email", "not-an-address"},
		{"settings", "set", "owner_email", "Boss <boss@example.com>"},
		{"settings", "set", "owner_email", "boss@localhost"},
		{"settings", "set", "owner_email", ""},
		{"settings", "set", "timezone", "Nowhere/City"},
		{"settings", "set", "timezone", "Local"},
		{"settings", "set", "timezone", ""},
		{"settings", "set", "last_summary_at", "2026-10-01T00:00:00Z"},
		{"settings", "set", "owner_email"},
		{"settings", "set"},
		{"settings", "show", "extra"},
		{"web-user", "set-email", "ayse", "ayşe@example.com"},
		{"web-user", "set-email", "ayse"},
		{"web-user", "set-email", "", "a@b.co"},
	} {
		code, _, stderr := runArgs(args...)
		assert.Equal(t, 2, code, "%q", args)
		assert.NotContains(t, stderr, "VENDOR_DATABASE_URL", "%q is refused before connecting", args)
	}
}

func TestUnknownSettingsCommandsAreRefused(t *testing.T) {
	for _, args := range [][]string{{"settings"}, {"settings", "frob"}, {"notify"}, {"notify", "frob"}} {
		code, _, _ := runArgs(args...)
		assert.Equal(t, 2, code, args)
	}
}

func TestNotifyRunNeedsTheSMTPSettingsBeforeTheDatabase(t *testing.T) {
	for _, env := range []map[string]string{
		{},
		{"VENDOR_SMTP_ADDR": "smtp.example.com:587"},
		{"VENDOR_SMTP_FROM": "console@example.com"},
		{"VENDOR_SMTP_ADDR": "smtp.example.com", "VENDOR_SMTP_FROM": "console@example.com"},
		{"VENDOR_SMTP_ADDR": "smtp.example.com:587", "VENDOR_SMTP_FROM": "console@example.com", "VENDOR_SMTP_USER": "u"},
	} {
		code, _, stderr := runEnv(env, "notify", "run")
		assert.Equal(t, 2, code, env)
		assert.Contains(t, stderr, "VENDOR_SMTP", env)
		assert.NotContains(t, stderr, "VENDOR_DATABASE_URL", env)
	}
	// A dry run sends nothing and so needs no SMTP settings: it goes on to the database.
	code, _, stderr := runEnv(map[string]string{}, "notify", "run", "--dry-run")
	assert.Equal(t, 1, code)
	assert.Contains(t, stderr, "VENDOR_DATABASE_URL")
}

func TestNotifyRunRefusesABadBaseURL(t *testing.T) {
	env := map[string]string{"VENDOR_SMTP_ADDR": "smtp.example.com:587", "VENDOR_SMTP_FROM": "console@example.com"}
	for _, u := range []string{"ftp://x.example", "https://user:pw@x.example", "not a url", "https://x.example/?q=1"} {
		code, _, stderr := runEnv(env, "notify", "run", "--base-url", u)
		assert.Equal(t, 2, code, u)
		assert.NotContains(t, stderr, "pw@", u)
	}
	code, _, _ := runEnv(env, "notify", "run", "extra")
	assert.Equal(t, 2, code)
	code, _, _ = runEnv(env, "notify")
	assert.Equal(t, 2, code)
}

func TestTheSMTPPasswordIsNeverPrinted(t *testing.T) {
	const pw = "hunter2-very-secret"
	for _, env := range []map[string]string{
		{"VENDOR_SMTP_ADDR": "smtp.example.com:587", "VENDOR_SMTP_FROM": "console@example.com", "VENDOR_SMTP_PASSWORD": pw},
		{"VENDOR_SMTP_ADDR": "smtp.example.com:587", "VENDOR_SMTP_FROM": "console@example.com", "VENDOR_SMTP_USER": "u",
			"VENDOR_SMTP_PASSWORD": pw + "\n"},
		{"VENDOR_SMTP_ADDR": "smtp.example.com:587", "VENDOR_SMTP_FROM": "bad from", "VENDOR_SMTP_USER": "u", "VENDOR_SMTP_PASSWORD": pw},
		{"VENDOR_SMTP_ADDR": "smtp.example.com:587", "VENDOR_SMTP_FROM": "console@example.com", "VENDOR_SMTP_USER": "u",
			"VENDOR_SMTP_PASSWORD": pw},
	} {
		_, out, stderr := runEnv(env, "notify", "run")
		assert.NotContains(t, out+stderr, pw)
	}
}
