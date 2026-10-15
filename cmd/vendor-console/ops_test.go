package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/license"
	"alice/internal/license/issuer"
)

func TestUsageListsTheOwnerCommands(t *testing.T) {
	_, _, stderr := runArgs()
	for _, want := range []string{"audit-head", "audit-verify [--head SEQ:HASH]", "audit show [--since YYYY-MM-DD]",
		"--actor NAME", "--action PREFIX", "--details", "verify-licenses (--pub FILE", "--keyset FILE",
		"license revoke --id LICENSE-ID --reason TEXT", "notify failed", "notify retry ID"} {
		assert.Contains(t, stderr, want)
	}
}

// writePub writes a fresh public key file and returns its path.
func writePub(t *testing.T) string {
	t.Helper()
	_, pub, err := issuer.GenerateKey("vk-2026-01", []byte(words0), issuer.KDFParams{MemoryKiB: 64, Time: 1, Threads: 1})
	require.NoError(t, err)
	p := filepath.Join(t.TempDir(), "pub.pem")
	require.NoError(t, os.WriteFile(p, pub, 0o600))
	return p
}

const words0 = "amber canyon violet orbit lantern quiet"

func TestOwnerCommandArgumentsAreCheckedBeforeTheDatabase(t *testing.T) {
	pub := writePub(t)
	emptyKS := filepath.Join(t.TempDir(), "ks.json")
	require.NoError(t, os.WriteFile(emptyKS, []byte(`{"keys": []}`), 0o600))
	for _, args := range [][]string{
		{"audit-verify", "--head", "bad"},
		{"audit-verify", "--head", "0:" + strings.Repeat("a", 64)},
		{"audit-verify", "--head", "5:" + strings.Repeat("g", 64)},
		{"audit-verify", "--head", "5:" + strings.Repeat("a", 63)},
		{"audit-verify", "extra"},
		{"audit-head", "extra"},
		{"audit", "show", "--limit", "0"},
		{"audit", "show", "--limit", "1001"},
		{"audit", "show", "--limit", "-1"},
		{"audit", "show", "--since", "15.10.2026"},
		{"audit", "show", "extra"},
		{"verify-licenses"},
		{"verify-licenses", "--pub", pub, "--keyset", emptyKS},
		{"verify-licenses", "--keyset", emptyKS},
		{"verify-licenses", "--pub", filepath.Join(t.TempDir(), "missing.pem")},
		{"verify-licenses", "--pub", emptyKS},
		{"verify-licenses", "--pub", pub, "extra"},
		{"license", "revoke", "--id", "LIC-1-1"},
		{"license", "revoke", "--id", "LIC-1-1", "--reason", "  "},
		{"license", "revoke", "--reason", "customer left"},
		{"notify", "failed", "extra"},
		{"notify", "retry"},
		{"notify", "retry", "0"},
		{"notify", "retry", "x"},
		{"notify", "retry", "1", "2"},
	} {
		code, _, stderr := runArgs(args...)
		assert.Equal(t, 2, code, "%q", args)
		assert.NotContains(t, stderr, "VENDOR_DATABASE_URL", "%q is refused before connecting", args)
	}
}

func TestUnknownOwnerSubcommandsAreRefused(t *testing.T) {
	for _, args := range [][]string{{"audit"}, {"audit", "frob"}, {"license"}, {"license", "frob"}} {
		code, _, stderr := runArgs(args...)
		assert.Equal(t, 2, code, "%q", args)
		assert.Contains(t, stderr, "unknown command", "%q", args)
	}
}

func TestValidOwnerCommandsGoOnToTheDatabase(t *testing.T) {
	pub := writePub(t)
	for _, args := range [][]string{
		{"audit-head"},
		{"audit-verify", "--head", "7:" + strings.Repeat("A", 64)},
		{"audit", "show", "--limit", "1000", "--since", "2026-10-01", "--actor", "x", "--action", "license.", "--details"},
		{"verify-licenses", "--pub", pub},
		{"license", "revoke", "--id", "LIC-1-1", "--reason", "customer left"},
		{"notify", "failed"},
		{"notify", "retry", "3"},
	} {
		code, _, stderr := runArgs(args...)
		assert.Equal(t, 1, code, "%q", args)
		assert.Contains(t, stderr, "VENDOR_DATABASE_URL", "%q", args)
	}
}

func TestOwnerCommandsNeverPrintTheDatabaseURLOrPassword(t *testing.T) {
	const pw = "db-pw-never-printed"
	// Nothing listens on port 1, so every command fails at the connection.
	dbURL := "postgres://vendor_owner_login:" + pw + "@127.0.0.1:1/vendor?sslmode=disable&connect_timeout=2"
	pub := writePub(t)
	old := connectTimeout
	connectTimeout = 300 * time.Millisecond // db.Open retries until the timeout
	t.Cleanup(func() { connectTimeout = old })
	for _, args := range [][]string{
		{"audit-head"},
		{"audit-verify"},
		{"audit-verify", "--head", "7:" + strings.Repeat("a", 64)},
		{"audit", "show", "--details"},
		{"verify-licenses", "--pub", pub},
		{"license", "revoke", "--id", "LIC-1-1", "--reason", "customer left"},
		{"notify", "failed"},
		{"notify", "retry", "3"},
	} {
		code, out, stderr := runEnv(map[string]string{"VENDOR_DATABASE_URL": dbURL}, args...)
		assert.Equal(t, 1, code, "%q", args)
		assert.NotContains(t, out+stderr, pw, "%q", args)
		assert.NotContains(t, out+stderr, "vendor_owner_login:", "%q", args)
		assert.NotContains(t, out+stderr, "127.0.0.1:1/vendor", "%q", args)
	}
}

func TestTermSafeReplacesControlAndFormatCharacters(t *testing.T) {
	for in, want := range map[string]string{
		"plain text":            "plain text",
		"Ayşe Çelik":            "Ayşe Çelik",
		"a\x1b[2Jb":             "a?[2Jb",
		"line\nbreak\r":         "line?break?",
		"bidi\u202eevil":        "bidi?evil",
		"zero\u200bwidth":       "zero?width",
		"sep\u2028x":            "sep?x",
		"bad\xffutf8":           "bad?utf8",
		"c1\u009bcontrol":       "c1?control",
		"tab\there":             "tab?here",
		"\u00adsoft hyphen":     "?soft hyphen",
		"keeps \uFFFD as given": "keeps \uFFFD as given",
	} {
		assert.Equal(t, want, termSafe(in), "%q", in)
	}
}

func TestShortenDetailsShortensOnlyInstallationIDs(t *testing.T) {
	id := license.NewInstallationID()
	short := id[:15] + "…"
	got := shortenDetails(`{"installation": "` + id + `", "targets": 5, "customer_id": 12345678901234567890,` +
		`"name": "ALICE wonderland", "new": {"installation": "` + strings.Map(unicode.ToLower, id) + `"}, "list": ["` + id + `"]}`)
	assert.NotContains(t, got, id)
	assert.Equal(t, 3, strings.Count(got, short), got)
	assert.Contains(t, got, `"targets":5`)
	assert.Contains(t, got, `12345678901234567890`, "large numbers keep their digits")
	assert.Contains(t, got, `"ALICE wonderland"`, "a value that is not an ID is kept")

	// A string that is not a valid ID (wrong check symbol) is not touched.
	bad := id[:len(id)-1] + string(flip(id[len(id)-1]))
	assert.Contains(t, shortenDetails(`{"installation":"`+bad+`"}`), bad)
	// Not JSON: returned as is (the caller still makes it terminal-safe).
	assert.Equal(t, "not json", shortenDetails("not json"))
	// HTML characters are not escaped.
	assert.Equal(t, `{"value":"a<b>&c"}`, shortenDetails(`{"value": "a<b>&c"}`))
}

// flip returns a different Crockford symbol.
func flip(c byte) byte {
	if c == '0' {
		return '1'
	}
	return '0'
}

func TestFirstRunesCutsByCharacter(t *testing.T) {
	assert.Equal(t, "ab", firstRunes("ab", 80))
	assert.Equal(t, "şş", firstRunes("şşş", 2))
}
