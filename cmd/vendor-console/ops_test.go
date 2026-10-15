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

func TestVerifyLicensesRefusesTwoPubFilesWithOneKeyID(t *testing.T) {
	a, b := writePub(t), writePub(t) // two different keys, both "vk-2026-01"
	code, out, stderr := runArgs("verify-licenses", "--pub", a, "--pub", b)
	assert.Equal(t, 2, code)
	assert.Empty(t, out)
	assert.Contains(t, stderr, `"vk-2026-01"`)
	assert.NotContains(t, stderr, "BEGIN")
	assert.NotContains(t, stderr, "VENDOR_DATABASE_URL", "refused before connecting")
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

// noIDLeft asserts that neither id nor any 9-character prefix of it is in s (the rule: an
// installation ID is never shown beyond 8 characters; here, no part of it at all).
func noIDLeft(t *testing.T, s, id string) {
	t.Helper()
	assert.NotContains(t, s, id[:9], "%s", s)
	body := strings.ReplaceAll(strings.TrimPrefix(id, "ALICE-"), "-", "")
	assert.NotContains(t, s, body[:9], "%s", s)
	assert.NotContains(t, s, strings.TrimPrefix(id, "ALICE-")[:9], "%s", s)
}

func TestRedactDetailsReplacesEveryInstallationID(t *testing.T) {
	id, other := license.NewInstallationID(), license.NewInstallationID()
	fp, fpOther := installationFingerprint(id), installationFingerprint(other)
	require.Regexp(t, `^inst#[0-9a-f]{8}$`, fp)
	require.NotEqual(t, fp, fpOther)
	bare := strings.TrimPrefix(id, "ALICE-")
	soft := strings.ReplaceAll(id, "-", "-\u00ad\u200b")
	cases := map[string]struct{ in, want string }{
		"alone":           {`{"installation":"` + id + `"}`, `{"installation":"` + fp + `"}`},
		"lower case":      {`{"i":"` + strings.Map(unicode.ToLower, id) + `"}`, `{"i":"` + fp + `"}`},
		"inside a string": {`{"note":"moved from ` + id + ` yesterday"}`, `{"note":"moved from ` + fp + ` yesterday"}`},
		"in an array":     {`{"features":["a","` + id + `"]}`, `{"features":["a","` + fp + `"]}`},
		"as a key":        {`{"` + id + `":{"x":1}}`, `{"` + fp + `":{"x":1}}`},
		"deep":            {`{"new":{"old":[{"k":"` + id + `"}]}}`, `{"new":{"old":[{"k":"` + fp + `"}]}}`},
		"without prefix":  {`{"i":"` + bare + `"}`, `{"i":"` + fp + `"}`},
		"no separators":   {`{"i":"` + strings.ReplaceAll(bare, "-", "") + `"}`, `{"i":"` + fp + `"}`},
		"soft hyphens":    {`{"i":"` + soft + `"}`, `{"i":"` + fp + `"}`},
		"two in one":      {`{"i":"` + id + ` and ` + other + `"}`, `{"i":"` + fp + ` and ` + fpOther + `"}`},
		// The ALICE prefix touches a letter, so only the ID's symbols match: "xALICE-" stays.
		"glued to a word":  {`{"i":"x` + id + `"}`, `{"i":"xALICE-` + fp + `"}`},
		"not JSON":         {`raw ` + id, `raw ` + fp},
		"numbers and html": {`{"targets":5,"customer_id":12345678901234567890,"v":"a<b>&c"}`, `{"customer_id":12345678901234567890,"targets":5,"v":"a<b>&c"}`},
	}
	for name, c := range cases {
		got := redactDetails(c.in)
		assert.Equal(t, c.want, got, name)
		noIDLeft(t, got, id)
		noIDLeft(t, got, other)
	}

	// A string with a wrong check symbol is not an installation ID (the product refuses it), so it
	// is left as it is.
	bad := id[:len(id)-1] + string(flip(id[len(id)-1]))
	assert.Equal(t, `{"i":"`+bad+`"}`, redactDetails(`{"i":"`+bad+`"}`))
	// A 16-symbol window inside a longer token (a sha256 hex) is not an ID.
	hash := strings.Repeat("0123456789abcdef", 4)
	assert.Equal(t, `{"file_sha256":"`+hash+`"}`, redactDetails(`{"file_sha256":"`+hash+`"}`))
	assert.Equal(t, `{"name":"ALICE wonderland"}`, redactDetails(`{"name":"ALICE wonderland"}`))
}

func TestRedactInstallationsIsStableAcrossSpellings(t *testing.T) {
	id := license.NewInstallationID()
	fp := installationFingerprint(id)
	for _, in := range []string{id, strings.Map(unicode.ToLower, id), strings.TrimPrefix(id, "ALICE-"),
		strings.ReplaceAll(id, "-", " ")} {
		assert.Equal(t, fp, redactInstallations(in), in)
	}
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
