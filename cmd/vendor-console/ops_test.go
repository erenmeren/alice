package main

import (
	"math/rand/v2"
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
		// Glue is no shield: the prefix is part of the ID's span wherever it stands.
		"glued to a word":  {`{"i":"x` + id + `"}`, `{"i":"x` + fp + `"}`},
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

// bodyOf returns the 16 symbols of a canonical ID.
func bodyOf(id string) string { return strings.ReplaceAll(strings.TrimPrefix(id, "ALICE-"), "-", "") }

func TestRedactFollowsTheParsersSeparatorRules(t *testing.T) {
	id := license.NewInstallationID()
	fp := installationFingerprint(id)
	b := bodyOf(id)
	for _, in := range []string{
		"ALICE-" + b[0:3] + "-" + b[3:7] + "-" + b[7:11] + "-" + b[11:15] + "-" + b[15:], // regrouped
		"ALICE-" + b[0:4] + "--" + b[4:8] + "-" + b[8:12] + "-" + b[12:],                 // double dash
		"ALICE-" + b[0:4] + "  " + b[4:8] + "  " + b[8:12] + "  " + b[12:],               // double spaces
		b[0:2] + " " + b[2:4] + " " + b[4:8] + " " + b[8:12] + " " + b[12:],              // odd grouping, no prefix
		"ALICE--" + b[0:4] + "-" + b[4:8] + "-" + b[8:12] + "-" + b[12:],                 // separators after the prefix
		"alice " + strings.Join(strings.Split(b, ""), "-"),                               // a dash after every symbol
	} {
		got := redactInstallations(in)
		assert.Equal(t, fp, got, in)
		got = redactInstallations("see: " + in + ".")
		assert.Equal(t, "see: "+fp+".", got, in)
	}
	// A tab is not a separator for the parser, so "ID" split by a tab is not an installation ID the
	// product would read; following the parser exactly, it is left as is (termSafe then shows the
	// tab as '?').
	split := "ALICE-" + b[0:8] + "\t" + b[8:]
	assert.Equal(t, split, redactInstallations(split))
}

func TestRedactFindsGluedIDs(t *testing.T) {
	id := license.NewInstallationID()
	fp := installationFingerprint(id)
	bare := strings.TrimPrefix(id, "ALICE-")
	for in, want := range map[string]string{
		id + "x":             fp + "x",
		id + "7":             fp + "7",
		id + "word":          fp + "word",
		"x" + id:             "x" + fp,
		"7" + id:             "7" + fp,
		"x" + id + "y":       "x" + fp + "y",
		"word" + id + "word": "word" + fp + "word",
		"#" + bare + "#":     "#" + fp + "#",
	} {
		got := redactInstallations(in)
		assert.NotContains(t, got, bodyOf(id)[:9], in)
		assert.NotContains(t, got, id[:9], in)
		assert.Equal(t, want, got, in)
	}
	// Bare and glued on both sides: found, perhaps with chance windows next to it (shown as more
	// fingerprints), but no symbol of the ID survives.
	for _, in := range []string{"xy" + bare + "z9", "Q" + bodyOf(id) + "R"} {
		got := redactInstallations(in)
		assert.Contains(t, got, fp, in)
		assert.NotContains(t, strings.ReplaceAll(got, "-", ""), bodyOf(id)[:9], in)
	}
}

// hexWindow returns 16 lower-case hex symbols that form a valid installation ID body.
func hexWindow(t *testing.T, rng *rand.Rand) string {
	t.Helper()
	const hexdigits = "0123456789abcdef"
	for {
		w := make([]byte, 16)
		for i := range 15 {
			w[i] = hexdigits[rng.IntN(16)]
		}
		for _, c := range []byte(hexdigits) {
			w[15] = c
			if _, err := license.ParseInstallationID(string(w)); err == nil {
				return string(w)
			}
		}
	}
}

func TestRedactLeavesHashesAlone(t *testing.T) {
	rng := rand.New(rand.NewPCG(1, 2))
	w := hexWindow(t, rng)
	pad := func(n int) string {
		b := make([]byte, n)
		for i := range b {
			b[i] = "0123456789abcdef"[rng.IntN(16)]
		}
		return string(b)
	}
	// A window that parses by chance inside a 64-hex sha256 is not an ID: the hash stays whole.
	sha := pad(24) + w + pad(24)
	require.Len(t, sha, 64)
	assert.Equal(t, `{"file_sha256":"`+sha+`"}`, redactDetails(`{"file_sha256":"`+sha+`"}`))
	// In a hex run shorter than 32 the same window is redacted.
	short := pad(4) + w + pad(4)
	assert.NotContains(t, redactInstallations(short), w)
}

func TestRedactFindsAnIDBetweenLongHexRunsAndInsideLongSymbolRuns(t *testing.T) {
	rng := rand.New(rand.NewPCG(3, 4))
	w := hexWindow(t, rng)
	fp := installationFingerprint(mustCanonical(t, w))
	pad := strings.Repeat("a", 40)
	// A 'Z' (not hex) breaks the hex runs: the all-hex ID is its own 16-byte run and is redacted.
	got := redactInstallations(pad + "Z" + w + "Z" + pad)
	assert.NotContains(t, got, w)
	assert.Contains(t, got, fp)

	// Inside a long run of symbols that is not hex-only.
	id := license.NewInstallationID()
	long := strings.Repeat("ZXY", 50) + id + strings.Repeat("QZ", 70)
	got = redactInstallations(long)
	assert.Contains(t, got, installationFingerprint(id))
	assert.NotContains(t, got, bodyOf(id)[:9])
	assert.NotContains(t, got, id[:9])
}

func mustCanonical(t *testing.T, s string) string {
	t.Helper()
	id, err := license.ParseInstallationID(s)
	require.NoError(t, err)
	return id
}

// TestLuhnPreCheckAgreesWithTheParser pins that the pre-check never refuses a window the product
// parser accepts (and accepts nothing it refuses), over random IDs, random windows and variants.
func TestLuhnPreCheckAgreesWithTheParser(t *testing.T) {
	rng := rand.New(rand.NewPCG(8, 9))
	const all = "0123456789ABCDEFGHJKMNPQRSTVWXYZabcdefghjkmnpqrstvwxyzOoIiLl"
	idx := make([]int, 16)
	for i := range idx {
		idx[i] = i
	}
	check := func(w string) {
		_, err := license.ParseInstallationID("ALICE-" + w)
		assert.Equal(t, err == nil, luhn32Valid(w, idx), "%q", w)
	}
	for range 20000 {
		b := make([]byte, 16)
		for i := range b {
			b[i] = all[rng.IntN(len(all))]
		}
		check(string(b))
	}
	for range 2000 {
		check(strings.Map(unicode.ToLower, bodyOf(license.NewInstallationID())))
		check(bodyOf(license.NewInstallationID()))
	}
}

// TestRedactIsLinearOnHugeInput guards against a quadratic scan: one long value in an audit row
// must not hang the CLI (before the fix, 1 MB of 'a' took minutes). The bound is generous: each
// input takes about 0.2 s here, about 1.3 s at most under the race detector.
func TestRedactIsLinearOnHugeInput(t *testing.T) {
	const size = 1 << 20
	rng := rand.New(rand.NewPCG(5, 6))
	random := make([]byte, size)
	const symbols = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
	for i := range random {
		random[i] = symbols[rng.IntN(len(symbols))]
	}
	for name, in := range map[string]string{
		"all a":          strings.Repeat("a", size),
		"0-":             strings.Repeat("0-", size/2),
		"ALICE ":         strings.Repeat("ALICE ", size/6),
		"random symbols": string(random),
	} {
		start := time.Now()
		got := redactInstallations(in)
		elapsed := time.Since(start)
		assert.Less(t, elapsed, 5*time.Second, "%s took %s", name, elapsed)
		assert.NotEmpty(t, got, name)
		t.Logf("%s: %s", name, elapsed)
	}
}

func TestRedactNeverLeaksARandomlySpelledID(t *testing.T) {
	rng := rand.New(rand.NewPCG(42, 7))
	const glue = "0123456789ABCDEFGHJKMNPQRSTVWXYZabcdefxyzu.,:;/_()[]{}#"
	pick := func(set string, n int) string {
		b := make([]byte, n)
		for i := range b {
			b[i] = set[rng.IntN(len(set))]
		}
		return string(b)
	}
	randCase := func(s string) string {
		b := []byte(s)
		for i, c := range b {
			if c >= 'A' && c <= 'Z' && rng.IntN(2) == 0 {
				b[i] = c + ('a' - 'A')
			}
		}
		return string(b)
	}
	seps := []string{"", "", "-", " ", "--", "  ", "- "}
	for range 200 {
		id := license.NewInstallationID()
		body := bodyOf(id)
		var sp strings.Builder
		if rng.IntN(3) > 0 {
			sp.WriteString(randCase("ALICE") + seps[rng.IntN(len(seps))])
		}
		for i := range 16 {
			if i > 0 && (i%4 == 0 || rng.IntN(6) == 0) {
				sp.WriteString(seps[rng.IntN(len(seps))])
			}
			sp.WriteByte(body[i])
		}
		spelled := randCase(sp.String())
		in := pick(glue, rng.IntN(4)) + spelled + pick(glue, rng.IntN(4))
		if rng.IntN(2) == 0 {
			in = "reason: moved " + in + " to new hardware"
		}
		got := redactInstallations(in)
		normalized := strings.Map(func(r rune) rune {
			if r == '-' || r == ' ' {
				return -1
			}
			return unicode.ToUpper(r)
		}, got)
		assert.NotContains(t, normalized, body[:9], "%q -> %q", in, got)
		assert.NotContains(t, got, id[:9], "%q -> %q", in, got)
		assert.Contains(t, got, installationFingerprint(id), "%q -> %q", in, got)
	}
}

func TestRedactKeepsKeysThatRedactToTheSameText(t *testing.T) {
	id := license.NewInstallationID()
	fp := installationFingerprint(id)
	got := redactDetails(`{"` + id + `":1,"` + strings.Map(unicode.ToLower, id) + `":2}`)
	// Sorted keys: the upper-case spelling sorts first and keeps the plain fingerprint.
	assert.Equal(t, `{"`+fp+`":1,"`+fp+`#2":2}`, got)
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
