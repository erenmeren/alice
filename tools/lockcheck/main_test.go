package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAcceptsTheRealLockfiles(t *testing.T) {
	assert.Empty(t, Check("../../web/package-lock.json"))
	assert.Empty(t, Check("../../go.sum"))
}

func writeTemp(t *testing.T, name, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	require.NoError(t, os.WriteFile(p, []byte(content), 0o600))
	return p
}

const goodIntegrity = "sha512-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="

func lock(extra, resolved, integrity string) string {
	return `{
  "name": "x",
  "version": "1.0.0",
  "lockfileVersion": 3,
  "requires": true,
  "packages": {
    "": {"name": "x", "version": "1.0.0"},
    "node_modules/a": {
      "version": "1.2.3",
` + extra + `      "resolved": "` + resolved + `",
      "integrity": "` + integrity + `",
      "license": "MIT",
      "funding": [{"type": "github", "url": "https://github.com/sponsors/a"}],
      "engines": {"node": ">=18"}
    }
  }
}
`
}

func TestAcceptsAWellFormedFixture(t *testing.T) {
	p := writeTemp(t, "package-lock.json", lock("", "https://registry.npmjs.org/a/-/a-1.2.3.tgz", goodIntegrity))
	assert.Empty(t, Check(p))
}

func TestRefusesAHiddenSecret(t *testing.T) {
	token := "ghp_" + strings.Repeat("a", 36) // built here, never a token-shaped literal in a committed file (M-20)

	// An extra field with a token as its value, on line 10.
	p := writeTemp(t, "package-lock.json", lock(`      "token": "`+token+"\",\n", "https://registry.npmjs.org/a/-/a-1.2.3.tgz", goodIntegrity))
	got := Check(p)
	require.Len(t, got, 1)
	assert.Contains(t, got[0], "package-lock.json:10:")
	assert.Contains(t, got[0], `"token"`)
	assert.NotContains(t, got[0], token, "a message never repeats a value")

	// A secret hidden in a known field is a shape error, also without the value in the message.
	p = writeTemp(t, "package-lock.json", lock(`      "deprecated": "x",`+"\n", "https://registry.npmjs.org/a/-/a-1.2.3.tgz?token="+token, goodIntegrity))
	got = Check(p)
	require.Len(t, got, 1)
	assert.Contains(t, got[0], "resolved has an unexpected shape")
	assert.NotContains(t, got[0], token)

	// Another host.
	got = Check(writeTemp(t, "package-lock.json", lock("", "https://evil.example/a-1.2.3.tgz", goodIntegrity)))
	require.Len(t, got, 1)
	assert.Contains(t, got[0], "resolved")
	assert.Contains(t, got[0], ":10:")

	// An integrity that is not sha512 base64.
	for _, bad := range []string{"sha1-AAAA", "sha512-not base64!", token} {
		got = Check(writeTemp(t, "package-lock.json", lock("", "https://registry.npmjs.org/a/-/a-1.2.3.tgz", bad)))
		require.Len(t, got, 1, bad)
		assert.Contains(t, got[0], "integrity")
		assert.NotContains(t, got[0], token)
	}

	// A top-level key that is not npm's.
	got = Check(writeTemp(t, "package-lock.json", strings.Replace(lock("", "https://registry.npmjs.org/a/-/a-1.2.3.tgz", goodIntegrity), `"requires": true,`, `"requires": true, "npmrc": "_authToken=`+token+`",`, 1)))
	require.Len(t, got, 1)
	assert.Contains(t, got[0], `"npmrc"`)
	assert.NotContains(t, got[0], token)

	// go.sum: a fourth field, and a short hash.
	hash := "h1:" + strings.Repeat("A", 43) + "="
	gs := "example.com/m v1.0.0 " + hash + "\n" +
		"example.com/m v1.0.0/go.mod " + hash + "\n" +
		"example.com/m v1.0.1 " + hash + " " + token + "\n" +
		"example.com/m v1.0.2 h1:short=\n"
	got = Check(writeTemp(t, "go.sum", gs))
	require.Len(t, got, 2)
	assert.Contains(t, got[0], "go.sum:3:")
	assert.Contains(t, got[1], "go.sum:4:")
	assert.NotContains(t, strings.Join(got, "\n"), token)
}

func TestRefusesBrokenInput(t *testing.T) {
	assert.Len(t, Check(writeTemp(t, "package-lock.json", "{")), 1)
	assert.Len(t, Check(writeTemp(t, "package-lock.json", "[]")), 1)
	assert.Len(t, Check(writeTemp(t, "package-lock.json", `{"packages": {}} {}`)), 1)
	assert.Len(t, Check(filepath.Join(t.TempDir(), "missing.json")), 1)
	got := Check(writeTemp(t, "package-lock.json", `{"lockfileVersion": 3, "packages": {"node_modules/a": {"dev": "yes", "bin": 3, "cpu": "x64", "funding": {"url": "http://x"}, "peerDependenciesMeta": {"b": {"x": 1}}, "dependencies": {"b": "\u0000"}}}}`))
	assert.GreaterOrEqual(t, len(got), 6)
}
