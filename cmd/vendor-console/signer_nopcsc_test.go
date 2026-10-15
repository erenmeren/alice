//go:build !yubikey

package main

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"alice/internal/vconsole/sign/pcsc"
)

// TestNoYubikeyTagGivesTheBuildMessage uses the real openCard of a build without the yubikey tag.
func TestNoYubikeyTagGivesTheBuildMessage(t *testing.T) {
	c := newTestCard(t, nil)
	openCard = pcsc.Connect // the build's own transport (newTestCard's cleanup restores the variable)
	getenv := func(k string) string {
		if k == dbEnv {
			return "postgres://nobody@127.0.0.1:1/none?sslmode=disable"
		}
		return ""
	}
	for _, args := range [][]string{
		{"issue", "--signer", "openpgp", "--key-id", testKeyID, "--pub", c.pubPath, "--not-in-key-set", "--request", "1",
			"--hash", strings.Repeat("a", 64), "--out", filepath.Join(c.dir, "lic.json")},
		{"signer", "info"},
		{"signer", "test", "--key-id", testKeyID, "--pub", c.pubPath},
	} {
		s := runSession(getenv, nil, goodPIN, args...)
		assert.Equal(t, 2, s.code, args)
		assert.Contains(t, s.errOut, "build with -tags yubikey", args)
		assert.NotContains(t, s.errOut, "database", args)
	}
	assert.NoFileExists(t, filepath.Join(c.dir, "lic.json"))
}
