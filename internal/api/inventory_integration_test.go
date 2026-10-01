//go:build integration

package api

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/providers/linuxssh"
)

// The inventory builds the authorized_keys line itself (it may not import linuxssh); it must be
// exactly the line the provider's setup script expects (Task 13 ruling), with and without from=.
func TestPlatformKeyLineMatchesTheProvider(t *testing.T) {
	_, c, _ := installed(t)
	for _, from := range []string{"", "10.0.0.5", "2001:db8::5"} {
		path := "/api/v1/ssh-keys/platform-key"
		if from != "" {
			path += "?from=" + from
		}
		rec := c.do(http.MethodGet, path, nil)
		requireStatus(t, rec, http.StatusOK)
		var body struct {
			PublicKey          string `json:"public_key"`
			Fingerprint        string `json:"fingerprint"`
			AuthorizedKeysLine string `json:"authorized_keys_line"`
			Profiles           map[string]struct {
				Script string `json:"script"`
			} `json:"profiles"`
		}
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
		require.NotEmpty(t, body.PublicKey)
		assert.Equal(t, linuxssh.AuthorizedKeysLine(body.PublicKey, from), body.AuthorizedKeysLine, "from=%q", from)
		for name, p := range body.Profiles {
			assert.Contains(t, p.Script, body.AuthorizedKeysLine, "the %s script installs the same line", name)
		}
		assert.NotContains(t, rec.Body.String(), "PRIVATE KEY")
	}
}

func TestProvidersListTheCompiledInProvider(t *testing.T) {
	_, c, _ := installed(t)
	rec := c.do(http.MethodGet, "/api/v1/providers", nil)
	requireStatus(t, rec, http.StatusOK)
	var body struct {
		Items []struct {
			Kind         string   `json:"kind"`
			Capabilities []string `json:"capabilities"`
		} `json:"items"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	require.Len(t, body.Items, 1)
	assert.Equal(t, "linuxssh", body.Items[0].Kind)
	assert.Contains(t, body.Items[0].Capabilities, "test_connection")
}
