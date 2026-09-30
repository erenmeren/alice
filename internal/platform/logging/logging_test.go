package logging_test

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/platform/logging"
)

const canary = "CANARY-7f3a91"

type selfRendering struct{}

func (selfRendering) LogValue() slog.Value {
	return slog.GroupValue(slog.String("user", "ayse"), slog.String("password", canary))
}

func decode(t *testing.T, buf *bytes.Buffer) map[string]any {
	t.Helper()
	var m map[string]any
	require.NoError(t, json.Unmarshal(buf.Bytes(), &m))
	return m
}

func TestSecretKeysAreRedacted(t *testing.T) {
	var buf bytes.Buffer
	log := logging.New(&buf, slog.LevelDebug)
	log.Info("login",
		"password", canary, "Password", canary, "new_password", canary,
		"client_secret", canary, "csrf_token", canary, "Authorization", canary,
		"cookie", canary, "passphrase", canary, "totp_code", canary,
		"private_key", canary, "privateKeyPEM", canary, "key", canary, "master_key", canary,
		"username", "ayse", "request_id", "r-1", "keys_dir", "/opt/alice/keys")
	out := buf.String()
	assert.NotContains(t, out, canary)
	m := decode(t, &buf)
	assert.Equal(t, logging.Redacted, m["password"])
	assert.Equal(t, logging.Redacted, m["master_key"])
	assert.Equal(t, "ayse", m["username"])
	assert.Equal(t, "r-1", m["request_id"])
	assert.Equal(t, "/opt/alice/keys", m["keys_dir"], "keys_dir is a path, not a key")
}

func TestGroupsWithAttrsAndLogValuersAreRedacted(t *testing.T) {
	var buf bytes.Buffer
	log := logging.New(&buf, slog.LevelInfo).With("token", canary).WithGroup("req")
	log.Info("x",
		slog.Group("auth", slog.String("secret", canary), slog.String("method", "totp")),
		slog.Any("creds", selfRendering{}))
	assert.NotContains(t, buf.String(), canary)
	m := decode(t, &buf)
	assert.Equal(t, logging.Redacted, m["token"])
	req := m["req"].(map[string]any)
	assert.Equal(t, "totp", req["auth"].(map[string]any)["method"])
	assert.Equal(t, "ayse", req["creds"].(map[string]any)["user"])
}

func TestLevelIsRespected(t *testing.T) {
	var buf bytes.Buffer
	log := logging.New(&buf, slog.LevelWarn)
	log.Info("hidden")
	assert.Empty(t, buf.String())
	log.Warn("shown")
	assert.Contains(t, buf.String(), "shown")
}
