package config_test

import (
	"bytes"
	"fmt"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/platform/config"
)

const dbURL = "postgres://alice:s3cret-pw@postgres:5432/alice?sslmode=disable"

func env(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestLoadDefaults(t *testing.T) {
	c, err := config.Load(env(map[string]string{"ALICE_DATABASE_URL": dbURL}))
	require.NoError(t, err)
	assert.Equal(t, dbURL, c.DatabaseURL)
	assert.Equal(t, ":8443", c.ListenAddr)
	assert.Equal(t, "127.0.0.1:8081", c.HealthAddr)
	assert.Equal(t, "/opt/alice/keys", c.KeysDir)
	assert.Equal(t, slog.LevelInfo, c.LogLevel)
	assert.Empty(t, c.TLSHosts)
}

func TestLoadOverrides(t *testing.T) {
	c, err := config.Load(env(map[string]string{
		"ALICE_LISTEN_ADDR": ":9443",
		"ALICE_HEALTH_ADDR": "127.0.0.1:9081",
		"ALICE_KEYS_DIR":    "/tmp/keys",
		"ALICE_LOG_LEVEL":   "DEBUG",
		"ALICE_TLS_HOSTS":   " alice.example.com , 10.0.0.5,, ",
	}))
	require.NoError(t, err)
	assert.Equal(t, ":9443", c.ListenAddr)
	assert.Equal(t, "127.0.0.1:9081", c.HealthAddr)
	assert.Equal(t, "/tmp/keys", c.KeysDir)
	assert.Equal(t, slog.LevelDebug, c.LogLevel)
	assert.Equal(t, []string{"alice.example.com", "10.0.0.5"}, c.TLSHosts)
}

func TestLoadRejectsUnknownLogLevel(t *testing.T) {
	_, err := config.Load(env(map[string]string{"ALICE_LOG_LEVEL": "loud"}))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ALICE_LOG_LEVEL")
}

func TestRequireDatabase(t *testing.T) {
	c, err := config.Load(env(nil))
	require.NoError(t, err)
	err = c.RequireDatabase()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ALICE_DATABASE_URL")

	c.DatabaseURL = dbURL
	assert.NoError(t, c.RequireDatabase())
}

func TestConfigNeverRevealsDatabasePassword(t *testing.T) {
	c, err := config.Load(env(map[string]string{"ALICE_DATABASE_URL": dbURL}))
	require.NoError(t, err)

	var buf bytes.Buffer
	slog.New(slog.NewJSONHandler(&buf, nil)).Info("config loaded", "config", c)
	for _, out := range []string{buf.String(), fmt.Sprintf("%v", c), fmt.Sprintf("%+v", c), fmt.Sprintf("%#v", c), c.String()} {
		assert.NotContains(t, out, "s3cret-pw")
	}
	assert.Contains(t, buf.String(), "postgres:5432")
}

func TestRedactionOfUnparseableURL(t *testing.T) {
	c := config.Config{DatabaseURL: "::not a url s3cret-pw"}
	assert.NotContains(t, c.String(), "s3cret-pw")
}
