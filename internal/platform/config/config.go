// Package config loads Alice's process configuration from environment variables.
// Values that contain secrets are never rendered in logs or formatted output.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
)

// Config is the process configuration.
type Config struct {
	DatabaseURL string
	ListenAddr  string
	HealthAddr  string
	KeysDir     string
	LogLevel    slog.Level
	TLSHosts    []string
}

// Load reads configuration using getenv (os.Getenv in production).
func Load(getenv func(string) string) (Config, error) {
	c := Config{
		DatabaseURL: getenv("ALICE_DATABASE_URL"),
		ListenAddr:  withDefault(getenv("ALICE_LISTEN_ADDR"), ":8443"),
		HealthAddr:  withDefault(getenv("ALICE_HEALTH_ADDR"), "127.0.0.1:8081"),
		KeysDir:     withDefault(getenv("ALICE_KEYS_DIR"), "/opt/alice/keys"),
		LogLevel:    slog.LevelInfo,
	}
	if lvl := strings.TrimSpace(getenv("ALICE_LOG_LEVEL")); lvl != "" {
		// slog.Level.UnmarshalText is case-insensitive.
		if err := c.LogLevel.UnmarshalText([]byte(lvl)); err != nil {
			return Config{}, fmt.Errorf("ALICE_LOG_LEVEL must be one of debug, info, warn, error (got %q)", lvl)
		}
	}
	for _, h := range strings.Split(getenv("ALICE_TLS_HOSTS"), ",") {
		if h = strings.TrimSpace(h); h != "" {
			c.TLSHosts = append(c.TLSHosts, h)
		}
	}
	return c, nil
}

// RequireDatabase reports a user-friendly error when no database is configured.
func (c Config) RequireDatabase() error {
	if strings.TrimSpace(c.DatabaseURL) == "" {
		return errors.New("ALICE_DATABASE_URL is not set; set it in deploy/.env (see docs/dev/getting-started.md)")
	}
	return nil
}

// LogValue implements slog.LogValuer so the database password is never logged.
func (c Config) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("database_url", redactURL(c.DatabaseURL)),
		slog.String("listen_addr", c.ListenAddr),
		slog.String("health_addr", c.HealthAddr),
		slog.String("keys_dir", c.KeysDir),
		slog.String("log_level", c.LogLevel.String()),
		slog.Any("tls_hosts", c.TLSHosts),
	)
}

// String renders the configuration with secrets redacted.
func (c Config) String() string {
	return fmt.Sprintf("Config{DatabaseURL:%s ListenAddr:%s HealthAddr:%s KeysDir:%s LogLevel:%s TLSHosts:%v}",
		redactURL(c.DatabaseURL), c.ListenAddr, c.HealthAddr, c.KeysDir, c.LogLevel, c.TLSHosts)
}

// GoString makes %#v safe as well.
func (c Config) GoString() string { return c.String() }

const redactedPlaceholder = "[redacted]"

// redactURL is allowlist-based: only well-formed postgres URLs are rendered,
// with every password masked. Anything else (key/value DSNs, other schemes,
// parse failures) becomes a fixed placeholder.
//
// The url.Parse error must never be returned or logged: it echoes the input,
// which may contain the password.
func redactURL(raw string) string {
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "postgres" && u.Scheme != "postgresql") {
		return redactedPlaceholder
	}
	q, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return redactedPlaceholder
	}
	for name := range q {
		if containsFold(name, "password") {
			q[name] = []string{"xxxxx"}
		}
	}
	u.RawQuery = q.Encode()
	return u.Redacted()
}

// containsFold reports whether s contains substr, ignoring ASCII case.
func containsFold(s, substr string) bool {
	for i := 0; i+len(substr) <= len(s); i++ {
		if strings.EqualFold(s[i:i+len(substr)], substr) {
			return true
		}
	}
	return false
}

// MarshalJSON emits the configuration with secrets redacted.
func (c Config) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		DatabaseURL string   `json:"database_url"`
		ListenAddr  string   `json:"listen_addr"`
		HealthAddr  string   `json:"health_addr"`
		KeysDir     string   `json:"keys_dir"`
		LogLevel    string   `json:"log_level"`
		TLSHosts    []string `json:"tls_hosts"`
	}{redactURL(c.DatabaseURL), c.ListenAddr, c.HealthAddr, c.KeysDir, c.LogLevel.String(), c.TLSHosts})
}

func withDefault(v, def string) string {
	if strings.TrimSpace(v) == "" {
		return def
	}
	return strings.TrimSpace(v)
}
