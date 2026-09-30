// Package config loads Alice's process configuration from environment variables.
// Values that contain secrets are never rendered in logs or formatted output.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
)

// Config is the process configuration.
type Config struct {
	// DatabaseURL is the application role (alice_app) connection used at runtime.
	DatabaseURL string
	// MigrateDatabaseURL is the schema owner connection used only for migrations.
	// Empty means DatabaseURL is used for both (single-role mode, warned at startup).
	MigrateDatabaseURL string
	ListenAddr         string
	HealthAddr         string
	KeysDir            string
	// StateDir holds state that must survive restarts outside the database: the license
	// time record (spec §16.5). It is a separate volume in the container.
	StateDir string
	LogLevel slog.Level
	TLSHosts []string
	// TrustedProxies are the reverse proxies whose X-Forwarded-For header is honoured.
	TrustedProxies []netip.Prefix
	// SMTP is the Phase 2 email configuration (R36; Settings replaces it in Phase 7).
	SMTP SMTP
}

// SMTP configures the mail server. The password is read from PasswordFile at startup and
// never held in Config.
type SMTP struct {
	Host         string
	Port         int
	From         string
	Username     string
	PasswordFile string
	TLSMode      string // "starttls" or "tls"
	CAFile       string // PEM file of a private CA; empty = the system roots
}

// Configured reports whether an SMTP server is set.
func (s SMTP) Configured() bool { return s.Host != "" }

// Load reads configuration using getenv (os.Getenv in production).
func Load(getenv func(string) string) (Config, error) {
	c := Config{
		DatabaseURL:        getenv("ALICE_DATABASE_URL"),
		MigrateDatabaseURL: strings.TrimSpace(getenv("ALICE_MIGRATE_DATABASE_URL")),
		ListenAddr:         withDefault(getenv("ALICE_LISTEN_ADDR"), ":8443"),
		HealthAddr:         withDefault(getenv("ALICE_HEALTH_ADDR"), "127.0.0.1:8081"),
		KeysDir:            withDefault(getenv("ALICE_KEYS_DIR"), "/opt/alice/keys"),
		StateDir:           withDefault(getenv("ALICE_STATE_DIR"), "/opt/alice/state"),
		LogLevel:           slog.LevelInfo,
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
	for _, p := range strings.Split(getenv("ALICE_TRUSTED_PROXIES"), ",") {
		if p = strings.TrimSpace(p); p == "" {
			continue
		}
		prefix, err := parsePrefix(p)
		if err != nil {
			return Config{}, fmt.Errorf("ALICE_TRUSTED_PROXIES entry %q is not an IP address or CIDR", p)
		}
		c.TrustedProxies = append(c.TrustedProxies, prefix)
	}
	smtpCfg, err := loadSMTP(getenv)
	if err != nil {
		return Config{}, err
	}
	c.SMTP = smtpCfg
	return c, nil
}

func loadSMTP(getenv func(string) string) (SMTP, error) {
	s := SMTP{
		Host:         strings.TrimSpace(getenv("ALICE_SMTP_HOST")),
		From:         strings.TrimSpace(getenv("ALICE_SMTP_FROM")),
		Username:     strings.TrimSpace(getenv("ALICE_SMTP_USERNAME")),
		PasswordFile: strings.TrimSpace(getenv("ALICE_SMTP_PASSWORD_FILE")),
		TLSMode:      withDefault(getenv("ALICE_SMTP_TLS"), "starttls"),
		CAFile:       strings.TrimSpace(getenv("ALICE_SMTP_CA_FILE")),
	}
	if s.TLSMode != "starttls" && s.TLSMode != "tls" {
		return SMTP{}, fmt.Errorf(`ALICE_SMTP_TLS must be "starttls" or "tls" (got %q)`, s.TLSMode)
	}
	s.Port = 587
	if s.TLSMode == "tls" {
		s.Port = 465
	}
	if p := strings.TrimSpace(getenv("ALICE_SMTP_PORT")); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 65535 {
			return SMTP{}, fmt.Errorf("ALICE_SMTP_PORT must be a number from 1 to 65535 (got %q)", p)
		}
		s.Port = n
	}
	if s.Host != "" && s.From == "" {
		return SMTP{}, errors.New("ALICE_SMTP_FROM must be set when ALICE_SMTP_HOST is set")
	}
	return s, nil
}

// parsePrefix accepts a CIDR ("10.0.0.0/8") or a single address ("10.0.0.1").
func parsePrefix(s string) (netip.Prefix, error) {
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return netip.Prefix{}, err
		}
		return p.Masked(), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	a = a.Unmap()
	return netip.PrefixFrom(a, a.BitLen()), nil
}

// MigrationURL is the connection used to apply migrations: the owner role when
// configured, otherwise the application role.
func (c Config) MigrationURL() string {
	if c.MigrateDatabaseURL != "" {
		return c.MigrateDatabaseURL
	}
	return c.DatabaseURL
}

// SeparateMigrationRole reports whether migrations run as a different database
// role than the application (required for the append-only audit log, SEC-071).
func (c Config) SeparateMigrationRole() bool {
	return c.MigrateDatabaseURL != "" && c.MigrateDatabaseURL != c.DatabaseURL
}

// RequireDatabase reports a user-friendly error when no database is configured.
func (c Config) RequireDatabase() error {
	if strings.TrimSpace(c.DatabaseURL) == "" {
		return errors.New("ALICE_DATABASE_URL is not set; set it in deploy/.env (see docs/dev/getting-started.md)")
	}
	return nil
}

func (c Config) proxies() []string {
	out := make([]string, len(c.TrustedProxies))
	for i, p := range c.TrustedProxies {
		out[i] = p.String()
	}
	return out
}

// LogValue implements slog.LogValuer so database passwords are never logged.
func (c Config) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("database_url", redactURL(c.DatabaseURL)),
		slog.String("migrate_database_url", redactURL(c.MigrateDatabaseURL)),
		slog.String("listen_addr", c.ListenAddr),
		slog.String("health_addr", c.HealthAddr),
		slog.String("keys_dir", c.KeysDir),
		slog.String("state_dir", c.StateDir),
		slog.Group("smtp", "host", c.SMTP.Host, "port", c.SMTP.Port, "from", c.SMTP.From, "username", c.SMTP.Username, "tls", c.SMTP.TLSMode),
		slog.String("log_level", c.LogLevel.String()),
		slog.Any("tls_hosts", c.TLSHosts),
		slog.Any("trusted_proxies", c.proxies()),
	)
}

// String renders the configuration with secrets redacted.
func (c Config) String() string {
	return fmt.Sprintf("Config{DatabaseURL:%s MigrateDatabaseURL:%s ListenAddr:%s HealthAddr:%s KeysDir:%s StateDir:%s LogLevel:%s TLSHosts:%v TrustedProxies:%v SMTP:%s:%d}",
		redactURL(c.DatabaseURL), redactURL(c.MigrateDatabaseURL), c.ListenAddr, c.HealthAddr, c.KeysDir, c.StateDir, c.LogLevel, c.TLSHosts, c.proxies(), c.SMTP.Host, c.SMTP.Port)
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
		DatabaseURL        string   `json:"database_url"`
		MigrateDatabaseURL string   `json:"migrate_database_url"`
		ListenAddr         string   `json:"listen_addr"`
		HealthAddr         string   `json:"health_addr"`
		KeysDir            string   `json:"keys_dir"`
		StateDir           string   `json:"state_dir"`
		SMTPHost           string   `json:"smtp_host"`
		LogLevel           string   `json:"log_level"`
		TLSHosts           []string `json:"tls_hosts"`
		TrustedProxies     []string `json:"trusted_proxies"`
	}{redactURL(c.DatabaseURL), redactURL(c.MigrateDatabaseURL), c.ListenAddr, c.HealthAddr, c.KeysDir,
		c.StateDir, c.SMTP.Host, c.LogLevel.String(), c.TLSHosts, c.proxies()})
}

func withDefault(v, def string) string {
	if strings.TrimSpace(v) == "" {
		return def
	}
	return strings.TrimSpace(v)
}
