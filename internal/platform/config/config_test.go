package config_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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

func TestRedactionOfPasswordForms(t *testing.T) {
	for _, raw := range []string{
		"postgres://a@h/db?password=s3cret-pw",
		"postgresql://a@h/db?sslmode=disable&sslpassword=s3cret-pw",
		"postgres://a@h/db?PGPassword=s3cret-pw",
		"host=db user=a password=s3cret-pw dbname=x",
		"mysql://a:s3cret-pw@h/db",
		"postgres://a:s3cret-pw@h/db?x=%zz",
	} {
		c := config.Config{DatabaseURL: raw}
		ptr := &c
		var text bytes.Buffer
		slog.New(slog.NewTextHandler(&text, nil)).Info("cfg", "config", c)
		var js bytes.Buffer
		require.NoError(t, json.NewEncoder(&js).Encode(c))
		for _, out := range []string{c.String(), fmt.Sprintf("%v", ptr), fmt.Sprintf("%+v", c), fmt.Sprintf("%#v", c), text.String(), js.String()} {
			assert.NotContains(t, out, "s3cret-pw", raw)
		}
	}
}

func TestRedactionKeepsNonSecretParts(t *testing.T) {
	c := config.Config{DatabaseURL: "postgres://a@h:5432/db?password=s3cret-pw&sslmode=disable"}
	assert.Contains(t, c.String(), "h:5432/db")
	assert.Contains(t, c.String(), "sslmode=disable")
}

func TestJSONMarshalNeverRevealsDatabasePassword(t *testing.T) {
	c, err := config.Load(env(map[string]string{"ALICE_DATABASE_URL": dbURL}))
	require.NoError(t, err)
	for _, v := range []any{c, &c} {
		b, err := json.Marshal(v)
		require.NoError(t, err)
		assert.NotContains(t, string(b), "s3cret-pw")
		assert.Contains(t, string(b), "postgres:5432")
	}
}

const ownerURL = "postgres://alice:0wner-pw@postgres:5432/alice?sslmode=disable"

func TestMigrationURLAndRoleSeparation(t *testing.T) {
	c, err := config.Load(env(map[string]string{"ALICE_DATABASE_URL": dbURL}))
	require.NoError(t, err)
	assert.Equal(t, dbURL, c.MigrationURL(), "without an owner URL the app URL migrates")
	assert.False(t, c.SeparateMigrationRole())

	c, err = config.Load(env(map[string]string{"ALICE_DATABASE_URL": dbURL, "ALICE_MIGRATE_DATABASE_URL": " " + ownerURL + " "}))
	require.NoError(t, err)
	assert.Equal(t, ownerURL, c.MigrationURL())
	assert.True(t, c.SeparateMigrationRole())

	c.MigrateDatabaseURL = dbURL
	assert.False(t, c.SeparateMigrationRole(), "the same URL twice is not a separate role")
}

func TestConfigNeverRevealsMigrationPassword(t *testing.T) {
	c, err := config.Load(env(map[string]string{"ALICE_DATABASE_URL": dbURL, "ALICE_MIGRATE_DATABASE_URL": ownerURL}))
	require.NoError(t, err)
	var buf bytes.Buffer
	slog.New(slog.NewJSONHandler(&buf, nil)).Info("config loaded", "config", c)
	js, err := json.Marshal(c)
	require.NoError(t, err)
	for _, out := range []string{buf.String(), fmt.Sprintf("%v", c), fmt.Sprintf("%#v", c), c.String(), string(js)} {
		assert.NotContains(t, out, "0wner-pw")
		assert.NotContains(t, out, "s3cret-pw")
	}
}

func TestTrustedProxies(t *testing.T) {
	c, err := config.Load(env(map[string]string{"ALICE_TRUSTED_PROXIES": " 10.0.0.0/8, 192.168.1.10 ,,::ffff:172.16.0.1, 2001:db8::/32"}))
	require.NoError(t, err)
	assert.Equal(t, []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("192.168.1.10/32"),
		netip.MustParsePrefix("172.16.0.1/32"),
		netip.MustParsePrefix("2001:db8::/32"),
	}, c.TrustedProxies)
	assert.Contains(t, c.String(), "10.0.0.0/8")

	c, err = config.Load(env(nil))
	require.NoError(t, err)
	assert.Empty(t, c.TrustedProxies, "no proxy is trusted by default")

	_, err = config.Load(env(map[string]string{"ALICE_TRUSTED_PROXIES": "10.0.0.0/8,proxy.local"}))
	require.Error(t, err)
	assert.Equal(t, `ALICE_TRUSTED_PROXIES entry "proxy.local" is not an IP address or CIDR`, err.Error())
}

func TestStateDirAndSMTPDefaults(t *testing.T) {
	c, err := config.Load(env(nil))
	require.NoError(t, err)
	assert.Equal(t, "/opt/alice/state", c.StateDir)
	assert.False(t, c.SMTP.Configured(), "no SMTP host: emails are recorded as skipped")
	assert.Equal(t, 587, c.SMTP.Port)
	assert.Equal(t, "starttls", c.SMTP.TLSMode)
}

func TestSMTPConfiguration(t *testing.T) {
	c, err := config.Load(env(map[string]string{
		"ALICE_STATE_DIR":          "/data/state",
		"ALICE_SMTP_HOST":          " mail.example.com ",
		"ALICE_SMTP_FROM":          "Alice <alice@example.com>",
		"ALICE_SMTP_USERNAME":      "alice",
		"ALICE_SMTP_PASSWORD_FILE": "/run/secrets/smtp_password",
		"ALICE_SMTP_TLS":           "tls",
		"ALICE_SMTP_CA_FILE":       "/opt/alice/keys/smtp-ca.pem",
	}))
	require.NoError(t, err)
	assert.Equal(t, "/data/state", c.StateDir)
	assert.True(t, c.SMTP.Configured())
	assert.Equal(t, config.SMTP{Host: "mail.example.com", Port: 465, From: "Alice <alice@example.com>", Username: "alice",
		PasswordFile: "/run/secrets/smtp_password", TLSMode: "tls", CAFile: "/opt/alice/keys/smtp-ca.pem"}, c.SMTP)
	assert.Contains(t, c.String(), "mail.example.com")

	for name, vars := range map[string]map[string]string{
		"port text":    {"ALICE_SMTP_HOST": "m", "ALICE_SMTP_FROM": "a@b.c", "ALICE_SMTP_PORT": "smtp"},
		"port range":   {"ALICE_SMTP_HOST": "m", "ALICE_SMTP_FROM": "a@b.c", "ALICE_SMTP_PORT": "70000"},
		"tls mode":     {"ALICE_SMTP_HOST": "m", "ALICE_SMTP_FROM": "a@b.c", "ALICE_SMTP_TLS": "none"},
		"missing from": {"ALICE_SMTP_HOST": "m"},
	} {
		_, err := config.Load(env(vars))
		assert.Error(t, err, name)
	}
}

// The SMTP password stays in its file: no rendering of the configuration contains it.
func TestConfigNeverRevealsSMTPPassword(t *testing.T) {
	const canary = "CANARY-smtp-password-7Qx2"
	pwFile := filepath.Join(t.TempDir(), "smtp_password")
	require.NoError(t, os.WriteFile(pwFile, []byte(canary+"\n"), 0o600))
	c, err := config.Load(env(map[string]string{
		"ALICE_SMTP_HOST": "mail.example.com", "ALICE_SMTP_FROM": "alice@example.com",
		"ALICE_SMTP_USERNAME": "alice", "ALICE_SMTP_PASSWORD_FILE": pwFile,
	}))
	require.NoError(t, err)
	var logs bytes.Buffer
	slog.New(slog.NewJSONHandler(&logs, nil)).Info("config loaded", "config", c)
	js, err := json.Marshal(c)
	require.NoError(t, err)
	for _, out := range []string{logs.String(), string(js), fmt.Sprintf("%v", c), fmt.Sprintf("%+v", c), fmt.Sprintf("%#v", c), c.String()} {
		assert.NotContains(t, out, canary)
	}
	assert.Contains(t, logs.String(), `"smtp":{"host":"mail.example.com"`)
}

// SMTP authentication needs both a user name and a password file; one without the other is
// a configuration mistake, not "no authentication".
func TestSMTPCredentialsArePaired(t *testing.T) {
	base := map[string]string{"ALICE_SMTP_HOST": "mail.example.com", "ALICE_SMTP_FROM": "alice@example.com"}
	with := func(k, v string) map[string]string {
		out := map[string]string{k: v}
		for bk, bv := range base {
			out[bk] = bv
		}
		return out
	}
	_, err := config.Load(env(with("ALICE_SMTP_USERNAME", "alice")))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ALICE_SMTP_USERNAME is set but ALICE_SMTP_PASSWORD_FILE is not")

	_, err = config.Load(env(with("ALICE_SMTP_PASSWORD_FILE", "/run/secrets/smtp_password")))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ALICE_SMTP_PASSWORD_FILE is set but ALICE_SMTP_USERNAME is not")

	c, err := config.Load(env(base))
	require.NoError(t, err, "no authentication at all is allowed")
	assert.Empty(t, c.SMTP.Username)
}

// files is a fake reader for LoadWith: a missing name is fs.ErrNotExist.
func files(m map[string]string) func(string) ([]byte, error) {
	return func(name string) ([]byte, error) {
		v, ok := m[name]
		if !ok {
			return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrNotExist}
		}
		return []byte(v), nil
	}
}

const (
	appURLNoPassword   = "postgres://alice_app@postgres:5432/alice?sslmode=disable"
	ownerURLNoPassword = "postgres://alice_owner@postgres:5432/alice?sslmode=disable"
)

func passwordOf(t *testing.T, raw string) string {
	t.Helper()
	u, err := url.Parse(raw)
	require.NoError(t, err)
	pw, ok := u.User.Password()
	require.True(t, ok, "the URL carries a password")
	return pw
}

// The production compose passes the passwords as files (docker secrets): the file's content
// without one trailing newline becomes the URL's password, and no rendering shows it.
func TestDatabasePasswordFromFile(t *testing.T) {
	c, err := config.LoadWith(env(map[string]string{
		"ALICE_DATABASE_URL":                   appURLNoPassword,
		"ALICE_DATABASE_PASSWORD_FILE":         "/run/secrets/db_app_password",
		"ALICE_MIGRATE_DATABASE_URL":           ownerURLNoPassword,
		"ALICE_MIGRATE_DATABASE_PASSWORD_FILE": "/run/secrets/db_owner_password",
	}), files(map[string]string{
		"/run/secrets/db_app_password":   "s3cret-pw\n",
		"/run/secrets/db_owner_password": "0wner/pw:@ ?#\n\n",
	}))
	require.NoError(t, err)
	assert.Equal(t, "s3cret-pw", passwordOf(t, c.DatabaseURL))
	assert.Equal(t, "0wner/pw:@ ?#\n", passwordOf(t, c.MigrateDatabaseURL), "only one trailing newline is removed; any byte survives the URL")
	assert.Equal(t, "/run/secrets/db_app_password", c.DatabasePasswordFile)
	assert.Equal(t, "/run/secrets/db_owner_password", c.MigratePasswordFile)
	assert.True(t, c.SeparateMigrationRole())

	var buf bytes.Buffer
	slog.New(slog.NewJSONHandler(&buf, nil)).Info("config loaded", "config", c)
	js, err := json.Marshal(c)
	require.NoError(t, err)
	for _, out := range []string{buf.String(), c.String(), fmt.Sprintf("%v", c), fmt.Sprintf("%#v", c), string(js)} {
		assert.NotContains(t, out, "s3cret-pw")
		assert.NotContains(t, out, "0wner")
		assert.Contains(t, out, "xxxxx")
	}
}

func TestPasswordFileWithPasswordInURLIsRefused(t *testing.T) {
	_, err := config.LoadWith(env(map[string]string{
		"ALICE_DATABASE_URL":           dbURL,
		"ALICE_DATABASE_PASSWORD_FILE": "/run/secrets/db_app_password",
	}), files(map[string]string{"/run/secrets/db_app_password": "other-pw"}))
	require.Error(t, err)
	assert.Equal(t, "ALICE_DATABASE_URL already contains a password; remove it or remove ALICE_DATABASE_PASSWORD_FILE", err.Error())

	_, err = config.LoadWith(env(map[string]string{
		"ALICE_DATABASE_URL":                   appURLNoPassword,
		"ALICE_MIGRATE_DATABASE_URL":           ownerURL,
		"ALICE_MIGRATE_DATABASE_PASSWORD_FILE": "/run/secrets/db_owner_password",
	}), files(map[string]string{"/run/secrets/db_owner_password": "other-pw"}))
	require.Error(t, err)
	assert.Equal(t, "ALICE_MIGRATE_DATABASE_URL already contains a password; remove it or remove ALICE_MIGRATE_DATABASE_PASSWORD_FILE", err.Error())
	assert.NotContains(t, err.Error(), "0wner-pw")
}

func TestEmptyOrUnreadablePasswordFileIsRefused(t *testing.T) {
	const canary = "canary-pw-71c4"
	cases := map[string]struct {
		vars  map[string]string
		files map[string]string
		want  string
	}{
		"empty app file": {
			vars:  map[string]string{"ALICE_DATABASE_URL": appURLNoPassword, "ALICE_DATABASE_PASSWORD_FILE": "/s/app"},
			files: map[string]string{"/s/app": "\n"},
			want:  "ALICE_DATABASE_PASSWORD_FILE",
		},
		"missing app file": {
			vars: map[string]string{"ALICE_DATABASE_URL": appURLNoPassword, "ALICE_DATABASE_PASSWORD_FILE": "/s/app"},
			want: "ALICE_DATABASE_PASSWORD_FILE",
		},
		"empty owner file": {
			vars: map[string]string{"ALICE_DATABASE_URL": appURLNoPassword, "ALICE_MIGRATE_DATABASE_URL": ownerURLNoPassword,
				"ALICE_MIGRATE_DATABASE_PASSWORD_FILE": "/s/owner"},
			files: map[string]string{"/s/owner": ""},
			want:  "ALICE_MIGRATE_DATABASE_PASSWORD_FILE",
		},
		"unreadable owner file": {
			vars: map[string]string{"ALICE_DATABASE_URL": appURLNoPassword, "ALICE_MIGRATE_DATABASE_URL": ownerURLNoPassword,
				"ALICE_MIGRATE_DATABASE_PASSWORD_FILE": "/s/owner"},
			want: "ALICE_MIGRATE_DATABASE_PASSWORD_FILE",
		},
		"file without a URL": {
			vars:  map[string]string{"ALICE_DATABASE_PASSWORD_FILE": "/s/app"},
			files: map[string]string{"/s/app": canary},
			want:  "ALICE_DATABASE_URL",
		},
		"owner file without an owner URL": {
			vars:  map[string]string{"ALICE_DATABASE_URL": appURLNoPassword, "ALICE_MIGRATE_DATABASE_PASSWORD_FILE": "/s/owner"},
			files: map[string]string{"/s/owner": canary},
			want:  "ALICE_MIGRATE_DATABASE_URL",
		},
		"unreadable for this user": {
			vars: map[string]string{"ALICE_DATABASE_URL": appURLNoPassword, "ALICE_DATABASE_PASSWORD_FILE": "/s/app"},
			want: "ALICE_DATABASE_PASSWORD_FILE names /s/app, which this user may not read",
		},
		"URL without a user": {
			vars:  map[string]string{"ALICE_DATABASE_URL": "postgres://postgres:5432/alice", "ALICE_DATABASE_PASSWORD_FILE": "/s/app"},
			files: map[string]string{"/s/app": canary},
			want:  "ALICE_DATABASE_URL names no user",
		},
		"password in the query": {
			vars:  map[string]string{"ALICE_DATABASE_URL": appURLNoPassword + "&Password=" + canary, "ALICE_DATABASE_PASSWORD_FILE": "/s/app"},
			files: map[string]string{"/s/app": "other"},
			want:  "ALICE_DATABASE_URL already contains a password",
		},
		"not a postgres URL": {
			vars:  map[string]string{"ALICE_DATABASE_URL": "mysql://alice_app@db/alice", "ALICE_DATABASE_PASSWORD_FILE": "/s/app"},
			files: map[string]string{"/s/app": canary},
			want:  "ALICE_DATABASE_URL is not a valid postgres:// URL",
		},
		"unparseable URL": {
			vars:  map[string]string{"ALICE_DATABASE_URL": "postgres://alice_app@host:notaport/" + canary, "ALICE_DATABASE_PASSWORD_FILE": "/s/app"},
			files: map[string]string{"/s/app": canary},
			want:  "ALICE_DATABASE_URL",
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			read := files(tc.files)
			if name == "unreadable for this user" {
				read = func(name string) ([]byte, error) {
					return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrPermission}
				}
			}
			_, err := config.LoadWith(env(tc.vars), read)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.want)
			assert.NotContains(t, err.Error(), canary)
		})
	}

	// The reader's own error can quote what it read; it is never passed on.
	_, err := config.LoadWith(env(map[string]string{"ALICE_DATABASE_URL": appURLNoPassword, "ALICE_DATABASE_PASSWORD_FILE": "/s/app"}),
		func(string) ([]byte, error) { return nil, errors.New("read failed near " + canary) })
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ALICE_DATABASE_PASSWORD_FILE")
	assert.NotContains(t, err.Error(), canary)
}

// Load keeps its signature and reads real files (M-11).
func TestLoadReadsThePasswordFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "db_app_password")
	require.NoError(t, os.WriteFile(path, []byte("s3cret-pw\n"), 0o600))
	c, err := config.Load(env(map[string]string{"ALICE_DATABASE_URL": appURLNoPassword, "ALICE_DATABASE_PASSWORD_FILE": path}))
	require.NoError(t, err)
	assert.Equal(t, "s3cret-pw", passwordOf(t, c.DatabaseURL))
}

func TestMigrateMode(t *testing.T) {
	c, err := config.Load(env(nil))
	require.NoError(t, err)
	assert.Equal(t, "on-start", c.Migrate)

	for _, v := range []string{"on-start", " external "} {
		c, err = config.Load(env(map[string]string{"ALICE_MIGRATE": v}))
		require.NoError(t, err)
		assert.Equal(t, strings.TrimSpace(v), c.Migrate)
	}
	for _, v := range []string{"External", "never", "true"} {
		_, err = config.Load(env(map[string]string{"ALICE_MIGRATE": v}))
		require.Error(t, err, v)
		assert.Contains(t, err.Error(), "ALICE_MIGRATE")
	}
}

func TestTimeZone(t *testing.T) {
	c, err := config.Load(env(nil))
	require.NoError(t, err)
	require.NotNil(t, c.TZ)
	assert.Equal(t, time.UTC, c.TZ)

	c, err = config.Load(env(map[string]string{"ALICE_TZ": "Europe/Istanbul"}))
	require.NoError(t, err)
	assert.Equal(t, "Europe/Istanbul", c.TZ.String())
	assert.Contains(t, c.String(), "Europe/Istanbul")

	for _, v := range []string{"Mars/Olympus", "Local", "../../etc/passwd"} {
		_, err = config.Load(env(map[string]string{"ALICE_TZ": v}))
		require.Error(t, err, v)
		assert.Contains(t, err.Error(), "ALICE_TZ")
	}
}

func TestBackupDirDefault(t *testing.T) {
	c, err := config.Load(env(nil))
	require.NoError(t, err)
	assert.Equal(t, "/opt/alice/backups", c.BackupDir)

	c, err = config.Load(env(map[string]string{"ALICE_BACKUP_DIR": " /srv/backups "}))
	require.NoError(t, err)
	assert.Equal(t, "/srv/backups", c.BackupDir)
	assert.Contains(t, c.String(), "/srv/backups")
}

func TestMigrateTimeout(t *testing.T) {
	c, err := config.Load(env(nil))
	require.NoError(t, err)
	assert.Equal(t, 30*time.Minute, c.MigrateTimeout, "the default leaves room for a large database")

	c, err = config.Load(env(map[string]string{"ALICE_MIGRATE_TIMEOUT": "2h"}))
	require.NoError(t, err)
	assert.Equal(t, 2*time.Hour, c.MigrateTimeout)

	for _, v := range []string{"30s", "25h", "soon"} {
		_, err = config.Load(env(map[string]string{"ALICE_MIGRATE_TIMEOUT": v}))
		require.Error(t, err, v)
		assert.Contains(t, err.Error(), "ALICE_MIGRATE_TIMEOUT")
	}
}
