package main

import (
	"bufio"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.yaml.in/yaml/v3"
)

const (
	releaseComposePath = "../../deploy/release/docker-compose.yml"
	releaseEnvTemplate = "../../deploy/release/env.template"
	releaseRolesScript = "../../deploy/release/postgres/initdb/10-alice-roles.sh"
)

// releaseService is the part of a production compose service these tests read.
type releaseService struct {
	Image       string            `yaml:"image"`
	PullPolicy  string            `yaml:"pull_policy"`
	Profiles    []string          `yaml:"profiles"`
	Restart     string            `yaml:"restart"`
	User        string            `yaml:"user"`
	Command     []string          `yaml:"command"`
	Entrypoint  []string          `yaml:"entrypoint"`
	Environment map[string]string `yaml:"environment"`
	Secrets     []string          `yaml:"secrets"`
	Ports       []string          `yaml:"ports"`
	Volumes     []string          `yaml:"volumes"`
	Networks    []string          `yaml:"networks"`
	ReadOnly    bool              `yaml:"read_only"`
	Tmpfs       []string          `yaml:"tmpfs"`
	CapDrop     []string          `yaml:"cap_drop"`
	CapAdd      []string          `yaml:"cap_add"`
	SecurityOpt []string          `yaml:"security_opt"`
	Privileged  bool              `yaml:"privileged"`
	Build       any               `yaml:"build"`
	DependsOn   map[string]struct {
		Condition string `yaml:"condition"`
	} `yaml:"depends_on"`
	Healthcheck struct {
		Test []string `yaml:"test"`
	} `yaml:"healthcheck"`
	Logging struct {
		Driver  string            `yaml:"driver"`
		Options map[string]string `yaml:"options"`
	} `yaml:"logging"`
}

type releaseComposeFile struct {
	Name     string                    `yaml:"name"`
	Services map[string]releaseService `yaml:"services"`
	Networks map[string]struct {
		Internal bool `yaml:"internal"`
	} `yaml:"networks"`
	Secrets map[string]struct {
		File string `yaml:"file"`
	} `yaml:"secrets"`
	Volumes map[string]any `yaml:"volumes"`
}

func readReleaseCompose(t *testing.T) releaseComposeFile {
	t.Helper()
	raw, err := os.ReadFile(releaseComposePath)
	require.NoError(t, err)
	var c releaseComposeFile
	require.NoError(t, yaml.Unmarshal(raw, &c))
	require.NotEmpty(t, c.Services)
	return c
}

func serviceNames(c releaseComposeFile) []string {
	out := make([]string, 0, len(c.Services))
	for n := range c.Services {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// C3: every production service is non-root, read-only, without capabilities or new privileges, never
// pulled, and logs with bounded files; only alice publishes a port; the database sits on the internal
// network only; migrate and alice-admin run only on request.
func TestReleaseComposeIsHardened(t *testing.T) {
	c := readReleaseCompose(t)
	assert.Empty(t, c.Name, "the project name comes from COMPOSE_PROJECT_NAME in .env")
	assert.Equal(t, []string{"alice", "alice-admin", "migrate", "postgres"}, serviceNames(c))

	for name, s := range c.Services {
		assert.True(t, s.ReadOnly, "%s: read_only", name)
		assert.Equal(t, []string{"ALL"}, s.CapDrop, "%s: cap_drop", name)
		assert.Empty(t, s.CapAdd, "%s: cap_add", name)
		assert.False(t, s.Privileged, "%s: privileged", name)
		assert.Equal(t, []string{"no-new-privileges:true"}, s.SecurityOpt, "%s: security_opt", name)
		assert.Equal(t, "never", s.PullPolicy, "%s: pull_policy", name)
		assert.Nil(t, s.Build, "%s: production images are loaded, never built", name)
		want := "10001:10001"
		if name == "postgres" {
			want = "70:70"
		}
		assert.Equal(t, want, s.User, "%s: numeric non-root user", name)
		assert.Equal(t, "json-file", s.Logging.Driver, "%s: logging driver", name)
		assert.NotEmpty(t, s.Logging.Options["max-size"], "%s: log size limit", name)
		assert.NotEmpty(t, s.Logging.Options["max-file"], "%s: log file limit", name)
	}

	pg := c.Services["postgres"]
	assert.Equal(t, "${POSTGRES_IMAGE}", pg.Image)
	assert.Equal(t, []string{"postgres", "-c", "log_error_verbosity=terse", "-c", "password_encryption=scram-sha-256"}, pg.Command)
	assert.Equal(t, []string{"CMD-SHELL", "pg_isready -h 127.0.0.1 -U postgres -d alice"}, pg.Healthcheck.Test)
	assert.Equal(t, []string{"backend"}, pg.Networks)
	assert.Equal(t, "/run/secrets/db_postgres_password", pg.Environment["POSTGRES_PASSWORD_FILE"])
	assert.Equal(t, "--auth-host=scram-sha-256", pg.Environment["POSTGRES_INITDB_ARGS"], "no trusted TCP rule (S-19)")
	assert.ElementsMatch(t, []string{"POSTGRES_PASSWORD_FILE", "POSTGRES_INITDB_ARGS"}, sortedKeys(pg.Environment))
	assert.ElementsMatch(t, []string{"/tmp", "/var/run/postgresql"}, pg.Tmpfs)

	for _, name := range []string{"postgres", "migrate", "alice-admin"} {
		assert.Empty(t, c.Services[name].Ports, "%s publishes nothing", name)
	}
	alice := c.Services["alice"]
	assert.Equal(t, "${ALICE_IMAGE}", alice.Image)
	assert.Equal(t, []string{"${ALICE_BIND:-0.0.0.0}:${ALICE_PORT:-443}:8443"}, alice.Ports)
	assert.ElementsMatch(t, []string{"frontend", "backend"}, alice.Networks)
	assert.Equal(t, "unless-stopped", alice.Restart)
	assert.Equal(t, []string{"CMD", "/usr/local/bin/alice", "healthcheck"}, alice.Healthcheck.Test)
	assert.Equal(t, []string{"postgres"}, sortedKeys(alice.DependsOn), "alice depends only on postgres")
	assert.Equal(t, "service_healthy", alice.DependsOn["postgres"].Condition)

	assert.True(t, c.Networks["backend"].Internal, "backend is internal")
	assert.False(t, c.Networks["frontend"].Internal)

	for _, name := range []string{"migrate", "alice-admin"} {
		s := c.Services[name]
		assert.Equal(t, []string{"admin"}, s.Profiles, "%s runs only through docker compose run", name)
		assert.Equal(t, "no", s.Restart, "%s: restart", name)
		assert.Equal(t, "${ALICE_IMAGE}", s.Image, "%s: image", name)
		assert.Equal(t, []string{"backend"}, s.Networks, "%s: networks", name)
	}
	assert.Equal(t, []string{"migrate"}, c.Services["migrate"].Command)
	assert.Equal(t, []string{"/usr/local/bin/alice"}, c.Services["alice-admin"].Entrypoint)
	assert.Empty(t, c.Services["alice"].Profiles)
	assert.Empty(t, c.Services["postgres"].Profiles)
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// P1-01: the long-running alice container can never act as the schema owner; only the one-shot
// migrate and alice-admin containers receive the owner password, and only postgres the superuser's.
func TestAliceServiceHoldsNoOwnerCredential(t *testing.T) {
	c := readReleaseCompose(t)
	alice := c.Services["alice"]
	for k, v := range alice.Environment {
		assert.False(t, strings.HasPrefix(k, "ALICE_MIGRATE_DATABASE"), "alice must not get %s", k)
		assert.NotContains(t, v, "alice_owner", "%s", k)
	}
	assert.Equal(t, "external", alice.Environment["ALICE_MIGRATE"])
	assert.Equal(t, "postgres://alice_app@postgres:5432/alice?sslmode=disable", alice.Environment["ALICE_DATABASE_URL"],
		"the app role, without a password")
	assert.Equal(t, "/run/secrets/db_app_password", alice.Environment["ALICE_DATABASE_PASSWORD_FILE"])
	assert.Equal(t, []string{"db_app_password"}, alice.Secrets)

	holders := map[string][]string{}
	for name, s := range c.Services {
		for _, sec := range s.Secrets {
			holders[sec] = append(holders[sec], name)
		}
		for k, v := range s.Environment {
			assert.NotRegexp(t, `://[^/@]*:[^/@]*@`, v, "%s %s: no password in a URL", name, k)
		}
	}
	for k := range holders {
		sort.Strings(holders[k])
	}
	assert.Equal(t, []string{"alice-admin", "migrate", "postgres"}, holders["db_owner_password"],
		"postgres creates the role; migrate and alice-admin use it")
	assert.Equal(t, []string{"postgres"}, holders["db_postgres_password"])
	assert.Equal(t, []string{"alice", "alice-admin", "postgres"}, holders["db_app_password"])

	// The owner URL and its file always come together, and only where the owner secret is mounted.
	for _, name := range []string{"migrate", "alice-admin"} {
		env := c.Services[name].Environment
		assert.Equal(t, "postgres://alice_owner@postgres:5432/alice?sslmode=disable", env["ALICE_MIGRATE_DATABASE_URL"], name)
		assert.Equal(t, "/run/secrets/db_owner_password", env["ALICE_MIGRATE_DATABASE_PASSWORD_FILE"], name)
	}
	// S-37: migrate needs no application credential.
	assert.NotContains(t, c.Services["migrate"].Environment, "ALICE_DATABASE_URL")
	assert.Equal(t, "postgres://alice_app@postgres:5432/alice?sslmode=disable", c.Services["alice-admin"].Environment["ALICE_DATABASE_URL"])
}

// C2/C3: the bind mounts are the installation layout exactly, and every secret is a file under
// ./secrets.
func TestReleaseComposeMountsMatchTheLayout(t *testing.T) {
	c := readReleaseCompose(t)
	appMounts := []string{"./keys:/opt/alice/keys", "./state:/opt/alice/state", "./backups:/opt/alice/backups"}
	want := map[string][]string{
		"postgres":    {"./data/postgres:/var/lib/postgresql/data", "./lib/initdb:/docker-entrypoint-initdb.d:ro"},
		"alice":       appMounts,
		"alice-admin": appMounts,
		"migrate":     nil,
	}
	for name, s := range c.Services {
		assert.ElementsMatch(t, want[name], s.Volumes, name)
	}
	assert.Empty(t, c.Volumes, "no named volume: everything lives in the installation directory")
	assert.Equal(t, []string{"db_app_password", "db_owner_password", "db_postgres_password"}, sortedKeys(c.Secrets))
	for name, s := range c.Secrets {
		assert.Equal(t, "./secrets/"+name, s.File)
	}
	env := c.Services["alice"].Environment
	assert.Equal(t, "/opt/alice/state", env["ALICE_STATE_DIR"])
	assert.Equal(t, "/opt/alice/backups", env["ALICE_BACKUP_DIR"])
	assert.Equal(t, "${ALICE_TZ:-UTC}", env["ALICE_TZ"])
	assert.Equal(t, "${ALICE_TLS_HOSTS:-}", env["ALICE_TLS_HOSTS"])
	admin := c.Services["alice-admin"].Environment
	for _, k := range []string{"ALICE_KEYS_DIR", "ALICE_STATE_DIR", "ALICE_BACKUP_DIR", "ALICE_TZ"} {
		assert.NotEmpty(t, admin[k], "alice-admin %s", k)
	}
}

// C2: .env holds exactly these keys and no secret.
func TestEnvTemplateHasNoSecret(t *testing.T) {
	f, err := os.Open(releaseEnvTemplate)
	require.NoError(t, err)
	defer func() { _ = f.Close() }()
	var got []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, _, ok := strings.Cut(line, "=")
		require.True(t, ok, "not KEY=VALUE: %q", line)
		got = append(got, k)
		assert.NotRegexp(t, `(?i)PASSWORD|SECRET|KEY|TOKEN`, k, "no secret in .env")
	}
	require.NoError(t, sc.Err())
	assert.Equal(t, []string{"COMPOSE_PROJECT_NAME", "ALICE_IMAGE", "POSTGRES_IMAGE", "ALICE_BIND", "ALICE_PORT",
		"ALICE_TLS_HOSTS", "ALICE_TZ"}, got)
}

// S-20: the role script never puts a password in an argument list; psql reads the secret files.
func TestRolesScriptKeepsPasswordsOutOfArguments(t *testing.T) {
	raw, err := os.ReadFile(releaseRolesScript)
	require.NoError(t, err)
	src := string(raw)
	assert.NotRegexp(t, regexp.MustCompile(`-v\s*\S*_pw=`), src)
	assert.NotRegexp(t, regexp.MustCompile(`(?m)^\s*[a-z_]*pw=`), src, "no shell variable holds a password")
	assert.Contains(t, src, "\\set owner_pw `cat /run/secrets/db_owner_password`")
	assert.Contains(t, src, "\\set app_pw `cat /run/secrets/db_app_password`")
	assert.Contains(t, src, "PASSWORD :'owner_pw'")
	assert.Contains(t, src, "PASSWORD :'app_pw'")
	assert.Contains(t, src, "<<'SQL'", "a quoted heredoc: the shell expands nothing")
	assert.NotContains(t, src, "<<SQL")
}
