//go:build integration

// Package release holds the tests of the production deployment files in this directory; it has no
// non-test Go code.
package release

import (
	"context"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/moby/moby/api/types/container"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
	"go.yaml.in/yaml/v3"

	"alice/internal/platform/db"
	"alice/migrations"
)

// Fixture passwords of a throw-away container (never production values).
const (
	postgresPW = "s3cret-pw"   //nolint:gosec // G101: test fixture
	ownerPW    = "0wner-pw"    //nolint:gosec // G101: test fixture
	appPW      = "app-test-pw" //nolint:gosec // G101: test fixture
)

// postgresService reads the postgres service of docker-compose.yml: the test runs the container
// with its user, command and environment, so it checks the file itself.
func postgresService(t *testing.T) (user string, command []string, environment map[string]string) {
	t.Helper()
	raw, err := os.ReadFile("docker-compose.yml")
	require.NoError(t, err)
	var c struct {
		Services map[string]struct {
			User        string            `yaml:"user"`
			Command     []string          `yaml:"command"`
			Environment map[string]string `yaml:"environment"`
		} `yaml:"services"`
	}
	require.NoError(t, yaml.Unmarshal(raw, &c))
	pg := c.Services["postgres"]
	require.NotEmpty(t, pg.Command)
	require.Equal(t, "70:70", pg.User)
	return pg.User, pg.Command, pg.Environment
}

// TestReleaseRolesScript runs postgres as the production compose does (its user, command and
// environment read from docker-compose.yml; read-only root, no capabilities, the secrets as files) with 10-alice-roles.sh as its only
// init script, then checks the roles, the database, the server settings and pg_hba (R43 row 7, S-19,
// S-20), and that the migrations apply as alice_owner on exactly this cluster.
func TestReleaseRolesScript(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	user, command, environment := postgresService(t)

	script, err := filepath.Abs("postgres/initdb/10-alice-roles.sh")
	require.NoError(t, err)
	secrets := t.TempDir()
	binds := []string{script + ":/docker-entrypoint-initdb.d/10-alice-roles.sh:ro"}
	for name, pw := range map[string]string{"db_postgres_password": postgresPW, "db_owner_password": ownerPW, "db_app_password": appPW} {
		p := filepath.Join(secrets, name)
		// A trailing newline, as install.sh writes it; uid 70 in the container must read the file.
		require.NoError(t, os.WriteFile(p, []byte(pw+"\n"), 0o600))
		require.NoError(t, os.Chmod(p, 0o644)) //nolint:gosec // G302: the container user reads the fixture
		binds = append(binds, p+":/run/secrets/"+name+":ro")
	}

	ctr, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:        "postgres:16-alpine@sha256:721873c34ceb9f8d8fc265984940dc982404c105f19ad51be9fdc5970a6080ea",
			Cmd:          command,
			Env:          environment,
			ExposedPorts: []string{"5432/tcp"},
			ConfigModifier: func(c *container.Config) {
				c.User = user
			},
			HostConfigModifier: func(hc *container.HostConfig) {
				hc.Binds = append(hc.Binds, binds...)
				hc.ReadonlyRootfs = true
				hc.Tmpfs = map[string]string{"/tmp": "", "/var/run/postgresql": ""}
				hc.CapDrop = []string{"ALL"}
				hc.SecurityOpt = []string{"no-new-privileges:true"}
			},
			WaitingFor: wait.ForAll(
				// The entrypoint's temporary server logs it once, the real server a second time.
				wait.ForLog("database system is ready to accept connections").WithOccurrence(2),
				wait.ForListeningPort("5432/tcp"),
			).WithDeadline(3 * time.Minute),
		},
		Started: true,
	})
	if ctr != nil {
		t.Cleanup(func() { _ = testcontainers.TerminateContainer(ctr) })
	}
	require.NoError(t, err)

	host, err := ctr.Host(ctx)
	require.NoError(t, err)
	port, err := ctr.MappedPort(ctx, "5432/tcp")
	require.NoError(t, err)
	connURL := func(user, pw, database string) string {
		u := url.URL{Scheme: "postgres", User: url.UserPassword(user, pw), Host: fmt.Sprintf("%s:%s", host, port.Port()),
			Path: "/" + database, RawQuery: "sslmode=disable"}
		return u.String()
	}

	su, err := pgx.Connect(ctx, connURL("postgres", postgresPW, "alice"))
	require.NoError(t, err)
	defer func() { _ = su.Close(ctx) }()

	type role struct{ super, createdb, login, createrole, replication, bypassRLS bool }
	readRole := func(name string) role {
		var r role
		require.NoError(t, su.QueryRow(ctx, `SELECT rolsuper, rolcreatedb, rolcanlogin, rolcreaterole, rolreplication, rolbypassrls
FROM pg_roles WHERE rolname = $1`, name).Scan(&r.super, &r.createdb, &r.login, &r.createrole, &r.replication, &r.bypassRLS), name)
		return r
	}
	assert.Equal(t, role{createdb: true, login: true}, readRole("alice_owner"), "alice_owner: LOGIN CREATEDB, nothing else")
	assert.Equal(t, role{login: true}, readRole("alice_app"), "alice_app: LOGIN only")

	var dbOwner string
	require.NoError(t, su.QueryRow(ctx, "SELECT pg_get_userbyid(datdba) FROM pg_database WHERE datname = 'alice'").Scan(&dbOwner))
	assert.Equal(t, "alice_owner", dbOwner)

	var canSet bool
	require.NoError(t, su.QueryRow(ctx, "SELECT has_parameter_privilege('alice_owner', 'session_replication_role', 'SET')").Scan(&canSet))
	assert.True(t, canSet, "alice_owner may switch off triggers for a restore")

	var publicCreate, appCreate bool
	var schemaOwner string
	require.NoError(t, su.QueryRow(ctx, `SELECT has_schema_privilege('public', 'public', 'CREATE'),
has_schema_privilege('alice_app', 'public', 'CREATE'), pg_get_userbyid(nspowner) FROM pg_namespace WHERE nspname = 'public'`).
		Scan(&publicCreate, &appCreate, &schemaOwner))
	assert.False(t, publicCreate, "PUBLIC has no CREATE on schema public")
	assert.False(t, appCreate, "alice_app has no CREATE on schema public")
	assert.Equal(t, "alice_owner", schemaOwner)

	var scram int
	require.NoError(t, su.QueryRow(ctx, `SELECT count(*) FROM pg_authid
WHERE rolname IN ('postgres', 'alice_owner', 'alice_app') AND rolpassword LIKE 'SCRAM-SHA-256$%'`).Scan(&scram))
	assert.Equal(t, 3, scram, "every password is stored as a SCRAM verifier")

	// S-19: the compose command is in effect, and every TCP rule asks for a SCRAM password.
	for setting, want := range map[string]string{"log_error_verbosity": "terse", "password_encryption": "scram-sha-256"} {
		var got string
		require.NoError(t, su.QueryRow(ctx, "SELECT current_setting($1)", setting).Scan(&got))
		assert.Equal(t, want, got, setting)
	}
	rows, err := su.Query(ctx, `SELECT line_number, type, coalesce(auth_method, ''), coalesce(error, '') FROM pg_hba_file_rules`)
	require.NoError(t, err)
	hostRules := 0
	for rows.Next() {
		var (
			line                 int
			typ, method, problem string
		)
		require.NoError(t, rows.Scan(&line, &typ, &method, &problem))
		assert.Empty(t, problem, "pg_hba.conf line %d", line)
		if strings.HasPrefix(typ, "host") {
			hostRules++
			assert.Equal(t, "scram-sha-256", method, "pg_hba.conf line %d (%s)", line, typ)
		}
	}
	require.NoError(t, rows.Err())
	assert.Positive(t, hostRules, "pg_hba has host rules")

	// Both application roles log in with their file passwords, over TCP.
	for user, pw := range map[string]string{"alice_owner": ownerPW, "alice_app": appPW} {
		c, err := pgx.Connect(ctx, connURL(user, pw, "alice"))
		require.NoError(t, err, user)
		var who string
		require.NoError(t, c.QueryRow(ctx, "SELECT current_user").Scan(&who))
		assert.Equal(t, user, who)
		require.NoError(t, c.Close(ctx))
	}
	_, err = pgx.Connect(ctx, connURL("alice_app", appPW+"\n", "alice"))
	require.Error(t, err, "the trailing newline of the secret file is not part of the password")

	// The migrations apply as alice_owner on this cluster, and alice_app then works with its grants.
	owner, err := db.Open(ctx, connURL("alice_owner", ownerPW, "alice"))
	require.NoError(t, err)
	require.NoError(t, db.Migrate(ctx, owner, migrations.FS))
	owner.Close()
	app, err := pgx.Connect(ctx, connURL("alice_app", appPW, "alice"))
	require.NoError(t, err)
	var n int
	require.NoError(t, app.QueryRow(ctx, "SELECT count(*) FROM settings").Scan(&n))
	_, err = app.Exec(ctx, "CREATE TABLE intruder (id int)")
	require.Error(t, err, "alice_app creates nothing")
	require.NoError(t, app.Close(ctx))

	// No password reached the server log (S-20; the init script runs inside the entrypoint).
	logs, err := ctr.Logs(ctx)
	require.NoError(t, err)
	raw, err := io.ReadAll(logs)
	require.NoError(t, err)
	for _, pw := range []string{postgresPW, ownerPW, appPW} {
		assert.NotContains(t, string(raw), pw)
	}
}
