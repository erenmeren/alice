//go:build integration

package ldap_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"log/slog"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"alice/internal/audit"
	"alice/internal/auth/ldap"
	"alice/internal/platform/clock"
	"alice/internal/platform/netaddr"
	"alice/internal/secrets"
	"alice/internal/testutil/fakeldap"
	"alice/internal/testutil/pgtest"
)

func TestMain(m *testing.M) {
	code := pgtest.Main(m)
	fakeldap.Stop()
	os.Exit(code)
}

// syncBuffer is a log sink the tests read.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

type harness struct {
	ctx   context.Context
	d     *pgtest.DB
	clk   *clock.Fake
	kr    *secrets.Keyring
	srv   *fakeldap.Server
	svc   *ldap.Service
	logs  *syncBuffer
	dials atomic.Int64
	// redirect, when set, sends a dial for this host:port to the real server instead.
	redirect atomic.Value // string
	admin    audit.Actor
	dir      ldap.Directory
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	d := pgtest.New(t)
	clk := clock.NewFake(time.Date(2026, 10, 15, 9, 0, 0, 0, time.UTC))
	kr, err := secrets.NewKeyring(1, bytes.Repeat([]byte{7}, 32))
	require.NoError(t, err)
	x := &harness{ctx: context.Background(), d: d, clk: clk, kr: kr, srv: fakeldap.Start(t), logs: &syncBuffer{}}
	x.redirect.Store("")
	x.svc = ldap.New(ldap.Config{Pool: d.App, Keyring: kr, Audit: audit.New(clk), Clock: clk, Log: slog.New(slog.NewTextHandler(x.logs, nil)),
		Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			x.dials.Add(1)
			if r := x.redirect.Load().(string); r != "" && r == addr {
				addr = x.srv.Endpoint()
			}
			return netaddr.DialContext(ctx, &net.Dialer{Timeout: ldap.DialTimeout}, network, addr)
		}})
	adminID := uuid.New()
	_, err = d.Owner.Exec(context.Background(), `INSERT INTO users (id, username, display_name, password_hash, role, created_at, updated_at)
VALUES ($1, 'ada-admin', 'Ada', '$argon2id$x', 'admin', now(), now())`, adminID)
	require.NoError(t, err)
	x.admin = audit.Actor{Type: audit.ActorUser, ID: adminID, Name: "ada-admin"}
	x.dir = x.create(t, "Corp LDAP", true)
	return x
}

// input is a directory input for the test directory.
func (x *harness) input(name string, enabled bool) ldap.DirectoryInput {
	return ldap.DirectoryInput{Name: name, Addresses: []string{x.srv.Address}, UserBaseDN: fakeldap.PeopleDN,
		UserFilter: fakeldap.UserFilter, LoginAttribute: "uid", UniqueIDAttribute: "entryUUID", DisplayNameAttribute: "cn",
		EmailAttribute: "mail", BindDN: fakeldap.ServiceDN, BindPassword: secrets.NewPlaintext([]byte(x.srv.ServicePassword())),
		GroupBaseDN: fakeldap.GroupsDN, GroupFilter: fakeldap.GroupFilter, GroupNameAttribute: "cn", CAPEM: string(x.srv.CAPEM),
		Enabled: enabled}
}

func (x *harness) create(t *testing.T, name string, enabled bool) ldap.Directory {
	t.Helper()
	d, err := x.svc.CreateDirectory(x.ctx, x.admin, x.input(name, enabled))
	require.NoError(t, err)
	return d
}

func (x *harness) update(t *testing.T, p ldap.DirectoryPatch) ldap.Directory {
	t.Helper()
	d, err := x.svc.UpdateDirectory(x.ctx, x.admin, x.dir.ID, x.dir.Version, p)
	require.NoError(t, err)
	x.dir = d
	return d
}

func (x *harness) verify(login, password string) (ldap.Identity, error) {
	id, _, err := x.svc.Verify(x.ctx, x.dir.ID, login, secrets.NewPlaintext([]byte(password)))
	return id, err
}

func (x *harness) count(t *testing.T, sql string, args ...any) int {
	t.Helper()
	var n int
	require.NoError(t, x.d.Owner.QueryRow(x.ctx, sql, args...).Scan(&n))
	return n
}

// seedUser inserts a directory user of the test directory, as a first sign-in will (Task 4).
func (x *harness) seedUser(t *testing.T, dirID uuid.UUID) {
	t.Helper()
	name := "dir-" + uuid.NewString()[:8]
	_, err := x.d.Owner.Exec(x.ctx, `INSERT INTO users (id, username, display_name, auth_source, role, role_source, ldap_directory_id,
ldap_unique_id, ldap_login, created_at, updated_at) VALUES ($1, $2, 'Dir User', 'ldap', 'operator', 'ldap_mapping', $3, $4, $5, now(), now())`,
		uuid.New(), name, dirID, hex.EncodeToString([]byte(uuid.NewString())), name)
	require.NoError(t, err)
}

func reasonOf(err error) [2]string {
	var le *ldap.LoginError
	if errors.As(err, &le) {
		return [2]string{le.Reason, le.Detail}
	}
	return [2]string{"", ""}
}

func ptr[T any](v T) *T { return &v }

func secretPtr(s string) *secrets.Plaintext { p := secrets.NewPlaintext([]byte(s)); return &p }
