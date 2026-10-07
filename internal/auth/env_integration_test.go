//go:build integration

package auth_test

import (
	"bytes"
	"context"
	"net/netip"
	"os"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/require"

	"alice/internal/audit"
	"alice/internal/auth"
	"alice/internal/platform/clock"
	"alice/internal/rbac"
	"alice/internal/secrets"
	"alice/internal/testutil/pgtest"
)

func TestMain(m *testing.M) { os.Exit(pgtest.Main(m)) }

// Small Argon2 parameters keep the suite fast; production values are tested in password_test.go.
var fastParams = auth.Argon2Params{MemoryKiB: 64, Time: 1, Threads: 1, SaltLen: 16, KeyLen: 32}

var meta = auth.Meta{IP: netip.MustParseAddr("192.0.2.10"), UserAgent: "test-agent", RequestID: "req-1"}

const adminPassword = "correct horse battery staple"

type env struct {
	ctx    context.Context
	svc    *auth.Service
	clk    *clock.Fake
	db     *pgtest.DB
	hasher *auth.Hasher
	notes  *noteRecorder
}

// noteRecorder records the e-mails auth queues (the outbox is notify's).
type noteRecorder struct {
	mu   sync.Mutex
	got  []string // template + " " + sorted params
	fail error    // returned instead of recording, when set
}

func (n *noteRecorder) NotifyAdmins(_ context.Context, _ pgx.Tx, template string, params map[string]string) error {
	if n.fail != nil {
		return n.fail
	}
	keys := make([]string, 0, len(params))
	for k, v := range params {
		keys = append(keys, k+"="+v)
	}
	sort.Strings(keys)
	n.mu.Lock()
	defer n.mu.Unlock()
	n.got = append(n.got, template+" "+strings.Join(keys, ","))
	return nil
}

func (n *noteRecorder) all() []string {
	n.mu.Lock()
	defer n.mu.Unlock()
	return append([]string(nil), n.got...)
}

// provider inserts an identity provider row (the SSO users' foreign key).
func (e *env) provider(t *testing.T) uuid.UUID {
	t.Helper()
	id := uuid.Must(uuid.NewV7())
	_, err := e.db.Owner.Exec(e.ctx, `INSERT INTO oidc_providers (id, name, issuer_url, client_id, scopes, groups_claim,
authorization_endpoint, token_endpoint, jwks_uri, enabled, created_at, updated_at) VALUES ($1, $2, 'https://idp.example.com',
$2, '{openid}', 'groups', 'https://idp.example.com/a', 'https://idp.example.com/t', 'https://idp.example.com/j', true, now(), now())`,
		id, "corp-"+id.String())
	require.NoError(t, err)
	return id
}

func newEnv(t *testing.T) *env {
	t.Helper()
	d := pgtest.New(t)
	// 09:00:00 is a TOTP step boundary, so codes computed at clk.Now() are stable.
	clk := clock.NewFake(time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC))
	kr, err := secrets.NewKeyring(1, bytes.Repeat([]byte{7}, 32))
	require.NoError(t, err)
	h := auth.NewHasher(fastParams, 4)
	notes := &noteRecorder{}
	svc := auth.NewService(auth.Config{Pool: d.App, Keyring: kr, Audit: audit.New(clk), Clock: clk, Hasher: h, RecoveryHasher: h, Notifier: notes})
	return &env{ctx: context.Background(), svc: svc, clk: clk, db: d, hasher: h, notes: notes}
}

func code(t *testing.T, secret string, at time.Time) string {
	t.Helper()
	c, err := totp.GenerateCode(secret, at)
	require.NoError(t, err)
	return c
}

// bootstrap creates the first admin "admin" and returns its TOTP secret and session.
func (e *env) bootstrap(t *testing.T) (string, auth.SessionResult) {
	t.Helper()
	enr, err := auth.NewTOTP("admin")
	require.NoError(t, err)
	hash, err := e.hasher.Hash(e.ctx, auth.NormalizePassword(adminPassword))
	require.NoError(t, err)
	res, err := e.svc.BootstrapAdmin(e.ctx, auth.BootstrapAdmin{
		Username: "admin", DisplayName: "Ayşe Yılmaz", Email: "ayse@example.com", PasswordHash: hash,
		TOTPSecret: enr.Secret, Code: code(t, enr.Secret, e.clk.Now()), Locale: "tr",
	}, meta, nil)
	require.NoError(t, err)
	return enr.Secret, res
}

// insertUser adds a local user without MFA directly in the database.
func (e *env) insertUser(t *testing.T, username string, role rbac.Role, password string) uuid.UUID {
	t.Helper()
	hash, err := e.hasher.Hash(e.ctx, auth.NormalizePassword(password))
	require.NoError(t, err)
	id := uuid.Must(uuid.NewV7())
	_, err = e.db.Owner.Exec(e.ctx, `INSERT INTO users (id, username, display_name, password_hash, role, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $6)`, id, username, username, hash, string(role), e.clk.Now())
	require.NoError(t, err)
	return id
}

// enroll performs the first login of a user without MFA and returns the TOTP secret and result.
func (e *env) enroll(t *testing.T, username, password string) (string, auth.SessionResult) {
	t.Helper()
	lr, err := e.svc.Login(e.ctx, username, password, meta)
	require.NoError(t, err)
	require.Equal(t, auth.StatusMFAEnrollmentRequired, lr.Status)
	p := e.principal(t, lr.SessionToken)
	enr, err := e.svc.EnrollMFA(e.ctx, p, meta)
	require.NoError(t, err)
	res, err := e.svc.VerifyMFA(e.ctx, p, auth.MFAInput{Code: code(t, enr.Secret, e.clk.Now())}, meta)
	require.NoError(t, err)
	return enr.Secret, res
}

// signIn performs password + TOTP login one step later than any earlier code.
func (e *env) signIn(t *testing.T, username, password, secret string) auth.SessionResult {
	t.Helper()
	e.clk.Advance(30 * time.Second)
	lr, err := e.svc.Login(e.ctx, username, password, meta)
	require.NoError(t, err)
	require.Equal(t, auth.StatusMFARequired, lr.Status)
	res, err := e.svc.VerifyMFA(e.ctx, e.principal(t, lr.SessionToken), auth.MFAInput{Code: code(t, secret, e.clk.Now())}, meta)
	require.NoError(t, err)
	return res
}

func (e *env) principal(t *testing.T, token string) auth.Principal {
	t.Helper()
	p, err := e.svc.Authenticate(e.ctx, token)
	require.NoError(t, err)
	return p
}

func (e *env) actions(t *testing.T) []string {
	t.Helper()
	rows, err := e.db.Owner.Query(e.ctx, "SELECT action || ':' || result FROM audit_log ORDER BY seq")
	require.NoError(t, err)
	defer rows.Close()
	var out []string
	for rows.Next() {
		var s string
		require.NoError(t, rows.Scan(&s))
		out = append(out, s)
	}
	require.NoError(t, rows.Err())
	return out
}

func (e *env) failedLogins(t *testing.T, username string) int {
	t.Helper()
	var n int
	require.NoError(t, e.db.Owner.QueryRow(e.ctx, "SELECT failed_logins FROM users WHERE username = $1", username).Scan(&n))
	return n
}

// reasons counts the failure rows of action by their details reason.
func (e *env) reasons(t *testing.T, action string) map[string]int {
	t.Helper()
	rows, err := e.db.Owner.Query(e.ctx, `SELECT details->>'reason', count(*) FROM audit_log
WHERE action = $1 AND result = 'failure' GROUP BY 1`, action)
	require.NoError(t, err)
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var reason string
		var n int
		require.NoError(t, rows.Scan(&reason, &n))
		out[reason] = n
	}
	require.NoError(t, rows.Err())
	return out
}

// countAction returns how many audit rows have the given action and result.
func (e *env) countAction(t *testing.T, action, result string) int {
	t.Helper()
	var n int
	require.NoError(t, e.db.Owner.QueryRow(e.ctx, "SELECT count(*) FROM audit_log WHERE action = $1 AND result = $2", action, result).Scan(&n))
	return n
}

// setFailures puts an account n consecutive failures in with no delay pending.
func (e *env) setFailures(t *testing.T, username string, n int) {
	t.Helper()
	_, err := e.db.Owner.Exec(e.ctx, "UPDATE users SET failed_logins = $2, locked_until = NULL WHERE username = $1", username, n)
	require.NoError(t, err)
}

// parallel runs f n times at once and returns every error.
func parallel(n int, f func() error) []error {
	errs := make([]error, n)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := range n {
		wg.Go(func() {
			<-start
			errs[i] = f()
		})
	}
	close(start)
	wg.Wait()
	return errs
}
