//go:build integration

package auth_test

import (
	"bytes"
	"crypto/sha256"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/audit"
	"alice/internal/auth"
	"alice/internal/rbac"
	"alice/internal/secrets"
)

// slowParams make one verification take a few milliseconds, so a burst against one
// account really queues.
var slowParams = auth.Argon2Params{MemoryKiB: 8 * 1024, Time: 1, Threads: 1, SaltLen: 16, KeyLen: 32}

const hashSlots = 2

// TestCredentialBurstDoesNotExhaustThePool fires 40 parallel logins at one existing
// account through a 10-connection pool. Credential checks wait for a slot before they
// take a connection, so at most hashSlots transactions hold connections, and other
// requests (here Authenticate of another user) keep working.
func TestCredentialBurstDoesNotExhaustThePool(t *testing.T) {
	e := newEnv(t)
	cfg, err := pgxpool.ParseConfig(e.db.AppURL)
	require.NoError(t, err)
	cfg.MaxConns = 10
	pool, err := pgxpool.NewWithConfig(e.ctx, cfg)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	kr, err := secrets.NewKeyring(1, bytes.Repeat([]byte{7}, 32))
	require.NoError(t, err)
	h := auth.NewHasher(slowParams, hashSlots)
	svc := auth.NewService(auth.Config{Pool: pool, Keyring: kr, Audit: audit.New(e.clk), Clock: e.clk, Hasher: h, RecoveryHasher: h})

	hash, err := h.Hash(e.ctx, auth.NormalizePassword(adminPassword))
	require.NoError(t, err)
	_, err = e.db.Owner.Exec(e.ctx, `INSERT INTO users (id, username, display_name, password_hash, role, created_at, updated_at)
VALUES ($1, 'target', 'target', $2, 'operator', $3, $3)`, uuid.Must(uuid.NewV7()), hash, e.clk.Now())
	require.NoError(t, err)

	// A signed-in bystander: a full session inserted directly.
	other := e.insertUser(t, "bystander", rbac.Operator, adminPassword)
	token := "bystander-session-token"
	sum := sha256.Sum256([]byte(token))
	now := e.clk.Now()
	_, err = e.db.Owner.Exec(e.ctx, `INSERT INTO sessions (id_hash, user_id, kind, created_at, last_seen_at, expires_at, idle_expires_at)
VALUES ($1, $2, 'full', $3, $3, $4, $5)`, sum[:], other, now, now.Add(auth.SessionAbsolute), now.Add(auth.SessionIdle))
	require.NoError(t, err)

	var maxAcquired atomic.Int32
	stop := make(chan struct{})
	probeDone := make(chan struct{})
	go func() {
		defer close(probeDone)
		for {
			select {
			case <-stop:
				return
			default:
			}
			if n := pool.Stat().AcquiredConns(); n > maxAcquired.Load() {
				maxAcquired.Store(n)
			}
			time.Sleep(200 * time.Microsecond)
		}
	}()

	var authElapsed time.Duration
	var authErr error
	authDone := make(chan struct{})
	go func() {
		defer close(authDone)
		time.Sleep(20 * time.Millisecond) // let the burst fill the queue first
		start := time.Now()
		_, authErr = svc.Authenticate(e.ctx, token)
		authElapsed = time.Since(start)
	}()

	errs := parallel(40, func() error {
		_, err := svc.Login(e.ctx, "target", adminPassword, meta)
		return err
	})
	<-authDone
	close(stop)
	<-probeDone

	for _, err := range errs {
		require.NoError(t, err)
	}
	require.NoError(t, authErr)
	assert.Less(t, authElapsed, 2*time.Second, "other requests are not starved by a credential burst")
	// The credential slots, plus Authenticate and one connection of slack.
	assert.LessOrEqual(t, int(maxAcquired.Load()), hashSlots+2, "credential checks wait for a slot before taking a connection")
}

// TestEveryCredentialPathTakesTheSameSlot checks that unknown users and blocked accounts
// wait in the same queue as real checks, so queueing time does not reveal whether an
// account exists, and that no more than the slot count run at once.
func TestEveryCredentialPathTakesTheSameSlot(t *testing.T) {
	e := newEnv(t)
	e.bootstrap(t)
	var calls, inFlight, peak atomic.Int32
	auth.SetCredentialSlotHook(e.svc, func(acquired bool) {
		if !acquired {
			inFlight.Add(-1)
			return
		}
		calls.Add(1)
		if n := inFlight.Add(1); n > peak.Load() {
			peak.Store(n)
		}
	})

	_, err := e.svc.Login(e.ctx, "no-such-user", "whatever whatever", meta)
	require.ErrorIs(t, err, auth.ErrInvalidCredentials)
	assert.Equal(t, int32(1), calls.Load(), "the unknown-user path takes a slot")

	e.setFailures(t, "admin", auth.LockThreshold-1)
	_, err = e.svc.Login(e.ctx, "admin", "definitely not it", meta)
	require.ErrorIs(t, err, auth.ErrInvalidCredentials)
	_, err = e.svc.Login(e.ctx, "admin", adminPassword, meta)
	require.ErrorIs(t, err, auth.ErrInvalidCredentials)
	assert.Equal(t, int32(3), calls.Load(), "the blocked path takes a slot")

	requireAll(t, parallel(20, func() error {
		_, err := e.svc.Login(e.ctx, "no-such-user", "whatever whatever", meta)
		return err
	}), auth.ErrInvalidCredentials)
	assert.Equal(t, int32(23), calls.Load())
	assert.LessOrEqual(t, int(peak.Load()), auth.CredentialSlots(e.svc))
	assert.Zero(t, inFlight.Load(), "every slot is released")
}

func TestLockTimeoutGivesARetryableError(t *testing.T) {
	e := newEnv(t)
	e.bootstrap(t)
	auth.SetLockTimeout(e.svc, 200*time.Millisecond)
	tx, err := e.db.Owner.Begin(e.ctx)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback(e.ctx) }()
	_, err = tx.Exec(e.ctx, "SELECT 1 FROM users WHERE username = 'admin' FOR UPDATE")
	require.NoError(t, err)

	start := time.Now()
	_, err = e.svc.Login(e.ctx, "admin", adminPassword, meta)
	require.ErrorIs(t, err, auth.ErrTryAgain)
	assert.Less(t, time.Since(start), 2*time.Second)
	assert.Equal(t, 0, e.failedLogins(t, "admin"), "an attempt that timed out is not counted")
}
