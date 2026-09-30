package auth

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"alice/internal/audit"
	"alice/internal/platform/db"
)

// failureDelay returns how long an account is blocked after its n-th consecutive failure,
// and whether that block is the 15-minute lockout (SEC-020).
func failureDelay(n int) (time.Duration, bool) {
	switch {
	case n >= LockThreshold:
		return LockDuration, true
	case n >= DelayThreshold:
		d := time.Duration(1<<(n-DelayThreshold)) * time.Second
		return min(d, MaxDelay), false
	default:
		return 0, false
	}
}

// account is a local user's credential and lockout state, read under a row lock.
type account struct {
	id          uuid.UUID
	name        string
	hash        *string
	disabled    bool
	enrolled    bool
	lockedUntil *time.Time
}

// blocked reports whether the account is in a progressive delay or locked out at now.
func (a account) blocked(now time.Time) bool {
	return a.lockedUntil != nil && now.Before(*a.lockedUntil)
}

// Account lock queries; both select the same columns for lockAccount.
const (
	lockAccountByNameSQL = `SELECT u.id, u.username::text, u.password_hash, u.disabled_at IS NOT NULL, u.locked_until,
EXISTS (SELECT 1 FROM user_mfa m WHERE m.user_id = u.id AND m.enrolled_at IS NOT NULL)
FROM users u WHERE u.username = $1 AND u.auth_source = 'local' FOR UPDATE OF u`
	lockAccountByIDSQL = `SELECT u.id, u.username::text, u.password_hash, u.disabled_at IS NOT NULL, u.locked_until,
EXISTS (SELECT 1 FROM user_mfa m WHERE m.user_id = u.id AND m.enrolled_at IS NOT NULL)
FROM users u WHERE u.id = $1 FOR UPDATE OF u`
)

// lockAccount reads one account with SELECT ... FOR UPDATE. Every attempt that checks a
// credential (login, MFA, step-up, password change) takes this lock first, so the lock
// check, the verification and the failure count of concurrent attempts on one account
// run one after another and the delay and lockout cannot be bypassed by parallel
// requests (SEC-020). query is lockAccountByNameSQL or lockAccountByIDSQL. Found is
// false when no row matches.
func lockAccount(ctx context.Context, tx pgx.Tx, query string, arg any) (account, bool, error) {
	var a account
	err := tx.QueryRow(ctx, query, arg).Scan(
		&a.id, &a.name, &a.hash, &a.disabled, &a.lockedUntil, &a.enrolled)
	if errors.Is(err, pgx.ErrNoRows) {
		return account{}, false, nil
	}
	if err != nil {
		return account{}, false, fmt.Errorf("lock account: %w", err)
	}
	return a, true, nil
}

// blockReason returns why an MFA or step-up attempt is refused without checking the
// code ("disabled" or "locked"), or "" when it may proceed.
func blockReason(a account, now time.Time) string {
	switch {
	case a.disabled:
		return "disabled"
	case a.blocked(now):
		return "locked"
	default:
		return ""
	}
}

// lockAccountByID locks the account of an authenticated principal; a vanished user is unauthenticated.
func lockAccountByID(ctx context.Context, tx pgx.Tx, id uuid.UUID) (account, error) {
	a, found, err := lockAccount(ctx, tx, lockAccountByIDSQL, id)
	if err != nil {
		return account{}, err
	}
	if !found {
		return account{}, ErrUnauthenticated
	}
	return a, nil
}

// recordFailure counts a failed password or code for an account locked by lockAccount,
// applies the progressive delay or lockout, and audits the failure (and the lockout).
// The audit rows are appended last, after the row locks, so the chain lock is never
// held while waiting for a user row.
func (s *Service) recordFailure(ctx context.Context, tx pgx.Tx, actor audit.Actor, userID uuid.UUID, action, reason string) error {
	now := s.clock.Now().UTC()
	var n int
	if err := tx.QueryRow(ctx, "UPDATE users SET failed_logins = failed_logins + 1, updated_at = $2 WHERE id = $1 RETURNING failed_logins",
		userID, now).Scan(&n); err != nil {
		return fmt.Errorf("count failure: %w", err)
	}
	d, locked := failureDelay(n)
	if d > 0 {
		if _, err := tx.Exec(ctx, "UPDATE users SET locked_until = $2 WHERE id = $1", userID, now.Add(d)); err != nil {
			return fmt.Errorf("delay account: %w", err)
		}
	}
	if _, err := s.audit.Append(ctx, tx, audit.Event{Actor: actor, Action: action, ObjectType: "user", ObjectID: userID.String(),
		Result: audit.Failure, Details: map[string]string{"reason": reason}}); err != nil {
		return err
	}
	if locked {
		if _, err := s.audit.Append(ctx, tx, audit.Event{Actor: actor, Action: "auth.lockout", ObjectType: "user", ObjectID: userID.String(),
			Result: audit.Failure, Details: map[string]string{"failed_logins": strconv.Itoa(n), "minutes": strconv.Itoa(int(LockDuration / time.Minute))}}); err != nil {
			return err
		}
	}
	return nil
}

// auditFailure writes a failure event without touching the counters.
func (s *Service) auditFailure(ctx context.Context, tx pgx.Tx, actor audit.Actor, action, objectID, reason string) error {
	_, err := s.audit.Append(ctx, tx, audit.Event{Actor: actor, Action: action, ObjectType: "user", ObjectID: objectID,
		Result: audit.Failure, Details: map[string]string{"reason": reason}})
	return err
}

// lockNotAvailable is the PostgreSQL SQLSTATE raised when lock_timeout expires.
const lockNotAvailable = "55P03"

// withCredentialSlot runs fn while holding one of the service's credential slots. The
// slot is taken before any pool connection, so at most cap(credSlots) credential checks
// hold connections at once, however many requests queue (each waits here, holding
// nothing). fn must not take another slot.
func (s *Service) withCredentialSlot(ctx context.Context, fn func() error) error {
	select {
	case s.credSlots <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	}
	if s.slotHook != nil {
		s.slotHook(true)
	}
	defer func() {
		if s.slotHook != nil {
			s.slotHook(false)
		}
		<-s.credSlots
	}()
	return fn()
}

// credentialTx runs fn in a transaction whose lock waits end after s.lockTimeout. A
// lock timeout rolls everything back (nothing verified or counted) and becomes ErrTryAgain.
// Callers hold a credential slot.
func (s *Service) credentialTx(ctx context.Context, fn func(tx pgx.Tx) error) error {
	err := db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, "SELECT set_config('lock_timeout', $1, true)", strconv.FormatInt(s.lockTimeout.Milliseconds(), 10)+"ms"); err != nil {
			return fmt.Errorf("set lock timeout: %w", err)
		}
		return fn(tx)
	})
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == lockNotAvailable {
		return fmt.Errorf("%w: %w", ErrTryAgain, err)
	}
	return err
}

// Login verifies username and password and opens a pending session that can only
// complete MFA. Every failure returns ErrInvalidCredentials (SEC-004).
//
// The whole attempt runs in one transaction holding the account's row lock (see
// lockAccount), including the Argon2 verification: attempts on one account are
// serialized, attempts on different accounts are not. Every attempt, for a known,
// unknown or blocked account, first waits for a credential slot.
func (s *Service) Login(ctx context.Context, username, password string, m Meta) (LoginResult, error) {
	pw := NormalizePassword(password)
	var (
		res         LoginResult
		failed      bool
		dummyVerify bool
	)
	err := s.withCredentialSlot(ctx, func() error {
		err := s.credentialTx(ctx, func(tx pgx.Tx) error {
			now := s.clock.Now().UTC()
			a, found, err := lockAccount(ctx, tx, lockAccountByNameSQL, username)
			if err != nil {
				return err
			}
			if !found || a.hash == nil {
				failed, dummyVerify = true, true
				return s.auditFailure(ctx, tx, audit.Actor{Type: audit.ActorUser, Name: unknownUserName, IP: m.IP, RequestID: m.RequestID}, "auth.login", "", "unknown_user")
			}
			actor := userActor(a.id, a.name, m)
			if a.blocked(now) {
				// Not counted and the password is not checked; the dummy run after the
				// transaction keeps the timing identical without holding the lock.
				failed, dummyVerify = true, true
				return s.auditFailure(ctx, tx, actor, "auth.login", a.id.String(), "locked")
			}
			ok, rehash, err := s.hasher.Verify(ctx, *a.hash, pw)
			if err != nil {
				return err
			}
			if !ok {
				failed = true
				return s.recordFailure(ctx, tx, actor, a.id, "auth.login", "bad_password")
			}
			if a.disabled {
				failed = true
				return s.auditFailure(ctx, tx, actor, "auth.login", a.id.String(), "disabled")
			}
			if rehash {
				newHash, err := s.hasher.Hash(ctx, pw)
				if err != nil {
					return err
				}
				if _, err := tx.Exec(ctx, "UPDATE users SET password_hash = $2, updated_at = $3 WHERE id = $1", a.id, newHash, now); err != nil {
					return fmt.Errorf("upgrade password hash: %w", err)
				}
			}
			token, err := s.insertSession(ctx, tx, newSession{userID: a.id, kind: "pending", createdAt: now, expiresAt: now.Add(PendingLifetime)}, m)
			if err != nil {
				return err
			}
			res = LoginResult{Status: StatusMFARequired, SessionToken: token}
			if !a.enrolled {
				res.Status = StatusMFAEnrollmentRequired
			}
			return nil
		})
		if dummyVerify {
			s.hasher.DummyVerify(ctx, pw) // SEC-004: unknown and blocked accounts cost the same as a real check
		}
		return err
	})
	if err != nil {
		return LoginResult{}, err
	}
	if failed {
		return LoginResult{}, ErrInvalidCredentials
	}
	return res, nil
}
