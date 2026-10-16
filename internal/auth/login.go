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
	"alice/internal/platform/validate"
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
	// source is users.auth_source. An SSO user (AuthOIDC) has no password and no TOTP and is never counted (C10); a
	// directory user (AuthLDAP) has no password but Alice's TOTP, counted like a local user's.
	source string
}

// passwordRefusal is the refusal of a password operation (change, TOTP step-up) on an account without an Alice
// password: ErrSSOUser for an SSO user, ErrDirectoryUser for a directory user, nil for a local user.
func (a account) passwordRefusal() error {
	return sourceRefusal(a.source)
}

// blocked reports whether the account is in a progressive delay or locked out at now.
func (a account) blocked(now time.Time) bool {
	return a.lockedUntil != nil && now.Before(*a.lockedUntil)
}

// Account lock queries; both select the same columns for lockAccount.
const (
	lockAccountByNameSQL = `SELECT u.id, u.username::text, u.password_hash, u.disabled_at IS NOT NULL, u.locked_until,
EXISTS (SELECT 1 FROM user_mfa m WHERE m.user_id = u.id AND m.enrolled_at IS NOT NULL), u.auth_source
FROM users u WHERE u.username = $1 AND u.auth_source = 'local' FOR UPDATE OF u`
	lockAccountByIDSQL = `SELECT u.id, u.username::text, u.password_hash, u.disabled_at IS NOT NULL, u.locked_until,
EXISTS (SELECT 1 FROM user_mfa m WHERE m.user_id = u.id AND m.enrolled_at IS NOT NULL), u.auth_source
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
		&a.id, &a.name, &a.hash, &a.disabled, &a.lockedUntil, &a.enrolled, &a.source)
	if err == nil || errors.Is(err, pgx.ErrNoRows) {
		if rerr := endLockWaitLimit(ctx, tx); rerr != nil {
			return account{}, false, rerr
		}
	}
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

// endLockWaitLimit lifts the lock_timeout set by credentialTx once the account lock is
// held. The timeout only bounds waiting for the account; later waits (the audit chain
// lock above all) must not abort a transaction that has already evaluated a credential,
// or a guess would be checked but not counted, and its outcome would show.
func endLockWaitLimit(ctx context.Context, tx pgx.Tx) error {
	if _, err := tx.Exec(ctx, "SELECT set_config('lock_timeout', '0', true)"); err != nil {
		return fmt.Errorf("reset lock timeout: %w", err)
	}
	return nil
}

// lockLoginName takes a transaction advisory lock on the typed username, folded to
// lower case in SQL like citext. Every Login takes it first, whether or not the account
// exists, so guesses against unknown names queue exactly like guesses against real ones
// and throughput does not reveal which names exist.
func lockLoginName(ctx context.Context, tx pgx.Tx, username string) error {
	if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1, hashtext(lower($2::text)))", loginNameLockNamespace, username); err != nil {
		return fmt.Errorf("lock login name: %w", err)
	}
	return nil
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
// A failure after a lockout has ended starts a new count at 1 (AUTH-1): the lockout caps
// guessing at LockThreshold evaluated guesses per LockDuration and is never permanent.
// The reset is part of the same UPDATE, so it is atomic under the row lock; a failure
// during a block never gets here (blocked answers locked first).
// The audit rows are appended last, after the row locks, so the chain lock is never
// held while waiting for a user row.
func (s *Service) recordFailure(ctx context.Context, tx pgx.Tx, actor audit.Actor, userID uuid.UUID, action, reason string) error {
	now := s.clock.Now().UTC()
	var n int
	if err := tx.QueryRow(ctx, `UPDATE users SET failed_logins = CASE
WHEN locked_until IS NOT NULL AND locked_until <= $2 AND failed_logins >= $3 THEN 1 ELSE failed_logins + 1 END,
updated_at = $2 WHERE id = $1 RETURNING failed_logins`,
		userID, now, LockThreshold).Scan(&n); err != nil {
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
		if err := s.notifyLockout(ctx, tx, userID, n); err != nil {
			return err
		}
	}
	return nil
}

// notifyLockout queues the lockout e-mail to the Administrators in the lockout's own
// transaction (SEC-020, R42 row 25): it is sent exactly when the lockout commits.
func (s *Service) notifyLockout(ctx context.Context, tx pgx.Tx, userID uuid.UUID, failures int) error {
	if s.notifier == nil {
		return nil
	}
	var username string
	if err := tx.QueryRow(ctx, "SELECT username::text FROM users WHERE id = $1", userID).Scan(&username); err != nil {
		return fmt.Errorf("read locked user: %w", err)
	}
	if err := s.notifier.NotifyAdmins(ctx, tx, TemplateLockout, map[string]string{"username": username,
		"minutes": strconv.Itoa(int(LockDuration / time.Minute)), "failed_logins": strconv.Itoa(failures)}); err != nil {
		return fmt.Errorf("queue lockout e-mail: %w", err)
	}
	return nil
}

// auditFailure writes a failure event without touching the counters.
func (s *Service) auditFailure(ctx context.Context, tx pgx.Tx, actor audit.Actor, action, objectID, reason string) error {
	_, err := s.audit.Append(ctx, tx, audit.Event{Actor: actor, Action: action, ObjectType: "user", ObjectID: objectID,
		Result: audit.Failure, Details: map[string]string{"reason": reason}})
	return err
}

// unstorableLoginName stands in for a typed name PostgreSQL cannot store (AUD-13). It is outside
// the username grammar (usernameRE), so no account can ever match it.
const unstorableLoginName = "\uFFFD"

// loginNameLockNamespace is the first key of the per-name advisory lock Login takes
// (pg_advisory_xact_lock(int4, int4)); the two-key form is a separate key space from
// the audit chain's single bigint key.
const loginNameLockNamespace int32 = 0x616c6331 // "alc1"

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

// credentialTx runs fn in a transaction whose wait for the login-name and account locks
// ends after s.lockTimeout; lockAccount lifts the limit as soon as the account lock is
// held, before any credential is evaluated. A lock timeout therefore rolls back an
// attempt that verified and counted nothing, and becomes ErrTryAgain. fn must start with
// lockAccount (Login: lockLoginName, then lockAccount). Callers hold a credential slot.
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
// Every attempt, for a known, unknown or blocked account, runs the same steps in the
// same order: wait for a credential slot; in one transaction take the per-name lock
// (lockLoginName), look the account up under its row lock (lockAccount), run exactly one
// Argon2 check (Verify for a real account, DummyVerify for an unknown or blocked one) and
// append the audit row. The Argon2 check always runs while the name lock is held, so
// attempts on one name are serialized whether or not the name exists, and parallel
// requests cannot tell the two apart by how they overlap (SEC-004, AUD-11). Attempts on
// different names are not serialized.
func (s *Service) Login(ctx context.Context, username, password string, m Meta) (LoginResult, error) {
	if !validate.StorableText(username) {
		// AUD-13: PostgreSQL cannot hold this name (NUL or invalid UTF-8), so it never reaches a
		// query; no account can have it, so it is an unknown user, with the same work and audit row.
		// The HTTP layer refuses such a body before calling Login; this covers every other caller.
		username = unstorableLoginName
	}
	pw := NormalizePassword(password)
	var (
		res    LoginResult
		failed bool
	)
	err := s.withCredentialSlot(ctx, func() error {
		return s.credentialTx(ctx, func(tx pgx.Tx) error {
			if err := lockLoginName(ctx, tx, username); err != nil {
				return err
			}
			now := s.clock.Now().UTC()
			a, found, err := lockAccount(ctx, tx, lockAccountByNameSQL, username)
			if err != nil {
				return err
			}
			if !found || a.hash == nil {
				// SEC-004, AUD-11: the dummy check runs here, under the name lock, where a real
				// account's check runs, so an unknown name queues exactly like a real one.
				failed = true
				s.hasher.DummyVerify(ctx, pw)
				return s.auditFailure(ctx, tx, audit.Actor{Type: audit.ActorUser, Name: unknownUserName, IP: m.IP, RequestID: m.RequestID}, "auth.login", "", "unknown_user")
			}
			actor := userActor(a.id, a.name, m)
			if a.blocked(now) {
				// Not counted and the password is not checked; the dummy check under the same
				// locks keeps the timing of a real check (AUD-11).
				failed = true
				s.hasher.DummyVerify(ctx, pw)
				return s.auditFailure(ctx, tx, actor, "auth.login", a.id.String(), "locked")
			}
			ok, rehash, err := s.checkSecret(ctx, s.hasher, "password", a.id, *a.hash, pw)
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
	})
	if err != nil {
		return LoginResult{}, err
	}
	if failed {
		return LoginResult{}, ErrInvalidCredentials
	}
	return res, nil
}
