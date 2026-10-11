// Package setup implements the first-run wizard: the one-time setup code, the wizard
// session, creation of the first administrator and the recovery passphrase (spec §18.5).
package setup

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"alice/internal/audit"
	"alice/internal/auth"
	"alice/internal/auth/ratelimit"
	"alice/internal/notify"
	"alice/internal/platform/clock"
	"alice/internal/platform/db"
	"alice/internal/platform/settings"
	"alice/internal/secrets"
)

// Errors returned by the setup service.
var (
	ErrAlreadySetUp         = errors.New("setup: an administrator already exists")
	ErrCodeInvalid          = errors.New("setup: setup code invalid")
	ErrSessionInvalid       = errors.New("setup: setup session missing or expired")
	ErrEnrollmentMissing    = errors.New("setup: start the administrator enrollment first")
	ErrPassphraseTooShort   = errors.New("setup: recovery passphrase too short")
	ErrPassphraseMismatch   = errors.New("setup: recovery passphrases differ")
	ErrPassphraseAlreadySet = errors.New("setup: recovery passphrase already set")
	ErrIncomplete           = errors.New("setup: recovery passphrase not set yet")
	// ErrLicenseChoiceMissing means Finish was asked before the license step was done.
	ErrLicenseChoiceMissing = errors.New("setup: choose a license option first")
	// ErrPassphraseTooWeak means the recovery passphrase rates "fair" (PassphraseStrength); ALC-SET-0010.
	ErrPassphraseTooWeak = errors.New("setup: the recovery passphrase is too easy to guess")
	// ErrForbidden means the caller is not an administrator's browser session inside its
	// step-up window (permission settings.manage).
	ErrForbidden = errors.New("setup: not allowed")
)

// LockedError means too many wrong setup codes came from this address.
type LockedError struct{ RetryAfter time.Duration }

func (e *LockedError) Error() string {
	return fmt.Sprintf("setup: too many wrong setup codes; try again in %s", e.RetryAfter.Round(time.Second))
}

// Limits (spec §18.5, SEC-086).
const (
	MinPassphraseLength = 16
	MaxPassphraseLength = 1024
	SessionIdle         = 60 * time.Minute
	MaxCodeFailures     = 5
	CodeLockDuration    = 15 * time.Minute
)

// Settings keys owned by setup.
const (
	keyTokenHash   = "setup.token_hash"
	keyLocale      = "locale.default"
	keyBackupKey   = "backup.key"
	keyCompletedAt = "setup.completed_at"

	keyLicenseChoice = "setup.license_choice"
	keyHTTPSChoice   = "setup.https_choice" // "uploaded" or "temporary"
	keyMailChoice    = "setup.mail_choice"  // "configured" or "skipped"
)

// LicenseState tells the wizard whether a license file was installed (license.Service). It
// reads through q, so a caller's transaction covers the answer.
type LicenseState interface {
	Installed(ctx context.Context, q db.Querier) (bool, error)
}

// Config holds the service dependencies.
type Config struct {
	Pool      *pgxpool.Pool
	Auth      *auth.Service
	Keyring   *secrets.Keyring
	Audit     *audit.Log
	Clock     clock.Clock
	Hasher    *auth.Hasher
	BackupKDF secrets.KDFParams // zero value means secrets.BackupKDF
	License   LicenseState      // nil: no license can be installed; the evaluation choice still completes the step
	Mail      MailSettings      // nil: mail counts as chosen only when it was skipped
}

// MailSettings tells the wizard whether a mail server is configured (notify.Settings).
type MailSettings interface {
	SMTP(ctx context.Context) (notify.SMTPSettings, bool, error)
}

// Service is the setup wizard backend.
type Service struct {
	pool    *pgxpool.Pool
	auth    *auth.Service
	keyring *secrets.Keyring
	audit   *audit.Log
	clock   clock.Clock
	hasher  *auth.Hasher
	kdf     secrets.KDFParams
	license LicenseState
	mail    MailSettings
	lockout *ratelimit.Lockout

	// codeMu makes "is this address locked, compare the code, count the failure" one step,
	// so parallel wrong codes from one address cannot all pass the lock check.
	codeMu sync.Mutex

	// Tests only (AUD-21): beforeBootstrap runs between the wizard-session check and the
	// administrator's creation, inBootstrapTx inside that transaction once it holds the users
	// lock and has consumed its session, afterCodeCheck inside StartSession's transaction after
	// the code matched (the setup code's row is locked then).
	beforeBootstrap, inBootstrapTx, afterCodeCheck, afterCodeRead func()
}

// New builds the service.
func New(c Config) *Service {
	kdf := c.BackupKDF
	if kdf == (secrets.KDFParams{}) {
		kdf = secrets.BackupKDF
	}
	return &Service{
		pool: c.Pool, auth: c.Auth, keyring: c.Keyring, audit: c.Audit, clock: c.Clock, hasher: c.Hasher, kdf: kdf, license: c.License, mail: c.Mail,
		lockout: ratelimit.NewLockout(c.Clock, MaxCodeFailures, CodeLockDuration, CodeLockDuration),
	}
}

// Status is what the wizard and the "finish setting up" banner need. NextStep is derived from the stored state
// (R43 row 16; position.go).
type Status struct {
	AdminExists           bool
	RecoveryPassphraseSet bool
	LicenseChosen         bool
	Completed             bool
	DefaultLocale         string
	HTTPSChosen           bool   // an uploaded certificate, or the temporary one kept
	MailChosen            bool   // mail settings exist, or the step was skipped
	NextStep              string // "", "passphrase", "https", "mail", "license", "platform" or "done"
}

func adminExists(ctx context.Context, q db.Querier) (bool, error) {
	var exists bool
	if err := q.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM users)").Scan(&exists); err != nil {
		return false, fmt.Errorf("check users: %w", err)
	}
	return exists, nil
}

func hasSetting(ctx context.Context, q db.Querier, key string) (bool, error) {
	var raw any
	return settings.Get(ctx, q, key, &raw)
}

// Status reports the setup progress.
func (s *Service) Status(ctx context.Context) (Status, error) {
	var st Status
	var err error
	if st.AdminExists, err = adminExists(ctx, s.pool); err != nil {
		return Status{}, err
	}
	if st.RecoveryPassphraseSet, err = hasSetting(ctx, s.pool, keyBackupKey); err != nil {
		return Status{}, err
	}
	if st.LicenseChosen, err = s.licenseChosen(ctx, s.pool); err != nil {
		return Status{}, err
	}
	if st.Completed, err = hasSetting(ctx, s.pool, keyCompletedAt); err != nil {
		return Status{}, err
	}
	if st.HTTPSChosen, err = hasSetting(ctx, s.pool, keyHTTPSChoice); err != nil {
		return Status{}, err
	}
	if st.MailChosen, err = s.mailChosen(ctx); err != nil {
		return Status{}, err
	}
	st.DefaultLocale = "en"
	var locale string
	found, err := settings.Get(ctx, s.pool, keyLocale, &locale)
	if err != nil {
		return Status{}, err
	}
	if found && locale != "" {
		st.DefaultLocale = locale
	}
	st.NextStep = nextStep(st)
	return st, nil
}

// ResetLockouts clears the wrong-code counters (used by the e2e reset endpoint only).
func (s *Service) ResetLockouts() { s.lockout.Reset() }
