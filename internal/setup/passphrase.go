package setup

import (
	"context"
	"strconv"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"golang.org/x/text/unicode/norm"

	"alice/internal/audit"
	"alice/internal/auth"
	"alice/internal/platform/db"
	"alice/internal/platform/settings"
	"alice/internal/platform/validate"
	"alice/internal/secrets"
)

// passphraseLock serializes concurrent attempts to set the recovery passphrase.
const passphraseLock int64 = 7160927315633811301

// SetRecoveryPassphrase generates the X25519 backup key pair and stores the private key
// wrapped by the passphrase (R4, SEC-048). Neither the passphrase nor a key derived from it
// is stored. The passphrase can be set only once.
func (s *Service) SetRecoveryPassphrase(ctx context.Context, p auth.Principal, m auth.Meta, passphrase, confirm string) error {
	pass := norm.NFKC.String(passphrase)
	n := utf8.RuneCountInString(pass)
	switch {
	case n < MinPassphraseLength:
		return ErrPassphraseTooShort
	case n > MaxPassphraseLength:
		var v validate.Errors
		v.Add("passphrase", validate.TooLong, map[string]string{"max": strconv.Itoa(MaxPassphraseLength)})
		return v
	case pass != norm.NFKC.String(confirm):
		return ErrPassphraseMismatch
	}
	if set, err := hasSetting(ctx, s.pool, keyBackupKey); err != nil {
		return err
	} else if set {
		return ErrPassphraseAlreadySet
	}
	wrapped, err := secrets.NewBackupKey([]byte(pass), s.kdf)
	if err != nil {
		return err
	}
	return db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1)", passphraseLock); err != nil {
			return err
		}
		set, err := hasSetting(ctx, tx, keyBackupKey)
		if err != nil {
			return err
		}
		if set {
			return ErrPassphraseAlreadySet
		}
		if err := settings.Set(ctx, tx, keyBackupKey, wrapped, s.clock.Now().UTC()); err != nil {
			return err
		}
		_, err = s.audit.Append(ctx, tx, audit.Event{Actor: p.Actor(m), Action: "setup.recovery_passphrase_set", ObjectType: "setting",
			ObjectID: keyBackupKey, Result: audit.Success})
		return err
	})
}

// Complete finishes the wizard. It requires the recovery passphrase and is idempotent.
func (s *Service) Complete(ctx context.Context, p auth.Principal, m auth.Meta) (Status, error) {
	err := db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1)", passphraseLock); err != nil {
			return err
		}
		set, err := hasSetting(ctx, tx, keyBackupKey)
		if err != nil {
			return err
		}
		if !set {
			return ErrIncomplete
		}
		done, err := hasSetting(ctx, tx, keyCompletedAt)
		if err != nil || done {
			return err
		}
		now := s.clock.Now().UTC()
		if err := settings.Set(ctx, tx, keyCompletedAt, now.Format(time.RFC3339), now); err != nil {
			return err
		}
		_, err = s.audit.Append(ctx, tx, audit.Event{Actor: p.Actor(m), Action: "setup.completed", ObjectType: "setting",
			ObjectID: keyCompletedAt, Result: audit.Success})
		return err
	})
	if err != nil {
		return Status{}, err
	}
	return s.Status(ctx)
}
