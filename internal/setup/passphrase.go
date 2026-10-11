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
	"alice/internal/rbac"
	"alice/internal/secrets"
)

// passphraseLock serializes concurrent attempts to set the recovery passphrase.
const passphraseLock int64 = 7160927315633811301

// keyBackupSender is the setting secret that holds the installation's backup sender private key (R43 row 41).
const keyBackupSender = "backup.sender"

// authorize repeats the route's settings.manage check (Administrator browser session with a
// fresh step-up) in the service: the passphrase can be set only once and never reset, so a
// routing mistake must not let anyone else set it.
func (s *Service) authorize(p auth.Principal) error {
	if rbac.Decide(rbac.SettingsManage, p.Subject(s.clock.Now())) != rbac.Allow {
		return ErrForbidden
	}
	return nil
}

// SetRecoveryPassphrase generates the X25519 backup key pair and stores the private key
// wrapped by the passphrase (R4, SEC-048). Neither the passphrase nor a key derived from it
// is stored. In the same transaction it stores the installation's backup sender key as the
// master-key envelope backup.sender (R43 row 41). The passphrase can be set only once.
func (s *Service) SetRecoveryPassphrase(ctx context.Context, p auth.Principal, m auth.Meta, passphrase, confirm string) error {
	if err := s.authorize(p); err != nil {
		return err
	}
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
	case PassphraseStrength(passphrase) == StrengthFair:
		// Rated on the typed text, as the browser's meter rates it; refused before any key is generated, so
		// neither backup.key nor backup.sender exists afterwards.
		return ErrPassphraseTooWeak
	}
	if set, err := hasSetting(ctx, s.pool, keyBackupKey); err != nil {
		return err
	} else if set {
		return ErrPassphraseAlreadySet
	}
	wrapped, sender, err := secrets.NewBackupKey([]byte(pass), s.kdf)
	if err != nil {
		return err
	}
	senderKey := sender.Bytes()
	defer clear(senderKey) // best effort (R43 row 53): ecdh keeps its own copy
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
		now := s.clock.Now().UTC()
		if err := settings.Set(ctx, tx, keyBackupKey, wrapped, now); err != nil {
			return err
		}
		if err := s.keyring.PutSetting(ctx, tx, keyBackupSender, secrets.NewPlaintext(senderKey), now); err != nil {
			return err
		}
		_, err = s.audit.Append(ctx, tx, audit.Event{Actor: p.Actor(m), Action: "setup.recovery_passphrase_set", ObjectType: "setting",
			ObjectID: keyBackupKey, Result: audit.Success})
		return err
	})
}

// Complete finishes the wizard. It requires the recovery passphrase and a license choice and is idempotent.
func (s *Service) Complete(ctx context.Context, p auth.Principal, m auth.Meta) (Status, error) {
	if err := s.authorize(p); err != nil {
		return Status{}, err
	}
	err := db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1)", passphraseLock); err != nil {
			return err
		}
		// An install that already finished (also under Phase 1, before the license step)
		// stays finished and answers as before.
		done, err := hasSetting(ctx, tx, keyCompletedAt)
		if err != nil || done {
			return err
		}
		set, err := hasSetting(ctx, tx, keyBackupKey)
		if err != nil {
			return err
		}
		if !set {
			return ErrIncomplete
		}
		chosen, err := s.licenseChosen(ctx, tx)
		if err != nil {
			return err
		}
		if !chosen {
			return ErrLicenseChoiceMissing
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
