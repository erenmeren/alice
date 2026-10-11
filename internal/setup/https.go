package setup

import (
	"context"

	"github.com/jackc/pgx/v5"

	"alice/internal/audit"
	"alice/internal/auth"
	"alice/internal/platform/db"
	"alice/internal/platform/settings"
)

// Values of setup.https_choice and setup.mail_choice.
const (
	httpsUploaded  = "uploaded"
	httpsTemporary = "temporary"
	mailSkipped    = "skipped"
)

// KeepTemporaryCertificate finishes the HTTPS step with Alice's temporary certificate (setup.https_choice =
// temporary, audited setup.https_kept_temporary). It is idempotent, and after the wizard finished it changes
// nothing and returns the status (S-39): the Settings page replaces the certificate instead.
func (s *Service) KeepTemporaryCertificate(ctx context.Context, p auth.Principal, m auth.Meta) (Status, error) {
	return s.choose(ctx, p, m, keyHTTPSChoice, httpsTemporary, "setup.https_kept_temporary")
}

// RecordCertificateUploaded records, inside the caller's transaction, that a certificate was uploaded
// (setup.https_choice = uploaded). The API calls it after tlscert.Store.Install and audits the replacement itself.
func (s *Service) RecordCertificateUploaded(ctx context.Context, tx pgx.Tx, p auth.Principal) error {
	if err := s.authorize(p); err != nil {
		return err
	}
	return settings.Set(ctx, tx, keyHTTPSChoice, httpsUploaded, s.clock.Now())
}

// choose stores a wizard choice once, with its audit row, unless the wizard finished or the step was done.
func (s *Service) choose(ctx context.Context, p auth.Principal, m auth.Meta, key, value, action string) (Status, error) {
	if err := s.authorize(p); err != nil {
		return Status{}, err
	}
	err := db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1)", passphraseLock); err != nil {
			return err
		}
		for _, k := range []string{keyCompletedAt, key} {
			if done, err := hasSetting(ctx, tx, k); err != nil || done {
				return err
			}
		}
		now := s.clock.Now().UTC()
		if err := settings.Set(ctx, tx, key, value, now); err != nil {
			return err
		}
		_, err := s.audit.Append(ctx, tx, audit.Event{Actor: p.Actor(m), Action: action, ObjectType: "setting", ObjectID: key,
			Result: audit.Success, Details: map[string]string{"choice": value}})
		return err
	})
	if err != nil {
		return Status{}, err
	}
	return s.Status(ctx)
}
