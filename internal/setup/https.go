package setup

import (
	"context"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"

	"alice/internal/audit"
	"alice/internal/auth"
	"alice/internal/platform/db"
	"alice/internal/platform/settings"
	"alice/internal/platform/tlscert"
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

// CertificateInstaller is the HTTPS certificate of the API (C11) for cmd/alice and the API's integration stack alike:
// the store serves and installs the pair; once it is in use, the wizard's HTTPS choice (setup.https_choice =
// uploaded) and the https.certificate_replaced row (subject, not_after, fingerprint; never the key) are recorded in
// one transaction.
//
// The pair is live before that transaction (a file swap is not part of a database transaction). If the transaction
// fails, it is retried once without the request's cancellation (a browser that went away must not leave the
// replacement unaudited); if the retry fails too, the error is logged with the fixed labels event=https.audit_failed
// and the fingerprint, and the caller gets the error while the new certificate stays in use.
type CertificateInstaller struct {
	Store *tlscert.Store
	Setup *Service
	Log   *slog.Logger
}

// Info is the certificate in use.
func (c CertificateInstaller) Info() tlscert.Info { return c.Store.Info() }

// Install checks the caller (settings.manage) before the pair is touched, installs it, then records the choice and
// the audit row (see CertificateInstaller).
func (c CertificateInstaller) Install(ctx context.Context, p auth.Principal, m auth.Meta, u tlscert.Upload) (tlscert.Info, error) {
	if err := c.Setup.authorize(p); err != nil {
		return tlscert.Info{}, err
	}
	info, err := c.Store.Install(u)
	if err != nil {
		return tlscert.Info{}, err
	}
	if err = c.Setup.recordCertificate(ctx, p, m, info); err != nil {
		c.Log.Warn("the HTTPS certificate is in use; recording it failed and is retried", "event", "https.audit_retry",
			"fingerprint", info.FingerprintSHA256)
		err = c.Setup.recordCertificate(context.WithoutCancel(ctx), p, m, info)
	}
	if err != nil {
		c.Log.Error("the HTTPS certificate is in use but its audit row could not be written", "event", "https.audit_failed",
			"fingerprint", info.FingerprintSHA256)
		return tlscert.Info{}, err
	}
	return info, nil
}

// recordCertificate stores setup.https_choice = uploaded and appends https.certificate_replaced in one transaction.
func (s *Service) recordCertificate(ctx context.Context, p auth.Principal, m auth.Meta, info tlscert.Info) error {
	return db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		if err := settings.Set(ctx, tx, keyHTTPSChoice, httpsUploaded, s.clock.Now()); err != nil {
			return err
		}
		_, err := s.audit.Append(ctx, tx, audit.Event{Actor: p.Actor(m), Action: "https.certificate_replaced", ObjectType: "certificate",
			ObjectID: "https", Result: audit.Success, Details: map[string]string{"subject": info.Subject,
				"not_after": info.NotAfter.UTC().Format(time.RFC3339), "fingerprint": info.FingerprintSHA256}})
		return err
	})
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
