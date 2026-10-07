package notify

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"alice/internal/audit"
	"alice/internal/platform/db"
	"alice/internal/platform/settings"
	"alice/internal/platform/validate"
)

// TestMail sends the test e-mail through the stored settings. It returns nil, a *CertError (the certificate was not
// trusted: it is remembered for SeenCertValidFor so that Trust can pin it) or a classified Err* sentinel — never the
// server's text. Every call is audited.
func (s *Settings) TestMail(ctx context.Context, a audit.Actor, to, locale string) error {
	if !validAddress(to) {
		return validate.Errors{{Field: "to", Code: validate.Email}}
	}
	rec, ok, err := s.load(ctx, s.pool)
	if err != nil {
		return err
	}
	if !ok {
		return ErrNotConfigured
	}
	cfg, release, err := s.config(ctx, s.pool, rec)
	defer release()
	if err != nil {
		return err
	}
	m, err := NewSMTPMailer(cfg, s.clock)
	if err != nil {
		return fmt.Errorf("notify: the stored mail settings are not usable: %w", err)
	}
	sendCtx, cancel := context.WithTimeout(ctx, TestMailTimeout)
	sendErr := m.Send(sendCtx, (&Sender{Catalog: s.catalog}).Render(to, TemplateTestMail, locale, nil))
	cancel()

	var ce *CertError
	isCert := errors.As(sendErr, &ce)
	details := map[string]string{"to": to, "result": "sent"}
	if sendErr != nil {
		details["result"], details["reason"] = "failed", ErrorCode(sendErr)
	}
	if isCert {
		details["fingerprint"] = ce.Cert.Fingerprint
	}
	err = db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		if isCert {
			now := s.clock.Now().UTC()
			if err := settings.Set(ctx, tx, seenKey, seenRecord{Fingerprint: ce.Cert.Fingerprint, Subject: ce.Cert.Subject,
				NotAfter: ce.Cert.NotAfter, SeenAt: now, Host: rec.Host, Port: rec.Port}, now); err != nil {
				return err
			}
		}
		return s.record(ctx, tx, audit.Event{Actor: a, Action: "settings.smtp_tested", Details: details})
	})
	if err != nil {
		return err
	}
	return sendErr
}

// Trust pins the certificate a failed test saw on the configured host and port within SeenCertValidFor (F-62, S-6).
func (s *Settings) Trust(ctx context.Context, a audit.Actor, version int, fingerprint string) (SMTPSettings, error) {
	if !fingerprintPattern.MatchString(fingerprint) {
		return SMTPSettings{}, validate.Errors{{Field: "fingerprint", Code: validate.Pattern}}
	}
	var out SMTPSettings
	err := s.mutate(ctx, version, func(tx pgx.Tx, rec smtpRecord, exists bool) error {
		if !exists {
			return ErrNotConfigured
		}
		var seen seenRecord
		found, err := settings.Get(ctx, tx, seenKey, &seen)
		if err != nil {
			return err
		}
		now := s.clock.Now().UTC()
		if !found || seen.Fingerprint != fingerprint || seen.Host != rec.Host || seen.Port != rec.Port ||
			now.Sub(seen.SeenAt) > SeenCertValidFor {
			return ErrCertNotSeen
		}
		rec.Trusted = &trustedRecord{Fingerprint: seen.Fingerprint, Subject: seen.Subject, NotAfter: seen.NotAfter,
			TrustedBy: a.Name, TrustedAt: now}
		rec.Version++
		rec.UpdatedAt = now
		if err := settings.Set(ctx, tx, smtpKey, rec, now); err != nil {
			return err
		}
		if err := settings.Delete(ctx, tx, seenKey); err != nil {
			return err
		}
		if out, err = s.view(ctx, tx, rec); err != nil {
			return err
		}
		return s.record(ctx, tx, audit.Event{Actor: a, Action: "settings.smtp_trusted",
			Details: map[string]string{"fingerprint": seen.Fingerprint, "subject": seen.Subject}})
	})
	return out, err
}

// Untrust drops the pin.
func (s *Settings) Untrust(ctx context.Context, a audit.Actor, version int) (SMTPSettings, error) {
	var out SMTPSettings
	err := s.mutate(ctx, version, func(tx pgx.Tx, rec smtpRecord, exists bool) error {
		if !exists {
			return ErrNotConfigured
		}
		details := map[string]string{}
		if rec.Trusted != nil {
			details["fingerprint"], details["subject"] = rec.Trusted.Fingerprint, rec.Trusted.Subject
		}
		now := s.clock.Now().UTC()
		rec.Trusted, rec.UpdatedAt = nil, now
		rec.Version++
		if err := settings.Set(ctx, tx, smtpKey, rec, now); err != nil {
			return err
		}
		var err error
		if out, err = s.view(ctx, tx, rec); err != nil {
			return err
		}
		return s.record(ctx, tx, audit.Event{Actor: a, Action: "settings.smtp_untrusted", Details: details})
	})
	return out, err
}
