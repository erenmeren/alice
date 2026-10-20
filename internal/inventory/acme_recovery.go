package inventory

// Expiry-aware notices of failing ACME renewals and the delivery of the renewal e-mails (owner decision 2026-10-20;
// docs/superpowers/rulings/acme-renewal-recovery.md).
//
// While the renewal of an issued certificate with automatic renewal on fails (failures > 0: failing, stopped, or an
// order running in such a series), the Administrators are e-mailed again when its current certificate reaches 14, 7, 3
// and 1 days before its end (renew.ExpiryNoticeDays), with the time left and the class and reason of the last failure.
// Each threshold goes once per certificate and expiry instant: the row in the alerts ledger (kind acme_renewal_expiry,
// unique per kind, object, expiry instant and threshold) is inserted in the transaction that queues the e-mail, and,
// as for the other expiry notices (alerts/expiry.Due), only the most urgent reached threshold is ever due (after a
// downtime the skipped, less urgent ones are not sent). A renewal that succeeds gives a new expiry instant, so a later
// series starts afresh. The notices go from the renewal planner, so they stop with it (in lock after the continuity
// window, where the general expiry notices of the certificate still go).
//
// A CA wait that leaves less than half of the renewal window (R47, renew.CAWaitCritical) is told at once, when the
// failure that carries it is counted (acmeCAWaitNotice: ledger kind acme_renewal_ca_wait, once per wait).

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"alice/internal/acme/renew"
	"alice/internal/alerts/expiry"
	"alice/internal/platform/db"
)

const (
	// acmeExpiryKind is the ledger kind of the notices (migration 00020).
	acmeExpiryKind = "acme_renewal_expiry"
	// acmeCAWaitKind is the ledger kind of the notices of a critical CA wait (migration 00022).
	acmeCAWaitKind = "acme_renewal_ca_wait"
	// acmeExpiryRead bounds the certificates one run looks at; acmeExpiryPerRun the notices it queues.
	acmeExpiryRead   = 200
	acmeExpiryPerRun = 20
)

// acmeExpiryNotices queues the due "expires soon while its renewal fails" e-mails (see the file comment), at most
// acmeExpiryPerRun per run, most urgent first; the rest go at the next run. One certificate that cannot be recorded is
// skipped and its error returned with the others'.
func (s *Service) acmeExpiryNotices(ctx context.Context, run *ACMERenewRun) error {
	days := renew.ExpiryNoticeDays()
	now := s.clock.Now().UTC()
	rows, err := s.pool.Query(ctx, `SELECT c.id, x.not_after,
    ARRAY(SELECT a.threshold_days FROM alerts a WHERE a.kind = $4 AND a.object_id = c.id AND a.expires_at = x.not_after)
FROM acme_certificates c JOIN certificates x ON x.id = c.current_certificate_id
WHERE c.deleted_at IS NULL AND c.auto_renew AND c.failures > 0 AND x.not_after > $1 AND x.not_after <= $2
ORDER BY x.not_after, c.id LIMIT $3`, now, now.Add(time.Duration(days[0])*24*time.Hour), acmeExpiryRead, acmeExpiryKind)
	if err != nil {
		return fmt.Errorf("inventory: find the failing ACME renewals near their expiry: %w", err)
	}
	type due struct {
		id       uuid.UUID
		notAfter time.Time
		level    int
	}
	var list []due
	for rows.Next() {
		var (
			d    due
			sent []int32
		)
		if err := rows.Scan(&d.id, &d.notAfter, &sent); err != nil {
			rows.Close()
			return fmt.Errorf("inventory: read a failing ACME renewal: %w", err)
		}
		levels := make([]int, len(sent))
		for i, l := range sent {
			levels[i] = int(l)
		}
		if level, ok := expiry.Due(d.notAfter, now, days, levels); ok && level != expiry.Expired {
			d.level = level
			list = append(list, d)
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return fmt.Errorf("inventory: read the failing ACME renewals: %w", err)
	}
	var errs []error
	for _, d := range list {
		if run.Warned >= acmeExpiryPerRun || ctx.Err() != nil {
			break
		}
		queued, err := s.acmeExpiryNotice(ctx, d.id, d.notAfter.UTC(), d.level, now)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if queued {
			run.Warned++
		}
	}
	return errors.Join(errs...)
}

// acmeExpiryNotice records one threshold in the ledger and, only in the transaction that inserted it, queues the e-mail.
// The certificate is read again under its row lock: one that renewed, recovered or was switched off meanwhile gets
// nothing.
func (s *Service) acmeExpiryNotice(ctx context.Context, id uuid.UUID, notAfter time.Time, level int, now time.Time) (bool, error) {
	queued := false
	err := db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		queued = false
		var (
			names           []string
			failures        int
			state, class    string
			code            string
			current         *time.Time
			autoRenew, live bool
		)
		err := tx.QueryRow(ctx, `SELECT c.names, c.failures, c.state, c.last_failure_class, c.last_error_code, x.not_after, c.auto_renew,
    c.deleted_at IS NULL
FROM acme_certificates c LEFT JOIN certificates x ON x.id = c.current_certificate_id WHERE c.id = $1 FOR UPDATE OF c SKIP LOCKED`, id).
			Scan(&names, &failures, &state, &class, &code, &current, &autoRenew, &live)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil // busy: the next run
		}
		if err != nil {
			return fmt.Errorf("inventory: read the ACME certificate: %w", err)
		}
		if !live || !autoRenew || failures == 0 || current == nil || !current.Equal(notAfter) {
			return nil
		}
		subject := "acme certificate"
		if len(names) > 0 {
			subject = truncRunes(names[0], 300)
		}
		var ledger uuid.UUID
		err = tx.QueryRow(ctx, `INSERT INTO alerts (id, kind, object_id, subject, expires_at, threshold_days, license_locked, emailed, created_at)
VALUES ($1, $2, $3, $4, $5, $6, false, $7, $8)
ON CONFLICT (kind, object_id, expires_at, threshold_days) DO NOTHING RETURNING id`, uuid.Must(uuid.NewV7()), acmeExpiryKind, id, subject, notAfter,
			level, s.notifier != nil, now).Scan(&ledger)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil // another planner recorded it
		}
		if err != nil {
			return fmt.Errorf("inventory: record the expiry notice: %w", err)
		}
		if s.notifier == nil {
			return nil
		}
		p := acmeNoticeParams(id, names, failures, code, &notAfter)
		p["days"] = strconv.Itoa(expiry.DaysLeft(notAfter, now))
		if err := s.notifier.NotifyAdmins(ctx, tx, acmeExpiringTemplate(state, class), p); err != nil {
			return fmt.Errorf("inventory: queue the expiry notice: %w", err)
		}
		queued = true
		return nil
	})
	return queued, err
}

// acmeExpiringTemplate is the e-mail for a certificate in state with the last failure's class: stopped for good (a
// person must act), failing for a cause that needs a person (Alice still tries a few times), or an outage (Alice keeps
// trying by itself, also when it stopped before: the recovery).
func acmeExpiringTemplate(state, class string) string {
	switch {
	case class == renew.ClassTransient:
		return TemplateACMERenewalExpiringTransient
	case state == ACMEStateStopped:
		return TemplateACMERenewalExpiringStopped
	}
	return TemplateACMERenewalExpiringPermanent
}

// acmeCAWaitNotice records, in tx, a CA wait of a certificate that leaves less than half of its renewal window
// (renew.CAWaitCritical, R47) in the alerts ledger (kind acmeCAWaitKind, threshold the whole days from the end of the
// wait to notAfter, 0 when the wait outlasts it) and, only when the row is new, queues TemplateACMERenewalCAWait (params
// of acmeNoticeParams, ca_not_before and days: the whole days left now). So each such wait is told once, and a CA that
// asks for a longer wait again is told again. Alice does not order before the CA's time: the e-mail is the warning.
func (s *Service) acmeCAWaitNotice(ctx context.Context, tx pgx.Tx, id uuid.UUID, names []string, failures int, code string, notAfter,
	caNotBefore, now time.Time) error {
	subject := "acme certificate"
	if len(names) > 0 {
		subject = truncRunes(names[0], 300)
	}
	left := min(max(int(notAfter.Sub(caNotBefore)/(24*time.Hour)), 0), 365)
	var ledger uuid.UUID
	err := tx.QueryRow(ctx, `INSERT INTO alerts (id, kind, object_id, subject, expires_at, threshold_days, license_locked, emailed, created_at)
VALUES ($1, $2, $3, $4, $5, $6, false, $7, $8)
ON CONFLICT (kind, object_id, expires_at, threshold_days) DO NOTHING RETURNING id`, uuid.Must(uuid.NewV7()), acmeCAWaitKind, id, subject, notAfter,
		left, s.notifier != nil, now).Scan(&ledger)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil // told already
	}
	if err != nil {
		return fmt.Errorf("inventory: record the CA's wait notice: %w", err)
	}
	if s.notifier == nil {
		return nil
	}
	p := acmeNoticeParams(id, names, failures, code, &notAfter)
	p["ca_not_before"] = caNotBefore.UTC().Format(acmeNoticeTime)
	p["days"] = strconv.Itoa(expiry.DaysLeft(notAfter, now))
	if err := s.notifier.NotifyAdmins(ctx, tx, TemplateACMERenewalCAWait, p); err != nil {
		return fmt.Errorf("inventory: queue the CA's wait notice: %w", err)
	}
	return nil
}

// ACMENoticeDelivery is how the newest renewal e-mail of an ACME certificate was delivered: its template, when it was
// queued, and how many of its copies (one per recipient) were sent, are still being tried, failed for good or were not
// sent because no mail server is set; LastErrorCode is the mail error of a copy that was not sent (” without one).
type ACMENoticeDelivery struct {
	Template      string     `json:"template"`
	QueuedAt      time.Time  `json:"queued_at"`
	Recipients    int        `json:"recipients"`
	Sent          int        `json:"sent"`
	Pending       int        `json:"pending"`
	Failed        int        `json:"failed"`
	Skipped       int        `json:"skipped"`
	SentAt        *time.Time `json:"sent_at,omitempty"`
	LastErrorCode string     `json:"last_error_code"`
}

// ACMENoticeDelivery returns the delivery of the newest renewal e-mail of a live ACME certificate (nil when none was
// queued). ErrNotFound.
func (s *Service) ACMENoticeDelivery(ctx context.Context, id uuid.UUID) (*ACMENoticeDelivery, error) {
	if _, err := getACMECert(ctx, s.pool, id, false); err != nil {
		return nil, err
	}
	var d ACMENoticeDelivery
	err := s.pool.QueryRow(ctx, `WITH last AS (
    SELECT created_at, template_key FROM notifications_outbox
    WHERE params ? 'acme_certificate_id' AND params->>'acme_certificate_id' = $1 ORDER BY created_at DESC LIMIT 1
)
SELECT l.template_key, l.created_at, count(*), count(*) FILTER (WHERE o.status = 'sent'), count(*) FILTER (WHERE o.status = 'pending'),
    count(*) FILTER (WHERE o.status = 'failed'), count(*) FILTER (WHERE o.status = 'skipped_no_smtp'), max(o.sent_at),
    COALESCE((array_agg(o.last_error_code ORDER BY o.id) FILTER (WHERE o.status <> 'sent' AND o.last_error_code <> ''))[1], '')
FROM last l JOIN notifications_outbox o ON o.params ? 'acme_certificate_id' AND o.params->>'acme_certificate_id' = $1
    AND o.created_at = l.created_at AND o.template_key = l.template_key
GROUP BY l.template_key, l.created_at`, id.String()).Scan(&d.Template, &d.QueuedAt, &d.Recipients, &d.Sent, &d.Pending, &d.Failed, &d.Skipped,
		&d.SentAt, &d.LastErrorCode)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("inventory: read the delivery of the renewal e-mails: %w", err)
	}
	d.QueuedAt = d.QueuedAt.UTC()
	if d.SentAt != nil {
		t := d.SentAt.UTC()
		d.SentAt = &t
	}
	return &d, nil
}
