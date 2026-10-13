package inventory

// The renewal planner of ACME certificates (plan 2026-10-13 Task 11; design row 6; amendments A2, A7): the transactional
// half. renew.Decide (internal/acme/renew) decides; this file reads one certificate under its row lock, applies the
// decision in the same transaction and writes the marks that make every notice and every stop happen once. It copies
// the Key Vault planner (kv_autodeploy.go): the licence gate first (nothing in lock: no CA contact, no row written, no
// failure counted), candidates chosen without a lock, then one transaction per certificate that takes its row with
// SKIP LOCKED (a certificate another planner or a person is changing is planned at the next run), so several
// processes may plan at once and each certificate gets at most one order (the row lock, then the unique index
// acme_orders_one_running and the job's dedupe key as backstops). An order is started by startOrderTx, the same path
// as a person's RequestOrder, with the system actor jobs and trigger renewal.
//
// The CA's renewal information (ARI) is asked for outside any transaction, at most acmeARIPerRun times per run, through
// the provider's guarded transport and only while the gate allows changes; the answer is cached on the row (window,
// when asked, when it may be asked again: renew.NextARICheck) and cleared when a new certificate is issued. A failed
// lookup is never a failure of the certificate and never blocks its renewal: the cached window (if any) stays and the
// local rule decides.
//
// Storm limits: at most ACMERenewWave orders start per run; a certificate waits renew.MinSpacing after its last order and
// its backoff after failures; while one certificate of a provider waits for the CA's rate limit (last_error_code
// acme.ca_rate_limited, next_attempt_at in the future), no other certificate of that provider is ordered.

import (
	"context"
	"encoding/pem"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"alice/internal/acme"
	"alice/internal/acme/renew"
	"alice/internal/audit"
	"alice/internal/license"
	"alice/internal/platform/db"
)

// Limits of one run of the renewal planner.
const (
	// ACMERenewWave is how many orders one run starts at most.
	ACMERenewWave = 5
	// acmeRenewPage is the size of a page of candidates; one run reads at most acmeRenewPages pages.
	acmeRenewPage  = 50
	acmeRenewPages = 3
	// acmeRateLimitHold is how long a series of rate limits of one certificate holds the provider's other
	// certificates at most (see acmeRenewCandidates).
	acmeRateLimitHold = 24 * time.Hour
	// acmeARIPerRun is how many renewal information lookups one run makes at most; acmeARITimeout bounds one.
	acmeARIPerRun  = 10
	acmeARITimeout = 30 * time.Second
	// acmeNoticeNames bounds the names param of the renewal e-mails.
	acmeNoticeNames = 500
	acmeNoticeTime  = "2006-01-02 15:04 UTC"
)

// ACMERenewRun counts what one run of the planner did.
type ACMERenewRun struct {
	// Started: renewal orders started; Stopped: automatic renewals stopped; Failed: certificates whose order could not
	// start (no active account: counted as a failure); ARIChecked: renewal information lookups.
	Started, Stopped, Failed, ARIChecked int
}

// acmeRenewHook runs after a certificate's candidate was read and before its transaction (tests: the world changes).
var acmeRenewHook func(id uuid.UUID)

// errRenewSkip rolls back a certificate's transaction without an error (the next run plans it again).
var errRenewSkip = errors.New("inventory: the certificate is planned at the next run")

// PlanACMERenewals runs the renewal planner once (acme.schedule; see the file comment). While the licence gate refuses
// changes it returns at once: no CA contact, no row written, no failure counted. The candidates are read page by page
// (at most acmeRenewPages pages of acmeRenewPage, most urgent first), so certificates that are skipped run after run
// (a key change that does not settle, a job that is still finishing) do not hide the ones after them. The certificates
// whose planning failed are skipped for this run and their errors returned together.
func (s *Service) PlanACMERenewals(ctx context.Context) (ACMERenewRun, error) {
	var run ACMERenewRun
	if s.license.Allow(license.ClassChange) != nil {
		return run, nil
	}
	var errs []error
	var after *renewCursor
	for page := 0; page < acmeRenewPages && run.Started < ACMERenewWave; page++ {
		cands, err := s.acmeRenewCandidates(ctx, after)
		if err != nil {
			return run, errors.Join(append(errs, err)...)
		}
		for _, c := range cands {
			if run.Started >= ACMERenewWave {
				break
			}
			if ctx.Err() != nil {
				return run, errors.Join(append(errs, ctx.Err())...)
			}
			if acmeRenewHook != nil {
				acmeRenewHook(c.id)
			}
			if err := s.planACMERenewal(ctx, c.id, &run); err != nil {
				errs = append(errs, err)
			}
		}
		if len(cands) < acmeRenewPage {
			break
		}
		after = &cands[len(cands)-1]
	}
	return run, errors.Join(errs...)
}

// renewCursor is a candidate and its place in the urgency order (the keyset of the next page).
type renewCursor struct {
	id       uuid.UUID
	priority time.Time
}

// acmeRenewCandidates lists the certificates that may have work now, most urgent first, after the cursor (nil: from
// the start): auto renewal on, not stopped, not deleted, issued, no running order, no order in the last
// renew.MinSpacing, not waiting for a backoff (a next_attempt_at beyond the cap is a candidate: the planner repairs it),
// not held by a rate limit of its provider, and either due by the local rule or an ARI window (one that ends after the
// current certificate began), or owing an ARI lookup, or past the failures that stop it.
//
// The provider hold: while another certificate of the provider waits for the CA's rate limit (last_error_code
// acme.ca_rate_limited, next_attempt_at in the future) and that series of rate limits began less than
// acmeRateLimitHold ago, the candidate waits too (no storm against a limiting CA). The hold never applies to a
// candidate past the middle of its renewal window (due + (not_after - due) / 2): that one is renewed regardless, so a
// certificate the CA limits for days for its own names cannot make the provider's other certificates expire.
func (s *Service) acmeRenewCandidates(ctx context.Context, after *renewCursor) ([]renewCursor, error) {
	now := s.clock.Now().UTC()
	afterID, afterPrio := uuid.Nil, time.Time{}
	if after != nil {
		afterID, afterPrio = after.id, after.priority
	}
	rows, err := s.pool.Query(ctx, `WITH c AS (
    SELECT c.id, c.provider_id, c.failures, c.next_attempt_at, c.ari_next_check_at, x.not_after,
           CASE WHEN c.ari_window_end > x.not_before THEN c.ari_window_start END AS ari_start,
           x.not_after - LEAST(make_interval(days => c.renew_before_days), GREATEST(x.not_after - x.not_before, interval '0') / 3) AS due
    FROM acme_certificates c JOIN certificates x ON x.id = c.current_certificate_id
    WHERE c.deleted_at IS NULL AND c.auto_renew AND c.state <> 'stopped'
), p AS (
    SELECT c.*, LEAST(c.due, COALESCE(c.ari_start, c.due)) AS priority FROM c
)
SELECT c.id, c.priority FROM p c
WHERE NOT EXISTS (SELECT 1 FROM acme_orders o WHERE o.acme_certificate_id = c.id AND o.state = 'running')
  AND NOT EXISTS (SELECT 1 FROM acme_orders o WHERE o.acme_certificate_id = c.id AND o.kind = 'issue'
                  AND o.started_at > $1::timestamptz - make_interval(secs => $3) AND o.started_at <= $1::timestamptz + make_interval(secs => $4))
  AND (c.next_attempt_at IS NULL OR c.next_attempt_at <= $1 OR c.next_attempt_at > $1::timestamptz + make_interval(secs => $5))
  AND (c.due + (c.not_after - c.due) / 2 <= $1
       OR NOT EXISTS (SELECT 1 FROM acme_certificates r WHERE r.provider_id = c.provider_id AND r.id <> c.id AND r.deleted_at IS NULL
                      AND r.last_error_code = 'acme.ca_rate_limited' AND r.next_attempt_at > $1
                      AND r.rate_limited_since > $1::timestamptz - make_interval(secs => $9)))
  AND (c.due <= $1 OR c.ari_start <= $1 OR c.ari_next_check_at IS NULL OR c.ari_next_check_at <= $1 OR c.failures >= $6)
  AND ($7::timestamptz IS NULL OR (c.priority, c.id) > ($7::timestamptz, $8::uuid))
ORDER BY c.priority, c.id LIMIT $2`, now, acmeRenewPage, renew.MinSpacing.Seconds(), renew.SkewTolerance.Seconds(), renew.MaxBackoff.Seconds(),
		renew.StopAfter, nullTime(afterPrio), afterID, acmeRateLimitHold.Seconds())
	if err != nil {
		return nil, fmt.Errorf("inventory: find the ACME certificates to renew: %w", err)
	}
	out, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (renewCursor, error) {
		var c renewCursor
		err := r.Scan(&c.id, &c.priority)
		return c, err
	})
	if err != nil {
		return nil, fmt.Errorf("inventory: find the ACME certificates to renew: %w", err)
	}
	return out, nil
}

// nullTime is nil for the zero time (a SQL NULL).
func nullTime(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}

// ariTarget is a certificate whose renewal window the planner asks the CA for.
type ariTarget struct {
	acmeCertificate, current, provider uuid.UUID
}

// planACMERenewal plans one certificate: its transaction, then (when the decision asks for it and the run's budget
// allows) a renewal information lookup and the transaction again, since the window may make it due now.
func (s *Service) planACMERenewal(ctx context.Context, id uuid.UUID, run *ACMERenewRun) error {
	ari, err := s.renewTx(ctx, id, run)
	if err != nil || ari == nil || run.ARIChecked >= acmeARIPerRun {
		return err
	}
	run.ARIChecked++
	if err := s.refreshACMEARI(ctx, *ari); err != nil {
		return err
	}
	_, err = s.renewTx(ctx, id, run)
	return err
}

// renewTx reads one certificate under its row lock (SKIP LOCKED), decides and applies the decision.
func (s *Service) renewTx(ctx context.Context, id uuid.UUID, run *ACMERenewRun) (*ariTarget, error) {
	var (
		ari                      *ariTarget
		started, stopped, failed bool
	)
	err := db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		ari, started, stopped, failed = nil, false, false, false
		var locked uuid.UUID
		err := tx.QueryRow(ctx, "SELECT id FROM acme_certificates WHERE id = $1 AND deleted_at IS NULL FOR UPDATE SKIP LOCKED", id).Scan(&locked)
		if errors.Is(err, pgx.ErrNoRows) {
			return errRenewSkip // deleted, or busy: the next run
		}
		if err != nil {
			return fmt.Errorf("inventory: lock the ACME certificate: %w", err)
		}
		// The gate is read again here: the licence may have locked since the run began.
		if s.license.Allow(license.ClassChange) != nil {
			return errRenewSkip
		}
		c, err := getACMECert(ctx, tx, id, true) // a fresh view of the running order, after the lock
		if err != nil {
			return err
		}
		now := s.clock.Now().UTC()
		in, notAfter, err := renewInput(ctx, tx, c, now)
		if err != nil {
			return err
		}
		d := renew.Decide(in)
		if d.RepairNextAttempt != nil {
			if _, err := tx.Exec(ctx, "UPDATE acme_certificates SET next_attempt_at = $2, updated_at = $3 WHERE id = $1", id, *d.RepairNextAttempt,
				now); err != nil {
				return fmt.Errorf("inventory: repair the next attempt of the ACME certificate: %w", err)
			}
		}
		switch d.Action {
		case renew.Stop:
			stopped, err = s.stopAutoRenew(ctx, tx, c.ID, c.Names, c.Failures, c.LastErrorCode, notAfter, now)
			return err
		case renew.Order:
			_, err := s.startOrderTx(ctx, tx, Actor{Audit: jobsActor}, c, ACMEOrderIssue, ACMETriggerRenewal)
			switch {
			case err == nil:
				started = true
			case errors.Is(err, ErrACMEOrderRunning), errors.Is(err, ErrACMERolloverPending):
				return errRenewSkip // a person's order or a key change that settles: the next run
			case errors.Is(err, ErrACMEAccountState):
				// The provider has no active account (or is gone): the renewal cannot start. Counted like a failed order,
				// so the backoff paces the planner and the e-mails tell the Administrators.
				failed = true
				return s.countACMEFailure(ctx, tx, c.ID, "acme.account_state", 0, now)
			default:
				return err
			}
		}
		if d.RefreshARI && c.CurrentCertificateID != nil {
			ari = &ariTarget{acmeCertificate: c.ID, current: *c.CurrentCertificateID, provider: c.ProviderID}
		}
		return nil
	})
	switch {
	case errors.Is(err, errRenewSkip):
		return nil, nil
	case err != nil:
		return nil, err
	}
	if started {
		run.Started++
	}
	if stopped {
		run.Stopped++
	}
	if failed {
		run.Failed++
	}
	return ari, nil
}

// renewInput reads what renew.Decide needs about c (read under its row lock), in statements of their own (a fresh
// snapshot), and returns the current certificate's end too.
func renewInput(ctx context.Context, tx pgx.Tx, c ACMECertificate, now time.Time) (renew.Input, *time.Time, error) {
	in := renew.Input{Now: now, RenewBeforeDays: c.RenewBeforeDays, AutoRenew: c.AutoRenew, State: c.State, OrderRunning: c.RunningOrderID != nil,
		Failures: c.Failures, NextAttemptAt: c.NextAttemptAt, LastAttemptAt: c.LastAttemptAt}
	var nb, na, ws, we *time.Time
	err := tx.QueryRow(ctx, `SELECT x.not_before, x.not_after, c.ari_window_start, c.ari_window_end, c.ari_checked_at, c.ari_next_check_at,
    (SELECT max(o.started_at) FROM acme_orders o WHERE o.acme_certificate_id = c.id AND o.kind = 'issue'
     AND o.started_at <= $2::timestamptz + make_interval(secs => $3))
FROM acme_certificates c LEFT JOIN certificates x ON x.id = c.current_certificate_id WHERE c.id = $1`, c.ID, now, renew.SkewTolerance.Seconds()).
		Scan(&nb, &na, &ws, &we, &in.ARICheckedAt, &in.ARINextCheckAt, &in.LastOrderAt)
	if err != nil {
		return in, nil, fmt.Errorf("inventory: read the ACME certificate's renewal state: %w", err)
	}
	if na != nil && nb != nil {
		in.NotBefore, in.NotAfter = nb.UTC(), na.UTC()
	}
	if ws != nil && we != nil {
		in.ARIWindow = &renew.Window{Start: ws.UTC(), End: we.UTC()}
	}
	return in, na, nil
}

// countACMEFailure counts a failed renewal of an ACME certificate in tx: failures + 1, state failing (stopped stays),
// last_error_code, last_attempt_at, next_attempt_at = now + max(backoff, retryAfter); then renew.AfterFailure: the
// "renewal failed" e-mail once per series (failure_notified_at), or the stop (stopAutoRenew).
func (s *Service) countACMEFailure(ctx context.Context, tx pgx.Tx, id uuid.UUID, code string, retryAfter time.Duration, now time.Time) error {
	var (
		failures  int
		autoRenew bool
		state     string
		notified  bool
		names     []string
		notAfter  *time.Time
	)
	err := tx.QueryRow(ctx, `SELECT c.failures, c.auto_renew, c.state, c.failure_notified_at IS NOT NULL, c.names, x.not_after
FROM acme_certificates c LEFT JOIN certificates x ON x.id = c.current_certificate_id WHERE c.id = $1 FOR UPDATE OF c`, id).
		Scan(&failures, &autoRenew, &state, &notified, &names, &notAfter)
	if err != nil {
		return fmt.Errorf("inventory: read the ACME certificate's failures: %w", err)
	}
	failures++
	next := now.Add(max(ACMEFailureBackoff(failures), retryAfter))
	// rate_limited_since: when the current series of rate limits began (kept while the CA keeps limiting, NULL otherwise).
	if _, err := tx.Exec(ctx, `UPDATE acme_certificates SET failures = $2, state = CASE WHEN state = 'stopped' THEN state ELSE 'failing' END,
rate_limited_since = CASE WHEN $3 <> 'acme.ca_rate_limited' THEN NULL
    WHEN last_error_code = 'acme.ca_rate_limited' AND rate_limited_since IS NOT NULL THEN rate_limited_since ELSE $4 END,
last_error_code = $3, last_attempt_at = $4, next_attempt_at = $5, updated_at = $4 WHERE id = $1`, id, failures, code, now, next); err != nil {
		return fmt.Errorf("inventory: record the ACME certificate's failure: %w", err)
	}
	out := renew.AfterFailure(renew.FailureState{Failures: failures, AutoRenew: autoRenew, Issued: notAfter != nil,
		Stopped: state == ACMEStateStopped, Notified: notified})
	switch {
	case out.Stop:
		_, err := s.stopAutoRenew(ctx, tx, id, names, failures, code, notAfter, now)
		return err
	case out.Notify:
		tag, err := tx.Exec(ctx, "UPDATE acme_certificates SET failure_notified_at = $2 WHERE id = $1 AND failure_notified_at IS NULL", id, now)
		if err != nil {
			return fmt.Errorf("inventory: mark the renewal notice: %w", err)
		}
		if tag.RowsAffected() == 1 && s.notifier != nil {
			if err := s.notifier.NotifyAdmins(ctx, tx, TemplateACMERenewalFailed, acmeNoticeParams(names, failures, code, notAfter)); err != nil {
				return fmt.Errorf("inventory: queue the renewal notice: %w", err)
			}
		}
	}
	return nil
}

// stopAutoRenew stops the automatic renewal of a certificate in tx (state stopped; the "renewal failed" mark is set too,
// so that only this e-mail goes) with the audit row acme.auto_renew.stopped and one e-mail; it reports false when it
// was stopped already (the state is the once-only mark). A successful order makes it active again.
func (s *Service) stopAutoRenew(ctx context.Context, tx pgx.Tx, id uuid.UUID, names []string, failures int, code string, notAfter *time.Time,
	now time.Time) (bool, error) {
	tag, err := tx.Exec(ctx, `UPDATE acme_certificates SET state = 'stopped', failure_notified_at = COALESCE(failure_notified_at, $2), updated_at = $2
WHERE id = $1 AND state <> 'stopped'`, id, now)
	if err != nil {
		return false, fmt.Errorf("inventory: stop the automatic renewal: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return false, nil
	}
	if _, err := s.audit.Append(ctx, tx, audit.Event{Actor: jobsActor, Action: "acme.auto_renew.stopped", ObjectType: "acme_certificate",
		ObjectID: id.String(), Result: audit.Success, Details: map[string]string{"acme_certificate_id": id.String(),
			"names": truncRunes(strings.Join(names, ","), maxAuditNames), "failed_count": strconv.Itoa(failures), "error_code": code}}); err != nil {
		return false, err
	}
	if s.notifier != nil {
		if err := s.notifier.NotifyAdmins(ctx, tx, TemplateACMEAutoRenewStopped, acmeNoticeParams(names, failures, code, notAfter)); err != nil {
			return false, fmt.Errorf("inventory: queue the stop notice: %w", err)
		}
	}
	return true, nil
}

// acmeNoticeParams are the params of the renewal e-mails (TemplateACMERenewalFailed).
func acmeNoticeParams(names []string, failures int, code string, notAfter *time.Time) map[string]string {
	p := map[string]string{"names": truncRunes(strings.Join(names, ", "), acmeNoticeNames), "count": strconv.Itoa(failures), "error_reason": code}
	if len(names) > 0 {
		p["name"] = names[0]
	}
	if notAfter != nil {
		p["expires_at"] = notAfter.UTC().Format(acmeNoticeTime)
	}
	return p
}

// refreshACMEARI asks the CA for the renewal window of t's current certificate and caches the answer on the row (only
// while the row still names that certificate). Only while the gate allows changes; through the provider's guarded
// transport; bounded by acmeARITimeout. A failure is not the certificate's: the cached window stays, the next lookup
// waits renew.NextARICheck (the CA's Retry-After when it gave one), and a CA without renewal information clears the
// window. It returns only database errors.
func (s *Service) refreshACMEARI(ctx context.Context, t ariTarget) error {
	if s.license.Allow(license.ClassChange) != nil {
		return nil
	}
	window, err := s.acmeRenewalInfo(ctx, t)
	now := s.clock.Now().UTC()
	var ae *acme.Error
	switch {
	case err == nil:
		_, err = s.pool.Exec(ctx, `UPDATE acme_certificates SET ari_window_start = $3, ari_window_end = $4, ari_checked_at = $5, ari_next_check_at = $6
WHERE id = $1 AND current_certificate_id = $2`, t.acmeCertificate, t.current, window.Start, window.End, now, renew.NextARICheck(now, window.RetryAfter))
	case errors.Is(err, acme.ErrNoARI):
		_, err = s.pool.Exec(ctx, `UPDATE acme_certificates SET ari_window_start = NULL, ari_window_end = NULL, ari_checked_at = $3, ari_next_check_at = $4
WHERE id = $1 AND current_certificate_id = $2`, t.acmeCertificate, t.current, now, renew.NextARICheck(now, 0))
	default:
		retry := time.Duration(0)
		reason := "unknown"
		if errors.As(err, &ae) {
			retry, reason = ae.RetryAfter(), ae.Reason
		}
		s.log.Info("the certificate authority's renewal information could not be read; the local rule decides", "acme_certificate_id",
			t.acmeCertificate.String(), "reason", reason)
		_, err = s.pool.Exec(ctx, `UPDATE acme_certificates SET ari_checked_at = $3, ari_next_check_at = $4 WHERE id = $1 AND current_certificate_id = $2`,
			t.acmeCertificate, t.current, now, renew.NextARICheck(now, retry))
	}
	if err != nil {
		return fmt.Errorf("inventory: record the renewal information: %w", err)
	}
	return nil
}

// errARILeaf: the current certificate's leaf cannot be read (it is never sent).
var errARILeaf = errors.New("inventory: the current certificate cannot be read")

// acmeRenewalInfo looks the window up: the provider (live; none is an error), the current certificate's leaf, an
// account-less client of the provider (renewal information is an unauthenticated GET).
func (s *Service) acmeRenewalInfo(ctx context.Context, t ariTarget) (acme.RenewalWindow, error) {
	p, err := getACMEProvider(ctx, s.pool, t.provider, false)
	if err != nil {
		return acme.RenewalWindow{}, err
	}
	var chain string
	if err := s.pool.QueryRow(ctx, "SELECT pem_chain FROM certificates WHERE id = $1", t.current).Scan(&chain); err != nil {
		return acme.RenewalWindow{}, fmt.Errorf("inventory: read the current certificate: %w", err)
	}
	block, _ := pem.Decode([]byte(chain))
	if block == nil {
		return acme.RenewalWindow{}, errARILeaf
	}
	c, err := s.acmeClientFor(p, nil, "")
	if err != nil {
		return acme.RenewalWindow{}, err
	}
	cctx, cancel := context.WithTimeout(ctx, acmeARITimeout)
	defer cancel()
	return c.RenewalInfo(cctx, block.Bytes)
}
