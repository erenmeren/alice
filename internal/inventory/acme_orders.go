package inventory

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"alice/internal/acme"
	"alice/internal/acme/keygen"
	"alice/internal/acme/renew"
	"alice/internal/acme/solver"
	"alice/internal/audit"
	"alice/internal/certs"
	"alice/internal/license"
	"alice/internal/platform/db"
	"alice/internal/platform/validate"
	"alice/internal/providers"
)

// ACME orders (plan 2026-10-13 Task 10; design rows 2, 6; amendments A2, A7, A8, A12).
//
// RequestOrder is how a person (Operator or Administrator: the API's AcmeOperate) or the renewal planner (Task 11,
// with a system actor) starts an order: the license gate first (in lock nothing is recorded and no CA is ever
// contacted), then, in one transaction holding the ACME certificate's row (the per-certificate lock), the order row
// (one running order per certificate: the unique index acme_orders_one_running, ErrACMEOrderRunning), the acme.issue
// job (payload: ids only; dedupe acme.issue:<certificate>) and the audit row acme.order.started.
//
// The acme.issue job (internal/jobs/acmejobs) does the CA conversation with the methods below and ends every order
// through FinishACMEOrder (success), SucceedACMETestOrder (a test run) or FailACMEOrder (anything else). Every
// challenge record is written into acme_orders.presented BEFORE it is published (AddACMEPresented, its own
// transaction) and taken out once it is removed again (RemoveACMEPresented), so whatever is left after an order ended
// (a hook that was down, a crash) is removed by the acme.cleanup job, which runs in every license state.
//
// Boundary with Task 11 (the renewal planner): FailACMEOrder writes the failure state of an issue order consistently
// (failures + 1, state failing unless stopped, last_error_code, last_attempt_at, next_attempt_at = now +
// max(ACMEFailureBackoff(failures), the CA's Retry-After capped at 24 h)); FinishACMEOrder resets it (next_attempt_at
// NULL). Deciding WHEN to order (renewal window, ARI, next_attempt_at, stop after 5 failures, e-mails) is Task 11's
// PlanACMERenewals, which calls RequestOrder.

// Order kinds and states (acme_orders.kind, acme_orders.state).
const (
	ACMEOrderIssue     = "issue"
	ACMEOrderTest      = "test"
	ACMEOrderRunning   = "running"
	ACMEOrderSucceeded = "succeeded"
	ACMEOrderFailed    = "failed"
)

// Job types of ACME orders (jobs registers them): acme.issue runs one order (payload order_id and
// acme_certificate_id; dedupe acme.issue:<certificate>: one live job per certificate), acme.cleanup removes what an
// ended order left published (payload order_id; dedupe acme.cleanup:<order>).
const (
	JobACMEIssue   = "acme.issue"
	JobACMECleanup = "acme.cleanup"
)

// Order failure codes Alice decides herself (the CA's are acme reasons).
const (
	// ACMEOrderAbandoned: the order ran longer than any job can (a crash) and could not be finished.
	ACMEOrderAbandoned = "acme.order_abandoned"
	// ACMELicenseLocked: the license gate refused changes while the order ran (no challenge was published after).
	ACMELicenseLocked = "license.locked"
)

// MaxACMEBackoff caps the wait after failed orders and a CA's Retry-After.
const MaxACMEBackoff = renew.MaxBackoff

// Order triggers (acme_orders.trigger): a person's order, or the renewal planner's (acme.schedule).
const (
	ACMETriggerManual  = "manual"
	ACMETriggerRenewal = "renewal"
)

// ACMEFailureBackoff is the wait before the next automatic order after failures consecutive failed orders: 1 h, 2 h,
// 4 h, ... capped at 24 h (design row 6). failures < 1 is no wait.
func ACMEFailureBackoff(failures int) time.Duration { return renew.Backoff(failures) }

// ACMEOrder is the view of an order. It has no secret (nothing of the pending key, only how many records are still
// published).
type ACMEOrder struct {
	ID                uuid.UUID  `json:"id"`
	ACMECertificateID uuid.UUID  `json:"acme_certificate_id"`
	Kind              string     `json:"kind"`
	State             string     `json:"state"`
	StartedAt         time.Time  `json:"started_at"`
	FinishedAt        *time.Time `json:"finished_at,omitempty"`
	ErrorCode         string     `json:"error_code"`
	CertificateID     *uuid.UUID `json:"certificate_id,omitempty"`
	RequestedBy       *uuid.UUID `json:"requested_by,omitempty"`
	Trigger           string     `json:"trigger"`
	Presented         int        `json:"presented"`
	CleanupAt         *time.Time `json:"cleanup_at,omitempty"`
	CleanupErrorCode  string     `json:"cleanup_error_code"`
}

const acmeOrderColumns = `o.id, o.acme_certificate_id, o.kind, o.state, o.started_at, o.finished_at, o.error_code, o.certificate_id,
o.requested_by, o.trigger, jsonb_array_length(o.presented), o.cleanup_at, o.cleanup_error_code`

func scanACMEOrder(row pgx.Row) (ACMEOrder, error) {
	var o ACMEOrder
	err := row.Scan(&o.ID, &o.ACMECertificateID, &o.Kind, &o.State, &o.StartedAt, &o.FinishedAt, &o.ErrorCode, &o.CertificateID,
		&o.RequestedBy, &o.Trigger, &o.Presented, &o.CleanupAt, &o.CleanupErrorCode)
	o.StartedAt = o.StartedAt.UTC()
	for _, t := range []**time.Time{&o.FinishedAt, &o.CleanupAt} {
		if *t != nil {
			u := (*t).UTC()
			*t = &u
		}
	}
	return o, err
}

func getACMEOrder(ctx context.Context, q db.Querier, id uuid.UUID) (ACMEOrder, error) {
	o, err := scanACMEOrder(q.QueryRow(ctx, "SELECT "+acmeOrderColumns+" FROM acme_orders o WHERE o.id = $1", id))
	if errors.Is(err, pgx.ErrNoRows) {
		return ACMEOrder{}, ErrNotFound
	}
	if err != nil {
		return ACMEOrder{}, fmt.Errorf("inventory: read the ACME order: %w", err)
	}
	return o, nil
}

// GetACMEOrder returns an order (ErrNotFound).
func (s *Service) GetACMEOrder(ctx context.Context, id uuid.UUID) (ACMEOrder, error) {
	return getACMEOrder(ctx, s.pool, id)
}

// MaxACMEOrdersListed bounds ListACMEOrders.
const MaxACMEOrdersListed = 100

// ListACMEOrders returns the newest orders of a live ACME certificate (at most limit, 1..100; 0 = 20).
func (s *Service) ListACMEOrders(ctx context.Context, acmeCertificateID uuid.UUID, limit int) ([]ACMEOrder, error) {
	if limit <= 0 {
		limit = 20
	}
	limit = min(limit, MaxACMEOrdersListed)
	if _, err := getACMECert(ctx, s.pool, acmeCertificateID, false); err != nil {
		return nil, err
	}
	rows, err := s.pool.Query(ctx, "SELECT "+acmeOrderColumns+` FROM acme_orders o WHERE o.acme_certificate_id = $1
ORDER BY o.started_at DESC, o.id DESC LIMIT $2`, acmeCertificateID, limit)
	if err != nil {
		return nil, fmt.Errorf("inventory: list the ACME orders: %w", err)
	}
	defer rows.Close()
	out := []ACMEOrder{}
	for rows.Next() {
		o, err := scanACMEOrder(rows)
		if err != nil {
			return nil, fmt.Errorf("inventory: read an ACME order: %w", err)
		}
		out = append(out, o)
	}
	return out, rows.Err()
}

// RequestOrder starts an order of kind issue (a certificate is ordered and stored) or test (the order stops at
// validated authorizations: no key, no certificate, no finalize). The license gate is asked first (license.ErrLocked
// and the like: nothing is recorded, no CA is contacted). Then, holding the certificate's row: ErrNotFound for a
// certificate that is not live; ErrACMEAccountState when its provider has no active account; ErrACMERolloverPending
// while the account's key change is unsettled; ErrACMEOrderRunning when an order of it runs (one at a time, also
// across processes: the unique index); the order (running), the acme.issue job and the audit row acme.order.started
// commit together. An issue order puts the certificate in state issuing (a stopped one stays stopped).
func (s *Service) RequestOrder(ctx context.Context, a Actor, acmeCertificateID uuid.UUID, kind string) (ACMEOrder, error) {
	if kind != ACMEOrderIssue && kind != ACMEOrderTest {
		return ACMEOrder{}, validate.Errors{{Field: "kind", Code: validate.OneOf, Params: map[string]string{"values": "issue, test"}}}
	}
	if err := s.license.Allow(license.ClassChange); err != nil {
		return ACMEOrder{}, err
	}
	var out ACMEOrder
	err := db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		c, err := getACMECert(ctx, tx, acmeCertificateID, true)
		if err != nil {
			return err
		}
		out, err = s.startOrderTx(ctx, tx, a, c, kind, ACMETriggerManual)
		return err
	})
	if err != nil {
		return ACMEOrder{}, err
	}
	return out, nil
}

// startOrderTx is the one way an order starts (RequestOrder and the renewal planner): c was read with its row lock
// in tx (getACMECert forUpdate: a fresh view of its running order). The order, the job and the audit row
// acme.order.started (with the trigger) are written in tx; the refusals are RequestOrder's.
func (s *Service) startOrderTx(ctx context.Context, tx pgx.Tx, a Actor, c ACMECertificate, kind, trigger string) (ACMEOrder, error) {
	if c.RunningOrderID != nil {
		return ACMEOrder{}, ErrACMEOrderRunning
	}
	p, err := getACMEProvider(ctx, tx, c.ProviderID, false)
	switch {
	case errors.Is(err, ErrNotFound):
		return ACMEOrder{}, ErrACMEAccountState
	case err != nil:
		return ACMEOrder{}, err
	case p.ActiveAccountID == nil:
		return ACMEOrder{}, ErrACMEAccountState
	case p.PendingRollover:
		return ACMEOrder{}, ErrACMERolloverPending
	}
	id := uuid.Must(uuid.NewV7())
	now := s.clock.Now().UTC()
	// A savepoint: a refused insert (the unique index, another process) must not abort the caller's transaction.
	sp, err := tx.Begin(ctx)
	if err != nil {
		return ACMEOrder{}, fmt.Errorf("inventory: open a savepoint: %w", err)
	}
	if _, err := sp.Exec(ctx, `INSERT INTO acme_orders (id, acme_certificate_id, kind, state, started_at, requested_by, trigger)
VALUES ($1, $2, $3, 'running', $4, $5, $6)`, id, c.ID, kind, now, actorRef(a), trigger); err != nil {
		_ = sp.Rollback(ctx)
		if db.IsUniqueViolationOn(err, "acme_orders_one_running") {
			return ACMEOrder{}, ErrACMEOrderRunning
		}
		return ACMEOrder{}, fmt.Errorf("inventory: store the ACME order: %w", err)
	}
	if err := sp.Commit(ctx); err != nil {
		return ACMEOrder{}, fmt.Errorf("inventory: release a savepoint: %w", err)
	}
	if kind == ACMEOrderIssue {
		if _, err := tx.Exec(ctx, `UPDATE acme_certificates SET state = CASE WHEN state = 'stopped' THEN state ELSE 'issuing' END, updated_at = $2
WHERE id = $1`, c.ID, now); err != nil {
			return ACMEOrder{}, fmt.Errorf("inventory: mark the ACME certificate as issuing: %w", err)
		}
	}
	_, err = s.jobs.EnqueueTx(ctx, tx, JobRequest{Type: JobACMEIssue,
		Payload: map[string]string{"order_id": id.String(), "acme_certificate_id": c.ID.String()},
		Kind:    a.jobKind(), CreatedBy: a.UserID, CreatedByRole: string(a.Role), DedupeKey: JobACMEIssue + ":" + c.ID.String()})
	if errors.Is(err, ErrJobConflict) {
		return ACMEOrder{}, ErrACMEOrderRunning // the job of the previous order is still finishing
	}
	if err != nil {
		return ACMEOrder{}, err
	}
	out, err := getACMEOrder(ctx, tx, id)
	if err != nil {
		return ACMEOrder{}, err
	}
	_, err = s.audit.Append(ctx, tx, audit.Event{Actor: a.Audit, Action: "acme.order.started", ObjectType: "acme_certificate",
		ObjectID: c.ID.String(), Result: audit.Success, Details: map[string]string{
			"order_id": id.String(), "acme_certificate_id": c.ID.String(), "kind": kind, "provider_id": c.ProviderID.String(), "trigger": trigger}})
	if err != nil {
		return ACMEOrder{}, err
	}
	return out, nil
}

// ACMEOrderWork is what the acme.issue job needs to run an order: the order, the names and the proof method of its
// ACME certificate, and the allow-lists in force now (the job checks them again: an Administrator may have narrowed
// them since the order was requested).
type ACMEOrderWork struct {
	Order            ACMEOrder
	OrderURL         string
	HasKey           bool
	Names            []string
	Challenge        string
	HookID           *uuid.UUID
	HTTPTargetID     *uuid.UUID
	ProviderID       uuid.UUID
	ProviderSuffixes []string
	HookSuffixes     []string // nil without a hook (or a deleted one: then nothing is admitted)
	// Deleted: the ACME certificate was deleted (the job ends the order without contacting the CA).
	Deleted bool
}

// ACMEOrderWork reads an order with its certificate, provider and hook (ErrNotFound).
func (s *Service) ACMEOrderWork(ctx context.Context, orderID uuid.UUID) (ACMEOrderWork, error) {
	o, err := getACMEOrder(ctx, s.pool, orderID)
	if err != nil {
		return ACMEOrderWork{}, err
	}
	w := ACMEOrderWork{Order: o}
	err = s.pool.QueryRow(ctx, `SELECT o.order_url, o.pending_key_ct IS NOT NULL, c.names, c.challenge, c.hook_id, c.http_target_id, c.provider_id,
    p.allowed_suffixes, (SELECT h.allowed_suffixes FROM acme_hooks h WHERE h.id = c.hook_id AND h.deleted_at IS NULL), c.deleted_at IS NOT NULL
FROM acme_orders o JOIN acme_certificates c ON c.id = o.acme_certificate_id JOIN acme_providers p ON p.id = c.provider_id
WHERE o.id = $1`, orderID).Scan(&w.OrderURL, &w.HasKey, &w.Names, &w.Challenge, &w.HookID, &w.HTTPTargetID, &w.ProviderID,
		&w.ProviderSuffixes, &w.HookSuffixes, &w.Deleted)
	if err != nil {
		return ACMEOrderWork{}, fmt.Errorf("inventory: read the ACME order's certificate: %w", err)
	}
	return w, nil
}

// NamesAllowed reports whether every name is still admitted by the provider's allow-list and, for DNS-01, the hook's.
func (w ACMEOrderWork) NamesAllowed() bool {
	for _, n := range w.Names {
		if !ACMENameAllowed(w.ProviderSuffixes, n) || (w.Challenge == ACMEChallengeDNS01 && !ACMENameAllowed(w.HookSuffixes, n)) {
			return false
		}
	}
	return true
}

// ACMEOrderClient builds the CA client of a running order: the provider's CURRENT active account (the ACME
// certificate is moved to it when it still names an older one, e.g. after a directory change), its key
// (ACMEAccountSigner: ErrACMERolloverPending while a key change is unsettled), the guarded transport with the
// provider's bundle. ErrACMEAccountState when the provider is deleted or has no active account; ErrACMEOrderNotRunning
// for an order that ended; ErrNotFound for an unknown order or a deleted ACME certificate.
func (s *Service) ACMEOrderClient(ctx context.Context, orderID uuid.UUID) (*acme.Client, error) {
	var state string
	var certID, providerID, accountID uuid.UUID
	err := s.pool.QueryRow(ctx, `SELECT o.state, c.id, c.provider_id, c.account_id FROM acme_orders o JOIN acme_certificates c ON c.id = o.acme_certificate_id
WHERE o.id = $1 AND c.deleted_at IS NULL`, orderID).Scan(&state, &certID, &providerID, &accountID)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return nil, ErrNotFound
	case err != nil:
		return nil, fmt.Errorf("inventory: read the ACME order: %w", err)
	case state != ACMEOrderRunning:
		return nil, ErrACMEOrderNotRunning
	}
	p, err := getACMEProvider(ctx, s.pool, providerID, false)
	if errors.Is(err, ErrNotFound) {
		return nil, ErrACMEAccountState
	}
	if err != nil {
		return nil, err
	}
	if p.ActiveAccountID == nil {
		return nil, ErrACMEAccountState
	}
	if *p.ActiveAccountID != accountID {
		if _, err := s.pool.Exec(ctx, "UPDATE acme_certificates SET account_id = $2, updated_at = $3 WHERE id = $1", certID, *p.ActiveAccountID,
			s.clock.Now().UTC()); err != nil {
			return nil, fmt.Errorf("inventory: move the ACME certificate to the active account: %w", err)
		}
	}
	signer, url, err := s.ACMEAccountSigner(ctx, *p.ActiveAccountID)
	if err != nil {
		return nil, err
	}
	return s.acmeClientFor(p, signer, url)
}

// RecordACMEOrderURL stores the CA's URL of a running order (acme.WithOnOrder), so a crash can be resumed.
func (s *Service) RecordACMEOrderURL(ctx context.Context, orderID uuid.UUID, url string) error {
	if len(url) > 2048 {
		return ErrACMEOrderNotRunning
	}
	tag, err := s.pool.Exec(ctx, "UPDATE acme_orders SET order_url = $2 WHERE id = $1 AND state = 'running'", orderID, url)
	if err != nil {
		return fmt.Errorf("inventory: record the ACME order's URL: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return ErrACMEOrderNotRunning
	}
	return nil
}

// ACMEPresented is one challenge record an order published (or is about to publish), with what publishes it: the
// hook (DNS-01) or the server (HTTP-01). It holds no secret: a DNS-01 value and an HTTP-01 key authorization are
// public by design (the CA and anyone can read them while they are published).
type ACMEPresented struct {
	Challenge solver.Challenge `json:"challenge"`
	HookID    *uuid.UUID       `json:"hook_id,omitempty"`
	TargetID  *uuid.UUID       `json:"target_id,omitempty"`
}

// AddACMEPresented appends a record to a running order's presented list in its own transaction, BEFORE the record
// is published (A12). ErrACMEOrderNotRunning for an order that ended.
func (s *Service) AddACMEPresented(ctx context.Context, orderID uuid.UUID, p ACMEPresented) error {
	b, err := json.Marshal([]ACMEPresented{p})
	if err != nil {
		return fmt.Errorf("inventory: encode the challenge record: %w", err)
	}
	tag, err := s.pool.Exec(ctx, "UPDATE acme_orders SET presented = presented || $2::jsonb WHERE id = $1 AND state = 'running'", orderID, string(b))
	if err != nil {
		return fmt.Errorf("inventory: record the challenge: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return ErrACMEOrderNotRunning
	}
	return nil
}

// RemoveACMEPresented takes a record out of an order's presented list once it was removed from the hook or server
// (running or ended: the freeze trigger lets the list shrink). A record that is not listed changes nothing.
func (s *Service) RemoveACMEPresented(ctx context.Context, orderID uuid.UUID, p ACMEPresented) error {
	b, err := json.Marshal(p)
	if err != nil {
		return fmt.Errorf("inventory: encode the challenge record: %w", err)
	}
	_, err = s.pool.Exec(ctx, `UPDATE acme_orders SET presented = COALESCE((SELECT jsonb_agg(e ORDER BY i)
    FROM jsonb_array_elements(presented) WITH ORDINALITY AS t(e, i) WHERE e <> $2::jsonb), '[]'::jsonb)
WHERE id = $1 AND presented @> jsonb_build_array($2::jsonb)`, orderID, string(b))
	if err != nil {
		return fmt.Errorf("inventory: forget the cleaned challenge: %w", err)
	}
	return nil
}

// SucceedACMETestOrder ends a running test order as succeeded (the authorizations were validated; nothing was
// issued) with the audit row acme.order.test_succeeded. The ACME certificate's state is not touched: a test run is
// not a renewal. ErrACMEOrderNotRunning for an issue order or one that ended; ErrNotFound.
func (s *Service) SucceedACMETestOrder(ctx context.Context, orderID uuid.UUID) error {
	return db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		var state, kind string
		var certID uuid.UUID
		err := tx.QueryRow(ctx, "SELECT state, kind, acme_certificate_id FROM acme_orders WHERE id = $1 FOR UPDATE", orderID).Scan(&state, &kind, &certID)
		switch {
		case errors.Is(err, pgx.ErrNoRows):
			return ErrNotFound
		case err != nil:
			return fmt.Errorf("inventory: read the ACME order: %w", err)
		case state != ACMEOrderRunning || kind != ACMEOrderTest:
			return ErrACMEOrderNotRunning
		}
		if _, err := tx.Exec(ctx, "UPDATE acme_orders SET state = 'succeeded', finished_at = $2 WHERE id = $1", orderID, s.clock.Now().UTC()); err != nil {
			return fmt.Errorf("inventory: finish the ACME test order: %w", err)
		}
		if err := s.enqueueCleanupTx(ctx, tx, orderID); err != nil {
			return err
		}
		_, err = s.audit.Append(ctx, tx, audit.Event{Actor: jobsActor, Action: "acme.order.test_succeeded", ObjectType: "acme_certificate",
			ObjectID: certID.String(), Result: audit.Success, Details: map[string]string{"order_id": orderID.String(),
				"acme_certificate_id": certID.String(), "kind": kind}})
		return err
	})
}

// FailACMEOrder ends a running order as failed with code (AbortACMEOrder: the pending key is deleted, audit
// acme.order.failed or acme.order.test_failed) and, in the same transaction, writes the ACME certificate's failure
// state. An issue order: failures + 1, state failing (stopped stays), last_error_code, last_attempt_at and
// next_attempt_at = now + max(ACMEFailureBackoff(failures), retryAfter capped at 24 h); from the third failure in a
// row of an issued certificate with automatic renewal on, the "renewal failed" e-mail goes once, and the fifth stops
// automatic renewal (state stopped, audit acme.auto_renew.stopped, one e-mail; renew.AfterFailure). A neutral code
// (renew.Neutral: the licence lock, an interrupted job) counts nothing: the order ends as AbandonACMEOrder ends it. A
// test run changes only next_attempt_at, and only to honour a CA's Retry-After (never earlier than it was). When
// records are still published, the acme.cleanup job is queued. An order that failed before only loses a leftover key
// (nothing else changes); ErrACMEOrderNotRunning for a succeeded order; ErrACMEErrorCode; ErrNotFound.
func (s *Service) FailACMEOrder(ctx context.Context, orderID uuid.UUID, code string, retryAfter time.Duration) error {
	if !errorCodeRE.MatchString(code) {
		return ErrACMEErrorCode
	}
	if renew.Neutral(code) {
		return s.AbandonACMEOrder(ctx, orderID, code)
	}
	retryAfter = min(max(retryAfter, 0), MaxACMEBackoff)
	return db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		ab, err := s.abortOrder(ctx, tx, orderID, code)
		if err != nil || !ab.ended {
			return err
		}
		now := s.clock.Now().UTC()
		if ab.kind == ACMEOrderIssue {
			if err := s.countACMEFailure(ctx, tx, ab.acmeCertificateID, code, retryAfter, now); err != nil {
				return err
			}
		} else if retryAfter > 0 {
			next := now.Add(retryAfter)
			if _, err := tx.Exec(ctx, `UPDATE acme_certificates SET next_attempt_at = GREATEST(COALESCE(next_attempt_at, $2), $2), updated_at = $3
WHERE id = $1`, ab.acmeCertificateID, next, now); err != nil {
				return fmt.Errorf("inventory: record the CA's wait: %w", err)
			}
		}
		return s.enqueueCleanupTx(ctx, tx, orderID)
	})
}

// AbandonACMEOrder ends a running order that was interrupted (a shutdown, a lost worker, a lock, a deleted definition,
// an order the CA never got far enough to finish) as failed with code, WITHOUT counting a failure: the pending key is
// deleted and the audit row written as by AbortACMEOrder, the ACME certificate's failures and next_attempt_at are not
// touched and an issue order's state goes back to what it says (stopped stays; failing with earlier failures; active
// with a current certificate; pending otherwise); the cleanup job is queued when records are left. Only a refusal by
// the CA or a failed validation is a failure (FailACMEOrder). ErrACMEOrderNotRunning for a succeeded order, ErrNotFound,
// ErrACMEErrorCode.
func (s *Service) AbandonACMEOrder(ctx context.Context, orderID uuid.UUID, code string) error {
	if !errorCodeRE.MatchString(code) {
		return ErrACMEErrorCode
	}
	return db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		ab, err := s.abortOrder(ctx, tx, orderID, code)
		if err != nil || !ab.ended {
			return err
		}
		if ab.kind == ACMEOrderIssue {
			if _, err := tx.Exec(ctx, `UPDATE acme_certificates SET state = CASE WHEN state = 'stopped' THEN 'stopped'
    WHEN failures > 0 THEN 'failing' WHEN current_certificate_id IS NOT NULL THEN 'active' ELSE 'pending' END, updated_at = $2
WHERE id = $1`, ab.acmeCertificateID, s.clock.Now().UTC()); err != nil {
				return fmt.Errorf("inventory: restore the ACME certificate's state: %w", err)
			}
		}
		return s.enqueueCleanupTx(ctx, tx, orderID)
	})
}

// enqueueCleanupTx queues the acme.cleanup job of an ended order whose presented list is not empty (dedupe
// acme.cleanup:<order>: a live job of the order answers again).
func (s *Service) enqueueCleanupTx(ctx context.Context, tx pgx.Tx, orderID uuid.UUID) error {
	var left int
	if err := tx.QueryRow(ctx, "SELECT jsonb_array_length(presented) FROM acme_orders WHERE id = $1 AND state <> 'running'", orderID).Scan(&left); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		return fmt.Errorf("inventory: read the ACME order's records: %w", err)
	}
	if left == 0 {
		return nil
	}
	_, err := s.jobs.EnqueueTx(ctx, tx, JobRequest{Type: JobACMECleanup, Payload: map[string]string{"order_id": orderID.String()},
		Kind: "system", DedupeKey: JobACMECleanup + ":" + orderID.String()})
	return err
}

// EnqueueACMECleanup queues the acme.cleanup job of an ended order that still lists published records (the acme.issue
// job calls it on every way out; nothing is queued for a running order or an empty list).
func (s *Service) EnqueueACMECleanup(ctx context.Context, orderID uuid.UUID) error {
	return db.InTx(ctx, s.pool, func(tx pgx.Tx) error { return s.enqueueCleanupTx(ctx, tx, orderID) })
}

// ACMECleanupWork is what the acme.cleanup job removes: the records an ended order still lists (Running true and no
// records for an order that still runs: its own job cleans up, or the sweep ends it first).
type ACMECleanupWork struct {
	ACMECertificateID uuid.UUID
	Running           bool
	Records           []ACMEPresented
}

// ACMECleanupWork reads an order's leftover records (ErrNotFound).
func (s *Service) ACMECleanupWork(ctx context.Context, orderID uuid.UUID) (ACMECleanupWork, error) {
	var w ACMECleanupWork
	var state string
	var raw []byte
	err := s.pool.QueryRow(ctx, "SELECT acme_certificate_id, state, presented FROM acme_orders WHERE id = $1", orderID).Scan(&w.ACMECertificateID, &state, &raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return w, ErrNotFound
	}
	if err != nil {
		return w, fmt.Errorf("inventory: read the ACME order's records: %w", err)
	}
	if state == ACMEOrderRunning {
		w.Running = true
		return w, nil
	}
	if err := json.Unmarshal(raw, &w.Records); err != nil {
		return w, fmt.Errorf("inventory: decode the ACME order's records: %w", err)
	}
	return w, nil
}

// RecordACMECleanup records a cleanup attempt of an ended order: when and with which failure ("" = every record is
// gone). The audit row acme.order.cleaned_up is written when the list became empty, acme.order.cleanup_failed when a
// final attempt (the job's last) left records behind; intermediate failures are only recorded on the order.
func (s *Service) RecordACMECleanup(ctx context.Context, orderID uuid.UUID, code string, final bool) error {
	if code != "" && !errorCodeRE.MatchString(code) {
		return ErrACMEErrorCode
	}
	return db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		var certID uuid.UUID
		var left int
		err := tx.QueryRow(ctx, `UPDATE acme_orders SET cleanup_at = $2, cleanup_error_code = $3 WHERE id = $1 AND state <> 'running'
RETURNING acme_certificate_id, jsonb_array_length(presented)`, orderID, s.clock.Now().UTC(), code).Scan(&certID, &left)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrACMEOrderNotRunning
		}
		if err != nil {
			return fmt.Errorf("inventory: record the cleanup of the ACME order: %w", err)
		}
		d := map[string]string{"order_id": orderID.String(), "acme_certificate_id": certID.String(), "records_count": strconv.Itoa(left)}
		switch {
		case left == 0 && code == "":
			_, err = s.audit.Append(ctx, tx, audit.Event{Actor: jobsActor, Action: "acme.order.cleaned_up", ObjectType: "acme_certificate",
				ObjectID: certID.String(), Result: audit.Success, Details: d})
		case final:
			d["error_code"] = code
			_, err = s.audit.Append(ctx, tx, audit.Event{Actor: jobsActor, Action: "acme.order.cleanup_failed", ObjectType: "acme_certificate",
				ObjectID: certID.String(), Result: audit.Failure, Details: d})
		}
		return err
	})
}

// ACMEStaleOrder is a running order no job runs any more (a crash, a lost worker).
type ACMEStaleOrder struct {
	ID        uuid.UUID
	Kind      string
	Names     []string
	OrderURL  string
	HasKey    bool
	StartedAt time.Time
	Presented int  // records still listed (published, or about to be)
	Deleted   bool // the ACME certificate was deleted
}

// maxACMESweepBatch bounds one sweep step.
const maxACMESweepBatch = 50

// StaleACMEOrders lists running orders started more than olderThan ago that no queued or running acme.issue job holds
// (a queued job still runs the order, a running one owns it), oldest first, at most 50: their job ended without ending
// them (a crash, a shutdown, a lost lease), or it is held in lock (blocked_license: an order is not kept waiting for an
// Administrator's confirmation; a confirmed job finds its order ended and does nothing).
func (s *Service) StaleACMEOrders(ctx context.Context, olderThan time.Duration) ([]ACMEStaleOrder, error) {
	rows, err := s.pool.Query(ctx, `SELECT o.id, o.kind, c.names, o.order_url, o.pending_key_ct IS NOT NULL, o.started_at,
    jsonb_array_length(o.presented), c.deleted_at IS NOT NULL
FROM acme_orders o JOIN acme_certificates c ON c.id = o.acme_certificate_id
WHERE o.state = 'running' AND o.started_at < $1
  AND NOT EXISTS (SELECT 1 FROM jobs j WHERE j.type = 'acme.issue' AND j.status IN ('queued', 'running')
                  AND j.payload->>'order_id' = o.id::text)
ORDER BY o.started_at, o.id LIMIT $2`, s.clock.Now().UTC().Add(-olderThan), maxACMESweepBatch)
	if err != nil {
		return nil, fmt.Errorf("inventory: list the stale ACME orders: %w", err)
	}
	defer rows.Close()
	var out []ACMEStaleOrder
	for rows.Next() {
		var o ACMEStaleOrder
		if err := rows.Scan(&o.ID, &o.Kind, &o.Names, &o.OrderURL, &o.HasKey, &o.StartedAt, &o.Presented, &o.Deleted); err != nil {
			return nil, fmt.Errorf("inventory: read a stale ACME order: %w", err)
		}
		out = append(out, o)
	}
	return out, rows.Err()
}

// EnqueueACMECleanups queues the acme.cleanup job of every ended order that still lists records, whose last cleanup
// attempt is older than retryAfter (or that never had one: a job lost before it ran) and that ended less than giveUpAfter
// ago (after that the records stay listed with the last failure on the order and its audit row acme.order.cleanup_failed:
// a hook or a server that is gone for good is not asked forever); at most 50 per call. It returns how many orders it
// asked for (a live job of an order answers again, dedupe).
func (s *Service) EnqueueACMECleanups(ctx context.Context, retryAfter, giveUpAfter time.Duration) (int, error) {
	n := 0
	err := db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT id FROM acme_orders WHERE state <> 'running' AND presented <> '[]'::jsonb
AND (cleanup_at IS NULL OR cleanup_at < $1) AND finished_at > $3 ORDER BY finished_at, id LIMIT $2`, s.clock.Now().UTC().Add(-retryAfter),
			maxACMESweepBatch, s.clock.Now().UTC().Add(-giveUpAfter))
		if err != nil {
			return fmt.Errorf("inventory: list the ACME orders to clean up: %w", err)
		}
		ids, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
		if err != nil {
			return fmt.Errorf("inventory: read the ACME orders to clean up: %w", err)
		}
		for _, id := range ids {
			if err := s.enqueueCleanupTx(ctx, tx, id); err != nil {
				return err
			}
			n++
		}
		return nil
	})
	return n, err
}

// ACMEFinishRefused reports whether an error of FinishACMEOrder refuses the chain or the order for good (the caller
// fails the order) rather than being a failure of the database, after which the order stays running with its key and
// the sweep finishes it from the CA (A8).
func ACMEFinishRefused(err error) bool {
	for _, r := range []error{ErrACMEChainMismatch, ErrACMEPendingKey, ErrACMEOrderNotRunning, ErrNotFound, errPendingKeySeal,
		certs.ErrTooLarge, certs.ErrKeyMismatch, certs.ErrExpired, certs.ErrKeyEncrypted, certs.ErrPFXPassword, certs.ErrWeak,
		certs.ErrUnsupportedKey, certs.ErrCSRMismatch, certs.ErrInvalid, certs.ErrNoKey} {
		if errors.Is(err, r) {
			return true
		}
	}
	return false
}

// ACMEOrderErrorCode is the closed code an order fails with for err, and the CA's Retry-After (capped at 24 h) when
// it is a rate limit. Only registered reasons come out (an acme reason, license.locked, a provider's code, a few
// inventory refusals, acme.order_abandoned or internal.unexpected); never a CA's or a database's text.
func ACMEOrderErrorCode(err error) (string, time.Duration) {
	var ie *ACMEError
	var ae *acme.Error
	var pe *providers.Error
	switch {
	case err == nil:
		return "internal.unexpected", 0
	case errors.Is(err, license.ErrLocked), errors.Is(err, license.ErrUnclassified):
		return ACMELicenseLocked, 0
	case errors.As(err, &ie):
		return ie.Reason, min(ie.RetryAfter, MaxACMEBackoff)
	case errors.As(err, &ae):
		reason := ae.Reason
		if !slices.Contains(acme.Reasons(), reason) {
			reason = acme.ReasonDirectoryInvalid
		}
		return reason, min(ae.RetryAfter(), MaxACMEBackoff)
	case errors.Is(err, ErrACMENameNotAllowed):
		return acme.ReasonNameNotAllowed, 0
	case errors.Is(err, ErrACMEChallengeUnavailable):
		return acme.ReasonChallengeUnavailable, 0
	case errors.Is(err, ErrACMEAccountState):
		return "acme.account_state", 0
	case errors.Is(err, ErrACMERolloverPending), errors.Is(err, ErrACMEProviderBusy):
		return "acme.rollover_pending", 0
	case errors.Is(err, ErrACMESecretUnreadable), errors.Is(err, errPendingKeySeal):
		return "acme.secret_unreadable", 0
	case errors.Is(err, keygen.ErrKeyPolicy):
		return acme.ReasonKeyPolicyNotAllowed, 0
	case errors.Is(err, ErrACMEPendingKey):
		return ACMEOrderAbandoned, 0
	case errors.Is(err, ErrNotFound):
		return "system.not_found", 0
	case ACMEFinishRefused(err), errors.Is(err, acme.ErrChainKeyMismatch):
		return acme.ReasonDirectoryInvalid, 0 // the CA's certificate does not fit the order
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return acme.ReasonNotIssuedInTime, 0
	case errors.As(err, &pe) && errorCodeRE.MatchString(pe.Code):
		return pe.Code, 0
	}
	return "internal.unexpected", 0
}
