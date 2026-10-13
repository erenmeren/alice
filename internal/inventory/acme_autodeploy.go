package inventory

// Automatic deployment of ACME certificates (plan 2026-10-13 Task 12; design row 7; amendment A2): the transactional
// half. planACMEAutoDeploy (acme_autodeploy_plan.go) decides; this file reads one ACME certificate under its row lock,
// applies the plan in the same transaction and writes the marks that make every notice and every stop happen once. It
// copies the Key Vault planner (kv_autodeploy.go): the licence gate first (nothing in lock), candidates chosen without
// a lock, then one transaction per certificate that takes its row with SKIP LOCKED (a certificate a person or another
// planner is changing is planned at the next run), so the planner is idempotent and several processes may run it at
// once; deployments_one_active is the backstop.
//
// ONE deploy path (A2, Review Focus 2): the planner creates a deployment only through prepareACMEDeployment, which runs
// readDeployCertificate, lockDeployTargets (targets then locations, id order) and checkDeployLocation exactly as the Key
// Vault planner and RequestDeployment do, and then the same insertDeployment as a person's request (trigger
// acme_renewal, the system actor jobs, a certificate.deploy job). The deployment engine (deployjobs) runs it, records
// its steps and writes the deployment.* audit rows; a failed deployment is rolled back by the engine and its failure is
// mailed by the engine (deployment.failed). Nothing here talks to a server.

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"alice/internal/audit"
	"alice/internal/license"
	"alice/internal/platform/db"
)

// TriggerACMERenewal is the trigger of a deployment the ACME planner created (deployments.trigger, migration 00013).
const TriggerACMERenewal = "acme_renewal"

// ACME automatic deployment notices (Task 12). Params: name (the certificate's first name), names (every name,
// comma-separated, bounded); the stop notice also count (the failed deployments) and error_reason (the closed reason of
// the last counted failure: notify.Sender renders it as the plain title of the code in the reader's language).
const (
	TemplateACMEAutoDeployStopped     = "acme.auto_deploy_stopped"
	TemplateACMEAutoDeployHeldLicense = "acme.auto_deploy_held_license"
	TemplateACMEAutoDeployHeldChain   = "acme.auto_deploy_held_chain"
)

// ACMEDeployTemplates lists the ACME automatic deployment e-mails (render tests).
func ACMEDeployTemplates() []string {
	return []string{TemplateACMEAutoDeployStopped, TemplateACMEAutoDeployHeldLicense, TemplateACMEAutoDeployHeldChain}
}

// acmeDeployPage is the size of a page of candidate certificates (the run reads every page until the batch is used).
var acmeDeployPage = 200

// ACMEDeployRun counts what one run of the planner did.
type ACMEDeployRun struct {
	// Created: deployments created; Held: certificates newly held for an Administrator; Stopped: waves stopped.
	Created, Held, Stopped int
}

// acmeDeployHook runs after a certificate's candidate was read and before its transaction (tests: the world changes).
var acmeDeployHook func(id uuid.UUID)

// acmeDeployInsertHook runs before a location's deployment is inserted (tests: a competing deployment appears).
var acmeDeployInsertHook func(location uuid.UUID)

// PlanACMEAutoDeploy runs the planner once over the ACME certificates that may have work and returns what it did (at most
// autoDeployBatch, 50, deployments in all; AutoDeployWave per certificate). It does nothing while the licence gate
// refuses changes (license.Allow(ClassChange) first; the gate is read again inside each certificate's transaction). A
// certificate whose planning failed is skipped for this run; the others are still planned and the errors are returned
// together. Audit rows: acme.auto_deploy.held, acme.auto_deploy.stopped (and the engine's deployment.requested).
func (s *Service) PlanACMEAutoDeploy(ctx context.Context) (ACMEDeployRun, error) {
	var run ACMEDeployRun
	if s.license.Allow(license.ClassChange) != nil {
		return run, nil
	}
	reopened, err := s.gateReopenedAt(ctx) // once per run
	if err != nil {
		return run, err
	}
	var errs []error
	after := uuid.Nil
	for run.Created < autoDeployBatch {
		ids, err := s.acmeDeployCandidates(ctx, after)
		if err != nil {
			return run, errors.Join(append(errs, err)...)
		}
		if len(ids) == 0 {
			break
		}
		after = ids[len(ids)-1]
		for _, id := range ids {
			if run.Created >= autoDeployBatch {
				break
			}
			if acmeDeployHook != nil {
				acmeDeployHook(id)
			}
			if err := s.planACMEDeploy(ctx, id, reopened, &run); err != nil {
				if errors.Is(err, ErrClaimLost) || ctx.Err() != nil {
					return run, errors.Join(append(errs, err)...)
				}
				errs = append(errs, err)
			}
		}
		if len(ids) < acmeDeployPage {
			break
		}
	}
	return run, errors.Join(errs...)
}

// acmeDeployCandidates lists, in id order after the cursor, the live ACME certificates with automatic deployment on and a
// current certificate that is neither held (unless released) nor stopped, with a bound location of a live server that
// either needs the current certificate (automatic deployment on, it does not serve it and did not get it) or carries an
// attention mark (which may need clearing).
func (s *Service) acmeDeployCandidates(ctx context.Context, after uuid.UUID) ([]uuid.UUID, error) {
	rows, err := s.pool.Query(ctx, `SELECT c.id FROM acme_certificates c
WHERE c.deleted_at IS NULL AND c.auto_deploy AND c.current_certificate_id IS NOT NULL AND c.id > $2
  AND (c.deploy_held_certificate_id IS DISTINCT FROM c.current_certificate_id OR c.deploy_released_certificate_id = c.current_certificate_id)
  AND EXISTS (SELECT 1 FROM acme_bindings b JOIN certificate_locations l ON l.id = b.location_id
              JOIN targets t ON t.id = l.target_id AND t.deleted_at IS NULL
              WHERE b.acme_certificate_id = c.id AND (b.attention_at IS NOT NULL OR (b.auto_deploy
                AND c.deploy_stopped_certificate_id IS DISTINCT FROM c.current_certificate_id
                AND l.certificate_id IS DISTINCT FROM c.current_certificate_id
                AND NOT EXISTS (SELECT 1 FROM deployments d WHERE d.location_id = l.id AND d.certificate_id = c.current_certificate_id
                                AND d.status IN ('succeeded', 'unchanged')))))
ORDER BY c.id LIMIT $1`, acmeDeployPage, after)
	if err != nil {
		return nil, fmt.Errorf("inventory: find the ACME certificates to deploy: %w", err)
	}
	ids, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
	if err != nil {
		return nil, fmt.Errorf("inventory: find the ACME certificates to deploy: %w", err)
	}
	return ids, nil
}

// errACMEDeploySkip rolls back a certificate's transaction without an error (the next run plans it again).
var errACMEDeploySkip = errors.New("inventory: the ACME certificate is planned at the next run")

// planACMEDeploy plans one ACME certificate in one transaction (see the file comment).
func (s *Service) planACMEDeploy(ctx context.Context, id uuid.UUID, reopened *time.Time, run *ACMEDeployRun) error {
	var created, held, stopped int
	err := db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		created, held, stopped = 0, 0, 0
		if err := checkClaim(ctx, tx); err != nil {
			return err
		}
		var locked uuid.UUID
		err := tx.QueryRow(ctx, "SELECT id FROM acme_certificates WHERE id = $1 AND deleted_at IS NULL FOR UPDATE SKIP LOCKED", id).Scan(&locked)
		if errors.Is(err, pgx.ErrNoRows) {
			return errACMEDeploySkip // deleted, or busy: the next run
		}
		if err != nil {
			return fmt.Errorf("inventory: lock the ACME certificate: %w", err)
		}
		// The gate is read again here: the licence may have locked since the run began.
		if s.license.Allow(license.ClassChange) != nil {
			return errACMEDeploySkip
		}
		now := s.clock.Now().UTC()
		sn, names, err := readACMEDeploySnapshot(ctx, tx, id, now)
		if err != nil {
			return err
		}
		sn.gateOpen, sn.reopened, sn.remaining = true, reopened, autoDeployBatch-run.Created
		p := planACMEAutoDeploy(sn)

		for _, m := range p.attention {
			if _, err := tx.Exec(ctx, `UPDATE acme_bindings SET attention_code = $3, attention_at = CASE WHEN $3 = '' THEN NULL ELSE $4::timestamptz END
WHERE acme_certificate_id = $1 AND location_id = $2`, id, m.location, m.code, now); err != nil {
				return fmt.Errorf("inventory: mark the binding: %w", err)
			}
		}
		if p.hold != "" {
			_, deployable, err := s.prepareACMEDeployment(ctx, tx, sn.current.id, p.candidate, 0, now)
			if err != nil || deployable == 0 {
				return err // nothing could be deployed now: nothing is held and nothing is said
			}
			ok, err := s.holdACMEDeploy(ctx, tx, id, sn.current.id, p.hold, names, reopened)
			if err != nil {
				return err
			}
			if ok {
				held = 1
			}
		}
		if len(p.deploy) > 0 && p.budget > 0 {
			if created, _, err = s.prepareACMEDeployment(ctx, tx, sn.current.id, p.deploy, p.budget, now); err != nil {
				return err
			}
		}
		if p.stop != nil {
			ok, err := s.stopACMEDeploy(ctx, tx, id, sn.current.id, names, p.stop.failed, p.stopCode)
			if err != nil {
				return err
			}
			if ok {
				stopped = 1
			}
		}
		return nil
	})
	if errors.Is(err, errACMEDeploySkip) {
		return nil
	}
	if err == nil {
		run.Created += created
		run.Held += held
		run.Stopped += stopped
	}
	return err
}

// readACMEDeploySnapshot reads what planACMEAutoDeploy needs about the locked certificate, in statements of their own (a
// fresh snapshot after the lock), and its names. issuedAt (what the licence rule compares with the time the gate last
// reopened) is when the current certificate became current: the end of the succeeded order that produced it, or the
// certificate row's creation when no order names it.
func readACMEDeploySnapshot(ctx context.Context, tx pgx.Tx, id uuid.UUID, now time.Time) (acmeDeploySnapshot, []string, error) {
	sn := acmeDeploySnapshot{now: now}
	var (
		names                     []string
		current, heldID, released *uuid.UUID
		stoppedID                 *uuid.UUID
	)
	err := tx.QueryRow(ctx, `SELECT auto_deploy, names, current_certificate_id, deploy_held_certificate_id, deploy_held_reason,
    deploy_released_certificate_id, deploy_stopped_certificate_id FROM acme_certificates WHERE id = $1`, id).
		Scan(&sn.autoDeploy, &names, &current, &heldID, &sn.heldReason, &released, &stoppedID)
	if err != nil {
		return sn, nil, fmt.Errorf("inventory: read the ACME certificate's deployment state: %w", err)
	}
	if current == nil {
		return sn, names, nil
	}
	same := func(p *uuid.UUID) bool { return p != nil && *p == *current }
	if !same(heldID) {
		sn.heldReason = ""
	}
	sn.released, sn.stopped = same(released), same(stoppedID)
	c := acmeDeployCert{id: *current}
	err = tx.QueryRow(ctx, `SELECT x.not_before, x.not_after, x.chain_complete, COALESCE((SELECT max(o.finished_at) FROM acme_orders o
    WHERE o.acme_certificate_id = $2 AND o.certificate_id = x.id AND o.state = 'succeeded'), x.created_at)
FROM certificates x WHERE x.id = $1`, c.id, id).Scan(&c.notBefore, &c.notAfter, &c.chainComplete, &c.issuedAt)
	if err != nil {
		return sn, nil, fmt.Errorf("inventory: read the current certificate: %w", err)
	}
	c.notBefore, c.notAfter, c.issuedAt = c.notBefore.UTC(), c.notAfter.UTC(), c.issuedAt.UTC()
	sn.current = &c

	rows, err := tx.Query(ctx, `SELECT b.location_id, b.auto_deploy, b.created_at, l.certificate_id, b.attention_code
FROM acme_bindings b JOIN certificate_locations l ON l.id = b.location_id
JOIN targets t ON t.id = l.target_id AND t.deleted_at IS NULL
WHERE b.acme_certificate_id = $1 ORDER BY b.location_id`, id)
	if err != nil {
		return sn, nil, fmt.Errorf("inventory: read the bindings: %w", err)
	}
	sn.bindings, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (acmeDeployBinding, error) {
		var b acmeDeployBinding
		err := r.Scan(&b.location, &b.autoDeploy, &b.createdAt, &b.served, &b.attentionCode)
		b.createdAt = b.createdAt.UTC()
		return b, err
	})
	if err != nil {
		return sn, nil, fmt.Errorf("inventory: read the bindings: %w", err)
	}
	locs := make([]uuid.UUID, 0, len(sn.bindings))
	for _, b := range sn.bindings {
		locs = append(locs, b.location)
	}
	rows, err = tx.Query(ctx, `SELECT d.location_id, d.certificate_id, d.trigger = $3, d.state = 'done', d.status, d.error_code, d.created_at, d.finished_at
FROM deployments d WHERE d.location_id = ANY($1) AND (d.state <> 'done' OR d.certificate_id = $2) ORDER BY d.created_at, d.id`, locs, c.id, TriggerACMERenewal)
	if err != nil {
		return sn, nil, fmt.Errorf("inventory: read the deployments: %w", err)
	}
	sn.deployments, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (acmeDeployment, error) {
		var d acmeDeployment
		err := r.Scan(&d.location, &d.certificate, &d.automatic, &d.done, &d.status, &d.errorCode, &d.createdAt, &d.finishedAt)
		d.createdAt, d.finishedAt = d.createdAt.UTC(), utcPtr(d.finishedAt)
		return d, err
	})
	if err != nil {
		return sn, nil, fmt.Errorf("inventory: read the deployments: %w", err)
	}
	return sn, names, nil
}

// prepareACMEDeployment is the ONLY way the ACME planner reaches insertDeployment (A2; a test walks the syntax tree to
// hold it so). It runs, in tx and in this order, what a person's RequestDeployment and the Key Vault planner run:
// readDeployCertificate (and the certificate's own refusals as an Operator's request gets them: no private key, a key
// type Alice cannot deploy, expired, not yet valid, an incomplete chain, which is never confirmed here),
// lockDeployTargets (the servers, then the locations, id order), and per location checkDeployLocation (a server that is
// ready, no recovery pending on it, no unfinished deployment of the location, the key type, a supported path); then
// insertDeployment with trigger acme_renewal and the system actor, in a savepoint per location (a refusal of the insert
// aborts only that location). It creates at most budget deployments and also reports how many of the locations passed
// the checks (budget 0: the checks only, for a hold). A location that vanished or whose server was deleted ends the
// attempt without an error (the next run sees it gone).
func (s *Service) prepareACMEDeployment(ctx context.Context, tx pgx.Tx, certificate uuid.UUID, locations []uuid.UUID, budget int,
	now time.Time) (created, deployable int, err error) {
	c, err := readDeployCertificate(ctx, tx, certificate)
	if err != nil {
		return 0, 0, err
	}
	if c.keyID == nil || (c.algorithm != "rsa" && c.algorithm != "ecdsa") || !now.Before(c.notAfter) || now.Before(c.notBefore) {
		return 0, 0, nil
	}
	if !c.chainComplete {
		budget = 0 // an incomplete chain needs an Administrator's confirmation, which the planner never gives
	}
	targets, locs, err := s.lockDeployTargets(ctx, tx, locations)
	if errors.Is(err, ErrNotFound) {
		s.log.Debug("automatic deployment skipped: a location or its server is gone", "certificate_id", certificate)
		return 0, 0, nil
	}
	if err != nil {
		return 0, 0, err
	}
	a := Actor{Audit: jobsActor}
	src := deploySource{Trigger: TriggerACMERenewal}
	for _, id := range locations {
		l := locs[id]
		if _, err := s.checkDeployLocation(ctx, tx, c, l, targets[l.target]); err != nil {
			continue // no person asked: no audit row, the location is simply not ready
		}
		deployable++
		if created >= budget {
			continue
		}
		if acmeDeployInsertHook != nil {
			acmeDeployInsertHook(id)
		}
		sp, err := tx.Begin(ctx)
		if err != nil {
			return created, deployable, fmt.Errorf("inventory: open a savepoint: %w", err)
		}
		if _, err := s.insertDeployment(ctx, sp, a, c, l, src, now); err != nil {
			_ = sp.Rollback(ctx)
			if errors.Is(err, ErrDeploymentInProgress) {
				continue
			}
			return created, deployable, err
		}
		if err := sp.Commit(ctx); err != nil {
			return created, deployable, fmt.Errorf("inventory: release a savepoint: %w", err)
		}
		created++
	}
	return created, deployable, nil
}

// holdACMEDeploy holds the current certificate for an Administrator (the column is the once-only mark): audit
// acme.auto_deploy.held and one e-mail. It reports false when it was held already.
func (s *Service) holdACMEDeploy(ctx context.Context, tx pgx.Tx, id, current uuid.UUID, reason string, names []string, reopened *time.Time) (bool, error) {
	tag, err := tx.Exec(ctx, `UPDATE acme_certificates SET deploy_held_certificate_id = $2, deploy_held_reason = $3
WHERE id = $1 AND deploy_held_certificate_id IS DISTINCT FROM $2`, id, current, reason)
	if err != nil {
		return false, fmt.Errorf("inventory: hold the certificate: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return false, nil
	}
	details := map[string]string{"acme_certificate_id": id.String(), "certificate_id": current.String(),
		"names": truncRunes(strings.Join(names, ","), maxAuditNames), "reason": reason}
	tpl := TemplateACMEAutoDeployHeldChain
	if reason == ACMEHoldLicense {
		tpl = TemplateACMEAutoDeployHeldLicense
		details["hold_rule"] = HoldRuleDetectedBeforeReopening
		if reopened != nil {
			details["reopened_at"] = reopened.UTC().Format(time.RFC3339)
		}
	}
	if _, err := s.audit.Append(ctx, tx, audit.Event{Actor: jobsActor, Action: "acme.auto_deploy.held", ObjectType: "acme_certificate",
		ObjectID: id.String(), Result: audit.Success, Details: details}); err != nil {
		return false, err
	}
	if s.notifier != nil {
		if err := s.notifier.NotifyAdmins(ctx, tx, tpl, acmeDeployParams(names)); err != nil {
			return false, fmt.Errorf("inventory: queue the hold notice: %w", err)
		}
	}
	return true, nil
}

// stopACMEDeploy stops the automatic deployments of the current certificate (the column is the once-only mark): audit
// acme.auto_deploy.stopped and one e-mail. It reports false when it was stopped already.
func (s *Service) stopACMEDeploy(ctx context.Context, tx pgx.Tx, id, current uuid.UUID, names []string, failed int, code string) (bool, error) {
	tag, err := tx.Exec(ctx, `UPDATE acme_certificates SET deploy_stopped_certificate_id = $2
WHERE id = $1 AND deploy_stopped_certificate_id IS DISTINCT FROM $2`, id, current)
	if err != nil {
		return false, fmt.Errorf("inventory: stop the automatic deployments: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return false, nil
	}
	if _, err := s.audit.Append(ctx, tx, audit.Event{Actor: jobsActor, Action: "acme.auto_deploy.stopped", ObjectType: "acme_certificate",
		ObjectID: id.String(), Result: audit.Success, Details: map[string]string{"acme_certificate_id": id.String(), "certificate_id": current.String(),
			"names": truncRunes(strings.Join(names, ","), maxAuditNames), "failed_count": strconv.Itoa(failed), "error_code": code}}); err != nil {
		return false, err
	}
	if s.notifier != nil {
		p := acmeDeployParams(names)
		p["count"], p["error_reason"] = strconv.Itoa(failed), code
		if err := s.notifier.NotifyAdmins(ctx, tx, TemplateACMEAutoDeployStopped, p); err != nil {
			return false, fmt.Errorf("inventory: queue the stop notice: %w", err)
		}
	}
	return true, nil
}

// acmeDeployParams are the params every automatic deployment e-mail has.
func acmeDeployParams(names []string) map[string]string {
	p := map[string]string{"names": truncRunes(strings.Join(names, ", "), acmeNoticeNames)}
	if len(names) > 0 {
		p["name"] = names[0]
	}
	return p
}

// Refusals of a queued automatic ACME deployment when its job runs (acmeDeployPrecheck): the state the planner queued it
// in no longer holds. The engine ends the deployment with the matching closed reason before it contacts the server; the
// planner treats every one of them as neutral (NeutralDeploymentReasons).
var (
	// ErrACMEBindingGone: the location no longer follows the ACME certificate (the binding was removed, the definition
	// deleted, or the location now follows another certificate).
	ErrACMEBindingGone = errors.New("inventory: the location no longer follows the ACME certificate")
	// ErrACMEAutoDeployOff: automatic deployment of the ACME certificate or of the binding was switched off.
	ErrACMEAutoDeployOff = errors.New("inventory: automatic deployment of the ACME certificate was switched off")
	// ErrACMESuperseded: a newer certificate replaced the one the deployment was queued for.
	ErrACMESuperseded = errors.New("inventory: the ACME certificate was renewed again since the deployment was queued")
	// ErrACMEDeployStopped: the automatic deployments of the certificate stopped after failures.
	ErrACMEDeployStopped = errors.New("inventory: the automatic deployments of the certificate stopped")
	// ErrACMEDeployHeld: the certificate is held for an Administrator.
	ErrACMEDeployHeld = errors.New("inventory: the certificate is held for an Administrator")
)

// Closed reasons of those refusals (deployments.error_code; neutral for the planner).
const (
	ReasonACMEBindingGone   = "acme.binding_gone"
	ReasonACMEAutoDeployOff = "acme.auto_deploy_off"
	ReasonACMESuperseded    = "acme.certificate_superseded"
	ReasonACMEDeployStopped = "acme.deploy_stopped"
	ReasonACMEDeployHeld    = "acme.deploy_held"
)

// acmeDeployPrecheck judges a queued automatic ACME deployment (trigger acme_renewal) again when its job is about to send:
// the location must still follow an ACME certificate whose certificates include the deployed one, automatic deployment
// must be on for the certificate and the binding, the deployed certificate must still be the current one, and its
// automatic deployments must be neither stopped nor held (unless released). One statement; read-only.
func (s *Service) acmeDeployPrecheck(ctx context.Context, d Deployment) error {
	var (
		live, certAuto, bindAuto, ours bool
		current, held, released        *uuid.UUID
		stopped                        *uuid.UUID
		reason                         string
	)
	err := s.pool.QueryRow(ctx, `SELECT c.deleted_at IS NULL, c.auto_deploy, b.auto_deploy, c.current_certificate_id, c.deploy_held_certificate_id,
    c.deploy_held_reason, c.deploy_released_certificate_id, c.deploy_stopped_certificate_id,
    c.current_certificate_id = $2 OR EXISTS (SELECT 1 FROM acme_orders o WHERE o.acme_certificate_id = c.id AND o.certificate_id = $2)
FROM acme_bindings b JOIN acme_certificates c ON c.id = b.acme_certificate_id WHERE b.location_id = $1`, d.LocationID, d.CertificateID).
		Scan(&live, &certAuto, &bindAuto, &current, &held, &reason, &released, &stopped, &ours)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrACMEBindingGone
	}
	if err != nil {
		return fmt.Errorf("inventory: judge the automatic deployment again: %w", err)
	}
	is := func(p *uuid.UUID) bool { return p != nil && *p == d.CertificateID }
	switch {
	case !live || !ours:
		return ErrACMEBindingGone
	case !certAuto || !bindAuto:
		return ErrACMEAutoDeployOff
	case !is(current):
		return ErrACMESuperseded
	case is(stopped):
		return ErrACMEDeployStopped
	case is(held) && (reason != ACMEHoldLicense || !is(released)):
		return ErrACMEDeployHeld
	}
	return nil
}
