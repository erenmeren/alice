package inventory

// The observation of bound locations (R52 item 3): the periodic drift.schedule (ScheduleDriftObservations, read-only
// work) queues one drift.observe job per server whose bound locations are due; the job (internal/jobs/targetjobs) scans
// the server's certificate files through the discovery path (Discover with certificates only, then Reconcile: the file
// observation), probes each due location's websites through the deployment engine's verification (VerifyDeployment
// with the desired certificate: the TLS observation, from Alice or from the server itself, with the R51 trust) and
// stores what it saw (RecordDriftObservations), which starts and ends drift episodes and sends their notices. Nothing
// here changes a server.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"alice/internal/audit"
	"alice/internal/platform/db"
	"alice/internal/providers"
)

// JobDriftObserve observes the bound locations of one server (payload empty; dedupe "drift.observe:<target id>": at
// most one live observation per server).
const JobDriftObserve = "drift.observe"

// boundLocationWhere selects the bound locations (an ACME binding or a Key Vault binding) of l.
const boundLocationWhere = `(l.binding_id IS NOT NULL OR EXISTS (SELECT 1 FROM acme_bindings b WHERE b.location_id = l.id))`

// ScheduleDriftObservations queues a drift.observe job for every server with a bound location whose observation is due
// (next_observe_at passed, or never observed), at most driftScheduleBatch locations per run, oldest due first, and
// stamps the next observation of each (DriftObserveInterval later, spread by the location's id over a tenth of the
// interval), in the transaction that queues the job: whatever the job's outcome, the location waits a full interval.
// Only connected or unreachable servers are observed (an unreachable server's probe records why it is unreachable); a
// location with an unfinished deployment waits for it. It also removes the observation rows of locations that no
// longer follow a binding. It returns how many jobs it queued.
func (s *Service) ScheduleDriftObservations(ctx context.Context) (int, error) {
	now := s.clock.Now().UTC()
	queued := 0
	err := db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		queued = 0
		if _, err := tx.Exec(ctx, `DELETE FROM location_observations o WHERE NOT EXISTS (SELECT 1 FROM certificate_locations l
WHERE l.id = o.location_id AND `+boundLocationWhere+`)`); err != nil {
			return fmt.Errorf("inventory: remove the observations of unbound locations: %w", err)
		}
		rows, err := tx.Query(ctx, `SELECT l.id, l.target_id FROM certificate_locations l
JOIN targets t ON t.id = l.target_id AND t.deleted_at IS NULL AND t.status = ANY($3)
LEFT JOIN location_observations o ON o.location_id = l.id
WHERE l.missing_since IS NULL AND `+boundLocationWhere+`
  AND (o.next_observe_at IS NULL OR o.next_observe_at <= $1)
  AND NOT EXISTS (SELECT 1 FROM deployments d WHERE d.location_id = l.id AND d.state <> 'done')
ORDER BY o.next_observe_at NULLS FIRST, l.id LIMIT $2`, now, driftScheduleBatch, []string{StatusOK, StatusUnreachable})
		if err != nil {
			return fmt.Errorf("inventory: find the locations to observe: %w", err)
		}
		type due struct{ location, target uuid.UUID }
		list, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (due, error) {
			var d due
			return d, r.Scan(&d.location, &d.target)
		})
		if err != nil {
			return fmt.Errorf("inventory: find the locations to observe: %w", err)
		}
		perTarget := map[uuid.UUID]int{}
		for _, d := range list {
			if perTarget[d.target] >= driftProbesPerTarget {
				continue // the next run takes it
			}
			if perTarget[d.target] == 0 {
				if _, err := s.jobs.EnqueueTx(ctx, tx, JobRequest{Type: JobDriftObserve, TargetID: d.target, Payload: map[string]string{},
					Kind: "scheduled", DedupeKey: JobDriftObserve + ":" + d.target.String()}); err != nil {
					return err
				}
				queued++
			}
			perTarget[d.target]++
			next := now.Add(DriftObserveInterval + driftSpread(d.location))
			if _, err := tx.Exec(ctx, `INSERT INTO location_observations (location_id, next_observe_at, updated_at) VALUES ($1, $2, $3)
ON CONFLICT (location_id) DO UPDATE SET next_observe_at = EXCLUDED.next_observe_at, updated_at = EXCLUDED.updated_at`, d.location, next, now); err != nil {
				return fmt.Errorf("inventory: stamp the next observation: %w", err)
			}
		}
		return nil
	})
	return queued, err
}

// driftSpread is a location's fixed offset within a tenth of DriftObserveInterval (from its id), so the locations bound
// at the same moment are observed at different times from then on.
func driftSpread(id uuid.UUID) time.Duration {
	n := int64(id[14])<<8 | int64(id[15])
	return time.Duration(n%int64((DriftObserveInterval/10)/time.Second)) * time.Second
}

// DriftProbe is one location an observation job probes: the verification request of its desired certificate.
type DriftProbe struct {
	LocationID uuid.UUID
	Request    providers.VerifyRequest
}

// DriftProbes returns what an observation job of the server probes: its bound locations that are not missing and have
// a desired certificate, longest unprobed first, at most driftProbesPerTarget. Each request expects the desired leaf
// (the deployment engine's verification: every endpoint of the location, from Alice where Alice's probe reaches the
// listen, else from the server itself) with no chain length, its SANs and key type, the location's verification
// settings, and the trust policy of the desired chain (R51: the system roots, with the issuing ACME authority's CA
// bundle).
func (s *Service) DriftProbes(ctx context.Context, target uuid.UUID) ([]DriftProbe, error) {
	rows, err := s.pool.Query(ctx, `SELECT l.id, l.cert_path, l.key_path, l.servers, l.verify_port, coalesce(l.verify_sni, ''), l.skip_verify,
    dc.fingerprint_sha256, dc.sans, dc.key_algorithm, dc.pem_chain,
    (SELECT p.ca_bundle_pem FROM acme_orders ao JOIN acme_certificates ac ON ac.id = ao.acme_certificate_id
     JOIN acme_providers p ON p.id = ac.provider_id WHERE ao.certificate_id = dc.id ORDER BY ao.finished_at DESC NULLS LAST LIMIT 1)
FROM certificate_locations l
`+driftSourceJoin+`
JOIN certificates dc ON dc.id = src.cert_id
LEFT JOIN location_observations o ON o.location_id = l.id
WHERE l.target_id = $1 AND l.missing_since IS NULL
ORDER BY o.tls_attempted_at NULLS FIRST, l.id LIMIT $2`, target, driftProbesPerTarget)
	if err != nil {
		return nil, fmt.Errorf("inventory: read the locations to probe: %w", err)
	}
	defer rows.Close()
	now := s.clock.Now().UTC()
	var out []DriftProbe
	for rows.Next() {
		var (
			p            DriftProbe
			servers      []byte
			port         *int
			chain, alg   string
			bundle       *string
			req          = &p.Request
			loc          = &req.Location
			verifyPort   int
			fingerprints string
		)
		if err := rows.Scan(&p.LocationID, &loc.CertPath, &loc.KeyPath, &servers, &port, &req.Verify.SNI, &req.Verify.Skip, &fingerprints,
			&req.SANs, &alg, &chain, &bundle); err != nil {
			return nil, fmt.Errorf("inventory: read a location to probe: %w", err)
		}
		if err := json.Unmarshal(servers, &loc.Servers); err != nil {
			return nil, fmt.Errorf("inventory: decode location servers: %w", err)
		}
		if port != nil {
			verifyPort = *port
		}
		req.Verify.Port, req.Fingerprint, loc.Supported = verifyPort, fingerprints, true
		if alg == "rsa" || alg == "ecdsa" {
			req.KeyType = alg
		}
		roots, store := s.roots, providers.TrustStoreSystem
		if bundle != nil && strings.TrimSpace(*bundle) != "" {
			roots, store = s.rootsWith(*bundle), providers.TrustStoreACME
		}
		if c := pemChain([]byte(chain)); roots != nil && len(c) > 0 {
			tp := providers.TrustPolicyFor(c, roots, store, now)
			req.Trust = &tp
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// DriftResult is what one probe of a location found (DriftResultOf builds it from the verification).
type DriftResult struct {
	LocationID uuid.UUID
	At         time.Time
	// Skipped: the location's verification is switched off; nothing is known of the website.
	Skipped bool
	// Reached: an endpoint completed a handshake; Served is the leaf of the first endpoint that did not serve the desired
	// certificate, else the desired one.
	Reached           bool
	Served            string
	Probe             string // DriftProbeAlice | DriftProbeHelper
	Level             int
	Trust, TrustError string
	// Error is the closed reason of a probe that completed no handshake (deployment.verify_unreachable, or the
	// provider's code when the server could not be used).
	Error string
}

// driftErrorRE is the shape location_observations.tls_error takes.
var driftErrorRE = regexp.MustCompile(`^[a-z][a-z0-9_.]{0,79}$`)

// DriftResultOf turns one verification of location's desired certificate (DriftProbes' request) at at into its result:
// a provider error (the SSH connection failed during a server-side probe) and a verification that completed no
// handshake are failures with their closed reason; a skipped verification is skipped; otherwise the website was
// reached and Served is what it served (a failed verification's served leaf; the desired one for a pass and for a
// served chain whose trust failed, whose trust is kept).
func DriftResultOf(location uuid.UUID, req providers.VerifyRequest, vr providers.VerifyResult, err error, at time.Time) DriftResult {
	r := DriftResult{LocationID: location, At: at.UTC()}
	var pe *providers.Error
	switch {
	case err != nil && errors.As(err, &pe) && driftErrorRE.MatchString(pe.Code):
		r.Error = pe.Code
		return r
	case err != nil:
		r.Error = "internal.unexpected"
		return r
	case vr.Mode == "skipped":
		r.Skipped = true
		return r
	case vr.Failure == providers.VerifyFailureNetwork || (!vr.OK && vr.Failure == "" && !hex64RE.MatchString(vr.Served)):
		r.Error = "deployment.verify_unreachable"
		return r
	}
	r.Reached, r.Probe = true, DriftProbeAlice
	if vr.Mode == "local" {
		r.Probe = DriftProbeHelper
	}
	switch {
	case vr.OK:
		r.Served, r.Level = req.Fingerprint, vr.Level
	case vr.Failure == providers.VerifyFailureTrust:
		r.Served = req.Fingerprint
	default:
		r.Served = hexFingerprint(vr.Served)
	}
	if vr.Trust.Status == providers.TrustUntrusted && vr.Trust.Error != "" {
		r.Trust, r.TrustError = providers.TrustUntrusted, vr.Trust.Error
	} else if vr.Trust.Status == providers.TrustTrusted || vr.Trust.Status == providers.TrustUnchecked {
		r.Trust = vr.Trust.Status
	}
	return r
}

// RecordDriftObservations stores what an observation job of target saw (one result per probed location; a result of a
// location on another server, or of a location no longer bound, is dropped) and then, per location, the transition its
// health makes (in one transaction per location, under the observation row's lock):
//   - drifted, no episode yet: the episode starts (drift_since, the leaf found and the observation that found it;
//     audit location.drift_detected); the notice goes at once in mode observe (TemplateDriftDetected) and approve
//     (TemplateDriftRepairReady); in mode auto the repair planner acts first;
//   - drifted, an episode in mode auto older than DriftAutoNoticeAfter: TemplateDriftDetected (no repair ended it);
//   - in sync: the desired certificate is remembered as seen in sync; an episode ends (audit location.drift_resolved),
//     with TemplateDriftRepaired when an automatic repair of the episode succeeded.
//
// Every notice is in the alerts ledger, once per episode. It returns how many locations drifted now.
func (s *Service) RecordDriftObservations(ctx context.Context, target uuid.UUID, results []DriftResult) (int, error) {
	drifted := 0
	var errs []error
	for _, r := range results {
		d, err := s.recordDriftObservation(ctx, target, r)
		if err != nil {
			if errors.Is(err, ErrClaimLost) || ctx.Err() != nil {
				return drifted, errors.Join(append(errs, err)...)
			}
			errs = append(errs, err)
			continue
		}
		if d {
			drifted++
		}
	}
	return drifted, errors.Join(errs...)
}

func (s *Service) recordDriftObservation(ctx context.Context, target uuid.UUID, r DriftResult) (bool, error) {
	drifted := false
	err := db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		drifted = false
		if err := checkClaim(ctx, tx); err != nil {
			return err
		}
		var on uuid.UUID
		err := tx.QueryRow(ctx, "SELECT l.target_id FROM certificate_locations l WHERE l.id = $1 AND "+boundLocationWhere, r.LocationID).Scan(&on)
		if errors.Is(err, pgx.ErrNoRows) || (err == nil && on != target) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("inventory: read the observed location: %w", err)
		}
		now := s.clock.Now().UTC()
		if _, err := tx.Exec(ctx, `INSERT INTO location_observations (location_id, updated_at) VALUES ($1, $2) ON CONFLICT (location_id) DO NOTHING`,
			r.LocationID, now); err != nil {
			return fmt.Errorf("inventory: prepare the location's observations: %w", err)
		}
		if _, err := tx.Exec(ctx, "SELECT 1 FROM location_observations WHERE location_id = $1 FOR UPDATE", r.LocationID); err != nil {
			return fmt.Errorf("inventory: lock the location's observations: %w", err)
		}
		switch {
		case r.Skipped:
			_, err = tx.Exec(ctx, "UPDATE location_observations SET tls_attempted_at = $2, tls_error = '', updated_at = $3 WHERE location_id = $1",
				r.LocationID, r.At, now)
		case !r.Reached:
			code := r.Error
			if !driftErrorRE.MatchString(code) {
				code = "internal.unexpected"
			}
			_, err = tx.Exec(ctx, "UPDATE location_observations SET tls_attempted_at = $2, tls_error = $3, updated_at = $4 WHERE location_id = $1",
				r.LocationID, r.At, code, now)
		default:
			trust, trustErr := r.Trust, r.TrustError
			if trust != providers.TrustUntrusted {
				trustErr = ""
			}
			_, err = tx.Exec(ctx, `UPDATE location_observations SET tls_attempted_at = $2, tls_error = '', tls_observed_at = $2, tls_fingerprint = $3,
    tls_probe = $4, tls_level = $5, tls_trust = $6, tls_trust_error = $7, updated_at = $8 WHERE location_id = $1`,
				r.LocationID, r.At, hexFingerprint(r.Served), r.Probe, min(max(r.Level, 0), providers.LevelHealthy), trust, trustErr, now)
		}
		if err != nil {
			return fmt.Errorf("inventory: store the observation: %w", err)
		}
		m, err := s.locationObservations(ctx, tx, []uuid.UUID{r.LocationID})
		if err != nil {
			return err
		}
		o := m[r.LocationID]
		drifted = o.Health == HealthDrifted
		return s.driftTransition(ctx, tx, o, now)
	})
	return drifted, err
}

// driftTransition writes the transition o's health makes (see RecordDriftObservations).
func (s *Service) driftTransition(ctx context.Context, tx pgx.Tx, o LocationObservation, now time.Time) error {
	switch o.Health {
	case HealthDrifted:
		if o.DriftSince != nil {
			if o.Mode == DriftModeAuto && !now.Before(o.DriftSince.Add(DriftAutoNoticeAfter)) {
				return s.driftNotice(ctx, tx, driftKind, TemplateDriftDetected, o, *o.DriftSince, o.DriftFingerprint)
			}
			return nil
		}
		fp, source := o.observedDrift()
		fp = hexFingerprint(fp)
		if _, err := tx.Exec(ctx, `UPDATE location_observations SET drift_since = $2, drift_fingerprint = $3, drift_source = $4, updated_at = $2
WHERE location_id = $1`, o.LocationID, now, fp, source); err != nil {
			return fmt.Errorf("inventory: start the drift: %w", err)
		}
		if _, err := s.audit.Append(ctx, tx, audit.Event{Actor: jobsActor, Action: "location.drift_detected", ObjectType: "certificate_location",
			ObjectID: o.LocationID.String(), Result: audit.Success, Details: map[string]string{"location_id": o.LocationID.String(),
				"target_id": o.TargetID.String(), "cert_path": o.certPath, "desired_fingerprint": o.Desired.Fingerprint, "observed_fingerprint": fp,
				"observed_by": source, "mode": o.Mode}}); err != nil {
			return err
		}
		switch o.Mode {
		case DriftModeObserve:
			return s.driftNotice(ctx, tx, driftKind, TemplateDriftDetected, o, now, fp)
		case DriftModeApprove:
			return s.driftNotice(ctx, tx, driftKind, TemplateDriftRepairReady, o, now, fp)
		}
		return nil
	case HealthInSync:
		if _, err := tx.Exec(ctx, `UPDATE location_observations SET in_sync_fingerprint = $2, in_sync_at = $3, drift_since = NULL, drift_fingerprint = '',
    drift_source = '', updated_at = $3 WHERE location_id = $1`, o.LocationID, o.Desired.Fingerprint, now); err != nil {
			return fmt.Errorf("inventory: record the location in sync: %w", err)
		}
		if o.DriftSince == nil {
			return nil
		}
		var repaired bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM deployments WHERE location_id = $1 AND trigger = $2 AND status IN ('succeeded', 'unchanged')
    AND created_at >= $3)`, o.LocationID, TriggerDriftRepair, *o.DriftSince).Scan(&repaired); err != nil {
			return fmt.Errorf("inventory: read the location's repairs: %w", err)
		}
		if _, err := s.audit.Append(ctx, tx, audit.Event{Actor: jobsActor, Action: "location.drift_resolved", ObjectType: "certificate_location",
			ObjectID: o.LocationID.String(), Result: audit.Success, Details: map[string]string{"location_id": o.LocationID.String(),
				"target_id": o.TargetID.String(), "cert_path": o.certPath, "drift_since": o.DriftSince.UTC().Format(time.RFC3339),
				"repaired_automatically": fmt.Sprint(repaired)}}); err != nil {
			return err
		}
		if repaired {
			return s.driftNotice(ctx, tx, driftRepairedKind, TemplateDriftRepaired, o, *o.DriftSince, o.DriftFingerprint)
		}
	}
	return nil
}
