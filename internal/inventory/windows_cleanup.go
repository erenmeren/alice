package inventory

import (
	"context"
	"crypto/sha1" //nolint:gosec // G505: a Windows thumbprint is the certificate's SHA-1, an identifier, not a security measure
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"alice/internal/audit"
	"alice/internal/platform/db"
	"alice/internal/providers"
)

// Alice's half of the Windows certificate cleanup (R62 W3, docs/superpowers/rulings/windows-iis.md Rulings 4, 8, 9, 12,
// 13). The helper decides what only the server knows (Alice imported the certificate, nothing on the server uses it, how
// long it has been unused); Alice decides what only Alice knows: no deployment may still roll back to it, no deployment
// is running with it, no location of the server still holds it, it is compromised (removed at once after its incident),
// and the server's switch. A certificate is removed only when both judges agree, the helper judging again at apply time.

// JobWindowsCleanup plans and applies the cleanup of one Windows server (payload: incident_id when an incident queued it;
// dedupe windows.cleanup:<target>:<unix day> for the daily run, windows.cleanup:<target>:incident:<incident>:<location>
// for an incident's, one per settled place). The handler is internal/jobs/winjobs.
const JobWindowsCleanup = "windows.cleanup"

// CleanupRollbackWindow is how long after a finished deployment its new and previous certificates stay on the server
// for a rollback (Ruling 8; §15 Q6).
const CleanupRollbackWindow = 7 * 24 * time.Hour

// CleanupMaxItems is the most certificates one apply removes (the helper's winproto.MaxCleanupItems); the next day's run
// takes the rest.
const CleanupMaxItems = 256

// TemplateWindowsCompromisedInStore tells the server's and the certificate's services that a compromised certificate is
// still in a machine store after its incident's cleanup (Ruling 9): params target_name, certificate_name, store,
// thumbprint, and incident_id, by which it is queued once per incident and certificate.
const TemplateWindowsCompromisedInStore = "windows.compromised_in_store"

// The reasons Alice keeps a candidate the helper would remove (CleanupKept.Reason).
const (
	CleanupKeptRollbackWindow    = "rollback_window"    // a deployment of the server finished less than CleanupRollbackWindow ago with it
	CleanupKeptDeploymentRunning = "deployment_running" // an unfinished deployment of the server names it
	CleanupKeptLocationHolds     = "location_holds"     // a location of the server (not missing) holds it or had it deployed last
	CleanupKeptSwitchOff         = "cleanup_off"        // the server's certificate_cleanup switch is off
)

// CleanupKept is a candidate Alice keeps, by its DER SHA-256, and why.
type CleanupKept struct{ SHA256, Reason string }

// CleanupDecision is Alice's judgement of a plan: the certificates to remove (compromised ones first, at most
// CleanupMaxItems) and the candidates she keeps. A candidate the helper does not find eligible yet is in neither.
type CleanupDecision struct {
	Remove []providers.CleanupItem
	Kept   []CleanupKept
}

// CleanupWatch returns the certificates the server's plan reports on (Ruling 9): every compromised certificate a
// deployment of the server names (new or previous) or a location of the server holds or had deployed last, each once,
// the newest compromise first, at most providers.MaxForbidden. Each is named by its thumbprint (the SHA-1 of the DER of
// its stored chain's first block) and its DER SHA-256.
func (s *Service) CleanupWatch(ctx context.Context, target uuid.UUID) ([]providers.CleanupRef, error) {
	rows, err := s.pool.Query(ctx, `SELECT c.fingerprint_sha256, c.pem_chain FROM certificates c
WHERE c.compromised_at IS NOT NULL AND c.fingerprint_sha256 IN (
    SELECT d.new_fingerprint FROM deployments d WHERE d.target_id = $1
    UNION SELECT d.previous_fingerprint FROM deployments d WHERE d.target_id = $1
    UNION SELECT l.deployed_fingerprint FROM certificate_locations l WHERE l.target_id = $1
    UNION SELECT lc.fingerprint_sha256 FROM certificate_locations l JOIN certificates lc ON lc.id = l.certificate_id WHERE l.target_id = $1)
ORDER BY c.compromised_at DESC, c.fingerprint_sha256 LIMIT $2`, target, providers.MaxForbidden)
	if err != nil {
		return nil, fmt.Errorf("inventory: read the compromised certificates of the server: %w", err)
	}
	type row struct{ fp, chain string }
	list, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (row, error) {
		var x row
		return x, r.Scan(&x.fp, &x.chain)
	})
	if err != nil {
		return nil, fmt.Errorf("inventory: read the compromised certificates of the server: %w", err)
	}
	out := make([]providers.CleanupRef, 0, len(list))
	for _, x := range list {
		b, _ := pem.Decode([]byte(x.chain))
		if b == nil {
			continue // no DER to name it by: never stored so (uploads and scans store a parsed chain)
		}
		sum := sha1.Sum(b.Bytes) //nolint:gosec // G401: see the import
		out = append(out, providers.CleanupRef{SHA1: hex.EncodeToString(sum[:]), SHA256: x.fp})
	}
	return out, nil
}

// cleanupFacts is what Alice knows about the certificates of one plan on one server.
type cleanupFacts struct {
	enabled     bool
	compromised map[string]bool // DER SHA-256s Alice holds as compromised
	running     map[string]bool // named by an unfinished deployment of the server
	recent      map[string]bool // named by a deployment of the server finished within CleanupRollbackWindow
	held        map[string]bool // held or last deployed by a location of the server that is not missing
}

// JudgeCleanup is Alice's judgement of a plan of the server (Rulings 8, 9, 13), candidate by candidate in the plan's
// order: with the switch off every candidate (and every removable compromised watched certificate) is kept cleanup_off;
// a compromised certificate the helper finds removable (a candidate, eligible or not yet, or a watched certificate) is
// removed at once with reason incident unless an unfinished deployment of the server names it; any other candidate the
// helper finds eligible is removed with the helper's reason unless an unfinished deployment names it, a location holds
// it, or a deployment finished less than CleanupRollbackWindow ago named it. Compromised certificates go first; at most
// CleanupMaxItems. ErrNotFound when the server is gone.
func (s *Service) JudgeCleanup(ctx context.Context, target uuid.UUID, plan providers.CleanupPlan) (CleanupDecision, error) {
	var d CleanupDecision
	f, err := s.cleanupFacts(ctx, target, plan)
	if err != nil {
		return d, err
	}
	var incident, aged []providers.CleanupItem
	queued := func(store, sha256 string) bool {
		return slices.ContainsFunc(incident, func(it providers.CleanupItem) bool {
			return it.SHA256 == sha256 && strings.EqualFold(it.Store, store)
		})
	}
	for _, c := range plan.Candidates {
		item := providers.CleanupItem{Store: c.Store, SHA1: c.SHA1, SHA256: c.SHA256}
		switch {
		case !f.enabled:
			d.Kept = append(d.Kept, CleanupKept{SHA256: c.SHA256, Reason: CleanupKeptSwitchOff})
		case f.compromised[c.SHA256] && f.running[c.SHA256]:
			d.Kept = append(d.Kept, CleanupKept{SHA256: c.SHA256, Reason: CleanupKeptDeploymentRunning})
		case f.compromised[c.SHA256]:
			item.Reason = providers.CleanupIncident
			incident = append(incident, item)
		case c.Eligible == "":
			// the helper's own wait (Ruling 8: the age is its clock's)
		case f.running[c.SHA256]:
			d.Kept = append(d.Kept, CleanupKept{SHA256: c.SHA256, Reason: CleanupKeptDeploymentRunning})
		case f.held[c.SHA256]:
			d.Kept = append(d.Kept, CleanupKept{SHA256: c.SHA256, Reason: CleanupKeptLocationHolds})
		case f.recent[c.SHA256]:
			d.Kept = append(d.Kept, CleanupKept{SHA256: c.SHA256, Reason: CleanupKeptRollbackWindow})
		default:
			item.Reason = c.Eligible
			aged = append(aged, item)
		}
	}
	for _, w := range plan.Watched {
		if w.State != providers.WatchRemovable || !f.compromised[w.SHA256] || slices.ContainsFunc(plan.Candidates, func(c providers.CleanupCertificate) bool {
			return c.SHA256 == w.SHA256 && strings.EqualFold(c.Store, w.Store)
		}) {
			continue
		}
		switch {
		case !f.enabled:
			d.Kept = append(d.Kept, CleanupKept{SHA256: w.SHA256, Reason: CleanupKeptSwitchOff})
		case f.running[w.SHA256]:
			d.Kept = append(d.Kept, CleanupKept{SHA256: w.SHA256, Reason: CleanupKeptDeploymentRunning})
		case !queued(w.Store, w.SHA256):
			incident = append(incident, providers.CleanupItem{Store: w.Store, SHA1: w.SHA1, SHA256: w.SHA256, Reason: providers.CleanupIncident})
		}
	}
	d.Remove = append(incident, aged...)
	if len(d.Remove) > CleanupMaxItems {
		d.Remove = d.Remove[:CleanupMaxItems]
	}
	return d, nil
}

// cleanupFacts reads the server's switch and what Alice knows about the plan's certificates.
func (s *Service) cleanupFacts(ctx context.Context, target uuid.UUID, plan providers.CleanupPlan) (cleanupFacts, error) {
	f := cleanupFacts{compromised: map[string]bool{}, running: map[string]bool{}, recent: map[string]bool{}, held: map[string]bool{}}
	err := s.pool.QueryRow(ctx, "SELECT certificate_cleanup FROM targets WHERE id = $1 AND deleted_at IS NULL", target).Scan(&f.enabled)
	if errors.Is(err, pgx.ErrNoRows) {
		return f, ErrNotFound
	}
	if err != nil {
		return f, fmt.Errorf("inventory: read the server's cleanup switch: %w", err)
	}
	fps := make([]string, 0, len(plan.Candidates)+len(plan.Watched))
	for _, c := range plan.Candidates {
		fps = append(fps, c.SHA256)
	}
	for _, w := range plan.Watched {
		fps = append(fps, w.SHA256)
	}
	since := s.clock.Now().UTC().Add(-CleanupRollbackWindow)
	rows, err := s.pool.Query(ctx, `SELECT x.fp,
    EXISTS (SELECT 1 FROM certificates c WHERE c.fingerprint_sha256 = x.fp AND c.compromised_at IS NOT NULL),
    EXISTS (SELECT 1 FROM deployments d WHERE d.target_id = $1 AND d.state <> 'done' AND x.fp IN (d.new_fingerprint, d.previous_fingerprint)),
    EXISTS (SELECT 1 FROM deployments d WHERE d.target_id = $1 AND d.state = 'done' AND d.finished_at > $3
            AND x.fp IN (d.new_fingerprint, d.previous_fingerprint)),
    EXISTS (SELECT 1 FROM certificate_locations l LEFT JOIN certificates lc ON lc.id = l.certificate_id
            WHERE l.target_id = $1 AND l.missing_since IS NULL AND (l.deployed_fingerprint = x.fp OR lc.fingerprint_sha256 = x.fp))
FROM unnest($2::text[]) AS x (fp) GROUP BY x.fp`, target, fps, since)
	if err != nil {
		return f, fmt.Errorf("inventory: read what Alice knows of the server's certificates: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var fp string
		var comp, run, rec, held bool
		if err := rows.Scan(&fp, &comp, &run, &rec, &held); err != nil {
			return f, fmt.Errorf("inventory: read what Alice knows of the server's certificates: %w", err)
		}
		f.compromised[fp], f.running[fp], f.recent[fp], f.held[fp] = comp, run, rec, held
	}
	if err := rows.Err(); err != nil {
		return f, fmt.Errorf("inventory: read what Alice knows of the server's certificates: %w", err)
	}
	return f, nil
}

// RecordCleanup records one cleanup of the server in one transaction: an audit row windows.certificate_removed (actor
// jobs; store, sha1, sha256, reason, and incident_id for an incident's job) for every certificate the apply removed;
// and, for an incident's job only (Ruling 9), one notice TemplateWindowsCompromisedInStore per watched compromised
// certificate that is still in a store afterwards (the helper kept it: not Alice's, or still used; or it was removable
// and not removed), to the server's and the certificate's services, at most once per incident and certificate
// (compromisedInStore), and only when no place of the incident on the server is still open (pending or deploying). A
// scheduled job tells nobody. Removals are recorded in every case.
func (s *Service) RecordCleanup(ctx context.Context, target uuid.UUID, incident *uuid.UUID, plan providers.CleanupPlan, d CleanupDecision,
	res providers.CleanupApplyResult) error {
	return db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		var gone []providers.CleanupItem // what the apply removed or found absent
		for i, r := range res.Results {
			if i >= len(d.Remove) || r.SHA256 != d.Remove[i].SHA256 {
				return fmt.Errorf("inventory: the apply's results do not match its items")
			}
			it := d.Remove[i]
			if r.Result != providers.CleanupRemoved && r.Result != providers.CleanupAbsent {
				continue
			}
			gone = append(gone, it)
			if r.Result != providers.CleanupRemoved {
				continue
			}
			details := map[string]string{"store": it.Store, "sha1": it.SHA1, "sha256": it.SHA256, "reason": it.Reason}
			if incident != nil {
				details["incident_id"] = incident.String()
			}
			if _, err := s.audit.Append(ctx, tx, audit.Event{Actor: jobsActor, Action: "windows.certificate_removed", ObjectType: "target",
				ObjectID: target.String(), Result: audit.Success, Details: details}); err != nil {
				return err
			}
		}
		if incident == nil || s.notifier == nil {
			return nil
		}
		// A place of the incident on this server that is still open (its deployment unfinished) may keep the certificate
		// in use: the job queued when the last place settles is the one that reports.
		var open bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM certificate_incident_locations il JOIN certificate_locations l ON l.id = il.location_id
WHERE il.incident_id = $1 AND l.target_id = $2 AND il.status = ANY ($3))`, *incident, target,
			[]string{IncidentLocationPending, IncidentLocationDeploying}).Scan(&open); err != nil {
			return fmt.Errorf("inventory: read the incident's open places: %w", err)
		}
		if open {
			return nil
		}
		var order []string
		stores := map[string][]string{}
		thumbs := map[string]string{}
		for _, w := range plan.Watched {
			removed := slices.ContainsFunc(gone, func(it providers.CleanupItem) bool {
				return it.SHA256 == w.SHA256 && strings.EqualFold(it.Store, w.Store)
			})
			stays := w.State == providers.WatchKept || (w.State == providers.WatchRemovable && !removed)
			if !stays {
				continue
			}
			if _, seen := stores[w.SHA256]; !seen {
				order = append(order, w.SHA256)
			}
			stores[w.SHA256], thumbs[w.SHA256] = append(stores[w.SHA256], w.Store), w.SHA1
		}
		for _, fp := range order {
			if err := s.compromisedInStore(ctx, tx, target, *incident, fp, strings.Join(stores[fp], ", "), thumbs[fp]); err != nil {
				return err
			}
		}
		return nil
	})
}

// compromisedInStore queues the notice about one compromised certificate still in a store of the server, once per
// incident and certificate: a second cleanup of the same incident (another place on the server settled after the first
// job ended) finds the notice already in the outbox by its incident_id and thumbprint, as the key preview e-mail finds
// its last one (sshkeys lastPreviewMail).
func (s *Service) compromisedInStore(ctx context.Context, tx pgx.Tx, target, incident uuid.UUID, fp, store, thumbprint string) error {
	var told bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM notifications_outbox WHERE template_key = $1 AND params->>'incident_id' = $2
    AND params->>'thumbprint' = $3)`, TemplateWindowsCompromisedInStore, incident.String(), thumbprint).Scan(&told); err != nil {
		return fmt.Errorf("inventory: read whether the incident's notice was queued: %w", err)
	}
	if told {
		return nil
	}
	var name string
	if err := tx.QueryRow(ctx, "SELECT name::text FROM targets WHERE id = $1", target).Scan(&name); err != nil {
		return fmt.Errorf("inventory: read the server's name: %w", err)
	}
	var certName string
	err := tx.QueryRow(ctx, `SELECT coalesce(nullif(label, ''), nullif(subject_cn, ''), left(fingerprint_sha256, 16)) FROM certificates
WHERE fingerprint_sha256 = $1`, fp).Scan(&certName)
	if errors.Is(err, pgx.ErrNoRows) {
		certName = fp[:min(16, len(fp))]
	} else if err != nil {
		return fmt.Errorf("inventory: read the certificate's name: %w", err)
	}
	svcs, err := targetServices(ctx, tx, target)
	if err != nil {
		return err
	}
	certSvcs, err := servicesOf(ctx, tx, "SELECT service_id FROM certificates WHERE fingerprint_sha256 = $1", fp)
	if err != nil {
		return err
	}
	for _, id := range certSvcs {
		if !slices.Contains(svcs, id) {
			svcs = append(svcs, id)
		}
	}
	params := map[string]string{"target_name": truncRunes(name, 200), "certificate_name": truncRunes(strings.TrimSpace(certName), 200),
		"store": store, "thumbprint": thumbprint, "incident_id": incident.String()}
	return s.notifier.NotifyServices(ctx, tx, svcs, TemplateWindowsCompromisedInStore, params)
}

// cleanupScheduleBatch bounds the servers one run of the schedule queues (the next hourly run takes the rest).
const cleanupScheduleBatch = 500

// ScheduleWindowsCleanup queues the daily windows.cleanup of every connected Windows server with the cleanup capability
// for which no windows.cleanup job (a daily or an incident's) was created in the last 24 hours (Ruling 13; job
// windows.cleanup_schedule, ClassReadOnly: it only queues, and pauses in lock). The dedupe key names the server and the
// UTC day. Disabled servers, servers whose host key changed or is unconfirmed, unreachable ones and Linux servers are
// never queued. It returns how many jobs it queued.
func (s *Service) ScheduleWindowsCleanup(ctx context.Context) (int, error) {
	now := s.clock.Now().UTC()
	n := 0
	err := db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		n = 0
		rows, err := tx.Query(ctx, `SELECT t.id FROM targets t
WHERE t.deleted_at IS NULL AND t.type = $1 AND t.status = $2 AND $3 = ANY (t.capabilities)
  AND NOT EXISTS (SELECT 1 FROM jobs j WHERE j.target_id = t.id AND j.type = $4 AND j.created_at > $5)
ORDER BY t.id LIMIT $6 FOR UPDATE OF t SKIP LOCKED`, TypeWindows, StatusOK, string(providers.CapCleanupCertificates), JobWindowsCleanup,
			now.Add(-24*time.Hour), cleanupScheduleBatch)
		if err != nil {
			return fmt.Errorf("inventory: find the Windows servers to clean up: %w", err)
		}
		ids, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
		if err != nil {
			return fmt.Errorf("inventory: find the Windows servers to clean up: %w", err)
		}
		for _, id := range ids {
			if _, err := s.jobs.EnqueueTx(ctx, tx, JobRequest{Type: JobWindowsCleanup, TargetID: id, Payload: map[string]string{}, Kind: "scheduled",
				DedupeKey: fmt.Sprintf("%s:%s:%d", JobWindowsCleanup, id, now.Unix()/86400)}); err != nil {
				return err
			}
			n++
		}
		return nil
	})
	return n, err
}

// queueIncidentCleanupTx queues, in the caller's transaction, the windows.cleanup of the server of an incident's place
// that has just settled, when the place is an http.sys binding on a server with the cleanup capability (Ruling 9; as
// ScheduleWindowsCleanup): payload incident_id. The dedupe key names the place
// (windows.cleanup:<target>:incident:<incident>:<location>), so a job already running for an earlier place of the server
// never absorbs a later place's: the job queued after the last settlement sees every place settled.
func (s *Service) queueIncidentCleanupTx(ctx context.Context, tx pgx.Tx, incident, location uuid.UUID) error {
	var target uuid.UUID
	var kind providers.LocationKind
	var capable bool
	if err := tx.QueryRow(ctx, `SELECT l.target_id, l.kind, $2 = ANY (t.capabilities) FROM certificate_locations l
JOIN targets t ON t.id = l.target_id WHERE l.id = $1`, location, string(providers.CapCleanupCertificates)).Scan(&target, &kind, &capable); err != nil {
		return fmt.Errorf("inventory: read the incident's place: %w", err)
	}
	if kind != providers.LocationWinSSLBinding || !capable {
		return nil
	}
	_, err := s.jobs.EnqueueTx(ctx, tx, JobRequest{Type: JobWindowsCleanup, TargetID: target, Payload: map[string]string{"incident_id": incident.String()},
		Kind: "system", DedupeKey: fmt.Sprintf("%s:%s:incident:%s:%s", JobWindowsCleanup, target, incident, location)})
	return err
}
