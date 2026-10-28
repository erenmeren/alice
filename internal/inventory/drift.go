package inventory

// What should be there, what Alice last deployed and what is observed today (R52, owner decision 2026-10-21,
// docs/superpowers/rulings/certificate-drift.md).
//
// A bound location (a certificate file that follows an ACME certificate or a Key Vault binding) has four facts, kept
// apart and each with its own time:
//   - the desired certificate: the binding's (the ACME certificate's current certificate, the binding's current vault
//     version);
//   - the last deployment: the newest succeeded or unchanged deployment to the location (deployments,
//     certificate_locations.deployed_fingerprint) and the level its verification proved (R51);
//   - the file: the certificate the last scan read in the file (certificate_locations.certificate_id) and when a scan
//     last read the file's content (file_observed_at, never last_seen_at, which also moves when a scan could not read
//     it), with the scan's own judgement that someone outside Alice changed it (changed_outside_at);
//   - the website: the certificate the endpoints served at the last probe that completed a handshake
//     (location_observations.tls_*: when, from Alice or from the server itself through the helper, the level and the
//     trust of the served chain), and the last probe attempt with its failure.
//
// The location's health is derived from these, never from a past success alone (locationHealth): a newer observation
// that disagrees with the desired certificate makes it drifted whatever Alice deployed before. The observation task
// (drift_observe.go) refreshes the file and the website, the repair planner (drift_repair.go) repairs what drifted in
// mode auto through the deployment engine.

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"alice/internal/audit"
	"alice/internal/platform/db"
	"alice/internal/platform/validate"
	"alice/internal/providers"
)

// Health of a bound location (LocationObservation.Health).
const (
	// HealthInSync: the newest observations agree with the desired certificate and one of them (or the deployment
	// that put it there) is younger than DriftStaleAfter.
	HealthInSync = "in_sync"
	// HealthDrifted: the location had the desired certificate (Alice deployed it or saw it there) and an observation
	// newer than that deployment disagrees: the website serves another certificate, or a scan found another one in the
	// file that Alice did not put there.
	HealthDrifted = "drifted"
	// HealthPending: a deployment to the location is running, or the desired certificate has not reached it yet (a
	// renewal that is not deployed, a binding made a moment ago).
	HealthPending = "pending"
	// HealthUnreachable: the last probe of the website completed no handshake (and is newer than the last one that did).
	HealthUnreachable = "unreachable"
	// HealthStale: nothing newer than DriftStaleAfter says what the location holds.
	HealthStale = "stale"
	// HealthUnmanaged: the location follows no binding (or the binding has no current certificate): nothing is
	// desired, so nothing drifts.
	HealthUnmanaged = "unmanaged"
)

// HealthStates lists the health values in the order the API documents them.
var HealthStates = []string{HealthInSync, HealthDrifted, HealthPending, HealthUnreachable, HealthStale, HealthUnmanaged}

// Repair modes of a bound location (location_observations.drift_mode; R52 item 4).
const (
	// DriftModeObserve: a drift is reported and mailed; nothing is changed.
	DriftModeObserve = "observe"
	// DriftModeApprove: a drift is reported with the repair prepared; a person starts it with one action (RepairDrift).
	DriftModeApprove = "approve"
	// DriftModeAuto: Alice repairs a drift through the deployment engine (a certificate.deploy_auto job, trigger
	// drift_repair) and backs off after DriftMaxRepairs repairs in DriftRepairWindow.
	DriftModeAuto = "auto"
	// DriftModeDefault is what SetDriftMode takes to go back to the default (auto when automatic deployment is on for
	// the binding, observe otherwise).
	DriftModeDefault = "default"
)

// Sources of a desired certificate (LocationObservation.Source).
const (
	DriftSourceACME     = "acme"
	DriftSourceKeyVault = "key_vault"
)

// Back-off reasons of an automatic repair (LocationObservation.BackoffReason).
const (
	// BackoffFlapping: DriftMaxRepairs repairs within DriftRepairWindow succeeded and the drift came back each time:
	// another tool keeps changing the file.
	BackoffFlapping = "flapping"
	// BackoffRepairFailing: DriftMaxRepairs repairs within DriftRepairWindow failed.
	BackoffRepairFailing = "repair_failing"
)

// Causes of a drifted Windows binding (LocationObservation.Cause; R62 Ruling 15): derived from the binding's problems,
// never stored.
const (
	// DriftCauseRepointed: the binding names another certificate than the desired one (someone bound another one).
	DriftCauseRepointed = "binding_repointed"
	// DriftCauseCertRemoved: the binding names a certificate its store no longer holds (problem cert_missing).
	DriftCauseCertRemoved = "cert_removed"
	// DriftCauseKeyUnusable: the store holds the certificate without a key http.sys can use (a key problem).
	DriftCauseKeyUnusable = "key_unusable"
)

// Problems of a Windows binding the drift rules read (the Windows provider's ProblemCertMissing, ProblemKeyMissing and
// ProblemKeyInaccessible; inventory may not import the provider). problemCertMissing is locations.go's.
const (
	problemKeyMissing      = "key_missing"
	problemKeyInaccessible = "key_inaccessible"
)

// warnAutoCertRebind is the Windows server's facts warning that its AutoCertRebind task is on (winproto.WarnAutoCertRebind:
// on a renewal by autoenrolment Windows re-points the bindings itself, design §6.2 item 4, §11).
const warnAutoCertRebind = "win_autocertrebind"

// warnRDPAutoenroll is the RDP listener's location warning that a policy autoenrols its certificate
// (winproto.WarnRDPAutoenroll, W6 Ruling 5): the likely cause when the listener drifts.
const warnRDPAutoenroll = "win_rdp_autoenroll"

// windowsBinding reports a kind the drift rules treat as an http.sys binding: the binding, and the RDP listener (W6
// Ruling 21: its certificate lives in My and its key must be usable, as a binding's).
func windowsBinding(kind providers.LocationKind) bool {
	return kind == providers.LocationWinSSLBinding || kind == providers.LocationWinRDP
}

// bindingBroken reports whether a location of kind with these problems is a Windows binding whose certificate left its
// store or whose key http.sys cannot use (R62 Ruling 14), or such an RDP listener (W6 Ruling 21). Never true for any
// other kind.
func bindingBroken(kind providers.LocationKind, problem, keyProblem string) bool {
	return windowsBinding(kind) &&
		(problem == problemCertMissing || keyProblem == problemKeyMissing || keyProblem == problemKeyInaccessible)
}

// driftCause is the cause of a drifted Windows binding (R62 Ruling 15): cert_removed (problem cert_missing),
// key_unusable (any key problem), else binding_repointed; "" for a location that is not drifted or not a Windows binding
// (the RDP listener is one, W6 Ruling 21).
func driftCause(kind providers.LocationKind, health, problem, keyProblem string) string {
	switch {
	case !windowsBinding(kind) || health != HealthDrifted:
		return ""
	case problem == problemCertMissing:
		return DriftCauseCertRemoved
	case keyProblem != "":
		return DriftCauseKeyUnusable
	}
	return DriftCauseRepointed
}

// driftRepairable reports whether a drift of this cause can be repaired by deploying the desired certificate again: not
// when the certificate left the store or its key is unusable (the binding is unsupported; R62 Ruling 14).
func driftRepairable(cause string) bool {
	return cause != DriftCauseCertRemoved && cause != DriftCauseKeyUnusable
}

// TriggerDriftRepair is the trigger of an automatic repair's deployment (deployments.trigger, migration 00027).
const TriggerDriftRepair = "drift_repair"

// Timings and bounds of the drift work (ruling of R52).
const (
	// DriftObserveInterval is how often a bound location is observed (a scan of the file and a probe of the website).
	DriftObserveInterval = 6 * time.Hour
	// DriftStaleAfter is how old the newest agreeing evidence may be before a location is stale.
	DriftStaleAfter = 24 * time.Hour
	// DriftRepairWindow and DriftMaxRepairs: automatic repair backs off when DriftMaxRepairs repairs of a location
	// within DriftRepairWindow all came back (flapping) or failed.
	DriftRepairWindow = 24 * time.Hour
	DriftMaxRepairs   = 3
	// DriftAutoNoticeAfter: a drift in mode auto is mailed when no repair ended it within this time.
	DriftAutoNoticeAfter = time.Hour
	// driftProbesPerTarget bounds the locations one observation job probes.
	driftProbesPerTarget = 20
	// driftScheduleBatch bounds the locations one run of the observation schedule takes.
	driftScheduleBatch = 200
	// driftRepairBatch bounds the repairs one run of the repair planner considers.
	driftRepairBatch = 50
)

// ObservedCertificate is a certificate as an observation names it: its leaf fingerprint and, when Alice holds the
// certificate, its row and end.
type ObservedCertificate struct {
	CertificateID *uuid.UUID
	Fingerprint   string
	NotAfter      *time.Time
}

// DeployedCertificate is the newest succeeded or unchanged deployment to a location and the level it proved (R51).
type DeployedCertificate struct {
	DeploymentID uuid.UUID
	Fingerprint  string
	At           *time.Time
	Level        int
}

// FileObservation is what the last scan that read the file found in it (Fingerprint "" when the file holds no
// certificate), when, and whether the scan found a change outside Alice.
type FileObservation struct {
	ObservedCertificate
	At               time.Time
	ChangedOutsideAt *time.Time
}

// TLSObservation is what the location's websites served at the last probe that completed a handshake: the leaf of the
// first endpoint that did not serve the desired certificate (else the desired one), when, from where (DriftProbeAlice:
// Alice's own probe; DriftProbeHelper: the server itself through the helper, for at least one endpoint), the level the
// probe proved (R51: served or trusted when the desired certificate was served) and the served chain's trust.
type TLSObservation struct {
	ObservedCertificate
	At         time.Time
	Probe      string
	Level      int
	Trust      string
	TrustError string
}

// Probe points of a TLS observation (TLSObservation.Probe).
const (
	DriftProbeAlice  = "alice"
	DriftProbeHelper = "helper"
)

// LocationObservation is the observation model of one location (R52 item 1) and the health derived from it (item 2).
type LocationObservation struct {
	LocationID     uuid.UUID
	TargetID       uuid.UUID
	Health         string
	Source         string     // DriftSourceACME, DriftSourceKeyVault, or "" when the location follows no binding
	SourceID       *uuid.UUID // the ACME certificate or the Key Vault binding
	Desired        *ObservedCertificate
	LastDeployment *DeployedCertificate
	File           *FileObservation // nil: no scan read the file
	TLS            *TLSObservation  // nil: no probe completed a handshake
	TLSAttemptAt   *time.Time
	TLSError       string // the closed reason of the last probe attempt when it failed
	// Mode is the effective repair mode; ModeSetting the stored one ("" for the default, DefaultMode).
	Mode, ModeSetting, DefaultMode string
	DriftSince                     *time.Time
	DriftFingerprint               string
	DriftSource                    string // "file" or "tls": the observation that found the drift
	BackoffReason                  string
	BackedOffAt                    *time.Time
	ActiveDeploymentID             *uuid.UUID
	NextObserveAt                  *time.Time
	// Cause is a drifted Windows binding's cause (DriftCause*; "" otherwise) and AutoCertRebind whether its server's
	// AutoCertRebind task is on (false for every other kind); R62 Ruling 15.
	Cause          string
	AutoCertRebind bool

	deployedAt *time.Time // the desired certificate's newest successful deployment to the location
	certPath   string
	kind       providers.LocationKind
	// rdpAutoenroll: the location has the warning win_rdp_autoenroll (read for every kind, used for win_rdp only).
	rdpAutoenroll bool
}

// healthInput is what locationHealth decides from.
type healthInput struct {
	desired         string
	deployedAt      *time.Time // the desired certificate's newest successful deployment to the location
	inSyncFP        string     // the certificate an earlier observation found in sync
	fileFP          string
	fileAt          *time.Time
	changedOutside  *time.Time
	fileBroken      bool // a Windows binding whose certificate left its store or whose key is unusable (bindingBroken)
	tlsFP           string
	tlsAt           *time.Time
	attemptAt       *time.Time
	attemptFailed   bool
	active          bool
	now, staleAfter time.Time
}

// newer reports whether t is set and later than ref (any set t is newer than an unset ref).
func newer(t, ref *time.Time) bool {
	return t != nil && (ref == nil || t.After(*ref))
}

// locationHealth derives a location's health from its observations, in this order (R52 item 2):
//   - unmanaged: nothing is desired;
//   - pending: a deployment runs, or the desired certificate never reached the location (no successful deployment of
//     it, and no observation, now or earlier, found it there);
//   - drifted: an observation newer than the desired certificate's last successful deployment disagrees with it: the
//     website served another leaf, or the scan read another certificate in the file and judged it a change outside
//     Alice (changed_outside_at: a certificate that Alice's own deployments can have left is never one); a Windows
//     binding that broke (fileBroken: its certificate left the store or its key is unusable, R62 Ruling 14) disagrees
//     on the same terms even when it still names the desired certificate;
//   - unreachable: the last probe completed no handshake and is newer than both the last one that did and the
//     deployment;
//   - stale: the newest agreeing evidence (the deployment, a file that holds the desired certificate, a website that
//     served it) is older than staleAfter;
//   - in sync otherwise.
//
// A past success alone never makes a location in sync once a newer observation disagrees.
func locationHealth(in healthInput) string {
	if in.desired == "" {
		return HealthUnmanaged
	}
	if in.active {
		return HealthPending
	}
	fileAgrees := in.fileAt != nil && in.fileFP == in.desired
	tlsAgrees := in.tlsAt != nil && in.tlsFP == in.desired
	if in.deployedAt == nil && in.inSyncFP != in.desired && !fileAgrees && !tlsAgrees {
		return HealthPending
	}
	fileDisagrees := newer(in.fileAt, in.deployedAt) && newer(in.changedOutside, in.deployedAt) && (in.fileFP != in.desired || in.fileBroken)
	tlsDisagrees := newer(in.tlsAt, in.deployedAt) && in.tlsFP != in.desired
	if fileDisagrees || tlsDisagrees {
		return HealthDrifted
	}
	if in.attemptFailed && newer(in.attemptAt, in.tlsAt) && newer(in.attemptAt, in.deployedAt) {
		return HealthUnreachable
	}
	evidence := in.deployedAt
	if fileAgrees && newer(in.fileAt, evidence) {
		evidence = in.fileAt
	}
	if tlsAgrees && newer(in.tlsAt, evidence) {
		evidence = in.tlsAt
	}
	if evidence == nil || evidence.Before(in.staleAfter) {
		return HealthStale
	}
	return HealthInSync
}

// driftSourceJoin is the binding a location follows, as a lateral join on l (certificate_locations): its kind, the ACME
// certificate or the Key Vault binding, the desired certificate (the ACME certificate's current one, the binding's
// current version's) and whether automatic deployment is on for it. A location follows one source at most.
const driftSourceJoin = `LEFT JOIN LATERAL (
    SELECT 'acme'::text AS kind, ac.id AS source_id, ac.current_certificate_id AS cert_id, ac.auto_deploy AND b.auto_deploy AS auto
    FROM acme_bindings b JOIN acme_certificates ac ON ac.id = b.acme_certificate_id AND ac.deleted_at IS NULL WHERE b.location_id = l.id
    UNION ALL
    SELECT 'key_vault', kb.id, v.certificate_id, kb.auto_deploy
    FROM bindings kb JOIN kv_certificates kc ON kc.id = kb.kv_certificate_id
    LEFT JOIN kv_certificate_versions v ON v.kv_certificate_id = kc.id AND v.version = kc.current_version
    WHERE kb.id = l.binding_id AND kb.deleted_at IS NULL
    LIMIT 1) src ON true`

// observationSelect reads the observation model of locations (scanObservation's order).
const observationSelect = `SELECT l.id, l.target_id, l.cert_path, l.file_observed_at, l.changed_outside_at,
    l.certificate_id, coalesce(fc.fingerprint_sha256, ''), fc.not_after,
    coalesce(src.kind, ''), src.source_id, coalesce(src.auto, false), dc.id, coalesce(dc.fingerprint_sha256, ''), dc.not_after,
    coalesce(o.drift_mode, ''), o.next_observe_at, o.tls_attempted_at, coalesce(o.tls_error, ''), o.tls_observed_at,
    coalesce(o.tls_fingerprint, ''), coalesce(o.tls_probe, ''), coalesce(o.tls_level, 0), coalesce(o.tls_trust, ''), coalesce(o.tls_trust_error, ''),
    (SELECT tc.id FROM certificates tc WHERE tc.fingerprint_sha256 = o.tls_fingerprint),
    (SELECT tc.not_after FROM certificates tc WHERE tc.fingerprint_sha256 = o.tls_fingerprint),
    coalesce(o.in_sync_fingerprint, ''), o.drift_since, coalesce(o.drift_fingerprint, ''), coalesce(o.drift_source, ''),
    coalesce(o.backoff_reason, ''), o.backed_off_at,
    (SELECT max(d.finished_at) FROM deployments d WHERE d.location_id = l.id AND d.certificate_id = dc.id AND d.status IN ('succeeded', 'unchanged')),
    ld.id, coalesce(ld.new_fingerprint, ''), ld.finished_at, coalesce(ld.verified, ''), coalesce(ld.trust_status, ''),
    (SELECT d.id FROM deployments d WHERE d.location_id = l.id AND d.state <> 'done' LIMIT 1),
    l.kind, l.problem, l.key_problem,
    coalesce((SELECT t.facts->'warnings' @> jsonb_build_array(jsonb_build_object('Code', '` + warnAutoCertRebind + `'))
              FROM targets t WHERE t.id = l.target_id), false),
    '` + warnRDPAutoenroll + `' = ANY (l.warnings)
FROM certificate_locations l
LEFT JOIN certificates fc ON fc.id = l.certificate_id
` + driftSourceJoin + `
LEFT JOIN certificates dc ON dc.id = src.cert_id
LEFT JOIN location_observations o ON o.location_id = l.id
LEFT JOIN LATERAL (SELECT d.id, d.new_fingerprint, d.finished_at, d.verified, d.trust_status FROM deployments d
    WHERE d.location_id = l.id AND d.status IN ('succeeded', 'unchanged') ORDER BY d.finished_at DESC NULLS LAST, d.id DESC LIMIT 1) ld ON true`

// scanObservation reads one observationSelect row and derives the health at now.
func scanObservation(row pgx.Row, now time.Time) (LocationObservation, error) {
	var (
		o                                  LocationObservation
		fileAt, changedOutside             *time.Time
		fileCert, desiredCert, tlsCert     *uuid.UUID
		fileFP, desiredFP, tlsFP, probe    string
		fileNotAfter, desiredNA, tlsNA     *time.Time
		tlsAt                              *time.Time
		level                              int
		trust, trustErr                    string
		lastID                             *uuid.UUID
		lastFP, lastVerified, lastTrust    string
		lastAt                             *time.Time
		active                             *uuid.UUID
		sourceKind                         string
		sourceID                           *uuid.UUID
		sourceAuto                         bool
		modeSetting, driftFP, driftSource  string
		backoff                            string
		driftSince, backedOff, next, attAt *time.Time
		attemptErr, inSyncFP               string
		problem, keyProblem                string
		autoCertRebind                     bool
	)
	err := row.Scan(&o.LocationID, &o.TargetID, &o.certPath, &fileAt, &changedOutside, &fileCert, &fileFP, &fileNotAfter,
		&sourceKind, &sourceID, &sourceAuto, &desiredCert, &desiredFP, &desiredNA,
		&modeSetting, &next, &attAt, &attemptErr, &tlsAt, &tlsFP, &probe, &level, &trust, &trustErr, &tlsCert, &tlsNA,
		&inSyncFP, &driftSince, &driftFP, &driftSource, &backoff, &backedOff,
		&o.deployedAt, &lastID, &lastFP, &lastAt, &lastVerified, &lastTrust, &active,
		&o.kind, &problem, &keyProblem, &autoCertRebind, &o.rdpAutoenroll)
	if errors.Is(err, pgx.ErrNoRows) {
		return LocationObservation{}, ErrNotFound
	}
	if err != nil {
		return LocationObservation{}, fmt.Errorf("inventory: read a location's observations: %w", err)
	}
	o.Source, o.SourceID = sourceKind, sourceID
	if desiredCert != nil && desiredFP != "" {
		o.Desired = &ObservedCertificate{CertificateID: desiredCert, Fingerprint: desiredFP, NotAfter: utcPtr(desiredNA)}
	}
	if lastID != nil {
		o.LastDeployment = &DeployedCertificate{DeploymentID: *lastID, Fingerprint: lastFP, At: utcPtr(lastAt),
			Level: providers.VerificationLevel(lastVerified, lastTrust)}
	}
	if fileAt != nil {
		o.File = &FileObservation{ObservedCertificate: ObservedCertificate{CertificateID: fileCert, Fingerprint: fileFP, NotAfter: utcPtr(fileNotAfter)},
			At: fileAt.UTC(), ChangedOutsideAt: utcPtr(changedOutside)}
	}
	if tlsAt != nil {
		o.TLS = &TLSObservation{ObservedCertificate: ObservedCertificate{CertificateID: tlsCert, Fingerprint: tlsFP, NotAfter: utcPtr(tlsNA)},
			At: tlsAt.UTC(), Probe: probe, Level: level, Trust: trust, TrustError: trustErr}
	}
	o.TLSAttemptAt, o.TLSError = utcPtr(attAt), attemptErr
	o.ModeSetting, o.DefaultMode = modeSetting, DriftModeObserve
	if sourceAuto {
		o.DefaultMode = DriftModeAuto
	}
	o.Mode = o.ModeSetting
	if o.Mode == "" {
		o.Mode = o.DefaultMode
	}
	o.DriftSince, o.DriftFingerprint, o.DriftSource = utcPtr(driftSince), driftFP, driftSource
	o.BackoffReason, o.BackedOffAt = backoff, utcPtr(backedOff)
	o.ActiveDeploymentID, o.NextObserveAt = active, utcPtr(next)
	o.deployedAt = utcPtr(o.deployedAt)
	in := healthInput{deployedAt: o.deployedAt, inSyncFP: inSyncFP, fileAt: fileAt, fileFP: fileFP, changedOutside: changedOutside,
		tlsAt: tlsAt, tlsFP: tlsFP, attemptAt: attAt, attemptFailed: attemptErr != "", active: active != nil, now: now,
		staleAfter: now.Add(-DriftStaleAfter), fileBroken: bindingBroken(o.kind, problem, keyProblem)}
	if o.Desired != nil {
		in.desired = o.Desired.Fingerprint
	}
	o.Health = locationHealth(in)
	o.Cause = driftCause(o.kind, o.Health, problem, keyProblem)
	o.AutoCertRebind = o.kind == providers.LocationWinSSLBinding && autoCertRebind
	return o, nil
}

// locationObservations reads the observation model of the locations (bound or not), keyed by location.
func (s *Service) locationObservations(ctx context.Context, q db.Querier, ids []uuid.UUID) (map[uuid.UUID]LocationObservation, error) {
	out := map[uuid.UUID]LocationObservation{}
	if len(ids) == 0 {
		return out, nil
	}
	now := s.clock.Now().UTC()
	rows, err := q.Query(ctx, observationSelect+" WHERE l.id = ANY($1)", ids)
	if err != nil {
		return nil, fmt.Errorf("inventory: read the locations' observations: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		o, err := scanObservation(rows, now)
		if err != nil {
			return nil, err
		}
		out[o.LocationID] = o
	}
	return out, rows.Err()
}

// LocationObservation returns the observation model of a location on a live server (ErrNotFound otherwise).
func (s *Service) LocationObservation(ctx context.Context, id uuid.UUID) (LocationObservation, error) {
	if err := s.liveLocation(ctx, id); err != nil {
		return LocationObservation{}, err
	}
	m, err := s.locationObservations(ctx, s.pool, []uuid.UUID{id})
	if err != nil {
		return LocationObservation{}, err
	}
	o, ok := m[id]
	if !ok {
		return LocationObservation{}, ErrNotFound
	}
	return o, nil
}

// withObservations attaches the observation model of each bound location to the list (an unbound one gets none).
func (s *Service) withObservations(ctx context.Context, items []CertificateLocation) error {
	ids := make([]uuid.UUID, 0, len(items))
	for _, l := range items {
		ids = append(ids, l.ID)
	}
	m, err := s.locationObservations(ctx, s.pool, ids)
	if err != nil {
		return err
	}
	for i := range items {
		if o, ok := m[items[i].ID]; ok && o.Source != "" {
			items[i].Observation = &o
		}
	}
	return nil
}

// Refusals of the drift actions.
var (
	// ErrDriftNotBound: the location follows no binding, so nothing is desired there (no mode, no repair).
	ErrDriftNotBound = errors.New("inventory: the location follows no binding")
	// ErrDriftNotDrifted: a repair was asked for a location that is not drifted.
	ErrDriftNotDrifted = errors.New("inventory: the location is not drifted")
	// ErrDriftRepairSuperseded: a queued repair no longer deploys the desired certificate (the binding was removed or
	// its certificate renewed since).
	ErrDriftRepairSuperseded = errors.New("inventory: the repair no longer deploys the desired certificate")
	// ErrDriftRepairOff: a queued automatic repair whose location is no longer in mode auto (a person chose another
	// mode, or automatic repair backed off).
	ErrDriftRepairOff = errors.New("inventory: automatic repair is off for the location")
	// ErrDriftNotRepairable: a repair was asked for a Windows binding whose certificate left its store or whose key
	// http.sys cannot use (cause cert_removed or key_unusable, R62 Ruling 14): deploying the desired certificate again
	// cannot repair it, and the binding is unsupported until a person fixes the store.
	ErrDriftNotRepairable = errors.New("inventory: the drifted binding cannot be repaired from Alice")
)

// Closed reasons of a queued repair that no longer holds (deployments.error_code).
const (
	ReasonDriftRepairSuperseded = "deployment.drift_repair_superseded"
	ReasonDriftRepairOff        = "deployment.drift_repair_off"
)

// SetDriftMode sets the repair mode of a bound location: observe, approve, auto, or default (the default for the
// binding). In one transaction, under the observation row's lock: ErrNotFound (no location on a live server),
// ErrDriftNotBound; then, when the effective mode becomes auto from another one, the rule for switching unattended
// deployment on (unattendedAllowed: an Administrator with a fresh step-up, ErrAdminRequired or
// ErrAutoDeployNeedsStepUp, and the licence gate). Any change clears an automatic repair's back-off. Audit
// location.drift_mode_changed (nothing when nothing changed).
func (s *Service) SetDriftMode(ctx context.Context, a Actor, id uuid.UUID, mode string, strictSession bool) (LocationObservation, error) {
	switch mode {
	case DriftModeObserve, DriftModeApprove, DriftModeAuto, DriftModeDefault:
	default:
		return LocationObservation{}, validateMode()
	}
	if err := s.liveLocation(ctx, id); err != nil {
		return LocationObservation{}, err
	}
	err := db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		now := s.clock.Now().UTC()
		if _, err := tx.Exec(ctx, `INSERT INTO location_observations (location_id, updated_at) VALUES ($1, $2) ON CONFLICT (location_id) DO NOTHING`,
			id, now); err != nil {
			return fmt.Errorf("inventory: prepare the location's observations: %w", err)
		}
		if _, err := tx.Exec(ctx, "SELECT 1 FROM location_observations WHERE location_id = $1 FOR UPDATE", id); err != nil {
			return fmt.Errorf("inventory: lock the location's observations: %w", err)
		}
		m, err := s.locationObservations(ctx, tx, []uuid.UUID{id})
		if err != nil {
			return err
		}
		o := m[id]
		if o.Source == "" {
			return ErrDriftNotBound
		}
		setting := mode
		if mode == DriftModeDefault {
			setting = ""
		}
		effective := setting
		if effective == "" {
			effective = o.DefaultMode
		}
		if setting == o.ModeSetting && o.BackedOffAt == nil {
			return nil
		}
		if effective == DriftModeAuto && (o.Mode != DriftModeAuto || o.BackedOffAt != nil) {
			if err := s.unattendedAllowed(a, strictSession); err != nil {
				return err
			}
		}
		if _, err := tx.Exec(ctx, `UPDATE location_observations SET drift_mode = nullif($2, ''), backoff_reason = '', backed_off_at = NULL, updated_at = $3
WHERE location_id = $1`, id, setting, now); err != nil {
			return fmt.Errorf("inventory: store the repair mode: %w", err)
		}
		_, err = s.audit.Append(ctx, tx, audit.Event{Actor: a.Audit, Action: "location.drift_mode_changed", ObjectType: "certificate_location",
			ObjectID: id.String(), Result: audit.Success, Details: map[string]string{"location_id": id.String(), "cert_path": o.certPath,
				"mode": mode, "effective_mode": effective, "previous_mode": o.Mode}})
		return err
	})
	if err != nil {
		return LocationObservation{}, err
	}
	return s.LocationObservation(ctx, id)
}

// validateMode is the refusal of an unknown repair mode.
func validateMode() error {
	return validate.Errors{{Field: "mode", Code: validate.OneOf, Params: map[string]string{"values": strings.Join(append(slices.Clone(driftModes),
		DriftModeDefault), ", ")}}}
}

// RepairDrift is a person's one action that repairs a drifted location: the desired certificate is deployed again
// through the request path of its source (DeployACMENow for an ACME certificate, RequestKVDeployment of the current
// version for a Key Vault binding), so every check, refusal, licence rule and audit row of a person's deployment
// applies. It works in every mode (in mode approve it is the prepared repair). ErrNotFound, ErrDriftNotBound,
// ErrDriftNotDrifted, ErrDriftNotRepairable (a Windows binding whose certificate or key broke, R62 Ruling 14).
func (s *Service) RepairDrift(ctx context.Context, a Actor, id uuid.UUID, strictSession bool) ([]RequestedDeployment, error) {
	o, err := s.LocationObservation(ctx, id)
	if err != nil {
		return nil, err
	}
	switch {
	case o.Source == "" || o.SourceID == nil:
		return nil, ErrDriftNotBound
	case o.Health != HealthDrifted:
		return nil, ErrDriftNotDrifted
	case !driftRepairable(o.Cause):
		return nil, ErrDriftNotRepairable
	}
	if o.Source == DriftSourceACME {
		return s.DeployACMENow(ctx, a, *o.SourceID, ACMEDeployInput{LocationIDs: []uuid.UUID{id}})
	}
	var version uuid.UUID
	err = s.pool.QueryRow(ctx, `SELECT v.id FROM bindings kb JOIN kv_certificates kc ON kc.id = kb.kv_certificate_id
JOIN kv_certificate_versions v ON v.kv_certificate_id = kc.id AND v.version = kc.current_version WHERE kb.id = $1`, *o.SourceID).Scan(&version)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrDriftNotBound
	}
	if err != nil {
		return nil, fmt.Errorf("inventory: read the binding's current version: %w", err)
	}
	return s.RequestKVDeployment(ctx, a, KVDeployInput{BindingID: *o.SourceID, VersionID: version, LocationIDs: []uuid.UUID{id},
		StrictSession: strictSession})
}

// driftRepairPrecheck judges a queued automatic repair (trigger drift_repair) again when its job is about to send: the
// location must still desire the deployed certificate (ErrDriftRepairSuperseded) and still be in mode auto without a
// back-off (ErrDriftRepairOff). Read-only.
func (s *Service) driftRepairPrecheck(ctx context.Context, d Deployment) error {
	m, err := s.locationObservations(ctx, s.pool, []uuid.UUID{d.LocationID})
	if err != nil {
		return err
	}
	o, ok := m[d.LocationID]
	switch {
	case !ok || o.Desired == nil || o.Desired.CertificateID == nil || *o.Desired.CertificateID != d.CertificateID:
		return ErrDriftRepairSuperseded
	case o.Mode != DriftModeAuto || o.BackedOffAt != nil:
		return ErrDriftRepairOff
	}
	return nil
}

// observedFingerprint is the leaf an observation that disagrees with the desired certificate found, and which one
// found it ("tls" before "file": the website is what visitors get).
func (o LocationObservation) observedDrift() (fingerprint, source string) {
	desired := ""
	if o.Desired != nil {
		desired = o.Desired.Fingerprint
	}
	if o.TLS != nil && o.TLS.Fingerprint != desired && newer(&o.TLS.At, o.deployedAt) {
		return o.TLS.Fingerprint, "tls"
	}
	if o.File != nil {
		return o.File.Fingerprint, "file"
	}
	return "", "file"
}

// hexFingerprint keeps a fingerprint the observation columns can hold ("" otherwise).
func hexFingerprint(fp string) string {
	if hex64RE.MatchString(fp) {
		return fp
	}
	return ""
}

// driftNames are the texts a drift notice names: the server, the file, the desired certificate and the observed one
// (a label or subject name when Alice holds it, else the first 16 hex digits of its fingerprint).
func driftNames(ctx context.Context, q db.Querier, o LocationObservation, observed string) (map[string]string, error) {
	p := map[string]string{"cert_path": o.certPath}
	var target string
	if err := q.QueryRow(ctx, "SELECT name::text FROM targets WHERE id = $1", o.TargetID).Scan(&target); err != nil {
		return nil, fmt.Errorf("inventory: read the server's name: %w", err)
	}
	p["target_name"] = target
	name := func(fp string) (string, error) {
		if fp == "" {
			return "", nil
		}
		var n string
		err := q.QueryRow(ctx, `SELECT coalesce(nullif(label, ''), nullif(subject_cn, ''), left(fingerprint_sha256, 16)) FROM certificates
WHERE fingerprint_sha256 = $1`, fp).Scan(&n)
		if errors.Is(err, pgx.ErrNoRows) {
			return fp[:min(16, len(fp))], nil
		}
		return n, err
	}
	var err error
	if o.Desired != nil {
		if p["certificate_name"], err = name(o.Desired.Fingerprint); err != nil {
			return nil, fmt.Errorf("inventory: read the desired certificate's name: %w", err)
		}
	}
	if p["observed_name"], err = name(observed); err != nil {
		return nil, fmt.Errorf("inventory: read the observed certificate's name: %w", err)
	}
	if p["observed_name"] == "" {
		p["observed_name"] = "-"
	}
	for k, v := range p {
		p[k] = truncRunes(strings.TrimSpace(v), 200)
	}
	return p, nil
}

// driftNotice records a drift notice of a location in the alerts ledger (kind, the location, the instant that names the
// episode or the back-off, threshold 0) and, only when the row is new, queues template for the location's services
// (its server's and its certificate's, R56). So each is told once. A Windows binding's goes in the Windows text of its
// cause, with windows_note when its server's AutoCertRebind task is on (notifyLocation, windowsLocationMail).
func (s *Service) driftNotice(ctx context.Context, tx pgx.Tx, kind, template string, o LocationObservation, at time.Time, observed string) error {
	params, err := driftNames(ctx, tx, o, observed)
	if err != nil {
		return err
	}
	subject := truncRunes(params["target_name"]+" "+o.certPath, 300)
	var ledger uuid.UUID
	err = tx.QueryRow(ctx, `INSERT INTO alerts (id, kind, object_id, subject, expires_at, threshold_days, license_locked, emailed, created_at)
VALUES ($1, $2, $3, $4, $5, 0, false, $6, $7)
ON CONFLICT (kind, object_id, expires_at, threshold_days) DO NOTHING RETURNING id`, uuid.Must(uuid.NewV7()), kind, o.LocationID, subject, at,
		s.notifier != nil, s.clock.Now().UTC()).Scan(&ledger)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil // told already
	}
	if err != nil {
		return fmt.Errorf("inventory: record the drift notice: %w", err)
	}
	if s.notifier == nil {
		return nil
	}
	if err := s.notifyLocation(ctx, tx, o, template, params); err != nil {
		return fmt.Errorf("inventory: queue the drift notice: %w", err)
	}
	return nil
}

// Ledger kinds of the drift notices (migration 00027).
const (
	driftKind         = "location_drift"
	driftRepairedKind = "location_drift_repaired"
	driftBackoffKind  = "location_drift_backoff"
)

// Drift notices to every Administrator (R52 item 5). Params: target_name, cert_path, certificate_name (the desired
// certificate) and observed_name (the certificate found instead, "-" when the file holds none). No URL, no code.
const (
	// TemplateDriftDetected: a location in mode observe drifted (or in mode auto, when no repair ended the drift
	// within DriftAutoNoticeAfter).
	TemplateDriftDetected = "location.drift_detected"
	// TemplateDriftRepairReady: a location in mode approve drifted; the repair is one action away.
	TemplateDriftRepairReady = "location.drift_repair_ready"
	// TemplateDriftRepaired: automatic repair put the desired certificate back and a new observation confirmed it.
	TemplateDriftRepaired = "location.drift_repaired"
	// TemplateDriftFlapping: automatic repair backed off because the drift came back after each of its repairs: another
	// tool keeps changing the file.
	TemplateDriftFlapping = "location.drift_flapping"
	// TemplateDriftRepairFailing: automatic repair backed off because its repairs failed.
	TemplateDriftRepairFailing = "location.drift_repair_failing"
)

// DriftTemplates lists the drift e-mails (render tests).
func DriftTemplates() []string {
	return []string{TemplateDriftDetected, TemplateDriftRepairReady, TemplateDriftRepaired, TemplateDriftFlapping, TemplateDriftRepairFailing}
}

// The Windows texts of the drift e-mails (R62 Ruling 16): R52's facts and params for an http.sys binding of a Windows
// server, naming the binding and its certificate store, never a file. A detected drift has one text per cause; an
// approve-mode drift whose cause cannot be repaired gets the detected text of its cause. Param windows_note
// (autocertrebind) asks notify.Sender.Render for the AutoCertRebind sentence (email.windows_note_autocertrebind).
const (
	TemplateDriftDetectedWindows            = "location.drift_detected_windows"
	TemplateDriftDetectedWindowsCertRemoved = "location.drift_detected_windows_cert_removed"
	TemplateDriftDetectedWindowsKeyUnusable = "location.drift_detected_windows_key_unusable"
	TemplateDriftRepairReadyWindows         = "location.drift_repair_ready_windows"
	TemplateDriftRepairedWindows            = "location.drift_repaired_windows"
	TemplateDriftFlappingWindows            = "location.drift_flapping_windows"
	TemplateDriftRepairFailingWindows       = "location.drift_repair_failing_windows"
)

// WindowsDriftTemplates lists the Windows texts of the drift e-mails (render tests).
func WindowsDriftTemplates() []string {
	return []string{TemplateDriftDetectedWindows, TemplateDriftDetectedWindowsCertRemoved, TemplateDriftDetectedWindowsKeyUnusable,
		TemplateDriftRepairReadyWindows, TemplateDriftRepairedWindows, TemplateDriftFlappingWindows, TemplateDriftRepairFailingWindows}
}

// windowsNoteAutoCertRebind is the value of param windows_note that asks for the AutoCertRebind sentence.
const windowsNoteAutoCertRebind = "autocertrebind"

// The values of param windows_note that ask for the RDP listener's sentence (email.windows_note_rdp), and for it with
// the RDP autoenrolment sentence (email.windows_note_rdp_autoenroll), W6 Ruling 20.
const (
	windowsNoteRDP           = "rdp"
	windowsNoteRDPAutoenroll = "rdp_autoenroll"
)

// windowsLocationMail is the template and params of a drift e-mail about o as queued (mirror of windowsDeploymentMail).
// Anything but a Windows binding keeps both as given, byte for byte. A Windows binding's is the Windows text: of its
// cause for a detected drift, the detected text of its cause for a prepared repair that cannot be made, else the
// Windows text of the template; with windows_note=autocertrebind when its server's AutoCertRebind task is on. The RDP
// listener's is a binding's with windows_note=rdp, or rdp_autoenroll when a policy autoenrols its certificate (W6
// Ruling 20); AutoCertRebind re-points bindings only.
func windowsLocationMail(o LocationObservation, template string, params map[string]string) (string, map[string]string) {
	if !windowsBinding(o.kind) || !slices.Contains(DriftTemplates(), template) {
		return template, params
	}
	detected := map[string]string{DriftCauseCertRemoved: TemplateDriftDetectedWindowsCertRemoved,
		DriftCauseKeyUnusable: TemplateDriftDetectedWindowsKeyUnusable}[o.Cause]
	if detected != "" && (template == TemplateDriftDetected || template == TemplateDriftRepairReady) {
		template = detected
	} else {
		template += windowsTemplateSuffix
	}
	out := make(map[string]string, len(params)+1)
	maps.Copy(out, params)
	switch {
	case o.kind == providers.LocationWinRDP && o.rdpAutoenroll:
		out["windows_note"] = windowsNoteRDPAutoenroll
	case o.kind == providers.LocationWinRDP:
		out["windows_note"] = windowsNoteRDP
	case o.AutoCertRebind:
		out["windows_note"] = windowsNoteAutoCertRebind
	}
	return template, out
}

// driftModes lists the stored repair modes.
var driftModes = []string{DriftModeObserve, DriftModeApprove, DriftModeAuto}
