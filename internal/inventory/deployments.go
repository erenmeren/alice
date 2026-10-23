package inventory

// Deployment records (spec §7.4, §12.6; R38 items 7, 8, 18). This file holds the types, the
// request and the reads; deployment_records.go the engine's writes (the state machine);
// deployment_outcome.go what a provider outcome means for the record; sweep.go the recovery
// sweep. The records are the only durable truth about what Alice did to a live website.
//
// State machine (deployments.state; status in brackets; every arrow is one transaction with its
// audit row, and nothing moves a deployment backwards or out of done; the trigger
// deployments_done_frozen refuses any change of a done row, SQLSTATE Z1003):
//
//	(insert)  -> queued [pending]          RequestDeployment: the row, its certificate.deploy job and
//	                                       deployment.requested commit together
//	queued    -> precheck [running]        BeginDeployment (idempotent in precheck; any other state
//	                                       returns the row unchanged); deployment.precheck_started
//	precheck  -> deploying [running]       StartDeployment(id, SendValues): records operation_id,
//	                                       expect_cert_sha256, new_chain_length, previous_fingerprint,
//	                                       previous_chain_length (exactly the values sent),
//	                                       rollback_info and started_at (the start record's time) in
//	                                       ONE update before the first send; deployment.started. Refused from any other state
//	                                       (ErrDeploymentState), and while another deployment on the
//	                                       server is recovering (ErrRecoveryPending). Deploying with an
//	                                       operation id means "a send may have happened"; queued,
//	                                       precheck or no operation id mean "nothing was sent"
//	deploying|recovering (sent)
//	          -> recovering [running|needs_attention]
//	                                       MarkRecovering, RequestRecovery, RecordOutcome (uncertain),
//	                                       SweepDeployments: recover_after (a zero or past time is now +
//	                                       RecoveryRetryInterval; after the first recovery request never
//	                                       sooner than that), recovery_attempts;
//	                                       deployment.recovering on entry, deployment.recovery_started
//	                                       per recovery job, deployment.needs_attention (and its email,
//	                                       by cause) on the first needs_attention, which then stays
//	                                       until done. From queued or precheck (or without an operation
//	                                       id) these are refused with ErrDeploymentState: a failure
//	                                       before the send is FinishDeployment(failed)
//	any unfinished -> done [terminal]      FinishDeployment / RecordOutcome (terminal) / the sweep:
//	                                       every final value in the single UPDATE that sets done;
//	                                       failed from any unfinished state; unchanged from precheck
//	                                       (with a verification) or after a send; succeeded,
//	                                       rolled_back, rollback_failed only after a send (deploying
//	                                       or recovering with an operation id); "skipped" counts as a
//	                                       verification only where the location skips it. Others:
//	                                       ErrDeploymentState.
//	done      -> (nothing)                 FinishDeployment, MarkRecovering, RequestRecovery and
//	                                       RecordOutcome on a done row are no-op successes (Z1003 is
//	                                       "already finished"); BeginDeployment returns it unchanged;
//	                                       RecordDeploymentStep and StartDeployment refuse it.
//
// Terminal statuses keep the meanings the changed-outside check relies on (aliceFingerprints in
// locations.go): failed = nothing was written on the server by this deployment; rolled_back = the
// previous files are back; succeeded/unchanged = the new certificate is in place and was verified
// (or the Administrator turned verification off); rollback_failed = unknown or mixed. An
// unfinished row (any status) is an open outcome.
//
// Progress of every unfinished state (see SweepDeployments for the details):
//   - queued: its certificate.deploy job is queued (same transaction), held for an Administrator
//     in lock (blocked_license: the license emails and the blocked-jobs panel tell them; a job an
//     Administrator discarded ends the deployment failed with deployment.cancelled through the
//     sweep, without a failure email), or finished without finishing the deployment (dead,
//     failed, succeeded, pruned): the sweep ends it failed.
//   - precheck: as queued (nothing has been sent yet).
//   - deploying: the job runs; when it does not (dead, queued for a retry, held, pruned) the sweep
//     hands the deployment to a certificate.deploy_recover job (ClassAlways: never held by the
//     license) at once.
//   - recovering: a recovery job is queued or running, or the sweep queues one when recover_after
//     has passed (RecoveryRetryInterval after the last one); a recovery job has one attempt and
//     its failure is never a dead-job alert; after RecoveryAttentionAfter attempts the
//     Administrators are emailed once (needs_attention); after MaxRecoveryAttempts (about a day)
//     the sweep ends it rollback_failed (deployment.recovery_exhausted, the outcome-unknown email).
//   - a deleted server's unfinished deployments end (deployment.target_deleted) once no job runs.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"alice/internal/audit"
	"alice/internal/authz"
	"alice/internal/license"
	"alice/internal/platform/db"
	"alice/internal/platform/validate"
	"alice/internal/providers"
	"alice/internal/rbac"
)

// Deployment states (deployments.state).
const (
	DeployStateQueued     = "queued"
	DeployStatePrecheck   = "precheck"
	DeployStateDeploying  = "deploying"
	DeployStateRecovering = "recovering"
	DeployStateDone       = "done"
)

// Deployment statuses (deployments.status). The terminal five are TerminalStatuses.
const (
	DeployStatusPending        = "pending"
	DeployStatusRunning        = "running"
	DeployStatusSucceeded      = "succeeded"
	DeployStatusUnchanged      = "unchanged"
	DeployStatusFailed         = "failed"
	DeployStatusRolledBack     = "rolled_back"
	DeployStatusRollbackFailed = "rollback_failed"
	DeployStatusNeedsAttention = "needs_attention"
)

// TerminalStatuses are the statuses of a done deployment, each known to aliceFingerprints.
func TerminalStatuses() []string {
	return []string{DeployStatusSucceeded, DeployStatusUnchanged, DeployStatusFailed, DeployStatusRolledBack, DeployStatusRollbackFailed}
}

// Limits and timings of deployments.
const (
	// MaxDeployLocations is how many websites one request may name (R38 item 18).
	MaxDeployLocations = 20
	// RecoveryRetryInterval spaces the recovery jobs of one deployment (plan decision 8: an
	// unreachable server is retried every 15 minutes; the needs_attention email says so).
	RecoveryRetryInterval = 15 * time.Minute
	// RecoveryAttentionAfter: when a recovery is requested after this many have not ended the
	// deployment (about an hour), the deployment needs attention and the Administrators are
	// emailed, once.
	RecoveryAttentionAfter = 4
	// MaxRecoveryAttempts bounds the recoveries of one deployment (about a day at
	// RecoveryRetryInterval); then the sweep ends it rollback_failed (deployment.recovery_exhausted:
	// the files may hold either certificate) and asks for manual action.
	MaxRecoveryAttempts = 96
	// FirstRecoveryDelay is what the engine names for the first recovery after an uncertain first
	// send (RecordOutcome / MarkRecovering with now + FirstRecoveryDelay): soon, but after the
	// helper's own budget has likely ended. A zero or past time means RecoveryRetryInterval.
	FirstRecoveryDelay = 30 * time.Second
	// BackupRoot is helperproto.BackupRoot (inventory may not import it; a test compares them):
	// the helper keeps an operation's backup in BackupRoot/<operation id>.
	BackupRoot = "/var/lib/alice-helper/backups"
)

const (
	defaultDeploymentLimit = 50
	maxDeploymentLimit     = 200
	// sweepBatch bounds the deployments one sweep handles (the rest wait for the next minute).
	sweepBatch = 100
	// recoverDedupePrefix + deployment id is the dedupe key of a recovery job.
	recoverDedupePrefix = JobDeployRecover + ":"
	deployDedupePrefix  = JobCertificateDeploy + ":"
)

var (
	// errorCodeRE is deployments.error_code's and verify_failed_reason's CHECK (non-empty).
	errorCodeRE = regexp.MustCompile(`^[A-Za-z0-9._-]{1,100}$`)
	hex64RE     = regexp.MustCompile(`^[0-9a-f]{64}$`)
	// deployPathRE is deployments.cert_path/key_path's CHECK (helperproto's argument shape).
	deployPathRE = regexp.MustCompile(`^/[A-Za-z0-9._/@:+-]+$`)
)

// jobsActor is the audit actor of what the deployment engine and the sweep record.
var jobsActor = audit.SystemActor("jobs")

// DeployRequestInput asks for a certificate on up to MaxDeployLocations locations.
type DeployRequestInput struct {
	CertificateID          uuid.UUID
	LocationIDs            []uuid.UUID // 1..20
	ConfirmIncompleteChain bool        // counts only for an Administrator (F-17)
	// source is the service whose key the deployment places (R49, design §5.6): nil for the certificate's own, the ACME
	// certificate's for its Deploy now. incident: a key-compromise incident's replacement, which needs no trust (the
	// key it replaces is there already).
	source   *uuid.UUID
	incident bool
}

// RequestedDeployment is one queued deployment.
type RequestedDeployment struct {
	ID         uuid.UUID
	JobID      uuid.UUID
	LocationID uuid.UUID
	Warnings   []string // "san_mismatch"; never nil
}

// DeploymentStep is one appended step event (R38 item 7).
type DeploymentStep struct {
	N      int
	Name   string
	Status string
	At     time.Time
	Params map[string]string
}

// Deployment is one deployment record.
type Deployment struct {
	ID                     uuid.UUID
	CertificateID          uuid.UUID
	CertificateName        string // label, else subject CN, else the first 16 hex of the fingerprint
	LocationID             uuid.UUID
	TargetID               uuid.UUID
	TargetName             string
	CertPath               string
	KeyPath                string
	JobID                  *uuid.UUID // nil once the job was pruned
	JobStatus              string     // its job's status ("" once pruned); blocked_license: held in lock for an Administrator (L-81)
	Trigger                string
	RequestedBy            *uuid.UUID
	RequestedByName        string
	State                  string
	Status                 string
	NewFingerprint         string
	PreviousFingerprint    string
	ConfirmIncompleteChain bool
	Backup                 *providers.BackupRef
	Verified               string
	ErrorCode              string
	ErrorParams            map[string]string // never nil
	FailedStep             string
	CreatedAt              time.Time
	StartedAt              *time.Time
	FinishedAt             *time.Time
	Steps                  []DeploymentStep // Deployment(...) only

	// Recorded values and outcome details (Task 15 additions).
	Result              string     // providers.DeployResult as last known ("" none, "uncertain" in recovery)
	Phase               string     // the helper journal phase of the last answer
	CauseStep           string     // the step whose failure started the rollback
	HelperError         string     // the helper's error class (ConfigErr*, file_changed) or ""
	VerifyFailedReason  string     // the verification failure that preceded an uncertain outcome
	VerifyFailedPort    *int       // its port
	OperationID         *uuid.UUID // the helper operation id sent (= ID), nil before the first send
	NewChainLength      int        // certificates sent; 0 before the first send
	PreviousChainLength int        // certificates served before the change; 0 = not compared
	ExpectCertSHA256    string     // the file hash the first send expected to replace
	RecoverAfter        *time.Time // the next recovery is not requested before this
	RecoveryAttempts    int        // recovery jobs requested

	// Task 12 additions: a Key Vault deployment names its binding and the vault version it deploys.
	BindingID *uuid.UUID // nil unless the deployment is from a vault
	KVVersion string     // the vault version (32 hex) or ""
	VaultName string     // the vault's name or ""
	Source    string     // "key_vault" when BindingID is set, "acme" for a certificate ordered from a CA, else "upload"

	// R48: the certificate the replaced file held (the backup a rollback would put back), recorded with the send
	// values; "" before the first send and when Alice did not know the file's certificate.
	RollbackLeafSHA256 string
	RollbackSPKISHA256 string

	// R51: what the verification of the new certificate found about the served chains (Trust.Status "" when not
	// measured: skipped, or a deployment from before R51), and the level a finished deployment proved
	// (providers.Level*: none unless it succeeded or was unchanged; then installed, served or trusted).
	Trust providers.Trust
	Level int
}

// DeploymentFilter selects deployments, newest first.
type DeploymentFilter struct {
	TargetID      uuid.UUID
	CertificateID uuid.UUID
	LocationID    uuid.UUID
	Cursor        string
	Limit         int // 1..200, default 50
	// Reach keeps the deployments the caller sees (R49 Phase 2: its server's service or its certificate's); the zero
	// value is every service.
	Reach authz.Reach
}

// DeploymentPage is one page of deployments.
type DeploymentPage struct {
	Items      []Deployment
	NextCursor string
}

func validateDeployInput(in DeployRequestInput) validate.Errors {
	var errs validate.Errors
	if n := len(in.LocationIDs); n < 1 || n > MaxDeployLocations {
		errs.Add("location_ids", validate.OutOfRange, map[string]string{"min": "1", "max": strconv.Itoa(MaxDeployLocations)})
		return errs
	}
	seen := map[uuid.UUID]bool{}
	for _, id := range in.LocationIDs {
		if seen[id] || id == uuid.Nil {
			errs.Add("location_ids", validate.Pattern, nil)
			break
		}
		seen[id] = true
	}
	return errs
}

// deployDenial is a refusal RequestDeployment audits after its transaction rolled back.
type deployDenial struct {
	location uuid.UUID
	reason   string
}

type deployCertificate struct {
	id                  uuid.UUID
	keyID               *uuid.UUID
	fingerprint         string
	algorithm           string
	sans                []string
	notBefore, notAfter time.Time
	chainComplete       bool
	// revoked and compromised: the final marks of migration 00021; a certificate carrying either is never deployed.
	revoked, compromised bool
	// service is the source service of the key (R49): the certificate's own, or the vault's or the ACME certificate's
	// for their deployments; a server of another service must accept it (design §5.6 (c)) unless trustExempt (an
	// incident's replacement).
	service     uuid.UUID
	trustExempt bool
}

// revocationRefusal is the refusal of a revoked or compromised certificate and its audit reason ("" for none).
func (c deployCertificate) revocationRefusal() (string, error) {
	switch {
	case c.revoked:
		return "revoked", ErrCertificateRevoked
	case c.compromised:
		return "compromised", ErrCertificateCompromised
	}
	return "", nil
}

type deployLocation struct {
	id, target         uuid.UUID
	certPath, keyPath  string
	fileSHA            string
	keyType            string
	servers            []providers.CertServer
	supported, missing bool
	kind               providers.LocationKind // R59 G1
	hasLocator         bool
}

// deployableIdentity reports whether a deployment can record the location (deployments' CHECK, migration 00031): a
// certificate file's two paths the helper accepts, or another kind's locator with its canonical text and no key path.
func (l deployLocation) deployableIdentity() bool {
	if l.kind.IsFile() {
		return deployablePath(l.certPath) && deployablePath(l.keyPath)
	}
	return l.hasLocator && l.certPath != "" && utf8.RuneCountInString(l.certPath) <= providers.MaxCanonicalLength && l.keyPath == ""
}

// deployable is the location half of whether Alice can deploy to a location (checkDeployLocation's first rule; the
// server half is canDeploy): found at the last scan, supported, and an identity a deployment can record. The incident
// engine's place selection and the impact view use this same rule, reading deployableColumns into deployableDest.
func (l deployLocation) deployable() bool { return !l.missing && l.supported && l.deployableIdentity() }

// deployableColumns are the columns of certificate_locations l that deployable reads, in deployableDest's order.
const deployableColumns = `l.supported, l.missing_since IS NOT NULL, l.cert_path, l.key_path, l.kind, l.locator IS NOT NULL`

// deployableDest are the scan destinations of deployableColumns.
func (l *deployLocation) deployableDest() []any {
	return []any{&l.supported, &l.missing, &l.certPath, &l.keyPath, &l.kind, &l.hasLocator}
}

// targetReady are the statuses a deployment may be requested in: connected, or reachable again
// by the job's own retries (unreachable), or being re-tested (checking). A server that needs a
// person (pending or changed host key, failed sign-in) or is disabled is refused (F-31).
var targetReady = []string{StatusOK, StatusUnreachable, StatusChecking}

// RequestDeployment validates and queues one deployment per location (spec §12.6): all or
// nothing, in one transaction with their certificate.deploy jobs. Refusals, in this order: the
// license lock (license.ErrLocked: a deployment changes a server, R38); the certificate
// (ErrNotFound; ErrCertificateRevoked or ErrCertificateCompromised, migration 00021; ErrNoPrivateKey; ErrCertificateExpired when not before not_after; F-17
// ErrChainUnconfirmed for an incomplete chain without an Administrator's confirmation); then per
// location, after locking the targets (id order) and the locations (id order) as discovery does:
// ErrNotFound (unknown, or its server deleted); ErrLocationUnsupported (missing at the last scan,
// unsupported, a path the helper cannot take, or not on a server whose provider deploys);
// ErrTargetNotReady; ErrNginxConfigInvalid; *KeyTypeMismatchError; ErrRecoveryPending (a
// deployment on the server is being recovered); ErrDeploymentInProgress (F-15; the unique index
// deployments_one_active decides between concurrent requests). A refusal decided for one location
// (and an unknown location) is a *LocationRefusalError naming it. Each refusal is audited
// deployment.denied after the rollback. Whether the website can be verified is the engine's
// pre-check (Task 16), not decided here. A server name the certificate does not cover is a
// warning (san_mismatch), not a refusal.
func (s *Service) RequestDeployment(ctx context.Context, a Actor, in DeployRequestInput) ([]RequestedDeployment, error) {
	if errs := validateDeployInput(in); len(errs) > 0 {
		return nil, errs
	}
	if err := s.license.Allow(license.ClassChange); err != nil {
		if reason := license.DenialReason(err); reason != "" { // locked, lock_due or unverified (AUD-02)
			s.auditDeployDenial(ctx, a, in.CertificateID, deployDenial{reason: reason})
		}
		return nil, err
	}
	var (
		out    []RequestedDeployment
		denial *deployDenial
	)
	err := db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		out, denial = nil, nil
		deny := func(loc uuid.UUID, reason string, err error) error {
			denial = &deployDenial{location: loc, reason: reason}
			return err
		}
		c, err := readDeployCertificate(ctx, tx, in.CertificateID)
		if err != nil {
			return err
		}
		if in.source != nil {
			c.service = *in.source
		}
		c.trustExempt = in.incident
		now := s.clock.Now().UTC()
		if reason, err := c.revocationRefusal(); err != nil {
			return deny(uuid.Nil, reason, err)
		}
		switch {
		case c.keyID == nil:
			return deny(uuid.Nil, "no_private_key", ErrNoPrivateKey)
		case c.algorithm != "rsa" && c.algorithm != "ecdsa":
			return deny(uuid.Nil, "unsupported_key", ErrUnsupportedKey)
		case !now.Before(c.notAfter):
			return deny(uuid.Nil, "expired", ErrCertificateExpired)
		case now.Before(c.notBefore):
			return deny(uuid.Nil, "not_yet_valid", ErrCertificateNotYetValid)
		case !c.chainComplete && (!in.ConfirmIncompleteChain || a.Role != rbac.Admin):
			return deny(uuid.Nil, "chain_unconfirmed", ErrChainUnconfirmed)
		}
		targets, locs, err := s.lockDeployTargets(ctx, tx, in.LocationIDs)
		if err != nil {
			return err
		}
		for _, id := range in.LocationIDs {
			l := locs[id]
			t := targets[l.target]
			if reason, err := s.checkDeployLocation(ctx, tx, c, l, t); err != nil {
				return deny(id, reason, err)
			}
		}
		for _, id := range in.LocationIDs {
			l := locs[id]
			r, err := s.insertDeployment(ctx, tx, a, c, l, deploySource{Trigger: "manual", Confirmed: in.ConfirmIncompleteChain && !c.chainComplete}, now)
			if errors.Is(err, ErrDeploymentInProgress) {
				return deny(id, "in_progress", err)
			}
			if err != nil {
				return err
			}
			out = append(out, r)
		}
		return nil
	})
	if denial != nil {
		s.auditDeployDenial(ctx, a, in.CertificateID, *denial)
		if err != nil && denial.location != uuid.Nil {
			err = &LocationRefusalError{LocationID: denial.location, Err: err}
		}
	}
	if err != nil {
		return nil, err
	}
	return out, nil
}

func readDeployCertificate(ctx context.Context, q db.Querier, id uuid.UUID) (deployCertificate, error) {
	var c deployCertificate
	err := q.QueryRow(ctx, `SELECT id, private_key_id, fingerprint_sha256, key_algorithm, sans, not_before, not_after, chain_complete,
    revoked_at IS NOT NULL, compromised_at IS NOT NULL, service_id
FROM certificates WHERE id = $1`, id).Scan(&c.id, &c.keyID, &c.fingerprint, &c.algorithm, &c.sans, &c.notBefore, &c.notAfter, &c.chainComplete,
		&c.revoked, &c.compromised, &c.service)
	if errors.Is(err, pgx.ErrNoRows) {
		return deployCertificate{}, ErrNotFound
	}
	if err != nil {
		return deployCertificate{}, fmt.Errorf("inventory: read certificate: %w", err)
	}
	return c, nil
}

// lockDeployTargets locks the live targets of the locations (id order), then the locations (id
// order, FOR NO KEY UPDATE: inserting a deployment that references one is not blocked): the lock
// order of discovery, target then location. A location that does not exist or whose target is
// deleted is ErrNotFound.
func (s *Service) lockDeployTargets(ctx context.Context, tx pgx.Tx, ids []uuid.UUID) (map[uuid.UUID]Target, map[uuid.UUID]deployLocation, error) {
	rows, err := tx.Query(ctx, "SELECT DISTINCT ON (target_id) target_id, id FROM certificate_locations WHERE id = ANY($1) ORDER BY target_id, id", ids)
	if err != nil {
		return nil, nil, fmt.Errorf("inventory: read the locations' servers: %w", err)
	}
	type serverOf struct{ target, location uuid.UUID }
	servers, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (serverOf, error) {
		var o serverOf
		return o, r.Scan(&o.target, &o.location)
	})
	if err != nil {
		return nil, nil, fmt.Errorf("inventory: read the locations' servers: %w", err)
	}
	targets := map[uuid.UUID]Target{}
	for _, sv := range servers {
		// FOR NO KEY UPDATE: nothing here changes the target's key, and the KEY SHARE locks that
		// job and deployment rows take on it (their foreign keys) do not conflict with it, so a
		// request never waits on the sweep's job insert while the sweep waits on its audit lock.
		t, err := scanTarget(tx.QueryRow(ctx, "SELECT "+targetColumns+" FROM targets WHERE id = $1 AND deleted_at IS NULL FOR NO KEY UPDATE", sv.target))
		if errors.Is(err, ErrNotFound) { // the server was deleted: name a website of it
			return nil, nil, &LocationRefusalError{LocationID: sv.location, Err: ErrNotFound}
		}
		if err != nil {
			return nil, nil, err
		}
		targets[sv.target] = t
	}
	rows, err = tx.Query(ctx, `SELECT id, target_id, cert_path, key_path, cert_file_sha256, key_type, servers, supported, missing_since IS NOT NULL,
    kind, locator IS NOT NULL
FROM certificate_locations WHERE id = ANY($1) ORDER BY id FOR NO KEY UPDATE`, ids)
	if err != nil {
		return nil, nil, fmt.Errorf("inventory: lock the locations: %w", err)
	}
	defer rows.Close()
	locs := map[uuid.UUID]deployLocation{}
	for rows.Next() {
		var l deployLocation
		var servers []byte
		if err := rows.Scan(&l.id, &l.target, &l.certPath, &l.keyPath, &l.fileSHA, &l.keyType, &servers, &l.supported, &l.missing,
			&l.kind, &l.hasLocator); err != nil {
			return nil, nil, fmt.Errorf("inventory: read a location: %w", err)
		}
		if err := json.Unmarshal(servers, &l.servers); err != nil {
			return nil, nil, fmt.Errorf("inventory: decode location servers: %w", err)
		}
		locs[l.id] = l
	}
	if err := rows.Err(); err != nil {
		return nil, nil, fmt.Errorf("inventory: lock the locations: %w", err)
	}
	if len(locs) != len(ids) {
		for _, id := range ids {
			if _, ok := locs[id]; !ok {
				return nil, nil, &LocationRefusalError{LocationID: id, Err: ErrNotFound}
			}
		}
		return nil, nil, ErrNotFound
	}
	return targets, locs, nil
}

// checkDeployLocation is RequestDeployment's per-location refusal and its audit reason. It is every deploy path's check
// (a person's request, a Key Vault or ACME binding's Deploy now, both automatic planners): one of them is the trust of
// R49 (design §5.6 (c)), an *authz.UntrustedError when the server's service does not accept the source service's keys.
func (s *Service) checkDeployLocation(ctx context.Context, tx pgx.Tx, c deployCertificate, l deployLocation, t Target) (string, error) {
	switch {
	case !l.deployable():
		return "location_unsupported", ErrLocationUnsupported
	case !s.canDeploy(t.Type):
		return "location_unsupported", ErrLocationUnsupported
	case !slices.Contains(targetReady, t.Status):
		return "target_not_ready", ErrTargetNotReady
	case l.kind.IsFile() && (t.Facts.WebServer == nil || !t.Facts.WebServer.ConfigValid):
		// The web server's configuration gates its files; another kind's provider refuses its own preconditions (R59).
		return "config_invalid", ErrNginxConfigInvalid
	case !hex64RE.MatchString(l.fileSHA):
		return "rescan_needed", ErrLocationNeedsDiscovery
	case l.keyType != "" && l.keyType != c.algorithm:
		return "key_type_mismatch", &KeyTypeMismatchError{Expected: l.keyType, Actual: c.algorithm}
	}
	if !c.trustExempt {
		if err := authz.CheckTrust(ctx, tx, c.service, t.ServiceID); errors.Is(err, ErrServiceUntrusted) {
			return ReasonServiceUntrusted, err
		} else if err != nil {
			return "", err
		}
	}
	var recovering, active bool
	err := tx.QueryRow(ctx, `SELECT
    EXISTS (SELECT 1 FROM deployments WHERE target_id = $1 AND state = $3),
    EXISTS (SELECT 1 FROM deployments WHERE location_id = $2 AND state <> $4)`,
		t.ID, l.id, DeployStateRecovering, DeployStateDone).Scan(&recovering, &active)
	switch {
	case err != nil:
		return "", fmt.Errorf("inventory: read the server's deployments: %w", err)
	case recovering:
		return "recovery_pending", ErrRecoveryPending
	case active:
		return "in_progress", ErrDeploymentInProgress
	}
	return "", nil
}

// deployablePath is deployments.cert_path/key_path's CHECK: a path the helper accepts.
func deployablePath(p string) bool { return len(p) <= 4096 && deployPathRE.MatchString(p) }

// can reports whether the registered provider of the target type has the capability.
func (s *Service) can(typ string, c providers.Capability) bool {
	p, ok := s.providerFor(typ)
	return ok && p.Capabilities().Has(c)
}

// canDeploy reports whether the registered provider of the target type deploys certificates.
func (s *Service) canDeploy(typ string) bool { return s.can(typ, providers.CapDeployCertificate) }

// deploySource says where a deployment comes from: its trigger ("manual" for a person's request,
// "kv_renewal" for the automatic planner), whether an Administrator confirmed an incomplete chain
// (F-17), and, for a Key Vault deployment, the binding and the stored version it deploys (written
// together: deployments_kv_source). Version is the vault's version string, for the audit row.
type deploySource struct {
	Trigger     string
	BindingID   *uuid.UUID
	KVVersionID *uuid.UUID
	Confirmed   bool
	Version     string
}

func (s *Service) insertDeployment(ctx context.Context, tx pgx.Tx, a Actor, c deployCertificate, l deployLocation, src deploySource,
	now time.Time) (RequestedDeployment, error) {
	id := uuid.Must(uuid.NewV7())
	_, err := tx.Exec(ctx, `INSERT INTO deployments (id, certificate_id, location_id, target_id, trigger, requested_by, state, status,
    new_fingerprint, cert_path, key_path, confirm_incomplete_chain, binding_id, kv_version_id, created_at, location_kind)
VALUES ($1, $2, $3, $4, $13, $5, $6, $7, $8, $9, $10, $11, $14, $15, $12, $16)`, id, c.id, l.id, l.target, nullableUser(a.UserID),
		DeployStateQueued, DeployStatusPending, c.fingerprint, l.certPath, l.keyPath, src.Confirmed, now, src.Trigger, src.BindingID, src.KVVersionID,
		l.kind.OrFile())
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" && pgErr.ConstraintName == "deployments_one_active" {
		return RequestedDeployment{}, ErrDeploymentInProgress
	}
	if err != nil {
		return RequestedDeployment{}, fmt.Errorf("inventory: store the deployment: %w", err)
	}
	// A deployment the automatic planners queued is continuity work (certificate.deploy_auto: it runs in the continuity
	// window of a lock); a person's is a change (certificate.deploy). Both share the handler and the dedupe namespace.
	// An automatic drift repair (R52) is upkeep of an already managed certificate too.
	jobType := JobCertificateDeploy
	if src.Trigger == TriggerACMERenewal || src.Trigger == triggerKVRenewal || src.Trigger == TriggerDriftRepair {
		jobType = JobCertificateDeployAuto
	}
	jobID, err := s.jobs.EnqueueTx(ctx, tx, JobRequest{Type: jobType, TargetID: l.target,
		Payload: map[string]string{"deployment_id": id.String()}, Kind: a.jobKind(), CreatedBy: a.UserID, CreatedByRole: string(a.Role),
		DedupeKey: deployDedupePrefix + id.String()})
	if err != nil {
		return RequestedDeployment{}, err
	}
	if _, err := tx.Exec(ctx, "UPDATE deployments SET job_id = $2 WHERE id = $1", id, jobID); err != nil {
		return RequestedDeployment{}, fmt.Errorf("inventory: link the deployment's job: %w", err)
	}
	warnings := []string{}
	if sanMismatch(c.sans, l.servers) {
		warnings = append(warnings, WarnSANMismatch)
	}
	details := map[string]string{"deployment_id": id.String(),
		"certificate_id": c.id.String(), "location_id": l.id.String(), "cert_path": l.certPath, "job_id": jobID.String(),
		"confirm_incomplete_chain": strconv.FormatBool(src.Confirmed)}
	if src.BindingID != nil {
		details["binding_id"] = src.BindingID.String()
		details["version"] = src.Version
	}
	_, err = s.audit.Append(ctx, tx, audit.Event{Actor: a.Audit, Action: "deployment.requested", ObjectType: "deployment",
		ObjectID: id.String(), Result: audit.Success, Details: details})
	if err != nil {
		return RequestedDeployment{}, err
	}
	return RequestedDeployment{ID: id, JobID: jobID, LocationID: l.id, Warnings: warnings}, nil
}

// auditDeployDenial records a refused request in its own transaction (the request's was rolled
// back); like auditLicenseDenial it outlives the request for at most detachedTimeout.
func (s *Service) auditDeployDenial(ctx context.Context, a Actor, certificate uuid.UUID, d deployDenial) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), detachedTimeout)
	defer cancel()
	details := map[string]string{"certificate_id": certificate.String(), "reason": d.reason}
	if d.location != uuid.Nil {
		details["location_id"] = d.location.String()
	}
	err := db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		_, err := s.audit.Append(ctx, tx, audit.Event{Actor: a.Audit, Action: "deployment.denied", ObjectType: "certificate",
			ObjectID: certificate.String(), Result: audit.Denied, Details: details})
		return err
	})
	if err != nil {
		s.log.Error("could not audit a refused deployment", "error_type", fmt.Sprintf("%T", err))
	}
}

// deploymentSelect reads Deployment rows (scanDeployment's order), for deleted targets too (history).
const deploymentSelect = `SELECT d.id, d.certificate_id, coalesce(nullif(c.label, ''), nullif(c.subject_cn, ''), left(c.fingerprint_sha256, 16)),
d.location_id, d.target_id, t.name::text, d.cert_path, d.key_path, d.job_id, d.trigger, d.requested_by, coalesce(u.display_name, ''),
d.state, d.status, d.new_fingerprint, d.previous_fingerprint, d.confirm_incomplete_chain, d.rollback_info, d.verified, d.error_code,
d.error_params, d.failed_step, d.created_at, d.started_at, d.finished_at, d.result, d.phase, d.cause_step, d.helper_error,
d.verify_failed_reason, d.verify_failed_port, d.operation_id, d.new_chain_length, d.previous_chain_length, d.expect_cert_sha256,
d.recover_after, d.recovery_attempts, coalesce(j.status, ''), d.binding_id, coalesce(v.version, ''), coalesce(vt.name::text, ''), c.source,
d.rollback_leaf_sha256, d.rollback_spki_sha256, d.trust_status, d.trust_error, d.trust_port, d.trust_store, d.trust_enforced
FROM deployments d
JOIN certificates c ON c.id = d.certificate_id
JOIN targets t ON t.id = d.target_id
LEFT JOIN users u ON u.id = d.requested_by
LEFT JOIN jobs j ON j.id = d.job_id
LEFT JOIN kv_certificate_versions v ON v.id = d.kv_version_id
LEFT JOIN kv_certificates kc ON kc.id = v.kv_certificate_id
LEFT JOIN targets vt ON vt.id = kc.target_id`

func scanDeployment(row pgx.Row) (Deployment, error) {
	var (
		d              Deployment
		backup, params []byte
		certSource     string
		trustPort      *int
	)
	err := row.Scan(&d.ID, &d.CertificateID, &d.CertificateName, &d.LocationID, &d.TargetID, &d.TargetName, &d.CertPath, &d.KeyPath,
		&d.JobID, &d.Trigger, &d.RequestedBy, &d.RequestedByName, &d.State, &d.Status, &d.NewFingerprint, &d.PreviousFingerprint,
		&d.ConfirmIncompleteChain, &backup, &d.Verified, &d.ErrorCode, &params, &d.FailedStep, &d.CreatedAt, &d.StartedAt, &d.FinishedAt,
		&d.Result, &d.Phase, &d.CauseStep, &d.HelperError, &d.VerifyFailedReason, &d.VerifyFailedPort, &d.OperationID, &d.NewChainLength,
		&d.PreviousChainLength, &d.ExpectCertSHA256, &d.RecoverAfter, &d.RecoveryAttempts, &d.JobStatus, &d.BindingID, &d.KVVersion, &d.VaultName, &certSource,
		&d.RollbackLeafSHA256, &d.RollbackSPKISHA256, &d.Trust.Status, &d.Trust.Error, &trustPort, &d.Trust.Store, &d.Trust.Enforced)
	if errors.Is(err, pgx.ErrNoRows) {
		return Deployment{}, ErrNotFound
	}
	if err != nil {
		return Deployment{}, fmt.Errorf("inventory: read deployment: %w", err)
	}
	if backup != nil {
		d.Backup = &providers.BackupRef{}
		if err := json.Unmarshal(backup, d.Backup); err != nil {
			return Deployment{}, fmt.Errorf("inventory: decode the deployment's backup: %w", err)
		}
	}
	d.ErrorParams = map[string]string{}
	if err := json.Unmarshal(params, &d.ErrorParams); err != nil {
		return Deployment{}, fmt.Errorf("inventory: decode the deployment's error params: %w", err)
	}
	if d.ErrorParams == nil {
		d.ErrorParams = map[string]string{}
	}
	if trustPort != nil {
		d.Trust.Port = *trustPort
	}
	if d.Status == DeployStatusSucceeded || d.Status == DeployStatusUnchanged {
		d.Level = providers.VerificationLevel(d.Verified, d.Trust.Status)
	}
	switch {
	case d.BindingID != nil:
		d.Source = "key_vault"
	case certSource == "acme":
		d.Source = "acme"
	default:
		d.Source = "upload"
	}
	d.CreatedAt = d.CreatedAt.UTC()
	d.StartedAt, d.FinishedAt, d.RecoverAfter = utcPtr(d.StartedAt), utcPtr(d.FinishedAt), utcPtr(d.RecoverAfter)
	return d, nil
}

// Deployment returns one deployment with its steps in order.
func (s *Service) Deployment(ctx context.Context, id uuid.UUID) (Deployment, error) {
	d, err := scanDeployment(s.pool.QueryRow(ctx, deploymentSelect+" WHERE d.id = $1", id))
	if err != nil {
		return Deployment{}, err
	}
	rows, err := s.pool.Query(ctx, "SELECT n, name, status, at, params FROM deployment_steps WHERE deployment_id = $1 ORDER BY n", id)
	if err != nil {
		return Deployment{}, fmt.Errorf("inventory: read deployment steps: %w", err)
	}
	defer rows.Close()
	d.Steps = []DeploymentStep{}
	for rows.Next() {
		var st DeploymentStep
		var params []byte
		if err := rows.Scan(&st.N, &st.Name, &st.Status, &st.At, &params); err != nil {
			return Deployment{}, fmt.Errorf("inventory: read deployment steps: %w", err)
		}
		st.Params = map[string]string{}
		if err := json.Unmarshal(params, &st.Params); err != nil {
			return Deployment{}, fmt.Errorf("inventory: decode step params: %w", err)
		}
		st.At = st.At.UTC()
		d.Steps = append(d.Steps, st)
	}
	return d, rows.Err()
}

func nullID(id uuid.UUID) *uuid.UUID {
	if id == uuid.Nil {
		return nil
	}
	return &id
}

// ListDeployments pages deployments newest first (created_at, id), filtered by target,
// certificate and location; the cursor is the last row's (created_at, id).
func (s *Service) ListDeployments(ctx context.Context, f DeploymentFilter) (DeploymentPage, error) {
	var errs validate.Errors
	limit := f.Limit
	switch {
	case limit == 0:
		limit = defaultDeploymentLimit
	case limit < 1 || limit > maxDeploymentLimit:
		errs.Add("limit", validate.OutOfRange, map[string]string{"min": "1", "max": strconv.Itoa(maxDeploymentLimit)})
	}
	var afterAt *time.Time
	afterID := uuid.Nil
	if f.Cursor != "" {
		at, id, err := decodeCursor(f.Cursor)
		if err != nil {
			errs.Add("cursor", validate.Pattern, nil)
		} else {
			afterAt, afterID = &at, id
		}
	}
	if len(errs) > 0 {
		return DeploymentPage{}, errs
	}
	rows, err := s.pool.Query(ctx, deploymentSelect+`
WHERE ($1::uuid IS NULL OR d.target_id = $1)
  AND ($2::uuid IS NULL OR d.certificate_id = $2)
  AND ($3::uuid IS NULL OR d.location_id = $3)
  AND ($4::timestamptz IS NULL OR (d.created_at, d.id) < ($4::timestamptz, $5::uuid))
  AND `+authz.DeploymentVisible("d", "$7")+`
ORDER BY d.created_at DESC, d.id DESC
LIMIT $6`, nullID(f.TargetID), nullID(f.CertificateID), nullID(f.LocationID), afterAt, afterID, limit+1, f.Reach.SQL())
	if err != nil {
		return DeploymentPage{}, fmt.Errorf("inventory: list deployments: %w", err)
	}
	defer rows.Close()
	page := DeploymentPage{Items: []Deployment{}}
	for rows.Next() {
		d, err := scanDeployment(rows)
		if err != nil {
			return DeploymentPage{}, err
		}
		page.Items = append(page.Items, d)
	}
	if err := rows.Err(); err != nil {
		return DeploymentPage{}, fmt.Errorf("inventory: list deployments: %w", err)
	}
	if len(page.Items) > limit {
		page.Items = page.Items[:limit]
		last := page.Items[limit-1]
		page.NextCursor = encodeCursor(last.CreatedAt, last.ID)
	}
	return page, nil
}
