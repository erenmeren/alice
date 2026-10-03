package inventory

// The deployment engine's side of the records (Task 16 calls these; see the state machine in
// deployments.go). The engine, per deployment job:
//
//  1. d := Deployment(id); a done deployment is left alone. In deploying or recovering a send may
//     have happened: never send again, recover (read DeploymentStatus first).
//  2. CheckRecoveryPending(id): another deployment on the server is being recovered (it was queued
//     before that recovery began) → FinishDeployment(failed, "deployment.recovery_pending") or a
//     retryable error; StartDeployment checks it again under the lock.
//  3. BeginDeployment (queued -> precheck), then m := DeploymentMaterial(id, true): the record, the
//     location, the certificate and the key (unsealed for this first send only).
//  4. The pre-check: VerifyDeployment(m.PrecheckRequest()) with the currently deployed
//     fingerprint and key type (the only "cannot check -> no change" guard). A refusal, and any
//     failure before the send, ends the deployment with FinishDeployment(failed): nothing was sent
//     (MarkRecovering, RequestRecovery and an uncertain RecordOutcome refuse it).
//  5. v := m.SendValues(served fingerprint, served chain length); StartDeployment(id, v) records
//     exactly what will be sent, in ONE update before the first send (precheck -> deploying).
//  6. DeployCertificate(m.DeployRequest(v)), the steps through RecordDeploymentStep; zero
//     m.PrivateKeyPEM as soon as the call returns.
//  7. rec := DeployOutcomeRecord(outcome, err, false); after a helper restore_failed
//     (rec.RetryRollback) run RollbackDeployment once more and record RollbackOutcomeRecord of that
//     instead; for a success set rec.Finish.CertFileSHA256 = m.NewCertSHA256; then
//     RecordOutcome(id, rec, now + FirstRecoveryDelay). An uncertain outcome stays in recovery:
//     the sweep queues the recovery when recover_after passes (D22: a job request has no run-at).
//
// A recovery job (one attempt; the sweep queues the next RecoveryRetryInterval later):
// m := DeploymentMaterial(id, false) (the RECORDED values; never re-derived), DeploymentStatus,
// then re-verify with m.VerifyRequest() (a committed journal is never success without it), roll
// back with m.RollbackRequest(), and RecordOutcome with the mapped record (a success's
// CertFileSHA256 is the journal's NewCertSHA256). It returns nil when it recorded an outcome
// (terminal or uncertain), and the provider's error (jobs.FromProvider) when it could not reach
// or use the server: the job then ends failed, never dead, and the sweep escalates
// (needs_attention after RecoveryAttentionAfter attempts, rollback_failed after
// MaxRecoveryAttempts). deployment.superseded is final (RollbackOutcomeRecord ends the deployment
// with it).

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"alice/internal/audit"
	"alice/internal/certs"
	"alice/internal/platform/db"
	"alice/internal/providers"
	"alice/internal/secrets"
)

// SendValues are what a deployment records before its first send (Task 12 ruling): the
// operation id (the deployment id), the certificate file hash the helper's compare-and-swap
// expects, the number of certificates sent, and what the website served before the change.
// Recovery reads them back from the record.
type SendValues struct {
	OperationID         uuid.UUID
	ExpectCertSHA256    string
	NewChainLength      int
	PreviousFingerprint string // "" when unknown (verification skipped)
	PreviousChainLength int    // 0 = not compared
}

// Material is what a deploy or recovery job needs to build its provider requests. The send values
// (ExpectCertSHA256, NewChainLength, PreviousFingerprint, PreviousChainLength) are the RECORDED
// ones once a send may have happened (Recorded); before, the location's and certificate's current
// ones. PrivateKeyPEM is empty unless withKey: a non-printable holder the caller zeroes.
type Material struct {
	Deployment         Deployment
	Location           providers.CertLocation // the RECORDED paths; servers and flags as last discovered
	CertificatePEM     []byte                 // leaf first, then the chain (public)
	PrivateKeyPEM      secrets.Plaintext
	Fingerprint        string    // the new leaf
	SANs               []string  // the new leaf's
	NotBefore          time.Time // the new leaf's (the engine re-checks the validity at run time)
	NotAfter           time.Time // the new leaf's
	KeyType            string    // "rsa" | "ecdsa" (the new leaf's algorithm)
	CurrentFingerprint string    // the leaf in the location's file at the last discovery ("" when unknown)
	OldSANs            []string  // the SANs of the previous leaf (SNI for default servers when checking it)
	ExpectCertSHA256   string    // the certificate file's SHA-256 the first send expects
	Verify             providers.VerifyOptions
	ConfigValid        bool
	// Task 15 additions.
	OldKeyType          string // the previous leaf's key type ("" = KeyType)
	NewChainLength      int    // certificates in the chain sent (recorded once Recorded)
	NewCertSHA256       string // SHA-256 of CertificatePEM: the file's hash once the helper wrote it
	PreviousFingerprint string // recorded; "" before the first send
	PreviousChainLength int    // recorded; 0 before the first send
	Recorded            bool   // state deploying, recovering or done: the send values come from the record
}

// PrecheckRequest verifies what the website serves now, before any change: the location's current
// certificate (the engine's pre-check, F-06, F-07).
func (m Material) PrecheckRequest() providers.VerifyRequest {
	return providers.VerifyRequest{Location: m.Location, Fingerprint: m.CurrentFingerprint, SANs: m.OldSANs, KeyType: m.oldKeyType(),
		Verify: m.Verify}
}

// SendValues are the values to record with StartDeployment, given what the pre-check found
// served (its fingerprint and chain length).
func (m Material) SendValues(previousFingerprint string, previousChainLength int) SendValues {
	return SendValues{OperationID: m.Deployment.ID, ExpectCertSHA256: m.ExpectCertSHA256, NewChainLength: m.NewChainLength,
		PreviousFingerprint: previousFingerprint, PreviousChainLength: previousChainLength}
}

// DeployRequest is the first send of v (after StartDeployment recorded it). It shares
// PrivateKeyPEM's holder: zeroing either zeroes both.
func (m Material) DeployRequest(v SendValues) providers.DeployRequest {
	return providers.DeployRequest{OperationID: v.OperationID, Location: m.Location, ExpectCertSHA256: v.ExpectCertSHA256,
		CertificatePEM: m.CertificatePEM, PrivateKeyPEM: m.PrivateKeyPEM, Fingerprint: m.Fingerprint, SANs: m.SANs, KeyType: m.KeyType,
		OldFingerprint: v.PreviousFingerprint, OldSANs: m.OldSANs, Verify: m.Verify, ChainLength: v.NewChainLength}
}

// VerifyRequest checks the new certificate with the recorded fingerprint and chain length (a
// committed journal is never success without it).
func (m Material) VerifyRequest() providers.VerifyRequest {
	return providers.VerifyRequest{Location: m.Location, Fingerprint: m.Fingerprint, ChainLength: m.NewChainLength,
		PreviousFingerprint: m.PreviousFingerprint, SANs: m.SANs, KeyType: m.KeyType, Verify: m.Verify}
}

// RollbackRequest restores the recorded operation and checks the recorded previous certificate.
func (m Material) RollbackRequest() providers.RollbackRequest {
	op := m.Deployment.ID
	if m.Deployment.OperationID != nil {
		op = *m.Deployment.OperationID
	}
	return providers.RollbackRequest{OperationID: op, Location: m.Location, OldFingerprint: m.PreviousFingerprint,
		OldChainLength: m.PreviousChainLength, OldSANs: m.OldSANs, KeyType: m.oldKeyType(), Verify: m.Verify}
}

func (m Material) oldKeyType() string {
	if m.OldKeyType != "" {
		return m.OldKeyType
	}
	return m.KeyType
}

// sent reports whether a send may have happened in this state.
func sent(state string) bool {
	return state == DeployStateDeploying || state == DeployStateRecovering || state == DeployStateDone
}

// chainLength counts the CERTIFICATE blocks of a PEM text (as the provider does).
func chainLength(p []byte) int {
	n := 0
	for rest := p; ; {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			return n
		}
		if b.Type == "CERTIFICATE" {
			n++
		}
	}
}

func sha256Hex(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// DeploymentMaterial reads what a job needs (see Material). withKey unseals the certificate's
// private key through loadKey with the certificate's own private_key_id, checks that it is the
// key of the certificate (its public key hash) and returns it as PEM; only before the first send
// (queued or precheck: recovery and rollback never need the key), else ErrDeploymentState.
func (s *Service) DeploymentMaterial(ctx context.Context, id uuid.UUID, withKey bool) (Material, error) {
	d, err := scanDeployment(s.pool.QueryRow(ctx, deploymentSelect+" WHERE d.id = $1", id))
	if err != nil {
		return Material{}, err
	}
	if withKey && sent(d.State) {
		return Material{}, ErrDeploymentState
	}
	m := Material{Deployment: d, Recorded: sent(d.State)}
	var (
		servers                      []byte
		verifyPort                   *int
		fileSHA, currentType         string
		keyID                        *uuid.UUID
		publicKey, pemChain, oldType string
		facts                        []byte
	)
	err = s.pool.QueryRow(ctx, `SELECT l.servers, l.supported AND l.missing_since IS NULL, l.resolved_cert_path, l.inherited, l.symlinked,
    l.custom_location, l.key_exists, l.key_mode, l.key_owner, l.key_group, l.cert_file_sha256, l.verify_port, coalesce(l.verify_sni, ''),
    l.skip_verify, coalesce(oc.fingerprint_sha256, ''), coalesce(oc.sans, '{}'), l.key_type,
    c.pem_chain, c.fingerprint_sha256, c.sans, c.not_before, c.not_after, c.key_algorithm, c.private_key_id, c.public_key_sha256, t.facts
FROM certificate_locations l
JOIN certificates c ON c.id = $2
JOIN targets t ON t.id = l.target_id
LEFT JOIN certificates oc ON oc.id = l.certificate_id
WHERE l.id = $1`, d.LocationID, d.CertificateID).Scan(&servers, &m.Location.Supported, &m.Location.ResolvedCertPath, &m.Location.Inherited,
		&m.Location.Symlinked, &m.Location.CustomLocation, &m.Location.KeyExists, &m.Location.KeyMode, &m.Location.KeyOwner,
		&m.Location.KeyGroup, &fileSHA, &verifyPort, &m.Verify.SNI, &m.Verify.Skip, &m.CurrentFingerprint, &m.OldSANs, &currentType,
		&pemChain, &m.Fingerprint, &m.SANs, &m.NotBefore, &m.NotAfter, &m.KeyType, &keyID, &publicKey, &facts)
	if errors.Is(err, pgx.ErrNoRows) {
		return Material{}, ErrNotFound
	}
	if err != nil {
		return Material{}, fmt.Errorf("inventory: read the deployment's material: %w", err)
	}
	if err := json.Unmarshal(servers, &m.Location.Servers); err != nil {
		return Material{}, fmt.Errorf("inventory: decode location servers: %w", err)
	}
	var f Facts
	if err := json.Unmarshal(facts, &f); err != nil {
		return Material{}, fmt.Errorf("inventory: decode target facts: %w", err)
	}
	m.ConfigValid = f.Nginx != nil && f.Nginx.ConfigValid
	m.Location.CertPath, m.Location.KeyPath = d.CertPath, d.KeyPath
	if verifyPort != nil {
		m.Verify.Port = *verifyPort
	}
	m.NotBefore, m.NotAfter = m.NotBefore.UTC(), m.NotAfter.UTC()
	m.CertificatePEM = []byte(pemChain)
	m.NewCertSHA256 = sha256Hex(m.CertificatePEM)
	oldType = currentType
	if m.Recorded {
		m.ExpectCertSHA256, m.NewChainLength = d.ExpectCertSHA256, d.NewChainLength
		m.PreviousFingerprint, m.PreviousChainLength = d.PreviousFingerprint, d.PreviousChainLength
		// The location may hold the new certificate by now: the previous one is the recorded leaf.
		m.OldSANs, oldType = []string{}, ""
		if d.PreviousFingerprint != "" {
			err := s.pool.QueryRow(ctx, "SELECT sans, key_algorithm FROM certificates WHERE fingerprint_sha256 = $1", d.PreviousFingerprint).
				Scan(&m.OldSANs, &oldType)
			if err != nil && !errors.Is(err, pgx.ErrNoRows) {
				return Material{}, fmt.Errorf("inventory: read the previous certificate: %w", err)
			}
		}
	} else {
		m.ExpectCertSHA256, m.NewChainLength = fileSHA, chainLength(m.CertificatePEM)
	}
	if oldType == "rsa" || oldType == "ecdsa" {
		m.OldKeyType = oldType
	}
	if m.OldSANs == nil {
		m.OldSANs = []string{}
	}
	if withKey {
		if keyID == nil {
			return Material{}, ErrNoPrivateKey
		}
		if m.PrivateKeyPEM, err = s.certificateKeyPEM(ctx, *keyID, publicKey); err != nil {
			return Material{}, err
		}
	}
	return m, nil
}

// errForeignKey: the sealed key is not the certificate's (its public key hash differs).
var errForeignKey = errors.New("inventory: the stored private key does not belong to the certificate")

// certificateKeyPEM unseals a certificate's key (keyID is the certificate's private_key_id, the only
// key id this is ever called with), checks it against the certificate's public key hash and
// returns it as PEM. The DER is zeroed before return; nothing here logs or returns key material.
func (s *Service) certificateKeyPEM(ctx context.Context, keyID uuid.UUID, publicKeySHA256 string) (secrets.Plaintext, error) {
	der, err := s.loadKey(ctx, s.pool, keyID)
	if err != nil {
		return secrets.Plaintext{}, err
	}
	defer der.Zero()
	info, err := certs.KeyInfoOf(der)
	if err != nil || info.PublicKeySHA256 != publicKeySHA256 {
		return secrets.Plaintext{}, errForeignKey
	}
	return certs.KeyPEM(der)
}

// lockedDeployment is the part of a deployment row its writers read under the row lock.
type lockedDeployment struct {
	id, location, target, certificate uuid.UUID
	state, status                     string
	certPath                          string
	newFingerprint, previous          string
	operation                         *uuid.UUID
	attempts                          int
	errorCode                         string
}

// wasSent reports whether a send may have happened: deploying or recovering with an operation id
// recorded by StartDeployment. A row without one never sent anything, whatever its state says.
func (d lockedDeployment) wasSent() bool {
	return (d.state == DeployStateDeploying || d.state == DeployStateRecovering) && d.operation != nil
}

const lockedDeploymentColumns = `d.id, d.location_id, d.target_id, d.certificate_id, d.state, d.status, d.cert_path, d.new_fingerprint,
d.previous_fingerprint, d.operation_id, d.recovery_attempts, d.error_code`

func scanLocked(row pgx.Row, extra ...any) (lockedDeployment, error) {
	var d lockedDeployment
	err := row.Scan(append([]any{&d.id, &d.location, &d.target, &d.certificate, &d.state, &d.status, &d.certPath, &d.newFingerprint,
		&d.previous, &d.operation, &d.attempts, &d.errorCode}, extra...)...)
	if errors.Is(err, pgx.ErrNoRows) {
		return lockedDeployment{}, ErrNotFound
	}
	if err != nil {
		return lockedDeployment{}, fmt.Errorf("inventory: read deployment: %w", err)
	}
	return d, nil
}

// lockDeployment reads a deployment under its row lock (FOR NO KEY UPDATE: references to it are
// not blocked).
func lockDeployment(ctx context.Context, tx pgx.Tx, id uuid.UUID) (lockedDeployment, error) {
	return scanLocked(tx.QueryRow(ctx, "SELECT "+lockedDeploymentColumns+" FROM deployments d WHERE d.id = $1 FOR NO KEY UPDATE", id))
}

func (s *Service) appendAudit(ctx context.Context, tx pgx.Tx, action string, result audit.Result, id uuid.UUID, details map[string]string) error {
	details["deployment_id"] = id.String()
	_, err := s.audit.Append(ctx, tx, audit.Event{Actor: jobsActor, Action: action, ObjectType: "deployment", ObjectID: id.String(),
		Result: result, Details: details})
	return err
}

// BeginDeployment moves a queued deployment to precheck (status running, started_at set when the
// pre-check begins; StartDeployment moves it to the start record) and
// returns it. It is idempotent: a deployment in any other state is returned unchanged, and the
// caller follows its state (deploying or recovering: recover; done: nothing to do).
func (s *Service) BeginDeployment(ctx context.Context, id uuid.UUID) (Deployment, error) {
	err := db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE deployments SET state = $3, status = $4, started_at = coalesce(started_at, $2)
WHERE id = $1 AND state = $5`, id, s.clock.Now().UTC(), DeployStatePrecheck, DeployStatusRunning, DeployStateQueued)
		if err != nil {
			return fmt.Errorf("inventory: begin the deployment: %w", err)
		}
		if tag.RowsAffected() == 0 {
			return nil
		}
		return s.appendAudit(ctx, tx, "deployment.precheck_started", audit.Success, id, map[string]string{})
	})
	if err != nil {
		return Deployment{}, err
	}
	return s.Deployment(ctx, id)
}

// StartDeployment records the send values in ONE update before the first send and moves the
// deployment from precheck to deploying (from then on a send may have happened, and recovery reads
// these values back). v must be exactly what the engine sends (Material.SendValues with the
// pre-check's served fingerprint and chain length): nothing here is re-read from the location or
// the certificate. rollback_info is the helper's backup of the operation (spec §6.3 item 3). Only
// from precheck (ErrDeploymentState otherwise, so a second start never overwrites a record), and
// never while another deployment on the server is being recovered (ErrRecoveryPending: the
// deployment was queued before that recovery began; finish it failed with
// deployment.recovery_pending, or retry later). started_at becomes the time of this start record
// (BeginDeployment set it when the pre-check began): a recovery that finds no journal on the server
// treats that as final only once the helper's budget has passed since then (S6).
//
// The recovery-pending check here and in CheckRecoveryPending is best-effort: it sees recoveries
// that have committed. A sibling deployment entering recovery in a concurrent transaction that has
// not committed yet is not seen, and both may start. That is safe: the per-target job lock (one job
// per server at a time) and the helper's own lock serialise the actual work on the server; the
// check only keeps new changes from starting while a recovery is known to be pending.
func (s *Service) StartDeployment(ctx context.Context, id uuid.UUID, v SendValues) error {
	return s.startDeployment(ctx, id, v)
}

// CheckRecoveryPending is ErrRecoveryPending when another deployment on the deployment's server
// is being recovered (state recovering): the deploy job checks it before its pre-check, and
// StartDeployment checks it again under the deployment's lock. Best-effort: see StartDeployment.
func (s *Service) CheckRecoveryPending(ctx context.Context, id uuid.UUID) error {
	return recoveryPending(ctx, s.pool, id)
}

func recoveryPending(ctx context.Context, q db.Querier, id uuid.UUID) error {
	var exists, pending bool
	err := q.QueryRow(ctx, `SELECT true, EXISTS (SELECT 1 FROM deployments o WHERE o.target_id = d.target_id AND o.id <> d.id AND o.state = $2)
FROM deployments d WHERE d.id = $1`, id, DeployStateRecovering).Scan(&exists, &pending)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return ErrNotFound
	case err != nil:
		return fmt.Errorf("inventory: read the server's recoveries: %w", err)
	case pending:
		return ErrRecoveryPending
	}
	return nil
}

func (s *Service) startDeployment(ctx context.Context, id uuid.UUID, v SendValues) error {
	return db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		d, err := lockDeployment(ctx, tx, id)
		if err != nil {
			return err
		}
		if d.state != DeployStatePrecheck {
			return ErrDeploymentState
		}
		if err := recoveryPending(ctx, tx, id); err != nil {
			return err
		}
		switch {
		case v.OperationID != id:
			return errors.New("inventory: the operation id is the deployment id")
		case !hex64RE.MatchString(v.ExpectCertSHA256):
			return errors.New("inventory: no file hash to compare: the location must be discovered again")
		case v.NewChainLength < 1:
			return errors.New("inventory: the certificate has no chain to send")
		case v.PreviousFingerprint != "" && !hex64RE.MatchString(v.PreviousFingerprint):
			return errors.New("inventory: the previous fingerprint is not a SHA-256")
		case v.PreviousChainLength < 0:
			return errors.New("inventory: a negative chain length")
		}
		backup, err := json.Marshal(providers.BackupRef{OperationID: id, Dir: BackupRoot + "/" + id.String()})
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE deployments SET state = $2, operation_id = $3, expect_cert_sha256 = $4, new_chain_length = $5,
    previous_fingerprint = $6, previous_chain_length = $7, rollback_info = $8, started_at = $9
WHERE id = $1`, id, DeployStateDeploying, v.OperationID, v.ExpectCertSHA256, v.NewChainLength, v.PreviousFingerprint,
			v.PreviousChainLength, backup, s.clock.Now().UTC()); err != nil {
			return fmt.Errorf("inventory: record the send: %w", err)
		}
		return s.appendAudit(ctx, tx, "deployment.started", audit.Success, id, map[string]string{"operation_id": id.String(),
			"previous_fingerprint": v.PreviousFingerprint, "new_fingerprint": d.newFingerprint})
	})
}

// stepParamKeys are the step params a record keeps (providers.StepLogger's primitives).
var stepParamKeys = []string{"error", "port", "mode", "served"}

// errorParamKeys are the error params a record keeps (the providers' allowlist, Tasks 11 and 17).
var errorParamKeys = []string{"port", "failed_step", "profile", "phase", "directory", "backup_dir", "expected", "actual", "mode",
	"helper_code", "subcommand"}

const (
	maxParamValue = 256  // bytes of one param value
	maxParamsJSON = 4096 // the columns' bound
)

// boundParams keeps the allowed keys, each value valid UTF-8 without control characters and at
// most maxParamValue bytes, and drops keys (last in order first) until the JSON fits
// maxParamsJSON. The result is never nil.
func boundParams(in map[string]string, allowed []string) map[string]string {
	out := map[string]string{}
	for _, k := range allowed {
		v, ok := in[k]
		if !ok {
			continue
		}
		v = strings.Map(func(r rune) rune {
			if r < 0x20 || r == 0x7f || r == utf8.RuneError {
				return -1
			}
			return r
		}, strings.ToValidUTF8(v, ""))
		for len(v) > maxParamValue {
			_, size := utf8.DecodeLastRuneInString(v)
			v = v[:len(v)-size]
		}
		out[k] = v
	}
	keys := slices.Sorted(maps.Keys(out))
	for len(keys) > 0 {
		b, err := json.Marshal(out)
		if err == nil && len(b) <= maxParamsJSON {
			break
		}
		delete(out, keys[len(keys)-1])
		keys = keys[:len(keys)-1]
	}
	return out
}

// RecordDeploymentStep appends a step event (R38 item 7) to an unfinished deployment, numbered
// under the deployment's row lock (concurrent writers get consecutive numbers). Params keep the
// keys error, port, mode and served. A finished deployment, an unknown step name or status (the
// record could not hold it) is ErrDeploymentState.
func (s *Service) RecordDeploymentStep(ctx context.Context, id uuid.UUID, name string, status providers.StepStatus, params map[string]string) error {
	switch status {
	case providers.StepStarted, providers.StepOK, providers.StepFailed, providers.StepSkipped:
	default:
		return ErrDeploymentState
	}
	if !codeRE.MatchString(name) {
		return ErrDeploymentState
	}
	raw, err := json.Marshal(boundParams(params, stepParamKeys))
	if err != nil {
		return err
	}
	return db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		d, err := lockDeployment(ctx, tx, id)
		if err != nil {
			return err
		}
		if d.state == DeployStateDone {
			return ErrDeploymentState
		}
		_, err = tx.Exec(ctx, `INSERT INTO deployment_steps (id, deployment_id, n, name, status, at, params)
SELECT $1, $2, coalesce(max(n), 0) + 1, $3, $4, $5, $6 FROM deployment_steps WHERE deployment_id = $2`,
			uuid.Must(uuid.NewV7()), id, name, string(status), s.clock.Now().UTC(), raw)
		if err != nil {
			return fmt.Errorf("inventory: record the step: %w", err)
		}
		return nil
	})
}

// DeploymentFinish is a deployment's final record. Status is one of TerminalStatuses.
type DeploymentFinish struct {
	Status     string
	ErrorCode  string            // a reason (ALC code); "" for a success
	Params     map[string]string // allowlisted and bounded (4 KiB) when stored
	FailedStep string
	Verified   string // "remote" | "local" | "skipped" | ""; required for succeeded and unchanged
	// Backup is accepted for the contract; the record keeps the backup reference StartDeployment
	// wrote before the first change (Alice's own, never a value from the server).
	Backup *providers.BackupRef

	// Task 15 additions: the outcome's other fields (see DeployOutcomeRecord).
	Result             string // providers.DeployResult as recorded ("" none)
	Phase              string // the helper journal phase of the last answer
	CauseStep          string
	HelperError        string
	VerifyFailedReason string // "" keeps the recorded one
	VerifyFailedPort   *int   // nil keeps the recorded one
	// CertFileSHA256 is the certificate file's hash after a success: Material.NewCertSHA256 after
	// the first send (the helper writes the PEM sent verbatim), the journal's NewCertSHA256 after a
	// recovery. "" leaves the location's hash unknown: the next deployment is refused
	// (ErrLocationNeedsDiscovery) until a discovery reads the file again.
	CertFileSHA256 string
}

var (
	results  = []string{"", "committed", "unchanged", "no_change", "rolled_back", "rollback_failed", "uncertain"}
	phases   = []string{"", providers.PhaseNone, providers.PhasePrepared, providers.PhaseWriting, providers.PhaseCommitted, providers.PhaseUnchanged, providers.PhaseRestoring, providers.PhaseRestored, providers.PhaseRestoreFailed}
	verifies = []string{"", "remote", "local", "skipped"}
)

func oneOf(v string, allowed []string) string {
	if slices.Contains(allowed, v) {
		return v
	}
	return ""
}

func stepOrBlank(v string) string {
	if codeRE.MatchString(v) {
		return v
	}
	return ""
}

// sanitizeCode is code when it fits deployments.error_code, else fallback.
func sanitizeCode(code, fallback string) string {
	if errorCodeRE.MatchString(code) {
		return code
	}
	return fallback
}

// errAlreadyFinished ends a transaction that found the deployment done: the caller succeeds.
var errAlreadyFinished = errors.New("inventory: the deployment has already finished")

// allowedFrom: only failed may end a deployment that never sent anything (queued, precheck, or a
// row without an operation id); unchanged also from precheck when the pre-check verified it;
// succeeded, rolled_back and rollback_failed need a send.
func allowedFrom(status string, d lockedDeployment, verified bool) bool {
	switch status {
	case DeployStatusFailed:
		return d.state != DeployStateDone
	case DeployStatusUnchanged:
		return d.wasSent() || (d.state == DeployStatePrecheck && verified)
	default:
		return d.wasSent()
	}
}

// errSkipNotAllowed: a "skipped" verification where the location's settings do not skip it.
var errSkipNotAllowed = fmt.Errorf("%w: verification was skipped but the location does not skip it", ErrDeploymentState)

// FinishDeployment records a deployment's end in one transaction: the location (locked first,
// as RequestDeployment and discovery lock it, so a request racing the end cannot deadlock with
// it), then the deployment under its row lock; every final value in the single UPDATE that sets
// done; for succeeded and unchanged the location's deployed_fingerprint, certificate, key type and
// file hash, changed_outside_at cleared; the audit rows; the emails to every Administrator
// (failed and rolled_back: deployment.failed; rollback_failed: deployment.rollback_failed; none
// for a deployment the license lock stopped). A finished deployment is left as it is and nil
// returned (Z1003 counts as finished). A status that is not terminal, or a success without a
// verification, is an error; a status the current state cannot reach, or a success "skipped" where
// the location's verification settings do not skip verification, is ErrDeploymentState.
func (s *Service) FinishDeployment(ctx context.Context, id uuid.UUID, f DeploymentFinish) error {
	if !slices.Contains(TerminalStatuses(), f.Status) {
		return errors.New("inventory: not a terminal deployment status")
	}
	if (f.Status == DeployStatusSucceeded || f.Status == DeployStatusUnchanged) && oneOf(f.Verified, verifies) == "" {
		return errors.New("inventory: a deployment succeeds only when verified")
	}
	err := db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		var location uuid.UUID
		err := tx.QueryRow(ctx, "SELECT location_id FROM deployments WHERE id = $1", id).Scan(&location)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("inventory: read deployment: %w", err)
		}
		if _, err := tx.Exec(ctx, "SELECT 1 FROM certificate_locations WHERE id = $1 FOR NO KEY UPDATE", location); err != nil {
			return fmt.Errorf("inventory: lock the location: %w", err)
		}
		d, err := lockDeployment(ctx, tx, id)
		if err != nil {
			return err
		}
		return s.finishLocked(ctx, tx, d, f)
	})
	if errors.Is(err, errAlreadyFinished) {
		return nil
	}
	return err
}

// isFrozen reports the done-freeze trigger's SQLSTATE.
func isFrozen(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "Z1003"
}

// finishLocked ends d, whose row this transaction holds locked (and, for a success, its
// location). See FinishDeployment.
func (s *Service) finishLocked(ctx context.Context, tx pgx.Tx, d lockedDeployment, f DeploymentFinish) error {
	if d.state == DeployStateDone {
		return errAlreadyFinished
	}
	verified := oneOf(f.Verified, verifies)
	if !allowedFrom(f.Status, d, verified != "") {
		return ErrDeploymentState
	}
	success := f.Status == DeployStatusSucceeded || f.Status == DeployStatusUnchanged
	if success && verified == "skipped" {
		var skip bool
		if err := tx.QueryRow(ctx, "SELECT skip_verify FROM certificate_locations WHERE id = $1", d.location).Scan(&skip); err != nil {
			return fmt.Errorf("inventory: read the location's verification settings: %w", err)
		}
		if !skip {
			return errSkipNotAllowed
		}
	}
	code := ""
	if !success {
		code = sanitizeCode(f.ErrorCode, "internal.unexpected")
	}
	params, err := json.Marshal(boundParams(f.Params, errorParamKeys))
	if err != nil {
		return err
	}
	var port *int
	if f.VerifyFailedPort != nil && *f.VerifyFailedPort >= 1 && *f.VerifyFailedPort <= 65535 {
		port = f.VerifyFailedPort
	}
	now := s.clock.Now().UTC()
	// A finish without a failed step keeps the recorded one, or names the verification whose
	// failure the deployment was recovered from (a rollback's outcome carries no step).
	var failedStep string
	err = tx.QueryRow(ctx, `UPDATE deployments SET state = $2, status = $3, result = $4, phase = $5, error_code = $6, error_params = $7,
    failed_step = CASE WHEN $8::text <> '' OR $3 IN ('succeeded', 'unchanged') THEN $8::text
                       WHEN failed_step <> '' THEN failed_step
                       WHEN verify_failed_reason <> '' OR $12::text <> '' THEN 'verify' ELSE '' END,
    cause_step = $9, helper_error = $10, verified = $11,
    verify_failed_reason = CASE WHEN $12::text = '' THEN verify_failed_reason ELSE $12::text END,
    verify_failed_port = coalesce($13::integer, verify_failed_port), finished_at = $14, recover_after = NULL
WHERE id = $1 RETURNING failed_step`, d.id, DeployStateDone, f.Status, oneOf(f.Result, results), oneOf(f.Phase, phases), code, params,
		stepOrBlank(f.FailedStep), stepOrBlank(f.CauseStep), stepOrBlank(f.HelperError), verified,
		sanitizeCode(f.VerifyFailedReason, ""), port, now).Scan(&failedStep)
	if isFrozen(err) {
		return errAlreadyFinished
	}
	if err != nil {
		return fmt.Errorf("inventory: finish the deployment: %w", err)
	}
	if success {
		// The hash of the file Alice wrote, when the engine knows it; never derived from the stored
		// chain (which may have changed since the send). Unknown: the next deployment waits for a
		// discovery (ErrLocationNeedsDiscovery).
		fileSHA := ""
		if hex64RE.MatchString(f.CertFileSHA256) {
			fileSHA = f.CertFileSHA256
		}
		// The file now holds the deployed certificate: the location says so at once, so the next
		// deployment's pre-check and compare-and-swap expect what Alice wrote (the next discovery
		// confirms it).
		if _, err := tx.Exec(ctx, `UPDATE certificate_locations SET deployed_fingerprint = $2, changed_outside_at = NULL, certificate_id = $3,
    key_type = (SELECT CASE WHEN key_algorithm IN ('rsa', 'ecdsa') THEN key_algorithm ELSE '' END FROM certificates WHERE id = $3),
    cert_file_sha256 = $4, version = version + 1
WHERE id = $1`, d.location, d.newFingerprint, d.certificate, fileSHA); err != nil {
			return fmt.Errorf("inventory: record the deployed certificate: %w", err)
		}
	}
	return s.finishRecords(ctx, tx, d, f.Status, code, failedStep, verified, oneOf(f.Phase, phases))
}

// rollbackFailedTemplate chooses the email of a rollback_failed deployment by what happened
// (the status stays rollback_failed, "unknown or mixed", for the changed-outside check).
func rollbackFailedTemplate(code, phase string) string {
	switch {
	case code == "deployment.recovery_exhausted" || code == "deployment.target_deleted":
		return TemplateDeploymentOutcomeUnknown
	case code == "deployment.superseded":
		return TemplateDeploymentSuperseded
	case phase == providers.PhaseRestored:
		return TemplateDeploymentRestoredUnverified
	}
	return TemplateDeploymentRollbackFailed
}

// finishRecords writes a finished deployment's audit rows and emails.
func (s *Service) finishRecords(ctx context.Context, tx pgx.Tx, d lockedDeployment, status, code, failedStep, verified, phase string) error {
	type ev struct {
		action  string
		result  audit.Result
		details map[string]string
	}
	var events []ev
	template := ""
	switch status {
	case DeployStatusSucceeded:
		events = []ev{{"deployment.succeeded", audit.Success, map[string]string{"new_fingerprint": d.newFingerprint,
			"previous_fingerprint": d.previous, "verified": verified}}}
	case DeployStatusUnchanged:
		events = []ev{{"deployment.unchanged", audit.Success, map[string]string{"new_fingerprint": d.newFingerprint, "verified": verified}}}
	case DeployStatusFailed:
		events = []ev{{"deployment.failed", audit.Failure, map[string]string{"reason": code, "failed_step": failedStep}}}
		template = TemplateDeploymentFailed
	case DeployStatusRolledBack:
		events = []ev{{"deployment.failed", audit.Failure, map[string]string{"reason": code, "failed_step": failedStep}},
			{"deployment.rolled_back", audit.Failure, map[string]string{"reason": code}}}
		template = TemplateDeploymentFailed
	case DeployStatusRollbackFailed:
		events = []ev{{"deployment.rollback_failed", audit.Failure, map[string]string{"reason": code, "failed_step": failedStep}}}
		template = rollbackFailedTemplate(code, phase)
	}
	if template != "" && code != "license.locked" {
		params, err := s.emailParams(ctx, tx, d)
		if err != nil {
			return err
		}
		if template == TemplateDeploymentRollbackFailed || template == TemplateDeploymentOutcomeUnknown {
			op := d.id
			if d.operation != nil {
				op = *d.operation
			}
			params["backup_dir"] = BackupRoot + "/" + op.String()
		}
		if err := s.notify(ctx, tx, template, params); err != nil {
			return err
		}
	}
	for _, e := range events {
		if err := s.appendAudit(ctx, tx, e.action, e.result, d.id, e.details); err != nil {
			return err
		}
	}
	return nil
}

// emailParams are the values a deployment email shows: the server's name (an Administrator's
// text), the certificate path (from the server's configuration; the sender keeps every param on
// one line) and the deployment id. Never key material.
func (s *Service) emailParams(ctx context.Context, tx pgx.Tx, d lockedDeployment) (map[string]string, error) {
	var name string
	if err := tx.QueryRow(ctx, "SELECT name::text FROM targets WHERE id = $1", d.target).Scan(&name); err != nil {
		return nil, fmt.Errorf("inventory: read the server's name: %w", err)
	}
	return map[string]string{"target_name": name, "cert_path": d.certPath, "deployment_id": d.id.String()}, nil
}

func (s *Service) notify(ctx context.Context, tx pgx.Tx, template string, params map[string]string) error {
	if s.notifier == nil {
		return nil
	}
	if err := s.notifier.NotifyAdmins(ctx, tx, template, params); err != nil {
		return fmt.Errorf("inventory: queue the %s email: %w", template, err)
	}
	return nil
}

// MarkRecovering moves a deployment that may have sent (deploying or recovering) to recovering
// with the next recovery not before retryAt; a zero or past retryAt means now +
// RecoveryRetryInterval (name now + FirstRecoveryDelay for a first recovery soon; once a recovery
// was requested, nothing sooner than now + RecoveryRetryInterval is kept). A deployment
// that never sent anything is ErrDeploymentState (a failure before the send is
// FinishDeployment(failed)). needsAttention flags it (status needs_attention: Alice cannot finish
// or undo it); the flag stays until the deployment ends, and its first setting audits
// deployment.needs_attention and emails every Administrator once, by cause (a lost connection, or
// an answer Alice could not use). A finished deployment is left as it is (nil).
func (s *Service) MarkRecovering(ctx context.Context, id uuid.UUID, retryAt time.Time, needsAttention bool) error {
	err := db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		d, err := lockDeployment(ctx, tx, id)
		if err != nil {
			return err
		}
		if d.state == DeployStateDone {
			return errAlreadyFinished
		}
		return s.markRecoveringLocked(ctx, tx, d, s.paced(retryAt, d.attempts), needsAttention)
	})
	if errors.Is(err, errAlreadyFinished) {
		return nil
	}
	return err
}

// paced is retryAt, or now + RecoveryRetryInterval for a zero or past time. Once a recovery was
// requested (attempts > 0) it is never sooner than now + RecoveryRetryInterval: FirstRecoveryDelay
// can only shorten the first recovery, and no caller can make the recoveries of one deployment
// poll the server faster than the sweep paces them.
func (s *Service) paced(retryAt time.Time, attempts int) time.Time {
	now := s.clock.Now().UTC()
	floor := now.Add(RecoveryRetryInterval)
	if retryAt.IsZero() || !retryAt.After(now) || (attempts > 0 && retryAt.Before(floor)) {
		return floor
	}
	return retryAt.UTC()
}

// needsAttentionTemplate: the lost-connection text when the last known cause is an SSH reason
// (the latest recovery job's error, else the deployment's), else the unconfirmed-outcome text.
func needsAttentionTemplate(ctx context.Context, tx pgx.Tx, d lockedDeployment) (string, error) {
	var cause string
	err := tx.QueryRow(ctx, `SELECT coalesce((SELECT last_error_code FROM jobs WHERE dedupe_key = $1 AND last_error_code <> ''
ORDER BY created_at DESC, id DESC LIMIT 1), $2)`, recoverDedupePrefix+d.id.String(), d.errorCode).Scan(&cause)
	if err != nil {
		return "", fmt.Errorf("inventory: read the recovery's cause: %w", err)
	}
	if strings.HasPrefix(cause, "ssh.") {
		return TemplateDeploymentNeedsAttention, nil
	}
	return TemplateDeploymentNeedsAttentionUnconfirmed, nil
}

func (s *Service) markRecoveringLocked(ctx context.Context, tx pgx.Tx, d lockedDeployment, retryAt time.Time, needsAttention bool) error {
	if !d.wasSent() {
		return ErrDeploymentState
	}
	status := DeployStatusRunning
	if needsAttention || d.status == DeployStatusNeedsAttention {
		status = DeployStatusNeedsAttention
	}
	if _, err := tx.Exec(ctx, "UPDATE deployments SET state = $2, status = $3, recover_after = $4 WHERE id = $1",
		d.id, DeployStateRecovering, status, retryAt); err != nil {
		return fmt.Errorf("inventory: mark the deployment recovering: %w", err)
	}
	if d.state != DeployStateRecovering {
		if err := s.appendAudit(ctx, tx, "deployment.recovering", audit.Success, d.id, map[string]string{"from_state": d.state}); err != nil {
			return err
		}
	}
	if status == DeployStatusNeedsAttention && d.status != DeployStatusNeedsAttention {
		params, err := s.emailParams(ctx, tx, d)
		if err != nil {
			return err
		}
		template, err := needsAttentionTemplate(ctx, tx, d)
		if err != nil {
			return err
		}
		if err := s.notify(ctx, tx, template, params); err != nil {
			return err
		}
		if err := s.appendAudit(ctx, tx, "deployment.needs_attention", audit.Failure, d.id,
			map[string]string{"attempt": strconv.Itoa(d.attempts)}); err != nil {
			return err
		}
	}
	return nil
}

// RequestRecovery queues a certificate.deploy_recover job for an unfinished deployment (kind
// system, payload deployment_id, dedupe certificate.deploy_recover:<id>, the deployment's
// server; ClassAlways: never held by the license, R38 item 8) and returns its id. A live recovery
// job answers instead (nothing piles up). A new one moves the deployment to recovering, counts the
// attempt, spaces the next by RecoveryRetryInterval (recover_after) and audits
// deployment.recovery_started; after RecoveryAttentionAfter attempts it needs attention (one
// email). A deployment that never sent anything is ErrDeploymentState; a finished one needs no
// recovery: (uuid.Nil, nil).
func (s *Service) RequestRecovery(ctx context.Context, id uuid.UUID) (uuid.UUID, error) {
	var jobID uuid.UUID
	err := db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		d, err := lockDeployment(ctx, tx, id)
		if err != nil {
			return err
		}
		if d.state == DeployStateDone {
			return errAlreadyFinished
		}
		jobID, err = s.requestRecoveryLocked(ctx, tx, d)
		return err
	})
	if errors.Is(err, errAlreadyFinished) {
		return uuid.Nil, nil
	}
	return jobID, err
}

func (s *Service) requestRecoveryLocked(ctx context.Context, tx pgx.Tx, d lockedDeployment) (uuid.UUID, error) {
	if !d.wasSent() {
		return uuid.Nil, ErrDeploymentState
	}
	dedupe := recoverDedupePrefix + d.id.String()
	var live uuid.UUID
	err := tx.QueryRow(ctx, "SELECT id FROM jobs WHERE dedupe_key = $1 AND status IN ('queued', 'running', 'blocked_license')", dedupe).Scan(&live)
	if err == nil {
		return live, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, fmt.Errorf("inventory: read the live recovery: %w", err)
	}
	jobID, err := s.jobs.EnqueueTx(ctx, tx, JobRequest{Type: JobDeployRecover, TargetID: d.target,
		Payload: map[string]string{"deployment_id": d.id.String()}, Kind: "system", DedupeKey: dedupe})
	if err != nil {
		return uuid.Nil, err
	}
	d.attempts++
	if _, err := tx.Exec(ctx, "UPDATE deployments SET recovery_attempts = $2 WHERE id = $1", d.id, d.attempts); err != nil {
		return uuid.Nil, fmt.Errorf("inventory: count the recovery: %w", err)
	}
	if err := s.markRecoveringLocked(ctx, tx, d, s.clock.Now().UTC().Add(RecoveryRetryInterval), d.attempts > RecoveryAttentionAfter); err != nil {
		return uuid.Nil, err
	}
	return jobID, s.appendAudit(ctx, tx, "deployment.recovery_started", audit.Success, d.id,
		map[string]string{"job_id": jobID.String(), "attempt": strconv.Itoa(d.attempts)})
}

// RecordOutcome records what a provider outcome means (DeployOutcomeRecord,
// RollbackOutcomeRecord): a terminal record finishes the deployment (FinishDeployment); a success
// "skipped" where the location does not skip verification is recorded as uncertain instead. An
// uncertain record keeps a deployment that may have sent in recovery with result uncertain, the
// reason and the earlier verification failure, the next recovery not before retryAt (zero or past:
// now + RecoveryRetryInterval; name now + FirstRecoveryDelay for a first recovery soon); for a
// deployment that never sent anything it is ErrDeploymentState. A finished deployment is left as
// it is (nil).
func (s *Service) RecordOutcome(ctx context.Context, id uuid.UUID, rec OutcomeRecord, retryAt time.Time) error {
	if rec.Terminal {
		err := s.FinishDeployment(ctx, id, rec.Finish)
		if !errors.Is(err, errSkipNotAllowed) {
			return err
		}
		rec = uncertainRecord(interruptedCode, nil)
	}
	f := rec.Finish
	params, err := json.Marshal(boundParams(f.Params, errorParamKeys))
	if err != nil {
		return err
	}
	var port *int
	if f.VerifyFailedPort != nil && *f.VerifyFailedPort >= 1 && *f.VerifyFailedPort <= 65535 {
		port = f.VerifyFailedPort
	}
	err = db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		d, err := lockDeployment(ctx, tx, id)
		if err != nil {
			return err
		}
		if d.state == DeployStateDone {
			return errAlreadyFinished
		}
		if !d.wasSent() {
			return ErrDeploymentState
		}
		code := sanitizeCode(f.ErrorCode, interruptedCode)
		_, err = tx.Exec(ctx, `UPDATE deployments SET result = 'uncertain', phase = '', failed_step = '', cause_step = '', helper_error = '',
    error_code = $2, error_params = $3,
    verify_failed_reason = CASE WHEN $4::text = '' THEN verify_failed_reason ELSE $4::text END,
    verify_failed_port = coalesce($5::integer, verify_failed_port)
WHERE id = $1`, id, code, params, sanitizeCode(f.VerifyFailedReason, ""), port)
		if err != nil {
			return fmt.Errorf("inventory: record the uncertain outcome: %w", err)
		}
		d.errorCode = code
		return s.markRecoveringLocked(ctx, tx, d, s.paced(retryAt, d.attempts), false)
	})
	if errors.Is(err, errAlreadyFinished) {
		return nil
	}
	return err
}
