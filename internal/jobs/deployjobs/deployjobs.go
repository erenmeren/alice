// Package deployjobs runs certificate deployments (spec §12.6) and their recovery (§8.8): the job
// handlers of certificate.deploy and certificate.deploy_recover. They connect a deployment record
// (inventory, the only durable truth about what Alice did to a live website) to the server (the
// provider's DeployCertificate, VerifyDeployment, RollbackDeployment and DeploymentStatus).
//
// Four properties hold on every path (each is enforced at one place, named here):
//
//  1. A send happens at most once per deployment. The only DeployCertificate call follows a
//     successful StartDeployment in the same run (deploy.go, send); StartDeployment moves the record
//     from precheck to deploying exactly once and refuses any other state, and a run that finds the
//     record deploying, recovering or done never reaches that call (handlers.follow).
//  2. Nothing is recorded as succeeded or unchanged without a passed verification (or a skip the
//     location's settings allow): the deploy path records what inventory.DeployOutcomeRecord maps
//     (a success only with Verified set, and the provider verifies before it answers committed);
//     the recovery path records a success only after its own VerifyDeployment with the recorded
//     fingerprint and chain length passed (recover.go, verified), never from the journal alone.
//  3. Nothing is recorded as failed ("nothing was written") after a send unless the journal or the
//     helper's answer proves nothing was written: a refusal (no_change with a *providers.Error, a
//     well-formed answer), the journal phase none or prepared with no helper running and a fence
//     that answered fenced (AUD-05: the operation can no longer run), or the journal phase
//     unchanged (the files already held the new pair). A restore answering "nothing to restore"
//     is uncertain (it contradicts the journal recovery read). Every other doubt is uncertain and
//     stays in recovery.
//  4. An interrupted deployment always ends in recovery or a terminal state: before the send the
//     record is queued or precheck (the job runs again, or the sweep ends it failed when the job
//     ended); from StartDeployment on it is deploying or recovering with an operation id, and the
//     sweep hands it to a certificate.deploy_recover job (ClassAlways) until it ends, escalating
//     after RecoveryAttentionAfter attempts and ending it after MaxRecoveryAttempts.
//
// The properties hold for the run that holds the job. Every write is fenced to the job run's claim
// (inventory.Claim on the context): a run that stalled past its lease, whose job was taken back,
// writes nothing and sends nothing more after its next fenced check (see deploy for the residual).
//
// A Key Vault deployment fails before the send when its secret cannot be read or checked: the deploy
// job reads the version's secret from the vault before it opens any SSH session (kv.go), so a vault
// that refuses (F-41: the role Key Vault Secrets User is missing), a version that was disabled or
// deleted, or a secret that is not the recorded version ends the deployment with the closed reason and
// nothing written or even connected.
//
// Recovery never needs the private key (DeploymentMaterial(id, false)) and never reads the vault; the
// deploy job obtains the key once, for the first send only (unsealed from Alice's own store for an
// uploaded certificate, read from the vault for a Key Vault one: never stored), and zeroes it on every
// path.
//
// The complete decision tables of both handlers are in the doc comments of deploy (deploy.go) and
// recoverDeployment (recover.go).
package deployjobs

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"

	"alice/internal/inventory"
	"alice/internal/jobs"
	"alice/internal/platform/clock"
	"alice/internal/providers"
)

// Inventory is the part of *inventory.Service the handlers use: the target and its session
// dependencies, and the deployment record's engine-facing methods (deployment_records.go). The pure
// mapping functions inventory.DeployOutcomeRecord and inventory.RollbackOutcomeRecord are called
// directly.
type Inventory interface {
	TargetRef(ctx context.Context, id uuid.UUID) (providers.TargetRef, inventory.Target, error)
	Credentials() providers.CredentialSource
	HostKeyStore() providers.HostKeyStore
	RecordConnectionFailure(ctx context.Context, id uuid.UUID, reason string) error

	Deployment(ctx context.Context, id uuid.UUID) (inventory.Deployment, error)
	CheckRecoveryPending(ctx context.Context, id uuid.UUID) error
	// OperationDeployment returns the deployment that owns operation op (known false: none).
	OperationDeployment(ctx context.Context, op uuid.UUID) (inventory.OperationOwner, bool, error)
	BeginDeployment(ctx context.Context, id uuid.UUID) (inventory.Deployment, error)
	DeploymentMaterial(ctx context.Context, id uuid.UUID, withKey bool) (inventory.Material, error)
	StartDeployment(ctx context.Context, id uuid.UUID, v inventory.SendValues) error
	RecordDeploymentStep(ctx context.Context, id uuid.UUID, name string, status providers.StepStatus, params map[string]string) error
	FinishDeployment(ctx context.Context, id uuid.UUID, f inventory.DeploymentFinish) error
	RecordOutcome(ctx context.Context, id uuid.UUID, rec inventory.OutcomeRecord, retryAt time.Time) error
	// CheckClaim is ErrClaimLost when the job run on the context (inventory.WithClaim) no longer
	// holds its job. Every write above checks the same in its own transaction.
	CheckClaim(ctx context.Context) error

	// VaultCredentials and KVDeployMaterial serve Key Vault deployments (R40 row 18, kv.go): the
	// vault's sign-in, and the check of the deployment's version secret that yields the first send's
	// material (the caller zeroes its PrivateKeyPEM; KVDeployMaterial zeroes the secret).
	VaultCredentials(id uuid.UUID) inventory.VaultCredentialSource
	// KVDeployPrecheck judges, without writing or reading the vault, whether the deployment may still
	// have its secret read (binding, website, automatic deployment, vault, certificate and version as
	// they are now); the engine asks before any vault call (kv.go).
	KVDeployPrecheck(ctx context.Context, id uuid.UUID) error
	KVDeployMaterial(ctx context.Context, id uuid.UUID, secret providers.CertificateSecret) (inventory.Material, error)
}

var _ Inventory = (*inventory.Service)(nil)

// Deps are the handlers' dependencies.
type Deps struct {
	Inventory Inventory
	Registry  *providers.Registry
	Clock     clock.Clock
	Log       *slog.Logger
	// FirstRecovery is when the first recovery of an uncertain first send is due (recover_after =
	// now + FirstRecovery); 0 = inventory.FirstRecoveryDelay.
	FirstRecovery time.Duration
}

// Register registers the deploy and recovery handlers on the runner.
// It panics at startup when a dependency is missing (a handler would otherwise fail at run time,
// in the middle of a deployment).
func Register(r *jobs.Runner, d Deps) {
	switch {
	case r == nil:
		panic("deployjobs: Register needs a runner")
	case d.Inventory == nil, d.Registry == nil, d.Clock == nil:
		panic("deployjobs: Register needs Deps.Inventory, Deps.Registry and Deps.Clock")
	}
	h := newHandlers(d)
	r.Handle(jobs.CertificateDeploy, h.deploy)
	r.Handle(jobs.CertificateDeployRecover, h.recoverJob)
}

type handlers struct{ d Deps }

func newHandlers(d Deps) *handlers {
	if d.Log == nil {
		d.Log = slog.New(slog.DiscardHandler)
	}
	if d.FirstRecovery <= 0 {
		d.FirstRecovery = inventory.FirstRecoveryDelay
	}
	return &handlers{d: d}
}

const (
	// A journal reading none or prepared with no helper running used to be final ("nothing was
	// written") 60 s after the start record (the helper's 50 s budget plus a margin). That rule
	// relied on the helper's budget starting when Alice sent the command, which a sudo or PAM
	// stall breaks (AUD-05); recovery now fences the operation on the server instead
	// (FenceDeployment), which needs no clock agreement and makes a wait redundant.
	//
	// noJournalUnknownAfter: a journal reading none or prepared for a deployment that was sent
	// longer ago than this proves nothing any more: the helper's sweep removes a committed (or
	// restored, unchanged, prepared) journal after helperproto.NginxBackupKeep (7 days), so after an
	// outage the new pair may be live and unverified with its journal gone. Recovery then records the
	// outcome as unknown (rollback_failed, deployment.outcome_unknown), never "nothing was written".
	// Live recovery ends after inventory.MaxRecoveryAttempts × RecoveryRetryInterval (96 × 15 min,
	// exactly 24 h, equal to this threshold: the last attempts may fall either side of it, both
	// answers are safe), so a recovery well after it can only follow an outage; the day is well
	// below the helper's retention and absorbs clock skew
	// (TestNoJournalThresholdIsWellBelowTheHelpersRetention).
	noJournalUnknownAfter = 24 * time.Hour
	// RecordTimeout bounds a record written with a context detached from the job's: the outcome
	// of a completed call is recorded even when the job's context ended meanwhile (lease lost,
	// shutdown). Recording an outcome usually takes two of them (the write and its re-read; three
	// when an unchanged-skipped outcome is rewritten as failed), and the runner's shutdown grace
	// leaves at least that time after cancelling the job (cmd/alice
	// TestShutdownFitsTheStopGracePeriod). It is not a guarantee: step records, a provider call
	// still unwinding and a slow database can use the grace first; a record cut off then leaves
	// the deployment deploying or recovering, and a recovery reads the truth from the journal.
	RecordTimeout = 15 * time.Second
	// stepTimeout bounds one step record.
	stepTimeout = 5 * time.Second
)

// Reasons the engine itself produces (besides the providers' and inventory's).
const (
	reasonNotFound        = "system.not_found"
	reasonUnexpected      = "internal.unexpected"
	reasonInterrupted     = "deployment.interrupted"
	reasonRecoveryPending = "deployment.recovery_pending"
	reasonExpired         = "certificate.expired"
	reasonNotYetValid     = "certificate.not_yet_valid"
	reasonNoPrivateKey    = "certificate.no_private_key"
	reasonConfigInvalid   = "nginx.config_invalid"
	reasonUnsupported     = "nginx.location_unsupported"
	reasonVerifyOther     = "deployment.verify_other"
	reasonBusy            = "nginx.busy"
	reasonKeyMismatch     = "certificate.key_mismatch"
	reasonConfigTest      = "deployment.config_test_failed"
	reasonReload          = "deployment.reload_failed"
	reasonOutcomeUnknown  = "deployment.outcome_unknown"
	// reasonServerOperationPending: the server refused the deployment because an interrupted
	// operation Alice no longer tracks blocks the pair, and Alice could not restore it (param
	// operation_id; the manual remedy is alice-helper nginx-restore --op <id> as root).
	reasonServerOperationPending = "deployment.server_operation_pending"
	// reasonPendingChangeRestored: Alice put back the files of an unfinished earlier change it no
	// longer tracked (param operation_id); the website serves the certificate from before that
	// change; this deployment's certificate was not written (status rolled_back).
	reasonPendingChangeRestored = "deployment.pending_change_restored"
	reasonSuperseded            = "deployment.superseded"
	reasonUnknownOperation      = "deployment.unknown_operation"
)

// detached is ctx without its cancellation, bounded by RecordTimeout: for the records that must
// outlive the job's context (the outcome of a call that completed; a refusal that is already
// known), as targetjobs and inventory do for the same reason.
func detached(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(ctx), RecordTimeout)
}

// deploymentID is the job payload's deployment id.
func deploymentID(j jobs.Job) (uuid.UUID, error) {
	id, err := uuid.Parse(j.Payload["deployment_id"])
	if err != nil || id == uuid.Nil {
		return uuid.Nil, jobs.Fail(reasonNotFound, nil, errors.New("deployjobs: the job names no deployment"))
	}
	return id, nil
}

// open returns a session after the target checks of targetjobs: a deleted target is
// system.not_found, a changed host key, an unconfirmed one or a disabled target refuses without
// connecting (F-31); a provider failure is recorded on the target and returned classified.
func (h *handlers) open(ctx context.Context, id uuid.UUID) (providers.Session, error) {
	ref, err := h.serverRef(ctx, id)
	if err != nil {
		return nil, err
	}
	p, ok := h.d.Registry.Get(ref.Kind)
	if !ok {
		return nil, jobs.Fail(reasonUnexpected, nil, fmt.Errorf("deployjobs: no provider %q", ref.Kind))
	}
	sess, err := p.Open(ctx, ref, h.d.Inventory.Credentials(), providers.Env{Clock: h.d.Clock, HostKeys: h.d.Inventory.HostKeyStore(), Log: h.d.Log})
	if err != nil {
		h.recordConnectionFailure(ctx, id, err)
		return nil, jobs.FromProvider(err)
	}
	return sess, nil
}

// serverRef is the target checks of open, without dialling: a deleted target is system.not_found,
// a changed host key, an unconfirmed one or a disabled target refuses (F-31). They are the record's
// own facts, so a Key Vault deployment asks them before it reads its secret.
func (h *handlers) serverRef(ctx context.Context, id uuid.UUID) (providers.TargetRef, error) {
	ref, t, err := h.d.Inventory.TargetRef(ctx, id)
	switch {
	case errors.Is(err, inventory.ErrNotFound):
		return ref, jobs.Fail(reasonNotFound, nil, err)
	case err != nil:
		return ref, jobs.Retry(reasonUnexpected, nil, err)
	case t.Status == inventory.StatusHostKeyChanged:
		return ref, jobs.Fail("target.host_key_changed", nil, nil)
	case t.Status == inventory.StatusDisabled:
		return ref, jobs.Fail("target.disabled", nil, nil)
	case t.Status == inventory.StatusPendingHostKey:
		return ref, jobs.Fail("target.host_key_unconfirmed", nil, nil)
	}
	return ref, nil
}

// recordConnectionFailure stores a provider failure's reason on the target (its status).
func (h *handlers) recordConnectionFailure(ctx context.Context, id uuid.UUID, err error) {
	var pe *providers.Error
	if !errors.As(err, &pe) {
		return
	}
	wctx, cancel := detached(ctx)
	defer cancel()
	if rerr := h.d.Inventory.RecordConnectionFailure(wctx, id, pe.Code); rerr != nil {
		h.d.Log.Error("could not record a connection failure", "target_id", id.String(), "error_type", fmt.Sprintf("%T", rerr))
	}
}

func (h *handlers) close(s providers.Session) {
	if err := s.Close(); err != nil {
		h.d.Log.Warn("closing a provider session failed", "error_type", fmt.Sprintf("%T", err))
	}
}

// failure is err as a *jobs.Failure (jobs.FromProvider's classification) whose params are only
// jobParams': whatever path a provider error takes to the jobs row, no param outside the allowlist
// is stored with it.
func failure(err error) *jobs.Failure {
	var f *jobs.Failure
	if !errors.As(jobs.FromProvider(err), &f) {
		f = &jobs.Failure{Class: jobs.Retryable, Reason: reasonUnexpected, Cause: err}
	}
	return &jobs.Failure{Class: f.Class, Reason: f.Reason, Params: jobParams(f.Params), Cause: f.Cause}
}

// staleRun is the answer of a run that found it no longer holds its job (inventory.ErrClaimLost):
// it stops without writing anything more; the run that holds the job now, or the sweep, owns the
// record. The runner drops the answer (its own writes are fenced the same way).
func staleRun(err error) (map[string]any, error) {
	return nil, jobs.Retry("job.lease_expired", nil, err)
}

// withClaim puts the job run on the context of every inventory write it makes (I-1).
func withClaim(ctx context.Context, j jobs.Job) context.Context {
	return inventory.WithClaim(ctx, inventory.Claim{JobID: j.ID, Attempt: j.Attempt})
}

// jobParamKeys are the params a job's error may carry: fixed labels and numbers only, never a path
// or remote text (the API's allowlist drops anything else too).
var jobParamKeys = []string{"port", "failed_step", "phase", "helper_code", "subcommand", "exit_code", "operation_id",
	// The vault provider's closed params (task 7-8 table): the role a forbidden read lacks (F-41), the
	// permission model, Azure's strict-shape codes and request id, the caller's address a firewall
	// refused, and "reason" (tenant_mismatch). None carries remote text.
	"role", "model", "aadsts", "azure_code", "azure_request_id", "client_address", "reason"}

func jobParams(in map[string]string) map[string]string {
	var out map[string]string
	for _, k := range jobParamKeys {
		if v, ok := in[k]; ok {
			if out == nil {
				out = map[string]string{}
			}
			out[k] = boundValue(v)
		}
	}
	return out
}

// maxParamValue is the longest param value, the bound inventory's record applies (boundParams): a
// job's params and the deployment's say the same.
const maxParamValue = 256

// boundValue is a param value as the deployment record keeps it: valid UTF-8 without control
// characters, at most maxParamValue bytes (cut at a rune boundary).
func boundValue(v string) string {
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
	return v
}

// mode says which job runs the recovery logic.
type mode int

const (
	// recoveryJob: a certificate.deploy_recover job (one attempt, never an alert; the sweep paces).
	recoveryJob mode = iota
	// deployJob: a certificate.deploy job that found a send may have happened (a run after a crash
	// or a lost lease). Its failures are permanent: the runner never runs it again, the sweep hands
	// the deployment to a recovery job.
	deployJob
)

// resultOf is a job's answer for the deployment as recorded (the jobs row and the record agree):
//
//	recovery job, done              success {"outcome": status}: it recorded (or found) the end
//	deploy job:
//	done succeeded | unchanged      success {"outcome", "verified"}
//	done failed | rolled_back       jobs.Fail(error_code, params): the job ends failed, never dead;
//	                                the deployment email (deployment.failed) is the alert
//	done rollback_failed            jobs.Attention(error_code, params): failed with needs_attention;
//	                                the deployment's own email is the alert
//	unfinished (recovering)         deploy job: jobs.Attention(deployment.interrupted): the job is
//	                                over, a recovery finishes the deployment; recovery job: success
//	                                {"outcome": "uncertain"} (it recorded what it learned; the
//	                                sweep queues the next one)
func resultOf(d inventory.Deployment, m mode) (map[string]any, error) {
	out := map[string]any{"deployment_id": d.ID.String()}
	if d.State != inventory.DeployStateDone {
		out["outcome"] = string(providers.DeployUncertain)
		if m == deployJob {
			return out, jobs.Attention(reasonInterrupted, nil, nil)
		}
		return out, nil
	}
	out["outcome"] = d.Status
	if m == recoveryJob {
		// The recovery did its part: the record holds the outcome (and its email, the alert).
		return out, nil
	}
	switch d.Status {
	case inventory.DeployStatusSucceeded, inventory.DeployStatusUnchanged:
		out["verified"] = d.Verified
		return out, nil
	case inventory.DeployStatusRollbackFailed:
		return out, jobs.Attention(d.ErrorCode, jobParams(d.ErrorParams), nil)
	}
	return out, jobs.Fail(d.ErrorCode, jobParams(d.ErrorParams), nil)
}

// report re-reads the deployment after a record was written and answers resultOf it, so the job's
// result says what the record says (inventory may have recorded a success with a skip the
// location no longer allows as uncertain, or the deployment may have ended meanwhile). When the
// read fails, fallback is the answer.
func (h *handlers) report(ctx context.Context, id uuid.UUID, m mode, fallback func() (map[string]any, error)) (map[string]any, error) {
	rctx, cancel := detached(ctx)
	defer cancel()
	d, err := h.d.Inventory.Deployment(rctx, id)
	if err != nil {
		return fallback()
	}
	return resultOf(d, m)
}

// record writes rec (RecordOutcome, detached from the job's context: the outcome of a call that
// completed is never lost because the job's context ended) and answers what was recorded. A failed
// write is retryable: nothing is lost, the next run finds the deployment deploying or recovering
// and reads the truth from the journal.
func (h *handlers) record(ctx context.Context, d inventory.Deployment, rec inventory.OutcomeRecord, retryAt time.Time, m mode, cause error) (map[string]any, error) {
	wctx, cancel := detached(ctx)
	err := h.d.Inventory.RecordOutcome(wctx, d.ID, rec, retryAt)
	cancel()
	if errors.Is(err, inventory.ErrDeploymentState) && rec.Terminal && rec.Finish.Status == inventory.DeployStatusUnchanged {
		// "Unchanged, verification skipped" where the location no longer skips verification (its
		// settings changed meanwhile): nothing was changed, and the verification the location now
		// asks for was not made. The deployment ends failed (verify_other), not in a retryable job
		// error that only retries and the sweep would end.
		rec = inventory.OutcomeRecord{Terminal: true, Finish: inventory.DeploymentFinish{Status: inventory.DeployStatusFailed,
			Result: string(providers.DeployNoChange), Phase: rec.Finish.Phase, ErrorCode: reasonVerifyOther, Params: map[string]string{}}}
		// No NothingWritten: inventory answers ErrDeploymentState for this record only before a send
		// (after one it records the skip as uncertain), where failed needs no proof.
		wctx, cancel = detached(ctx)
		err = h.d.Inventory.RecordOutcome(wctx, d.ID, rec, retryAt)
		cancel()
	}
	if errors.Is(err, inventory.ErrClaimLost) {
		h.d.Log.Warn("a stale run did not record its outcome: its job is held by another run", "deployment_id", d.ID.String())
		return staleRun(err)
	}
	if err != nil {
		h.d.Log.Error("could not record a deployment outcome", "deployment_id", d.ID.String(), "error_type", fmt.Sprintf("%T", err))
		return nil, jobs.Retry(reasonUnexpected, nil, err)
	}
	res, jerr := h.report(ctx, d.ID, m, func() (map[string]any, error) { return fallbackResult(d, rec, m) })
	if jerr == nil && !rec.Terminal && m == recoveryJob && cause != nil {
		// The recovery could not conclude because of the server: the job ends failed quietly
		// (one attempt, never an alert) with the provider's reason; the sweep paces the next.
		return res, failure(cause)
	}
	return res, jerr
}

// fallbackResult answers rec when the record cannot be read back.
func fallbackResult(d inventory.Deployment, rec inventory.OutcomeRecord, m mode) (map[string]any, error) {
	d.State, d.Status = inventory.DeployStateRecovering, inventory.DeployStatusRunning
	if rec.Terminal {
		d.State, d.Status, d.ErrorCode, d.Verified = inventory.DeployStateDone, rec.Finish.Status, rec.Finish.ErrorCode, rec.Finish.Verified
		d.ErrorParams = maps.Clone(rec.Finish.Params)
	}
	return resultOf(d, m)
}

// recorder is the providers.StepLogger of a deployment: each step goes to the job's step log and
// is appended to the record (RecordDeploymentStep, detached from the job's context and bounded; a
// failed step record is logged by type and does not stop the deployment).
type recorder struct {
	base context.Context // detached from the job's cancellation
	inv  Inventory
	id   uuid.UUID
	next jobs.StepRecorder
	log  *slog.Logger
	// lost, when set, is called once a step write is refused because this run no longer holds its
	// job (inventory.ErrClaimLost): it cancels the provider call in flight, so that a stale run's
	// provider does not send its inline restore (the provider checks its context before every
	// command; its steps are recorded before the commands that follow them).
	lost context.CancelFunc
	// verifyFail is the last failed verification of the new certificate this run recorded (step
	// verify, failed, with its reason): when the helper's own rollback ends restore_failed and
	// the engine's one more restore succeeds, the outcome knows no cause, and this is the reason
	// the deployment was rolled back.
	mu         sync.Mutex
	verifyFail rollbackCause
}

func (h *handlers) recorder(ctx context.Context, id uuid.UUID, steps jobs.StepRecorder) *recorder {
	return &recorder{base: context.WithoutCancel(ctx), inv: h.d.Inventory, id: id, next: steps, log: h.d.Log}
}

// Step implements providers.StepLogger.
func (r *recorder) Step(name string, status providers.StepStatus, params map[string]string) {
	if name == providers.StepNameVerify && status == providers.StepFailed && reasonRE.MatchString(params["reason"]) {
		r.mu.Lock()
		r.verifyFail = rollbackCause{reason: params["reason"], port: portOf(params), step: providers.StepNameVerify}
		r.mu.Unlock()
	}
	if r.next != nil {
		r.next.Step(name, status, params)
	}
	ctx, cancel := context.WithTimeout(r.base, stepTimeout)
	defer cancel()
	err := r.inv.RecordDeploymentStep(ctx, r.id, name, status, params)
	if errors.Is(err, inventory.ErrClaimLost) && r.lost != nil {
		r.log.Warn("a stale run stops its provider call: its job is held by another run", "deployment_id", r.id.String())
		r.lost()
		return
	}
	if err != nil {
		r.log.Error("could not record a deployment step", "deployment_id", r.id.String(), "step", name, "error_type", fmt.Sprintf("%T", err))
	}
}

// lastVerifyFailure is the last failed verification of the new certificate this run recorded.
func (r *recorder) lastVerifyFailure() rollbackCause {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.verifyFail
}

// causeReason is the reason of the helper's own rollback by the step that started it (as the nginx
// provider names it), for a journal the engine reads instead of an answer.
func causeReason(causeStep, class string) string {
	switch {
	case causeStep == providers.StepNameConfigTest && class == providers.ConfigErrKeyMismatch:
		return reasonKeyMismatch
	case causeStep == providers.StepNameConfigTest:
		return reasonConfigTest
	case causeStep == providers.StepNameReload:
		return reasonReload
	}
	return ""
}

// sentLongAgo reports whether the start record is older than noJournalUnknownAfter: a missing
// journal may then have been swept by the helper after a change it made.
func (h *handlers) sentLongAgo(d inventory.Deployment, now time.Time) bool {
	return d.StartedAt != nil && now.Sub(*d.StartedAt) > noJournalUnknownAfter
}
