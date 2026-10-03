// Package targetjobs holds the job handlers that connect providers to the inventory (spec §8.2):
// target.test_connection, target.discover and sshkey.remove. Every handler refuses a target whose
// host key changed before opening anything (F-31, "including scheduled jobs").
package targetjobs

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"

	"github.com/google/uuid"

	"alice/internal/audit"
	"alice/internal/inventory"
	"alice/internal/jobs"
	"alice/internal/platform/clock"
	"alice/internal/providers"
)

// Inventory is the part of *inventory.Service the handlers use.
type Inventory interface {
	TargetRef(ctx context.Context, id uuid.UUID) (providers.TargetRef, inventory.Target, error)
	Credentials() providers.CredentialSource
	HostKeyStore() providers.HostKeyStore
	PlatformKey(ctx context.Context) (inventory.PlatformKey, error)
	ProtectedFingerprints(ctx context.Context) ([]string, error)
	RecordConnectionOK(ctx context.Context, id uuid.UUID, r providers.ConnectionReport) error
	RecordConnectionFailure(ctx context.Context, id uuid.UUID, reason string) error
	Reconcile(ctx context.Context, id uuid.UUID, res providers.DiscoveryResult) (inventory.ReconcileSummary, error)
	RequestDiscovery(ctx context.Context, a inventory.Actor, id uuid.UUID) (uuid.UUID, error)
	KeyLocation(ctx context.Context, id uuid.UUID) (inventory.KeyLocation, error)
	MarkKeyRemoved(ctx context.Context, locationID uuid.UUID, actor audit.Actor, res providers.AuthKeyResult) error
	RecordRemovalFailure(ctx context.Context, locationID uuid.UUID, actor audit.Actor, reason string) error
}

// Deps are the handlers' dependencies.
type Deps struct {
	Inventory Inventory
	Registry  *providers.Registry
	Clock     clock.Clock
	Log       *slog.Logger
}

var _ Inventory = (*inventory.Service)(nil)

// Register registers the three handlers on the runner.
func Register(r *jobs.Runner, d Deps) {
	h := newHandlers(d)
	r.Handle(jobs.TargetTestConnection, h.testConnection)
	r.Handle(jobs.TargetDiscover, h.discover)
	r.Handle(jobs.SSHKeyRemove, h.removeKey)
}

type handlers struct{ d Deps }

func newHandlers(d Deps) *handlers {
	if d.Log == nil {
		d.Log = slog.New(slog.DiscardHandler)
	}
	return &handlers{d: d}
}

// jobsActor is the system actor of work a handler starts on its own (the first discovery).
var jobsActor = inventory.Actor{Audit: audit.SystemActor("jobs")}

// connectionReasons are the failures of a key operation that say something about the connection
// itself; only these change the target's status and last error (§8.4, R37 item 13). A refusal of
// the operation (own key, last root key, file changed, ...) is audited on the key instead.
var connectionReasons = []string{"ssh.auth_failed", "ssh.unreachable", "ssh.timeout", "ssh.helper_missing", "ssh.helper_outdated"}

// open returns a session after the target checks. needConfirmed refuses a target whose host key
// is not confirmed yet (discovery, removal); a connection test may run on it: that is how the
// fingerprint is shown in the first place. A changed host key refuses everything without
// connecting (F-31); only a re-pin (or a dismissal) leaves that status. A disabled target runs
// nothing. fresh asks the provider for a new connection rather than a reused one (the explicit
// connection test, R37 item 21).
func (h *handlers) open(ctx context.Context, id uuid.UUID, needConfirmed, fresh bool) (providers.Session, inventory.Target, error) {
	ref, t, err := h.d.Inventory.TargetRef(ctx, id)
	switch {
	case errors.Is(err, inventory.ErrNotFound):
		return nil, t, jobs.Fail("system.not_found", nil, err)
	case err != nil:
		return nil, t, jobs.Retry("internal.unexpected", nil, err)
	case t.Status == inventory.StatusHostKeyChanged:
		return nil, t, jobs.Fail("target.host_key_changed", nil, nil)
	case t.Status == inventory.StatusDisabled:
		return nil, t, jobs.Fail("target.disabled", nil, nil)
	case needConfirmed && t.Status == inventory.StatusPendingHostKey:
		return nil, t, jobs.Fail("target.host_key_unconfirmed", nil, nil)
	}
	p, ok := h.d.Registry.Get(ref.Kind)
	if !ok {
		return nil, t, jobs.Fail("internal.unexpected", nil, fmt.Errorf("targetjobs: no provider %q", ref.Kind))
	}
	sess, err := p.Open(ctx, ref, h.d.Inventory.Credentials(), providers.Env{Clock: h.d.Clock, HostKeys: h.d.Inventory.HostKeyStore(), Log: h.d.Log,
		FreshConnection: fresh})
	if err != nil {
		h.recordFailure(ctx, id, err)
		return nil, t, jobs.FromProvider(err)
	}
	return sess, t, nil
}

// recordFailure stores the reason of a provider failure on the target (status and last error,
// inventory's mapping of the reason).
func (h *handlers) recordFailure(ctx context.Context, id uuid.UUID, err error) {
	var pe *providers.Error
	if !errors.As(err, &pe) {
		return
	}
	if rerr := h.d.Inventory.RecordConnectionFailure(ctx, id, pe.Code); rerr != nil {
		h.d.Log.Error("could not record a connection failure", "target_id", id.String(), "error_type", fmt.Sprintf("%T", rerr))
	}
}

func (h *handlers) close(s providers.Session) {
	if err := s.Close(); err != nil {
		h.d.Log.Warn("closing a provider session failed", "error_type", fmt.Sprintf("%T", err))
	}
}

// retestFailure ends the scheduled re-test of an unreachable target (ScheduleDiscovery) as a plain
// failure when the server did not answer as it should: its single attempt would otherwise make the
// job dead and email every Administrator once per discovery interval for as long as the server is
// down. The failure is already on the target (its status and last error, recorded once per
// transition), and the next interval tests again. A test a person asked for, and a failure that is
// not the server's (the database), keep their classification.
func retestFailure(j jobs.Job, err error) error {
	var (
		pe *providers.Error
		f  *jobs.Failure
	)
	if j.Kind == jobs.KindScheduled && errors.As(err, &pe) && errors.As(err, &f) && f.Class == jobs.Retryable {
		return jobs.Fail(f.Reason, f.Params, err)
	}
	return err
}

func (h *handlers) testConnection(ctx context.Context, j jobs.Job, _ jobs.StepRecorder) (map[string]any, error) {
	sess, t, err := h.open(ctx, j.TargetID, false, true)
	if err != nil {
		return nil, retestFailure(j, err)
	}
	defer h.close(sess)
	rep, err := sess.TestConnection(ctx)
	if err != nil {
		h.recordFailure(ctx, j.TargetID, err)
		return nil, retestFailure(j, jobs.FromProvider(err))
	}
	// The report carries the key the server presented: inventory compares it with the pinned key.
	err = h.d.Inventory.RecordConnectionOK(ctx, j.TargetID, rep)
	if errors.Is(err, inventory.ErrNotFound) {
		return nil, jobs.Fail("system.not_found", nil, err) // deleted while it was tested
	}
	if err != nil {
		return nil, jobs.Retry("internal.unexpected", nil, err)
	}
	out := map[string]any{"host_key_fingerprint": rep.HostKey.Fingerprint, "helper_version": rep.HelperVersion}
	// The first successful test after a confirmation or a re-pin (status checking), of a server
	// that was unreachable (the scheduled re-test, ScheduleDiscovery), or of a target never
	// scanned, starts a discovery by itself, once the target is connected (status ok).
	if t.Status != inventory.StatusChecking && t.Status != inventory.StatusUnreachable && t.LastDiscoveryAt != nil {
		return out, nil
	}
	_, now, err := h.d.Inventory.TargetRef(ctx, j.TargetID)
	if err != nil || now.Status != inventory.StatusOK {
		return out, nil
	}
	id, err := h.d.Inventory.RequestDiscovery(ctx, jobsActor, j.TargetID)
	if err != nil {
		h.d.Log.Error("could not queue the first discovery", "target_id", j.TargetID.String(), "error_type", fmt.Sprintf("%T", err))
		return out, nil
	}
	out["discovery_job_id"] = id.String()
	return out, nil
}

func (h *handlers) discover(ctx context.Context, j jobs.Job, _ jobs.StepRecorder) (map[string]any, error) {
	sess, _, err := h.open(ctx, j.TargetID, true, false)
	if err != nil {
		return nil, err
	}
	defer h.close(sess)
	res, err := sess.Discover(ctx, providers.DiscoverRequest{SSHKeys: true})
	if err != nil {
		h.recordFailure(ctx, j.TargetID, err)
		return nil, jobs.FromProvider(err)
	}
	sum, err := h.d.Inventory.Reconcile(ctx, j.TargetID, res)
	if errors.Is(err, inventory.ErrNotFound) {
		return nil, jobs.Fail("system.not_found", nil, err) // deleted while it was scanned
	}
	if err != nil {
		return nil, jobs.Retry("internal.unexpected", nil, err)
	}
	return map[string]any{"key_count": sum.Keys, "new_count": sum.New, "missing_count": sum.Missing, "partial": res.Partial}, nil
}

// writeTracker forwards steps and remembers whether the provider started the write step, after
// which a failure is never retried blindly (§8.4).
type writeTracker struct {
	next  providers.StepLogger
	wrote bool
}

func (w *writeTracker) Step(name string, status providers.StepStatus, params map[string]string) {
	if name == "write" && status == providers.StepStarted {
		w.wrote = true
	}
	if w.next != nil {
		w.next.Step(name, status, params)
	}
}

func reasonOf(err error) (string, map[string]string) {
	var f *jobs.Failure
	if errors.As(err, &f) {
		return f.Reason, f.Params
	}
	var pe *providers.Error
	if errors.As(err, &pe) {
		return pe.Code, pe.Params
	}
	return "internal.unexpected", nil
}

func (h *handlers) removeKey(ctx context.Context, j jobs.Job, steps jobs.StepRecorder) (map[string]any, error) {
	locID, err := uuid.Parse(j.Payload["location_id"])
	if err != nil {
		return nil, jobs.Fail("sshkey.not_removable", nil, err)
	}
	actor := audit.Actor{Type: audit.ActorSystem, Name: "jobs", RequestID: j.ID.String()}
	loc, err := h.d.Inventory.KeyLocation(ctx, locID)
	if errors.Is(err, inventory.ErrNotFound) && j.Attempt > 1 {
		// The target was deleted after an earlier attempt, which may have changed the file before
		// its bookkeeping failed. Alice cannot reach the server any more to find out: the attempt
		// is audited and a person looks, rather than the job ending without a record.
		h.removalFailed(ctx, locID, actor, "system.not_found")
		return nil, jobs.Attention("system.not_found", nil, err)
	}
	if errors.Is(err, inventory.ErrNotFound) {
		return nil, jobs.Fail("sshkey.not_removable", nil, err)
	}
	if err != nil {
		return nil, jobs.Retry("internal.unexpected", nil, err)
	}
	if loc.RemovedAt != nil {
		return map[string]any{"already_removed": true}, nil
	}
	// The user and the file come from the location row; the payload must name the same ones.
	if loc.TargetID != j.TargetID || loc.Fingerprint != j.Payload["fingerprint"] || loc.OSUser != j.Payload["os_user"] ||
		loc.FilePath != j.Payload["file_path"] {
		return nil, jobs.Fail("sshkey.not_removable", nil, nil)
	}
	protected, err := h.d.Inventory.ProtectedFingerprints(ctx)
	if err != nil {
		return nil, jobs.Retry("internal.unexpected", nil, err)
	}
	if len(protected) == 0 {
		// Without the platform key nothing can tell Alice's own key apart: never remove blindly.
		return nil, jobs.Retry("internal.unexpected", nil, inventory.ErrNoPlatformKey)
	}
	if loc.IsAliceConnectionKey || slices.Contains(protected, loc.Fingerprint) {
		h.removalFailed(ctx, locID, actor, "sshkey.own_key_protected")
		return nil, jobs.Fail("sshkey.own_key_protected", nil, nil)
	}
	sess, _, err := h.open(ctx, j.TargetID, true, false)
	if err != nil {
		reason, _ := reasonOf(err)
		h.removalFailed(ctx, locID, actor, reason)
		return nil, err
	}
	defer h.close(sess)
	rec := &writeTracker{next: steps}
	res, err := sess.RemoveAuthorizedKey(ctx, providers.AuthKeyChange{
		OperationID: j.ID, OSUser: loc.OSUser, FilePath: loc.FilePath, Fingerprint: loc.Fingerprint,
		ProtectedFingerprints: protected, AllowLastRootKey: j.Payload["confirm_last_root_key"] == "true",
	}, rec)
	if err != nil {
		return h.removeFailed(ctx, j, locID, actor, rec.wrote, res, err)
	}
	if res.Changed && !res.Verified {
		// §13.4 step 5: the re-read after the write shows other content, so the removal is not
		// confirmed. Until a restore exists a person looks at it, with the helper's backup.
		h.removalFailed(ctx, locID, actor, reasonVerifyFailed)
		return uncertain(res), jobs.Attention(reasonVerifyFailed, nil, nil)
	}
	if err := h.d.Inventory.MarkKeyRemoved(ctx, locID, actor, res); err != nil {
		// The remote change is done; a retry finds the key absent (idempotent) and records it.
		return nil, jobs.Retry("internal.unexpected", nil, err)
	}
	return map[string]any{"changed": res.Changed, "removed": res.Removed, "verified": res.Verified}, nil
}

// reasonVerifyFailed: the file read back after a removal is not the content that was written.
const reasonVerifyFailed = "sshkey.verify_failed"

// uncertain is the result of a removal whose outcome a person must check.
func uncertain(res providers.AuthKeyResult) map[string]any {
	out := map[string]any{"changed": res.Changed, "removed": res.Removed, "verified": false}
	if res.Backup != "" {
		out["backup"] = res.Backup // where the helper kept the previous file
	}
	return out
}

// removeFailed handles a provider failure of a removal. Before the write a failure is classified
// as the provider says (a retryable one runs again). Once the write was sent, or when the
// provider reports a change together with the error (the outcome is uncertain), the job stops for
// a person and is never retried: the file may already have changed (§8.4). The key's state is left
// to the next discovery.
func (h *handlers) removeFailed(ctx context.Context, j jobs.Job, locID uuid.UUID, actor audit.Actor, wrote bool,
	res providers.AuthKeyResult, err error) (map[string]any, error) {
	reason, params := reasonOf(err)
	h.removalFailed(ctx, locID, actor, reason)
	if slices.Contains(connectionReasons, reason) {
		h.recordFailure(ctx, j.TargetID, err)
	}
	if !wrote && !res.Changed {
		return nil, jobs.FromProvider(err)
	}
	return uncertain(res), jobs.Attention(reason, params, err)
}

// removalFailed audits a failed removal; the record does not depend on the job's context (a lost
// lease or a shutdown must not erase it).
func (h *handlers) removalFailed(ctx context.Context, locID uuid.UUID, actor audit.Actor, reason string) {
	if err := h.d.Inventory.RecordRemovalFailure(context.WithoutCancel(ctx), locID, actor, reason); err != nil {
		h.d.Log.Error("could not audit a failed key removal", "error_type", fmt.Sprintf("%T", err))
	}
}
