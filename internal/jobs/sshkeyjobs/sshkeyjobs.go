// Package sshkeyjobs holds the job handlers of the SSH key module (spec §13.4-§13.6, C9): sshkey.add
// deploys a generated key into one key file and proves it with a test login; rotation.location carries
// one location of a rotation run through its add, the removal of the old key, or its undo.
//
// Together with the store (internal/sshkeys) and the database this package keeps two properties:
//   - the old key is removed only with the operation id sshkeys.BeginRemove (or a retry recorded by
//     RecordReverify) handed out, after a login with the new key as that location's user that this job
//     made immediately before (RecordReverify): no other path sends a removal of the old fingerprint;
//   - an undo removes only the new key's fingerprint (the run generated it), never the old one.
//
// Every remote change is preceded by the store call that records it is about to be sent, and followed by
// the call that records its answer; a crash between the two is resumed by the next job from the recorded
// state (an add in flight is verified first, a removal or an undo in flight lists the file first).
package sshkeyjobs

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"time"

	"github.com/google/uuid"

	"alice/internal/audit"
	"alice/internal/inventory"
	"alice/internal/jobs"
	"alice/internal/platform/clock"
	"alice/internal/providers"
	"alice/internal/sshkeys"
)

// Keys is the part of *sshkeys.Service the handlers use (C9).
type Keys interface {
	DeployJob(ctx context.Context, jobID, targetID uuid.UUID, payload map[string]string) (sshkeys.DeployJob, error)
	FinishDeploy(ctx context.Context, actor audit.Actor, d sshkeys.DeployJob, out sshkeys.DeployOutcome) error
	BeginDeploySend(ctx context.Context, jobID uuid.UUID, d sshkeys.DeployJob) (sshkeys.DeploySend, error)
	DeploySends(ctx context.Context, jobID uuid.UUID) (sshkeys.DeploySendRecord, error)
	UndoWait() time.Duration
	KeySigner(keyID uuid.UUID) providers.CredentialSource
	LocationWork(ctx context.Context, locationID uuid.UUID) (sshkeys.LocationWork, error)
	BeginAdd(ctx context.Context, locationID uuid.UUID) (uuid.UUID, error)
	FinishAdd(ctx context.Context, locationID uuid.UUID, r sshkeys.AddRecord) error
	RecordVerify(ctx context.Context, locationID uuid.UUID, r sshkeys.VerifyRecord) error
	RecordReverify(ctx context.Context, locationID uuid.UUID, r sshkeys.VerifyRecord) error
	BeginRemove(ctx context.Context, locationID uuid.UUID) (uuid.UUID, error)
	FinishRemove(ctx context.Context, actor audit.Actor, locationID uuid.UUID, r sshkeys.RemoveRecord) error
	BeginUndo(ctx context.Context, locationID uuid.UUID) (uuid.UUID, error)
	FinishUndo(ctx context.Context, actor audit.Actor, locationID uuid.UUID, r sshkeys.UndoRecord) error
	Advance(ctx context.Context, rotationID uuid.UUID) error
}

// Targets is the part of *inventory.Service the handlers use to open sessions (as targetjobs) and to
// queue a discovery when the record must catch up with a file.
type Targets interface {
	TargetRef(ctx context.Context, id uuid.UUID) (providers.TargetRef, inventory.Target, error)
	Credentials() providers.CredentialSource
	HostKeyStore() providers.HostKeyStore
	RecordConnectionFailure(ctx context.Context, id uuid.UUID, reason string) error
	RequestDiscovery(ctx context.Context, a inventory.Actor, id uuid.UUID) (uuid.UUID, error)
}

var (
	_ Keys    = (*sshkeys.Service)(nil)
	_ Targets = (*inventory.Service)(nil)
)

// Deps are the handlers' dependencies.
type Deps struct {
	Keys     Keys
	Targets  Targets
	Registry *providers.Registry
	Clock    clock.Clock
	Log      *slog.Logger // nil = discard
}

// Register installs the handlers of sshkey.add and rotation.location on the runner. It panics on a missing dependency.
func Register(r *jobs.Runner, d Deps) {
	if d.Keys == nil || d.Targets == nil || d.Registry == nil || d.Clock == nil {
		panic("sshkeyjobs: Deps needs Keys, Targets, Registry and Clock")
	}
	if d.Log == nil {
		d.Log = slog.New(slog.DiscardHandler)
	}
	h := &handlers{d: d}
	r.Handle(jobs.SSHKeyAdd, h.deploy)
	r.Handle(jobs.RotationLocation, h.location)
}

type handlers struct{ d Deps }

// systemActor is the audit actor of a job's records: the system actor "jobs" with the job id.
func systemActor(j jobs.Job) audit.Actor {
	return audit.Actor{Type: audit.ActorSystem, Name: "jobs", RequestID: j.ID.String()}
}

// discoveryActor queues the discovery a handler asks for on its own.
var discoveryActor = inventory.Actor{Audit: audit.SystemActor("jobs")}

// connectionReasons are the failures of a key operation that say something about the connection itself;
// only these change the target's status (as targetjobs). A test login's failure never does.
var connectionReasons = []string{"ssh.auth_failed", "ssh.unreachable", "ssh.timeout", "ssh.address_not_allowed", "ssh.helper_missing", "ssh.helper_outdated"}

// open returns a session after the target checks (as targetjobs with a confirmed host key required and a
// pooled connection): a changed host key, a disabled target or an unconfirmed one refuses without
// connecting. A provider failure of the open is recorded on the target.
func (h *handlers) open(ctx context.Context, id uuid.UUID) (providers.Session, error) {
	ref, t, err := h.d.Targets.TargetRef(ctx, id)
	switch {
	case errors.Is(err, inventory.ErrNotFound):
		return nil, jobs.Fail("system.not_found", nil, err)
	case err != nil:
		return nil, jobs.Retry("internal.unexpected", nil, err)
	case t.Status == inventory.StatusHostKeyChanged:
		return nil, jobs.Fail("target.host_key_changed", nil, nil)
	case t.Status == inventory.StatusDisabled:
		return nil, jobs.Fail("target.disabled", nil, nil)
	case t.Status == inventory.StatusPendingHostKey:
		return nil, jobs.Fail("target.host_key_unconfirmed", nil, nil)
	}
	p, ok := h.d.Registry.Get(ref.Kind)
	if !ok {
		return nil, jobs.Fail("internal.unexpected", nil, fmt.Errorf("sshkeyjobs: no provider %q", ref.Kind))
	}
	sess, err := p.Open(ctx, ref, h.d.Targets.Credentials(), providers.Env{Clock: h.d.Clock, HostKeys: h.d.Targets.HostKeyStore(), Log: h.d.Log})
	if err != nil {
		h.recordFailure(ctx, id, err)
		return nil, jobs.FromProvider(err)
	}
	return sess, nil
}

// recordFailure stores a provider failure's reason on the target (its status and last error). The
// record does not depend on the job's context.
func (h *handlers) recordFailure(ctx context.Context, id uuid.UUID, err error) {
	var pe *providers.Error
	if !errors.As(err, &pe) {
		return
	}
	if rerr := h.d.Targets.RecordConnectionFailure(context.WithoutCancel(ctx), id, pe.Code); rerr != nil {
		h.d.Log.Error("could not record a connection failure", "target_id", id.String(), "error_type", fmt.Sprintf("%T", rerr))
	}
}

// recordIfConnection records a failure of a key operation on the target when it is about the connection.
func (h *handlers) recordIfConnection(ctx context.Context, id uuid.UUID, err error) {
	if slices.Contains(connectionReasons, reasonOf(err)) {
		h.recordFailure(ctx, id, err)
	}
}

func (h *handlers) close(s providers.Session) {
	if err := s.Close(); err != nil {
		h.d.Log.Warn("closing a provider session failed", "error_type", fmt.Sprintf("%T", err))
	}
}

// discover queues a discovery of the server so that the record catches up with a file Alice could not
// account for (an already-present line, a failed undo).
func (h *handlers) discover(ctx context.Context, id uuid.UUID) {
	if _, err := h.d.Targets.RequestDiscovery(context.WithoutCancel(ctx), discoveryActor, id); err != nil {
		h.d.Log.Warn("could not queue a discovery", "target_id", id.String(), "error_type", fmt.Sprintf("%T", err))
	}
}

// writeTracker forwards steps and remembers whether the provider started the write step, after which a
// failure is never taken as "nothing changed" (§8.4).
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

// definiteNoChange reports whether a failed add or removal certainly changed nothing: no change was
// reported and either the write never started or the helper refused it because the file changed under
// it (compare-and-set). Anything else after the write started is uncertain.
func definiteNoChange(wrote bool, res providers.AuthKeyResult, err error) bool {
	if res.Changed {
		return false
	}
	if !wrote {
		return true
	}
	return isCode(err, "ssh.file_changed")
}

// isCode reports whether err is a provider error with the reason code.
func isCode(err error, code string) bool {
	var pe *providers.Error
	return errors.As(err, &pe) && pe.Code == code
}

// reasonOf is the closed reason of an error: a *jobs.Failure's or a *providers.Error's code, else
// internal.unexpected (never free text).
func reasonOf(err error) string {
	var f *jobs.Failure
	if errors.As(err, &f) {
		return f.Reason
	}
	var pe *providers.Error
	if errors.As(err, &pe) {
		return pe.Code
	}
	return "internal.unexpected"
}

// login tries the key as the user (a fresh connection, only that key offered).
func (h *handlers) login(ctx context.Context, sess providers.Session, user string, keyID uuid.UUID) (providers.KeyLoginOutcome, error) {
	r, err := sess.VerifyKeyLogin(ctx, providers.KeyLoginRequest{OSUser: user, Key: h.d.Keys.KeySigner(keyID)})
	return r.Outcome, err
}

// errType names an error's type for the logs (its text may carry remote output).
func errType(err error) string { return fmt.Sprintf("%T", err) }
