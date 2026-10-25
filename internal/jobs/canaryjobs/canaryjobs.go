// Package canaryjobs holds the canary deployment's jobs (R65, design docs/superpowers/specs/2026-10-24-canary-deployment-design.md
// §9.4, §18): the queue handler canary.check, which observes one holding wave-1 deployment once (the TLS baseline, the
// provider's own VerifyDeployment of the deployment's verification request, then the optional HTTPS application check
// through httpcheck) and records the round, and the periodic task canary.advance, which decides every rollout
// (inventory.AdvanceRollouts). Both are ClassAlways.
package canaryjobs

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"

	"alice/internal/inventory"
	"alice/internal/jobs"
	"alice/internal/platform/clock"
	"alice/internal/providers"
	"alice/internal/providers/httpcheck"
)

// Inventory is the part of *inventory.Service the handler and the task use.
type Inventory interface {
	TargetRef(ctx context.Context, id uuid.UUID) (providers.TargetRef, inventory.Target, error)
	Credentials() providers.CredentialSource
	HostKeyStore() providers.HostKeyStore
	RecordConnectionFailure(ctx context.Context, id uuid.UUID, reason string) error
	CanaryRoundTarget(ctx context.Context, id uuid.UUID) (inventory.CanaryTarget, error)
	RecordCanaryRound(ctx context.Context, id uuid.UUID, r inventory.CanaryRound) error
	AdvanceRollouts(ctx context.Context) (int, error)
}

var _ Inventory = (*inventory.Service)(nil)

// Deps are the handler's dependencies. Checker is the HTTP application check (httpcheck.HTTPChecker in the product);
// UserAgent is its User-Agent ("Alice-canary/<version>").
type Deps struct {
	Inventory Inventory
	Registry  *providers.Registry
	Checker   httpcheck.Checker
	Clock     clock.Clock
	Log       *slog.Logger
	UserAgent string
}

// Register registers the canary.check handler on the runner. It panics on a missing dependency.
func Register(r *jobs.Runner, d Deps) {
	if d.Inventory == nil || d.Registry == nil || d.Checker == nil || d.Clock == nil {
		panic("canaryjobs: Register needs the inventory, the provider registry, the checker and a clock")
	}
	if d.Log == nil {
		d.Log = slog.New(slog.DiscardHandler)
	}
	if d.UserAgent == "" {
		d.UserAgent = "Alice-canary"
	}
	h := &handlers{d: d}
	r.Handle(jobs.CanaryCheck, h.check)
}

type handlers struct{ d Deps }

// roundTimeout bounds one round: a connection, the provider's verification and the HTTP check (at most 10 s).
var roundTimeout = 2 * time.Minute

// check is canary.check: the deployment's round target (a deployment that no longer holds records nothing), a session on
// its server (the target checks of every connecting job; a refusal or a connection failure is an unknown round), the
// TLS baseline, the HTTP check when the policy has one and the baseline did not fail, and the record. It answers the
// round's result; it fails only when the round could not be recorded (one attempt, no dead-job e-mail).
func (h *handlers) check(jobCtx context.Context, j jobs.Job, _ jobs.StepRecorder) (map[string]any, error) {
	ctx, cancel := context.WithTimeout(inventory.WithClaim(jobCtx, inventory.Claim{JobID: j.ID, Attempt: j.Attempt}), roundTimeout)
	defer cancel()
	id, err := uuid.Parse(j.Payload["deployment_id"])
	if err != nil || id == uuid.Nil {
		return nil, jobs.Fail("system.not_found", nil, errors.New("canaryjobs: the job names no deployment"))
	}
	target, err := h.d.Inventory.CanaryRoundTarget(ctx, id)
	switch {
	case errors.Is(err, inventory.ErrDeploymentState), errors.Is(err, inventory.ErrNotFound):
		return map[string]any{"deployment_id": id.String(), "outcome": "not_holding"}, nil
	case err != nil:
		return nil, jobs.Fail("internal.unexpected", nil, err)
	case target.TargetID != j.TargetID:
		return nil, jobs.Fail("internal.unexpected", nil, errors.New("canaryjobs: the job's server is not the deployment's"))
	}
	round := h.observe(ctx, target)
	if err := h.d.Inventory.RecordCanaryRound(ctx, id, round); err != nil {
		if errors.Is(err, inventory.ErrClaimLost) {
			return nil, jobs.Fail("internal.unexpected", nil, err)
		}
		return nil, jobs.Retry("internal.unexpected", nil, err)
	}
	out := map[string]any{"deployment_id": id.String(), "outcome": round.Result, "tls": round.TLS}
	if round.Reason != "" {
		out["reason"] = round.Reason
	}
	if round.HTTPStatus > 0 {
		out["http_status"] = round.HTTPStatus
	}
	return out, nil
}

// observe runs one round (design §9.5): fail when the baseline or the HTTP check fails; unknown when the session or
// the provider gave no result; pass otherwise (a skipped baseline with no HTTP check is time only).
func (h *handlers) observe(ctx context.Context, t inventory.CanaryTarget) inventory.CanaryRound {
	sess, reason := h.open(ctx, t.TargetID)
	if sess == nil {
		return inventory.CanaryRound{Result: inventory.RoundUnknown, Reason: reason, TLS: inventory.RoundUnknown}
	}
	defer func() {
		if err := sess.Close(); err != nil {
			h.d.Log.Warn("closing a provider session failed", "error_type", fmt.Sprintf("%T", err))
		}
	}()
	vr, err := sess.VerifyDeployment(ctx, t.Verify)
	if err != nil {
		code := "internal.unexpected"
		var pe *providers.Error
		if errors.As(err, &pe) {
			code = pe.Code
		}
		return inventory.CanaryRound{Result: inventory.RoundUnknown, Reason: code, TLS: inventory.RoundUnknown}
	}
	round := inventory.CanaryRound{Result: inventory.RoundPass, TLS: inventory.RoundPass}
	switch {
	case !vr.OK:
		return inventory.CanaryRound{Result: inventory.RoundFail, Reason: vr.Reason, TLS: inventory.RoundFail}
	case vr.Mode == "skipped":
		round.TLS = inventory.RoundSkipped
	}
	if t.Check == nil {
		return round
	}
	c := t.Check
	res := h.d.Checker.Check(ctx, httpcheck.Request{Address: c.Address, Port: c.Port, ServerName: c.ServerName, Path: c.Path,
		ExpectStatus: c.ExpectStatus, Timeout: c.Timeout, ExpectLeafSHA256: c.ExpectLeafSHA256, UserAgent: h.d.UserAgent})
	round.HTTPStatus, round.LatencyMS = res.HTTPStatus, res.LatencyMS
	if !res.OK {
		round.Result, round.Reason = inventory.RoundFail, res.Reason
	}
	return round
}

// open returns a session on the server after the target checks of every job that connects (a changed or unconfirmed
// host key and a disabled server run nothing, F-31), or nil and the reason (an unknown round). A connection failure is
// recorded on the server.
func (h *handlers) open(ctx context.Context, id uuid.UUID) (providers.Session, string) {
	ref, t, err := h.d.Inventory.TargetRef(ctx, id)
	switch {
	case errors.Is(err, inventory.ErrNotFound):
		return nil, "system.not_found"
	case err != nil:
		return nil, "internal.unexpected"
	case t.Status == inventory.StatusHostKeyChanged:
		return nil, "target.host_key_changed"
	case t.Status == inventory.StatusDisabled:
		return nil, "target.disabled"
	case t.Status == inventory.StatusPendingHostKey:
		return nil, "target.host_key_unconfirmed"
	}
	p, ok := h.d.Registry.Get(ref.Kind)
	if !ok {
		return nil, "internal.unexpected"
	}
	sess, err := p.Open(ctx, ref, h.d.Inventory.Credentials(), providers.Env{Clock: h.d.Clock, HostKeys: h.d.Inventory.HostKeyStore(), Log: h.d.Log})
	if err != nil {
		var pe *providers.Error
		if errors.As(err, &pe) {
			if rerr := h.d.Inventory.RecordConnectionFailure(ctx, id, pe.Code); rerr != nil {
				h.d.Log.Error("could not record a connection failure", "target_id", id.String(), "error_type", fmt.Sprintf("%T", rerr))
			}
			return nil, pe.Code
		}
		return nil, "internal.unexpected"
	}
	return sess, ""
}

// AdvanceTask is the periodic canary.advance (ClassAlways): it runs inventory.AdvanceRollouts on the leader every
// `every` (10 s in a release build; never on the wall clock in the e2e build: a journey runs it with
// POST /test/scheduler/run {"task": "canary.advance"}).
func AdvanceTask(inv Inventory, every time.Duration, log *slog.Logger) jobs.Task {
	if inv == nil {
		panic("canaryjobs: AdvanceTask needs the inventory")
	}
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return jobs.Task{Type: jobs.CanaryAdvance, Every: every, Run: func(ctx context.Context) error {
		n, err := inv.AdvanceRollouts(ctx)
		if n > 0 {
			log.Info("advanced canary rollouts", "rollouts", n)
		}
		return err
	}}
}
