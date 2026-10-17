// Package acmejobs holds the jobs of ACME certificate orders (plan 2026-10-13 Task 10; design rows 1, 2, 6; amendments
// A7, A8, A10, A12): acme.issue (one order: an issue order ends with a stored certificate, a test run with validated
// authorizations only), acme.cleanup (removes what an ended order left published) and the periodic acme.sweep (ends
// the orders a crash left running and queues leftover cleanups).
//
// The CA conversation runs here, on the Alice server: the account key, the order's private key and the hook secret are
// opened by the inventory and live only for the call (A10); nothing secret is in a job payload, a result, a log line or
// an error (the order's error code is a closed reason). An order is ended on every way out, a panic included (the
// order is ended, then the panic goes on to the runner): success (inventory.FinishACMEOrder or SucceedACMETestOrder) or
// inventory.FailACMEOrder with the order's code (a failure is counted and backed off), called on a context detached
// from the job's. Two ways out leave the order running with its key and its CA URL for the sweep to finish from the CA
// (A8): a database failure while the issued certificate is stored, and a job context that ended (shutdown, lost
// lease) after the CA created the order and its key was persisted. A job context that ended before that aborts the
// order with job.lease_expired without counting a failure. Every challenge record is persisted before it is published
// (A12), removed from the record once it is gone, and the acme.cleanup job (ClassAlways) removes what is left in every
// license state.
//
// Licence: acme.issue is ClassChange (the runner never claims it in lock); the handler asks the gate again before
// each publication and once more right before finalize, so a lock that begins during an order publishes nothing more,
// sends no CSR and ends the order (license.locked; what was published is cleaned up). The sweep contacts a CA only to
// resume an interrupted order, and only while the gate allows changes.
package acmejobs

import (
	"context"
	"crypto"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"

	"alice/internal/acme"
	"alice/internal/acme/keygen"
	"alice/internal/acme/solver"
	"alice/internal/acme/solver/dns01"
	"alice/internal/acme/solver/http01"
	"alice/internal/inventory"
	"alice/internal/jobs"
	"alice/internal/license"
	"alice/internal/platform/clock"
	"alice/internal/providers"
)

// Inventory is the part of *inventory.Service the ACME jobs use.
type Inventory interface {
	ACMEOrderWork(ctx context.Context, orderID uuid.UUID) (inventory.ACMEOrderWork, error)
	ACMEOrderClient(ctx context.Context, orderID uuid.UUID) (*acme.Client, error)
	NewACMEOrderKey(ctx context.Context, orderID uuid.UUID) (crypto.Signer, error)
	LoadPendingKey(ctx context.Context, orderID uuid.UUID) (crypto.Signer, error)
	FinishACMEOrder(ctx context.Context, orderID uuid.UUID, chainDER [][]byte) (inventory.ACMEIssued, error)
	SucceedACMETestOrder(ctx context.Context, orderID uuid.UUID) error
	FailACMEOrder(ctx context.Context, orderID uuid.UUID, code string, retryAfter time.Duration) error
	AbandonACMEOrder(ctx context.Context, orderID uuid.UUID, code string) error
	GetACMEOrder(ctx context.Context, id uuid.UUID) (inventory.ACMEOrder, error)
	RecordACMEOrderURL(ctx context.Context, orderID uuid.UUID, url string) error
	AddACMEPresented(ctx context.Context, orderID uuid.UUID, p inventory.ACMEPresented) error
	RemoveACMEPresented(ctx context.Context, orderID uuid.UUID, p inventory.ACMEPresented) error
	EnqueueACMECleanup(ctx context.Context, orderID uuid.UUID) error
	ACMECleanupWork(ctx context.Context, orderID uuid.UUID) (inventory.ACMECleanupWork, error)
	RecordACMECleanup(ctx context.Context, orderID uuid.UUID, code string, final bool) error
	ACMEHookSolverConfig(ctx context.Context, hookID uuid.UUID) (dns01.Config, error)
	ACMEHookCleanupConfig(ctx context.Context, hookID uuid.UUID) (dns01.Config, error)
	StaleACMEOrders(ctx context.Context, olderThan time.Duration) ([]inventory.ACMEStaleOrder, error)
	EnqueueACMECleanups(ctx context.Context, retryAfter, giveUpAfter time.Duration) (int, error)
	TargetRef(ctx context.Context, id uuid.UUID) (providers.TargetRef, inventory.Target, error)
	Credentials() providers.CredentialSource
	HostKeyStore() providers.HostKeyStore
}

var _ Inventory = (*inventory.Service)(nil)

// Gate is the license gate (license.Service).
type Gate interface {
	Allow(c license.Class) error
}

// Deps are the jobs' dependencies.
type Deps struct {
	Inventory Inventory
	Registry  *providers.Registry // the HTTP-01 server's session (the nginx provider)
	Gate      Gate
	Clock     clock.Clock
	Log       *slog.Logger
}

// Budgets. An order is bounded by the client's own OrderTimeout (10 minutes) and CleanupTimeout; these bound what is
// recorded on a context detached from the job's, the opening of an HTTP-01 server's session, and how old a running
// order must be before the sweep treats it as abandoned (no job runs longer than an order plus its cleanup).
const (
	recordTimeout = 30 * time.Second
	openTimeout   = time.Minute
	// StaleAfter is the age from which the sweep ends a running order no queued or running job holds. Such an order
	// has no worker any more except, at worst, one whose lease was lost and that has not noticed yet: the runner
	// cancels a job within its lease (45 s) and the reaper takes it back within a minute, so 5 minutes is past both;
	// a clean shutdown therefore blocks new requests for the certificate for about 5 minutes, not an order timeout.
	StaleAfter = 5 * time.Minute
	// CleanupRetry is how long the sweep waits after a failed cleanup before it queues the cleanup again, and
	// CleanupGiveUp how long after the order ended it stops (the records stay listed with the last failure).
	CleanupRetry  = time.Hour
	CleanupGiveUp = 7 * 24 * time.Hour
)

// Job failure reasons that are not an order's code.
const (
	reasonNotFound     = "system.not_found"
	reasonUnexpected   = "internal.unexpected"
	reasonLeaseExpired = "job.lease_expired"
)

// Register registers acme.issue and acme.cleanup; it panics on a missing dependency, so a build that forgot one never
// starts.
func Register(r *jobs.Runner, d Deps) {
	if r == nil || d.Inventory == nil || d.Registry == nil || d.Gate == nil || d.Clock == nil {
		panic("acmejobs: Register needs a runner, Deps.Inventory, Deps.Registry, Deps.Gate and Deps.Clock")
	}
	h := newHandlers(d)
	r.Handle(jobs.ACMEIssue, h.issue)
	r.Handle(jobs.ACMECleanup, h.cleanup)
}

type handlers struct {
	d Deps
	// newHTTP01 builds the HTTP-01 solver (http01.New; tests replace it: the solver's own check fetches port 80 of
	// the name, which a test cannot serve).
	newHTTP01 func(http01.Config) (solver.Solver, error)
	// crash is a test seam: when it reports true at a stage the handler stops there as if the process died (no
	// further CA call, no record, no cleanup). nil in production.
	crash func(stage string) bool
}

func newHandlers(d Deps) *handlers {
	if d.Log == nil {
		d.Log = slog.New(slog.DiscardHandler)
	}
	return &handlers{d: d, newHTTP01: func(c http01.Config) (solver.Solver, error) { return http01.New(c) }}
}

// detached is a context for the records of an order that must outlive the job's context.
func detached(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(ctx), recordTimeout)
}

// errCrashed is what a handler returns after the crash seam stopped it.
var errCrashed = errors.New("acmejobs: stopped by the crash seam")

func (h *handlers) crashed(stage string) bool { return h.crash != nil && h.crash(stage) }

// errLocked is the cause of an order ended because the gate refused changes during it.
var errLocked = fmt.Errorf("acmejobs: %w", license.ErrLocked)

// orderID is the job payload's order id.
func orderID(j jobs.Job) (uuid.UUID, error) {
	id, err := uuid.Parse(j.Payload["order_id"])
	if err != nil || id == uuid.Nil {
		return uuid.Nil, jobs.Fail(reasonNotFound, nil, errors.New("acmejobs: the job names no order"))
	}
	return id, nil
}

// issue runs one order (acme.issue). The job's own result carries ids, the outcome and the order's code; its
// failure reason is the order's code.
func (h *handlers) issue(ctx context.Context, j jobs.Job, _ jobs.StepRecorder) (map[string]any, error) {
	id, err := orderID(j)
	if err != nil {
		return nil, err
	}
	w, err := h.d.Inventory.ACMEOrderWork(ctx, id)
	switch {
	case errors.Is(err, inventory.ErrNotFound):
		return nil, jobs.Fail(reasonNotFound, nil, err)
	case err != nil:
		return nil, jobs.Fail(reasonUnexpected, nil, err)
	case w.Order.State != inventory.ACMEOrderRunning:
		// The sweep ended it (a job that was blocked in lock and confirmed later): nothing to do.
		return map[string]any{"order_id": id.String(), "state": w.Order.State}, nil
	}
	o := &orderRun{h: h, w: w, id: id}
	return o.run(ctx)
}

// orderRun is one acme.issue run.
type orderRun struct {
	h  *handlers
	w  inventory.ACMEOrderWork
	id uuid.UUID
	// crashed: the crash seam stopped the run (nothing more is done, as after a real crash).
	crashed bool
	// urlRecorded and keyStored: the CA created the order and its key is persisted, so the sweep can resume it.
	urlRecorded, keyStored bool
}

// errPanicked and errUnended are the failures of a run that panicked or returned without ending its order.
var (
	errPanicked = errors.New("acmejobs: the order run panicked")
	errUnended  = errors.New("acmejobs: the order run returned without ending the order")
)

// run does the order and ends it on every way out, a panic included (the order is ended, then the panic goes on to
// the runner). Outcomes: success; a failure (FailACMEOrder: failure counted, backoff); left running for the sweep (the
// issued certificate could not be stored, or the job's context ended after the CA created the order and its key was
// persisted: a shutdown or a lost lease is not the certificate's failure); interrupted before that (AbandonACMEOrder
// with job.lease_expired: nothing counted).
func (o *orderRun) run(ctx context.Context) (res map[string]any, err error) {
	inv := o.h.d.Inventory
	var failure error
	succeeded, leftRunning := false, false
	defer func() {
		p := recover()
		if o.crashed {
			res, err = nil, jobs.Fail(reasonUnexpected, nil, errCrashed)
			if p != nil {
				panic(p)
			}
			return
		}
		if !succeeded && !leftRunning && failure == nil {
			failure = errUnended
			if p != nil {
				failure = errPanicked
			}
		}
		dctx, cancel := detached(ctx)
		defer cancel()
		params := map[string]string{"order_id": o.id.String()}
		interrupted := ctx.Err() != nil && failure != nil && p == nil
		switch {
		case succeeded:
		case interrupted && o.urlRecorded && o.keyStored:
			leftRunning = true
			o.h.d.Log.Warn("an ACME order was interrupted; the ACME sweep resumes it", "order_id", o.id.String(), "event", "acme_order_interrupted")
			res, err = nil, jobs.Fail(reasonLeaseExpired, params, ctx.Err())
		case interrupted:
			if aerr := inv.AbandonACMEOrder(dctx, o.id, reasonLeaseExpired); aerr != nil && !errors.Is(aerr, inventory.ErrACMEOrderNotRunning) {
				o.h.d.Log.Error("could not end an interrupted ACME order", "order_id", o.id.String(), "error_type", fmt.Sprintf("%T", aerr))
			}
			res, err = nil, jobs.Fail(reasonLeaseExpired, params, ctx.Err())
		case leftRunning:
			o.h.d.Log.Error("the issued certificate could not be stored; the ACME sweep finishes the order", "order_id", o.id.String(),
				"event", "acme_order_left_running")
			res, err = nil, jobs.Fail(reasonUnexpected, params, nil)
		default:
			code, after := inventory.ACMEOrderErrorCode(failure)
			if ferr := inv.FailACMEOrder(dctx, o.id, code, after); ferr != nil && !errors.Is(ferr, inventory.ErrACMEOrderNotRunning) {
				o.h.d.Log.Error("could not end a failed ACME order", "order_id", o.id.String(), "error_type", fmt.Sprintf("%T", ferr))
			}
			res, err = nil, jobs.Fail(code, params, failure)
		}
		if cerr := inv.EnqueueACMECleanup(dctx, o.id); cerr != nil {
			o.h.d.Log.Error("could not queue the cleanup of an ACME order", "order_id", o.id.String(), "error_type", fmt.Sprintf("%T", cerr))
		}
		if p != nil {
			panic(p)
		}
	}()
	if o.w.Deleted {
		failure = inventory.ErrNotFound
		return nil, nil
	}
	if err := o.h.d.Gate.Allow(license.ClassChange); err != nil {
		failure = errLocked
		return nil, nil
	}
	if !o.w.NamesAllowed() {
		failure = inventory.ErrACMENameNotAllowed
		return nil, nil
	}
	client, err := inv.ACMEOrderClient(ctx, o.id)
	if err != nil {
		failure = err
		return nil, nil
	}
	sol, closeSolver, err := o.h.solverFor(ctx, o.w)
	if err != nil {
		failure = err
		return nil, nil
	}
	defer closeSolver()
	sol = &crashSolver{Solver: sol, o: o}
	opts := o.options(ctx)
	if o.w.Order.Kind == inventory.ACMEOrderTest {
		if err := client.TestOrder(ctx, o.w.Names, sol, opts...); err != nil {
			failure = err
			return nil, nil
		}
		dctx, cancel := detached(ctx)
		defer cancel()
		if err := inv.SucceedACMETestOrder(dctx, o.id); err != nil {
			failure = err
			return nil, nil
		}
		succeeded = true
		return map[string]any{"order_id": o.id.String(), "kind": inventory.ACMEOrderTest, "state": inventory.ACMEOrderSucceeded}, nil
	}

	signer, err := inv.NewACMEOrderKey(ctx, o.id)
	if err != nil {
		failure = err
		return nil, nil
	}
	o.keyStored = true
	csr, err := keygen.NewCSR(signer, o.w.Names)
	if err != nil {
		failure = err
		return nil, nil
	}
	chain, err := client.Order(ctx, o.w.Names, csr, sol, opts...)
	if err != nil {
		failure = err
		return nil, nil
	}
	if o.crashed || o.h.crashed("issued") {
		o.crashed = true
		return nil, nil
	}
	dctx, cancel := detached(ctx)
	defer cancel()
	issued, err := inv.FinishACMEOrder(dctx, o.id, chain)
	if err != nil && !inventory.ACMEFinishRefused(err) {
		issued, err = inv.FinishACMEOrder(dctx, o.id, chain) // one more try: a database that answered late
		if errors.Is(err, inventory.ErrACMEOrderNotRunning) {
			// The first commit may have landed with its answer lost: the order says what happened.
			if cur, gerr := inv.GetACMEOrder(dctx, o.id); gerr == nil && cur.State == inventory.ACMEOrderSucceeded && cur.CertificateID != nil {
				issued, err = inventory.ACMEIssued{CertificateID: *cur.CertificateID}, nil
			}
		}
	}
	switch {
	case err == nil:
		succeeded = true
		return map[string]any{"order_id": o.id.String(), "kind": inventory.ACMEOrderIssue, "state": inventory.ACMEOrderSucceeded,
			"certificate_id": issued.CertificateID.String(), "reused": issued.Reused, "chain_complete": issued.ChainComplete}, nil
	case inventory.ACMEFinishRefused(err):
		failure = err
	default:
		leftRunning = true
	}
	return nil, nil
}

// options are the order's callbacks: the CA's order URL is stored for a resume (A8); each challenge is persisted
// before it is published (A12), after the gate was asked again (a lock that began during the order publishes
// nothing more), and the gate is asked once more right before finalize; a challenge that was removed again is taken
// out of the record (one whose removal failed stays for the cleanup job).
func (o *orderRun) options(ctx context.Context) []acme.OrderOption {
	inv := o.h.d.Inventory
	return []acme.OrderOption{
		acme.WithOnOrder(func(url string) error {
			dctx, cancel := detached(ctx)
			defer cancel()
			if err := inv.RecordACMEOrderURL(dctx, o.id, url); err != nil {
				return err
			}
			o.urlRecorded = true
			return nil
		}),
		acme.WithBeforeFinalize(func() error {
			if err := o.h.d.Gate.Allow(license.ClassChange); err != nil {
				return errLocked
			}
			return nil
		}),
		acme.WithOnPresent(func(ch solver.Challenge) error {
			if err := o.h.d.Gate.Allow(license.ClassChange); err != nil {
				return errLocked
			}
			dctx, cancel := detached(ctx)
			defer cancel()
			return inv.AddACMEPresented(dctx, o.id, o.record(ch))
		}),
		acme.WithOnCleanUp(func(ch solver.Challenge, cerr error) {
			if o.crashed {
				return
			}
			if cerr != nil {
				o.h.d.Log.Warn("a challenge record could not be removed; the cleanup job tries again", "order_id", o.id.String(),
					"event", "acme_challenge_cleanup_failed", "reason", acme.ReasonOf(cerr))
				return
			}
			dctx, cancel := detached(ctx)
			defer cancel()
			if err := inv.RemoveACMEPresented(dctx, o.id, o.record(ch)); err != nil {
				o.h.d.Log.Error("could not forget a removed challenge record", "order_id", o.id.String(), "error_type", fmt.Sprintf("%T", err))
			}
		}),
	}
}

// record is the persisted form of a challenge with what publishes it.
func (o *orderRun) record(ch solver.Challenge) inventory.ACMEPresented {
	return inventory.ACMEPresented{Challenge: ch, HookID: o.w.HookID, TargetID: o.w.HTTPTargetID}
}

// crashSolver lets the crash seam stop an order right after a challenge was published, as a dead process would: no
// further call reaches the hook or the server.
type crashSolver struct {
	solver.Solver
	o *orderRun
}

func (c *crashSolver) Present(ctx context.Context, ch solver.Challenge) error {
	if err := c.Solver.Present(ctx, ch); err != nil {
		return err
	}
	if c.o.h.crashed("presented") {
		c.o.crashed = true
		return errCrashed
	}
	return nil
}

func (c *crashSolver) CleanUp(ctx context.Context, ch solver.Challenge) error {
	if c.o.crashed {
		return nil
	}
	return c.Solver.CleanUp(ctx, ch)
}

// solverFor builds the order's solver: DNS-01 through the certificate's hook (its secret is opened for the solver
// and zeroed at once; the solver keeps its own copy for the order), HTTP-01 through the session of the certificate's
// Nginx server (closed by the returned function).
func (h *handlers) solverFor(ctx context.Context, w inventory.ACMEOrderWork) (solver.Solver, func(), error) {
	switch {
	case w.Challenge == inventory.ACMEChallengeDNS01 && w.HookID != nil:
		cfg, err := h.d.Inventory.ACMEHookSolverConfig(ctx, *w.HookID)
		if err != nil {
			return nil, nil, err
		}
		defer cfg.Secret.Zero()
		s, err := dns01.New(cfg)
		if err != nil {
			return nil, nil, &acme.Error{Reason: acme.ReasonHookRefused}
		}
		return s, func() {}, nil
	case w.Challenge == inventory.ACMEChallengeHTTP01 && w.HTTPTargetID != nil:
		pub, closePub, err := h.openPublisher(ctx, *w.HTTPTargetID)
		if err != nil {
			return nil, nil, err
		}
		s, err := h.newHTTP01(http01.Config{Publisher: pub, AllowedSuffixes: w.ProviderSuffixes})
		if err != nil {
			closePub()
			return nil, nil, inventory.ErrACMEChallengeUnavailable
		}
		return s, closePub, nil
	}
	return nil, nil, inventory.ErrACMEChallengeUnavailable
}

// openPublisher opens a session on an HTTP-01 server: a live Nginx server whose host key is confirmed and that is
// not disabled, through the provider registry; the session's PublishHTTP01Token and RemoveHTTP01Token (the helper,
// protocol 7: an older helper answers ssh.helper_outdated_http01, ALC-SSH-0013) make it the solver's publisher.
func (h *handlers) openPublisher(ctx context.Context, targetID uuid.UUID) (http01.Publisher, func(), error) {
	ref, t, err := h.d.Inventory.TargetRef(ctx, targetID)
	switch {
	case errors.Is(err, inventory.ErrNotFound):
		return nil, nil, inventory.ErrACMEChallengeUnavailable
	case err != nil:
		return nil, nil, err
	}
	p, ok := h.d.Registry.Get(ref.Kind)
	if !ok || !p.Capabilities().Has(providers.CapHTTP01) { // only a provider that publishes HTTP-01 tokens
		return nil, nil, inventory.ErrACMEChallengeUnavailable
	}
	switch t.Status {
	case inventory.StatusDisabled:
		return nil, nil, providers.NewError("target.disabled", false, nil, nil)
	case inventory.StatusHostKeyChanged:
		return nil, nil, providers.NewError("target.host_key_changed", false, nil, nil)
	case inventory.StatusPendingHostKey:
		return nil, nil, providers.NewError("target.host_key_unconfirmed", false, nil, nil)
	}
	octx, cancel := context.WithTimeout(ctx, openTimeout)
	defer cancel()
	sess, err := p.Open(octx, ref, h.d.Inventory.Credentials(), providers.Env{Clock: h.d.Clock, HostKeys: h.d.Inventory.HostKeyStore(), Log: h.d.Log})
	if err != nil {
		return nil, nil, err
	}
	pub, ok := sess.(http01.Publisher)
	if !ok {
		_ = sess.Close()
		return nil, nil, inventory.ErrACMEChallengeUnavailable
	}
	return pub, func() { _ = sess.Close() }, nil
}
