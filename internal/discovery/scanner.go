package discovery

// The scanner (design decisions 1 and 6, amendments A2-A5): one scan of one scope. The rules and the scan policy are
// built from one settings read, per scan; the scope is expanded (host names resolved once); the dialable endpoints are
// probed by a pool of workers behind a token bucket, each connection through netaddr.ScanDialContext only (the policy
// checks every address again at connect time); results stream to the ingester in batches. The license gate is asked
// before every batch, the cancel flag is polled, and the whole scan is capped at MaxScanDuration.

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/google/uuid"

	"alice/internal/discovery/tlsprobe"
	"alice/internal/license"
	"alice/internal/platform/clock"
	"alice/internal/platform/netaddr"
)

// Limits of a scan's run (design decision 1).
const (
	// ConnectTimeout bounds one TCP connect; the handshake has its own (tlsprobe.HandshakeTimeout).
	ConnectTimeout = 3 * time.Second
	// MaxScanDuration caps a whole scan: then it ends timed_out, its results so far kept.
	MaxScanDuration = 60 * time.Minute
	// BatchSize is how many endpoints one ingestion transaction (and one license check) covers.
	BatchSize = 500
	// DefaultLease is the job runner's default lease: a scan left running for longer by a run that is gone is
	// interrupted.
	DefaultLease = 45 * time.Second
	// DefaultPollInterval is how often a running scan reads its cancel flag.
	DefaultPollInterval = time.Second
)

// Licenser is the license gate (*license.Service).
type Licenser interface {
	Allow(c license.Class) error
}

// Deps are what a scan needs. Store and License are required (a nil License refuses: fail closed). NewPolicy builds
// the scan policy (nil: netaddr.NewScanPolicy, the production policy; tests inject a permissive one, amendment A2);
// DatabaseURL is Alice's database DSN, whose hosts the policy refuses. Resolver looks up the scope's host names (nil:
// SystemResolver). Clock is the time source of the scan's timestamps, its cap and its rate (nil: clock.Real). Lease is
// the job lease (zero: DefaultLease), PollInterval the cancel poll (zero: DefaultPollInterval).
type Deps struct {
	Store        Store
	License      Licenser
	NewPolicy    func(context.Context, netaddr.ScanPolicyInputs) (netaddr.ScanPolicy, error)
	DatabaseURL  string
	Resolver     Resolver
	Clock        clock.Clock
	Lease        time.Duration
	PollInterval time.Duration

	// Test seams (in-package tests only): the expansion (default Expand), the batch size (default BatchSize), the
	// token bucket (default newBucket), a hook run once the dispatch has stopped and the chain parser (default
	// tlsprobe.ParsePresentedChain).
	expand    func(context.Context, Scope, ExpandInputs) (*Expansion, error)
	batch     int
	newBucket func(clock.Clock, int) waiter
	onStop    func()
	parse     func([][]byte) (tlsprobe.Chain, error)
}

func (d Deps) withDefaults() Deps {
	if d.NewPolicy == nil {
		d.NewPolicy = netaddr.NewScanPolicy
	}
	if d.Resolver == nil {
		d.Resolver = SystemResolver
	}
	if d.Clock == nil {
		d.Clock = clock.Real{}
	}
	if d.Lease <= 0 {
		d.Lease = DefaultLease
	}
	if d.PollInterval <= 0 {
		d.PollInterval = DefaultPollInterval
	}
	if d.expand == nil {
		d.expand = Expand
	}
	if d.batch <= 0 {
		d.batch = BatchSize
	}
	if d.newBucket == nil {
		d.newBucket = newBucket
	}
	if d.parse == nil {
		d.parse = tlsprobe.ParsePresentedChain
	}
	if d.onStop == nil {
		d.onStop = func() {}
	}
	return d
}

// allow asks the license gate for read-only work.
func (d Deps) allow() error {
	if d.License == nil {
		return license.ErrLocked
	}
	return d.License.Allow(license.ClassReadOnly)
}

// lockReason is the error_code of a scan the license gate stopped: license.locked, license.unverified or
// license.lock_due.
func lockReason(err error) string {
	if r := license.DenialReason(err); r != "" {
		return "license." + r
	}
	return "license.locked"
}

// Run runs scan scanID: the netdisco.scan job's work (Task 8 wires it). It returns an error only when the database
// fails; every other end (cancelled, timed out, refused rules) is recorded in the scan's state and error_code. A scan
// found finished is left alone, one left running by a dead run is ended as interrupted (BeginScan): Run is idempotent.
func Run(ctx context.Context, deps Deps, scanID uuid.UUID) error {
	d := deps.withDefaults()
	st, err := d.Store.BeginScan(ctx, scanID, d.Clock.Now(), d.Lease)
	if err != nil || !st.Run {
		return err
	}
	finish := func(state, code string, probed bool) error {
		return d.Store.FinishScan(context.WithoutCancel(ctx), Finish{ScanID: scanID, ScopeID: st.ScopeID, Now: d.Clock.Now(),
			State: state, ErrorCode: code, Probed: probed})
	}
	switch {
	case st.ScopeDeleted:
		return finish(ScanFailed, ReasonScopeNotFound, false)
	case !st.Scope.Enabled || st.CancelRequested:
		return finish(ScanCancelled, ReasonCancelled, false)
	}
	if err := d.allow(); err != nil {
		return finish(ScanCancelled, lockReason(err), false)
	}
	rules, policy, err := d.rulesAndPolicy(ctx, st.Scope)
	if err != nil {
		return finish(ScanFailed, ReasonEntryNotAllowed, false)
	}
	x, err := d.expand(ctx, st.Scope, ExpandInputs{Rules: rules, Policy: policy, Resolver: d.Resolver})
	if err != nil {
		return finish(ScanFailed, expandReason(ctx, err), false)
	}
	if err := d.Store.PrepareScan(ctx, scanID, st.ScopeID, x, d.Clock.Now()); err != nil {
		return errors.Join(err, finish(ScanFailed, ReasonInterrupted, false))
	}
	s := &scan{Deps: d, id: scanID, scopeID: st.ScopeID, scope: st.Scope, policy: policy, deadline: st.StartedAt.Add(MaxScanDuration)}
	state, code, err := s.probe(ctx, x)
	return errors.Join(err, finish(state, code, true))
}

// rulesAndPolicy reads the settings once and builds from that one reading both the rules Expand applies and the scan
// policy that checks every connection (amendment A2). It fails closed: a read error, a list that does not parse, no
// allowed network, or a policy that cannot be built (Alice's own addresses, gateways or database host unreadable).
func (d Deps) rulesAndPolicy(ctx context.Context, s Scope) (Rules, netaddr.ScanPolicy, error) {
	set, err := d.Store.ReadRules(ctx)
	if err != nil {
		return Rules{}, nil, err
	}
	allowed, err1 := ParseNetworks(set.AllowedNetworks)
	global, err2 := ParseNetworks(set.GlobalExclusions)
	scoped, err3 := ParseNetworks(s.Exclusions)
	if err := errors.Join(err1, err2, err3); err != nil {
		return Rules{}, nil, err
	}
	if len(allowed) == 0 {
		return Rules{}, nil, ErrNotAllowed
	}
	rules := Rules{AllowedNetworks: allowed, GlobalExclusions: global}
	policy, err := d.NewPolicy(ctx, netaddr.ScanPolicyInputs{AllowedNetworks: rules.AllowedNetworks,
		GlobalExclusions: rules.GlobalExclusions, ScopeExclusions: scoped, DatabaseURL: d.DatabaseURL})
	if err != nil {
		return Rules{}, nil, err
	}
	return rules, policy, nil
}

// expandReason is the error_code of an expansion that failed.
func expandReason(ctx context.Context, err error) string {
	switch {
	case ctx.Err() != nil:
		return ReasonInterrupted
	case errors.Is(err, ErrTooLarge):
		return ReasonScopeTooLarge
	case errors.Is(err, ErrSchedule):
		return ReasonScheduleInvalid
	case errors.Is(err, ErrInvalid):
		return ReasonEntryInvalid
	}
	return ReasonEntryNotAllowed // ErrNotAllowed, or no policy or resolver: fail closed
}

// scan is one running scan.
type scan struct {
	Deps
	id, scopeID uuid.UUID
	scope       Scope
	policy      netaddr.ScanPolicy
	deadline    time.Time
}

// Why the dispatch stopped (the cause of its context).
var (
	errCancelRequested = errors.New("discovery: cancel requested")
	errTimedOut        = errors.New("discovery: the scan reached its time cap")
	errIngestFailed    = errors.New("discovery: a batch could not be recorded")
)

// lockStop is the cause of a dispatch the license gate stopped.
type lockStop struct{ err error }

func (l lockStop) Error() string { return "discovery: license: " + l.err.Error() }

// probe streams the excluded endpoints to the ingester, then dispatches the dialable ones to the workers one token at a
// time, and returns the scan's final state. Stopping (cancel, cap, license, a failed batch) stops the dispatch at once:
// no endpoint is dialed after it; the probes in flight end within one connect and handshake timeout and are recorded.
// Memory is flat: channels are bounded and results are written in batches.
func (s *scan) probe(ctx context.Context, x *Expansion) (state, code string, err error) {
	dctx, stop := context.WithCancelCause(ctx)
	defer stop(nil)
	workers := min(max(s.scope.Concurrency, 1), MaxConcurrency)
	rate := min(max(s.scope.RatePerSec, 1), MaxRate)

	jobs := make(chan Endpoint)
	results := make(chan Result, workers)
	var probing sync.WaitGroup
	for range workers {
		probing.Go(func() { s.work(ctx, jobs, results) })
	}
	ingested := make(chan error, 1)
	go func() { ingested <- s.ingest(ctx, results, stop) }()
	pctx, endPoll := context.WithCancel(dctx)
	defer endPoll()
	polled := make(chan struct{})
	go func() {
		defer close(polled)
		s.poll(pctx, stop)
	}()

	for _, e := range x.Excluded {
		results <- Result{Endpoint: e, Code: tlsprobe.CodePolicy}
	}
	bucket := s.newBucket(s.Clock, rate)
dispatch:
	for i, e := range x.Dial {
		if i > 0 && i%s.batch == 0 {
			if err := s.allow(); err != nil {
				stop(lockStop{err})
				break
			}
		}
		if bucket.Wait(dctx) != nil {
			break
		}
		if !s.Clock.Now().Before(s.deadline) {
			stop(errTimedOut)
			break
		}
		if dctx.Err() != nil {
			break
		}
		select {
		case jobs <- e:
		case <-dctx.Done():
			break dispatch
		}
	}
	endPoll()
	<-polled
	cause := context.Cause(dctx) // nil: every endpoint was dispatched
	s.onStop()
	close(jobs)
	probing.Wait()
	close(results)
	if err := <-ingested; err != nil {
		return ScanFailed, ReasonInterrupted, err
	}
	return outcome(cause)
}

// outcome maps the cause of the dispatch's end to the scan's state.
func outcome(cause error) (state, code string, err error) {
	var lock lockStop
	switch {
	case cause == nil:
		return ScanDone, "", nil
	case errors.Is(cause, errCancelRequested):
		return ScanCancelled, ReasonCancelled, nil
	case errors.Is(cause, errTimedOut):
		return ScanTimedOut, ReasonTimedOut, nil
	case errors.As(cause, &lock):
		return ScanCancelled, lockReason(lock.err), nil
	}
	return ScanCancelled, ReasonInterrupted, nil // the job's context ended (shutdown, lost lease)
}

// work probes the endpoints it receives (the dispatch hands none out once it has stopped). A probe ended by the job's
// context (not a result) is dropped.
func (s *scan) work(ctx context.Context, jobs <-chan Endpoint, results chan<- Result) {
	for e := range jobs {
		if r, ok := s.probeOne(ctx, e); ok {
			results <- r
		}
	}
}

// dialer is the one place discovery opens a connection (the guard test pins it): a plain net.Dialer with the connect
// timeout, through netaddr.ScanDialContext, so the scan policy checks the address on the socket before it connects.
// No proxy, no other transport.
func (s *scan) dialer() tlsprobe.DialFunc {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		return netaddr.ScanDialContext(ctx, s.policy, &net.Dialer{Timeout: ConnectTimeout}, network, address)
	}
}

// probeOne captures the chain of one endpoint: it dials Endpoint.Address (never its host name) and parses what came. A
// panic while probing or parsing (hostile input reaching a bug) is the endpoint's result, malformed: the scan goes on.
func (s *scan) probeOne(ctx context.Context, e Endpoint) (r Result, ok bool) {
	defer func() {
		if recover() != nil {
			r, ok = Result{Endpoint: e, Code: tlsprobe.CodeMalformed}, true
		}
	}()
	addr := netip.AddrPortFrom(e.Address, e.Port).String()
	res, err := tlsprobe.CapturePresentedChain(ctx, s.dialer(), addr, e.SNI)
	if err != nil {
		code, ok := tlsprobe.CodeOf(err)
		return Result{Endpoint: e, Code: code}, ok
	}
	chain, err := s.parse(res.Certificates)
	if err != nil {
		code, _ := tlsprobe.CodeOf(err) // ParsePresentedChain fails with an *Error only
		return Result{Endpoint: e, Code: code}, true
	}
	return PresentedResult(e, res.Certificates, chain, res.TLSVersion, res.CipherSuite), true
}

// store writes one batch; a panic in the store is returned as an error (the ingester goes on draining).
func (s *scan) store(ctx context.Context, b Batch) (err error) {
	defer func() {
		if p := recover(); p != nil {
			err = fmt.Errorf("discovery: recording a batch panicked: %v", p)
		}
	}()
	return s.Store.Ingest(ctx, b)
}

// ingest writes the results in batches. A failed batch stops the dispatch and is returned; the rest is drained
// unwritten.
func (s *scan) ingest(ctx context.Context, results <-chan Result, stop context.CancelCauseFunc) error {
	batch := make([]Result, 0, s.batch)
	var failed error
	flush := func() {
		if len(batch) > 0 && failed == nil {
			failed = s.store(context.WithoutCancel(ctx), Batch{ScanID: s.id, ScopeID: s.scopeID, Now: s.Clock.Now(), Results: batch})
			if failed != nil {
				stop(errIngestFailed)
			}
		}
		batch = batch[:0]
	}
	for r := range results {
		batch = append(batch, r)
		if len(batch) == s.batch {
			flush()
		}
	}
	flush()
	return failed
}

// poll reads the cancel flag and the cap every PollInterval until the dispatch stops (pctx ends).
func (s *scan) poll(pctx context.Context, stop context.CancelCauseFunc) {
	for {
		select {
		case <-pctx.Done():
			return
		case <-s.Clock.After(s.PollInterval):
		}
		if !s.Clock.Now().Before(s.deadline) {
			stop(errTimedOut)
			return
		}
		if c, err := s.Store.CancelRequested(pctx, s.id); err == nil && c {
			stop(errCancelRequested)
			return
		}
	}
}

// waiter is a rate limiter.
type waiter interface {
	Wait(ctx context.Context) error
}

// bucket is a token bucket of one token refilled every 1/rate seconds: consecutive Waits return at least that far
// apart on the clock, and an idle period stores no burst.
type bucket struct {
	clock    clock.Clock
	interval time.Duration
	mu       sync.Mutex
	next     time.Time
}

func newBucket(c clock.Clock, rate int) waiter {
	return &bucket{clock: c, interval: time.Second / time.Duration(rate)}
}

// Wait blocks until the next token or ctx ends.
func (b *bucket) Wait(ctx context.Context) error {
	b.mu.Lock()
	now := b.clock.Now()
	at := b.next
	if at.Before(now) {
		at = now
	}
	b.next = at.Add(b.interval)
	b.mu.Unlock()
	if d := at.Sub(now); d > 0 {
		select {
		case <-b.clock.After(d):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return ctx.Err()
}
