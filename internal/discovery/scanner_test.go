package discovery

import (
	"context"
	"crypto/tls"
	"errors"
	"net/netip"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/discovery/tlsprobe"
	"alice/internal/license"
	"alice/internal/platform/clock"
	"alice/internal/platform/netaddr"
	"alice/internal/testutil/fakefleet"
	"alice/internal/testutil/scanpolicy"
)

// memStore is a Store in memory: it records what the scanner asked and wrote.
type memStore struct {
	mu         sync.Mutex
	start      ScanStart
	beginErr   error
	rules      RuleSettings
	rulesErr   error
	rulesReads int
	cancel     atomic.Bool
	cancelSeen atomic.Bool
	cancelErr  error
	prepared   *Expansion
	prepareErr error
	ingestErr  error // returned from the first Ingest on
	batches    []Batch
	finished   []Finish
}

func newMemStore(s Scope) *memStore {
	return &memStore{
		start: ScanStart{Run: true, ScopeID: uuid.New(), Scope: s, StartedAt: time.Now().UTC()},
		rules: RuleSettings{AllowedNetworks: []string{"10.0.0.0/8"}},
	}
}

func (m *memStore) BeginScan(context.Context, uuid.UUID, time.Time, time.Duration) (ScanStart, error) {
	return m.start, m.beginErr
}

func (m *memStore) ReadRules(context.Context) (RuleSettings, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.rulesReads++
	return m.rules, m.rulesErr
}

func (m *memStore) CancelRequested(context.Context, uuid.UUID) (bool, error) {
	c := m.cancel.Load()
	if c {
		m.cancelSeen.Store(true)
	}
	return c, m.cancelErr
}

func (m *memStore) PrepareScan(_ context.Context, _, _ uuid.UUID, x *Expansion, _ time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.prepared = x
	return m.prepareErr
}

func (m *memStore) Ingest(_ context.Context, b Batch) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.ingestErr != nil {
		return m.ingestErr
	}
	b.Results = slices.Clone(b.Results)
	m.batches = append(m.batches, b)
	return nil
}

func (m *memStore) FinishScan(_ context.Context, f Finish) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.finished = append(m.finished, f)
	return nil
}

// results returns every ingested result.
func (m *memStore) results() []Result {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []Result
	for _, b := range m.batches {
		out = append(out, b.Results...)
	}
	return out
}

func (m *memStore) finish(t *testing.T) Finish {
	t.Helper()
	m.mu.Lock()
	defer m.mu.Unlock()
	require.Len(t, m.finished, 1)
	return m.finished[0]
}

// gate is a license gate that refuses from its lockFrom-th call on (0: never).
type gate struct {
	mu       sync.Mutex
	calls    int
	lockFrom int
	err      error
}

func (g *gate) Allow(c license.Class) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.calls++
	if c != license.ClassReadOnly {
		return errors.New("unexpected class " + c.String())
	}
	if g.lockFrom > 0 && g.calls >= g.lockFrom {
		if g.err != nil {
			return g.err
		}
		return license.ErrLocked
	}
	return nil
}

// dialCounter is the dial-counting ScanControl of the tests: the scan policy every connection is checked against at
// connect time (netaddr.ScanControl calls CheckScan on the socket before it connects). Once armed (after the
// expansion, which asks the policy too) it records every address a dial checks and runs hook.
type dialCounter struct {
	inner netaddr.ScanPolicy
	armed atomic.Bool
	mu    sync.Mutex
	dials []netip.Addr
	hook  func(n int, a netip.Addr)
}

func (p *dialCounter) CheckScan(a netip.Addr) error {
	if p.armed.Load() {
		p.mu.Lock()
		p.dials = append(p.dials, a)
		n := len(p.dials)
		p.mu.Unlock()
		if p.hook != nil {
			p.hook(n, a)
		}
	}
	return p.inner.CheckScan(a)
}

func (p *dialCounter) dialed() []netip.Addr {
	p.mu.Lock()
	defer p.mu.Unlock()
	return slices.Clone(p.dials)
}

// fleetOf starts a fleet of kinds on 127.0.0.1.
func fleetOf(t *testing.T, kinds ...fakefleet.Kind) *fakefleet.Fleet {
	t.Helper()
	f, err := fakefleet.New(fakefleet.Options{Kinds: kinds, IdleTimeout: 10 * time.Second, SlowLorisInterval: 10 * time.Millisecond,
		GiantBytes: 1 << 20, HugeChainCerts: 50})
	require.NoError(t, err)
	t.Cleanup(func() { _ = f.Close() })
	return f
}

// settle waits until every connection to the fleet has been logged and ended, and asserts no application byte.
func settle(t *testing.T, f *fakefleet.Fleet) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	require.NoError(t, f.WaitIdle(ctx))
	require.Zero(t, f.AppBytesAfterHandshake(), "the scanner sends no application byte")
}

func addrPort(t *testing.T, s string) netip.AddrPort {
	t.Helper()
	ap, err := netip.ParseAddrPort(s)
	require.NoError(t, err)
	return ap
}

// fleetEndpoints are endpoints at the fleet's servers (the expansion a test injects in place of Expand: the real
// one never yields loopback).
func fleetEndpoints(t *testing.T, f *fakefleet.Fleet, kinds ...fakefleet.Kind) []Endpoint {
	t.Helper()
	var out []Endpoint
	for _, k := range kinds {
		ap := addrPort(t, f.Addr(k))
		out = append(out, Endpoint{Address: ap.Addr(), Port: ap.Port()})
	}
	return out
}

// fixed returns an expand seam that ignores the scope and returns x (the inputs are kept for the test).
func fixed(x *Expansion, got *ExpandInputs) func(context.Context, Scope, ExpandInputs) (*Expansion, error) {
	return func(_ context.Context, _ Scope, in ExpandInputs) (*Expansion, error) {
		if got != nil {
			*got = in
		}
		if p, ok := in.Policy.(*dialCounter); ok {
			p.armed.Store(true)
		}
		cp := *x
		return &cp, nil
	}
}

func labScope() Scope {
	return Scope{Name: "lab", Entries: []string{"10.0.0.1"}, Ports: []int{443}, Enabled: true, RatePerSec: MaxRate, Concurrency: 4}
}

// deps returns the dependencies of a unit test: the memory store, an open gate and the counting policy over
// Permissive(except...).
func deps(st *memStore, p *dialCounter) Deps {
	return Deps{
		Store: st, License: &gate{},
		NewPolicy: func(context.Context, netaddr.ScanPolicyInputs) (netaddr.ScanPolicy, error) {
			return p, nil
		},
		DatabaseURL: "postgres://alice@192.0.2.10/alice", PollInterval: time.Millisecond,
	}
}

func counter(except ...string) *dialCounter {
	var ps []netip.Prefix
	for _, s := range except {
		ps = append(ps, netip.MustParsePrefix(s))
	}
	return &dialCounter{inner: scanpolicy.Permissive(ps...)}
}

func run(t *testing.T, d Deps) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	return Run(ctx, d, uuid.New())
}

func codes(rs []Result) map[string]tlsprobe.Code {
	out := map[string]tlsprobe.Code{}
	for _, r := range rs {
		out[netip.AddrPortFrom(r.Endpoint.Address, r.Endpoint.Port).String()+" "+r.Endpoint.SNI] = r.Code
	}
	return out
}

// TestExcludedAddressesAreNeverDialed (Review Focus 2): the real Expand over a scope with literal addresses, a range
// with a scope and a global exclusion inside it, and a host name resolving to a public address, an address the policy
// refuses and a globally excluded one. Every dialable address is mapped onto the fleet (loopback, allowed by the
// permissive test policy); the dial-counting policy and the fleet's access log show exactly those connections, and
// every excluded endpoint is recorded excluded/policy without a dial.
func TestExcludedAddressesAreNeverDialed(t *testing.T) {
	f := fleetOf(t, fakefleet.KindValid, fakefleet.KindSelfSigned, fakefleet.KindExpired, fakefleet.KindSNI)
	s := Scope{Name: "lab", Entries: []string{"10.77.0.1", "10.66.0.5", "10.55.0.0/30", "mixed.example"}, Ports: []int{443},
		Exclusions: []string{"10.55.0.2"}, Enabled: true, RatePerSec: MaxRate, Concurrency: 4}
	st := newMemStore(s)
	st.rules.GlobalExclusions = []string{"10.55.0.3/32"}
	p := counter("10.66.0.0/16")
	d := deps(st, p)
	res := &stubResolver{answers: map[string][]netip.Addr{"mixed.example": addrs("10.77.0.2", "10.66.0.7", "10.55.0.3")}}
	d.Resolver = res
	onto := map[netip.Addr]netip.AddrPort{
		netip.MustParseAddr("10.77.0.1"): addrPort(t, f.Addr(fakefleet.KindValid)),
		netip.MustParseAddr("10.55.0.0"): addrPort(t, f.Addr(fakefleet.KindSelfSigned)),
		netip.MustParseAddr("10.55.0.1"): addrPort(t, f.Addr(fakefleet.KindExpired)),
		netip.MustParseAddr("10.77.0.2"): addrPort(t, f.Addr(fakefleet.KindSNI)),
	}
	var excluded []string
	d.expand = func(ctx context.Context, s Scope, in ExpandInputs) (*Expansion, error) {
		x, err := Expand(ctx, s, in)
		require.NoError(t, err)
		for _, e := range x.Excluded {
			excluded = append(excluded, e.Address.String())
		}
		for i, e := range x.Dial {
			ap, ok := onto[e.Address]
			require.True(t, ok, "dialable %s is not one the test expects", e.Address)
			x.Dial[i].Address, x.Dial[i].Port = ap.Addr(), ap.Port()
		}
		p.armed.Store(true)
		return x, nil
	}
	require.NoError(t, run(t, d))
	settle(t, f)

	require.ElementsMatch(t, []string{"10.66.0.5", "10.66.0.7", "10.55.0.3"}, excluded,
		"refused by the policy (literal and resolved) and a resolved address inside a global exclusion; 10.55.0.2/.3 literals are subtracted")
	want := []netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("127.0.0.1")}
	require.Equal(t, want, p.dialed(), "four connections, all to the fleet: no excluded address reached the socket")
	for _, k := range []fakefleet.Kind{fakefleet.KindValid, fakefleet.KindSelfSigned, fakefleet.KindExpired, fakefleet.KindSNI} {
		require.EqualValues(t, 1, f.Server(k).Accepted(), k)
	}
	got := codes(st.results())
	require.Len(t, got, 7)
	for _, r := range st.results() {
		if r.Code == tlsprobe.CodePolicy {
			require.Contains(t, excluded, r.Endpoint.Address.String())
			state, code := StateFor(r.Code)
			require.Equal(t, [2]string{"excluded", "policy"}, [2]string{state, code})
			continue
		}
		require.Empty(t, r.Code, r.Endpoint)
		require.Equal(t, "127.0.0.1", r.Endpoint.Address.String())
	}
	require.Equal(t, []string{"mixed.example"}, res.asked, "the name is resolved once, at expansion; dials use addresses")
	fin := st.finish(t)
	require.Equal(t, ScanDone, fin.State)
	require.True(t, fin.Probed)
}

// TestRealPolicyRefusesLoopbackAtConnectTime: an expansion that (by a bug) hands the scanner the loopback fleet is
// still refused, on the socket, by the production policy (netaddr.NewScanPolicy, built per scan): nothing reaches the
// fleet, and the endpoints are recorded as excluded by the policy.
func TestRealPolicyRefusesLoopbackAtConnectTime(t *testing.T) {
	f := fleetOf(t, fakefleet.KindValid, fakefleet.KindSelfSigned)
	st := newMemStore(labScope())
	st.rules.AllowedNetworks = []string{"0.0.0.0/0", "::/0"}
	d := deps(st, nil)
	d.NewPolicy = nil // production policy
	eps := fleetEndpoints(t, f, fakefleet.KindValid, fakefleet.KindSelfSigned)
	eps = append(eps, Endpoint{Address: netip.MustParseAddr("::1"), Port: eps[0].Port}, Endpoint{Address: netip.MustParseAddr("::ffff:127.0.0.1"), Port: eps[0].Port})
	var in ExpandInputs
	d.expand = fixed(&Expansion{Dial: eps, Endpoints: len(eps)}, &in)
	require.NoError(t, run(t, d))
	settle(t, f)
	require.Zero(t, f.Server(fakefleet.KindValid).Accepted()+f.Server(fakefleet.KindSelfSigned).Accepted(), "loopback is never dialed")
	for _, r := range st.results() {
		require.Equal(t, tlsprobe.CodePolicy, r.Code, r.Endpoint)
	}
	require.Len(t, st.results(), 4)
	require.Error(t, in.Policy.CheckScan(netip.MustParseAddr("127.0.0.1")))
	require.Equal(t, ScanDone, st.finish(t).State)
}

// rebindingResolver answers first with first, then with later (DNS rebinding).
type rebindingResolver struct {
	mu           sync.Mutex
	first, later []netip.Addr
	asked        int
}

func (r *rebindingResolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.asked++
	if r.asked == 1 {
		return r.first, nil
	}
	return r.later, nil
}

// TestDNSRebindingIsRefusedAtDialTime: the name is resolved once (to an allowed address); a second lookup would answer
// loopback, but the scanner never looks again: it dials the address. And when the policy's verdict on that address
// changes between the expansion and the connection (an address that became Alice's own, say), the connect-time check
// refuses it: nothing connects, the endpoint is recorded excluded.
func TestDNSRebindingIsRefusedAtDialTime(t *testing.T) {
	s := labScope()
	s.Entries = []string{"rebind.example"}
	st := newMemStore(s)
	refuse := &atomic.Bool{}
	inner := counter()
	flip := &flipPolicy{inner: inner, refuse: refuse}
	d := deps(st, nil)
	d.NewPolicy = func(context.Context, netaddr.ScanPolicyInputs) (netaddr.ScanPolicy, error) { return flip, nil }
	r := &rebindingResolver{first: addrs("10.77.0.9"), later: addrs("127.0.0.1")}
	d.Resolver = r
	d.expand = func(ctx context.Context, s Scope, in ExpandInputs) (*Expansion, error) {
		x, err := Expand(ctx, s, in)
		inner.armed.Store(true)
		refuse.Store(true) // from now on the policy refuses 10.77.0.9
		return x, err
	}
	require.NoError(t, run(t, d))
	require.Equal(t, 1, r.asked, "resolved once")
	require.Equal(t, []netip.Addr{netip.MustParseAddr("10.77.0.9")}, inner.dialed(), "the connection was checked for the resolved address only")
	rs := st.results()
	require.Len(t, rs, 1)
	require.Equal(t, tlsprobe.CodePolicy, rs[0].Code)
	require.Equal(t, "rebind.example", rs[0].Endpoint.Host)
	require.Equal(t, "rebind.example", rs[0].Endpoint.SNI)
}

// flipPolicy refuses 10.77.0.9 once refuse is set.
type flipPolicy struct {
	inner  netaddr.ScanPolicy
	refuse *atomic.Bool
}

func (p *flipPolicy) CheckScan(a netip.Addr) error {
	err := p.inner.CheckScan(a)
	if p.refuse.Load() && a == netip.MustParseAddr("10.77.0.9") {
		return netaddr.ErrScanRefused
	}
	return err
}

// TestRulesAndPolicyComeFromOneRead (ledger carry, Task 5): the settings are read once, and the rules Expand applies
// and the policy every connection is checked against are built from that one reading; the policy Expand gets is the
// one the scan dials through.
func TestRulesAndPolicyComeFromOneRead(t *testing.T) {
	s := labScope()
	s.Exclusions = []string{"10.0.0.128/25"}
	st := newMemStore(s)
	st.rules = RuleSettings{AllowedNetworks: []string{"10.0.0.0/8", "::ffff:192.168.0.0/112"}, GlobalExclusions: []string{"10.1.0.0/16"}}
	var built []netaddr.ScanPolicyInputs
	p := counter()
	d := deps(st, p)
	d.NewPolicy = func(_ context.Context, in netaddr.ScanPolicyInputs) (netaddr.ScanPolicy, error) {
		built = append(built, in)
		return p, nil
	}
	var in ExpandInputs
	d.expand = fixed(&Expansion{}, &in)
	require.NoError(t, run(t, d))
	require.Equal(t, 1, st.rulesReads, "one settings read")
	require.Len(t, built, 1, "one policy per scan")
	require.Equal(t, in.AllowedNetworks, built[0].AllowedNetworks)
	require.Equal(t, in.GlobalExclusions, built[0].GlobalExclusions)
	require.Equal(t, []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("192.168.0.0/16")}, in.AllowedNetworks)
	require.Equal(t, []netip.Prefix{netip.MustParsePrefix("10.1.0.0/16")}, in.GlobalExclusions)
	require.Equal(t, []netip.Prefix{netip.MustParsePrefix("10.0.0.128/25")}, built[0].ScopeExclusions)
	require.Equal(t, "postgres://alice@192.0.2.10/alice", built[0].DatabaseURL)
	require.Same(t, p, in.Policy)
	require.Equal(t, SystemResolver, in.Resolver)
}

// TestNothingIsScannedWithoutAllowedNetworks (ledger carry, Task 3): an absent setting, a stored empty list, a list
// that does not parse, a settings read error and a policy that cannot be built all end the scan failed with
// discovery.entry_not_allowed before anything is expanded or dialed.
func TestNothingIsScannedWithoutAllowedNetworks(t *testing.T) {
	for name, mod := range map[string]func(*memStore, *Deps){
		"absent":         func(m *memStore, _ *Deps) { m.rules = RuleSettings{} },
		"stored empty":   func(m *memStore, _ *Deps) { m.rules = RuleSettings{AllowedNetworks: []string{}} },
		"read error":     func(m *memStore, _ *Deps) { m.rulesErr = errors.New("connection refused") },
		"unparsable":     func(m *memStore, _ *Deps) { m.rules.AllowedNetworks = []string{"10.0.0.0/8", "not a network"} },
		"bad exclusions": func(m *memStore, _ *Deps) { m.rules.GlobalExclusions = []string{"example.com"} },
		"bad scope exclusion": func(m *memStore, _ *Deps) {
			m.start.Scope.Exclusions = []string{"10.0.0.0/33"}
		},
		"policy cannot be built": func(_ *memStore, d *Deps) {
			d.NewPolicy = func(context.Context, netaddr.ScanPolicyInputs) (netaddr.ScanPolicy, error) {
				return nil, errors.New("interfaces unreadable")
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			st := newMemStore(labScope())
			d := deps(st, counter())
			expanded := false
			d.expand = func(context.Context, Scope, ExpandInputs) (*Expansion, error) {
				expanded = true
				return &Expansion{}, nil
			}
			mod(st, &d)
			require.NoError(t, run(t, d))
			require.False(t, expanded)
			require.Nil(t, st.prepared)
			require.Equal(t, Finish{ScanID: st.finish(t).ScanID, ScopeID: st.start.ScopeID, Now: st.finish(t).Now, State: ScanFailed,
				ErrorCode: ReasonEntryNotAllowed}, st.finish(t))
		})
	}
}

// TestRunEndsWithoutProbing: a deleted scope, a switched-off one, a cancel before the start and a locked license end the
// scan without a dial; a scan with nothing to do (finished, or recovered) and a store error do not finish anything.
func TestRunEndsWithoutProbing(t *testing.T) {
	for name, tc := range map[string]struct {
		mod         func(*memStore, *Deps)
		state, code string
	}{
		"scope deleted":    {func(m *memStore, _ *Deps) { m.start.ScopeDeleted = true }, ScanFailed, ReasonScopeNotFound},
		"scope off":        {func(m *memStore, _ *Deps) { m.start.Scope.Enabled = false }, ScanCancelled, ReasonCancelled},
		"cancel requested": {func(m *memStore, _ *Deps) { m.start.CancelRequested = true }, ScanCancelled, ReasonCancelled},
		"locked":           {func(_ *memStore, d *Deps) { d.License = &gate{lockFrom: 1} }, ScanCancelled, "license.locked"},
		"unverified":       {func(_ *memStore, d *Deps) { d.License = &gate{lockFrom: 1, err: license.ErrUnverified} }, ScanCancelled, "license.unverified"},
		"no gate":          {func(_ *memStore, d *Deps) { d.License = nil }, ScanCancelled, "license.locked"},
		"too large": {func(_ *memStore, d *Deps) {
			d.expand = func(context.Context, Scope, ExpandInputs) (*Expansion, error) {
				return nil, fail(ErrTooLarge, "entries", -1, "", "")
			}
		}, ScanFailed, ReasonScopeTooLarge},
		"invalid": {func(_ *memStore, d *Deps) {
			d.expand = func(context.Context, Scope, ExpandInputs) (*Expansion, error) {
				return nil, fail(ErrInvalid, "entries", 0, "", "")
			}
		}, ScanFailed, ReasonEntryInvalid},
		"schedule": {func(_ *memStore, d *Deps) {
			d.expand = func(context.Context, Scope, ExpandInputs) (*Expansion, error) {
				return nil, fail(ErrSchedule, "window", -1, "", "")
			}
		}, ScanFailed, ReasonScheduleInvalid},
		"not allowed": {func(_ *memStore, d *Deps) {
			d.expand = func(context.Context, Scope, ExpandInputs) (*Expansion, error) {
				return nil, fail(ErrNotAllowed, "entries", 0, "", "")
			}
		}, ScanFailed, ReasonEntryNotAllowed},
	} {
		t.Run(name, func(t *testing.T) {
			st := newMemStore(labScope())
			p := counter()
			d := deps(st, p)
			d.expand = fixed(&Expansion{Dial: []Endpoint{{Address: netip.MustParseAddr("10.0.0.1"), Port: 1}}}, nil)
			tc.mod(st, &d)
			require.NoError(t, run(t, d))
			fin := st.finish(t)
			require.Equal(t, [2]string{tc.state, tc.code}, [2]string{fin.State, fin.ErrorCode})
			require.False(t, fin.Probed)
			require.Empty(t, p.dialed())
		})
	}
	t.Run("nothing to do", func(t *testing.T) {
		st := newMemStore(labScope())
		st.start.Run = false
		require.NoError(t, run(t, deps(st, counter())))
		require.Empty(t, st.finished)
	})
	t.Run("begin fails", func(t *testing.T) {
		st := newMemStore(labScope())
		st.beginErr = ErrScanBusy
		require.ErrorIs(t, run(t, deps(st, counter())), ErrScanBusy)
		require.Empty(t, st.finished)
	})
	t.Run("expansion interrupted", func(t *testing.T) {
		st := newMemStore(labScope())
		d := deps(st, counter())
		ctx, cancel := context.WithCancel(context.Background())
		d.expand = func(context.Context, Scope, ExpandInputs) (*Expansion, error) { cancel(); return nil, context.Canceled }
		require.NoError(t, Run(ctx, d, uuid.New()))
		require.Equal(t, ReasonInterrupted, st.finish(t).ErrorCode)
	})
	t.Run("prepare fails", func(t *testing.T) {
		st := newMemStore(labScope())
		st.prepareErr = errors.New("db down")
		d := deps(st, counter())
		d.expand = fixed(&Expansion{}, nil)
		require.ErrorContains(t, run(t, d), "db down")
		require.Equal(t, [2]string{ScanFailed, ReasonInterrupted}, [2]string{st.finish(t).State, st.finish(t).ErrorCode})
	})
}

// TestCancelStopsTheDispatch: the cancel flag is polled; once it is seen nothing more is dialed, the probe in flight
// finishes and is recorded, the scan ends cancelled.
func TestCancelStopsTheDispatch(t *testing.T) {
	f := fleetOf(t, fakefleet.KindValid)
	st := newMemStore(labScope())
	st.start.Scope.Concurrency = 1
	p := counter()
	stopped := make(chan struct{})
	p.hook = func(n int, _ netip.Addr) {
		if n == 1 {
			st.cancel.Store(true)
			<-stopped // the dispatch has stopped before this first connection is made
		}
	}
	d := deps(st, p)
	d.onStop = func() { close(stopped) }
	ep := fleetEndpoints(t, f, fakefleet.KindValid)[0]
	var eps []Endpoint
	for i := range 5 {
		eps = append(eps, Endpoint{Address: ep.Address, Port: ep.Port, SNI: "n" + strconv.Itoa(i) + ".example"})
	}
	d.expand = fixed(&Expansion{Dial: eps, Endpoints: 5}, nil)
	require.NoError(t, run(t, d))
	settle(t, f)
	require.True(t, st.cancelSeen.Load())
	require.Len(t, p.dialed(), 1, "no dial after the cancel was seen")
	require.EqualValues(t, 1, f.Server(fakefleet.KindValid).Accepted())
	require.Len(t, st.results(), 1, "the probe in flight is recorded")
	require.Empty(t, st.results()[0].Code)
	fin := st.finish(t)
	require.Equal(t, [2]string{ScanCancelled, ReasonCancelled}, [2]string{fin.State, fin.ErrorCode})
	require.True(t, fin.Probed)
}

// TestTimeoutKeepsPartialResults: the whole-scan cap on the injected clock; the clock passes it during the first
// connection, nothing more is dialed, the first result is kept, the scan ends timed_out. No wall-clock threshold.
func TestTimeoutKeepsPartialResults(t *testing.T) {
	f := fleetOf(t, fakefleet.KindValid, fakefleet.KindExpired)
	fake := clock.NewFake(time.Date(2026, 10, 14, 9, 0, 0, 0, time.UTC))
	st := newMemStore(labScope())
	st.start.StartedAt = fake.Now()
	st.start.Scope.Concurrency = 1
	p := counter()
	p.hook = func(n int, _ netip.Addr) {
		if n == 1 {
			fake.Advance(MaxScanDuration + time.Second)
		}
	}
	d := deps(st, p)
	d.Clock = fake
	eps := fleetEndpoints(t, f, fakefleet.KindValid, fakefleet.KindExpired)
	d.expand = fixed(&Expansion{Dial: eps, Endpoints: 2}, nil)
	require.NoError(t, run(t, d))
	settle(t, f)
	require.Len(t, p.dialed(), 1)
	require.Zero(t, f.Server(fakefleet.KindExpired).Accepted())
	require.Len(t, st.results(), 1, "partial results are kept")
	fin := st.finish(t)
	require.Equal(t, [2]string{ScanTimedOut, ReasonTimedOut}, [2]string{fin.State, fin.ErrorCode})
	require.True(t, fin.Probed)
	require.Equal(t, fake.Now(), fin.Now)
}

// TestTimeoutSeenByThePoll: the cap is also seen by the poll while the dispatch waits for a worker.
func TestTimeoutSeenByThePoll(t *testing.T) {
	fake := clock.NewFake(time.Date(2026, 10, 14, 9, 0, 0, 0, time.UTC))
	st := newMemStore(labScope())
	st.start.StartedAt = fake.Now()
	st.start.Scope.Concurrency = 1
	release := make(chan struct{})
	dialing := make(chan struct{})
	p := counter()
	p.hook = func(n int, _ netip.Addr) {
		if n == 1 {
			close(dialing)
			<-release
		}
	}
	d := deps(st, p)
	d.Clock = fake
	d.newBucket = func(clock.Clock, int) waiter { return noWait{} }
	d.onStop = func() { close(release) }
	refused := netip.MustParseAddr("127.0.0.1")
	d.expand = fixed(&Expansion{Dial: []Endpoint{{Address: refused, Port: 1}, {Address: refused, Port: 2}}}, nil)
	done := make(chan error)
	go func() { done <- run(t, d) }()
	<-dialing
	fake.BlockUntil(1, 0) // the poll waits
	fake.Advance(MaxScanDuration)
	require.NoError(t, <-done)
	require.Equal(t, ScanTimedOut, st.finish(t).State)
	require.Len(t, p.dialed(), 1)
}

type noWait struct{}

func (noWait) Wait(ctx context.Context) error { return ctx.Err() }

// TestLockMidScanStopsDialing (A5): the gate is asked before every batch; when it refuses, nothing more is dialed and
// the scan ends cancelled with the lock reason. The fleet's log has exactly the first batch.
func TestLockMidScanStopsDialing(t *testing.T) {
	f := fleetOf(t, fakefleet.KindValid)
	st := newMemStore(labScope())
	p := counter()
	g := &gate{lockFrom: 2} // the start's check passes, the check before the second batch refuses
	d := deps(st, p)
	d.License = g
	d.batch = 3
	ep := fleetEndpoints(t, f, fakefleet.KindValid)[0]
	var eps []Endpoint
	for i := range 7 {
		eps = append(eps, Endpoint{Address: ep.Address, Port: ep.Port, SNI: "n" + strconv.Itoa(i) + ".example"})
	}
	d.expand = fixed(&Expansion{Dial: eps, Endpoints: 7}, nil)
	require.NoError(t, run(t, d))
	settle(t, f)
	require.Len(t, p.dialed(), 3)
	require.EqualValues(t, 3, f.Server(fakefleet.KindValid).Accepted())
	var snis []string
	for _, a := range f.Server(fakefleet.KindValid).Log() {
		snis = append(snis, a.SNI)
	}
	require.ElementsMatch(t, []string{"n0.example", "n1.example", "n2.example"}, snis)
	require.Equal(t, 2, g.calls)
	fin := st.finish(t)
	require.Equal(t, [2]string{ScanCancelled, "license.locked"}, [2]string{fin.State, fin.ErrorCode})
	require.Len(t, st.results(), 3)
}

// TestConcurrencyIsBounded: at most the scope's concurrency of connections are in flight, and that many are reached.
func TestConcurrencyIsBounded(t *testing.T) {
	st := newMemStore(labScope())
	st.start.Scope.Concurrency = 3
	var inFlight, peak atomic.Int32
	full := make(chan struct{})
	release := make(chan struct{})
	p := counter()
	p.hook = func(int, netip.Addr) {
		n := inFlight.Add(1)
		for {
			old := peak.Load()
			if n <= old || peak.CompareAndSwap(old, n) {
				break
			}
		}
		if n == 3 {
			close(full)
		}
		<-release
		inFlight.Add(-1)
	}
	d := deps(st, p)
	d.newBucket = func(clock.Clock, int) waiter { return noWait{} }
	var eps []Endpoint
	for i := range 9 {
		eps = append(eps, Endpoint{Address: netip.MustParseAddr("127.0.0.1"), Port: uint16(1 + i)})
	}
	d.expand = fixed(&Expansion{Dial: eps}, nil)
	done := make(chan error)
	go func() { done <- run(t, d) }()
	<-full
	close(release)
	require.NoError(t, <-done)
	require.EqualValues(t, 3, peak.Load())
	require.Len(t, p.dialed(), 9)
	require.Len(t, st.results(), 9)
	for _, r := range st.results() {
		require.Equal(t, tlsprobe.CodeRefused, r.Code, "nothing listens on these ports")
	}
}

// TestScopeRateAndConcurrencyAreClamped: the bucket gets the scope's rate within 1..MaxRate.
func TestScopeRateAndConcurrencyAreClamped(t *testing.T) {
	for in, want := range map[int]int{0: 1, 7: 7, 100: 100, 250: 100} {
		st := newMemStore(labScope())
		st.start.Scope.RatePerSec, st.start.Scope.Concurrency = in, in
		d := deps(st, counter())
		got := -1
		d.newBucket = func(_ clock.Clock, r int) waiter { got = r; return noWait{} }
		d.expand = fixed(&Expansion{}, nil)
		require.NoError(t, run(t, d))
		require.Equal(t, want, got, in)
	}
}

// TestBucketSpacesConnections: rate r lets one connection through every 1/r on the clock and keeps no burst; the
// fake clock is moved exactly to each timer the bucket waits on, so no wall-clock time is involved.
func TestBucketSpacesConnections(t *testing.T) {
	start := time.Date(2026, 10, 14, 9, 0, 0, 0, time.UTC)
	fake := clock.NewFake(start)
	b := newBucket(fake, 20)
	ticked := make(chan time.Duration)
	go func() {
		for range 21 {
			_ = b.Wait(context.Background())
			ticked <- fake.Now().Sub(start)
		}
	}()
	for i := range 21 {
		if i > 0 {
			fake.BlockUntil(1, 0)
			require.True(t, fake.AdvanceToNextTimer())
		}
		require.Equal(t, time.Duration(i)*50*time.Millisecond, <-ticked, i)
	}
	// idle for 10 s: the next token is immediate, the one after it 50 ms later (no burst stored)
	fake.Advance(10 * time.Second)
	require.NoError(t, b.Wait(context.Background()))
	t0 := fake.Now()
	waited := make(chan error)
	go func() { waited <- b.Wait(context.Background()) }()
	fake.BlockUntil(1, 0)
	require.True(t, fake.AdvanceToNextTimer())
	require.NoError(t, <-waited)
	require.Equal(t, 50*time.Millisecond, fake.Now().Sub(t0))
	ctx, cancel := context.WithCancel(context.Background())
	go func() { waited <- b.Wait(ctx) }()
	fake.BlockUntil(1, 0)
	cancel()
	require.ErrorIs(t, <-waited, context.Canceled)
}

// TestIngestFailureFailsTheScan: a batch that cannot be written stops the dispatch; the scan ends failed
// (interrupted) and Run returns the error.
func TestIngestFailureFailsTheScan(t *testing.T) {
	st := newMemStore(labScope())
	st.ingestErr = errors.New("disk full")
	st.start.Scope.Concurrency = 1
	stopped := make(chan struct{})
	p := counter()
	p.hook = func(n int, _ netip.Addr) {
		if n == 1 {
			<-stopped
		}
	}
	d := deps(st, p)
	d.batch = 1
	d.onStop = func() { close(stopped) }
	var eps []Endpoint
	for i := range 50 {
		eps = append(eps, Endpoint{Address: netip.MustParseAddr("127.0.0.1"), Port: uint16(1 + i)})
	}
	d.expand = fixed(&Expansion{Dial: eps, Excluded: []Endpoint{{Address: netip.MustParseAddr("10.9.9.9"), Port: 443, excluded: true}}}, nil)
	require.ErrorContains(t, run(t, d), "disk full")
	fin := st.finish(t)
	require.Equal(t, [2]string{ScanFailed, ReasonInterrupted}, [2]string{fin.State, fin.ErrorCode})
	require.LessOrEqual(t, len(p.dialed()), 1, "the failed batch stopped the dispatch (before or after the first endpoint)")
}

// TestParentContextEndsTheScan: the job's context ending (shutdown, lost lease) stops the dispatch; the scan is
// cancelled as interrupted, recorded on a context that is not the job's.
func TestParentContextEndsTheScan(t *testing.T) {
	st := newMemStore(labScope())
	st.start.Scope.Concurrency = 1
	ctx, cancel := context.WithCancel(context.Background())
	p := counter()
	p.hook = func(n int, _ netip.Addr) {
		if n == 2 {
			cancel()
		}
	}
	d := deps(st, p)
	var eps []Endpoint
	for i := range 10 {
		eps = append(eps, Endpoint{Address: netip.MustParseAddr("127.0.0.1"), Port: uint16(1 + i)})
	}
	d.expand = fixed(&Expansion{Dial: eps}, nil)
	require.NoError(t, Run(ctx, d, uuid.New()))
	fin := st.finish(t)
	require.Equal(t, [2]string{ScanCancelled, ReasonInterrupted}, [2]string{fin.State, fin.ErrorCode})
	require.LessOrEqual(t, len(p.dialed()), 3)
	for _, r := range st.results() {
		require.NotEqual(t, tlsprobe.Code(""), r.Code)
	}
}

func TestOutcomeAndReasons(t *testing.T) {
	require.Equal(t, "license.lock_due", lockReason(license.ErrLockDue))
	require.Equal(t, "license.locked", lockReason(errors.New("other")))
	require.Equal(t, ReasonEntryNotAllowed, expandReason(context.Background(), errors.New("no policy")))
	require.Contains(t, lockStop{license.ErrLocked}.Error(), "license")
	state, code, err := outcome(context.Canceled)
	require.NoError(t, err)
	require.Equal(t, [2]string{ScanCancelled, ReasonInterrupted}, [2]string{state, code})
}

// TestCancelPollErrorsAreIgnored: a failing read of the flag does not stop the scan.
func TestCancelPollErrorsAreIgnored(t *testing.T) {
	st := newMemStore(labScope())
	st.cancelErr = errors.New("db blip")
	st.start.Scope.Concurrency = 1
	release := make(chan struct{})
	dialing := make(chan struct{})
	p := counter()
	p.hook = func(n int, _ netip.Addr) {
		if n == 1 {
			close(dialing)
			<-release
		}
	}
	d := deps(st, p)
	d.newBucket = func(clock.Clock, int) waiter { return noWait{} }
	refused := netip.MustParseAddr("127.0.0.1")
	d.expand = fixed(&Expansion{Dial: []Endpoint{{Address: refused, Port: 1}, {Address: refused, Port: 2}}}, nil)
	fake := clock.NewFake(time.Date(2026, 10, 14, 9, 0, 0, 0, time.UTC))
	st.start.StartedAt = fake.Now()
	d.Clock = fake
	done := make(chan error)
	go func() { done <- run(t, d) }()
	<-dialing
	for range 3 { // three polls fail; the scan goes on
		fake.BlockUntil(1, 0)
		fake.Advance(time.Millisecond)
	}
	close(release)
	require.NoError(t, <-done)
	assert.Equal(t, ScanDone, st.finish(t).State)
	assert.Len(t, p.dialed(), 2)
}

// TestUnstorableLeafIsMalformed (Task 6 carry): a server whose leaf Go parses but whose validity is reversed completes
// the handshake; ParsePresentedChain refuses the leaf, and the endpoint is recorded malformed without a certificate.
func TestUnstorableLeafIsMalformed(t *testing.T) {
	now := time.Date(2026, 10, 14, 0, 0, 0, 0, time.UTC)
	der := testCert(t, "reversed.example", now.Add(time.Hour), now.Add(-time.Hour))
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: certKey}},
		MinVersion: tls.VersionTLS12})
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.(*tls.Conn).Handshake()
			_ = c.Close()
		}
	}()
	st := newMemStore(labScope())
	d := deps(st, counter())
	ap := addrPort(t, ln.Addr().String())
	d.expand = fixed(&Expansion{Dial: []Endpoint{{Address: ap.Addr(), Port: ap.Port()}}}, nil)
	require.NoError(t, run(t, d))
	rs := st.results()
	require.Len(t, rs, 1)
	require.Equal(t, tlsprobe.CodeMalformed, rs[0].Code)
	require.Empty(t, rs[0].Presented)
}
