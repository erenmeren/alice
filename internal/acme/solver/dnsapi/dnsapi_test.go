package dnsapi

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/acme"
	"alice/internal/acme/solver"
)

// memProvider is an in-memory Provider: zones by name, TXT values per name, scripted errors and change polls.
type memProvider struct {
	mu        sync.Mutex
	zones     []Zone
	records   map[string][]string
	findErr   error
	addErr    error
	removeErr error
	doneErr   error
	change    string
	pending   int // ChangeDone answers false this many times
	finds     int
	polls     int
	badZone   *Zone // FindZone answers this zone whatever the name
}

func newMem(zones ...string) *memProvider {
	m := &memProvider{records: map[string][]string{}}
	for i, z := range zones {
		m.zones = append(m.zones, Zone{Name: z, ID: fmt.Sprintf("id-%d", i)})
	}
	return m
}

func (m *memProvider) Kind() string { return "memory" }

func (m *memProvider) FindZone(_ context.Context, fqdn string) (Zone, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.finds++
	if m.findErr != nil {
		return Zone{}, m.findErr
	}
	if m.badZone != nil {
		return *m.badZone, nil
	}
	z, ok := Longest(fqdn, m.zones)
	if !ok {
		return Zone{}, acme.DNSZoneNotFound("")
	}
	return z, nil
}

func (m *memProvider) AddTXT(_ context.Context, _ Zone, fqdn, value string, _ int) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.addErr != nil {
		return "", m.addErr
	}
	m.records[fqdn] = append(m.records[fqdn], value)
	return m.change, nil
}

func (m *memProvider) RemoveTXT(_ context.Context, _ Zone, fqdn, value string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.removeErr != nil {
		return m.removeErr
	}
	var keep []string
	for _, v := range m.records[fqdn] {
		if v != value {
			keep = append(keep, v)
		}
	}
	m.records[fqdn] = keep
	return nil
}

func (m *memProvider) ChangeDone(context.Context, string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.polls++
	if m.doneErr != nil {
		return false, m.doneErr
	}
	if m.pending > 0 {
		m.pending--
		return false, nil
	}
	return true, nil
}

type fakeClock struct {
	mu    sync.Mutex
	t     time.Time
	slept []time.Duration
}

func (f *fakeClock) now() time.Time { f.mu.Lock(); defer f.mu.Unlock(); return f.t }
func (f *fakeClock) sleep(ctx context.Context, d time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	f.mu.Lock()
	f.t = f.t.Add(d)
	f.slept = append(f.slept, d)
	f.mu.Unlock()
	return nil
}

func newSolver(t *testing.T, p Provider, cfg Config) (*Solver, *fakeClock) {
	t.Helper()
	cfg.Provider = p
	if cfg.AllowedSuffixes == nil {
		cfg.AllowedSuffixes = []string{"example.com"}
	}
	s, err := New(cfg)
	require.NoError(t, err)
	c := &fakeClock{t: time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)}
	s.now, s.sleep = c.now, c.sleep
	return s, c
}

func ch(domain, value string) solver.Challenge {
	return solver.Challenge{Type: solver.DNS01, Domain: domain, Token: "tok", DNSName: "_acme-challenge." + domain, DNSValue: value}
}

// failure checks err's reason and returns the *acme.Error's identifier.
func failure(t *testing.T, err error, reason string) string {
	t.Helper()
	var ae *acme.Error
	require.ErrorAs(t, err, &ae)
	assert.Equal(t, reason, ae.Reason)
	return ae.Identifier
}

func TestNewValidates(t *testing.T) {
	p := newMem("example.com")
	_, err := New(Config{})
	assert.ErrorIs(t, err, ErrProvider)
	for name, cfg := range map[string]Config{
		"wait":          {PropagationWait: MaxPropagationWait + time.Second},
		"poll negative": {PollTimeout: -time.Second},
		"poll":          {PollTimeout: MaxPollTimeout + time.Second},
		"step small":    {PollInterval: time.Millisecond},
		"step large":    {PollInterval: MaxPollInterval + time.Second},
	} {
		cfg.Provider = p
		_, err := New(cfg)
		assert.ErrorIs(t, err, ErrWait, name)
	}
	_, err = New(Config{Provider: p, TTL: MinTTL - 1})
	assert.ErrorIs(t, err, ErrTTL)
	_, err = New(Config{Provider: p, TTL: MaxTTL + 1})
	assert.ErrorIs(t, err, ErrTTL)
	_, err = New(Config{Provider: p, AllowedSuffixes: []string{"*.example.com"}})
	assert.ErrorIs(t, err, ErrSuffix)

	s, err := New(Config{Provider: p})
	require.NoError(t, err)
	assert.Equal(t, DefaultPropagationWait, s.wait)
	assert.Equal(t, DefaultPollTimeout, s.pollMax)
	assert.Equal(t, DefaultPollInterval, s.pollStep)
	assert.Equal(t, DefaultTTL, s.ttl)
	s, err = New(Config{Provider: p, PropagationWait: -1})
	require.NoError(t, err)
	assert.Zero(t, s.wait)
	assert.Equal(t, []string{solver.DNS01}, s.Types())
	assert.Equal(t, "memory", s.Kind())
	for _, f := range []string{fmt.Sprint(s), fmt.Sprintf("%#v", s), fmt.Sprintf("%+v", s), s.GoString()} {
		assert.Equal(t, "dnsapi.Solver{kind: memory}", f)
	}
}

func TestPresentAndCleanUp(t *testing.T) {
	p := newMem("example.com", "sub.example.com")
	s, c := newSolver(t, p, Config{PropagationWait: 7 * time.Second})
	ctx := context.Background()
	require.NoError(t, s.Present(ctx, ch("www.sub.example.com", "v1")))
	wild := ch("www.sub.example.com", "v2")
	wild.Wildcard = true
	require.NoError(t, s.Present(ctx, wild))
	assert.Equal(t, []string{"v1", "v2"}, p.records["_acme-challenge.www.sub.example.com"])
	assert.Equal(t, 1, p.finds, "the zone is looked up once per name")
	assert.Equal(t, []time.Duration{7 * time.Second, 7 * time.Second}, c.slept)
	assert.Zero(t, p.polls, "no change to wait for")

	require.NoError(t, s.CleanUp(ctx, wild))
	assert.Equal(t, []string{"v1"}, p.records["_acme-challenge.www.sub.example.com"])
	// CleanUp runs after the order's context ended.
	dead, cancel := context.WithCancel(ctx)
	cancel()
	require.NoError(t, s.CleanUp(dead, ch("www.sub.example.com", "v1")))
	assert.Empty(t, p.records["_acme-challenge.www.sub.example.com"])
}

func TestPresentWaitsForTheChange(t *testing.T) {
	p := newMem("example.com")
	p.change, p.pending = "C1", 3
	s, c := newSolver(t, p, Config{PropagationWait: -1, PollInterval: time.Second})
	require.NoError(t, s.Present(context.Background(), ch("example.com", "v")))
	assert.Equal(t, 4, p.polls)
	assert.Equal(t, []time.Duration{time.Second, time.Second, time.Second}, c.slept)

	// Never in sync: the poll time runs out.
	p.pending = 1 << 20
	s, _ = newSolver(t, p, Config{PropagationWait: -1, PollTimeout: 10 * time.Second, PollInterval: 2 * time.Second})
	failure(t, s.Present(context.Background(), ch("a.example.com", "v")), acme.ReasonNotIssuedInTime)

	// MaxPolls caps the polls even with time left.
	p.polls = 0
	s, _ = newSolver(t, p, Config{PropagationWait: -1, PollTimeout: MaxPollTimeout, PollInterval: MinPollInterval})
	failure(t, s.Present(context.Background(), ch("b.example.com", "v")), acme.ReasonNotIssuedInTime)
	assert.Equal(t, MaxPolls, p.polls)

	// A poll that fails is the provider's error; a context that ends while waiting is the context's.
	p.doneErr = acme.DNSProviderError("", 503, false)
	id := failure(t, s.Present(context.Background(), ch("c.example.com", "v")), acme.ReasonDNSProviderError)
	assert.Equal(t, "c.example.com", id)
	p.doneErr = nil
	ctx, cancel := context.WithCancel(context.Background())
	s.sleep = func(context.Context, time.Duration) error { cancel(); return context.Canceled }
	assert.ErrorIs(t, s.Present(ctx, ch("d.example.com", "v")), context.Canceled)
}

func TestNamesAreCheckedBeforeAnyCall(t *testing.T) {
	p := newMem("example.com")
	s, _ := newSolver(t, p, Config{AllowedSuffixes: []string{".example.com"}})
	ctx := context.Background()
	failure(t, s.Present(ctx, ch("example.com", "v")), acme.ReasonNameNotAllowed)
	failure(t, s.Present(ctx, ch("other.test", "v")), acme.ReasonNameNotAllowed)
	id := failure(t, s.Present(ctx, ch("bad_name.example.com", "v")), acme.ReasonNameNotAllowed)
	assert.Empty(t, id)
	failure(t, s.CleanUp(ctx, ch("other.test", "v")), acme.ReasonNameNotAllowed)
	failure(t, s.Present(ctx, solver.Challenge{Type: solver.HTTP01, Domain: "a.example.com", DNSValue: "v"}), acme.ReasonDNSProviderError)
	failure(t, s.Present(ctx, ch("a.example.com", "with space")), acme.ReasonDNSProviderError)
	wrong := ch("a.example.com", "v")
	wrong.DNSName = "_acme-challenge.b.example.com"
	failure(t, s.Present(ctx, wrong), acme.ReasonDNSProviderError)
	assert.Zero(t, p.finds, "nothing was asked")

	none, _ := newSolver(t, p, Config{AllowedSuffixes: []string{}})
	failure(t, none.Present(ctx, ch("a.example.com", "v")), acme.ReasonNameNotAllowed)
}

func TestProviderErrors(t *testing.T) {
	ctx := context.Background()
	p := newMem("example.com")
	s, _ := newSolver(t, p, Config{PropagationWait: -1})
	// No zone: the provider's error with the name filled in.
	id := failure(t, s.Present(ctx, ch("www.other.test", "v")), acme.ReasonNameNotAllowed)
	assert.Equal(t, "www.other.test", id)
	p.zones = nil
	id = failure(t, s.Present(ctx, ch("www.example.com", "v")), acme.ReasonDNSZoneNotFound)
	assert.Equal(t, "www.example.com", id)
	// A zone that does not hold the name is never used.
	p.badZone = &Zone{Name: "elsewhere.test", ID: "x"}
	failure(t, s.Present(ctx, ch("a.example.com", "v")), acme.ReasonDNSZoneNotFound)
	p.badZone = &Zone{Name: "example.com"}
	failure(t, s.Present(ctx, ch("b.example.com", "v")), acme.ReasonDNSZoneNotFound)
	p.badZone = nil
	p.zones = []Zone{{Name: "example.com", ID: "z"}}

	// A foreign error text never leaves the solver; a deadline inside the provider is an outage.
	p.addErr = errors.New("secret answer text")
	err := s.Present(ctx, ch("c.example.com", "v"))
	failure(t, err, acme.ReasonDNSProviderError)
	assert.NotContains(t, err.Error(), "secret answer text")
	assert.Equal(t, acme.ClassPermanent, acme.FailureClass(err))
	p.addErr = fmt.Errorf("wrapped: %w", context.DeadlineExceeded)
	err = s.Present(ctx, ch("c.example.com", "v"))
	failure(t, err, acme.ReasonDNSProviderError)
	assert.Equal(t, acme.ClassTransient, acme.FailureClass(err))
	p.addErr = acme.DNSProviderError("given.example.com", 401, false)
	id = failure(t, s.Present(ctx, ch("c.example.com", "v")), acme.ReasonDNSAuthFailed)
	assert.Equal(t, "given.example.com", id, "an identifier the provider set is kept")
	p.addErr = nil

	p.removeErr = acme.DNSProviderError("", 500, false)
	failure(t, s.CleanUp(ctx, ch("c.example.com", "v")), acme.ReasonDNSProviderError)
	p.removeErr = nil
	p.findErr = acme.DNSProviderError("", 0, true)
	failure(t, s.CleanUp(ctx, ch("new.example.com", "v")), acme.ReasonDNSProviderError)

	// A dead context is reported as itself.
	dead, cancel := context.WithCancel(ctx)
	cancel()
	assert.ErrorIs(t, s.Present(dead, ch("d.example.com", "v")), context.Canceled)
}

func TestSleepCtx(t *testing.T) {
	require.NoError(t, sleepCtx(context.Background(), time.Millisecond))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	assert.ErrorIs(t, sleepCtx(ctx, time.Hour), context.Canceled)
	s := &Solver{sleep: sleepCtx}
	assert.ErrorIs(t, s.sleepFor(ctx, 0), context.Canceled)
	require.NoError(t, s.sleepFor(context.Background(), 0))
}
