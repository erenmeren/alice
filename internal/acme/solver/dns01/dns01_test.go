package dns01

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/acme"
	"alice/internal/acme/solver"
	"alice/internal/acme/transport"
	"alice/internal/secrets"
	"alice/internal/testutil/fakeacme"
)

const testSecret = "s3cr3t-hook-key-0123456789"

func registeredClient(t *testing.T, f *fakeacme.Server) *acme.Client {
	t.Helper()
	hc, err := transport.New(string(f.CAPEM()))
	require.NoError(t, err)
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	c, err := acme.New(acme.Config{DirectoryURL: f.DirectoryURL(), Key: k, HTTPClient: hc, Contact: "admin@example.test"})
	require.NoError(t, err)
	_, err = c.RegisterAccount(ctx5(t), "", nil, true)
	require.NoError(t, err)
	return c
}

func csrFor(t *testing.T, names ...string) ([]byte, *ecdsa.PrivateKey) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: names[0]}, DNSNames: names}, k)
	require.NoError(t, err)
	return der, k
}

func ctx5(t *testing.T) context.Context {
	t.Helper()
	c, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	return c
}

func pemOf(s *httptest.Server) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.Certificate().Raw}))
}

// fakeClock makes the solver's waits instant and records them.
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
	defer f.mu.Unlock()
	f.t = f.t.Add(d)
	f.slept = append(f.slept, d)
	return nil
}

func withClock(s *Solver) *fakeClock {
	fc := &fakeClock{t: time.Unix(1_800_000_000, 0)}
	s.now, s.sleep = fc.now, fc.sleep
	return fc
}

func chal(domain, value string) solver.Challenge {
	d := strings.TrimPrefix(domain, "*.")
	return solver.Challenge{Type: solver.DNS01, Domain: d, Wildcard: strings.HasPrefix(domain, "*."), Token: "tok",
		DNSName: "_acme-challenge." + d, DNSValue: value}
}

func reasonOf(err error) string { return acme.ReasonOf(err) }

// stub is an httptest TLS hook that records requests and answers by a function.
type stub struct {
	*httptest.Server
	mu    sync.Mutex
	reqs  []rec
	conns atomic.Int32
	reply func(n int, r rec) (int, string)
}

type rec struct {
	Header http.Header
	Body   string
}

func newStub(t *testing.T, reply func(n int, r rec) (int, string)) *stub {
	t.Helper()
	st := &stub{reply: reply}
	st.Server = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		st.mu.Lock()
		st.reqs = append(st.reqs, rec{Header: r.Header.Clone(), Body: string(b)})
		n := len(st.reqs)
		cur := st.reqs[n-1]
		st.mu.Unlock()
		code, body := st.reply(n, cur)
		w.WriteHeader(code)
		_, _ = w.Write([]byte(body))
	}))
	st.Config.ConnState = func(_ net.Conn, s http.ConnState) {
		if s == http.StateNew {
			st.conns.Add(1)
		}
	}
	st.StartTLS()
	t.Cleanup(st.Close)
	return st
}

func (st *stub) requests() []rec {
	st.mu.Lock()
	defer st.mu.Unlock()
	return append([]rec(nil), st.reqs...)
}

func (st *stub) solver(t *testing.T, mut ...func(*Config)) *Solver {
	t.Helper()
	cfg := Config{URL: st.URL + "/hook?token=querysecret", Secret: secrets.NewPlaintext([]byte(testSecret)), CABundlePEM: pemOf(st.Server),
		PropagationWait: -1, AllowedSuffixes: []string{"example.test"}}
	for _, m := range mut {
		m(&cfg)
	}
	s, err := New(cfg)
	require.NoError(t, err)
	withClock(s)
	return s
}

func ok(int, rec) (int, string) { return 200, `{"ok":true}` }

func TestPresentWireFormat(t *testing.T) {
	st := newStub(t, ok)
	s := st.solver(t, func(c *Config) { c.TTL = 120 })
	require.NoError(t, s.Present(ctx5(t), chal("*.Example.test.", "val-1")))
	reqs := st.requests()
	require.Len(t, reqs, 1)
	r := reqs[0]
	assert.Equal(t, `{"action":"present","fqdn":"_acme-challenge.example.test","value":"val-1","ttl":120}`, r.Body)
	assert.Equal(t, "Bearer "+testSecret, r.Header.Get("Authorization"))
	assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
	assert.Equal(t, "alice-acme/1", r.Header.Get("User-Agent"))
	m := hmac.New(sha256.New, []byte(testSecret))
	m.Write([]byte(r.Body))
	assert.Equal(t, hex.EncodeToString(m.Sum(nil)), r.Header.Get("X-Alice-Signature"))
	assert.Equal(t, []string{solver.DNS01}, s.Types())
}

func TestSuccessStatusesAndRefusals(t *testing.T) {
	for _, tc := range []struct {
		code int
		ok   bool
	}{{200, true}, {204, true}, {201, false}, {301, false}, {401, false}, {403, false}, {404, false}, {500, false}, {503, false}} {
		st := newStub(t, func(int, rec) (int, string) { return tc.code, "DETAIL-" + testSecret + " leaks" })
		s := st.solver(t)
		err := s.Present(ctx5(t), chal("a.example.test", "v"))
		if tc.ok {
			require.NoError(t, err, tc.code)
			continue
		}
		require.Error(t, err, tc.code)
		assert.Equal(t, acme.ReasonHookRefused, reasonOf(err), tc.code)
		assertClean(t, err, st.URL)
		assertClean(t, s.CleanUp(ctx5(t), chal("a.example.test", "v")), st.URL)
	}
}

func assertClean(t *testing.T, err error, url string) {
	t.Helper()
	if err == nil {
		return
	}
	for _, bad := range []string{testSecret, "DETAIL", "leaks", "querysecret", "?token", url, "127.0.0.1", "Bearer"} {
		assert.NotContains(t, err.Error(), bad)
		assert.NotContains(t, fmt.Sprintf("%v %+v %#v", err, err, err), bad)
	}
}

func TestReadyPollingThenReady(t *testing.T) {
	st := newStub(t, func(n int, _ rec) (int, string) {
		if n < 4 {
			return 200, `{"ready":false}`
		}
		return 200, `{"ready":true}`
	})
	s := st.solver(t, func(c *Config) { c.PollInterval = time.Second; c.PropagationWait = 20 * time.Second })
	fc := withClock(s)
	require.NoError(t, s.Present(ctx5(t), chal("a.example.test", "v")))
	assert.Len(t, st.requests(), 4)
	assert.Equal(t, []time.Duration{time.Second, time.Second, time.Second}, fc.slept, "polls, no propagation wait once ready")
}

func TestNeverReady(t *testing.T) {
	st := newStub(t, func(int, rec) (int, string) { return 200, `{"ready":false}` })
	s := st.solver(t, func(c *Config) { c.PollInterval = time.Second; c.PollTimeout = 5 * time.Second })
	err := s.Present(ctx5(t), chal("a.example.test", "v"))
	require.Error(t, err)
	assert.Equal(t, acme.ReasonNotIssuedInTime, reasonOf(err))
	assert.Len(t, st.requests(), 6)
}

func TestNoReadyFieldWaitsPropagation(t *testing.T) {
	for _, body := range []string{"", "ok", `{"ok":true}`, `{"ready":"yes"}`, `[true]`, strings.Repeat("x", MaxReplyBytes+10), `{"ready":true,` + strings.Repeat(" ", MaxReplyBytes) + `}`} {
		st := newStub(t, func(int, rec) (int, string) { return 200, body })
		s := st.solver(t, func(c *Config) { c.PropagationWait = 7 * time.Second })
		fc := withClock(s)
		require.NoError(t, s.Present(ctx5(t), chal("a.example.test", "v")), body)
		assert.Equal(t, []time.Duration{7 * time.Second}, fc.slept, "reply %.20q", body)
		assert.Len(t, st.requests(), 1)
	}
}

func TestDefaultsAndLimits(t *testing.T) {
	base := Config{URL: "https://hook.example.test/x", Secret: secrets.NewPlaintext([]byte("k"))}
	s, err := New(base)
	require.NoError(t, err)
	assert.Equal(t, DefaultPropagationWait, s.wait)
	assert.Equal(t, DefaultPollTimeout, s.pollMax)
	assert.Equal(t, DefaultTTL, s.ttl)
	for name, mut := range map[string]func(*Config){
		"wait too long":  func(c *Config) { c.PropagationWait = 121 * time.Second },
		"poll too long":  func(c *Config) { c.PollTimeout = 101 * time.Second },
		"poll negative":  func(c *Config) { c.PollTimeout = -1 },
		"step too small": func(c *Config) { c.PollInterval = 499 * time.Millisecond },
		"step too big":   func(c *Config) { c.PollInterval = time.Minute },
		"ttl big":        func(c *Config) { c.TTL = 86401 },
		"ttl negative":   func(c *Config) { c.TTL = -1 },
		"bad suffix":     func(c *Config) { c.AllowedSuffixes = []string{"*.example.test"} },
		"empty suffix":   func(c *Config) { c.AllowedSuffixes = []string{""} },
		"bad ca":         func(c *Config) { c.CABundlePEM = "not pem" },
	} {
		c := base
		mut(&c)
		_, err := New(c)
		assert.Error(t, err, name)
	}
	c := base
	c.PropagationWait = 120 * time.Second
	c.PollTimeout = MaxPollTimeout
	_, err = New(c)
	assert.NoError(t, err)
}

func TestNewRejectsBadURLsAndSecrets(t *testing.T) {
	sec := secrets.NewPlaintext([]byte("k"))
	for _, u := range []string{"http://hook.example.test/x", "https://user:pw@hook.example.test/x", "https://user@hook.example.test/x",
		"https:///x", "ftp://h/x", "", "://", "https://hook.example.test/x#frag", "hook.example.test"} {
		_, err := New(Config{URL: u, Secret: sec})
		require.ErrorIs(t, err, ErrURL, u)
		assert.NotContains(t, err.Error(), "pw")
	}
	_, err := New(Config{URL: "https://hook.example.test/x"})
	assert.ErrorIs(t, err, ErrSecret)
	_, err = New(Config{URL: "https://hook.example.test/x", Secret: secrets.NewPlaintext(nil)})
	assert.ErrorIs(t, err, ErrSecret)
}

func TestNameAllowListNeverDials(t *testing.T) {
	st := newStub(t, ok)
	s := st.solver(t, func(c *Config) { c.AllowedSuffixes = []string{"example.test", ".sub.corp.test"} })
	for _, d := range []string{"evil.test", "notexample.test", "example.test.evil.test", "corp.test", "sub.corp.test", "bad name.example.test", "", "a..example.test", "*.evil.test"} {
		for name, f := range map[string]func(context.Context, solver.Challenge) error{"present": s.Present, "cleanup": s.CleanUp} {
			err := f(ctx5(t), solver.Challenge{Type: solver.DNS01, Domain: strings.TrimPrefix(d, "*."), DNSValue: "v"})
			require.Error(t, err, "%s %q", name, d)
			assert.Equal(t, acme.ReasonNameNotAllowed, reasonOf(err), "%s %q", name, d)
		}
	}
	assert.Zero(t, st.conns.Load(), "no connection was opened")
	assert.Empty(t, st.requests())
	// allowed forms
	for _, d := range []string{"example.test", "a.b.example.test", "x.sub.corp.test", "*.example.test"} {
		require.NoError(t, s.Present(ctx5(t), chal(d, "v")), d)
	}
	assert.Len(t, st.requests(), 4)
}

func TestEmptyAllowListRefusesAll(t *testing.T) {
	st := newStub(t, ok)
	s := st.solver(t, func(c *Config) { c.AllowedSuffixes = nil })
	err := s.Present(ctx5(t), chal("example.test", "v"))
	assert.Equal(t, acme.ReasonNameNotAllowed, reasonOf(err))
	assert.Zero(t, st.conns.Load())
}

func TestBadChallengesAreRefusedLocally(t *testing.T) {
	st := newStub(t, ok)
	s := st.solver(t)
	for _, ch := range []solver.Challenge{
		{Type: solver.HTTP01, Domain: "a.example.test", DNSValue: "v"},
		{Type: solver.DNS01, Domain: "a.example.test"},
		{Type: solver.DNS01, Domain: "a.example.test", DNSValue: strings.Repeat("v", 513)},
		{Type: solver.DNS01, Domain: "a.example.test", DNSValue: "has space"},
		{Type: solver.DNS01, Domain: "a.example.test", DNSValue: "v", DNSName: "_acme-challenge.other.example.test"},
	} {
		assert.Equal(t, acme.ReasonHookRefused, reasonOf(s.Present(ctx5(t), ch)))
		assert.Equal(t, acme.ReasonHookRefused, reasonOf(s.CleanUp(ctx5(t), ch)))
	}
	assert.Zero(t, st.conns.Load())
}

func TestNoSecretInPrintsOrErrors(t *testing.T) {
	st := newStub(t, ok)
	s := st.solver(t)
	cfg := Config{URL: st.URL + "/hook?token=querysecret", Secret: secrets.NewPlaintext([]byte(testSecret)), CABundlePEM: "x"}
	for _, v := range []any{s, *s, cfg, &cfg} {
		for _, f := range []string{"%v", "%+v", "%#v", "%s"} {
			out := fmt.Sprintf(f, v)
			assert.NotContains(t, out, testSecret)
			assert.NotContains(t, out, "querysecret")
		}
	}
	assert.Contains(t, fmt.Sprintf("%v", s), "127.0.0.1")
	// unreachable hook: the error holds neither the URL nor the secret
	dead := newStub(t, ok)
	ds := dead.solver(t)
	dead.Close()
	err := ds.Present(ctx5(t), chal("a.example.test", "v"))
	require.Error(t, err)
	assert.Equal(t, acme.ReasonHookRefused, reasonOf(err))
	assertClean(t, err, dead.URL)
	// unknown CA
	other := newStub(t, ok)
	us, err := New(Config{URL: other.URL, Secret: secrets.NewPlaintext([]byte(testSecret)), PropagationWait: -1, AllowedSuffixes: []string{"example.test"}})
	require.NoError(t, err)
	err = us.Present(ctx5(t), chal("a.example.test", "v"))
	assert.Equal(t, acme.ReasonHookRefused, reasonOf(err))
	assertClean(t, err, other.URL)
}

func TestCABundleHonoured(t *testing.T) {
	st := newStub(t, ok)
	good := st.solver(t)
	require.NoError(t, good.Present(ctx5(t), chal("a.example.test", "v")))
	// no bundle: the self-signed server is not trusted
	s, err := New(Config{URL: st.URL, Secret: secrets.NewPlaintext([]byte(testSecret)), PropagationWait: -1, AllowedSuffixes: []string{"example.test"}})
	require.NoError(t, err)
	assert.Equal(t, acme.ReasonHookRefused, reasonOf(s.Present(ctx5(t), chal("a.example.test", "v"))))
	// BaseRoots (the e2e build's fake CA) is trusted instead of the system roots.
	base := x509.NewCertPool()
	base.AddCert(st.Certificate())
	s, err = New(Config{URL: st.URL, Secret: secrets.NewPlaintext([]byte(testSecret)), PropagationWait: -1, AllowedSuffixes: []string{"example.test"},
		BaseRoots: base})
	require.NoError(t, err)
	require.NoError(t, s.Present(ctx5(t), chal("a.example.test", "v")))
}

func TestContextDeadlineAndCleanupContext(t *testing.T) {
	block := make(chan struct{})
	st := newStub(t, func(int, rec) (int, string) { <-block; return 200, "" })
	t.Cleanup(func() { close(block) })
	s := st.solver(t)
	c, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	err := s.Present(c, chal("a.example.test", "v"))
	require.ErrorIs(t, err, context.DeadlineExceeded)
	assertClean(t, err, st.URL)

	// CleanUp ignores the caller's cancelled context
	st2 := newStub(t, ok)
	s2 := st2.solver(t)
	dead, cancel2 := context.WithCancel(context.Background())
	cancel2()
	require.NoError(t, s2.CleanUp(dead, chal("a.example.test", "v")))
	assert.Len(t, st2.requests(), 1)
	assert.Contains(t, st2.requests()[0].Body, `"action":"cleanup"`)

	// Present with a dead context while waiting
	st3 := newStub(t, ok)
	s3 := st3.solver(t, func(c *Config) { c.PropagationWait = time.Second })
	s3.sleep = sleepCtx
	short, cancel3 := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel3()
	assert.ErrorIs(t, s3.Present(short, chal("a.example.test", "v")), context.DeadlineExceeded)
}

func TestCleanUpAfterPresentFailureAndIdempotentPresent(t *testing.T) {
	st := newStub(t, func(n int, _ rec) (int, string) {
		if n == 1 {
			return 500, ""
		}
		return 200, ""
	})
	s := st.solver(t)
	ch := chal("a.example.test", "v")
	require.Error(t, s.Present(ctx5(t), ch))
	require.NoError(t, s.CleanUp(ctx5(t), ch))
	require.NoError(t, s.Present(ctx5(t), ch))
	require.NoError(t, s.Present(ctx5(t), ch))
}

func TestCleanUpError(t *testing.T) {
	st := newStub(t, func(int, rec) (int, string) { return 502, "x" })
	s := st.solver(t)
	err := s.CleanUp(ctx5(t), chal("a.example.test", "v"))
	assert.Equal(t, acme.ReasonHookRefused, reasonOf(err))
}

// ---- against the real fake CA hook receiver ----

func startFake(t *testing.T) *fakeacme.Server {
	t.Helper()
	f, err := fakeacme.New(fakeacme.Options{})
	require.NoError(t, err)
	require.NoError(t, f.Start())
	t.Cleanup(f.Close)
	return f
}

func fakeSolver(t *testing.T, f *fakeacme.Server, mut ...func(*Config)) *Solver {
	t.Helper()
	cr := f.Credentials()
	cfg := Config{URL: cr.HookURL, Secret: secrets.NewPlaintext([]byte(cr.HookSecret)), CABundlePEM: string(f.CAPEM()),
		PropagationWait: -1, AllowedSuffixes: []string{"example.test"}}
	for _, m := range mut {
		m(&cfg)
	}
	s, err := New(cfg)
	require.NoError(t, err)
	return s
}

func TestAgainstFakeHookSharedName(t *testing.T) {
	f := startFake(t)
	s := fakeSolver(t, f)
	wild, base := chal("*.example.test", "wild-value"), chal("example.test", "base-value")
	require.NoError(t, s.Present(ctx5(t), wild))
	require.NoError(t, s.Present(ctx5(t), base))
	require.NoError(t, s.Present(ctx5(t), base), "idempotent")
	assert.ElementsMatch(t, []string{"wild-value", "base-value"}, f.DNSRecords()["_acme-challenge.example.test"])
	require.NoError(t, s.CleanUp(ctx5(t), wild))
	assert.Equal(t, []string{"base-value"}, f.DNSRecords()["_acme-challenge.example.test"], "only the exact value is removed")
	require.NoError(t, s.CleanUp(ctx5(t), base))
	assert.Empty(t, f.DNSRecords())
	assert.Equal(t, 3, f.Counters()["hook-present"])
	assert.Equal(t, 2, f.Counters()["hook-cleanup"])
}

func TestAgainstFakeHookWrongSecret(t *testing.T) {
	f := startFake(t)
	s := fakeSolver(t, f, func(c *Config) { c.Secret = secrets.NewPlaintext([]byte("wrong-secret")) })
	err := s.Present(ctx5(t), chal("example.test", "v"))
	require.Error(t, err)
	assert.Equal(t, acme.ReasonHookRefused, reasonOf(err))
	assert.NotContains(t, err.Error(), "wrong-secret")
	assert.NotContains(t, err.Error(), "bearer", "the hook's answer text is not copied")
	assert.Empty(t, f.DNSRecords())
}

func TestEndToEndOrderThroughFakeCA(t *testing.T) {
	f := startFake(t)
	hs := fakeSolver(t, f)
	cl := registeredClient(t, f)
	der, _ := csrFor(t, "*.example.test", "example.test")
	var presented, cleaned []string
	chain, err := cl.Order(ctx5(t), []string{"*.example.test", "example.test"}, der, hs,
		acme.WithOnPresent(func(c solver.Challenge) error { presented = append(presented, c.DNSValue); return nil }),
		acme.WithOnCleanUp(func(c solver.Challenge, _ error) { cleaned = append(cleaned, c.DNSValue) }))
	require.NoError(t, err)
	assert.NotEmpty(t, chain)
	assert.Len(t, presented, 2)
	assert.Len(t, cleaned, 2)
	assert.Empty(t, f.DNSRecords(), "everything was cleaned up through the hook")
	assert.GreaterOrEqual(t, f.Counters()["hook-present"], 2)
	assert.GreaterOrEqual(t, f.Counters()["hook-cleanup"], 2)
}

func TestEndToEndNameNotAllowedAndHookRefusal(t *testing.T) {
	f := startFake(t)
	cl := registeredClient(t, f)
	der, _ := csrFor(t, "example.test")
	_, err := cl.Order(ctx5(t), []string{"example.test"}, der, fakeSolver(t, f, func(c *Config) { c.AllowedSuffixes = []string{"other.test"} }))
	require.Error(t, err)
	assert.Equal(t, acme.ReasonNameNotAllowed, acme.ReasonOf(err))
	assert.Zero(t, f.Counters()["hook-present"])

	_, err = cl.Order(ctx5(t), []string{"example.test"}, der, fakeSolver(t, f, func(c *Config) { c.Secret = secrets.NewPlaintext([]byte("nope")) }))
	require.Error(t, err)
	assert.Equal(t, acme.ReasonHookRefused, acme.ReasonOf(err))
}

func TestParseHookReply(t *testing.T) {
	for in, want := range map[string][2]bool{`{"ready":true}`: {true, true}, `{"ready":false}`: {false, true}, ` {"ready":true,"x":1} `: {true, true},
		`{}`: {false, false}, `{"ready":1}`: {false, false}, `null`: {false, false}, ``: {false, false}, `{"ready":true`: {false, false}} {
		r, k := parseHookReply([]byte(in))
		assert.Equal(t, want, [2]bool{r, k}, in)
	}
}

func FuzzParseHookReply(f *testing.F) {
	for _, s := range []string{`{"ready":true}`, `{"ready":false}`, `{}`, `[]`, `null`, `{"ready":"true"}`, "", `{"ready":true}x`} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		ready, known := parseHookReply(b)
		if !known {
			require.False(t, ready)
			return
		}
		var v map[string]json.RawMessage
		require.NoError(t, json.Unmarshal(b, &v), "known only for a JSON object")
		require.Contains(t, []string{"true", "false"}, strings.TrimSpace(string(v["ready"])))
	})
}

func TestSecretValidation(t *testing.T) {
	for _, k := range []string{"a\nb", "a\rb", "a\x00b", "a\x7fb", "caf\xc3\xa9", "tab\tx"} {
		_, err := New(Config{URL: "https://hook.example.test/x", Secret: secrets.NewPlaintext([]byte(k))})
		assert.ErrorIs(t, err, ErrSecret, "%q", k)
	}
	_, err := New(Config{URL: "https://hook.example.test/x", Secret: secrets.NewPlaintext([]byte("a b~!"))})
	assert.NoError(t, err)
}

func TestAttemptCap(t *testing.T) {
	st := newStub(t, func(int, rec) (int, string) { return 200, `{"ready":false}` })
	s := st.solver(t, func(c *Config) { c.PollInterval = MinPollInterval; c.PollTimeout = MaxPollTimeout })
	err := s.Present(ctx5(t), chal("a.example.test", "v"))
	assert.Equal(t, acme.ReasonNotIssuedInTime, reasonOf(err))
	assert.Len(t, st.requests(), MaxPresentAttempts, "a hook cannot be hit more than the cap")
}

func TestNotReadyThenSilentStillWaits(t *testing.T) {
	st := newStub(t, func(n int, _ rec) (int, string) {
		if n == 1 {
			return 200, `{"ready":false}`
		}
		return 204, ""
	})
	s := st.solver(t, func(c *Config) { c.PollInterval = time.Second; c.PropagationWait = 9 * time.Second })
	fc := withClock(s)
	require.NoError(t, s.Present(ctx5(t), chal("a.example.test", "v")))
	assert.Equal(t, []time.Duration{time.Second, 9 * time.Second}, fc.slept)
}

func TestRedirectNotFollowed(t *testing.T) {
	target := newStub(t, ok)
	hook := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", target.URL+"/x")
		w.WriteHeader(http.StatusTemporaryRedirect)
	}))
	t.Cleanup(hook.Close)
	s, err := New(Config{URL: hook.URL, Secret: secrets.NewPlaintext([]byte(testSecret)), CABundlePEM: pemOf(hook), PropagationWait: -1,
		AllowedSuffixes: []string{"example.test"}})
	require.NoError(t, err)
	err = s.Present(ctx5(t), chal("a.example.test", "v"))
	assert.Equal(t, acme.ReasonHookRefused, reasonOf(err))
	assert.Empty(t, target.requests())
	assert.Zero(t, target.conns.Load())
}

func TestPollBoundBelowClientCallTimeout(t *testing.T) {
	assert.Less(t, MaxPollTimeout, acme.DefaultCallTimeout)
}
