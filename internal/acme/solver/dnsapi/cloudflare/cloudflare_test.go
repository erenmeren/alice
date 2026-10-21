package cloudflare_test

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/acme"
	"alice/internal/acme/solver"
	"alice/internal/acme/solver/dnsapi"
	"alice/internal/acme/solver/dnsapi/cloudflare"
	"alice/internal/secrets"
	fcf "alice/internal/testutil/fakecloudflare"
)

func ctx(t *testing.T) context.Context {
	t.Helper()
	c, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	return c
}

// randomWord is a run-time token-shaped string (no token literal is ever committed).
func randomWord(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func newFake(t *testing.T, o fcf.Options) *fcf.Server {
	t.Helper()
	if o.Token == "" {
		o.Token = randomWord(20)
	}
	return fcf.Start(t, o)
}

func providerFor(t *testing.T, f *fcf.Server, token ...string) *cloudflare.Provider {
	t.Helper()
	tok := f.Token()
	if len(token) > 0 {
		tok = token[0]
	}
	p, err := cloudflare.New(cloudflare.WithMapAddr(cloudflare.Config{APIToken: secrets.NewPlaintext([]byte(tok)), BaseRoots: f.CAPool()}, f.MapAddr))
	require.NoError(t, err)
	return p
}

func solverFor(t *testing.T, p dnsapi.Provider, mut ...func(*dnsapi.Config)) *dnsapi.Solver {
	t.Helper()
	cfg := dnsapi.Config{Provider: p, AllowedSuffixes: []string{"example.com", "example.test", "other.test"}, PropagationWait: -1}
	for _, m := range mut {
		m(&cfg)
	}
	s, err := dnsapi.New(cfg)
	require.NoError(t, err)
	return s
}

func chal(domain, value string) solver.Challenge {
	d := strings.TrimPrefix(domain, "*.")
	return solver.Challenge{Type: solver.DNS01, Domain: d, Wildcard: strings.HasPrefix(domain, "*."), Token: "tok",
		DNSName: solver.ChallengeLabel + d, DNSValue: value}
}

func zone(f *fcf.Server, name string) dnsapi.Zone { return dnsapi.Zone{Name: name, ID: f.ZoneID(name)} }

func TestNewValidatesTheToken(t *testing.T) {
	for name, tok := range map[string][]byte{
		"empty": nil, "short": []byte(strings.Repeat("a", cloudflare.MinTokenBytes-1)),
		"long": []byte(strings.Repeat("a", cloudflare.MaxTokenBytes+1)), "space": []byte(strings.Repeat("a", 20) + " b"),
		"control": []byte(strings.Repeat("a", 20) + "\n"), "non-ascii": []byte(strings.Repeat("a", 20) + "\xc3\xa7"),
	} {
		_, err := cloudflare.New(cloudflare.Config{APIToken: secrets.NewPlaintext(tok)})
		assert.ErrorIs(t, err, cloudflare.ErrToken, name)
	}
	for _, n := range []int{cloudflare.MinTokenBytes, cloudflare.MaxTokenBytes} {
		p, err := cloudflare.New(cloudflare.Config{APIToken: secrets.NewPlaintext([]byte(strings.Repeat("a", n)))})
		require.NoError(t, err)
		assert.Equal(t, dnsapi.KindCloudflare, p.Kind())
		done, err := p.ChangeDone(ctx(t), "")
		assert.True(t, done)
		assert.NoError(t, err)
	}
	// A mapping without roots would trust the system roots for a fake: refused.
	_, err := cloudflare.New(cloudflare.WithMapAddr(cloudflare.Config{APIToken: secrets.NewPlaintext([]byte(randomWord(20)))}, func(a string) string { return a }))
	assert.ErrorIs(t, err, cloudflare.ErrClient)
}

func TestNewCopiesTheToken(t *testing.T) {
	f := newFake(t, fcf.Options{Zones: []string{"example.com"}})
	b := []byte(f.Token())
	p, err := cloudflare.New(cloudflare.WithMapAddr(cloudflare.Config{APIToken: secrets.NewPlaintext(b), BaseRoots: f.CAPool()}, f.MapAddr))
	require.NoError(t, err)
	clear(b) // the caller zeroes its own copy
	_, err = p.FindZone(ctx(t), "_acme-challenge.example.com")
	require.NoError(t, err)
}

func TestPresentAndCleanUpKeepOtherValues(t *testing.T) {
	f := newFake(t, fcf.Options{Zones: []string{"example.com"}})
	f.AddRecord("example.com", "TXT", "_acme-challenge.example.com", `"someone-else"`, 300)
	f.AddRecord("example.com", "A", "www.example.com", "192.0.2.1", 300)
	s := solverFor(t, providerFor(t, f))
	wild, base := chal("*.example.com", "wild-value"), chal("example.com", "base-value")
	require.NoError(t, s.Present(ctx(t), wild))
	require.NoError(t, s.Present(ctx(t), base))
	require.NoError(t, s.Present(ctx(t), base), "an identical record is success")
	assert.Equal(t, []string{"base-value", "someone-else", "wild-value"}, f.TXT("_acme-challenge.example.com"))
	for _, r := range f.Records() {
		if r.Type == "TXT" && r.Content != `"someone-else"` {
			assert.Contains(t, []string{`"wild-value"`, `"base-value"`}, r.Content, "the content is one quoted string")
			assert.Equal(t, dnsapi.DefaultTTL, r.TTL)
			assert.Equal(t, "_acme-challenge.example.com", r.Name)
		}
	}
	require.NoError(t, s.CleanUp(ctx(t), wild))
	assert.Equal(t, []string{"base-value", "someone-else"}, f.TXT("_acme-challenge.example.com"), "only the exact value goes")
	require.NoError(t, s.CleanUp(ctx(t), base))
	require.NoError(t, s.CleanUp(ctx(t), base), "a value that is gone is success")
	assert.Equal(t, []string{"someone-else"}, f.TXT("_acme-challenge.example.com"))
	assert.Len(t, f.Records(), 2)
	c := f.Counters()
	// One lookup per candidate (_acme-challenge.example.com, then example.com), once per name: the solver caches it.
	assert.Equal(t, 2, c[fcf.OpZones])
	assert.Equal(t, 3, c[fcf.OpCreate])
	assert.Equal(t, 3, c[fcf.OpList])
	assert.Equal(t, 2, c[fcf.OpDelete])
}

func TestLongestZoneWins(t *testing.T) {
	f := newFake(t, fcf.Options{Zones: []string{"example.com", "sub.example.com", "_acme-challenge.deleg.example.com"}})
	p := providerFor(t, f)
	for fqdn, want := range map[string]string{
		"_acme-challenge.a.sub.example.com": "sub.example.com",
		"_acme-challenge.sub.example.com":   "sub.example.com",
		"_acme-challenge.b.example.com":     "example.com",
		"_acme-challenge.deleg.example.com": "_acme-challenge.deleg.example.com",
	} {
		z, err := p.FindZone(ctx(t), fqdn)
		require.NoError(t, err, fqdn)
		assert.Equal(t, zone(f, want), z, fqdn)
	}
	s := solverFor(t, p)
	require.NoError(t, s.Present(ctx(t), chal("a.sub.example.com", "v")))
	recs := f.Records()
	require.Len(t, recs, 1)
	assert.Equal(t, f.ZoneID("sub.example.com"), recs[0].ZoneID)
}

func TestZoneNotFound(t *testing.T) {
	f := newFake(t, fcf.Options{Zones: []string{"example.com", "other.test"}, TokenZones: []string{"example.com"}})
	s := solverFor(t, providerFor(t, f))
	for _, d := range []string{"example.test", "other.test"} {
		err := s.Present(ctx(t), chal("a."+d, "v"))
		require.Error(t, err, d)
		assert.Equal(t, acme.ReasonDNSZoneNotFound, acme.ReasonOf(err), d)
		assert.Equal(t, acme.ClassPermanent, acme.FailureClass(err), d)
		assert.Contains(t, err.Error(), "a."+d)
	}
	assert.Empty(t, f.Records())
	// a.example.test: 2 candidates (a.example.test, example.test) after the fqdn itself.
	assert.Equal(t, 6, f.Counters()[fcf.OpZones])
}

func TestZoneOutsideTheTokenIsAuthFailed(t *testing.T) {
	f := newFake(t, fcf.Options{Zones: []string{"example.com", "other.test"}, TokenZones: []string{"example.com"}})
	p := providerFor(t, f)
	_, err := p.AddTXT(ctx(t), zone(f, "other.test"), "_acme-challenge.other.test", "v", 60)
	assert.Equal(t, acme.ReasonDNSAuthFailed, acme.ReasonOf(err))
	err = p.RemoveTXT(ctx(t), zone(f, "other.test"), "_acme-challenge.other.test", "v")
	assert.Equal(t, acme.ReasonDNSAuthFailed, acme.ReasonOf(err))
}

func TestWrongToken(t *testing.T) {
	f := newFake(t, fcf.Options{Zones: []string{"example.com"}})
	wrong := randomWord(20)
	s := solverFor(t, providerFor(t, f, wrong))
	err := s.Present(ctx(t), chal("example.com", "v"))
	require.Error(t, err)
	assert.Equal(t, acme.ReasonDNSAuthFailed, acme.ReasonOf(err))
	assert.Equal(t, acme.ClassPermanent, acme.FailureClass(err))
	assertClean(t, err, wrong)
	assert.Empty(t, f.Records())
}

// TestAnswersAreClassified drives every op through every kind of failure: the reason and the class follow the
// status (a dead connection, a 408, a 429 and a 5xx are outages; any other refusal is a setting) and Cloudflare's
// auth codes in a 400 read as a refused credential.
func TestAnswersAreClassified(t *testing.T) {
	huge := `{"success":true,"errors":[],"result":[],"pad":"` + strings.Repeat("x", dnsapi.MaxResponseBytes) + `"}`
	for _, tc := range []struct {
		name   string
		fault  fcf.Fault
		reason string
		class  string
	}{
		{"reset", fcf.Fault{Reset: true}, acme.ReasonDNSProviderError, acme.ClassTransient},
		{"408", fcf.Fault{Status: 408}, acme.ReasonDNSProviderError, acme.ClassTransient},
		{"429", fcf.Fault{Status: 429, Code: 971}, acme.ReasonDNSProviderError, acme.ClassTransient},
		{"500", fcf.Fault{Status: 500}, acme.ReasonDNSProviderError, acme.ClassTransient},
		{"503 with a body", fcf.Fault{Status: 503, Body: "<html>down</html>"}, acme.ReasonDNSProviderError, acme.ClassTransient},
		{"400", fcf.Fault{Status: 400, Code: 1004}, acme.ReasonDNSProviderError, acme.ClassPermanent},
		{"404", fcf.Fault{Status: 404, Code: 7003}, acme.ReasonDNSProviderError, acme.ClassPermanent},
		{"400 auth 9109", fcf.Fault{Status: 400, Code: 9109}, acme.ReasonDNSAuthFailed, acme.ClassPermanent},
		{"400 auth 6003 chain", fcf.Fault{Status: 400, Body: `{"success":false,"errors":[{"code":1,"error_chain":[{"code":6111}]}],"result":null}`}, acme.ReasonDNSAuthFailed, acme.ClassPermanent},
		{"401", fcf.Fault{Status: 401, Code: 10000}, acme.ReasonDNSAuthFailed, acme.ClassPermanent},
		{"403", fcf.Fault{Status: 403, Code: 10000}, acme.ReasonDNSAuthFailed, acme.ClassPermanent},
		{"redirect", fcf.Fault{Status: 302, Location: "https://elsewhere.test/", Body: `{"success":true,"errors":[],"result":[]}`}, acme.ReasonDNSProviderError, acme.ClassPermanent},
		{"not json", fcf.Fault{Status: 200, Body: "{not json"}, acme.ReasonDNSProviderError, acme.ClassPermanent},
		{"no success flag", fcf.Fault{Status: 200, Body: `{"result":[]}`}, acme.ReasonDNSProviderError, acme.ClassPermanent},
		{"success false", fcf.Fault{Status: 200, Body: `{"success":false,"errors":[{"code":1}],"result":[]}`}, acme.ReasonDNSProviderError, acme.ClassPermanent},
		{"bad result_info", fcf.Fault{Status: 200, Body: `{"success":true,"errors":[],"result":[],"result_info":"x"}`}, acme.ReasonDNSProviderError, acme.ClassPermanent},
		{"oversized", fcf.Fault{Status: 200, Body: huge}, acme.ReasonDNSProviderError, acme.ClassPermanent},
	} {
		for _, op := range []string{fcf.OpZones, fcf.OpCreate, fcf.OpList, fcf.OpDelete} {
			if op == fcf.OpDelete && tc.fault.Status == 404 {
				continue // a record that is gone already: TestDeleteOfAGoneRecordIsSuccess
			}
			f := newFake(t, fcf.Options{Zones: []string{"example.com"}})
			p := providerFor(t, f)
			s := solverFor(t, p)
			ch := chal("example.com", "v")
			if op == fcf.OpList || op == fcf.OpDelete {
				require.NoError(t, s.Present(ctx(t), ch))
			}
			f.FailNext(op, tc.fault)
			var err error
			if op == fcf.OpList || op == fcf.OpDelete {
				err = s.CleanUp(ctx(t), ch)
			} else {
				err = s.Present(ctx(t), ch)
			}
			require.Error(t, err, tc.name+" "+op)
			assert.Equal(t, tc.reason, acme.ReasonOf(err), tc.name+" "+op)
			assert.Equal(t, tc.class, acme.FailureClass(err), tc.name+" "+op)
			assertClean(t, err, f.Token(), "down", "elsewhere")
		}
	}
}

func TestResultShapeErrors(t *testing.T) {
	f := newFake(t, fcf.Options{Zones: []string{"example.com"}})
	p := providerFor(t, f)
	f.FailNext(fcf.OpZones, fcf.Fault{Body: `{"success":true,"errors":[],"result":{"id":"x"}}`})
	_, err := p.FindZone(ctx(t), "_acme-challenge.example.com")
	assert.Equal(t, acme.ReasonDNSProviderError, acme.ReasonOf(err))
	assert.Equal(t, "example.com", identifier(err))
}

func TestInvalidIDsAreRefused(t *testing.T) {
	f := newFake(t, fcf.Options{Zones: []string{"example.com"}})
	p := providerFor(t, f)
	for _, id := range []string{"../../accounts", strings.Repeat("A", 32), strings.Repeat("a", 31), "", strings.Repeat("g", 32)} {
		f.FailNext(fcf.OpZones, fcf.Fault{Body: `{"success":true,"errors":[],"result":[{"id":"` + id + `","name":"example.com","status":"active"}]}`})
		f.FailNext(fcf.OpZones, fcf.Fault{Body: `{"success":true,"errors":[],"result":[{"id":"` + id + `","name":"example.com","status":"active"}]}`})
		_, err := p.FindZone(ctx(t), "_acme-challenge.example.com")
		assert.Equal(t, acme.ReasonDNSZoneNotFound, acme.ReasonOf(err), id)
	}
	// A zone of another name, or one that is not active, is not the candidate's zone.
	for _, body := range []string{
		`{"success":true,"errors":[],"result":[{"id":"` + f.ZoneID("example.com") + `","name":"evil.com","status":"active"}]}`,
		`{"success":true,"errors":[],"result":[{"id":"` + f.ZoneID("example.com") + `","name":"example.com","status":"pending"}]}`,
		`{"success":true,"errors":[],"result":[{"id":"` + f.ZoneID("example.com") + `","name":"*.example.com","status":"active"}]}`,
	} {
		f.FailNext(fcf.OpZones, fcf.Fault{Body: body})
		f.FailNext(fcf.OpZones, fcf.Fault{Body: body})
		_, err := p.FindZone(ctx(t), "_acme-challenge.example.com")
		assert.Equal(t, acme.ReasonDNSZoneNotFound, acme.ReasonOf(err), body)
	}
	// A record listing whose matching record has a bad ID is refused (it would go into the DELETE path).
	f.FailNext(fcf.OpList, fcf.Fault{Body: `{"success":true,"errors":[],"result":[{"id":"../x","type":"TXT","name":"_acme-challenge.example.com","content":"\"v\""}]}`})
	err := p.RemoveTXT(ctx(t), zone(f, "example.com"), "_acme-challenge.example.com", "v")
	assert.Equal(t, acme.ReasonDNSProviderError, acme.ReasonOf(err))
	assert.Zero(t, f.Counters()[fcf.OpDelete])
	// A record of another name or type in the answer is left alone, whatever its ID.
	f.FailNext(fcf.OpList, fcf.Fault{Body: `{"success":true,"errors":[],"result":[{"id":"../x","type":"A","name":"_acme-challenge.example.com","content":"v"},` +
		`{"id":"../y","type":"TXT","name":"other.example.com","content":"v"}]}`})
	require.NoError(t, p.RemoveTXT(ctx(t), zone(f, "example.com"), "_acme-challenge.example.com", "v"))
	// A zone handle that is not an ID never reaches a URL.
	before := len(f.Requests())
	_, err = p.AddTXT(ctx(t), dnsapi.Zone{Name: "example.com", ID: "../x"}, "_acme-challenge.example.com", "v", 60)
	assert.Equal(t, acme.ReasonDNSProviderError, acme.ReasonOf(err))
	err = p.RemoveTXT(ctx(t), dnsapi.Zone{Name: "example.com", ID: "../x"}, "_acme-challenge.example.com", "v")
	assert.Equal(t, acme.ReasonDNSProviderError, acme.ReasonOf(err))
	assert.Len(t, f.Requests(), before)
}

func TestTTL(t *testing.T) {
	f := newFake(t, fcf.Options{Zones: []string{"example.com"}})
	p := providerFor(t, f)
	for i, tc := range [][2]int{{1, 60}, {30, 60}, {59, 60}, {60, 60}, {300, 300}} {
		v := "v" + strconv.Itoa(i)
		_, err := p.AddTXT(ctx(t), zone(f, "example.com"), "_acme-challenge.example.com", v, tc[0])
		require.NoError(t, err)
		for _, r := range f.Records() {
			if r.Content == `"`+v+`"` {
				assert.Equal(t, tc[1], r.TTL, tc[0])
			}
		}
	}
	// Through the solver: its lowest TTL (30) is raised to Cloudflare's minimum.
	s := solverFor(t, p, func(c *dnsapi.Config) { c.TTL = dnsapi.MinTTL })
	require.NoError(t, s.Present(ctx(t), chal("a.example.com", "w")))
	recs := f.Records()
	assert.Equal(t, cloudflare.MinTTL, recs[len(recs)-1].TTL)
}

func TestRemoveFollowsPagesAndUnquotedValues(t *testing.T) {
	f := newFake(t, fcf.Options{Zones: []string{"example.com"}})
	p := providerFor(t, f)
	name := "_acme-challenge.example.com"
	for i := range 250 {
		f.AddRecord("example.com", "TXT", name, `"filler-`+strconv.Itoa(i)+`"`, 60)
	}
	f.AddRecord("example.com", "TXT", name, "target", 60)   // unquoted, page 3
	f.AddRecord("example.com", "TXT", name, `"target"`, 60) // quoted (another tool's record)
	require.NoError(t, p.RemoveTXT(ctx(t), zone(f, "example.com"), name, "target"))
	assert.Len(t, f.Records(), 250)
	assert.NotContains(t, f.TXT(name), "target")
	assert.Equal(t, 3, f.Counters()[fcf.OpList])
	assert.Equal(t, 2, f.Counters()[fcf.OpDelete])

	// Beyond MaxRecordPages pages the listing stops: a value there stays (documented limit).
	for i := 250; i < 100*cloudflare.MaxRecordPages; i++ {
		f.AddRecord("example.com", "TXT", name, `"filler-`+strconv.Itoa(i)+`"`, 60)
	}
	f.AddRecord("example.com", "TXT", name, `"late"`, 60)
	require.NoError(t, p.RemoveTXT(ctx(t), zone(f, "example.com"), name, "late"))
	assert.Contains(t, f.TXT(name), "late")
	assert.Equal(t, 3+cloudflare.MaxRecordPages, f.Counters()[fcf.OpList])
}

func TestDeleteOfAGoneRecordIsSuccess(t *testing.T) {
	f := newFake(t, fcf.Options{Zones: []string{"example.com"}})
	p := providerFor(t, f)
	s := solverFor(t, p)
	ch := chal("example.com", "v")
	require.NoError(t, s.Present(ctx(t), ch))
	f.FailNext(fcf.OpDelete, fcf.Fault{Status: 404, Code: 81044})
	require.NoError(t, s.CleanUp(ctx(t), ch))
	// A cleanup with nothing there sends no delete.
	f2 := newFake(t, fcf.Options{Zones: []string{"example.com"}})
	require.NoError(t, solverFor(t, providerFor(t, f2)).CleanUp(ctx(t), ch))
	assert.Zero(t, f2.Counters()[fcf.OpDelete])
}

func TestIdenticalRecordCodes(t *testing.T) {
	f := newFake(t, fcf.Options{Zones: []string{"example.com"}})
	p := providerFor(t, f)
	for _, fault := range []fcf.Fault{
		{Status: 400, Code: 81058},
		{Status: 200, Body: `{"success":false,"errors":[{"code":81058}],"result":null}`},
	} {
		f.FailNext(fcf.OpCreate, fault)
		_, err := p.AddTXT(ctx(t), zone(f, "example.com"), "_acme-challenge.example.com", "v", 60)
		require.NoError(t, err)
	}
	// The code in another status is not the duplicate answer.
	f.FailNext(fcf.OpCreate, fcf.Fault{Status: 409, Code: 81058})
	_, err := p.AddTXT(ctx(t), zone(f, "example.com"), "_acme-challenge.example.com", "v", 60)
	assert.Equal(t, acme.ReasonDNSProviderError, acme.ReasonOf(err))
}

func TestDeadContextAndZero(t *testing.T) {
	f := newFake(t, fcf.Options{Zones: []string{"example.com"}})
	p := providerFor(t, f)
	s := solverFor(t, p)
	dead, cancel := context.WithCancel(context.Background())
	cancel()
	assert.ErrorIs(t, s.Present(dead, chal("example.com", "v")), context.Canceled)
	f.FailNext(fcf.OpZones, fcf.Fault{Delay: time.Minute})
	short, cancel2 := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel2()
	_, err := p.FindZone(short, "_acme-challenge.example.com")
	assert.ErrorIs(t, err, context.DeadlineExceeded)

	before := len(f.Requests())
	p.Zero()
	_, err = p.FindZone(ctx(t), "_acme-challenge.example.com")
	assert.Equal(t, acme.ReasonDNSProviderError, acme.ReasonOf(err))
	assert.Equal(t, acme.ClassPermanent, acme.FailureClass(err))
	assert.Len(t, f.Requests(), before, "nothing is sent after Zero")
}

// ---- secrets ----

func assertClean(t *testing.T, err error, words ...string) {
	t.Helper()
	for _, form := range []string{fmt.Sprintf("%v", err), fmt.Sprintf("%+v", err), fmt.Sprintf("%#v", err), err.Error()} {
		for _, w := range append(words, "cloudflare.com", "Bearer", "Authorization", "client/v4", "CANARY") {
			assert.NotContains(t, form, w)
		}
	}
}

func identifier(err error) string {
	var e *acme.Error
	if errors.As(err, &e) {
		return e.Identifier
	}
	return ""
}

func TestTokenNeverPrinted(t *testing.T) {
	f := newFake(t, fcf.Options{Zones: []string{"example.com"}})
	tok := f.Token()
	cfg := cloudflare.WithMapAddr(cloudflare.Config{APIToken: secrets.NewPlaintext([]byte(tok)), BaseRoots: f.CAPool()}, f.MapAddr)
	p, err := cloudflare.New(cfg)
	require.NoError(t, err)
	s := solverFor(t, p)
	for _, v := range []any{cfg, &cfg, p, s} {
		for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x"} {
			assert.NotContains(t, fmt.Sprintf(verb, v), tok, verb)
			assert.NotContains(t, fmt.Sprintf(verb, v), hex.EncodeToString([]byte(tok)), verb)
		}
	}
	assert.Equal(t, "cloudflare.Config{APIToken: redacted}", fmt.Sprintf("%#v", cfg))
	assert.Equal(t, "cloudflare.Provider{token: redacted}", p.String())
	assert.Equal(t, p.String(), p.GoString())
	assert.Equal(t, cfg.String(), cfg.GoString())
	require.NoError(t, s.Present(ctx(t), chal("example.com", "v")))
	require.NoError(t, s.CleanUp(ctx(t), chal("example.com", "v")))
	assert.NotContains(t, fmt.Sprintf("%#v", f.Requests()), tok, "the fake's log holds no token")
}

func TestCanaryInAnswersNeverReachesAnError(t *testing.T) {
	canary := "CANARY-" + randomWord(8)
	for _, status := range []int{200, 400, 401, 403, 404, 429, 500} {
		for _, op := range []string{fcf.OpZones, fcf.OpCreate, fcf.OpList, fcf.OpDelete} {
			if op == fcf.OpDelete && status == 404 {
				continue // success: the record is gone
			}
			f := newFake(t, fcf.Options{Zones: []string{"example.com"}})
			s := solverFor(t, providerFor(t, f))
			ch := chal("example.com", "v")
			if op == fcf.OpList || op == fcf.OpDelete {
				require.NoError(t, s.Present(ctx(t), ch))
			}
			body := `{"success":false,"errors":[{"code":1000,"message":"` + canary + ` ` + f.Token() + `"}],"messages":[{"code":1,"message":"` + canary + `"}],"result":"` + canary + `"}`
			f.FailNext(op, fcf.Fault{Status: status, Body: body})
			var err error
			if op == fcf.OpList || op == fcf.OpDelete {
				err = s.CleanUp(ctx(t), ch)
			} else {
				err = s.Present(ctx(t), ch)
			}
			require.Error(t, err)
			assertClean(t, err, canary, f.Token())
		}
	}
}
