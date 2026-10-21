package route53

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/acme"
	"alice/internal/acme/solver"
	"alice/internal/acme/solver/dnsapi"
	"alice/internal/secrets"
	"alice/internal/testutil/fakeroute53"
)

const (
	testRole       = "arn:aws:iam::123456789012:role/alice-dns"
	testExternalID = "alice-external-7"
)

func ctx30(t *testing.T) context.Context {
	t.Helper()
	c, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	return c
}

func startFake(t *testing.T, o fakeroute53.Options) *fakeroute53.Server {
	t.Helper()
	if o.Zones == nil {
		o.Zones = []fakeroute53.Zone{{Name: "example.test"}}
	}
	return fakeroute53.Start(t, o)
}

func newProvider(t *testing.T, f *fakeroute53.Server, mut ...func(*Config)) *Provider {
	t.Helper()
	cfg := fakeConfig(f)
	for _, m := range mut {
		m(&cfg)
	}
	p, err := New(cfg)
	require.NoError(t, err)
	return p
}

func withRole(c *Config) { c.RoleARN, c.ExternalID = testRole, testExternalID }

func newSolver(t *testing.T, p *Provider, suffixes ...string) *dnsapi.Solver {
	t.Helper()
	if len(suffixes) == 0 {
		suffixes = []string{"example.test"}
	}
	s, err := dnsapi.New(dnsapi.Config{Provider: p, AllowedSuffixes: suffixes, PropagationWait: -1, PollInterval: 500 * time.Millisecond})
	require.NoError(t, err)
	return s
}

func chal(domain, value string) solver.Challenge {
	return solver.Challenge{Type: solver.DNS01, Domain: domain, DNSValue: value}
}

func zoneOf(t *testing.T, f *fakeroute53.Server, name string) dnsapi.Zone {
	t.Helper()
	id := f.ZoneID(name, false)
	require.NotEmpty(t, id)
	return dnsapi.Zone{Name: name, ID: id}
}

func reasonOf(err error) string { return acme.ReasonOf(err) }

func statusOf(t *testing.T, err error) int {
	t.Helper()
	var ae *acme.Error
	require.ErrorAs(t, err, &ae)
	return ae.Status
}

// ---- configuration ----

func TestNewValidates(t *testing.T) {
	f := startFake(t, fakeroute53.Options{})
	good := fakeConfig(f)
	cases := []struct {
		name string
		mut  func(*Config)
		want error
	}{
		{"key id lower case", func(c *Config) { c.AccessKeyID = "fakeabcdefghijklmnop" }, ErrAccessKey},
		{"key id short", func(c *Config) { c.AccessKeyID = "FAKE0123" }, ErrAccessKey},
		{"key id empty", func(c *Config) { c.AccessKeyID = "" }, ErrAccessKey},
		{"secret empty", func(c *Config) { c.SecretAccessKey = secrets.Plaintext{} }, ErrSecretKey},
		{"secret short", func(c *Config) { c.SecretAccessKey = secrets.NewPlaintext([]byte("short")) }, ErrSecretKey},
		{"secret space", func(c *Config) { c.SecretAccessKey = secrets.NewPlaintext([]byte("abcdefgh ijklmnopqrst")) }, ErrSecretKey},
		{"secret non-ascii", func(c *Config) { c.SecretAccessKey = secrets.NewPlaintext([]byte("abcdefghijklmnopqrst\xc3\xa7")) }, ErrSecretKey},
		{"secret too long", func(c *Config) { c.SecretAccessKey = secrets.NewPlaintext([]byte(strings.Repeat("a", 129))) }, ErrSecretKey},
		{"role china partition", func(c *Config) { c.RoleARN = "arn:aws-cn:iam::123456789012:role/x" }, ErrRoleARN},
		{"role user", func(c *Config) { c.RoleARN = "arn:aws:iam::123456789012:user/x" }, ErrRoleARN},
		{"role account", func(c *Config) { c.RoleARN = "arn:aws:iam::12345:role/x" }, ErrRoleARN},
		{"role chars", func(c *Config) { c.RoleARN = "arn:aws:iam::123456789012:role/a b" }, ErrRoleARN},
		{"external id without role", func(c *Config) { c.ExternalID = "abc" }, ErrExternalID},
		{"external id short", func(c *Config) { c.RoleARN, c.ExternalID = testRole, "a" }, ErrExternalID},
		{"external id chars", func(c *Config) { c.RoleARN, c.ExternalID = testRole, "a b" }, ErrExternalID},
		{"external id too long", func(c *Config) { c.RoleARN, c.ExternalID = testRole, strings.Repeat("a", 1225) }, ErrExternalID},
		{"map without roots", func(c *Config) { c.BaseRoots = nil }, dnsapi.ErrMapNeedsRoots},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := good
			tc.mut(&cfg)
			p, err := New(cfg)
			assert.Nil(t, p)
			assert.ErrorIs(t, err, tc.want)
		})
	}
	ok := good
	ok.RoleARN, ok.ExternalID = "arn:aws:iam::123456789012:role/path/to/alice+dns=,.@_-", "a:b/c=d"
	_, err := New(ok)
	require.NoError(t, err)
	ok.ExternalID = strings.Repeat("a", 1224)
	_, err = New(ok)
	require.NoError(t, err, "the longest external ID")
	assert.Empty(t, f.Requests(), "New makes no network call")
}

func TestNewCopiesTheSecret(t *testing.T) {
	f := startFake(t, fakeroute53.Options{})
	raw := []byte(f.SecretAccessKey())
	cfg := fakeConfig(f)
	cfg.SecretAccessKey = secrets.NewPlaintext(raw)
	p, err := New(cfg)
	require.NoError(t, err)
	clear(raw)
	_, err = p.FindZone(ctx30(t), "_acme-challenge.example.test")
	require.NoError(t, err, "the provider signs with its own copy after the caller zeroed its secret")

	p.Zero()
	assert.Equal(t, make([]byte, len(raw)), p.secret.Bytes(), "Zero clears the provider's copy")
	_, err = p.FindZone(ctx30(t), "_acme-challenge.example.test")
	assert.Equal(t, acme.ReasonDNSAuthFailed, reasonOf(err))
}

func TestZeroClearsTemporaryCredentials(t *testing.T) {
	f := startFake(t, fakeroute53.Options{RoleARN: testRole, ExternalID: testExternalID})
	p := newProvider(t, f, withRole)
	_, err := p.FindZone(ctx30(t), "_acme-challenge.example.test")
	require.NoError(t, err)
	require.NotNil(t, p.temp)
	tmp := *p.temp
	p.Zero()
	assert.Nil(t, p.temp)
	assert.Equal(t, make([]byte, len(tmp.secret.Bytes())), tmp.secret.Bytes())
	assert.Equal(t, make([]byte, len(tmp.token.Bytes())), tmp.token.Bytes())
	p.Zero() // twice is harmless
}

func TestKind(t *testing.T) {
	f := startFake(t, fakeroute53.Options{})
	assert.Equal(t, dnsapi.KindRoute53, newProvider(t, f).Kind())
}

// ---- zones ----

func TestFindZoneLongestPublicZone(t *testing.T) {
	f := startFake(t, fakeroute53.Options{Zones: []fakeroute53.Zone{
		{Name: "example.test"}, {Name: "www.example.test"}, {Name: "sub.www.example.test", Private: true},
		{Name: "_acme-challenge.deleg.example.test"}, {Name: "other.test", Private: true},
	}})
	p := newProvider(t, f)
	z, err := p.FindZone(ctx30(t), "_acme-challenge.sub.www.example.test")
	require.NoError(t, err)
	assert.Equal(t, dnsapi.Zone{Name: "www.example.test", ID: f.ZoneID("www.example.test", false)}, z, "the private zone is skipped, the longest public zone wins")

	z, err = p.FindZone(ctx30(t), "_acme-challenge.deleg.example.test")
	require.NoError(t, err)
	assert.Equal(t, "_acme-challenge.deleg.example.test", z.Name, "a zone of the challenge label itself")

	z, err = p.FindZone(ctx30(t), "_acme-challenge.a.b.example.test")
	require.NoError(t, err)
	assert.Equal(t, "example.test", z.Name)

	_, err = p.FindZone(ctx30(t), "_acme-challenge.other.test")
	require.Error(t, err)
	assert.Equal(t, acme.ReasonDNSZoneNotFound, reasonOf(err), "a private zone only is no zone")
	assert.Contains(t, err.Error(), "other.test")
	assert.NotContains(t, err.Error(), "_acme-challenge")
}

func TestFindZonePublicAndPrivateOfOneName(t *testing.T) {
	f := startFake(t, fakeroute53.Options{Zones: []fakeroute53.Zone{{Name: "example.test", Private: true}, {Name: "example.test"}}})
	z, err := newProvider(t, f).FindZone(ctx30(t), "_acme-challenge.example.test")
	require.NoError(t, err)
	assert.Equal(t, f.ZoneID("example.test", false), z.ID)
}

func TestFindZoneRefusesBadAnswers(t *testing.T) {
	f := startFake(t, fakeroute53.Options{})
	p := newProvider(t, f)
	listing := func(id, name string) string {
		return `<?xml version="1.0"?><ListHostedZonesByNameResponse xmlns="` + apiNS + `"><HostedZones><HostedZone><Id>` + id +
			`</Id><Name>` + name + `</Name><Config><PrivateZone>false</PrivateZone></Config></HostedZone></HostedZones></ListHostedZonesByNameResponse>`
	}
	for name, body := range map[string]string{
		"id with a path":   listing("/hostedzone/Z1/../../x", "example.test."),
		"id lower case":    listing("/hostedzone/z1", "example.test."),
		"id without kind":  listing("Z1", "example.test."),
		"not xml":          "<html>proxy</html",
		"another document": `<GetChangeResponse><ChangeInfo><Id>/change/C1</Id></ChangeInfo></GetChangeResponse>`,
	} {
		t.Run(name, func(t *testing.T) {
			stop := f.FailAll(fakeroute53.OpZones, fakeroute53.Fault{Body: body}) // every candidate's lookup
			defer stop()
			_, err := p.FindZone(ctx30(t), "_acme-challenge.example.test")
			require.Error(t, err)
			assert.Equal(t, acme.ReasonDNSProviderError, reasonOf(err))
			assert.Equal(t, acme.ClassPermanent, acme.FailureClass(err))
		})
	}
	// A zone of another name (Route 53 lists from the name on) or with an invalid name is not taken.
	f.FailNext(fakeroute53.OpZones, fakeroute53.Fault{Body: listing("/hostedzone/Z1", "*.example.test.")})
	f.FailNext(fakeroute53.OpZones, fakeroute53.Fault{Body: listing("/hostedzone/Z1", "zzz.test.")})
	_, err := p.FindZone(ctx30(t), "_acme-challenge.www.example.test")
	require.NoError(t, err, "the third candidate, example.test, is answered by the fake itself")
}

// ---- records ----

func TestEndToEndPresentAndCleanUpWaitsForInsync(t *testing.T) {
	f := startFake(t, fakeroute53.Options{InsyncAfter: 1})
	s := newSolver(t, newProvider(t, f))
	wild, base := chal("example.test", "wild-value"), chal("example.test", "base-value")
	wild.Wildcard = true
	require.NoError(t, s.Present(ctx30(t), wild))
	require.NoError(t, s.Present(ctx30(t), base))
	ttl, values, ok := f.RecordSet("_acme-challenge.example.test")
	require.True(t, ok)
	assert.Equal(t, dnsapi.DefaultTTL, ttl)
	assert.ElementsMatch(t, []string{"wild-value", "base-value"}, values, "the UPSERT keeps the other value")
	assert.Equal(t, 4, f.Counters()[fakeroute53.OpGetChange], "each change answered PENDING once, then INSYNC")

	require.NoError(t, s.CleanUp(ctx30(t), wild))
	_, values, _ = f.RecordSet("_acme-challenge.example.test")
	assert.Equal(t, []string{"base-value"}, values, "only the exact value is removed")
	require.NoError(t, s.CleanUp(ctx30(t), base))
	_, _, ok = f.RecordSet("_acme-challenge.example.test")
	assert.False(t, ok, "the last value deletes the set")
	require.NoError(t, s.CleanUp(ctx30(t), base), "removing a value that is gone succeeds")
	assert.Equal(t, 4, f.Counters()[fakeroute53.OpGetChange], "clean-up never waits for INSYNC")
	assert.Equal(t, 2, f.Counters()[fakeroute53.OpZones], "the zone is looked up once per name (two candidates)")
}

func TestAddTXTIsIdempotentAndKeepsForeignValues(t *testing.T) {
	f := startFake(t, fakeroute53.Options{})
	p := newProvider(t, f)
	z := zoneOf(t, f, "example.test")
	const fqdn = "_acme-challenge.example.test"
	require.True(t, f.SetRecord(fqdn, 300, `v=other "quoted" \ tool`))

	change, err := p.AddTXT(ctx30(t), z, fqdn, "alice-value", 60)
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(change, "/change/C"), change)
	ttl, values, _ := f.RecordSet(fqdn)
	assert.Equal(t, 60, ttl)
	assert.ElementsMatch(t, []string{`v=other "quoted" \ tool`, "alice-value"}, values)

	again, err := p.AddTXT(ctx30(t), z, fqdn, "alice-value", 60)
	require.NoError(t, err)
	assert.Empty(t, again, "a value that is there needs no change")
	assert.Equal(t, 1, f.Counters()[fakeroute53.OpChange])

	require.NoError(t, p.RemoveTXT(ctx30(t), z, fqdn, "alice-value"))
	ttl, values, _ = f.RecordSet(fqdn)
	assert.Equal(t, []string{`v=other "quoted" \ tool`}, values, "the foreign value stays, unchanged")
	assert.Equal(t, 60, ttl, "the rest keeps the set's TTL")
}

func TestLongValueIsSplitIntoStrings(t *testing.T) {
	f := startFake(t, fakeroute53.Options{})
	p := newProvider(t, f)
	z := zoneOf(t, f, "example.test")
	long := strings.Repeat("x", 300)
	_, err := p.AddTXT(ctx30(t), z, "_acme-challenge.example.test", long, 60)
	require.NoError(t, err, "a value over 255 bytes is sent as two character strings")
	_, values, _ := f.RecordSet("_acme-challenge.example.test")
	assert.Equal(t, []string{long}, values)
	require.NoError(t, p.RemoveTXT(ctx30(t), z, "_acme-challenge.example.test", long))
	assert.Empty(t, f.Records())
}

func TestReadTXTIgnoresTheNextSet(t *testing.T) {
	f := startFake(t, fakeroute53.Options{})
	p := newProvider(t, f)
	z := zoneOf(t, f, "example.test")
	// ListResourceRecordSets answers the next set in Route 53's order when there is none at the name.
	require.True(t, f.SetRecord("_acme-challenge.zzz.example.test", 60, "neighbour"))
	require.NoError(t, p.RemoveTXT(ctx30(t), z, "_acme-challenge.aaa.example.test", "neighbour"))
	_, err := p.AddTXT(ctx30(t), z, "_acme-challenge.aaa.example.test", "mine", 60)
	require.NoError(t, err)
	assert.Equal(t, map[string][]string{"_acme-challenge.zzz.example.test": {"neighbour"}, "_acme-challenge.aaa.example.test": {"mine"}}, f.Records())
}

func TestRemoveTXTDeleteRace(t *testing.T) {
	f := startFake(t, fakeroute53.Options{})
	p := newProvider(t, f)
	z := zoneOf(t, f, "example.test")
	const fqdn = "_acme-challenge.example.test"
	empty := `<ListResourceRecordSetsResponse xmlns="` + apiNS + `"><ResourceRecordSets></ResourceRecordSets><IsTruncated>false</IsTruncated><MaxItems>1</MaxItems></ListResourceRecordSetsResponse>`

	// The DELETE is refused (the set changed) and the set read again no longer holds the value: success.
	require.True(t, f.SetRecord(fqdn, 60, "v"))
	f.FailNext(fakeroute53.OpChange, fakeroute53.Fault{Code: "InvalidChangeBatch"})
	f.FailNext(fakeroute53.OpList, fakeroute53.Fault{Delay: time.Nanosecond}) // the first read: the real answer
	f.FailNext(fakeroute53.OpList, fakeroute53.Fault{Body: empty})
	require.NoError(t, p.RemoveTXT(ctx30(t), z, fqdn, "v"))

	// Refused and still there: the refusal is reported, permanent.
	f.FailNext(fakeroute53.OpChange, fakeroute53.Fault{Code: "InvalidChangeBatch"})
	err := p.RemoveTXT(ctx30(t), z, fqdn, "v")
	require.Error(t, err)
	assert.Equal(t, acme.ReasonDNSProviderError, reasonOf(err))
	assert.Equal(t, 400, statusOf(t, err))
	assert.Equal(t, acme.ClassPermanent, acme.FailureClass(err))
	_, values, _ := f.RecordSet(fqdn)
	assert.Equal(t, []string{"v"}, values)
}

func TestInvalidZoneIDNeverReachesAPath(t *testing.T) {
	f := startFake(t, fakeroute53.Options{})
	p := newProvider(t, f)
	bad := dnsapi.Zone{Name: "example.test", ID: "../hostedzone/Z1"}
	_, err := p.AddTXT(ctx30(t), bad, "_acme-challenge.example.test", "v", 60)
	assert.Equal(t, acme.ReasonDNSProviderError, reasonOf(err))
	assert.Equal(t, acme.ReasonDNSProviderError, reasonOf(p.RemoveTXT(ctx30(t), bad, "_acme-challenge.example.test", "v")))
	assert.Empty(t, f.Requests())
}

func TestAnswersWithInvalidShapesAreRefused(t *testing.T) {
	f := startFake(t, fakeroute53.Options{})
	p := newProvider(t, f)
	z := zoneOf(t, f, "example.test")
	const fqdn = "_acme-challenge.example.test"
	changeAnswer := func(id string) string {
		return `<ChangeResourceRecordSetsResponse xmlns="` + apiNS + `"><ChangeInfo><Id>` + id + `</Id><Status>PENDING</Status></ChangeInfo></ChangeResourceRecordSetsResponse>`
	}
	for name, tc := range map[string]struct{ op, body string }{
		"change id with a query":  {fakeroute53.OpChange, changeAnswer("/change/C1?x=1")},
		"change id of a zone":     {fakeroute53.OpChange, changeAnswer("/hostedzone/Z1")},
		"change id too long":      {fakeroute53.OpChange, changeAnswer("/change/" + strings.Repeat("C", 33))},
		"change answer not xml":   {fakeroute53.OpChange, "{}"},
		"listing of another kind": {fakeroute53.OpList, changeAnswer("/change/C1")},
		"listing not xml":         {fakeroute53.OpList, "<"},
		"set without values": {fakeroute53.OpList, `<ListResourceRecordSetsResponse><ResourceRecordSets><ResourceRecordSet><Name>` + fqdn +
			`.</Name><Type>TXT</Type><TTL>60</TTL></ResourceRecordSet></ResourceRecordSets></ListResourceRecordSetsResponse>`},
	} {
		t.Run(name, func(t *testing.T) {
			f.FailNext(tc.op, fakeroute53.Fault{Body: tc.body})
			_, err := p.AddTXT(ctx30(t), z, fqdn, "v-"+name, 60)
			require.Error(t, err)
			assert.Equal(t, acme.ReasonDNSProviderError, reasonOf(err))
			assert.Equal(t, 200, statusOf(t, err))
		})
	}
}

// ---- changes ----

func TestChangeDone(t *testing.T) {
	f := startFake(t, fakeroute53.Options{InsyncAfter: 2})
	p := newProvider(t, f)
	change, err := p.AddTXT(ctx30(t), zoneOf(t, f, "example.test"), "_acme-challenge.example.test", "v", 60)
	require.NoError(t, err)
	for range 2 {
		done, err := p.ChangeDone(ctx30(t), change)
		require.NoError(t, err)
		assert.False(t, done, "PENDING")
	}
	done, err := p.ChangeDone(ctx30(t), change)
	require.NoError(t, err)
	assert.True(t, done, "INSYNC")

	for _, bad := range []string{"", "C1", "/change/", "/change/c1", "/change/C1/../x", "/hostedzone/Z1"} {
		_, err := p.ChangeDone(ctx30(t), bad)
		assert.Equal(t, acme.ReasonDNSProviderError, reasonOf(err), bad)
	}
	_, err = p.ChangeDone(ctx30(t), "/change/CUNKNOWN")
	assert.Equal(t, acme.ReasonDNSProviderError, reasonOf(err))
	assert.Equal(t, 404, statusOf(t, err))

	get := func(id, status string) string {
		return `<GetChangeResponse xmlns="` + apiNS + `"><ChangeInfo><Id>` + id + `</Id><Status>` + status + `</Status></ChangeInfo></GetChangeResponse>`
	}
	for name, body := range map[string]string{
		"unknown status": get(change, "DONE"),
		"another change": get("/change/COTHER", "INSYNC"),
		"not xml":        "nope",
	} {
		f.FailNext(fakeroute53.OpGetChange, fakeroute53.Fault{Body: body})
		_, err := p.ChangeDone(ctx30(t), change)
		assert.Equal(t, acme.ReasonDNSProviderError, reasonOf(err), name)
	}
	assert.Equal(t, 2, strings.Count(change, "/"), "the handle is /change/<ID>")
}

// ---- failures ----

func TestFailureClasses(t *testing.T) {
	cases := []struct {
		name      string
		op        string
		fault     fakeroute53.Fault
		reason    string
		status    int
		transient bool
	}{
		{"throttling", fakeroute53.OpChange, fakeroute53.Fault{Code: "Throttling"}, acme.ReasonDNSProviderError, 429, true},
		{"prior request", fakeroute53.OpChange, fakeroute53.Fault{Code: "PriorRequestNotComplete"}, acme.ReasonDNSProviderError, 429, true},
		{"server error", fakeroute53.OpChange, fakeroute53.Fault{Status: 500}, acme.ReasonDNSProviderError, 500, true},
		{"unavailable", fakeroute53.OpList, fakeroute53.Fault{Status: 503}, acme.ReasonDNSProviderError, 503, true},
		{"reset", fakeroute53.OpList, fakeroute53.Fault{Reset: true}, acme.ReasonDNSProviderError, 0, true},
		{"invalid change batch", fakeroute53.OpChange, fakeroute53.Fault{Code: "InvalidChangeBatch"}, acme.ReasonDNSProviderError, 400, false},
		{"invalid input", fakeroute53.OpChange, fakeroute53.Fault{Code: "InvalidInput"}, acme.ReasonDNSProviderError, 400, false},
		{"no such zone", fakeroute53.OpList, fakeroute53.Fault{Status: 404, Code: "NoSuchHostedZone"}, acme.ReasonDNSZoneNotFound, 0, false},
		{"access denied", fakeroute53.OpChange, fakeroute53.Fault{Status: 403, Code: "AccessDenied"}, acme.ReasonDNSAuthFailed, 403, false},
		{"expired token as 400", fakeroute53.OpList, fakeroute53.Fault{Code: "ExpiredToken"}, acme.ReasonDNSAuthFailed, 403, false},
		{"redirect", fakeroute53.OpList, fakeroute53.Fault{Status: 302, Body: " "}, acme.ReasonDNSProviderError, 302, false},
		{"oversized", fakeroute53.OpList, fakeroute53.Fault{Body: strings.Repeat("x", dnsapi.MaxResponseBytes+1)}, acme.ReasonDNSProviderError, 200, false},
		{"error without code", fakeroute53.OpChange, fakeroute53.Fault{Status: 409, Body: "<ErrorResponse><Error><Code>a b</Code></Error></ErrorResponse>"}, acme.ReasonDNSProviderError, 409, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := startFake(t, fakeroute53.Options{})
			p := newProvider(t, f)
			f.FailNext(tc.op, tc.fault)
			_, err := p.AddTXT(ctx30(t), zoneOf(t, f, "example.test"), "_acme-challenge.example.test", "v", 60)
			require.Error(t, err)
			assert.Equal(t, tc.reason, reasonOf(err))
			var ae *acme.Error
			require.ErrorAs(t, err, &ae)
			assert.Equal(t, tc.status, ae.Status)
			assert.Equal(t, "example.test", ae.Identifier)
			want := acme.ClassPermanent
			if tc.transient {
				want = acme.ClassTransient
			}
			assert.Equal(t, want, acme.FailureClass(err))
		})
	}
}

func TestWrongSecretIsAuthFailure(t *testing.T) {
	f := startFake(t, fakeroute53.Options{})
	p := newProvider(t, f, func(c *Config) { c.SecretAccessKey = secrets.NewPlaintext([]byte("wrong-secret-0123456789")) })
	err := newSolver(t, p).Present(ctx30(t), chal("example.test", "v"))
	require.Error(t, err)
	assert.Equal(t, acme.ReasonDNSAuthFailed, reasonOf(err))
	assert.Equal(t, acme.ClassPermanent, acme.FailureClass(err))
	assert.Equal(t, 1, f.Counters()["auth-failed"])

	other := newProvider(t, f, func(c *Config) { c.AccessKeyID = "FAKEUNKNOWNKEY0000" })
	_, err = other.FindZone(ctx30(t), "_acme-challenge.example.test")
	assert.Equal(t, acme.ReasonDNSAuthFailed, reasonOf(err), "an unknown key ID: InvalidClientTokenId")
}

func TestStaleClockIsRefused(t *testing.T) {
	f := startFake(t, fakeroute53.Options{})
	p := newProvider(t, f)
	p.setNow(func() time.Time { return time.Now().Add(-6 * time.Minute) })
	_, err := p.FindZone(ctx30(t), "_acme-challenge.example.test")
	assert.Equal(t, acme.ReasonDNSAuthFailed, reasonOf(err), "an X-Amz-Date six minutes off is refused")
}

func TestContextEnds(t *testing.T) {
	f := startFake(t, fakeroute53.Options{})
	p := newProvider(t, f)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	f.FailNext(fakeroute53.OpZones, fakeroute53.Fault{Delay: 5 * time.Second})
	_, err := p.FindZone(ctx, "_acme-challenge.example.test")
	assert.ErrorIs(t, err, context.DeadlineExceeded)
}

// ---- assumed role ----

func sharedClock() (now func() time.Time, advance func(time.Duration)) {
	var off atomic.Int64
	return func() time.Time { return time.Now().Add(time.Duration(off.Load())) },
		func(d time.Duration) { off.Add(int64(d)) }
}

func TestAssumeRoleSignsWithTheSession(t *testing.T) {
	now, advance := sharedClock()
	f := startFake(t, fakeroute53.Options{RoleARN: testRole, ExternalID: testExternalID, Now: now})
	p := newProvider(t, f, withRole)
	p.setNow(now)
	s := newSolver(t, p)
	require.NoError(t, s.Present(ctx30(t), chal("example.test", "v1")))
	require.NoError(t, s.CleanUp(ctx30(t), chal("example.test", "v1")))
	sessions := f.Sessions()
	require.Len(t, sessions, 1, "one sign-in serves every call while the session is fresh")
	assert.Regexp(t, `^alice-acme-[0-9a-f]{8}$`, sessions[0].RoleSessionName)
	assert.Equal(t, 900, sessions[0].DurationSeconds)
	assert.Equal(t, testExternalID, sessions[0].ExternalID)
	assert.Zero(t, f.Counters()["auth-failed"], "Route 53 accepts only the role here: every call carried the session token")

	advance(12*time.Minute + 30*time.Second) // 2.5 minutes left: still fresh
	_, err := p.FindZone(ctx30(t), "_acme-challenge.example.test")
	require.NoError(t, err)
	assert.Len(t, f.Sessions(), 1)
	advance(time.Minute) // 1.5 minutes left: renewed
	_, err = p.FindZone(ctx30(t), "_acme-challenge.example.test")
	require.NoError(t, err)
	assert.Len(t, f.Sessions(), 2)

	// AWS refuses the session (revoked or expired early): it is dropped and the next call signs in again.
	f.FailNext(fakeroute53.OpZones, fakeroute53.Fault{Status: 403, Code: "ExpiredToken"})
	_, err = p.FindZone(ctx30(t), "_acme-challenge.example.test")
	assert.Equal(t, acme.ReasonDNSAuthFailed, reasonOf(err))
	_, err = p.FindZone(ctx30(t), "_acme-challenge.example.test")
	require.NoError(t, err)
	assert.Len(t, f.Sessions(), 3)
}

func TestRoleRequiredByTheAccount(t *testing.T) {
	f := startFake(t, fakeroute53.Options{RoleARN: testRole})
	_, err := newProvider(t, f).FindZone(ctx30(t), "_acme-challenge.example.test")
	assert.Equal(t, acme.ReasonDNSAuthFailed, reasonOf(err), "the long-term key alone is refused AccessDenied")
}

func TestAssumeRoleFailures(t *testing.T) {
	stsAnswer := func(keyID, secret, token, exp string) string {
		return `<AssumeRoleResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><AssumeRoleResult><Credentials><AccessKeyId>` + keyID +
			`</AccessKeyId><SecretAccessKey>` + secret + `</SecretAccessKey><SessionToken>` + token + `</SessionToken><Expiration>` + exp +
			`</Expiration></Credentials></AssumeRoleResult></AssumeRoleResponse>`
	}
	later := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	okSecret, okToken := strings.Repeat("s", 24), strings.Repeat("t", 24) // well-shaped, low entropy: no scanner reads a key here
	cases := []struct {
		name      string
		fault     *fakeroute53.Fault
		mut       func(*Config)
		reason    string
		transient bool
	}{
		{"wrong external id", nil, func(c *Config) { c.ExternalID = "other-id" }, acme.ReasonDNSAuthFailed, false},
		{"wrong role", nil, func(c *Config) { c.RoleARN = "arn:aws:iam::123456789012:role/other" }, acme.ReasonDNSAuthFailed, false},
		{"wrong secret", nil, func(c *Config) { c.SecretAccessKey = secrets.NewPlaintext([]byte("wrong-secret-0123456789")) }, acme.ReasonDNSAuthFailed, false},
		{"denied", &fakeroute53.Fault{Status: 403, Code: "AccessDenied"}, nil, acme.ReasonDNSAuthFailed, false},
		{"validation", &fakeroute53.Fault{Code: "ValidationError"}, nil, acme.ReasonDNSAuthFailed, false},
		{"throttled", &fakeroute53.Fault{Code: "Throttling"}, nil, acme.ReasonDNSProviderError, true},
		{"server error", &fakeroute53.Fault{Status: 500}, nil, acme.ReasonDNSProviderError, true},
		{"reset", &fakeroute53.Fault{Reset: true}, nil, acme.ReasonDNSProviderError, true},
		{"not xml", &fakeroute53.Fault{Body: "<oops"}, nil, acme.ReasonDNSProviderError, false},
		{"another document", &fakeroute53.Fault{Body: "<ErrorResponse/>"}, nil, acme.ReasonDNSProviderError, false},
		{"key id shape", &fakeroute53.Fault{Body: stsAnswer("asia-lower-case-key", okSecret, okToken, later)}, nil, acme.ReasonDNSProviderError, false},
		{"secret shape", &fakeroute53.Fault{Body: stsAnswer("ASIA0123456789ABCDEF", "short", okToken, later)}, nil, acme.ReasonDNSProviderError, false},
		{"token shape", &fakeroute53.Fault{Body: stsAnswer("ASIA0123456789ABCDEF", okSecret, "tok en with spaces in it", later)}, nil, acme.ReasonDNSProviderError, false},
		{"expired", &fakeroute53.Fault{Body: stsAnswer("ASIA0123456789ABCDEF", okSecret, okToken, "2020-01-01T00:00:00Z")}, nil, acme.ReasonDNSProviderError, false},
		{"bad time", &fakeroute53.Fault{Body: stsAnswer("ASIA0123456789ABCDEF", okSecret, okToken, "tomorrow")}, nil, acme.ReasonDNSProviderError, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := startFake(t, fakeroute53.Options{RoleARN: testRole, ExternalID: testExternalID})
			muts := []func(*Config){withRole}
			if tc.mut != nil {
				muts = append(muts, tc.mut)
			}
			p := newProvider(t, f, muts...)
			if tc.fault != nil {
				f.FailNext(fakeroute53.OpAssumeRole, *tc.fault)
			}
			_, err := p.FindZone(ctx30(t), "_acme-challenge.example.test")
			require.Error(t, err)
			assert.Equal(t, tc.reason, reasonOf(err))
			want := acme.ClassPermanent
			if tc.transient {
				want = acme.ClassTransient
			}
			assert.Equal(t, want, acme.FailureClass(err))
			assert.Nil(t, p.temp)
			assert.Zero(t, f.Counters()[fakeroute53.OpZones], "nothing reached Route 53")
		})
	}
}

func TestAssumeRoleRandomFailure(t *testing.T) {
	f := startFake(t, fakeroute53.Options{RoleARN: testRole, ExternalID: testExternalID})
	p := newProvider(t, f, withRole)
	p.random = strings.NewReader("")
	_, err := p.FindZone(ctx30(t), "_acme-challenge.example.test")
	assert.Equal(t, acme.ReasonDNSProviderError, reasonOf(err), "a local failure is not a refused sign-in")
	assert.Empty(t, f.Requests())
}

func TestRequestBuildFailures(t *testing.T) {
	f := startFake(t, fakeroute53.Options{})
	p := newProvider(t, f)
	// A method net/http refuses stands for any request that cannot be built: a fixed error, nothing sent.
	_, _, _, err := p.call(ctx30(t), "example.test", "BAD METHOD", zonesPath, nil, nil)
	assert.Equal(t, acme.ReasonDNSProviderError, reasonOf(err))
	assert.Empty(t, f.Requests())
	//nolint:staticcheck // SA1012: a nil context is the way to make NewRequestWithContext fail in assumeRole
	_, _, err = newProvider(t, f, withRole).assumeRole(nil, "example.test")
	assert.Equal(t, acme.ReasonDNSProviderError, reasonOf(err))
}

func TestErrorsAreAlwaysACMEErrors(t *testing.T) {
	f := startFake(t, fakeroute53.Options{})
	p := newProvider(t, f)
	f.FailAll(fakeroute53.OpZones, fakeroute53.Fault{Status: 500})
	_, err := p.FindZone(ctx30(t), "_acme-challenge.example.test")
	var ae *acme.Error
	assert.True(t, errors.As(err, &ae))
}
