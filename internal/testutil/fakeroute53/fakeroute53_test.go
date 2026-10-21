package fakeroute53

import (
	"context"
	"crypto/tls"
	"encoding/xml"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---- a test client: signs with the fake's own canonical form (checked against the AWS suite below) ----

type creds struct{ keyID, secret, token string }

type call struct {
	method, host, path string
	query              url.Values
	body               string
	service            string
	at                 time.Time
	mutate             func(*http.Request) // after signing
	ctx                context.Context
}

type answer struct {
	status int
	body   string
	err    error
}

func (a answer) code() string {
	var e errorXML
	if xml.Unmarshal([]byte(a.body), &e) != nil {
		return ""
	}
	if e.XMLName.Local == codeInvalidChangeBatch {
		return codeInvalidChangeBatch
	}
	return e.Error.Code
}

func client(s *Server) *http.Client {
	d := &net.Dialer{Timeout: 5 * time.Second}
	return &http.Client{
		Transport: &http.Transport{
			Proxy: nil,
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return d.DialContext(ctx, network, s.MapAddr(addr))
			},
			TLSClientConfig:   &tls.Config{RootCAs: s.CAPool(), MinVersion: tls.VersionTLS12},
			DisableKeepAlives: true,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

func signRequest(req *http.Request, body []byte, c creds, service string, at time.Time) {
	amzDate := at.UTC().Format("20060102T150405Z")
	req.Header.Set("X-Amz-Date", amzDate)
	signed := []string{"host", "x-amz-date"}
	if req.Header.Get("Content-Type") != "" {
		signed = append(signed, "content-type")
	}
	if c.token != "" {
		req.Header.Set("X-Amz-Security-Token", c.token)
		signed = append(signed, "x-amz-security-token")
	}
	sort.Strings(signed)
	if req.Host == "" {
		req.Host = req.URL.Host
	}
	scope := []string{amzDate[:8], Region, service, "aws4_request"}
	sig := expectedSignature(req, body, signed, amzDate, scope, c.secret)
	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential="+c.keyID+"/"+strings.Join(scope, "/")+
		", SignedHeaders="+strings.Join(signed, ";")+", Signature="+sig)
}

func send(t *testing.T, s *Server, c creds, cl call) answer {
	t.Helper()
	if cl.host == "" {
		cl.host = Route53Host
	}
	if cl.service == "" {
		cl.service = "route53"
		if cl.host == STSHost {
			cl.service = "sts"
		}
	}
	if cl.at.IsZero() {
		cl.at = time.Now()
	}
	if cl.ctx == nil {
		cl.ctx = context.Background()
	}
	u := url.URL{Scheme: "https", Host: cl.host, Path: cl.path, RawQuery: cl.query.Encode()}
	var rd io.Reader
	if cl.body != "" {
		rd = strings.NewReader(cl.body)
	}
	req, err := http.NewRequestWithContext(cl.ctx, cl.method, u.String(), rd)
	require.NoError(t, err)
	if cl.body != "" {
		ct := "application/xml"
		if cl.host == STSHost {
			ct = "application/x-www-form-urlencoded; charset=utf-8"
		}
		req.Header.Set("Content-Type", ct)
	}
	signRequest(req, []byte(cl.body), c, cl.service, cl.at)
	if cl.mutate != nil {
		cl.mutate(req)
	}
	res, err := client(s).Do(req)
	if err != nil {
		return answer{err: err}
	}
	defer res.Body.Close()
	b, err := io.ReadAll(res.Body)
	require.NoError(t, err)
	return answer{status: res.StatusCode, body: string(b)}
}

func longTerm(s *Server) creds { return creds{keyID: s.AccessKeyID(), secret: s.SecretAccessKey()} }

// ---- the canonical form against the AWS SigV4 test suite ----

// The suite's example credentials (key ID "AKIDEXAMPLE", the secret AWS's documentation prints as its example
// key): a published example only, which gitleaks and trivy accept.
var suiteSecret = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"

func TestExpectedSignatureSuiteVectors(t *testing.T) {
	scope := []string{"20150830", "us-east-1", "service", "aws4_request"}
	r := httptest.NewRequest("GET", "https://example.amazonaws.com/", nil)
	r.Header.Set("X-Amz-Date", "20150830T123600Z")
	assert.Equal(t, "5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31",
		expectedSignature(r, nil, []string{"host", "x-amz-date"}, "20150830T123600Z", scope, suiteSecret), "get-vanilla")

	r = httptest.NewRequest("GET", "https://example.amazonaws.com/?Param2=value2&Param1=value1", nil)
	r.Header.Set("X-Amz-Date", "20150830T123600Z")
	assert.Equal(t, "b97d918cfa904a5beff61c982a1b6f458b799221646efd99d3219ec94cdf2500",
		expectedSignature(r, nil, []string{"host", "x-amz-date"}, "20150830T123600Z", scope, suiteSecret), "get-vanilla-query-order-key-case")

	r = httptest.NewRequest("POST", "https://example.amazonaws.com/", strings.NewReader("Param1=value1"))
	r.Header.Set("X-Amz-Date", "20150830T123600Z")
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	assert.Equal(t, "ff11897932ad3f4e8b18135d722051e5ac45fc38421b1da7b9d196a0fe09473a",
		expectedSignature(r, []byte("Param1=value1"), []string{"content-type", "host", "x-amz-date"}, "20150830T123600Z", scope, suiteSecret),
		"post-x-www-form-urlencoded")

	r = httptest.NewRequest("GET", "https://example.amazonaws.com/", nil)
	r.Header.Set("X-Amz-Date", "20150830T123600Z")
	r.Header.Set("My-Header1", " value1")
	r.Header.Set("My-Header2", ` "a   b   c"`)
	assert.Equal(t, "acc3ed3afb60bb290fc8d2dd0098b9911fcaa05412b367055dee359757a9c736",
		expectedSignature(r, nil, []string{"host", "my-header1", "my-header2", "x-amz-date"}, "20150830T123600Z", scope, suiteSecret),
		"get-header-value-trim")
	assert.Equal(t, ` "a   b   c"`, r.Header.Get("My-Header2"), "the request's headers are not changed")
	assert.Equal(t, "/", fakeCanonicalPath(""))
	assert.Equal(t, "/%25E1%2588%25B4", fakeCanonicalPath("/%E1%88%B4"), "each segment encoded once more")
	assert.Equal(t, "a=1&a-b=1", fakeCanonicalQuery(url.Values{"a-b": {"1"}, "a": {"1"}}))
}

// ---- Route 53 ----

func changeBody(action, name string, ttl int, values ...string) string {
	var rr strings.Builder
	for _, v := range values {
		rr.WriteString("<ResourceRecord><Value>")
		_ = xml.EscapeText(&rr, []byte(v))
		rr.WriteString("</Value></ResourceRecord>")
	}
	return `<?xml version="1.0" encoding="UTF-8"?><ChangeResourceRecordSetsRequest xmlns="` + r53NS + `"><ChangeBatch><Comment>t</Comment>` +
		`<Changes><Change><Action>` + action + `</Action><ResourceRecordSet><Name>` + name + `</Name><Type>TXT</Type><TTL>` +
		fmt.Sprint(ttl) + `</TTL><ResourceRecords>` + rr.String() + `</ResourceRecords></ResourceRecordSet></Change></Changes></ChangeBatch></ChangeResourceRecordSetsRequest>`
}

func changeID(t *testing.T, a answer) string {
	t.Helper()
	require.Equal(t, 200, a.status, a.body)
	var c changeResponseXML
	require.NoError(t, xml.Unmarshal([]byte(a.body), &c))
	assert.Equal(t, "ChangeResourceRecordSetsResponse", c.XMLName.Local)
	assert.Equal(t, "PENDING", c.ChangeInfo.Status)
	return c.ChangeInfo.ID
}

func zonesPage(t *testing.T, a answer) listZonesXML {
	t.Helper()
	require.Equal(t, 200, a.status, a.body)
	var l listZonesXML
	require.NoError(t, xml.Unmarshal([]byte(a.body), &l))
	return l
}

func TestListHostedZonesByName(t *testing.T) {
	s := Start(t, Options{Zones: []Zone{{Name: "Example.Test."}, {Name: "www.example.test"}, {Name: "a.test"}, {Name: "example.test", Private: true}}})
	assert.Equal(t, "example.test", normName("Example.Test."))
	c := longTerm(s)
	get := func(q url.Values) answer {
		return send(t, s, c, call{method: "GET", path: "/2013-04-01/hostedzonesbyname", query: q})
	}
	all := zonesPage(t, get(nil))
	var names []string
	for _, z := range all.HostedZones {
		names = append(names, z.Name)
	}
	assert.Equal(t, []string{"a.test.", "example.test.", "example.test.", "www.example.test."}, names, "labels reversed, then ID")

	page := zonesPage(t, get(url.Values{"dnsname": {"www.example.test"}, "maxitems": {"10"}}))
	require.Len(t, page.HostedZones, 1)
	assert.Equal(t, "/hostedzone/"+s.ZoneID("www.example.test", false), page.HostedZones[0].ID)
	assert.False(t, page.IsTruncated)

	page = zonesPage(t, get(url.Values{"dnsname": {"example.test"}, "maxitems": {"1"}}))
	require.Len(t, page.HostedZones, 1)
	assert.True(t, page.IsTruncated)
	assert.Equal(t, "example.test.", page.NextDNSName)
	assert.NotEmpty(t, page.NextHostedZoneID)

	for _, q := range []url.Values{{"maxitems": {"0"}}, {"maxitems": {"101"}}, {"maxitems": {"x"}}, {"hostedzoneid": {"Z1"}}} {
		assert.Equal(t, "InvalidInput", get(q).code(), q)
	}
	assert.Equal(t, "InvalidDomainName", get(url.Values{"dnsname": {"bad name!"}}).code())
	assert.Equal(t, 1+1+1, s.Counters()[OpZones])

	id := s.AddZone(Zone{Name: "new.test"})
	assert.Equal(t, id, s.ZoneID("new.test", false))
	assert.Empty(t, s.ZoneID("new.test", true))
	assert.Empty(t, s.ZoneID("none.test", false))
}

func TestChangesListsAndGetChange(t *testing.T) {
	sink := &recSink{}
	s := Start(t, Options{Zones: []Zone{{Name: "example.test"}}, InsyncAfter: 2, Sink: sink})
	c := longTerm(s)
	zid := s.ZoneID("example.test", false)
	rrset := "/2013-04-01/hostedzone/" + zid + "/rrset"
	post := func(body string) answer { return send(t, s, c, call{method: "POST", path: rrset + "/", body: body}) }
	list := func(q url.Values) answer { return send(t, s, c, call{method: "GET", path: rrset, query: q}) }
	const name = "_acme-challenge.example.test."

	id := changeID(t, post(changeBody("CREATE", name, 60, `"one"`)))
	assert.True(t, strings.HasPrefix(id, "/change/C"))
	assert.Equal(t, codeInvalidChangeBatch, post(changeBody("CREATE", name, 60, `"one"`)).code(), "it exists")
	changeID(t, post(changeBody("UPSERT", name, 120, `"one"`, `"two" "parts"`)))
	ttl, vals, ok := s.RecordSet(name)
	require.True(t, ok)
	assert.Equal(t, 120, ttl)
	assert.Equal(t, []string{"one", "twoparts"}, vals)
	assert.Equal(t, []string{"set _acme-challenge.example.test one", "set _acme-challenge.example.test twoparts"}, sink.log())

	// Without the slash too (both paths are served).
	changeID(t, send(t, s, c, call{method: "POST", path: rrset, body: changeBody("UPSERT", "x.example.test", 60, `"x"`)}))

	var l listSetsXML
	a := list(url.Values{"name": {name}, "type": {"TXT"}, "maxitems": {"1"}})
	require.NoError(t, xml.Unmarshal([]byte(a.body), &l))
	require.Len(t, l.Sets, 1)
	assert.Equal(t, name, l.Sets[0].Name)
	assert.Equal(t, 2, len(l.Sets[0].Records))
	assert.True(t, l.IsTruncated)
	assert.Equal(t, "x.example.test.", l.NextRecordName)

	l = listSetsXML{}
	require.NoError(t, xml.Unmarshal([]byte(list(url.Values{"name": {"_a.example.test"}, "type": {"TXT"}}).body), &l))
	require.Len(t, l.Sets, 2, "no set at the name: the following sets")
	l = listSetsXML{}
	require.NoError(t, xml.Unmarshal([]byte(list(url.Values{"name": {"a.example.test"}, "type": {"TXT"}}).body), &l))
	require.Len(t, l.Sets, 1, `"_" sorts before "a": only x.example.test follows`)
	assert.Equal(t, "InvalidInput", list(url.Values{"name": {"x.example.test"}, "type": {"TXTZ"}}).code(), "an invalid type is refused")
	l = listSetsXML{}
	require.NoError(t, xml.Unmarshal([]byte(list(url.Values{"name": {"x.example.test"}, "type": {"TLSA"}}).body), &l))
	assert.Len(t, l.Sets, 1, "a type sorted before TXT at the name: the TXT set")
	l = listSetsXML{}
	require.NoError(t, xml.Unmarshal([]byte(list(nil).body), &l))
	assert.Len(t, l.Sets, 2)

	assert.Equal(t, "InvalidInput", list(url.Values{"type": {"TXT"}}).code(), "a type needs a name")
	assert.Equal(t, "InvalidInput", list(url.Values{"maxitems": {"301"}}).code())
	assert.Equal(t, "InvalidInput", list(url.Values{"name": {"a.example.test"}, "type": {"BOGUS"}}).code())
	assert.Equal(t, "NoSuchHostedZone", send(t, s, c, call{method: "GET", path: "/2013-04-01/hostedzone/ZNONE/rrset"}).code())

	for name, tc := range map[string]struct{ body, code string }{
		"delete other values":      {changeBody("DELETE", name, 120, `"one"`), codeInvalidChangeBatch},
		"delete other ttl":         {changeBody("DELETE", name, 60, `"one"`, `"two" "parts"`), codeInvalidChangeBatch},
		"delete missing":           {changeBody("DELETE", "nothing.example.test", 60, `"a"`), codeInvalidChangeBatch},
		"outside the zone":         {changeBody("UPSERT", "example.org", 60, `"a"`), codeInvalidChangeBatch},
		"unquoted":                 {changeBody("UPSERT", name, 60, `abc`), codeInvalidChangeBatch},
		"unterminated":             {changeBody("UPSERT", name, 60, `"abc`), codeInvalidChangeBatch},
		"dangling escape":          {changeBody("UPSERT", name, 60, `"abc\`), codeInvalidChangeBatch},
		"string too long":          {changeBody("UPSERT", name, 60, `"`+strings.Repeat("a", 256)+`"`), codeInvalidChangeBatch},
		"no values":                {changeBody("UPSERT", name, 60), codeInvalidChangeBatch},
		"empty value":              {changeBody("UPSERT", name, 60, ` `), codeInvalidChangeBatch},
		"bad action":               {changeBody("REPLACE", name, 60, `"a"`), "InvalidInput"},
		"bad ttl":                  {changeBody("UPSERT", name, -1, `"a"`), "InvalidInput"},
		"not txt":                  {strings.Replace(changeBody("UPSERT", name, 60, `"a"`), "<Type>TXT", "<Type>A", 1), "InvalidInput"},
		"no ttl":                   {strings.Replace(changeBody("UPSERT", name, 60, `"a"`), "<TTL>60</TTL>", "", 1), "InvalidInput"},
		"two values in one record": {strings.Replace(changeBody("UPSERT", name, 60, `"a"`), "</Value>", `</Value><Value>"b"</Value>`, 1), "InvalidInput"},
		"no namespace":             {strings.Replace(changeBody("UPSERT", name, 60, `"a"`), ` xmlns="`+r53NS+`"`, "", 1), "InvalidInput"},
		"not xml":                  {"<", "InvalidInput"},
		"no changes":               {`<ChangeResourceRecordSetsRequest xmlns="` + r53NS + `"><ChangeBatch/></ChangeResourceRecordSetsRequest>`, "InvalidInput"},
	} {
		a := post(tc.body)
		assert.Equal(t, tc.code, a.code(), name)
		assert.Equal(t, 400, a.status, name)
	}
	assert.Equal(t, "NoSuchHostedZone", send(t, s, c, call{method: "POST", path: "/2013-04-01/hostedzone/ZNONE/rrset/", body: changeBody("UPSERT", name, 60, `"a"`)}).code())

	del := post(changeBody("DELETE", name, 120, `"two" "parts"`, `"one"`))
	changeID(t, del)
	_, _, ok = s.RecordSet(name)
	assert.False(t, ok)
	assert.Contains(t, sink.log(), "clear _acme-challenge.example.test one")

	getChange := func(id string) (int, string) {
		a := send(t, s, c, call{method: "GET", path: "/2013-04-01" + id})
		var r changeResponseXML
		_ = xml.Unmarshal([]byte(a.body), &r)
		return a.status, r.ChangeInfo.Status
	}
	for _, want := range []string{"PENDING", "PENDING", "INSYNC", "INSYNC"} {
		st, got := getChange(id)
		assert.Equal(t, 200, st)
		assert.Equal(t, want, got)
	}
	st, _ := getChange("/change/CNONE")
	assert.Equal(t, 404, st)
	assert.Equal(t, 4, s.Counters()[OpGetChange])
}

type recSink struct {
	mu  sync.Mutex
	got []string
}

func (r *recSink) DNSSet(fqdn, value string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.got = append(r.got, "set "+fqdn+" "+value)
}

func (r *recSink) DNSClear(fqdn, value string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.got = append(r.got, "clear "+fqdn+" "+value)
}

func (r *recSink) log() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := append([]string(nil), r.got...)
	sort.Strings(out)
	return out
}

func TestSetRecordAndViews(t *testing.T) {
	sink := &recSink{}
	s := Start(t, Options{Zones: []Zone{{Name: "example.test"}, {Name: "sub.example.test"}, {Name: "priv.test", Private: true}}, Sink: sink})
	assert.True(t, s.SetRecord("_acme-challenge.a.sub.example.test", 300, `x"y`, ""))
	ttl, vals, ok := s.RecordSet("_acme-challenge.a.sub.example.test.")
	assert.True(t, ok)
	assert.Equal(t, 300, ttl)
	assert.Equal(t, []string{`x"y`, ""}, vals)
	assert.False(t, s.SetRecord("x.priv.test", 60, "v"), "private zones are not seeded")
	assert.False(t, s.SetRecord("other.test", 60, "v"))
	assert.Equal(t, map[string][]string{"_acme-challenge.a.sub.example.test": {`x"y`, ""}}, s.Records())
	assert.True(t, s.SetRecord("_acme-challenge.a.sub.example.test", 60))
	_, _, ok = s.RecordSet("_acme-challenge.a.sub.example.test")
	assert.False(t, ok)
	assert.Empty(t, s.Records())
	assert.Equal(t, []string{"clear _acme-challenge.a.sub.example.test ", `clear _acme-challenge.a.sub.example.test x"y`,
		"set _acme-challenge.a.sub.example.test ", `set _acme-challenge.a.sub.example.test x"y`}, sink.log())

	assert.Equal(t, `"`+strings.Repeat("a", 255)+`" "a"`, quote(strings.Repeat("a", 256)))
	assert.Equal(t, `"a\\b\"c"`, quote(`a\b"c`))
	assert.Equal(t, "*", unquote(`"\052"`))
	assert.Equal(t, "plain", unquote("plain"))
}

// ---- signatures ----

func TestSignatureRefusals(t *testing.T) {
	now := time.Now()
	s := Start(t, Options{Zones: []Zone{{Name: "example.test"}}, Now: func() time.Time { return now }})
	c := longTerm(s)
	zones := func(cr creds, cl call) answer {
		cl.method, cl.path = "GET", "/2013-04-01/hostedzonesbyname"
		if cl.at.IsZero() {
			cl.at = now
		}
		return send(t, s, cr, cl)
	}
	setAuth := func(v string) func(*http.Request) {
		return func(r *http.Request) {
			if v == "" {
				r.Header.Del("Authorization")
				return
			}
			r.Header.Set("Authorization", v)
		}
	}
	editAuth := func(old, repl string) func(*http.Request) {
		return func(r *http.Request) {
			r.Header.Set("Authorization", strings.Replace(r.Header.Get("Authorization"), old, repl, 1))
		}
	}
	cases := []struct {
		name string
		cr   creds
		cl   call
		code string
	}{
		{"no header", c, call{mutate: setAuth("")}, "MissingAuthenticationToken"},
		{"other scheme", c, call{mutate: setAuth("Bearer x")}, "IncompleteSignature"},
		{"no fields", c, call{mutate: setAuth("AWS4-HMAC-SHA256 nonsense")}, "IncompleteSignature"},
		{"short scope", c, call{mutate: editAuth("/aws4_request", "")}, "IncompleteSignature"},
		{"wrong secret", creds{keyID: c.keyID, secret: "not-the-secret"}, call{}, "SignatureDoesNotMatch"},
		{"unknown key", creds{keyID: "FAKEUNKNOWN000000000", secret: c.secret}, call{}, "InvalidClientTokenId"},
		{"long-term key with a token", creds{keyID: c.keyID, secret: c.secret, token: "tok"}, call{}, "InvalidClientTokenId"},
		{"stale", c, call{at: now.Add(-6 * time.Minute)}, "SignatureDoesNotMatch"},
		{"future", c, call{at: now.Add(6 * time.Minute)}, "SignatureDoesNotMatch"},
		{"bad date", c, call{mutate: func(r *http.Request) { r.Header.Set("X-Amz-Date", "yesterday") }}, "IncompleteSignature"},
		{"wrong service", c, call{service: "sts"}, "SignatureDoesNotMatch"},
		{"wrong region", c, call{mutate: editAuth("/us-east-1/", "/eu-west-1/")}, "SignatureDoesNotMatch"},
		{"host not signed", c, call{mutate: editAuth("SignedHeaders=host;x-amz-date", "SignedHeaders=x-amz-date")}, "SignatureDoesNotMatch"},
		{"unsorted", c, call{mutate: editAuth("SignedHeaders=host;x-amz-date", "SignedHeaders=x-amz-date;host")}, "SignatureDoesNotMatch"},
		{"changed after signing", c, call{mutate: func(r *http.Request) { r.URL.RawQuery = "dnsname=other.test" }}, "SignatureDoesNotMatch"},
	}
	for _, tc := range cases {
		a := zones(tc.cr, tc.cl)
		assert.Equal(t, 403, a.status, tc.name)
		assert.Equal(t, tc.code, a.code(), tc.name)
		assert.NotContains(t, a.body, c.secret)
	}
	assert.Equal(t, len(cases), s.Counters()["auth-failed"])
	assert.Empty(t, s.LastSignature())
	assert.Equal(t, 200, zones(c, call{}).status)
	assert.Len(t, s.LastSignature(), 64)

	assert.Equal(t, "UnknownOperation", send(t, s, c, call{method: "GET", path: "/2013-04-01/healthcheck", at: now}).code())
	assert.Equal(t, "UnknownOperation", send(t, s, c, call{method: "DELETE", path: "/2013-04-01/change/C1", at: now}).code())
	assert.Equal(t, "UnknownOperation", send(t, s, c, call{method: "GET", path: "/other", at: now}).code())
}

func TestUnknownHostAndDirectHandler(t *testing.T) {
	s := Start(t, Options{})
	srv := httptest.NewServer(s.Handler())
	t.Cleanup(srv.Close)
	req, err := http.NewRequest("GET", srv.URL+"/", nil)
	require.NoError(t, err)
	req.Host = "elsewhere.example"
	res, err := srv.Client().Do(req)
	require.NoError(t, err)
	_ = res.Body.Close()
	assert.Equal(t, 404, res.StatusCode)
	reqs := s.Requests()
	require.Len(t, reqs, 1)
	assert.Equal(t, Request{Method: "GET", Host: "elsewhere.example", Path: "/", Op: "", Status: 404}, reqs[0])

	assert.Equal(t, "route53.amazonaws.com:80", s.MapAddr("route53.amazonaws.com:80"))
	assert.Equal(t, "example.com:443", s.MapAddr("example.com:443"))
	assert.Equal(t, "nonsense", s.MapAddr("nonsense"))
	assert.NotEqual(t, "STS.amazonaws.com:443", s.MapAddr("STS.amazonaws.com:443"))
	assert.NotEmpty(t, s.CAPEM())
	assert.NotNil(t, s.TLSConfig())
	assert.True(t, strings.HasPrefix(s.AccessKeyID(), "FAKE"))
	assert.Len(t, s.SecretAccessKey(), 40)
}

// ---- STS ----

func assume(t *testing.T, s *Server, c creds, form url.Values, at time.Time) answer {
	t.Helper()
	return send(t, s, c, call{method: "POST", host: STSHost, path: "/", body: form.Encode(), at: at})
}

func roleForm(role, external string) url.Values {
	f := url.Values{"Action": {"AssumeRole"}, "Version": {"2011-06-15"}, "RoleArn": {role}, "RoleSessionName": {"alice-acme-0a1b2c3d"}, "DurationSeconds": {"900"}}
	if external != "" {
		f.Set("ExternalId", external)
	}
	return f
}

const role = "arn:aws:iam::123456789012:role/alice-dns"

func TestAssumeRole(t *testing.T) {
	var off atomic.Int64
	now := func() time.Time { return time.Now().Add(time.Duration(off.Load())) }
	s := Start(t, Options{Zones: []Zone{{Name: "example.test"}}, RoleARN: role, ExternalID: "ext-1", Now: now})
	c := longTerm(s)

	a := assume(t, s, c, roleForm(role, "ext-1"), now())
	require.Equal(t, 200, a.status, a.body)
	var r assumeRoleXML
	require.NoError(t, xml.Unmarshal([]byte(a.body), &r))
	assert.Equal(t, "arn:aws:sts::123456789012:assumed-role/alice-dns/alice-acme-0a1b2c3d", r.AssumedRoleARN)
	exp, err := time.Parse(time.RFC3339, r.Expiration)
	require.NoError(t, err)
	assert.WithinDuration(t, now().Add(900*time.Second), exp, 2*time.Second)
	tmp := creds{keyID: r.AccessKeyID, secret: r.SecretAccessKey, token: r.SessionToken}
	assert.Equal(t, []Session{{RoleSessionName: "alice-acme-0a1b2c3d", DurationSeconds: 900, ExternalID: "ext-1"}}, s.Sessions())
	issued := s.IssuedCredentials()
	require.Len(t, issued, 1)
	assert.Equal(t, r.SessionToken, issued[0].SessionToken)

	zones := func(cr creds, mutate func(*http.Request)) answer {
		return send(t, s, cr, call{method: "GET", path: "/2013-04-01/hostedzonesbyname", at: now(), mutate: mutate})
	}
	assert.Equal(t, 200, zones(tmp, nil).status, "the role's credentials reach Route 53")
	assert.Equal(t, "AccessDenied", zones(c, nil).code(), "the long-term key does not, with a role configured")
	assert.Equal(t, "InvalidClientTokenId", zones(creds{keyID: tmp.keyID, secret: tmp.secret, token: "other-token"}, nil).code())
	assert.Equal(t, "InvalidClientTokenId", zones(creds{keyID: tmp.keyID, secret: tmp.secret}, nil).code(), "no token")
	notSigned := func(r *http.Request) {
		r.Header.Set("Authorization", strings.Replace(r.Header.Get("Authorization"), ";x-amz-security-token", "", 1))
	}
	assert.Equal(t, "SignatureDoesNotMatch", zones(tmp, notSigned).code(), "the token must be signed")
	assert.Equal(t, "AccessDenied", assume(t, s, tmp, roleForm(role, "ext-1"), now()).code(), "no role chaining")

	for name, tc := range map[string]struct {
		form url.Values
		code string
	}{
		"wrong role":        {roleForm("arn:aws:iam::123456789012:role/other", "ext-1"), "AccessDenied"},
		"no external id":    {roleForm(role, ""), "AccessDenied"},
		"wrong external id": {roleForm(role, "ext-2"), "AccessDenied"},
		"no role":           {func() url.Values { f := roleForm(role, "ext-1"); f.Del("RoleArn"); return f }(), "ValidationError"},
		"short duration":    {func() url.Values { f := roleForm(role, "ext-1"); f.Set("DurationSeconds", "899"); return f }(), "ValidationError"},
		"bad duration":      {func() url.Values { f := roleForm(role, "ext-1"); f.Set("DurationSeconds", "x"); return f }(), "ValidationError"},
		"bad session name":  {func() url.Values { f := roleForm(role, "ext-1"); f.Set("RoleSessionName", "a b"); return f }(), "ValidationError"},
		"other action":      {func() url.Values { f := roleForm(role, "ext-1"); f.Set("Action", "GetCallerIdentity"); return f }(), "InvalidAction"},
		"other version":     {func() url.Values { f := roleForm(role, "ext-1"); f.Set("Version", "2010-01-01"); return f }(), "InvalidAction"},
	} {
		assert.Equal(t, tc.code, assume(t, s, c, tc.form, now()).code(), name)
	}
	noDuration := roleForm(role, "ext-1")
	noDuration.Del("DurationSeconds")
	a = assume(t, s, c, noDuration, now())
	require.Equal(t, 200, a.status)
	assert.Equal(t, 3600, s.Sessions()[1].DurationSeconds, "STS's default")

	assert.Equal(t, "MalformedQueryString", send(t, s, c, call{method: "POST", host: STSHost, path: "/", body: "a=%zz", at: now()}).code())
	assert.Equal(t, "InvalidAction", send(t, s, c, call{method: "GET", host: STSHost, path: "/", at: now()}).code())
	assert.Equal(t, "SignatureDoesNotMatch", send(t, s, creds{keyID: c.keyID, secret: "wrong"}, call{method: "POST", host: STSHost, path: "/", body: "a=b", at: now()}).code())

	off.Store(int64(16 * time.Minute))
	assert.Equal(t, "ExpiredToken", zones(tmp, nil).code())
}

func TestAssumeRoleWithoutARoleOrAccount(t *testing.T) {
	s := Start(t, Options{})
	assert.Equal(t, "AccessDenied", assume(t, s, longTerm(s), roleForm(role, ""), time.Now()).code())
	s2 := Start(t, Options{RoleARN: "not-an-arn"})
	a := assume(t, s2, longTerm(s2), roleForm("not-an-arn", ""), time.Now())
	require.Equal(t, 200, a.status)
	assert.Contains(t, a.body, "arn:aws:sts::000000000000:assumed-role/not-an-arn/")
}

// ---- faults ----

func TestFaults(t *testing.T) {
	s := Start(t, Options{Zones: []Zone{{Name: "example.test"}}})
	c := longTerm(s)
	zones := func(ctx context.Context) answer {
		return send(t, s, c, call{method: "GET", path: "/2013-04-01/hostedzonesbyname", ctx: ctx})
	}
	cases := []struct {
		f      Fault
		status int
		code   string
	}{
		{Fault{Code: "Throttling"}, 400, "Throttling"},
		{Fault{Status: 403}, 403, "AccessDenied"},
		{Fault{Status: 404}, 404, "NoSuchHostedZone"},
		{Fault{Status: 429}, 429, "Throttling"},
		{Fault{Status: 503}, 503, "ServiceUnavailable"},
		{Fault{Status: 500}, 500, "InternalFailure"},
		{Fault{Status: 400}, 400, "InvalidInput"},
		{Fault{Code: codeInvalidChangeBatch}, 400, codeInvalidChangeBatch},
	}
	for _, tc := range cases {
		s.FailNext(OpZones, tc.f)
		a := zones(context.Background())
		assert.Equal(t, tc.status, a.status, tc.f)
		assert.Equal(t, tc.code, a.code(), tc.f)
	}
	var e errorXML
	s.FailNext(OpZones, Fault{Status: 502})
	require.NoError(t, xml.Unmarshal([]byte(zones(context.Background()).body), &e))
	assert.Equal(t, "Receiver", e.Error.Type)

	s.FailNext(OpZones, Fault{Body: "canary"})
	a := zones(context.Background())
	assert.Equal(t, answer{status: 200, body: "canary"}, a)
	s.FailNext(OpZones, Fault{Status: 418, Body: "teapot"})
	assert.Equal(t, answer{status: 418, body: "teapot"}, zones(context.Background()))

	s.FailNext(OpZones, Fault{Reset: true})
	assert.Error(t, zones(context.Background()).err)

	s.FailNext(OpZones, Fault{Delay: 20 * time.Millisecond})
	start := time.Now()
	assert.Equal(t, 200, zones(context.Background()).status, "a delay alone delays the real answer")
	assert.GreaterOrEqual(t, time.Since(start), 20*time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	s.FailNext(OpZones, Fault{Delay: 5 * time.Second, Status: 500})
	assert.Error(t, zones(ctx).err, "the delay honours the request's context")

	stop := s.FailAll(OpZones, Fault{Status: 500})
	for range 3 {
		assert.Equal(t, 500, zones(context.Background()).status)
	}
	stop()
	stop() // twice is harmless
	assert.Equal(t, 200, zones(context.Background()).status)

	s.FailNext(OpList, Fault{Status: 500}) // another operation's fault is not taken
	assert.Equal(t, 200, zones(context.Background()).status)

	s.FailNext(OpAssumeRole, Fault{Code: "Throttling"})
	assert.Equal(t, "Throttling", assume(t, s, c, roleForm(role, ""), time.Now()).code(), "faults answer before the role check")
	assert.Equal(t, 16, s.Counters()["fault"], "every fault answered; a delay alone and one cut short by the context are not")
}

func TestRequestLogHoldsNoSecrets(t *testing.T) {
	s := Start(t, Options{Zones: []Zone{{Name: "example.test"}}, RoleARN: role})
	c := longTerm(s)
	a := assume(t, s, c, roleForm(role, ""), time.Now())
	require.Equal(t, 200, a.status)
	cr := s.IssuedCredentials()[0]
	tmp := creds{keyID: cr.AccessKeyID, secret: cr.SecretAccessKey, token: cr.SessionToken}
	b := send(t, s, tmp, call{method: "POST", path: "/2013-04-01/hostedzone/" + s.ZoneID("example.test", false) + "/rrset/",
		body: changeBody("UPSERT", "_acme-challenge.example.test", 60, `"needle-value"`)})
	require.Equal(t, 200, b.status)
	log := fmt.Sprintf("%+v %#v", s.Requests(), s.Requests())
	for _, n := range []string{c.secret, cr.SecretAccessKey, cr.SessionToken, s.LastSignature(), "needle-value", "_acme-challenge"} {
		assert.NotContains(t, log, n)
	}
	reqs := s.Requests()
	require.Len(t, reqs, 2)
	assert.Equal(t, Request{Method: "POST", Host: STSHost, Path: "/", Op: OpAssumeRole, Status: 200}, reqs[0])
	assert.Equal(t, OpChange, reqs[1].Op)
	assert.Equal(t, map[string]int{OpAssumeRole: 1, OpChange: 1}, s.Counters())
}

func TestNewAndStart(t *testing.T) {
	s, err := New(Options{AccessKeyID: "FAKEFIXEDKEY0000", SecretAccessKey: "fixed-secret-value-0123"})
	require.NoError(t, err)
	defer s.Close()
	assert.Equal(t, "FAKEFIXEDKEY0000", s.AccessKeyID())
	assert.Equal(t, "fixed-secret-value-0123", s.SecretAccessKey())
	assert.Equal(t, 200, send(t, s, longTerm(s), call{method: "GET", path: "/2013-04-01/hostedzonesbyname"}).status)
}

func TestOperation(t *testing.T) {
	for _, tc := range []struct{ host, method, path, op string }{
		{Route53Host, "GET", "/2013-04-01/hostedzonesbyname", OpZones},
		{Route53Host, "GET", "/2013-04-01/hostedzone/Z1/rrset", OpList},
		{Route53Host, "POST", "/2013-04-01/hostedzone/Z1/rrset/", OpChange},
		{Route53Host, "GET", "/2013-04-01/change/C1", OpGetChange},
		{Route53Host, "PUT", "/2013-04-01/hostedzone/Z1/rrset", ""},
		{Route53Host, "GET", "/2012-01-01/change/C1", ""},
		{STSHost, "POST", "/", OpAssumeRole},
		{STSHost, "POST", "/x", ""},
	} {
		assert.Equal(t, tc.op, operation(tc.host, tc.method, tc.path), tc)
	}
	assert.Empty(t, pathPart("/a", 3))
}
