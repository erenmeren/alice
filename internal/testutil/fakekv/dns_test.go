package fakekv_test

import (
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/testutil/fakekv"
)

const mgmt = "https://management.azure.com"

// mgmtToken signs in with the client secret for the Resource Manager.
func mgmtToken(t *testing.T, s *fakekv.Server, c *fakekv.TestClient, scope string) string {
	t.Helper()
	form := url.Values{"grant_type": {"client_credentials"}, "client_id": {s.ClientID()}, "client_secret": {s.Secret()}, "scope": {scope}}
	r := c.Raw(t, http.MethodPost, "https://login.microsoftonline.com/"+s.TenantID()+"/oauth2/v2.0/token",
		http.Header{"Content-Type": {"application/x-www-form-urlencoded"}}, form.Encode())
	require.Equal(t, http.StatusOK, r.Status, string(r.Body))
	var tok struct {
		AccessToken string `json:"access_token"`
	}
	require.NoError(t, json.Unmarshal(r.Body, &tok))
	return tok.AccessToken
}

type armClient struct {
	t   *testing.T
	s   *fakekv.Server
	c   *fakekv.TestClient
	tok string
}

func newARM(t *testing.T, o fakekv.Options) *armClient {
	t.Helper()
	if o.DNSZones == nil {
		o.DNSZones = []string{"example.test", "www.example.test"}
	}
	s := fakekv.Start(t, o)
	c := s.TestClient()
	return &armClient{t: t, s: s, c: c, tok: mgmtToken(t, s, c, mgmt+"/.default")}
}

// do sends one request; path gets api-version 2018-05-01 unless it carries a query.
func (a *armClient) do(method, path, body string, hdr ...string) fakekv.Response {
	a.t.Helper()
	target := path
	if !strings.HasPrefix(path, "https://") {
		target = mgmt + path
	}
	if !strings.Contains(target, "?") {
		target += "?api-version=" + fakekv.DNSAPIVersion
	}
	h := http.Header{"Authorization": {"Bearer " + a.tok}}
	if body != "" {
		h.Set("Content-Type", "application/json")
	}
	for i := 0; i+1 < len(hdr); i += 2 {
		h.Set(hdr[i], hdr[i+1])
	}
	return a.c.Raw(a.t, method, target, h, body)
}

func armCode(t *testing.T, r fakekv.Response) string {
	t.Helper()
	var e struct {
		Error struct{ Code, Message string } `json:"error"`
	}
	require.NoError(t, json.Unmarshal(r.Body, &e), string(r.Body))
	require.NotEmpty(t, e.Error.Message)
	return e.Error.Code
}

func txtBody(ttl int, values ...string) string {
	recs := make([]any, 0, len(values))
	for _, v := range values {
		recs = append(recs, map[string]any{"value": []string{v}})
	}
	b, _ := json.Marshal(map[string]any{"properties": map[string]any{"TTL": ttl, "TXTRecords": recs, "metadata": map[string]string{"k": "v"}}})
	return string(b)
}

func TestDNSTokensAreChecked(t *testing.T) {
	now := time.Now()
	var mu sync.Mutex
	clock := func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	a := newARM(t, fakekv.Options{Now: clock})
	path := a.s.DNSZonesPath()

	r := a.c.Raw(t, http.MethodGet, mgmt+path+"?api-version="+fakekv.DNSAPIVersion, nil, "")
	assert.Equal(t, http.StatusUnauthorized, r.Status)
	assert.Equal(t, "AuthenticationFailed", armCode(t, r))
	assert.NotEmpty(t, r.Header.Get("WWW-Authenticate"))

	vault := a.s.TestClientToken()
	r = a.c.Raw(t, http.MethodGet, mgmt+path+"?api-version="+fakekv.DNSAPIVersion, http.Header{"Authorization": {"Bearer " + vault}}, "")
	assert.Equal(t, "InvalidAuthenticationTokenAudience", armCode(t, r), "a Key Vault token is not a Resource Manager token")

	r = a.c.Raw(t, http.MethodGet, mgmt+path+"?api-version="+fakekv.DNSAPIVersion, http.Header{"Authorization": {"Bearer forged"}}, "")
	assert.Equal(t, "InvalidAuthenticationToken", armCode(t, r))

	// The Resource Manager token is no Key Vault token either.
	r = a.c.Raw(t, http.MethodGet, a.s.VaultURL()+"/certificates?api-version="+fakekv.APIVersion, http.Header{"Authorization": {"Bearer " + a.tok}}, "")
	assert.Equal(t, http.StatusUnauthorized, r.Status)

	assert.Equal(t, http.StatusOK, a.do(http.MethodGet, path, "").Status)
	mu.Lock()
	now = now.Add(2 * time.Hour)
	mu.Unlock()
	r = a.do(http.MethodGet, path, "")
	assert.Equal(t, "ExpiredAuthenticationToken", armCode(t, r))

	// An unauthenticated request never consumes a fault.
	a.s.FailNext("/subscriptions/", fakekv.Fault{Status: http.StatusInternalServerError})
	r = a.c.Raw(t, http.MethodGet, mgmt+path+"?api-version="+fakekv.DNSAPIVersion, nil, "")
	assert.Equal(t, http.StatusUnauthorized, r.Status)
}

func TestDNSRoutingAndRefusals(t *testing.T) {
	a := newARM(t, fakekv.Options{DNSPrivateZones: []string{"private.test"}})
	zones := a.s.DNSZonesPath()
	sub, rg := a.s.DNSSubscriptionID(), a.s.DNSResourceGroup()
	assert.Equal(t, "alice-dns", rg)

	r := a.do(http.MethodGet, zones+"?api-version=2017-09-01", "")
	assert.Equal(t, "NoRegisteredProviderFound", armCode(t, r))
	r = a.do(http.MethodGet, "/subscriptions/"+sub+"/resourceGroups/"+rg+"/providers/Microsoft.Network/privateDnsZones", "")
	assert.Equal(t, "InvalidResourceType", armCode(t, r))
	r = a.do(http.MethodGet, strings.Replace(zones, sub, fakekv.UniqueClientID(), 1), "")
	assert.Equal(t, "SubscriptionNotFound", armCode(t, r))
	r = a.do(http.MethodGet, strings.Replace(zones, rg, "other", 1), "")
	assert.Equal(t, "ResourceGroupNotFound", armCode(t, r))
	assert.Equal(t, http.StatusMethodNotAllowed, a.do(http.MethodPost, zones, "").Status)
	assert.Equal(t, http.StatusMethodNotAllowed, a.do(http.MethodPatch, a.s.DNSRecordPath("example.test", "x"), "").Status)
	r = a.do(http.MethodGet, zones+"/example.test", "")
	assert.Equal(t, "NotFound", armCode(t, r))
	r = a.do(http.MethodGet, zones+"/example.test/A/www", "")
	assert.Equal(t, "NotFound", armCode(t, r))
	r = a.do(http.MethodGet, a.s.DNSRecordPath("missing.test", "x"), "")
	assert.Equal(t, "ParentResourceNotFound", armCode(t, r))
	r = a.do(http.MethodPut, a.s.DNSRecordPath("private.test", "x"), txtBody(60, "v"))
	assert.Equal(t, "ParentResourceNotFound", armCode(t, r), "a private zone has no public record sets")

	// ARM paths are case-insensitive.
	upper := "/SUBSCRIPTIONS/" + sub + "/RESOURCEGROUPS/" + "ALICE-DNS" + "/PROVIDERS/MICROSOFT.NETWORK/DNSZONES"
	assert.Equal(t, http.StatusOK, a.do(http.MethodGet, upper, "").Status)
}

func TestDNSZoneListingShapeAndPaging(t *testing.T) {
	a := newARM(t, fakekv.Options{DNSZones: []string{"a.test", "B.test.", "c.test"}, DNSPrivateZones: []string{"p.test"}, DNSPageSize: 2})
	a.s.SetDNSTXT("a.test", "_acme-challenge", 60, "x")
	var names, kinds []string
	next := a.s.DNSZonesPath()
	pages := 0
	for next != "" {
		r := a.do(http.MethodGet, next, "")
		require.Equal(t, http.StatusOK, r.Status, string(r.Body))
		var page struct {
			Value []struct {
				ID, Name, Type, Location string
				Properties               struct {
					ZoneType           string   `json:"zoneType"`
					NumberOfRecordSets int      `json:"numberOfRecordSets"`
					NameServers        []string `json:"nameServers"`
				} `json:"properties"`
			} `json:"value"`
			NextLink string `json:"nextLink"`
		}
		require.NoError(t, json.Unmarshal(r.Body, &page))
		for _, z := range page.Value {
			names = append(names, z.Name)
			kinds = append(kinds, z.Properties.ZoneType)
			assert.Equal(t, "Microsoft.Network/dnszones", z.Type)
			assert.Equal(t, "global", z.Location)
			assert.True(t, strings.HasSuffix(z.ID, "/dnszones/"+z.Name))
			assert.Len(t, z.Properties.NameServers, 4)
			if z.Name == "a.test" {
				assert.Equal(t, 3, z.Properties.NumberOfRecordSets)
			}
		}
		if page.NextLink != "" {
			assert.True(t, strings.HasPrefix(page.NextLink, mgmt+a.s.DNSZonesPath()+"?"), page.NextLink)
		}
		next = page.NextLink
		pages++
	}
	assert.Equal(t, []string{"a.test", "b.test", "c.test", "p.test"}, names)
	assert.Equal(t, []string{"Public", "Public", "Public", "Private"}, kinds)
	assert.Equal(t, 2, pages)

	r := a.do(http.MethodGet, a.s.DNSZonesPath()+"?api-version="+fakekv.DNSAPIVersion+"&$skipToken=x", "")
	assert.Equal(t, "InvalidSkipToken", armCode(t, r))
	r = a.do(http.MethodGet, a.s.DNSZonesPath()+"?api-version="+fakekv.DNSAPIVersion+"&$skipToken=99", "")
	assert.Equal(t, http.StatusBadRequest, r.Status)
}

type sink struct {
	mu  sync.Mutex
	ops []string
}

func (s *sink) DNSSet(fqdn, value string) {
	s.mu.Lock()
	s.ops = append(s.ops, "set "+fqdn+" "+value)
	s.mu.Unlock()
}
func (s *sink) DNSClear(fqdn, value string) {
	s.mu.Lock()
	s.ops = append(s.ops, "clear "+fqdn+" "+value)
	s.mu.Unlock()
}

func TestDNSRecordSetETagsAndSink(t *testing.T) {
	sk := &sink{}
	a := newARM(t, fakekv.Options{DNSSink: sk})
	path := a.s.DNSRecordPath("example.test", "_acme-challenge")

	r := a.do(http.MethodGet, path, "")
	assert.Equal(t, "NotFound", armCode(t, r))
	r = a.do(http.MethodPut, path, txtBody(60, "one"), "If-Match", "some-etag")
	assert.Equal(t, "PreconditionFailed", armCode(t, r), "If-Match on nothing")
	r = a.do(http.MethodPut, path, txtBody(60, "one"), "If-None-Match", "*")
	require.Equal(t, http.StatusCreated, r.Status, string(r.Body))
	etag := r.Header.Get("ETag")
	require.NotEmpty(t, etag)
	r = a.do(http.MethodPut, path, txtBody(60, "one"), "If-None-Match", "*")
	assert.Equal(t, "PreconditionFailed", armCode(t, r), "If-None-Match on a set that exists")

	r = a.do(http.MethodGet, path, "")
	require.Equal(t, http.StatusOK, r.Status)
	var rs struct {
		ID, Name, Type, Etag string
		Properties           struct {
			TTL        int               `json:"TTL"`
			Fqdn       string            `json:"fqdn"`
			Metadata   map[string]string `json:"metadata"`
			TXTRecords []struct {
				Value []string `json:"value"`
			} `json:"TXTRecords"`
		} `json:"properties"`
	}
	require.NoError(t, json.Unmarshal(r.Body, &rs))
	assert.Equal(t, etag, rs.Etag)
	assert.Equal(t, "_acme-challenge", rs.Name)
	assert.Equal(t, "Microsoft.Network/dnszones/TXT", rs.Type)
	assert.Equal(t, "_acme-challenge.example.test.", rs.Properties.Fqdn)
	assert.Equal(t, map[string]string{"k": "v"}, rs.Properties.Metadata)
	assert.Equal(t, 60, rs.Properties.TTL)

	r = a.do(http.MethodPut, path, txtBody(120, "one", "two"), "If-Match", "stale")
	assert.Equal(t, http.StatusPreconditionFailed, r.Status)
	r = a.do(http.MethodPut, path, txtBody(120, "one", "two"), "If-Match", etag)
	require.Equal(t, http.StatusOK, r.Status)
	assert.NotEqual(t, etag, r.Header.Get("ETag"))
	assert.Equal(t, map[string][]string{"_acme-challenge.example.test": {"one", "two"}}, a.s.DNSRecords())
	assert.Equal(t, 120, a.s.DNSRecordTTL("_acme-challenge.example.test"))
	assert.Equal(t, map[string]string{"k": "v"}, a.s.DNSRecordMetadata("_acme-challenge.example.test"))
	assert.Zero(t, a.s.DNSRecordTTL("nothing.example.test"))
	assert.Nil(t, a.s.DNSRecordMetadata("nothing.example.test"))

	r = a.do(http.MethodPut, path, txtBody(120, "two"), "If-Match", "*")
	require.Equal(t, http.StatusOK, r.Status)
	r = a.do(http.MethodDelete, path, "", "If-Match", "stale")
	assert.Equal(t, http.StatusPreconditionFailed, r.Status)
	r = a.do(http.MethodDelete, path, "", "If-Match", r.Header.Get("x-none"))
	assert.Equal(t, http.StatusOK, r.Status, "an empty If-Match is no condition")
	r = a.do(http.MethodDelete, path, "")
	assert.Equal(t, http.StatusNoContent, r.Status, "deleting what is not there")
	assert.Empty(t, a.s.DNSRecords())

	// The apex.
	r = a.do(http.MethodPut, a.s.DNSRecordPath("www.example.test", "@"), txtBody(60, "apex"))
	require.Equal(t, http.StatusCreated, r.Status)
	assert.Equal(t, []string{"apex"}, a.s.DNSRecords()["www.example.test"])

	sk.mu.Lock()
	defer sk.mu.Unlock()
	assert.Equal(t, []string{
		"set _acme-challenge.example.test one",
		"set _acme-challenge.example.test two",
		"clear _acme-challenge.example.test one",
		"clear _acme-challenge.example.test two",
		"set www.example.test apex",
	}, sk.ops)
}

func TestDNSBadBodiesAndReadOnly(t *testing.T) {
	a := newARM(t, fakekv.Options{})
	path := a.s.DNSRecordPath("example.test", "x")
	for _, body := range []string{
		"{not json", `{}`, `{"properties":{}}`, `{"properties":{"TTL":0,"TXTRecords":[{"value":["v"]}]}}`,
		`{"properties":{"TTL":60,"TXTRecords":[]}}`, `{"properties":{"TTL":60,"TXTRecords":[{"value":[]}]}}`,
		`{"properties":{"TTL":60,"TXTRecords":[{"value":["` + strings.Repeat("v", 1025) + `"]}]}}`,
		`{"properties":{"TTL":60,"TXTRecords":[{"value":["1","2","3","4","5","6","7","8","9","10","11"]}]}}`,
	} {
		r := a.do(http.MethodPut, path, body)
		assert.Equal(t, "BadRequest", armCode(t, r), body)
	}
	assert.Equal(t, http.StatusBadRequest, a.c.Raw(t, http.MethodPut, mgmt+path+"?api-version="+fakekv.DNSAPIVersion,
		http.Header{"Authorization": {"Bearer " + a.tok}}, "").Status, "no body")

	a.s.SetDNSReadOnly(true)
	r := a.do(http.MethodPut, path, txtBody(60, "v"))
	assert.Equal(t, http.StatusForbidden, r.Status)
	assert.Equal(t, "AuthorizationFailed", armCode(t, r))
	assert.Contains(t, string(r.Body), a.s.ObjectID())
	assert.Equal(t, http.StatusForbidden, a.do(http.MethodDelete, path, "").Status)
	assert.Equal(t, http.StatusNotFound, a.do(http.MethodGet, path, "").Status, "reads are allowed")
	a.s.SetDNSReadOnly(false)
	assert.Equal(t, http.StatusCreated, a.do(http.MethodPut, path, txtBody(60, "v")).Status)

	a.s.SetDNSTXT("example.test", "x", 0)
	assert.Empty(t, a.s.DNSRecords(), "no values deletes")
}

func TestDNSFaultsAndLog(t *testing.T) {
	a := newARM(t, fakekv.Options{})
	path := a.s.DNSRecordPath("example.test", "x")
	a.s.FailNext(path, fakekv.Fault{})
	a.s.FailNext(path, fakekv.Fault{Status: http.StatusTooManyRequests, RetryAfter: "3"})
	assert.Equal(t, http.StatusNotFound, a.do(http.MethodGet, path, "").Status, "a pass-through fault is the real answer")
	r := a.do(http.MethodPut, path, txtBody(60, "v"))
	assert.Equal(t, http.StatusTooManyRequests, r.Status)
	assert.Equal(t, "3", r.Header.Get("Retry-After"))
	assert.Equal(t, "Throttled", armCode(t, r), "the ARM error shape")
	assert.Empty(t, a.s.DNSRecords(), "the fault answered instead of the route")

	stop := a.s.FailAll(a.s.DNSZonesPath(), fakekv.Fault{Status: http.StatusServiceUnavailable})
	assert.Equal(t, http.StatusServiceUnavailable, a.do(http.MethodGet, a.s.DNSZonesPath(), "").Status)
	assert.Equal(t, http.StatusServiceUnavailable, a.do(http.MethodGet, path, "").Status, "the listing's key covers the record sets")
	stop()

	log := fmt.Sprintf("%#v", a.s.Requests())
	assert.NotContains(t, log, a.tok)
	assert.NotContains(t, log, a.s.Secret())
	var mgmtSeen bool
	for _, r := range a.s.Requests() {
		if r.Host == "management.azure.com" {
			mgmtSeen = true
			assert.Equal(t, []string{"api-version"}, r.Query)
			assert.True(t, r.HadAuth)
			assert.NotZero(t, r.Status)
		}
	}
	assert.True(t, mgmtSeen)
	assert.Equal(t, a.s.DialAddr("login.microsoftonline.com:443"), a.s.DialAddr("Management.Azure.com:443"))
	leaf, err := x509.ParseCertificate(a.s.TLSConfig().Certificates[0].Certificate[0])
	require.NoError(t, err)
	assert.Contains(t, leaf.DNSNames, "management.azure.com")
}

func TestDNSManagedIdentityToken(t *testing.T) {
	mi := fakekv.UniqueClientID()
	s := fakekv.Start(t, fakekv.Options{ManagedIdentity: true, MIClientID: mi, DNSZones: []string{"example.test"}})
	c := s.TestClient()
	r := c.Raw(t, http.MethodGet, "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource="+
		url.QueryEscape(mgmt)+"&client_id="+mi, http.Header{"Metadata": {"true"}}, "")
	require.Equal(t, http.StatusOK, r.Status)
	var tok struct {
		AccessToken string `json:"access_token"`
	}
	require.NoError(t, json.Unmarshal(r.Body, &tok))
	r = c.Raw(t, http.MethodGet, mgmt+s.DNSZonesPath()+"?api-version="+fakekv.DNSAPIVersion, http.Header{"Authorization": {"Bearer " + tok.AccessToken}}, "")
	assert.Equal(t, http.StatusOK, r.Status)
}
