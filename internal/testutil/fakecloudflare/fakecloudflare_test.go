package fakecloudflare

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const base = "https://" + Host + prefix

// client reaches the fake through MapAddr, trusting its CA only.
func client(s *Server) *http.Client {
	d := &net.Dialer{}
	return &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, n, a string) (net.Conn, error) {
			return d.DialContext(ctx, n, s.MapAddr(a))
		},
		TLSClientConfig: &tls.Config{RootCAs: s.CAPool(), MinVersion: tls.VersionTLS12},
	}}
}

type answer struct {
	Status     int
	Success    bool            `json:"success"`
	Errors     []apiError      `json:"errors"`
	Messages   []apiError      `json:"messages"`
	Result     json.RawMessage `json:"result"`
	ResultInfo *resultInfo     `json:"result_info"`
	Raw        string          `json:"-"`
	Header     http.Header     `json:"-"`
}

func call(t *testing.T, s *Server, token, method, path, body string) answer {
	t.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	req, err := http.NewRequestWithContext(t.Context(), method, base+path, rd)
	require.NoError(t, err)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	res, err := client(s).Do(req)
	require.NoError(t, err)
	defer res.Body.Close()
	b, err := io.ReadAll(res.Body)
	require.NoError(t, err)
	a := answer{Status: res.StatusCode, Raw: string(b), Header: res.Header}
	_ = json.Unmarshal(b, &a)
	return a
}

func codes(a answer) []int {
	var out []int
	for _, e := range a.Errors {
		out = append(out, e.Code)
	}
	return out
}

type sink struct {
	mu  sync.Mutex
	set map[string][]string
}

func (k *sink) DNSSet(fqdn, v string) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.set == nil {
		k.set = map[string][]string{}
	}
	k.set[fqdn] = append(k.set[fqdn], v)
}

func (k *sink) DNSClear(fqdn, v string) {
	k.mu.Lock()
	defer k.mu.Unlock()
	var keep []string
	for _, x := range k.set[fqdn] {
		if x != v {
			keep = append(keep, x)
		}
	}
	k.set[fqdn] = keep
}

func TestZonesAndRecordsLifecycle(t *testing.T) {
	sk := &sink{}
	s := Start(t, Options{Zones: []string{"Example.com.", "sub.example.com"}, Sink: sk})
	tok := s.Token()
	assert.True(t, strings.HasPrefix(tok, "fake-cf-"))
	id := s.ZoneID("example.com")
	assert.Len(t, id, 32)
	assert.Empty(t, s.ZoneID("nope.com"))

	a := call(t, s, tok, "GET", "/zones?name=example.com&status=active&per_page=5", "")
	require.Equal(t, 200, a.Status, a.Raw)
	assert.True(t, a.Success)
	var zones []zoneJSON
	require.NoError(t, json.Unmarshal(a.Result, &zones))
	require.Len(t, zones, 1)
	assert.Equal(t, zoneJSON{ID: id, Name: "example.com", Status: "active", Type: "full",
		NameServers: []string{"ada.ns.cloudflare.com", "bob.ns.cloudflare.com"}, OriginalNameServers: []string{}}, zones[0])
	assert.Equal(t, &resultInfo{Page: 1, PerPage: 5, Count: 1, TotalCount: 1, TotalPages: 1}, a.ResultInfo)
	assert.Equal(t, "application/json", a.Header.Get("Content-Type"))

	a = call(t, s, tok, "GET", "/zones", "")
	require.NoError(t, json.Unmarshal(a.Result, &zones))
	assert.Len(t, zones, 2)
	a = call(t, s, tok, "GET", "/zones?status=pending", "")
	require.NoError(t, json.Unmarshal(a.Result, &zones))
	assert.Empty(t, zones)
	assert.Equal(t, "[]", string(a.Result))

	// Create: quoted content, then a duplicate (quoted or not) is 81058.
	a = call(t, s, tok, "POST", "/zones/"+id+"/dns_records", `{"type":"TXT","name":"_acme-challenge.example.com","content":"\"v1\"","ttl":60}`)
	require.Equal(t, 200, a.Status, a.Raw)
	assert.Empty(t, a.Messages)
	var rec recordJSON
	require.NoError(t, json.Unmarshal(a.Result, &rec))
	assert.Len(t, rec.ID, 32)
	assert.Equal(t, `"v1"`, rec.Content)
	assert.Equal(t, "example.com", rec.ZoneName)
	assert.NotEmpty(t, rec.CreatedOn)
	for _, c := range []string{`"\"v1\""`, `"v1"`} {
		a = call(t, s, tok, "POST", "/zones/"+id+"/dns_records", `{"type":"TXT","name":"_acme-challenge.example.com","content":`+c+`,"ttl":120}`)
		assert.Equal(t, 400, a.Status)
		assert.Equal(t, []int{81058}, codes(a))
		assert.False(t, a.Success)
	}
	// An unquoted value is accepted with a warning message.
	a = call(t, s, tok, "POST", "/zones/"+id+"/dns_records", `{"type":"TXT","name":"_ACME-challenge.example.com.","content":"v2","ttl":1}`)
	require.Equal(t, 200, a.Status, a.Raw)
	require.Len(t, a.Messages, 1)
	assert.Equal(t, 100, a.Messages[0].Code)
	assert.Equal(t, []string{"v1", "v2"}, s.TXT("_acme-challenge.example.com"))
	assert.ElementsMatch(t, []string{"v1", "v2"}, sk.set["_acme-challenge.example.com"])

	// List with filters and paging.
	other := s.AddRecord("example.com", "A", "www.example.com", "192.0.2.1", 300)
	assert.Len(t, other, 32)
	assert.Empty(t, s.AddRecord("nope.com", "TXT", "x.nope.com", "v", 60))
	a = call(t, s, tok, "GET", "/zones/"+id+"/dns_records?type=TXT&name=_acme-challenge.example.com&per_page=5&page=1", "")
	var recs []recordJSON
	require.NoError(t, json.Unmarshal(a.Result, &recs))
	assert.Len(t, recs, 2)
	assert.Equal(t, 1, a.ResultInfo.TotalPages)
	a = call(t, s, tok, "GET", "/zones/"+id+"/dns_records?content=v2", "")
	require.NoError(t, json.Unmarshal(a.Result, &recs))
	require.Len(t, recs, 1)
	a = call(t, s, tok, "GET", "/zones/"+id+"/dns_records", "")
	require.NoError(t, json.Unmarshal(a.Result, &recs))
	assert.Len(t, recs, 3)
	assert.Equal(t, 100, a.ResultInfo.PerPage)
	a = call(t, s, tok, "GET", "/zones/"+id+"/dns_records?per_page=5&page=9", "")
	assert.Equal(t, "[]", string(a.Result))

	// Delete: the record goes, the sink loses only that value, a second delete is 404 81044.
	a = call(t, s, tok, "DELETE", "/zones/"+id+"/dns_records/"+rec.ID, "")
	require.Equal(t, 200, a.Status, a.Raw)
	assert.JSONEq(t, `{"id":"`+rec.ID+`"}`, string(a.Result))
	assert.Equal(t, []string{"v2"}, s.TXT("_acme-challenge.example.com"))
	assert.Equal(t, []string{"v2"}, sk.set["_acme-challenge.example.com"])
	a = call(t, s, tok, "DELETE", "/zones/"+id+"/dns_records/"+rec.ID, "")
	assert.Equal(t, 404, a.Status)
	assert.Equal(t, []int{81044}, codes(a))
	assert.Len(t, s.Records(), 2)

	assert.Equal(t, map[string]int{OpZones: 3, OpCreate: 4, OpList: 4, OpDelete: 2}, s.Counters())
	for _, r := range s.Requests() {
		assert.NotContains(t, r.Path, "?")
		assert.NotZero(t, r.Status)
	}
}

func TestRefusals(t *testing.T) {
	s := Start(t, Options{Zones: []string{"example.com", "other.com"}, TokenZones: []string{"example.com"}})
	tok := s.Token()
	id, otherID := s.ZoneID("example.com"), s.ZoneID("other.com")
	rec := `{"type":"TXT","name":"_acme-challenge.example.com","content":"\"v\"","ttl":60}`
	for _, tc := range []struct {
		name, token, method, path, body string
		status                          int
		code                            int
	}{
		{"no header", "", "GET", "/zones", "", 400, 6003},
		{"wrong token", "not-the-token", "GET", "/zones", "", 401, 10000},
		{"unknown route", tok, "GET", "/accounts", "", 404, 7000},
		{"unknown zone sub-route", tok, "GET", "/zones/" + id + "/settings", "", 404, 7000},
		{"method", tok, "PUT", "/zones", "", 405, 7001},
		{"method on records", tok, "PATCH", "/zones/" + id + "/dns_records", "", 405, 7001},
		{"method on a record", tok, "GET", "/zones/" + id + "/dns_records/" + NewID(), "", 405, 7001},
		{"unknown zone", tok, "GET", "/zones/" + NewID() + "/dns_records", "", 404, 7003},
		{"zone outside the token", tok, "GET", "/zones/" + otherID + "/dns_records", "", 403, 10000},
		{"create outside the token", tok, "POST", "/zones/" + otherID + "/dns_records", rec, 403, 10000},
		{"delete outside the token", tok, "DELETE", "/zones/" + otherID + "/dns_records/" + NewID(), "", 403, 10000},
		{"create unknown zone", tok, "POST", "/zones/" + NewID() + "/dns_records", rec, 404, 7003},
		{"delete unknown zone", tok, "DELETE", "/zones/" + NewID() + "/dns_records/" + NewID(), "", 404, 7003},
		{"bad body", tok, "POST", "/zones/" + id + "/dns_records", "{", 400, 9207},
		{"not TXT", tok, "POST", "/zones/" + id + "/dns_records", `{"type":"A","name":"a.example.com","content":"192.0.2.1","ttl":60}`, 400, 1004},
		{"outside the zone", tok, "POST", "/zones/" + id + "/dns_records", `{"type":"TXT","name":"a.other.com","content":"v","ttl":60}`, 400, 9005},
		{"empty content", tok, "POST", "/zones/" + id + "/dns_records", `{"type":"TXT","name":"a.example.com","content":"","ttl":60}`, 400, 9009},
		{"low ttl", tok, "POST", "/zones/" + id + "/dns_records", `{"type":"TXT","name":"a.example.com","content":"v","ttl":30}`, 400, 9021},
		{"high ttl", tok, "POST", "/zones/" + id + "/dns_records", `{"type":"TXT","name":"a.example.com","content":"v","ttl":86401}`, 400, 9021},
		{"zones paging", tok, "GET", "/zones?per_page=500", "", 400, 1001},
		{"zones page", tok, "GET", "/zones?page=0", "", 400, 1001},
		{"records paging", tok, "GET", "/zones/" + id + "/dns_records?per_page=x", "", 400, 1001},
		{"records page", tok, "GET", "/zones/" + id + "/dns_records?page=x", "", 400, 1001},
	} {
		a := call(t, s, tc.token, tc.method, tc.path, tc.body)
		assert.Equal(t, tc.status, a.Status, tc.name)
		require.NotEmpty(t, a.Errors, tc.name)
		assert.Equal(t, tc.code, a.Errors[0].Code, tc.name)
		assert.False(t, a.Success, tc.name)
		assert.Equal(t, "null", string(a.Result), tc.name)
	}
	a := call(t, s, "", "GET", "/zones", "")
	assert.Equal(t, 6111, a.Errors[0].ErrorChain[0].Code)
	// The restricted token does not see the other zone.
	a = call(t, s, tok, "GET", "/zones?name=other.com", "")
	assert.Equal(t, "[]", string(a.Result))
	assert.Empty(t, s.Records())
}

func TestFaults(t *testing.T) {
	s := Start(t, Options{Zones: []string{"example.com"}})
	tok := s.Token()
	s.FailNext(OpZones, Fault{Status: 503})
	s.FailNext(OpZones, Fault{Status: 429, Code: 971})
	a := call(t, s, tok, "GET", "/zones", "")
	assert.Equal(t, 503, a.Status)
	assert.Equal(t, []int{1503}, codes(a))
	a = call(t, s, tok, "GET", "/zones", "")
	assert.Equal(t, 429, a.Status)
	assert.Equal(t, []int{971}, codes(a))
	assert.Equal(t, 200, call(t, s, tok, "GET", "/zones", "").Status)

	// A fault applies before the token is checked; an unknown route takes none.
	s.FailNext(OpList, Fault{Body: "CANARY-body"})
	a = call(t, s, "", "GET", "/zones/x/dns_records", "")
	assert.Equal(t, 200, a.Status)
	assert.Equal(t, "CANARY-body", a.Raw)
	s.FailNext(OpDelete, Fault{Status: 302, Location: "https://elsewhere.test/"})
	req, err := http.NewRequestWithContext(t.Context(), "DELETE", base+"/zones/x/dns_records/y", nil)
	require.NoError(t, err)
	c := client(s)
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	res, err := c.Do(req)
	require.NoError(t, err)
	_ = res.Body.Close()
	assert.Equal(t, 302, res.StatusCode)
	assert.Equal(t, "https://elsewhere.test/", res.Header.Get("Location"))

	stop := s.FailAll(OpCreate, Fault{Status: 500, Body: "{not json"})
	for range 2 {
		a = call(t, s, tok, "POST", "/zones/x/dns_records", "{}")
		assert.Equal(t, 500, a.Status)
		assert.Equal(t, "{not json", a.Raw)
	}
	stop()
	stop() // a second stop is harmless
	assert.Equal(t, 404, call(t, s, tok, "POST", "/zones/x/dns_records", "{}").Status)

	// Reset: the request fails, the log keeps status 0.
	s.FailNext(OpZones, Fault{Reset: true})
	req, err = http.NewRequestWithContext(t.Context(), "GET", base+"/zones", nil)
	require.NoError(t, err)
	_, err = client(s).Do(req) //nolint:bodyclose // no response
	require.Error(t, err)
	reqs := s.Requests()
	assert.Equal(t, Request{Method: "GET", Path: prefix + "/zones", Op: OpZones}, reqs[len(reqs)-1])

	// Delay: the real answer follows; a request that gives up first gets none.
	s.FailNext(OpZones, Fault{Delay: 20 * time.Millisecond})
	start := time.Now()
	assert.Equal(t, 200, call(t, s, tok, "GET", "/zones", "").Status)
	assert.GreaterOrEqual(t, time.Since(start), 20*time.Millisecond)
	s.FailNext(OpZones, Fault{Delay: time.Minute, Status: 500})
	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()
	req, err = http.NewRequestWithContext(ctx, "GET", base+"/zones", nil)
	require.NoError(t, err)
	_, err = client(s).Do(req) //nolint:bodyclose // no response
	require.Error(t, err)
}

func TestHandlerWithoutTheListenerAndResetOverHTTP2(t *testing.T) {
	s, err := New(Options{Token: "given-token-word", Zones: []string{"example.com"}})
	require.NoError(t, err)
	defer s.Close()
	assert.Equal(t, "given-token-word", s.Token())
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "http://anything"+prefix+"/zones", nil)
	req.Header.Set("Authorization", "Bearer given-token-word")
	s.Handler().ServeHTTP(rr, req)
	assert.Equal(t, 200, rr.Code)

	// A recorder cannot be hijacked: the reset aborts the handler instead.
	s.FailNext(OpZones, Fault{Reset: true})
	assert.PanicsWithValue(t, http.ErrAbortHandler, func() { s.Handler().ServeHTTP(httptest.NewRecorder(), req) })
}

func TestTLSAndMapAddr(t *testing.T) {
	s := Start(t, Options{})
	assert.Equal(t, s.Addr(), s.MapAddr("API.Cloudflare.com:443"))
	for _, a := range []string{"api.cloudflare.com:80", "example.com:443", "garbage"} {
		assert.Equal(t, a, s.MapAddr(a))
	}
	blk, _ := pem.Decode(s.CAPEM())
	require.NotNil(t, blk)
	assert.Equal(t, "CERTIFICATE", blk.Type)
	// The certificate names the API host only.
	conn, err := tls.Dial("tcp", s.Addr(), &tls.Config{RootCAs: s.CAPool(), ServerName: Host, MinVersion: tls.VersionTLS12})
	require.NoError(t, err)
	_ = conn.Close()
	_, err = tls.Dial("tcp", s.Addr(), &tls.Config{RootCAs: s.CAPool(), ServerName: "example.com", MinVersion: tls.VersionTLS12})
	require.Error(t, err)
	// TLSConfig is the listener's (a copy): another harness serves Handler with it.
	c := s.TLSConfig()
	require.Len(t, c.Certificates, 1)
	c.Certificates = nil
	assert.Len(t, s.TLSConfig().Certificates, 1, "a copy")
}

func TestRequestLogHasNoSecrets(t *testing.T) {
	s := Start(t, Options{Zones: []string{"example.com"}})
	id := s.ZoneID("example.com")
	call(t, s, s.Token(), "POST", "/zones/"+id+"/dns_records", `{"type":"TXT","name":"a.example.com","content":"\"body-word\"","ttl":60}`)
	call(t, s, s.Token(), "GET", "/zones?name=query-word", "")
	b, err := json.Marshal(s.Requests())
	require.NoError(t, err)
	for _, w := range []string{s.Token(), "body-word", "query-word", "Bearer"} {
		assert.NotContains(t, string(b), w)
	}
}

func TestUnquoteAndConcurrency(t *testing.T) {
	for in, want := range map[string]string{`"a"`: "a", `a`: "a", `"`: `"`, `""`: "", `"a`: `"a`} {
		assert.Equal(t, want, Unquote(in), in)
	}
	s := Start(t, Options{Zones: []string{"example.com"}})
	id := s.ZoneID("example.com")
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Go(func() {
			body := bytes.NewBufferString(`{"type":"TXT","name":"a.example.com","content":"\"v` + string(rune('a'+i)) + `\"","ttl":60}`)
			call(t, s, s.Token(), "POST", "/zones/"+id+"/dns_records", body.String())
			_ = s.Records()
			_ = s.Counters()
		})
	}
	wg.Wait()
	assert.Len(t, s.TXT("a.example.com"), 8)
}
