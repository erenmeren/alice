// Package cloudflare is the Cloudflare DNS provider of the DNS-01 solver (R57): an API token (a Bearer token with
// the Zone:Read and DNS:Edit permissions of the zones it may change), zone lookup by name, TXT record create and
// delete over https://api.cloudflare.com/client/v4.
//
// # What is sent
//
//	GET    /zones?name=<candidate>&per_page=5&status=active      (one per candidate zone name, longest first)
//	POST   /zones/<zone id>/dns_records                          {"type":"TXT","name":<fqdn>,"content":"\"<value>\"","ttl":<ttl>}
//	GET    /zones/<zone id>/dns_records?name=<fqdn>&page=<n>&per_page=100&type=TXT
//	DELETE /zones/<zone id>/dns_records/<record id>
//
// Every request carries "Authorization: Bearer <token>". The TXT content is sent as one quoted character string:
// Cloudflare's documentation asks for the quotes (an unquoted value is accepted with a warning), and the value of a
// DNS-01 challenge is base64url, so it never holds a quote or a backslash that would need escaping. The TTL is at
// least MinTTL: Cloudflare refuses a lower one outside the Enterprise plan, and its TTL 1 means "automatic" (300 s),
// never what the solver asked for.
//
// # Answers
//
// Cloudflare answers every call with {"success":bool,"errors":[{"code":int,"message":string}],"result":...}. Only the
// status, the success flag and the error codes are read: a message text is the provider's own words and could carry
// anything, so it never reaches an error. A zone or record ID goes into a URL path and must be 32 lower-case hex
// characters, whatever the answer says.
package cloudflare

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"

	"alice/internal/acme"
	"alice/internal/acme/solver"
	"alice/internal/acme/solver/dnsapi"
	"alice/internal/secrets"
)

// Host is the only host the provider sends a request to.
const Host = "api.cloudflare.com"

// Limits of the provider.
const (
	// MinTTL is the lowest TTL Cloudflare accepts outside the Enterprise plan; a lower one is raised to it.
	MinTTL = 60
	// MinTokenBytes and MaxTokenBytes bound an API token (Cloudflare's are 40 characters today).
	MinTokenBytes = 20
	MaxTokenBytes = 256
	// MaxRecordPages caps the pages of one record listing (100 records each): a name with more TXT records than
	// that is not a challenge name.
	MaxRecordPages = 5

	baseURL        = "https://" + Host + "/client/v4"
	zonesPerPage   = 5
	recordsPerPage = 100
	// codeIdentical is Cloudflare's "An identical record already exists." (an earlier attempt's record).
	codeIdentical = 81058
)

// authCodes are Cloudflare's error codes of a refused credential that it answers with a 400 (an invalid or
// malformed token, invalid request headers): reported as a 403 so they read as acme.ReasonDNSAuthFailed.
var authCodes = map[int]bool{10000: true, 9109: true, 9106: true, 6003: true, 6111: true}

var (
	// ErrToken is a token that is empty, too long or not printable ASCII.
	ErrToken = errors.New("cloudflare: the API token is empty or has characters a token cannot have")
	// ErrClient is an HTTP client that could not be built (an address mapping without roots).
	ErrClient = errors.New("cloudflare: the HTTP client could not be built")
)

// Config configures a Provider.
type Config struct {
	// APIToken is the Cloudflare API token (never a Global API Key). New copies it; the caller zeroes its own.
	APIToken secrets.Plaintext
	// BaseRoots replaces the system roots when set (the e2e build's trust of its fake services).
	BaseRoots *x509.CertPool

	mapAddr func(string) string // the package's own tests
}

// String never shows the token.
func (c Config) String() string { return "cloudflare.Config{APIToken: redacted}" }

// GoString is String.
func (c Config) GoString() string { return c.String() }

// Format keeps every verb on String.
func (c Config) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, c.String()) }

// Provider implements dnsapi.Provider for Cloudflare.
type Provider struct {
	token  secrets.Plaintext // the provider's own copy; Zero clears it
	zeroed atomic.Bool
	client *http.Client
}

var _ dnsapi.Provider = (*Provider)(nil)

// New validates the configuration and builds the provider. It makes no network call.
func New(cfg Config) (*Provider, error) {
	tok := cfg.APIToken.Bytes()
	if !validToken(tok) {
		return nil, ErrToken
	}
	client, err := dnsapi.NewHTTPClient(dnsapi.HTTPOptions{Hosts: []string{Host}, Roots: cfg.BaseRoots, MapAddr: cfg.mapAddr})
	if err != nil {
		return nil, ErrClient
	}
	return &Provider{token: secrets.NewPlaintext(append([]byte(nil), tok...)), client: client}, nil
}

// validToken admits MinTokenBytes..MaxTokenBytes of printable ASCII without a space: the token is an HTTP header
// value, and a space or a control character would change the header's meaning.
func validToken(b []byte) bool {
	if len(b) < MinTokenBytes || len(b) > MaxTokenBytes {
		return false
	}
	for _, c := range b {
		if c < 0x21 || c > 0x7e {
			return false
		}
	}
	return true
}

// Zero overwrites the provider's copy of the token, once the provider is no longer used: every later call fails
// before anything is sent (acme.ReasonDNSProviderError, permanent).
func (p *Provider) Zero() {
	p.zeroed.Store(true)
	p.token.Zero()
}

// String never shows the token.
func (p *Provider) String() string { return "cloudflare.Provider{token: redacted}" }

// GoString is String.
func (p *Provider) GoString() string { return p.String() }

// Format keeps every verb on String.
func (p *Provider) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, p.String()) }

// Kind implements dnsapi.Provider.
func (*Provider) Kind() string { return dnsapi.KindCloudflare }

// FindZone asks for each candidate zone name, longest first, and takes the first active zone Cloudflare has by
// exactly that name. A token limited to some zones sees only those: a zone outside them reads as not found.
func (p *Provider) FindZone(ctx context.Context, fqdn string) (dnsapi.Zone, error) {
	d := domainOf(fqdn)
	for _, cand := range dnsapi.Candidates(fqdn) {
		q := url.Values{"name": {cand}, "status": {"active"}, "per_page": {strconv.Itoa(zonesPerPage)}}
		var zones []struct {
			ID     string `json:"id"`
			Name   string `json:"name"`
			Status string `json:"status"`
		}
		if _, err := p.call(ctx, http.MethodGet, "/zones", q, nil, d, &zones); err != nil {
			return dnsapi.Zone{}, err
		}
		for _, z := range zones {
			n, ok := dnsapi.NormalizeZoneName(z.Name)
			if ok && n == cand && validID(z.ID) && (z.Status == "" || z.Status == "active") {
				return dnsapi.Zone{Name: n, ID: z.ID}, nil
			}
		}
	}
	return dnsapi.Zone{}, acme.DNSZoneNotFound(d)
}

// AddTXT creates one TXT record with the value. Cloudflare keeps every record of a name apart, so the other values
// at the name stay; an identical record (an earlier attempt's) is success. The record is live at once.
func (p *Provider) AddTXT(ctx context.Context, z dnsapi.Zone, fqdn, value string, ttl int) (string, error) {
	d := domainOf(fqdn)
	if !validID(z.ID) {
		return "", acme.DNSProviderError(d, 0, false)
	}
	ttl = max(ttl, MinTTL)
	body, err := json.Marshal(struct {
		Type    string `json:"type"`
		Name    string `json:"name"`
		Content string `json:"content"`
		TTL     int    `json:"ttl"`
	}{"TXT", fqdn, quote(value), ttl})
	if err != nil {
		return "", acme.DNSProviderError(d, 0, false)
	}
	a, err := p.exchange(ctx, http.MethodPost, "/zones/"+z.ID+"/dns_records", nil, body, d)
	if err != nil {
		return "", err
	}
	if (a.status == http.StatusBadRequest || ok2xx(a.status)) && a.hasCode(codeIdentical) {
		return "", nil
	}
	if err := a.check(d); err != nil {
		return "", err
	}
	return "", nil
}

// RemoveTXT lists the TXT records at fqdn (up to MaxRecordPages pages), then deletes every one whose content is the
// value, quoted or not. A record that is gone already (404) and a value that is not there are success.
func (p *Provider) RemoveTXT(ctx context.Context, z dnsapi.Zone, fqdn, value string) error {
	d := domainOf(fqdn)
	if !validID(z.ID) {
		return acme.DNSProviderError(d, 0, false)
	}
	var ids []string
	for page := 1; page <= MaxRecordPages; page++ {
		q := url.Values{"type": {"TXT"}, "name": {fqdn}, "per_page": {strconv.Itoa(recordsPerPage)}, "page": {strconv.Itoa(page)}}
		var recs []struct {
			ID      string `json:"id"`
			Type    string `json:"type"`
			Name    string `json:"name"`
			Content string `json:"content"`
		}
		a, err := p.call(ctx, http.MethodGet, "/zones/"+z.ID+"/dns_records", q, nil, d, &recs)
		if err != nil {
			return err
		}
		for _, r := range recs {
			if r.Type != "TXT" || !strings.EqualFold(strings.TrimSuffix(r.Name, "."), fqdn) || (r.Content != value && r.Content != quote(value)) {
				continue
			}
			if !validID(r.ID) {
				// The record's ID goes into the DELETE path: an answer that is not an ID is refused.
				return acme.DNSProviderError(d, a.status, false)
			}
			ids = append(ids, r.ID)
		}
		if a.info.TotalPages <= page {
			break
		}
	}
	for _, id := range ids {
		a, err := p.exchange(ctx, http.MethodDelete, "/zones/"+z.ID+"/dns_records/"+id, nil, nil, d)
		if err != nil {
			return err
		}
		if a.status == http.StatusNotFound {
			continue
		}
		if err := a.check(d); err != nil {
			return err
		}
	}
	return nil
}

// ChangeDone implements dnsapi.Provider: a Cloudflare record is live on its servers when the create returns.
func (*Provider) ChangeDone(context.Context, string) (bool, error) { return true, nil }

// answer is one parsed Cloudflare answer: the status, whether the body was the API's envelope, its success flag,
// its error codes (never the messages) and the listing's page count.
type answer struct {
	status  int
	parsed  bool
	success bool
	codes   []int
	result  json.RawMessage
	info    struct {
		TotalPages int `json:"total_pages"`
	}
}

func (a answer) hasCode(c int) bool {
	for _, x := range a.codes {
		if x == c {
			return true
		}
	}
	return false
}

// check turns an answer that is not a success into a fixed *acme.Error: the status and nothing of the body. A
// refused credential Cloudflare answers with a 400 reads as a 403.
func (a answer) check(d string) error {
	if ok2xx(a.status) && a.parsed && a.success {
		return nil
	}
	status := a.status
	if status == http.StatusBadRequest {
		for _, c := range a.codes {
			if authCodes[c] {
				status = http.StatusForbidden
				break
			}
		}
	}
	return acme.DNSProviderError(d, status, false)
}

// call is exchange and check, with the result decoded into out.
func (p *Provider) call(ctx context.Context, method, path string, q url.Values, body []byte, d string, out any) (answer, error) {
	a, err := p.exchange(ctx, method, path, q, body, d)
	if err != nil {
		return a, err
	}
	if err := a.check(d); err != nil {
		return a, err
	}
	if err := json.Unmarshal(a.result, out); err != nil {
		return a, acme.DNSProviderError(d, a.status, false)
	}
	return a, nil
}

// exchange sends one request and parses the envelope. The error is a transport failure only (or a dead context);
// a refusal is in the answer, for the caller to judge.
func (p *Provider) exchange(ctx context.Context, method, path string, q url.Values, body []byte, d string) (answer, error) {
	if p.zeroed.Load() {
		return answer{}, acme.DNSProviderError(d, 0, false)
	}
	u := baseURL + path
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, rd)
	if err != nil {
		return answer{}, acme.DNSProviderError(d, 0, false)
	}
	req.Header.Set("Authorization", "Bearer "+string(p.token.Bytes()))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	status, _, raw, err := dnsapi.Do(ctx, p.client, req, d)
	if err != nil {
		return answer{}, err
	}
	a := answer{status: status}
	var env struct {
		Success *bool `json:"success"`
		Errors  []struct {
			Code       int `json:"code"`
			ErrorChain []struct {
				Code int `json:"code"`
			} `json:"error_chain"`
		} `json:"errors"`
		Result     json.RawMessage `json:"result"`
		ResultInfo json.RawMessage `json:"result_info"`
	}
	if json.Unmarshal(raw, &env) != nil || env.Success == nil {
		return a, nil
	}
	a.parsed, a.success, a.result = true, *env.Success, env.Result
	for _, e := range env.Errors {
		a.codes = append(a.codes, e.Code)
		for _, c := range e.ErrorChain {
			a.codes = append(a.codes, c.Code)
		}
	}
	if len(env.ResultInfo) > 0 && json.Unmarshal(env.ResultInfo, &a.info) != nil {
		a.parsed = false
	}
	return a, nil
}

func ok2xx(status int) bool { return status >= 200 && status < 300 }

// validID admits Cloudflare's IDs only: 32 lower-case hex characters (they go into URL paths).
func validID(id string) bool {
	if len(id) != 32 {
		return false
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

func quote(v string) string { return `"` + v + `"` }

// domainOf is the name an error reports: the fqdn without the challenge label.
func domainOf(fqdn string) string { return strings.TrimPrefix(fqdn, solver.ChallengeLabel) }
