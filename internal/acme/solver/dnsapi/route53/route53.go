// Package route53 is the Amazon Route 53 DNS provider of the DNS-01 solver (R57): an IAM access key (optionally
// assuming a role through STS), hosted zone lookup by name, ChangeResourceRecordSets and the wait for INSYNC, over
// the Route 53 API 2013-04-01 signed with AWS Signature Version 4 (sigv4.go, no SDK).
//
// # What the credentials need
//
// The IAM policy of the access key (or of the role, when one is assumed) needs route53:ListHostedZonesByName,
// route53:ListResourceRecordSets, route53:ChangeResourceRecordSets and route53:GetChange, and with a role the access
// key needs sts:AssumeRole on it. The role session lasts SessionDuration (900 s, STS's minimum) and is renewed when
// less than two minutes remain.
//
// # Which zone
//
// Public hosted zones only: a private zone answers resolvers inside its VPCs, never the CA. Of the zones whose name
// is the record name or a parent of it, the longest wins (dnsapi.Candidates, one ListHostedZonesByName per
// candidate); when an account has several public zones of one name, the first Route 53 lists is used.
//
// # The TXT record set
//
// Route 53 holds one record set per name and type, so a value is added by reading the set and writing it back with
// the value added (UPSERT), and removed by writing back the rest, or by deleting the set when the value was its
// last. Another value at the name (a wildcard's and its base name's, or another tool's) is kept as Route 53 returned
// it. Two writers changing the same set at the same moment can still overwrite each other's value: Route 53 has no
// conditional write for record sets. A change is live when GetChange answers INSYNC.
package route53

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"alice/internal/acme"
	"alice/internal/acme/solver"
	"alice/internal/acme/solver/dnsapi"
	"alice/internal/platform/clock"
	"alice/internal/secrets"
)

// Hosts the provider sends requests to: the Route 53 API (global, signed for us-east-1) and STS (AssumeRole only).
const (
	Host    = "route53.amazonaws.com"
	STSHost = "sts.amazonaws.com"
	Region  = "us-east-1"
)

// Configuration errors (fixed texts).
var (
	ErrAccessKey  = errors.New("route53: the access key ID is not an AWS access key ID")
	ErrSecretKey  = errors.New("route53: the secret access key is empty or has characters a key cannot have")
	ErrRoleARN    = errors.New("route53: the role is not an IAM role ARN")
	ErrExternalID = errors.New("route53: the external ID is too long or has characters it cannot have")
)

var (
	accessKeyPattern  = regexp.MustCompile(`^[A-Z0-9]{16,128}$`)
	roleARNPattern    = regexp.MustCompile(`^arn:aws:iam::[0-9]{12}:role/[A-Za-z0-9+=,.@_/-]{1,512}$`)
	externalIDPattern = regexp.MustCompile(`^[A-Za-z0-9+=,.@:/-]+$`) // 2..1224 characters, checked apart: RE2 caps a repeat at 1000
)

// API paths (version 2013-04-01). The change path ends in "/" as in the API reference.
const (
	apiPrefix   = "/2013-04-01"
	zonesPath   = apiPrefix + "/hostedzonesbyname"
	zonePrefix  = "/hostedzone/"
	changeIDPfx = "/change/"
	zoneLookups = "10" // maxitems of one ListHostedZonesByName: zones of one name share a page
)

// Config configures a Provider.
type Config struct {
	// AccessKeyID is the IAM access key ID (public: shown in the UI and the audit log).
	AccessKeyID string
	// SecretAccessKey is its secret. New copies it; the caller zeroes its own.
	SecretAccessKey secrets.Plaintext
	// RoleARN, when set, is assumed through STS AssumeRole with the access key, and Route 53 is called with the
	// role's temporary credentials. ExternalID is sent with it when set.
	RoleARN    string
	ExternalID string
	// BaseRoots replaces the system roots when set (the e2e build's trust of its fake services).
	BaseRoots *x509.CertPool

	mapAddr func(string) string // the package's own tests
}

// String shows the access key ID and whether a role is assumed: never the secret.
func (c Config) String() string { return describe("route53.Config", c.AccessKeyID, c.RoleARN != "") }

// GoString is String.
func (c Config) GoString() string { return c.String() }

// Format keeps every verb on String.
func (c Config) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, c.String()) }

func describe(kind, keyID string, role bool) string {
	if !accessKeyPattern.MatchString(keyID) {
		keyID = "invalid"
	}
	r := "none"
	if role {
		r = "set"
	}
	return kind + "{AccessKeyID: " + keyID + ", Role: " + r + "}"
}

// Provider implements dnsapi.Provider for Route 53.
type Provider struct {
	keyID      string
	secret     secrets.Plaintext // the provider's copy
	role       string
	externalID string
	client     *http.Client
	now        func() time.Time
	random     io.Reader // the role session names

	mu          sync.Mutex
	temp        *credentials // the role's temporary credentials, nil before the first sign-in
	tempExpires time.Time
}

var _ dnsapi.Provider = (*Provider)(nil)

// New validates the configuration and builds the provider. It makes no network call.
func New(cfg Config) (*Provider, error) {
	if !accessKeyPattern.MatchString(cfg.AccessKeyID) {
		return nil, ErrAccessKey
	}
	if !secretShape(cfg.SecretAccessKey.Bytes()) {
		return nil, ErrSecretKey
	}
	if cfg.RoleARN != "" && !roleARNPattern.MatchString(cfg.RoleARN) {
		return nil, ErrRoleARN
	}
	if cfg.ExternalID != "" && (cfg.RoleARN == "" || len(cfg.ExternalID) < 2 || len(cfg.ExternalID) > 1224 ||
		!externalIDPattern.MatchString(cfg.ExternalID)) {
		return nil, ErrExternalID
	}
	client, err := dnsapi.NewHTTPClient(dnsapi.HTTPOptions{Hosts: []string{Host, STSHost}, Roots: cfg.BaseRoots, MapAddr: cfg.mapAddr})
	if err != nil {
		return nil, err
	}
	return &Provider{
		keyID: cfg.AccessKeyID, secret: secrets.NewPlaintext(bytes.Clone(cfg.SecretAccessKey.Bytes())),
		role: cfg.RoleARN, externalID: cfg.ExternalID, client: client, now: clock.Real{}.Now, random: rand.Reader,
	}, nil
}

// String shows the access key ID and whether a role is assumed: never a secret or a session token.
func (p *Provider) String() string { return describe("route53.Provider", p.keyID, p.role != "") }

// GoString is String.
func (p *Provider) GoString() string { return p.String() }

// Format keeps every verb on String.
func (p *Provider) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, p.String()) }

// Zero clears the provider's copy of the secret access key and its temporary credentials. The provider must not be
// used afterwards.
func (p *Provider) Zero() {
	p.secret.Zero()
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.temp != nil {
		p.temp.secret.Zero()
		p.temp.token.Zero()
		p.temp = nil
	}
}

// Kind implements dnsapi.Provider.
func (*Provider) Kind() string { return dnsapi.KindRoute53 }

// FindZone implements dnsapi.Provider: the first candidate name (longest first) that is a public hosted zone.
func (p *Provider) FindZone(ctx context.Context, fqdn string) (dnsapi.Zone, error) {
	d := domainOf(fqdn)
	for _, cand := range dnsapi.Candidates(fqdn) {
		q := url.Values{"dnsname": {cand}, "maxitems": {zoneLookups}}
		status, body, _, err := p.call(ctx, d, http.MethodGet, zonesPath, q, nil)
		if err != nil {
			return dnsapi.Zone{}, err
		}
		var a listZonesAnswer
		if xml.Unmarshal(body, &a) != nil || a.XMLName.Local != "ListHostedZonesByNameResponse" {
			return dnsapi.Zone{}, acme.DNSProviderError(d, status, false)
		}
		for _, z := range a.Zones {
			if n, ok := dnsapi.NormalizeZoneName(z.Name); !ok || n != cand || z.Config.PrivateZone == "true" {
				continue
			}
			id, ok := strings.CutPrefix(z.ID, zonePrefix)
			if !ok || !awsID.MatchString(id) {
				return dnsapi.Zone{}, acme.DNSProviderError(d, status, false)
			}
			return dnsapi.Zone{Name: cand, ID: id}, nil
		}
	}
	return dnsapi.Zone{}, acme.DNSZoneNotFound(d)
}

// txtSet is the TXT record set at a name as Route 53 holds it: values in Route 53's quoted form.
type txtSet struct {
	ttl    int
	values []string
}

// has reports whether the set holds value (compared as text, not in quoted form).
func (s *txtSet) has(value string) bool {
	return s != nil && indexOf(s.values, value) >= 0
}

func indexOf(raw []string, value string) int {
	for i, v := range raw {
		if unquoteTXT(v) == value {
			return i
		}
	}
	return -1
}

// AddTXT implements dnsapi.Provider: the set is written back with the value added (UPSERT), with ttl.
func (p *Provider) AddTXT(ctx context.Context, z dnsapi.Zone, fqdn, value string, ttl int) (string, error) {
	d := domainOf(fqdn)
	if !awsID.MatchString(z.ID) {
		return "", acme.DNSProviderError(d, 0, false)
	}
	cur, err := p.readTXT(ctx, d, z.ID, fqdn)
	if err != nil {
		return "", err
	}
	if cur.has(value) {
		return "", nil
	}
	var values []string
	if cur != nil {
		values = append(values, cur.values...)
	}
	values = append(values, quoteTXT(value))
	id, _, err := p.change(ctx, d, z.ID, "UPSERT", fqdn, ttl, values)
	return id, err
}

// RemoveTXT implements dnsapi.Provider: the rest of the set is written back, or the set is deleted when value was
// its last. It does not wait for the change to be INSYNC: nothing waits on a removal.
func (p *Provider) RemoveTXT(ctx context.Context, z dnsapi.Zone, fqdn, value string) error {
	d := domainOf(fqdn)
	if !awsID.MatchString(z.ID) {
		return acme.DNSProviderError(d, 0, false)
	}
	cur, err := p.readTXT(ctx, d, z.ID, fqdn)
	if err != nil || !cur.has(value) {
		return err
	}
	rest := append([]string(nil), cur.values...)
	for i := indexOf(rest, value); i >= 0; i = indexOf(rest, value) {
		rest = append(rest[:i], rest[i+1:]...)
	}
	if len(rest) > 0 {
		_, _, err = p.change(ctx, d, z.ID, "UPSERT", fqdn, cur.ttl, rest)
		return err
	}
	_, code, err := p.change(ctx, d, z.ID, "DELETE", fqdn, cur.ttl, cur.values)
	if err != nil && code == codeInvalidChangeBatch {
		// The set changed since it was read (deleted, or another value added): a DELETE must match the set exactly.
		// The answer's text says which, but is never read: the set is read again instead, and a value that is gone
		// is success.
		again, rerr := p.readTXT(ctx, d, z.ID, fqdn)
		if rerr == nil && !again.has(value) {
			return nil
		}
	}
	return err
}

// ChangeDone implements dnsapi.Provider: GetChange's INSYNC.
func (p *Provider) ChangeDone(ctx context.Context, changeID string) (bool, error) {
	id, ok := strings.CutPrefix(changeID, changeIDPfx)
	if !ok || !awsID.MatchString(id) {
		return false, acme.DNSProviderError("", 0, false)
	}
	status, body, _, err := p.call(ctx, "", http.MethodGet, apiPrefix+changeIDPfx+id, nil, nil)
	if err != nil {
		return false, err
	}
	var a changeAnswer
	if xml.Unmarshal(body, &a) != nil || a.XMLName.Local != "GetChangeResponse" || a.ID != changeID {
		return false, acme.DNSProviderError("", status, false)
	}
	switch a.Status {
	case "INSYNC":
		return true, nil
	case "PENDING":
		return false, nil
	}
	return false, acme.DNSProviderError("", status, false)
}

// readTXT reads the TXT set at fqdn (nil when there is none). ListResourceRecordSets starts at the name and type
// asked and returns the next set in Route 53's order when there is none there, so the answer's name and type are
// compared before it is used.
func (p *Provider) readTXT(ctx context.Context, d, zoneID, fqdn string) (*txtSet, error) {
	q := url.Values{"name": {fqdn + "."}, "type": {"TXT"}, "maxitems": {"1"}}
	status, body, _, err := p.call(ctx, d, http.MethodGet, apiPrefix+zonePrefix+zoneID+"/rrset", q, nil)
	if err != nil {
		return nil, err
	}
	var a listSetsAnswer
	if xml.Unmarshal(body, &a) != nil || a.XMLName.Local != "ListResourceRecordSetsResponse" {
		return nil, acme.DNSProviderError(d, status, false)
	}
	if len(a.Sets) == 0 {
		return nil, nil
	}
	s := a.Sets[0]
	if solver.ASCIILower(s.Name) != fqdn+"." || s.Type != "TXT" {
		return nil, nil
	}
	if len(s.Records) == 0 || s.TTL < 0 {
		return nil, acme.DNSProviderError(d, status, false)
	}
	return &txtSet{ttl: s.TTL, values: fromRecords(s.Records)}, nil
}

// change sends one ChangeResourceRecordSets of the TXT set at fqdn and returns the change's ID ("/change/<ID>")
// and, for a refused batch, the AWS error code.
func (p *Provider) change(ctx context.Context, d, zoneID, action, fqdn string, ttl int, values []string) (string, string, error) {
	req := changeRequest{Comment: changeComment, Changes: []change{{Action: action,
		Set: txtSetXML{Name: fqdn + ".", Type: "TXT", TTL: ttl, Records: toRecords(values)}}}}
	out, err := xml.Marshal(req)
	if err != nil {
		return "", "", acme.DNSProviderError(d, 0, false)
	}
	body := append([]byte(xml.Header), out...)
	status, answer, code, err := p.call(ctx, d, http.MethodPost, apiPrefix+zonePrefix+zoneID+"/rrset/", nil, body)
	if err != nil {
		return "", code, err
	}
	var a changeAnswer
	if xml.Unmarshal(answer, &a) != nil || a.XMLName.Local != "ChangeResourceRecordSetsResponse" {
		return "", "", acme.DNSProviderError(d, status, false)
	}
	if id, ok := strings.CutPrefix(a.ID, changeIDPfx); !ok || !awsID.MatchString(id) {
		return "", "", acme.DNSProviderError(d, status, false)
	}
	return a.ID, "", nil
}

// call sends one signed Route 53 request and returns the status and body of a 2xx answer. Any other answer is an
// *acme.Error from its status and AWS error code (also returned, for the callers that act on one).
func (p *Provider) call(ctx context.Context, d, method, path string, q url.Values, body []byte) (int, []byte, string, error) {
	creds, err := p.signingCredentials(ctx, d)
	if err != nil {
		return 0, nil, "", err
	}
	u := url.URL{Scheme: "https", Host: Host, Path: path, RawQuery: q.Encode()}
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), rd)
	if err != nil {
		return 0, nil, "", acme.DNSProviderError(d, 0, false)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/xml")
	}
	sign(req, body, creds, Region, "route53", p.now())
	status, _, answer, err := dnsapi.Do(ctx, p.client, req, d)
	if err != nil {
		return 0, nil, "", err
	}
	if status >= 200 && status < 300 {
		return status, answer, "", nil
	}
	code := errorCode(answer)
	e := apiError(d, status, code)
	if e.Reason == acme.ReasonDNSAuthFailed {
		p.dropTemporary(creds)
	}
	return status, nil, code, e
}

// domainOf is the name an error reports: the record name without the challenge label.
func domainOf(fqdn string) string { return strings.TrimPrefix(fqdn, solver.ChallengeLabel) }
