// Package azuredns is the Azure DNS provider of the DNS-01 solver (R57): a Microsoft Entra ID service principal
// (client secret or certificate) or the managed identity of the machine Alice runs on, signed in with the same
// azidentity credentials and guards as the Key Vault provider (public cloud only, the configured tenant only, a token
// for the Azure Resource Manager only), and the DNS zones of one subscription and resource group over
// https://management.azure.com (Microsoft.Network/dnsZones, api-version 2018-05-01).
//
// # What the identity needs
//
// Reader on the resource group (the zone listing) and "DNS Zone Contributor" on the zone or the resource group (the
// TXT record sets). Public zones only: a zone the listing reports as "Private" is skipped (Azure Private DNS is a
// different resource type, and the CA cannot see it anyway).
//
// # The record set
//
// Azure DNS names a record set relative to its zone ("_acme-challenge.www", "@" for the apex) and keeps every TXT
// value of a name in one record set. An add reads the set and writes it back with the value added (If-None-Match: *
// when there is none, If-Match: <etag> otherwise), a removal writes it back without the value (or deletes it with
// If-Match when that was the last one); a 412 (someone else changed the set in between) re-reads and tries again, at
// most three times. A change is live on Azure's name servers at once: AddTXT returns no change to poll.
package azuredns

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"

	"alice/internal/acme"
	"alice/internal/acme/solver"
	"alice/internal/acme/solver/dnsapi"
	"alice/internal/platform/azureid"
	"alice/internal/secrets"
)

// Sign-in methods (the same values as the Key Vault credential's, providers.AzureAuth*).
const (
	AuthClientSecret    = "client_secret"
	AuthCertificate     = "certificate"
	AuthManagedIdentity = "managed_identity"
)

// Fixed endpoints.
const (
	ManagementHost  = "management.azure.com"
	ManagementScope = "https://management.azure.com/.default"
	APIVersion      = "2018-05-01"
)

// Limits.
const (
	// MaxClientSecretBytes is the longest client secret New accepts.
	MaxClientSecretBytes = 1024
	// MaxResourceGroupLen is Azure's limit of a resource group name.
	MaxResourceGroupLen = 90
	// MaxZonePages caps the pages of one zone listing.
	MaxZonePages = 10
	// MaxPreconditionRetries is how often an add or a removal re-reads the record set after a 412.
	MaxPreconditionRetries = 3
)

// Configuration errors (fixed texts).
var (
	ErrIdentity      = errors.New("azuredns: the sign-in identity is not complete or not valid")
	ErrSubscription  = errors.New("azuredns: the subscription ID is not a GUID")
	ErrResourceGroup = errors.New("azuredns: the resource group name is not valid")
)

// Config configures a Provider.
type Config struct {
	Auth string // Auth*
	// TenantID is the directory (tenant) GUID; empty for a managed identity.
	TenantID string
	// ClientID is the application (client) GUID; for a managed identity the optional user-assigned client ID.
	ClientID string
	// ClientSecret (AuthClientSecret); New copies it, the caller zeroes its own.
	ClientSecret secrets.Plaintext
	// CertificateDER and PrivateKeyDER (AuthCertificate): the registered certificate and its RSA key, PKCS #8.
	CertificateDER []byte
	PrivateKeyDER  secrets.Plaintext
	// SubscriptionID (a GUID) and ResourceGroup hold the DNS zones.
	SubscriptionID string
	ResourceGroup  string
	// BaseRoots replaces the system roots when set (the e2e build's trust of its fake services).
	BaseRoots *x509.CertPool

	mapAddr func(string) string // the package's own tests
}

// String names the sign-in method, the tenant, the client, the subscription and the resource group: never a
// secret or a key.
func (c Config) String() string {
	return describe("azuredns.Config", c.Auth, c.TenantID, c.ClientID, c.SubscriptionID, c.ResourceGroup)
}

// GoString is String.
func (c Config) GoString() string { return c.String() }

// Format keeps every verb on String.
func (c Config) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, c.String()) }

func describe(name, auth, tenant, client, sub, rg string) string {
	return name + "{auth: " + auth + ", tenant: " + tenant + ", client: " + client + ", subscription: " + sub +
		", resource_group: " + rg + "}"
}

// Provider implements dnsapi.Provider for Azure DNS. It is safe for concurrent use.
type Provider struct {
	auth, tenant, client, sub, rg string
	zonesRaw                      string // the escaped path of the zone listing
	zonesPath                     string // the same, unescaped (a nextLink must name it)
	mgmt                          *http.Client

	mu   sync.Mutex
	cred azcore.TokenCredential // nil once Zero ran
}

var _ dnsapi.Provider = (*Provider)(nil)

// New validates the configuration and builds the provider (the credential, no token yet). It makes no network call.
func New(cfg Config) (*Provider, error) {
	id, err := validIdentity(cfg)
	if err != nil {
		return nil, err
	}
	sub, ok := azureid.NormalizeGUID(cfg.SubscriptionID)
	if !ok {
		return nil, ErrSubscription
	}
	if !validResourceGroup(cfg.ResourceGroup) {
		return nil, ErrResourceGroup
	}
	p := &Provider{auth: id.auth, tenant: id.tenant, client: id.client, sub: sub, rg: cfg.ResourceGroup}
	p.zonesPath = "/subscriptions/" + sub + "/resourceGroups/" + cfg.ResourceGroup + "/providers/Microsoft.Network/dnsZones"
	p.zonesRaw = "/subscriptions/" + sub + "/resourceGroups/" + url.PathEscape(cfg.ResourceGroup) + "/providers/Microsoft.Network/dnsZones"
	if p.mgmt, err = dnsapi.NewHTTPClient(dnsapi.HTTPOptions{Hosts: []string{ManagementHost}, Roots: cfg.BaseRoots, MapAddr: cfg.mapAddr}); err != nil {
		return nil, err
	}
	login, err := dnsapi.NewHTTPClient(dnsapi.HTTPOptions{Hosts: []string{azureid.AuthorityHost}, Roots: cfg.BaseRoots, MapAddr: cfg.mapAddr})
	if err != nil {
		return nil, err
	}
	imds := newIMDSTransport(cfg.mapAddr)
	p.cred, err = newCredential(id, clientOptions(recordingTransport{next: login}), clientOptions(recordingTransport{next: imds}))
	clear(id.secret)
	if err != nil {
		return nil, err
	}
	return p, nil
}

// validIdentity checks the sign-in fields of cfg and copies (parses) the credential material.
func validIdentity(cfg Config) (identity, error) {
	id := identity{auth: cfg.Auth}
	secret, keyDER := cfg.ClientSecret.Bytes(), cfg.PrivateKeyDER.Bytes()
	var ok bool
	switch cfg.Auth {
	case AuthClientSecret, AuthCertificate:
		if id.tenant, ok = azureid.NormalizeGUID(cfg.TenantID); !ok {
			return identity{}, ErrIdentity
		}
		if id.client, ok = azureid.NormalizeGUID(cfg.ClientID); !ok {
			return identity{}, ErrIdentity
		}
	case AuthManagedIdentity:
		if cfg.TenantID != "" || len(secret) != 0 || len(keyDER) != 0 || len(cfg.CertificateDER) != 0 {
			return identity{}, ErrIdentity
		}
		if cfg.ClientID != "" {
			if id.client, ok = azureid.NormalizeGUID(cfg.ClientID); !ok {
				return identity{}, ErrIdentity
			}
		}
		return id, nil
	default:
		return identity{}, ErrIdentity
	}
	if cfg.Auth == AuthClientSecret {
		if len(secret) == 0 || len(secret) > MaxClientSecretBytes || len(keyDER) != 0 || len(cfg.CertificateDER) != 0 {
			return identity{}, ErrIdentity
		}
		id.secret = append([]byte(nil), secret...)
		return id, nil
	}
	if len(secret) != 0 || len(keyDER) == 0 || len(cfg.CertificateDER) == 0 {
		return identity{}, ErrIdentity
	}
	cert, err := x509.ParseCertificate(cfg.CertificateDER)
	if err != nil {
		return identity{}, ErrIdentity
	}
	key, err := x509.ParsePKCS8PrivateKey(keyDER)
	rsaKey, isRSA := key.(*rsa.PrivateKey) // MSAL signs PS256: RSA only
	if err != nil || !isRSA {
		return identity{}, ErrIdentity
	}
	if pub, ok := cert.PublicKey.(*rsa.PublicKey); !ok || !pub.Equal(&rsaKey.PublicKey) {
		return identity{}, ErrIdentity // the key must be the certificate's
	}
	id.cert, id.key = cert, rsaKey
	return id, nil
}

// validResourceGroup is Azure's resource group rule over ASCII: 1 to 90 letters, digits, '-', '_', '.', '(' and ')',
// not ending with '.'.
func validResourceGroup(rg string) bool {
	if rg == "" || len(rg) > MaxResourceGroupLen || strings.HasSuffix(rg, ".") {
		return false
	}
	for i := 0; i < len(rg); i++ {
		c := rg[i]
		switch {
		case 'a' <= c && c <= 'z', 'A' <= c && c <= 'Z', '0' <= c && c <= '9':
		case c == '-', c == '_', c == '.', c == '(', c == ')':
		default:
			return false
		}
	}
	return true
}

// String names the sign-in method, the tenant, the client, the subscription and the resource group only.
func (p *Provider) String() string {
	return describe("azuredns.Provider", p.auth, p.tenant, p.client, p.sub, p.rg)
}

// GoString is String.
func (p *Provider) GoString() string { return p.String() }

// Format keeps every verb on String.
func (p *Provider) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, p.String()) }

// Kind implements dnsapi.Provider.
func (*Provider) Kind() string { return dnsapi.KindAzureDNS }

// ChangeDone implements dnsapi.Provider: an Azure DNS change is live on its name servers at once.
func (*Provider) ChangeDone(context.Context, string) (bool, error) { return true, nil }

// Zero drops the provider's credential once it is no longer used: every later call fails with dns_auth_failed.
// The SDK's own copy of the client secret or key (a Go string, a parsed key) cannot be overwritten; it is left to
// the garbage collector.
func (p *Provider) Zero() {
	p.mu.Lock()
	p.cred = nil
	p.mu.Unlock()
}

// domainOf is the identifier of fqdn's errors: the name without the challenge label.
func domainOf(fqdn string) string { return strings.TrimPrefix(fqdn, solver.ChallengeLabel) }

// token asks the guarded credential for a Resource Manager token (azidentity caches it until shortly before it
// expires).
func (p *Provider) token(ctx context.Context, d string) (string, error) {
	p.mu.Lock()
	cred := p.cred
	p.mu.Unlock()
	if cred == nil {
		return "", acme.DNSSignInError(d, 0, false)
	}
	w := &signInWire{}
	tok, err := cred.GetToken(withWire(ctx, w), policy.TokenRequestOptions{Scopes: []string{ManagementScope}, TenantID: p.tenant})
	if err != nil {
		if ce := ctx.Err(); ce != nil {
			return "", ce
		}
		return "", signInFailure(d, err, w)
	}
	return tok.Token, nil
}

// call sends one Resource Manager request (rawURL is already escaped) with the bearer token.
func (p *Provider) call(ctx context.Context, d, method, rawURL string, hdr map[string]string, body []byte) (int, http.Header, []byte, error) {
	tok, err := p.token(ctx, d)
	if err != nil {
		return 0, nil, nil, err
	}
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, rawURL, rd)
	if err != nil {
		return 0, nil, nil, acme.DNSProviderError(d, 0, false)
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	return dnsapi.Do(ctx, p.mgmt, req, d)
}

// zoneList is the answer of the zone listing.
type zoneList struct {
	Value []struct {
		Name       string `json:"name"`
		Properties struct {
			ZoneType string `json:"zoneType"`
		} `json:"properties"`
	} `json:"value"`
	NextLink string `json:"nextLink"`
}

// FindZone implements dnsapi.Provider: the longest public zone of the resource group that holds fqdn.
func (p *Provider) FindZone(ctx context.Context, fqdn string) (dnsapi.Zone, error) {
	d := domainOf(fqdn)
	next := "https://" + ManagementHost + p.zonesRaw + "?api-version=" + APIVersion
	var zones []dnsapi.Zone
	for page := 1; ; page++ {
		status, _, body, err := p.call(ctx, d, http.MethodGet, next, nil, nil)
		if err != nil {
			return dnsapi.Zone{}, err
		}
		switch {
		case status == http.StatusNotFound: // ResourceGroupNotFound, SubscriptionNotFound
			return dnsapi.Zone{}, acme.DNSZoneNotFound(d)
		case status != http.StatusOK:
			return dnsapi.Zone{}, acme.DNSProviderError(d, status, false)
		}
		var list zoneList
		if json.Unmarshal(body, &list) != nil || list.Value == nil {
			return dnsapi.Zone{}, acme.DNSProviderError(d, status, false)
		}
		for _, z := range list.Value {
			if z.Name == "" || strings.EqualFold(z.Properties.ZoneType, "Private") {
				continue
			}
			zones = append(zones, dnsapi.Zone{Name: z.Name, ID: z.Name})
		}
		if list.NextLink == "" {
			break
		}
		// A nextLink is followed only to the same listing on the same host, and only so far: an incomplete
		// listing could pick a parent zone where a longer one exists, so a bad link or too many pages fail.
		if !p.sameListing(list.NextLink) || page >= MaxZonePages {
			return dnsapi.Zone{}, acme.DNSProviderError(d, 0, false)
		}
		next = list.NextLink
	}
	z, ok := dnsapi.Longest(fqdn, zones)
	if !ok {
		return dnsapi.Zone{}, acme.DNSZoneNotFound(d)
	}
	return z, nil
}

// sameListing reports whether link is the zone listing of this provider on https://management.azure.com.
func (p *Provider) sameListing(link string) bool {
	u, err := url.Parse(link)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Fragment != "" || u.Opaque != "" {
		return false
	}
	port := u.Port()
	return foldASCII(u.Hostname()) == ManagementHost && (port == "" || port == "443") &&
		foldASCII(u.Path) == foldASCII(p.zonesPath)
}

// txtRecord is one TXT record: its value is the concatenation of its strings.
type txtRecord struct {
	Value []string `json:"value"`
}

func (r txtRecord) joined() string { return strings.Join(r.Value, "") }

// recordSet is the part of a TXT record set the provider reads and writes back.
type recordSet struct {
	Etag       string `json:"etag"`
	Properties *struct {
		TTL        *int            `json:"TTL"`
		Metadata   json.RawMessage `json:"metadata"`
		TXTRecords []txtRecord     `json:"TXTRecords"`
	} `json:"properties"`
}

// putBody is what a PUT sends: the metadata that was there, the TTL and the records.
type putBody struct {
	Properties putProperties `json:"properties"`
}

type putProperties struct {
	Metadata   json.RawMessage `json:"metadata,omitempty"`
	TTL        int             `json:"TTL"`
	TXTRecords []txtRecord     `json:"TXTRecords"`
}

func (p *Provider) recordURL(z dnsapi.Zone, fqdn string) string {
	rel := dnsapi.RelativeName(fqdn, z.Name)
	return "https://" + ManagementHost + p.zonesRaw + "/" + url.PathEscape(z.ID) + "/TXT/" + url.PathEscape(rel) +
		"?api-version=" + APIVersion
}

// current is a record set as read: exists false when there is none.
type current struct {
	exists  bool
	etag    string
	ttl     int
	meta    json.RawMessage
	records []txtRecord
}

func (c current) has(value string) bool {
	for _, r := range c.records {
		if r.joined() == value {
			return true
		}
	}
	return false
}

func (p *Provider) read(ctx context.Context, d, u string) (current, error) {
	status, hdr, body, err := p.call(ctx, d, http.MethodGet, u, nil, nil)
	switch {
	case err != nil:
		return current{}, err
	case status == http.StatusNotFound:
		return current{}, nil
	case status != http.StatusOK:
		return current{}, acme.DNSProviderError(d, status, false)
	}
	var rs recordSet
	if json.Unmarshal(body, &rs) != nil || rs.Properties == nil {
		return current{}, acme.DNSProviderError(d, status, false)
	}
	c := current{exists: true, etag: rs.Etag, meta: rs.Properties.Metadata, records: rs.Properties.TXTRecords}
	if c.etag == "" {
		c.etag = hdr.Get("ETag")
	}
	if c.etag == "" {
		return current{}, acme.DNSProviderError(d, status, false) // a write could not be made conditional
	}
	if rs.Properties.TTL != nil {
		c.ttl = *rs.Properties.TTL
	}
	if string(c.meta) == "null" {
		c.meta = nil
	}
	return c, nil
}

// put writes the record set; it reports a 412 as conflict.
func (p *Provider) put(ctx context.Context, d, u string, cond map[string]string, body putBody) (conflict bool, err error) {
	b, err := json.Marshal(body)
	if err != nil {
		return false, acme.DNSProviderError(d, 0, false)
	}
	status, _, answer, err := p.call(ctx, d, http.MethodPut, u, cond, b)
	switch {
	case err != nil:
		return false, err
	case status == http.StatusPreconditionFailed:
		return true, nil
	case status == http.StatusNotFound: // ParentResourceNotFound: the zone went away
		return false, acme.DNSZoneNotFound(d)
	case status != http.StatusOK && status != http.StatusCreated:
		return false, acme.DNSProviderError(d, status, false)
	}
	var rs recordSet
	if json.Unmarshal(answer, &rs) != nil || rs.Properties == nil {
		return false, acme.DNSProviderError(d, status, false)
	}
	return false, nil
}

// conflictError is the error of a record set that kept changing under the provider: another writer, expected to
// finish (transient).
func conflictError(d string) error {
	return acme.DNSProviderError(d, http.StatusPreconditionFailed, true)
}

// AddTXT implements dnsapi.Provider.
func (p *Provider) AddTXT(ctx context.Context, z dnsapi.Zone, fqdn, value string, ttl int) (string, error) {
	d := domainOf(fqdn)
	u := p.recordURL(z, fqdn)
	for attempt := 0; attempt <= MaxPreconditionRetries; attempt++ {
		cur, err := p.read(ctx, d, u)
		if err != nil {
			return "", err
		}
		if cur.has(value) {
			return "", nil
		}
		body := putBody{Properties: putProperties{Metadata: cur.meta, TTL: ttl,
			TXTRecords: append(append([]txtRecord(nil), cur.records...), txtRecord{Value: []string{value}})}}
		cond := map[string]string{"If-None-Match": "*"}
		if cur.exists {
			cond = map[string]string{"If-Match": cur.etag}
		}
		conflict, err := p.put(ctx, d, u, cond, body)
		if err != nil {
			return "", err
		}
		if !conflict {
			return "", nil
		}
	}
	return "", conflictError(d)
}

// RemoveTXT implements dnsapi.Provider.
func (p *Provider) RemoveTXT(ctx context.Context, z dnsapi.Zone, fqdn, value string) error {
	d := domainOf(fqdn)
	u := p.recordURL(z, fqdn)
	for attempt := 0; attempt <= MaxPreconditionRetries; attempt++ {
		cur, err := p.read(ctx, d, u)
		if err != nil {
			return err
		}
		if !cur.has(value) {
			return nil
		}
		var rest []txtRecord
		for _, r := range cur.records {
			if r.joined() != value {
				rest = append(rest, r)
			}
		}
		cond := map[string]string{"If-Match": cur.etag}
		if len(rest) == 0 {
			status, _, _, err := p.call(ctx, d, http.MethodDelete, u, cond, nil)
			switch {
			case err != nil:
				return err
			case status == http.StatusOK || status == http.StatusNoContent || status == http.StatusNotFound:
				return nil
			case status != http.StatusPreconditionFailed:
				return acme.DNSProviderError(d, status, false)
			}
			continue
		}
		ttl := cur.ttl
		if ttl <= 0 {
			ttl = dnsapi.DefaultTTL
		}
		conflict, err := p.put(ctx, d, u, cond, putBody{Properties: putProperties{Metadata: cur.meta, TTL: ttl, TXTRecords: rest}})
		var ae *acme.Error
		switch {
		case errors.As(err, &ae) && ae.Reason == acme.ReasonDNSZoneNotFound:
			return nil // the zone, and the value with it, is gone
		case err != nil:
			return err
		case !conflict:
			return nil
		}
	}
	return conflictError(d)
}
