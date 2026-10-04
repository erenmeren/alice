// Package azurekv is the Azure Key Vault provider (spec §11): sign-in to Entra ID, the data plane of
// one vault and the closed mapping of every Azure failure. Every HTTP request it makes, and the
// SDK's, goes through the guarded transports of transport.go; the text of an Azure, SDK, MSAL or
// HTTP error is never kept (errors.go).
package azurekv

import (
	"context"
	"crypto/x509"
	"io"
	"log/slog"
	"os"
	"sync"
	"time"

	"github.com/google/uuid"

	"alice/internal/platform/azureid"
	"alice/internal/platform/clock"
	"alice/internal/platform/validate"
	"alice/internal/providers"
)

// Limits (R40 rows 3, 8, 15, 16; ruling S15 sets the retry model: three attempts per page).
const (
	MaxAttempts        = 3                // attempts of one request (page)
	TryTimeout         = 30 * time.Second // one attempt
	MaxRetryAfter      = 60 * time.Second // the longest Retry-After Alice waits for
	PollBudget         = 11 * time.Minute // a Discover call
	PreflightBudget    = 45 * time.Second // inventory's add check uses it as its context bound
	SecretReadAttempts = 2                // ruling S3: a deployment's secret read
	SecretReadBudget   = time.Minute      // ruling S3: its total
	MaxBody            = 4 << 20
	MaxHeaderBytes     = 64 << 10
	MaxKVCertificates  = 5000
	MaxKVKeys          = 5000
	MaxKVSecrets       = 10000
	MaxKVDetails       = 100
	MaxKVKeyDetails    = 100
	MaxKVVersions      = 100
	MaxKVVersionRead   = 1000 // versions read of one certificate before its listing is cut (D28)
	VaultRate          = 5    // requests per second per vault
	VaultConcurrency   = 4
	// MaxListPages bounds the pages of one listing: the largest bound (MaxKVSecrets 10,000 secrets,
	// plus the managed ones of up to MaxKVCertificates certificates) at the page size of 25 is about
	// 600 pages; 1000 leaves room and still ends a cycling vault within seconds.
	MaxListPages = 1000
	// MaxNextLink bounds one nextLink (a real one is about 200 bytes): the links of a listing are
	// remembered to catch a cycle, so each must be small.
	MaxNextLink = 4 << 10
)

// Options configures the provider.
type Options struct {
	// RootCAs returns the roots Azure's TLS certificates are verified with; a nil function or a nil
	// pool means the system roots. The e2e build returns the fake service's CA (R40 row 35).
	RootCAs func() (*x509.CertPool, error)

	// The fields below are the test seam. They are unexported on purpose: only code of this package
	// (its tests) can set them, no environment variable reaches them, and the production host rule
	// stays "<name>.vault.azure.net:443" exactly: a test maps the dialled address to the fake's
	// listener while the request URL and the TLS server name remain the real vault name. The e2e
	// and integration harnesses get a build-tagged setter in a later task, never an exported field.
	dialAddr func(addr string) string
	dial     dialFunc
	jitter   func(max time.Duration) time.Duration
	try      time.Duration
}

// Provider implements providers.Provider and providers.ConnectionCache.
type Provider struct {
	o Options

	mu       sync.Mutex
	limiters map[string]*vaultLimiter      // by vault host
	hosts    map[uuid.UUID]string          // target -> vault host
	users    map[string]map[uuid.UUID]bool // vault host -> the targets that share its limiter
}

// New builds the provider.
func New(o Options) *Provider {
	return &Provider{o: o, limiters: map[string]*vaultLimiter{}, hosts: map[uuid.UUID]string{}, users: map[string]map[uuid.UUID]bool{}}
}

var (
	_ providers.Provider        = (*Provider)(nil)
	_ providers.ConnectionCache = (*Provider)(nil)
)

// Kind implements providers.Provider.
func (*Provider) Kind() providers.Kind { return providers.KindAzureKV }

// DisplayNameKey implements providers.Provider.
func (*Provider) DisplayNameKey() string { return "provider.azurekv.name" }

// Capabilities implements providers.Provider.
func (*Provider) Capabilities() providers.CapabilitySet {
	return providers.NewCapabilitySet(providers.CapTestConnection, providers.CapDiscoverCerts, providers.CapDiscoverKVKeys,
		providers.CapDiscoverKVSecrets, providers.CapReadCertificateSecret, providers.CapImportCertificate)
}

// vaultURLPattern is the form ParseVault produces.
const vaultURLPattern = `^https://[a-z](-?[a-z0-9])+\.vault\.azure\.net$`

// ConfigSchema implements providers.Provider.
func (*Provider) ConfigSchema() providers.ConfigSchema {
	return providers.ConfigSchema{Fields: []providers.Field{
		{Name: "vault_url", Type: providers.FieldString, Required: true, Pattern: vaultURLPattern, Max: 80,
			LabelKey: "provider.azurekv.fields.vault_url.label", HelpKey: "provider.azurekv.fields.vault_url.help"},
	}}
}

// CredentialSchema implements providers.Provider.
func (*Provider) CredentialSchema() providers.CredentialSchema {
	return providers.CredentialSchema{Fields: []providers.Field{
		{Name: "auth", Type: providers.FieldEnum, Required: true, LabelKey: "provider.azurekv.fields.auth.label",
			Values: []string{providers.AzureAuthClientSecret, providers.AzureAuthCertificate, providers.AzureAuthManagedIdentity}},
		{Name: "tenant_id", Type: providers.FieldString, LabelKey: "provider.azurekv.fields.tenant_id.label"},
		{Name: "client_id", Type: providers.FieldString, LabelKey: "provider.azurekv.fields.client_id.label"},
		{Name: "client_secret", Type: providers.FieldString, LabelKey: "provider.azurekv.fields.client_secret.label"},
		{Name: "certificate", Type: providers.FieldString, LabelKey: "provider.azurekv.fields.certificate.label"},
	}}
}

// ValidateConfig implements providers.Provider.
func (*Provider) ValidateConfig(cfg providers.TargetConfig) []validate.FieldError {
	u, _ := cfg["vault_url"].(string)
	switch _, err := azureid.ParseVault(u); {
	case u == "":
		return []validate.FieldError{{Field: "vault_url", Code: validate.Required}}
	case err != nil:
		return []validate.FieldError{{Field: "vault_url", Code: validate.Pattern}}
	}
	return nil
}

// ForgetTarget implements providers.ConnectionCache: it drops the target's claim on its vault's
// limiter, and the limiter itself when no other target of the same vault host remains. A session in
// flight keeps the limiter it holds.
func (p *Provider) ForgetTarget(target uuid.UUID) {
	p.mu.Lock()
	defer p.mu.Unlock()
	host, ok := p.hosts[target]
	if !ok {
		return
	}
	delete(p.hosts, target)
	delete(p.users[host], target)
	if len(p.users[host]) == 0 {
		delete(p.users, host)
		delete(p.limiters, host)
	}
}

func (p *Provider) limiterFor(target uuid.UUID, host string, clk clock.Clock) *vaultLimiter {
	p.mu.Lock()
	defer p.mu.Unlock()
	if old, ok := p.hosts[target]; ok && old != host { // a target that moved to another vault
		delete(p.users[old], target)
	}
	p.hosts[target] = host
	if p.users[host] == nil {
		p.users[host] = map[uuid.UUID]bool{}
	}
	p.users[host][target] = true
	l, ok := p.limiters[host]
	if !ok {
		l = newVaultLimiter(clk, VaultRate, VaultConcurrency)
		p.limiters[host] = l
	}
	return l
}

// Open implements providers.Provider.
func (p *Provider) Open(ctx context.Context, t providers.TargetRef, cred providers.CredentialSource, env providers.Env) (providers.Session, error) {
	if err := ctx.Err(); err != nil {
		return nil, providers.NewError(codeUnreachable, true, err, nil)
	}
	raw, _ := t.Config["vault_url"].(string)
	vault, err := azureid.ParseVault(raw)
	if err != nil {
		return nil, providers.NewError(codeAddressNotAllowed, false, nil, nil)
	}
	// See refusedEnvironment: the session is refused before anything is decrypted.
	if refusedEnvironment() {
		return nil, providers.NewError(codeAddressNotAllowed, false, nil, nil)
	}
	src, ok := cred.(providers.AzureCredentialSource)
	if !ok {
		return nil, providers.NewError(codeAuthFailed, false, nil, nil)
	}
	id, release, err := src.AzureIdentity(ctx)
	if err != nil {
		return nil, providers.NewError(codeInternal, true, nil, nil)
	}
	defer release()

	var roots *x509.CertPool
	if p.o.RootCAs != nil {
		if roots, err = p.o.RootCAs(); err != nil {
			return nil, providers.NewError(codeTLSUntrusted, false, nil, nil)
		}
	}
	clk := env.Clock
	if clk == nil {
		clk = clock.Real{}
	}
	log := env.Log
	if log == nil {
		log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	login := newGuardedTransport([]string{azureid.AuthorityHost}, roots, p.o.dialAddr)
	vaultTr := newGuardedTransport([]string{vault.Host}, roots, p.o.dialAddr)
	login.dialOverride, vaultTr.dialOverride = p.o.dial, p.o.dial
	imds := newIMDSTransport(p.o.dialAddr, p.o.dial)
	closers := []func(){login.CloseIdleConnections, vaultTr.CloseIdleConnections, imds.CloseIdleConnections}

	cr, err := newCredential(id, clientOptions(login), clientOptions(imds))
	if err != nil {
		for _, c := range closers {
			c()
		}
		if id.Auth == providers.AzureAuthManagedIdentity { // the SDK picked another source (App Service, Service Fabric, MSI_ENDPOINT): fail closed
			return nil, providers.NewError(codeManagedIdentityGone, false, nil, nil)
		}
		return nil, providers.NewError(codeAuthFailed, false, nil, nil)
	}
	r := &retryer{clock: clk, limiter: p.limiterFor(t.ID, vault.Host, clk), log: log, jitter: p.o.jitter, tryTimeout: p.o.try}
	api, err := newSDKAPI(vault, cr, clientOptions(vaultTr), r)
	if err != nil {
		for _, c := range closers {
			c()
		}
		return nil, providers.NewError(codeUnexpected, false, nil, nil)
	}
	return &session{vault: vault, api: api, clock: clk, log: log, auth: id.Auth, closers: closers}, nil
}

// refusedEnv are environment variables that make the Azure SDK or MSAL act outside Alice's guard:
//   - AZURE_REGIONAL_AUTHORITY_NAME and MSAL_FORCE_REGION make MSAL detect its region with a bare
//     http.Client (http.DefaultTransport, and any HTTP_PROXY): a request to the metadata address
//     outside every guard. MSAL reads them at the first token, after Open.
//   - AZURE_SDK_GO_LOGGING makes the SDK print every failed call (URL, status, Azure's JSON body
//     and message) to stderr; it is read when the SDK is initialised, so only refusing the session
//     keeps Azure's text out of the process output (the Secret rule, ruling S4).
//
// azure.address_not_allowed is the closest closed code: the SDK would otherwise act on an address
// or a log this provider does not allow.
var refusedEnv = []string{"AZURE_REGIONAL_AUTHORITY_NAME", "MSAL_FORCE_REGION", "AZURE_SDK_GO_LOGGING"}

func refusedEnvironment() bool {
	for _, name := range refusedEnv {
		if os.Getenv(name) != "" {
			return true
		}
	}
	return false
}

// session is one connection scope on one vault.
type session struct {
	providers.UnsupportedSession
	vault   azureid.Vault
	api     kvAPI
	clock   clock.Clock
	log     *slog.Logger
	auth    string
	closers []func()
}

// Close drops the idle connections of the session's transports.
func (s *session) Close() error {
	for _, c := range s.closers {
		c()
	}
	return nil
}
