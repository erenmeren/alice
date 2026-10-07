// Package oidc is Alice's OpenID Connect single sign-on (spec §7.1, SEC-010..015): identity providers whose
// endpoints are fixed at configuration time, a bounded key set, the authorization code flow with PKCE and a
// single-use state bound to the browser, group-to-role mappings with the "SSO users may be Admin" switch, and the
// identity provider step-up. Users, sessions and refusals are internal/auth's.
package oidc

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"alice/internal/audit"
	"alice/internal/auth"
	"alice/internal/platform/clock"
	"alice/internal/secrets"
)

// Limits and names (C1, C11).
const (
	StateLifetime    = 10 * time.Minute
	StepUpMaxAge     = 5 * time.Minute
	HTTPTimeout      = 10 * time.Second
	MaxProviders     = 5
	MaxMappings      = 200
	JWKSRefetchEvery = time.Minute
	MaxResponseBytes = 1 << 20
	AllowAdminKey    = auth.SSOAllowAdminKey
	CallbackPath     = "/api/v1/auth/oidc/%s/callback"
)

// SigningAlgs are the ID token signature algorithms Alice accepts (SEC-012).
var SigningAlgs = []string{"RS256", "ES256", "PS256"}

// Endpoints are the provider's endpoints, read from discovery at configuration time only.
type Endpoints struct{ Authorization, Token, JWKS string }

// Provider is a configured identity provider; it never carries the client secret.
type Provider struct {
	ID              uuid.UUID
	Name            string
	IssuerURL       string
	ClientID        string
	HasClientSecret bool
	Scopes          []string
	GroupsClaim     string
	CAPEM           string
	Endpoints       Endpoints
	Enabled         bool
	RedirectURI     string // "" while general.public_url is unset
	Version         int
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

// ProviderInput creates a provider. The caller owns and zeroes ClientSecret.
type ProviderInput struct {
	Name, IssuerURL, ClientID, GroupsClaim, CAPEM string
	ClientSecret                                  secrets.Plaintext // required
	Scopes                                        []string          // nil: openid, profile, email
	Enabled                                       bool
}

// ProviderPatch changes selected fields; nil fields stay. The caller owns and zeroes ClientSecret.
type ProviderPatch struct {
	Name, IssuerURL, ClientID, GroupsClaim, CAPEM *string
	ClientSecret                                  *secrets.Plaintext
	Scopes                                        *[]string
	Enabled                                       *bool
}

// PublicProvider is what the sign-in page shows.
type PublicProvider struct {
	ID   uuid.UUID
	Name string
}

// SSOSettings is the "SSO users may be Admin" switch.
type SSOSettings struct {
	AllowAdminRole bool
	Version        int
}

// DiscoveryError says why a provider's discovery failed; Cause is one of connect, tls, status, document,
// issuer_mismatch, not_https, jwks. Nothing of the provider's answer is kept.
type DiscoveryError struct{ Cause string }

func (e *DiscoveryError) Error() string {
	return "oidc: the identity provider's discovery failed (" + e.Cause + ")"
}

// Errors of the service.
var (
	ErrNotFound             = errors.New("oidc: not found")
	ErrVersion              = errors.New("oidc: the version does not match")
	ErrTooMany              = errors.New("oidc: too many identity providers or group mappings")
	ErrProviderInUse        = errors.New("oidc: the identity provider still has users")
	ErrPublicURLMissing     = errors.New("oidc: Alice's public address is not set")
	ErrAdminMappingDisabled = errors.New("oidc: groups cannot be mapped to Administrator while SSO users may not be Admin")
	ErrAdminMappingsExist   = errors.New("oidc: groups are still mapped to Administrator")
)

// LoginError is a refused sign-in or step-up with its closed reason (C15 without the "sso." prefix).
type LoginError struct {
	Reason string
	StepUp bool   // the refused sign-in was a step-up: the callback returns to Next, not to the sign-in page
	Next   string // the state's safe next path ("" when no state was found)
}

func (e *LoginError) Error() string { return "oidc: the sign-in was refused (" + e.Reason + ")" }

// Config holds the service's dependencies.
type Config struct {
	Pool    *pgxpool.Pool
	Keyring *secrets.Keyring
	Audit   *audit.Log
	Clock   clock.Clock
	Auth    *auth.Service
	Dial    func(ctx context.Context, network, addr string) (net.Conn, error) // nil: netaddr.DialContext
	Log     *slog.Logger
}

// Service manages identity providers and runs SSO sign-ins.
type Service struct {
	pool    *pgxpool.Pool
	keyring *secrets.Keyring
	audit   *audit.Log
	clock   clock.Clock
	auth    *auth.Service
	dial    func(ctx context.Context, network, addr string) (net.Conn, error)
	log     *slog.Logger

	keySets sync.Map // keySetKey -> *keySet: one bounded cache per provider version
}

type keySetKey struct {
	id      uuid.UUID
	version int
}

// New builds the service.
func New(c Config) *Service {
	log := c.Log
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Service{pool: c.Pool, keyring: c.Keyring, audit: c.Audit, clock: c.Clock, auth: c.Auth, dial: c.Dial, log: log}
}

// RedirectURI is the provider's callback address under Alice's public address, "" while it is unset.
func RedirectURI(publicURL string, id uuid.UUID) string {
	if publicURL == "" {
		return ""
	}
	return strings.TrimSuffix(publicURL, "/") + fmt.Sprintf(CallbackPath, id)
}

// secretKey is the setting_secrets key of a provider's client secret.
func secretKey(id uuid.UUID) string { return "sso.provider." + id.String() + ".client_secret" }

// userID is the actor's user ID for created_by: a user actor's ID, else NULL (D-s3-04).
func userID(a audit.Actor) any {
	if a.Type == audit.ActorUser && a.ID != uuid.Nil {
		return a.ID
	}
	return nil
}
