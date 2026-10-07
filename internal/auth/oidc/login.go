package oidc

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"time"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"golang.org/x/oauth2"

	"alice/internal/auth"
	"alice/internal/auth/oidc/claims"
	"alice/internal/platform/settings"
	"alice/internal/rbac"
)

// BeginInput starts a sign-in or, with StepUp, an SSO user's step-up.
type BeginInput struct {
	ProviderID  uuid.UUID // ignored for a step-up (the user's own provider)
	Next        string    // claims.SafeNext applies
	StepUp      bool
	SessionHash []byte    // step-up only
	UserID      uuid.UUID // step-up only
}

// Begin is where to send the browser, and the binding cookie's value.
type Begin struct {
	AuthorizeURL string
	Binding      string // the cookie value; only its SHA-256 is stored
}

// Completion is a finished sign-in or step-up.
type Completion struct {
	Session auth.SessionResult
	Next    string
	StepUp  bool
}

// random32 is 32 bytes from crypto/rand in base64url without padding: 43 characters.
func random32() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func sum(v string) []byte {
	h := sha256.Sum256([]byte(v))
	return h[:]
}

func (s *Service) oauthConfig(p Provider, publicURL, secret string) *oauth2.Config {
	return &oauth2.Config{ClientID: p.ClientID, ClientSecret: secret, RedirectURL: RedirectURI(publicURL, p.ID), Scopes: p.Scopes,
		Endpoint: oauth2.Endpoint{AuthURL: p.Endpoints.Authorization, TokenURL: p.Endpoints.Token, AuthStyle: oauth2.AuthStyleInHeader}}
}

// Begin starts a sign-in (SEC-010, SEC-011): a 256-bit state, nonce and binding value, a PKCE S256 verifier, one
// oidc_login_states row holding the state's and the binding's SHA-256, and the provider's authorize URL. A step-up
// asks the provider for a fresh sign-in (prompt=login, max_age=0).
func (s *Service) Begin(ctx context.Context, in BeginInput) (Begin, error) {
	providerID := in.ProviderID
	if in.StepUp {
		if err := s.pool.QueryRow(ctx, `SELECT oidc_provider_id FROM users WHERE id = $1 AND auth_source = 'oidc'`, in.UserID).
			Scan(&providerID); err != nil {
			return Begin{}, auth.ErrNotSSOUser
		}
	}
	p, err := s.loadProvider(ctx, s.pool, providerID)
	if err != nil {
		return Begin{}, err
	}
	if !p.Enabled {
		return Begin{}, &LoginError{Reason: "provider_disabled", StepUp: in.StepUp}
	}
	g, err := settings.GetGeneral(ctx, s.pool)
	if err != nil {
		return Begin{}, err
	}
	if g.PublicURL == "" {
		return Begin{}, ErrPublicURLMissing
	}
	state, nonce, binding := random32(), random32(), random32()
	verifier := oauth2.GenerateVerifier()
	purpose, session, user := "login", []byte(nil), any(nil)
	if in.StepUp {
		purpose, session, user = "stepup", in.SessionHash, in.UserID
	}
	now := s.clock.Now().UTC()
	if _, err := s.pool.Exec(ctx, `INSERT INTO oidc_login_states (state_hash, provider_id, binding_hash, nonce, code_verifier, purpose,
session_hash, user_id, next_path, created_at, expires_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
		sum(state), p.ID, sum(binding), nonce, verifier, purpose, session, user, claims.SafeNext(in.Next), now, now.Add(StateLifetime)); err != nil {
		return Begin{}, fmt.Errorf("oidc: store the sign-in state: %w", err)
	}
	opts := []oauth2.AuthCodeOption{oauth2.S256ChallengeOption(verifier), gooidc.Nonce(nonce)}
	if in.StepUp {
		opts = append(opts, oauth2.SetAuthURLParam("prompt", "login"), oauth2.SetAuthURLParam("max_age", "0"))
	}
	return Begin{AuthorizeURL: s.oauthConfig(p, g.PublicURL, "").AuthCodeURL(state, opts...), Binding: binding}, nil
}

// loginState is a consumed oidc_login_states row.
type loginState struct {
	providerID uuid.UUID
	binding    []byte
	nonce      string
	verifier   string
	stepUp     bool
	session    []byte
	user       *uuid.UUID
	next       string
	expires    time.Time
}

// consumeState deletes the state row and returns it: a state is used at most once (SEC-011).
func (s *Service) consumeState(ctx context.Context, state string) (loginState, bool, error) {
	var r loginState
	var purpose string
	err := s.pool.QueryRow(ctx, `DELETE FROM oidc_login_states WHERE state_hash = $1
RETURNING provider_id, binding_hash, nonce, code_verifier, purpose, session_hash, user_id, next_path, expires_at`, sum(state)).
		Scan(&r.providerID, &r.binding, &r.nonce, &r.verifier, &purpose, &r.session, &r.user, &r.next, &r.expires)
	if errors.Is(err, pgx.ErrNoRows) {
		return loginState{}, false, nil
	}
	if err != nil {
		return loginState{}, false, fmt.Errorf("oidc: read the sign-in state: %w", err)
	}
	r.stepUp = purpose == "stepup"
	return r, true, nil
}

// keySetFor is the provider version's bounded key set, kept across sign-ins so the refetch bound holds.
func (s *Service) keySetFor(p Provider) (*keySet, error) {
	k := keySetKey{id: p.ID, version: p.Version}
	if ks, ok := s.keySets.Load(k); ok {
		return ks.(*keySet), nil
	}
	client, err := s.httpClient(p.CAPEM)
	if err != nil {
		return nil, err
	}
	ks, _ := s.keySets.LoadOrStore(k, newKeySet(client, p.Endpoints.JWKS, s.clock))
	return ks.(*keySet), nil
}

// refusal is a refused completion: its closed reason and, for a token problem, the claims reason (both safe to log).
type refusal struct {
	reason string
	detail string
}

// Complete finishes a sign-in or step-up from the callback's query (C11): it consumes the state, checks the
// browser binding, exchanges the code with the PKCE verifier, verifies the ID token with the provider's key set and
// claims.Validate, resolves the role from the groups, and signs the user in (or steps the session up). Every
// refusal is audited once through auth.RefuseOIDC and returned as a *LoginError.
func (s *Service) Complete(ctx context.Context, providerID uuid.UUID, q url.Values, binding string, m auth.Meta) (Completion, error) {
	id := auth.OIDCIdentity{ProviderID: providerID}
	var st loginState
	refuse := func(r refusal) error {
		if err := s.auth.RefuseOIDC(ctx, id, r.reason, m); err != nil {
			return err
		}
		s.log.InfoContext(ctx, "single sign-on refused", "provider_id", providerID.String(), "reason", r.reason, "detail", r.detail,
			"stepup", st.stepUp, "request_id", m.RequestID)
		return &LoginError{Reason: r.reason, StepUp: st.stepUp, Next: st.next}
	}
	c, r, err := s.complete(ctx, providerID, q, binding, m, &id, &st)
	if err != nil {
		return Completion{}, err
	}
	if r != nil {
		return Completion{}, refuse(*r)
	}
	return c, nil
}

func (s *Service) complete(ctx context.Context, providerID uuid.UUID, q url.Values, binding string, m auth.Meta,
	id *auth.OIDCIdentity, st *loginState) (Completion, *refusal, error) {
	state := q.Get("state")
	if state == "" {
		return Completion{}, &refusal{reason: "login_expired"}, nil
	}
	row, found, err := s.consumeState(ctx, state)
	if err != nil {
		return Completion{}, nil, err
	}
	if !found {
		return Completion{}, &refusal{reason: "login_expired"}, nil
	}
	*st = row
	if !s.clock.Now().Before(row.expires) || row.providerID != providerID || subtle.ConstantTimeCompare(row.binding, sum(binding)) != 1 {
		return Completion{}, &refusal{reason: "login_expired"}, nil
	}
	if q.Get("error") != "" {
		return Completion{}, &refusal{reason: "idp_error"}, nil
	}
	p, err := s.loadProvider(ctx, s.pool, providerID)
	if err != nil {
		return Completion{}, nil, err
	}
	id.Issuer = p.IssuerURL
	if !p.Enabled {
		return Completion{}, &refusal{reason: "provider_disabled"}, nil
	}
	raw, r, err := s.exchange(ctx, p, q.Get("code"), row.verifier)
	if err != nil || r != nil {
		return Completion{}, r, err
	}
	c, r, err := s.verify(ctx, p, raw, row)
	if err != nil || r != nil {
		return Completion{}, r, err
	}
	*id = auth.OIDCIdentity{ProviderID: p.ID, Issuer: c.Issuer, Subject: c.Subject, Username: claims.Username(c), DisplayName: c.Name,
		Email: c.Email}
	if id.DisplayName == "" {
		id.DisplayName = id.Username
	}
	role, r, err := s.resolveRole(ctx, p, c)
	if err != nil || r != nil {
		return Completion{}, r, err
	}
	var res auth.SessionResult
	if row.stepUp {
		res, err = s.auth.StepUpOIDC(ctx, row.session, *row.user, *id, role, m)
	} else {
		res, err = s.auth.SignInOIDC(ctx, *id, role, m)
	}
	switch {
	case errors.Is(err, auth.ErrOIDCEmailInUse):
		return Completion{}, &refusal{reason: "email_in_use"}, nil
	case errors.Is(err, auth.ErrOIDCUserDisabled):
		return Completion{}, &refusal{reason: "user_disabled"}, nil
	case errors.Is(err, auth.ErrOIDCOtherUser):
		return Completion{}, &refusal{reason: "stepup_other_user"}, nil
	case errors.Is(err, auth.ErrUnauthenticated), errors.Is(err, auth.ErrNotSSOUser):
		return Completion{}, &refusal{reason: "login_expired"}, nil // S-1: the session ended meanwhile
	case errors.Is(err, auth.ErrOIDCIdentityInvalid):
		return Completion{}, &refusal{reason: "login_invalid", detail: "identity"}, nil
	case err != nil:
		return Completion{}, nil, err
	}
	return Completion{Session: res, Next: row.next, StepUp: row.stepUp}, nil, nil
}

// exchange trades the code for the ID token with the PKCE verifier. The client secret is opened for this one
// request and zeroed after it (the string copy x/oauth2 keeps cannot be cleared: known limitation, as P4-04).
func (s *Service) exchange(ctx context.Context, p Provider, code, verifier string) (string, *refusal, error) {
	if code == "" {
		return "", &refusal{reason: "login_invalid", detail: "no_code"}, nil
	}
	client, err := s.httpClient(p.CAPEM)
	if err != nil {
		return "", nil, err
	}
	g, err := settings.GetGeneral(ctx, s.pool)
	if err != nil {
		return "", nil, err
	}
	secret, ok, err := s.keyring.GetSetting(ctx, s.pool, secretKey(p.ID))
	if err != nil {
		return "", nil, err
	}
	if !ok {
		return "", &refusal{reason: "login_invalid", detail: "no_client_secret"}, nil
	}
	cfg := s.oauthConfig(p, g.PublicURL, string(secret.Bytes()))
	secret.Zero()
	tok, err := cfg.Exchange(context.WithValue(ctx, oauth2.HTTPClient, client), code, oauth2.VerifierOption(verifier))
	var re *oauth2.RetrieveError
	switch {
	case errors.As(err, &re) && (re.Response == nil || re.Response.StatusCode < 500):
		return "", &refusal{reason: "login_invalid", detail: "token_refused"}, nil
	case err != nil:
		return "", &refusal{reason: "idp_unreachable"}, nil
	}
	raw, _ := tok.Extra("id_token").(string)
	if raw == "" {
		return "", &refusal{reason: "login_invalid", detail: "no_id_token"}, nil
	}
	return raw, nil, nil
}

// verify checks the ID token's signature with the provider's key set and its claims with claims.Validate (all time
// checks are claims.Validate's, with the injected clock).
func (s *Service) verify(ctx context.Context, p Provider, raw string, row loginState) (claims.Claims, *refusal, error) {
	ks, err := s.keySetFor(p)
	if err != nil {
		return claims.Claims{}, nil, err
	}
	var probe fetchProbe
	tok, err := gooidc.NewVerifier(p.IssuerURL, ks, &gooidc.Config{ClientID: p.ClientID, SupportedSigningAlgs: SigningAlgs,
		SkipExpiryCheck: true}).Verify(withFetchProbe(ctx, &probe), raw)
	if err != nil && probe.failed {
		return claims.Claims{}, &refusal{reason: "idp_unreachable", detail: "jwks"}, nil // M-1, O-11
	}
	if err != nil {
		return claims.Claims{}, &refusal{reason: "login_invalid", detail: "signature"}, nil
	}
	var payload json.RawMessage
	if err := tok.Claims(&payload); err != nil {
		return claims.Claims{}, &refusal{reason: "login_invalid", detail: string(claims.ReasonMalformed)}, nil
	}
	c, err := claims.Parse(payload)
	if err == nil {
		e := claims.Expect{Issuer: p.IssuerURL, ClientID: p.ClientID, Nonce: row.nonce, Now: s.clock.Now()}
		if row.stepUp {
			e.MaxAuthAge = StepUpMaxAge
		}
		err = claims.Validate(c, e)
	}
	if err != nil {
		detail := string(claims.ReasonMalformed)
		var ce *claims.Error
		if errors.As(err, &ce) {
			detail = string(ce.Reason)
		}
		return claims.Claims{}, &refusal{reason: "login_invalid", detail: detail}, nil
	}
	return c, nil, nil
}

// resolveRole maps the token's groups to a role (SEC-014): an overage is groups_overage, a malformed claim
// login_invalid, no mapped group no_access. It runs for sign-ins and step-ups alike (S-1).
func (s *Service) resolveRole(ctx context.Context, p Provider, c claims.Claims) (rbac.Role, *refusal, error) {
	groups, err := claims.Groups(c, p.GroupsClaim)
	switch {
	case errors.Is(err, claims.ErrOverage):
		return "", &refusal{reason: "groups_overage"}, nil
	case err != nil:
		return "", &refusal{reason: "login_invalid", detail: "groups"}, nil
	}
	mappings, err := mappingsFor(ctx, s.pool, p.ID)
	if err != nil {
		return "", nil, err
	}
	sw, err := s.Settings(ctx)
	if err != nil {
		return "", nil, err
	}
	role, ok := claims.ResolveRole(groups, mappings, sw.AllowAdminRole)
	if !ok {
		return "", &refusal{reason: "no_access"}, nil
	}
	return role, nil, nil
}
