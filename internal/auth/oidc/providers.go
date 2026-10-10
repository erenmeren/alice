package oidc

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"alice/internal/audit"
	"alice/internal/auth/oidc/claims"
	"alice/internal/platform/db"
	"alice/internal/platform/settings"
	"alice/internal/platform/validate"
	"alice/internal/secrets"
)

// Validation limits of a provider (C13).
const (
	maxNameRunes   = 60
	maxClientID    = 255
	maxSecretBytes = 1024
	maxScopes      = 10
	maxCAPEMBytes  = 64 << 10
	maxCACerts     = 20
)

var (
	scopeRE       = regexp.MustCompile(`^[A-Za-z0-9_.:/-]{1,64}$`)
	groupsClaimRE = regexp.MustCompile(`^[A-Za-z0-9_.:/-]{1,100}$`)
	defaultScopes = []string{"openid", "profile", "email"}
)

// PostgreSQL error codes and the provider table's unique indexes.
const (
	foreignKeyViolation = "23503"
	nameIndex           = "oidc_providers_name"
	clientIndex         = "oidc_providers_client"
)

const providerColumns = `p.id, p.name, p.issuer_url, p.client_id, p.scopes, p.groups_claim, p.ca_pem, p.authorization_endpoint,
p.token_endpoint, p.jwks_uri, p.enabled, p.version, p.created_at, p.updated_at,
EXISTS (SELECT 1 FROM setting_secrets s WHERE s.key = 'sso.provider.' || p.id::text || '.client_secret')`

func scanProvider(row pgx.Row) (Provider, error) {
	var p Provider
	err := row.Scan(&p.ID, &p.Name, &p.IssuerURL, &p.ClientID, &p.Scopes, &p.GroupsClaim, &p.CAPEM, &p.Endpoints.Authorization,
		&p.Endpoints.Token, &p.Endpoints.JWKS, &p.Enabled, &p.Version, &p.CreatedAt, &p.UpdatedAt, &p.HasClientSecret)
	if errors.Is(err, pgx.ErrNoRows) {
		return Provider{}, ErrNotFound
	}
	if err != nil {
		return Provider{}, fmt.Errorf("oidc: read the identity provider: %w", err)
	}
	p.CreatedAt, p.UpdatedAt = p.CreatedAt.UTC(), p.UpdatedAt.UTC()
	return p, nil
}

func (s *Service) loadProvider(ctx context.Context, q db.Querier, id uuid.UUID) (Provider, error) {
	return scanProvider(q.QueryRow(ctx, "SELECT "+providerColumns+" FROM oidc_providers p WHERE p.id = $1", id))
}

// withRedirect sets the providers' redirect URIs from general.public_url.
func (s *Service) withRedirect(ctx context.Context, ps ...*Provider) error {
	g, err := settings.GetGeneral(ctx, s.pool)
	if err != nil {
		return err
	}
	for _, p := range ps {
		p.RedirectURI = RedirectURI(g.PublicURL, p.ID)
	}
	return nil
}

// Providers lists the configured identity providers by name.
func (s *Service) Providers(ctx context.Context) ([]Provider, error) {
	rows, err := s.pool.Query(ctx, "SELECT "+providerColumns+" FROM oidc_providers p ORDER BY lower(p.name)")
	if err != nil {
		return nil, fmt.Errorf("oidc: list identity providers: %w", err)
	}
	defer rows.Close()
	out := []Provider{}
	for rows.Next() {
		p, err := scanProvider(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("oidc: list identity providers: %w", err)
	}
	ptrs := make([]*Provider, len(out))
	for i := range out {
		ptrs[i] = &out[i]
	}
	return out, s.withRedirect(ctx, ptrs...)
}

// Provider returns one identity provider.
func (s *Service) Provider(ctx context.Context, id uuid.UUID) (Provider, error) {
	p, err := s.loadProvider(ctx, s.pool, id)
	if err != nil {
		return Provider{}, err
	}
	return p, s.withRedirect(ctx, &p)
}

// PublicProviders lists the enabled identity providers by name, for the sign-in page.
func (s *Service) PublicProviders(ctx context.Context) ([]PublicProvider, error) {
	rows, err := s.pool.Query(ctx, "SELECT id, name FROM oidc_providers WHERE enabled ORDER BY lower(name)")
	if err != nil {
		return nil, fmt.Errorf("oidc: list identity providers: %w", err)
	}
	out, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (PublicProvider, error) {
		var p PublicProvider
		return p, r.Scan(&p.ID, &p.Name)
	})
	if err != nil {
		return nil, fmt.Errorf("oidc: list identity providers: %w", err)
	}
	return out, nil
}

// fields are a provider's values under validation.
type fields struct {
	name, issuer, clientID, groupsClaim, caPEM string
	secret                                     []byte
	secretGiven                                bool
	scopes                                     []string
}

func plainText(s string) bool {
	return utf8.ValidString(s) && strings.IndexFunc(s, func(r rune) bool { return unicode.IsControl(r) || unicode.Is(unicode.Cf, r) }) < 0
}

// validate checks a provider's values (C13), in the order of the API body.
func (f fields) validate() error {
	var v validate.Errors
	switch n := utf8.RuneCountInString(f.name); {
	case strings.TrimSpace(f.name) == "":
		v.Add("name", validate.Required, nil)
	case n > maxNameRunes:
		v.Add("name", validate.TooLong, map[string]string{"max": strconv.Itoa(maxNameRunes)})
	case !plainText(f.name):
		v.Add("name", validate.Pattern, nil)
	}
	if claims.ValidateIssuer(f.issuer) != nil {
		v.Add("issuer_url", validate.Pattern, nil)
	}
	switch {
	case f.clientID == "":
		v.Add("client_id", validate.Required, nil)
	case len(f.clientID) > maxClientID:
		v.Add("client_id", validate.TooLong, map[string]string{"max": strconv.Itoa(maxClientID)})
	case strings.IndexFunc(f.clientID, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) >= 0 || !utf8.ValidString(f.clientID):
		v.Add("client_id", validate.Pattern, nil)
	}
	if f.secretGiven {
		switch {
		case len(f.secret) == 0:
			v.Add("client_secret", validate.Required, nil)
		case len(f.secret) > maxSecretBytes:
			v.Add("client_secret", validate.TooLong, map[string]string{"max": strconv.Itoa(maxSecretBytes)})
		}
	}
	validateScopes(&v, f.scopes)
	if !groupsClaimRE.MatchString(f.groupsClaim) {
		v.Add("groups_claim", validate.Pattern, nil)
	}
	if !validCAPEM(f.caPEM) {
		v.Add("ca_pem", validate.Pattern, nil)
	}
	return v.Err()
}

func validateScopes(v *validate.Errors, scopes []string) {
	switch {
	case len(scopes) == 0 || len(scopes) > maxScopes:
		v.Add("scopes", validate.OutOfRange, map[string]string{"min": "1", "max": strconv.Itoa(maxScopes)})
		return
	case !slices.Contains(scopes, "openid"):
		v.Add("scopes", validate.Required, map[string]string{"value": "openid"})
		return
	}
	seen := map[string]bool{}
	for _, sc := range scopes {
		if !scopeRE.MatchString(sc) {
			v.Add("scopes", validate.Pattern, nil)
			return
		}
		if seen[sc] {
			v.Add("scopes", validate.Duplicate, nil)
			return
		}
		seen[sc] = true
	}
}

// validCAPEM accepts "" or 1 to 20 PEM CERTIFICATE blocks that parse, within 64 KiB, and nothing else.
func validCAPEM(s string) bool {
	if s == "" {
		return true
	}
	if len(s) > maxCAPEMBytes {
		return false
	}
	rest, n := []byte(s), 0
	for {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			break
		}
		if b.Type != "CERTIFICATE" || n == maxCACerts {
			return false
		}
		if _, err := x509.ParseCertificate(b.Bytes); err != nil {
			return false
		}
		n++
	}
	return n > 0 && len(bytes.TrimSpace(rest)) == 0
}

// uniqueError turns a violated unique index into the field it names.
func uniqueError(err error) error {
	var pg *pgconn.PgError
	if errors.As(err, &pg) {
		switch pg.ConstraintName {
		case nameIndex:
			return validate.Errors{{Field: "name", Code: validate.Duplicate}}
		case clientIndex:
			return validate.Errors{{Field: "client_id", Code: validate.Duplicate}}
		}
	}
	return err
}

func (s *Service) publicURL(ctx context.Context) (string, error) {
	g, err := settings.GetGeneral(ctx, s.pool)
	return g.PublicURL, err
}

func providerDetails(p Provider) map[string]string {
	return map[string]string{"provider_id": p.ID.String(), "name": p.Name, "issuer": p.IssuerURL, "client_id": p.ClientID,
		"scopes": strings.Join(p.Scopes, " "), "groups_claim": p.GroupsClaim, "ca_set": strconv.FormatBool(p.CAPEM != ""),
		"enabled": strconv.FormatBool(p.Enabled)}
}

// CreateProvider validates the input, reads the provider's discovery document once and stores the provider with
// its client secret as an envelope, audited as sso.provider_created.
func (s *Service) CreateProvider(ctx context.Context, a audit.Actor, in ProviderInput) (Provider, error) {
	scopes := in.Scopes
	if scopes == nil {
		scopes = slices.Clone(defaultScopes)
	}
	groupsClaim := in.GroupsClaim
	if groupsClaim == "" {
		groupsClaim = "groups"
	}
	f := fields{name: in.Name, issuer: in.IssuerURL, clientID: in.ClientID, groupsClaim: groupsClaim, caPEM: in.CAPEM,
		secret: in.ClientSecret.Bytes(), secretGiven: true, scopes: scopes}
	if err := f.validate(); err != nil {
		return Provider{}, err
	}
	var n int
	if err := s.pool.QueryRow(ctx, "SELECT count(*) FROM oidc_providers").Scan(&n); err != nil {
		return Provider{}, fmt.Errorf("oidc: count identity providers: %w", err)
	}
	if n >= MaxProviders {
		return Provider{}, ErrTooMany
	}
	public, err := s.publicURL(ctx)
	if err != nil {
		return Provider{}, err
	}
	if in.Enabled && public == "" {
		return Provider{}, ErrPublicURLMissing
	}
	ep, err := s.discover(ctx, in.IssuerURL, in.CAPEM)
	if err != nil {
		return Provider{}, err
	}
	now := s.clock.Now().UTC()
	p := Provider{ID: uuid.Must(uuid.NewV7()), Name: in.Name, IssuerURL: in.IssuerURL, ClientID: in.ClientID, Scopes: scopes,
		GroupsClaim: groupsClaim, CAPEM: in.CAPEM, Endpoints: ep, Enabled: in.Enabled, Version: 1, HasClientSecret: true,
		CreatedAt: now, UpdatedAt: now}
	p.RedirectURI = RedirectURI(public, p.ID)
	err = db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO oidc_providers (id, name, issuer_url, client_id, scopes, groups_claim, ca_pem,
authorization_endpoint, token_endpoint, jwks_uri, enabled, version, created_by, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, 1, $12, $13, $13)`, p.ID, p.Name, p.IssuerURL, p.ClientID, p.Scopes, p.GroupsClaim,
			p.CAPEM, ep.Authorization, ep.Token, ep.JWKS, p.Enabled, userID(a), now); err != nil {
			return uniqueError(fmt.Errorf("oidc: store the identity provider: %w", err))
		}
		if err := s.keyring.PutSetting(ctx, tx, secretKey(p.ID), in.ClientSecret, now); err != nil {
			return err
		}
		_, err := s.audit.Append(ctx, tx, audit.Event{Actor: a, Action: "sso.provider_created", ObjectType: "oidc_provider",
			ObjectID: p.ID.String(), Result: audit.Success, Details: providerDetails(p)})
		return err
	})
	if err != nil {
		return Provider{}, err
	}
	return p, nil
}

// UpdateProvider changes a provider at the given version. A changed issuer or CA bundle reads discovery again; a
// given secret replaces the stored one, and a changed issuer needs one. Audited as sso.provider_changed.
func (s *Service) UpdateProvider(ctx context.Context, a audit.Actor, id uuid.UUID, version int, patch ProviderPatch) (Provider, error) {
	cur, err := s.loadProvider(ctx, s.pool, id)
	if err != nil {
		return Provider{}, err
	}
	if cur.Version != version {
		return Provider{}, ErrVersion
	}
	p := cur
	set := func(dst *string, src *string) {
		if src != nil {
			*dst = *src
		}
	}
	set(&p.Name, patch.Name)
	set(&p.IssuerURL, patch.IssuerURL)
	set(&p.ClientID, patch.ClientID)
	set(&p.GroupsClaim, patch.GroupsClaim)
	set(&p.CAPEM, patch.CAPEM)
	if patch.Scopes != nil {
		p.Scopes = *patch.Scopes
	}
	if patch.Enabled != nil {
		p.Enabled = *patch.Enabled
	}
	f := fields{name: p.Name, issuer: p.IssuerURL, clientID: p.ClientID, groupsClaim: p.GroupsClaim, caPEM: p.CAPEM, scopes: p.Scopes}
	if patch.ClientSecret != nil {
		f.secret, f.secretGiven = patch.ClientSecret.Bytes(), true
	} else if p.IssuerURL != cur.IssuerURL {
		// The stored client secret is never sent to another issuer: a new issuer needs the secret again (a 422 on
		// client_secret), so an Administrator or a stepped-up session cannot redirect it to a provider they control.
		f.secretGiven = true
	}
	if err := f.validate(); err != nil {
		return Provider{}, err
	}
	if p.IssuerURL != cur.IssuerURL {
		// I-1: SSO users are matched by (provider, subject) and a subject is only unique within its issuer (O-09);
		// pointing a provider with users at another issuer would hand their accounts to that issuer's subjects.
		var inUse bool
		if err := s.pool.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM users WHERE oidc_provider_id = $1)", id).Scan(&inUse); err != nil {
			return Provider{}, fmt.Errorf("oidc: read the provider's users: %w", err)
		}
		if inUse {
			return Provider{}, ErrProviderInUse
		}
	}
	public, err := s.publicURL(ctx)
	if err != nil {
		return Provider{}, err
	}
	if p.Enabled && public == "" {
		return Provider{}, ErrPublicURLMissing
	}
	if p.IssuerURL != cur.IssuerURL || p.CAPEM != cur.CAPEM {
		if p.Endpoints, err = s.discover(ctx, p.IssuerURL, p.CAPEM); err != nil {
			return Provider{}, err
		}
	}
	now := s.clock.Now().UTC()
	err = db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		if p.IssuerURL != cur.IssuerURL {
			// Checked again under the provider's row lock: a first sign-in's user insert takes FOR KEY SHARE on
			// this row (the foreign key), so it cannot slip in between. Two statements: the EXISTS must run with a
			// snapshot taken after the lock was granted, so it sees a user committed while this waited.
			if _, err := tx.Exec(ctx, "SELECT 1 FROM oidc_providers WHERE id = $1 FOR UPDATE", id); err != nil {
				return fmt.Errorf("oidc: lock the provider: %w", err)
			}
			var inUse bool
			if err := tx.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM users WHERE oidc_provider_id = $1)", id).Scan(&inUse); err != nil {
				return fmt.Errorf("oidc: read the provider's users: %w", err)
			}
			if inUse {
				return ErrProviderInUse
			}
		}
		tag, err := tx.Exec(ctx, `UPDATE oidc_providers SET name = $3, issuer_url = $4, client_id = $5, scopes = $6, groups_claim = $7,
ca_pem = $8, authorization_endpoint = $9, token_endpoint = $10, jwks_uri = $11, enabled = $12, version = version + 1, updated_at = $13
WHERE id = $1 AND version = $2`, id, version, p.Name, p.IssuerURL, p.ClientID, p.Scopes, p.GroupsClaim, p.CAPEM,
			p.Endpoints.Authorization, p.Endpoints.Token, p.Endpoints.JWKS, p.Enabled, now)
		if err != nil {
			return uniqueError(fmt.Errorf("oidc: update the identity provider: %w", err))
		}
		if tag.RowsAffected() == 0 {
			return ErrVersion
		}
		if patch.ClientSecret != nil {
			if err := s.keyring.PutSetting(ctx, tx, secretKey(id), *patch.ClientSecret, now); err != nil {
				return err
			}
		}
		d := providerDetails(p)
		d["client_auth_replaced"] = strconv.FormatBool(patch.ClientSecret != nil)
		_, err = s.audit.Append(ctx, tx, audit.Event{Actor: a, Action: "sso.provider_changed", ObjectType: "oidc_provider",
			ObjectID: id.String(), Result: audit.Success, Details: d})
		return err
	})
	if err != nil {
		return Provider{}, err
	}
	return s.Provider(ctx, id)
}

// RefreshProvider reads the provider's discovery document again (the Administrator's action, never a sign-in).
func (s *Service) RefreshProvider(ctx context.Context, a audit.Actor, id uuid.UUID, version int) (Provider, error) {
	cur, err := s.loadProvider(ctx, s.pool, id)
	if err != nil {
		return Provider{}, err
	}
	if cur.Version != version {
		return Provider{}, ErrVersion
	}
	ep, err := s.discover(ctx, cur.IssuerURL, cur.CAPEM)
	if err != nil {
		return Provider{}, err
	}
	err = db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE oidc_providers SET authorization_endpoint = $3, token_endpoint = $4, jwks_uri = $5,
version = version + 1, updated_at = $6 WHERE id = $1 AND version = $2`, id, version, ep.Authorization, ep.Token, ep.JWKS, s.clock.Now().UTC())
		if err != nil {
			return fmt.Errorf("oidc: refresh the identity provider: %w", err)
		}
		if tag.RowsAffected() == 0 {
			return ErrVersion
		}
		_, err = s.audit.Append(ctx, tx, audit.Event{Actor: a, Action: "sso.provider_refreshed", ObjectType: "oidc_provider",
			ObjectID: id.String(), Result: audit.Success, Details: map[string]string{"provider_id": id.String()}})
		return err
	})
	if err != nil {
		return Provider{}, err
	}
	return s.Provider(ctx, id)
}

// DeleteProvider removes a provider that has no users (ErrProviderInUse otherwise), its mappings and its secret.
func (s *Service) DeleteProvider(ctx context.Context, a audit.Actor, id uuid.UUID, version int) error {
	err := db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		var name string
		err := tx.QueryRow(ctx, "DELETE FROM oidc_providers WHERE id = $1 AND version = $2 RETURNING name", id, version).Scan(&name)
		if errors.Is(err, pgx.ErrNoRows) {
			if _, lerr := s.loadProvider(ctx, tx, id); lerr != nil {
				return lerr
			}
			return ErrVersion
		}
		var pg *pgconn.PgError
		if errors.As(err, &pg) && pg.Code == foreignKeyViolation {
			return ErrProviderInUse
		}
		if err != nil {
			return fmt.Errorf("oidc: delete the identity provider: %w", err)
		}
		if err := secrets.DeleteSetting(ctx, tx, secretKey(id)); err != nil {
			return err
		}
		_, err = s.audit.Append(ctx, tx, audit.Event{Actor: a, Action: "sso.provider_deleted", ObjectType: "oidc_provider",
			ObjectID: id.String(), Result: audit.Success, Details: map[string]string{"provider_id": id.String(), "name": name}})
		return err
	})
	return err
}
