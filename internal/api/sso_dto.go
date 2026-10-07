package api

import (
	"time"

	"github.com/google/uuid"

	"alice/internal/auth/oidc"
)

// The single sign-on answers (C13). A provider never carries its client secret: has_client_secret says one is stored (S-08).

type endpointsDTO struct {
	Authorization string `json:"authorization"`
	Token         string `json:"token"`
	JWKS          string `json:"jwks"`
}

type identityProviderDTO struct {
	ID              uuid.UUID    `json:"id"`
	Name            string       `json:"name"`
	IssuerURL       string       `json:"issuer_url"`
	ClientID        string       `json:"client_id"`
	HasClientSecret bool         `json:"has_client_secret"`
	Scopes          []string     `json:"scopes"`
	GroupsClaim     string       `json:"groups_claim"`
	CAPEM           string       `json:"ca_pem"`
	Endpoints       endpointsDTO `json:"endpoints"`
	Enabled         bool         `json:"enabled"`
	RedirectURI     string       `json:"redirect_uri"`
	Version         int          `json:"version"`
	CreatedAt       time.Time    `json:"created_at"`
	UpdatedAt       time.Time    `json:"updated_at"`
}

func identityProviderJSON(p oidc.Provider) identityProviderDTO {
	return identityProviderDTO{ID: p.ID, Name: p.Name, IssuerURL: p.IssuerURL, ClientID: p.ClientID, HasClientSecret: p.HasClientSecret,
		Scopes: nonNil(p.Scopes), GroupsClaim: p.GroupsClaim, CAPEM: p.CAPEM,
		Endpoints: endpointsDTO{Authorization: p.Endpoints.Authorization, Token: p.Endpoints.Token, JWKS: p.Endpoints.JWKS},
		Enabled:   p.Enabled, RedirectURI: p.RedirectURI, Version: p.Version, CreatedAt: p.CreatedAt.UTC(), UpdatedAt: p.UpdatedAt.UTC()}
}

type publicProviderDTO struct {
	ID   uuid.UUID `json:"id"`
	Name string    `json:"name"`
}

type mappingDTO struct {
	ID         uuid.UUID `json:"id"`
	ProviderID uuid.UUID `json:"provider_id"`
	Group      string    `json:"group"`
	Role       string    `json:"role"`
	CreatedAt  time.Time `json:"created_at"`
}

func mappingJSON(m oidc.Mapping) mappingDTO {
	return mappingDTO{ID: m.ID, ProviderID: m.ProviderID, Group: m.Group, Role: string(m.Role), CreatedAt: m.CreatedAt.UTC()}
}

type ssoSettingsDTO struct {
	AllowAdminRole bool `json:"allow_admin_role"`
	Version        int  `json:"version"`
}
