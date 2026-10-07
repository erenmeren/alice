package oidc

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"alice/internal/auth/oidc/claims"
	"alice/internal/platform/validate"
)

// discoveryDoc is the part of the OpenID Provider metadata Alice reads.
type discoveryDoc struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
}

// discover reads the provider's discovery document once, at configuration time (R42 row 11): the issuer must match
// exactly, every endpoint must be an https:// address, and the key set must hold at least one signing key.
func (s *Service) discover(ctx context.Context, issuer, caPEM string) (Endpoints, error) {
	client, err := s.httpClient(caPEM)
	if errors.Is(err, errCABundle) {
		return Endpoints{}, validate.Errors{{Field: "ca_pem", Code: validate.Pattern}}
	}
	if err != nil {
		return Endpoints{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimSuffix(issuer, "/")+"/.well-known/openid-configuration", nil)
	if err != nil {
		return Endpoints{}, &DiscoveryError{Cause: "connect"}
	}
	res, err := client.Do(req)
	if err != nil {
		return Endpoints{}, &DiscoveryError{Cause: transportCause(err)}
	}
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusOK {
		return Endpoints{}, &DiscoveryError{Cause: "status"}
	}
	var doc discoveryDoc
	if err := json.NewDecoder(res.Body).Decode(&doc); err != nil || doc.Issuer == "" || doc.AuthorizationEndpoint == "" ||
		doc.TokenEndpoint == "" || doc.JWKSURI == "" {
		return Endpoints{}, &DiscoveryError{Cause: "document"}
	}
	if doc.Issuer != issuer {
		return Endpoints{}, &DiscoveryError{Cause: "issuer_mismatch"}
	}
	for _, e := range []string{doc.AuthorizationEndpoint, doc.TokenEndpoint, doc.JWKSURI} {
		if claims.ValidateIssuer(e) != nil {
			return Endpoints{}, &DiscoveryError{Cause: "not_https"}
		}
	}
	keys, _, err := newKeySet(client, doc.JWKSURI, s.clock).fetch(ctx)
	if err != nil || len(keys) == 0 {
		return Endpoints{}, &DiscoveryError{Cause: "jwks"}
	}
	return Endpoints{Authorization: doc.AuthorizationEndpoint, Token: doc.TokenEndpoint, JWKS: doc.JWKSURI}, nil
}

// transportCause tells a certificate problem from any other connection failure.
func transportCause(err error) string {
	var (
		verify   *tls.CertificateVerificationError
		unknown  x509.UnknownAuthorityError
		hostname x509.HostnameError
		invalid  x509.CertificateInvalidError
	)
	if errors.As(err, &verify) || errors.As(err, &unknown) || errors.As(err, &hostname) || errors.As(err, &invalid) {
		return "tls"
	}
	return "connect"
}
