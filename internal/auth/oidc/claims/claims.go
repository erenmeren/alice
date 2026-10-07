// Package claims checks the claims of an OpenID Connect ID token after its signature was verified (spec §15.3
// SEC-012, §25.5 O-02 and O-03; R42 rows 18-24). It is pure: the caller passes the expected values and the time.
package claims

import (
	"bytes"
	"crypto/subtle"
	"encoding/json"
	"math"
	"slices"
	"time"
)

// Leeway is the clock skew accepted on exp, iat, nbf and auth_time (SEC-012).
const Leeway = 60 * time.Second

// Claims are the standard claims Alice reads; the raw claims are kept for Groups.
type Claims struct {
	Issuer            string
	Audience          []string
	AuthorizedParty   string
	Subject           string
	Nonce             string
	Expiry            time.Time
	IssuedAt          time.Time
	NotBefore         time.Time
	AuthTime          time.Time
	Email             string
	Name              string
	PreferredUsername string
	UPN               string

	raw map[string]json.RawMessage
}

// Reason is the closed reason of a refused token; it is safe to log and audit.
type Reason string

// Reasons.
const (
	ReasonMalformed Reason = "malformed"
	ReasonIssuer    Reason = "issuer"
	ReasonAudience  Reason = "audience"
	ReasonAzp       Reason = "azp"
	ReasonSubject   Reason = "subject"
	ReasonExpired   Reason = "expired"
	ReasonIssuedAt  Reason = "issued_at"
	ReasonNotBefore Reason = "not_before"
	ReasonNonce     Reason = "nonce"
	ReasonAuthTime  Reason = "auth_time"
)

// Error is a refused token. Its text names the reason only, never a claim value.
type Error struct{ Reason Reason }

func (e *Error) Error() string { return "claims: the ID token was refused (" + string(e.Reason) + ")" }

func fail(r Reason) error { return &Error{Reason: r} }

// Parse reads the claims of a payload whose signature was already checked.
func Parse(payload []byte) (Claims, error) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(payload, &raw); err != nil || raw == nil {
		return Claims{}, fail(ReasonMalformed)
	}
	c := Claims{raw: raw}
	for key, dst := range map[string]*string{"iss": &c.Issuer, "azp": &c.AuthorizedParty, "sub": &c.Subject, "nonce": &c.Nonce,
		"email": &c.Email, "name": &c.Name, "preferred_username": &c.PreferredUsername, "upn": &c.UPN} {
		if v, ok := raw[key]; ok && !isNull(v) {
			if err := json.Unmarshal(v, dst); err != nil {
				return Claims{}, fail(ReasonMalformed)
			}
		}
	}
	if v, ok := raw["aud"]; ok && !isNull(v) {
		var one string
		if err := json.Unmarshal(v, &one); err == nil {
			c.Audience = []string{one}
		} else if err := json.Unmarshal(v, &c.Audience); err != nil {
			return Claims{}, fail(ReasonMalformed)
		}
	}
	for key, dst := range map[string]*time.Time{"exp": &c.Expiry, "iat": &c.IssuedAt, "nbf": &c.NotBefore, "auth_time": &c.AuthTime} {
		if v, ok := raw[key]; ok && !isNull(v) {
			var f float64
			if err := json.Unmarshal(v, &f); err != nil || math.IsNaN(f) || f < 0 || f > 1e11 {
				return Claims{}, fail(ReasonMalformed)
			}
			*dst = time.Unix(int64(f), 0).UTC()
		}
	}
	return c, nil
}

func isNull(v json.RawMessage) bool { return bytes.Equal(bytes.TrimSpace(v), []byte("null")) }

// Expect holds what a token must say.
type Expect struct {
	Issuer, ClientID, Nonce string
	Now                     time.Time
	MaxAuthAge              time.Duration
}

// Validate checks c against e and returns nil or an *Error.
func Validate(c Claims, e Expect) error {
	now := e.Now
	switch {
	case c.Issuer != e.Issuer:
		return fail(ReasonIssuer)
	case !slices.Contains(c.Audience, e.ClientID):
		return fail(ReasonAudience)
	case len(c.Audience) > 1 && c.AuthorizedParty != e.ClientID, c.AuthorizedParty != "" && c.AuthorizedParty != e.ClientID:
		return fail(ReasonAzp)
	case c.Subject == "" || len(c.Subject) > 255:
		return fail(ReasonSubject)
	case c.Expiry.IsZero() || !now.Before(c.Expiry.Add(Leeway)):
		return fail(ReasonExpired)
	case c.IssuedAt.IsZero() || c.IssuedAt.After(now.Add(Leeway)):
		return fail(ReasonIssuedAt)
	case !c.NotBefore.IsZero() && c.NotBefore.After(now.Add(Leeway)):
		return fail(ReasonNotBefore)
	case e.Nonce == "" || subtle.ConstantTimeCompare([]byte(c.Nonce), []byte(e.Nonce)) != 1:
		return fail(ReasonNonce)
	}
	if e.MaxAuthAge > 0 && (c.AuthTime.IsZero() || c.AuthTime.After(now.Add(Leeway)) || now.Sub(c.AuthTime) > e.MaxAuthAge+Leeway) {
		return fail(ReasonAuthTime)
	}
	return nil
}
