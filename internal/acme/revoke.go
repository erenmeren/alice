package acme

import (
	"context"
	"errors"
	"net/http"

	xacme "golang.org/x/crypto/acme"
)

// RevocationReason is an RFC 5280 CRLReason code a revocation request carries (RFC 8555 section 7.6). Alice offers the
// five reasons a subscriber may give (public CAs accept exactly these): unspecified, keyCompromise, affiliationChanged,
// superseded and cessationOfOperation. cACompromise, certificateHold, removeFromCRL, privilegeWithdrawn and
// aACompromise are a CA's own reasons and are refused locally.
type RevocationReason int

// The reasons Alice sends.
const (
	RevokeUnspecified          RevocationReason = 0
	RevokeKeyCompromise        RevocationReason = 1
	RevokeAffiliationChanged   RevocationReason = 3
	RevokeSuperseded           RevocationReason = 4
	RevokeCessationOfOperation RevocationReason = 5
)

var revocationNames = map[RevocationReason]string{
	RevokeUnspecified: "unspecified", RevokeKeyCompromise: "keyCompromise", RevokeAffiliationChanged: "affiliationChanged",
	RevokeSuperseded: "superseded", RevokeCessationOfOperation: "cessationOfOperation",
}

// RevocationReasonNames lists the reasons Alice sends by their RFC 5280 names, in code order.
func RevocationReasonNames() []string {
	return []string{"unspecified", "keyCompromise", "affiliationChanged", "superseded", "cessationOfOperation"}
}

// String is the RFC 5280 name ("" for a reason Alice does not send).
func (r RevocationReason) String() string { return revocationNames[r] }

// Valid reports whether Alice sends the reason.
func (r RevocationReason) Valid() bool { _, ok := revocationNames[r]; return ok }

// ParseRevocationReason reads an RFC 5280 reason name (exact case, as RFC 5280 spells it).
func ParseRevocationReason(name string) (RevocationReason, bool) {
	for r, n := range revocationNames {
		if n == name {
			return r, true
		}
	}
	return 0, false
}

// Sentinels of a revocation.
var (
	// ErrRevokeUnsupported: the CA's directory has no revokeCert.
	ErrRevokeUnsupported = errors.New("acme: the CA does not offer certificate revocation")
	// ErrRevocationReason: a reason Alice does not send (refused before any request).
	ErrRevocationReason = errors.New("acme: the revocation reason is not one a subscriber gives")
)

// Revoke asks the CA to revoke the certificate whose leaf DER is given, signed with the account key (the JWS kid: the
// account that ordered it; RFC 8555 section 7.6). A CA that answers alreadyRevoked has the end state asked for: Revoke
// returns nil (golang.org/x/crypto/acme does so too). Errors, each an *Error: ReasonRevokeUnsupported when the directory
// has no revokeCert (no request is sent); ReasonRevokeReasonRefused for a reason Alice does not send (no request) or
// that the CA refuses (badRevocationReason); ReasonRevokeUnauthorized when the CA refuses this account for this
// certificate (unauthorized, or a 403/404: the account did not order it, or the CA does not know it); otherwise the
// usual classification (unreachable, rate limited, account rejected, ...).
func (c *Client) Revoke(ctx context.Context, leafDER []byte, reason RevocationReason) error {
	if c.cfg.Key == nil {
		return newError(ReasonAccountRejected, ErrNoKey)
	}
	if !reason.Valid() {
		return newError(ReasonRevokeReasonRefused, ErrRevocationReason)
	}
	if len(leafDER) == 0 {
		return newError(ReasonRevokeUnauthorized, ErrBadAnswer)
	}
	d, err := c.Discover(ctx)
	if err != nil {
		return err
	}
	if !d.SupportsRevocation() {
		return newError(ReasonRevokeUnsupported, ErrRevokeUnsupported)
	}
	err = c.call(ctx, func(ctx context.Context) error {
		return c.lib.RevokeCert(ctx, nil, leafDER, xacme.CRLReasonCode(reason))
	})
	if err == nil {
		return nil
	}
	ce := c.classify(err, opAccount, "", "")
	var e *Error
	if errors.As(ce, &e) {
		switch t := shortType(e.ProblemType); {
		case t == "badRevocationReason":
			e.Reason = ReasonRevokeReasonRefused
		case t == "unauthorized", t == "" && (e.Status == http.StatusForbidden || e.Status == http.StatusNotFound),
			t == "malformed" && e.Status == http.StatusNotFound:
			e.Reason = ReasonRevokeUnauthorized
		}
	}
	return ce
}
