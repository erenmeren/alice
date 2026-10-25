package revocation

import (
	"context"
	"crypto"
	"crypto/x509"
	"net/http"
	"net/url"
	"slices"
	"time"

	"golang.org/x/crypto/ocsp"
)

// checkOCSP asks the responder at u about leaf. Only a response the issuer signed (or a responder certificate the
// issuer signed for OCSP signing, which the library checks) and that is current decides; no nonce is sent (RFC 5019
// responders ignore it; the freshness window is the replay control, R64 Ruling 16).
func (r *Run) checkOCSP(ctx context.Context, u *url.URL, leaf, issuer *x509.Certificate) Result {
	req, err := ocsp.CreateRequest(leaf, issuer, &ocsp.RequestOptions{Hash: crypto.SHA1})
	if err != nil {
		return failed(CodeInvalidAnswer)
	}
	body, code := r.fetch(ctx, http.MethodPost, u, req, maxOCSPAnswer)
	if code != "" {
		return failed(code)
	}
	now := r.c.clk.Now()
	resp, err := ocsp.ParseResponseForCert(body, leaf, issuer)
	if err != nil || !delegateAllowed(resp, issuer, now) || !ocspFresh(resp, now) {
		return failed(CodeInvalidAnswer)
	}
	switch {
	case resp.Status == ocsp.Good, resp.Status == ocsp.Revoked && resp.RevocationReason == reasonRemoveFromCRL:
		return Result{Status: StatusGood, Method: "ocsp"} // removeFromCRL lifts a hold: never a revocation
	case resp.Status == ocsp.Revoked:
		return revokedResult("ocsp", resp.RevocationReason, resp.RevokedAt)
	}
	return Result{Status: StatusUnknown, Method: "ocsp"}
}

// delegateAllowed reports whether the response's signer may speak for the issuer (final review C1, R64). The library
// checks that the issuer signed a delegated responder's certificate but not its purpose or validity: a delegated
// responder needs id-kp-OCSPSigning (RFC 6960 §4.2.2.2) and must be valid now; otherwise any leaf of the CA could sign
// "revoked" for every certificate of it.
func delegateAllowed(resp *ocsp.Response, issuer *x509.Certificate, now time.Time) bool {
	d := resp.Certificate
	if d == nil || d.Equal(issuer) {
		return true // signed by the issuer itself (ParseResponseForCert verified the signature)
	}
	return slices.Contains(d.ExtKeyUsage, x509.ExtKeyUsageOCSPSigning) && !now.Before(d.NotBefore) && !now.After(d.NotAfter)
}

// maxOCSPAge is how old an answer without a next update may be (final review M4).
const maxOCSPAge = 7 * 24 * time.Hour

// ocspFresh reports whether a response is current at now: not issued in the future and not past its next update,
// each with the allowed skew; an answer without a next update counts for at most 7 days after it was issued.
func ocspFresh(resp *ocsp.Response, now time.Time) bool {
	if resp.ThisUpdate.After(now.Add(freshness)) {
		return false
	}
	if resp.NextUpdate.IsZero() {
		return !resp.ThisUpdate.Before(now.Add(-maxOCSPAge))
	}
	return !resp.NextUpdate.Before(now.Add(-freshness))
}
