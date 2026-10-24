package revocation

import (
	"context"
	"crypto"
	"crypto/x509"
	"net/http"
	"net/url"
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
	resp, err := ocsp.ParseResponseForCert(body, leaf, issuer)
	if err != nil || !ocspFresh(resp, r.c.clk.Now()) {
		return failed(CodeInvalidAnswer)
	}
	switch resp.Status {
	case ocsp.Good:
		return Result{Status: StatusGood, Method: "ocsp"}
	case ocsp.Revoked:
		return revokedResult("ocsp", resp.RevocationReason, resp.RevokedAt)
	}
	return Result{Status: StatusUnknown, Method: "ocsp"}
}

// ocspFresh reports whether a response is current at now: not issued in the future and not past its next update,
// each with the allowed skew.
func ocspFresh(resp *ocsp.Response, now time.Time) bool {
	if resp.ThisUpdate.After(now.Add(freshness)) {
		return false
	}
	return resp.NextUpdate.IsZero() || !resp.NextUpdate.Before(now.Add(-freshness))
}
