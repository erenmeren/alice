package revocation

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/url"
)

// checkCRL reads the CRL at u (cached for the run) and looks for leaf's serial. The CRL counts only when the issuer
// signed it and it names the leaf's issuer; a listed serial counts even in a stale CRL (a revocation is permanent), an
// unlisted one only in a current CRL (R64 Ruling 16).
func (r *Run) checkCRL(ctx context.Context, u *url.URL, leaf, issuer *x509.Certificate) Result {
	key := u.String()
	e, ok := r.crls[key]
	if !ok {
		e = r.fetchCRL(ctx, u, leaf, issuer)
		if e.code != codeDeferred && len(r.crls) < maxCachedCRLs {
			r.crls[key] = e
		}
	}
	if e.code != "" {
		return failed(e.code)
	}
	for _, entry := range e.list.RevokedCertificateEntries {
		if entry.SerialNumber != nil && entry.SerialNumber.Cmp(leaf.SerialNumber) == 0 {
			return revokedResult("crl", entry.ReasonCode, entry.RevocationTime)
		}
	}
	if !e.list.NextUpdate.IsZero() && e.list.NextUpdate.Before(r.c.clk.Now().Add(-freshness)) {
		return failed(CodeInvalidAnswer)
	}
	return Result{Status: StatusGood, Method: "crl"}
}

// fetchCRL fetches and verifies a CRL: DER, or one PEM block labelled X509 CRL.
func (r *Run) fetchCRL(ctx context.Context, u *url.URL, leaf, issuer *x509.Certificate) crlEntry {
	body, code := r.fetch(ctx, http.MethodGet, u, nil, maxCRLAnswer)
	if code != "" {
		return crlEntry{code: code}
	}
	if blk, _ := pem.Decode(body); blk != nil && blk.Type == "X509 CRL" {
		body = blk.Bytes
	}
	list, err := x509.ParseRevocationList(body)
	if err != nil || list.CheckSignatureFrom(issuer) != nil || !bytes.Equal(list.RawIssuer, leaf.RawIssuer) {
		return crlEntry{code: CodeInvalidAnswer}
	}
	return crlEntry{list: list}
}
