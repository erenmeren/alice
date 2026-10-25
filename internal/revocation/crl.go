package revocation

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"net/http"
	"net/url"
)

// checkCRL reads the CRL at u (cached for the run, per issuer) and looks for leaf's serial. The CRL counts only when the
// issuer signed it, it names the leaf's issuer and it is not a delta CRL; a listed serial counts even in a stale CRL (a
// revocation is permanent), an unlisted one only in a current CRL; an entry with removeFromCRL is no revocation (R64
// Ruling 16, final review M1). The cache key is the address and the issuer: a CRL verified for one issuer is never
// searched for a leaf of another (final review C2).
func (r *Run) checkCRL(ctx context.Context, u *url.URL, leaf, issuer *x509.Certificate) Result {
	key := crlKey(u, issuer)
	e, ok := r.crls[key]
	if !ok {
		var size int
		e, size = r.fetchCRL(ctx, u, leaf, issuer)
		if e.code != codeDeferred && size <= maxCachedCRLBytes && len(r.crls) < maxCachedCRLs {
			r.crls[key] = e
		}
	}
	if e.code != "" {
		return failed(e.code)
	}
	for _, entry := range e.list.RevokedCertificateEntries {
		if entry.SerialNumber != nil && entry.SerialNumber.Cmp(leaf.SerialNumber) == 0 && entry.ReasonCode != reasonRemoveFromCRL {
			return revokedResult("crl", entry.ReasonCode, entry.RevocationTime)
		}
	}
	if !e.list.NextUpdate.IsZero() && e.list.NextUpdate.Before(r.c.clk.Now().Add(-freshness)) {
		return failed(CodeInvalidAnswer)
	}
	return Result{Status: StatusGood, Method: "crl"}
}

// crlKey is the cache key of a CRL: its address and the SHA-256 of the issuer's public key and name.
func crlKey(u *url.URL, issuer *x509.Certificate) string {
	h := sha256.New()
	h.Write(issuer.RawSubjectPublicKeyInfo)
	h.Write(issuer.RawSubject)
	return hex.EncodeToString(h.Sum(nil)) + " " + u.String()
}

// oidDeltaCRLIndicator marks a delta CRL (RFC 5280 §5.2.4), which lists changes only: Alice does not read one.
var oidDeltaCRLIndicator = asn1.ObjectIdentifier{2, 5, 29, 27}

// fetchCRL fetches and verifies a CRL (DER, or one PEM block labelled X509 CRL) and answers its size.
func (r *Run) fetchCRL(ctx context.Context, u *url.URL, leaf, issuer *x509.Certificate) (crlEntry, int) {
	body, code := r.fetch(ctx, http.MethodGet, u, nil, maxCRLAnswer)
	if code != "" {
		return crlEntry{code: code}, 0
	}
	if blk, _ := pem.Decode(body); blk != nil && blk.Type == "X509 CRL" {
		body = blk.Bytes
	}
	list, err := x509.ParseRevocationList(body)
	if err != nil || list.CheckSignatureFrom(issuer) != nil || !bytes.Equal(list.RawIssuer, leaf.RawIssuer) {
		return crlEntry{code: CodeInvalidAnswer}, len(body)
	}
	for _, ext := range list.Extensions {
		if ext.Id.Equal(oidDeltaCRLIndicator) {
			return crlEntry{code: CodeInvalidAnswer}, len(body)
		}
	}
	return crlEntry{list: list}, len(body)
}
