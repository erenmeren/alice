package fakeacme

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"math/big"
	"net/http"
	"strings"
	"time"
)

// acceptedReasons are the RFC 5280 reason codes the fake accepts in a revocation request: unspecified (0),
// keyCompromise (1), affiliationChanged (3), superseded (4) and cessationOfOperation (5), as public CAs do (Let's Encrypt
// accepts exactly these). cACompromise, certificateHold, removeFromCRL, privilegeWithdrawn, aACompromise and unknown
// values are badRevocationReason (RFC 8555 section 7.6).
var acceptedReasons = map[int]bool{0: true, 1: true, 3: true, 4: true, 5: true}

// handleRevoke answers POST revokeCert (RFC 8555 section 7.6). The request is signed either by an account (kid) or by
// the certificate's own key (jwk). An account may revoke only the certificates it ordered (GUESS: public CAs also
// accept an account that holds valid authorizations for every name; the fake does not), a jwk only the certificate of
// that key; anything else is unauthorized (403). A certificate the fake never issued is 404 malformed (GUESS), a reason
// it does not accept 400 badRevocationReason, a certificate revoked already 400 alreadyRevoked (the first reason
// stays). Success is 200 with an empty body.
func (s *Server) handleRevoke(w http.ResponseWriter, _ *http.Request, req *jwsReq) {
	var p struct {
		Certificate string `json:"certificate"`
		Reason      *int   `json:"reason"`
	}
	if prob := decodeJSON(req.payload, &p); prob != nil {
		s.writeProblem(w, prob)
		return
	}
	der, err := base64.RawURLEncoding.DecodeString(p.Certificate)
	if err != nil || len(der) == 0 {
		s.writeProblem(w, malformed(http.StatusBadRequest, "the certificate is not base64url DER"))
		return
	}
	reason := 0
	if p.Reason != nil {
		reason = *p.Reason
	}
	if !acceptedReasons[reason] {
		s.writeProblem(w, newProblem(http.StatusBadRequest, "badRevocationReason", "the CA does not accept this revocation reason"))
		return
	}
	s.mu.Lock()
	var c *issued
	for _, x := range s.st.certs {
		if bytes.Equal(x.leaf.Raw, der) {
			c = x
			break
		}
	}
	if c == nil {
		s.mu.Unlock()
		s.writeProblem(w, malformed(http.StatusNotFound, "the CA did not issue this certificate"))
		return
	}
	authorized := false
	if req.acct != nil {
		authorized = c.account == req.acct.id
	} else {
		authorized = samePublicKey(c.leaf, req.key)
	}
	switch {
	case !authorized:
		s.mu.Unlock()
		s.writeProblem(w, newProblem(http.StatusForbidden, "unauthorized", "the requester may not revoke this certificate"))
		return
	case !c.revokedAt.IsZero():
		s.mu.Unlock()
		s.writeProblem(w, newProblem(http.StatusBadRequest, "alreadyRevoked", "the certificate is revoked already"))
		return
	}
	c.revokedAt, c.reason = s.now(), reason
	s.st.counters["revoked"]++
	s.mu.Unlock()
	w.WriteHeader(http.StatusOK)
}

// samePublicKey reports whether pub is the leaf's public key (compared by its SubjectPublicKeyInfo encoding).
func samePublicKey(leaf *x509.Certificate, pub any) bool {
	if pub == nil {
		return false
	}
	spki, err := x509.MarshalPKIXPublicKey(pub)
	return err == nil && bytes.Equal(spki, leaf.RawSubjectPublicKeyInfo)
}

// CertStatus is what the fake says about a certificate it issued: "valid" or "revoked", and for a revoked one when and
// with which RFC 5280 reason code.
type CertStatus struct {
	Serial    string    `json:"serial"`
	Status    string    `json:"status"`
	Reason    int       `json:"reason"`
	RevokedAt time.Time `json:"revoked_at"`
	NotAfter  time.Time `json:"not_after"`
}

// CertificateStatus reports the status of the certificate with that serial number (hexadecimal, any case, leading zeros
// ignored); false when the fake did not issue it (or forgot it in a Reset).
func (s *Server) CertificateStatus(serialHex string) (CertStatus, bool) {
	want, ok := new(big.Int).SetString(strings.TrimPrefix(strings.TrimPrefix(serialHex, "0x"), "0X"), 16) // either case of hex digit
	if !ok {
		return CertStatus{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, c := range s.st.certs {
		if c.leaf.SerialNumber.Cmp(want) != 0 {
			continue
		}
		st := CertStatus{Serial: c.leaf.SerialNumber.Text(16), Status: "valid", NotAfter: c.leaf.NotAfter.UTC()}
		if !c.revokedAt.IsZero() {
			st.Status, st.Reason, st.RevokedAt = "revoked", c.reason, c.revokedAt.UTC()
		}
		return st, true
	}
	return CertStatus{}, false
}

// adminCertificate is GET /certificate?serial=<hex> of the control API.
func (s *Server) adminCertificate(q func(string) string) (any, *adminError) {
	st, ok := s.CertificateStatus(q("serial"))
	if !ok {
		return nil, &adminError{status: http.StatusNotFound, msg: "no certificate with that serial number"}
	}
	return st, nil
}
