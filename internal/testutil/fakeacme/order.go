package fakeacme

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	orderLifetime = 7 * 24 * time.Hour
	maxIdents     = 100
)

var labelRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// checkName validates a dns identifier value (a wildcard keeps its "*.").
func checkName(v string) (base string, wildcard bool, err error) {
	base = v
	if rest, ok := strings.CutPrefix(v, "*."); ok {
		base, wildcard = rest, true
	}
	if base != asciiLower(base) || len(base) > 253 || strings.Count(base, ".") < 1 {
		return "", false, fmt.Errorf("%q is not a fully qualified lower-case name", v)
	}
	for _, l := range strings.Split(base, ".") {
		if !labelRE.MatchString(l) {
			return "", false, fmt.Errorf("%q is not a valid DNS name", v)
		}
	}
	return base, wildcard, nil
}

func (s *Server) rejected(base string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, r := range s.cfg.rejected {
		if base == r || strings.HasSuffix(base, "."+r) {
			return true
		}
	}
	return false
}

func (s *Server) handleNewOrder(w http.ResponseWriter, _ *http.Request, req *jwsReq) {
	var p struct {
		Identifiers []identifier `json:"identifiers"`
	}
	if prob := decodeJSON(req.payload, &p); prob != nil {
		s.writeProblem(w, prob)
		return
	}
	if len(p.Identifiers) == 0 || len(p.Identifiers) > maxIdents {
		s.writeProblem(w, malformed(http.StatusBadRequest, "an order needs 1 to 100 identifiers"))
		return
	}
	s.mu.Lock()
	offered := append([]string(nil), s.cfg.challenges...)
	s.mu.Unlock()
	now := s.now()
	o := &order{id: randHex(8), account: req.acct.id, status: "pending", expires: now.Add(orderLifetime)}
	var azs []*authz
	seen := map[string]bool{}
	for _, id := range p.Identifiers {
		if id.Type != "dns" {
			s.writeProblem(w, newProblem(http.StatusBadRequest, "unsupportedIdentifier", "only dns identifiers are supported"))
			return
		}
		base, wild, err := checkName(id.Value)
		if err != nil {
			s.writeProblem(w, newProblem(http.StatusBadRequest, "rejectedIdentifier", err.Error()))
			return
		}
		if seen[id.Value] {
			s.writeProblem(w, malformed(http.StatusBadRequest, "duplicate identifier "+id.Value))
			return
		}
		seen[id.Value] = true
		if s.rejected(base) {
			s.writeProblem(w, newProblem(http.StatusBadRequest, "rejectedIdentifier", "the CA will not issue for "+id.Value+" (configured in the fake)"))
			return
		}
		types := offered
		if wild {
			types = nil
			if contains(offered, DNS01) {
				types = []string{DNS01}
			}
		}
		if len(types) == 0 {
			s.writeProblem(w, newProblem(http.StatusBadRequest, "rejectedIdentifier", "no challenge type can validate "+id.Value))
			return
		}
		az := &authz{id: randHex(8), account: req.acct.id, ident: identifier{Type: "dns", Value: base}, wildcard: wild, status: "pending",
			expires: now.Add(orderLifetime)}
		for _, t := range types {
			az.challenges = append(az.challenges, &challenge{typ: t, token: b64(randBytes(24)), status: "pending"})
		}
		azs = append(azs, az)
		o.idents = append(o.idents, identifier{Type: "dns", Value: id.Value})
		o.authzs = append(o.authzs, az.id)
	}
	s.mu.Lock()
	for _, az := range azs {
		s.st.authzs[az.id] = az
	}
	s.st.orders[o.id] = o
	oc := *o
	s.mu.Unlock()
	w.Header().Set("Location", s.override("order", s.BaseURL()+"/acme/order/"+o.id))
	writeJSON(w, http.StatusCreated, s.orderDoc(&oc))
}

// orderDoc renders an order. It takes a copy and holds no lock.
func (s *Server) orderDoc(o *order) map[string]any {
	base := s.BaseURL()
	authzs := make([]string, len(o.authzs))
	for i, id := range o.authzs {
		authzs[i] = s.override("authz", base+"/acme/authz/"+id)
	}
	doc := map[string]any{
		"status": o.status, "expires": o.expires.UTC().Format(time.RFC3339), "identifiers": o.idents, "authorizations": authzs,
		"finalize": s.override("finalize", base+"/acme/finalize/"+o.id),
	}
	if o.status == "valid" {
		doc["certificate"] = s.override("certificate", base+"/acme/cert/"+o.certID)
	}
	if o.problem != nil {
		doc["error"] = o.problem.doc()
	}
	return doc
}

// refreshLocked moves an order along: pending becomes ready or invalid with its authorizations,
// processing counts its polls down to valid. The caller holds mu.
func (s *Server) refreshLocked(o *order) {
	switch o.status {
	case "pending":
		valid := 0
		for _, id := range o.authzs {
			switch s.st.authzs[id].status {
			case "valid":
				valid++
			case "invalid", "deactivated", "expired", "revoked":
				o.status = "invalid"
				o.problem = newProblem(http.StatusForbidden, "unauthorized", "an authorization of the order is invalid")
				return
			}
		}
		if valid == len(o.authzs) {
			o.status = "ready"
		}
	case "processing":
		if o.polls > 0 {
			o.polls--
		} else {
			o.status = "valid"
		}
	}
}

// ownedOrder returns a copy of the caller's order after refreshing it, or writes the problem.
func (s *Server) ownedOrder(w http.ResponseWriter, r *http.Request, req *jwsReq, refresh bool) (order, bool) {
	s.mu.Lock()
	o := s.st.orders[r.PathValue("id")]
	if o == nil {
		s.mu.Unlock()
		s.writeProblem(w, malformed(http.StatusNotFound, "no such order"))
		return order{}, false
	}
	if o.account != req.acct.id {
		s.mu.Unlock()
		s.writeProblem(w, newProblem(http.StatusForbidden, "unauthorized", "this is not your order"))
		return order{}, false
	}
	if refresh {
		s.refreshLocked(o)
	}
	oc := *o
	s.mu.Unlock()
	return oc, true
}

func (s *Server) handleOrder(w http.ResponseWriter, r *http.Request, req *jwsReq) {
	o, ok := s.ownedOrder(w, r, req, true)
	if !ok {
		return
	}
	if o.status == "processing" {
		w.Header().Set("Retry-After", "1")
	}
	w.Header().Set("Location", s.BaseURL()+"/acme/order/"+o.id)
	writeJSON(w, http.StatusOK, s.orderDoc(&o))
}

func csrNames(csr *x509.CertificateRequest) ([]string, error) {
	if len(csr.IPAddresses) > 0 || len(csr.EmailAddresses) > 0 || len(csr.URIs) > 0 {
		return nil, fmt.Errorf("the CSR holds a SAN that is not a DNS name")
	}
	names := append([]string(nil), csr.DNSNames...)
	if csr.Subject.CommonName != "" {
		found := false
		for _, n := range names {
			found = found || n == csr.Subject.CommonName
		}
		if !found && len(names) > 0 {
			return nil, fmt.Errorf("the CSR common name is not among its DNS names")
		}
		if !found {
			names = append(names, csr.Subject.CommonName)
		}
	}
	return names, nil
}

func goodKey(pub any) bool {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		return k.N.BitLen() >= 2048
	case *ecdsa.PublicKey:
		return k.Curve == elliptic.P256() || k.Curve == elliptic.P384()
	}
	return false
}

func (s *Server) handleFinalize(w http.ResponseWriter, r *http.Request, req *jwsReq) {
	var p struct {
		CSR string `json:"csr"`
	}
	if prob := decodeJSON(req.payload, &p); prob != nil {
		s.writeProblem(w, prob)
		return
	}
	o, ok := s.ownedOrder(w, r, req, true)
	if !ok {
		return
	}
	if o.status != "ready" {
		s.writeProblem(w, newProblem(http.StatusForbidden, "orderNotReady", "the order is "+o.status+", not ready"))
		return
	}
	der, err := base64.RawURLEncoding.DecodeString(p.CSR)
	if err != nil {
		s.writeProblem(w, newProblem(http.StatusBadRequest, "badCSR", "the csr is not base64url"))
		return
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err == nil {
		err = csr.CheckSignature()
	}
	if err != nil {
		s.writeProblem(w, newProblem(http.StatusBadRequest, "badCSR", "the csr does not parse or its signature is wrong"))
		return
	}
	if !goodKey(csr.PublicKey) {
		s.writeProblem(w, newProblem(http.StatusBadRequest, "badPublicKey", "the key must be ECDSA P-256 or P-384, or RSA of at least 2048 bits"))
		return
	}
	names, err := csrNames(csr)
	if err != nil {
		s.writeProblem(w, newProblem(http.StatusBadRequest, "badCSR", err.Error()))
		return
	}
	want := map[string]bool{}
	for _, id := range o.idents {
		want[id.Value] = true
	}
	have := map[string]bool{}
	for _, n := range names {
		have[n] = true
	}
	if len(have) != len(want) {
		s.writeProblem(w, newProblem(http.StatusBadRequest, "badCSR", "the csr names do not match the order's identifiers"))
		return
	}
	for n := range have {
		if !want[n] {
			s.writeProblem(w, newProblem(http.StatusBadRequest, "badCSR", "the csr names do not match the order's identifiers"))
			return
		}
	}
	ordered := make([]string, 0, len(o.idents))
	for _, id := range o.idents {
		ordered = append(ordered, id.Value)
	}
	s.mu.Lock()
	life, polls := s.cfg.lifetime, s.cfg.processingPolls
	s.mu.Unlock()
	cert, err := s.pki.issue(ordered, csr.PublicKey, s.now(), life)
	if err != nil {
		s.writeProblem(w, newProblem(http.StatusInternalServerError, "serverInternal", "issuance failed"))
		return
	}
	cert.id, cert.account = randHex(12), req.acct.id
	s.mu.Lock()
	cur := s.st.orders[o.id]
	if cur.status != "ready" { // a concurrent finalize won
		s.mu.Unlock()
		s.writeProblem(w, newProblem(http.StatusForbidden, "orderNotReady", "the order was finalized meanwhile"))
		return
	}
	s.st.certs[cert.id] = cert
	s.st.byARI[ariID(cert.leaf)] = cert
	s.st.counters["issued"]++
	cur.certID = cert.id
	cur.status, cur.polls = "valid", 0
	if polls > 0 {
		cur.status, cur.polls = "processing", polls
	}
	oc := *cur
	s.mu.Unlock()
	if oc.status == "processing" {
		w.Header().Set("Retry-After", "1")
	}
	w.Header().Set("Location", s.BaseURL()+"/acme/order/"+oc.id)
	writeJSON(w, http.StatusOK, s.orderDoc(&oc))
}

func (s *Server) handleCertificate(w http.ResponseWriter, r *http.Request, req *jwsReq) {
	n := 0
	if v := r.PathValue("n"); v != "" {
		var err error
		if n, err = strconv.Atoi(v); err != nil || n < 0 {
			s.writeProblem(w, malformed(http.StatusNotFound, "no such certificate chain"))
			return
		}
	}
	s.mu.Lock()
	c := s.st.certs[r.PathValue("id")]
	s.mu.Unlock()
	if c == nil || c.account != req.acct.id || n >= len(c.chains) {
		s.writeProblem(w, malformed(http.StatusNotFound, "no such certificate"))
		return
	}
	base := s.BaseURL()
	for i := range c.chains {
		if i != n {
			u := base + "/acme/cert/" + c.id
			if i > 0 {
				u += "/alt/" + strconv.Itoa(i)
			}
			w.Header().Add("Link", "<"+u+">;rel=\"alternate\"")
		}
	}
	w.Header().Set("Content-Type", "application/pem-certificate-chain")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(c.chains[n])
}
