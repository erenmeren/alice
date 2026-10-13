package fakeacme

import (
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
)

func accountDoc(base string, a *account) map[string]any {
	doc := map[string]any{"status": a.status, "orders": base + "/acme/acct/" + a.id + "/orders"}
	if len(a.contact) > 0 {
		doc["contact"] = a.contact
	}
	return doc
}

func (s *Server) accountURL(id string) string { return s.BaseURL() + "/acme/acct/" + id }

func validContacts(c []string) bool {
	for _, x := range c {
		if !strings.HasPrefix(x, "mailto:") || len(x) < len("mailto:a@b") || strings.ContainsAny(x, "?,; \r\n") {
			return false
		}
	}
	return true
}

func (s *Server) handleNewAccount(w http.ResponseWriter, _ *http.Request, req *jwsReq) {
	var p struct {
		Contact                []string        `json:"contact"`
		TermsOfServiceAgreed   bool            `json:"termsOfServiceAgreed"`
		OnlyReturnExisting     bool            `json:"onlyReturnExisting"`
		ExternalAccountBinding json.RawMessage `json:"externalAccountBinding"`
	}
	if prob := decodeJSON(req.payload, &p); prob != nil {
		s.writeProblem(w, prob)
		return
	}
	thumb := thumbprint(req.key)
	s.mu.Lock()
	id, exists := s.st.byThumb[thumb]
	var acct account
	if exists {
		acct = *s.st.accounts[id]
	}
	requireEAB := s.cfg.requireEAB
	s.mu.Unlock()
	if exists {
		w.Header().Set("Location", s.accountURL(id))
		writeJSON(w, http.StatusOK, accountDoc(s.BaseURL(), &acct))
		return
	}
	if p.OnlyReturnExisting {
		s.writeProblem(w, newProblem(http.StatusBadRequest, "accountDoesNotExist", "no account for this key"))
		return
	}
	if !validContacts(p.Contact) {
		s.writeProblem(w, newProblem(http.StatusBadRequest, "invalidContact", "a contact must be a mailto: URL without hfields"))
		return
	}
	if !s.opts.NoTerms && !p.TermsOfServiceAgreed {
		w.Header().Add("Link", "<"+s.BaseURL()+"/terms>;rel=\"terms-of-service\"")
		s.writeProblem(w, newProblem(http.StatusForbidden, "userActionRequired", "you must agree to the terms of service"))
		return
	}
	if len(p.ExternalAccountBinding) > 0 {
		if prob := s.checkEAB(p.ExternalAccountBinding, req); prob != nil {
			s.writeProblem(w, prob)
			return
		}
	} else if requireEAB {
		s.writeProblem(w, newProblem(http.StatusForbidden, "externalAccountRequired", "this CA requires an external account binding"))
		return
	}
	a := &account{id: randHex(8), key: req.key, thumb: thumb, contact: p.Contact, status: "valid"}
	s.mu.Lock()
	s.st.accounts[a.id] = a
	s.st.byThumb[thumb] = a.id
	s.mu.Unlock()
	w.Header().Set("Location", s.accountURL(a.id))
	writeJSON(w, http.StatusCreated, accountDoc(s.BaseURL(), a))
}

// checkEAB verifies an external account binding (RFC 8555 section 7.3.4): an HS256 JWS over the
// account key's JWK, with the configured key id and HMAC key, for the newAccount URL.
func (s *Server) checkEAB(raw json.RawMessage, req *jwsReq) *problem {
	bad := func(detail string) *problem {
		return newProblem(http.StatusUnauthorized, "unauthorized", "external account binding: "+detail)
	}
	var j flatJWS
	if err := json.Unmarshal(raw, &j); err != nil {
		return malformed(http.StatusBadRequest, "externalAccountBinding is not a flattened JWS")
	}
	ph, err := base64.RawURLEncoding.DecodeString(j.Protected)
	var h struct {
		Alg string `json:"alg"`
		KID string `json:"kid"`
		URL string `json:"url"`
	}
	if err != nil || json.Unmarshal(ph, &h) != nil {
		return malformed(http.StatusBadRequest, "externalAccountBinding has no valid protected header")
	}
	if h.Alg != "HS256" {
		return bad("the algorithm must be HS256")
	}
	if h.URL != s.BaseURL()+"/acme/new-acct" {
		return bad("the url must be the newAccount URL")
	}
	if subtle.ConstantTimeCompare([]byte(h.KID), []byte(s.opts.EABKID)) != 1 {
		return bad("unknown key id")
	}
	sig, err := base64.RawURLEncoding.DecodeString(j.Signature)
	if err != nil || !macOK(s.opts.EABKey, j.Protected+"."+j.Payload, sig) {
		return bad("the MAC does not verify")
	}
	pl, err := base64.RawURLEncoding.DecodeString(j.Payload)
	if err != nil {
		return bad("the payload is not base64url")
	}
	pub, err := parseJWK(pl)
	if err != nil || thumbprint(pub) != thumbprint(req.key) {
		return bad("the payload is not the account key")
	}
	return nil
}

// handleAccount: POST-as-GET returns the account; {"contact"} updates it; {"status":"deactivated"}
// deactivates it.
func (s *Server) handleAccount(w http.ResponseWriter, r *http.Request, req *jwsReq) {
	id := r.PathValue("id")
	if req.acct.id != id {
		s.writeProblem(w, newProblem(http.StatusForbidden, "unauthorized", "this is not your account"))
		return
	}
	if len(req.payload) > 0 {
		var p struct {
			Contact *[]string `json:"contact"`
			Status  string    `json:"status"`
		}
		if prob := decodeJSON(req.payload, &p); prob != nil {
			s.writeProblem(w, prob)
			return
		}
		if p.Contact != nil && !validContacts(*p.Contact) {
			s.writeProblem(w, newProblem(http.StatusBadRequest, "invalidContact", "a contact must be a mailto: URL"))
			return
		}
		if p.Status != "" && p.Status != "deactivated" {
			s.writeProblem(w, malformed(http.StatusBadRequest, "the only status an account can be set to is deactivated"))
			return
		}
		s.mu.Lock()
		a := s.st.accounts[id]
		if p.Contact != nil {
			a.contact = *p.Contact
		}
		if p.Status == "deactivated" {
			a.status = "deactivated"
		}
		s.mu.Unlock()
	}
	s.mu.Lock()
	a := *s.st.accounts[id]
	s.mu.Unlock()
	w.Header().Set("Location", s.accountURL(id))
	writeJSON(w, http.StatusOK, accountDoc(s.BaseURL(), &a))
}

// handleKeyChange implements account key rollover (RFC 8555 section 7.3.5): the outer JWS is signed
// by the old key (kid), its payload is an inner JWS signed by the new key (jwk, no nonce) whose
// payload names the account and the old key.
func (s *Server) handleKeyChange(w http.ResponseWriter, _ *http.Request, req *jwsReq) {
	var inner flatJWS
	if prob := decodeJSON(req.payload, &inner); prob != nil {
		s.writeProblem(w, prob)
		return
	}
	ph, err := base64.RawURLEncoding.DecodeString(inner.Protected)
	var ih jwsHeader
	if err != nil || json.Unmarshal(ph, &ih) != nil || len(ih.JWK) == 0 || ih.KID != "" {
		s.writeProblem(w, malformed(http.StatusBadRequest, "the inner JWS needs a jwk and no kid"))
		return
	}
	if ih.Nonce != "" {
		s.writeProblem(w, malformed(http.StatusBadRequest, "the inner JWS must not carry a nonce"))
		return
	}
	if ih.URL != req.header.URL {
		s.writeProblem(w, malformed(http.StatusBadRequest, "the inner and outer JWS must name the same url"))
		return
	}
	newKey, err := parseJWK(ih.JWK)
	if err != nil {
		s.writeProblem(w, malformed(http.StatusBadRequest, "the new key is not acceptable: "+err.Error()))
		return
	}
	if err := verifyJWS(inner, ih, newKey); err != nil {
		s.writeProblem(w, malformed(http.StatusBadRequest, "the inner JWS signature failed: "+err.Error()))
		return
	}
	pl, err := base64.RawURLEncoding.DecodeString(inner.Payload)
	var kc struct {
		Account string          `json:"account"`
		OldKey  json.RawMessage `json:"oldKey"`
	}
	if err != nil || json.Unmarshal(pl, &kc) != nil {
		s.writeProblem(w, malformed(http.StatusBadRequest, "the inner payload is not valid"))
		return
	}
	old, err := parseJWK(kc.OldKey)
	if kc.Account != s.accountURL(req.acct.id) || err != nil || thumbprint(old) != thumbprint(req.key) {
		s.writeProblem(w, malformed(http.StatusBadRequest, "the inner payload does not name this account and its current key"))
		return
	}
	thumb := thumbprint(newKey)
	s.mu.Lock()
	if other, taken := s.st.byThumb[thumb]; taken {
		s.mu.Unlock()
		w.Header().Set("Location", s.accountURL(other))
		s.writeProblem(w, newProblem(http.StatusConflict, "malformed", "the new key is already an account key"))
		return
	}
	a := s.st.accounts[req.acct.id]
	delete(s.st.byThumb, a.thumb)
	a.key, a.thumb = newKey, thumb
	s.st.byThumb[thumb] = a.id
	acct := *a
	s.mu.Unlock()
	w.Header().Set("Location", s.accountURL(acct.id))
	writeJSON(w, http.StatusOK, accountDoc(s.BaseURL(), &acct))
}
