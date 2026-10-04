package fakekv

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"software.sslmate.com/src/go-pkcs12"
)

const (
	pageSize        = 25 // documented default and maximum of maxresults
	recoverableDays = 90
	recoveryLevel   = "Recoverable+Purgeable"
)

// rbacActions maps the fake's action names to the data actions Azure RBAC names in its 403 message
// (GUESS: the message text is modelled on observed Azure messages, not verified).
var rbacActions = map[string]string{
	"certificates/list":   "Microsoft.KeyVault/vaults/certificates/read",
	"certificates/get":    "Microsoft.KeyVault/vaults/certificates/read",
	"certificates/import": "Microsoft.KeyVault/vaults/certificates/import/action",
	"keys/list":           "Microsoft.KeyVault/vaults/keys/read",
	"keys/get":            "Microsoft.KeyVault/vaults/keys/read",
	"secrets/list":        "Microsoft.KeyVault/vaults/secrets/readMetadata/action",
	"secrets/get":         "Microsoft.KeyVault/vaults/secrets/getSecret/action",
}

// policyActions is the access-policy permission each action needs.
var policyActions = map[string]string{
	"certificates/list": "certificates list", "certificates/get": "certificates get",
	"certificates/import": "certificates import", "keys/list": "keys list", "keys/get": "keys get",
	"secrets/list": "secrets list", "secrets/get": "secrets get",
}

// serveVault is the pipeline of a request for the vault host: the challenge answers first (an
// unauthenticated request never consumes a fault, scan defect D11), then latency, hold and scripted
// faults, then the firewall, the api-version, the role and the route.
func (s *Server) serveVault(w http.ResponseWriter, r *http.Request) {
	switch s.checkToken(r) {
	case tokenOK:
	case tokenMissing:
		s.challengeFail(w, "AKV10000: Request is missing a Bearer or PoP token.")
		return
	case tokenExpired:
		// GUESS: the code and text of an expired token's 401.
		s.challengeFail(w, "AKV10001: Bearer token is expired or not yet valid.")
		return
	case tokenWrongAudience:
		s.challengeFail(w, "AKV10032: Invalid audience. The token was not issued for this resource.") // GUESS
		return
	default:
		s.challengeFail(w, "AKV10032: Invalid issuer. The token was not issued by a trusted authority.") // GUESS
		return
	}
	s.serveWithFaults(w, r, s.vaultRoute)
}

// challengeFail answers 401 with the Key Vault challenge. The standard challenge names the tenant's
// login authority and the vault resource; the SDK's challenge-resource verification (ruling S2, left on)
// requires the resource's domain to be the vault host's parent domain, which "https://vault.azure.net" is.
func (s *Server) challengeFail(w http.ResponseWriter, msg string) {
	s.mu.Lock()
	c := s.challenge
	tid := s.o.TenantID
	s.mu.Unlock()
	if c == "" {
		c = `Bearer authorization="https://login.microsoftonline.com/` + tid + `", resource="https://vault.azure.net"`
	}
	w.Header().Set("WWW-Authenticate", c)
	kvFail(w, http.StatusUnauthorized, "Unauthorized", "", msg)
}

func (s *Server) callerText() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return "appid=" + s.o.ClientID + ";oid=" + s.oid + ";iss=https://sts.windows.net/" + s.tid + "/"
}

func (s *Server) vaultRoute(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	fw := s.firewall
	s.mu.Unlock()
	if fw != "" {
		// Partly documented: "Client address (00.00.00.00) is not authorized and caller is not a trusted
		// service" (https://learn.microsoft.com/en-us/azure/key-vault/general/rest-error-codes). The
		// "Client address: x" line and the inner code ForbiddenByFirewall are GUESS (S10 item 2).
		kvFail(w, http.StatusForbidden, "Forbidden", "ForbiddenByFirewall",
			"Client address ("+fw+") is not authorized and caller is not a trusted service.\r\nClient address: "+fw+
				"\r\nCaller: "+s.callerText()+"\r\nVault: "+s.o.VaultName+";location=westeurope")
		return
	}
	if r.URL.Query().Get("api-version") != APIVersion {
		kvFail(w, http.StatusBadRequest, "BadParameter", "",
			"The api-version '"+r.URL.Query().Get("api-version")+"' is not supported by this endpoint; use "+APIVersion+".") // GUESS text
		return
	}
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	get, post := r.Method == http.MethodGet, r.Method == http.MethodPost
	n := len(parts)
	switch {
	case parts[0] == "certificates" && n == 1:
		s.onlyIf(w, get, "certificates/list", func() { s.listCertificates(w, r) })
	case parts[0] == "certificates" && n == 3 && parts[2] == "versions":
		s.onlyIf(w, get, "certificates/list", func() { s.listCertificateVersions(w, r, parts[1]) })
	case parts[0] == "certificates" && n == 3 && parts[2] == "import":
		s.onlyIf(w, post, "certificates/import", func() { s.importCertificate(w, r, parts[1]) })
	case parts[0] == "certificates" && (n == 2 || n == 3):
		s.onlyIf(w, get, "certificates/get", func() { s.getCertificate(w, parts[1], optPart(parts, 2)) })
	case parts[0] == "keys" && n == 1:
		s.onlyIf(w, get, "keys/list", func() { s.listKeys(w, r) })
	case parts[0] == "keys" && (n == 2 || n == 3):
		s.onlyIf(w, get, "keys/get", func() { s.getKey(w, parts[1], optPart(parts, 2)) })
	case parts[0] == "secrets" && n == 1:
		s.onlyIf(w, get, "secrets/list", func() { s.listSecrets(w, r) })
	case parts[0] == "secrets" && (n == 2 || n == 3):
		s.onlyIf(w, get, "secrets/get", func() { s.getSecret(w, parts[1], optPart(parts, 2)) })
	default:
		kvFail(w, http.StatusNotFound, "NotFound", "", "Unknown route: the fake serves only certificates, keys and secrets reads and certificate import.") // GUESS
	}
}

func optPart(parts []string, i int) string {
	if i < len(parts) {
		return parts[i]
	}
	return ""
}

// onlyIf runs fn when the method fits (else 405: GUESS) and the role is held (else 403).
func (s *Server) onlyIf(w http.ResponseWriter, methodOK bool, action string, fn func()) {
	if !methodOK {
		w.Header().Set("Allow", "GET, POST")
		kvFail(w, http.StatusMethodNotAllowed, "MethodNotAllowed", "", "The method is not allowed for this route.") // GUESS
		return
	}
	s.mu.Lock()
	revoked := s.revoked[action]
	s.mu.Unlock()
	if revoked {
		s.forbidden(w, action)
		return
	}
	fn()
}

// forbidden answers a missing role. rbac: Forbidden / ForbiddenByRbac; access_policy: Forbidden /
// ForbiddenByPolicy as the contract fixes it. GUESS: both inner codes are unverified (from memory the
// real access-policy answer carries "AccessDenied"); the message texts are modelled on observed ones.
func (s *Server) forbidden(w http.ResponseWriter, action string) {
	if s.o.Model == "access_policy" {
		kvFail(w, http.StatusForbidden, "Forbidden", "ForbiddenByPolicy",
			"The user, group or application '"+s.callerText()+"' does not have "+policyActions[action]+
				" permission on key vault '"+s.o.VaultName+";location=westeurope'.")
		return
	}
	kvFail(w, http.StatusForbidden, "Forbidden", "ForbiddenByRbac",
		"Caller is not authorized to perform action on resource.\r\nIf role assignments, deny assignments or role definitions were changed recently, please observe propagation time.\r\n"+
			"Caller: "+s.callerText()+"\r\nAction: '"+rbacActions[action]+"'\r\nVault: "+s.o.VaultName+";location=westeurope")
}

// RevokeRole removes a permission: "certificates/list", "certificates/get", "certificates/import",
// "keys/list", "keys/get", "secrets/list", "secrets/get". Calls needing it answer 403.
func (s *Server) RevokeRole(action string) { s.mu.Lock(); s.revoked[action] = true; s.mu.Unlock() }

// GrantRole restores a permission.
func (s *Server) GrantRole(action string) { s.mu.Lock(); delete(s.revoked, action); s.mu.Unlock() }

// Firewall makes every vault call answer 403 ForbiddenByFirewall naming clientAddress ("" = off).
func (s *Server) Firewall(clientAddress string) {
	s.mu.Lock()
	s.firewall = clientAddress
	s.mu.Unlock()
}

// ---- paging ----

// pageRequest reads maxresults and $skiptoken. The skiptoken is opaque to clients: base64url of a
// JSON object holding the last name (or version) returned (GUESS: the real token's content differs).
func pageRequest(w http.ResponseWriter, r *http.Request) (marker string, max int, ok bool) {
	max = pageSize
	if v := r.URL.Query().Get("maxresults"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > pageSize {
			// Documented range 1..25; the answer to a value outside it is a GUESS.
			kvFail(w, http.StatusBadRequest, "BadParameter", "", "The parameter maxresults must be between 1 and 25.")
			return "", 0, false
		}
		max = n
	}
	if tok := r.URL.Query().Get("$skiptoken"); tok != "" {
		raw, err := b64url.DecodeString(tok)
		var m struct {
			NextMarker string
		}
		if err != nil || json.Unmarshal(raw, &m) != nil || m.NextMarker == "" {
			kvFail(w, http.StatusBadRequest, "BadParameter", "", "The $skiptoken is not valid.") // GUESS
			return "", 0, false
		}
		marker = m.NextMarker
	}
	return marker, max, true
}

// nextLinkFor builds the link to the page after lastKey. It keeps the api-version and maxresults and
// names the vault host WITH ":443", as the REST reference's sample does.
func (s *Server) nextLinkFor(path, lastKey string, max int) *string {
	tok, _ := json.Marshal(map[string]any{"NextMarker": lastKey, "TargetLocation": 0})
	l := "https://" + s.vaultHostN + ":443/" + strings.Trim(path, "/") + "?api-version=" + APIVersion +
		"&$skiptoken=" + b64url.EncodeToString(tok) + "&maxresults=" + strconv.Itoa(max)
	return &l
}

// pageOf returns the keys after marker (at most max) and whether more remain.
func pageOf(keys []string, marker string, max int) (page []string, more bool) {
	start := 0
	if marker != "" {
		start = sort.Search(len(keys), func(i int) bool { return keys[i] > marker })
	}
	end := start + max
	if end >= len(keys) {
		return keys[start:], false
	}
	return keys[start:end], true
}

// ---- certificates ----

func attrsOf(v *version) attributes {
	return attributes{Enabled: v.enabled, Nbf: unixPtr(v.cert.NotBefore), Exp: unixPtr(v.cert.NotAfter),
		Created: unix(v.created), Updated: unix(v.updated), RecoverableDays: recoverableDays, RecoveryLevel: recoveryLevel}
}

func (s *Server) certID(name, ver string) string {
	if ver == "" {
		return s.VaultURL() + "/certificates/" + name
	}
	return s.VaultURL() + "/certificates/" + name + "/" + ver
}

func (s *Server) listCertificates(w http.ResponseWriter, r *http.Request) {
	marker, max, ok := pageRequest(w, r)
	if !ok {
		return
	}
	s.mu.Lock()
	page, more := pageOf(s.liveCertNames(), marker, max)
	items := make([]certItem, 0, len(page))
	for _, n := range page {
		e := s.certs[n]
		cur := e.versions[len(e.versions)-1]
		items = append(items, certItem{ID: s.certID(n, ""), X5t: thumbprint(cur.cert.Raw), Attributes: attrsOf(cur), Tags: map[string]any{}})
	}
	s.mu.Unlock()
	res := listResult[certItem]{Value: items}
	if more {
		res.NextLink = s.nextLinkFor("/certificates", page[len(page)-1], max)
	}
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) listCertificateVersions(w http.ResponseWriter, r *http.Request, name string) {
	marker, max, ok := pageRequest(w, r)
	if !ok {
		return
	}
	s.mu.Lock()
	e := s.certs[name]
	if e == nil || e.deleted {
		s.mu.Unlock()
		s.notFound(w, "CertificateNotFound", "certificate", name)
		return
	}
	order := make([]*version, len(e.versions))
	copy(order, e.versions)
	if !s.o.VersionsOldestFirst {
		for i, j := 0, len(order)-1; i < j; i, j = i+1, j-1 {
			order[i], order[j] = order[j], order[i]
		}
	}
	// The marker is the last version ID returned: continue after its position in the listing order.
	start := 0
	if marker != "" {
		start = len(order)
		for i, v := range order {
			if v.id == marker {
				start = i + 1
			}
		}
	}
	end := start + max
	more := end < len(order)
	if end > len(order) {
		end = len(order)
	}
	items := make([]certItem, 0, end-start)
	for _, v := range order[start:end] {
		items = append(items, certItem{ID: s.certID(name, v.id), X5t: thumbprint(v.cert.Raw), Attributes: attrsOf(v), Tags: map[string]any{}})
	}
	s.mu.Unlock()
	res := listResult[certItem]{Value: items}
	if more {
		res.NextLink = s.nextLinkFor("/certificates/"+name+"/versions", items[len(items)-1].ID[strings.LastIndexByte(items[len(items)-1].ID, '/')+1:], max)
	}
	writeJSON(w, http.StatusOK, res)
}

// notFound answers 404 with the "X was not found" text (GUESS: the codes CertificateNotFound,
// SecretNotFound and KeyNotFound and this text follow what Key Vault is known to answer, unverified).
func (s *Server) notFound(w http.ResponseWriter, code, kind, name string) {
	kvFail(w, http.StatusNotFound, code, "", "A "+kind+" with (name/id) "+name+" was not found in this key vault. "+
		"If you recently deleted this "+kind+" you may be able to recover it using the correct recovery command.")
}

func (s *Server) bundleOf(e *certEntry, v *version) certBundle {
	pub := v.cert.PublicKey
	kp := keyProps{Exportable: e.policy.exportable, ReuseKey: e.policy.reuseKey}
	switch p := pub.(type) {
	case *ecdsa.PublicKey:
		kp.Kty, kp.KeySize, kp.Crv = "EC", p.Curve.Params().BitSize, p.Curve.Params().Name
	case *rsa.PublicKey:
		kp.Kty, kp.KeySize = "RSA", p.N.BitLen()
	}
	days := v.cert.NotAfter.Sub(v.cert.NotBefore).Hours() / 24
	xp := x509Props{Subject: v.cert.Subject.String(), Ekus: []string{}, KeyUsage: []string{}, ValidityMonths: int(days/30.4375 + 0.5)}
	if len(v.cert.DNSNames) > 0 {
		xp.Sans = &sans{DNSNames: v.cert.DNSNames}
	}
	var la lifetimeAction
	la.Trigger.LifetimePercentage = e.policy.actionPct
	la.Action.ActionType = e.policy.actionType
	return certBundle{
		ID: s.certID(e.name, v.id), Kid: s.VaultURL() + "/keys/" + e.name + "/" + v.id, Sid: s.VaultURL() + "/secrets/" + e.name + "/" + v.id,
		X5t: thumbprint(v.cert.Raw), Cer: base64.StdEncoding.EncodeToString(v.cert.Raw), Attributes: attrsOf(v), Tags: map[string]any{},
		Policy: certPolicy{ID: s.certID(e.name, "policy"), KeyProps: kp, SecretProps: secretProps{ContentType: e.policy.contentType}, X509Props: xp,
			LifetimeActions: []lifetimeAction{la}, Issuer: issuerParams{Name: e.policy.issuer},
			Attributes: policyAttributes{Enabled: true, Created: unix(e.created), Updated: unix(e.updated)}},
	}
}

func (s *Server) getCertificate(w http.ResponseWriter, name, ver string) {
	s.mu.Lock()
	e, v := s.find(name, ver)
	if e == nil || e.deleted || v == nil {
		s.mu.Unlock()
		s.notFound(w, "CertificateNotFound", "certificate", joinID(name, ver))
		return
	}
	b := s.bundleOf(e, v)
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, b)
}

func joinID(name, ver string) string {
	if ver == "" {
		return name
	}
	return name + "/" + ver
}

// importBody is the request of Import Certificate.
type importBody struct {
	Value      *string `json:"value"`
	Pwd        *string `json:"pwd"`
	Attributes *struct {
		Enabled *bool `json:"enabled"`
	} `json:"attributes"`
	Policy *struct {
		KeyProps *struct {
			Exportable *bool `json:"exportable"`
			ReuseKey   *bool `json:"reuse_key"`
		} `json:"key_props"`
		SecretProps *struct {
			ContentType string `json:"contentType"`
		} `json:"secret_props"`
		Issuer *struct {
			Name string `json:"name"`
		} `json:"issuer"`
		LifetimeActions []lifetimeAction `json:"lifetime_actions"`
	} `json:"policy"`
}

// importCertificate creates a NEW version with created = now on the fake's clock (ruling S14: an import
// is a version created after the request). Validation is a GUESS throughout (S10 item 7): the value
// must be a base64 PFX (any profile go-pkcs12 decodes: Modern, LegacyRC2, LegacyDES) holding a leaf with
// an RSA or ECDSA private key that opens with pwd; PEM is refused; for an existing name the policy is
// replaced only when the request carries one; a soft-deleted name answers 409.
func (s *Server) importCertificate(w http.ResponseWriter, r *http.Request, name string) {
	if !nameRE.MatchString(name) {
		kvFail(w, http.StatusBadRequest, "BadParameter", "", "The certificate name must match ^[0-9a-zA-Z-]+$.") // pattern documented
		return
	}
	var body importBody
	if err := json.NewDecoder(io.LimitReader(r.Body, 4<<20)).Decode(&body); err != nil || body.Value == nil || *body.Value == "" {
		kvFail(w, http.StatusBadRequest, "BadParameter", "", "The request body is not valid: the value property is required.") // GUESS text
		return
	}
	raw, err := base64.StdEncoding.DecodeString(*body.Value)
	if err != nil || strings.HasPrefix(string(raw), "-----BEGIN") {
		kvFail(w, http.StatusBadRequest, "BadParameter", "", "The certificate value is not a base64 PKCS#12 file.") // GUESS: PEM import is not modelled
		return
	}
	pwd := ""
	if body.Pwd != nil {
		pwd = *body.Pwd
	}
	key, leaf, chain, err := pkcs12.DecodeChain(raw, pwd)
	if err != nil || leaf == nil {
		kvFail(w, http.StatusBadRequest, "BadParameter", "", "Import of the certificate failed: the PKCS#12 file could not be read or the password is wrong.") // GUESS text
		return
	}
	switch key.(type) {
	case *rsa.PrivateKey, *ecdsa.PrivateKey:
	default:
		kvFail(w, http.StatusBadRequest, "BadParameter", "", "The certificate's private key type is not supported.") // GUESS
		return
	}
	now := s.o.Now()
	v := &version{id: newVersionID(), cert: leaf, chain: chain, key: key, created: now, updated: now, enabled: true, served: map[string]string{}}
	if body.Attributes != nil && body.Attributes.Enabled != nil {
		v.enabled = *body.Attributes.Enabled
	}
	s.mu.Lock()
	e := s.certs[name]
	switch {
	case e != nil && e.deleted:
		s.mu.Unlock()
		kvFail(w, http.StatusConflict, "Conflict", "", "Certificate "+name+" is currently in a deleted but recoverable state, and its name cannot be reused; "+
			"in this state, the certificate can only be recovered or purged.") // GUESS: code and text
		return
	case e == nil:
		ct := "application/x-pkcs12"
		e = &certEntry{name: name, imported: true, created: now, updated: now, o: CertOptions{CommonName: leaf.Subject.CommonName, SANs: leaf.DNSNames, Exportable: true},
			policy: policyState{exportable: true, contentType: ct, issuer: "Unknown", actionType: "EmailContacts", actionPct: 80}}
		s.certs[name] = e
	}
	if p := body.Policy; p != nil {
		if p.KeyProps != nil && p.KeyProps.Exportable != nil {
			e.policy.exportable = *p.KeyProps.Exportable
			e.o.Exportable = *p.KeyProps.Exportable
		}
		if p.KeyProps != nil && p.KeyProps.ReuseKey != nil {
			e.policy.reuseKey = *p.KeyProps.ReuseKey
		}
		if p.SecretProps != nil && p.SecretProps.ContentType != "" {
			e.policy.contentType = p.SecretProps.ContentType
			e.o.ContentType = p.SecretProps.ContentType
		}
		if p.Issuer != nil && p.Issuer.Name != "" {
			e.policy.issuer = p.Issuer.Name
		}
		if len(p.LifetimeActions) > 0 {
			e.policy.actionType = p.LifetimeActions[0].Action.ActionType
			e.policy.actionPct = p.LifetimeActions[0].Trigger.LifetimePercentage
		}
		e.updated = now
	}
	e.o.CommonName, e.o.SANs = leaf.Subject.CommonName, leaf.DNSNames
	e.versions = append(e.versions, v)
	b := s.bundleOf(e, v)
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, b)
}

// ---- secrets ----

func (s *Server) listSecrets(w http.ResponseWriter, r *http.Request) {
	marker, max, ok := pageRequest(w, r)
	if !ok {
		return
	}
	s.mu.Lock()
	// Certificates have a backing secret of the same name (documented: "When a Key Vault certificate is
	// created, an addressable key and secret are also created with the same name"); it is listed
	// with managed: true (the listing flag is as the SecretItem model defines it).
	names := s.liveCertNames()
	for n := range s.secrets {
		names = append(names, n)
	}
	sort.Strings(names)
	page, more := pageOf(names, marker, max)
	items := make([]secretItem, 0, len(page))
	for _, n := range page {
		if p := s.secrets[n]; p != nil {
			items = append(items, secretItem{ID: s.VaultURL() + "/secrets/" + n, ContentType: p.contentType, Tags: map[string]any{},
				Attributes: attributes{Enabled: true, Created: unix(p.created), Updated: unix(p.created), RecoverableDays: recoverableDays, RecoveryLevel: recoveryLevel}})
			continue
		}
		e := s.certs[n]
		cur := e.versions[len(e.versions)-1]
		items = append(items, secretItem{ID: s.VaultURL() + "/secrets/" + n, ContentType: e.policy.contentType, Attributes: attrsOf(cur), Tags: map[string]any{}, Managed: true})
	}
	s.mu.Unlock()
	res := listResult[secretItem]{Value: items}
	if more {
		res.NextLink = s.nextLinkFor("/secrets", page[len(page)-1], max)
	}
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) getSecret(w http.ResponseWriter, name, ver string) {
	if ver == "" {
		// Alice never asks for "latest": the fake makes a test fail loudly (brief), unlike Azure.
		kvFail(w, http.StatusBadRequest, "BadParameter", "", "fakekv: a secret must be read by version; Alice never asks for the latest.")
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if p := s.secrets[name]; p != nil {
		if p.id != ver {
			s.notFound(w, "SecretNotFound", "secret", name+"/"+ver)
			return
		}
		writeJSON(w, http.StatusOK, secretBundle{Value: p.value, ContentType: p.contentType, ID: s.VaultURL() + "/secrets/" + name + "/" + p.id,
			Attributes: attributes{Enabled: true, Created: unix(p.created), Updated: unix(p.created), RecoverableDays: recoverableDays, RecoveryLevel: recoveryLevel}, Tags: map[string]any{}})
		return
	}
	e, v := s.find(name, ver)
	if e == nil || e.deleted || v == nil {
		s.notFound(w, "SecretNotFound", "secret", name+"/"+ver)
		return
	}
	if !v.enabled {
		// GUESS (S10 item 1): 403 Forbidden with inner code SecretDisabled.
		kvFail(w, http.StatusForbidden, "Forbidden", "SecretDisabled", "Operation get is not allowed on a disabled secret.")
		return
	}
	if !e.policy.exportable {
		// GUESS (S10 item 3, as the brief fixes it): a non-exportable certificate's secret read is a 403
		// carrying the inner code of the vault's permission model.
		inner := "ForbiddenByRbac"
		if s.o.Model == "access_policy" {
			inner = "ForbiddenByPolicy"
		}
		kvFail(w, http.StatusForbidden, "Forbidden", inner, "The private key of this certificate is not exportable.")
		return
	}
	writeJSON(w, http.StatusOK, secretBundle{Value: s.servedLocked(e, v), ContentType: e.policy.contentType, ID: s.VaultURL() + "/secrets/" + name + "/" + v.id,
		Kid: s.VaultURL() + "/keys/" + name + "/" + v.id, Managed: true, Attributes: attrsOf(v), Tags: map[string]any{}})
}

// ---- keys ----

func keyAttrs(k *keyEntry) attributes {
	a := attributes{Enabled: k.o.Enabled, Created: unix(k.created), Updated: unix(k.updated), RecoverableDays: recoverableDays, RecoveryLevel: recoveryLevel}
	if k.o.Expires != nil {
		a.Exp = unixPtr(*k.o.Expires)
	}
	return a
}

func (s *Server) listKeys(w http.ResponseWriter, r *http.Request) {
	marker, max, ok := pageRequest(w, r)
	if !ok {
		return
	}
	s.mu.Lock()
	names := s.liveCertNames() // a certificate's backing key is listed too, managed: true
	for n := range s.keys {
		names = append(names, n)
	}
	sort.Strings(names)
	page, more := pageOf(names, marker, max)
	items := make([]keyItem, 0, len(page))
	for _, n := range page {
		if k := s.keys[n]; k != nil {
			items = append(items, keyItem{Kid: s.VaultURL() + "/keys/" + n, Attributes: keyAttrs(k), Tags: map[string]any{}})
			continue
		}
		e := s.certs[n]
		items = append(items, keyItem{Kid: s.VaultURL() + "/keys/" + n, Attributes: attrsOf(e.versions[len(e.versions)-1]), Tags: map[string]any{}, Managed: true})
	}
	s.mu.Unlock()
	res := listResult[keyItem]{Value: items}
	if more {
		res.NextLink = s.nextLinkFor("/keys", page[len(page)-1], max)
	}
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) getKey(w http.ResponseWriter, name, ver string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if k := s.keys[name]; k != nil {
		if ver != "" && ver != k.id {
			s.notFound(w, "KeyNotFound", "key", name+"/"+ver)
			return
		}
		j := k.pub
		j.Kid = s.VaultURL() + "/keys/" + name + "/" + k.id
		writeJSON(w, http.StatusOK, keyBundle{Key: j, Attributes: keyAttrs(k), Tags: map[string]any{}})
		return
	}
	e, v := s.find(name, ver)
	if e == nil || e.deleted || v == nil {
		s.notFound(w, "KeyNotFound", "key", joinID(name, ver))
		return
	}
	j := jwkOfPublic(v.cert.PublicKey)
	j.Kid = s.VaultURL() + "/keys/" + name + "/" + v.id
	writeJSON(w, http.StatusOK, keyBundle{Key: j, Attributes: attrsOf(v), Tags: map[string]any{}, Managed: true})
}
