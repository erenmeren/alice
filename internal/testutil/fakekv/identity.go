package fakekv

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

// RegisterCertificate registers another certificate credential of the application (RSA).
func (s *Server) RegisterCertificate(c *x509.Certificate) {
	s.mu.Lock()
	s.extraCerts = append(s.extraCerts, c)
	s.mu.Unlock()
}

// entraErrors holds the AADSTS texts. Texts are modelled on the public error-code reference
// (https://learn.microsoft.com/en-us/entra/identity-platform/reference-error-codes); the HTTP
// statuses and the exact wording are GUESSES except where noted.
var entraTexts = map[int]string{
	7000215: "Invalid client secret provided. Ensure the secret being sent in the request is the client secret value, not the client secret ID, for a secret added to app '%s'.",
	7000222: "The provided client secret keys for app '%s' are expired. Visit the Azure portal to create new keys for your app: https://aka.ms/NewClientSecret, or consider using certificate credentials for added security: https://aka.ms/certCreds.",
	700016:  "Application with identifier '%s' was not found in the directory '%s'. This can happen if the application has not been installed by the administrator of the tenant or consented to by any user in the tenant. You may have sent your authentication request to the wrong tenant.",
	90002:   "Tenant '%s' not found. Check to make sure you have the correct tenant ID and are signing into the correct cloud. Check with your subscription administrator, this may happen if there are no active subscriptions for the tenant.",
	700027:  "Client assertion contains an invalid signature. [Reason - The key was not found.]",
	700024:  "Client assertion is not within its valid time range.",
	700023:  "Client assertion audience claim does not match Realm issuer.",
	700021:  "Client assertion application identifier does not match 'client_id' parameter. Review the documentation at https://docs.microsoft.com/azure/active-directory/develop/active-directory-certificate-credentials.",
	70011:   "The provided request must include a 'scope' input parameter. The provided value for the input parameter 'scope' is not valid.",
	70003:   "The app is configured with the 'client_credentials' grant only; the grant type requested is not supported.",
	900144:  "The request body must contain the following parameter: '%s'.",
	7000216: "'client_assertion', 'client_secret' or 'request' is required for the 'client_credentials' grant type.",
}

// entraFail writes an Entra error: {error, error_description, error_codes, timestamp, trace_id,
// correlation_id, error_uri}. The description never echoes a secret or an assertion.
func (s *Server) entraFail(w http.ResponseWriter, status int, errCode string, aadsts int, args ...any) {
	ts := s.o.Now().UTC().Format("2006-01-02 15:04:05Z")
	trace, corr := uuid.NewString(), uuid.NewString()
	text := entraTexts[aadsts]
	if n := strings.Count(text, "%s"); n > 0 {
		parts := strings.SplitN(text, "%s", n+1)
		var b strings.Builder
		for i, p := range parts {
			b.WriteString(p)
			if i < len(args) && i < n {
				b.WriteString(args[i].(string))
			}
		}
		text = b.String()
	}
	desc := "AADSTS" + strconv.Itoa(aadsts) + ": " + text + "\r\nTrace ID: " + trace + "\r\nCorrelation ID: " + corr + "\r\nTimestamp: " + ts
	h := w.Header()
	h.Set("Cache-Control", "no-store, no-cache")
	h.Set("Pragma", "no-cache")
	writeJSON(w, status, map[string]any{"error": errCode, "error_description": desc, "error_codes": []int{aadsts},
		"timestamp": ts, "trace_id": trace, "correlation_id": corr, "error_uri": "https://login.microsoftonline.com/error?code=" + strconv.Itoa(aadsts)})
}

// serveLogin serves https://login.microsoftonline.com: OpenID configuration and the v2.0 token endpoint.
func (s *Server) serveLogin(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	switch {
	case len(parts) == 4 && parts[1] == "v2.0" && parts[2] == ".well-known" && parts[3] == "openid-configuration":
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		s.openIDConfiguration(w, parts[0])
	case len(parts) == 4 && parts[1] == "oauth2" && parts[2] == "v2.0" && parts[3] == "token":
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		s.token(w, r, parts[0])
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func (s *Server) knownTenant(t string) bool { return foldASCII(t) == foldASCII(s.o.TenantID) }

// openIDConfiguration answers the discovery document MSAL reads to find the token endpoint and
// to validate the issuer. Fields: a subset of the real document
// (https://login.microsoftonline.com/<tenant>/v2.0/.well-known/openid-configuration); for an unknown
// tenant the status 400 with invalid_tenant and AADSTS90002 is a GUESS (S10 item 8).
func (s *Server) openIDConfiguration(w http.ResponseWriter, tenant string) {
	if !s.knownTenant(tenant) {
		s.entraFail(w, http.StatusBadRequest, "invalid_tenant", 90002, tenant)
		return
	}
	base := "https://" + loginHost + "/" + s.o.TenantID
	writeJSON(w, http.StatusOK, map[string]any{
		"token_endpoint":                        base + "/oauth2/v2.0/token",
		"token_endpoint_auth_methods_supported": []string{"client_secret_post", "private_key_jwt", "client_secret_basic"},
		"jwks_uri":                              base + "/discovery/v2.0/keys",
		"response_modes_supported":              []string{"query", "fragment", "form_post"},
		"subject_types_supported":               []string{"pairwise"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"response_types_supported":              []string{"code", "id_token", "code id_token", "id_token token"},
		"scopes_supported":                      []string{"openid", "profile", "email", "offline_access"},
		"issuer":                                base + "/v2.0",
		"authorization_endpoint":                base + "/oauth2/v2.0/authorize",
		"device_authorization_endpoint":         base + "/oauth2/v2.0/devicecode",
		"http_logout_supported":                 true,
		"end_session_endpoint":                  base + "/oauth2/v2.0/logout",
		"claims_supported":                      []string{"sub", "iss", "aud", "exp", "iat", "tid", "oid"},
		"tenant_region_scope":                   "EU",
		"cloud_instance_name":                   "microsoftonline.com",
		"cloud_graph_host_name":                 "graph.windows.net",
		"msgraph_host":                          "graph.microsoft.com",
		"rbac_url":                              "https://pas.windows.net",
	})
}

// token serves POST /<tenant>/oauth2/v2.0/token for grant_type=client_credentials. Checks, in order:
// tenant, parameters, client_id, then the credential (secret, or the PS256 assertion), then scope.
func (s *Server) token(w http.ResponseWriter, r *http.Request, tenant string) {
	if !s.knownTenant(tenant) {
		s.entraFail(w, http.StatusBadRequest, "invalid_request", 90002, tenant)
		return
	}
	if err := r.ParseForm(); err != nil {
		s.entraFail(w, http.StatusBadRequest, "invalid_request", 900144, "grant_type")
		return
	}
	form := r.PostForm
	if form.Get("grant_type") != "client_credentials" {
		s.entraFail(w, http.StatusBadRequest, "unsupported_grant_type", 70003)
		return
	}
	if form.Get("client_id") != s.o.ClientID {
		s.entraFail(w, http.StatusBadRequest, "unauthorized_client", 700016, form.Get("client_id"), tenant)
		return
	}
	endpoint := "https://" + loginHost + "/" + s.o.TenantID + "/oauth2/v2.0/token"
	switch {
	case form.Get("client_secret") != "":
		if form.Get("client_secret") != s.o.Secret {
			s.entraFail(w, http.StatusUnauthorized, "invalid_client", 7000215, s.o.ClientID)
			return
		}
		s.mu.Lock()
		expired := s.expiredSec
		s.mu.Unlock()
		if expired {
			s.entraFail(w, http.StatusUnauthorized, "invalid_client", 7000222, s.o.ClientID)
			return
		}
	case form.Get("client_assertion") != "":
		if form.Get("client_assertion_type") != "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" {
			s.entraFail(w, http.StatusUnauthorized, "invalid_client", 700027)
			return
		}
		if code := s.verifyAssertion(form.Get("client_assertion"), endpoint); code != 0 {
			s.entraFail(w, http.StatusUnauthorized, "invalid_client", code, s.o.ClientID)
			return
		}
	default:
		s.entraFail(w, http.StatusUnauthorized, "invalid_client", 7000216)
		return
	}
	aud := ""
	for _, sc := range strings.Fields(form.Get("scope")) {
		if a, ok := strings.CutSuffix(sc, "/.default"); ok && strings.HasPrefix(a, "https://") {
			aud = a
		}
	}
	if aud == "" {
		s.entraFail(w, http.StatusBadRequest, "invalid_scope", 70011)
		return
	}
	tok, _, exp := s.issueToken(aud, false)
	h := w.Header()
	h.Set("Cache-Control", "no-store, no-cache")
	h.Set("Pragma", "no-cache")
	life := int(exp.Sub(s.o.Now()).Seconds())
	writeJSON(w, http.StatusOK, map[string]any{"token_type": "Bearer", "expires_in": life, "ext_expires_in": life, "access_token": tok})
}

// verifyAssertion checks a client assertion (a JWT signed PS256 with a registered certificate's key)
// and returns 0 or the AADSTS code: 700027 for an unreadable assertion, an unregistered certificate or
// a wrong signature; 700024 for a time claim outside its range (60 s of skew); 700021 / 700023 for
// iss/sub and aud (GUESS codes). The header x5t#S256 is accepted in standard base64 (what MSAL v1.9.0
// sends, scan defect D10) and in base64url.
func (s *Server) verifyAssertion(a, aud string) int {
	parts := strings.Split(a, ".")
	if len(parts) != 3 {
		return 700027
	}
	hb, e1 := b64url.DecodeString(parts[0])
	cb, e2 := b64url.DecodeString(parts[1])
	sig, e3 := b64url.DecodeString(parts[2])
	var hdr struct {
		Alg     string `json:"alg"`
		X5tS256 string `json:"x5t#S256"`
	}
	var claims struct {
		Aud, Iss, Sub string
		Nbf, Exp      json.Number
	}
	if e1 != nil || e2 != nil || e3 != nil || json.Unmarshal(hb, &hdr) != nil || json.Unmarshal(cb, &claims) != nil || hdr.Alg != "PS256" {
		return 700027
	}
	var cert *x509.Certificate
	s.mu.Lock()
	for _, c := range s.extraCerts {
		sum := sha256.Sum256(c.Raw)
		if hdr.X5tS256 == base64.StdEncoding.EncodeToString(sum[:]) || hdr.X5tS256 == b64url.EncodeToString(sum[:]) {
			cert = c
		}
	}
	s.mu.Unlock()
	if cert == nil {
		return 700027
	}
	pub, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return 700027
	}
	h := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if rsa.VerifyPSS(pub, crypto.SHA256, h[:], sig, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthAuto}) != nil {
		return 700027
	}
	now := s.o.Now()
	nbf, errN := strconv.ParseInt(claims.Nbf.String(), 10, 64)
	exp, errE := strconv.ParseInt(claims.Exp.String(), 10, 64)
	const skew = 60 * time.Second
	if errN != nil || errE != nil || now.Add(skew).Before(time.Unix(nbf, 0)) || now.Add(-skew).After(time.Unix(exp, 0)) {
		return 700024
	}
	if claims.Iss != s.o.ClientID || claims.Sub != s.o.ClientID {
		return 700021
	}
	if claims.Aud != aud {
		return 700023
	}
	return 0
}

// serveIMDS serves the managed-identity endpoint of an Azure VM,
// GET /metadata/identity/oauth2/token?api-version=2018-02-01&resource=...[&client_id=...]
// with the header "Metadata: true"
// (https://learn.microsoft.com/en-us/entra/identity/managed-identities-azure-resources/how-to-use-vm-token).
// The success answer has the documented fields with STRING numbers; the 400 answers and their
// descriptions are GUESSES (S10 item 9), except "Identity not found" which the documentation names.
func (s *Server) serveIMDS(w http.ResponseWriter, r *http.Request) {
	i := s.record(r)
	sw := &statusWriter{ResponseWriter: w}
	defer func() { s.setStatus(i, sw.status) }()
	s.serveWithFaults(sw, r, s.imdsToken)
}

func imdsFail(w http.ResponseWriter, status int, desc string) {
	writeJSON(w, status, map[string]any{"error": "invalid_request", "error_description": desc})
}

func (s *Server) imdsToken(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/metadata/identity/oauth2/token" {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if r.Header.Get("Metadata") != "true" {
		imdsFail(w, http.StatusBadRequest, "Required metadata header not specified or not correct")
		return
	}
	q := r.URL.Query()
	if q.Get("api-version") == "" {
		imdsFail(w, http.StatusBadRequest, "Required query variable 'api-version' is missing")
		return
	}
	resource := q.Get("resource")
	if resource == "" {
		imdsFail(w, http.StatusBadRequest, "Required query variable 'resource' is missing")
		return
	}
	if !s.o.ManagedIdentity || q.Get("client_id") != s.o.MIClientID {
		imdsFail(w, http.StatusBadRequest, "Identity not found")
		return
	}
	aud := strings.TrimSuffix(resource, "/")
	tok, nbf, exp := s.issueToken(aud, false)
	now := s.o.Now()
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token": tok, "client_id": s.o.ClientID,
		"expires_in": strconv.Itoa(int(exp.Sub(now).Seconds())), "expires_on": strconv.FormatInt(exp.Unix(), 10),
		"ext_expires_in": strconv.Itoa(int(exp.Sub(now).Seconds())), "not_before": strconv.FormatInt(nbf.Unix(), 10),
		"resource": resource, "token_type": "Bearer",
	})
}
