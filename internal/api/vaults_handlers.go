package api

import (
	"errors"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"

	"alice/internal/inventory"
	"alice/internal/license"
	"alice/internal/platform/azureid"
	"alice/internal/platform/validate"
	"alice/internal/rbac"
	"alice/internal/secrets"
)

// vaultRoutes are the Key Vault operations that are not part of the Phase 3 target routes (those, listing,
// changing, deleting, testing and "Check now", handle vaults too: targets_handlers.go). Adding a vault and
// replacing its credentials need credentials.manage (Administrator with step-up, never an API token, R40 row 11);
// reading a vault's inventory needs read; releasing a held version is an Administrator's decision with step-up
// (ruling S6). All changes are refused in lock (ClassChange).
//
// The inventory of a vault is addressed through the vault (/targets/{id}/kv/...): the inventory queries are
// scoped by vault, so a vault certificate, version or import is never reachable under another vault's id.
func (s *server) vaultRoutes() []route {
	return []route{
		{method: http.MethodPost, pattern: "/api/v1/key-vaults", scope: scopeCreate, perm: rbac.CredentialsManage, lic: license.ClassChange, handler: s.createVault},
		{method: http.MethodPut, pattern: "/api/v1/targets/{id}/vault-credentials", scope: scopeResource, perm: rbac.CredentialsManage, lic: license.ClassChange, handler: s.replaceVaultCredentials},
		{method: http.MethodGet, pattern: "/api/v1/targets/{id}/kv/certificates", scope: scopeResource, perm: rbac.Read, handler: s.listKVCertificates},
		{method: http.MethodGet, pattern: "/api/v1/targets/{id}/kv/certificates/{certificate_id}", scope: scopeResource, perm: rbac.Read, handler: s.getKVCertificate},
		{method: http.MethodPost, pattern: "/api/v1/targets/{id}/kv/certificates/{certificate_id}/versions/{version_id}/actions/release",
			scope: scopeResource, perm: rbac.CredentialsManage, lic: license.ClassChange, handler: s.releaseVersion},
		{method: http.MethodGet, pattern: "/api/v1/targets/{id}/kv/keys", scope: scopeResource, perm: rbac.Read, handler: s.listKVKeys},
		{method: http.MethodGet, pattern: "/api/v1/targets/{id}/kv/secrets", scope: scopeResource, perm: rbac.Read, handler: s.listKVSecrets},
	}
}

// Body caps (R40): adding a vault or replacing its credentials carries a PFX (768 KiB, as an upload).
const (
	maxVaultBody    = 768 << 10
	maxBindingBody  = 16 << 10
	maxKVDeployBody = 8 << 10
	maxImportBody   = 4 << 10
	maxActionBody   = 4 << 10
)

// secretBody is what adding a vault or replacing its credentials carries. The secret fields are secretText:
// byte slices this handler owns and zeroes (zero) on every path, never strings.
type secretBody struct {
	Name                string     `json:"name"`
	VaultURL            string     `json:"vault_url"`
	Auth                string     `json:"auth"`
	TenantID            string     `json:"tenant_id"`
	ClientID            string     `json:"client_id"`
	ClientSecret        secretText `json:"client_secret"`
	SecretExpiresOn     *time.Time `json:"secret_expires_on"`
	CertificatePEM      secretText `json:"certificate_pem"`
	PrivateKeyPEM       secretText `json:"private_key_pem"`
	PFXBase64           secretText `json:"pfx_base64"`
	PFXPassword         secretText `json:"pfx_password"`
	PollIntervalMinutes int        `json:"poll_interval_minutes"`
	ServiceID           *uuid.UUID `json:"service_id"` // a new vault's service (R49; absent: the Default service)
	pfx                 []byte     // PFXBase64 decoded
}

// zero clears every byte slice of the body. Safe to call more than once.
func (b *secretBody) zero() {
	b.ClientSecret.zero()
	b.CertificatePEM.zero()
	b.PrivateKeyPEM.zero()
	b.PFXBase64.zero()
	b.PFXPassword.zero()
	clear(b.pfx)
}

var vaultCreateKeys = []string{"name", "vault_url", "auth", "tenant_id", "client_id", "client_secret", "secret_expires_on", "certificate_pem",
	"private_key_pem", "pfx_base64", "pfx_password", "poll_interval_minutes", "service_id"}

var vaultCredentialKeys = []string{"auth", "tenant_id", "client_id", "client_secret", "secret_expires_on", "certificate_pem", "private_key_pem",
	"pfx_base64", "pfx_password"}

// credential turns the body into the inventory's credential input: GUIDs in canonical form, the PFX decoded.
// Problems are collected in v. The returned input holds the handler's own slices: the caller zeroes the body.
func (b *secretBody) credential(v *validate.Errors) inventory.VaultCredentialInput {
	in := inventory.VaultCredentialInput{Auth: b.Auth, TenantID: b.TenantID, ClientID: b.ClientID, SecretExpiresOn: b.SecretExpiresOn}
	for _, f := range []struct {
		field string
		val   *string
	}{{"tenant_id", &in.TenantID}, {"client_id", &in.ClientID}} {
		if *f.val == "" {
			continue
		}
		g, ok := azureid.NormalizeGUID(*f.val)
		if !ok {
			v.Add(f.field, validate.Pattern, nil)
			continue
		}
		*f.val = g
	}
	in.ClientSecret = secrets.NewPlaintext(b.ClientSecret)
	in.Certificate.CertificatePEM = b.CertificatePEM
	in.Certificate.PrivateKeyPEM = b.PrivateKeyPEM
	if len(b.PFXBase64) > 0 {
		pfx, ok := decodeBase64Secret(b.PFXBase64)
		if !ok {
			v.Add("pfx_base64", validate.Pattern, nil)
		}
		b.pfx = pfx
		in.Certificate.PFX = pfx
	}
	in.Certificate.PFXPassword = string(b.PFXPassword) // a Go string: it cannot be cleared (as the Phase 4 upload's)
	return in
}

func (s *server) createVault(w http.ResponseWriter, r *http.Request) {
	refs := s.serviceRefs(r)
	var req secretBody
	defer req.zero()
	if !s.decodeExact(w, r, &req, maxVaultBody, vaultCreateKeys...) {
		return
	}
	var v validate.Errors
	in := req.credential(&v)
	pv, err := azureid.ParseVault(req.VaultURL)
	if err != nil {
		v.Add("vault_url", validate.Pattern, nil)
	}
	if err := v.Err(); err != nil {
		s.fail(w, r, err)
		return
	}
	t, rep, jobID, err := s.deps.Inventory.CreateVault(r.Context(), s.actor(r), inventory.NewVault{
		Name: req.Name, VaultURL: pv.URL, Auth: in.Auth, TenantID: in.TenantID, ClientID: in.ClientID, ClientSecret: in.ClientSecret,
		SecretExpiresOn: in.SecretExpiresOn, Certificate: in.Certificate, PollIntervalMinutes: req.PollIntervalMinutes,
		ServiceID: derefOr(req.ServiceID, uuid.Nil),
	})
	req.zero()
	if err != nil {
		s.failVault(w, r, err)
		return
	}
	a := accepted(jobID)
	w.Header().Set("ETag", etag(t.Version))
	w.Header().Set("Location", "/api/v1/targets/"+t.ID.String())
	writeJSON(w, http.StatusCreated, map[string]any{"target": targetJSON(t, refs), "access": accessJSON(rep.Azure), "job_id": a.JobID, "status_url": a.StatusURL})
}

// failVault is fail with the vault's own wording of a duplicate.
func (s *server) failVault(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, inventory.ErrDuplicateTarget) {
		s.writeError(w, r, ErrKVVaultDuplicate)
		return
	}
	s.fail(w, r, err)
}

func (s *server) replaceVaultCredentials(w http.ResponseWriter, r *http.Request) {
	refs := s.serviceRefs(r)
	id, ok := pathUUID(r, "id")
	if !ok {
		s.writeError(w, r, ErrNotFound)
		return
	}
	version, ok := ifMatch(r)
	if !ok {
		s.writeError(w, r, ErrPreconditionFailed)
		return
	}
	var req secretBody
	defer req.zero()
	if !s.decodeExact(w, r, &req, maxVaultBody, vaultCredentialKeys...) {
		return
	}
	var v validate.Errors
	in := req.credential(&v)
	if err := v.Err(); err != nil {
		s.fail(w, r, err)
		return
	}
	t, rep, jobID, err := s.deps.Inventory.ReplaceVaultCredentials(r.Context(), s.actor(r), id, version, in)
	req.zero()
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var job *string
	if jobID != uuid.Nil {
		j := jobID.String()
		job = &j
	}
	w.Header().Set("ETag", etag(t.Version))
	writeJSON(w, http.StatusOK, map[string]any{"target": targetJSON(t, refs), "access": accessJSON(rep.Azure), "job_id": job})
}

// strictAction reports whether the caller meets credentials.manage right now: an Administrator's browser
// session with a fresh step-up. It is for the operations whose route permission is weaker (deploying a held
// version, adding websites to a binding that deploys automatically, deleting a vault with its bindings): the
// refusal is written, audited like the guard's and false is returned. Inventory enforces the role again
// (ErrAdminRequired, ErrHeldNeedsAdmin); step-up and the token rule are the API's alone.
func (s *server) strictAction(w http.ResponseWriter, r *http.Request) bool {
	return s.strictActionFor(w, r, rbac.CredentialsManage)
}

// strictActionFor is strictAction for another permission that is an Administrator's browser session with a fresh
// step-up (acme.manage: switching unattended ACME deployment on through a binding, ruling of Task 12 I2).
func (s *server) strictActionFor(w http.ResponseWriter, r *http.Request, perm rbac.Permission) bool {
	p := principalFrom(r.Context())
	rt := route{method: r.Method, pattern: strings.TrimPrefix(r.Pattern, r.Method+" "), perm: perm}
	switch rbac.Decide(perm, p.Subject(s.deps.Clock.Now())) {
	case rbac.Allow:
		return true
	case rbac.DenyStepUp:
		s.auditDenied(r, rt, p, "stepup")
		s.writeError(w, r, ErrStepUpRequired)
	default:
		s.auditDenied(r, rt, p, "permission")
		s.writeError(w, r, ErrForbidden)
	}
	return false
}

// strictSession says whether the caller meets credentials.manage right now (an Administrator's browser session
// with a fresh step-up, not an API token). It is handed to the inventory on every call that has a strict case,
// which refuses that case itself without it.
func (s *server) strictSession(r *http.Request) bool {
	return rbac.Decide(rbac.CredentialsManage, principalFrom(r.Context()).Subject(s.deps.Clock.Now())) == rbac.Allow
}

// kvFilter reads the query of a vault inventory list: q, expires_before (RFC 3339 or a date), missing, cursor, limit.
func kvFilter(r *http.Request, v *validate.Errors) inventory.KVFilter {
	q := r.URL.Query()
	f := inventory.KVFilter{Query: q.Get("q"), Missing: q.Get("missing"), Cursor: q.Get("cursor"), Limit: pageLimit(q.Get("limit"), v)}
	if raw := q.Get("expires_before"); raw != "" {
		t, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			t, err = time.Parse(time.DateOnly, raw)
		}
		if err != nil {
			v.Add("expires_before", validate.Pattern, nil)
		} else {
			t = t.UTC()
			f.ExpiresBefore = &t
		}
	}
	if !slices.Contains([]string{inventory.KVMissingHide, inventory.KVMissingInclude, inventory.KVMissingOnly}, f.Missing) {
		v.Add("missing", validate.OneOf, map[string]string{"values": inventory.KVMissingInclude + ", " + inventory.KVMissingOnly})
	}
	if utf8.RuneCountInString(f.Query) > maxQueryRunes {
		v.Add("q", validate.TooLong, map[string]string{"max": strconv.Itoa(maxQueryRunes)})
	}
	if len(f.Cursor) > maxCursorBytes {
		v.Add("cursor", validate.TooLong, map[string]string{"max": strconv.Itoa(maxCursorBytes)})
	}
	return f
}

// vaultAndFilter parses the vault id and the list query; on failure it has answered.
func (s *server) vaultAndFilter(w http.ResponseWriter, r *http.Request) (uuid.UUID, inventory.KVFilter, bool) {
	id, ok := pathUUID(r, "id")
	if !ok {
		s.writeError(w, r, ErrNotFound)
		return uuid.Nil, inventory.KVFilter{}, false
	}
	var v validate.Errors
	f := kvFilter(r, &v)
	if err := v.Err(); err != nil {
		s.fail(w, r, err)
		return uuid.Nil, inventory.KVFilter{}, false
	}
	return id, f, true
}

func (s *server) listKVCertificates(w http.ResponseWriter, r *http.Request) {
	id, f, ok := s.vaultAndFilter(w, r)
	if !ok {
		return
	}
	page, err := s.deps.Inventory.ListKVCertificates(r.Context(), id, f)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	items := make([]kvCertificateDTO, 0, len(page.Items))
	for _, c := range page.Items {
		items = append(items, kvCertificateJSON(c))
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "next_cursor": nextCursor(page.NextCursor)})
}

func (s *server) listKVKeys(w http.ResponseWriter, r *http.Request) {
	id, f, ok := s.vaultAndFilter(w, r)
	if !ok {
		return
	}
	keys, next, err := s.deps.Inventory.ListKVKeys(r.Context(), id, f)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	items := make([]kvKeyDTO, 0, len(keys))
	for _, k := range keys {
		items = append(items, kvKeyJSON(k))
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "next_cursor": nextCursor(next)})
}

func (s *server) listKVSecrets(w http.ResponseWriter, r *http.Request) {
	id, f, ok := s.vaultAndFilter(w, r)
	if !ok {
		return
	}
	list, next, err := s.deps.Inventory.ListKVSecrets(r.Context(), id, f)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	items := make([]kvSecretDTO, 0, len(list))
	for _, sec := range list {
		items = append(items, kvSecretJSON(sec))
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "next_cursor": nextCursor(next)})
}

func (s *server) getKVCertificate(w http.ResponseWriter, r *http.Request) {
	vault, ok1 := pathUUID(r, "id")
	id, ok2 := pathUUID(r, "certificate_id")
	if !ok1 || !ok2 {
		s.writeError(w, r, ErrNotFound)
		return
	}
	d, err := s.deps.Inventory.KVCertificate(r.Context(), vault, id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, kvCertificateDetailJSON(d))
}

// releaseVersion lifts the hold of a version (spec §11.6 item 8). The route is scoped to the vault and the
// certificate; confirm_incomplete_chain is the Administrator's acknowledgement that a version held for its
// incomplete chain is released with that chain (the route is an Administrator's already). It approves no
// deployment: automatic deployment holds the version again, and Deploy now asks for the confirmation again.
func (s *server) releaseVersion(w http.ResponseWriter, r *http.Request) {
	vault, ok1 := pathUUID(r, "id")
	cert, ok2 := pathUUID(r, "certificate_id")
	version, ok3 := pathUUID(r, "version_id")
	if !ok1 || !ok2 || !ok3 {
		s.writeError(w, r, ErrNotFound)
		return
	}
	var req struct {
		ConfirmIncompleteChain bool `json:"confirm_incomplete_chain"`
	}
	if !s.decodeExactOptional(w, r, &req, maxActionBody, "confirm_incomplete_chain") {
		return
	}
	got, err := s.deps.Inventory.ReleaseVersion(r.Context(), s.actor(r), inventory.ReleaseInput{
		VaultID: vault, KVCertificateID: cert, VersionID: version, ConfirmIncompleteChain: req.ConfirmIncompleteChain,
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, kvVersionJSON(got))
}

// vaultTypes are the values of GET /targets?type=.
var vaultTypes = append(append([]string{inventory.TypeLinux}, inventory.WebServerTypes()...), inventory.TypeAzureKeyVault)

// accessCheckRequest is the optional body of POST /targets/{id}/actions/test.
type accessCheckRequest struct {
	ReadSecretOf string `json:"read_secret_of"`
}
