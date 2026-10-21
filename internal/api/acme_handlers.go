package api

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"

	"alice/internal/authz/services"
	"alice/internal/inventory"
	"alice/internal/license"
	"alice/internal/platform/validate"
	"alice/internal/rbac"
	"alice/internal/secrets"
)

// acmeRoutes are the ACME certificate issuance operations (plan 2026-10-13 Task 13; decision D6, amendments A5, A9,
// A13). Everyone reads (acme.view, read tokens included). Certificate authorities (providers), their accounts, DNS hooks
// and the certificate definitions with their name lists are an Administrator's browser session with a fresh step-up,
// never an API token (acme.manage). Operators and operate tokens order a renewal, run a test run, bind locations of
// existing certificates and deploy them (acme.operate); switching unattended deployment ON through a binding is an
// Administrator's act with a fresh step-up (strictActionFor, ruling of Task 12 I2), which the inventory repeats as a
// role check with the licence gate.
//
// Licence: every route that contacts a CA or a server, or prepares that contact, is ClassChange (403 license.locked in
// lock, nothing recorded, no CA contact). Removing a binding and deleting a certificate definition only reduce what
// Alice does (no renewal, no deployment): they are ClassAlways, like the Key Vault binding removal. The routes that
// contact a CA or start work are limited to 10 a minute per user or token (limitACME, A5).
func (s *server) acmeRoutes() []route {
	const (
		providers = "/api/v1/acme/providers"
		accounts  = "/api/v1/acme/accounts"
		hooks     = "/api/v1/acme/hooks"
		certs     = "/api/v1/acme/certificates"
	)
	view, operate, manage := rbac.AcmeView, rbac.AcmeOperate, rbac.AcmeManage
	change, always := license.ClassChange, license.ClassAlways
	return []route{
		{method: http.MethodGet, pattern: providers, scope: scopeAny, perm: view, handler: s.listACMEProviders},
		{method: http.MethodPost, pattern: providers, scope: scopePlatform, perm: manage, lic: change, handler: s.createACMEProvider},
		{method: http.MethodGet, pattern: providers + "/{id}", scope: scopeAny, perm: view, handler: s.getACMEProvider},
		{method: http.MethodPatch, pattern: providers + "/{id}", scope: scopePlatform, perm: manage, lic: change, handler: s.updateACMEProvider},
		{method: http.MethodDelete, pattern: providers + "/{id}", scope: scopePlatform, perm: manage, lic: change, handler: s.deleteACMEProvider},
		{method: http.MethodPost, pattern: providers + "/{id}/account", scope: scopePlatform, perm: manage, lic: change, limit: limitACME, handler: s.registerACMEAccount},
		{method: http.MethodPost, pattern: providers + "/{id}/preview", scope: scopePlatform, perm: rbac.AcmePreview, lic: change, limit: limitACME,
			handler: s.previewACMEProvider},
		{method: http.MethodPost, pattern: accounts + "/{id}/rollover", scope: scopePlatform, perm: manage, lic: change, limit: limitACME, handler: s.rolloverACMEAccount},
		{method: http.MethodPost, pattern: accounts + "/{id}/rollover/recover", scope: scopePlatform, perm: manage, lic: change, limit: limitACME,
			handler: s.recoverACMERollover},
		{method: http.MethodPost, pattern: accounts + "/{id}/deactivate", scope: scopePlatform, perm: manage, lic: change, limit: limitACME, handler: s.deactivateACMEAccount},
		{method: http.MethodGet, pattern: hooks, scope: scopeAny, perm: view, handler: s.listACMEHooks},
		{method: http.MethodPost, pattern: hooks, scope: scopePlatform, perm: manage, lic: change, handler: s.createACMEHook},
		{method: http.MethodGet, pattern: hooks + "/{id}", scope: scopeAny, perm: view, handler: s.getACMEHook},
		{method: http.MethodPatch, pattern: hooks + "/{id}", scope: scopePlatform, perm: manage, lic: change, handler: s.updateACMEHook},
		{method: http.MethodDelete, pattern: hooks + "/{id}", scope: scopePlatform, perm: manage, lic: change, handler: s.deleteACMEHook},
		{method: http.MethodGet, pattern: certs, scope: scopeList, perm: view, handler: s.listACMECertificates},
		{method: http.MethodPost, pattern: certs, scope: scopeCreate, perm: manage, lic: change, handler: s.createACMECertificate},
		{method: http.MethodGet, pattern: certs + "/{id}", scope: scopeResource, resolve: by(services.KindACMECertificate, "id"), perm: view, handler: s.getACMECertificate},
		// limitACME: switching auto_renew on re-arms automatic renewal (a fresh series against the CA, like /rearm).
		{method: http.MethodPatch, pattern: certs + "/{id}", scope: scopeResource, resolve: by(services.KindACMECertificate, "id"), perm: manage, lic: change, limit: limitACME, handler: s.updateACMECertificate},
		{method: http.MethodDelete, pattern: certs + "/{id}", scope: scopeResource, resolve: by(services.KindACMECertificate, "id"), perm: manage, lic: always, handler: s.deleteACMECertificate},
		{method: http.MethodPost, pattern: certs + "/{id}/order", scope: scopeResource, resolve: by(services.KindACMECertificate, "id"), perm: operate, lic: change, limit: limitACME, handler: s.orderACME(inventory.ACMEOrderIssue)},
		{method: http.MethodPost, pattern: certs + "/{id}/test", scope: scopeResource, resolve: by(services.KindACMECertificate, "id"), perm: operate, lic: change, limit: limitACME, handler: s.orderACME(inventory.ACMEOrderTest)},
		{method: http.MethodGet, pattern: certs + "/{id}/orders", scope: scopeResource, resolve: by(services.KindACMECertificate, "id"), perm: view, handler: s.listACMEOrders},
		{method: http.MethodPost, pattern: certs + "/{id}/rearm", scope: scopeResource, resolve: by(services.KindACMECertificate, "id"), perm: manage, lic: change, limit: limitACME, handler: s.rearmACME},
		{method: http.MethodPost, pattern: certs + "/{id}/release-hold", scope: scopeResource, resolve: by(services.KindACMECertificate, "id"), perm: manage, lic: change, handler: s.releaseACMEHold},
		// Revocation at the CA (RFC 8555 section 7.6, 2026-10-20): cannot be undone; a CA call like an order.
		{method: http.MethodPost, pattern: certs + "/{id}/revoke", scope: scopeResource, resolve: by(services.KindACMECertificate, "id"), perm: manage, lic: change, limit: limitACME, handler: s.revokeACME},
		{method: http.MethodGet, pattern: certs + "/{id}/bindings", scope: scopeResource, resolve: by(services.KindACMECertificate, "id"), perm: view, handler: s.listACMEBindings},
		{method: http.MethodPut, pattern: certs + "/{id}/bindings/{location_id}", scope: scopeCross, resolve: by(services.KindACMECertificate, "id"), perm: operate, lic: change, handler: s.putACMEBinding},
		{method: http.MethodDelete, pattern: certs + "/{id}/bindings/{location_id}", scope: scopeResource, resolve: byEither(services.KindACMECertificate, "id", services.KindACMEBindingPlace, "location_id"), perm: operate, lic: always, handler: s.deleteACMEBinding},
		{method: http.MethodPost, pattern: certs + "/{id}/deploy", scope: scopeResource, resolve: by(services.KindACMECertificate, "id"), perm: operate, lic: change, limit: limitACME, handler: s.deployACME},
	}
}

// Body caps of the ACME changes (SEC-023). A provider or hook carries a CA bundle of at most 64 KiB (JSON escapes each
// line break as two bytes); a certificate at most 100 names of at most 253 bytes.
const (
	maxACMEProviderBody = 128 << 10
	maxACMEHookBody     = 128 << 10
	maxACMECertBody     = 64 << 10
	maxACMEAccountBody  = 4 << 10
	maxACMEBindingBody  = 1 << 10
	maxACMEDeployBody   = 8 << 10

	maxACMEURLBytes      = 2048
	maxACMEBundleBytes   = 64 << 10
	maxACMEKIDBytes      = 255
	maxACMEHMACBytes     = 1024
	maxACMEContactBytes  = 254
	maxACMESuffixes      = 100
	maxACMESuffixBytes   = 253
	maxACMENameBytes     = 253
	maxACMEHookSecretLen = 256
	maxACMEFieldRunes    = 100
)

// acmeCertStates are the values of GET /acme/certificates?state=.
var acmeCertStates = []string{inventory.ACMEStatePending, inventory.ACMEStateIssuing, inventory.ACMEStateActive, inventory.ACMEStateFailing,
	inventory.ACMEStateStopped}

// checkHTTPSURL adds a field error unless raw is an absolute https URL of at most maxACMEURLBytes without user
// information (the inventory applies the full rule again: no query, no fragment, no control characters).
func checkHTTPSURL(field, raw string, v *validate.Errors) {
	if raw == "" {
		v.Add(field, validate.Required, nil)
		return
	}
	if len(raw) > maxACMEURLBytes {
		v.Add(field, validate.TooLong, map[string]string{"max": strconv.Itoa(maxACMEURLBytes)})
		return
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
		v.Add(field, validate.Pattern, nil)
	}
}

func checkMaxBytes(field, raw string, max int, v *validate.Errors) {
	if len(raw) > max {
		v.Add(field, validate.TooLong, map[string]string{"max": strconv.Itoa(max)})
	}
}

func checkMaxRunes(field, raw string, max int, v *validate.Errors) {
	if utf8.RuneCountInString(raw) > max {
		v.Add(field, validate.TooLong, map[string]string{"max": strconv.Itoa(max)})
	}
}

// checkSuffixes bounds an allow-list: at most 100 entries of at most 253 bytes (the inventory checks the labels).
func checkSuffixes(field string, list []string, v *validate.Errors) {
	if len(list) > maxACMESuffixes {
		v.Add(field, validate.TooLong, map[string]string{"max": strconv.Itoa(maxACMESuffixes)})
		return
	}
	for _, sfx := range list {
		if len(sfx) > maxACMESuffixBytes {
			v.Add(field, validate.TooLong, map[string]string{"max": strconv.Itoa(maxACMESuffixBytes)})
			return
		}
	}
}

// checkNames applies the name rules at the boundary (inventory.CheckACMENames, the rule the inventory and the order
// use): 1..100 DNS names of at most 253 bytes, a wildcard only as the whole first label, no address, no duplicates.
func checkNames(names []string, v *validate.Errors) {
	for _, n := range names {
		if len(n) > maxACMENameBytes {
			v.Add("names", validate.TooLong, map[string]string{"max": strconv.Itoa(maxACMENameBytes)})
			return
		}
	}
	if fe := inventory.CheckACMENames(names); fe != nil {
		*v = append(*v, *fe)
	}
}

// parseOptionalID reads an optional id of a body ("" or null: none).
func parseOptionalID(raw *string, field string, v *validate.Errors) *uuid.UUID {
	if raw == nil || *raw == "" {
		return nil
	}
	id, err := uuid.Parse(*raw)
	if err != nil || id == uuid.Nil {
		v.Add(field, validate.Pattern, nil)
		return nil
	}
	return &id
}

// eabInput turns the write-only EAB fields into the inventory's input; nil when neither is given. The HMAC text stays
// in the handler's slice (the inventory zeroes the Plaintext, the handler its body). Both or neither.
func eabInput(kid *string, hmac secretText, v *validate.Errors) *inventory.ACMEEABInput {
	if (kid == nil || *kid == "") && len(hmac) == 0 {
		return nil
	}
	switch {
	case kid == nil || *kid == "":
		v.Add("eab_kid", validate.Required, nil)
	case len(hmac) == 0:
		v.Add("eab_hmac", validate.Required, nil)
	case len(*kid) > maxACMEKIDBytes:
		v.Add("eab_kid", validate.TooLong, map[string]string{"max": strconv.Itoa(maxACMEKIDBytes)})
	case len(hmac) > maxACMEHMACBytes:
		v.Add("eab_hmac", validate.TooLong, map[string]string{"max": strconv.Itoa(maxACMEHMACBytes)})
	default:
		if _, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(string(hmac), "=")); err != nil {
			v.Add("eab_hmac", validate.Pattern, nil)
		}
		return &inventory.ACMEEABInput{KID: *kid, HMAC: secrets.NewPlaintext(hmac)}
	}
	return nil
}

// hasMailtoPrefix reports whether c starts with "mailto:" in any letter case.
func hasMailtoPrefix(c string) bool {
	return len(c) >= len("mailto:") && strings.EqualFold(c[:len("mailto:")], "mailto:")
}

// asciiLower lower-cases A-Z only (names are ASCII DNS names; no locale rule applies).
func asciiLower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if 'A' <= c && c <= 'Z' {
			b[i] = c + ('a' - 'A')
		}
	}
	return string(b)
}

// --- providers ---

type acmeProviderBody struct {
	Name                   *string    `json:"name"`
	DirectoryURL           *string    `json:"directory_url"`
	Preset                 *string    `json:"preset"`
	CABundlePEM            *string    `json:"ca_bundle_pem"`
	EABKID                 *string    `json:"eab_kid"`
	EABHMAC                secretText `json:"eab_hmac"`
	AllowedSuffixes        *[]string  `json:"allowed_suffixes"`
	RemoveEAB              bool       `json:"remove_eab"`
	ConfirmDirectoryChange bool       `json:"confirm_directory_change"`
}

var (
	acmeProviderCreateKeys = []string{"name", "directory_url", "preset", "ca_bundle_pem", "eab_kid", "eab_hmac", "allowed_suffixes"}
	acmeProviderPatchKeys  = append(slices.Clone(acmeProviderCreateKeys), "remove_eab", "confirm_directory_change")
)

// check bounds the fields that are present (create: name and directory_url are required).
func (b *acmeProviderBody) check(create bool, v *validate.Errors) {
	if create && b.Name == nil {
		v.Add("name", validate.Required, nil)
	}
	if b.Name != nil {
		checkMaxRunes("name", *b.Name, maxACMEFieldRunes, v)
	}
	if b.DirectoryURL != nil || create {
		checkHTTPSURL("directory_url", deref(b.DirectoryURL), v)
	}
	if b.Preset != nil && *b.Preset != "" && !slices.Contains(inventory.ACMEPresets(), *b.Preset) {
		v.Add("preset", validate.OneOf, map[string]string{"values": strings.Join(inventory.ACMEPresets(), ", ")})
	}
	if b.CABundlePEM != nil {
		checkMaxBytes("ca_bundle_pem", *b.CABundlePEM, maxACMEBundleBytes, v)
	}
	if b.AllowedSuffixes != nil {
		checkSuffixes("allowed_suffixes", *b.AllowedSuffixes, v)
	}
}

func deref(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

func (s *server) listACMEProviders(w http.ResponseWriter, r *http.Request) {
	list, err := s.deps.ACME.ListACMEProviders(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	items := make([]acmeProviderDTO, 0, len(list))
	for _, p := range list {
		items = append(items, acmeProviderJSON(p))
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *server) createACMEProvider(w http.ResponseWriter, r *http.Request) {
	var req acmeProviderBody
	defer func() { req.EABHMAC.zero() }() // the slice the decoder fills, not the nil one of now
	if !s.decodeExact(w, r, &req, maxACMEProviderBody, acmeProviderCreateKeys...) {
		return
	}
	var v validate.Errors
	req.check(true, &v)
	eab := eabInput(req.EABKID, req.EABHMAC, &v)
	if err := v.Err(); err != nil {
		s.fail(w, r, err)
		return
	}
	in := inventory.ACMEProviderInput{Name: deref(req.Name), DirectoryURL: deref(req.DirectoryURL), Preset: deref(req.Preset),
		CABundlePEM: deref(req.CABundlePEM), EAB: eab}
	if req.AllowedSuffixes != nil {
		in.AllowedSuffixes = *req.AllowedSuffixes
	}
	p, err := s.deps.ACME.CreateACMEProvider(r.Context(), s.actor(r), in)
	req.EABHMAC.zero()
	if err != nil {
		s.fail(w, r, err)
		return
	}
	w.Header().Set("Location", "/api/v1/acme/providers/"+p.ID.String())
	writeJSON(w, http.StatusCreated, acmeProviderJSON(p))
}

func (s *server) getACMEProvider(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(r, "id")
	if !ok {
		s.writeError(w, r, ErrNotFound)
		return
	}
	p, err := s.deps.ACME.GetACMEProvider(r.Context(), id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	accounts, err := s.deps.ACME.ListACMEAccounts(r.Context(), id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	d := acmeProviderJSON(p)
	d.Accounts = make([]acmeAccountDTO, 0, len(accounts))
	for _, a := range accounts {
		d.Accounts = append(d.Accounts, acmeAccountJSON(a))
	}
	writeJSON(w, http.StatusOK, d)
}

func (s *server) updateACMEProvider(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(r, "id")
	if !ok {
		s.writeError(w, r, ErrNotFound)
		return
	}
	var req acmeProviderBody
	defer func() { req.EABHMAC.zero() }() // the slice the decoder fills, not the nil one of now
	if !s.decodeExact(w, r, &req, maxACMEProviderBody, acmeProviderPatchKeys...) {
		return
	}
	var v validate.Errors
	req.check(false, &v)
	eab := eabInput(req.EABKID, req.EABHMAC, &v) // with remove_eab too: the inventory refuses the pair (field eab)
	if err := v.Err(); err != nil {
		s.fail(w, r, err)
		return
	}
	p, err := s.deps.ACME.UpdateACMEProvider(r.Context(), s.actor(r), id, inventory.ACMEProviderPatch{Name: req.Name, DirectoryURL: req.DirectoryURL,
		Preset: req.Preset, CABundlePEM: req.CABundlePEM, AllowedSuffixes: req.AllowedSuffixes, EAB: eab, RemoveEAB: req.RemoveEAB,
		ConfirmDirectoryChange: req.ConfirmDirectoryChange})
	req.EABHMAC.zero()
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, acmeProviderJSON(p))
}

func (s *server) deleteACMEProvider(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(r, "id")
	if !ok {
		s.writeError(w, r, ErrNotFound)
		return
	}
	if err := s.deps.ACME.DeleteACMEProvider(r.Context(), s.actor(r), id); err != nil {
		s.fail(w, r, err)
		return
	}
	noContent(w)
}

// --- accounts ---

// registerACMEAccount creates the provider's account at the CA: contact_email (optional; a plain address, a mailto:
// prefix is accepted), tos_accepted (required when the CA publishes terms of service: 422 ALC-ACM-0003 otherwise) and
// accepted_terms_url (optional: the terms URL the preview showed; when the CA's terms differ now, 422 ALC-ACM-0003).
func (s *server) registerACMEAccount(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(r, "id")
	if !ok {
		s.writeError(w, r, ErrNotFound)
		return
	}
	var req struct {
		ContactEmail     string `json:"contact_email"`
		TOSAccepted      bool   `json:"tos_accepted"`
		AcceptedTermsURL string `json:"accepted_terms_url"`
	}
	if !s.decodeExactOptional(w, r, &req, maxACMEAccountBody, "contact_email", "tos_accepted", "accepted_terms_url") {
		return
	}
	var v validate.Errors
	checkMaxBytes("contact_email", req.ContactEmail, maxACMEContactBytes, &v)
	checkMaxBytes("accepted_terms_url", req.AcceptedTermsURL, maxACMEURLBytes, &v)
	if c := strings.TrimSpace(req.ContactEmail); strings.Contains(c, ":") && !hasMailtoPrefix(c) {
		v.Add("contact_email", validate.Email, nil) // only an e-mail contact (no tel: or other scheme)
	}
	if err := v.Err(); err != nil {
		s.fail(w, r, err)
		return
	}
	a, err := s.deps.ACME.RegisterACMEAccountTerms(r.Context(), s.actor(r), id, req.ContactEmail, req.TOSAccepted, req.AcceptedTermsURL)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, acmeAccountJSON(a))
}

// previewACMEProvider reads the provider's CA directory for the registration form (no body): the terms of service URL
// (only a safe https link; terms_url_unsafe otherwise), whether an external account binding is required, and the
// optional resources. Nothing is stored and no secret is read.
func (s *server) previewACMEProvider(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(r, "id")
	if !ok {
		s.writeError(w, r, ErrNotFound)
		return
	}
	p, err := s.deps.ACME.PreviewACMEProvider(r.Context(), id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, acmePreviewDTO{TermsOfServiceURL: p.TermsOfServiceURL, TermsURLUnsafe: p.TermsURLUnsafe,
		ExternalAccountRequired: p.ExternalAccountRequired, KeyChangeSupported: p.KeyChangeSupported, RenewalInfoSupported: p.RenewalInfoSupported,
		Website: p.Website})
}

// accountAction answers one of the account operations that contact the CA (no body): the account it returns.
func (s *server) accountAction(w http.ResponseWriter, r *http.Request,
	op func(ctx context.Context, a inventory.Actor, id uuid.UUID) (inventory.ACMEAccount, error)) {
	id, ok := pathUUID(r, "id")
	if !ok {
		s.writeError(w, r, ErrNotFound)
		return
	}
	a, err := op(r.Context(), s.actor(r), id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, acmeAccountJSON(a))
}

// rolloverACMEAccount changes the account key at the CA (A6); it answers the new active account.
func (s *server) rolloverACMEAccount(w http.ResponseWriter, r *http.Request) {
	s.accountAction(w, r, s.deps.ACME.RolloverACMEAccount)
}

// recoverACMERollover settles a key change whose outcome Alice did not learn ("Check key change").
func (s *server) recoverACMERollover(w http.ResponseWriter, r *http.Request) {
	s.accountAction(w, r, s.deps.ACME.RecoverACMERollover)
}

func (s *server) deactivateACMEAccount(w http.ResponseWriter, r *http.Request) {
	s.accountAction(w, r, s.deps.ACME.DeactivateACMEAccount)
}

// --- hooks ---

type acmeHookBody struct {
	Name                   *string    `json:"name"`
	URL                    *string    `json:"url"`
	CABundlePEM            *string    `json:"ca_bundle_pem"`
	Secret                 secretText `json:"secret"`
	AllowedSuffixes        *[]string  `json:"allowed_suffixes"`
	PropagationWaitSeconds *int       `json:"propagation_wait_seconds"`
	PollTimeoutSeconds     *int       `json:"poll_timeout_seconds"`
}

var acmeHookKeys = []string{"name", "url", "ca_bundle_pem", "secret", "allowed_suffixes", "propagation_wait_seconds", "poll_timeout_seconds"}

func (b *acmeHookBody) check(create bool, v *validate.Errors) {
	if create && b.Name == nil {
		v.Add("name", validate.Required, nil)
	}
	if b.Name != nil {
		checkMaxRunes("name", *b.Name, maxACMEFieldRunes, v)
	}
	if b.URL != nil || create {
		checkHTTPSURL("url", deref(b.URL), v)
	}
	if b.CABundlePEM != nil {
		checkMaxBytes("ca_bundle_pem", *b.CABundlePEM, maxACMEBundleBytes, v)
	}
	if create && len(b.Secret) == 0 {
		v.Add("secret", validate.Required, nil)
	}
	if len(b.Secret) > maxACMEHookSecretLen {
		v.Add("secret", validate.TooLong, map[string]string{"max": strconv.Itoa(maxACMEHookSecretLen)})
	}
	if b.AllowedSuffixes != nil {
		checkSuffixes("allowed_suffixes", *b.AllowedSuffixes, v)
	}
}

func (s *server) listACMEHooks(w http.ResponseWriter, r *http.Request) {
	list, err := s.deps.ACME.ListACMEHooks(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	items := make([]acmeHookDTO, 0, len(list))
	for _, h := range list {
		items = append(items, acmeHookJSON(h))
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *server) createACMEHook(w http.ResponseWriter, r *http.Request) {
	var req acmeHookBody
	defer func() { req.Secret.zero() }() // the slice the decoder fills, not the nil one of now
	if !s.decodeExact(w, r, &req, maxACMEHookBody, acmeHookKeys...) {
		return
	}
	var v validate.Errors
	req.check(true, &v)
	if err := v.Err(); err != nil {
		s.fail(w, r, err)
		return
	}
	in := inventory.ACMEHookInput{Name: deref(req.Name), URL: deref(req.URL), CABundlePEM: deref(req.CABundlePEM),
		Secret: secrets.NewPlaintext(req.Secret), PropagationWaitSeconds: req.PropagationWaitSeconds}
	if req.AllowedSuffixes != nil {
		in.AllowedSuffixes = *req.AllowedSuffixes
	}
	if req.PollTimeoutSeconds != nil {
		in.PollTimeoutSeconds = *req.PollTimeoutSeconds
	}
	h, err := s.deps.ACME.CreateACMEHook(r.Context(), s.actor(r), in)
	req.Secret.zero()
	if err != nil {
		s.fail(w, r, err)
		return
	}
	w.Header().Set("Location", "/api/v1/acme/hooks/"+h.ID.String())
	writeJSON(w, http.StatusCreated, acmeHookJSON(h))
}

func (s *server) getACMEHook(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(r, "id")
	if !ok {
		s.writeError(w, r, ErrNotFound)
		return
	}
	h, err := s.deps.ACME.GetACMEHook(r.Context(), id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, acmeHookJSON(h))
}

func (s *server) updateACMEHook(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(r, "id")
	if !ok {
		s.writeError(w, r, ErrNotFound)
		return
	}
	var req acmeHookBody
	defer func() { req.Secret.zero() }() // the slice the decoder fills, not the nil one of now
	if !s.decodeExact(w, r, &req, maxACMEHookBody, acmeHookKeys...) {
		return
	}
	var v validate.Errors
	req.check(false, &v)
	if err := v.Err(); err != nil {
		s.fail(w, r, err)
		return
	}
	var secret secrets.Plaintext
	if len(req.Secret) > 0 {
		secret = secrets.NewPlaintext(req.Secret)
	}
	h, err := s.deps.ACME.UpdateACMEHook(r.Context(), s.actor(r), id, inventory.ACMEHookPatch{Name: req.Name, URL: req.URL, CABundlePEM: req.CABundlePEM,
		Secret: secret, AllowedSuffixes: req.AllowedSuffixes, PropagationWaitSeconds: req.PropagationWaitSeconds,
		PollTimeoutSeconds: req.PollTimeoutSeconds})
	req.Secret.zero()
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, acmeHookJSON(h))
}

func (s *server) deleteACMEHook(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(r, "id")
	if !ok {
		s.writeError(w, r, ErrNotFound)
		return
	}
	if err := s.deps.ACME.DeleteACMEHook(r.Context(), s.actor(r), id); err != nil {
		s.fail(w, r, err)
		return
	}
	noContent(w)
}

// --- certificates ---

type acmeCertBody struct {
	ProviderID      *string   `json:"provider_id"`
	Names           *[]string `json:"names"`
	KeyType         *string   `json:"key_type"`
	Challenge       *string   `json:"challenge"`
	HookID          *string   `json:"hook_id"`
	HTTPTargetID    *string   `json:"http_target_id"`
	RenewBeforeDays *int      `json:"renew_before_days"`
	AutoRenew       *bool     `json:"auto_renew"`
	AutoDeploy      *bool     `json:"auto_deploy"`
	// ServiceID: a new definition's service (R49; absent: the Default service). A change never takes it (assign moves).
	ServiceID *uuid.UUID `json:"service_id"`
}

var acmeCertKeys = []string{"provider_id", "names", "key_type", "challenge", "hook_id", "http_target_id", "renew_before_days", "auto_renew",
	"auto_deploy"}

// check bounds the body; HTTP-01 is enabled (the helper suites ran, Task 7: the http01Enabled gate of A1 is gone), so
// both proof methods are accepted.
func (b *acmeCertBody) check(create bool, v *validate.Errors) (provider, hook, target *uuid.UUID) {
	if create && b.ProviderID == nil {
		v.Add("provider_id", validate.Required, nil)
	}
	provider = parseOptionalID(b.ProviderID, "provider_id", v)
	if create || b.Names != nil {
		var names []string
		if b.Names != nil {
			names = *b.Names
		}
		checkNames(names, v)
	}
	if b.KeyType != nil {
		checkMaxRunes("key_type", *b.KeyType, maxACMEFieldRunes, v)
	}
	if b.Challenge != nil && *b.Challenge != inventory.ACMEChallengeDNS01 && *b.Challenge != inventory.ACMEChallengeHTTP01 {
		v.Add("challenge", validate.OneOf, map[string]string{"values": inventory.ACMEChallengeDNS01 + ", " + inventory.ACMEChallengeHTTP01})
	}
	if create && b.Challenge == nil {
		v.Add("challenge", validate.Required, nil)
	}
	hook = parseOptionalID(b.HookID, "hook_id", v)
	target = parseOptionalID(b.HTTPTargetID, "http_target_id", v)
	return provider, hook, target
}

// acmeCertCursor is the list's keyset position: the creation time (Unix nanoseconds) and the id of the last item.
func acmeCertCursor(c inventory.ACMECertificate) string {
	return strconv.FormatInt(c.CreatedAt.UnixNano(), 10) + "." + c.ID.String()
}

func parseACMECertCursor(raw string) (time.Time, uuid.UUID, bool) {
	ns, id, ok := strings.Cut(raw, ".")
	if !ok {
		return time.Time{}, uuid.Nil, false
	}
	n, err := strconv.ParseInt(ns, 10, 64)
	if err != nil {
		return time.Time{}, uuid.Nil, false
	}
	u, err := uuid.Parse(id)
	if err != nil {
		return time.Time{}, uuid.Nil, false
	}
	return time.Unix(0, n).UTC(), u, true
}

// listACMECertificates is the list of ACME certificates, oldest first, in pages (cursor, limit 1..200, default 50) with
// the filters state, provider_id and q (a part of one of the names).
func (s *server) listACMECertificates(w http.ResponseWriter, r *http.Request) {
	refs := s.serviceRefs(r)
	q := r.URL.Query()
	var v validate.Errors
	state, query, cursor := q.Get("state"), asciiLower(strings.TrimSpace(q.Get("q"))), q.Get("cursor")
	provider := optionalUUID(q.Get("provider_id"), "provider_id", &v)
	limit := pageLimit(q.Get("limit"), &v)
	filter := s.serviceFilter(r, &v) // R49: service_id and environment_id
	if state != "" && !slices.Contains(acmeCertStates, state) {
		v.Add("state", validate.OneOf, map[string]string{"values": strings.Join(acmeCertStates, ", ")})
	}
	if utf8.RuneCountInString(query) > maxQueryRunes {
		v.Add("q", validate.TooLong, map[string]string{"max": strconv.Itoa(maxQueryRunes)})
	}
	var (
		afterT  time.Time
		afterID uuid.UUID
	)
	switch {
	case len(cursor) > maxCursorBytes:
		v.Add("cursor", validate.TooLong, map[string]string{"max": strconv.Itoa(maxCursorBytes)})
	case cursor != "":
		var ok bool
		if afterT, afterID, ok = parseACMECertCursor(cursor); !ok {
			v.Add("cursor", validate.Pattern, nil)
		}
	}
	if err := v.Err(); err != nil {
		s.fail(w, r, err)
		return
	}
	all, err := s.deps.ACME.ListACMECertificatesIn(r.Context(), s.reachOf(r, rbac.AcmeView))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	items := make([]acmeCertificateDTO, 0, min(limit, len(all)))
	next := ""
	var last inventory.ACMECertificate
	for _, c := range all {
		if cursor != "" && (c.CreatedAt.Before(afterT) || (c.CreatedAt.Equal(afterT) && c.ID.String() <= afterID.String())) {
			continue
		}
		if (state != "" && c.State != state) || (provider != uuid.Nil && c.ProviderID != provider) || !inServices(filter, c.ServiceID) ||
			(query != "" && !slices.ContainsFunc(c.Names, func(n string) bool { return strings.Contains(n, query) })) {
			continue
		}
		if len(items) == limit {
			next = acmeCertCursor(last)
			break
		}
		items = append(items, acmeCertificateJSON(c, s.deps.Clock.Now(), refs))
		last = c
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "next_cursor": nextCursor(next)})
}

func (s *server) createACMECertificate(w http.ResponseWriter, r *http.Request) {
	refs := s.serviceRefs(r)
	var req acmeCertBody
	if !s.decodeExact(w, r, &req, maxACMECertBody, append(slices.Clone(acmeCertKeys), "service_id")...) {
		return
	}
	var v validate.Errors
	provider, hook, target := req.check(true, &v)
	if err := v.Err(); err != nil {
		s.fail(w, r, err)
		return
	}
	in := inventory.ACMECertificateInput{ProviderID: *provider, Names: *req.Names, KeyType: deref(req.KeyType), Challenge: deref(req.Challenge),
		HookID: hook, HTTPTargetID: target, AutoRenew: req.AutoRenew, ServiceID: derefOr(req.ServiceID, uuid.Nil)}
	if req.RenewBeforeDays != nil {
		in.RenewBeforeDays = *req.RenewBeforeDays
	}
	if req.AutoDeploy != nil {
		in.AutoDeploy = *req.AutoDeploy
	}
	c, err := s.deps.ACME.CreateACMECertificate(r.Context(), s.actor(r), in)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	w.Header().Set("Location", "/api/v1/acme/certificates/"+c.ID.String())
	writeJSON(w, http.StatusCreated, acmeCertificateJSON(c, s.deps.Clock.Now(), refs))
}

// getACMECertificate is one certificate with its bindings (state, attention mark) and its deploy hold and stop marks.
func (s *server) getACMECertificate(w http.ResponseWriter, r *http.Request) {
	refs := s.serviceRefs(r)
	id, ok := pathUUID(r, "id")
	if !ok {
		s.writeError(w, r, ErrNotFound)
		return
	}
	c, err := s.deps.ACME.GetACMECertificate(r.Context(), id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	bindings, err := s.deps.ACME.ListACMEBindings(r.Context(), id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	notice, err := s.deps.ACME.ACMENoticeDelivery(r.Context(), id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	d := acmeCertificateJSON(c, s.deps.Clock.Now(), refs)
	list := make([]acmeBindingDTO, 0, len(bindings))
	for _, b := range bindings {
		list = append(list, acmeBindingJSON(b))
	}
	d.Bindings = &list
	d.LastNotice = acmeNoticeJSON(notice)
	writeJSON(w, http.StatusOK, d)
}

func (s *server) updateACMECertificate(w http.ResponseWriter, r *http.Request) {
	refs := s.serviceRefs(r)
	id, ok := pathUUID(r, "id")
	if !ok {
		s.writeError(w, r, ErrNotFound)
		return
	}
	var req acmeCertBody
	if !s.decodeExact(w, r, &req, maxACMECertBody, acmeCertKeys...) {
		return
	}
	var v validate.Errors
	provider, hook, target := req.check(false, &v)
	if req.ProviderID != nil && provider == nil && *req.ProviderID == "" {
		v.Add("provider_id", validate.Required, nil)
	}
	if err := v.Err(); err != nil {
		s.fail(w, r, err)
		return
	}
	c, err := s.deps.ACME.UpdateACMECertificate(r.Context(), s.actor(r), id, inventory.ACMECertificatePatch{ProviderID: provider, Names: req.Names,
		KeyType: req.KeyType, Challenge: req.Challenge, HookID: hook, HTTPTargetID: target, RenewBeforeDays: req.RenewBeforeDays,
		AutoRenew: req.AutoRenew, AutoDeploy: req.AutoDeploy})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, acmeCertificateJSON(c, s.deps.Clock.Now(), refs))
}

func (s *server) deleteACMECertificate(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(r, "id")
	if !ok {
		s.writeError(w, r, ErrNotFound)
		return
	}
	if err := s.deps.ACME.DeleteACMECertificate(r.Context(), s.actor(r), id); err != nil {
		s.fail(w, r, err)
		return
	}
	noContent(w)
}

// orderACME starts an order of the kind ("Renew now"/"Get the certificate", or a test run that stops at validated
// authorizations); 202 with the order, which the acme.issue job carries on.
func (s *server) orderACME(kind string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := pathUUID(r, "id")
		if !ok {
			s.writeError(w, r, ErrNotFound)
			return
		}
		o, err := s.deps.ACME.RequestOrder(r.Context(), s.actor(r), id, kind)
		if err != nil {
			s.fail(w, r, err)
			return
		}
		writeJSON(w, http.StatusAccepted, acmeOrderJSON(o))
	}
}

// listACMEOrders is the newest orders of a certificate (limit 1..100, default 20).
func (s *server) listACMEOrders(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(r, "id")
	if !ok {
		s.writeError(w, r, ErrNotFound)
		return
	}
	limit := 20
	if raw := r.URL.Query().Get("limit"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 || n > inventory.MaxACMEOrdersListed {
			s.fail(w, r, validate.Errors{{Field: "limit", Code: validate.OutOfRange,
				Params: map[string]string{"min": "1", "max": strconv.Itoa(inventory.MaxACMEOrdersListed)}}})
			return
		}
		limit = n
	}
	list, err := s.deps.ACME.ListACMEOrders(r.Context(), id, limit)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	items := make([]acmeOrderDTO, 0, len(list))
	for _, o := range list {
		items = append(items, acmeOrderJSON(o))
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

// rearmACME is "Check again and resume" (the web's Renew now): it switches automatic renewal on again, starts it afresh
// (no failures, no wait) and queues an order of the person at once for an issued certificate (owner decision
// 2026-10-20); 200 with the certificate, whose running_order_id names the order.
func (s *server) rearmACME(w http.ResponseWriter, r *http.Request) {
	refs := s.serviceRefs(r)
	id, ok := pathUUID(r, "id")
	if !ok {
		s.writeError(w, r, ErrNotFound)
		return
	}
	c, err := s.deps.ACME.ReArmACMEAutoRenew(r.Context(), s.actor(r), id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, acmeCertificateJSON(c, s.deps.Clock.Now(), refs))
}

// releaseACMEHold releases the current certificate from the licence hold of automatic deployment.
func (s *server) releaseACMEHold(w http.ResponseWriter, r *http.Request) {
	refs := s.serviceRefs(r)
	id, ok := pathUUID(r, "id")
	if !ok {
		s.writeError(w, r, ErrNotFound)
		return
	}
	if err := s.deps.ACME.ReleaseACMEDeployHold(r.Context(), s.actor(r), id); err != nil {
		s.fail(w, r, err)
		return
	}
	c, err := s.deps.ACME.GetACMECertificate(r.Context(), id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, acmeCertificateJSON(c, s.deps.Clock.Now(), refs))
}

func (s *server) listACMEBindings(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(r, "id")
	if !ok {
		s.writeError(w, r, ErrNotFound)
		return
	}
	list, err := s.deps.ACME.ListACMEBindings(r.Context(), id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	target := func(b inventory.ACMEBinding) uuid.UUID { return b.TargetID }
	seen, err := s.targetsSeen(r, targetIDsOf(list, target))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	list, hidden := keepSeen(list, target, seen) // R49 Phase 2: the bindings on the caller's servers
	items := make([]acmeBindingDTO, 0, len(list))
	for _, b := range list {
		items = append(items, acmeBindingJSON(b))
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "hidden_count": hidden})
}

// putACMEBinding binds a location to the certificate (or changes its auto_deploy). Switching unattended deployment ON
// — a new binding with auto_deploy true, or an existing one switched from off to on — is an Administrator's browser
// session with a fresh step-up, never an API token (Task 12 ruling I2). The decision is the inventory's, inside its
// transaction under the certificate's row lock, with the strength of this session (strictSession; ErrAutoDeployNeedsStepUp,
// ErrAdminRequired, the licence): a switch-off between this handler's read and the call cannot let a request without the
// step-up switch it on again (Task 13 fix round 1, as the Key Vault's UpdateBindingLocationsStrict). The handler's own
// read only answers the plain case early, audited like the guard (strictActionFor acme.manage). Binding with auto_deploy
// off, keeping it on and switching it off need only acme.operate.
func (s *server) putACMEBinding(w http.ResponseWriter, r *http.Request) {
	id, ok1 := pathUUID(r, "id")
	loc, ok2 := pathUUID(r, "location_id")
	if !ok1 || !ok2 {
		s.writeError(w, r, ErrNotFound)
		return
	}
	var req struct {
		AutoDeploy bool `json:"auto_deploy"`
	}
	if !s.decodeExactOptional(w, r, &req, maxACMEBindingBody, "auto_deploy") {
		return
	}
	if req.AutoDeploy {
		on, err := s.bindingAutoDeployOn(r, id, loc)
		if err != nil {
			s.fail(w, r, err)
			return
		}
		if !on && !s.strictActionFor(w, r, rbac.AcmeManage) {
			return
		}
	}
	strict := rbac.Decide(rbac.AcmeManage, principalFrom(r.Context()).Subject(s.deps.Clock.Now())) == rbac.Allow
	b, err := s.deps.ACME.AddACMEBindingStrict(r.Context(), s.actor(r), id, loc, req.AutoDeploy, strict)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, acmeBindingJSON(b))
}

// bindingAutoDeployOn reports whether the location is bound to the certificate with automatic deployment on already
// (ErrNotFound for an unknown certificate).
func (s *server) bindingAutoDeployOn(r *http.Request, id, loc uuid.UUID) (bool, error) {
	list, err := s.deps.ACME.ListACMEBindings(r.Context(), id)
	if err != nil {
		return false, err
	}
	return slices.ContainsFunc(list, func(b inventory.ACMEBinding) bool { return b.LocationID == loc && b.AutoDeploy }), nil
}

func (s *server) deleteACMEBinding(w http.ResponseWriter, r *http.Request) {
	id, ok1 := pathUUID(r, "id")
	loc, ok2 := pathUUID(r, "location_id")
	if !ok1 || !ok2 {
		s.writeError(w, r, ErrNotFound)
		return
	}
	if err := s.deps.ACME.RemoveACMEBinding(r.Context(), s.actor(r), id, loc); err != nil {
		s.fail(w, r, err)
		return
	}
	noContent(w)
}

// deployACME is "Deploy now" of the current certificate to bound locations (none named: every bound location; at most
// 20): Phase 4 deployments with trigger manual through RequestDeployment. confirm_incomplete_chain is an Administrator's
// acknowledgement (the inventory ignores it for anyone else, as for a Phase 4 deployment).
func (s *server) deployACME(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(r, "id")
	if !ok {
		s.writeError(w, r, ErrNotFound)
		return
	}
	var req struct {
		LocationIDs            []string `json:"location_ids"`
		ConfirmIncompleteChain bool     `json:"confirm_incomplete_chain"`
	}
	if !s.decodeExactOptional(w, r, &req, maxACMEDeployBody, "location_ids", "confirm_incomplete_chain") {
		return
	}
	var v validate.Errors
	var ids []uuid.UUID
	if len(req.LocationIDs) > 0 {
		ids = parseIDList(req.LocationIDs, "location_ids", inventory.MaxDeployLocations, &v)
	}
	if err := v.Err(); err != nil {
		s.fail(w, r, err)
		return
	}
	got, err := s.deps.ACME.DeployACMENow(r.Context(), s.actor(r), id, inventory.ACMEDeployInput{LocationIDs: ids,
		ConfirmIncompleteChain: req.ConfirmIncompleteChain})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	items := make([]requestedDeploymentDTO, 0, len(got))
	for _, d := range got {
		items = append(items, requestedDeploymentJSON(d))
	}
	writeJSON(w, http.StatusAccepted, map[string][]requestedDeploymentDTO{"deployments": items})
}
