package api

import (
	"errors"
	"net/http"
	"slices"
	"strconv"

	"github.com/google/uuid"

	"alice/internal/authz/services"
	"alice/internal/inventory"
	"alice/internal/license"
	"alice/internal/platform/validate"
	"alice/internal/rbac"
)

// bindingRoutes connect a vault certificate to websites (R40 rows 22-24). Creating, changing and deploying are
// certificates.operate (Operators too: the same as a Phase 4 deployment); switching automatic deployment is
// credentials.manage (Administrator with step-up, no token: ruling S6). Switching it off and removing a binding
// are safety actions that work in lock (ClassAlways: amends R40 row 22); switching it on is refused in lock by
// the inventory itself, as is every change it makes.
func (s *server) bindingRoutes() []route {
	return []route{
		{method: http.MethodGet, pattern: "/api/v1/certificate-locations", scope: scopeList, perm: rbac.Read, handler: s.listDeployableLocations},
		{method: http.MethodPost, pattern: "/api/v1/bindings", scope: scopeCross, perm: rbac.CertificatesOperate, lic: license.ClassChange, handler: s.createBinding},
		{method: http.MethodGet, pattern: "/api/v1/bindings/{id}", scope: scopeResource, resolve: &resolver{kind: services.KindKVBinding, param: "id", anyVisible: true}, perm: rbac.Read, handler: s.getBinding},
		// Design §5.6 "either side": a person of a website's service may release its own websites (R64 ruling 9), so the
		// guard lets in certificates.operate on any service the binding is visible from; bindingChange then refuses an
		// addition and the release of a website the caller holds no right on unless the caller is the vault's side.
		{method: http.MethodPatch, pattern: "/api/v1/bindings/{id}", scope: scopeCross, resolve: &resolver{kind: services.KindKVBinding, param: "id", anyVisible: true}, perm: rbac.CertificatesOperate, lic: license.ClassChange, handler: s.updateBinding},
		{method: http.MethodPut, pattern: "/api/v1/bindings/{id}/auto-deploy", scope: scopeResource, resolve: by(services.KindKVBinding, "id"), perm: rbac.CredentialsManage, lic: license.ClassAlways, handler: s.setAutoDeploy},
		{method: http.MethodDelete, pattern: "/api/v1/bindings/{id}", scope: scopeResource, resolve: by(services.KindKVBinding, "id"), perm: rbac.CertificatesOperate, lic: license.ClassAlways, handler: s.deleteBinding},
		{method: http.MethodPost, pattern: "/api/v1/bindings/{id}/actions/deploy", scope: scopeResource, resolve: by(services.KindKVBinding, "id"), perm: rbac.CertificatesOperate, lic: license.ClassChange, handler: s.deployBinding},
	}
}

// parseIDList reads a list of UUIDs of 1..max entries without duplicates.
func parseIDList(raw []string, field string, max int, v *validate.Errors) []uuid.UUID {
	ids := make([]uuid.UUID, 0, len(raw))
	if n := len(raw); n < 1 || n > max {
		v.Add(field, validate.OutOfRange, map[string]string{"min": "1", "max": strconv.Itoa(max)})
		return nil
	}
	for _, s := range raw {
		id, err := uuid.Parse(s)
		if err != nil || id == uuid.Nil {
			v.Add(field, validate.Pattern, nil)
			return nil
		}
		if slices.Contains(ids, id) {
			v.Add(field, validate.Duplicate, nil)
			return nil
		}
		ids = append(ids, id)
	}
	return ids
}

// bindingAnswer writes a binding with its strong validator. Its websites on servers outside the caller's services are
// left out and counted (R49 Phase 2, design §5.8: hidden_count).
func (s *server) bindingAnswer(w http.ResponseWriter, r *http.Request, status int, b inventory.Binding) {
	target := func(l inventory.BindingLocation) uuid.UUID { return l.TargetID }
	seen, err := s.targetsSeen(r, targetIDsOf(b.Locations, target))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var hidden int
	b.Locations, hidden = keepSeen(b.Locations, target, seen)
	d := bindingJSON(b)
	d.HiddenCount = hidden
	w.Header().Set("ETag", etag(b.Version))
	writeJSON(w, status, d)
}

func (s *server) listDeployableLocations(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	var v validate.Errors
	f := inventory.LocationFilter{Query: q.Get("q"), KeyType: q.Get("key_type"), Unbound: parseBool(q.Get("unbound"), "unbound", &v),
		Cursor: q.Get("cursor"), Limit: pageLimit(q.Get("limit"), &v), Reach: s.reachOf(r, rbac.Read)}
	// R65: service_id (repeatable) keeps the websites of these services (the canary editor's first picker).
	for i, raw := range q["service_id"] {
		id, err := uuid.Parse(raw)
		if err != nil || id == uuid.Nil || i >= maxServiceFilter {
			v.Add("service_id", validate.Pattern, nil)
			break
		}
		f.ServiceIDs = append(f.ServiceIDs, id)
	}
	if f.KeyType != "" && f.KeyType != "rsa" && f.KeyType != "ecdsa" {
		v.Add("key_type", validate.OneOf, map[string]string{"values": "rsa, ecdsa"})
	}
	if len(f.Cursor) > maxCursorBytes {
		v.Add("cursor", validate.TooLong, map[string]string{"max": strconv.Itoa(maxCursorBytes)})
	}
	if err := v.Err(); err != nil {
		s.fail(w, r, err)
		return
	}
	page, err := s.deps.Inventory.ListDeployableLocations(r.Context(), f)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	items := make([]deployableLocationDTO, 0, len(page.Items))
	for _, l := range page.Items {
		items = append(items, deployableLocationJSON(l))
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "next_cursor": nextCursor(page.NextCursor)})
}

func (s *server) createBinding(w http.ResponseWriter, r *http.Request) {
	var req struct {
		KVCertificateID string   `json:"kv_certificate_id"`
		LocationIDs     []string `json:"location_ids"`
	}
	if !s.decodeExact(w, r, &req, maxBindingBody, "kv_certificate_id", "location_ids") {
		return
	}
	var v validate.Errors
	cert, err := uuid.Parse(req.KVCertificateID)
	if err != nil || cert == uuid.Nil {
		v.Add("kv_certificate_id", validate.Pattern, nil)
	}
	ids := parseIDList(req.LocationIDs, "location_ids", inventory.MaxBindingLocations, &v)
	if err := v.Err(); err != nil {
		s.fail(w, r, err)
		return
	}
	// R49 Phase 2, design §5.6: certificates.operate on the vault's service (the source) and on every website's.
	if !s.checkBindingSource(w, r, cert) || !s.checkDestinationsOf(w, r, rbac.CertificatesOperate, services.KindLocation, ids) {
		return
	}
	b, err := s.deps.Inventory.CreateBinding(r.Context(), s.actor(r), inventory.BindingInput{KVCertificateID: cert, LocationIDs: ids})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	w.Header().Set("Location", "/api/v1/bindings/"+b.ID.String())
	s.bindingAnswer(w, r, http.StatusCreated, b)
}

func (s *server) getBinding(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(r, "id")
	if !ok {
		s.writeError(w, r, ErrNotFound)
		return
	}
	b, err := s.deps.Inventory.Binding(r.Context(), id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.bindingAnswer(w, r, http.StatusOK, b)
}

// updateBinding replaces the websites of a binding. Adding websites to a binding that deploys automatically
// puts them under automatic deployment, which is an Administrator's act with a fresh step-up and no token
// (ruling S6); the binding is read to see whether that is what the request does. Releasing websites, or any
// change to a binding that does not deploy automatically, is an ordinary change. An Operator's attempt to add
// is left to the inventory, which refuses it and audits the refusal.
func (s *server) updateBinding(w http.ResponseWriter, r *http.Request) {
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
	var req struct {
		LocationIDs []string `json:"location_ids"`
	}
	if !s.decodeExact(w, r, &req, maxBindingBody, "location_ids") {
		return
	}
	var v validate.Errors
	ids := parseIDList(req.LocationIDs, "location_ids", inventory.MaxBindingLocations, &v)
	if err := v.Err(); err != nil {
		s.fail(w, r, err)
		return
	}
	cur, err := s.deps.Inventory.Binding(r.Context(), id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if cur.Version != version {
		s.writeError(w, r, ErrPreconditionFailed) // changed since the caller read it: nothing else is judged
		return
	}
	if ids, ok = s.bindingChange(w, r, cur, ids); !ok {
		return
	}
	if s.roleOn(r) == rbac.Admin && cur.AutoDeploy && addsLocations(cur, ids) && !s.strictAction(w, r) {
		return
	}
	b, err := s.deps.Inventory.UpdateBindingLocationsStrict(r.Context(), s.actor(r), id, version, ids, s.strictSession(r))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.bindingAnswer(w, r, http.StatusOK, b)
}

// checkBindingSource is design §5.6 (a) for a new Key Vault binding: certificates.operate on the vault's service. A
// vault certificate the caller cannot see is answered as an unknown one (404); one it sees but may not bind, 403.
func (s *server) checkBindingSource(w http.ResponseWriter, r *http.Request, kvCert uuid.UUID) bool {
	reach := s.reachOf(r, rbac.CertificatesOperate)
	if reach.All() || s.deps.Services == nil {
		return true
	}
	res, err := s.deps.Services.Resolve(r.Context(), services.KindKVCertificate, kvCert)
	switch {
	case errors.Is(err, services.ErrResourceNotFound):
		return true // the inventory answers the unknown certificate
	case err != nil:
		s.fail(w, r, err)
		return false
	case !s.reachOf(r, rbac.Read).ContainsAny(res.Visible):
		s.writeError(w, r, ErrNotFound)
		return false
	case !reach.Contains(res.Owning):
		s.writeError(w, r, ErrForbidden)
		return false
	}
	return true
}

// bindingChange is design §5.6 for a change of a Key Vault binding's websites. With certificates.operate on the
// vault's service the caller may add websites (each needs the permission on its own service) and release any. Without
// it, the caller holds the permission on the service of one of the websites only (the guard checked): it may release
// its own websites and nothing else. The websites the caller does not see are kept as they are, whatever the list
// names (the caller cannot name them), so the list it answers is the one the inventory stores. It writes the refusal
// and returns false.
func (s *server) bindingChange(w http.ResponseWriter, r *http.Request, cur inventory.Binding, ids []uuid.UUID) ([]uuid.UUID, bool) {
	reach := s.reachOf(r, rbac.CertificatesOperate)
	if reach.All() {
		return ids, true
	}
	target := func(l inventory.BindingLocation) uuid.UUID { return l.TargetID }
	seen, err := s.targetsSeen(r, targetIDsOf(cur.Locations, target))
	if err != nil {
		s.fail(w, r, err)
		return nil, false
	}
	out := slices.Clone(ids)
	for _, l := range cur.Locations {
		if !seen(l.TargetID) && !slices.Contains(out, l.LocationID) {
			out = append(out, l.LocationID) // a website of another service stays
		}
	}
	res, _ := pathResource(r.Context())
	vaultSide := res.Owning != uuid.Nil && reach.Contains(res.Owning)
	var added []uuid.UUID
	for _, id := range out {
		if !slices.ContainsFunc(cur.Locations, func(l inventory.BindingLocation) bool { return l.LocationID == id }) {
			added = append(added, id)
		}
	}
	if len(added) > 0 {
		if !vaultSide {
			s.writeError(w, r, ErrForbidden)
			return nil, false
		}
		if !s.checkDestinationsOf(w, r, rbac.CertificatesOperate, services.KindLocation, added) {
			return nil, false
		}
	}
	if !vaultSide {
		owners, err := s.deps.Services.TargetServices(r.Context(), targetIDsOf(cur.Locations, target))
		if err != nil {
			s.fail(w, r, err)
			return nil, false
		}
		for _, l := range cur.Locations {
			if !slices.Contains(out, l.LocationID) && !reach.Contains(owners[l.TargetID]) {
				s.writeError(w, r, ErrForbidden) // releasing a website the caller sees but holds no right on
				return nil, false
			}
		}
	}
	return out, true
}

// addsLocations reports whether ids names a website the binding does not have.
func addsLocations(b inventory.Binding, ids []uuid.UUID) bool {
	for _, id := range ids {
		if !slices.ContainsFunc(b.Locations, func(l inventory.BindingLocation) bool { return l.LocationID == id }) {
			return true
		}
	}
	return false
}

func (s *server) setAutoDeploy(w http.ResponseWriter, r *http.Request) {
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
	var req struct {
		Enabled *bool `json:"enabled"`
	}
	if !s.decodeExact(w, r, &req, maxActionBody, "enabled") {
		return
	}
	if req.Enabled == nil {
		var v validate.Errors
		v.Add("enabled", validate.Required, nil)
		s.fail(w, r, v)
		return
	}
	if *req.Enabled && !s.reachOf(r, rbac.CertificatesOperate).All() {
		// R49 Phase 2, design §11: switching automatic deployment on also needs certificates.operate on the service of
		// every website it will deploy to.
		cur, err := s.deps.Inventory.Binding(r.Context(), id)
		if err != nil {
			s.fail(w, r, err)
			return
		}
		locs := make([]uuid.UUID, 0, len(cur.Locations))
		for _, l := range cur.Locations {
			locs = append(locs, l.LocationID)
		}
		if !s.checkDestinationsOf(w, r, rbac.CertificatesOperate, services.KindLocation, locs) {
			return
		}
	}
	b, err := s.deps.Inventory.SetAutoDeploy(r.Context(), s.actor(r), id, version, *req.Enabled)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.bindingAnswer(w, r, http.StatusOK, b)
}

func (s *server) deleteBinding(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(r, "id")
	if !ok {
		s.writeError(w, r, ErrNotFound)
		return
	}
	if err := s.deps.Inventory.DeleteBinding(r.Context(), s.actor(r), id); err != nil {
		s.fail(w, r, err)
		return
	}
	noContent(w)
}

// deployBinding is "Deploy now": one Phase 4 deployment per website for one stored version. A held version
// (found while the license was expired, or with an incomplete chain) is deployed by an Administrator with a
// fresh step-up and no token (ruling S6, enforced here at request time: the inventory only re-checks the role).
// confirm_incomplete_chain (F-17) counts for an Administrator only.
func (s *server) deployBinding(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(r, "id")
	if !ok {
		s.writeError(w, r, ErrNotFound)
		return
	}
	var req struct {
		VersionID              string   `json:"version_id"`
		LocationIDs            []string `json:"location_ids"`
		ConfirmIncompleteChain bool     `json:"confirm_incomplete_chain"`
		CanaryOverride         bool     `json:"canary_override"`
	}
	if !s.decodeExact(w, r, &req, maxKVDeployBody, "version_id", "location_ids", "confirm_incomplete_chain", "canary_override") {
		return
	}
	var v validate.Errors
	version, err := uuid.Parse(req.VersionID)
	if err != nil || version == uuid.Nil {
		v.Add("version_id", validate.Required, nil)
	}
	var ids []uuid.UUID
	if len(req.LocationIDs) > 0 {
		ids = parseIDList(req.LocationIDs, "location_ids", inventory.MaxBindingLocations, &v)
	}
	if err := v.Err(); err != nil {
		s.fail(w, r, err)
		return
	}
	admin := s.roleOn(r) == rbac.Admin // the role on the vault's service (R49 Phase 2, design §5.5)
	// The version must be one of this connection's certificate's versions, for every role: another certificate's
	// version id is as unknown as a random one (404), and a held one needs the strict session.
	held, err := s.versionHeld(r, id, version)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if admin && held && !s.strictAction(w, r) {
		return
	}
	if !s.canaryOverrideAllowed(w, r, req.CanaryOverride) {
		return
	}
	got, rollout, err := s.deps.Inventory.RequestKVDeploymentWithRollout(r.Context(), s.actor(r), inventory.KVDeployInput{
		BindingID: id, VersionID: version, LocationIDs: ids, ConfirmIncompleteChain: req.ConfirmIncompleteChain && admin,
		StrictSession: s.strictSession(r), CanaryOverride: req.CanaryOverride,
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusAccepted, deployAnswer(got, rollout))
}

// versionHeld reads the binding's certificate and says whether the named version is held; ErrNotFound when
// the certificate has no such version.
func (s *server) versionHeld(r *http.Request, bindingID, version uuid.UUID) (bool, error) {
	b, err := s.deps.Inventory.Binding(r.Context(), bindingID)
	if err != nil {
		return false, err
	}
	d, err := s.deps.Inventory.KVCertificate(r.Context(), b.VaultID, b.KVCertificateID)
	if err != nil {
		return false, err
	}
	for _, v := range d.Versions {
		if v.ID == version {
			return v.Held, nil
		}
	}
	return false, inventory.ErrNotFound
}

// maxServiceFilter bounds the service_id values of a website list.
const maxServiceFilter = 50
