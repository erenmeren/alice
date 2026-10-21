package api

import (
	"errors"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/google/uuid"

	"alice/internal/authz/services"
	"alice/internal/inventory"
	"alice/internal/license"
	"alice/internal/platform/validate"
	"alice/internal/rbac"
)

// targetRoutes manage servers and their host keys (spec §9.6 "targets", R37 items 8 and 12). Adding,
// changing and removing a server and confirming a fingerprint are infrastructure changes
// (ClassChange); test and discovery are recurring read-only work (ClassReadOnly, §8.6). Both
// classes are refused in lock (R9).
func (s *server) targetRoutes() []route {
	return []route{
		{method: http.MethodGet, pattern: "/api/v1/targets", scope: scopeList, perm: rbac.Read, handler: s.listTargets},
		{method: http.MethodPost, pattern: "/api/v1/targets", scope: scopeCreate, perm: rbac.TargetsManage, lic: license.ClassChange, handler: s.createTarget},
		{method: http.MethodGet, pattern: "/api/v1/targets/{id}", scope: scopeResource, resolve: by(services.KindTarget, "id"), perm: rbac.Read, handler: s.getTarget},
		{method: http.MethodPatch, pattern: "/api/v1/targets/{id}", scope: scopeResource, resolve: by(services.KindTarget, "id"), perm: rbac.TargetsManage, lic: license.ClassChange, handler: s.updateTarget},
		{method: http.MethodDelete, pattern: "/api/v1/targets/{id}", scope: scopeResource, resolve: by(services.KindTarget, "id"), perm: rbac.TargetsManage, lic: license.ClassChange, handler: s.deleteTarget},
		{method: http.MethodPost, pattern: "/api/v1/targets/{id}/actions/test", scope: scopeResource, resolve: by(services.KindTarget, "id"), perm: rbac.InventoryOperate, lic: license.ClassReadOnly, handler: s.testTarget},
		{method: http.MethodPost, pattern: "/api/v1/targets/{id}/actions/discover", scope: scopeResource, resolve: by(services.KindTarget, "id"), perm: rbac.InventoryOperate, lic: license.ClassReadOnly, handler: s.discoverTarget},
		{method: http.MethodGet, pattern: "/api/v1/targets/{id}/host-keys", scope: scopeResource, resolve: by(services.KindTarget, "id"), perm: rbac.Read, handler: s.listHostKeys},
		{method: http.MethodPost, pattern: "/api/v1/targets/{id}/host-keys/{key_id}/actions/confirm", scope: scopeResource, resolve: by(services.KindTarget, "id"), perm: rbac.HostKeysConfirm, lic: license.ClassChange, handler: s.confirmHostKey},
		{method: http.MethodPost, pattern: "/api/v1/targets/{id}/host-keys/{key_id}/actions/repin", scope: scopeResource, resolve: by(services.KindTarget, "id"), perm: rbac.HostKeysRepin, lic: license.ClassChange, handler: s.repinHostKey},
		{method: http.MethodGet, pattern: "/api/v1/targets/{id}/ssh-keys", scope: scopeResource, resolve: by(services.KindTarget, "id"), perm: rbac.Read, handler: s.listTargetKeys},
		{method: http.MethodGet, pattern: "/api/v1/targets/{id}/certificate-locations", scope: scopeResource, resolve: by(services.KindTarget, "id"), perm: rbac.Read, handler: s.listTargetLocations},
	}
}

// maxRepinBody caps the re-pin request (a fingerprint and a reason of at most 500 characters).
const maxRepinBody = 8 << 10

// actor is the caller as the inventory needs it: audit identity, user and role.
func (s *server) actor(r *http.Request) inventory.Actor {
	p := principalFrom(r.Context())
	// Role is the caller's role on the path resource's service (R49 Phase 2, design §5.5: the inventory's conditional
	// permissions are judged there); Access is every grant, for the checks the inventory makes under its row locks.
	return inventory.Actor{Audit: p.Actor(s.meta(r)), UserID: p.UserID, Role: s.roleOn(r), Access: s.accessOf(r)}
}

// etag is the strong validator of a target version.
func etag(version int) string { return `"` + strconv.Itoa(version) + `"` }

var ifMatchRE = regexp.MustCompile(`^"([1-9][0-9]{0,9})"$`)

// ifMatch returns the target version named by a single strong If-Match validator. Weak validators,
// lists and "*" are refused: a change must name the exact version it was based on (§9.1).
func ifMatch(r *http.Request) (int, bool) {
	m := ifMatchRE.FindStringSubmatch(r.Header.Get("If-Match"))
	if m == nil {
		return 0, false
	}
	n, err := strconv.Atoi(m[1])
	return n, err == nil
}

// parseBool reads an optional boolean query parameter ("true" or "false").
func parseBool(raw, field string, v *validate.Errors) bool {
	switch raw {
	case "", "false":
		return false
	case "true":
		return true
	default:
		v.Add(field, validate.OneOf, map[string]string{"values": "true, false"})
		return false
	}
}

func (s *server) listTargets(w http.ResponseWriter, r *http.Request) {
	refs := s.serviceRefs(r)
	typ := r.URL.Query().Get("type")
	var v validate.Errors
	if typ != "" && !slices.Contains(vaultTypes, typ) {
		v.Add("type", validate.OneOf, map[string]string{"values": strings.Join(vaultTypes, ", ")})
	}
	filter := s.serviceFilter(r, &v) // R49: service_id and environment_id
	if err := v.Err(); err != nil {
		s.fail(w, r, v)
		return
	}
	reach := s.reachOf(r, rbac.Read) // R49 Phase 2: the servers and Key Vaults of the caller's services
	ts, err := s.deps.Inventory.ListTargets(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	items := make([]targetDTO, 0, len(ts))
	for _, t := range ts {
		if (typ == "" || t.Type == typ) && inServices(filter, t.ServiceID) && reach.Contains(t.ServiceID) {
			items = append(items, targetJSON(t, refs))
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "next_cursor": nil})
}

func (s *server) createTarget(w http.ResponseWriter, r *http.Request) {
	refs := s.serviceRefs(r)
	var req struct {
		Name     string `json:"name"`
		Type     string `json:"type"`
		Host     string `json:"host"`
		Port     int    `json:"port"`
		Username string `json:"username"`
		// ServiceID is the service the new resource goes to (R49; absent: the Default service). Changes never take it:
		// a resource moves only by POST /api/v1/services/{id}/actions/assign.
		ServiceID *uuid.UUID `json:"service_id"`
	}
	if !s.decode(w, r, &req) {
		return
	}
	if req.Type == "" {
		req.Type = "linux"
	}
	// R49 Phase 2, design §4.4: the service the new server goes to, checked against the caller's reach.
	service, ok := s.serviceForCreate(w, r, rbac.TargetsManage, req.ServiceID)
	if !ok {
		return
	}
	t, jobID, err := s.deps.Inventory.CreateTarget(r.Context(), s.actor(r), inventory.NewTarget{
		Name: req.Name, Type: req.Type, Host: req.Host, Port: req.Port, Username: req.Username, ServiceID: service,
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	a := accepted(jobID)
	w.Header().Set("ETag", etag(t.Version))
	writeJSON(w, http.StatusCreated, map[string]any{"target": targetJSON(t, refs), "job_id": a.JobID, "status_url": a.StatusURL})
}

func (s *server) getTarget(w http.ResponseWriter, r *http.Request) {
	refs := s.serviceRefs(r)
	id, ok := pathUUID(r, "id")
	if !ok {
		s.writeError(w, r, ErrNotFound)
		return
	}
	t, err := s.deps.Inventory.GetTarget(r.Context(), id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	w.Header().Set("ETag", etag(t.Version))
	writeJSON(w, http.StatusOK, targetJSON(t, refs))
}

func (s *server) updateTarget(w http.ResponseWriter, r *http.Request) {
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
	var req struct {
		Name                   *string `json:"name"`
		DiscoveryIntervalHours *int    `json:"discovery_interval_hours"`
		PollIntervalMinutes    *int    `json:"poll_interval_minutes"` // vaults only (5..1440)
	}
	if !s.decode(w, r, &req) {
		return
	}
	t, err := s.deps.Inventory.UpdateTarget(r.Context(), s.actor(r), id, version,
		inventory.TargetPatch{Name: req.Name, DiscoveryIntervalHours: req.DiscoveryIntervalHours, PollIntervalMinutes: req.PollIntervalMinutes})
	if err != nil {
		s.failTarget(w, r, id, err)
		return
	}
	w.Header().Set("ETag", etag(t.Version))
	writeJSON(w, http.StatusOK, targetJSON(t, refs))
}

func (s *server) deleteTarget(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(r, "id")
	if !ok {
		s.writeError(w, r, ErrNotFound)
		return
	}
	var v validate.Errors
	remove := parseBool(r.URL.Query().Get("remove_bindings"), "remove_bindings", &v)
	if err := v.Err(); err != nil {
		s.fail(w, r, err)
		return
	}
	// A vault is deleted with DeleteVault (the Phase 3 DeleteTarget answers ErrNotAServer for it). Removing its
	// connected websites with it is an Administrator's act with a fresh step-up and no token (ruling S6).
	if remove {
		if !s.strictAction(w, r) {
			return
		}
		err := s.deps.Inventory.DeleteVault(r.Context(), s.actor(r), id, true)
		if !errors.Is(err, inventory.ErrNotAVault) {
			s.finishDelete(w, r, err)
			return
		}
	}
	err := s.deps.Inventory.DeleteTarget(r.Context(), s.actor(r), id)
	if errors.Is(err, inventory.ErrNotAServer) {
		err = s.deps.Inventory.DeleteVault(r.Context(), s.actor(r), id, false)
	}
	s.finishDelete(w, r, err)
}

func (s *server) finishDelete(w http.ResponseWriter, r *http.Request, err error) {
	if err != nil {
		s.fail(w, r, err)
		return
	}
	noContent(w)
}

// failTarget is fail with the vault's own wording of a duplicate name: the target is read to see whether it
// is a vault (a failed read leaves the answer for servers).
func (s *server) failTarget(w http.ResponseWriter, r *http.Request, id uuid.UUID, err error) {
	if errors.Is(err, inventory.ErrDuplicateTarget) {
		if t, gerr := s.deps.Inventory.GetTarget(r.Context(), id); gerr == nil && t.Type == inventory.TypeAzureKeyVault {
			s.writeError(w, r, ErrKVVaultDuplicate)
			return
		}
	}
	s.fail(w, r, err)
}

func (s *server) testTarget(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(r, "id")
	if !ok {
		s.writeError(w, r, ErrNotFound)
		return
	}
	// A vault's access check may also read one certificate's secret, to prove the role that deploys it.
	var req accessCheckRequest
	if !s.decodeExactOptional(w, r, &req, maxActionBody, "read_secret_of") {
		return
	}
	var jobID uuid.UUID
	var err error
	if req.ReadSecretOf != "" {
		certID, perr := uuid.Parse(req.ReadSecretOf)
		if perr != nil || certID == uuid.Nil {
			var v validate.Errors
			v.Add("read_secret_of", validate.Pattern, nil)
			s.fail(w, r, v)
			return
		}
		jobID, err = s.deps.Inventory.RequestAccessCheck(r.Context(), s.actor(r), id, certID)
	} else {
		jobID, err = s.deps.Inventory.RequestTest(r.Context(), s.actor(r), id)
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusAccepted, accepted(jobID))
}

func (s *server) discoverTarget(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(r, "id")
	if !ok {
		s.writeError(w, r, ErrNotFound)
		return
	}
	jobID, err := s.deps.Inventory.RequestDiscovery(r.Context(), s.actor(r), id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusAccepted, accepted(jobID))
}

func (s *server) listHostKeys(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(r, "id")
	if !ok {
		s.writeError(w, r, ErrNotFound)
		return
	}
	keys, err := s.deps.Inventory.ListHostKeys(r.Context(), id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	items := make([]hostKeyDTO, 0, len(keys))
	for _, k := range keys {
		items = append(items, hostKeyJSON(k))
	}
	writeJSON(w, http.StatusOK, map[string][]hostKeyDTO{"items": items})
}

// hostKeyIDs parses both path identifiers of a host-key action; on failure it has answered 404.
func (s *server) hostKeyIDs(w http.ResponseWriter, r *http.Request) (target, key uuid.UUID, ok bool) {
	t, ok1 := pathUUID(r, "id")
	k, ok2 := pathUUID(r, "key_id")
	if !ok1 || !ok2 {
		s.writeError(w, r, ErrNotFound)
		return uuid.Nil, uuid.Nil, false
	}
	return t, k, true
}

func (s *server) confirmHostKey(w http.ResponseWriter, r *http.Request) {
	targetID, keyID, ok := s.hostKeyIDs(w, r)
	if !ok {
		return
	}
	var req struct {
		Fingerprint string `json:"fingerprint"`
	}
	if !s.decode(w, r, &req) {
		return
	}
	if req.Fingerprint == "" {
		var v validate.Errors
		v.Add("fingerprint", validate.Required, nil)
		s.fail(w, r, v)
		return
	}
	jobID, err := s.deps.Inventory.ConfirmHostKey(r.Context(), s.actor(r), targetID, keyID, req.Fingerprint)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusAccepted, accepted(jobID))
}

func (s *server) repinHostKey(w http.ResponseWriter, r *http.Request) {
	targetID, keyID, ok := s.hostKeyIDs(w, r)
	if !ok {
		return
	}
	var req struct {
		Fingerprint string `json:"fingerprint"`
		Reason      string `json:"reason"`
	}
	if !s.decodeLimit(w, r, &req, maxRepinBody) {
		return
	}
	if req.Fingerprint == "" {
		var v validate.Errors
		v.Add("fingerprint", validate.Required, nil)
		s.fail(w, r, v)
		return
	}
	// The reason rules (10–500 characters, no PEM block, S-05) are enforced by the inventory.
	jobID, err := s.deps.Inventory.RepinHostKey(r.Context(), s.actor(r), targetID, keyID, req.Fingerprint, req.Reason)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusAccepted, accepted(jobID))
}

func (s *server) listTargetKeys(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(r, "id")
	if !ok {
		s.writeError(w, r, ErrNotFound)
		return
	}
	var v validate.Errors
	missing := parseBool(r.URL.Query().Get("missing"), "missing", &v)
	if err := v.Err(); err != nil {
		s.fail(w, r, err)
		return
	}
	locs, err := s.deps.Inventory.ListTargetKeys(r.Context(), id, missing)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	items := make([]keyLocationDTO, 0, len(locs))
	for _, l := range locs {
		items = append(items, keyLocationJSON(l))
	}
	writeJSON(w, http.StatusOK, map[string][]keyLocationDTO{"items": items})
}
