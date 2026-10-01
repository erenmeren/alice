package api

import (
	"net/http"
	"regexp"
	"strconv"

	"github.com/google/uuid"

	"alice/internal/inventory"
	"alice/internal/license"
	"alice/internal/platform/validate"
	"alice/internal/rbac"
)

// targetRoutes manage servers and their host keys (spec §9.6 "targets", R37 items 8 and 12). Every
// state-changing route under /targets is ClassChange: adding, changing and removing a server and
// confirming a fingerprint change the managed inventory, and a person's request to test or scan a
// server starts work on it; all of them are refused in lock (R9). The jobs they queue keep their
// own classes (test and discovery are ClassReadOnly jobs, §8.6).
func (s *server) targetRoutes() []route {
	return []route{
		{method: http.MethodGet, pattern: "/api/v1/targets", perm: rbac.Read, handler: s.listTargets},
		{method: http.MethodPost, pattern: "/api/v1/targets", perm: rbac.TargetsManage, lic: license.ClassChange, handler: s.createTarget},
		{method: http.MethodGet, pattern: "/api/v1/targets/{id}", perm: rbac.Read, handler: s.getTarget},
		{method: http.MethodPatch, pattern: "/api/v1/targets/{id}", perm: rbac.TargetsManage, lic: license.ClassChange, handler: s.updateTarget},
		{method: http.MethodDelete, pattern: "/api/v1/targets/{id}", perm: rbac.TargetsManage, lic: license.ClassChange, handler: s.deleteTarget},
		{method: http.MethodPost, pattern: "/api/v1/targets/{id}/actions/test", perm: rbac.InventoryOperate, lic: license.ClassChange, handler: s.testTarget},
		{method: http.MethodPost, pattern: "/api/v1/targets/{id}/actions/discover", perm: rbac.InventoryOperate, lic: license.ClassChange, handler: s.discoverTarget},
		{method: http.MethodGet, pattern: "/api/v1/targets/{id}/host-keys", perm: rbac.Read, handler: s.listHostKeys},
		{method: http.MethodPost, pattern: "/api/v1/targets/{id}/host-keys/{key_id}/actions/confirm", perm: rbac.HostKeysConfirm, lic: license.ClassChange, handler: s.confirmHostKey},
		{method: http.MethodPost, pattern: "/api/v1/targets/{id}/host-keys/{key_id}/actions/repin", perm: rbac.HostKeysRepin, lic: license.ClassChange, handler: s.repinHostKey},
		{method: http.MethodGet, pattern: "/api/v1/targets/{id}/ssh-keys", perm: rbac.Read, handler: s.listTargetKeys},
	}
}

// maxRepinBody caps the re-pin request (a fingerprint and a reason of at most 500 characters).
const maxRepinBody = 8 << 10

// actor is the caller as the inventory needs it: audit identity, user and role.
func (s *server) actor(r *http.Request) inventory.Actor {
	p := principalFrom(r.Context())
	return inventory.Actor{Audit: p.Actor(s.meta(r)), UserID: p.UserID, Role: p.Role}
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
	ts, err := s.deps.Inventory.ListTargets(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	items := make([]targetDTO, 0, len(ts))
	for _, t := range ts {
		items = append(items, targetJSON(t))
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "next_cursor": nil})
}

func (s *server) createTarget(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name     string `json:"name"`
		Type     string `json:"type"`
		Host     string `json:"host"`
		Port     int    `json:"port"`
		Username string `json:"username"`
	}
	if !s.decode(w, r, &req) {
		return
	}
	if req.Type == "" {
		req.Type = "linux"
	}
	t, jobID, err := s.deps.Inventory.CreateTarget(r.Context(), s.actor(r), inventory.NewTarget{
		Name: req.Name, Type: req.Type, Host: req.Host, Port: req.Port, Username: req.Username,
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	a := accepted(jobID)
	w.Header().Set("ETag", etag(t.Version))
	writeJSON(w, http.StatusCreated, map[string]any{"target": targetJSON(t), "job_id": a.JobID, "status_url": a.StatusURL})
}

func (s *server) getTarget(w http.ResponseWriter, r *http.Request) {
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
	writeJSON(w, http.StatusOK, targetJSON(t))
}

func (s *server) updateTarget(w http.ResponseWriter, r *http.Request) {
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
	}
	if !s.decode(w, r, &req) {
		return
	}
	t, err := s.deps.Inventory.UpdateTarget(r.Context(), s.actor(r), id, version,
		inventory.TargetPatch{Name: req.Name, DiscoveryIntervalHours: req.DiscoveryIntervalHours})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	w.Header().Set("ETag", etag(t.Version))
	writeJSON(w, http.StatusOK, targetJSON(t))
}

func (s *server) deleteTarget(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(r, "id")
	if !ok {
		s.writeError(w, r, ErrNotFound)
		return
	}
	if err := s.deps.Inventory.DeleteTarget(r.Context(), s.actor(r), id); err != nil {
		s.fail(w, r, err)
		return
	}
	noContent(w)
}

func (s *server) testTarget(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(r, "id")
	if !ok {
		s.writeError(w, r, ErrNotFound)
		return
	}
	jobID, err := s.deps.Inventory.RequestTest(r.Context(), s.actor(r), id)
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
