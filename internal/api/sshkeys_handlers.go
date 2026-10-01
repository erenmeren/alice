package api

import (
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/google/uuid"

	"alice/internal/inventory"
	"alice/internal/license"
	"alice/internal/platform/validate"
	"alice/internal/providers"
	"alice/internal/rbac"
)

// sshKeyRoutes are the SSH key inventory (§9.6 "ssh-keys"). Removing a key changes a managed
// server (ClassChange, refused in lock); Operators may remove keys (§15.4); Alice's own key is
// refused by the inventory, the provider and a database trigger (SEC-081).
func (s *server) sshKeyRoutes() []route {
	return []route{
		{method: http.MethodGet, pattern: "/api/v1/ssh-keys", perm: rbac.Read, handler: s.listSSHKeys},
		{method: http.MethodGet, pattern: "/api/v1/ssh-keys/platform-key", perm: rbac.TargetsManage, handler: s.platformKey},
		{method: http.MethodGet, pattern: "/api/v1/ssh-keys/{id}", perm: rbac.Read, handler: s.getSSHKey},
		{method: http.MethodPost, pattern: "/api/v1/ssh-keys/locations/{id}/actions/remove", perm: rbac.InventoryOperate, lic: license.ClassChange, handler: s.removeKeyLocation},
	}
}

// knownFlags are the flag filter values (providers.Flag*).
var knownFlags = []string{providers.FlagWeak, providers.FlagCommand, providers.FlagRootWithoutFrom,
	providers.FlagDuplicate, providers.FlagCertAuthority, providers.FlagSecurityKey}

// Query parameter bounds of the key list.
const (
	maxQueryRunes  = 200
	maxCursorBytes = 512
	maxOSUserBytes = 32
)

// pageLimit reads ?limit= (1..200, default 50).
func pageLimit(raw string, v *validate.Errors) int {
	if raw == "" {
		return 50
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 1 || n > 200 {
		v.Add("limit", validate.OutOfRange, map[string]string{"min": "1", "max": "200"})
		return 0
	}
	return n
}

// optionalUUID reads an optional UUID query parameter.
func optionalUUID(raw, field string, v *validate.Errors) uuid.UUID {
	if raw == "" {
		return uuid.Nil
	}
	id, err := uuid.Parse(raw)
	if err != nil {
		v.Add(field, validate.Pattern, nil)
		return uuid.Nil
	}
	return id
}

func (s *server) listSSHKeys(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	var v validate.Errors
	f := inventory.KeyFilter{
		TargetID:       optionalUUID(q.Get("target_id"), "target_id", &v),
		OSUser:         q.Get("os_user"),
		Query:          q.Get("q"),
		Flag:           q.Get("flag"),
		IncludeMissing: parseBool(q.Get("missing"), "missing", &v),
		Cursor:         q.Get("cursor"),
		Limit:          pageLimit(q.Get("limit"), &v),
	}
	if len(f.OSUser) > maxOSUserBytes {
		v.Add("os_user", validate.TooLong, map[string]string{"max": strconv.Itoa(maxOSUserBytes)})
	}
	if utf8.RuneCountInString(f.Query) > maxQueryRunes {
		v.Add("q", validate.TooLong, map[string]string{"max": strconv.Itoa(maxQueryRunes)})
	}
	if f.Flag != "" && !slices.Contains(knownFlags, f.Flag) {
		v.Add("flag", validate.OneOf, map[string]string{"values": strings.Join(knownFlags, ", ")})
	}
	if len(f.Cursor) > maxCursorBytes {
		v.Add("cursor", validate.TooLong, map[string]string{"max": strconv.Itoa(maxCursorBytes)})
	}
	if err := v.Err(); err != nil {
		s.fail(w, r, err)
		return
	}
	page, err := s.deps.Inventory.ListSSHKeys(r.Context(), f)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	items := make([]sshKeyDTO, 0, len(page.Items))
	for _, k := range page.Items {
		items = append(items, sshKeyJSON(k, false))
	}
	var next any
	if page.NextCursor != "" {
		next = page.NextCursor
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "next_cursor": next})
}

func (s *server) getSSHKey(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(r, "id")
	if !ok {
		s.writeError(w, r, ErrNotFound)
		return
	}
	k, err := s.deps.Inventory.GetSSHKey(r.Context(), id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, sshKeyJSON(k, true))
}

// platformKey returns Alice's public key and the setup snippets (§12.2, §18.5 step 7). ?from= adds
// a from="…" restriction to the authorized_keys line (SEC-082); it must be an IP address.
func (s *server) platformKey(w http.ResponseWriter, r *http.Request) {
	from := r.URL.Query().Get("from")
	if from != "" {
		if _, err := netip.ParseAddr(from); err != nil {
			var v validate.Errors
			v.Add("from", validate.Pattern, nil)
			s.fail(w, r, v)
			return
		}
	}
	g, err := s.deps.Inventory.SetupGuide(r.Context(), from)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, platformKeyJSON(g))
}

func (s *server) removeKeyLocation(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(r, "id")
	if !ok {
		s.writeError(w, r, ErrNotFound)
		return
	}
	var req struct {
		ConfirmLastRootKey bool `json:"confirm_last_root_key"`
	}
	// The body is optional: an empty POST removes the key without the root confirmation.
	if !s.decodeOptional(w, r, &req) {
		return
	}
	jobID, err := s.deps.Inventory.RequestKeyRemoval(r.Context(), s.actor(r), id, req.ConfirmLastRootKey)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusAccepted, accepted(jobID))
}
