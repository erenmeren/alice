package api

import (
	"errors"
	"net/http"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/google/uuid"

	"alice/internal/authz/services"
	"alice/internal/inventory"
	"alice/internal/license"
	"alice/internal/platform/validate"
	"alice/internal/providers"
	"alice/internal/rbac"
	"alice/internal/secrets"
	"alice/internal/sshkeys"
	"alice/internal/sshkeys/keymat"
)

// sshKeyRoutes are the SSH key inventory (§9.6 "ssh-keys"). Removing a key changes a managed
// server (ClassChange, refused in lock); Operators may remove keys (§15.4); Alice's own key is
// refused by the inventory, the provider and a database trigger (SEC-081).
func (s *server) sshKeyRoutes() []route {
	return []route{
		{method: http.MethodGet, pattern: "/api/v1/ssh-keys", scope: scopeList, perm: rbac.Read, handler: s.listSSHKeys},
		{method: http.MethodGet, pattern: "/api/v1/ssh-keys/platform-key", scope: scopeAny, perm: rbac.TargetsManage, handler: s.platformKey},
		{method: http.MethodGet, pattern: "/api/v1/ssh-keys/{id}", scope: scopeResource, resolve: by(services.KindSSHKey, "id"), perm: rbac.Read, handler: s.getSSHKey},
		// Phase 7 (C13): the list as a CSV file, with the list's filters; a read, so it works in lock.
		{method: http.MethodGet, pattern: "/api/v1/ssh-keys/export", scope: scopeList, perm: rbac.Read, limit: limitExport, getOnly: true,
			handler: s.exportSSHKeys},
		{method: http.MethodPost, pattern: "/api/v1/ssh-keys/locations/{id}/actions/remove", scope: scopeResource, resolve: by(services.KindSSHKeyLocation, "id"), perm: rbac.InventoryOperate, lic: license.ClassChange, handler: s.removeKeyLocation},
		// Phase 6 (C13): generation and deploy are Operators' too (R41 row 7); the private key leaves Alice only through
		// the download, an Administrator's browser session with step-up, 5 per minute, allowed in lock (row 5).
		{method: http.MethodPost, pattern: "/api/v1/ssh-keys/generate", scope: scopeCreate, perm: rbac.InventoryOperate, lic: license.ClassChange, handler: s.generateSSHKey},
		{method: http.MethodPost, pattern: "/api/v1/ssh-keys/{id}/actions/deploy", scope: scopeCross, resolve: by(services.KindSSHKey, "id"), perm: rbac.InventoryOperate, lic: license.ClassChange, handler: s.deploySSHKey},
		{method: http.MethodPost, pattern: "/api/v1/ssh-keys/{id}/actions/download-private-key", scope: scopeResource, resolve: by(services.KindSSHKey, "id"), perm: rbac.SSHKeysDownload, lic: license.ClassAlways,
			limit: limitDownload, handler: s.downloadPrivateKey},
		{method: http.MethodGet, pattern: "/api/v1/targets/{id}/key-files", scope: scopeResource, resolve: by(services.KindTarget, "id"), perm: rbac.Read, handler: s.keyFiles},
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
	refs := s.serviceRefs(r)
	f, ok := s.sshKeyFilter(w, r, true)
	if !ok {
		return
	}
	page, err := s.deps.Inventory.ListSSHKeys(r.Context(), f)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	items := make([]sshKeyDTO, 0, len(page.Items))
	for _, k := range page.Items {
		items = append(items, sshKeyJSON(k, false, refs))
	}
	var next any
	if page.NextCursor != "" {
		next = page.NextCursor
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "next_cursor": next})
}

// sshKeyFilter reads the SSH key list's filters: the list (paged) and its export, which is never a page and refuses
// cursor and limit. It answers 422 itself.
func (s *server) sshKeyFilter(w http.ResponseWriter, r *http.Request, paged bool) (inventory.KeyFilter, bool) {
	q := r.URL.Query()
	var v validate.Errors
	f := inventory.KeyFilter{
		TargetID:       optionalUUID(q.Get("target_id"), "target_id", &v),
		OSUser:         q.Get("os_user"),
		Query:          q.Get("q"),
		Flag:           q.Get("flag"),
		IncludeMissing: parseBool(q.Get("missing"), "missing", &v),
	}
	f.ServiceIDs = s.serviceFilter(r, &v) // R49: service_id and environment_id
	f.Reach = s.reachOf(r, rbac.Read)     // R49 Phase 2: the keys the caller sees
	if paged {
		f.Cursor, f.Limit = q.Get("cursor"), pageLimit(q.Get("limit"), &v)
	} else {
		refusePaging(q, &v)
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
		return inventory.KeyFilter{}, false
	}
	return f, true
}

func (s *server) getSSHKey(w http.ResponseWriter, r *http.Request) {
	refs := s.serviceRefs(r)
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
	target := func(l inventory.KeyLocation) uuid.UUID { return l.TargetID }
	seen, err := s.targetsSeen(r, targetIDsOf(k.Locations, target))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var hidden int
	k.Locations, hidden = keepSeen(k.Locations, target, seen) // R49 Phase 2: the locations on the caller's servers
	d := sshKeyDetailDTO{sshKeyDTO: sshKeyJSON(k, true, refs), HiddenCount: hidden}
	if k.Managed && s.deps.SSHKeys != nil {
		m, err := s.deps.SSHKeys.ManagedKey(r.Context(), id)
		switch {
		case errors.Is(err, sshkeys.ErrNotManaged):
			// A key the inventory calls managed whose private key Alice does not hold: listed only.
		case err != nil:
			s.fail(w, r, err)
			return
		default:
			d.ManagedKey = managedKeyJSON(m)
		}
	}
	writeJSON(w, http.StatusOK, d)
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

// Body limits of the Phase 6 key routes: a generation and a deploy carry a few short strings; the download a reason
// (at most 500 runes) and a passphrase (at most 1024 bytes, JSON-escaped up to six bytes each).
const (
	maxKeyActionBody = 16 << 10
	maxDownloadBody  = 16 << 10
)

// keyTypeValues is the OneOf text of key_type.
func keyTypeValues() string {
	var out []string
	for _, kt := range keymat.KeyTypes() {
		out = append(out, string(kt))
	}
	return strings.Join(out, ", ")
}

// generateSSHKey creates a key whose private key Alice keeps sealed (spec §13.5, R41 rows 3, 7). The answer is the key
// as GET /ssh-keys/{id} shows it, with managed_key; it never carries the private key (S-08).
func (s *server) generateSSHKey(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Label   string `json:"label"`
		KeyType string `json:"key_type"`
		// ServiceID is the service the new resource goes to (R49; absent: the Default service). Changes never take it:
		// a resource moves only by POST /api/v1/services/{id}/actions/assign.
		ServiceID *uuid.UUID `json:"service_id"`
	}
	if !s.decodeExact(w, r, &req, maxKeyActionBody, "label", "key_type", "service_id") {
		return
	}
	// key_type is required (C13 "exact keys"; the web always sends it): an absent one is not a silent Ed25519.
	var v validate.Errors
	switch {
	case req.KeyType == "":
		v.Add("key_type", validate.Required, nil)
	case !slices.Contains(keymat.KeyTypes(), keymat.KeyType(req.KeyType)):
		v.Add("key_type", validate.OneOf, map[string]string{"values": keyTypeValues()})
	}
	if err := v.Err(); err != nil {
		s.fail(w, r, err)
		return
	}
	m, err := s.deps.SSHKeys.Generate(r.Context(), s.actor(r), sshkeys.GenerateInput{Label: req.Label, KeyType: req.KeyType,
		ServiceID: derefOr(req.ServiceID, uuid.Nil)})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, generatedKeyJSON(m, s.serviceRefs(r)))
}

// deploySSHKey queues the deploy of a generated key to one user's key file on a server (spec §13.4). The service
// decides everything again in its transaction and once more when the job runs (S7: never the connection account or
// one of its files; options only from= and restrict).
func (s *server) deploySSHKey(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(r, "id")
	if !ok {
		s.writeError(w, r, ErrNotFound)
		return
	}
	var req struct {
		TargetID string `json:"target_id"`
		OSUser   string `json:"os_user"`
		FilePath string `json:"file_path"`
		From     string `json:"from"`
		Restrict bool   `json:"restrict"`
	}
	if !s.decodeExact(w, r, &req, maxKeyActionBody, "target_id", "os_user", "file_path", "from", "restrict") {
		return
	}
	var v validate.Errors
	target := requiredUUID(req.TargetID, "target_id", &v)
	if req.OSUser == "" {
		v.Add("os_user", validate.Required, nil)
	}
	if req.FilePath == "" {
		v.Add("file_path", validate.Required, nil)
	}
	if err := v.Err(); err != nil {
		s.fail(w, r, err)
		return
	}
	jobID, err := s.deps.SSHKeys.RequestDeploy(r.Context(), s.actor(r), sshkeys.DeployInput{KeyID: id, TargetID: target,
		OSUser: req.OSUser, FilePath: req.FilePath, From: req.From, Restrict: req.Restrict})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusAccepted, accepted(jobID))
}

// requiredUUID reads a required UUID body field.
func requiredUUID(raw, field string, v *validate.Errors) uuid.UUID {
	if raw == "" {
		v.Add(field, validate.Required, nil)
		return uuid.Nil
	}
	id, err := uuid.Parse(raw)
	if err != nil {
		v.Add(field, validate.Pattern, nil)
		return uuid.Nil
	}
	return id
}

// downloadFileNameRE is the closed form of the file name the service builds ("alice-<slug>-<8 hex>.key"); the header
// is written only with a name of this form, so nothing from a request or a server can reach it.
var downloadFileNameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,199}$`)

// fallbackKeyFileName stands in for a name that is not of the closed form (never expected).
const fallbackKeyFileName = "alice-key.key"

// downloadPrivateKey answers the OpenSSH file of a generated key (S-09; R41 rows 4, 5). The service commits the audit
// row and the counter before it returns the file; only then is the first byte written. The body's passphrase is a
// secretText this handler zeroes on every path; the file is zeroed after the write. Every refusal is the usual JSON
// error, never a file. A passphrase given as "" is an empty, non-nil secretText, which the service refuses as too
// short, so an empty field never silently means "unencrypted"; null or an absent key means unencrypted.
func (s *server) downloadPrivateKey(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Reason     string     `json:"reason"`
		Passphrase secretText `json:"passphrase"`
	}
	defer func() { req.Passphrase.zero() }()
	id, ok := pathUUID(r, "id")
	if !ok {
		s.writeError(w, r, ErrNotFound)
		return
	}
	if !s.decodeExact(w, r, &req, maxDownloadBody, "reason", "passphrase") {
		return
	}
	var pass []byte
	if req.Passphrase != nil {
		pass = req.Passphrase
	}
	dl, err := s.deps.SSHKeys.DownloadPrivateKey(r.Context(), s.actor(r), sshkeys.DownloadInput{KeyID: id, Reason: req.Reason, Passphrase: pass})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	file := downloadedFile(dl)
	defer file.Zero()
	name := dl.FileName
	if !downloadFileNameRE.MatchString(name) {
		name = fallbackKeyFileName
	}
	body := file.Bytes()
	h := w.Header()
	h.Set("Content-Type", "application/octet-stream")
	h.Set("Content-Disposition", `attachment; filename="`+name+`"`)
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body) // a failed write after the audit row is still recorded as downloaded (S-09: audit first)
}

// keyFiles lists, per user, the authorized_keys files the SSH server reads as the last scan found them: the files a
// key can be deployed to (C13). The connection account is never offered, and neither is any file it reads (S7). When
// the scan did not list the connection account's files completely and once, nothing is offered and refusal says why
// (the deploy would be refused with the same code).
func (s *server) keyFiles(w http.ResponseWriter, r *http.Request) {
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
	if !inventory.IsServer(t.Type) {
		s.writeError(w, r, ErrNotFound) // a Key Vault has no key files
		return
	}
	writeJSON(w, http.StatusOK, keyFilesJSON(t))
}

// downloadedFile is the file of a download (the service's secrets.Plaintext, which the handler zeroes).
func downloadedFile(dl sshkeys.Download) secrets.Plaintext { return dl.Body }
