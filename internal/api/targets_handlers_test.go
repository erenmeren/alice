package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/inventory"
	"alice/internal/license"
	"alice/internal/platform/validate"
	"alice/internal/providers"
	"alice/internal/rbac"
)

var (
	targetID = uuid.MustParse("0192b000-0000-7000-8000-0000000000a1")
	jobID    = uuid.MustParse("0192b000-0000-7000-8000-0000000000b1")
	keyID    = uuid.MustParse("0192b000-0000-7000-8000-0000000000c1")
)

// sampleTarget fills every field, so the JSON shape test sees all of them.
func sampleTarget() inventory.Target {
	at := time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC)
	return inventory.Target{
		ID: targetID, Name: "web-01", Type: "linux", Host: "web-01.example.com", Port: 22, Username: "alice-svc",
		Status: "ok", LastErrorCode: "ssh.timeout", LastSuccessAt: &at, LastDiscoveryAt: &at,
		DiscoveryInterval: 24 * time.Hour, KeysManagedElsewhere: true,
		Facts: inventory.Facts{
			OS:            providers.OSRelease{ID: "ubuntu", VersionID: "22.04", PrettyName: "Ubuntu 22.04.4 LTS"},
			HelperVersion: "1.0.0", HelperProtocol: 1,
			SSHD:       &providers.SSHDSummary{Read: true, PubkeyAuthentication: "yes", AuthorizedKeysFile: []string{".ssh/authorized_keys"}, AuthorizedKeysCommand: "none"},
			HostKeys:   []providers.DiscoveredHostKey{{KeyType: "ssh-ed25519", Bits: 256, Fingerprint: "SHA256:host"}},
			Warnings:   []providers.Warning{{Code: "strict_modes", Params: map[string]string{"file_path": "/home/x/.ssh/authorized_keys"}}},
			Unreadable: []providers.UnreadableLine{{OSUser: "deploy", FilePath: "/home/deploy/.ssh/authorized_keys", LineNo: 3}},
		},
		Capabilities: []string{"authorized_keys", "discover_ssh_keys", "test_connection"},
		Version:      7, CreatedAt: at, UpdatedAt: at,
	}
}

// callWith is call() plus extra request headers.
func callWith(h http.Handler, method, target, id, body string, hdr map[string]string) *httptest.ResponseRecorder {
	var req *http.Request
	if body != "" {
		req = httptest.NewRequest(method, target, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
	} else {
		req = httptest.NewRequest(method, target, nil)
	}
	req = as(req, id)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func inventoryDeps(t *testing.T) (Deps, *fakeInventory) {
	t.Helper()
	d := testDeps(t, nil)
	inv := &fakeInventory{}
	d.Inventory = inv
	return d, inv
}

func errorDetails(t *testing.T, rec *httptest.ResponseRecorder) []validate.FieldError {
	t.Helper()
	var body struct {
		Error struct {
			Details []validate.FieldError `json:"details"`
		} `json:"error"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	return body.Error.Details
}

func TestCreateTargetReturnsTargetAndJob(t *testing.T) {
	d, inv := inventoryDeps(t)
	var gotActor inventory.Actor
	var gotIn inventory.NewTarget
	inv.CreateTargetFn = func(_ context.Context, a inventory.Actor, in inventory.NewTarget) (inventory.Target, uuid.UUID, error) {
		gotActor, gotIn = a, in
		return sampleTarget(), jobID, nil
	}
	rec := call(NewHandler(d), http.MethodPost, "/api/v1/targets", "admin",
		`{"name":"web-01","host":"web-01.example.com","port":2222,"username":"alice-svc"}`)
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())

	var body struct {
		Target    map[string]any `json:"target"`
		JobID     string         `json:"job_id"`
		StatusURL string         `json:"status_url"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	assert.Equal(t, jobID.String(), body.JobID)
	assert.Equal(t, "/api/v1/jobs/"+jobID.String(), body.StatusURL)
	assert.Equal(t, "web-01", body.Target["name"])
	assert.Equal(t, inventory.NewTarget{Name: "web-01", Type: "linux", Host: "web-01.example.com", Port: 2222, Username: "alice-svc"}, gotIn,
		"the type defaults to linux")
	assert.Equal(t, adminID, gotActor.UserID)
	assert.Equal(t, rbac.Admin, gotActor.Role)
	assert.Equal(t, "admin", gotActor.Audit.Name)
	assert.NotEmpty(t, gotActor.Audit.RequestID)
}

func TestTargetJSONHasExactlyTheDocumentedFields(t *testing.T) {
	raw, err := json.Marshal(targetJSON(sampleTarget()))
	require.NoError(t, err)
	var m map[string]any
	require.NoError(t, json.Unmarshal(raw, &m))
	var keys []string
	for k := range m {
		keys = append(keys, k)
	}
	assert.ElementsMatch(t, []string{"id", "name", "type", "host", "port", "username", "status", "last_error",
		"last_success_at", "last_discovery_at", "discovery_interval_hours", "keys_managed_elsewhere", "capabilities",
		"facts", "version", "created_at", "updated_at"}, keys)
	text := string(raw)
	for _, banned := range []string{"credential", "private", "secret", `"password"`} {
		assert.NotContains(t, text, banned)
	}
	assert.Equal(t, float64(24), m["discovery_interval_hours"])
	assert.Equal(t, map[string]any{"code": "ALC-SSH-0003", "reason": "ssh.timeout"}, m["last_error"])
	facts := m["facts"].(map[string]any)
	assert.Equal(t, "Ubuntu 22.04.4 LTS", facts["os"].(map[string]any)["pretty_name"])
	assert.Equal(t, true, facts["sshd"].(map[string]any)["read"])
	assert.Len(t, facts["unreadable"], 1)
}

func TestTargetWithoutErrorHasNullLastError(t *testing.T) {
	tg := sampleTarget()
	tg.LastErrorCode = ""
	tg.Facts = inventory.Facts{}
	raw, err := json.Marshal(targetJSON(tg))
	require.NoError(t, err)
	assert.Contains(t, string(raw), `"last_error":null`)
	assert.Contains(t, string(raw), `"host_keys":[]`, "lists are never null")
	assert.Contains(t, string(raw), `"sshd":null`)
}

func TestCreateTargetValidationDetails(t *testing.T) {
	d, inv := inventoryDeps(t)
	inv.CreateTargetFn = func(context.Context, inventory.Actor, inventory.NewTarget) (inventory.Target, uuid.UUID, error) {
		var v validate.Errors
		v.Add("host", validate.Pattern, nil)
		return inventory.Target{}, uuid.Nil, v
	}
	rec := call(NewHandler(d), http.MethodPost, "/api/v1/targets", "admin", `{"name":"x","host":"169.254.169.254"}`)
	require.Equal(t, http.StatusUnprocessableEntity, rec.Code)
	assert.Equal(t, "ALC-SYS-0006", decodeErr(t, rec).Error.Code)
	assert.Equal(t, []validate.FieldError{{Field: "host", Code: validate.Pattern}}, errorDetails(t, rec))
}

func TestCreateTargetRejectsUnknownFields(t *testing.T) {
	d, inv := inventoryDeps(t)
	called := false
	inv.CreateTargetFn = func(context.Context, inventory.Actor, inventory.NewTarget) (inventory.Target, uuid.UUID, error) {
		called = true
		return inventory.Target{}, uuid.Nil, nil
	}
	rec := call(NewHandler(d), http.MethodPost, "/api/v1/targets", "admin", `{"name":"x","host":"h","credential":"x"}`)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.False(t, called)
}

func TestCreateTargetLicenseErrors(t *testing.T) {
	d, inv := inventoryDeps(t)
	inv.CreateTargetFn = func(context.Context, inventory.Actor, inventory.NewTarget) (inventory.Target, uuid.UUID, error) {
		return inventory.Target{}, uuid.Nil, &license.TargetLimitError{Max: 5, Used: 5}
	}
	rec := call(NewHandler(d), http.MethodPost, "/api/v1/targets", "admin", `{"name":"x","host":"h"}`)
	require.Equal(t, http.StatusConflict, rec.Code)
	assert.Equal(t, "ALC-LIC-0008", decodeErr(t, rec).Error.Code)
	assert.Contains(t, rec.Body.String(), `"max":"5"`)

	// In lock the guard refuses the route before the handler runs (R9, L-26).
	called := false
	inv.CreateTargetFn = func(context.Context, inventory.Actor, inventory.NewTarget) (inventory.Target, uuid.UUID, error) {
		called = true
		return inventory.Target{}, uuid.Nil, nil
	}
	d.License.(*fakeLicense).set(license.ErrLocked)
	fa := d.Audit.(*fakeAudit)
	rec = call(NewHandler(d), http.MethodPost, "/api/v1/targets", "admin", `{"name":"x","host":"h"}`)
	require.Equal(t, http.StatusForbidden, rec.Code)
	assert.Equal(t, "license.locked", decodeErr(t, rec).Error.Reason)
	assert.False(t, called)
	assert.Equal(t, 1, fa.Count("request.denied_license"))
}

func TestGetTargetSetsETag(t *testing.T) {
	d, inv := inventoryDeps(t)
	inv.GetTargetFn = func(_ context.Context, id uuid.UUID) (inventory.Target, error) {
		require.Equal(t, targetID, id)
		return sampleTarget(), nil
	}
	rec := call(NewHandler(d), http.MethodGet, "/api/v1/targets/"+targetID.String(), "auditor", "")
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, `"7"`, rec.Header().Get("ETag"))

	rec = call(NewHandler(d), http.MethodGet, "/api/v1/targets/not-a-uuid", "auditor", "")
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

func TestPatchTargetNeedsMatchingIfMatch(t *testing.T) {
	d, inv := inventoryDeps(t)
	calls := 0
	var gotVersion int
	var gotPatch inventory.TargetPatch
	inv.UpdateTargetFn = func(_ context.Context, _ inventory.Actor, _ uuid.UUID, v int, p inventory.TargetPatch) (inventory.Target, error) {
		calls++
		gotVersion, gotPatch = v, p
		tg := sampleTarget()
		tg.Version = v + 1
		return tg, nil
	}
	h := NewHandler(d)
	path := "/api/v1/targets/" + targetID.String()
	body := `{"name":"web-02","discovery_interval_hours":12}`
	for _, hdr := range []map[string]string{nil, {"If-Match": "7"}, {"If-Match": `W/"7"`}, {"If-Match": `"0"`}, {"If-Match": `"7", "8"`}, {"If-Match": `*`}} {
		rec := callWith(h, http.MethodPatch, path, "admin", body, hdr)
		assert.Equal(t, http.StatusPreconditionFailed, rec.Code, "%v", hdr)
		assert.Equal(t, "ALC-SYS-0008", decodeErr(t, rec).Error.Code, "%v", hdr)
	}
	assert.Equal(t, 0, calls, "the service is never asked without a valid version")

	rec := callWith(h, http.MethodPatch, path, "admin", body, map[string]string{"If-Match": `"7"`})
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, 7, gotVersion)
	require.NotNil(t, gotPatch.Name)
	assert.Equal(t, "web-02", *gotPatch.Name)
	require.NotNil(t, gotPatch.DiscoveryIntervalHours)
	assert.Equal(t, 12, *gotPatch.DiscoveryIntervalHours)
	assert.Equal(t, `"8"`, rec.Header().Get("ETag"))

	inv.UpdateTargetFn = func(context.Context, inventory.Actor, uuid.UUID, int, inventory.TargetPatch) (inventory.Target, error) {
		return inventory.Target{}, inventory.ErrVersionMismatch
	}
	rec = callWith(h, http.MethodPatch, path, "admin", body, map[string]string{"If-Match": `"7"`})
	assert.Equal(t, http.StatusPreconditionFailed, rec.Code)
}

func TestTargetActionsAnswerAccepted(t *testing.T) {
	d, inv := inventoryDeps(t)
	var tested, discovered uuid.UUID
	inv.RequestTestFn = func(_ context.Context, a inventory.Actor, id uuid.UUID) (uuid.UUID, error) {
		assert.Equal(t, rbac.Operator, a.Role)
		tested = id
		return jobID, nil
	}
	inv.RequestDiscoveryFn = func(_ context.Context, _ inventory.Actor, id uuid.UUID) (uuid.UUID, error) {
		discovered = id
		return uuid.Nil, inventory.ErrHostKeyChanged
	}
	inv.DeleteTargetFn = func(context.Context, inventory.Actor, uuid.UUID) error { return nil }
	h := NewHandler(d)
	base := "/api/v1/targets/" + targetID.String()

	rec := call(h, http.MethodPost, base+"/actions/test", "operator", "")
	require.Equal(t, http.StatusAccepted, rec.Code)
	assert.JSONEq(t, `{"job_id":"`+jobID.String()+`","status_url":"/api/v1/jobs/`+jobID.String()+`"}`, rec.Body.String())
	assert.Equal(t, targetID, tested)

	rec = call(h, http.MethodPost, base+"/actions/discover", "operator", "")
	require.Equal(t, http.StatusConflict, rec.Code)
	assert.Equal(t, "ALC-TGT-0004", decodeErr(t, rec).Error.Code)
	assert.Equal(t, targetID, discovered)

	rec = call(h, http.MethodDelete, base, "admin", "")
	assert.Equal(t, http.StatusNoContent, rec.Code)
}

func TestHostKeyConfirmAndRepin(t *testing.T) {
	d, inv := inventoryDeps(t)
	var gotFP, gotReason string
	var gotTarget, gotKey uuid.UUID
	inv.ConfirmHostKeyFn = func(_ context.Context, _ inventory.Actor, tID, kID uuid.UUID, fp string) (uuid.UUID, error) {
		gotTarget, gotKey, gotFP = tID, kID, fp
		if fp != "SHA256:right" {
			return uuid.Nil, inventory.ErrHostKeyStale
		}
		return jobID, nil
	}
	inv.RepinHostKeyFn = func(_ context.Context, _ inventory.Actor, _, _ uuid.UUID, fp, reason string) (uuid.UUID, error) {
		gotFP, gotReason = fp, reason
		if len(reason) < 10 {
			var v validate.Errors
			v.Add("reason", validate.TooShort, map[string]string{"min": "10"})
			return uuid.Nil, v
		}
		return jobID, nil
	}
	h := NewHandler(d)
	base := "/api/v1/targets/" + targetID.String() + "/host-keys/" + keyID.String() + "/actions/"

	rec := call(h, http.MethodPost, base+"confirm", "admin", `{"fingerprint":"SHA256:wrong"}`)
	require.Equal(t, http.StatusConflict, rec.Code)
	assert.Equal(t, "ALC-TGT-0003", decodeErr(t, rec).Error.Code)

	rec = call(h, http.MethodPost, base+"confirm", "admin", `{"fingerprint":"SHA256:right"}`)
	require.Equal(t, http.StatusAccepted, rec.Code)
	assert.Equal(t, targetID, gotTarget)
	assert.Equal(t, keyID, gotKey)
	assert.Equal(t, "SHA256:right", gotFP)

	rec = call(h, http.MethodPost, base+"confirm", "admin", `{}`)
	require.Equal(t, http.StatusUnprocessableEntity, rec.Code)
	assert.Equal(t, []validate.FieldError{{Field: "fingerprint", Code: validate.Required}}, errorDetails(t, rec))

	rec = call(h, http.MethodPost, base+"repin", "admin-stepup", `{"fingerprint":"SHA256:new","reason":"short"}`)
	require.Equal(t, http.StatusUnprocessableEntity, rec.Code)
	rec = call(h, http.MethodPost, base+"repin", "admin-stepup", `{"fingerprint":"SHA256:new","reason":"Server reinstalled (ticket 4711)"}`)
	require.Equal(t, http.StatusAccepted, rec.Code)
	assert.Equal(t, "SHA256:new", gotFP)
	assert.Equal(t, "Server reinstalled (ticket 4711)", gotReason)

	big := `{"fingerprint":"SHA256:new","reason":"` + strings.Repeat("x", 9000) + `"}`
	rec = call(h, http.MethodPost, base+"repin", "admin-stepup", big)
	assert.Equal(t, http.StatusRequestEntityTooLarge, rec.Code, "the repin body is capped at 8 KiB")
}

func TestListHostKeysShowsVerifyCommand(t *testing.T) {
	d, inv := inventoryDeps(t)
	at := time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC)
	inv.ListHostKeysFn = func(context.Context, uuid.UUID) ([]inventory.HostKeyRecord, error) {
		return []inventory.HostKeyRecord{
			{ID: keyID, KeyType: "ssh-ed25519", Fingerprint: "SHA256:a", Status: "pinned", ObservedAt: at, ConfirmedAt: &at, ConfirmedByName: "ada"},
			{ID: uuid.New(), KeyType: "ecdsa-sha2-nistp256", Fingerprint: "SHA256:b", Status: "observed", ObservedAt: at},
			{ID: uuid.New(), KeyType: "ssh-rsa", Fingerprint: "SHA256:c", Status: "superseded", ObservedAt: at, SupersededAt: &at},
		}, nil
	}
	rec := call(NewHandler(d), http.MethodGet, "/api/v1/targets/"+targetID.String()+"/host-keys", "auditor", "")
	require.Equal(t, http.StatusOK, rec.Code)
	var body struct {
		Items []map[string]any `json:"items"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	require.Len(t, body.Items, 3)
	assert.Equal(t, "ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub", body.Items[0]["verify_command"])
	assert.Equal(t, "ssh-keygen -lf /etc/ssh/ssh_host_ecdsa_key.pub", body.Items[1]["verify_command"])
	assert.Equal(t, "ssh-keygen -lf /etc/ssh/ssh_host_rsa_key.pub", body.Items[2]["verify_command"])
	assert.Equal(t, "ada", body.Items[0]["confirmed_by_name"])
	assert.Nil(t, body.Items[1]["confirmed_at"])
}

func TestListTargetKeysPassesMissingFlag(t *testing.T) {
	d, inv := inventoryDeps(t)
	var got []bool
	inv.ListTargetKeysFn = func(_ context.Context, _ uuid.UUID, missing bool) ([]inventory.KeyLocation, error) {
		got = append(got, missing)
		return nil, nil
	}
	h := NewHandler(d)
	base := "/api/v1/targets/" + targetID.String() + "/ssh-keys"
	rec := call(h, http.MethodGet, base, "operator", "")
	require.Equal(t, http.StatusOK, rec.Code)
	assert.JSONEq(t, `{"items":[]}`, rec.Body.String())
	require.Equal(t, http.StatusOK, call(h, http.MethodGet, base+"?missing=true", "operator", "").Code)
	assert.Equal(t, []bool{false, true}, got)
	assert.Equal(t, http.StatusUnprocessableEntity, call(h, http.MethodGet, base+"?missing=yes", "operator", "").Code)
}

// Every state-changing route of the server, SSH key and job groups is refused in lock (R9, §13.4):
// asking for a connection test or a scan is recurring read-only work (ClassReadOnly, R37 item 8),
// everything else changes the managed inventory or servers (ClassChange).
func TestInfrastructureRoutesAreGated(t *testing.T) {
	readOnly := map[string]bool{
		"POST /api/v1/targets/{id}/actions/test":     true,
		"POST /api/v1/targets/{id}/actions/discover": true,
	}
	n := 0
	for _, rt := range newServer(Deps{}).apiRoutes() {
		if safeMethod(rt.method) || !underAny(rt.pattern, []string{"/api/v1/targets", "/api/v1/ssh-keys", "/api/v1/jobs"}) {
			continue
		}
		n++
		want := license.ClassChange
		if readOnly[rt.method+" "+rt.pattern] {
			want = license.ClassReadOnly
		}
		assert.Equal(t, want, rt.lic, "%s %s", rt.method, rt.pattern)
		assert.True(t, gated(rt.lic), "%s %s", rt.method, rt.pattern)
	}
	assert.Equal(t, 10, n)
}

func TestTargetActionsAreRefusedInLock(t *testing.T) {
	d, inv := inventoryDeps(t)
	called := false
	inv.RequestTestFn = func(context.Context, inventory.Actor, uuid.UUID) (uuid.UUID, error) {
		called = true
		return jobID, nil
	}
	inv.RequestDiscoveryFn = inv.RequestTestFn
	d.License.(*fakeLicense).set(license.ErrLocked)
	h := NewHandler(d)
	for _, action := range []string{"test", "discover"} {
		rec := call(h, http.MethodPost, "/api/v1/targets/"+targetID.String()+"/actions/"+action, "operator", "")
		assert.Equal(t, http.StatusForbidden, rec.Code, action)
		assert.Equal(t, "ALC-LIC-0001", decodeErr(t, rec).Error.Code, action)
	}
	assert.False(t, called)
	var classes []string
	for _, e := range d.Audit.(*fakeAudit).Events() {
		if e.Action == "request.denied_license" {
			classes = append(classes, e.Details["class"])
		}
	}
	assert.Equal(t, []string{"read_only", "read_only"}, classes)
}
