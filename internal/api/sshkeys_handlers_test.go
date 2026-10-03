package api

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/inventory"
	"alice/internal/platform/validate"
	"alice/internal/providers"
)

func TestListSSHKeysValidatesTheQuery(t *testing.T) {
	d, inv := inventoryDeps(t)
	called := false
	inv.ListSSHKeysFn = func(context.Context, inventory.KeyFilter) (inventory.KeyPage, error) {
		called = true
		return inventory.KeyPage{}, nil
	}
	rec := call(NewHandler(d), http.MethodGet, "/api/v1/ssh-keys?target_id=nope&limit=0&flag=nope&missing=maybe", "auditor", "")
	require.Equal(t, http.StatusUnprocessableEntity, rec.Code)
	var fields []string
	for _, f := range errorDetails(t, rec) {
		fields = append(fields, f.Field)
	}
	assert.ElementsMatch(t, []string{"target_id", "limit", "flag", "missing"}, fields)
	assert.False(t, called)
}

func TestListSSHKeysPassesTheFilter(t *testing.T) {
	d, inv := inventoryDeps(t)
	var got inventory.KeyFilter
	at := time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC)
	inv.ListSSHKeysFn = func(_ context.Context, f inventory.KeyFilter) (inventory.KeyPage, error) {
		got = f
		return inventory.KeyPage{Items: []inventory.SSHKey{{ID: keyID, Fingerprint: "SHA256:k", KeyType: "ssh-ed25519", Bits: 256,
			PublicKey: "ssh-ed25519 AAAA", Comment: "deploy@laptop", LocationCount: 2, TargetCount: 1, FirstSeenAt: at}}, NextCursor: "c2"}, nil
	}
	q := "?target_id=" + targetID.String() + "&os_user=deploy&q=laptop&flag=" + providers.FlagWeak + "&missing=true&cursor=c1&limit=20"
	rec := call(NewHandler(d), http.MethodGet, "/api/v1/ssh-keys"+q, "operator", "")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, inventory.KeyFilter{TargetID: targetID, OSUser: "deploy", Query: "laptop", Flag: providers.FlagWeak,
		IncludeMissing: true, Cursor: "c1", Limit: 20}, got)
	var body struct {
		Items      []map[string]any `json:"items"`
		NextCursor *string          `json:"next_cursor"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	require.Len(t, body.Items, 1)
	assert.Equal(t, "deploy@laptop", body.Items[0]["comment"])
	assert.NotContains(t, body.Items[0], "locations", "lists carry no locations")
	require.NotNil(t, body.NextCursor)
	assert.Equal(t, "c2", *body.NextCursor)

	rec = call(NewHandler(d), http.MethodGet, "/api/v1/ssh-keys", "operator", "")
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, 50, got.Limit, "the default page size")
}

func TestGetSSHKeyIncludesLocations(t *testing.T) {
	d, inv := inventoryDeps(t)
	at := time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC)
	inv.GetSSHKeyFn = func(context.Context, uuid.UUID) (inventory.SSHKey, error) {
		return inventory.SSHKey{ID: keyID, Fingerprint: "SHA256:k", IsPlatformKey: true, FirstSeenAt: at, Locations: []inventory.KeyLocation{{
			ID: uuid.New(), SSHKeyID: keyID, Fingerprint: "SHA256:k", KeyType: "ssh-ed25519", TargetID: targetID, TargetName: "web-01",
			OSUser: "alice-svc", FilePath: "/var/lib/alice-svc/.ssh/authorized_keys", LineNo: 1, FirstSeenAt: at, LastSeenAt: at,
			IsAliceConnectionKey: true}}}, nil
	}
	rec := call(NewHandler(d), http.MethodGet, "/api/v1/ssh-keys/"+keyID.String(), "auditor", "")
	require.Equal(t, http.StatusOK, rec.Code)
	var body map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	locs := body["locations"].([]any)
	require.Len(t, locs, 1)
	loc := locs[0].(map[string]any)
	assert.Equal(t, true, loc["is_alice_connection_key"])
	assert.Equal(t, "web-01", loc["target_name"])
	assert.Equal(t, []any{}, loc["flags"])
	assert.Nil(t, loc["removed_at"])
}

func TestRemoveOwnKeyIsRefused(t *testing.T) {
	d, inv := inventoryDeps(t)
	var confirms []bool
	inv.RequestKeyRemovalFn = func(_ context.Context, _ inventory.Actor, id uuid.UUID, confirm bool) (uuid.UUID, error) {
		confirms = append(confirms, confirm)
		if id == keyID {
			return uuid.Nil, inventory.ErrOwnKeyProtected
		}
		return jobID, nil
	}
	h := NewHandler(d)
	rec := call(h, http.MethodPost, "/api/v1/ssh-keys/locations/"+keyID.String()+"/actions/remove", "operator", "")
	require.Equal(t, http.StatusConflict, rec.Code)
	e := decodeErr(t, rec)
	assert.Equal(t, "ALC-KEY-0001", e.Error.Code)
	assert.Equal(t, "errors.sshkey.own_key_protected", e.Error.MessageKey)
	assert.Contains(t, e.Error.Message, "Alice needs this key to connect to this server and will not remove it.")

	other := uuid.New().String()
	rec = call(h, http.MethodPost, "/api/v1/ssh-keys/locations/"+other+"/actions/remove", "operator", `{"confirm_last_root_key":true}`)
	require.Equal(t, http.StatusAccepted, rec.Code)
	assert.Equal(t, []bool{false, true}, confirms)

	rec = call(h, http.MethodPost, "/api/v1/ssh-keys/locations/"+other+"/actions/remove", "operator", `{"force":true}`)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestRemoveRefusals(t *testing.T) {
	d, inv := inventoryDeps(t)
	h := NewHandler(d)
	path := "/api/v1/ssh-keys/locations/" + keyID.String() + "/actions/remove"
	for _, tc := range []struct {
		err    error
		status int
		code   string
	}{
		{inventory.ErrLastRootKey, http.StatusConflict, "ALC-KEY-0002"},
		{inventory.ErrNotRemovable, http.StatusConflict, "ALC-KEY-0003"},
		{inventory.ErrSSHDUnreadable, http.StatusConflict, "ALC-KEY-0004"},
		{inventory.ErrKeysManagedElsewhere, http.StatusConflict, "ALC-SSH-0008"},
		{inventory.ErrHostKeyChanged, http.StatusConflict, "ALC-TGT-0004"},
		{inventory.ErrJobConflict, http.StatusConflict, "ALC-JOB-0005"},
		{inventory.ErrNotFound, http.StatusNotFound, "ALC-SYS-0001"},
	} {
		inv.RequestKeyRemovalFn = func(context.Context, inventory.Actor, uuid.UUID, bool) (uuid.UUID, error) {
			return uuid.Nil, tc.err
		}
		rec := call(h, http.MethodPost, path, "operator", "")
		assert.Equal(t, tc.status, rec.Code, tc.code)
		assert.Equal(t, tc.code, decodeErr(t, rec).Error.Code)
	}
	// Auditors and read tokens never remove keys.
	for _, id := range []string{"auditor", "alice_read_admin"} {
		assert.Equal(t, http.StatusForbidden, call(h, http.MethodPost, path, id, "").Code, id)
	}
}

func TestPlatformKeyGuide(t *testing.T) {
	d, inv := inventoryDeps(t)
	var gotFrom string
	inv.SetupGuideFn = func(_ context.Context, from string) (inventory.Guide, error) {
		gotFrom = from
		return inventory.Guide{
			PlatformKey:        inventory.PlatformKey{ID: keyID, PublicKey: "ssh-ed25519 AAAA alice", Fingerprint: "SHA256:p"},
			AuthorizedKeysLine: `from="10.0.0.5",no-agent-forwarding ssh-ed25519 AAAA alice`,
			HelperPath:         "/usr/local/libexec/alice-helper", HelperProtocol: 1,
			Profiles: map[string]providers.SetupSnippet{
				"linux": {Profile: "linux", Sudoers: "Cmnd_Alias ALICE_COMMON", Script: "set -eu"},
				"nginx": {Profile: "nginx", Sudoers: "Cmnd_Alias ALICE_NGINX_ONLY", Script: "set -eu"},
			},
		}, nil
	}
	h := NewHandler(d)
	rec := call(h, http.MethodGet, "/api/v1/ssh-keys/platform-key?from=not-an-ip", "admin", "")
	require.Equal(t, http.StatusUnprocessableEntity, rec.Code)
	assert.Equal(t, []validate.FieldError{{Field: "from", Code: validate.Pattern}}, errorDetails(t, rec))

	rec = call(h, http.MethodGet, "/api/v1/ssh-keys/platform-key?from=10.0.0.5", "admin", "")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, "10.0.0.5", gotFrom)
	var body map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	assert.Equal(t, "SHA256:p", body["fingerprint"])
	assert.Equal(t, float64(1), body["helper_protocol"])
	profiles := body["profiles"].(map[string]any)
	assert.Equal(t, "set -eu", profiles["linux"].(map[string]any)["script"])
	assert.Equal(t, "Cmnd_Alias ALICE_NGINX_ONLY", profiles["nginx"].(map[string]any)["sudoers"])
	assert.NotContains(t, rec.Body.String(), "private")

	assert.Equal(t, http.StatusForbidden, call(h, http.MethodGet, "/api/v1/ssh-keys/platform-key", "operator", "").Code)
}

// A chunked request has no Content-Length: an empty chunked body is the same as no body, and a
// chunked JSON body is read.
func TestRemoveAcceptsAChunkedBody(t *testing.T) {
	d, inv := inventoryDeps(t)
	var confirms []bool
	inv.RequestKeyRemovalFn = func(_ context.Context, _ inventory.Actor, _ uuid.UUID, confirm bool) (uuid.UUID, error) {
		confirms = append(confirms, confirm)
		return jobID, nil
	}
	h := NewHandler(d)
	path := "/api/v1/ssh-keys/locations/" + keyID.String() + "/actions/remove"
	for _, body := range []string{"", `{"confirm_last_root_key":true}`} {
		req := as(httptest.NewRequest(http.MethodPost, path, nil), "operator")
		req.Body = io.NopCloser(strings.NewReader(body))
		req.ContentLength = -1
		req.TransferEncoding = []string{"chunked"}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusAccepted, rec.Code, "body %q: %s", body, rec.Body.String())
	}
	assert.Equal(t, []bool{false, true}, confirms)
}

func TestListSSHKeysCarriesMissing(t *testing.T) {
	d, inv := inventoryDeps(t)
	inv.ListSSHKeysFn = func(context.Context, inventory.KeyFilter) (inventory.KeyPage, error) {
		return inventory.KeyPage{Items: []inventory.SSHKey{
			{ID: keyID, Fingerprint: "SHA256:gone", Missing: true},
			{ID: uuid.New(), Fingerprint: "SHA256:here"},
		}}, nil
	}
	rec := call(NewHandler(d), http.MethodGet, "/api/v1/ssh-keys?missing=true", "auditor", "")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var body struct {
		Items []map[string]any `json:"items"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	require.Len(t, body.Items, 2)
	assert.Equal(t, true, body.Items[0]["missing"])
	assert.Equal(t, false, body.Items[1]["missing"], "the field is present on every item")
}
