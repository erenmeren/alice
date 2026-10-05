package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/inventory"
	"alice/internal/jobs"
	"alice/internal/license"
	"alice/internal/platform/validate"
	"alice/internal/providers"
	"alice/internal/secrets"
	"alice/internal/sshkeys"
)

var (
	managedID = uuid.MustParse("0192e000-0000-7000-8000-0000000000e1")
	policyID  = uuid.MustParse("0192e000-0000-7000-8000-0000000000e2")
	runID     = uuid.MustParse("0192e000-0000-7000-8000-0000000000e3")
	locID     = uuid.MustParse("0192e000-0000-7000-8000-0000000000e4")
)

func sshDeps(t *testing.T) (Deps, *fakeSSHKeys, *fakeInventory) {
	t.Helper()
	d := testDeps(t, nil)
	fk := &fakeSSHKeys{}
	inv := &fakeInventory{}
	d.SSHKeys, d.Inventory = fk, inv
	return d, fk, inv
}

func sampleManaged() sshkeys.ManagedKey {
	at := time.Date(2026, 10, 1, 9, 0, 0, 0, time.FixedZone("x", 3600))
	from := uuid.MustParse("0192e000-0000-7000-8000-0000000000f1")
	return sshkeys.ManagedKey{ID: managedID, PrivateKeyID: uuid.New(), Fingerprint: "SHA256:abc", PublicKey: "ssh-ed25519 AAAAC3Nza",
		KeyType: "ed25519", Bits: 256, Label: "ci deploy", Comment: "alice:ci-deploy:2026-10-01", CreatedBy: adminID, CreatedAt: at,
		RotatedFrom: &from, DownloadCount: 2, LastDownloadedAt: &at, PolicyID: &policyID}
}

func decodeMap(t *testing.T, b []byte) map[string]any {
	t.Helper()
	var m map[string]any
	require.NoError(t, json.Unmarshal(b, &m), string(b))
	return m
}

// TestGenerateAndDeployHandlers: the body is read with exact keys, a key type outside the four is 422 before the
// service is asked, the answer is the key with managed_key; a deploy answers 202 with the job; both are refused in
// lock with no call.
func TestGenerateAndDeployHandlers(t *testing.T) {
	d, fk, _ := sshDeps(t)
	h := NewHandler(d)
	var gotGen sshkeys.GenerateInput
	fk.GenerateFn = func(_ context.Context, a inventory.Actor, in sshkeys.GenerateInput) (sshkeys.ManagedKey, error) {
		assert.Equal(t, operatorID, a.UserID)
		gotGen = in
		return sampleManaged(), nil
	}
	rec := call(h, http.MethodPost, "/api/v1/ssh-keys/generate", "operator", `{"label":"ci deploy","key_type":"rsa-4096"}`)
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())
	assert.Equal(t, sshkeys.GenerateInput{Label: "ci deploy", KeyType: "rsa-4096"}, gotGen)
	m := decodeMap(t, rec.Body.Bytes())
	assert.Equal(t, managedID.String(), m["id"])
	assert.Equal(t, "ssh-ed25519", m["key_type"])
	assert.Equal(t, true, m["managed"])
	mk := m["managed_key"].(map[string]any)
	assert.Equal(t, "ci deploy", mk["label"])
	assert.Equal(t, "ed25519", mk["key_type"])
	assert.Equal(t, adminID.String(), mk["created_by"])
	assert.Equal(t, "0192e000-0000-7000-8000-0000000000f1", mk["rotated_from"])
	assert.Equal(t, "2026-10-01T08:00:00Z", mk["created_at"], "times are UTC")
	assert.Equal(t, policyID.String(), mk["policy_id"])
	assert.Nil(t, mk["open_rotation_id"])
	for _, k := range []string{"private_key", "passphrase", "secret", "private_key_id", "pkcs8"} {
		assert.NotContains(t, rec.Body.String(), `"`+k+`"`, "S-08: no private key field")
	}

	fk.reset()
	for body, want := range map[string]int{
		`{"label":"x","key_type":"dsa"}`:           http.StatusUnprocessableEntity,
		`{"label":"x","key_type":"ed25519","x":1}`: http.StatusBadRequest,
		`{"label":"x","label":"y"}`:                http.StatusBadRequest,
		`{"label":"x","key_type":"ed25519"} trail`: http.StatusBadRequest,
		`["label"]`: http.StatusBadRequest,
		`{"label":"x","key_type":"ed25519","Label":""}`: http.StatusBadRequest,
	} {
		rec := call(h, http.MethodPost, "/api/v1/ssh-keys/generate", "operator", body)
		assert.Equal(t, want, rec.Code, body)
	}
	assert.Empty(t, fk.Calls(), "no refused body reaches the service")
	rec = call(h, http.MethodPost, "/api/v1/ssh-keys/generate", "operator", `{"label":"x","key_type":"dsa"}`)
	assert.Equal(t, []validate.FieldError{{Field: "key_type", Code: validate.OneOf, Params: map[string]string{"values": "ed25519, rsa-3072, rsa-4096, ecdsa-p256"}}},
		errorDetails(t, rec))

	fk.GenerateFn = func(context.Context, inventory.Actor, sshkeys.GenerateInput) (sshkeys.ManagedKey, error) {
		return sshkeys.ManagedKey{}, sshkeys.ErrGenerateBusy
	}
	rec = call(h, http.MethodPost, "/api/v1/ssh-keys/generate", "operator", `{"label":"x","key_type":"ed25519"}`)
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
	assert.Equal(t, "ALC-KEY-0011", decodeErr(t, rec).Error.Code)
	assert.True(t, decodeErr(t, rec).Error.Retryable)
	assert.Equal(t, "1", rec.Header().Get("Retry-After"))

	var gotDeploy sshkeys.DeployInput
	fk.RequestDeployFn = func(_ context.Context, _ inventory.Actor, in sshkeys.DeployInput) (uuid.UUID, error) {
		gotDeploy = in
		return jobID, nil
	}
	path := "/api/v1/ssh-keys/" + managedID.String() + "/actions/deploy"
	rec = call(h, http.MethodPost, path, "operator", `{"target_id":"`+targetID.String()+`","os_user":"deploy","file_path":"/home/deploy/.ssh/authorized_keys","from":"10.0.0.0/8","restrict":true}`)
	require.Equal(t, http.StatusAccepted, rec.Code, rec.Body.String())
	assert.JSONEq(t, `{"job_id":"`+jobID.String()+`","status_url":"/api/v1/jobs/`+jobID.String()+`"}`, rec.Body.String())
	assert.Equal(t, sshkeys.DeployInput{KeyID: managedID, TargetID: targetID, OSUser: "deploy", FilePath: "/home/deploy/.ssh/authorized_keys",
		From: "10.0.0.0/8", Restrict: true}, gotDeploy)

	fk.reset()
	rec = call(h, http.MethodPost, path, "operator", `{"target_id":"nope","os_user":"","file_path":""}`)
	assert.Equal(t, http.StatusUnprocessableEntity, rec.Code)
	assert.Len(t, errorDetails(t, rec), 3)
	rec = call(h, http.MethodPost, path, "operator", `{"target_id":"`+targetID.String()+`","os_user":"d","file_path":"/f","options":"command=x"}`)
	assert.Equal(t, http.StatusBadRequest, rec.Code, "only from= and restrict can be asked for")
	rec = call(h, http.MethodPost, "/api/v1/ssh-keys/not-a-uuid/actions/deploy", "operator", `{}`)
	assert.Equal(t, http.StatusNotFound, rec.Code)
	assert.Empty(t, fk.Calls())

	// The service's refusals keep their codes.
	for err, code := range map[error]string{sshkeys.ErrConnectionAccount: "ALC-KEY-0009", sshkeys.ErrConnectionFilesUnknown: "ALC-KEY-0014",
		sshkeys.ErrNotAKeyFile: "ALC-KEY-0013", inventory.ErrTargetDisabled: "ALC-TGT-0006", sshkeys.ErrRetired: "ALC-KEY-0007",
		inventory.ErrJobConflict: "ALC-JOB-0005", inventory.ErrNotAServer: "ALC-SYS-0001"} {
		fk.RequestDeployFn = func(context.Context, inventory.Actor, sshkeys.DeployInput) (uuid.UUID, error) { return uuid.Nil, err }
		rec = call(h, http.MethodPost, path, "operator", `{"target_id":"`+targetID.String()+`","os_user":"d","file_path":"/f"}`)
		assert.Equal(t, code, decodeErr(t, rec).Error.Code, err.Error())
	}

	// In lock both are refused before the service is asked (ClassChange).
	d.License.(*fakeLicense).set(license.ErrLocked)
	fk.reset()
	h = NewHandler(d)
	rec = call(h, http.MethodPost, "/api/v1/ssh-keys/generate", "operator", `{"label":"x","key_type":"ed25519"}`)
	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Equal(t, "ALC-LIC-0001", decodeErr(t, rec).Error.Code)
	rec = call(h, http.MethodPost, path, "operator", `{"target_id":"`+targetID.String()+`","os_user":"d","file_path":"/f"}`)
	assert.Equal(t, "ALC-LIC-0001", decodeErr(t, rec).Error.Code)
	assert.Empty(t, fk.Calls())
}

// The detail route adds managed_key for a key Alice generated, null otherwise; a key the inventory calls managed
// without a private key answers null too.
func TestGetSSHKeyAddsManagedKey(t *testing.T) {
	d, fk, inv := sshDeps(t)
	key := inventory.SSHKey{ID: managedID, Fingerprint: "SHA256:abc", KeyType: "ssh-ed25519", Managed: true}
	inv.GetSSHKeyFn = func(context.Context, uuid.UUID) (inventory.SSHKey, error) { return key, nil }
	fk.ManagedKeyFn = func(_ context.Context, id uuid.UUID) (sshkeys.ManagedKey, error) {
		require.Equal(t, managedID, id)
		m := sampleManaged()
		m.CreatedBy = uuid.Nil // generated by a rotation
		return m, nil
	}
	h := NewHandler(d)
	rec := call(h, http.MethodGet, "/api/v1/ssh-keys/"+managedID.String(), "auditor", "")
	require.Equal(t, http.StatusOK, rec.Code)
	m := decodeMap(t, rec.Body.Bytes())
	mk := m["managed_key"].(map[string]any)
	assert.Nil(t, mk["created_by"], "a key a rotation generated has no person")
	assert.EqualValues(t, 2, mk["download_count"])

	fk.ManagedKeyFn = func(context.Context, uuid.UUID) (sshkeys.ManagedKey, error) {
		return sshkeys.ManagedKey{}, sshkeys.ErrNotManaged
	}
	rec = call(h, http.MethodGet, "/api/v1/ssh-keys/"+managedID.String(), "auditor", "")
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, decodeMap(t, rec.Body.Bytes()), "managed_key")
	assert.Nil(t, decodeMap(t, rec.Body.Bytes())["managed_key"])

	fk.ManagedKeyFn = func(context.Context, uuid.UUID) (sshkeys.ManagedKey, error) {
		return sshkeys.ManagedKey{}, errNotConfigured
	}
	rec = call(h, http.MethodGet, "/api/v1/ssh-keys/"+managedID.String(), "auditor", "")
	assert.Equal(t, http.StatusInternalServerError, rec.Code)

	fk.reset()
	key.Managed = false
	rec = call(h, http.MethodGet, "/api/v1/ssh-keys/"+managedID.String(), "auditor", "")
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Nil(t, decodeMap(t, rec.Body.Bytes())["managed_key"])
	assert.Empty(t, fk.Calls(), "a key found on a server is not asked about")

	// The list keeps its shape: no managed_key there.
	inv.ListSSHKeysFn = func(context.Context, inventory.KeyFilter) (inventory.KeyPage, error) {
		return inventory.KeyPage{Items: []inventory.SSHKey{key}}, nil
	}
	rec = call(h, http.MethodGet, "/api/v1/ssh-keys", "auditor", "")
	require.Equal(t, http.StatusOK, rec.Code)
	assert.NotContains(t, rec.Body.String(), "managed_key")
}

// downloadBody is a canary file: never printed by the service, the handler hands it out byte for byte.
func downloadBody() []byte {
	return []byte("-----BEGIN " + "OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA-canary\n-----END " + "OPENSSH PRIVATE KEY-----\n")
}

// TestDownloadNeedsSessionAdminStepUp: never an API token, never without a fresh step-up, never another role; the
// file comes with the headers that keep it out of caches and sniffers; the sixth download of a user in a minute
// answers 429.
func TestDownloadNeedsSessionAdminStepUp(t *testing.T) {
	d, fk, _ := sshDeps(t)
	var served *secrets.Plaintext
	fk.DownloadPrivateKeyFn = func(_ context.Context, a inventory.Actor, in sshkeys.DownloadInput) (sshkeys.Download, error) {
		assert.Equal(t, adminID, a.UserID)
		assert.Equal(t, managedID, in.KeyID)
		p := secrets.NewPlaintext(downloadBody())
		served = &p
		return sshkeys.Download{FileName: "alice-ci-deploy-1a2b3c4d.key", Body: p}, nil
	}
	h := NewHandler(d)
	path := "/api/v1/ssh-keys/" + managedID.String() + "/actions/download-private-key"
	body := `{"reason":"rotate the CI runner key"}`
	for id, want := range map[string]string{"alice_operate_admin": "ALC-AUTH-0002", "alice_read_admin": "ALC-AUTH-0002",
		"admin": "ALC-AUTH-0003", "operator-stepup": "ALC-AUTH-0002", "auditor-stepup": "ALC-AUTH-0002", "": "ALC-AUTH-0001"} {
		rec := call(h, http.MethodPost, path, id, body)
		assert.Equal(t, want, decodeErr(t, rec).Error.Code, id)
		assert.Empty(t, rec.Header().Get("Content-Disposition"), id)
	}
	assert.Empty(t, fk.Calls(), "no refused caller reaches the service")

	h = NewHandler(d) // a fresh limit: the refusals above count against the user's downloads
	rec := call(h, http.MethodPost, path, "admin-stepup", body)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, "application/octet-stream", rec.Header().Get("Content-Type"))
	assert.Equal(t, `attachment; filename="alice-ci-deploy-1a2b3c4d.key"`, rec.Header().Get("Content-Disposition"))
	assert.Equal(t, "no-store", rec.Header().Get("Cache-Control"))
	assert.Equal(t, "nosniff", rec.Header().Get("X-Content-Type-Options"))
	assert.Equal(t, strconv.Itoa(len(downloadBody())), rec.Header().Get("Content-Length"))
	assert.Equal(t, downloadBody(), rec.Body.Bytes())
	require.NotNil(t, served)
	assert.Equal(t, make([]byte, len(downloadBody())), served.Bytes(), "the file is zeroed after the write")

	// A name that is not of the closed form never reaches the header.
	fk.DownloadPrivateKeyFn = func(context.Context, inventory.Actor, sshkeys.DownloadInput) (sshkeys.Download, error) {
		return sshkeys.Download{FileName: "evil\"\r\nSet-Cookie: x=1.key", Body: secrets.NewPlaintext([]byte("x"))}, nil
	}
	rec = call(h, http.MethodPost, path, "admin-stepup", body)
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, `attachment; filename="alice-key.key"`, rec.Header().Get("Content-Disposition"))
	assert.Empty(t, rec.Header().Get("Set-Cookie"))

	// Five per minute per user (the two above count), whichever session; the sixth is 429 with Retry-After.
	for i := 0; i < 3; i++ {
		rec = call(h, http.MethodPost, path, "admin-stepup", body)
		require.Equal(t, http.StatusOK, rec.Code, i)
	}
	n := len(fk.Calls())
	rec = call(h, http.MethodPost, path, "admin-stepup", body)
	assert.Equal(t, http.StatusTooManyRequests, rec.Code)
	assert.Equal(t, "ALC-SYS-0005", decodeErr(t, rec).Error.Code)
	assert.NotEmpty(t, rec.Header().Get("Retry-After"))
	assert.Len(t, fk.Calls(), n, "a limited download never reaches the service")
	// Another user is not limited by it; the limit resets with the e2e reset.
	d.Clock.(interface{ Advance(time.Duration) }).Advance(61 * time.Second)
	rec = call(h, http.MethodPost, path, "admin-stepup", body)
	assert.Equal(t, http.StatusOK, rec.Code, "the bucket refills after a minute")

	// Allowed in lock (R41 row 5).
	d.License.(*fakeLicense).set(license.ErrLocked)
	rec = call(NewHandler(d), http.MethodPost, path, "admin-stepup", body)
	assert.Equal(t, http.StatusOK, rec.Code, "the download is allowed while the license is locked")
}

// The download limit is reset with the other limits (the e2e reset endpoint).
func TestResetLimitsResetsTheDownloadLimit(t *testing.T) {
	d, fk, _ := sshDeps(t)
	fk.DownloadPrivateKeyFn = func(context.Context, inventory.Actor, sshkeys.DownloadInput) (sshkeys.Download, error) {
		return sshkeys.Download{FileName: "alice-x-00000000.key", Body: secrets.NewPlaintext([]byte("x"))}, nil
	}
	srv := New(d)
	path := "/api/v1/ssh-keys/" + managedID.String() + "/actions/download-private-key"
	for i := 0; i < 5; i++ {
		require.Equal(t, http.StatusOK, call(srv.Handler(), http.MethodPost, path, "admin-stepup", `{"reason":"0123456789"}`).Code)
	}
	assert.Equal(t, http.StatusTooManyRequests, call(srv.Handler(), http.MethodPost, path, "admin-stepup", `{"reason":"0123456789"}`).Code)
	srv.ResetLimits()
	assert.Equal(t, http.StatusOK, call(srv.Handler(), http.MethodPost, path, "admin-stepup", `{"reason":"0123456789"}`).Code)
}

// TestDownloadZeroesThePassphrase: every slice the passphrase was copied into, and the body buffer, are zero when the
// handler returns, on success and on every failure path; an empty passphrase is non-nil (the service refuses it), an
// absent or null one is nil.
func TestDownloadZeroesThePassphrase(t *testing.T) {
	d, fk, _ := sshDeps(t)
	w := watchSecrets(t)
	var seen []byte
	var wasNil bool
	result := func(err error) {
		fk.DownloadPrivateKeyFn = func(_ context.Context, _ inventory.Actor, in sshkeys.DownloadInput) (sshkeys.Download, error) {
			seen, wasNil = append([]byte(nil), in.Passphrase...), in.Passphrase == nil
			if err != nil {
				return sshkeys.Download{}, err
			}
			return sshkeys.Download{FileName: "alice-x-00000000.key", Body: secrets.NewPlaintext([]byte("file"))}, nil
		}
	}
	var h http.Handler
	path := "/api/v1/ssh-keys/" + managedID.String() + "/actions/download-private-key"
	var verr validate.Errors
	verr.Add("reason", validate.TooShort, map[string]string{"min": "10"})
	for _, tc := range []struct {
		name, body string
		err        error
		slices     int
		status     int
	}{
		{"success", `{"reason":"0123456789ab","passphrase":"correct horse battery"}`, nil, 1, http.StatusOK},
		{"escaped passphrase", `{"reason":"0123456789ab","passphrase":"line\nbreak ç passphrase"}`, nil, 1, http.StatusOK},
		{"service validation", `{"reason":"short","passphrase":"correct horse battery"}`, verr, 1, http.StatusUnprocessableEntity},
		{"not managed", `{"reason":"0123456789ab","passphrase":"correct horse battery"}`, sshkeys.ErrNotManaged, 1, http.StatusConflict},
		{"destroyed", `{"reason":"0123456789ab","passphrase":"correct horse battery"}`, sshkeys.ErrDestroyed, 1, http.StatusGone},
		{"clock behind", `{"reason":"0123456789ab","passphrase":"correct horse battery"}`, sshkeys.ErrClockBehind, 1, http.StatusServiceUnavailable},
		{"unknown key after the passphrase", `{"reason":"0123456789ab","passphrase":"correct horse battery","x":1}`, nil, 0, http.StatusBadRequest},
		{"repeated passphrase", `{"passphrase":"correct horse battery","passphrase":"other passphrase!"}`, nil, 0, http.StatusBadRequest},
		{"passphrase not a string", `{"reason":"0123456789ab","passphrase":123}`, nil, 0, http.StatusBadRequest},
	} {
		result(tc.err)
		fk.reset()
		h := NewHandler(d) // a fresh download limit per case
		rec, body := callObserved(h, http.MethodPost, path, "admin-stepup", tc.body, nil)
		assert.Equal(t, tc.status, rec.Code, "%s: %s", tc.name, rec.Body.String())
		w.requireZeroed(t, tc.name, tc.slices)
		body.requireZeroed(t, tc.name)
		assert.NotContains(t, rec.Body.String(), "horse", tc.name)
		if tc.status == http.StatusOK {
			assert.Equal(t, "file", rec.Body.String(), tc.name)
		}
	}
	// The service saw the passphrase while it ran (it encrypts the file with it).
	result(nil)
	h = NewHandler(d)
	rec, _ := callObserved(h, http.MethodPost, path, "admin-stepup", `{"reason":"0123456789ab","passphrase":"correct horse battery"}`, nil)
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "correct horse battery", string(seen))
	w.requireZeroed(t, "seen", 1)

	// "" is an empty, non-nil passphrase (refused by the service as too short); null and absent mean unencrypted.
	for body, wantNil := range map[string]bool{`{"reason":"0123456789ab","passphrase":""}`: false,
		`{"reason":"0123456789ab","passphrase":null}`: true, `{"reason":"0123456789ab"}`: true} {
		rec, _ := callObserved(NewHandler(d), http.MethodPost, path, "admin-stepup", body, nil)
		require.Equal(t, http.StatusOK, rec.Code, body)
		assert.Equal(t, wantNil, wasNil, body)
		w.mu.Lock()
		w.slices = nil
		w.mu.Unlock()
	}
}

// TestDownloadErrorsAreJSON: every refusal is the usual error body, never a file.
func TestDownloadErrorsAreJSON(t *testing.T) {
	d, fk, _ := sshDeps(t)
	path := "/api/v1/ssh-keys/" + managedID.String() + "/actions/download-private-key"
	var verr validate.Errors
	verr.Add("reason", validate.TooShort, map[string]string{"min": "10"})
	for _, tc := range []struct {
		err    error
		status int
		code   string
	}{
		{sshkeys.ErrNotManaged, http.StatusConflict, "ALC-KEY-0006"},
		{sshkeys.ErrDestroyed, http.StatusGone, "ALC-KEY-0008"},
		{verr, http.StatusUnprocessableEntity, "ALC-SYS-0006"},
		{sshkeys.ErrClockBehind, http.StatusServiceUnavailable, "ALC-KEY-0015"},
		{inventory.ErrNotFound, http.StatusNotFound, "ALC-SYS-0001"},
	} {
		fk.DownloadPrivateKeyFn = func(context.Context, inventory.Actor, sshkeys.DownloadInput) (sshkeys.Download, error) {
			return sshkeys.Download{}, tc.err
		}
		h := NewHandler(d)
		rec := call(h, http.MethodPost, path, "admin-stepup", `{"reason":"0123456789ab"}`)
		assert.Equal(t, tc.status, rec.Code, tc.code)
		assert.Equal(t, tc.code, decodeErr(t, rec).Error.Code)
		assert.Equal(t, "application/json; charset=utf-8", rec.Header().Get("Content-Type"), tc.code)
		assert.Empty(t, rec.Header().Get("Content-Disposition"), tc.code)
		if tc.code == "ALC-SYS-0006" {
			assert.Equal(t, "reason", errorDetails(t, rec)[0].Field)
		}
		if tc.code == "ALC-KEY-0015" {
			assert.True(t, decodeErr(t, rec).Error.Retryable, "a clock step back is a retryable closed error")
			assert.Equal(t, "60", rec.Header().Get("Retry-After"))
		}
	}
	h := NewHandler(d)
	rec := call(h, http.MethodPost, "/api/v1/ssh-keys/nope/actions/download-private-key", "admin-stepup", `{"reason":"0123456789ab"}`)
	assert.Equal(t, http.StatusNotFound, rec.Code)
	rec = call(h, http.MethodPost, path, "admin-stepup", `{"reason":"`+strings.Repeat("a", 9000)+`"}`)
	assert.Equal(t, http.StatusRequestEntityTooLarge, rec.Code)
}

// TestKeyFilesHandler: the files of every user as the last scan found them, the first as the default; never the
// connection account or a file it reads; nothing (with the refusal's code) when the connection account's files are
// not known completely and once.
func TestKeyFilesHandler(t *testing.T) {
	d, _, inv := sshDeps(t)
	tg := sampleTarget()
	tg.Username = "alice-svc"
	tg.Facts.KeyFiles = []providers.UserKeyFiles{
		{OSUser: "deploy", Files: []string{"/home/deploy/.ssh/authorized_keys", "/home/deploy/.ssh/authorized_keys2"}, Complete: true},
		{OSUser: "alice-svc", Files: []string{"/var/lib/alice-svc/.ssh/authorized_keys", "/etc/ssh/shared_keys"}, Complete: true},
		{OSUser: "backup", Files: []string{"/etc/ssh/shared_keys"}, Complete: true},
		{OSUser: "web", Files: []string{"/etc/ssh/shared_keys", "/srv/web/.ssh/authorized_keys"}, Complete: false},
	}
	inv.GetTargetFn = func(_ context.Context, id uuid.UUID) (inventory.Target, error) {
		if id != targetID {
			return inventory.Target{}, inventory.ErrNotFound
		}
		return tg, nil
	}
	h := NewHandler(d)
	path := "/api/v1/targets/" + targetID.String() + "/key-files"
	rec := call(h, http.MethodGet, path, "auditor", "")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.JSONEq(t, `{"items":[
		{"os_user":"deploy","files":["/home/deploy/.ssh/authorized_keys","/home/deploy/.ssh/authorized_keys2"],"default_file":"/home/deploy/.ssh/authorized_keys"},
		{"os_user":"web","files":["/srv/web/.ssh/authorized_keys"],"default_file":"/srv/web/.ssh/authorized_keys"}],
		"scanned_at":"2026-10-01T09:00:00Z","refusal":null}`, rec.Body.String())

	for name, files := range map[string][]providers.UserKeyFiles{
		"incomplete": {{OSUser: "alice-svc", Files: []string{"/var/lib/alice-svc/.ssh/authorized_keys"}}, {OSUser: "deploy", Files: []string{"/d"}, Complete: true}},
		"absent":     {{OSUser: "deploy", Files: []string{"/d"}, Complete: true}},
		"twice": {{OSUser: "alice-svc", Files: []string{"/a"}, Complete: true}, {OSUser: "alice-svc", Files: []string{"/b"}, Complete: true},
			{OSUser: "deploy", Files: []string{"/d"}, Complete: true}},
	} {
		tg.Facts.KeyFiles = files
		rec = call(h, http.MethodGet, path, "auditor", "")
		require.Equal(t, http.StatusOK, rec.Code, name)
		m := decodeMap(t, rec.Body.Bytes())
		assert.Equal(t, []any{}, m["items"], name)
		assert.Equal(t, map[string]any{"code": "ALC-KEY-0014", "reason": "sshkey.connection_files_unknown"}, m["refusal"], name)
	}

	// A server record without a user name is the service user's.
	tg.Username = ""
	tg.Facts.KeyFiles = []providers.UserKeyFiles{{OSUser: "alice-svc", Files: []string{"/a"}, Complete: true}, {OSUser: "alice-svc2", Files: []string{"/a", "/b"}, Complete: true}}
	tg.LastDiscoveryAt = nil
	rec = call(h, http.MethodGet, path, "alice_read_auditor", "")
	assert.JSONEq(t, `{"items":[{"os_user":"alice-svc2","files":["/b"],"default_file":"/b"}],"scanned_at":null,"refusal":null}`, rec.Body.String())

	tg.Type = "azure_key_vault"
	assert.Equal(t, http.StatusNotFound, call(h, http.MethodGet, path, "auditor", "").Code, "a Key Vault has no key files")
	assert.Equal(t, http.StatusNotFound, call(h, http.MethodGet, "/api/v1/targets/"+uuid.NewString()+"/key-files", "auditor", "").Code)
	assert.Equal(t, http.StatusNotFound, call(h, http.MethodGet, "/api/v1/targets/x/key-files", "auditor", "").Code)
}

// TestJobItemsCarrySSHKeyAndRotationIDs: a sshkey.add job names its key, a rotation.location job its run (F5).
func TestJobItemsCarrySSHKeyAndRotationIDs(t *testing.T) {
	d, fj := jobsDeps(t)
	add := sampleView(jobs.StatusSucceeded, "")
	add.Type, add.SSHKeyID = "sshkey.add", managedID
	add.Result = map[string]any{"result": "verified"}
	loc := sampleView(jobs.StatusFailed, "rotation.retries_exhausted")
	loc.ID, loc.Type, loc.RotationID, loc.ErrorParams = uuid.New(), "rotation.location", runID, nil
	fj.ListFn = func(context.Context, jobs.ListFilter) ([]jobs.View, string, error) {
		return []jobs.View{add, loc}, "", nil
	}
	rec := call(NewHandler(d), http.MethodGet, "/api/v1/jobs", "auditor", "")
	require.Equal(t, http.StatusOK, rec.Code)
	var page struct {
		Items []map[string]any `json:"items"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &page))
	require.Len(t, page.Items, 2)
	assert.Equal(t, managedID.String(), page.Items[0]["ssh_key_id"])
	assert.Nil(t, page.Items[0]["rotation_id"])
	assert.Equal(t, map[string]any{"result": "verified"}, page.Items[0]["result"])
	assert.Equal(t, runID.String(), page.Items[1]["rotation_id"])
	assert.Nil(t, page.Items[1]["ssh_key_id"])
	assert.Equal(t, map[string]any{"code": "ALC-ROT-0016", "reason": "rotation.retries_exhausted"}, page.Items[1]["error"])
}

// No answer of a Phase 6 route other than the download carries the file or a passphrase.
func TestOnlyTheDownloadAnswersKeyMaterial(t *testing.T) {
	d, fk, inv := sshDeps(t)
	canary := downloadBody()
	fk.GenerateFn = func(context.Context, inventory.Actor, sshkeys.GenerateInput) (sshkeys.ManagedKey, error) {
		return sampleManaged(), nil
	}
	inv.GetSSHKeyFn = func(context.Context, uuid.UUID) (inventory.SSHKey, error) {
		return inventory.SSHKey{ID: managedID, Managed: true}, nil
	}
	fk.ManagedKeyFn = func(context.Context, uuid.UUID) (sshkeys.ManagedKey, error) { return sampleManaged(), nil }
	h := NewHandler(d)
	for _, rec := range []*bytes.Buffer{
		call(h, http.MethodPost, "/api/v1/ssh-keys/generate", "admin", `{"label":"x","key_type":"ed25519"}`).Body,
		call(h, http.MethodGet, "/api/v1/ssh-keys/"+managedID.String(), "admin", "").Body,
	} {
		assert.NotContains(t, rec.String(), "PRIVATE KEY")
		assert.False(t, bytes.Contains(rec.Bytes(), canary[11:30]))
	}
}
