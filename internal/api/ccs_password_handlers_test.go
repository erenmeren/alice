package api

import (
	"bytes"
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/inventory"
	"alice/internal/secrets"
)

// PUT /targets/{id}/ccs-password (R68, W5 Rulings 9-11): an Administrator with step-up sets the CCS password of a
// Windows server; the answer is the target, with the date and never the password.

var ccsPath = "/api/v1/targets/" + targetID.String() + "/ccs-password"

// ccsSecret is a password of the CCS rule, built at run time (never a literal).
func ccsSecret() string { return "Ccs-" + strings.ReplaceAll(uuid.NewString(), "-", "") }

func sampleWindows(setAt *time.Time) inventory.Target {
	t := sampleTarget()
	t.Type, t.Name, t.Port, t.Username, t.CCSPasswordSetAt = "windows", "iis-01", 22, "alice-svc", setAt
	return t
}

func ccsDeps(t *testing.T) (http.Handler, *fakeInventory, *fakeAudit) {
	t.Helper()
	d, inv := inventoryDeps(t)
	return NewHandler(d), inv, d.Audit.(*fakeAudit)
}

func TestSetCCSPasswordHandler(t *testing.T) {
	h, inv, _ := ccsDeps(t)
	pw := ccsSecret()
	at := time.Date(2026, 10, 27, 9, 0, 0, 0, time.UTC)
	var (
		got      []byte
		given    secrets.Plaintext
		ver      int
		id       uuid.UUID
		calls    int
		inventor inventory.Actor
	)
	inv.SetCCSPasswordFn = func(_ context.Context, a inventory.Actor, target uuid.UUID, v int, p secrets.Plaintext) (inventory.Target, error) {
		calls++
		got, given, ver, id, inventor = bytes.Clone(p.Bytes()), p, v, target, a
		return sampleWindows(&at), nil
	}
	body := `{"password":"` + pw + `"}`
	hdr := map[string]string{"If-Match": `"7"`}

	rec := callWith(h, http.MethodPut, ccsPath, "admin", body, hdr)
	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Equal(t, ErrStepUpRequired.Code, decodeErr(t, rec).Error.Code, "an Administrator needs a fresh step-up")
	rec = callWith(h, http.MethodPut, ccsPath, "alice_operate_admin", body, hdr)
	assert.Equal(t, http.StatusForbidden, rec.Code, "never an API token")
	assert.Equal(t, http.StatusForbidden, callWith(h, http.MethodPut, ccsPath, "operator-stepup", body, hdr).Code, "an Operator")
	assert.Zero(t, calls, "no refusal reached the inventory")

	rec = callWith(h, http.MethodPut, ccsPath, "admin-stepup", body, hdr)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, []byte(pw), got)
	assert.Equal(t, make([]byte, len(pw)), given.Bytes(), "the handler zeroes the password after the call")
	assert.Equal(t, 7, ver)
	assert.Equal(t, targetID, id)
	assert.Equal(t, adminID, inventor.UserID)
	assert.Equal(t, `"7"`, rec.Header().Get("ETag"))
	obj := jsonObj(t, rec)
	assert.Equal(t, "2026-10-27T09:00:00Z", obj["ccs_password_set_at"])
	assert.Equal(t, targetID.String(), obj["id"], "the answer is the target")
	assert.NotContains(t, obj, "password")

	// A Windows server without a password says null; another target has no such field.
	inv.SetCCSPasswordFn = func(context.Context, inventory.Actor, uuid.UUID, int, secrets.Plaintext) (inventory.Target, error) {
		return sampleWindows(nil), nil
	}
	obj = jsonObj(t, callWith(h, http.MethodPut, ccsPath, "admin-stepup", body, hdr))
	v, ok := obj["ccs_password_set_at"]
	assert.True(t, ok)
	assert.Nil(t, v)
	assert.NotContains(t, mustJSON(targetJSON(sampleTarget(), serviceRefs{})), "ccs_password_set_at", "a Linux server has no CCS")

	// If-Match is required; a stale one is 412; another field or a number is refused before the inventory.
	assert.Equal(t, http.StatusPreconditionFailed, call(h, http.MethodPut, ccsPath, "admin-stepup", body).Code)
	inv.SetCCSPasswordFn = func(context.Context, inventory.Actor, uuid.UUID, int, secrets.Plaintext) (inventory.Target, error) {
		return inventory.Target{}, inventory.ErrVersionMismatch
	}
	assert.Equal(t, http.StatusPreconditionFailed, callWith(h, http.MethodPut, ccsPath, "admin-stepup", body, hdr).Code)
	assert.Equal(t, http.StatusBadRequest, callWith(h, http.MethodPut, ccsPath, "admin-stepup", `{"password":"`+pw+`","x":1}`, hdr).Code)
	assert.Equal(t, http.StatusBadRequest, callWith(h, http.MethodPut, ccsPath, "admin-stepup", `{"password":123456789012}`, hdr).Code)
	assert.Equal(t, http.StatusRequestEntityTooLarge,
		callWith(h, http.MethodPut, ccsPath, "admin-stepup", `{"password":"`+strings.Repeat("a", 5000)+`"}`, hdr).Code)

	// A target that is not a Windows server, an unknown one.
	inv.SetCCSPasswordFn = func(context.Context, inventory.Actor, uuid.UUID, int, secrets.Plaintext) (inventory.Target, error) {
		return inventory.Target{}, inventory.ErrNotWindowsTarget
	}
	rec = callWith(h, http.MethodPut, ccsPath, "admin-stepup", body, hdr)
	assert.Equal(t, http.StatusConflict, rec.Code)
	assert.Equal(t, "ALC-WIN-0011", decodeErr(t, rec).Error.Code)
	inv.SetCCSPasswordFn = func(context.Context, inventory.Actor, uuid.UUID, int, secrets.Plaintext) (inventory.Target, error) {
		return inventory.Target{}, inventory.ErrNotFound
	}
	assert.Equal(t, http.StatusNotFound, callWith(h, http.MethodPut, ccsPath, "admin-stepup", body, hdr).Code)
	assert.Equal(t, http.StatusNotFound, callWith(h, http.MethodPut, "/api/v1/targets/x/ccs-password", "admin-stepup", body, hdr).Code)
}

// Review Focus 2: the submitted password is in no answer (success, refusal, rule violation, malformed body) and in no
// audit row the API writes.
func TestCCSPasswordNeverEchoed(t *testing.T) {
	h, inv, aud := ccsDeps(t)
	pw := ccsSecret()
	at := time.Date(2026, 10, 27, 9, 0, 0, 0, time.UTC)
	inv.SetCCSPasswordFn = func(context.Context, inventory.Actor, uuid.UUID, int, secrets.Plaintext) (inventory.Target, error) {
		return sampleWindows(&at), nil
	}
	hdr := map[string]string{"If-Match": `"7"`}
	body := `{"password":"` + pw + `"}`
	var answers []string
	for _, who := range []string{"admin", "alice_operate_admin", "operator-stepup", "admin-stepup"} {
		answers = append(answers, callWith(h, http.MethodPut, ccsPath, who, body, hdr).Body.String())
	}
	answers = append(answers, callWith(h, http.MethodPut, ccsPath, "admin-stepup", `{"password":"`+pw+`","extra":"`+pw+`"}`, hdr).Body.String())
	inv.SetCCSPasswordFn = func(context.Context, inventory.Actor, uuid.UUID, int, secrets.Plaintext) (inventory.Target, error) {
		return inventory.Target{}, inventory.ErrCCSPasswordInvalid
	}
	rec := callWith(h, http.MethodPut, ccsPath, "admin-stepup", `{"password":"`+pw+` "}`, hdr)
	assert.Equal(t, http.StatusUnprocessableEntity, rec.Code)
	assert.Equal(t, "ALC-WIN-0019", decodeErr(t, rec).Error.Code)
	answers = append(answers, rec.Body.String())
	for i, a := range answers {
		assert.NotContains(t, a, pw, "answer %d", i)
	}
	require.NotEmpty(t, aud.Events(), "the refusals were audited")
	for _, e := range aud.Events() {
		assert.NotContains(t, mustJSON(e), pw, e.Action)
	}
}
