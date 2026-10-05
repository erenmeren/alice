package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/inventory"
	"alice/internal/license"
	"alice/internal/platform/validate"
	"alice/internal/secrets"
	"alice/internal/sshkeys"
	"alice/internal/sshkeys/plan"
)

var digest64 = strings.Repeat("ab", 32)

func samplePolicy(enabled bool, version int) sshkeys.Policy {
	at := time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC)
	next := at.Add(90 * 24 * time.Hour)
	p := sshkeys.Policy{ID: policyID, SSHKeyID: managedID, Name: "ci", Enabled: enabled, IntervalDays: 90, OverlapMinutes: 7*1440 + 30,
		NotifyBeforeHours: 24, NewKeyType: "same", Version: version, CreatedAt: at, UpdatedAt: at}
	if enabled {
		p.NextRunAt = &next
	}
	return p
}

func sampleRotation(status string) sshkeys.Rotation {
	at := time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC)
	newKey := uuid.MustParse("0192e000-0000-7000-8000-0000000000f2")
	newLoc := uuid.MustParse("0192e000-0000-7000-8000-0000000000f3")
	return sshkeys.Rotation{ID: runID, PolicyID: policyID, OldKeyID: managedID, NewKeyID: &newKey, OldFingerprint: "SHA256:old",
		NewFingerprint: "SHA256:new", Trigger: sshkeys.TriggerManual, Status: status, Digest: digest64, NewKeyType: "ed25519",
		OverlapMinutes: 1440, PlannedFor: at, NotifiedAt: at, StartedAt: &at, ResultCode: "", KeptCount: 1,
		Plan: plan.Plan{Changes: 1, Skips: 1},
		Locations: []sshkeys.RotationLocation{
			{ID: locID, N: 1, TargetID: targetID, TargetName: "web-01", OSUser: "deploy", FilePath: "/home/deploy/.ssh/authorized_keys",
				State: sshkeys.LocVerified, VerifiedAt: &at, NewLocationID: &newLoc, AddResendCount: 2, AddResentAt: &at},
			{ID: uuid.New(), N: 2, TargetID: targetID, TargetName: "web-01", OSUser: "root", FilePath: "/root/.ssh/authorized_keys",
				State: sshkeys.LocSkipped, SkipReason: plan.SkipSSHDUnreadable},
		},
		Steps:   []sshkeys.Step{{N: 1, Name: "adding_new", Status: "ok", At: at}},
		Version: 3}
}

// routeCall is a request that a permitted caller can send to a route and the service accepts.
type routeCall struct {
	body string
	hdr  map[string]string
}

// phase6Calls are the Phase 6 routes with a body and headers the handler accepts.
func phase6Calls() map[string]routeCall {
	ifm := map[string]string{"If-Match": `"3"`}
	return map[string]routeCall{
		"POST /api/v1/ssh-keys/generate":                          {body: `{"label":"ci","key_type":"ed25519"}`},
		"POST /api/v1/ssh-keys/{id}/actions/deploy":               {body: `{"target_id":"` + targetID.String() + `","os_user":"d","file_path":"/f"}`},
		"POST /api/v1/ssh-keys/{id}/actions/download-private-key": {body: `{"reason":"0123456789ab"}`},
		"GET /api/v1/targets/{id}/key-files":                      {},
		"GET /api/v1/rotation/policies":                           {},
		"POST /api/v1/rotation/policies":                          {body: `{"ssh_key_id":"` + managedID.String() + `","name":"ci","interval_days":90}`},
		"GET /api/v1/rotation/policies/{id}":                      {},
		"PATCH /api/v1/rotation/policies/{id}":                    {body: `{"interval_days":1}`, hdr: ifm},
		"DELETE /api/v1/rotation/policies/{id}":                   {hdr: ifm},
		"POST /api/v1/rotation/policies/{id}/actions/enable":      {hdr: ifm},
		"POST /api/v1/rotation/policies/{id}/actions/disable":     {hdr: ifm},
		"POST /api/v1/rotation/policies/{id}/actions/preview":     {},
		"POST /api/v1/rotation/policies/{id}/actions/run":         {body: `{"plan_digest":"` + digest64 + `"}`},
		"GET /api/v1/rotation/runs":                               {},
		"GET /api/v1/rotation/runs/{id}":                          {},
		"POST /api/v1/rotation/runs/{id}/actions/continue":        {},
		"POST /api/v1/rotation/runs/{id}/actions/finish-now":      {},
		"POST /api/v1/rotation/runs/{id}/actions/keep-old":        {body: `{"location_ids":["` + locID.String() + `"]}`},
		"POST /api/v1/rotation/runs/{id}/actions/abort":           {},
	}
}

// succeeding configures every method of the fakes to succeed.
func succeeding(fk *fakeSSHKeys, inv *fakeInventory) {
	ok := func(context.Context, inventory.Actor, uuid.UUID) error { return nil }
	fk.GenerateFn = func(context.Context, inventory.Actor, sshkeys.GenerateInput) (sshkeys.ManagedKey, error) {
		return sampleManaged(), nil
	}
	fk.RequestDeployFn = func(context.Context, inventory.Actor, sshkeys.DeployInput) (uuid.UUID, error) { return jobID, nil }
	fk.DownloadPrivateKeyFn = func(context.Context, inventory.Actor, sshkeys.DownloadInput) (sshkeys.Download, error) {
		return sshkeys.Download{FileName: "alice-ci-00000000.key", Body: secrets.NewPlaintext([]byte("file"))}, nil
	}
	fk.CreatePolicyFn = func(context.Context, inventory.Actor, sshkeys.PolicyInput) (sshkeys.Policy, error) {
		return samplePolicy(false, 1), nil
	}
	fk.UpdatePolicyFn = func(context.Context, inventory.Actor, uuid.UUID, int, sshkeys.PolicyPatch) (sshkeys.Policy, error) {
		return samplePolicy(false, 4), nil
	}
	fk.SetPolicyEnabledFn = func(_ context.Context, _ inventory.Actor, _ uuid.UUID, _ int, on bool) (sshkeys.Policy, error) {
		return samplePolicy(on, 4), nil
	}
	fk.DeletePolicyFn = func(context.Context, inventory.Actor, uuid.UUID, int) error { return nil }
	fk.PolicyFn = func(context.Context, uuid.UUID) (sshkeys.Policy, error) { return samplePolicy(true, 3), nil }
	fk.PoliciesFn = func(context.Context) ([]sshkeys.Policy, error) { return []sshkeys.Policy{samplePolicy(true, 3)}, nil }
	fk.PreviewFn = func(context.Context, inventory.Actor, uuid.UUID) (sshkeys.Preview, error) {
		return sshkeys.Preview{PolicyID: policyID, Digest: digest64}, nil
	}
	fk.RunNowFn = func(context.Context, inventory.Actor, uuid.UUID, string) (sshkeys.Rotation, error) {
		return sampleRotation(sshkeys.StatusAddingNew), nil
	}
	fk.RotationFn = func(context.Context, uuid.UUID) (sshkeys.Rotation, error) {
		return sampleRotation(sshkeys.StatusOverlap), nil
	}
	fk.RotationSummariesFn = func(context.Context, sshkeys.RotationFilter) ([]sshkeys.RotationSummary, string, error) {
		return []sshkeys.RotationSummary{sampleSummary()}, "", nil
	}
	fk.ContinueFn, fk.FinishNowFn, fk.AbortFn = ok, ok, ok
	fk.KeepOldFn = func(context.Context, inventory.Actor, uuid.UUID, []uuid.UUID) error { return nil }
	inv.GetTargetFn = func(context.Context, uuid.UUID) (inventory.Target, error) { return sampleTarget(), nil }
}

// TestRotationRoutesAuthz: every rotation route and the Phase 6 key routes, as every identity, in and out of lock:
// a refused request never reaches the service (no side effect) and an authenticated refusal is audited; an allowed
// one reaches it. Expected decisions are the hand-written matrix (expectedMatrix), not rbac.Decide.
func TestRotationRoutesAuthz(t *testing.T) {
	calls := phase6Calls()
	for _, locked := range []bool{false, true} {
		d, fk, inv := sshDeps(t)
		succeeding(fk, inv)
		if locked {
			d.License.(*fakeLicense).set(license.ErrLocked)
		}
		s := newServer(d)
		h := s.handler(s.apiRoutes())
		fa := d.Audit.(*fakeAudit)
		seen := 0
		for _, rt := range s.apiRoutes() {
			key := rt.method + " " + rt.pattern
			c, ok := calls[key]
			if !ok {
				continue
			}
			seen++
			target := pathParamRE.ReplaceAllString(rt.pattern, uuid.NewString())
			for _, id := range identities {
				(&Server{s: s}).ResetLimits()
				fk.reset()
				before := fa.Count("authz.denied")
				rec := callWith(h, rt.method, target, id, c.body, c.hdr)
				name := key + " as " + id
				if locked {
					name += " (locked)"
				}
				want := expectedMatrix[rt.perm][id]
				switch {
				case want == allw && locked && gated(rt.lic):
					assert.Equal(t, http.StatusForbidden, rec.Code, name)
					assert.Equal(t, "ALC-LIC-0001", decodeErr(t, rec).Error.Code, name)
					assert.Empty(t, fk.Calls(), name)
				case want == allw:
					assert.Less(t, rec.Code, 300, "%s: %s", name, rec.Body.String())
					if rt.pattern != "/api/v1/targets/{id}/key-files" {
						assert.NotEmpty(t, fk.Calls(), name)
					}
				case want == step:
					assert.Equal(t, http.StatusForbidden, rec.Code, name)
					assert.Equal(t, "ALC-AUTH-0003", decodeErr(t, rec).Error.Code, name)
				default:
					assert.Equal(t, want, rec.Code, name)
				}
				if want != allw {
					assert.Empty(t, fk.Calls(), "a refused request has no side effect: %s", name)
				}
				if (want == forb || want == step) && authenticatedUser(id) {
					assert.Equal(t, before+1, fa.Count("authz.denied"), "the refusal is audited: %s", name)
				}
			}
		}
		assert.Equal(t, len(calls), seen, "every Phase 6 route is in the table")
	}
	// The permissions as the plan amends them (rows 7, 24, 25; S2): enable and every decision need step-up and no token.
	routes := map[string]string{}
	for _, rt := range newServer(Deps{}).apiRoutes() {
		routes[rt.method+" "+rt.pattern] = string(rt.perm)
	}
	for key, perm := range map[string]string{
		"POST /api/v1/rotation/policies/{id}/actions/enable": "rotation.operate", "POST /api/v1/rotation/policies/{id}/actions/run": "rotation.operate",
		"POST /api/v1/rotation/runs/{id}/actions/continue": "rotation.operate", "POST /api/v1/rotation/runs/{id}/actions/finish-now": "rotation.operate",
		"POST /api/v1/rotation/runs/{id}/actions/keep-old": "rotation.operate", "POST /api/v1/rotation/runs/{id}/actions/abort": "rotation.manage",
		"POST /api/v1/rotation/policies": "rotation.manage", "PATCH /api/v1/rotation/policies/{id}": "rotation.manage",
		"DELETE /api/v1/rotation/policies/{id}": "rotation.manage", "POST /api/v1/rotation/policies/{id}/actions/disable": "rotation.manage",
		"POST /api/v1/rotation/policies/{id}/actions/preview": "rotation.manage", "POST /api/v1/ssh-keys/generate": "inventory.operate",
		"POST /api/v1/ssh-keys/{id}/actions/deploy": "inventory.operate", "POST /api/v1/ssh-keys/{id}/actions/download-private-key": "sshkeys.download",
	} {
		assert.Equal(t, perm, routes[key], key)
	}
}

// TestPolicyHandlers: create answers 201 with ETag "1"; PATCH, DELETE, enable and disable need a strong If-Match
// (412 without, never asking the service) and pass its version; a stale version is the service's 412.
func TestPolicyHandlers(t *testing.T) {
	d, fk, _ := sshDeps(t)
	h := NewHandler(d)
	var gotIn sshkeys.PolicyInput
	fk.CreatePolicyFn = func(_ context.Context, a inventory.Actor, in sshkeys.PolicyInput) (sshkeys.Policy, error) {
		assert.Equal(t, adminID, a.UserID)
		gotIn = in
		return samplePolicy(false, 1), nil
	}
	rec := call(h, http.MethodPost, "/api/v1/rotation/policies", "alice_operate_admin",
		`{"ssh_key_id":"`+managedID.String()+`","name":"ci","interval_days":90}`)
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())
	assert.Equal(t, `"1"`, rec.Header().Get("ETag"))
	assert.Equal(t, sshkeys.PolicyInput{SSHKeyID: managedID, Name: "ci", IntervalDays: 90, OverlapDays: 7}, gotIn, "overlap defaults to 7 days")
	m := decodeMap(t, rec.Body.Bytes())
	assert.Equal(t, false, m["enabled"])
	assert.EqualValues(t, 7, m["overlap_days"], "minutes / 1440, rounded down")
	assert.EqualValues(t, 7*1440+30, m["overlap_minutes"])
	assert.Nil(t, m["next_run_at"])
	assert.Nil(t, m["last_run_result"])
	assert.Nil(t, m["last_run_status"])

	rec = call(h, http.MethodPost, "/api/v1/rotation/policies", "admin",
		`{"ssh_key_id":"`+managedID.String()+`","name":"ci","interval_days":90,"overlap_days":0,"notify_before_hours":2,"new_key_type":"rsa-4096"}`)
	require.Equal(t, http.StatusCreated, rec.Code)
	assert.Equal(t, sshkeys.PolicyInput{SSHKeyID: managedID, Name: "ci", IntervalDays: 90, OverlapDays: 0, NotifyBeforeHours: 2, NewKeyType: "rsa-4096"}, gotIn)

	fk.reset()
	for _, body := range []string{`{"name":"x"}`, `{"ssh_key_id":"nope","name":"x"}`} {
		rec = call(h, http.MethodPost, "/api/v1/rotation/policies", "admin", body)
		assert.Equal(t, http.StatusUnprocessableEntity, rec.Code, body)
		assert.Equal(t, "ssh_key_id", errorDetails(t, rec)[0].Field, body)
	}
	assert.Equal(t, http.StatusBadRequest, call(h, http.MethodPost, "/api/v1/rotation/policies", "admin", `{"ssh_key_id":"`+managedID.String()+`","enabled":true}`).Code,
		"a policy is never created switched on")
	assert.Empty(t, fk.Calls())
	for err, code := range map[error]string{sshkeys.ErrPolicyExists: "ALC-ROT-0001", sshkeys.ErrRotationInProgress: "ALC-ROT-0002",
		sshkeys.ErrOwnKeyProtected: "ALC-KEY-0001", sshkeys.ErrNotManaged: "ALC-KEY-0006", sshkeys.ErrRetired: "ALC-KEY-0007"} {
		fk.CreatePolicyFn = func(context.Context, inventory.Actor, sshkeys.PolicyInput) (sshkeys.Policy, error) {
			return sshkeys.Policy{}, err
		}
		rec = call(h, http.MethodPost, "/api/v1/rotation/policies", "admin", `{"ssh_key_id":"`+managedID.String()+`","name":"x","interval_days":1}`)
		assert.Equal(t, code, decodeErr(t, rec).Error.Code)
	}

	// GET answers the ETag; the list has no ETag.
	fk.PolicyFn = func(_ context.Context, id uuid.UUID) (sshkeys.Policy, error) {
		if id != policyID {
			return sshkeys.Policy{}, sshkeys.ErrNotFound
		}
		p := samplePolicy(true, 3)
		last := runID
		p.LastRunID, p.LastRunStatus, p.LastRunResult = &last, sshkeys.StatusCancelled, sshkeys.ReasonNoticeUndelivered
		return p, nil
	}
	pp := "/api/v1/rotation/policies/" + policyID.String()
	rec = call(h, http.MethodGet, pp, "alice_read_auditor", "")
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, `"3"`, rec.Header().Get("ETag"))
	m = decodeMap(t, rec.Body.Bytes())
	assert.Equal(t, runID.String(), m["last_run_id"])
	assert.Equal(t, "cancelled", m["last_run_status"])
	assert.Equal(t, map[string]any{"code": "ALC-ROT-0017", "reason": "rotation.notice_undelivered"}, m["last_run_result"], "M4: why the run did not happen")
	assert.Equal(t, "2026-12-30T09:00:00Z", m["next_run_at"])
	assert.Equal(t, http.StatusNotFound, call(h, http.MethodGet, "/api/v1/rotation/policies/"+uuid.NewString(), "auditor", "").Code)
	assert.Equal(t, http.StatusNotFound, call(h, http.MethodGet, "/api/v1/rotation/policies/x", "auditor", "").Code)
	fk.PoliciesFn = func(context.Context) ([]sshkeys.Policy, error) { return nil, nil }
	rec = call(h, http.MethodGet, "/api/v1/rotation/policies", "auditor", "")
	assert.JSONEq(t, `{"items":[]}`, rec.Body.String())

	// If-Match on every change of a policy.
	var gotVersion int
	var gotPatch sshkeys.PolicyPatch
	fk.UpdatePolicyFn = func(_ context.Context, _ inventory.Actor, _ uuid.UUID, v int, p sshkeys.PolicyPatch) (sshkeys.Policy, error) {
		gotVersion, gotPatch = v, p
		return samplePolicy(false, v+1), nil
	}
	fk.DeletePolicyFn = func(_ context.Context, _ inventory.Actor, _ uuid.UUID, v int) error {
		gotVersion = v
		return nil
	}
	fk.SetPolicyEnabledFn = func(_ context.Context, _ inventory.Actor, _ uuid.UUID, v int, on bool) (sshkeys.Policy, error) {
		gotVersion = v
		return samplePolicy(on, v+1), nil
	}
	changes := []struct{ method, path, id, body string }{
		{http.MethodPatch, pp, "admin", `{"name":"ci2"}`},
		{http.MethodDelete, pp, "admin", ""},
		{http.MethodPost, pp + "/actions/enable", "admin-stepup", ""},
		{http.MethodPost, pp + "/actions/disable", "admin", ""},
	}
	for _, c := range changes {
		fk.reset()
		for _, hdr := range []map[string]string{nil, {"If-Match": "3"}, {"If-Match": `W/"3"`}, {"If-Match": `"3", "4"`}, {"If-Match": "*"}, {"If-Match": `"0"`}} {
			rec := callWith(h, c.method, c.path, c.id, c.body, hdr)
			assert.Equal(t, http.StatusPreconditionFailed, rec.Code, "%s %s %v", c.method, c.path, hdr)
			assert.Equal(t, "ALC-SYS-0008", decodeErr(t, rec).Error.Code)
		}
		assert.Empty(t, fk.Calls(), "%s %s: the service is never asked without a valid version", c.method, c.path)
		rec := callWith(h, c.method, c.path, c.id, c.body, map[string]string{"If-Match": `"3"`})
		assert.Less(t, rec.Code, 300, "%s %s: %s", c.method, c.path, rec.Body.String())
		assert.Equal(t, 3, gotVersion, c.path)
		if rec.Code == http.StatusOK {
			assert.Equal(t, `"4"`, rec.Header().Get("ETag"), c.path)
		}
	}
	require.NotNil(t, gotPatch.Name)
	assert.Equal(t, "ci2", *gotPatch.Name)
	assert.Nil(t, gotPatch.IntervalDays)
	rec = callWith(h, http.MethodDelete, pp, "admin", "", map[string]string{"If-Match": `"3"`})
	assert.Equal(t, http.StatusNoContent, rec.Code)
	assert.Empty(t, rec.Body.String())

	// A stale version is the service's answer: 412.
	fk.UpdatePolicyFn = func(context.Context, inventory.Actor, uuid.UUID, int, sshkeys.PolicyPatch) (sshkeys.Policy, error) {
		return sshkeys.Policy{}, sshkeys.ErrVersionMismatch
	}
	fk.DeletePolicyFn = func(context.Context, inventory.Actor, uuid.UUID, int) error { return sshkeys.ErrRotationInProgress }
	rec = callWith(h, http.MethodPatch, pp, "admin", `{"name":"x"}`, map[string]string{"If-Match": `"2"`})
	assert.Equal(t, http.StatusPreconditionFailed, rec.Code)
	rec = callWith(h, http.MethodDelete, pp, "admin", "", map[string]string{"If-Match": `"2"`})
	assert.Equal(t, "ALC-ROT-0002", decodeErr(t, rec).Error.Code, "a started run refuses the deletion")
	// Unknown or repeated keys, and a body on enable, are refused before the service.
	fk.reset()
	assert.Equal(t, http.StatusBadRequest, callWith(h, http.MethodPatch, pp, "admin", `{"enabled":true}`, map[string]string{"If-Match": `"3"`}).Code)
	assert.Equal(t, http.StatusBadRequest, callWith(h, http.MethodPatch, pp, "admin", `{"name":"a","name":"b"}`, map[string]string{"If-Match": `"3"`}).Code)
	assert.Equal(t, http.StatusBadRequest, callWith(h, http.MethodPost, pp+"/actions/enable", "admin-stepup", `{"x":1}`, map[string]string{"If-Match": `"3"`}).Code)
	assert.Equal(t, http.StatusNotFound, callWith(h, http.MethodPatch, "/api/v1/rotation/policies/x", "admin", `{}`, map[string]string{"If-Match": `"3"`}).Code)
	assert.Empty(t, fk.Calls())
}

// TestEditOfEnabledPolicySwitchesItOff (S2, API level): an operate token may change a policy that is on, and the
// answer shows it switched off (the service's rule); the token can never switch it on again, nor can a session
// without step-up; switching it on is the enable route with step-up only. The handler passes no "enabled" field and
// cannot be asked to keep it on.
func TestEditOfEnabledPolicySwitchesItOff(t *testing.T) {
	d, fk, _ := sshDeps(t)
	enabled := true
	version := 3
	fk.UpdatePolicyFn = func(_ context.Context, _ inventory.Actor, _ uuid.UUID, v int, p sshkeys.PolicyPatch) (sshkeys.Policy, error) {
		if v != version {
			return sshkeys.Policy{}, sshkeys.ErrVersionMismatch
		}
		if p.IntervalDays != nil || p.OverlapDays != nil || p.NotifyBeforeHours != nil || p.NewKeyType != nil {
			enabled = false // the service's S2 rule, modelled
		}
		version++
		return samplePolicy(enabled, version), nil
	}
	fk.SetPolicyEnabledFn = func(_ context.Context, _ inventory.Actor, _ uuid.UUID, v int, on bool) (sshkeys.Policy, error) {
		if v != version {
			return sshkeys.Policy{}, sshkeys.ErrVersionMismatch
		}
		enabled = on
		version++
		return samplePolicy(enabled, version), nil
	}
	h := NewHandler(d)
	pp := "/api/v1/rotation/policies/" + policyID.String()
	rec := callWith(h, http.MethodPatch, pp, "alice_operate_admin", `{"interval_days":1,"overlap_days":0,"notify_before_hours":1,"new_key_type":"rsa-4096"}`,
		map[string]string{"If-Match": `"3"`})
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	m := decodeMap(t, rec.Body.Bytes())
	assert.Equal(t, false, m["enabled"], "an edit of a policy that is on leaves it off")
	assert.Nil(t, m["next_run_at"])
	assert.Equal(t, `"4"`, rec.Header().Get("ETag"))
	assert.Equal(t, http.StatusBadRequest, callWith(h, http.MethodPatch, pp, "alice_operate_admin", `{"enabled":true}`, map[string]string{"If-Match": `"4"`}).Code,
		"PATCH cannot switch a policy on")

	fk.reset()
	for id, code := range map[string]string{"alice_operate_admin": "ALC-AUTH-0002", "admin": "ALC-AUTH-0003", "operator-stepup": "ALC-AUTH-0002"} {
		rec = callWith(h, http.MethodPost, pp+"/actions/enable", id, "", map[string]string{"If-Match": `"4"`})
		assert.Equal(t, code, decodeErr(t, rec).Error.Code, id)
	}
	assert.Empty(t, fk.Calls(), "no refused caller switches it on")
	assert.False(t, enabled)
	rec = callWith(h, http.MethodPost, pp+"/actions/enable", "admin-stepup", "", map[string]string{"If-Match": `"4"`})
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, true, decodeMap(t, rec.Body.Bytes())["enabled"])
	// A token may switch it off again (a safety action).
	rec = callWith(h, http.MethodPost, pp+"/actions/disable", "alice_operate_admin", "", map[string]string{"If-Match": `"5"`})
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, false, decodeMap(t, rec.Body.Bytes())["enabled"])
}

// TestPreviewAndRunHandlers: the preview's fields of C13; Run now needs a well-formed digest (422 before the service)
// and answers 202 with the run; a changed plan is 409 ALC-ROT-0003.
func TestPreviewAndRunHandlers(t *testing.T) {
	d, fk, _ := sshDeps(t)
	at := time.Date(2026, 10, 2, 9, 0, 0, 0, time.FixedZone("x", 7200))
	loc, tgt := uuid.New(), uuid.New()
	fk.PreviewFn = func(_ context.Context, a inventory.Actor, id uuid.UUID) (sshkeys.Preview, error) {
		assert.Equal(t, policyID, id)
		return sshkeys.Preview{PolicyID: policyID, Digest: digest64, PlannedFor: at, Emailed: true, Plan: plan.Plan{
			KeyID: managedID, Fingerprint: "SHA256:old", NewKeyType: "ed25519", Overlap: 1440, Changes: 1, Skips: 1,
			Actions: []plan.Action{
				{N: 1, LocationID: loc, TargetID: tgt, TargetName: "web-01", OSUser: "deploy", FilePath: "/home/deploy/.ssh/authorized_keys",
					Options: `from="10.0.0.1"`, Verify: false, VerifyNote: plan.NoteFromOption, RemoveLine: `from="10.0.0.1" ssh-ed25519 AAAA old`,
					AddLine: `from="10.0.0.1" ed25519 (new key) alice:ci:2026-10-02`},
				{N: 2, LocationID: uuid.New(), TargetID: tgt, TargetName: "web-01", OSUser: "<script>", FilePath: "/root/x", Skip: plan.SkipDuplicateLines},
			}}}, nil
	}
	h := NewHandler(d)
	pp := "/api/v1/rotation/policies/" + policyID.String()
	rec := call(h, http.MethodPost, pp+"/actions/preview", "alice_operate_admin", "")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var pv map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &pv))
	assert.Equal(t, digest64, pv["plan_digest"])
	assert.Equal(t, "2026-10-02T07:00:00Z", pv["planned_for"])
	assert.Equal(t, true, pv["emailed"])
	assert.EqualValues(t, 1, pv["change_count"])
	assert.EqualValues(t, 1, pv["skip_count"])
	assert.EqualValues(t, 1440, pv["overlap_minutes"])
	assert.Equal(t, "ed25519", pv["new_key_type"])
	actions := pv["actions"].([]any)
	require.Len(t, actions, 2)
	first := actions[0].(map[string]any)
	assert.Equal(t, "", first["skip_reason"])
	assert.Equal(t, "from_option", first["verify_note"])
	assert.Equal(t, loc.String(), first["location_id"])
	second := actions[1].(map[string]any)
	assert.Equal(t, "duplicate_lines", second["skip_reason"])
	assert.Equal(t, "<script>", second["os_user"], "a server's user name is data")
	assert.Equal(t, http.StatusBadRequest, call(h, http.MethodPost, pp+"/actions/preview", "admin", `{"x":1}`).Code)
	fk.PreviewFn = func(context.Context, inventory.Actor, uuid.UUID) (sshkeys.Preview, error) {
		return sshkeys.Preview{}, license.ErrLocked
	}
	assert.Equal(t, "ALC-LIC-0001", decodeErr(t, call(h, http.MethodPost, pp+"/actions/preview", "admin", "")).Error.Code)

	var gotDigest string
	fk.RunNowFn = func(_ context.Context, a inventory.Actor, id uuid.UUID, dg string) (sshkeys.Rotation, error) {
		assert.Equal(t, adminID, a.UserID)
		gotDigest = dg
		return sampleRotation(sshkeys.StatusAddingNew), nil
	}
	fk.reset()
	for body, field := range map[string]string{`{"plan_digest":"abc"}`: "validation.pattern", `{"plan_digest":"` + strings.Repeat("AB", 32) + `"}`: "validation.pattern",
		`{"plan_digest":""}`: "validation.required", `{}`: "validation.required"} {
		rec = call(h, http.MethodPost, pp+"/actions/run", "admin-stepup", body)
		assert.Equal(t, http.StatusUnprocessableEntity, rec.Code, body)
		assert.Equal(t, []validate.FieldError{{Field: "plan_digest", Code: field}}, errorDetails(t, rec), body)
	}
	assert.Equal(t, http.StatusBadRequest, call(h, http.MethodPost, pp+"/actions/run", "admin-stepup", "").Code)
	assert.Empty(t, fk.Calls())
	rec = call(h, http.MethodPost, pp+"/actions/run", "admin-stepup", `{"plan_digest":"`+digest64+`"}`)
	require.Equal(t, http.StatusAccepted, rec.Code, rec.Body.String())
	assert.JSONEq(t, `{"rotation_id":"`+runID.String()+`","status_url":"/api/v1/rotation/runs/`+runID.String()+`"}`, rec.Body.String())
	assert.Equal(t, digest64, gotDigest)

	for err, want := range map[error]struct {
		status int
		code   string
	}{
		sshkeys.ErrPlanChanged:        {http.StatusConflict, "ALC-ROT-0003"},
		sshkeys.ErrRotationInProgress: {http.StatusConflict, "ALC-ROT-0002"},
		sshkeys.ErrNothingToRotate:    {http.StatusConflict, "ALC-ROT-0004"},
		sshkeys.ErrPlanTooLarge:       {http.StatusConflict, "ALC-ROT-0019"},
		sshkeys.ErrGenerateBusy:       {http.StatusServiceUnavailable, "ALC-KEY-0011"},
		sshkeys.ErrNotFound:           {http.StatusNotFound, "ALC-SYS-0001"},
	} {
		fk.RunNowFn = func(context.Context, inventory.Actor, uuid.UUID, string) (sshkeys.Rotation, error) {
			return sshkeys.Rotation{}, err
		}
		rec = call(h, http.MethodPost, pp+"/actions/run", "admin-stepup", `{"plan_digest":"`+digest64+`"}`)
		assert.Equal(t, want.status, rec.Code, err.Error())
		assert.Equal(t, want.code, decodeErr(t, rec).Error.Code, err.Error())
	}
}

// TestRunDTOActionsAllowed: actions_allowed is sshkeys.AllowedActions with the license gate's answer; the run's
// result and every place's error are errorRefs (F4); kept_count and skipped places are shown (S11).
func TestRunDTOActionsAllowed(t *testing.T) {
	d, fk, _ := sshDeps(t)
	run := sampleRotation(sshkeys.StatusOverlap)
	fk.RotationFn = func(_ context.Context, id uuid.UUID) (sshkeys.Rotation, error) {
		if id != runID {
			return sshkeys.Rotation{}, sshkeys.ErrNotFound
		}
		return run, nil
	}
	path := "/api/v1/rotation/runs/" + runID.String()
	get := func() map[string]any {
		rec := call(NewHandler(d), http.MethodGet, path, "admin", "") // an Administrator session may take every decision
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		return decodeMap(t, rec.Body.Bytes())
	}
	m := get()
	assert.Equal(t, []any{"finish_now", "abort"}, m["actions_allowed"])
	assert.EqualValues(t, 1, m["kept_count"])
	assert.EqualValues(t, 1, m["skip_count"])
	assert.Nil(t, m["result"])
	locs := m["locations"].([]any)
	require.Len(t, locs, 2)
	assert.Equal(t, "sshd_unreadable", locs[1].(map[string]any)["skip_reason"])
	assert.Equal(t, "skipped", locs[1].(map[string]any)["state"])
	assert.Nil(t, locs[0].(map[string]any)["error"])
	assert.Len(t, m["steps"].([]any), 1)
	assert.Equal(t, map[string]any{}, m["steps"].([]any)[0].(map[string]any)["params"])

	d.License.(*fakeLicense).set(license.ErrLocked)
	locked := []any{}
	for _, a := range sshkeys.AllowedActions(run, false) {
		locked = append(locked, a)
	}
	assert.Equal(t, locked, get()["actions_allowed"], "in lock the service's answer with the gate closed")
	assert.NotContains(t, get()["actions_allowed"], "finish_now")

	d.License.(*fakeLicense).set(nil)
	run = sampleRotation(sshkeys.StatusVerifyingNew)
	run.AwaitingDecision = true
	run.Locations[1].State, run.Locations[1].SkipReason, run.Locations[1].VerifyNote = sshkeys.LocUnverifiable, "", plan.NoteFromOption
	assert.Equal(t, []any{"keep_old", "abort"}, get()["actions_allowed"])

	run = sampleRotation(sshkeys.StatusAborted)
	run.ResultCode = sshkeys.ReasonVerifyFailed
	run.Locations[0].State, run.Locations[0].ErrorCode = sshkeys.LocUndoFailed, sshkeys.ReasonOldKeyGone
	run.Steps = nil
	m = get()
	assert.Equal(t, []any{}, m["actions_allowed"])
	assert.Equal(t, map[string]any{"code": "ALC-ROT-0007", "reason": "rotation.verify_failed"}, m["result"])
	assert.Equal(t, map[string]any{"code": "ALC-ROT-0018", "reason": "rotation.old_key_gone"}, m["locations"].([]any)[0].(map[string]any)["error"])
	assert.Equal(t, []any{}, m["steps"], "the detail always has its steps")

	// A paused run: exactly what the service offers with the gate open (Continue appears once the renewal notice is out).
	run = sampleRotation(sshkeys.StatusAddingNew)
	run.PausedLicense = true
	var want []any
	for _, a := range sshkeys.AllowedActions(run, true) {
		want = append(want, a)
	}
	assert.Equal(t, want, get()["actions_allowed"])

	// The list has no steps, filters by policy and key, pages by cursor.
	var gotF sshkeys.RotationFilter
	fk.RotationSummariesFn = func(_ context.Context, f sshkeys.RotationFilter) ([]sshkeys.RotationSummary, string, error) {
		gotF = f
		return []sshkeys.RotationSummary{sampleSummary()}, "next-page", nil
	}
	rec := call(NewHandler(d), http.MethodGet, "/api/v1/rotation/runs?policy_id="+policyID.String()+"&ssh_key_id="+managedID.String()+"&cursor=c1&limit=10", "alice_read_auditor", "")
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, sshkeys.RotationFilter{PolicyID: policyID, KeyID: managedID, Cursor: "c1", Limit: 10}, gotF)
	var page struct {
		Items      []map[string]any `json:"items"`
		NextCursor *string          `json:"next_cursor"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &page))
	require.Len(t, page.Items, 1)
	assert.NotContains(t, page.Items[0], "steps")
	require.NotNil(t, page.NextCursor)
	assert.Equal(t, "next-page", *page.NextCursor)
	fk.RotationSummariesFn = func(context.Context, sshkeys.RotationFilter) ([]sshkeys.RotationSummary, string, error) {
		return nil, "", sshkeys.ErrBadCursor
	}
	assert.Equal(t, "ALC-SYS-0004", decodeErr(t, call(NewHandler(d), http.MethodGet, "/api/v1/rotation/runs?cursor=bad", "auditor", "")).Error.Code)
	fk.RotationSummariesFn = func(context.Context, sshkeys.RotationFilter) ([]sshkeys.RotationSummary, string, error) {
		return nil, "", nil
	}
	assert.JSONEq(t, `{"items":[],"next_cursor":null}`, call(NewHandler(d), http.MethodGet, "/api/v1/rotation/runs", "auditor", "").Body.String())
	for _, q := range []string{"policy_id=x", "ssh_key_id=x", "limit=0", "limit=201", "cursor=" + strings.Repeat("a", 513)} {
		assert.Equal(t, http.StatusUnprocessableEntity, call(NewHandler(d), http.MethodGet, "/api/v1/rotation/runs?"+q, "auditor", "").Code, q)
	}
	assert.Equal(t, http.StatusNotFound, call(NewHandler(d), http.MethodGet, "/api/v1/rotation/runs/"+uuid.NewString(), "auditor", "").Code)
	assert.Equal(t, http.StatusNotFound, call(NewHandler(d), http.MethodGet, "/api/v1/rotation/runs/x", "auditor", "").Code)
}

// The decisions answer 204, pass the run id, and keep the service's refusals; keep-old validates its ids before the
// service is asked.
func TestRunDecisionHandlers(t *testing.T) {
	d, fk, _ := sshDeps(t)
	var gotRun uuid.UUID
	var gotLocs []uuid.UUID
	decide := func(_ context.Context, a inventory.Actor, id uuid.UUID) error {
		assert.Equal(t, adminID, a.UserID)
		gotRun = id
		return nil
	}
	fk.ContinueFn, fk.FinishNowFn, fk.AbortFn = decide, decide, decide
	fk.KeepOldFn = func(_ context.Context, _ inventory.Actor, id uuid.UUID, l []uuid.UUID) error {
		gotRun, gotLocs = id, l
		return nil
	}
	h := NewHandler(d)
	rp := "/api/v1/rotation/runs/" + runID.String() + "/actions/"
	for _, a := range []string{"continue", "finish-now", "abort"} {
		gotRun = uuid.Nil
		rec := call(h, http.MethodPost, rp+a, "admin-stepup", "")
		assert.Equal(t, http.StatusNoContent, rec.Code, a)
		assert.Equal(t, runID, gotRun, a)
		assert.Equal(t, http.StatusNoContent, call(h, http.MethodPost, rp+a, "admin-stepup", "{}").Code, a)
		assert.Equal(t, http.StatusBadRequest, call(h, http.MethodPost, rp+a, "admin-stepup", `{"x":1}`).Code, a)
		assert.Equal(t, http.StatusNotFound, call(h, http.MethodPost, "/api/v1/rotation/runs/x/actions/"+a, "admin-stepup", "").Code, a)
	}
	other := uuid.New()
	rec := call(h, http.MethodPost, rp+"keep-old", "admin-stepup", `{"location_ids":["`+locID.String()+`","`+other.String()+`"]}`)
	require.Equal(t, http.StatusNoContent, rec.Code, rec.Body.String())
	assert.Equal(t, []uuid.UUID{locID, other}, gotLocs)

	fk.reset()
	many := make([]string, maxKeepOld+1)
	for i := range many {
		many[i] = `"` + uuid.NewString() + `"`
	}
	for body, code := range map[string]string{
		`{"location_ids":[]}`: validate.Required, `{"location_ids":["x"]}`: validate.Pattern,
		`{"location_ids":["` + locID.String() + `","` + locID.String() + `"]}`: validate.Duplicate,
		`{"location_ids":[` + strings.Join(many, ",") + `]}`:                   validate.OutOfRange,
	} {
		rec := call(h, http.MethodPost, rp+"keep-old", "admin-stepup", body)
		assert.Equal(t, http.StatusUnprocessableEntity, rec.Code, code)
		assert.Equal(t, code, errorDetails(t, rec)[0].Code)
	}
	assert.Equal(t, http.StatusBadRequest, call(h, http.MethodPost, rp+"keep-old", "admin-stepup", `{"location_ids":"x"}`).Code)
	assert.Empty(t, fk.Calls())

	// The service's refusals: a run that does not wait (409), a renewal notice not yet queued, the lock.
	for err, code := range map[error]string{sshkeys.ErrNotWaiting: "ALC-ROT-0005", license.ErrLocked: "ALC-LIC-0001",
		sshkeys.ErrNotFound: "ALC-SYS-0001", errors.New("boom"): "ALC-SYS-0003"} {
		fk.ContinueFn = func(context.Context, inventory.Actor, uuid.UUID) error { return err }
		fk.KeepOldFn = func(context.Context, inventory.Actor, uuid.UUID, []uuid.UUID) error { return err }
		assert.Equal(t, code, decodeErr(t, call(h, http.MethodPost, rp+"continue", "admin-stepup", "")).Error.Code)
		assert.Equal(t, code, decodeErr(t, call(h, http.MethodPost, rp+"keep-old", "admin-stepup", `{"location_ids":["`+locID.String()+`"]}`)).Error.Code)
	}
}

// Every rotation route answers 404 for an id that is not a UUID without asking the service, and passes a service
// failure through fail (here an unknown error: the generic internal error).
func TestRotationRoutesRefuseBadIDsAndPassFailures(t *testing.T) {
	d, fk, _ := sshDeps(t)
	h := NewHandler(d)
	ifm := map[string]string{"If-Match": `"3"`}
	for _, c := range []struct{ method, path, id, body string }{
		{http.MethodGet, "/api/v1/rotation/policies/x", "admin", ""},
		{http.MethodPatch, "/api/v1/rotation/policies/x", "admin", `{}`},
		{http.MethodDelete, "/api/v1/rotation/policies/x", "admin", ""},
		{http.MethodPost, "/api/v1/rotation/policies/x/actions/enable", "admin-stepup", ""},
		{http.MethodPost, "/api/v1/rotation/policies/x/actions/disable", "admin", ""},
		{http.MethodPost, "/api/v1/rotation/policies/x/actions/preview", "admin", ""},
		{http.MethodPost, "/api/v1/rotation/policies/x/actions/run", "admin-stepup", `{"plan_digest":"` + digest64 + `"}`},
		{http.MethodPost, "/api/v1/rotation/runs/x/actions/keep-old", "admin-stepup", `{"location_ids":["` + locID.String() + `"]}`},
	} {
		assert.Equal(t, http.StatusNotFound, callWith(h, c.method, c.path, c.id, c.body, ifm).Code, c.path)
	}
	assert.Empty(t, fk.Calls())

	boom := errors.New("boom")
	fk.PoliciesFn = func(context.Context) ([]sshkeys.Policy, error) { return nil, boom }
	fk.DeletePolicyFn = func(context.Context, inventory.Actor, uuid.UUID, int) error { return boom }
	fk.SetPolicyEnabledFn = func(context.Context, inventory.Actor, uuid.UUID, int, bool) (sshkeys.Policy, error) {
		return sshkeys.Policy{}, boom
	}
	fk.UpdatePolicyFn = func(context.Context, inventory.Actor, uuid.UUID, int, sshkeys.PolicyPatch) (sshkeys.Policy, error) {
		return sshkeys.Policy{}, boom
	}
	fk.RotationFn = func(context.Context, uuid.UUID) (sshkeys.Rotation, error) { return sshkeys.Rotation{}, boom }
	pp := "/api/v1/rotation/policies/" + policyID.String()
	for _, c := range []struct{ method, path, id, body string }{
		{http.MethodGet, "/api/v1/rotation/policies", "auditor", ""},
		{http.MethodDelete, pp, "admin", ""},
		{http.MethodPatch, pp, "admin", `{"name":"x"}`},
		{http.MethodPost, pp + "/actions/enable", "admin-stepup", ""},
		{http.MethodGet, "/api/v1/rotation/runs/" + runID.String(), "auditor", ""},
	} {
		rec := callWith(h, c.method, c.path, c.id, c.body, ifm)
		assert.Equal(t, http.StatusInternalServerError, rec.Code, c.path)
		assert.NotContains(t, rec.Body.String(), "boom", c.path)
	}
	assert.Equal(t, http.StatusBadRequest, callWith(h, http.MethodPost, pp+"/actions/disable", "admin", `{"x":1}`, ifm).Code)
	assert.Equal(t, http.StatusBadRequest, callWith(h, http.MethodPost, "/api/v1/rotation/runs/"+runID.String()+"/actions/keep-old", "admin-stepup", `{"x":1}`, nil).Code)
	assert.Equal(t, http.StatusNotFound, call(h, http.MethodGet, "/api/v1/ssh-keys/x", "auditor", "").Code)
}

// An explicit notify_before_hours 0 or new_key_type "" is a validation error, never a silent default; absent fields
// keep the defaults (review M4). The planner's unknown new key type marks the field (review M13).
func TestPolicyFieldsAreNeverSilentlyDefaulted(t *testing.T) {
	d, fk, _ := sshDeps(t)
	fk.CreatePolicyFn = func(context.Context, inventory.Actor, sshkeys.PolicyInput) (sshkeys.Policy, error) {
		return samplePolicy(false, 1), nil
	}
	fk.UpdatePolicyFn = func(context.Context, inventory.Actor, uuid.UUID, int, sshkeys.PolicyPatch) (sshkeys.Policy, error) {
		return samplePolicy(false, 4), nil
	}
	h := NewHandler(d)
	pp := "/api/v1/rotation/policies/" + policyID.String()
	ifm := map[string]string{"If-Match": `"3"`}
	base := `"ssh_key_id":"` + managedID.String() + `","name":"ci","interval_days":90`
	for body, want := range map[string]validate.FieldError{
		`{` + base + `,"notify_before_hours":0}`: {Field: "notify_before_hours", Code: validate.OutOfRange, Params: map[string]string{"min": "1", "max": "168"}},
		`{` + base + `,"new_key_type":""}`:       {Field: "new_key_type", Code: validate.OneOf, Params: map[string]string{"values": "same, ed25519, rsa-3072, rsa-4096, ecdsa-p256"}},
	} {
		fk.reset()
		rec := call(h, http.MethodPost, "/api/v1/rotation/policies", "admin", body)
		assert.Equal(t, http.StatusUnprocessableEntity, rec.Code, body)
		assert.Equal(t, []validate.FieldError{want}, errorDetails(t, rec), body)
		assert.Empty(t, fk.Calls(), body)
	}
	for body, field := range map[string]string{`{"notify_before_hours":0}`: "notify_before_hours", `{"new_key_type":""}`: "new_key_type"} {
		fk.reset()
		rec := callWith(h, http.MethodPatch, pp, "admin", body, ifm)
		assert.Equal(t, http.StatusUnprocessableEntity, rec.Code, body)
		assert.Equal(t, field, errorDetails(t, rec)[0].Field, body)
		assert.Empty(t, fk.Calls(), body)
	}
	assert.Equal(t, http.StatusCreated, call(h, http.MethodPost, "/api/v1/rotation/policies", "admin", `{`+base+`}`).Code, "absent fields keep the defaults")
	fk.UpdatePolicyFn = func(context.Context, inventory.Actor, uuid.UUID, int, sshkeys.PolicyPatch) (sshkeys.Policy, error) {
		return sshkeys.Policy{}, fmt.Errorf("plan: %w", plan.ErrNewKeyType)
	}
	rec := callWith(h, http.MethodPatch, pp, "admin", `{"new_key_type":"same"}`, ifm)
	assert.Equal(t, http.StatusUnprocessableEntity, rec.Code)
	assert.Equal(t, []validate.FieldError{{Field: "new_key_type", Code: validate.OneOf, Params: map[string]string{"values": "same, ed25519, rsa-3072, rsa-4096, ecdsa-p256"}}},
		errorDetails(t, rec))
}

// The run list is the service's summary read (counts only, no plan, places or steps); places and steps are on the
// detail only (review I2, re-review N3); the page size is the usual 1-200 (default 50). Each count bucket is the
// service's own (OpenAPI documents them).
func TestRunListHasCountsNotLocations(t *testing.T) {
	d, fk, _ := sshDeps(t)
	var gotLimit int
	fk.RotationSummariesFn = func(_ context.Context, f sshkeys.RotationFilter) ([]sshkeys.RotationSummary, string, error) {
		gotLimit = f.Limit
		return []sshkeys.RotationSummary{sampleSummary()}, "", nil
	}
	run := sampleRotation(sshkeys.StatusRemovingOld)
	run.Locations = append(run.Locations,
		sshkeys.RotationLocation{ID: uuid.New(), N: 3, State: sshkeys.LocRemoved},
		sshkeys.RotationLocation{ID: uuid.New(), N: 4, State: sshkeys.LocRemoveFailed, ErrorCode: sshkeys.ReasonNewKeyFailed},
		sshkeys.RotationLocation{ID: uuid.New(), N: 5, State: sshkeys.LocKeptOld},
		sshkeys.RotationLocation{ID: uuid.New(), N: 6, State: sshkeys.LocCancelled, ErrorCode: sshkeys.ReasonConnectionAccountFile},
		sshkeys.RotationLocation{ID: uuid.New(), N: 7, State: sshkeys.LocRemoving})
	fk.RotationFn = func(context.Context, uuid.UUID) (sshkeys.Rotation, error) { return run, nil }
	h := NewHandler(d)
	rec := call(h, http.MethodGet, "/api/v1/rotation/runs", "auditor", "")
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, 50, gotLimit, "the usual default page")
	assert.Equal(t, []string{"RotationSummaries"}, fk.Calls(), "the list never reads runs in full")
	var page struct {
		Items []map[string]any `json:"items"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &page))
	require.Len(t, page.Items, 1)
	item := page.Items[0]
	for _, k := range []string{"locations", "steps", "actions_allowed", "plan_digest"} {
		assert.NotContains(t, item, k)
	}
	assert.Equal(t, map[string]any{"total": 15.0, "verified": 3.0, "removed": 2.0, "kept": 1.0, "failed": 1.0, "skipped": 2.0,
		"undone": 1.0, "cancelled": 2.0, "in_flight": 3.0}, item["location_counts"])
	assert.Equal(t, map[string]any{"code": "ALC-KEY-0017", "reason": "sshkey.connection_account_file"}, item["result"])
	assert.EqualValues(t, 3, item["kept_count"])
	assert.Equal(t, runID.String(), item["id"])
	call(h, http.MethodGet, "/api/v1/rotation/runs?limit=200", "auditor", "")
	assert.Equal(t, 200, gotLimit)
	assert.Equal(t, http.StatusUnprocessableEntity, call(h, http.MethodGet, "/api/v1/rotation/runs?limit=201", "auditor", "").Code)

	// The detail counts its places with the service's buckets, which add up to the total.
	m := decodeMap(t, call(h, http.MethodGet, "/api/v1/rotation/runs/"+runID.String(), "auditor", "").Body.Bytes())
	assert.Len(t, m["locations"], 7)
	assert.Contains(t, m, "steps")
	assert.Equal(t, map[string]any{"total": 7.0, "verified": 1.0, "removed": 1.0, "kept": 1.0, "failed": 1.0, "skipped": 1.0,
		"undone": 0.0, "cancelled": 1.0, "in_flight": 1.0}, m["location_counts"])
	loc := m["locations"].([]any)[0].(map[string]any)
	assert.EqualValues(t, 2, loc["add_resend_count"])
	assert.Equal(t, "2026-10-01T09:00:00Z", loc["add_resent_at"])
}

func sampleSummary() sshkeys.RotationSummary {
	at := time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC)
	return sshkeys.RotationSummary{ID: runID, PolicyID: policyID, OldKeyID: managedID, OldFingerprint: "SHA256:old", Trigger: sshkeys.TriggerScheduled,
		Status: sshkeys.StatusAborted, NewKeyType: "ed25519", PlannedFor: at, NotifiedAt: at, FinishedAt: &at,
		ResultCode: sshkeys.ReasonConnectionAccountFile, KeptCount: 3, Version: 2,
		Counts: sshkeys.LocationCounts{Total: 15, Verified: 3, Removed: 2, Kept: 1, Failed: 1, Skipped: 2, Undone: 1, Cancelled: 2, InFlight: 3}}
}

// The run shows why Continue waits (notice_state, only while the license allows changes) and why the renewal notice
// could not be queued (notice_error), as closed errorRefs (re-review N7).
func TestRunDTOShowsTheNoticeState(t *testing.T) {
	d, fk, _ := sshDeps(t)
	run := sampleRotation(sshkeys.StatusOverlap)
	run.PausedLicense = true
	run.NoticeState, run.NoticeError = sshkeys.ReasonNoticePending, sshkeys.ReasonNoticeQueueFailed
	fk.RotationFn = func(context.Context, uuid.UUID) (sshkeys.Rotation, error) { return run, nil }
	m := decodeMap(t, call(NewHandler(d), http.MethodGet, "/api/v1/rotation/runs/"+runID.String(), "auditor", "").Body.Bytes())
	assert.Equal(t, map[string]any{"code": "ALC-ROT-0021", "reason": "rotation.notice_pending"}, m["notice_state"])
	assert.Equal(t, map[string]any{"code": "ALC-NTF-0001", "reason": "notify.queue_failed"}, m["notice_error"])
	// In lock the service answers rotation.paused_license (Continue waits for the license); the API passes it on.
	run.NoticeState, run.NoticeError = sshkeys.ReasonPausedLicense, ""
	d.License.(*fakeLicense).set(license.ErrLocked)
	m = decodeMap(t, call(NewHandler(d), http.MethodGet, "/api/v1/rotation/runs/"+runID.String(), "auditor", "").Body.Bytes())
	assert.Equal(t, map[string]any{"code": "ALC-ROT-0011", "reason": "rotation.paused_license"}, m["notice_state"])
	assert.Nil(t, m["notice_error"])
	run.NoticeState, run.NoticeError = "", ""
	d.License.(*fakeLicense).set(nil)
	m = decodeMap(t, call(NewHandler(d), http.MethodGet, "/api/v1/rotation/runs/"+runID.String(), "auditor", "").Body.Bytes())
	assert.Contains(t, m, "notice_state")
	assert.Nil(t, m["notice_state"])
	assert.Nil(t, m["notice_error"])
}

// Stop and undo is accepted while the license is locked (its undo follows L-86); the other decisions are refused then.
// The decisions' refusals keep their codes: Keep old and Finish now in lock (403 ALC-LIC-0001) and on a paused run
// (409 ALC-ROT-0005); Run now on a run cancelled meanwhile (409 ALC-ROT-0005).
func TestAbortIsAllowedInLock(t *testing.T) {
	d, fk, _ := sshDeps(t)
	succeeding(fk, &fakeInventory{})
	d.License.(*fakeLicense).set(license.ErrLocked)
	h := NewHandler(d)
	rp := "/api/v1/rotation/runs/" + runID.String() + "/actions/"
	assert.Equal(t, http.StatusNoContent, call(h, http.MethodPost, rp+"abort", "alice_operate_admin", "").Code)
	assert.Equal(t, http.StatusNoContent, call(h, http.MethodPost, rp+"abort", "admin", "").Code)
	for _, a := range []string{"continue", "finish-now"} {
		assert.Equal(t, "ALC-LIC-0001", decodeErr(t, call(h, http.MethodPost, rp+a, "admin-stepup", "")).Error.Code, a)
	}
	for _, rt := range newServer(Deps{}).apiRoutes() {
		if rt.pattern == "/api/v1/rotation/runs/{id}/actions/abort" {
			assert.Equal(t, license.ClassAlways, rt.lic)
		}
	}

	d.License.(*fakeLicense).set(nil)
	for err, want := range map[error]string{license.ErrLocked: "ALC-LIC-0001", sshkeys.ErrNotWaiting: "ALC-ROT-0005"} {
		fk.KeepOldFn = func(context.Context, inventory.Actor, uuid.UUID, []uuid.UUID) error { return err }
		fk.FinishNowFn = func(context.Context, inventory.Actor, uuid.UUID) error { return err }
		h = NewHandler(d)
		assert.Equal(t, want, decodeErr(t, call(h, http.MethodPost, rp+"keep-old", "admin-stepup", `{"location_ids":["`+locID.String()+`"]}`)).Error.Code)
		assert.Equal(t, want, decodeErr(t, call(h, http.MethodPost, rp+"finish-now", "admin-stepup", "")).Error.Code)
	}
	fk.RunNowFn = func(context.Context, inventory.Actor, uuid.UUID, string) (sshkeys.Rotation, error) {
		return sshkeys.Rotation{}, sshkeys.ErrNotWaiting
	}
	rec := call(h, http.MethodPost, "/api/v1/rotation/policies/"+policyID.String()+"/actions/run", "admin-stepup", `{"plan_digest":"`+digest64+`"}`)
	assert.Equal(t, http.StatusConflict, rec.Code)
	assert.Equal(t, "ALC-ROT-0005", decodeErr(t, rec).Error.Code)

	// A place refused at send time carries its closed reason.
	run := sampleRotation(sshkeys.StatusAborted)
	run.ResultCode = sshkeys.ReasonConnectionFilesUnknown
	run.Locations[0].State, run.Locations[0].ErrorCode = sshkeys.LocCancelled, sshkeys.ReasonConnectionAccountFile
	fk.RotationFn = func(context.Context, uuid.UUID) (sshkeys.Rotation, error) { return run, nil }
	m := decodeMap(t, call(h, http.MethodGet, "/api/v1/rotation/runs/"+runID.String(), "auditor", "").Body.Bytes())
	assert.Equal(t, map[string]any{"code": "ALC-KEY-0014", "reason": "sshkey.connection_files_unknown"}, m["result"])
	assert.Equal(t, map[string]any{"code": "ALC-KEY-0017", "reason": "sshkey.connection_account_file"}, m["locations"].([]any)[0].(map[string]any)["error"])
}

// actions_allowed is the service's list cut to what the caller may do on the matching routes, from the same rbac
// table: an Administrator session gets every decision (it can step up), an operate token of an Administrator only
// abort (rotation.manage), every other caller none.
func TestRunActionsFollowTheCaller(t *testing.T) {
	d, fk, _ := sshDeps(t)
	run := sampleRotation(sshkeys.StatusOverlap) // the service offers finish_now and abort
	require.Equal(t, []string{"finish_now", "abort"}, sshkeys.AllowedActions(run, true))
	fk.RotationFn = func(context.Context, uuid.UUID) (sshkeys.Rotation, error) { return run, nil }
	h := NewHandler(d)
	for id, want := range map[string][]any{
		"admin": {"finish_now", "abort"}, "admin-stepup": {"finish_now", "abort"},
		"alice_operate_admin": {"abort"}, "alice_read_admin": {},
		"operator": {}, "operator-stepup": {}, "auditor-stepup": {}, "alice_operate_operator": {}, "alice_read_auditor": {},
	} {
		m := decodeMap(t, call(h, http.MethodGet, "/api/v1/rotation/runs/"+runID.String(), id, "").Body.Bytes())
		assert.Equal(t, want, m["actions_allowed"], id)
	}
}

// A place refused at send time for a planner reason carries rotation.skipped_at_send as its error and the planner's
// reason in skip_reason (the web shows rotation.skip.<skip_reason>).
func TestSkippedAtSendNamesItsSkipReason(t *testing.T) {
	d, fk, _ := sshDeps(t)
	run := sampleRotation(sshkeys.StatusAddingNew)
	run.Locations[0].State, run.Locations[0].ErrorCode, run.Locations[0].SkipReason = sshkeys.LocCancelled, sshkeys.ReasonSkippedAtSend, plan.SkipSSHDUnreadable
	fk.RotationFn = func(context.Context, uuid.UUID) (sshkeys.Rotation, error) { return run, nil }
	m := decodeMap(t, call(NewHandler(d), http.MethodGet, "/api/v1/rotation/runs/"+runID.String(), "auditor", "").Body.Bytes())
	loc := m["locations"].([]any)[0].(map[string]any)
	assert.Equal(t, map[string]any{"code": "ALC-ROT-0024", "reason": "rotation.skipped_at_send"}, loc["error"])
	assert.Equal(t, "sshd_unreadable", loc["skip_reason"])
	assert.Equal(t, "cancelled", loc["state"])
}
