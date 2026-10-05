//go:build integration

package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/rbac"
)

// Authorization of the Phase 6 routes over the wire (Review Focus 5; R41 rows 3-7, 24, 25 as amended by S2): every
// role, with and without step-up, every token scope, in and out of licence lock, and ids of the wrong kind.

// caller is one identity of the matrix.
type caller struct {
	name   string
	c      *client
	stepUp func() // nil: never steps up
}

// callers builds the identities: the Administrator's session (stepped up before each call), a second Administrator's
// session that never stepped up, the Administrator's operate and read tokens, an Operator's session (stepped up) and
// operate token, an Auditor's session (stepped up) and read token.
func (e *keyEnv) callers(days int) []caller {
	e.t.Helper()
	bea := e.createUser(e.admin, e.adminAcct, "bea", "admin", "a second administrator password")
	bc := e.freshClient()
	e.firstSignIn(bc, bea)
	e.signedIn(bc, bea)
	otto := e.createUser(e.admin, e.adminAcct, "otto", "operator", operatorPassword)
	oc := e.freshClient()
	e.firstSignIn(oc, otto)
	e.signedIn(oc, otto)
	audrey := e.createUser(e.admin, e.adminAcct, "audrey", "auditor", operatorPassword)
	ac := e.freshClient()
	e.firstSignIn(ac, audrey)
	e.signedIn(ac, audrey)
	token := func(c *client, a *account, scope string) *client {
		tok, _ := createToken(e.t, e.stack, c, a, scope, days)
		api := e.freshClient()
		api.bearer = tok
		return api
	}
	return []caller{
		{"admin session, step-up", e.admin, func() { e.stepUp(e.admin, e.adminAcct) }},
		{"admin session, no step-up", bc, nil},
		{"admin operate token", token(e.admin, e.adminAcct, "operate"), nil},
		{"admin read token", token(e.admin, e.adminAcct, "read"), nil},
		{"operator session, step-up", oc, func() { e.stepUp(oc, otto) }},
		{"operator operate token", token(oc, otto, "operate"), nil},
		{"auditor session, step-up", ac, func() { e.stepUp(ac, audrey) }},
		{"auditor read token", token(ac, audrey, "read"), nil},
	}
}

// phase6Route is one non-GET Phase 6 route with a body its handler refuses (or an id that does not exist), so a call
// that passes the guard changes nothing.
type phase6Route struct {
	name   string
	perm   rbac.Permission
	always bool // licence class always
	call   func(c *client) *httptest.ResponseRecorder
}

func (e *keyEnv) phase6Routes() []phase6Route {
	none := uuid.NewString()
	ifm := withHeader("If-Match", `"1"`)
	post := func(path string, body any, opts ...reqOpt) func(c *client) *httptest.ResponseRecorder {
		return func(c *client) *httptest.ResponseRecorder { return c.do(http.MethodPost, path, body, opts...) }
	}
	p := "/api/v1/rotation/policies/" + none
	r := "/api/v1/rotation/runs/" + none
	return []phase6Route{
		{"generate", rbac.InventoryOperate, false, post("/api/v1/ssh-keys/generate", map[string]string{"label": "x", "key_type": "dsa"})},
		{"deploy", rbac.InventoryOperate, false, post("/api/v1/ssh-keys/"+none+"/actions/deploy", map[string]any{"target_id": e.targetID,
			"os_user": "deploy", "file_path": deployKeysPath})},
		{"download", rbac.SSHKeysDownload, true, post("/api/v1/ssh-keys/"+none+"/actions/download-private-key", map[string]string{"reason": downloadReason})},
		{"create policy", rbac.RotationManage, false, post("/api/v1/rotation/policies", map[string]any{"ssh_key_id": none, "name": "x", "interval_days": 0})},
		{"edit policy", rbac.RotationManage, false, func(c *client) *httptest.ResponseRecorder {
			return c.do(http.MethodPatch, p, map[string]any{"name": "y"}, ifm)
		}},
		{"delete policy", rbac.RotationManage, false, func(c *client) *httptest.ResponseRecorder { return c.do(http.MethodDelete, p, nil, ifm) }},
		{"disable policy", rbac.RotationManage, false, post(p+"/actions/disable", nil, ifm)},
		{"preview", rbac.RotationManage, false, post(p+"/actions/preview", nil)},
		{"enable policy", rbac.RotationOperate, false, post(p+"/actions/enable", nil, ifm)},
		{"run now", rbac.RotationOperate, false, post(p+"/actions/run", map[string]string{"plan_digest": strings.Repeat("a", 64)})},
		{"continue", rbac.RotationOperate, false, post(r+"/actions/continue", nil)},
		{"finish now", rbac.RotationOperate, false, post(r+"/actions/finish-now", nil)},
		{"keep old", rbac.RotationOperate, false, post(r+"/actions/keep-old", map[string]any{"location_ids": []string{none}})},
		{"stop and undo", rbac.RotationManage, true, post(r+"/actions/abort", nil)},
	}
}

// mayCall is the matrix of the contract (C13 as amended): who passes the guard for each permission.
func mayCall(perm rbac.Permission, who string) (bool, string) {
	switch perm {
	case rbac.InventoryOperate:
		ok := slices.Contains([]string{"admin session, step-up", "admin session, no step-up", "admin operate token", "operator session, step-up",
			"operator operate token"}, who)
		return ok, "ALC-AUTH-0002"
	case rbac.RotationManage:
		ok := slices.Contains([]string{"admin session, step-up", "admin session, no step-up", "admin operate token"}, who)
		return ok, "ALC-AUTH-0002"
	case rbac.SSHKeysDownload, rbac.RotationOperate:
		if who == "admin session, no step-up" {
			return false, "ALC-AUTH-0003"
		}
		return who == "admin session, step-up", "ALC-AUTH-0002"
	}
	panic("unknown permission " + string(perm))
}

// errCode is the ALC code of an error answer ("" for any other answer).
func errCode(rec *httptest.ResponseRecorder) string {
	var e apiError
	if json.Unmarshal(rec.Body.Bytes(), &e) != nil {
		return ""
	}
	return e.Error.Code
}

// TestPhase6RoutesAuthzOverTheWire calls every Phase 6 route that changes something as every identity, out of and in
// licence lock: a caller the matrix refuses gets 403 with ALC-AUTH-0002 (or ALC-AUTH-0003 for a missing step-up) in both;
// a caller it admits reaches the handler (its 4xx is the handler's, never an authorization code) out of lock, and in
// lock gets 403 ALC-LIC-0001 except for the download and Stop and undo (class always). Nothing is created by any call.
func TestPhase6RoutesAuthzOverTheWire(t *testing.T) {
	e := newKeyEnv(t)
	callers := e.callers(60)
	rows := e.phase6Rows()
	check := func(locked bool) {
		for _, rt := range e.phase6Routes() {
			for _, who := range callers {
				if who.stepUp != nil {
					who.stepUp()
				}
				rec := rt.call(who.c)
				code := errCode(rec)
				ok, denial := mayCall(rt.perm, who.name)
				switch {
				case !ok:
					assert.Equal(t, http.StatusForbidden, rec.Code, "%s as %s (locked %v): %s", rt.name, who.name, locked, rec.Body.String())
					assert.Equal(t, denial, code, "%s as %s (locked %v)", rt.name, who.name, locked)
				case locked && !rt.always:
					assert.Equal(t, "ALC-LIC-0001", code, "%s as %s in lock: %s", rt.name, who.name, rec.Body.String())
				default:
					assert.NotContains(t, []string{"ALC-AUTH-0001", "ALC-AUTH-0002", "ALC-AUTH-0003", "ALC-LIC-0001"}, code,
						"%s as %s (locked %v): %s", rt.name, who.name, locked, rec.Body.String())
					assert.Contains(t, []int{http.StatusBadRequest, http.StatusNotFound, http.StatusPreconditionFailed, http.StatusUnprocessableEntity},
						rec.Code, "%s as %s (locked %v): the handler's answer, %s", rt.name, who.name, locked, rec.Body.String())
				}
			}
		}
	}
	check(false)
	assert.Equal(t, rows, e.phase6Rows(), "no call created or deleted anything")
	e.lockNow()
	e.advance(6 * time.Minute) // signing in again counts as a step-up for its five minutes
	check(true)
	assert.Equal(t, rows, e.phase6Rows())
}

// TestPhase6ObjectsOfTheWrongKind: ids of another kind of object (a policy id as a run, a run id as a policy, a key id as
// a policy, a policy id as a key) are 404, and a run's decisions never act on another run's places (409 ALC-ROT-0005,
// nothing changes).
func TestPhase6ObjectsOfTheWrongKind(t *testing.T) {
	e := newKeyEnv(t)
	k1 := e.generate(e.admin, "first", "ed25519")
	e.deployed(k1)
	p1, _ := e.createPolicy(e.admin, k1.id, 1)
	run1 := e.runNow(p1, e.preview(e.admin, p1).PlanDigest)
	e.drain()
	k2 := e.generate(e.admin, "second", "ed25519")
	e.deployed(k2)
	p2, _ := e.createPolicy(e.admin, k2.id, 1)
	run2 := e.runNow(p2, e.preview(e.admin, p2).PlanDigest)
	e.drain()
	r1, r2 := e.run(e.admin, run1), e.run(e.admin, run2)
	require.Equal(t, "overlap", r1.Status)
	require.Equal(t, "overlap", r2.Status)

	e.stepUp(e.admin, e.adminAcct)
	for _, c := range []struct{ method, path string }{
		{http.MethodGet, "/api/v1/rotation/runs/" + p1}, {http.MethodGet, "/api/v1/rotation/policies/" + run1},
		{http.MethodGet, "/api/v1/rotation/policies/" + k1.id}, {http.MethodGet, "/api/v1/ssh-keys/" + p1},
		{http.MethodPost, "/api/v1/rotation/runs/" + p1 + "/actions/abort"}, {http.MethodPost, "/api/v1/rotation/runs/" + k1.id + "/actions/finish-now"},
		{http.MethodPost, "/api/v1/rotation/policies/" + run1 + "/actions/preview"}, {http.MethodPost, "/api/v1/ssh-keys/" + p1 + "/actions/download-private-key"},
	} {
		var body any
		if strings.HasSuffix(c.path, "download-private-key") {
			body = map[string]string{"reason": downloadReason}
		}
		requireError(t, e.admin.do(c.method, c.path, body), http.StatusNotFound, "ALC-SYS-0001")
	}
	rows := e.phase6Rows()
	other := r2.Locations[0]["id"].(string)
	requireError(t, e.admin.do(http.MethodPost, "/api/v1/rotation/runs/"+run1+"/actions/keep-old", map[string]any{"location_ids": []string{other}}),
		http.StatusConflict, "ALC-ROT-0005")
	assert.Equal(t, rows, e.phase6Rows())
	assert.Equal(t, "overlap", e.run(e.admin, run1).Status)
	assert.Equal(t, "verified", e.run(e.admin, run2).Locations[0]["state"])
}

// decide calls one decision of a run as c and returns the answer.
func decide(c *client, runID, action string, keepOld []string) *httptest.ResponseRecorder {
	path := "/api/v1/rotation/runs/" + runID + "/actions/" + strings.ReplaceAll(action, "_", "-")
	if action == "keep_old" {
		return c.do(http.MethodPost, path, map[string]any{"location_ids": keepOld})
	}
	return c.do(http.MethodPost, path, nil)
}

// runState builds a run in one state for the actions test and returns the run and the places Keep old would name.
type runState struct {
	name  string
	build func(t *testing.T) (*keyEnv, string, []string)
}

func unverifiableRun(t *testing.T) (*keyEnv, string, []string) {
	e := newKeyEnv(t)
	k := e.generate(e.admin, "undecided", "ed25519")
	e.deployed(k)
	job := e.deploy(e.admin, k.id, e.targetID, "root", rootKeysPath)
	e.drain()
	require.Equal(t, "succeeded", e.job(e.admin, job)["status"])
	e.f.emu.SetSSHD(strings.Replace(sshdOf(e.f), "permitrootlogin prohibit-password", "permitrootlogin no", 1))
	e.discover(e.targetID)
	policyID, _ := e.createPolicy(e.admin, k.id, 1)
	runID := e.runNow(policyID, e.preview(e.admin, policyID).PlanDigest)
	e.drain()
	e.sweep(1)
	r := e.run(e.admin, runID)
	require.Equal(t, "verifying_new", r.Status)
	var keep []string
	for _, l := range r.Locations {
		if l["state"] == "unverifiable" {
			keep = append(keep, l["id"].(string))
		}
	}
	return e, runID, keep
}

// TestActionsAllowedAreWhatTheRoutesAccept: for runs in overlap, waiting for a decision, paused in lock and renewed with
// the renewal notice queued, and for each kind of caller, every decision actions_allowed offers is accepted (204, each
// on a fresh run in that state) and every decision it does not offer is refused (and changes nothing).
func TestActionsAllowedAreWhatTheRoutesAccept(t *testing.T) {
	states := []runState{
		{"overlap", func(t *testing.T) (*keyEnv, string, []string) {
			e := newKeyEnv(t)
			_, _, runID := e.overlapRun(7)
			return e, runID, nil
		}},
		{"waiting for a decision", unverifiableRun},
		{"paused in lock", func(t *testing.T) (*keyEnv, string, []string) {
			e, _, _, runID := lockedOverlap(t)
			e.hourly(4 * 24 * time.Hour)
			require.True(t, e.run(e.admin, runID).PausedLicense)
			return e, runID, nil
		}},
		{"renewed, notice queued", func(t *testing.T) (*keyEnv, string, []string) {
			e, _, _, runID := lockedOverlap(t)
			e.hourly(4 * 24 * time.Hour)
			e.renew()
			e.sweep(1)
			return e, runID, nil
		}},
	}
	all := []string{"continue", "finish_now", "keep_old", "abort"}
	for _, st := range states {
		t.Run(st.name, func(t *testing.T) {
			e, runID, keep := st.build(t)
			callers := e.callers(60)
			offers := map[string][]string{}
			for _, who := range callers {
				r := decodeBody[runDoc](t, who.c.do(http.MethodGet, "/api/v1/rotation/runs/"+runID, nil))
				offers[who.name] = r.ActionsAllowed
				status := r.Status
				for _, a := range all {
					if slices.Contains(r.ActionsAllowed, a) {
						continue
					}
					if who.stepUp != nil {
						who.stepUp()
					}
					rec := decide(who.c, runID, a, keep)
					assert.NotEqual(t, http.StatusNoContent, rec.Code, "%s as %s was not offered but accepted", a, who.name)
					assert.Equal(t, status, e.run(e.admin, runID).Status, "%s as %s changed the run", a, who.name)
				}
			}
			t.Logf("offers: %v", offers)
			assert.Empty(t, offers["operator session, step-up"])
			assert.Empty(t, offers["auditor read token"])
			assert.Empty(t, offers["admin read token"])
			// A browser session is offered what it may do after the step-up the page asks for (callerActions).
			assert.Equal(t, offers["admin session, step-up"], offers["admin session, no step-up"])
			// Every offer is accepted, each on a fresh run in the same state.
			for _, who := range []string{"admin session, step-up", "admin operate token"} {
				for _, a := range offers[who] {
					e2, run2, keep2 := st.build(t)
					c2 := e2.callers(60)
					idx := slices.IndexFunc(c2, func(c caller) bool { return c.name == who })
					if c2[idx].stepUp != nil {
						c2[idx].stepUp()
					}
					rec := decide(c2[idx].c, run2, a, keep2)
					assert.Equal(t, http.StatusNoContent, rec.Code, "%s offered to %s: %s", a, who, rec.Body.String())
				}
			}
		})
	}
}
