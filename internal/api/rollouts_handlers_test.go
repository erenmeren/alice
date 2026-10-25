package api

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/authz"
	"alice/internal/inventory"
	"alice/internal/license"
	"alice/internal/rbac"
)

var (
	rolloutID   = uuid.MustParse("0192c000-0000-7000-8000-0000000000a1")
	rolloutLoc2 = uuid.MustParse("0192c000-0000-7000-8000-0000000000a2")
)

func sampleRolloutDetail(state string) inventory.RolloutDetail {
	at := time.Date(2026, 10, 25, 10, 0, 0, 0, time.UTC)
	until := at.Add(10 * time.Minute)
	dep := uuid.MustParse("0192c000-0000-7000-8000-0000000000a3")
	status := 200
	r := inventory.Rollout{ID: rolloutID, CertificateID: certID, PolicyVersion: 2, Origin: inventory.RolloutOriginManual, State: state,
		Settings: authz.CanarySettings{Count: 1, Hold: 10 * time.Minute, Interval: 30 * time.Second, Timeout: 5 * time.Second, Failures: 2,
			Check: &authz.CanaryCheck{Path: "/healthz", ExpectStatus: []int{200}, Timeout: "5s"}, OverrideAllowed: true},
		Wave1: []uuid.UUID{locationID}, Wave2: []uuid.UUID{rolloutLoc2}, ReasonParams: map[string]string{}, Skipped: []inventory.RolloutSkip{},
		HoldStartedAt: &at, HoldUntil: &until, CreatedAt: at}
	return inventory.RolloutDetail{Rollout: r, CertificateName: "Web", Now: at.Add(time.Minute), Locations: []inventory.RolloutLocation{
		{Wave: 1, LocationID: locationID, TargetID: targetID, TargetName: "web-01", Site: "/etc/nginx/ssl/www.crt", DeploymentID: &dep,
			DeploymentState: inventory.DeployStateHolding, DeploymentStatus: inventory.DeployStatusRunning,
			Canary: &inventory.CanaryView{Rounds: 2, Passes: 2, LastResult: "pass", LastTLS: "pass", LastHTTPStatus: &status, NextCheckAt: at}},
		{Wave: 2, LocationID: rolloutLoc2, TargetID: targetID, TargetName: "web-01", Site: "/etc/nginx/ssl/b.crt"},
	}}
}

// CAN-29 (design §13.2, §13.3, §17.1): the rollout routes, their rights, step-up and licence classes.
func TestRolloutRoutes(t *testing.T) {
	d, inv := inventoryDeps(t)
	detail := sampleRolloutDetail(inventory.RolloutHold)
	inv.RolloutDetailFn = func(_ context.Context, id uuid.UUID) (inventory.RolloutDetail, error) {
		if id != rolloutID {
			return inventory.RolloutDetail{}, inventory.ErrRolloutNotFound
		}
		return detail, nil
	}
	var continued, aborted int
	inv.ContinueRolloutFn = func(context.Context, inventory.Actor, uuid.UUID) (inventory.Rollout, error) {
		continued++
		return detail.Rollout, nil
	}
	inv.AbortRolloutFn = func(context.Context, inventory.Actor, uuid.UUID) (inventory.Rollout, error) {
		aborted++
		if detail.State == inventory.RolloutWave2 {
			return inventory.Rollout{}, &inventory.RolloutStateError{State: inventory.RolloutWave2}
		}
		return detail.Rollout, nil
	}
	h := NewHandler(d)
	base := "/api/v1/deployment-rollouts/" + rolloutID.String()

	rec := call(h, http.MethodGet, base, "auditor", "")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var body map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	assert.Equal(t, "hold", body["state"])
	assert.Equal(t, []any{}, body["allowed_actions"], "an Auditor may read, not act")
	waves := body["waves"].([]any)
	require.Len(t, waves, 2)
	w1 := waves[0].(map[string]any)["locations"].([]any)
	require.Len(t, w1, 1)
	assert.Equal(t, "holding", w1[0].(map[string]any)["deployment_state"])
	assert.Equal(t, "pass", w1[0].(map[string]any)["canary"].(map[string]any)["last_result"])
	assert.Equal(t, "10m", body["settings"].(map[string]any)["hold"])
	assert.Equal(t, "2026-10-25T10:01:00Z", body["now"])

	rec = call(h, http.MethodGet, base, "operator", "")
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	assert.Equal(t, []any{"abort"}, body["allowed_actions"], "continue needs passing last rounds and is listed only then")

	rec = call(h, http.MethodGet, "/api/v1/deployment-rollouts/"+uuid.NewString(), "operator", "")
	assert.Equal(t, http.StatusNotFound, rec.Code)
	assert.Equal(t, ErrDeployRolloutNotFound.Code, rolloutErrCode(t, rec))
	assert.Equal(t, http.StatusNotFound, call(h, http.MethodGet, "/api/v1/deployment-rollouts/x", "operator", "").Code)

	// Continue: a fresh step-up in a browser session, never a token.
	for who, want := range map[string]int{"operator": http.StatusForbidden, "alice_operate_operator": http.StatusForbidden,
		"auditor-stepup": http.StatusForbidden} {
		rec = call(h, http.MethodPost, base+"/actions/continue", who, "")
		assert.Equal(t, want, rec.Code, who)
	}
	assert.Equal(t, ErrStepUpRequired.Code, rolloutErrCode(t, call(h, http.MethodPost, base+"/actions/continue", "operator", "")))
	assert.Zero(t, continued)
	rec = call(h, http.MethodPost, base+"/actions/continue", "operator-stepup", "")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, 1, continued)

	// Abort: an Operator, no step-up.
	rec = call(h, http.MethodPost, base+"/actions/abort", "operator", "")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, 1, aborted)
	assert.Equal(t, http.StatusForbidden, call(h, http.MethodPost, base+"/actions/abort", "auditor", "").Code)
	detail.State = inventory.RolloutWave2
	rec = call(h, http.MethodPost, base+"/actions/abort", "operator", "")
	assert.Equal(t, http.StatusConflict, rec.Code)
	assert.Equal(t, ErrDeployRolloutState.Code, rolloutErrCode(t, rec))
	var eb struct {
		Error struct {
			Params map[string]string `json:"params"`
		} `json:"error"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &eb))
	assert.Equal(t, "wave2", eb.Error.Params["state"])
}

func rolloutErrCode(t *testing.T, rec interface{ Result() *http.Response }) string {
	t.Helper()
	var eb errBody
	res := rec.Result()
	defer res.Body.Close()
	require.NoError(t, json.NewDecoder(res.Body).Decode(&eb))
	return eb.Error.Code
}

// The licence classes of the rollout routes: continue is a change (refused in lock), abort always works.
func TestRolloutRouteClasses(t *testing.T) {
	classes := map[string]license.Class{}
	for _, rt := range newServer(Deps{}).apiRoutes() {
		classes[rt.method+" "+rt.pattern] = rt.lic
	}
	assert.Equal(t, license.ClassChange, classes["POST /api/v1/deployment-rollouts/{id}/actions/continue"])
	assert.Equal(t, license.ClassAlways, classes["POST /api/v1/deployment-rollouts/{id}/actions/abort"])
}

// Design decision 26: an ACME-sourced rollout is steered with certificates.operate; acme.operate grants the same people.
func TestCanaryPermissionsEquivalent(t *testing.T) {
	a, ok := rbac.PolicyFor(rbac.AcmeOperate)
	require.True(t, ok)
	c, ok := rbac.PolicyFor(rbac.CertificatesOperate)
	require.True(t, ok)
	assert.Equal(t, a.Roles, c.Roles)
	assert.Equal(t, a.TokenScope, c.TokenScope)
	assert.Equal(t, a.StepUp, c.StepUp)
}

// CAN-30 (design §13.1): deploying to all at once needs a fresh step-up in a browser session, on the three deploy routes.
func TestDeployOverrideNeedsStepUp(t *testing.T) {
	d, inv := inventoryDeps(t)
	var got []inventory.DeployRequestInput
	inv.RequestDeploymentWithRolloutFn = func(_ context.Context, _ inventory.Actor, in inventory.DeployRequestInput) ([]inventory.RequestedDeployment, *inventory.Rollout, error) {
		got = append(got, in)
		if in.CanaryOverride && in.LocationIDs[0] == rolloutLoc2 {
			return nil, nil, inventory.ErrCanaryOverrideForbidden
		}
		return []inventory.RequestedDeployment{{ID: deployID, JobID: uuid.New(), LocationID: locationID}}, nil, nil
	}
	h := NewHandler(d)
	path := "/api/v1/certificates/" + certID.String() + "/deploy"
	body := `{"location_ids":["` + locationID.String() + `"],"canary_override":true}`
	assert.Equal(t, ErrStepUpRequired.Code, rolloutErrCode(t, call(h, http.MethodPost, path, "operator", body)))
	assert.Equal(t, http.StatusForbidden, call(h, http.MethodPost, path, "alice_operate_operator", body).Code)
	assert.Empty(t, got, "nothing requested")
	rec := call(h, http.MethodPost, path, "operator-stepup", body)
	require.Equal(t, http.StatusAccepted, rec.Code, rec.Body.String())
	require.Len(t, got, 1)
	assert.True(t, got[0].CanaryOverride)
	rec = call(h, http.MethodPost, path, "operator-stepup", `{"location_ids":["`+rolloutLoc2.String()+`"],"canary_override":true}`)
	assert.Equal(t, http.StatusUnprocessableEntity, rec.Code)
	assert.Equal(t, ErrSVCCanaryOverrideForbidden.Code, rolloutErrCode(t, rec))
	// Without the override no step-up is asked.
	require.Equal(t, http.StatusAccepted, call(h, http.MethodPost, path, "operator", `{"location_ids":["`+locationID.String()+`"]}`).Code)
}

// The ACME Deploy now takes the override the same way (the Key Vault one: canary_integration_test.go).
func TestDeployNowOverrideNeedsStepUp(t *testing.T) {
	ah, af, _ := acmeDeps(t)
	var acme []inventory.ACMEDeployInput
	af.DeployACMENowRolloutFn = func(_ context.Context, _ inventory.Actor, _ uuid.UUID, in inventory.ACMEDeployInput) ([]inventory.RequestedDeployment, *inventory.Rollout, error) {
		acme = append(acme, in)
		r := sampleRolloutDetail(inventory.RolloutWave1).Rollout
		return []inventory.RequestedDeployment{{ID: deployID, JobID: uuid.New(), LocationID: locationID}}, &r, nil
	}
	apath := "/api/v1/acme/certificates/" + acmeCertID.String() + "/deploy"
	assert.Equal(t, ErrStepUpRequired.Code, rolloutErrCode(t, call(ah, http.MethodPost, apath, "operator", `{"canary_override":true}`)))
	assert.Empty(t, acme)
	rec := call(ah, http.MethodPost, apath, "operator-stepup", `{"canary_override":true}`)
	require.Equal(t, http.StatusAccepted, rec.Code, rec.Body.String())
	require.Len(t, acme, 1)
	assert.True(t, acme[0].CanaryOverride)
	var answer map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &answer))
	ro := answer["rollout"].(map[string]any)
	assert.Equal(t, rolloutID.String(), ro["id"])
	assert.Equal(t, []any{locationID.String()}, ro["wave1"])
	assert.Equal(t, []any{rolloutLoc2.String()}, ro["wave2"])
}

// A deployment answer names its rollout; the detail its latest observation; the list filters by rollout.
func TestDeploymentDTOHasRolloutAndCanary(t *testing.T) {
	dep := sampleDeployment()
	r := rolloutID
	dep.RolloutID, dep.Wave, dep.RolloutState = &r, 1, inventory.RolloutHold
	status := 503
	dep.Canary = &inventory.CanaryView{Rounds: 3, ConsecutiveFailures: 1, LastResult: "fail", LastReason: "canary.http_status", LastHTTPStatus: &status}
	j := deploymentDetailJSON(dep)
	require.NotNil(t, j.Rollout)
	assert.Equal(t, rolloutRefDTO{ID: rolloutID.String(), Wave: 1, State: "hold"}, *j.Rollout)
	require.NotNil(t, j.Canary)
	assert.Equal(t, "canary.http_status", j.Canary.LastReason)
	assert.Nil(t, deploymentJSON(sampleDeployment()).Rollout)

	d, inv := inventoryDeps(t)
	var filter inventory.DeploymentFilter
	inv.ListDeploymentsFn = func(_ context.Context, f inventory.DeploymentFilter) (inventory.DeploymentPage, error) {
		filter = f
		return inventory.DeploymentPage{}, nil
	}
	h := NewHandler(d)
	require.Equal(t, http.StatusOK, call(h, http.MethodGet, "/api/v1/deployments?rollout_id="+rolloutID.String(), "operator", "").Code)
	assert.Equal(t, rolloutID, filter.RolloutID)
	assert.Equal(t, http.StatusUnprocessableEntity, call(h, http.MethodGet, "/api/v1/deployments?rollout_id=x", "operator", "").Code)
}

// The website list filters by service (the canary editor's first picker).
func TestLocationsFilterByService(t *testing.T) {
	d, inv := inventoryDeps(t)
	var filter inventory.LocationFilter
	inv.ListDeployableLocationsFn = func(_ context.Context, f inventory.LocationFilter) (inventory.DeployableLocationPage, error) {
		filter = f
		return inventory.DeployableLocationPage{}, nil
	}
	h := NewHandler(d)
	a, b := uuid.New(), uuid.New()
	require.Equal(t, http.StatusOK, call(h, http.MethodGet, "/api/v1/certificate-locations?service_id="+a.String()+"&service_id="+b.String(),
		"operator", "").Code)
	assert.Equal(t, []uuid.UUID{a, b}, filter.ServiceIDs)
	assert.Equal(t, http.StatusUnprocessableEntity, call(h, http.MethodGet, "/api/v1/certificate-locations?service_id=x", "operator", "").Code)
}

// The durations of a rollout's settings are written as the policy writes them.
func TestDurationText(t *testing.T) {
	for d, want := range map[time.Duration]string{90 * time.Second: "90s", 2 * time.Minute: "2m", time.Hour: "1h", 0: "0s"} {
		assert.Equal(t, want, durationText(d))
	}
	s := rolloutSettingsJSON(inventory.Rollout{Settings: authz.CanarySettings{Hold: time.Hour}})
	assert.Nil(t, s.Check)
	assert.Nil(t, requestedRolloutJSON(nil))
}

func TestReasonOrBlank(t *testing.T) {
	for _, ok := range []string{"canary.http_status", "deployment.verify_failed", "license.locked", "lock_due", "target_not_ready"} {
		assert.Equal(t, ok, reasonOrBlank(ok))
	}
	for _, bad := range []string{"Bad Text", "a.b.c.d", "", "x;y"} {
		assert.Empty(t, reasonOrBlank(bad), bad)
	}
}
