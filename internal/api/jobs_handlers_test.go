package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/audit"
	"alice/internal/jobs"
	"alice/internal/providers"
)

func jobsDeps(t *testing.T) (Deps, *fakeJobs) {
	t.Helper()
	d := testDeps(t, nil)
	fj := &fakeJobs{}
	d.Jobs = fj
	return d, fj
}

func sampleView(status jobs.Status, reason string) jobs.View {
	at := time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC)
	return jobs.View{ID: jobID, Type: "sshkey.remove", Kind: "user", Status: status, TargetID: targetID, Attempts: 1,
		MaxAttempts: 3, LastErrorCode: reason, ErrorParams: map[string]string{"fingerprint": "SHA256:x"},
		Result: map[string]any{"steps": []any{}}, CreatedAt: at, RunAt: at}
}

func TestJobJSONMapsTheErrorReason(t *testing.T) {
	raw, err := json.Marshal(jobJSON(sampleView(jobs.Status("failed"), "target.host_key_unconfirmed")))
	require.NoError(t, err)
	var m map[string]any
	require.NoError(t, json.Unmarshal(raw, &m))
	assert.Equal(t, map[string]any{"code": "ALC-TGT-0002", "reason": "target.host_key_unconfirmed",
		"params": map[string]any{"fingerprint": "SHA256:x"}}, m["error"])
	assert.Equal(t, targetID.String(), m["target_id"])

	raw, err = json.Marshal(jobJSON(sampleView(jobs.Status("failed"), "weird.reason")))
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(raw, &m))
	assert.Equal(t, "ALC-SYS-0003", m["error"].(map[string]any)["code"])
	assert.Equal(t, "internal.unexpected", m["error"].(map[string]any)["reason"], "an unknown reason gets the generic text")

	v := sampleView(jobs.Status("succeeded"), "")
	v.TargetID = uuid.Nil
	raw, err = json.Marshal(jobJSON(v))
	require.NoError(t, err)
	assert.Contains(t, string(raw), `"error":null`)
	assert.Contains(t, string(raw), `"target_id":null`)
}

// A job's stored error params pass the same allowlist as a provider error answered directly: a
// handler that ever stored remote text or a key line in them cannot leak it through the API.
func TestJobJSONFiltersStoredErrorParams(t *testing.T) {
	v := sampleView(jobs.Status("failed"), "ssh.helper_outdated")
	v.ErrorParams = map[string]string{"helper_protocol": "1", "required_protocol": "2", "stderr": "remote text",
		"line": "ssh-ed25519 AAAA"}
	v.Result = map[string]any{"steps": []any{}, "error_params": map[string]any{"stderr": "remote text", "line": "ssh-ed25519 AAAA"}}
	raw, err := json.Marshal(jobJSON(v))
	require.NoError(t, err)
	var m map[string]any
	require.NoError(t, json.Unmarshal(raw, &m))
	assert.Equal(t, map[string]any{"helper_protocol": "1", "required_protocol": "2"}, m["error"].(map[string]any)["params"])
	assert.NotContains(t, string(raw), "remote text")
	assert.NotContains(t, string(raw), "AAAA")
	assert.Equal(t, map[string]any{"steps": []any{}}, m["result"], "the raw params are not repeated in the result")

	v.ErrorParams = map[string]string{"stderr": "remote text"}
	raw, err = json.Marshal(jobJSON(v))
	require.NoError(t, err)
	assert.NotContains(t, string(raw), `"params"`, "nothing allowlisted: no params at all")
}

func TestListJobsValidatesAndFilters(t *testing.T) {
	d, fj := jobsDeps(t)
	var got jobs.ListFilter
	fj.ListFn = func(_ context.Context, f jobs.ListFilter) ([]jobs.View, string, error) {
		got = f
		return []jobs.View{sampleView(jobs.Status("blocked_license"), "license.locked")}, "", nil
	}
	h := NewHandler(d)
	rec := call(h, http.MethodGet, "/api/v1/jobs?status=sleeping&limit=500", "auditor", "")
	require.Equal(t, http.StatusUnprocessableEntity, rec.Code)
	assert.Len(t, errorDetails(t, rec), 2)

	rec = call(h, http.MethodGet, "/api/v1/jobs?status=blocked_license&target_id="+targetID.String(), "auditor", "")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, jobs.ListFilter{Status: jobs.Status("blocked_license"), TargetID: targetID, Limit: 50}, got)
	assert.Contains(t, rec.Body.String(), `"next_cursor":null`)
}

func TestConfirmAndDiscardJobs(t *testing.T) {
	d, fj := jobsDeps(t)
	var confirmedBy uuid.UUID
	var actor audit.Actor
	fj.ConfirmFn = func(_ context.Context, a audit.Actor, by, id uuid.UUID) error {
		if id != jobID {
			return jobs.ErrNotWaiting
		}
		actor, confirmedBy = a, by
		return nil
	}
	fj.DiscardFn = func(context.Context, audit.Actor, uuid.UUID, uuid.UUID) error { return jobs.ErrNotFound }
	fj.GetFn = func(context.Context, uuid.UUID) (jobs.View, error) { return sampleView(jobs.Status("queued"), ""), nil }
	h := NewHandler(d)

	rec := call(h, http.MethodPost, "/api/v1/jobs/"+uuid.NewString()+"/actions/confirm", "admin", "")
	require.Equal(t, http.StatusConflict, rec.Code)
	assert.Equal(t, "ALC-JOB-0001", decodeErr(t, rec).Error.Code)

	rec = call(h, http.MethodPost, "/api/v1/jobs/"+jobID.String()+"/actions/confirm", "admin", "")
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), `"status":"queued"`)
	assert.Equal(t, adminID, confirmedBy)
	assert.Equal(t, "admin", actor.Name)

	rec = call(h, http.MethodPost, "/api/v1/jobs/"+jobID.String()+"/actions/discard", "admin", "")
	assert.Equal(t, http.StatusNotFound, rec.Code)

	// Only an Administrator's browser session may run or discard paused work (R29): not an
	// Operator, and not an API token of either scope.
	for _, id := range []string{"operator", "operator-stepup", "auditor", "alice_operate_operator", "alice_read_admin", "alice_operate_admin"} {
		for _, action := range []string{"confirm", "discard"} {
			rec := call(h, http.MethodPost, "/api/v1/jobs/"+jobID.String()+"/actions/"+action, id, "")
			assert.Equal(t, http.StatusForbidden, rec.Code, "%s as %s", action, id)
		}
	}
}

func TestJobJSONKeepsTheResult(t *testing.T) {
	v := sampleView(jobs.Status("failed"), "sshkey.verify_failed")
	v.Result = map[string]any{"needs_attention": true, "backup": "/root/.ssh/authorized_keys.alice-bak"}
	raw, err := json.Marshal(jobJSON(v))
	require.NoError(t, err)
	var m map[string]any
	require.NoError(t, json.Unmarshal(raw, &m))
	assert.Equal(t, "ALC-KEY-0005", m["error"].(map[string]any)["code"])
	assert.Equal(t, true, m["result"].(map[string]any)["needs_attention"])

	v.Result = nil
	raw, err = json.Marshal(jobJSON(v))
	require.NoError(t, err)
	assert.Contains(t, string(raw), `"result":{}`)
}

func TestProvidersList(t *testing.T) {
	d := testDeps(t, nil)
	d.Providers = fakeProviders{items: []providers.Descriptor{{
		Kind: providers.KindLinuxSSH, DisplayNameKey: "provider.linuxssh.name",
		Capabilities: []providers.Capability{providers.CapAuthorizedKeys, providers.CapTestConnection},
		ConfigSchema: providers.ConfigSchema{Fields: []providers.Field{{Name: "host", Type: "host", Required: true, LabelKey: "provider.linuxssh.fields.host.label", Max: 253}}},
	}}}
	rec := call(NewHandler(d), http.MethodGet, "/api/v1/providers", "auditor", "")
	require.Equal(t, http.StatusOK, rec.Code)
	assert.JSONEq(t, `{"items":[{"kind":"linuxssh","display_name_key":"provider.linuxssh.name",
		"capabilities":["authorized_keys","test_connection"],
		"config_schema":{"fields":[{"name":"host","type":"host","required":true,"default":null,
		"label_key":"provider.linuxssh.fields.host.label","help_key":"","pattern":"","min":0,"max":253,"values":[]}]}}]}`, rec.Body.String())
}

// The action succeeded even if reading the job back fails: the answer is 202 with the job's
// address, never an error that would invite a second confirmation.
func TestJobActionAnswersAcceptedWhenTheReadBackFails(t *testing.T) {
	d, fj := jobsDeps(t)
	fj.ConfirmFn = func(context.Context, audit.Actor, uuid.UUID, uuid.UUID) error { return nil }
	fj.DiscardFn = func(context.Context, audit.Actor, uuid.UUID, uuid.UUID) error { return nil }
	fj.GetFn = func(context.Context, uuid.UUID) (jobs.View, error) { return jobs.View{}, errors.New("database gone") }
	h := NewHandler(d)
	for _, action := range []string{"confirm", "discard"} {
		rec := call(h, http.MethodPost, "/api/v1/jobs/"+jobID.String()+"/actions/"+action, "admin", "")
		require.Equal(t, http.StatusAccepted, rec.Code, action)
		assert.JSONEq(t, `{"job_id":"`+jobID.String()+`","status_url":"/api/v1/jobs/`+jobID.String()+`"}`, rec.Body.String())
	}
}
