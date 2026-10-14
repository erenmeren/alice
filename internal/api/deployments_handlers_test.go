package api

import (
	"context"
	"encoding/json"
	"net/http"
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

func sampleDeployment() inventory.Deployment {
	at := time.Date(2026, 10, 3, 10, 0, 0, 0, time.FixedZone("x", 3*3600))
	port := 8443
	job := uuid.MustParse("0192c000-0000-7000-8000-0000000000e1")
	return inventory.Deployment{
		ID: deployID, CertificateID: certID, CertificateName: "Web", LocationID: locationID, TargetID: targetID, TargetName: "web-01",
		CertPath: "/etc/nginx/ssl/www.crt", KeyPath: "/etc/nginx/ssl/www.key", JobID: &job, JobStatus: "succeeded", Trigger: "manual",
		RequestedBy: &adminID, RequestedByName: "Admin", State: inventory.DeployStateDone, Status: inventory.DeployStatusRolledBack,
		NewFingerprint: strings.Repeat("a", 64), PreviousFingerprint: strings.Repeat("b", 64), ConfirmIncompleteChain: true,
		Backup:    &providers.BackupRef{OperationID: deployID, Dir: inventory.BackupRoot + "/" + deployID.String()},
		Verified:  "",
		ErrorCode: "deployment.verify_unreachable",
		ErrorParams: map[string]string{"backup_dir": inventory.BackupRoot + "/" + deployID.String(),
			"stderr": "nginx: [emerg] secret text", "helper_code": "IO_ERROR"},
		FailedStep: "verify", CreatedAt: at, StartedAt: &at, FinishedAt: &at,
		Result: "rolled_back", Phase: "restored", CauseStep: "verify", HelperError: "",
		VerifyFailedReason: "deployment.verify_unreachable", VerifyFailedPort: &port, RecoveryAttempts: 1, RecoverAfter: &at,
		Steps: []inventory.DeploymentStep{
			{N: 1, Name: "backup", Status: "ok", At: at, Params: map[string]string{}},
			{N: 2, Name: "verify", Status: "failed", At: at, Params: map[string]string{"port": "8443", "reason": "deployment.verify_unreachable",
				"error": "Bad Text", "served": "not-a-hash", "line": "ssl_certificate_key /etc/x;"}},
			{N: 3, Name: "verify_current", Status: "ok", At: at, Params: map[string]string{"mode": "remote", "served": strings.Repeat("c", 64)}},
		},
	}
}

func TestDeploymentDTOHasTheDocumentedFields(t *testing.T) {
	listFields := []string{"id", "certificate_id", "certificate_name", "location_id", "target_id", "target_name", "cert_path", "key_path",
		"job_id", "job_status", "trigger", "state", "status", "result", "phase", "new_fingerprint", "previous_fingerprint",
		"confirm_incomplete_chain", "verified", "verify_failed", "error", "failed_step", "cause_step", "helper_error", "backup_dir",
		"requested_by", "requested_by_name", "recovery_attempts", "recover_after", "created_at", "started_at", "finished_at",
		"source", "binding_id", "kv_version", "vault_name"}
	assert.Equal(t, sorted(listFields...), jsonKeys(t, deploymentJSON(sampleDeployment())))
	assert.Equal(t, sorted(append(listFields, "steps")...), jsonKeys(t, deploymentDetailJSON(sampleDeployment())))
}

func TestGetDeploymentRendersStepsAndError(t *testing.T) {
	d, inv := inventoryDeps(t)
	inv.DeploymentFn = func(_ context.Context, id uuid.UUID) (inventory.Deployment, error) {
		if id != deployID {
			return inventory.Deployment{}, inventory.ErrNotFound
		}
		return sampleDeployment(), nil
	}
	h := NewHandler(d)
	rec := call(h, http.MethodGet, "/api/v1/deployments/"+deployID.String(), "auditor", "")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var body map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	assert.Equal(t, map[string]any{"code": "ALC-DEP-0005", "reason": "deployment.verify_unreachable",
		"params": map[string]any{"backup_dir": inventory.BackupRoot + "/" + deployID.String(), "helper_code": "IO_ERROR", "port": "8443"}},
		body["error"], "the code, the allowlisted params, and the recorded port the text names")
	assert.Equal(t, map[string]any{"code": "ALC-DEP-0005", "reason": "deployment.verify_unreachable", "params": map[string]any{"port": "8443"}},
		body["verify_failed"])
	assert.Equal(t, inventory.BackupRoot+"/"+deployID.String(), body["backup_dir"])
	assert.Equal(t, "2026-10-03T07:00:00Z", body["created_at"], "UTC")
	assert.Equal(t, []any{
		map[string]any{"n": 1.0, "name": "backup", "status": "ok", "at": "2026-10-03T07:00:00Z", "params": map[string]any{}},
		map[string]any{"n": 2.0, "name": "verify", "status": "failed", "at": "2026-10-03T07:00:00Z",
			"params": map[string]any{"port": "8443", "reason": "deployment.verify_unreachable"}},
		map[string]any{"n": 3.0, "name": "verify_current", "status": "ok", "at": "2026-10-03T07:00:00Z",
			"params": map[string]any{"mode": "remote", "served": strings.Repeat("c", 64)}},
	}, body["steps"], "step params keep only allowlisted keys with well-formed values")
	assert.NotContains(t, rec.Body.String(), "secret text")
	assert.NotContains(t, rec.Body.String(), "ssl_certificate_key")
	assert.NotContains(t, rec.Body.String(), "Bad Text")

	assert.Equal(t, http.StatusNotFound, call(h, http.MethodGet, "/api/v1/deployments/"+uuid.NewString(), "auditor", "").Code)
	assert.Equal(t, http.StatusNotFound, call(h, http.MethodGet, "/api/v1/deployments/x", "auditor", "").Code)
}

// A stored reason renders through its documented code; rollback_failed is split by what the
// record says happened; an unknown reason is internal.unexpected, never shown raw.
func TestDeploymentErrorIsRefinedAndNeverRaw(t *testing.T) {
	for _, tc := range []struct {
		code, phase, helperError string
		want                     string
	}{
		{"", "", "", ""},
		{"deployment.rollback_failed", "restore_failed", "", "ALC-DEP-0008"},
		{"deployment.rollback_failed", "restored", "", "ALC-DEP-0019"},
		{"deployment.rollback_failed", "", "file_changed", "ALC-DEP-0020"},
		{"deployment.rollback_reload_failed", "restored", "", "ALC-DEP-0009"},
		{"nginx.io_error", "", "", "ALC-NGX-0009"},
		{"deployment.interrupted", "", "", "ALC-DEP-0010"},
		{"deployment.recovery_exhausted", "", "", "ALC-DEP-0017"},
		{"something.new", "", "", "ALC-SYS-0003"},
	} {
		dep := sampleDeployment()
		dep.ErrorCode, dep.Phase, dep.HelperError, dep.VerifyFailedPort = tc.code, tc.phase, tc.helperError, nil
		dto := deploymentJSON(dep)
		if tc.want == "" {
			assert.Nil(t, dto.Error)
			continue
		}
		require.NotNil(t, dto.Error, tc.code)
		assert.Equal(t, tc.want, dto.Error.Code, tc.code)
		assert.NotEqual(t, "something.new", dto.Error.Reason)
	}
	// Remote-looking values never pass: an odd phase, a path with spaces, a non-numeric port.
	dep := sampleDeployment()
	dep.Phase, dep.HelperError, dep.FailedStep = "Restored!", "<b>", "verify old"
	dep.ErrorParams = map[string]string{"port": "443; rm", "backup_dir": "/x y", "phase": "ok", "expected": "RSA KEY"}
	dto := deploymentJSON(dep)
	assert.Empty(t, dto.Phase)
	assert.Empty(t, dto.HelperError)
	assert.Empty(t, dto.FailedStep)
	assert.Equal(t, map[string]string{"phase": "ok", "port": "8443"}, dto.Error.Params)
	dep.Backup = &providers.BackupRef{Dir: "relative/dir"}
	assert.Empty(t, deploymentJSON(dep).BackupDir)
}

func TestListDeployments(t *testing.T) {
	d, inv := inventoryDeps(t)
	var got inventory.DeploymentFilter
	calls := 0
	inv.ListDeploymentsFn = func(_ context.Context, f inventory.DeploymentFilter) (inventory.DeploymentPage, error) {
		got = f
		calls++
		dep := sampleDeployment()
		dep.Steps = nil
		return inventory.DeploymentPage{Items: []inventory.Deployment{dep}, NextCursor: "c2"}, nil
	}
	h := NewHandler(d)
	for q, field := range map[string]string{
		"target_id=x": "target_id", "certificate_id=1": "certificate_id", "location_id=z": "location_id", "limit=0": "limit",
		"limit=500": "limit", "cursor=" + strings.Repeat("c", 600): "cursor",
	} {
		rec := call(h, http.MethodGet, "/api/v1/deployments?"+q, "auditor", "")
		require.Equal(t, http.StatusUnprocessableEntity, rec.Code, q)
		assert.Equal(t, field, errorDetails(t, rec)[0].Field, q)
	}
	assert.Zero(t, calls)
	rec := call(h, http.MethodGet, "/api/v1/deployments?target_id="+targetID.String()+"&certificate_id="+certID.String()+
		"&location_id="+locationID.String()+"&cursor=c1&limit=5", "alice_read_auditor", "")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, inventory.DeploymentFilter{TargetID: targetID, CertificateID: certID, LocationID: locationID, Cursor: "c1", Limit: 5}, got)
	var body struct {
		Items      []map[string]any `json:"items"`
		NextCursor string           `json:"next_cursor"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	require.Len(t, body.Items, 1)
	assert.NotContains(t, body.Items[0], "steps", "the list has no steps")
	assert.Equal(t, "c2", body.NextCursor)
	inv.ListDeploymentsFn = func(context.Context, inventory.DeploymentFilter) (inventory.DeploymentPage, error) {
		return inventory.DeploymentPage{}, validate.Errors{{Field: "cursor", Code: validate.Pattern}}
	}
	assert.Equal(t, http.StatusUnprocessableEntity, call(h, http.MethodGet, "/api/v1/deployments?cursor=bad", "auditor", "").Code)
	inv.ListDeploymentsFn = func(_ context.Context, f inventory.DeploymentFilter) (inventory.DeploymentPage, error) {
		got = f
		return inventory.DeploymentPage{}, nil
	}
	rec = call(h, http.MethodGet, "/api/v1/deployments", "auditor", "")
	assert.JSONEq(t, `{"items":[],"next_cursor":null}`, rec.Body.String())
	assert.Equal(t, inventory.DeploymentFilter{Limit: 50}, got)
}

func TestTargetDTOCarriesNginxFacts(t *testing.T) {
	tg := sampleTarget()
	tg.Type = inventory.TypeNginx
	tg.Facts.Nginx = &providers.NginxFacts{Version: "1.24.0", ConfPath: "/etc/nginx/nginx.conf", ConfigValid: false, ConfigError: "untrusted",
		ConfigErrorReason: "not_root_controlled", ConfigErrorFile: "/etc/nginx/conf.d/a b.conf", Found: true}
	raw, err := json.Marshal(targetJSON(tg))
	require.NoError(t, err)
	assert.Contains(t, string(raw), `"type":"nginx"`)
	assert.Contains(t, string(raw), `"nginx":{"version":"1.24.0","conf_path":"/etc/nginx/nginx.conf","config_valid":false,"config_error":"untrusted",`+
		`"config_error_reason":"not_root_controlled","config_error_file":"/etc/nginx/conf.d/a b.conf","found":true}`)
	raw, err = json.Marshal(targetJSON(sampleTarget()))
	require.NoError(t, err)
	assert.NotContains(t, string(raw), `"nginx"`, "a Linux server has no Nginx facts")

	d, inv := inventoryDeps(t)
	var gotType string
	inv.CreateTargetFn = func(_ context.Context, _ inventory.Actor, in inventory.NewTarget) (inventory.Target, uuid.UUID, error) {
		gotType = in.Type
		return tg, jobID, nil
	}
	rec := call(NewHandler(d), http.MethodPost, "/api/v1/targets", "admin", `{"name":"web","type":"nginx","host":"web.example.com","port":22,"username":"alice-svc"}`)
	require.Equal(t, http.StatusCreated, rec.Code)
	assert.Equal(t, "nginx", gotType)
}

// A deployment of a vault version says so: source key_vault with its binding, the 32-hex version and the vault's name;
// any other deployment is an upload and carries none of them.
func TestDeploymentSourceFields(t *testing.T) {
	d := sampleDeployment()
	assert.Equal(t, "upload", deploymentJSON(d).Source)
	assert.Nil(t, deploymentJSON(d).BindingID)
	binding := uuid.MustParse("0192d000-0000-7000-8000-0000000000a4")
	d.BindingID, d.KVVersion, d.VaultName, d.Source = &binding, strings.Repeat("a", 32), "prod-vault", "key_vault"
	got := deploymentJSON(d)
	assert.Equal(t, "key_vault", got.Source)
	require.NotNil(t, got.BindingID)
	assert.Equal(t, binding.String(), *got.BindingID)
	assert.Equal(t, strings.Repeat("a", 32), got.KVVersion)
	assert.Equal(t, "prod-vault", got.VaultName)
	d.KVVersion = "not a version"
	assert.Empty(t, deploymentJSON(d).KVVersion)

	// A deployment of a certificate ordered from a certificate authority says acme, not upload (final review finding 3).
	a := sampleDeployment()
	a.Source = "acme"
	assert.Equal(t, "acme", deploymentJSON(a).Source)
	a.Source = "something else"
	assert.Equal(t, "upload", deploymentJSON(a).Source)
}
