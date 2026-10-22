package api

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/inventory"
	"alice/internal/providers"
)

// deploymentKeys are the members of a deployment before R61, in sorted order: a deployment of a certificate file shows
// exactly these (its JSON is unchanged by the Windows fields).
var deploymentKeys = []string{"backup_dir", "binding_id", "cause_step", "cert_path", "certificate_id", "certificate_name",
	"confirm_incomplete_chain", "created_at", "error", "failed_step", "finished_at", "helper_error", "id", "job_id", "job_status",
	"key_path", "kv_version", "location_id", "new_fingerprint", "phase", "previous_fingerprint", "recover_after",
	"recovery_attempts", "requested_by", "requested_by_name", "result", "source", "started_at", "state", "status", "target_id",
	"target_name", "trigger", "vault_name", "verification", "verified", "verify_failed"}

func deploymentMap(t *testing.T, v any) map[string]any {
	t.Helper()
	b, err := json.Marshal(v)
	require.NoError(t, err)
	var m map[string]any
	require.NoError(t, json.Unmarshal(b, &m))
	return m
}

func sortedKeys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

// R61 Ruling 17: a Windows deployment names where the previous certificate is (backup_store, backup_sha1) and has no
// backup folder (backup_dir ""); a deployment of a certificate file is unchanged: the same members, its backup_dir.
func TestWindowsDeploymentDTO(t *testing.T) {
	sha1 := strings.Repeat("0a", 20)
	op := uuid.New()
	win := inventory.Deployment{ID: op, CertPath: "http.sys/ipport/0.0.0.0:443", Status: inventory.DeployStatusRollbackFailed,
		Backup: &providers.BackupRef{OperationID: op, Store: "WebHosting", PreviousSHA1: sha1, PreviousSHA256: strings.Repeat("b", 64)}}
	m := deploymentMap(t, deploymentJSON(win))
	assert.Equal(t, "WebHosting", m["backup_store"])
	assert.Equal(t, sha1, m["backup_sha1"])
	assert.Equal(t, "", m["backup_dir"])
	assert.NotContains(t, m, "backup_sha256", "the previous fingerprint is previous_fingerprint")
	want := append(slices.Clone(deploymentKeys), "backup_sha1", "backup_store")
	slices.Sort(want)
	assert.Equal(t, want, sortedKeys(m))

	// Values outside their rule are not shown.
	for _, b := range []providers.BackupRef{
		{OperationID: op, Store: `My\x`, PreviousSHA1: strings.Repeat("AB", 20)},
		{OperationID: op, Store: strings.Repeat("a", 65), PreviousSHA1: sha1 + "0"},
		{OperationID: op, Store: "Call 555 0100 for support"},
		{OperationID: op, Store: "Root"},
		{OperationID: op},
	} {
		m := deploymentMap(t, deploymentJSON(inventory.Deployment{ID: op, Backup: &b}))
		assert.NotContains(t, m, "backup_store", "%+v", b)
		assert.NotContains(t, m, "backup_sha1", "%+v", b)
	}
	for _, store := range []string{"My", "MY", "my", "WebHosting", "WEBHOSTING"} {
		m := deploymentMap(t, deploymentJSON(inventory.Deployment{ID: op, Backup: &providers.BackupRef{OperationID: op, Store: store}}))
		assert.Equal(t, store, m["backup_store"])
	}

	// Nginx: the members and the backup folder as before.
	dir := "/var/lib/alice-helper/backups/" + op.String()
	at := time.Date(2026, 10, 22, 9, 0, 0, 0, time.UTC)
	ngx := inventory.Deployment{ID: op, CertPath: "/etc/nginx/a.pem", KeyPath: "/etc/nginx/a.key", CreatedAt: at,
		Backup: &providers.BackupRef{OperationID: op, Dir: dir}}
	m = deploymentMap(t, deploymentJSON(ngx))
	assert.Equal(t, deploymentKeys, sortedKeys(m))
	assert.Equal(t, dir, m["backup_dir"])
	m = deploymentMap(t, deploymentJSON(inventory.Deployment{ID: op, CertPath: "/a", KeyPath: "/b"}))
	assert.Equal(t, deploymentKeys, sortedKeys(m), "no backup yet")
	assert.Equal(t, "", m["backup_dir"])
}

// R61 Ruling 16: the verify step of a Windows deployment shows chain_differs with the two chain lengths; values
// outside their rule are dropped.
func TestWindowsVerifyStepParams(t *testing.T) {
	d := inventory.Deployment{ID: uuid.New(), Steps: []inventory.DeploymentStep{
		{N: 1, Name: "verify", Status: "ok", Params: map[string]string{"chain_differs": "true", "deployed_chain": "2", "built_chain": "3",
			"mode": "remote"}},
		{N: 2, Name: "verify", Status: "ok", Params: map[string]string{"chain_differs": "yes", "deployed_chain": "-1", "built_chain": "123"}},
	}}
	out := deploymentDetailJSON(d)
	require.Len(t, out.Steps, 2)
	assert.Equal(t, map[string]string{"chain_differs": "true", "deployed_chain": "2", "built_chain": "3", "mode": "remote"}, out.Steps[0].Params)
	assert.Equal(t, map[string]string{}, out.Steps[1].Params)
}
