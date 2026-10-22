//go:build integration

package inventory_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/inventory"
)

type queuedMail struct {
	Template string
	Params   map[string]string
}

// deploymentMails is the deployment e-mails queued for deployment id (one row per recipient; ada is the only one).
func (f *winDeployFixture) deploymentMails(id uuid.UUID) []queuedMail {
	f.h.t.Helper()
	rows, err := f.h.db.Owner.Query(f.h.ctx, `SELECT template_key, params FROM notifications_outbox
WHERE template_key LIKE 'deployment.%' AND params->>'deployment_id' = $1 ORDER BY created_at, id`, id.String())
	require.NoError(f.h.t, err)
	defer rows.Close()
	var out []queuedMail
	for rows.Next() {
		var (
			m   queuedMail
			raw []byte
		)
		require.NoError(f.h.t, rows.Scan(&m.Template, &raw))
		require.NoError(f.h.t, json.Unmarshal(raw, &m.Params))
		out = append(out, m)
	}
	require.NoError(f.h.t, rows.Err())
	return out
}

// R61: a Windows deployment's e-mails are the Windows texts, and where a Linux one names the helper's backup folder
// (backup_dir) a Windows one names the previous certificate its start record wrote (store \ thumbprint, else what is
// known of it). A file's e-mails are exactly as before.
func TestWindowsDeploymentEmailsNameThePreviousCertificate(t *testing.T) {
	f := newWinDeployFixture(t)
	h := f.h
	base := func(id uuid.UUID, path string) map[string]string {
		return map[string]string{"target_name": "iis-01", "cert_path": path, "deployment_id": id.String()}
	}

	// The restore failed: the previous certificate, never a backup folder.
	r := f.request(f.bound)
	f.start(r.ID, nil)
	require.NoError(t, h.svc.FinishDeployment(h.ctx, r.ID, inventory.DeploymentFinish{Status: inventory.DeployStatusRollbackFailed,
		Result: "rollback_failed", FailedStep: "restore", ErrorCode: "windows.backup_missing"}))
	want := base(r.ID, "http.sys/ipport/0.0.0.0:443")
	want["previous_certificate"] = `MY \ ` + thumbprint(f.old)
	assert.Equal(t, []queuedMail{{inventory.WindowsTemplate(inventory.TemplateDeploymentRollbackFailed), want}}, f.deploymentMails(r.ID))

	// A start record without the store and thumbprint (a scan changed the binding meanwhile): needs attention, then the
	// outcome is unknown; the previous certificate by its SHA-256.
	r2 := f.request(f.spare)
	f.start(r2.ID, func() {
		_, err := h.db.Owner.Exec(h.ctx, "UPDATE certificate_locations SET cert_file_sha256 = $2 WHERE id = $1", f.spare, derSHA(f.nw))
		require.NoError(t, err)
	})
	require.NoError(t, h.svc.MarkRecovering(h.ctx, r2.ID, time.Time{}, true))
	require.NoError(t, h.svc.FinishDeployment(h.ctx, r2.ID, inventory.DeploymentFinish{Status: inventory.DeployStatusRollbackFailed,
		ErrorCode: "deployment.outcome_unknown"}))
	unknown := base(r2.ID, "http.sys/ipport/0.0.0.0:8443")
	unknown["previous_certificate"] = "SHA-256 " + derSHA(f.old)
	assert.Equal(t, []queuedMail{
		{inventory.WindowsTemplate(inventory.TemplateDeploymentNeedsAttentionUnconfirmed), base(r2.ID, "http.sys/ipport/0.0.0.0:8443")},
		{inventory.WindowsTemplate(inventory.TemplateDeploymentOutcomeUnknown), unknown},
	}, f.deploymentMails(r2.ID))

	// A deployment that failed before any change: the Windows text, no previous certificate.
	r3 := f.request(f.bound)
	require.NoError(t, h.svc.FinishDeployment(h.ctx, r3.ID, inventory.DeploymentFinish{Status: inventory.DeployStatusFailed,
		ErrorCode: "windows.unreachable"}))
	assert.Equal(t, []queuedMail{{inventory.WindowsTemplate(inventory.TemplateDeploymentFailed), base(r3.ID, "http.sys/ipport/0.0.0.0:443")}},
		f.deploymentMails(r3.ID))

	// A file: the Linux text and the helper's backup folder, as before.
	rf := f.request(f.file)
	f.start(rf.ID, nil)
	require.NoError(t, h.svc.FinishDeployment(h.ctx, rf.ID, inventory.DeploymentFinish{Status: inventory.DeployStatusRollbackFailed,
		Result: "rollback_failed", FailedStep: "restore", ErrorCode: "deployment.rollback_failed"}))
	file := map[string]string{"target_name": "web-01", "cert_path": "/etc/nginx/ssl/www.crt", "deployment_id": rf.ID.String(),
		"backup_dir": inventory.BackupRoot + "/" + rf.ID.String()}
	assert.Equal(t, []queuedMail{{inventory.TemplateDeploymentRollbackFailed, file}}, f.deploymentMails(rf.ID))
}
