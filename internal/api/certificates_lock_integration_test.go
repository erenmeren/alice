//go:build integration

package api

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/providers"
	"alice/internal/providers/linuxssh/helperproto"
)

// License lock and certificates (L-26, L-29, L-80..L-82). The lock comes from the real license
// service: the evaluation ends after 30 days on the stack's clock.

// lockNow ends the evaluation and signs both browsers in again (their sessions ended with the
// 31 days).
func (n *nj) lockNow() {
	n.t.Helper()
	n.clock.Advance(31 * 24 * time.Hour)
	require.NoError(n.t, n.license.Tick(context.Background()))
	require.True(n.t, n.license.Snapshot().Eval.Locked())
	n.signIn(n.admin, n.adminAcct)
	n.signIn(n.op, n.opAcct)
}

func nginxCommands(f *nginxFixture) []string {
	var out []string
	for _, c := range f.server.Commands() {
		if strings.Contains(c, "nginx-") || strings.Contains(c, "tls-probe") {
			out = append(out, c)
		}
	}
	return out
}

// In lock nothing on a server is changed and no certificate is stored, reads work, a deployment
// that was already sent is still recovered (recovery is never gated), and a deployment queued
// before the lock is held until an Administrator confirms it after the renewal.
func TestLockAndCertificateDeployments(t *testing.T) {
	n := newNJ(t, wwwSite())
	b, _, bLocs := n.addNginx("web-02", apiSite())
	leaf := n.issue()
	certID := n.uploadCertificate(n.op, certBody(leaf, "Renewed"))
	rec := n.op.do(http.MethodPost, "/api/v1/certificates/csr", map[string]any{"common_name": wwwName, "key_type": "ecdsa-p256"})
	requireStatus(t, rec, http.StatusCreated)
	csrID := decodeBody[csrView](t, rec).ID

	// Before the lock: a deployment to web-02 was sent and its answer lost; one to web-01 is queued.
	b.emu.HangupAfter(helperproto.StepReload)
	sent := n.deploy(n.op, certID, bLocs[apiCert])[0]
	queued := n.deploy(n.op, certID, n.locs[wwwCert])[0]
	ran, err := n.runner.RunOnce(context.Background()) // the oldest job: web-02's
	require.NoError(t, err)
	require.True(t, ran)
	require.Equal(t, "recovering", n.deployment(n.op, sent.ID).State)
	require.Equal(t, "queued", n.deployment(n.op, queued.ID).State)
	bCommands, bNginx := len(b.server.Commands()), len(nginxCommands(b))

	n.lockNow()
	before := map[string]int{"certificates": n.count("certificates"), "managed_private_keys": n.count("managed_private_keys"),
		"csr_requests": n.count("csr_requests"), "deployments": n.count("deployments"), "location_updates": n.auditCount("location.updated")}
	denied := n.auditCount("request.denied_license")
	aBefore := len(n.f.server.Commands())

	refused := []struct {
		method, path string
		body         any
	}{
		{http.MethodPost, "/api/v1/certificates/upload", certBody(n.issue(), "Locked")},
		{http.MethodPost, "/api/v1/certificates/csr", map[string]any{"common_name": wwwName, "key_type": "ecdsa-p256"}},
		{http.MethodPost, "/api/v1/certificates/csr/" + csrID + "/actions/cancel", nil},
		{http.MethodPost, "/api/v1/certificates/csr/" + csrID + "/actions/complete", map[string]any{"certificate_pem": "x"}},
		{http.MethodPost, "/api/v1/certificates/" + certID + "/deploy", map[string]any{"location_ids": []string{n.locs[wwwCert]}}},
	}
	for _, r := range refused {
		requireError(t, n.op.do(r.method, r.path, r.body), http.StatusForbidden, "ALC-LIC-0001")
	}
	// The lock is decided before the body is read: a malformed body is refused the same way.
	requireError(t, n.op.do(http.MethodPost, "/api/v1/certificates/upload", "{not json"), http.StatusForbidden, "ALC-LIC-0001")
	n.stepUp(n.admin, n.adminAcct)
	requireError(t, n.admin.do(http.MethodPatch, "/api/v1/locations/"+n.locs[wwwCert], map[string]any{"verify_port": 8443}, ifMatchOf("1")),
		http.StatusForbidden, "ALC-LIC-0001")
	assert.Equal(t, denied+len(refused)+2, n.auditCount("request.denied_license"), "every refusal is audited")
	assert.Equal(t, before, map[string]int{"certificates": n.count("certificates"), "managed_private_keys": n.count("managed_private_keys"),
		"csr_requests": n.count("csr_requests"), "deployments": n.count("deployments"), "location_updates": n.auditCount("location.updated")})

	for _, p := range []string{"/api/v1/certificates", "/api/v1/certificates/" + certID, "/api/v1/certificates/csr", "/api/v1/certificates/csr/" + csrID,
		"/api/v1/targets/" + n.targetID + "/certificate-locations", "/api/v1/deployments", "/api/v1/deployments/" + queued.ID,
		"/api/v1/deployments/" + sent.ID, "/api/v1/deployments?target_id=" + n.targetID} {
		requireStatus(t, n.op.do(http.MethodGet, p, nil), http.StatusOK)
	}

	// L-82: the recovery runs in lock and ends the sent deployment from the helper's journal.
	d := n.settle(n.op, sent.ID)
	assert.Equal(t, "succeeded", d.Status)
	b.requirePair(t, apiCert, apiKey, apiName, leaf)
	assert.Equal(t, 1, b.emu.DeployCount())
	assert.Greater(t, len(b.server.Commands()), bCommands, "the recovery talked to web-02")
	recoveryCommands := nginxCommands(b)[bNginx:]
	assert.NotEmpty(t, recoveryCommands)
	for _, c := range recoveryCommands {
		assert.NotContains(t, c, "nginx-deploy", "no deployment is sent in lock")
	}

	// L-81: the queued deployment is held; web-01 never saw a command in lock.
	assert.Equal(t, aBefore, len(n.f.server.Commands()), "L-29: no command reached web-01 in lock")
	q := n.deployment(n.op, queued.ID)
	assert.Equal(t, "queued", q.State)
	assert.Equal(t, "blocked_license", q.JobStatus, "the deployment says it is held")
	assert.Equal(t, "blocked_license", n.job(n.op, queued.JobID)["status"])
	assert.Zero(t, n.f.emu.DeployCount())
	rec = n.admin.do(http.MethodGet, "/api/v1/jobs?status=blocked_license", nil)
	requireStatus(t, rec, http.StatusOK)
	var listed []string
	for _, j := range decodeBody[struct {
		Items []map[string]any `json:"items"`
	}](t, rec).Items {
		listed = append(listed, j["id"].(string))
	}
	assert.Equal(t, []string{queued.JobID}, listed)

	// A renewal alone starts nothing; only an Administrator's confirmation does.
	now := n.clock.Now()
	n.stepUp(n.admin, n.adminAcct)
	requireStatus(t, n.admin.do(http.MethodPost, "/api/v1/license", map[string]string{"license": n.signedLicense("LIC-R", now, now.AddDate(1, 0, 0), 10)}),
		http.StatusOK)
	assert.Zero(t, n.runJobs())
	assert.Equal(t, "blocked_license", n.deployment(n.op, queued.ID).JobStatus)
	requireError(t, n.op.do(http.MethodPost, "/api/v1/jobs/"+queued.JobID+"/actions/confirm", nil), http.StatusForbidden, "ALC-AUTH-0002")
	requireStatus(t, n.admin.do(http.MethodPost, "/api/v1/jobs/"+queued.JobID+"/actions/confirm", nil), http.StatusOK)
	assert.Equal(t, 1, n.runJobs())
	q = n.deployment(n.op, queued.ID)
	assert.Equal(t, "succeeded", q.Status)
	n.f.requirePair(t, wwwCert, wwwKey, wwwName, leaf)
	assert.Equal(t, 1, n.f.emu.DeployCount())
	assert.Empty(t, n.deploymentEmails())
}

// lockDuring is a session whose deployment finds the license locked: the evaluation ends while
// the helper runs.
type lockDuring struct {
	providers.Session
	n *nj
}

func (l lockDuring) DeployCertificate(ctx context.Context, req providers.DeployRequest, log providers.StepLogger) (providers.DeployOutcome, error) {
	l.n.clock.Advance(31 * 24 * time.Hour)
	require.NoError(l.n.t, l.n.license.Tick(ctx))
	return l.Session.DeployCertificate(ctx, req, log)
}

// L-80: a deployment running when the license locks finishes (the lock is checked when a job is
// claimed, never in the middle of a change); the deployment queued behind it on the same server is
// held.
func TestInFlightDeploymentFinishesAcrossTheLock(t *testing.T) {
	n := newNJ(t, wwwSite(), apiSite())
	leaf := n.issue()
	certID := n.uploadCertificate(n.op, certBody(leaf, "Renewed"))
	deps := n.deploy(n.op, certID, n.locs[wwwCert], n.locs[apiCert])
	n.setWrap(func(_ providers.TargetRef, s providers.Session) providers.Session {
		return lockDuring{Session: s, n: n}
	})
	ran, err := n.runner.RunOnce(context.Background())
	require.NoError(t, err)
	require.True(t, ran)
	n.setWrap(nil)
	require.True(t, n.license.Snapshot().Eval.Locked())
	n.signIn(n.op, n.opAcct)

	var first, second depView
	first = n.deployment(n.op, deps[0].ID)
	second = n.deployment(n.op, deps[1].ID)
	if first.State != "done" {
		first, second = second, first
	}
	assert.Equal(t, "succeeded", first.Status, "the deployment in flight finished in lock")
	assert.Equal(t, 1, n.f.emu.DeployCount())

	n.clock.Advance(2 * time.Second) // the runner sweeps queued changes in lock once per poll
	n.runJobs()
	second = n.deployment(n.op, second.ID)
	assert.Equal(t, "queued", second.State)
	assert.Equal(t, "blocked_license", second.JobStatus)
	assert.Equal(t, 1, n.f.emu.DeployCount(), "nothing else was sent in lock")
}
