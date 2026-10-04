//go:build integration

package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/providers"
	"alice/internal/providers/linuxssh/helperproto"
	"alice/internal/testutil/pki"
)

// Failure journeys (F-03..F-07, F-09, F-12): each ends in the documented state with the documented
// error code and exactly the documented emails; the server holds a complete pair and serves what
// the record says.

// deployOne uploads a new certificate as the Operator, requests it for the www website and runs
// the queue. It returns the certificate, the deployment's id and its final view.
func (n *nj) deployOne() (pki.Leaf, string, depView) {
	n.t.Helper()
	leaf := n.issue()
	certID := n.uploadCertificate(n.op, certBody(leaf, "Renewed"))
	ref := n.deploy(n.op, certID, n.locs[wwwCert])[0]
	n.runJobs()
	return leaf, ref.ID, n.deployment(n.op, ref.ID)
}

func TestDeployFailureJourneys(t *testing.T) {
	type row struct {
		name   string
		setup  func(n *nj)
		status string
		code   string
		step   string
		steps  []string // the step sequence the deployment shows
		pair   string   // "old": the old pair is served; "": not asserted
		emails map[string]int
	}
	rows := []row{
		{name: "nginx -t fails after the write", setup: func(n *nj) { n.f.emu.FailConfigTest(1) },
			status: "rolled_back", code: "ALC-DEP-0007", step: "config_test",
			steps: []string{"verify_current:started", "verify_current:ok", "backup:ok", "write_key:ok", "write_cert:ok", "config_test:failed", "restore:ok", "rollback_config_test:ok", "rollback_reload:ok", "verify_old:started", "verify_old:ok"}, pair: "old", emails: map[string]int{"deployment.failed": 1}},
		{name: "reload fails", setup: func(n *nj) { n.f.emu.FailReload(1) },
			status: "rolled_back", code: "ALC-DEP-0006", step: "reload",
			steps: []string{"verify_current:started", "verify_current:ok", "backup:ok", "write_key:ok", "write_cert:ok", "config_test:ok", "reload:failed", "restore:ok", "rollback_config_test:ok", "rollback_reload:ok", "verify_old:started", "verify_old:ok"}, pair: "old", emails: map[string]int{"deployment.failed": 1}},
		{name: "the reload fails and so does the rollback's: Nginx never loaded the new files", setup: func(n *nj) { n.f.emu.FailReload(2) },
			status: "rolled_back", code: "ALC-DEP-0006", step: "reload",
			steps: []string{"verify_current:started", "verify_current:ok", "backup:ok", "write_key:ok", "write_cert:ok", "config_test:ok", "reload:failed", "restore:ok", "rollback_config_test:ok", "rollback_reload:failed", "restore:ok", "rollback_config_test:ok", "rollback_reload:ok", "verify_old:started", "verify_old:ok"}, pair: "old", emails: map[string]int{"deployment.failed": 1}},
		// The helper's first rollback cannot reload; the one more restore of the engine can. The record
		// keeps the verification as the cause (not "interrupted").
		{name: "the rollback needs a second restore", setup: func(n *nj) {
			n.f.emu.ServeOtherAfterReload(443, strings.Repeat("ef", 32))
			n.f.emu.ArmFaultsFor(helperproto.SubNginxRestore)
			n.f.emu.FailReload(1)
		}, status: "rolled_back", code: "ALC-DEP-0004", step: "verify",
			steps: []string{"verify_current:started", "verify_current:ok", "backup:ok", "write_key:ok", "write_cert:ok", "config_test:ok", "reload:ok", "verify:started", "verify:failed", "restore:ok", "rollback_config_test:ok", "rollback_reload:failed", "restore:ok", "rollback_config_test:ok", "rollback_reload:ok", "verify_old:started", "verify_old:ok"}, pair: "old", emails: map[string]int{"deployment.failed": 1}},
		{name: "verification fails and the rollback succeeds", setup: func(n *nj) { n.f.emu.NoopReload(true) },
			status: "rolled_back", code: "ALC-DEP-0003", step: "verify",
			steps: []string{"verify_current:started", "verify_current:ok", "backup:ok", "write_key:ok", "write_cert:ok", "config_test:ok", "reload:ok", "verify:started", "verify:failed", "restore:ok", "rollback_config_test:ok", "rollback_reload:ok", "verify_old:started", "verify_old:ok"}, pair: "old", emails: map[string]int{"deployment.failed": 1}},
	}
	for _, tc := range rows {
		t.Run(tc.name, func(t *testing.T) {
			n := newNJ(t, wwwSite())
			tc.setup(n)
			_, id, d := n.deployOne()
			assert.Equal(t, "done", d.State)
			assert.Equal(t, tc.status, d.Status)
			assert.Equal(t, tc.code, d.errorCode())
			assert.Equal(t, tc.step, d.FailedStep)
			assert.Equal(t, tc.steps, d.stepList())
			assert.Equal(t, 1, n.f.emu.DeployCount())
			if tc.pair == "old" {
				n.f.requirePair(t, wwwCert, wwwKey, wwwName, n.f.old)
			}
			assert.Equal(t, tc.emails, n.deploymentEmails())
			assert.Equal(t, 1, n.auditCount("deployment.rolled_back"))
			assert.Equal(t, "", n.location(n.admin, n.targetID, wwwCert)["deployed_fingerprint"], "the location was not changed")
			assert.Equal(t, "failed", n.job(n.admin, d.JobID)["status"], "the deployment's email is the alert; the job is not dead")
			_ = id
		})
	}
}

// The deployment is changed and the automatic restore does not end well. The deployment view names
// the cause (not the generic rollback_failed text), the email tells the administrators what to do
// and where the backup is.
func TestRollbackFailureJourneys(t *testing.T) {
	type row struct {
		name   string
		setup  func(n *nj)
		code   string
		email  string
		phase  string
		helper string
	}
	for _, tc := range []row{
		// The new certificate was loaded and failed verification; the files are back, but Nginx cannot
		// reload them twice: it still serves the new certificate from memory.
		{name: "the reload of the rollback fails again", setup: func(n *nj) {
			n.f.emu.ServeOtherAfterReload(443, strings.Repeat("cd", 32))
			n.f.emu.ArmFaultsFor(helperproto.SubNginxRestore)
			n.f.emu.FailReload(2)
		}, code: "ALC-DEP-0009", email: "deployment.rollback_failed", phase: "restore_failed"},
		{name: "another program changed the files before the restore", setup: func(n *nj) {
			n.f.emu.NoopReload(true)
			n.f.emu.ArmFaultsFor(helperproto.SubNginxRestore)
			n.f.emu.InterfereAt(helperproto.StepRestore, wwwKey, []byte("changed by another program\n"))
		}, code: "ALC-DEP-0020", email: "deployment.rollback_failed", helper: "file_changed"},
		{name: "the files are back but the old certificate is not served", setup: func(n *nj) {
			n.setWrap(func(_ providers.TargetRef, s providers.Session) providers.Session {
				return otherAnswers{Session: s, f: n.f}
			})
		}, code: "ALC-DEP-0019", email: "deployment.restored_unverified", phase: "restored"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			n := newNJ(t, wwwSite())
			tc.setup(n)
			_, id, d := n.deployOne()
			assert.Equal(t, "done", d.State)
			assert.Equal(t, "rollback_failed", d.Status)
			assert.Equal(t, tc.code, d.errorCode())
			assert.Equal(t, tc.phase, d.Phase)
			assert.Equal(t, tc.helper, d.HelperError)
			assert.Equal(t, "/var/lib/alice-helper/backups/"+id, d.BackupDir)
			assert.Equal(t, map[string]int{tc.email: 1}, n.deploymentEmails())
			assert.Equal(t, 1, n.auditCount("deployment.rollback_failed"))
			assert.Equal(t, "failed", n.job(n.admin, d.JobID)["status"], "no second alert from a dead job")
			assert.Zero(t, n.emails("job.dead"))
			if tc.email == "deployment.rollback_failed" {
				assert.Equal(t, "/var/lib/alice-helper/backups/"+id, n.emailParam(tc.email, "backup_dir"))
			}
		})
	}
}

// otherAnswers is a session of a server where something else (a load balancer) starts answering
// for the website the moment the deployment starts and stays: neither the new certificate nor the
// restored one is ever served by the website.
type otherAnswers struct {
	providers.Session
	f *nginxFixture
}

func (s otherAnswers) DeployCertificate(ctx context.Context, req providers.DeployRequest, log providers.StepLogger) (providers.DeployOutcome, error) {
	s.f.emu.ServeOther(443, strings.Repeat("ab", 32))
	return s.Session.DeployCertificate(ctx, req, log)
}

// F-06, F-07: a website Alice cannot check is never changed, and neither is one where something
// else answers; nothing is sent and the deployment is failed with the reason and the port.
func TestPrecheckRefusesWebsitesAliceCannotCheck(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(n *nj)
		code  string
	}{
		{"F-07 the website cannot be reached", func(n *nj) { n.f.emu.LocalProbeFails(true) }, "ALC-DEP-0005"},
		{"F-06 something else answers", func(n *nj) { n.f.emu.ServeOther(443, strings.Repeat("ab", 32)) }, "ALC-DEP-0004"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			n := newNJ(t, wwwSite())
			// Two servers make Alice's own probe unreachable: only the server's probe decides.
			n.addNginx("web-02", wwwSite())
			tc.setup(n)
			_, _, d := n.deployOne()
			assert.Equal(t, "done", d.State)
			assert.Equal(t, "failed", d.Status)
			assert.Equal(t, tc.code, d.errorCode())
			assert.Equal(t, map[string]string{"port": "443"}, d.Error.Params)
			assert.Equal(t, []string{"verify_current:started", "verify_current:failed"}, d.stepList())
			assert.Zero(t, n.f.emu.DeployCount(), "nothing was sent")
			assert.Equal(t, map[string]int{"deployment.failed": 1}, n.deploymentEmails())
			assert.Zero(t, n.auditCount("deployment.started"))
			assert.Equal(t, 1, n.auditCount("deployment.failed"))
			assert.Equal(t, "", n.location(n.admin, n.targetID, wwwCert)["deployed_fingerprint"])
		})
	}
}

// Refusals at request time: the request is refused as a whole (nothing is queued for any
// location), with a stable code and the location that was refused.
func TestDeployRefusalsAtRequestTime(t *testing.T) {
	// A refusal about the certificate (no key, not valid) is decided before any location is looked
	// at and names none; one decided for a location names it.
	refused := func(t *testing.T, n *nj, rec *httptest.ResponseRecorder, status int, code, location string) {
		t.Helper()
		requireError(t, rec, status, code)
		if location != "" {
			assert.Equal(t, location, decodeBody[paramsBody](t, rec).Error.Params["location_id"], "the refused location is named")
		}
	}
	noDeployments := func(t *testing.T, n *nj) {
		t.Helper()
		assert.Zero(t, n.count("deployments"))
		assert.Zero(t, n.count("jobs WHERE type = 'certificate.deploy'"))
		assert.Zero(t, n.f.emu.DeployCount())
	}

	t.Run("a website Alice cannot manage", func(t *testing.T) {
		n := newNJ(t, wwwSite())
		n.f.emu.AddUnsupported([]string{"vars.example.test"}, 443, "/etc/nginx/ssl/$host.crt", "variable")
		n.discover(n.admin, n.targetID)
		bad := n.locationIDs(n.admin, n.targetID)["/etc/nginx/ssl/$host.crt"]
		certID := n.uploadCertificate(n.op, certBody(n.issue(), "New"))
		refused(t, n, n.requestDeploy(n.op, certID, bad), http.StatusConflict, "ALC-NGX-0007", bad)
		// All or nothing: the supported website in the same request is not deployed either.
		refused(t, n, n.requestDeploy(n.op, certID, n.locs[wwwCert], bad), http.StatusConflict, "ALC-NGX-0007", bad)
		noDeployments(t, n)
		assert.Equal(t, 2, n.auditCount("deployment.denied"))
	})
	t.Run("a certificate without a private key", func(t *testing.T) {
		n := newNJ(t, wwwSite())
		discovered := n.location(n.admin, n.targetID, wwwCert)["certificate"].(map[string]any)["id"].(string)
		refused(t, n, n.requestDeploy(n.op, discovered, n.locs[wwwCert]), http.StatusConflict, "ALC-CRT-0009", "")
		noDeployments(t, n)
	})
	t.Run("not yet valid and expired", func(t *testing.T) {
		n := newNJ(t, wwwSite())
		now := n.clock.Now()
		future := n.ca.Issue(pki.Opts{CommonName: wwwName, SANs: []string{wwwName}, NotBefore: now.Add(time.Hour), NotAfter: now.Add(48 * time.Hour)}, now)
		refused(t, n, n.requestDeploy(n.op, n.uploadCertificate(n.op, certBody(future, "Future")), n.locs[wwwCert]), http.StatusConflict,
			"ALC-CRT-0014", "")
		short := n.ca.Issue(pki.Opts{CommonName: wwwName, SANs: []string{wwwName}, NotAfter: now.Add(2 * time.Hour)}, now)
		shortID := n.uploadCertificate(n.op, certBody(short, "Short"))
		n.clock.Advance(3 * time.Hour)
		n.signIn(n.op, n.opAcct)
		refused(t, n, n.requestDeploy(n.op, shortID, n.locs[wwwCert]), http.StatusUnprocessableEntity, "ALC-CRT-0003", "")
		noDeployments(t, n)
	})
	t.Run("already in progress", func(t *testing.T) {
		n := newNJ(t, wwwSite())
		certID := n.uploadCertificate(n.op, certBody(n.issue(), "New"))
		first := n.deploy(n.op, certID, n.locs[wwwCert])
		rec := n.requestDeploy(n.op, certID, n.locs[wwwCert])
		refused(t, n, rec, http.StatusConflict, "ALC-DEP-0001", n.locs[wwwCert])
		assert.Equal(t, 1, n.count("deployments"), "the second request created nothing")
		n.runJobs()
		assert.Equal(t, "succeeded", n.deployment(n.op, first[0].ID).Status)
		assert.Equal(t, 1, n.f.emu.DeployCount())
	})
	t.Run("a recovery is pending", func(t *testing.T) {
		n := newNJ(t, wwwSite())
		certID := n.uploadCertificate(n.op, certBody(n.issue(), "New"))
		n.f.emu.HangupAfter(helperproto.StepReload)
		first := n.deploy(n.op, certID, n.locs[wwwCert])
		n.runJobs()
		d := n.deployment(n.op, first[0].ID)
		require.Equal(t, "recovering", d.State)
		assert.Equal(t, "uncertain", d.Result)
		other := n.uploadCertificate(n.op, certBody(n.issue(), "Another"))
		refused(t, n, n.requestDeploy(n.op, other, n.locs[wwwCert]), http.StatusConflict, "ALC-DEP-0002", n.locs[wwwCert])
		assert.Equal(t, 1, n.count("deployments"))
		assert.Equal(t, "succeeded", n.settle(n.op, first[0].ID).Status, "the recovery finishes the first deployment")
		assert.Equal(t, 1, n.f.emu.DeployCount())
	})
	t.Run("too many and unknown locations", func(t *testing.T) {
		n := newNJ(t, wwwSite())
		certID := n.uploadCertificate(n.op, certBody(n.issue(), "New"))
		var ids []string
		for range 21 {
			ids = append(ids, uuid.NewString())
		}
		requireError(t, n.requestDeploy(n.op, certID, ids...), http.StatusUnprocessableEntity, "ALC-SYS-0006")
		requireError(t, n.requestDeploy(n.op, certID), http.StatusUnprocessableEntity, "ALC-SYS-0006")
		unknown := uuid.NewString()
		refused(t, n, n.requestDeploy(n.op, certID, n.locs[wwwCert], unknown), http.StatusNotFound, "ALC-SYS-0001", unknown)
		refused(t, n, n.requestDeploy(n.op, uuid.NewString(), n.locs[wwwCert]), http.StatusNotFound, "ALC-SYS-0001", "")
		noDeployments(t, n)
	})
}
