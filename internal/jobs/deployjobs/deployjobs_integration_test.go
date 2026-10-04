//go:build integration

package deployjobs

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/inventory"
	"alice/internal/jobs"
	"alice/internal/providers"
	"alice/internal/providers/linuxssh/helperproto"
	"alice/internal/testutil/pki"
)

func stepList(steps []inventory.DeploymentStep) []string {
	out := []string{}
	for _, s := range steps {
		out = append(out, s.Name+":"+s.Status)
	}
	return out
}

// The journey of spec §12.6 through the real queue, runner, inventory, nginx provider and the
// emulated server.
func TestDeployJourneyThroughTheQueue(t *testing.T) {
	e := newEnv(t)
	s := e.addServer("web-01", wwwSite())
	reloads := s.emu.Reloads()
	id := e.request(s.locs[wwwCert])[0]
	e.drain()

	d := e.deployment(id)
	assert.Equal(t, inventory.DeployStateDone, d.State)
	assert.Equal(t, inventory.DeployStatusSucceeded, d.Status)
	assert.Equal(t, "remote", d.Verified)
	assert.Equal(t, []string{"verify_current:started", "verify_current:ok", "backup:ok", "write_key:ok", "write_cert:ok", "config_test:ok",
		"reload:ok", "verify:started", "verify:ok"}, stepList(d.Steps))
	assert.Equal(t, pki.Fingerprint(e.old.Cert), d.PreviousFingerprint, "the served certificate before the change is recorded")
	assert.Equal(t, 2, d.NewChainLength)
	assert.Equal(t, 2, d.PreviousChainLength)
	require.NotNil(t, d.OperationID)
	assert.Equal(t, id, *d.OperationID)
	e.assertPair(s, wwwCert, wwwKey, wwwName, e.nw)
	assert.Equal(t, reloads+1, s.emu.Reloads())
	assert.Equal(t, 1, s.emu.DeployCount())

	loc := e.location(s, wwwCert)
	assert.Equal(t, pki.Fingerprint(e.nw.Cert), loc.DeployedFingerprint)
	assert.Equal(t, sha(e.nw.FullchainPEM), loc.CertFileSHA256, "the next deployment's compare-and-swap expects the file Alice wrote")

	for _, a := range []string{"deployment.requested", "deployment.precheck_started", "deployment.started", "deployment.succeeded"} {
		assert.Equal(t, 1, e.audits(a), a)
	}
	assert.Zero(t, e.count("SELECT count(*) FROM notifications_outbox WHERE template_key LIKE 'deployment.%'"), "a success sends no email")
	v := e.jobOf(id)
	assert.Equal(t, jobs.StatusSucceeded, v.Status)
	assert.Equal(t, "succeeded", v.Result["outcome"])
	assert.Equal(t, "remote", v.Result["verified"])
}

func (e *env) location(s *server, certPath string) inventory.CertificateLocation {
	e.t.Helper()
	list, err := e.inv.ListLocations(e.ctx, s.target, false)
	require.NoError(e.t, err)
	for _, l := range list.Items {
		if l.CertPath == certPath {
			return l
		}
	}
	e.t.Fatalf("no location %s", certPath)
	return inventory.CertificateLocation{}
}

// A second request of the same certificate after a success ends unchanged, without a reload.
func TestDeploySameCertificateTwice(t *testing.T) {
	e := newEnv(t)
	s := e.addServer("web-01", wwwSite())
	first := e.request(s.locs[wwwCert])[0]
	e.drain()
	require.Equal(t, inventory.DeployStatusSucceeded, e.deployment(first).Status)
	reloads := s.emu.Reloads()
	second := e.request(s.locs[wwwCert])[0]
	e.drain()
	d := e.deployment(second)
	assert.Equal(t, inventory.DeployStatusUnchanged, d.Status)
	assert.Equal(t, reloads, s.emu.Reloads(), "no second reload")
	e.assertPair(s, wwwCert, wwwKey, wwwName, e.nw)
}

// concurrency tracks the deployments in flight per server.
type concurrency struct {
	mu       sync.Mutex
	inFlight map[uuid.UUID]int
	max      int
}

type countingSession struct {
	providers.Session
	c      *concurrency
	target uuid.UUID
}

func (s countingSession) DeployCertificate(ctx context.Context, req providers.DeployRequest, log providers.StepLogger) (providers.DeployOutcome, error) {
	s.c.mu.Lock()
	s.c.inFlight[s.target]++
	s.c.max = max(s.c.max, s.c.inFlight[s.target])
	s.c.mu.Unlock()
	time.Sleep(20 * time.Millisecond) // give an overlapping run its chance
	defer func() {
		s.c.mu.Lock()
		s.c.inFlight[s.target]--
		s.c.mu.Unlock()
	}()
	return s.Session.DeployCertificate(ctx, req, log)
}

// F-15: deployments to one server never overlap (the queue's per-target lock); a batch is one
// deployment per website, each with its own job.
func TestF15DeploymentsToOneServerNeverOverlap(t *testing.T) {
	e := newEnv(t)
	a := e.addServer("web-01", wwwSite(), apiSite())
	b := e.addServer("web-02", wwwSite())
	c := &concurrency{inFlight: map[uuid.UUID]int{}}
	e.setWrap(func(t providers.TargetRef, s providers.Session) providers.Session {
		return countingSession{Session: s, c: c, target: t.ID}
	})
	ids := e.request(a.locs[wwwCert], a.locs[apiCert], b.locs[wwwCert])
	second := e.newRunner("alice-2")
	e.register(second)
	var wg sync.WaitGroup
	for _, r := range []*jobs.Runner{e.runner, second} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 20 {
				ran, err := r.RunOnce(e.ctx)
				assert.NoError(t, err)
				if !ran {
					return
				}
			}
		}()
	}
	wg.Wait()
	e.drain()
	for _, id := range ids {
		assert.Equal(t, inventory.DeployStatusSucceeded, e.deployment(id).Status)
	}
	assert.Equal(t, 1, c.max, "at most one deployment in flight per server")
	assert.Equal(t, 2, a.emu.DeployCount())
	e.assertPair(a, wwwCert, wwwKey, wwwName, e.nw)
	e.assertPair(a, apiCert, apiKey, apiName, e.nw)
	e.assertPair(b, wwwCert, wwwKey, wwwName, e.nw)
}

// F-16: one request for two servers; one fails and is rolled back, the other succeeds.
func TestF16OneServerFailsTheOtherSucceeds(t *testing.T) {
	e := newEnv(t)
	a := e.addServer("web-01", wwwSite())
	b := e.addServer("web-02", wwwSite())
	b.emu.FailReload(1)
	ids := e.request(a.locs[wwwCert], b.locs[wwwCert])
	e.drain()
	assert.Equal(t, inventory.DeployStatusSucceeded, e.deployment(ids[0]).Status)
	d := e.deployment(ids[1])
	assert.Equal(t, inventory.DeployStatusRolledBack, d.Status)
	assert.Equal(t, "deployment.reload_failed", d.ErrorCode)
	assert.Equal(t, "reload", d.FailedStep)
	e.assertPair(a, wwwCert, wwwKey, wwwName, e.nw)
	e.assertPair(b, wwwCert, wwwKey, wwwName, e.old)
	assert.Equal(t, 1, e.count("SELECT count(*) FROM notifications_outbox WHERE template_key = 'deployment.failed'"), "one email for the failure")
	v := e.jobOf(ids[1])
	assert.Equal(t, jobs.StatusFailed, v.Status, "the job ends failed, not dead: the deployment email is the alert")
	assert.Zero(t, e.count("SELECT count(*) FROM notifications_outbox WHERE template_key = 'job.dead'"))
}

// F-19 at run time: a certificate that expired after the request is refused before any change.
func TestF19ExpiredAtRunTimeIsRefusedAndAudited(t *testing.T) {
	e := newEnv(t)
	s := e.addServer("web-01", wwwSite())
	id := e.request(s.locs[wwwCert])[0]
	e.clock.Advance(e.nw.Cert.NotAfter.Sub(e.clock.Now()) + time.Minute)
	e.drain()
	d := e.deployment(id)
	assert.Equal(t, inventory.DeployStatusFailed, d.Status)
	assert.Equal(t, "certificate.expired", d.ErrorCode)
	assert.Zero(t, s.emu.DeployCount())
	assert.Equal(t, 1, e.audits("deployment.failed"))
	assert.Zero(t, e.audits("deployment.started"))
	e.assertPair(s, wwwCert, wwwKey, wwwName, e.old)
}

// F-07: a website Alice cannot check is never changed; F-06: neither is one where something else
// answers.
func TestPrecheckRefusesWebsitesAliceCannotCheck(t *testing.T) {
	for _, tc := range []struct {
		name   string
		setup  func(e *env, s *server)
		reason string
	}{
		{"F-07 unreachable", func(_ *env, s *server) { s.emu.LocalProbeFails(true) }, "deployment.verify_unreachable"},
		{"F-06 something else answers", func(_ *env, s *server) { s.emu.ServeOther(443, sha([]byte("other"))) }, "deployment.verify_other"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			s := e.addServer("web-01", wwwSite())
			// Two servers make Alice's own probe unreachable: only the server's probe decides.
			e.addServer("web-02", wwwSite())
			tc.setup(e, s)
			id := e.request(s.locs[wwwCert])[0]
			e.drain()
			d := e.deployment(id)
			assert.Equal(t, inventory.DeployStatusFailed, d.Status)
			assert.Equal(t, tc.reason, d.ErrorCode)
			assert.Equal(t, "443", d.ErrorParams["port"])
			assert.Equal(t, "verify_current", d.FailedStep, "the pre-check is the step that refused")
			assert.Equal(t, 1, e.count("SELECT count(*) FROM audit_log WHERE action = 'deployment.failed' AND details->>'failed_step' = 'verify_current'"))
			assert.Zero(t, s.emu.DeployCount(), "nothing was sent")
			assert.Equal(t, []string{"verify_current:started", "verify_current:failed"}, stepList(d.Steps))
		})
	}
}

// unreachableVerify is a session whose verification cannot reach the server (a retryable failure
// before any change).
type unreachableVerify struct{ providers.Session }

func (unreachableVerify) VerifyDeployment(context.Context, providers.VerifyRequest) (providers.VerifyResult, error) {
	return providers.VerifyResult{}, providers.NewError("ssh.unreachable", true, nil, nil)
}

// A connection failure before any change is retried; after the last attempt the deployment ends
// failed and the job is failed (never dead with a second alert). A permanent one (the helper is
// missing, F-14's kind) ends it at once.
func TestUnreachableServerBeforeTheChange(t *testing.T) {
	e := newEnv(t)
	s := e.addServer("web-01", wwwSite(), apiSite())
	e.setWrap(func(_ providers.TargetRef, s providers.Session) providers.Session { return unreachableVerify{s} })
	id := e.request(s.locs[wwwCert])[0]
	for range 2 {
		e.drain()
		assert.Equal(t, inventory.DeployStatePrecheck, e.deployment(id).State, "retried: nothing was sent")
		e.clock.Advance(time.Hour)
	}
	e.drain()
	d := e.deployment(id)
	assert.Equal(t, inventory.DeployStatusFailed, d.Status)
	assert.Equal(t, "ssh.unreachable", d.ErrorCode)
	assert.Equal(t, "verify_current", d.FailedStep, "the pre-check could not be completed")
	v := e.jobOf(id)
	assert.Equal(t, jobs.StatusFailed, v.Status)
	assert.Equal(t, 3, v.Attempts)
	assert.Zero(t, e.count("SELECT count(*) FROM notifications_outbox WHERE template_key = 'job.dead'"))
	assert.Equal(t, 1, e.count("SELECT count(*) FROM notifications_outbox WHERE template_key = 'deployment.failed'"))
	assert.Zero(t, s.emu.DeployCount())

	e.setWrap(nil)
	s.emu.SetHelperMissing(true)
	id = e.request(s.locs[apiCert])[0]
	e.drain()
	d = e.deployment(id)
	assert.Equal(t, inventory.DeployStatusFailed, d.Status)
	assert.Equal(t, "ssh.helper_missing", d.ErrorCode)
	assert.Empty(t, d.FailedStep, "no step ran: the session could not be used")
	assert.Equal(t, 1, e.jobOf(id).Attempts, "a permanent failure is not retried")
	assert.Zero(t, e.count("SELECT count(*) FROM notifications_outbox WHERE template_key = 'job.dead'"))
}

// F-08: the connection drops while the helper runs: the outcome is uncertain, the recovery
// verifies the journal's commit and ends succeeded.
func TestLostConnectionDuringTheSendIsRecovered(t *testing.T) {
	e := newEnv(t)
	s := e.addServer("web-01", wwwSite())
	id := e.request(s.locs[wwwCert])[0]
	s.emu.HangupAfter(helperproto.StepReload)
	e.drain()
	d := e.deployment(id)
	require.Equal(t, inventory.DeployStateRecovering, d.State)
	assert.Equal(t, "uncertain", d.Result)
	require.NotNil(t, d.RecoverAfter)
	assert.Equal(t, e.clock.Now().Add(inventory.FirstRecoveryDelay), *d.RecoverAfter)
	v := e.jobOf(id)
	assert.Equal(t, jobs.StatusFailed, v.Status)
	assert.Equal(t, "deployment.interrupted", v.LastErrorCode)
	d = e.settle(id)
	assert.Equal(t, inventory.DeployStatusSucceeded, d.Status)
	e.assertPair(s, wwwCert, wwwKey, wwwName, e.nw)
	assert.Equal(t, 1, s.emu.DeployCount(), "never sent twice")
	assert.Equal(t, 1, e.audits("deployment.recovery_started"))
}

// F-05 with a lost answer: the reload did nothing, the answer was lost; the recovery's own
// verification fails and it rolls back.
func TestRecoveryRollsBackAnUnservedCommit(t *testing.T) {
	e := newEnv(t)
	s := e.addServer("web-01", wwwSite())
	id := e.request(s.locs[wwwCert])[0]
	s.emu.NoopReload(true)
	s.emu.HangupAfter(helperproto.StepReload)
	e.drain()
	require.Equal(t, helperproto.PhaseCommitted, s.emu.NginxPhase(id.String()))
	d := e.settle(id)
	assert.Equal(t, inventory.DeployStatusRolledBack, d.Status)
	assert.Equal(t, "deployment.verify_failed", d.ErrorCode)
	assert.Equal(t, "deployment.verify_failed", d.VerifyFailedReason)
	e.assertPair(s, wwwCert, wwwKey, wwwName, e.old)
	assert.Equal(t, 1, e.audits("deployment.rolled_back"))
}

// F-17: an incomplete chain is refused unless an Administrator confirms it (RequestDeployment,
// audited); a confirmed one is deployed as it is and verified with the chain length recorded.
func TestF17IncompleteChainNeedsAnAdministrator(t *testing.T) {
	e := newEnv(t)
	s := e.addServer("web-01", wwwSite())
	other := pki.NewCA("Other", pki.ECDSA256, e.clock.Now()).Issue(pki.Opts{CommonName: wwwName, SANs: []string{wwwName}}, e.clock.Now())
	c, _, err := e.inv.UploadCertificate(e.ctx, e.admin, inventory.UploadInput{CertificatePEM: string(other.FullchainPEM),
		PrivateKeyPEM: string(other.KeyPEM)})
	require.NoError(t, err)
	require.False(t, c.ChainComplete)
	_, err = e.inv.RequestDeployment(e.ctx, e.admin, inventory.DeployRequestInput{CertificateID: c.ID, LocationIDs: []uuid.UUID{s.locs[wwwCert]}})
	require.ErrorIs(t, err, inventory.ErrChainUnconfirmed)
	assert.Equal(t, 1, e.audits("deployment.denied"))

	got, err := e.inv.RequestDeployment(e.ctx, e.admin, inventory.DeployRequestInput{CertificateID: c.ID, LocationIDs: []uuid.UUID{s.locs[wwwCert]},
		ConfirmIncompleteChain: true})
	require.NoError(t, err)
	e.drain()
	d := e.deployment(got[0].ID)
	assert.Equal(t, inventory.DeployStatusSucceeded, d.Status)
	assert.True(t, d.ConfirmIncompleteChain)
	assert.Equal(t, 2, d.NewChainLength, "the chain as uploaded is what was sent and verified")
	assert.Equal(t, pki.Fingerprint(other.Cert), s.emu.Served(443, wwwName))
}

// The verification of the new certificate fails and the helper's own rollback ends restore_failed
// (its reload fails, so Nginx still holds the new certificate); the engine's one more nginx-restore
// puts everything back. The record keeps why the deployment was rolled back: the verification
// failure the run recorded before the restore, not "interrupted".
func TestRollbackAfterARestoreFailureKeepsTheVerificationCause(t *testing.T) {
	e := newEnv(t)
	s := e.addServer("web-01", wwwSite())
	// Something else answers after the deployment's reload; the rollback's first reload fails.
	s.emu.ServeOtherAfterReload(443, sha([]byte("balancer")))
	s.emu.ArmFaultsFor(helperproto.SubNginxRestore)
	s.emu.FailReload(1)
	id := e.request(s.locs[wwwCert])[0]
	e.drain()
	d := e.deployment(id)
	assert.Equal(t, inventory.DeployStateDone, d.State)
	assert.Equal(t, inventory.DeployStatusRolledBack, d.Status)
	assert.Equal(t, "deployment.verify_other", d.ErrorCode, "the cause is the verification that failed, not an interruption")
	assert.Equal(t, "deployment.verify_other", d.VerifyFailedReason)
	require.NotNil(t, d.VerifyFailedPort)
	assert.Equal(t, 443, *d.VerifyFailedPort)
	assert.Equal(t, "verify", d.CauseStep)
	e.assertPair(s, wwwCert, wwwKey, wwwName, e.old)
}

// A sent deployment whose answer was lost, then Alice stays down for 8 days: the helper's sweep
// removed the committed journal, so nginx-status answers none although the new pair is live and
// was never verified. That is not "nothing was written": the outcome is unknown (rollback_failed,
// deployment.outcome_unknown, the outcome-unknown email), the location is released, and nothing is
// sent or restored.
func TestRecoveryAfterALongOutageWithoutAJournalIsUnknown(t *testing.T) {
	e := newEnv(t)
	s := e.addServer("web-01", wwwSite())
	id := e.request(s.locs[wwwCert])[0]
	s.emu.HangupAfter(helperproto.StepReload)
	e.drain()
	require.Equal(t, inventory.DeployStateRecovering, e.deployment(id).State)
	require.Equal(t, helperproto.PhaseCommitted, s.emu.NginxPhase(id.String()))

	e.clock.Advance(8 * 24 * time.Hour)
	s.emu.SweepOperation(id.String())
	d := e.settle(id)
	assert.Equal(t, inventory.DeployStatusRollbackFailed, d.Status)
	assert.Equal(t, "deployment.outcome_unknown", d.ErrorCode)
	assert.Equal(t, 1, e.count("SELECT count(*) FROM notifications_outbox WHERE template_key = 'deployment.outcome_unknown'"))
	assert.Zero(t, e.count("SELECT count(*) FROM notifications_outbox WHERE template_key = 'deployment.failed'"), "never \"nothing changed\"")
	assert.Equal(t, 1, e.audits("deployment.rollback_failed"))
	assert.Zero(t, e.audits("deployment.failed"))
	assert.Equal(t, 1, s.emu.DeployCount(), "never sent twice")
	e.assertPair(s, wwwCert, wwwKey, wwwName, e.nw) // the files were left as the outage found them

	// The location is released: a new deployment can be requested.
	again := e.request(s.locs[wwwCert])
	assert.Len(t, again, 1)
}

// Just under the threshold a missing journal is fenced and means "nothing was written" (a journal
// swept within the day by a server clock jump is the documented limitation this pins).
func TestRecoveryWithoutAJournalJustUnderADayIsNothingWritten(t *testing.T) {
	e := newEnv(t)
	s := e.addServer("web-01", wwwSite())
	id := e.request(s.locs[wwwCert])[0]
	s.emu.HangupAfter(helperproto.StepReload)
	e.drain()
	require.Equal(t, inventory.DeployStateRecovering, e.deployment(id).State)
	started := *e.deployment(id).StartedAt

	s.emu.SweepOperation(id.String())
	e.clock.Advance(noJournalUnknownAfter - 5*time.Minute - e.clock.Now().Sub(started))
	d := e.settle(id)
	assert.Equal(t, inventory.DeployStatusFailed, d.Status)
	assert.Equal(t, "deployment.interrupted", d.ErrorCode)
	require.NotNil(t, d.FinishedAt)
	assert.Less(t, d.FinishedAt.Sub(started), noJournalUnknownAfter)
}
