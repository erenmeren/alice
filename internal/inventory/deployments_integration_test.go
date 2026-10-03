//go:build integration

package inventory_test

import (
	"crypto/x509"
	"encoding/json"
	"errors"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/certs"
	"alice/internal/inventory"
	"alice/internal/jobs"
	"alice/internal/license"
	"alice/internal/platform/validate"
	"alice/internal/providers"
	"alice/internal/providers/linuxssh/helperproto"
	"alice/internal/rbac"
	"alice/internal/secrets"
	"alice/internal/testutil/pki"
)

// deployFixture: two connected Nginx targets, web-01 (www.crt, b.crt) and web-02 (www.crt, api.crt,
// spare.crt and an unsupported var.crt), every supported location holding the ECDSA leaf old; an
// uploaded ECDSA certificate nw with its key (its chain complete: Config.Roots holds the test CA's
// root); old, discovered without a key; an uploaded RSA certificate of the same CA (D31: its chain
// is complete, so the key type refusal is not masked by the chain check); an uploaded certificate
// of another CA whose chain is incomplete. Jobs go to the real queue (deployments reference job
// rows) and are recorded.
type deployFixture struct {
	h                           *harness
	admin, operator             inventory.Actor
	target1, target2            uuid.UUID
	loc1, loc5                  uuid.UUID // web-01: www.crt, b.crt
	loc2, loc3onTarget2, loc4   uuid.UUID // web-02: www.crt, api.crt, spare.crt
	unsupported                 uuid.UUID // web-02: var.crt
	old, nw, rsaLeaf, otherLeaf pki.Leaf
	cert, discovered            inventory.Certificate
	rsaCert, incomplete         inventory.Certificate
}

func newDeployFixture(t *testing.T) *deployFixture {
	t.Helper()
	ca := pki.NewCA("Dep", pki.ECDSA256, start)
	roots := x509.NewCertPool()
	roots.AddCert(ca.Root)
	h := newHarness(t, withNginxProvider(), withRoots(roots))
	h.jobs.next = jobs.NewQueue(jobs.QueueConfig{Pool: h.db.App, Keyring: h.keyring, Audit: h.audit, Clock: h.clock, Gate: h.lic})
	f := &deployFixture{h: h}
	f.admin = h.user("ada", rbac.Admin, "ada@example.com")
	f.operator = h.user("oya", rbac.Operator, "")
	now := h.clock.Now()
	www := pki.Opts{CommonName: "www.example.test", SANs: []string{"www.example.test"}}
	f.old, f.nw = ca.Issue(www, now), ca.Issue(www, now)
	f.rsaLeaf = ca.Issue(pki.Opts{CommonName: "www.example.test", SANs: []string{"www.example.test"}, KeyType: pki.RSA2048}, now)
	f.otherLeaf = pki.NewCA("Other", pki.ECDSA256, now).Issue(www, now)

	t1, t2 := nginxTarget(t, h, f.admin, "web-01"), nginxTarget(t, h, f.admin, "web-02")
	f.target1, f.target2 = t1.ID, t2.ID
	unsupported := providers.CertLocation{CertPath: "/etc/nginx/ssl/var.crt", KeyPath: "/etc/nginx/ssl/var.key", Supported: false,
		Unsupported: providers.UnsupportedVariable, Servers: []providers.CertServer{{Names: []string{"var.example.test"}}}}
	_, err := h.svc.Reconcile(h.ctx, t1.ID, providers.DiscoveryResult{Nginx: nginxOK, Certificates: []providers.DiscoveredCertificate{
		dc(cl("/etc/nginx/ssl/www.crt", "/etc/nginx/ssl/www.key", "www.example.test"), f.old),
		dc(cl("/etc/nginx/ssl/b.crt", "/etc/nginx/ssl/b.key", "www.example.test"), f.old)}})
	require.NoError(t, err)
	_, err = h.svc.Reconcile(h.ctx, t2.ID, providers.DiscoveryResult{Nginx: nginxOK, Certificates: []providers.DiscoveredCertificate{
		dc(cl("/etc/nginx/ssl/www.crt", "/etc/nginx/ssl/www.key", "www.example.test"), f.old),
		dc(cl("/etc/nginx/ssl/api.crt", "/etc/nginx/ssl/api.key", "www.example.test"), f.old),
		dc(cl("/etc/nginx/ssl/spare.crt", "/etc/nginx/ssl/spare.key", "www.example.test"), f.old),
		{Location: unsupported}}})
	require.NoError(t, err)
	l1, l2 := byPath(t, h, t1.ID, false), byPath(t, h, t2.ID, false)
	f.loc1, f.loc5 = l1["/etc/nginx/ssl/www.crt"].ID, l1["/etc/nginx/ssl/b.crt"].ID
	f.loc2, f.loc3onTarget2, f.loc4 = l2["/etc/nginx/ssl/www.crt"].ID, l2["/etc/nginx/ssl/api.crt"].ID, l2["/etc/nginx/ssl/spare.crt"].ID
	f.unsupported = l2["/etc/nginx/ssl/var.crt"].ID
	require.NotEqual(t, uuid.Nil, f.unsupported)

	upload := func(l pki.Leaf) inventory.Certificate {
		c, _, err := h.svc.UploadCertificate(h.ctx, f.admin, pemUpload(l))
		require.NoError(t, err)
		return c
	}
	f.cert, f.rsaCert, f.incomplete = upload(f.nw), upload(f.rsaLeaf), upload(f.otherLeaf)
	require.True(t, f.cert.ChainComplete)
	require.True(t, f.rsaCert.ChainComplete, "D31")
	require.False(t, f.incomplete.ChainComplete)
	f.discovered = f.certByFingerprint(t, pki.Fingerprint(f.old.Cert))
	require.False(t, f.discovered.HasPrivateKey)
	return f
}

func (f *deployFixture) certByFingerprint(t *testing.T, fp string) inventory.Certificate {
	t.Helper()
	page, err := f.h.svc.ListCertificates(f.h.ctx, inventory.CertificateFilter{Query: fp})
	require.NoError(t, err)
	require.Len(t, page.Items, 1)
	return page.Items[0]
}

func (f *deployFixture) setTargetStatus(id uuid.UUID, status string) {
	f.h.t.Helper()
	_, err := f.h.db.Owner.Exec(f.h.ctx, "UPDATE targets SET status = $2 WHERE id = $1", id, status)
	require.NoError(f.h.t, err)
}

func (f *deployFixture) setConfigValid(id uuid.UUID, valid bool) {
	f.h.t.Helper()
	_, err := f.h.db.Owner.Exec(f.h.ctx, "UPDATE targets SET facts = jsonb_set(facts, '{nginx,config_valid}', to_jsonb($2::boolean)) WHERE id = $1",
		id, valid)
	require.NoError(f.h.t, err)
}

// markRecovering inserts, as the owner, a deployment in recovery of spare.crt (D31: a location
// without an active deployment) on the target.
func (f *deployFixture) markRecovering(target uuid.UUID) uuid.UUID {
	f.h.t.Helper()
	require.Equal(f.h.t, f.target2, target, "spare.crt is on web-02")
	id := uuid.Must(uuid.NewV7())
	_, err := f.h.db.Owner.Exec(f.h.ctx, `INSERT INTO deployments (id, certificate_id, location_id, target_id, trigger, state, status,
new_fingerprint, cert_path, key_path, created_at) VALUES ($1, $2, $3, $4, 'manual', 'recovering', 'running', $5, '/etc/nginx/ssl/spare.crt',
'/etc/nginx/ssl/spare.key', $6)`, id, f.cert.ID, f.loc4, target, f.cert.Fingerprint, f.h.clock.Now())
	require.NoError(f.h.t, err)
	return id
}

func (f *deployFixture) request(a inventory.Actor, cert uuid.UUID, locs ...uuid.UUID) uuid.UUID {
	f.h.t.Helper()
	got, err := f.h.svc.RequestDeployment(f.h.ctx, a, inventory.DeployRequestInput{CertificateID: cert, LocationIDs: locs})
	require.NoError(f.h.t, err)
	require.Len(f.h.t, got, len(locs))
	return got[0].ID
}

// deploying is a deployment of nw to loc that the engine has started (state deploying).
func (f *deployFixture) deploying(loc uuid.UUID) uuid.UUID {
	f.h.t.Helper()
	id := f.request(f.admin, f.cert.ID, loc)
	f.start(id)
	return id
}

func (f *deployFixture) start(id uuid.UUID) {
	f.h.t.Helper()
	_, err := f.h.svc.BeginDeployment(f.h.ctx, id)
	require.NoError(f.h.t, err)
	require.NoError(f.h.t, f.h.svc.StartDeployment(f.h.ctx, id, pki.Fingerprint(f.old.Cert), providers.BackupRef{OperationID: id}))
}

func (f *deployFixture) get(id uuid.UUID) inventory.Deployment {
	f.h.t.Helper()
	d, err := f.h.svc.Deployment(f.h.ctx, id)
	require.NoError(f.h.t, err)
	return d
}

func (f *deployFixture) jobStatus(id uuid.UUID, status, code string) {
	f.h.t.Helper()
	_, err := f.h.db.Owner.Exec(f.h.ctx, `UPDATE jobs SET status = $2, last_error_code = $3,
finished_at = CASE WHEN $2 IN ('succeeded', 'failed', 'cancelled', 'dead') THEN $4::timestamptz END WHERE id = $1`,
		id, status, code, f.h.clock.Now())
	require.NoError(f.h.t, err)
}

func (f *deployFixture) jobOf(id uuid.UUID) uuid.UUID {
	f.h.t.Helper()
	d := f.get(id)
	require.NotNil(f.h.t, d.JobID)
	return *d.JobID
}

type outboxRow struct {
	Template string
	Params   map[string]string
}

func (f *deployFixture) emails() []outboxRow {
	f.h.t.Helper()
	rows, err := f.h.db.Owner.Query(f.h.ctx, "SELECT template_key, params FROM notifications_outbox WHERE template_key LIKE 'deployment.%' ORDER BY created_at, id")
	require.NoError(f.h.t, err)
	defer rows.Close()
	var out []outboxRow
	for rows.Next() {
		var r outboxRow
		require.NoError(f.h.t, rows.Scan(&r.Template, &r.Params))
		out = append(out, r)
	}
	require.NoError(f.h.t, rows.Err())
	return out
}

// recoverJobs is the certificate.deploy_recover jobs of a deployment, oldest first, as "status".
func (f *deployFixture) recoverJobs(id uuid.UUID) []string {
	f.h.t.Helper()
	rows, err := f.h.db.Owner.Query(f.h.ctx, `SELECT status FROM jobs WHERE type = 'certificate.deploy_recover' AND dedupe_key = $1
ORDER BY created_at, id`, "certificate.deploy_recover:"+id.String())
	require.NoError(f.h.t, err)
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var s string
		require.NoError(f.h.t, rows.Scan(&s))
		out = append(out, s)
	}
	require.NoError(f.h.t, rows.Err())
	return out
}

func stepNames(steps []inventory.DeploymentStep) []string {
	out := []string{}
	for _, s := range steps {
		out = append(out, s.Name+":"+s.Status)
	}
	return out
}

func TestRequestDeploymentQueuesOneJobPerLocation(t *testing.T) {
	f := newDeployFixture(t)
	before := len(f.h.jobs.requests())
	got, err := f.h.svc.RequestDeployment(f.h.ctx, f.operator, inventory.DeployRequestInput{CertificateID: f.cert.ID,
		LocationIDs: []uuid.UUID{f.loc1, f.loc2}})
	require.NoError(t, err)
	require.Len(t, got, 2)
	assert.Equal(t, f.loc1, got[0].LocationID, "in the order asked")
	assert.Equal(t, f.loc2, got[1].LocationID)
	assert.Equal(t, []string{}, got[0].Warnings)
	reqs := f.h.jobs.requests()[before:]
	require.Len(t, reqs, 2)
	assert.Equal(t, inventory.JobCertificateDeploy, reqs[0].Type)
	assert.Equal(t, map[string]string{"deployment_id": got[0].ID.String()}, reqs[0].Payload, "ids only, never key material")
	assert.Equal(t, "certificate.deploy:"+got[0].ID.String(), reqs[0].DedupeKey)
	assert.Equal(t, f.target1, reqs[0].TargetID)
	assert.Equal(t, "user", reqs[0].Kind)
	assert.Equal(t, f.operator.UserID, reqs[0].CreatedBy)
	assert.Equal(t, string(rbac.Operator), reqs[0].CreatedByRole)
	d, err := f.h.svc.Deployment(f.h.ctx, got[0].ID)
	require.NoError(t, err)
	assert.Equal(t, inventory.DeployStateQueued, d.State)
	assert.Equal(t, inventory.DeployStatusPending, d.Status)
	assert.Equal(t, "/etc/nginx/ssl/www.crt", d.CertPath)
	assert.Equal(t, "/etc/nginx/ssl/www.key", d.KeyPath)
	assert.Equal(t, pki.Fingerprint(f.nw.Cert), d.NewFingerprint)
	assert.Equal(t, "manual", d.Trigger)
	assert.Equal(t, got[0].JobID, *d.JobID, "the deployment names its job")
	assert.Equal(t, "web-01", d.TargetName)
	assert.Equal(t, "www.example.test", d.CertificateName)
	assert.Equal(t, "oya Yılmaz", d.RequestedByName)
	assert.Equal(t, map[string]string{}, d.ErrorParams)
	assert.Equal(t, 2, f.h.audits("deployment.requested"))
	assert.Equal(t, map[string]string{"deployment_id": got[0].ID.String(), "certificate_id": f.cert.ID.String(), "location_id": f.loc1.String(),
		"cert_path": "/etc/nginx/ssl/www.crt", "job_id": got[0].JobID.String(), "confirm_incomplete_chain": "false"},
		f.h.auditDetails("deployment.requested")[0])
	var class string
	var maxAttempts int
	require.NoError(t, f.h.db.Owner.QueryRow(f.h.ctx, "SELECT class, max_attempts FROM jobs WHERE id = $1", got[0].JobID).Scan(&class, &maxAttempts))
	assert.Equal(t, "change", class, "a deployment changes a server: refused and held in lock")
	assert.Equal(t, 3, maxAttempts)
	loc, err := f.h.svc.GetLocation(f.h.ctx, f.loc1)
	require.NoError(t, err)
	assert.Equal(t, &got[0].ID, loc.ActiveDeploymentID)
}

func TestRequestDeploymentRefusals(t *testing.T) {
	f := newDeployFixture(t)
	ctx := f.h.ctx
	req := func(a inventory.Actor, cert uuid.UUID, confirm bool, locs ...uuid.UUID) error {
		_, err := f.h.svc.RequestDeployment(ctx, a, inventory.DeployRequestInput{CertificateID: cert, LocationIDs: locs, ConfirmIncompleteChain: confirm})
		return err
	}
	// F-15: one active deployment per location.
	require.NoError(t, req(f.operator, f.cert.ID, false, f.loc1))
	assert.ErrorIs(t, req(f.operator, f.cert.ID, false, f.loc1), inventory.ErrDeploymentInProgress)
	// A discovered certificate without its key.
	assert.ErrorIs(t, req(f.operator, f.discovered.ID, false, f.loc2), inventory.ErrNoPrivateKey)
	// F-19: expired.
	f.h.clock.Advance(400 * 24 * time.Hour)
	assert.ErrorIs(t, req(f.operator, f.cert.ID, false, f.loc2), inventory.ErrCertificateExpired)
	f.h.clock.Advance(-400 * 24 * time.Hour)
	// Key type: an RSA certificate into an ECDSA place.
	err := req(f.operator, f.rsaCert.ID, false, f.loc2)
	var kt *inventory.KeyTypeMismatchError
	require.ErrorAs(t, err, &kt)
	assert.Equal(t, inventory.KeyTypeMismatchError{Expected: "ecdsa", Actual: "rsa"}, *kt)
	assert.ErrorIs(t, err, inventory.ErrKeyTypeMismatch)
	// F-17: an incomplete chain needs an Administrator's confirmation.
	assert.ErrorIs(t, req(f.operator, f.incomplete.ID, true, f.loc2), inventory.ErrChainUnconfirmed, "an Operator's confirmation does not count")
	assert.ErrorIs(t, req(f.admin, f.incomplete.ID, false, f.loc2), inventory.ErrChainUnconfirmed)
	require.NoError(t, req(f.admin, f.incomplete.ID, true, f.loc2))
	// Unsupported, missing, not ready, invalid configuration, recovery pending.
	assert.ErrorIs(t, req(f.admin, f.cert.ID, false, f.unsupported), inventory.ErrLocationUnsupported)
	f.setTargetStatus(f.target2, "host_key_changed")
	assert.ErrorIs(t, req(f.admin, f.cert.ID, false, f.loc3onTarget2), inventory.ErrTargetNotReady)
	f.setTargetStatus(f.target2, "pending_host_key")
	assert.ErrorIs(t, req(f.admin, f.cert.ID, false, f.loc3onTarget2), inventory.ErrTargetNotReady)
	f.setTargetStatus(f.target2, "ok")
	f.setConfigValid(f.target2, false)
	assert.ErrorIs(t, req(f.admin, f.cert.ID, false, f.loc3onTarget2), inventory.ErrNginxConfigInvalid)
	f.setConfigValid(f.target2, true)
	f.markRecovering(f.target2)
	assert.ErrorIs(t, req(f.admin, f.cert.ID, false, f.loc3onTarget2), inventory.ErrRecoveryPending)
	// All or nothing: a refused location queues none of the others.
	before := len(f.h.jobs.requests())
	deployments := f.h.count("SELECT count(*) FROM deployments")
	assert.Error(t, req(f.admin, f.cert.ID, false, f.loc5, f.unsupported))
	assert.Len(t, f.h.jobs.requests(), before)
	assert.Equal(t, deployments, f.h.count("SELECT count(*) FROM deployments"))
	var verrs validate.Errors
	require.ErrorAs(t, req(f.admin, f.cert.ID, false), &verrs, "no location")
	assert.Equal(t, map[string]string{"location_ids": validate.OutOfRange}, fieldsOf(verrs))
	assert.Equal(t, map[string]string{"min": "1", "max": "20"}, verrs[0].Params)
	many := make([]uuid.UUID, 21)
	for i := range many {
		many[i] = uuid.New()
	}
	assert.Equal(t, map[string]string{"location_ids": validate.OutOfRange}, fieldsOf(req(f.admin, f.cert.ID, false, many...)), "R38 #18: 20 websites")
	assert.Equal(t, map[string]string{"location_ids": validate.Pattern}, fieldsOf(req(f.admin, f.cert.ID, false, f.loc5, f.loc5)), "duplicates")
	assert.ErrorIs(t, req(f.admin, uuid.New(), false, f.loc5), inventory.ErrNotFound, "an unknown certificate")
	assert.ErrorIs(t, req(f.admin, f.cert.ID, false, uuid.New()), inventory.ErrNotFound, "an unknown location")
	reasons := []string{}
	for _, d := range f.h.auditDetails("deployment.denied") {
		reasons = append(reasons, d["reason"])
		assert.NotContains(t, d, "key_type", "detail keys pass the denylist")
	}
	assert.Subset(t, reasons, []string{"no_private_key", "expired", "key_type_mismatch", "chain_unconfirmed", "location_unsupported",
		"target_not_ready", "config_invalid", "recovery_pending", "in_progress"})
	denied := f.h.auditDetails("deployment.denied")
	assert.Equal(t, map[string]string{"certificate_id": f.cert.ID.String(), "location_id": f.loc1.String(), "reason": "in_progress"}, denied[0])
	assert.Equal(t, 1, f.h.count("SELECT count(*) FROM audit_log WHERE action = 'deployment.denied' AND result = 'denied' AND details->>'reason' = 'in_progress'"))
}

// A location that went missing at the last scan, a deleted server and a target type without a
// deploying provider are refused too, and a locked license refuses before anything is read.
func TestRequestDeploymentRefusesMissingDeletedAndLocked(t *testing.T) {
	f := newDeployFixture(t)
	ctx := f.h.ctx
	req := func(locs ...uuid.UUID) error {
		_, err := f.h.svc.RequestDeployment(ctx, f.admin, inventory.DeployRequestInput{CertificateID: f.cert.ID, LocationIDs: locs})
		return err
	}
	_, err := f.h.db.Owner.Exec(ctx, "UPDATE certificate_locations SET missing_since = $2 WHERE id = $1", f.loc5, f.h.clock.Now())
	require.NoError(t, err)
	assert.ErrorIs(t, req(f.loc5), inventory.ErrLocationUnsupported, "missing")
	_, err = f.h.db.Owner.Exec(ctx, "UPDATE targets SET type = 'linux' WHERE id = $1", f.target1)
	require.NoError(t, err)
	assert.ErrorIs(t, req(f.loc1), inventory.ErrLocationUnsupported, "not an Nginx server")
	_, err = f.h.db.Owner.Exec(ctx, "UPDATE targets SET type = 'nginx' WHERE id = $1", f.target1)
	require.NoError(t, err)
	f.setTargetStatus(f.target1, "unreachable")
	_, err = f.h.svc.RequestDeployment(ctx, f.admin, inventory.DeployRequestInput{CertificateID: f.cert.ID, LocationIDs: []uuid.UUID{f.loc1}})
	require.NoError(t, err, "unreachable servers are retried by the job")
	require.NoError(t, f.h.svc.DeleteTarget(ctx, f.admin, f.target2))
	assert.ErrorIs(t, req(f.loc2), inventory.ErrNotFound, "a deleted server")

	f.h.clock.Advance(40 * 24 * time.Hour) // the evaluation ends: lock
	require.NoError(t, f.h.lic.Tick(ctx))
	require.ErrorIs(t, f.h.lic.Allow(license.ClassChange), license.ErrLocked)
	assert.ErrorIs(t, req(f.loc5), license.ErrLocked)
	d := f.h.auditDetails("deployment.denied")
	assert.Equal(t, "locked", d[len(d)-1]["reason"])
}

// Two requests for one location at once: exactly one wins, the other is told why.
func TestRequestDeploymentRace(t *testing.T) {
	f := newDeployFixture(t)
	for range 5 {
		var wg sync.WaitGroup
		errs := make([]error, 2)
		for i := range errs {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, errs[i] = f.h.svc.RequestDeployment(f.h.ctx, f.admin, inventory.DeployRequestInput{CertificateID: f.cert.ID,
					LocationIDs: []uuid.UUID{f.loc1}})
			}()
		}
		wg.Wait()
		ok := 0
		for _, err := range errs {
			if err == nil {
				ok++
				continue
			}
			assert.ErrorIs(t, err, inventory.ErrDeploymentInProgress)
		}
		assert.Equal(t, 1, ok)
		// Finish it so the next round races again.
		var id uuid.UUID
		require.NoError(t, f.h.db.Owner.QueryRow(f.h.ctx, "SELECT id FROM deployments WHERE location_id = $1 AND state <> 'done'", f.loc1).Scan(&id))
		require.NoError(t, f.h.svc.FinishDeployment(f.h.ctx, id, inventory.DeploymentFinish{Status: inventory.DeployStatusFailed,
			ErrorCode: "deployment.interrupted"}))
	}
}

// The request and its job commit together: a queue that fails leaves no deployment behind.
func TestRequestDeploymentAndItsJobCommitTogether(t *testing.T) {
	f := newDeployFixture(t)
	f.h.jobs.mu.Lock()
	f.h.jobs.fail = errors.New("queue down")
	f.h.jobs.mu.Unlock()
	_, err := f.h.svc.RequestDeployment(f.h.ctx, f.admin, inventory.DeployRequestInput{CertificateID: f.cert.ID, LocationIDs: []uuid.UUID{f.loc1}})
	require.Error(t, err)
	assert.Zero(t, f.h.count("SELECT count(*) FROM deployments"))
	assert.Zero(t, f.h.audits("deployment.requested"))
	f.request(f.admin, f.cert.ID, f.loc1)
}

func TestRequestDeploymentWarnsAboutNames(t *testing.T) {
	f := newDeployFixture(t)
	ca := pki.NewCA("Dep2", pki.ECDSA256, f.h.clock.Now())
	other := ca.Issue(pki.Opts{CommonName: "other.example.test", SANs: []string{"other.example.test"}}, f.h.clock.Now())
	c, _, err := f.h.svc.UploadCertificate(f.h.ctx, f.admin, pemUpload(other))
	require.NoError(t, err)
	got, err := f.h.svc.RequestDeployment(f.h.ctx, f.admin, inventory.DeployRequestInput{CertificateID: c.ID, LocationIDs: []uuid.UUID{f.loc1},
		ConfirmIncompleteChain: true})
	require.NoError(t, err, "a name mismatch warns, it does not refuse")
	assert.Equal(t, []string{"san_mismatch"}, got[0].Warnings)
	assert.Equal(t, "true", f.h.auditDetails("deployment.requested")[0]["confirm_incomplete_chain"])
	assert.True(t, f.get(got[0].ID).ConfirmIncompleteChain)
}

func TestDeploymentStateMachine(t *testing.T) {
	f := newDeployFixture(t)
	ctx := f.h.ctx
	id := f.request(f.admin, f.cert.ID, f.loc1)
	assert.ErrorIs(t, f.h.svc.StartDeployment(ctx, id, pki.Fingerprint(f.old.Cert), providers.BackupRef{OperationID: id}),
		inventory.ErrDeploymentState, "queued: no precheck yet")
	d, err := f.h.svc.BeginDeployment(ctx, id)
	require.NoError(t, err)
	assert.Equal(t, inventory.DeployStatePrecheck, d.State)
	assert.Equal(t, inventory.DeployStatusRunning, d.Status)
	require.NotNil(t, d.StartedAt)
	again, err := f.h.svc.BeginDeployment(ctx, id)
	require.NoError(t, err)
	assert.Equal(t, d.StartedAt, again.StartedAt, "idempotent")
	assert.Equal(t, 1, f.h.audits("deployment.precheck_started"))

	m, err := f.h.svc.DeploymentMaterial(ctx, id, true)
	require.NoError(t, err)
	assert.Contains(t, string(m.PrivateKeyPEM.Bytes()), "PRIVATE KEY")
	got, err := certs.KeyInfoOf(secrets.NewPlaintext(keyDER(t, m.PrivateKeyPEM.Bytes())))
	require.NoError(t, err)
	want, err := certs.KeyInfoOf(secrets.NewPlaintext(keyDER(t, f.nw.KeyPEM)))
	require.NoError(t, err)
	assert.Equal(t, want.PublicKeySHA256, got.PublicKeySHA256, "the certificate's own key")
	assert.Equal(t, "/etc/nginx/ssl/www.key", m.Location.KeyPath)
	assert.Equal(t, "/etc/nginx/ssl/www.crt", m.Location.CertPath)
	assert.True(t, m.Location.Supported)
	assert.Equal(t, pki.Fingerprint(f.old.Cert), m.CurrentFingerprint)
	assert.Equal(t, []string{"www.example.test"}, m.OldSANs)
	assert.Equal(t, sha(f.old.FullchainPEM), m.ExpectCertSHA256)
	assert.True(t, m.ConfigValid)
	assert.Equal(t, pki.Fingerprint(f.nw.Cert), m.Fingerprint)
	assert.Equal(t, "ecdsa", m.KeyType)
	assert.Equal(t, 2, m.NewChainLength, "leaf and intermediate")
	assert.False(t, m.Recorded)
	assert.Equal(t, f.nw.Cert.NotAfter.UTC(), m.NotAfter)
	pre := m.PrecheckRequest()
	assert.Equal(t, pki.Fingerprint(f.old.Cert), pre.Fingerprint, "the pre-check verifies what is deployed now")
	assert.Equal(t, "ecdsa", pre.KeyType)
	v := m.SendValues(pki.Fingerprint(f.old.Cert), 2)
	assert.Equal(t, inventory.SendValues{OperationID: id, ExpectCertSHA256: sha(f.old.FullchainPEM), NewChainLength: 2,
		PreviousFingerprint: pki.Fingerprint(f.old.Cert), PreviousChainLength: 2}, v)
	dr := m.DeployRequest(v)
	assert.Equal(t, id, dr.OperationID)
	assert.Equal(t, 2, dr.ChainLength)
	assert.Equal(t, pki.Fingerprint(f.old.Cert), dr.OldFingerprint)
	assert.Equal(t, m.PrivateKeyPEM.Bytes(), dr.PrivateKeyPEM.Bytes(), "the same holder: zeroing one zeroes both")
	m.PrivateKeyPEM.Zero()
	assert.NotContains(t, string(dr.PrivateKeyPEM.Bytes()), "PRIVATE KEY")
	m2, err := f.h.svc.DeploymentMaterial(ctx, id, false)
	require.NoError(t, err)
	assert.Empty(t, m2.PrivateKeyPEM.Bytes())

	require.NoError(t, f.h.svc.StartDeploymentWith(ctx, id, v))
	assert.ErrorIs(t, f.h.svc.StartDeploymentWith(ctx, id, v), inventory.ErrDeploymentState, "a send is recorded once")
	_, err = f.h.svc.DeploymentMaterial(ctx, id, true)
	assert.ErrorIs(t, err, inventory.ErrDeploymentState, "the key is unsealed for the first send only")
	d = f.get(id)
	assert.Equal(t, inventory.DeployStateDeploying, d.State)
	assert.Equal(t, &id, d.OperationID)
	assert.Equal(t, sha(f.old.FullchainPEM), d.ExpectCertSHA256)
	assert.Equal(t, 2, d.NewChainLength)
	assert.Equal(t, pki.Fingerprint(f.old.Cert), d.PreviousFingerprint)
	assert.Equal(t, 2, d.PreviousChainLength)
	require.NotNil(t, d.Backup)
	assert.Equal(t, id, d.Backup.OperationID)
	assert.Equal(t, 1, f.h.audits("deployment.started"))
	// What recovery reads is the record, even after the location and the chain changed.
	_, err = f.h.db.Owner.Exec(ctx, "UPDATE certificate_locations SET cert_file_sha256 = $2 WHERE id = $1", f.loc1, sha([]byte("other")))
	require.NoError(t, err)
	rm, err := f.h.svc.DeploymentMaterial(ctx, id, false)
	require.NoError(t, err)
	assert.True(t, rm.Recorded)
	assert.Equal(t, sha(f.old.FullchainPEM), rm.ExpectCertSHA256)
	rb := rm.RollbackRequest()
	assert.Equal(t, providers.RollbackRequest{OperationID: id, Location: rm.Location, OldFingerprint: pki.Fingerprint(f.old.Cert), OldChainLength: 2,
		OldSANs: []string{"www.example.test"}, KeyType: "ecdsa", Verify: rm.Verify}, rb)
	vr := rm.VerifyRequest()
	assert.Equal(t, pki.Fingerprint(f.nw.Cert), vr.Fingerprint)
	assert.Equal(t, 2, vr.ChainLength)
	assert.Equal(t, pki.Fingerprint(f.old.Cert), vr.PreviousFingerprint)

	require.NoError(t, f.h.svc.RecordDeploymentStep(ctx, id, "backup", providers.StepOK, nil))
	require.NoError(t, f.h.svc.RecordDeploymentStep(ctx, id, "write_key", providers.StepOK, map[string]string{"mode": "0600", "secret": "x"}))
	err = f.h.svc.FinishDeployment(ctx, id, inventory.DeploymentFinish{Status: inventory.DeployStatusSucceeded})
	assert.Error(t, err, "success needs a verification")
	require.NoError(t, f.h.svc.FinishDeployment(ctx, id, inventory.DeploymentFinish{Status: inventory.DeployStatusSucceeded, Verified: "remote",
		Result: "committed", Phase: "committed", Backup: &providers.BackupRef{OperationID: id, Dir: "/var/lib/alice-helper/backups/" + id.String()}}))
	require.NoError(t, f.h.svc.FinishDeployment(ctx, id, inventory.DeploymentFinish{Status: inventory.DeployStatusFailed}), "a second finish changes nothing")
	require.NoError(t, f.h.svc.MarkRecovering(ctx, id, f.h.clock.Now(), true), "nothing moves a finished deployment")
	jobID, err := f.h.svc.RequestRecovery(ctx, id)
	require.NoError(t, err)
	assert.Equal(t, uuid.Nil, jobID, "a finished deployment needs no recovery")
	assert.ErrorIs(t, f.h.svc.RecordDeploymentStep(ctx, id, "reload", providers.StepOK, nil), inventory.ErrDeploymentState)
	d, err = f.h.svc.Deployment(ctx, id)
	require.NoError(t, err)
	assert.Equal(t, inventory.DeployStateDone, d.State)
	assert.Equal(t, inventory.DeployStatusSucceeded, d.Status)
	assert.Equal(t, "committed", d.Result)
	assert.Equal(t, "remote", d.Verified)
	assert.Equal(t, []string{"backup:ok", "write_key:ok"}, stepNames(d.Steps))
	assert.Equal(t, map[string]string{"mode": "0600"}, d.Steps[1].Params, "allowlisted step params")
	assert.Equal(t, map[string]string{}, d.Steps[0].Params)
	assert.Equal(t, 1, d.Steps[0].N)
	require.NotNil(t, d.FinishedAt)
	assert.Nil(t, d.RecoverAfter)
	loc, err := f.h.svc.GetLocation(ctx, f.loc1)
	require.NoError(t, err)
	assert.Equal(t, pki.Fingerprint(f.nw.Cert), loc.DeployedFingerprint, "a later discovery of this leaf is not 'changed outside Alice'")
	full, err := f.h.svc.GetCertificate(ctx, f.cert.ID)
	require.NoError(t, err)
	assert.Equal(t, sha([]byte(full.PEMChain)), loc.CertFileSHA256, "the next compare-and-swap expects the file Alice wrote")
	assert.Nil(t, loc.ActiveDeploymentID, "the location is free again")
	assert.Equal(t, 1, f.h.audits("deployment.succeeded"))
	assert.Equal(t, map[string]string{"deployment_id": id.String(), "new_fingerprint": pki.Fingerprint(f.nw.Cert),
		"previous_fingerprint": pki.Fingerprint(f.old.Cert), "verified": "remote"}, f.h.auditDetails("deployment.succeeded")[0])
	assert.Empty(t, f.emails(), "a success sends no email")
	// The database refuses any change of a finished deployment (Z1003), whoever asks.
	_, err = f.h.db.App.Exec(ctx, "UPDATE deployments SET status = 'failed' WHERE id = $1", id)
	var pgErr *pgconn.PgError
	require.ErrorAs(t, err, &pgErr)
	assert.Equal(t, "Z1003", pgErr.Code)
}

// The record keeps the legacy StartDeployment's values from the database, and a key whose public
// key is not the certificate's is never handed out.
func TestStartDeploymentRecordsTheSendValues(t *testing.T) {
	f := newDeployFixture(t)
	id := f.request(f.admin, f.cert.ID, f.loc1)
	f.start(id)
	d := f.get(id)
	assert.Equal(t, sha(f.old.FullchainPEM), d.ExpectCertSHA256)
	assert.Equal(t, 2, d.NewChainLength, "never 0 once a send may have happened")
	assert.Equal(t, 0, d.PreviousChainLength, "not compared")
	assert.Equal(t, &id, d.OperationID)

	id2 := f.request(f.admin, f.cert.ID, f.loc2)
	_, err := f.h.svc.BeginDeployment(f.h.ctx, id2)
	require.NoError(t, err)
	for name, v := range map[string]inventory.SendValues{
		"another operation id": {OperationID: uuid.New(), ExpectCertSHA256: sha(f.old.FullchainPEM), NewChainLength: 2},
		"no file hash":         {OperationID: id2, NewChainLength: 2},
		"no chain":             {OperationID: id2, ExpectCertSHA256: sha(f.old.FullchainPEM)},
		"bad previous":         {OperationID: id2, ExpectCertSHA256: sha(f.old.FullchainPEM), NewChainLength: 2, PreviousFingerprint: "x"},
	} {
		assert.Error(t, f.h.svc.StartDeploymentWith(f.h.ctx, id2, v), name)
	}
	assert.Equal(t, inventory.DeployStatePrecheck, f.get(id2).State)
}

func TestDeploymentMaterialRefusesAForeignKey(t *testing.T) {
	f := newDeployFixture(t)
	id := f.request(f.admin, f.cert.ID, f.loc1)
	// As the owner and past the trigger, the RSA certificate's sealed key is moved to nw: it opens
	// (its envelope is bound to its own row), and only the public key check can refuse it.
	ctx := f.h.ctx
	var keyID uuid.UUID
	require.NoError(t, f.h.db.Owner.QueryRow(ctx, "SELECT private_key_id FROM certificates WHERE id = $1", f.rsaCert.ID).Scan(&keyID))
	for _, step := range []struct {
		sql  string
		args []any
	}{
		{"ALTER TABLE certificates DISABLE TRIGGER certificates_key_check", nil},
		{"UPDATE certificates SET private_key_id = NULL WHERE id = ANY($1)", []any{[]uuid.UUID{f.cert.ID, f.rsaCert.ID}}},
		{"UPDATE certificates SET private_key_id = $2 WHERE id = $1", []any{f.cert.ID, keyID}},
		{"ALTER TABLE certificates ENABLE TRIGGER certificates_key_check", nil},
	} {
		_, err := f.h.db.Owner.Exec(ctx, step.sql, step.args...)
		require.NoError(t, err)
	}
	m, err := f.h.svc.DeploymentMaterial(ctx, id, true)
	require.EqualError(t, err, "inventory: the stored private key does not belong to the certificate")
	assert.Empty(t, m.PrivateKeyPEM.Bytes())
}

// deployments_one_active is the backstop: a writer that does not take the location lock (here the
// owner, uncommitted while the request runs) still cannot give a location two active deployments,
// and the request is told why instead of failing with a database error.
func TestRequestDeploymentUniqueIndexBackstop(t *testing.T) {
	f := newDeployFixture(t)
	ctx := f.h.ctx
	tx, err := f.h.db.Owner.Begin(ctx)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback(ctx) }()
	// Without foreign key checks the row takes no lock on its target or location, so the request
	// gets past its locks and its explicit check (which cannot see the uncommitted row).
	_, err = tx.Exec(ctx, "SET LOCAL session_replication_role = replica")
	require.NoError(t, err)
	_, err = tx.Exec(ctx, `INSERT INTO deployments (id, certificate_id, location_id, target_id, trigger, state, status, new_fingerprint,
cert_path, key_path, created_at) VALUES ($1, $2, $3, $4, 'manual', 'queued', 'pending', $5, '/etc/nginx/ssl/www.crt', '/etc/nginx/ssl/www.key', $6)`,
		uuid.Must(uuid.NewV7()), f.cert.ID, f.loc1, f.target1, f.cert.Fingerprint, f.h.clock.Now())
	require.NoError(t, err)
	done := make(chan error, 1)
	go func() {
		_, err := f.h.svc.RequestDeployment(ctx, f.admin, inventory.DeployRequestInput{CertificateID: f.cert.ID, LocationIDs: []uuid.UUID{f.loc1}})
		done <- err
	}()
	// The request's INSERT waits on the uncommitted row's index entry.
	require.Eventually(t, func() bool {
		return f.h.count(`SELECT count(*) FROM pg_stat_activity WHERE wait_event_type = 'Lock' AND query LIKE 'INSERT INTO deployments%'`) == 1
	}, 10*time.Second, 10*time.Millisecond)
	require.NoError(t, tx.Commit(ctx))
	assert.ErrorIs(t, <-done, inventory.ErrDeploymentInProgress)
	assert.Equal(t, "in_progress", f.h.auditDetails("deployment.denied")[0]["reason"])
}

func finishCase(t *testing.T, f *deployFixture, loc uuid.UUID, fin inventory.DeploymentFinish) uuid.UUID {
	t.Helper()
	id := f.deploying(loc)
	require.NoError(t, f.h.svc.FinishDeployment(f.h.ctx, id, fin))
	return id
}

// L-82 wording: a rolled-back deployment shows the failure and the rollback.
func TestFinishDeploymentAuditsAndEmails(t *testing.T) {
	f := newDeployFixture(t)
	params := func(id uuid.UUID, target, path string) map[string]string {
		return map[string]string{"target_name": target, "cert_path": path, "deployment_id": id.String()}
	}

	rolled := finishCase(t, f, f.loc1, inventory.DeploymentFinish{Status: inventory.DeployStatusRolledBack, ErrorCode: "deployment.reload_failed",
		FailedStep: "reload", CauseStep: "reload", Result: "rolled_back", Phase: "restored", Verified: "remote"})
	assert.Equal(t, []map[string]string{{"deployment_id": rolled.String(), "reason": "deployment.reload_failed", "failed_step": "reload"}},
		f.h.auditDetails("deployment.failed"))
	assert.Equal(t, []map[string]string{{"deployment_id": rolled.String(), "reason": "deployment.reload_failed"}}, f.h.auditDetails("deployment.rolled_back"))
	assert.Equal(t, []outboxRow{{"deployment.failed", params(rolled, "web-01", "/etc/nginx/ssl/www.crt")}}, f.emails())
	d := f.get(rolled)
	assert.Equal(t, "reload", d.FailedStep)
	assert.Equal(t, "reload", d.CauseStep)
	assert.Equal(t, "restored", d.Phase)
	loc, err := f.h.svc.GetLocation(f.h.ctx, f.loc1)
	require.NoError(t, err)
	assert.Empty(t, loc.DeployedFingerprint, "nothing new is in place")

	broken := finishCase(t, f, f.loc1, inventory.DeploymentFinish{Status: inventory.DeployStatusRollbackFailed, ErrorCode: "deployment.rollback_failed",
		FailedStep: "restore", CauseStep: "verify", HelperError: "file_changed", Result: "rollback_failed",
		Params: map[string]string{"backup_dir": "/x", "port": "443", "secret": "dropped"},
		Backup: &providers.BackupRef{OperationID: uuid.New(), Dir: "/tmp/elsewhere"}})
	assert.Equal(t, []map[string]string{{"deployment_id": broken.String(), "reason": "deployment.rollback_failed", "failed_step": "restore"}},
		f.h.auditDetails("deployment.rollback_failed"))
	want := params(broken, "web-01", "/etc/nginx/ssl/www.crt")
	want["backup_dir"] = helperproto.BackupRoot + "/" + broken.String()
	assert.Equal(t, outboxRow{"deployment.rollback_failed", want}, f.emails()[1], "the backup directory is Alice's own, never remote text")
	d = f.get(broken)
	assert.Equal(t, map[string]string{"backup_dir": "/x", "port": "443"}, d.ErrorParams)
	assert.Equal(t, "file_changed", d.HelperError)

	failed := f.request(f.admin, f.cert.ID, f.loc2)
	require.NoError(t, f.h.svc.FinishDeployment(f.h.ctx, failed, inventory.DeploymentFinish{Status: inventory.DeployStatusFailed,
		ErrorCode: "nginx.config_invalid"}), "a refused deployment ends from any unfinished state")
	assert.Equal(t, outboxRow{"deployment.failed", params(failed, "web-02", "/etc/nginx/ssl/www.crt")}, f.emails()[2])
	assert.Equal(t, 2, f.h.audits("deployment.failed"))

	unchanged := finishCase(t, f, f.loc3onTarget2, inventory.DeploymentFinish{Status: inventory.DeployStatusUnchanged, Result: "unchanged",
		Phase: "unchanged", Verified: "local"})
	assert.Equal(t, 1, f.h.audits("deployment.unchanged"))
	assert.Len(t, f.emails(), 3, "unchanged: no email")
	loc, err = f.h.svc.GetLocation(f.h.ctx, f.loc3onTarget2)
	require.NoError(t, err)
	assert.Equal(t, pki.Fingerprint(f.nw.Cert), loc.DeployedFingerprint)
	_ = unchanged

	// Refused transitions: success without a send; an unknown status.
	early := f.request(f.admin, f.cert.ID, f.loc4)
	assert.ErrorIs(t, f.h.svc.FinishDeployment(f.h.ctx, early, inventory.DeploymentFinish{Status: inventory.DeployStatusSucceeded, Verified: "remote"}),
		inventory.ErrDeploymentState)
	assert.ErrorIs(t, f.h.svc.FinishDeployment(f.h.ctx, early, inventory.DeploymentFinish{Status: inventory.DeployStatusRolledBack, FailedStep: "reload"}),
		inventory.ErrDeploymentState)
	assert.Error(t, f.h.svc.FinishDeployment(f.h.ctx, early, inventory.DeploymentFinish{Status: inventory.DeployStatusNeedsAttention}))
	assert.Error(t, f.h.svc.FinishDeployment(f.h.ctx, early, inventory.DeploymentFinish{Status: "done"}))
	assert.ErrorIs(t, f.h.svc.FinishDeployment(f.h.ctx, uuid.New(), inventory.DeploymentFinish{Status: inventory.DeployStatusFailed}), inventory.ErrNotFound)
	assert.Equal(t, inventory.DeployStateQueued, f.get(early).State)

	// Hostile values are bounded before they reach the row.
	big := map[string]string{}
	for _, k := range []string{"port", "failed_step", "profile", "phase", "directory", "backup_dir", "expected", "actual", "mode", "helper_code", "subcommand"} {
		big[k] = stringOf('a', 2000)
	}
	require.NoError(t, f.h.svc.FinishDeployment(f.h.ctx, early, inventory.DeploymentFinish{Status: inventory.DeployStatusFailed,
		ErrorCode: "not a code; DROP TABLE", FailedStep: "Bad Step", Params: big}))
	d = f.get(early)
	assert.Equal(t, "internal.unexpected", d.ErrorCode)
	assert.Empty(t, d.FailedStep)
	raw, err := json.Marshal(d.ErrorParams)
	require.NoError(t, err)
	assert.LessOrEqual(t, len(raw), 4096)
	assert.NotEmpty(t, d.ErrorParams)
}

func stringOf(c byte, n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = c
	}
	return string(b)
}

func TestMarkRecoveringEmailsOnce(t *testing.T) {
	f := newDeployFixture(t)
	ctx := f.h.ctx
	id := f.deploying(f.loc1)
	t1 := f.h.clock.Now().Add(10 * time.Second)
	require.NoError(t, f.h.svc.MarkRecovering(ctx, id, t1, false))
	d := f.get(id)
	assert.Equal(t, inventory.DeployStateRecovering, d.State)
	assert.Equal(t, inventory.DeployStatusRunning, d.Status)
	require.NotNil(t, d.RecoverAfter)
	assert.Equal(t, t1, *d.RecoverAfter)
	assert.Empty(t, f.emails())
	assert.Equal(t, 1, f.h.audits("deployment.recovering"))
	t2 := t1.Add(15 * time.Minute)
	require.NoError(t, f.h.svc.MarkRecovering(ctx, id, t2, true))
	require.NoError(t, f.h.svc.MarkRecovering(ctx, id, t2.Add(time.Minute), true))
	require.NoError(t, f.h.svc.MarkRecovering(ctx, id, t2.Add(2*time.Minute), false))
	d = f.get(id)
	assert.Equal(t, inventory.DeployStatusNeedsAttention, d.Status, "needs attention until the deployment ends")
	assert.Equal(t, t2.Add(2*time.Minute), *d.RecoverAfter)
	assert.Equal(t, []outboxRow{{"deployment.needs_attention", map[string]string{"target_name": "web-01", "cert_path": "/etc/nginx/ssl/www.crt",
		"deployment_id": id.String()}}}, f.emails())
	assert.Equal(t, 1, f.h.audits("deployment.needs_attention"))
	assert.Equal(t, 1, f.h.audits("deployment.recovering"), "the episode began once")
	loc, err := f.h.svc.GetLocation(ctx, f.loc1)
	require.NoError(t, err)
	assert.Equal(t, &id, loc.ActiveDeploymentID, "needs_attention keeps the location held")
	_, err = f.h.svc.RequestDeployment(ctx, f.admin, inventory.DeployRequestInput{CertificateID: f.cert.ID, LocationIDs: []uuid.UUID{f.loc5}})
	assert.ErrorIs(t, err, inventory.ErrRecoveryPending, "no new deployment on a server being recovered")
}

func TestRequestRecoveryDoesNotPileUp(t *testing.T) {
	f := newDeployFixture(t)
	ctx := f.h.ctx
	id := f.deploying(f.loc1)
	j1, err := f.h.svc.RequestRecovery(ctx, id)
	require.NoError(t, err)
	j2, err := f.h.svc.RequestRecovery(ctx, id)
	require.NoError(t, err)
	assert.Equal(t, j1, j2, "the live recovery answers")
	assert.Equal(t, []string{"queued"}, f.recoverJobs(id))
	assert.Equal(t, 1, f.h.audits("deployment.recovery_started"))
	d := f.get(id)
	assert.Equal(t, 1, d.RecoveryAttempts)
	assert.Equal(t, inventory.DeployStateRecovering, d.State)
	var class, kind string
	var maxAttempts int
	var payload map[string]string
	require.NoError(t, f.h.db.Owner.QueryRow(ctx, "SELECT class, kind, max_attempts, payload FROM jobs WHERE id = $1", j1).Scan(&class, &kind,
		&maxAttempts, &payload))
	assert.Equal(t, "always", class, "R38 #8: recovery is never blocked by the license")
	assert.Equal(t, "system", kind)
	assert.Equal(t, 5, maxAttempts)
	assert.Equal(t, map[string]string{"deployment_id": id.String()}, payload)
}

func TestListDeploymentsAndDetail(t *testing.T) {
	f := newDeployFixture(t)
	ctx := f.h.ctx
	d1 := f.request(f.operator, f.cert.ID, f.loc1)
	f.h.clock.Advance(time.Minute)
	d2 := f.request(f.admin, f.cert.ID, f.loc2)
	f.h.clock.Advance(time.Minute)
	got, err := f.h.svc.RequestDeployment(ctx, f.admin, inventory.DeployRequestInput{CertificateID: f.incomplete.ID,
		LocationIDs: []uuid.UUID{f.loc5}, ConfirmIncompleteChain: true})
	require.NoError(t, err)
	d3 := got[0].ID
	page, err := f.h.svc.ListDeployments(ctx, inventory.DeploymentFilter{})
	require.NoError(t, err)
	ids := func(p inventory.DeploymentPage) []uuid.UUID {
		out := []uuid.UUID{}
		for _, d := range p.Items {
			out = append(out, d.ID)
		}
		return out
	}
	assert.Equal(t, []uuid.UUID{d3, d2, d1}, ids(page), "newest first")
	assert.Empty(t, page.NextCursor)
	page, err = f.h.svc.ListDeployments(ctx, inventory.DeploymentFilter{TargetID: f.target1})
	require.NoError(t, err)
	assert.Equal(t, []uuid.UUID{d3, d1}, ids(page))
	page, err = f.h.svc.ListDeployments(ctx, inventory.DeploymentFilter{CertificateID: f.incomplete.ID})
	require.NoError(t, err)
	assert.Equal(t, []uuid.UUID{d3}, ids(page))
	page, err = f.h.svc.ListDeployments(ctx, inventory.DeploymentFilter{LocationID: f.loc2})
	require.NoError(t, err)
	assert.Equal(t, []uuid.UUID{d2}, ids(page))
	page, err = f.h.svc.ListDeployments(ctx, inventory.DeploymentFilter{Limit: 2})
	require.NoError(t, err)
	assert.Equal(t, []uuid.UUID{d3, d2}, ids(page))
	require.NotEmpty(t, page.NextCursor)
	page, err = f.h.svc.ListDeployments(ctx, inventory.DeploymentFilter{Limit: 2, Cursor: page.NextCursor})
	require.NoError(t, err)
	assert.Equal(t, []uuid.UUID{d1}, ids(page))
	assert.Empty(t, page.NextCursor)
	assert.Nil(t, page.Items[0].Steps, "the list carries no steps")
	_, err = f.h.svc.ListDeployments(ctx, inventory.DeploymentFilter{Cursor: "!!"})
	assert.Equal(t, map[string]string{"cursor": validate.Pattern}, fieldsOf(err))
	_, err = f.h.svc.ListDeployments(ctx, inventory.DeploymentFilter{Limit: 201})
	assert.Equal(t, map[string]string{"limit": validate.OutOfRange}, fieldsOf(err))

	f.start(d1)
	require.NoError(t, f.h.svc.RecordDeploymentStep(ctx, d1, "backup", providers.StepStarted, nil))
	require.NoError(t, f.h.svc.RecordDeploymentStep(ctx, d1, "backup", providers.StepOK, nil))
	require.NoError(t, f.h.svc.RecordDeploymentStep(ctx, d1, "write_key", providers.StepFailed, map[string]string{"error": "key_load"}))
	d, err := f.h.svc.Deployment(ctx, d1)
	require.NoError(t, err)
	assert.Equal(t, []string{"backup:started", "backup:ok", "write_key:failed"}, stepNames(d.Steps))
	assert.Equal(t, []int{1, 2, 3}, []int{d.Steps[0].N, d.Steps[1].N, d.Steps[2].N})
	assert.Equal(t, "oya Yılmaz", d.RequestedByName)
	_, err = f.h.svc.Deployment(ctx, uuid.New())
	assert.ErrorIs(t, err, inventory.ErrNotFound)
	assert.ErrorIs(t, f.h.svc.RecordDeploymentStep(ctx, d1, "Bad Name", providers.StepOK, nil), inventory.ErrDeploymentState)
	assert.ErrorIs(t, f.h.svc.RecordDeploymentStep(ctx, d1, "backup", "weird", nil), inventory.ErrDeploymentState)

	// Concurrent step writers each get their own number.
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			assert.NoError(t, f.h.svc.RecordDeploymentStep(ctx, d1, "reload", providers.StepStarted, map[string]string{"port": strconv.Itoa(i)}))
		}()
	}
	wg.Wait()
	d, err = f.h.svc.Deployment(ctx, d1)
	require.NoError(t, err)
	assert.Len(t, d.Steps, 11)
}

// The backup root inventory names in emails is the helper's (inventory may not import helperproto).
func TestBackupRootIsTheHelpers(t *testing.T) {
	assert.Equal(t, helperproto.BackupRoot, inventory.BackupRoot)
}
