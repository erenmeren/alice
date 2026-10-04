//go:build integration

package inventory_test

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/inventory"
	"alice/internal/providers"
	"alice/internal/testutil/pki"
)

// autoFixture is a binding of web-cert to three websites (loc1, loc2, loc3) with automatic deployment
// switched on at the start; renew adds versions through the poll as a renewal in Azure would.
type autoFixture struct {
	*bindFixture
	bind inventory.Binding
}

func newAutoFixture(t *testing.T, auto bool) *autoFixture {
	t.Helper()
	b := newBindFixture(t)
	f := &autoFixture{bindFixture: b}
	f.bind = b.create(b.admin, b.web, b.loc1, b.loc2, b.loc3)
	if auto {
		f.bind = f.setAuto(true)
	}
	return f
}

func (f *autoFixture) setAuto(on bool) inventory.Binding {
	f.h.t.Helper()
	cur, err := f.h.svc.Binding(f.h.ctx, f.bind.ID)
	require.NoError(f.h.t, err)
	got, err := f.h.svc.SetAutoDeploy(f.h.ctx, f.admin, f.bind.ID, cur.Version, on)
	require.NoError(f.h.t, err)
	return got
}

// renew advances the clock a minute and lets a poll see version n as the vault certificate's current
// version, created now. leaf may be nil for a fresh ECDSA leaf; older names versions it lists too.
func (f *autoFixture) renew(n int, leaf *pki.Leaf, older ...string) pki.Leaf {
	f.h.t.Helper()
	f.h.clock.Advance(time.Minute)
	l := f.issue("web.example.test", pki.ECDSA256)
	if leaf != nil {
		l = *leaf
	}
	f.h.reconcile(f.vault, kvResult(f.h.kvc("web-cert", l, ver(n), f.h.clock.Now(), true, older...)))
	return l
}

func (f *autoFixture) plan() int {
	f.h.t.Helper()
	n, err := f.h.svc.PlanKVAutoDeploy(f.h.ctx)
	require.NoError(f.h.t, err)
	return n
}

type depRow struct {
	ID, Location           uuid.UUID
	Trigger, State, Status string
	Binding, Version       *uuid.UUID
}

func (f *autoFixture) deps(version string) []depRow {
	f.h.t.Helper()
	rows, err := f.h.db.Owner.Query(f.h.ctx, `SELECT d.id, d.location_id, d.trigger, d.state, d.status, d.binding_id, d.kv_version_id FROM deployments d
JOIN kv_certificate_versions v ON v.id = d.kv_version_id WHERE v.version = $1 ORDER BY d.created_at, d.id`, version)
	require.NoError(f.h.t, err)
	defer rows.Close()
	var out []depRow
	for rows.Next() {
		var r depRow
		require.NoError(f.h.t, rows.Scan(&r.ID, &r.Location, &r.Trigger, &r.State, &r.Status, &r.Binding, &r.Version))
		out = append(out, r)
	}
	require.NoError(f.h.t, rows.Err())
	return out
}

func (f *autoFixture) locationsOf(version string) []uuid.UUID {
	out := []uuid.UUID{}
	for _, d := range f.deps(version) {
		out = append(out, d.Location)
	}
	return out
}

func (f *autoFixture) finish(id uuid.UUID, status, code string) {
	f.h.t.Helper()
	if status == inventory.DeployStatusSucceeded { // the engine's path to a success is not what these tests are about
		f.exec(`UPDATE deployments SET state = 'done', status = 'succeeded', result = 'committed', phase = 'committed', verified = 'remote',
finished_at = $2 WHERE id = $1`, id, f.h.clock.Now())
		return
	}
	require.NoError(f.h.t, f.h.svc.FinishDeployment(f.h.ctx, id, inventory.DeploymentFinish{Status: status, ErrorCode: code}))
}

func (f *autoFixture) finishAll(version, status, code string) {
	f.h.t.Helper()
	for _, d := range f.deps(version) {
		if d.State != inventory.DeployStateDone {
			f.finish(d.ID, status, code)
		}
	}
}

// moreLocations adds n websites to web-01 (found by a scan) and returns their ids.
func (f *autoFixture) moreLocations(n int) []uuid.UUID {
	f.h.t.Helper()
	certs := []providers.DiscoveredCertificate{
		dc(cl("/etc/nginx/ssl/www.crt", "/etc/nginx/ssl/www.key", "www.example.test"), f.old),
		dc(cl("/etc/nginx/ssl/b.crt", "/etc/nginx/ssl/b.key", "www.example.test"), f.old)}
	for i := range n {
		certs = append(certs, dc(cl(fmt.Sprintf("/etc/nginx/ssl/x%d.crt", i), fmt.Sprintf("/etc/nginx/ssl/x%d.key", i), "www.example.test"), f.old))
	}
	_, err := f.h.svc.Reconcile(f.h.ctx, f.target1, providers.DiscoveryResult{Nginx: nginxOK, Certificates: certs})
	require.NoError(f.h.t, err)
	found := byPath(f.h.t, f.h, f.target1, false)
	var ids []uuid.UUID
	for i := range n {
		ids = append(ids, found[fmt.Sprintf("/etc/nginx/ssl/x%d.crt", i)].ID)
	}
	return ids
}

func (f *autoFixture) bindingState() (stopped string, version int) {
	f.h.t.Helper()
	require.NoError(f.h.t, f.h.db.Owner.QueryRow(f.h.ctx, "SELECT stopped_version, version FROM bindings WHERE id = $1", f.bind.ID).Scan(&stopped, &version))
	return stopped, version
}

func (f *autoFixture) mails() map[string]int {
	f.h.t.Helper()
	out := map[string]int{}
	for _, tpl := range inventory.Templates() {
		if n := f.h.emails(tpl); n > 0 && len(tpl) > 3 && tpl[:3] == "kv." && tpl != inventory.TemplateKVCertificateRemoved && tpl != inventory.TemplateKVCertificateRemovedBound {
			out[tpl] = n
		}
	}
	return out
}

// TestAutoDeployApplyTable is the planner against a database, row by row on a fresh fixture. The pure
// decision has its own table (TestAutoDeployPlanTable); what is checked here is what is read, what is
// written, in which transaction, and that nothing is done twice.
func TestAutoDeployApplyTable(t *testing.T) {
	t.Run("a new version, three websites: one deployment each, created like a manual request", func(t *testing.T) {
		f := newAutoFixture(t, true)
		f.renew(2, nil)
		require.Equal(t, 3, f.plan())
		ds := f.deps(ver(2))
		require.Len(t, ds, 3)
		for _, d := range ds {
			assert.Equal(t, "kv_renewal", d.Trigger)
			require.NotNil(t, d.Binding)
			assert.Equal(t, f.bind.ID, *d.Binding)
			assert.Equal(t, f.versionID(f.web, ver(2)), *d.Version)
			assert.Equal(t, inventory.DeployStateQueued, d.State)
		}
		assert.ElementsMatch(t, []uuid.UUID{f.loc1, f.loc2, f.loc3}, f.locationsOf(ver(2)))
		deployJobs := 0
		for _, r := range f.h.jobs.requests() {
			if r.Type == inventory.JobCertificateDeploy {
				deployJobs++
				assert.Equal(t, "system", r.Kind)
			}
		}
		assert.Equal(t, 3, deployJobs)
		ev := f.h.auditDetails("deployment.requested")
		require.Len(t, ev, 3)
		assert.Equal(t, ver(2), ev[0]["version"])
		assert.Equal(t, f.bind.ID.String(), ev[0]["binding_id"])
		assert.Zero(t, f.plan(), "nothing more while they run: running the planner again changes nothing")
		assert.Len(t, f.deps(ver(2)), 3)
		assert.Empty(t, f.mails(), "no mail for a version that is deployed")
	})

	t.Run("a version detected before automatic deployment was switched on is not deployed", func(t *testing.T) {
		f := newAutoFixture(t, false)
		f.renew(2, nil)
		f.h.clock.Advance(time.Minute)
		f.setAuto(true)
		assert.Zero(t, f.plan())
		assert.Zero(t, f.h.count("SELECT count(*) FROM deployments"))
		assert.Equal(t, map[string]int{inventory.TemplateKVSkippedManual: 1}, f.mails())
		assert.Zero(t, f.plan())
		assert.Equal(t, map[string]int{inventory.TemplateKVSkippedManual: 1}, f.mails(), "once")
		var skipped, notified *time.Time
		require.NoError(t, f.h.db.Owner.QueryRow(f.h.ctx, "SELECT skipped_notified_at, notified_at FROM kv_certificate_versions WHERE id = $1", f.versionID(f.web, ver(2))).Scan(&skipped, &notified))
		assert.NotNil(t, skipped)
		assert.Nil(t, notified, "the two marks are separate (D25)")
	})

	t.Run("automatic deployment off: one mail, nothing deployed", func(t *testing.T) {
		f := newAutoFixture(t, false)
		f.renew(2, nil)
		assert.Zero(t, f.plan())
		assert.Equal(t, map[string]int{inventory.TemplateKVNewVersion: 1}, f.mails())
		assert.Zero(t, f.plan())
		assert.Equal(t, map[string]int{inventory.TemplateKVNewVersion: 1}, f.mails())
		assert.Zero(t, f.h.count("SELECT count(*) FROM deployments"))
	})

	t.Run("a held version is mailed once and never planned until released", func(t *testing.T) {
		f := newAutoFixture(t, true)
		f.renew(2, nil)
		v2 := f.versionID(f.web, ver(2))
		f.exec("UPDATE kv_certificate_versions SET held = true, held_reason = 'license' WHERE id = $1", v2)
		assert.Zero(t, f.plan())
		assert.Zero(t, f.plan())
		assert.Equal(t, map[string]int{inventory.TemplateKVNewVersionHeldLicense: 1}, f.mails())
		assert.Zero(t, f.h.count("SELECT count(*) FROM deployments"))
		_, err := f.h.svc.ReleaseVersion(f.h.ctx, f.admin, inventory.ReleaseInput{VaultID: f.vault, KVCertificateID: f.web, VersionID: v2})
		require.NoError(t, err)
		assert.Equal(t, 3, f.plan(), "released: planned")
	})

	t.Run("a version that cannot be deployed is skipped with one mail", func(t *testing.T) {
		for name, tc := range map[string]struct {
			sql      string
			template string
			timed    bool
		}{
			"disabled":      {"UPDATE kv_certificate_versions SET enabled = false WHERE id = $1", inventory.TemplateKVSkippedDisabled, false},
			"expired":       {"UPDATE kv_certificate_versions SET expires = $2::timestamptz - interval '1 day' WHERE id = $1", inventory.TemplateKVSkippedExpired, true},
			"not yet valid": {"UPDATE kv_certificate_versions SET not_before = $2::timestamptz + interval '400 days' WHERE id = $1", inventory.TemplateKVSkippedNotYetValid, true},
		} {
			t.Run(name, func(t *testing.T) {
				f := newAutoFixture(t, true)
				f.renew(2, nil)
				if tc.timed {
					f.exec(tc.sql, f.versionID(f.web, ver(2)), f.h.clock.Now())
				} else {
					f.exec(tc.sql, f.versionID(f.web, ver(2)))
				}
				assert.Zero(t, f.plan())
				assert.Zero(t, f.plan())
				assert.Equal(t, map[string]int{tc.template: 1}, f.mails())
				assert.Zero(t, f.h.count("SELECT count(*) FROM deployments"))
			})
		}
	})

	t.Run("older than what a website serves: that website is skipped, one mail", func(t *testing.T) {
		f := newAutoFixture(t, true)
		f.h.clock.Advance(time.Minute)
		short := f.ca.Issue(pki.Opts{CommonName: "web.example.test", SANs: []string{"web.example.test"}, KeyType: pki.ECDSA256}, f.h.clock.Now().Add(-30*24*time.Hour))
		f.renew(2, &short)
		assert.Zero(t, f.plan(), "every website serves a certificate that ends later")
		assert.Equal(t, map[string]int{inventory.TemplateKVSkippedOlder: 1}, f.mails())
		// One website serves an older certificate: it is deployed, the others are not.
		early := f.ca.Issue(pki.Opts{CommonName: "early.example.test", SANs: []string{"early.example.test"}, KeyType: pki.ECDSA256}, f.h.clock.Now().Add(-85*24*time.Hour))
		up, _, err := f.h.svc.UploadCertificate(f.h.ctx, f.admin, pemUpload(early))
		require.NoError(t, err)
		f.exec("UPDATE certificate_locations SET certificate_id = $2 WHERE id = $1", f.loc2, up.ID)
		require.Equal(t, 1, f.plan(), "the website whose certificate ends sooner gets the version")
		assert.Equal(t, []uuid.UUID{f.loc2}, f.locationsOf(ver(2)))
		assert.Equal(t, map[string]int{inventory.TemplateKVSkippedOlder: 1}, f.mails(), "and the notice was sent once")
	})

	t.Run("not exportable or details unknown: nothing, silently", func(t *testing.T) {
		f := newAutoFixture(t, true)
		f.renew(2, nil)
		v2 := f.versionID(f.web, ver(2))
		f.exec("UPDATE kv_certificate_versions SET exportable = false WHERE id = $1", v2)
		assert.Zero(t, f.plan())
		f.exec("UPDATE kv_certificate_versions SET exportable = true, certificate_id = NULL WHERE id = $1", v2)
		assert.Zero(t, f.plan())
		assert.Empty(t, f.mails())
	})

	t.Run("eight websites: a wave of five, then the rest as they finish", func(t *testing.T) {
		f := newAutoFixture(t, false)
		extra := f.moreLocations(5)
		cur, err := f.h.svc.Binding(f.h.ctx, f.bind.ID)
		require.NoError(t, err)
		_, err = f.h.svc.UpdateBindingLocations(f.h.ctx, f.admin, f.bind.ID, cur.Version, append([]uuid.UUID{f.loc1, f.loc2, f.loc3}, extra...))
		require.NoError(t, err)
		f.setAuto(true)
		f.renew(2, nil)
		require.Equal(t, inventory.AutoDeployWave, f.plan())
		first := f.deps(ver(2))
		f.finish(first[0].ID, inventory.DeployStatusSucceeded, "")
		f.finish(first[1].ID, inventory.DeployStatusSucceeded, "")
		assert.Equal(t, 2, f.plan(), "two finished: two more")
		assert.Len(t, f.deps(ver(2)), 7)
		assert.Zero(t, f.plan(), "the wave is full again")
		f.finishAll(ver(2), inventory.DeployStatusSucceeded, "")
		assert.Equal(t, 1, f.plan(), "the eighth website")
		assert.Len(t, f.deps(ver(2)), 8)
		f.finishAll(ver(2), inventory.DeployStatusSucceeded, "")
		assert.Zero(t, f.plan(), "everything is deployed")
	})

	t.Run("a website that serves the leaf or got the version already is left alone", func(t *testing.T) {
		f := newAutoFixture(t, true)
		l := f.renew(2, nil)
		f.exec("UPDATE certificate_locations SET certificate_id = (SELECT id FROM certificates WHERE fingerprint_sha256 = $2) WHERE id = $1", f.loc1, pki.Fingerprint(l.Cert))
		manual, err := f.h.svc.RequestKVDeployment(f.h.ctx, f.admin, inventory.KVDeployInput{BindingID: f.bind.ID, VersionID: f.versionID(f.web, ver(2)), LocationIDs: []uuid.UUID{f.loc2}})
		require.NoError(t, err)
		f.finish(manual[0].ID, inventory.DeployStatusSucceeded, "")
		require.Equal(t, 1, f.plan())
		assert.Equal(t, []uuid.UUID{f.loc3}, f.locationsOf(ver(2))[1:])
	})

	t.Run("an unfinished deployment blocks a website; a later version coalesces to the newest", func(t *testing.T) {
		f := newAutoFixture(t, true)
		f.renew(2, nil)
		require.Equal(t, 3, f.plan())
		f.renew(3, nil)
		assert.Zero(t, f.plan(), "every website is busy: no parallel deployment")
		d2 := f.deps(ver(2))
		f.finish(d2[0].ID, inventory.DeployStatusSucceeded, "")
		require.Equal(t, 1, f.plan())
		assert.Equal(t, []uuid.UUID{d2[0].Location}, f.locationsOf(ver(3)), "the website that finished gets the newest version only")
		f.finishAll(ver(2), inventory.DeployStatusSucceeded, "")
		f.finishAll(ver(3), inventory.DeployStatusSucceeded, "")
		assert.Equal(t, 2, f.plan())
		assert.Len(t, f.deps(ver(2)), 3)
		assert.Len(t, f.deps(ver(3)), 3)
		assert.Equal(t, 2, f.h.audits("kv.certificate.new_version"), "the renewals were announced by the poll, not by the planner")
	})

	t.Run("a failed website waits an hour and is tried again", func(t *testing.T) {
		f := newAutoFixture(t, true)
		f.renew(2, nil)
		require.Equal(t, 3, f.plan())
		ds := f.deps(ver(2))
		f.finish(ds[0].ID, inventory.DeployStatusFailed, "deployment.failed")
		f.finish(ds[1].ID, inventory.DeployStatusSucceeded, "")
		f.finish(ds[2].ID, inventory.DeployStatusSucceeded, "")
		f.h.clock.Advance(30 * time.Minute)
		assert.Zero(t, f.plan())
		f.h.clock.Advance(31 * time.Minute)
		assert.Equal(t, 1, f.plan())
		assert.Equal(t, []uuid.UUID{ds[0].Location, ds[0].Location}, []uuid.UUID{f.locationsOf(ver(2))[0], f.locationsOf(ver(2))[3]})
	})

	t.Run("three failures stop the wave: one audit row, one mail, nothing more", func(t *testing.T) {
		f := newAutoFixture(t, true)
		f.renew(2, nil)
		require.Equal(t, 3, f.plan())
		f.finishAll(ver(2), inventory.DeployStatusFailed, "deployment.failed")
		_, versionBefore := f.bindingState()
		assert.Zero(t, f.plan())
		stopped, versionAfter := f.bindingState()
		assert.Equal(t, ver(2), stopped)
		assert.Equal(t, versionBefore+1, versionAfter, "a change a person may have read")
		ev := f.h.auditDetails("kv.auto_deploy.stopped")
		require.Len(t, ev, 1)
		assert.Equal(t, f.bind.ID.String(), ev[0]["binding_id"])
		assert.Equal(t, ver(2), ev[0]["version"])
		assert.Equal(t, "3", ev[0]["failed_count"])
		assert.Equal(t, map[string]int{inventory.TemplateKVAutoDeployStopped: 1}, f.mails())
		f.h.clock.Advance(3 * time.Hour)
		assert.Zero(t, f.plan())
		assert.Zero(t, f.plan())
		assert.Equal(t, map[string]int{inventory.TemplateKVAutoDeployStopped: 1}, f.mails())
		assert.Len(t, f.h.auditDetails("kv.auto_deploy.stopped"), 1)
		assert.Len(t, f.deps(ver(2)), 3)
		// The stop names V2 only: V3 is planned.
		f.renew(3, nil)
		assert.Equal(t, 3, f.plan())
		// Switching automatic deployment off and on again forgets the stop and its failures.
		f.finishAll(ver(3), inventory.DeployStatusSucceeded, "")
		f.setAuto(false)
		f.setAuto(true)
		stopped, _ = f.bindingState()
		assert.Empty(t, stopped)
	})

	t.Run("refusals that are not failures never stop the wave", func(t *testing.T) {
		f := newAutoFixture(t, true)
		f.renew(2, nil)
		require.Equal(t, 3, f.plan())
		f.finishAll(ver(2), inventory.DeployStatusFailed, inventory.ReasonBindingGone)
		assert.Zero(t, f.plan())
		stopped, _ := f.bindingState()
		assert.Empty(t, stopped)
		assert.Empty(t, f.h.auditDetails("kv.auto_deploy.stopped"))
	})

	t.Run("the certificate is missing from the vault: nothing", func(t *testing.T) {
		f := newAutoFixture(t, true)
		f.renew(2, nil)
		f.exec("UPDATE kv_certificates SET missing_since = $2 WHERE id = $1", f.web, f.h.clock.Now())
		assert.Zero(t, f.plan())
		assert.Empty(t, f.mails())
	})

	t.Run("unsupported website or server not ready: skipped silently, the others planned", func(t *testing.T) {
		f := newAutoFixture(t, true)
		f.renew(2, nil)
		f.setTargetStatus(f.target2, "auth_failed") // loc2 and loc3 are on web-02
		require.Equal(t, 1, f.plan())
		assert.Equal(t, []uuid.UUID{f.loc1}, f.locationsOf(ver(2)))
		f.setTargetStatus(f.target2, "ok")
		f.exec("UPDATE certificate_locations SET supported = false WHERE id = $1", f.loc2)
		require.Equal(t, 1, f.plan())
		assert.Equal(t, []uuid.UUID{f.loc1, f.loc3}, f.locationsOf(ver(2)))
		assert.Empty(t, f.h.auditDetails("deployment.denied"), "no person asked: no refusal is audited")
	})

	t.Run("a vault that is disabled or has lost its sign-in is left alone; a degraded one is planned", func(t *testing.T) {
		for status, want := range map[string]int{"disabled": 0, "auth_failed": 0, "unreachable": 0, "degraded": 3, "ok": 3} {
			t.Run(status, func(t *testing.T) {
				f := newAutoFixture(t, true)
				f.renew(2, nil)
				f.exec("UPDATE targets SET status = $2 WHERE id = $1", f.vault, status)
				assert.Equal(t, want, f.plan())
			})
		}
	})

	t.Run("the pointer alone decides nothing: the version's own row does", func(t *testing.T) {
		f := newAutoFixture(t, false)
		f.renew(2, nil, ver(1))
		f.renew(3, nil, ver(2), ver(1))
		f.h.clock.Advance(time.Minute)
		f.setAuto(true)
		// V3 is deleted in Azure: the certificate's current version is V2 again, a row that was stored
		// before automatic deployment was switched on.
		f.exec("UPDATE kv_certificates SET current_version = $2 WHERE id = $1", f.web, ver(2))
		assert.Zero(t, f.plan())
		assert.Equal(t, map[string]int{inventory.TemplateKVSkippedManual: 1}, f.mails())
	})

	t.Run("the licence locks mid-wave: nothing is planned", func(t *testing.T) {
		f := newAutoFixture(t, true)
		f.renew(2, nil)
		f.h.clock.Advance(40 * 24 * time.Hour)
		require.NoError(t, f.h.lic.Tick(f.h.ctx))
		assert.Zero(t, f.plan())
		assert.Zero(t, f.h.count("SELECT count(*) FROM deployments"))
		assert.Empty(t, f.mails())
	})

	t.Run("automatic deployment switched off mid-wave", func(t *testing.T) {
		f := newAutoFixture(t, true)
		f.renew(2, nil)
		require.Equal(t, 3, f.plan())
		f.setAuto(false)
		f.finishAll(ver(2), inventory.DeployStatusSucceeded, "")
		f.renew(3, nil)
		assert.Zero(t, f.plan())
		assert.Equal(t, map[string]int{inventory.TemplateKVNewVersion: 1}, f.mails())
		assert.Len(t, f.deps(ver(3)), 0)
	})

	t.Run("a binding or a website removed mid-wave", func(t *testing.T) {
		f := newAutoFixture(t, true)
		f.renew(2, nil)
		cur, err := f.h.svc.Binding(f.h.ctx, f.bind.ID)
		require.NoError(t, err)
		_, err = f.h.svc.UpdateBindingLocations(f.h.ctx, f.admin, f.bind.ID, cur.Version, []uuid.UUID{f.loc1, f.loc3})
		require.NoError(t, err)
		require.Equal(t, 2, f.plan())
		assert.ElementsMatch(t, []uuid.UUID{f.loc1, f.loc3}, f.locationsOf(ver(2)))
		f.finishAll(ver(2), inventory.DeployStatusSucceeded, "")
		f.renew(3, nil)
		require.NoError(t, f.h.svc.DeleteBinding(f.h.ctx, f.admin, f.bind.ID))
		assert.Zero(t, f.plan())
		assert.Len(t, f.deps(ver(3)), 0)
	})

	t.Run("the run's own batch is bounded", func(t *testing.T) {
		defer inventory.SetAutoDeployBatch(2)()
		f := newAutoFixture(t, true)
		f.renew(2, nil)
		assert.Equal(t, 2, f.plan())
		assert.Equal(t, 1, f.plan())
		assert.Len(t, f.deps(ver(2)), 3)
	})
}

// Running the planner from many polls at once creates each deployment once (D24: no lock outlives its
// transaction; each binding is planned in one transaction under the vault's and the binding's locks).
func TestAutoDeployIsExactlyOnceUnderConcurrency(t *testing.T) {
	f := newAutoFixture(t, true)
	f.renew(2, nil)
	var wg sync.WaitGroup
	total := make([]int, 8)
	errs := make([]error, 8)
	for i := range total {
		wg.Add(1)
		go func() {
			defer wg.Done()
			total[i], errs[i] = f.h.svc.PlanKVAutoDeploy(f.h.ctx)
		}()
	}
	wg.Wait()
	sum := 0
	for i := range total {
		require.NoError(t, errs[i])
		sum += total[i]
	}
	assert.Equal(t, 3, sum)
	assert.Len(t, f.deps(ver(2)), 3)
	assert.Equal(t, 3, f.h.count("SELECT count(DISTINCT location_id) FROM deployments"))
	assert.Equal(t, 3, f.h.audits("deployment.requested"))

	// And the same race for the one-time facts: a stopped wave and a notice.
	f.finishAll(ver(2), inventory.DeployStatusFailed, "deployment.failed")
	for i := range total {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, errs[i] = f.h.svc.PlanKVAutoDeploy(f.h.ctx)
		}()
	}
	wg.Wait()
	for _, err := range errs {
		require.NoError(t, err)
	}
	assert.Equal(t, 1, f.h.emails(inventory.TemplateKVAutoDeployStopped))
	assert.Len(t, f.h.auditDetails("kv.auto_deploy.stopped"), 1)
}

// A deployment created by the planner meets the engine's material step: an incomplete chain holds the
// version (S7), the planner then mails once and plans nothing until an Administrator releases it.
func TestAutoDeployHoldsAnIncompleteChain(t *testing.T) {
	f := newAutoFixture(t, true)
	l := f.renew(2, nil)
	require.Equal(t, 3, f.plan())
	ds := f.deps(ver(2))
	for _, d := range ds {
		_, err := f.h.svc.BeginDeployment(f.h.ctx, d.ID)
		require.NoError(t, err)
	}
	_, secret := pemSecret(string(l.KeyPEM) + string(l.CertPEM)) // the intermediate is missing
	_, err := f.h.svc.KVDeployMaterial(f.h.ctx, ds[0].ID, secret)
	require.ErrorIs(t, err, inventory.ErrChainUnconfirmed)
	for _, d := range ds {
		_, secret := pemSecret(string(l.KeyPEM) + string(l.FullchainPEM))
		_, err := f.h.svc.KVDeployMaterial(f.h.ctx, d.ID, secret)
		if d.ID != ds[0].ID {
			assert.ErrorIs(t, err, inventory.ErrVersionHeld, "a sibling is refused before it reads")
		}
		f.finish(d.ID, inventory.DeployStatusFailed, map[bool]string{true: inventory.ReasonChainUnconfirmed, false: inventory.ReasonVersionHeld}[d.ID == ds[0].ID])
	}
	assert.Zero(t, f.plan())
	assert.Zero(t, f.plan())
	assert.Equal(t, map[string]int{inventory.TemplateKVNewVersionHeldChain: 1}, f.mails())
	stopped, _ := f.bindingState()
	assert.Empty(t, stopped, "a hold is not a failed wave")
	_, err = f.h.svc.ReleaseVersion(f.h.ctx, f.admin, inventory.ReleaseInput{VaultID: f.vault, KVCertificateID: f.web, VersionID: f.versionID(f.web, ver(2)), ConfirmIncompleteChain: true})
	require.NoError(t, err)
	assert.Zero(t, f.plan(), "each website waits an hour after its refused attempt")
	f.h.clock.Advance(61 * time.Minute)
	assert.Equal(t, 3, f.plan())
}

// A notice is sent once however many planners meet the version at once.
func TestAutoDeployNoticeIsSentOnceUnderConcurrency(t *testing.T) {
	f := newAutoFixture(t, false)
	f.renew(2, nil)
	var wg sync.WaitGroup
	errs := make([]error, 8)
	for i := range errs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, errs[i] = f.h.svc.PlanKVAutoDeploy(f.h.ctx)
		}()
	}
	wg.Wait()
	for _, err := range errs {
		require.NoError(t, err)
	}
	assert.Equal(t, map[string]int{inventory.TemplateKVNewVersion: 1}, f.mails())
}

// A planner run whose job lost its lease writes nothing, and a cancelled run stops with its error.
func TestAutoDeployIsFencedToItsJobAndStopsWhenCancelled(t *testing.T) {
	f := newAutoFixture(t, true)
	f.renew(2, nil)
	claimed := inventory.WithClaim(f.h.ctx, inventory.Claim{JobID: uuid.New(), Attempt: 1})
	n, err := f.h.svc.PlanKVAutoDeploy(claimed)
	assert.ErrorIs(t, err, inventory.ErrClaimLost)
	assert.Zero(t, n)
	assert.Zero(t, f.h.count("SELECT count(*) FROM deployments"))
	ctx, cancel := context.WithCancel(f.h.ctx)
	cancel()
	_, err = f.h.svc.PlanKVAutoDeploy(ctx)
	assert.Error(t, err)
	assert.Zero(t, f.h.count("SELECT count(*) FROM deployments"))
	assert.Equal(t, 3, f.plan(), "and the next run is unharmed")
}
