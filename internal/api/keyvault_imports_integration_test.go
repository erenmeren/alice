//go:build integration

package api

import (
	"context"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/testutil/fakekv"
)

// TestImportNeverResendsOverTheWire is Task 15's TestImportJobNeverResends with the real provider against the fake: the
// vault processed the import and the answer was lost (a reset connection, a 503). Exactly one authenticated POST was
// sent, exactly one version exists, a rerun of the jobs, a second request for the name and the schedule send nothing,
// the import is "uncertain" (never "failed": re-sending would create a second version) and a later poll settles it.
func TestImportNeverResendsOverTheWire(t *testing.T) {
	for _, fault := range []struct {
		name string
		f    fakekv.Fault
	}{
		{"connection reset after the vault processed it", fakekv.Fault{Reset: true, Apply: true}},
		{"503 after the vault processed it", fakekv.Fault{Status: http.StatusServiceUnavailable, Apply: true}},
	} {
		t.Run(fault.name, func(t *testing.T) {
			k := newKVNJ(t, fakekv.Options{}, wwwSite())
			k.addWebCert("web-cert")
			vault := k.addVault("prod-vault")
			certID := k.uploadCertificate(k.op, certBody(k.issue(), "To import"))
			k.kv.FailNext("/certificates/once-cert/import", fault.f)

			im := k.requestImport(certID, vault, "once-cert", false)
			assert.Equal(t, "uncertain", im.State)
			assert.Equal(t, 1, importPosts(k.kv), "one authenticated POST")
			require.Len(t, k.kv.Versions("once-cert"), 1, "the vault holds exactly one version")
			job := k.job(k.admin, k.importJobID(vault, im.ID))
			assert.EqualValues(t, 1, job["attempts"], "the job was not run again")

			// A real second run: the SAME job delivered again (a lost lease, a requeue after a crash) reads the record
			// back and sends nothing (an import found "running" is TestImportFoundRunningIsNeverSent).
			jobID := k.importJobID(vault, im.ID)
			requeue := func() {
				_, err := k.db.Owner.Exec(context.Background(), `UPDATE jobs SET status = 'queued', finished_at = NULL, locked_by = NULL,
locked_until = NULL, run_at = $2 WHERE id = $1`, jobID, k.clock.Now())
				require.NoError(t, err)
				require.Positive(t, k.runKV(), "the job really ran again")
			}
			requeue()
			assert.Equal(t, 1, importPosts(k.kv), "a redelivered job sends nothing")
			k.pass(20 * time.Minute)
			k.runKV()
			rec := k.importRaw(certID, vault, "once-cert", false)
			requireError(t, rec, http.StatusConflict, "ALC-AKV-0024")
			rec = k.importRaw(certID, vault, "once-cert", true)
			requireError(t, rec, http.StatusConflict, "ALC-AKV-0024")
			assert.Equal(t, 1, importPosts(k.kv))
			assert.Len(t, k.kv.Versions("once-cert"), 1)
			assert.Equal(t, "uncertain", k.importOf(vault, im.ID).State)

			// A poll (here the schedule's) sees the version with the thumbprint, created after the request: settled, still one POST.
			require.NoError(t, k.schedule())
			got := k.importOf(vault, im.ID)
			assert.Equal(t, "succeeded", got.State)
			assert.Equal(t, k.kv.Versions("once-cert")[0], got.Version)
			assert.Equal(t, 1, importPosts(k.kv))
			assert.Len(t, k.kv.Versions("once-cert"), 1)
		})
	}
}

func (k *kvnj) importJobID(vault, id string) string {
	k.t.Helper()
	rec := k.admin.do(http.MethodGet, "/api/v1/targets/"+vault+"/kv/imports/"+id, nil)
	requireStatus(k.t, rec, http.StatusOK)
	return decodeBody[map[string]any](k.t, rec)["job_id"].(string)
}

// TestKeyVaultClockSkewAndWholeSeconds pins how Azure's own clock enters the decisions (ruling S14 and the planner's
// eligibility): Azure reports "created" in whole seconds, and Alice compares it with its own times.
//   - whole seconds: a request made half a second past a second still settles by the version Azure stamped with the
//     truncated second (the request time is truncated too);
//   - Azure behind Alice: a version created "before" the request cannot settle an uncertain import (it could be an
//     older certificate with that thumbprint): the import stays unknown and ends at the 72-hour rule as outcome
//     unknown (ALC-AKV-0026); a renewal stamped before the moment automatic deployment was switched on is not
//     deployed automatically (the Administrators are told: TestKeyVaultSkewedRenewalIsAnnounced);
//   - Azure ahead of Alice: both work.
func TestKeyVaultClockSkewAndWholeSeconds(t *testing.T) {
	t.Run("whole seconds", func(t *testing.T) {
		// The request and the vault's version land in the SAME second, a quarter of a second past its start: Azure's
		// created is 12:00:07, the request time 12:00:07.25; settling compares created with the request time cut to
		// the second (without the cut the version would look older than the request and never settle).
		k := newKVNJ(t, fakekv.Options{}, wwwSite())
		k.addWebCert("web-cert")
		vault := k.addVault("prod-vault")
		certID := k.uploadCertificate(k.op, certBody(k.issue(), "To import"))
		k.kv.FailNext("/certificates/half-cert/import", fakekv.Fault{Reset: true, Apply: true})
		k.stepUp(k.admin, k.adminAcct) // moves the clock 31 s: do it first, then fix the time of the request
		start := k.clock.Now().Truncate(time.Second).Add(time.Second)
		k.clock.Set(start.Add(250 * time.Millisecond))
		rec := k.admin.do(http.MethodPost, "/api/v1/certificates/"+certID+"/actions/import-to-key-vault", map[string]any{"target_id": vault, "name": "half-cert"})
		requireStatus(t, rec, http.StatusAccepted)
		id := decodeBody[struct {
			Import importView `json:"import"`
		}](t, rec).Import.ID
		k.runKV()
		im := k.importOf(vault, id)
		require.Equal(t, "uncertain", im.State)
		require.Equal(t, start, k.clock.Now().Truncate(time.Second), "the request and the vault's version are in one second")
		created := k.kv.Leaf("half-cert", "")
		require.NotNil(t, created)
		k.clock.Advance(time.Minute)
		k.checkNow(vault)
		assert.Equal(t, "succeeded", k.importOf(vault, im.ID).State)
	})

	// A name that exists in the vault but that Alice never polled: the import is refused as a name that exists, and
	// nothing is sent (the provider checks before it sends unless the caller confirmed).
	t.Run("a name Alice does not know", func(t *testing.T) {
		k := newKVNJ(t, fakekv.Options{}, wwwSite())
		k.addWebCert("web-cert")
		vault := k.addVault("prod-vault")
		k.kv.AddCertificate("secret-cert", fakekv.CertOptions{CommonName: "s.example.test", Exportable: true}) // never polled
		certID := k.uploadCertificate(k.op, certBody(k.issue(), "To import"))
		im := k.requestImport(certID, vault, "secret-cert", false)
		assert.Equal(t, "failed", im.State)
		assert.Equal(t, "ALC-AKV-0023", im.errCode())
		assert.Equal(t, 0, importPosts(k.kv), "nothing was sent")
		assert.Len(t, k.kv.Versions("secret-cert"), 1, "the vault's certificate is untouched")
	})

	t.Run("azure ahead", func(t *testing.T) {
		var skew atomic.Int64
		skew.Store(int64(10 * time.Minute))
		k := newKVNJSkew(t, fakekv.Options{}, &skew, wwwSite())
		k.addWebCert("web-cert")
		vault := k.addVault("prod-vault")
		certID := k.uploadCertificate(k.op, certBody(k.issue(), "To import"))
		k.kv.FailNext("/certificates/ahead-cert/import", fakekv.Fault{Reset: true, Apply: true})
		im := k.requestImport(certID, vault, "ahead-cert", false)
		require.Equal(t, "uncertain", im.State)
		k.clock.Advance(time.Minute)
		k.checkNow(vault)
		assert.Equal(t, "succeeded", k.importOf(vault, im.ID).State)
		bid, _ := k.bindWeb(vault, k.locs[wwwCert])
		requireStatus(t, k.autoDeploy(bid, 1, true), http.StatusOK)
		k.clock.Advance(2 * time.Minute)
		v := k.kv.Renew("web-cert")
		k.clock.Advance(time.Minute)
		k.checkNow(vault)
		require.NoError(t, k.plan())
		deps := k.kvDeployments(k.op, k.locs[wwwCert])
		require.Len(t, deps, 1)
		assert.Equal(t, v, deps[0].KVVersion)
	})

	t.Run("azure behind", func(t *testing.T) {
		var skew atomic.Int64
		skew.Store(-int64(10 * time.Minute))
		k := newKVNJSkew(t, fakekv.Options{}, &skew, wwwSite())
		k.addWebCert("web-cert")
		vault := k.addVault("prod-vault")
		certID := k.uploadCertificate(k.op, certBody(k.issue(), "To import"))
		k.kv.FailNext("/certificates/behind-cert/import", fakekv.Fault{Reset: true, Apply: true})
		im := k.requestImport(certID, vault, "behind-cert", false)
		require.Equal(t, "uncertain", im.State)
		k.clock.Advance(time.Minute)
		k.checkNow(vault)
		assert.Equal(t, "uncertain", k.importOf(vault, im.ID).State, "a version stamped before the request cannot settle it")
		k.pass(73 * time.Hour)
		require.NoError(t, k.schedule())
		got := k.importOf(vault, im.ID)
		assert.Equal(t, "failed", got.State)
		assert.Equal(t, "ALC-AKV-0026", got.errCode(), "outcome unknown after the unconditional end")

		// Planner eligibility: the renewal is stamped ten minutes before automatic deployment was switched on.
		bid, _ := k.bindWeb(vault, k.locs[wwwCert])
		requireStatus(t, k.autoDeploy(bid, 1, true), http.StatusOK)
		k.clock.Advance(2 * time.Minute)
		k.kv.Renew("web-cert")
		k.clock.Advance(time.Minute)
		k.checkNow(vault)
		require.NoError(t, k.plan())
		assert.Empty(t, k.kvDeployments(k.op, k.locs[wwwCert]), "not deployed automatically")
	})
}

// TestImportFoundRunningIsNeverSent: a run that died right after the mark left the import "running" and the job queued
// again: the handler must not open a session or send; it records the import as uncertain.
func TestImportFoundRunningIsNeverSent(t *testing.T) {
	k := newKVNJ(t, fakekv.Options{}, wwwSite())
	k.addWebCert("web-cert")
	vault := k.addVault("prod-vault")
	certID := k.uploadCertificate(k.op, certBody(k.issue(), "To import"))
	rec := k.importRaw(certID, vault, "crashed-cert", false)
	requireStatus(t, rec, http.StatusAccepted)
	id := decodeBody[struct {
		Import importView `json:"import"`
	}](t, rec).Import.ID
	// The crash: the mark was committed (running, sent_at set) and the process died before the send.
	_, err := k.db.Owner.Exec(context.Background(), "UPDATE kv_imports SET state = 'running', sent_at = $2 WHERE id = $1", id, k.clock.Now())
	require.NoError(t, err)
	require.Positive(t, k.runKV())
	got := k.importOf(vault, id)
	assert.Equal(t, "uncertain", got.State, "found running, it is recorded as uncertain")
	assert.Zero(t, importPosts(k.kv), "nothing was sent")
	assert.Empty(t, k.kv.Versions("crashed-cert"))
	assert.Empty(t, k.sentPFXs(), "the provider was not even asked")
}

// TestKeyVaultSkewedRenewalIsAnnounced: Azure's clock runs ten minutes behind Alice's, so a renewal made after automatic
// deployment was switched on is stamped before it. By the strict rule it is not deployed automatically, and the
// Administrators are told to deploy it by hand (kv.version_skipped_manual, once: fix 4ccdae8).
func TestKeyVaultSkewedRenewalIsAnnounced(t *testing.T) {
	var skew atomic.Int64
	skew.Store(-int64(10 * time.Minute))
	k := newKVNJSkew(t, fakekv.Options{}, &skew, wwwSite())
	k.addWebCert("web-cert")
	vault := k.addVault("prod-vault")
	bid, _ := k.bindWeb(vault, k.locs[wwwCert])
	requireStatus(t, k.autoDeploy(bid, 1, true), http.StatusOK)
	k.clock.Advance(2 * time.Minute)
	k.kv.Renew("web-cert")
	k.clock.Advance(time.Minute)
	k.checkNow(vault)
	require.NoError(t, k.plan())
	assert.Empty(t, k.kvDeployments(k.op, k.locs[wwwCert]), "not deployed automatically")
	assert.Equal(t, 1, k.emails("kv.version_skipped_manual"), "the Administrators are told to deploy it by hand")
	k.pass(time.Hour)
	require.NoError(t, k.plan())
	assert.Equal(t, 1, k.emails("kv.version_skipped_manual"), "once")
}
