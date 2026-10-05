//go:build integration

package api

import (
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

			// A rerun, the passing of time, the schedule and a second request send nothing.
			k.runKV()
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
//     deployed automatically (and, see TestKeyVaultSkewedRenewalIsNotSilent, nobody is told);
//   - Azure ahead of Alice: both work.
func TestKeyVaultClockSkewAndWholeSeconds(t *testing.T) {
	t.Run("whole seconds", func(t *testing.T) {
		k := newKVNJ(t, fakekv.Options{}, wwwSite())
		k.addWebCert("web-cert")
		vault := k.addVault("prod-vault")
		certID := k.uploadCertificate(k.op, certBody(k.issue(), "To import"))
		k.clock.Advance(500 * time.Millisecond)
		k.kv.FailNext("/certificates/half-cert/import", fakekv.Fault{Reset: true, Apply: true})
		im := k.requestImport(certID, vault, "half-cert", false)
		require.Equal(t, "uncertain", im.State)
		k.clock.Advance(time.Minute)
		k.checkNow(vault)
		assert.Equal(t, "succeeded", k.importOf(vault, im.ID).State)
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
