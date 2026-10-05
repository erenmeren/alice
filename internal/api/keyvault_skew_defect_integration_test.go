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

// TestKeyVaultSkewedRenewalIsNotSilent (fails: nothing tells the Administrators): Azure's clock runs ten minutes behind
// Alice's, so a renewal made after automatic deployment was switched on is stamped before it. It is (correctly, by the
// strict rule) not deployed automatically, but the "deploy it manually" email (kv.version_skipped_manual) that every
// other miss of the rule gets is not sent either: the planner only mails a version that is later than the binding by
// Azure's stamp, so under skew a real renewal is neither deployed nor announced.
func TestKeyVaultSkewedRenewalIsNotSilent(t *testing.T) {
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
	assert.Equal(t, 1, k.emails("kv.version_skipped_manual")+k.emails("kv.new_version_available"), "the Administrators are told about the new version")
}
