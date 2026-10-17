//go:build integration

package inventory_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/inventory"
	"alice/internal/jobs"
	"alice/internal/providers"
	"alice/internal/rbac"
)

func rows(code string, kinds ...string) []providers.KVListFailure {
	var out []providers.KVListFailure
	for _, k := range kinds {
		out = append(out, providers.KVListFailure{Object: k, Err: providers.NewError(code, true, nil, nil)})
	}
	return out
}

func (h *harness) setInterval(id uuid.UUID, seconds int) {
	h.t.Helper()
	_, err := h.db.Owner.Exec(h.ctx, "UPDATE targets SET discovery_interval_seconds = $2 WHERE id = $1", id, seconds)
	require.NoError(h.t, err)
}

// I1: a failed list is classified by its reason with the table of RecordKVFailure; the real provider
// returns unreachable, throttled and unexpected answers as rows.
func TestListFailureRowsFollowTheReasonClasses(t *testing.T) {
	h := newHarness(t, withAzure())
	h.user("ada", rbac.Admin, "ada@example.com")
	cases := []struct {
		reason, status string
		code           string
		failures       int
	}{
		{"azure.unreachable", inventory.StatusUnreachable, "azure.unreachable", 1},
		{"azure.vault_not_found", inventory.StatusUnreachable, "azure.vault_not_found", 1},
		{"azure.tls_untrusted", inventory.StatusUnreachable, "azure.tls_untrusted", 1},
		{"azure.address_not_allowed", inventory.StatusUnreachable, "azure.address_not_allowed", 1},
		{"azure.unexpected_response", inventory.StatusOK, "azure.unexpected_response", 1}, // N6: the code is recorded
		{"internal.unexpected", inventory.StatusOK, "internal.unexpected", 1},
		{"azure.throttled", inventory.StatusOK, "", 1},
		{"azure.forbidden", inventory.StatusDegraded, "azure.forbidden", 0},
		{"azure.firewall", inventory.StatusDegraded, "azure.firewall", 0},
		{"azure.auth_failed", inventory.StatusAuthFailed, "azure.auth_failed", 1},
		{"azure.credentials_expired", inventory.StatusAuthFailed, "azure.credentials_expired", 1},
		{"azure.clock_skew", inventory.StatusAuthFailed, "azure.clock_skew", 1},
		{"azure.managed_identity_unavailable", inventory.StatusAuthFailed, "azure.managed_identity_unavailable", 1},
	}
	for i, c := range cases {
		v := h.vault(fmt.Sprintf("vlt%d", i))
		r := kvResult()
		r.KV.Failures = rows(c.reason, "certificates")
		sum := h.reconcile(v, r)
		row := h.vaultRow(v)
		assert.Equal(t, c.status, row.Status, c.reason)
		assert.Equal(t, c.code, row.Code, c.reason)
		assert.Equal(t, c.failures, row.PollFailures, c.reason)
		assert.Equal(t, c.status, sum.Status, c.reason)
		assert.Nil(t, row.LastSuccess, c.reason)
	}

	// Precedence when several lists fail with different reasons: sign-in > unreachable >
	// forbidden/firewall > throttled > anything else.
	pick := func(name string, certs, keys, secrets string) vaultRow {
		v := h.vault(name)
		r := kvResult()
		r.KV.Failures = append(append(rows(certs, "certificates"), rows(keys, "keys")...), rows(secrets, "secrets")...)
		h.reconcile(v, r)
		return h.vaultRow(v)
	}
	got := pick("pick1", "azure.forbidden", "azure.unreachable", "azure.unexpected_response")
	// N4: the certificate list's own failure decides first; keys and secrets only degrade.
	assert.Equal(t, inventory.StatusDegraded, got.Status)
	assert.Equal(t, "azure.forbidden", got.Code)
	got = pick("pick2", "azure.unreachable", "azure.auth_failed", "azure.forbidden")
	assert.Equal(t, inventory.StatusUnreachable, got.Status)
	got = pick("pick3", "azure.unexpected_response", "azure.throttled", "azure.forbidden")
	assert.Equal(t, inventory.StatusDegraded, got.Status)
	assert.Equal(t, "azure.forbidden", got.Code)
	got = pick("pick4", "azure.unexpected_response", "azure.throttled", "azure.throttled")
	assert.Equal(t, inventory.StatusOK, got.Status, "throttled and unexpected only: one cycle, the status stays")
	assert.Equal(t, 1, got.Facts.KVThrottledCycles)

	// Sign-in failures as rows count toward the mail at the third in a row, once; the episode is
	// re-armed when something else sets the vault ok (M3): an access check clears the streak.
	v := h.vault("signin")
	fail := func() {
		h.clock.Advance(time.Minute)
		r := kvResult()
		r.KV.Failures = rows("azure.auth_failed", "certificates")
		h.reconcile(v, r)
	}
	fail()
	fail()
	assert.Equal(t, 0, h.emails("kv.auth_failed"))
	fail()
	fail()
	assert.Equal(t, 1, h.emails("kv.auth_failed"), "once per episode")
	require.NoError(t, h.svc.RecordKVConnection(h.ctx, v, providers.ConnectionReport{Azure: &providers.AzureFacts{PermissionModel: "rbac", CheckedAt: h.clock.Now(),
		Checks: []providers.AzureCheck{{Name: providers.AzureCheckSignIn, Result: providers.AzureResultOK}, {Name: providers.AzureCheckListCertificates, Result: providers.AzureResultOK}}}}))
	assert.Equal(t, inventory.StatusOK, h.vaultRow(v).Status)
	assert.Equal(t, 4, h.vaultRow(v).Facts.KVAuthFailures, "the stale counter is still stored")
	fail()
	fail()
	assert.Equal(t, 1, h.emails("kv.auth_failed"))
	fail()
	assert.Equal(t, 2, h.emails("kv.auth_failed"), "the new episode sends its own mail at its third failure")
	// A successful poll re-arms it too.
	h.clock.Advance(time.Minute)
	h.reconcile(v, kvResult(h.kvc("alpha", h.kvLeaf("a.example.test"), ver(1), h.clock.Now(), true)))
	fail()
	fail()
	fail()
	assert.Equal(t, 3, h.emails("kv.auth_failed"))
}

// M4: a poll that got an answer proves the sign-in and the network, so it clears auth_failed and
// unreachable even when the answer was a throttled or unexpected list.
func TestAPollThatSignedInClearsAuthFailed(t *testing.T) {
	h := newHarness(t, withAzure())
	h.user("ada", rbac.Admin, "ada@example.com")
	for i, reason := range []string{"azure.throttled", "azure.unexpected_response"} {
		for j, first := range []string{"azure.auth_failed", "azure.unreachable"} {
			v := h.vault(fmt.Sprintf("vlt%d%d", i, j))
			require.NoError(t, h.svc.RecordKVFailure(h.ctx, v, providers.NewError(first, false, nil, nil)))
			require.NotEqual(t, inventory.StatusOK, h.vaultRow(v).Status)
			h.clock.Advance(time.Minute)
			r := kvResult()
			r.KV.Failures = rows(reason, "keys")
			h.reconcile(v, r)
			assert.Equal(t, inventory.StatusOK, h.vaultRow(v).Status, "%s after %s", reason, first)
			if reason == "azure.throttled" {
				assert.Empty(t, h.vaultRow(v).Code)
			} else {
				assert.Equal(t, reason, h.vaultRow(v).Code, "R3: the unexpected answer leaves its code on the cleared vault (N6)")
			}
		}
	}
	// A degraded vault (a missing role) stays degraded under a throttled cycle.
	v := h.vault("degraded")
	require.NoError(t, h.svc.RecordKVFailure(h.ctx, v, providers.NewError("azure.forbidden", false, nil, nil)))
	r := kvResult()
	r.KV.Failures = rows("azure.throttled", "keys")
	h.reconcile(v, r)
	assert.Equal(t, inventory.StatusDegraded, h.vaultRow(v).Status)
	assert.Equal(t, "azure.forbidden", h.vaultRow(v).Code)
}

// M6 (S15): a listing cut short by the poll's budget counts as a throttled cycle and as a failed
// poll for the backoff; a cut at the bound itself is a plain success.
func TestABudgetCutPollCountsAsAThrottledCycle(t *testing.T) {
	h := newHarness(t, withAzure())
	h.user("ada", rbac.Admin, "ada@example.com")
	v := h.vault("prod")
	now := h.clock.Now()
	l := h.kvLeaf("a.example.test")
	cut := func(kinds ...string) providers.DiscoveryResult {
		r := kvResult(h.kvc("alpha", l, ver(1), now, true))
		r.KV.Truncated = kinds
		return r
	}
	h.reconcile(v, kvResult(h.kvc("alpha", l, ver(1), now, true)))
	base := h.vaultRow(v)
	for i := 1; i <= 3; i++ {
		h.clock.Advance(time.Minute)
		h.reconcile(v, cut("certificates"))
		row := h.vaultRow(v)
		assert.Equal(t, i, row.Facts.KVThrottledCycles)
		assert.Equal(t, i, row.PollFailures, "backoff counts it")
		assert.True(t, base.LastSuccess.Equal(*row.LastSuccess), "a cut listing is not a success")
		if i < 3 {
			assert.Equal(t, inventory.StatusOK, row.Status)
		} else {
			assert.Equal(t, inventory.StatusDegraded, row.Status)
			assert.Equal(t, "azure.throttled", row.Code)
		}
		assert.Equal(t, []string{"certificates"}, row.Facts.KVPoll.Truncated)
		assert.Nil(t, h.certRow(v, "alpha").Missing)
	}
	// The next complete poll recovers.
	h.clock.Advance(time.Minute)
	h.reconcile(v, kvResult(h.kvc("alpha", l, ver(1), now, true)))
	assert.Equal(t, inventory.StatusOK, h.vaultRow(v).Status)
	assert.Zero(t, h.vaultRow(v).Facts.KVThrottledCycles)

	// Keys or secrets cut by the budget count too.
	h.clock.Advance(time.Minute)
	r := kvResult(h.kvc("alpha", l, ver(1), now, true))
	r.KV.Keys, r.KV.Truncated = []providers.KVKey{kvKey("k1", false, now, true)}, []string{"keys"}
	h.reconcile(v, r)
	assert.Equal(t, 1, h.vaultRow(v).Facts.KVThrottledCycles)

	// Cut at the bound: the kind holds as many items as the bound, a permanent state, not a failure.
	big := providers.DiscoveryResult{KV: &providers.KVInventory{Truncated: []string{"certificates"}}}
	for i := range 5000 {
		big.KV.Certificates = append(big.KV.Certificates, providers.KVCertificate{Name: fmt.Sprintf("c%d", i), Thumbprint: fmt.Sprintf("%040x", i), Enabled: true})
	}
	h.clock.Advance(time.Minute)
	h.reconcile(v, big)
	row := h.vaultRow(v)
	assert.Zero(t, row.Facts.KVThrottledCycles)
	assert.Zero(t, row.PollFailures)
	assert.True(t, h.clock.Now().Equal(*row.LastSuccess))
}

// M7: forbidden and firewall are a configuration state: degraded, and polled at the normal interval
// (the plan's row 13 names no backoff for them).
func TestForbiddenDoesNotBackOff(t *testing.T) {
	h := newHarness(t, withAzure())
	h.user("ada", rbac.Admin, "")
	v := h.vault("prod")
	for range 3 {
		h.clock.Advance(time.Minute)
		r := kvResult()
		r.KV.Failures = rows("azure.forbidden", "certificates")
		h.reconcile(v, r)
		require.NoError(t, h.svc.RecordKVFailure(h.ctx, v, providers.NewError("azure.firewall", false, nil, nil)))
	}
	assert.Zero(t, h.vaultRow(v).PollFailures)
	assert.Equal(t, inventory.StatusDegraded, h.vaultRow(v).Status)
	// An unreachable vault does back off, and a forbidden answer afterwards ends it.
	require.NoError(t, h.svc.RecordKVFailure(h.ctx, v, providers.NewError("azure.unreachable", true, nil, nil)))
	assert.Equal(t, 1, h.vaultRow(v).PollFailures)
	require.NoError(t, h.svc.RecordKVFailure(h.ctx, v, providers.NewError("azure.forbidden", false, nil, nil)))
	assert.Equal(t, 1, h.vaultRow(v).PollFailures, "unchanged by a refusal")
	r := kvResult()
	r.KV.Failures = rows("azure.forbidden", "certificates")
	h.reconcile(v, r)
	assert.Zero(t, h.vaultRow(v).PollFailures, "the vault answered: the delay ends")
}

// I3: a kind in Failures is never marked missing, for each kind on its own, even when the listing
// carries items and KeysListed/SecretsListed is set.
func TestAFailedListingWithItemsMarksNothing(t *testing.T) {
	h := newHarness(t, withAzure())
	h.user("ada", rbac.Admin, "ada@example.com")
	v := h.vault("prod")
	now := h.clock.Now()
	la, lb := h.kvLeaf("a.example.test"), h.kvLeaf("b.example.test")
	full := func() providers.DiscoveryResult {
		r := kvResult(h.kvc("alpha", la, ver(1), now, true), h.kvc("beta", lb, ver(2), now, true))
		r.KV.Keys = []providers.KVKey{kvKey("k1", false, now, true), kvKey("k2", false, now, true)}
		r.KV.Secrets = []providers.KVSecret{kvSecret("s1", now), kvSecret("s2", now)}
		r.KV.KeysListed, r.KV.SecretsListed = true, true
		return r
	}
	h.reconcile(v, full())
	missing := func() int {
		return h.count(`SELECT (SELECT count(*) FROM kv_certificates WHERE missing_since IS NOT NULL) + (SELECT count(*) FROM kv_keys WHERE missing_since IS NOT NULL)
 + (SELECT count(*) FROM kv_secrets WHERE missing_since IS NOT NULL)`)
	}
	h.clock.Advance(time.Minute)
	r := full()
	r.KV.Certificates = r.KV.Certificates[1:] // alpha absent, the listing carries beta, and it failed
	r.KV.Failures = rows("azure.forbidden", "certificates")
	h.reconcile(v, r)
	assert.Zero(t, missing(), "certificates in Failures")
	r = full()
	r.KV.Keys = r.KV.Keys[1:]
	r.KV.Failures = rows("azure.forbidden", "keys")
	h.reconcile(v, r)
	assert.Zero(t, missing(), "keys in Failures, KeysListed true")
	r = full()
	r.KV.Secrets = r.KV.Secrets[1:]
	r.KV.Failures = rows("azure.forbidden", "secrets")
	h.reconcile(v, r)
	assert.Zero(t, missing(), "secrets in Failures, SecretsListed true")
	// "versions" truncated is global but marks nothing missing anyway: certificates complete still mark.
	r = full()
	r.KV.Certificates = r.KV.Certificates[1:]
	r.KV.Truncated = []string{"versions"}
	h.reconcile(v, r)
	assert.NotNil(t, h.certRow(v, "alpha").Missing)
	assert.Zero(t, h.count("SELECT count(*) FROM kv_certificate_versions WHERE false"))
}

// I3: an older poll (its time is earlier than a sighting a newer poll stored) marks nothing missing
// and revives nothing.
func TestAnOlderPollMarksAndRevivesNothing(t *testing.T) {
	h := newHarness(t, withAzure())
	h.user("ada", rbac.Admin, "ada@example.com")
	v := h.vault("prod")
	t0 := h.clock.Now()
	la, lb := h.kvLeaf("a.example.test"), h.kvLeaf("b.example.test")
	full := func() providers.DiscoveryResult {
		r := kvResult(h.kvc("alpha", la, ver(1), t0, true), h.kvc("beta", lb, ver(2), t0, true))
		r.KV.Keys = []providers.KVKey{kvKey("k1", false, t0, true), kvKey("k2", false, t0, true)}
		r.KV.Secrets = []providers.KVSecret{kvSecret("s1", t0), kvSecret("s2", t0)}
		r.KV.KeysListed, r.KV.SecretsListed = true, true
		return r
	}
	h.reconcile(v, full())
	// A newer poll (one hour later) saw everything.
	h.clock.Set(t0.Add(time.Hour))
	h.reconcile(v, full())
	// An older poll (30 minutes) that lacks alpha, k1 and s1 arrives late: it must not mark them.
	h.clock.Set(t0.Add(30 * time.Minute))
	r := full()
	r.KV.Certificates, r.KV.Keys, r.KV.Secrets = r.KV.Certificates[1:], r.KV.Keys[1:], r.KV.Secrets[1:]
	sum := h.reconcile(v, r)
	assert.Zero(t, sum.MissingCertificates+sum.MissingKeys+sum.MissingSecrets)
	assert.Zero(t, h.count(`SELECT (SELECT count(*) FROM kv_certificates WHERE missing_since IS NOT NULL) + (SELECT count(*) FROM kv_keys WHERE missing_since IS NOT NULL)
 + (SELECT count(*) FROM kv_secrets WHERE missing_since IS NOT NULL)`))

	// A newer poll marks alpha missing; an older listing-only sighting does not revive it.
	h.clock.Set(t0.Add(2 * time.Hour))
	h.reconcile(v, kvResult(h.kvc("beta", lb, ver(2), t0, true)))
	require.NotNil(t, h.certRow(v, "alpha").Missing)
	h.clock.Set(t0.Add(90 * time.Minute))
	h.reconcile(v, kvResult(h.kvc("alpha", la, "", t0, false), h.kvc("beta", lb, "", t0, false)))
	assert.NotNil(t, h.certRow(v, "alpha").Missing, "an older listing-only sighting does not revive it")
	// A later one does.
	h.clock.Set(t0.Add(3 * time.Hour))
	h.reconcile(v, kvResult(h.kvc("alpha", la, "", t0, false), h.kvc("beta", lb, "", t0, false)))
	assert.Nil(t, h.certRow(v, "alpha").Missing)
}

// I3: the backoff cap and exponent of the scheduling query.
func TestScheduleBackoffCapAndExponent(t *testing.T) {
	h := newHarness(t, withAzure())
	h.user("ada", rbac.Admin, "")
	slow := h.vault("slow") // 30 minutes
	fast := h.vault("fast") // 5 minutes
	h.setInterval(slow, 1800)
	h.setInterval(fast, 300)
	_, err := h.db.Owner.Exec(h.ctx, "UPDATE targets SET poll_failures = 2 WHERE id = $1", slow)
	require.NoError(t, err)
	_, err = h.db.Owner.Exec(h.ctx, "UPDATE targets SET poll_failures = 3 WHERE id = $1", fast)
	require.NoError(t, err)
	n, err := h.svc.ScheduleKVPolls(h.ctx) // never scheduled: both due
	require.NoError(t, err)
	require.Equal(t, 2, n)
	due := func(d time.Duration) map[uuid.UUID]bool {
		before := len(h.jobs.requests())
		h.clock.Advance(d)
		_, err := h.svc.ScheduleKVPolls(h.ctx)
		require.NoError(t, err)
		out := map[uuid.UUID]bool{}
		for _, r := range h.jobs.requests()[before:] {
			out[r.TargetID] = true
		}
		return out
	}
	// fast: 5 min * 2^min(3,2) = 20 min (not 40); slow: 30 min * 4 = 120 min, capped at max(30 min, 1 h) = 60 min.
	assert.Empty(t, due(19*time.Minute))
	got := due(time.Minute)
	assert.Equal(t, map[uuid.UUID]bool{fast: true}, got, "20 minutes: the 5 minute vault with three failures")
	_, err = h.db.Owner.Exec(h.ctx, "UPDATE targets SET last_scheduled_at = $2 WHERE id = $1", fast, h.clock.Now().Add(100*24*time.Hour)) // parked
	require.NoError(t, err)
	assert.Empty(t, due(39*time.Minute)) // 59 min since the start: the slow vault is not yet due
	got = due(time.Minute)
	assert.True(t, got[slow], "60 minutes: the cap, not 120")
}

// I3: the removal caps (M2): 20 mails and 200 audit rows, the rest is counted in one summary mail
// and in the poll's audit row.
func TestRemovalCapsAreSignalled(t *testing.T) {
	h := newHarness(t, withAzure())
	h.user("ada", rbac.Admin, "ada@example.com")
	v := h.vault("prod")
	now := h.clock.Now()
	var cs []providers.KVCertificate
	for i := range 252 {
		cs = append(cs, providers.KVCertificate{Name: fmt.Sprintf("c%03d", i), Thumbprint: fmt.Sprintf("%040x", i+1), Enabled: true, Updated: &now})
	}
	h.reconcile(v, kvResult(cs...))
	h.clock.Advance(time.Minute)
	sum := h.reconcile(v, kvResult(cs[251])) // 251 vanish from a complete listing
	assert.Equal(t, 251, sum.MissingCertificates)
	assert.Equal(t, 251, h.count("SELECT count(*) FROM kv_certificates WHERE missing_since IS NOT NULL"))
	assert.Equal(t, 20, h.removalEmails(), "one mail each for the first 20")
	assert.Equal(t, 1, h.emails("kv.certificates_removed_more"), "and one summary mail")
	var params string
	require.NoError(t, h.db.Owner.QueryRow(h.ctx, "SELECT params::text FROM notifications_outbox WHERE template_key = 'kv.certificates_removed_more'").Scan(&params))
	assert.JSONEq(t, `{"target_name":"prod","count":"231"}`, params)
	assert.Equal(t, 20, h.count("SELECT count(*) FROM kv_certificates WHERE removed_notified_at IS NOT NULL"))
	assert.Equal(t, 200, h.audits("kv.certificate.removed"))
	d := h.auditDetails("target.discovered")
	last := d[len(d)-1]
	assert.Equal(t, "251", last["removed_count"])
	assert.Equal(t, "200", last["audited_count"])
	assert.Equal(t, "20", last["notified_count"])
	// Under the caps there is no summary mail.
	before := h.emails("kv.certificates_removed_more")
	h.clock.Advance(time.Minute)
	h.reconcile(v, kvResult())
	h.clock.Advance(time.Minute)
	h.reconcile(v, kvResult())
	assert.Equal(t, before, h.emails("kv.certificates_removed_more"))
}

// I3: the final transaction of ReconcileKV and the transaction of RecordKVFailure hold the vault's
// row from their read of the facts to their write: a change another transaction commits while they
// wait is not overwritten (the facts are rewritten whole from what was read).
func TestFinalTransactionsHoldTheVaultRow(t *testing.T) {
	h := newHarness(t, withAzure())
	h.user("ada", rbac.Admin, "")
	v := h.vault("prod")
	marker := "2026-01-02T03:04:05Z"
	blocked := func(name string, call func()) {
		tx, err := h.db.Owner.Begin(h.ctx)
		require.NoError(t, err)
		_, err = tx.Exec(h.ctx, "SELECT 1 FROM targets WHERE id = $1 FOR UPDATE", v)
		require.NoError(t, err)
		finished := make(chan struct{})
		go func() { call(); close(finished) }()
		time.Sleep(400 * time.Millisecond) // the call has read the vault by now, if it does not wait for the lock
		_, err = tx.Exec(h.ctx, "UPDATE targets SET facts = jsonb_set(facts, '{kv_metadata_at}', to_jsonb($2::text)) WHERE id = $1", v, marker)
		require.NoError(t, err)
		require.NoError(t, tx.Commit(h.ctx))
		select {
		case <-finished:
		case <-time.After(10 * time.Second):
			t.Fatalf("%s did not finish", name)
		}
		var got string
		require.NoError(t, h.db.Owner.QueryRow(h.ctx, "SELECT coalesce(facts->>'kv_metadata_at', '') FROM targets WHERE id = $1", v).Scan(&got))
		assert.Equal(t, marker, got, "%s kept what the other transaction wrote", name)
		_, err = h.db.Owner.Exec(h.ctx, "UPDATE targets SET facts = facts - 'kv_metadata_at' WHERE id = $1", v)
		require.NoError(t, err)
	}
	// Nothing to store (no batch runs), so only the final transaction can wait.
	blocked("ReconcileKV", func() { _, _ = h.svc.ReconcileKV(h.ctx, v, kvResult()) })
	blocked("RecordKVFailure", func() { _ = h.svc.RecordKVFailure(h.ctx, v, providers.NewError("azure.unreachable", true, nil, nil)) })
}

// I3: the final transaction re-checks that the vault is still there and enabled, and that the job
// run still holds its job, after the last batch committed.
func TestFinalTransactionRechecksTheVaultAndTheClaim(t *testing.T) {
	h := newHarness(t, withAzure())
	h.jobs.next = jobs.NewQueue(jobs.QueueConfig{Pool: h.db.App, Keyring: h.keyring, Audit: h.audit, Clock: h.clock, Gate: h.lic})
	admin := h.user("ada", rbac.Admin, "ada@example.com")
	res := func() providers.DiscoveryResult {
		return kvResult(h.kvc("alpha", h.kvLeaf("a.example.test"), ver(1), h.clock.Now(), true))
	}
	for _, how := range []string{"disabled", "deleted"} {
		v := h.vault("v-" + how)
		restore := inventory.SetKVBatchHook(func(kind string, batch int) {
			set := "status = 'disabled'"
			if how == "deleted" {
				set = "deleted_at = now()"
			}
			_, err := h.db.Owner.Exec(h.ctx, "UPDATE targets SET "+set+" WHERE id = $1", v)
			require.NoError(t, err)
		})
		sum, err := h.svc.ReconcileKV(h.ctx, v, res())
		restore()
		require.NoError(t, err)
		assert.Equal(t, how, sum.Dropped)
		row := h.vaultRow(v)
		assert.Nil(t, row.LastSuccess, "the final transaction wrote nothing (%s)", how)
		assert.Nil(t, row.Facts.KVReconciledAt)
		assert.Zero(t, h.audits("target.discovered"))
	}
	v := h.vault("claim")
	job, err := h.svc.RequestDiscovery(h.ctx, admin, v)
	require.NoError(t, err)
	_, err = h.db.Owner.Exec(h.ctx, "UPDATE jobs SET status = 'running', attempts = 1 WHERE id = $1", job)
	require.NoError(t, err)
	restore := inventory.SetKVBatchHook(func(string, int) {
		_, err := h.db.Owner.Exec(h.ctx, "UPDATE jobs SET attempts = 2 WHERE id = $1", job)
		require.NoError(t, err)
	})
	defer restore()
	_, err = h.svc.ReconcileKV(inventory.WithClaim(h.ctx, inventory.Claim{JobID: job, Attempt: 1}), v, res())
	require.ErrorIs(t, err, inventory.ErrClaimLost)
	row := h.vaultRow(v)
	assert.Nil(t, row.LastSuccess, "the final transaction wrote nothing")
	assert.Zero(t, h.audits("target.discovered"))
}

// M5: two empty polls that overlap are one observation; the second must start after the first
// finished.
func TestEmptyListingNeedsALaterPoll(t *testing.T) {
	h := newHarness(t, withAzure())
	h.user("ada", rbac.Admin, "ada@example.com")
	v := h.vault("prod")
	h.reconcile(v, kvResult(h.kvc("alpha", h.kvLeaf("a.example.test"), ver(1), h.clock.Now(), true)))
	h.clock.Advance(time.Minute)
	h.reconcile(v, kvResult()) // the first empty poll, finished now
	require.NotNil(t, h.vaultRow(v).Facts.KVEmptyAt)
	h.reconcile(v, kvResult()) // started at the same moment: the same observation
	assert.Nil(t, h.certRow(v, "alpha").Missing)
	assert.Equal(t, 1, h.vaultRow(v).Facts.KVEmptyPolls)
	h.clock.Set(h.clock.Now().Add(-time.Second)) // started before the first finished
	h.reconcile(v, kvResult())
	assert.Nil(t, h.certRow(v, "alpha").Missing)
	h.clock.Set(h.clock.Now().Add(2 * time.Second))
	h.reconcile(v, kvResult())
	assert.NotNil(t, h.certRow(v, "alpha").Missing, "a later poll believes it")
	assert.Nil(t, h.vaultRow(v).Facts.KVEmptyAt)
}

// M8: certificates that are marked missing are not "known": the provider is not told about 5,000
// certificates when one is live.
func TestKnownLeavesOutMissingObjects(t *testing.T) {
	h := newHarness(t, withAzure())
	h.user("ada", rbac.Admin, "ada@example.com")
	v := h.vault("prod")
	now := h.clock.Now()
	la, lb := h.kvLeaf("a.example.test"), h.kvLeaf("b.example.test")
	r := kvResult(h.kvc("alpha", la, ver(1), now, true), h.kvc("beta", lb, ver(2), now, true))
	r.KV.Keys = []providers.KVKey{kvKey("k1", false, now, true), kvKey("k2", false, now, true)}
	r.KV.KeysListed = true
	h.reconcile(v, r)
	h.clock.Advance(time.Minute)
	r = kvResult(h.kvc("beta", lb, "", now, false))
	r.KV.Keys, r.KV.KeysListed = []providers.KVKey{kvKey("k2", false, now, true)}, true
	h.reconcile(v, r)
	require.NotNil(t, h.certRow(v, "alpha").Missing)
	h.clock.Advance(100 * time.Hour) // keys are asked for again
	req, err := h.svc.KVPollRequest(h.ctx, v)
	require.NoError(t, err)
	assert.Equal(t, []string{"beta"}, mapKeys(req.KVKnown))
	assert.Equal(t, []string{"k2"}, mapKeys(req.KVKnownKeys))
}

func mapKeys[V any](m map[string]V) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

// M1: an older read that is reconciled later cannot move the pointer back to a version Alice
// already has; a version that is provably newer can.
func TestAnOlderReadCannotMoveTheCurrentVersionBack(t *testing.T) {
	h := newHarness(t, withAzure())
	h.user("ada", rbac.Admin, "ada@example.com")
	v := h.vault("prod")
	t0 := h.clock.Now()
	l1, l2 := h.kvLeaf("www.example.test"), h.kvLeaf("www.example.test")
	h.reconcile(v, kvResult(h.kvc("web-cert", l1, ver(1), t0, true)))
	h.clock.Advance(time.Hour)
	t1 := h.clock.Now()
	h.reconcile(v, kvResult(h.kvc("web-cert", l2, ver(2), t1, true, ver(1))))
	require.Equal(t, ver(2), h.certRow(v, "web-cert").Version)
	// The read of v1 (created t0) is reconciled after the read of v2.
	h.clock.Advance(time.Minute)
	sum := h.reconcile(v, kvResult(h.kvc("web-cert", l1, ver(1), t0, true)))
	assert.Zero(t, sum.NewVersions)
	got := h.certRow(v, "web-cert")
	assert.Equal(t, ver(2), got.Version, "the pointer stays")
	assert.Equal(t, thumbOf(l2), got.Thumb)
	assert.Equal(t, 1, h.audits("kv.certificate.new_version"))

	// A version row Alice has from a listing (history) and that is newer than the current one moves it.
	h.clock.Advance(time.Hour)
	l3 := h.kvLeaf("www.example.test")
	t3 := h.clock.Now()
	r := h.kvc("web-cert", l2, ver(2), t1, true, ver(3))
	r.Versions[1].Created, r.Versions[1].Thumbprint = &t3, thumbOf(l3)
	h.reconcile(v, kvResult(r))
	require.Equal(t, ver(2), h.certRow(v, "web-cert").Version)
	h.clock.Advance(time.Minute)
	h.reconcile(v, kvResult(h.kvc("web-cert", l3, ver(3), t3, true)))
	assert.Equal(t, ver(3), h.certRow(v, "web-cert").Version, "provably newer: created later")
}

// The LocationCount of a vault certificate's binding counts websites on live servers only (as
// Binding.LocationCount).
func TestKVCertificateBindingCountsLiveServersOnly(t *testing.T) {
	h := newHarness(t, withAzure(), withNginxProvider())
	admin := h.user("ada", rbac.Admin, "")
	v := h.vault("prod")
	live, dead := nginxTarget(t, h, admin, "web-live"), nginxTarget(t, h, admin, "web-dead")
	h.reconcile(v, kvResult(h.kvc("web-cert", h.kvLeaf("www.example.test"), ver(1), h.clock.Now(), true)))
	cert := h.certRow(v, "web-cert")
	binding := h.bindCertificate(cert.ID, v)
	for _, tg := range []inventory.Target{live, dead} {
		_, err := h.svc.Reconcile(h.ctx, tg.ID, providers.DiscoveryResult{WebServer: nginxOK, Certificates: []providers.DiscoveredCertificate{
			dc(cl("/etc/nginx/ssl/a.crt", "/etc/nginx/ssl/a.key"), h.kvLeaf("a.example.test"))}})
		require.NoError(t, err)
	}
	_, err := h.db.Owner.Exec(h.ctx, "UPDATE certificate_locations SET binding_id = $1", binding)
	require.NoError(t, err)
	d, err := h.svc.KVCertificate(h.ctx, v, cert.ID)
	require.NoError(t, err)
	assert.Equal(t, 2, d.Binding.LocationCount)
	_, err = h.db.Owner.Exec(h.ctx, "UPDATE targets SET deleted_at = $2 WHERE id = $1", dead.ID, h.clock.Now())
	require.NoError(t, err)
	d, err = h.svc.KVCertificate(h.ctx, v, cert.ID)
	require.NoError(t, err)
	assert.Equal(t, 1, d.Binding.LocationCount, "a website on a deleted server is not counted")
	_ = pgx.ErrNoRows
}
