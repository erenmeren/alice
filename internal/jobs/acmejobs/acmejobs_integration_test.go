//go:build integration

package acmejobs

import (
	"encoding/base64"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/acme"
	"alice/internal/acme/solver"
	"alice/internal/acme/solver/http01"
	"alice/internal/inventory"
	"alice/internal/jobs"
	"alice/internal/platform/netaddr/netaddrtest"
	"alice/internal/testutil/fakeacme"
)

// issuedRow is the stored certificate of a succeeded order.
type issuedRow struct {
	Source        string
	ChainComplete bool
	HasKey        bool
	Names         []string
}

func (w *world) issued(o inventory.ACMEOrder) issuedRow {
	w.t.Helper()
	require.NotNil(w.t, o.CertificateID)
	var r issuedRow
	require.NoError(w.t, w.db.Owner.QueryRow(w.ctx, `SELECT source, chain_complete, private_key_id IS NOT NULL, sans FROM certificates
WHERE id = $1`, *o.CertificateID).Scan(&r.Source, &r.ChainComplete, &r.HasKey, &r.Names))
	return r
}

// The whole DNS-01 order through the fake CA and its hook: a source acme certificate with a complete chain and a sealed
// key, the order succeeded without a key left in it, nothing left published, the audit rows of each step.
func TestIssueDNS01(t *testing.T) {
	w := newWorld(t)
	c := w.dnsCert("www.example.test", "api.example.test")
	o := w.order(c, inventory.ACMEOrderIssue)
	w.drain()

	o = w.getOrder(o.ID)
	assert.Equal(t, inventory.ACMEOrderSucceeded, o.State)
	assert.Empty(t, o.ErrorCode)
	assert.Zero(t, o.Presented, "every record was removed")
	assert.Zero(t, w.keyColumns(o.ID), "the key moved into managed_private_keys")
	r := w.issued(o)
	assert.Equal(t, "acme", r.Source)
	assert.True(t, r.ChainComplete, "the provider's bundle completes the chain (A3)")
	assert.True(t, r.HasKey)
	assert.ElementsMatch(t, []string{"www.example.test", "api.example.test"}, r.Names)
	got := w.getCert(c.ID)
	assert.Equal(t, inventory.ACMEStateActive, got.State)
	assert.Equal(t, *o.CertificateID, *got.CurrentCertificateID)
	assert.Zero(t, got.Failures)
	assert.Zero(t, w.dnsLeft(), "the hook removed both TXT values")
	assert.Equal(t, 2, w.fake.Counters()["hook-present"])
	assert.Equal(t, 2, w.fake.Counters()["hook-cleanup"])
	status, _, attempts := w.job("acme.issue")
	assert.Equal(t, string(jobs.StatusSucceeded), status)
	assert.Equal(t, 1, attempts)
	assert.Equal(t, 1, w.audits("acme.order.started"))
	assert.Equal(t, 1, w.audits("acme.order.succeeded"))
	assert.Zero(t, w.audits("acme.order.failed"))
	assert.Zero(t, w.count("SELECT count(*) FROM jobs WHERE type = 'acme.cleanup'"), "nothing was left to clean up")
	var url string
	require.NoError(t, w.db.Owner.QueryRow(w.ctx, "SELECT order_url FROM acme_orders WHERE id = $1", o.ID).Scan(&url))
	assert.True(t, strings.HasPrefix(url, w.fake.BaseURL()+"/acme/order/"), "the order URL is kept for a resume")
	w.noSecrets()
}

func TestIssueWildcard(t *testing.T) {
	w := newWorld(t)
	c := w.dnsCert("*.example.test", "example.test")
	o := w.order(c, inventory.ACMEOrderIssue)
	w.drain()
	o = w.getOrder(o.ID)
	require.Equal(t, inventory.ACMEOrderSucceeded, o.State, o.ErrorCode)
	assert.ElementsMatch(t, []string{"*.example.test", "example.test"}, w.issued(o).Names)
	assert.Zero(t, w.dnsLeft())
}

// HTTP-01 through the Nginx server's session: the token files are written and removed by the server's publisher and
// the fake CA validates them over HTTP.
func TestIssueHTTP01(t *testing.T) {
	w := newWorld(t)
	web := w.webTarget("web-1")
	c, err := w.inv.CreateACMECertificate(w.ctx, w.admin, inventory.ACMECertificateInput{ProviderID: w.provider.ID,
		Names: []string{"www.example.test", "shop.example.test"}, Challenge: inventory.ACMEChallengeHTTP01, HTTPTargetID: &web,
		KeyType: "rsa_2048"})
	require.NoError(t, err)
	addr := strings.TrimPrefix(w.web.URL, "http://")
	w.fake.SetHTTPTarget("www.example.test", addr)
	w.fake.SetHTTPTarget("shop.example.test", addr)
	o := w.order(c, inventory.ACMEOrderIssue)
	w.drain()
	o = w.getOrder(o.ID)
	require.Equal(t, inventory.ACMEOrderSucceeded, o.State, o.ErrorCode)
	assert.Equal(t, 2, w.pub.puts)
	assert.Zero(t, w.pub.live(), "both token files removed")
	assert.Equal(t, 2, w.fake.Counters()["validations-http-01"])
	var alg string
	require.NoError(t, w.db.Owner.QueryRow(w.ctx, `SELECT k.algorithm FROM certificates c JOIN managed_private_keys k ON k.id = c.private_key_id
WHERE c.id = $1`, *o.CertificateID).Scan(&alg))
	assert.Equal(t, "rsa", alg, "the certificate's key policy")

	// A server that is not reachable as a publisher ends the order with the provider's code, nothing published.
	_, err = w.db.Owner.Exec(w.ctx, "UPDATE targets SET status = 'disabled' WHERE id = $1", web)
	require.NoError(t, err)
	o = w.order(c, inventory.ACMEOrderIssue)
	w.drain()
	assert.Equal(t, "target.disabled", w.getOrder(o.ID).ErrorCode)
}

// A test run validates the authorizations and stops: no key, no certificate, no finalize at the CA.
func TestTestRunIssuesNothing(t *testing.T) {
	w := newWorld(t)
	c := w.dnsCert("try.example.test")
	finalized, newOrders := w.fake.Counters()["finalize"], w.fake.Counters()["new-order"]
	o := w.order(c, inventory.ACMEOrderTest)
	w.drain()
	o = w.getOrder(o.ID)
	assert.Equal(t, inventory.ACMEOrderSucceeded, o.State)
	assert.Nil(t, o.CertificateID)
	assert.Zero(t, w.keyColumns(o.ID))
	assert.Equal(t, finalized, w.fake.Counters()["finalize"], "no finalize")
	assert.Equal(t, newOrders+1, w.fake.Counters()["new-order"])
	assert.Zero(t, w.count("SELECT count(*) FROM certificates"))
	assert.Zero(t, w.count("SELECT count(*) FROM managed_private_keys"))
	assert.Equal(t, 1, w.audits("acme.order.test_succeeded"))
	assert.Equal(t, inventory.ACMEStatePending, w.getCert(c.ID).State, "a test run is not a renewal")
	assert.Zero(t, w.dnsLeft())

	// A failed test run counts no failure.
	require.NoError(t, w.fake.FailValidation(fakeacme.DNS01, true))
	o = w.order(c, inventory.ACMEOrderTest)
	w.drain()
	assert.Equal(t, acme.ReasonValidationFailedDNS, w.getOrder(o.ID).ErrorCode)
	assert.Equal(t, 1, w.audits("acme.order.test_failed"))
	assert.Zero(t, w.getCert(c.ID).Failures)
	_, code, _ := w.job("acme.issue")
	assert.Equal(t, acme.ReasonValidationFailedDNS, code, "the job's reason is the order's code")
}

// In lock nothing reaches the CA: the request is refused, and a job queued before the lock is never claimed.
func TestLockedOrdersNeverReachTheCA(t *testing.T) {
	w := newWorld(t)
	c := w.dnsCert("lock.example.test")
	o := w.order(c, inventory.ACMEOrderIssue)
	w.fake.ClearRequests()
	w.gate.locked.Store(true)
	before := w.fake.Counters()["new-order"]
	_, err := w.inv.RequestOrder(w.ctx, w.operator, w.dnsCert("lock2.example.test").ID, inventory.ACMEOrderIssue)
	require.Error(t, err)
	w.drain()
	assert.Equal(t, before, w.fake.Counters()["new-order"])
	assert.Empty(t, w.fake.Requests(), "the CA was not contacted")
	assert.Equal(t, inventory.ACMEOrderRunning, w.getOrder(o.ID).State, "the queued order waits; the sweep ends it later")

	// The sweep (ClassAlways) runs in lock: the old order is abandoned without asking the CA.
	w.clock.Advance(StaleAfter + time.Minute)
	require.NoError(t, w.h.sweep(w.ctx))
	assert.Equal(t, inventory.ACMEOrderAbandoned, w.getOrder(o.ID).ErrorCode)
	assert.Empty(t, w.fake.Requests())
}

// A lock that begins in the middle of an order: the next challenge is not published, the order fails license.locked,
// its key is deleted, and the cleanup job (ClassAlways) removes what was left in lock.
func TestLockDuringAnOrderStillCleansUp(t *testing.T) {
	w := newWorld(t)
	c := w.dnsCert("one.example.test", "two.example.test")
	o := w.order(c, inventory.ACMEOrderIssue)
	// The lock begins once the first challenge is published: the second meets it. The hook is down just then, so the
	// order's own cleanup of the first record fails.
	w.gate.lockWhen = func() bool { return w.fake.Counters()["hook-present"] >= 1 }
	w.gate.onLock = func() {
		require.NoError(t, w.fake.AddFault(fakeacme.Fault{Endpoint: "hook", Kind: fakeacme.FaultServerInternal, Times: 1}))
	}
	ran, err := w.runner.RunOnce(w.ctx) // the acme.issue job only
	require.NoError(t, err)
	require.True(t, ran)
	require.True(t, w.gate.locked.Load())
	o = w.getOrder(o.ID)
	assert.Equal(t, inventory.ACMELicenseLocked, o.ErrorCode)
	assert.Zero(t, w.keyColumns(o.ID), "the pending key is deleted")
	assert.Equal(t, 1, w.fake.Counters()["hook-present"], "nothing was published after the lock")
	assert.Equal(t, 1, o.Presented, "the record whose removal failed is kept")
	assert.Equal(t, 1, w.dnsLeft())
	assert.Zero(t, w.fake.Counters()["finalize"])

	// The cleanup job was queued with the failure and runs in lock.
	w.drain()
	require.True(t, w.gate.locked.Load())
	o = w.getOrder(o.ID)
	assert.Zero(t, o.Presented)
	assert.Zero(t, w.dnsLeft(), "the record was removed in lock")
	status, _, _ := w.job("acme.cleanup")
	assert.Equal(t, string(jobs.StatusSucceeded), status)
	assert.Equal(t, 1, w.audits("acme.order.cleaned_up"))
}

// A CA rate limit: the order fails at once (no sleeping on the Retry-After), and the next attempt is the CA's wait.
func TestRateLimitedOrderStoresTheWait(t *testing.T) {
	w := newWorld(t)
	c := w.dnsCert("rl.example.test")
	require.NoError(t, w.fake.AddFault(fakeacme.Fault{Endpoint: "new-order", Kind: fakeacme.FaultRateLimited, Times: 1, RetryAfter: 3 * time.Hour}))
	o := w.order(c, inventory.ACMEOrderIssue)
	start := time.Now() //nolint:forbidigo // wall time: the order must not sleep on the CA's Retry-After
	w.drain()
	assert.Less(t, time.Since(start), 30*time.Second) //nolint:forbidigo // see above
	assert.Equal(t, acme.ReasonCARateLimited, w.getOrder(o.ID).ErrorCode)
	got := w.getCert(c.ID)
	assert.Equal(t, inventory.ACMEStateFailing, got.State)
	assert.Equal(t, 1, got.Failures)
	assert.Equal(t, acme.ReasonCARateLimited, got.LastErrorCode)
	assert.Equal(t, w.clock.Now().UTC().Add(3*time.Hour), *got.NextAttemptAt, "the CA's Retry-After, longer than the 1 h backoff")
}

// A failed validation: the order and the certificate carry the code, the records are removed, the key is deleted.
func TestValidationFailure(t *testing.T) {
	w := newWorld(t)
	c := w.dnsCert("bad.example.test")
	require.NoError(t, w.fake.FailValidation(fakeacme.DNS01, true))
	o := w.order(c, inventory.ACMEOrderIssue)
	w.drain()
	o = w.getOrder(o.ID)
	assert.Equal(t, inventory.ACMEOrderFailed, o.State)
	assert.Equal(t, acme.ReasonValidationFailedDNS, o.ErrorCode)
	assert.Zero(t, o.Presented)
	assert.Zero(t, w.dnsLeft())
	assert.Zero(t, w.keyColumns(o.ID))
	got := w.getCert(c.ID)
	assert.Equal(t, acme.ReasonValidationFailedDNS, got.LastErrorCode)
	assert.Equal(t, inventory.ACMEStateFailing, got.State)
	assert.Equal(t, w.clock.Now().UTC().Add(time.Hour), *got.NextAttemptAt)
	assert.Equal(t, 1, w.audits("acme.order.failed"))
	status, code, _ := w.job("acme.issue")
	assert.Equal(t, string(jobs.StatusFailed), status)
	assert.Equal(t, acme.ReasonValidationFailedDNS, code)

	// A success afterwards resets the failure state.
	require.NoError(t, w.fake.FailValidation(fakeacme.DNS01, false))
	o = w.order(c, inventory.ACMEOrderIssue)
	w.drain()
	require.Equal(t, inventory.ACMEOrderSucceeded, w.getOrder(o.ID).State)
	got = w.getCert(c.ID)
	assert.Zero(t, got.Failures)
	assert.Empty(t, got.LastErrorCode)
	assert.Nil(t, got.NextAttemptAt)
}

// Refusals found when the job starts: the CA is not contacted.
func TestJobTimeRefusalsSendNothing(t *testing.T) {
	w := newWorld(t)
	c := w.dnsCert("late.example.test")

	// The provider's list was narrowed after the request.
	o := w.order(c, inventory.ACMEOrderIssue)
	_, err := w.inv.UpdateACMEProvider(w.ctx, w.admin, w.provider.ID, inventory.ACMEProviderPatch{AllowedSuffixes: &[]string{"other.test"}})
	require.NoError(t, err)
	w.fake.ClearRequests()
	w.drain()
	assert.Equal(t, acme.ReasonNameNotAllowed, w.getOrder(o.ID).ErrorCode)
	assert.Empty(t, w.fake.Requests())
	_, err = w.inv.UpdateACMEProvider(w.ctx, w.admin, w.provider.ID, inventory.ACMEProviderPatch{AllowedSuffixes: &[]string{"example.test"}})
	require.NoError(t, err)

	// An unsettled key change of the account signs nothing.
	o = w.order(c, inventory.ACMEOrderIssue)
	_, err = w.db.Owner.Exec(w.ctx, `INSERT INTO acme_accounts (id, provider_id, key_ct, key_nonce, key_wrapped_dek, key_version, state,
pending_since, created_at, updated_at) VALUES ($1, $2, '\x01', decode(repeat('00', 12), 'hex'), '\x02', 1, 'pending_rollover', now(), now(), now())`,
		uuid.New(), w.provider.ID)
	require.NoError(t, err)
	w.drain()
	assert.Equal(t, "acme.rollover_pending", w.getOrder(o.ID).ErrorCode)
	assert.Empty(t, w.fake.Requests())
	_, err = w.db.Owner.Exec(w.ctx, "DELETE FROM acme_accounts WHERE state = 'pending_rollover'")
	require.NoError(t, err)

	// The account was deactivated after the request.
	o = w.order(c, inventory.ACMEOrderIssue)
	_, err = w.inv.DeactivateACMEAccount(w.ctx, w.admin, w.account.ID)
	require.NoError(t, err)
	w.fake.ClearRequests()
	w.drain()
	assert.Equal(t, "acme.account_state", w.getOrder(o.ID).ErrorCode)
	assert.Empty(t, w.fake.Requests())
	assert.Equal(t, 3, w.getCert(c.ID).Failures)
}

// A hook that is down when the leftovers are cleaned up: the job retries on the queue's backoff, records each failure
// on the order and the last one with an audit row (no dead-job e-mail); an hour later the sweep queues it again and
// it succeeds.
func TestCleanupRetriesThenTheSweepTriesAgain(t *testing.T) {
	w := newWorld(t)
	c := w.dnsCert("left.example.test")
	o := w.order(c, inventory.ACMEOrderTest)
	hook := w.hook.ID
	rec := inventory.ACMEPresented{HookID: &hook}
	rec.Challenge.Type, rec.Challenge.Domain = "dns-01", "left.example.test"
	rec.Challenge.DNSName, rec.Challenge.DNSValue = "_acme-challenge.left.example.test", "value-left-behind"
	require.NoError(t, w.inv.AddACMEPresented(w.ctx, o.ID, rec))
	w.fake.DNSSet(rec.Challenge.DNSName, rec.Challenge.DNSValue)
	require.NoError(t, w.inv.FailACMEOrder(w.ctx, o.ID, acme.ReasonHookRefused, 0)) // queues the cleanup
	// The order's own acme.issue job finds the order ended and does nothing.
	require.NoError(t, w.fake.AddFault(fakeacme.Fault{Endpoint: "hook", Kind: fakeacme.FaultServerInternal}))
	for range 6 {
		w.drain()
		w.clock.Advance(40 * time.Minute)
	}
	status, code, attempts := w.job("acme.cleanup")
	assert.Equal(t, string(jobs.StatusFailed), status, "failed, not dead: no dead-job alert (AlertsWhenExhausted)")
	assert.Equal(t, acme.ReasonHookRefused, code)
	assert.Equal(t, 5, attempts)
	g := w.getOrder(o.ID)
	assert.Equal(t, 1, g.Presented)
	assert.Equal(t, acme.ReasonHookRefused, g.CleanupErrorCode)
	assert.Equal(t, 1, w.audits("acme.order.cleanup_failed"), "one row for the final attempt")
	assert.Zero(t, w.count("SELECT count(*) FROM notifications_outbox WHERE template_key = 'job.dead'"), "no dead-job e-mail: the sweep tries again")
	assert.Equal(t, 1, w.dnsLeft())

	w.fake.ClearFaults()
	w.clock.Advance(CleanupRetry)
	require.NoError(t, w.h.sweep(w.ctx))
	w.drain()
	g = w.getOrder(o.ID)
	assert.Zero(t, g.Presented)
	assert.Empty(t, g.CleanupErrorCode)
	assert.Zero(t, w.dnsLeft())
	assert.Equal(t, 1, w.audits("acme.order.cleaned_up"))
}

// A crash after a challenge was published (the process died: nothing more was sent, nothing recorded): the sweep
// cannot finish the order at the CA (its authorizations were never validated), abandons it, deletes its key and the
// cleanup job removes the published record.
func TestCrashAfterPresentIsAbandonedAndCleaned(t *testing.T) {
	w := newWorld(t)
	c := w.dnsCert("crash.example.test")
	w.h.crash = func(stage string) bool { return stage == "presented" }
	o := w.order(c, inventory.ACMEOrderIssue)
	w.drain()
	w.h.crash = nil
	o = w.getOrder(o.ID)
	require.Equal(t, inventory.ACMEOrderRunning, o.State, "a dead process ends nothing")
	assert.Equal(t, 1, o.Presented)
	assert.Equal(t, 4, w.keyColumns(o.ID))
	assert.Equal(t, 1, w.dnsLeft())

	require.NoError(t, w.h.sweep(w.ctx))
	assert.Equal(t, inventory.ACMEOrderRunning, w.getOrder(o.ID).State, "too young to be abandoned")
	w.clock.Advance(StaleAfter + time.Minute)
	require.NoError(t, w.h.sweep(w.ctx))
	o = w.getOrder(o.ID)
	assert.Equal(t, inventory.ACMEOrderFailed, o.State)
	assert.Equal(t, inventory.ACMEOrderAbandoned, o.ErrorCode)
	assert.Zero(t, w.keyColumns(o.ID))
	w.drain()
	assert.Zero(t, w.getOrder(o.ID).Presented)
	assert.Zero(t, w.dnsLeft())
	assert.Equal(t, inventory.ACMEStateFailing, w.getCert(c.ID).State)
}

// A crash after the CA issued the certificate and before it was stored: the sweep resumes the order from the CA with
// the persisted key and URL and stores the certificate (A8).
func TestCrashAfterIssueIsResumedBySweep(t *testing.T) {
	w := newWorld(t)
	c := w.dnsCert("resume.example.test")
	w.h.crash = func(stage string) bool { return stage == "issued" }
	o := w.order(c, inventory.ACMEOrderIssue)
	w.drain()
	w.h.crash = nil
	require.Equal(t, inventory.ACMEOrderRunning, w.getOrder(o.ID).State)
	assert.Equal(t, 1, w.fake.Counters()["issued"])
	assert.Zero(t, w.count("SELECT count(*) FROM certificates"))

	// In lock the sweep never asks the CA: the order waits... until it is abandoned; so resume first with the gate open.
	w.clock.Advance(StaleAfter + time.Minute)
	finalized := w.fake.Counters()["finalize"]
	require.NoError(t, w.h.sweep(w.ctx))
	o = w.getOrder(o.ID)
	require.Equal(t, inventory.ACMEOrderSucceeded, o.State, o.ErrorCode)
	assert.Equal(t, finalized, w.fake.Counters()["finalize"], "the issued certificate is downloaded, not ordered again")
	assert.Equal(t, 1, w.fake.Counters()["issued"])
	assert.Equal(t, "acme", w.issued(o).Source)
	assert.Equal(t, inventory.ACMEStateActive, w.getCert(c.ID).State)
	assert.Zero(t, w.keyColumns(o.ID))
}

// In lock a crashed order that could be resumed waits without a CA call, and is abandoned after ResumeFor.
func TestSweepInLockNeverAsksTheCA(t *testing.T) {
	w := newWorld(t)
	c := w.dnsCert("lockcrash.example.test")
	w.h.crash = func(stage string) bool { return stage == "issued" }
	o := w.order(c, inventory.ACMEOrderIssue)
	w.drain()
	w.h.crash = nil
	w.clock.Advance(StaleAfter + time.Minute)
	w.gate.locked.Store(true)
	w.fake.ClearRequests()
	require.NoError(t, w.h.sweep(w.ctx))
	assert.Empty(t, w.fake.Requests())
	assert.Equal(t, inventory.ACMEOrderRunning, w.getOrder(o.ID).State, "nothing is published: it waits for the lock to end")
	assert.Equal(t, 4, w.keyColumns(o.ID))
	w.clock.Advance(ResumeFor)
	require.NoError(t, w.h.sweep(w.ctx))
	assert.Empty(t, w.fake.Requests())
	assert.Equal(t, inventory.ACMEOrderAbandoned, w.getOrder(o.ID).ErrorCode, "after ResumeFor it is abandoned, still without a CA call")
	assert.Zero(t, w.keyColumns(o.ID))
}

// Nothing secret leaves the vault: no hook secret, account key, order key or EAB key in a job payload or result, an
// audit row or a log line.
func (w *world) noSecrets() {
	w.t.Helper()
	var text strings.Builder
	rows, err := w.db.Owner.Query(w.ctx, "SELECT payload::text, result::text FROM jobs")
	require.NoError(w.t, err)
	for rows.Next() {
		var p, r string
		require.NoError(w.t, rows.Scan(&p, &r))
		text.WriteString(p + r)
	}
	rows.Close()
	rows, err = w.db.Owner.Query(w.ctx, "SELECT details::text FROM audit_log")
	require.NoError(w.t, err)
	for rows.Next() {
		var d string
		require.NoError(w.t, rows.Scan(&d))
		text.WriteString(d)
	}
	rows.Close()
	text.WriteString(w.logs.String())
	all := text.String()
	secret := w.fake.Credentials().HookSecret
	assert.NotContains(w.t, all, secret)
	assert.NotContains(w.t, all, base64.StdEncoding.EncodeToString([]byte(secret)))
	assert.NotContains(w.t, all, "PRIVATE KEY")
	var ct []byte
	require.NoError(w.t, w.db.Owner.QueryRow(w.ctx, "SELECT key_ct FROM acme_accounts LIMIT 1").Scan(&ct))
	assert.NotContains(w.t, all, base64.StdEncoding.EncodeToString(ct)[:16])
}

// The sweep task is ClassAlways and runs its two steps.
func TestSweepTask(t *testing.T) {
	w := newWorld(t)
	task := SweepTask(Deps{Inventory: w.inv, Registry: w.reg, Gate: w.gate, Clock: w.clock}, time.Minute)
	assert.Equal(t, jobs.ACMESweep, task.Type)
	assert.Equal(t, time.Minute, task.Every)
	require.NoError(t, task.Run(w.ctx))
	assert.Panics(t, func() { SweepTask(Deps{}, time.Minute) })
}

// The real HTTP-01 path: the job opens the Nginx server's session (a fake publisher at the session boundary), the
// real http01 solver publishes through it, fetches the token itself and removes it; the fake CA validates over HTTP.
func TestIssueHTTP01WithTheRealSolver(t *testing.T) {
	w := newWorld(t)
	addr := strings.TrimPrefix(w.web.URL, "http://")
	_, portText, err := net.SplitHostPort(addr)
	require.NoError(t, err)
	port, err := strconv.Atoi(portText)
	require.NoError(t, err)
	var checks atomic.Int64
	w.h.newHTTP01 = func(c http01.Config) (solver.Solver, error) {
		s, err := http01.New(c)
		if err != nil {
			return nil, err
		}
		http01.SetTestTarget(s, port, netaddrtest.Resolver(func(string) []netip.Addr {
			checks.Add(1)
			return []netip.Addr{netip.MustParseAddr("127.0.0.1")}
		}))
		return s, nil
	}
	web := w.webTarget("web-real")
	c, err := w.inv.CreateACMECertificate(w.ctx, w.admin, inventory.ACMECertificateInput{ProviderID: w.provider.ID,
		Names: []string{"real.example.test"}, Challenge: inventory.ACMEChallengeHTTP01, HTTPTargetID: &web})
	require.NoError(t, err)
	w.fake.SetHTTPTarget("real.example.test", addr)
	o := w.order(c, inventory.ACMEOrderIssue)
	w.drain()
	o = w.getOrder(o.ID)
	require.Equal(t, inventory.ACMEOrderSucceeded, o.State, o.ErrorCode)
	assert.Positive(t, checks.Load(), "the solver checked the token URL itself")
	assert.Equal(t, 1, w.pub.puts)
	assert.Zero(t, w.pub.live(), "the token file was removed")
	assert.Zero(t, o.Presented)

	// A token that is not served: the solver's own check fails before the CA is asked to validate.
	w.pub.mu.Lock()
	w.pub.hide = true
	w.pub.mu.Unlock()
	validations := w.fake.Counters()["validations-http-01"]
	o = w.order(c, inventory.ACMEOrderIssue)
	w.drain()
	assert.Equal(t, acme.ReasonValidationFailedHTTP, w.getOrder(o.ID).ErrorCode)
	assert.Equal(t, validations, w.fake.Counters()["validations-http-01"])
	assert.Zero(t, w.pub.live())
}

// The gate is asked once more right before finalize: a lock that begins after the authorizations were validated sends
// no CSR (M3).
func TestLockBeforeFinalizeSendsNoCSR(t *testing.T) {
	w := newWorld(t)
	c := w.dnsCert("fin.example.test")
	o := w.order(c, inventory.ACMEOrderIssue)
	w.gate.lockWhen = func() bool { return w.fake.Counters()["validations-dns-01"] >= 1 }
	w.drain()
	o = w.getOrder(o.ID)
	assert.Equal(t, inventory.ACMELicenseLocked, o.ErrorCode)
	assert.Zero(t, w.fake.Counters()["finalize"])
	assert.Zero(t, w.keyColumns(o.ID))
	assert.Zero(t, w.dnsLeft())
}

// An order whose acme.issue job is still running is not stale, however old (M10).
func TestStaleExcludesARunningJob(t *testing.T) {
	w := newWorld(t)
	c := w.dnsCert("busy.example.test")
	o := w.order(c, inventory.ACMEOrderIssue)
	_, err := w.db.Owner.Exec(w.ctx, `UPDATE jobs SET status = 'running', attempts = 1, started_at = $1, locked_by = 'other-worker',
locked_until = $2 WHERE type = 'acme.issue'`, w.clock.Now(), w.clock.Now().Add(time.Hour))
	require.NoError(t, err)
	w.clock.Advance(StaleAfter + time.Minute)
	stale, err := w.inv.StaleACMEOrders(w.ctx, StaleAfter)
	require.NoError(t, err)
	assert.Empty(t, stale)
	require.NoError(t, w.h.sweep(w.ctx))
	assert.Equal(t, inventory.ACMEOrderRunning, w.getOrder(o.ID).State)
	_, err = w.db.Owner.Exec(w.ctx, "UPDATE jobs SET status = 'failed', finished_at = $1 WHERE type = 'acme.issue'", w.clock.Now())
	require.NoError(t, err)
	stale, err = w.inv.StaleACMEOrders(w.ctx, StaleAfter)
	require.NoError(t, err)
	assert.Len(t, stale, 1)
}
