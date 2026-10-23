//go:build integration

package inventory_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/acme"
	"alice/internal/inventory"
	"alice/internal/platform/validate"
	"alice/internal/providers"
	"alice/internal/rbac"
	"alice/internal/testutil/fakeacme"
	"alice/internal/testutil/pki"
)

// R50: a running order keeps the RFC 9773 identifier of the certificate it renews and what became of the replaces
// field; a value outside the closed list, an empty or oversized identifier, and an order that ended are refused.
func TestRecordACMEOrderReplaces(t *testing.T) {
	w := newACMEDeployWorld(t)
	require.NoError(t, w.h.lic.Tick(w.h.ctx))
	c := w.define(w.provider, "www.example.test")
	o, err := w.h.svc.RequestOrder(w.h.ctx, w.operator, c.ID, inventory.ACMEOrderIssue)
	require.NoError(t, err)
	const certID = "aYhba4dGQEHhs3uEe6CuLN4ByNQ.AIdlQyE"
	for _, outcome := range inventory.ACMEReplacesOutcomes() {
		require.NoError(t, w.h.svc.RecordACMEOrderReplaces(w.h.ctx, o.ID, certID, outcome), outcome)
		got, err := w.h.svc.GetACMEOrder(w.h.ctx, o.ID)
		require.NoError(t, err)
		assert.Equal(t, certID, got.Replaces)
		assert.Equal(t, outcome, got.ReplacesOutcome)
	}
	last := inventory.ACMEReplacesOutcomes()[len(inventory.ACMEReplacesOutcomes())-1]
	for name, tc := range map[string]struct{ id, outcome string }{
		"unknown outcome":     {certID, "maybe"},
		"empty outcome":       {certID, ""},
		"empty identifier":    {"", acme.ReplacesSent},
		"identifier too long": {strings.Repeat("a", 513), acme.ReplacesSent},
	} {
		err := w.h.svc.RecordACMEOrderReplaces(w.h.ctx, o.ID, tc.id, tc.outcome)
		require.Error(t, err, name)
		assert.NotErrorIs(t, err, inventory.ErrACMEOrderNotRunning, name)
	}
	got, err := w.h.svc.GetACMEOrder(w.h.ctx, o.ID)
	require.NoError(t, err)
	assert.Equal(t, last, got.ReplacesOutcome, "a refused value changes nothing")

	require.NoError(t, w.h.svc.FailACMEOrder(w.h.ctx, o.ID, acme.ReasonValidationFailedDNS, 0))
	err = w.h.svc.RecordACMEOrderReplaces(w.h.ctx, o.ID, certID, acme.ReplacesSent)
	require.ErrorIs(t, err, inventory.ErrACMEOrderNotRunning)
	err = w.h.svc.RecordACMEOrderReplaces(w.h.ctx, uuid.New(), certID, acme.ReplacesSent)
	require.ErrorIs(t, err, inventory.ErrACMEOrderNotRunning)
}

// R49 (design §5.6): automatic deployment of an ACME certificate stops at a bound website of another service that does
// not trust the certificate's: the binding is marked, the stop is audited and mailed once, nothing is queued there.
func TestACMEAutoDeployAcrossServicesIsUntrusted(t *testing.T) {
	w := newACMEDeployWorld(t)
	require.NoError(t, w.h.lic.Tick(w.h.ctx))
	c, cur := w.issued("www.example.test")
	w.bind(w.get(c.ID), true, w.loc1, w.loc2)
	w.h.moveTo("targets", w.target2, w.h.newService("Payments")) // loc2 is on web-02

	run := w.plan()
	assert.Equal(t, 1, run.Created, "web-01's website, in the certificate's service")
	assert.Equal(t, []uuid.UUID{w.loc1}, locationsOf(w.deps(cur)))
	assert.Equal(t, map[uuid.UUID]string{w.loc2: inventory.ReasonServiceUntrusted}, w.attention(w.get(c.ID)))
	assert.Equal(t, 1, w.h.audits("acme.auto_deploy.untrusted"))
	d := w.h.auditDetails("acme.auto_deploy.untrusted")[0]
	assert.Equal(t, w.loc2.String(), d["location_ids"])
	assert.Equal(t, "1", d["location_count"])
	assert.Equal(t, 1, w.h.emails(inventory.TemplateACMEAutoDeployUntrusted))

	w.h.clock.Advance(time.Minute)
	w.plan()
	assert.Equal(t, 1, w.h.audits("acme.auto_deploy.untrusted"), "the mark is the once-only flag")
	assert.Equal(t, 1, w.h.emails(inventory.TemplateACMEAutoDeployUntrusted))
	assert.Len(t, w.deps(cur), 1)
}

// withClosedPool gives the service a pool of the harness's database that is closed already: every query fails.
func withClosedPool() harnessOption {
	return func(c *inventory.Config) {
		p, err := pgxpool.NewWithConfig(context.Background(), c.Pool.Config())
		if err != nil {
			panic(err)
		}
		p.Close()
		c.Pool = p
	}
}

// The ACME and incident paths report a database that cannot be reached as an error of their own, never as a refusal
// (not found, a state) and never as success; the licence gate (its own pool) is open, so each reaches its database work.
func TestACMEAndIncidentPathsReportADatabaseFailure(t *testing.T) {
	h := newHarness(t, withClosedPool())
	h.installLicense("LIC-DEAD-DB", 5, 365)
	require.NoError(t, h.lic.Tick(h.ctx))
	a := h.user("ada", rbac.Admin, "")
	id, other := uuid.New(), uuid.New()
	ctx, svc := h.ctx, h.svc
	for name, call := range map[string]func() error{
		"AdvanceIncidents": func() error { _, err := svc.AdvanceIncidents(ctx); return err },
		"AdvanceIncident":  func() error { _, err := svc.AdvanceIncident(ctx, id); return err },
		"GetIncident":      func() error { _, err := svc.GetIncident(ctx, id); return err },
		"ListIncidents":    func() error { _, err := svc.ListIncidents(ctx, nil, false, 0); return err },
		"StartIncident":    func() error { _, err := svc.StartIncident(ctx, a, id, inventory.IncidentInput{}); return err },
		"RetryIncident":    func() error { _, err := svc.RetryIncident(ctx, a, id); return err },
		"RevokeIncidentNow": func() error {
			_, err := svc.RevokeIncidentNow(ctx, a, id)
			return err
		},
		"ChooseIncidentReplacement": func() error { _, err := svc.ChooseIncidentReplacement(ctx, a, id, other); return err },
		"CloseIncident":             func() error { _, err := svc.CloseIncident(ctx, a, id); return err },
		"CertificateImpact":         func() error { _, err := svc.CertificateImpact(ctx, id); return err },
		"GetACMEOrder":              func() error { _, err := svc.GetACMEOrder(ctx, id); return err },
		"ListACMEOrders":            func() error { _, err := svc.ListACMEOrders(ctx, id, 0); return err },
		"RecordACMEOrderURL":        func() error { return svc.RecordACMEOrderURL(ctx, id, "https://ca.example.test/order/1") },
		"RecordACMEOrderReplaces":   func() error { return svc.RecordACMEOrderReplaces(ctx, id, "a.b", acme.ReplacesSent) },
		"StaleACMEOrders":           func() error { _, err := svc.StaleACMEOrders(ctx, time.Hour); return err },
		"EnqueueACMECleanups":       func() error { _, err := svc.EnqueueACMECleanups(ctx, time.Hour, 24*time.Hour); return err },
		"ACMECleanupWork":           func() error { _, err := svc.ACMECleanupWork(ctx, id); return err },
		"RevokeACMECertificate": func() error {
			_, err := svc.RevokeACMECertificate(ctx, a, id, inventory.ACMERevokeInput{Reason: "superseded"})
			return err
		},
		"PlanACMEAutoDeploy":   func() error { _, err := svc.PlanACMEAutoDeploy(ctx); return err },
		"PlanACMERenewals":     func() error { _, err := svc.PlanACMERenewals(ctx); return err },
		"ListACMECertificates": func() error { _, err := svc.ListACMECertificates(ctx); return err },
		"GetACMECertificate":   func() error { _, err := svc.GetACMECertificate(ctx, id); return err },
		"ListACMEBindings":     func() error { _, err := svc.ListACMEBindings(ctx, id); return err },
		"ListACMEAccounts":     func() error { _, err := svc.ListACMEAccounts(ctx, id); return err },
		"GetACMEAccount":       func() error { _, err := svc.GetACMEAccount(ctx, id); return err },
		"ListACMEProviders":    func() error { _, err := svc.ListACMEProviders(ctx); return err },
		"GetACMEProvider":      func() error { _, err := svc.GetACMEProvider(ctx, id); return err },
		"ListACMEHooks":        func() error { _, err := svc.ListACMEHooks(ctx); return err },
		"ACMENoticeDelivery":   func() error { _, err := svc.ACMENoticeDelivery(ctx, id); return err },
	} {
		err := call()
		require.Error(t, err, name)
		for _, refusal := range []error{inventory.ErrNotFound, inventory.ErrIncidentState, inventory.ErrACMEOrderNotRunning} {
			assert.NotErrorIs(t, err, refusal, name)
		}
	}
}

// The revocation of an ACME certificate's version is refused before the CA is asked: a certificate never issued, a
// version that does not exist, and a version that has expired (a CA no longer lists it).
func TestACMERevokeRefusalsBeforeTheCA(t *testing.T) {
	w := newACMEDeployWorld(t)
	require.NoError(t, w.h.lic.Tick(w.h.ctx))
	never := w.define(w.provider, "api.example.test")
	_, err := w.h.svc.RevokeACMECertificate(w.h.ctx, w.admin, never.ID, inventory.ACMERevokeInput{Reason: "superseded"})
	require.ErrorIs(t, err, inventory.ErrACMENotIssued)

	c, cur := w.issued("www.example.test")
	missing := uuid.New()
	_, err = w.h.svc.RevokeACMECertificate(w.h.ctx, w.admin, c.ID, inventory.ACMERevokeInput{CertificateID: &missing, Reason: "superseded"})
	require.ErrorIs(t, err, inventory.ErrNotFound)

	w.h.clock.Set(w.certOf(cur).NotAfter.Add(time.Minute))
	require.NoError(t, w.h.lic.Tick(w.h.ctx))
	_, err = w.h.svc.RevokeACMECertificate(w.h.ctx, w.admin, c.ID, inventory.ACMERevokeInput{Reason: "superseded"})
	require.ErrorIs(t, err, inventory.ErrCertificateExpired)
	assert.Zero(t, w.fake.Counters()["revoke-cert"], "the CA was never asked")
	assert.Zero(t, w.h.audits("acme.certificate.revoke_failed"))
}

// An account that does not exist, a sealed key this master key cannot open, and an account whose provider was deleted:
// each is refused before anything is signed or sent to the CA.
func TestACMEAccountRefusals(t *testing.T) {
	w := newACMEDeployWorld(t)
	require.NoError(t, w.h.lic.Tick(w.h.ctx))
	_, err := w.h.svc.GetACMEAccount(w.h.ctx, uuid.New())
	require.ErrorIs(t, err, inventory.ErrNotFound)

	spare, err := w.h.svc.GetACMEProvider(w.h.ctx, w.newProvider("Spare CA", false).ID)
	require.NoError(t, err)
	require.NotNil(t, spare.ActiveAccountID)
	acct := *spare.ActiveAccountID
	before := w.fake.Counters()
	_, err = w.h.db.Owner.Exec(w.h.ctx, "UPDATE acme_accounts SET key_ct = overlay(key_ct placing '\\x00'::bytea from 1 for 1) WHERE id = $1", acct)
	require.NoError(t, err)
	_, _, err = w.h.svc.ACMEAccountSigner(w.h.ctx, acct)
	require.ErrorIs(t, err, inventory.ErrACMESecretUnreadable)

	_, err = w.h.db.Owner.Exec(w.h.ctx, "UPDATE acme_providers SET deleted_at = now() WHERE id = $1", spare.ID)
	require.NoError(t, err)
	_, err = w.h.svc.RolloverACMEAccount(w.h.ctx, w.admin, acct)
	require.ErrorIs(t, err, inventory.ErrACMEAccountState)
	_, err = w.h.svc.DeactivateACMEAccount(w.h.ctx, w.admin, acct)
	require.ErrorIs(t, err, inventory.ErrACMEAccountState)
	_, err = w.h.svc.RecoverACMERollover(w.h.ctx, w.admin, acct)
	require.ErrorIs(t, err, inventory.ErrACMEAccountState)
	after := w.fake.Counters()
	assert.Equal(t, before["key-change"], after["key-change"], "nothing reached the CA")
	assert.Equal(t, before["account"], after["account"])
}

// registerDuring registers an account of provider p while the CA's new-account answer is held back, and runs change on
// the database once the CA has the request (the account then exists at the CA).
func (w *acmeDeployWorld) registerDuring(p inventory.ACMEProvider, change func()) error {
	w.h.t.Helper()
	require.NoError(w.h.t, w.fake.AddFault(fakeacme.Fault{Endpoint: "new-account", Kind: fakeacme.FaultSlow, Times: 1, Delay: 2 * time.Second}))
	asked := w.fake.Counters()["new-account"]
	done := make(chan error, 1)
	go func() {
		_, err := w.h.svc.RegisterACMEAccount(w.h.ctx, w.admin, p.ID, "ops@example.test", false)
		done <- err
	}()
	require.Eventually(w.h.t, func() bool { return w.fake.Counters()["new-account"] > asked }, 10*time.Second, 10*time.Millisecond)
	change()
	select {
	case err := <-done:
		return err
	case <-time.After(30 * time.Second):
		require.FailNow(w.h.t, "the registration did not return")
		return nil
	}
}

// An account Alice made at the CA but cannot keep (its provider was deleted, pointed at another CA, or got an account
// from a concurrent registration meanwhile) is refused, and Alice deactivates the orphan at the CA, best effort.
func TestACMERegistrationThatCannotBeKeptDeactivatesTheOrphan(t *testing.T) {
	for name, tc := range map[string]struct {
		change func(w *acmeDeployWorld, p inventory.ACMEProvider)
		want   error
	}{
		"provider deleted": {func(w *acmeDeployWorld, p inventory.ACMEProvider) {
			_, err := w.h.db.Owner.Exec(w.h.ctx, "UPDATE acme_providers SET deleted_at = now() WHERE id = $1", p.ID)
			require.NoError(w.h.t, err)
		}, inventory.ErrNotFound},
		"directory changed": {func(w *acmeDeployWorld, p inventory.ACMEProvider) {
			_, err := w.h.db.Owner.Exec(w.h.ctx, "UPDATE acme_providers SET directory_url = directory_url || '?moved' WHERE id = $1", p.ID)
			require.NoError(w.h.t, err)
		}, inventory.ErrACMEDirectoryChange},
		"another registration won": {func(w *acmeDeployWorld, p inventory.ACMEProvider) {
			_, err := w.h.db.Owner.Exec(w.h.ctx, `INSERT INTO acme_accounts (id, provider_id, contact_email, account_url, key_ct, key_nonce,
    key_wrapped_dek, key_version, state, created_at, updated_at)
SELECT $2, $3, contact_email, account_url, key_ct, key_nonce, key_wrapped_dek, key_version, 'active', now(), now()
FROM acme_accounts WHERE provider_id = $1 AND state = 'active'`, w.provider.ID, uuid.Must(uuid.NewV7()), p.ID)
			require.NoError(w.h.t, err)
		}, inventory.ErrACMEAccountExists},
	} {
		t.Run(name, func(t *testing.T) {
			w := newACMEDeployWorld(t)
			require.NoError(t, w.h.lic.Tick(w.h.ctx))
			p, err := w.h.svc.CreateACMEProvider(w.h.ctx, w.admin, inventory.ACMEProviderInput{Name: "Late CA", DirectoryURL: w.fake.DirectoryURL(),
				CABundlePEM: string(w.fake.CAPEM()), AllowedSuffixes: []string{"example.test"}})
			require.NoError(t, err)
			deactivations := w.fake.Counters()["account"]
			err = w.registerDuring(p, func() { tc.change(w, p) })
			require.ErrorIs(t, err, tc.want)
			assert.Greater(t, w.fake.Counters()["account"], deactivations, "the orphan is deactivated at the CA")
			assert.Zero(t, w.h.count("SELECT count(*) FROM acme_accounts WHERE provider_id = $1 AND contact_email = 'ops@example.test' AND created_by IS NOT NULL", p.ID),
				"nothing of this registration was stored")
			assert.Zero(t, w.h.count("SELECT count(*) FROM audit_log WHERE action = 'acme.account.registered' AND details->>'provider_id' = $1", p.ID.String()))
		})
	}
}

// R50: an order of a certificate whose names no longer include any of its current certificate's names renews no
// predecessor (RFC 9773 section 5); the cleanup of a running order is refused.
func TestACMEOrderWorkWithoutAPredecessorAndCleanupOfARunningOrder(t *testing.T) {
	w := newACMEDeployWorld(t)
	require.NoError(t, w.h.lic.Tick(w.h.ctx))
	c, _ := w.issued("www.example.test")
	names := []string{"shop.example.test"}
	_, err := w.h.svc.UpdateACMECertificate(w.h.ctx, w.admin, c.ID, inventory.ACMECertificatePatch{Names: &names})
	require.NoError(t, err)
	o, err := w.h.svc.RequestOrder(w.h.ctx, w.operator, c.ID, inventory.ACMEOrderIssue)
	require.NoError(t, err)
	work, err := w.h.svc.ACMEOrderWork(w.h.ctx, o.ID)
	require.NoError(t, err)
	assert.Equal(t, names, work.Names)
	assert.Nil(t, work.Replaces, "no shared name: no predecessor")
	require.ErrorIs(t, w.h.svc.RecordACMECleanup(w.h.ctx, o.ID, "", true), inventory.ErrACMEOrderNotRunning)
}

// The deployment records refuse what does not hold: an unknown deployment, rollback targets that are not hashes; an outcome recorded for a deployment that ended already changes nothing.
func TestDeploymentRecordRefusals(t *testing.T) {
	f := newDeployFixture(t)
	f.h.installLicense("LIC-RECORDS", 5, 365)
	require.NoError(t, f.h.lic.Tick(f.h.ctx))
	ctx := f.h.ctx
	require.ErrorIs(t, f.h.svc.CheckRecoveryPending(ctx, uuid.New()), inventory.ErrNotFound)

	other := f.request(f.admin, f.cert.ID, f.loc1)
	_, err := f.h.svc.BeginDeployment(ctx, other)
	require.NoError(t, err)
	good := inventory.SendValues{OperationID: other, ExpectCertSHA256: sha(f.old.FullchainPEM), NewChainLength: 2}
	for name, v := range map[string]inventory.SendValues{
		"leaf":       func() inventory.SendValues { x := good; x.RollbackLeafSHA256 = "zz"; return x }(),
		"public key": func() inventory.SendValues { x := good; x.RollbackSPKISHA256 = "not-a-hash"; return x }(),
	} {
		require.Error(t, f.h.svc.StartDeployment(ctx, other, v), name)
	}
	assert.Equal(t, inventory.DeployStatePrecheck, f.get(other).State, "nothing was recorded")

	require.NoError(t, f.h.svc.FinishDeployment(ctx, other, inventory.DeploymentFinish{Status: inventory.DeployStatusFailed, ErrorCode: "deployment.reload_failed"}))
	require.NoError(t, f.h.svc.RecordOutcome(ctx, other, inventory.OutcomeRecord{Finish: inventory.DeploymentFinish{Status: inventory.DeployStatusFailed,
		ErrorCode: "deployment.interrupted"}}, time.Time{}))
	d := f.get(other)
	assert.Equal(t, inventory.DeployStateDone, d.State)
	assert.Equal(t, "deployment.reload_failed", d.ErrorCode, "the finished record is kept")
}

// An ACME binding needs the server's service to accept the certificate's keys (R49); a bound website whose newest
// observation found another certificate than the current one is drifted (R52).
func TestACMEBindingAcrossServicesAndADriftedBinding(t *testing.T) {
	w := newACMEDeployWorld(t)
	require.NoError(t, w.h.lic.Tick(w.h.ctx))
	c, cur := w.issued("www.example.test")
	w.h.moveTo("targets", w.target2, w.h.newService("Payments"))
	_, err := w.h.svc.AddACMEBinding(w.h.ctx, w.operator, c.ID, w.loc2, false)
	var lr *inventory.LocationRefusalError
	require.ErrorAs(t, err, &lr)
	assert.Equal(t, w.loc2, lr.LocationID)
	require.ErrorIs(t, err, inventory.ErrServiceUntrusted)

	w.serves(w.loc1, cur)
	w.bind(w.get(c.ID), false, w.loc1)
	list, err := w.h.svc.ListACMEBindings(w.h.ctx, c.ID)
	require.NoError(t, err)
	require.Len(t, list, 1)
	assert.NotEqual(t, inventory.ACMEBindingDrifted, list[0].State)
	_, err = w.h.db.Owner.Exec(w.h.ctx, `INSERT INTO location_observations (location_id, tls_attempted_at, tls_observed_at, tls_fingerprint, tls_probe,
    tls_level, updated_at) VALUES ($1, $2, $2, $3, 'alice', 2, $2)
ON CONFLICT (location_id) DO UPDATE SET tls_attempted_at = $2, tls_observed_at = $2, tls_fingerprint = $3, tls_probe = 'alice', tls_level = 2,
    updated_at = $2`, w.loc1, w.h.clock.Now(), pki.Fingerprint(w.old.Cert))
	require.NoError(t, err)
	list, err = w.h.svc.ListACMEBindings(w.h.ctx, c.ID)
	require.NoError(t, err)
	require.Len(t, list, 1)
	assert.Equal(t, inventory.ACMEBindingDrifted, list[0].State)
	require.NotNil(t, list[0].Observation)
	assert.Equal(t, inventory.HealthDrifted, list[0].Observation.Health)
}

// The key of an order is stored once and only on a running order: an order that ended, or got its key from another
// worker, while this one generated its key is refused and nothing of the new key is kept. Aborting an order that does
// not exist or succeeded is refused as well.
func TestACMEOrderKeyAndEndRefusals(t *testing.T) {
	w := newACMEDeployWorld(t)
	require.NoError(t, w.h.lic.Tick(w.h.ctx))
	ctx, svc := w.h.ctx, w.h.svc
	c := w.define(w.provider, "www.example.test")

	// Another worker stored the key meanwhile.
	o, err := svc.RequestOrder(ctx, w.operator, c.ID, inventory.ACMEOrderIssue)
	require.NoError(t, err)
	inner := false
	inventory.SetKeygenSeam(svc, func() {
		if inner {
			return
		}
		inner = true
		_, err := svc.NewACMEOrderKey(ctx, o.ID)
		require.NoError(t, err)
	})
	_, err = svc.NewACMEOrderKey(ctx, o.ID)
	require.ErrorIs(t, err, inventory.ErrACMEPendingKey)
	_, err = svc.LoadPendingKey(ctx, o.ID)
	require.NoError(t, err, "the first key is the order's")

	// The order failed meanwhile.
	w.failRunningOrder(o.ID, acme.ReasonValidationFailedDNS)
	o2, err := svc.RequestOrder(ctx, w.operator, c.ID, inventory.ACMEOrderIssue)
	require.NoError(t, err)
	inventory.SetKeygenSeam(svc, func() {
		require.NoError(t, svc.AbortACMEOrder(ctx, o2.ID, "system.interrupted"))
	})
	_, err = svc.NewACMEOrderKey(ctx, o2.ID)
	require.ErrorIs(t, err, inventory.ErrACMEOrderNotRunning)
	inventory.SetKeygenSeam(svc, nil)
	assert.Zero(t, w.h.count("SELECT count(*) FROM acme_orders WHERE id = $1 AND pending_key_ct IS NOT NULL", o2.ID))

	_, err = svc.NewACMEOrderKey(ctx, o2.ID)
	require.ErrorIs(t, err, inventory.ErrACMEOrderNotRunning)
	require.ErrorIs(t, svc.AbortACMEOrder(ctx, uuid.New(), "system.interrupted"), inventory.ErrNotFound)

	// A succeeded order cannot be aborted.
	_, cur := w.issued("api.example.test")
	var done uuid.UUID
	require.NoError(t, w.h.db.Owner.QueryRow(ctx, "SELECT id FROM acme_orders WHERE certificate_id = $1", cur).Scan(&done))
	require.ErrorIs(t, svc.AbortACMEOrder(ctx, done, "system.interrupted"), inventory.ErrACMEOrderNotRunning)
	_, err = svc.LoadPendingKey(ctx, done)
	require.ErrorIs(t, err, inventory.ErrACMEOrderNotRunning)
}

// The ACME definitions refuse a field their method does not take, and their patches keep only what changes; the
// Key Vault requests refuse the ids they need before anything is read.
func TestACMEAndKVInputRefusals(t *testing.T) {
	w := newACMEDeployWorld(t)
	require.NoError(t, w.h.lic.Tick(w.h.ctx))
	ctx, svc := w.h.ctx, w.h.svc
	hook, off := w.hook.ID, false
	c, err := svc.CreateACMECertificate(ctx, w.admin, inventory.ACMECertificateInput{ProviderID: w.provider.ID, Names: []string{"www.example.test"},
		Challenge: inventory.ACMEChallengeDNS01, HookID: &hook, AutoRenew: &off})
	require.NoError(t, err)
	assert.False(t, c.AutoRenew)
	var verr validate.Errors
	_, err = svc.UpdateACMECertificate(ctx, w.admin, c.ID, inventory.ACMECertificatePatch{HTTPTargetID: &w.target1})
	require.ErrorAs(t, err, &verr)
	assert.Equal(t, "http_target_id", verr[0].Field, "a dns-01 certificate has no server")

	bad := "ftp://ca.example.test/directory"
	_, err = svc.UpdateACMEProvider(ctx, w.admin, w.provider.ID, inventory.ACMEProviderPatch{DirectoryURL: &bad})
	require.ErrorAs(t, err, &verr)
	assert.Equal(t, "directory_url", verr[0].Field)

	bundle := string(w.fake.CAPEM()) + string(w.fake.IssuerRootPEM())
	got, err := svc.UpdateACMEHook(ctx, w.admin, w.hook.ID, inventory.ACMEHookPatch{CABundlePEM: &bundle})
	require.NoError(t, err)
	assert.Contains(t, got.CABundlePEM, strings.TrimSpace(string(w.fake.IssuerRootPEM())))
	assert.Equal(t, "ca_bundle", w.h.auditDetails("acme.hook.updated")[0]["fields"])

	_, _, err = svc.OpenACMEEAB(ctx, uuid.New())
	require.ErrorIs(t, err, inventory.ErrNotFound)

	_, err = svc.RequestKVDeployment(ctx, w.admin, inventory.KVDeployInput{LocationIDs: []uuid.UUID{w.loc1}})
	require.ErrorAs(t, err, &verr)
	assert.Equal(t, "binding_id", verr[0].Field)
	_, err = svc.CreateBinding(ctx, w.admin, inventory.BindingInput{LocationIDs: []uuid.UUID{w.loc1}})
	require.ErrorAs(t, err, &verr)
	assert.Equal(t, "kv_certificate_id", verr[0].Field)
	_, err = svc.ReleaseVersion(ctx, w.admin, inventory.ReleaseInput{VaultID: uuid.New(), KVCertificateID: uuid.New()})
	require.ErrorAs(t, err, &verr)
	assert.Equal(t, "version_id", verr[0].Field)
}

// A Key Vault binding gains a website only where the server's service accepts the vault's keys and the website exists;
// a vault version whose certificate was revoked or marked compromised is never deployed (00021).
func TestKVBindingAndDeploymentRefusals(t *testing.T) {
	b := newBindFixture(t)
	h := b.h
	h.installLicense("LIC-KV-REFUSALS", 5, 365)
	require.NoError(t, h.lic.Tick(h.ctx))
	bind := b.create(b.admin, b.web, b.loc1)

	h.moveTo("targets", b.target2, h.newService("Payments")) // loc2 is on web-02
	_, err := h.svc.UpdateBindingLocations(h.ctx, b.admin, bind.ID, bind.Version, []uuid.UUID{b.loc1, b.loc2})
	require.ErrorIs(t, err, inventory.ErrServiceUntrusted)
	missing := uuid.New()
	_, err = h.svc.UpdateBindingLocations(h.ctx, b.admin, bind.ID, bind.Version, []uuid.UUID{b.loc1, missing})
	require.ErrorIs(t, err, inventory.ErrNotFound)
	var lr *inventory.LocationRefusalError
	require.ErrorAs(t, err, &lr)
	assert.Equal(t, missing, lr.LocationID)
	assert.Equal(t, 2, h.count("SELECT count(*) FROM audit_log WHERE action = 'binding.denied'"))

	version := b.versionID(b.web, ver(1))
	for _, tc := range []struct {
		set  string
		want error
	}{
		{"compromised_at = now()", inventory.ErrCertificateCompromised},
		{"revoked_at = now(), revocation_reason = 'keyCompromise'", inventory.ErrCertificateRevoked}, // revoked is said first
	} {
		_, err := h.db.Owner.Exec(h.ctx, "UPDATE certificates SET "+tc.set+" WHERE id = (SELECT certificate_id FROM kv_certificate_versions WHERE id = $1)",
			version)
		require.NoError(t, err)
		_, err = h.svc.RequestKVDeployment(h.ctx, b.admin, inventory.KVDeployInput{BindingID: bind.ID, VersionID: version, LocationIDs: []uuid.UUID{b.loc1},
			StrictSession: true})
		require.ErrorIs(t, err, tc.want, tc.set)
	}
	assert.Zero(t, h.count("SELECT count(*) FROM deployments WHERE binding_id = $1", bind.ID))
}

// A deployment verifies on the location's own port; a failed verification keeps the port it failed on and the trust
// found there (R51), and the record reads them back.
func TestDeploymentRecordKeepsTheVerificationPortAndTrust(t *testing.T) {
	f := newDeployFixture(t)
	f.h.installLicense("LIC-TRUST-PORT", 5, 365)
	require.NoError(t, f.h.lic.Tick(f.h.ctx))
	loc := byPath(t, f.h, f.target1, false)["/etc/nginx/ssl/www.crt"]
	port := 8443
	_, err := f.h.svc.UpdateLocation(f.h.ctx, f.admin, loc.ID, loc.Version, inventory.LocationPatch{VerifyPort: &port})
	require.NoError(t, err)
	id := f.request(f.admin, f.cert.ID, f.loc1)
	m, err := f.h.svc.DeploymentMaterial(f.h.ctx, id, false)
	require.NoError(t, err)
	assert.Equal(t, 8443, m.Verify.Port, "the location's own verification port")
	require.NoError(t, f.h.svc.FinishDeployment(f.h.ctx, id, inventory.DeploymentFinish{Status: inventory.DeployStatusFailed,
		ErrorCode: "deployment.verify_untrusted", VerifyFailedReason: "deployment.verify_untrusted", VerifyFailedPort: &port,
		Trust: providers.Trust{Status: providers.TrustUntrusted, Error: providers.TrustErrIncompleteChain, Port: 8443, Store: providers.TrustStoreSystem,
			Enforced: true}}))
	d := f.get(id)
	require.NotNil(t, d.VerifyFailedPort)
	assert.Equal(t, 8443, *d.VerifyFailedPort)
	assert.Equal(t, providers.Trust{Status: providers.TrustUntrusted, Error: providers.TrustErrIncompleteChain, Port: 8443,
		Store: providers.TrustStoreSystem, Enforced: true}, d.Trust)
}

// A Key Vault certificate's impact lists its vault version and the website that follows its binding; an incident of it
// skips that website (the vault is its source) and the impact names the open incident.
func TestImpactAndIncidentOfAKeyVaultCertificate(t *testing.T) {
	b := newBindFixture(t)
	h := b.h
	h.installLicense("LIC-KV-IMPACT", 5, 365)
	require.NoError(t, h.lic.Tick(h.ctx))
	b.create(b.admin, b.web, b.loc1)
	var cert uuid.UUID
	require.NoError(t, h.db.Owner.QueryRow(h.ctx, "SELECT certificate_id FROM kv_certificate_versions WHERE id = $1", b.versionID(b.web, ver(1))).Scan(&cert))
	_, err := h.db.Owner.Exec(h.ctx, "UPDATE certificate_locations SET certificate_id = $2 WHERE id = $1", b.loc1, cert)
	require.NoError(t, err)

	imp, err := h.svc.CertificateImpact(h.ctx, cert)
	require.NoError(t, err)
	require.Len(t, imp.Vaults, 1)
	assert.Equal(t, b.vault, imp.Vaults[0].VaultID)
	assert.Equal(t, b.web, imp.Vaults[0].KVCertificateID)
	assert.True(t, imp.Vaults[0].Current)
	assert.Equal(t, inventory.ImpactMatchCertificate, imp.Vaults[0].Match)
	require.Len(t, imp.Locations, 1)
	assert.True(t, imp.Locations[0].KVBound)
	assert.Nil(t, imp.OpenIncidentID)

	i, err := h.svc.StartIncident(h.ctx, b.admin, cert, inventory.IncidentInput{})
	require.NoError(t, err)
	assert.Equal(t, inventory.IncidentRevocationNotPossible, i.Revocation)
	assert.Equal(t, map[uuid.UUID]string{b.loc1: "skipped:" + inventory.IncidentCodeFollowsKeyVault}, locationStatus(i))
	imp, err = h.svc.CertificateImpact(h.ctx, cert)
	require.NoError(t, err)
	require.NotNil(t, imp.OpenIncidentID)
	assert.Equal(t, i.ID, *imp.OpenIncidentID)
}

// R62 Ruling 17: a listed ACME binding carries the kind of its location: server_file for a certificate file,
// win_sslbinding for an IIS binding.
func TestListACMEBindingsCarriesTheLocationKind(t *testing.T) {
	w := newACMEDeployWorld(t)
	require.NoError(t, w.h.lic.Tick(w.h.ctx))
	c, cur := w.issued("www.example.test")
	w.serves(w.loc1, cur)
	w.bind(w.get(c.ID), false, w.loc1)
	list, err := w.h.svc.ListACMEBindings(w.h.ctx, c.ID)
	require.NoError(t, err)
	require.Len(t, list, 1)
	assert.Equal(t, providers.LocationServerFile, list[0].LocationKind)

	_, err = w.h.db.Owner.Exec(w.h.ctx, `UPDATE certificate_locations SET kind = 'win_sslbinding', locator = '{"type":"ipport","ip":"0.0.0.0","port":443}'::jsonb,
    key_path = '', resolved_cert_path = '', key_mode = '', key_owner = '', key_group = '', symlinked = false WHERE id = $1`, w.loc1)
	require.NoError(t, err)
	list, err = w.h.svc.ListACMEBindings(w.h.ctx, c.ID)
	require.NoError(t, err)
	require.Len(t, list, 1)
	assert.Equal(t, providers.LocationWinSSLBinding, list[0].LocationKind)
}
