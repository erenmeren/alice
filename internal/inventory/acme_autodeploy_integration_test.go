//go:build integration

package inventory_test

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/acme/keygen"
	"alice/internal/acme/solver"
	"alice/internal/inventory"
	"alice/internal/license"
	"alice/internal/notify"
	"alice/internal/providers"
	"alice/internal/secrets"
	"alice/internal/testutil/fakeacme"
	"alice/internal/testutil/pki"
)

// acmeDeployWorld is the deployment fixture (two Nginx servers: web-01 www.crt, b.crt; web-02 www.crt, api.crt, spare.crt
// (an RSA location here), var.crt (unsupported); every location serves the old certificate) plus a running fake CA, a
// provider whose bundle holds the fake's TLS CA and its issuing root (the issued chains are complete, A3), its account,
// a DNS hook, and a ten-year licence (the tests move the clock).
type acmeDeployWorld struct {
	*deployFixture
	fake     *fakeacme.Server
	provider inventory.ACMEProvider
	hook     inventory.ACMEHook
}

func newACMEDeployWorld(t *testing.T) *acmeDeployWorld {
	t.Helper()
	return newACMEDeployWorldLicensed(t, true)
}

// newACMEDeployWorldLicensed is newACMEDeployWorld, on the 30-day evaluation when licensed is false.
func newACMEDeployWorldLicensed(t *testing.T, licensed bool) *acmeDeployWorld {
	t.Helper()
	f := newDeployFixture(t)
	h := f.h
	fake, err := fakeacme.New(fakeacme.Options{Now: h.clock.Now, NoTerms: true})
	require.NoError(t, err)
	require.NoError(t, fake.Start())
	t.Cleanup(fake.Close)
	w := &acmeDeployWorld{deployFixture: f, fake: fake}
	_, err = h.db.Owner.Exec(h.ctx, "UPDATE certificate_locations SET key_type = 'rsa' WHERE id = $1", f.loc4)
	require.NoError(t, err)
	if licensed {
		h.installLicense("LIC-ACME-DEPLOY", 5, 3650)
	}
	w.provider = w.newProvider("Deploy CA", true)
	none := 0
	w.hook, err = h.svc.CreateACMEHook(h.ctx, f.admin, inventory.ACMEHookInput{Name: "dns", URL: fake.Credentials().HookURL,
		CABundlePEM: string(fake.CAPEM()), Secret: secrets.NewPlaintext([]byte(fake.Credentials().HookSecret)),
		AllowedSuffixes: []string{"example.test"}, PropagationWaitSeconds: &none, PollTimeoutSeconds: 5})
	require.NoError(t, err)
	return w
}

// newProvider adds a provider of the fake (with its issuing root in the bundle when root) and registers its account.
func (w *acmeDeployWorld) newProvider(name string, root bool) inventory.ACMEProvider {
	w.h.t.Helper()
	bundle := string(w.fake.CAPEM())
	if root {
		bundle += string(w.fake.IssuerRootPEM())
	}
	p, err := w.h.svc.CreateACMEProvider(w.h.ctx, w.admin, inventory.ACMEProviderInput{Name: name, DirectoryURL: w.fake.DirectoryURL(),
		CABundlePEM: bundle, AllowedSuffixes: []string{"example.test"}})
	require.NoError(w.h.t, err)
	_, err = w.h.svc.RegisterACMEAccount(w.h.ctx, w.admin, p.ID, "ops@example.test", false)
	require.NoError(w.h.t, err)
	return p
}

// define creates a DNS-01 ACME certificate of the provider with automatic deployment on.
func (w *acmeDeployWorld) define(p inventory.ACMEProvider, names ...string) inventory.ACMECertificate {
	w.h.t.Helper()
	hook := w.hook.ID
	c, err := w.h.svc.CreateACMECertificate(w.h.ctx, w.admin, inventory.ACMECertificateInput{ProviderID: p.ID, Names: names,
		Challenge: inventory.ACMEChallengeDNS01, HookID: &hook, AutoDeploy: true})
	require.NoError(w.h.t, err)
	return c
}

// issue runs an order of the certificate through the fake CA as the acme.issue job does and returns the new current
// certificate.
func (w *acmeDeployWorld) issue(c inventory.ACMECertificate) uuid.UUID {
	w.h.t.Helper()
	ctx := w.h.ctx
	o, err := w.h.svc.RequestOrder(ctx, w.operator, c.ID, inventory.ACMEOrderIssue)
	require.NoError(w.h.t, err)
	work, err := w.h.svc.ACMEOrderWork(ctx, o.ID)
	require.NoError(w.h.t, err)
	client, err := w.h.svc.ACMEOrderClient(ctx, o.ID)
	require.NoError(w.h.t, err)
	signer, err := w.h.svc.NewACMEOrderKey(ctx, o.ID)
	require.NoError(w.h.t, err)
	csr, err := keygen.NewCSR(signer, work.Names)
	require.NoError(w.h.t, err)
	sol := solver.NewMemory(solver.DNS01)
	sol.AfterPresent = func(_ context.Context, ch solver.Challenge) error { w.fake.DNSSet(ch.DNSName, ch.DNSValue); return nil }
	sol.AfterCleanUp = func(_ context.Context, ch solver.Challenge) error {
		w.fake.DNSClear(ch.DNSName, ch.DNSValue)
		return nil
	}
	chain, err := client.Order(ctx, work.Names, csr, sol)
	require.NoError(w.h.t, err)
	got, err := w.h.svc.FinishACMEOrder(ctx, o.ID, chain)
	require.NoError(w.h.t, err)
	// The acme.issue job's work was done here: it ends as the handler would end it.
	_, err = w.h.db.Owner.Exec(ctx, "UPDATE jobs SET status = 'succeeded', finished_at = $1 WHERE type = 'acme.issue' AND status = 'queued'",
		w.h.clock.Now())
	require.NoError(w.h.t, err)
	return got.CertificateID
}

// issued defines and issues a certificate of the main provider.
func (w *acmeDeployWorld) issued(names ...string) (inventory.ACMECertificate, uuid.UUID) {
	w.h.t.Helper()
	c := w.define(w.provider, names...)
	cur := w.issue(c)
	return w.get(c.ID), cur
}

func (w *acmeDeployWorld) get(id uuid.UUID) inventory.ACMECertificate {
	w.h.t.Helper()
	c, err := w.h.svc.GetACMECertificate(w.h.ctx, id)
	require.NoError(w.h.t, err)
	return c
}

// bind binds the locations (an Administrator when automatic deployment is on: unattended deployment is theirs to
// switch on, an Operator otherwise).
func (w *acmeDeployWorld) bind(c inventory.ACMECertificate, auto bool, locs ...uuid.UUID) {
	w.h.t.Helper()
	a := w.operator
	if auto {
		a = w.admin
	}
	for _, l := range locs {
		_, err := w.h.svc.AddACMEBinding(w.h.ctx, a, c.ID, l, auto)
		require.NoError(w.h.t, err)
	}
}

func (w *acmeDeployWorld) plan() inventory.ACMEDeployRun {
	w.h.t.Helper()
	require.NoError(w.h.t, w.h.lic.Tick(w.h.ctx))
	run, err := w.h.svc.PlanACMEAutoDeploy(w.h.ctx)
	require.NoError(w.h.t, err)
	return run
}

type acmeDep struct {
	ID, Location, Certificate uuid.UUID
	Trigger, State, Status    string
}

// deps are the deployments of the certificate, oldest first.
func (w *acmeDeployWorld) deps(cert uuid.UUID) []acmeDep {
	w.h.t.Helper()
	rows, err := w.h.db.Owner.Query(w.h.ctx, `SELECT id, location_id, certificate_id, trigger, state, status FROM deployments
WHERE certificate_id = $1 ORDER BY created_at, id`, cert)
	require.NoError(w.h.t, err)
	defer rows.Close()
	var out []acmeDep
	for rows.Next() {
		var d acmeDep
		require.NoError(w.h.t, rows.Scan(&d.ID, &d.Location, &d.Certificate, &d.Trigger, &d.State, &d.Status))
		out = append(out, d)
	}
	require.NoError(w.h.t, rows.Err())
	return out
}

func locationsOf(ds []acmeDep) []uuid.UUID {
	out := []uuid.UUID{}
	for _, d := range ds {
		out = append(out, d.Location)
	}
	return out
}

// finish ends a deployment: succeeded through the owner (the engine's path to a success is not what these tests are
// about), otherwise through FinishDeployment.
func (w *acmeDeployWorld) finish(id uuid.UUID, status, code string) {
	w.h.t.Helper()
	if status == inventory.DeployStatusSucceeded {
		_, err := w.h.db.Owner.Exec(w.h.ctx, `UPDATE deployments SET state = 'done', status = 'succeeded', result = 'committed', phase = 'committed',
verified = 'remote', finished_at = $2 WHERE id = $1`, id, w.h.clock.Now())
		require.NoError(w.h.t, err)
		return
	}
	require.NoError(w.h.t, w.h.svc.FinishDeployment(w.h.ctx, id, inventory.DeploymentFinish{Status: status, ErrorCode: code}))
}

func (w *acmeDeployWorld) finishAll(cert uuid.UUID, status, code string) {
	w.h.t.Helper()
	for _, d := range w.deps(cert) {
		if d.State != inventory.DeployStateDone {
			w.finish(d.ID, status, code)
		}
	}
}

func (w *acmeDeployWorld) attention(c inventory.ACMECertificate) map[uuid.UUID]string {
	w.h.t.Helper()
	list, err := w.h.svc.ListACMEBindings(w.h.ctx, c.ID)
	require.NoError(w.h.t, err)
	out := map[uuid.UUID]string{}
	for _, b := range list {
		if b.State == inventory.ACMEBindingAttention {
			out[b.LocationID] = b.AttentionCode
		}
	}
	return out
}

// moreLocations adds n locations serving the old certificate to web-01 (found by a scan) and returns their ids.
func (w *acmeDeployWorld) moreLocations(n int) []uuid.UUID {
	w.h.t.Helper()
	certs := []providers.DiscoveredCertificate{
		dc(cl("/etc/nginx/ssl/www.crt", "/etc/nginx/ssl/www.key", "www.example.test"), w.old),
		dc(cl("/etc/nginx/ssl/b.crt", "/etc/nginx/ssl/b.key", "www.example.test"), w.old)}
	for i := range n {
		certs = append(certs, dc(cl(fmt.Sprintf("/etc/nginx/ssl/x%d.crt", i), fmt.Sprintf("/etc/nginx/ssl/x%d.key", i), "www.example.test"), w.old))
	}
	_, err := w.h.svc.Reconcile(w.h.ctx, w.target1, providers.DiscoveryResult{WebServer: nginxOK, Certificates: certs})
	require.NoError(w.h.t, err)
	found := byPath(w.h.t, w.h, w.target1, false)
	var ids []uuid.UUID
	for i := range n {
		ids = append(ids, found[fmt.Sprintf("/etc/nginx/ssl/x%d.crt", i)].ID)
	}
	return ids
}

// Bindings: added by an Operator without a licence (automatic deployment off), listed with their state, re-added (automatic deployment changed or
// nothing), removed; every change is audited with the actor.
func TestACMEBindingsAddListRemove(t *testing.T) {
	w := newACMEDeployWorld(t)
	c, cur := w.issued("www.example.test")
	lock := &lockableLicense{LicenseGate: w.h.lic}
	lock.locked.Store(true)
	svc := inventory.New(inventory.Config{Pool: w.h.db.App, Keyring: w.h.keyring, Audit: w.h.audit, Clock: w.h.clock, License: lock,
		Registry: w.h.svc.Registry(), Jobs: w.h.jobs})
	b, err := svc.AddACMEBinding(w.h.ctx, w.operator, c.ID, w.loc1, false)
	require.NoError(t, err, "a binding without unattended deployment changes no server: an Operator, no licence")
	assert.Equal(t, w.loc1, b.LocationID)
	assert.Equal(t, w.target1, b.TargetID)
	assert.Equal(t, "web-01", b.TargetName)
	assert.Equal(t, "/etc/nginx/ssl/www.crt", b.CertPath)
	assert.False(t, b.AutoDeploy)
	assert.Equal(t, inventory.ACMEBindingPending, b.State)
	require.Len(t, w.h.auditDetails("acme.binding.added"), 1)
	d := w.h.auditDetails("acme.binding.added")[0]
	assert.Equal(t, c.ID.String(), d["acme_certificate_id"])
	assert.Equal(t, w.loc1.String(), d["location_id"])
	assert.Equal(t, "false", d["auto_deploy"])
	assert.Equal(t, 1, w.h.count("SELECT count(*) FROM audit_log WHERE action = 'acme.binding.added' AND actor_id = $1", w.operator.UserID))

	// Ruling (fix round 1): switching unattended deployment on is an Administrator's act under the licence gate.
	_, err = svc.AddACMEBinding(w.h.ctx, w.operator, c.ID, w.loc1, true)
	assert.ErrorIs(t, err, inventory.ErrAdminRequired, "an Operator cannot switch unattended deployment on")
	_, err = svc.AddACMEBinding(w.h.ctx, w.operator, c.ID, w.loc2, true)
	assert.ErrorIs(t, err, inventory.ErrAdminRequired, "nor bind with it on")
	_, err = svc.AddACMEBinding(w.h.ctx, w.admin, c.ID, w.loc1, true)
	assert.ErrorIs(t, err, license.ErrLocked, "an Administrator in lock cannot either")
	assert.Zero(t, w.h.audits("acme.binding.updated"))
	b, err = w.h.svc.AddACMEBinding(w.h.ctx, w.admin, c.ID, w.loc1, true)
	require.NoError(t, err)
	assert.True(t, b.AutoDeploy)
	assert.Equal(t, 1, w.h.audits("acme.binding.updated"))
	_, err = svc.AddACMEBinding(w.h.ctx, w.operator, c.ID, w.loc1, true)
	require.NoError(t, err, "binding again as it is changes nothing and needs nobody")
	assert.Equal(t, 1, w.h.audits("acme.binding.added"))
	assert.Equal(t, 1, w.h.audits("acme.binding.updated"))
	b, err = svc.AddACMEBinding(w.h.ctx, w.operator, c.ID, w.loc1, false)
	require.NoError(t, err, "switching off is a safety act: an Operator, in lock")
	assert.False(t, b.AutoDeploy)
	assert.Equal(t, 2, w.h.audits("acme.binding.updated"))

	// The certificate's own switch: on is an Administrator's act under the licence gate too; off is not gated.
	off, on := false, true
	_, err = w.h.svc.UpdateACMECertificate(w.h.ctx, w.admin, c.ID, inventory.ACMECertificatePatch{AutoDeploy: &off})
	require.NoError(t, err)
	_, err = w.h.svc.UpdateACMECertificate(w.h.ctx, w.operator, c.ID, inventory.ACMECertificatePatch{AutoDeploy: &on})
	assert.ErrorIs(t, err, inventory.ErrAdminRequired)
	_, err = svc.UpdateACMECertificate(w.h.ctx, w.admin, c.ID, inventory.ACMECertificatePatch{AutoDeploy: &on})
	assert.ErrorIs(t, err, license.ErrLocked)
	_, err = w.h.svc.UpdateACMECertificate(w.h.ctx, w.admin, c.ID, inventory.ACMECertificatePatch{AutoDeploy: &on})
	require.NoError(t, err)
	hook := w.hook.ID
	_, err = svc.CreateACMECertificate(w.h.ctx, w.admin, inventory.ACMECertificateInput{ProviderID: w.provider.ID, Names: []string{"x.example.test"},
		Challenge: inventory.ACMEChallengeDNS01, HookID: &hook, AutoDeploy: true})
	assert.ErrorIs(t, err, license.ErrLocked, "created with unattended deployment on: under the gate")

	w.bind(c, true, w.loc2)
	list, err := w.h.svc.ListACMEBindings(w.h.ctx, c.ID)
	require.NoError(t, err)
	require.Len(t, list, 2)
	assert.Equal(t, 2, w.get(c.ID).Bindings)

	// A location that serves the current certificate is current.
	_, err = w.h.db.Owner.Exec(w.h.ctx, "UPDATE certificate_locations SET certificate_id = $2 WHERE id = $1", w.loc2, cur)
	require.NoError(t, err)
	list, err = w.h.svc.ListACMEBindings(w.h.ctx, c.ID)
	require.NoError(t, err)
	for _, b := range list {
		if b.LocationID == w.loc2 {
			assert.Equal(t, inventory.ACMEBindingCurrent, b.State)
		}
	}

	require.NoError(t, svc.RemoveACMEBinding(w.h.ctx, w.operator, c.ID, w.loc1))
	assert.Equal(t, 1, w.h.audits("acme.binding.removed"))
	assert.ErrorIs(t, svc.RemoveACMEBinding(w.h.ctx, w.operator, c.ID, w.loc1), inventory.ErrNotFound)
	assert.ErrorIs(t, svc.RemoveACMEBinding(w.h.ctx, w.operator, uuid.New(), w.loc2), inventory.ErrNotFound)
	_, err = w.h.svc.ListACMEBindings(w.h.ctx, uuid.New())
	assert.ErrorIs(t, err, inventory.ErrNotFound)

	// Deleting the certificate removes its bindings (Task 10) and frees the location for another.
	require.NoError(t, w.h.svc.DeleteACMECertificate(w.h.ctx, w.admin, c.ID))
	other, _ := w.issued("www.example.test")
	w.bind(other, true, w.loc2)
}

// The refusals of AddACMEBinding, in their order, and the one-source rule both ways with a Key Vault binding.
func TestACMEBindingRefusals(t *testing.T) {
	w := newACMEDeployWorld(t)
	add := func(c uuid.UUID, loc uuid.UUID) error {
		_, err := w.h.svc.AddACMEBinding(w.h.ctx, w.admin, c, loc, true)
		return err
	}
	pending := w.define(w.provider, "api.example.test")
	assert.ErrorIs(t, add(pending.ID, w.loc1), inventory.ErrACMENotIssued)
	assert.ErrorIs(t, add(uuid.New(), w.loc1), inventory.ErrNotFound)

	c, _ := w.issued("www.example.test")
	err := add(c.ID, uuid.New())
	assert.ErrorIs(t, err, inventory.ErrNotFound)
	var lr *inventory.LocationRefusalError
	require.ErrorAs(t, err, &lr)
	assert.ErrorIs(t, add(c.ID, w.unsupported), inventory.ErrLocationUnsupported)
	_, err = w.h.db.Owner.Exec(w.h.ctx, "UPDATE certificate_locations SET missing_since = $2 WHERE id = $1", w.loc5, w.h.clock.Now())
	require.NoError(t, err)
	assert.ErrorIs(t, add(c.ID, w.loc5), inventory.ErrLocationUnsupported, "missing at the last scan")
	err = add(c.ID, w.loc4)
	var km *inventory.KeyTypeMismatchError
	require.ErrorAs(t, err, &km, "an RSA location for an ECDSA certificate")
	assert.Equal(t, "rsa", km.Expected)
	assert.Equal(t, "ecdsa", km.Actual)
	require.ErrorAs(t, err, &lr)
	assert.Equal(t, w.loc4, lr.LocationID)

	// One source per location: another ACME certificate ...
	require.NoError(t, add(c.ID, w.loc1))
	other, _ := w.issued("www.example.test")
	assert.ErrorIs(t, add(other.ID, w.loc1), inventory.ErrACMELocationBound)
	// ... and a vault certificate, both ways.
	vault := w.h.vault("prod")
	leaf := w.ca.Issue(pki.Opts{CommonName: "web.example.test", SANs: []string{"web.example.test"}}, w.h.clock.Now())
	w.h.reconcile(vault, kvResult(w.h.kvc("web-cert", leaf, ver(1), w.h.clock.Now(), true)))
	kv := w.h.certRow(vault, "web-cert").ID
	_, err = w.h.svc.CreateBinding(w.h.ctx, w.admin, inventory.BindingInput{KVCertificateID: kv, LocationIDs: []uuid.UUID{w.loc1}})
	assert.ErrorIs(t, err, inventory.ErrLocationBound, "a location that follows an ACME certificate cannot join a vault binding")
	_, err = w.h.svc.CreateBinding(w.h.ctx, w.admin, inventory.BindingInput{KVCertificateID: kv, LocationIDs: []uuid.UUID{w.loc2}})
	require.NoError(t, err)
	assert.ErrorIs(t, add(c.ID, w.loc2), inventory.ErrACMELocationBound, "a location of a vault binding cannot follow an ACME certificate")

	// A deleted server: the location is gone.
	_, err = w.h.db.Owner.Exec(w.h.ctx, "UPDATE targets SET deleted_at = now() WHERE id = $1", w.target2)
	require.NoError(t, err)
	assert.ErrorIs(t, add(c.ID, w.loc3onTarget2), inventory.ErrNotFound)
	assert.Len(t, fieldList(add(c.ID, uuid.Nil)), 1, "the nil location is a field error")
}

// A13 under concurrency: a key type change and a new binding of the same certificate are serialized by the row lock;
// never both succeed (a location of the old type bound to a certificate whose next key is of another type).
func TestACMEKeyTypeChangeAndBindingAreSerialized(t *testing.T) {
	w := newACMEDeployWorld(t)
	rsa := "rsa_2048"
	for i := range 6 {
		c, _ := w.issued("www.example.test")
		loc := w.loc1
		if i%2 == 1 {
			loc = w.loc2
		}
		// The test holds the row lock so that both requests are queued behind it, then lets them race.
		tx, err := w.h.db.Owner.Begin(w.h.ctx)
		require.NoError(t, err)
		_, err = tx.Exec(w.h.ctx, "SELECT 1 FROM acme_certificates WHERE id = $1 FOR UPDATE", c.ID)
		require.NoError(t, err)
		var wg sync.WaitGroup
		var bindErr, typeErr error
		wg.Add(2)
		go func() {
			defer wg.Done()
			_, bindErr = w.h.svc.AddACMEBinding(w.h.ctx, w.admin, c.ID, loc, true)
		}()
		go func() {
			defer wg.Done()
			_, typeErr = w.h.svc.UpdateACMECertificate(w.h.ctx, w.admin, c.ID, inventory.ACMECertificatePatch{KeyType: &rsa})
		}()
		time.Sleep(50 * time.Millisecond)
		require.NoError(t, tx.Rollback(w.h.ctx))
		wg.Wait()
		if bindErr == nil {
			assert.ErrorIs(t, typeErr, inventory.ErrACMEKeyTypeLocked, "run %d", i)
			assert.Equal(t, "ecdsa_p256", w.get(c.ID).KeyType)
		} else {
			assert.NoError(t, typeErr, "run %d", i)
			var km *inventory.KeyTypeMismatchError
			assert.ErrorAs(t, bindErr, &km, "run %d", i)
			assert.Zero(t, w.get(c.ID).Bindings)
		}
		require.NoError(t, w.h.svc.DeleteACMECertificate(w.h.ctx, w.admin, c.ID))
	}
}

// One source per location under concurrency: two ACME certificates, or an ACME certificate and a vault certificate,
// that bind the same location at once: exactly one wins.
func TestACMEBindingOneSourceUnderConcurrency(t *testing.T) {
	w := newACMEDeployWorld(t)
	a, _ := w.issued("www.example.test")
	b, _ := w.issued("www.example.test")
	vault := w.h.vault("prod")
	leaf := w.ca.Issue(pki.Opts{CommonName: "web.example.test", SANs: []string{"web.example.test"}}, w.h.clock.Now())
	w.h.reconcile(vault, kvResult(w.h.kvc("web-cert", leaf, ver(1), w.h.clock.Now(), true)))
	kv := w.h.certRow(vault, "web-cert").ID
	for _, loc := range []uuid.UUID{w.loc1, w.loc5, w.loc2} {
		errs := make([]error, 3)
		var wg sync.WaitGroup
		start := make(chan struct{})
		for i, f := range []func() error{
			func() error { _, err := w.h.svc.AddACMEBinding(w.h.ctx, w.admin, a.ID, loc, true); return err },
			func() error { _, err := w.h.svc.AddACMEBinding(w.h.ctx, w.admin, b.ID, loc, true); return err },
			func() error {
				_, err := w.h.svc.CreateBinding(w.h.ctx, w.admin, inventory.BindingInput{KVCertificateID: kv, LocationIDs: []uuid.UUID{loc}})
				return err
			},
		} {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				errs[i] = f()
			}()
		}
		close(start)
		wg.Wait()
		ok := 0
		for _, err := range errs {
			if err == nil {
				ok++
				continue
			}
			assert.True(t, errors.Is(err, inventory.ErrACMELocationBound) || errors.Is(err, inventory.ErrLocationBound) ||
				errors.Is(err, inventory.ErrBindingExists), "%v", err)
		}
		assert.Equal(t, 1, ok, "exactly one binding of the location: %v", errs)
		var sources int
		require.NoError(t, w.h.db.Owner.QueryRow(w.h.ctx, `SELECT (SELECT count(*) FROM acme_bindings WHERE location_id = $1)
    + (SELECT count(*) FROM certificate_locations WHERE id = $1 AND binding_id IS NOT NULL)`, loc).Scan(&sources))
		assert.Equal(t, 1, sources)
	}
}

// A new ACME certificate is deployed by the planner to its bound locations through the deployment records of a person's
// request (trigger acme_renewal, a system job, deployment.requested by the system actor); nothing twice; a renewal is
// deployed again; a binding with automatic deployment off and a certificate with it off are left alone.
func TestACMEAutoDeployDeploysANewCertificate(t *testing.T) {
	w := newACMEDeployWorld(t)
	c, cur := w.issued("www.example.test")
	w.bind(c, true, w.loc1, w.loc2)
	w.bind(c, false, w.loc5)
	before := len(w.h.jobs.requests())
	run := w.plan()
	assert.Equal(t, inventory.ACMEDeployRun{Created: 2}, run)
	ds := w.deps(cur)
	require.Len(t, ds, 2)
	assert.ElementsMatch(t, []uuid.UUID{w.loc1, w.loc2}, locationsOf(ds))
	for _, d := range ds {
		assert.Equal(t, inventory.TriggerACMERenewal, d.Trigger)
		assert.Equal(t, inventory.DeployStateQueued, d.State)
		got, err := w.h.svc.Deployment(w.h.ctx, d.ID)
		require.NoError(t, err)
		assert.Equal(t, "acme", got.Source, "a deployment of an ACME certificate is not an upload (final review finding 3)")
	}
	reqs := w.h.jobs.requests()[before:]
	require.Len(t, reqs, 2)
	for _, r := range reqs {
		assert.Equal(t, inventory.JobCertificateDeployAuto, r.Type, "the planner's deployment is continuity work (owner decision 2026-10-20)")
		assert.Equal(t, "system", r.Kind)
	}
	requested := w.h.auditDetails("deployment.requested")
	require.Len(t, requested, 2)
	assert.Equal(t, 2, w.h.count("SELECT count(*) FROM audit_log WHERE action = 'deployment.requested' AND actor_type = 'system' AND actor_name = 'jobs'"))
	assert.Equal(t, cur.String(), requested[0]["certificate_id"])

	assert.Equal(t, inventory.ACMEDeployRun{}, w.plan(), "busy: nothing twice")
	w.finishAll(cur, inventory.DeployStatusSucceeded, "")
	assert.Equal(t, inventory.ACMEDeployRun{}, w.plan(), "deployed: nothing more")

	// Automatic deployment of the certificate off: nothing; on again: the renewal goes out.
	off := false
	_, err := w.h.svc.UpdateACMECertificate(w.h.ctx, w.admin, c.ID, inventory.ACMECertificatePatch{AutoDeploy: &off})
	require.NoError(t, err)
	w.h.clock.Advance(time.Hour)
	renewed := w.issue(c)
	assert.Equal(t, inventory.ACMEDeployRun{}, w.plan())
	on := true
	_, err = w.h.svc.UpdateACMECertificate(w.h.ctx, w.admin, c.ID, inventory.ACMECertificatePatch{AutoDeploy: &on})
	require.NoError(t, err)
	assert.Equal(t, 2, w.plan().Created)
	assert.ElementsMatch(t, []uuid.UUID{w.loc1, w.loc2}, locationsOf(w.deps(renewed)))
}

// Waves of five per certificate; the run's batch bounds all certificates.
func TestACMEAutoDeployWavesAndBatch(t *testing.T) {
	w := newACMEDeployWorld(t)
	extra := w.moreLocations(6)
	c, cur := w.issued("www.example.test")
	w.bind(c, true, append([]uuid.UUID{w.loc1}, extra...)...)
	assert.Equal(t, inventory.AutoDeployWave, w.plan().Created)
	assert.Zero(t, w.plan().Created, "the wave is full")
	w.finishAll(cur, inventory.DeployStatusSucceeded, "")
	assert.Equal(t, 2, w.plan().Created, "the rest")
	assert.Len(t, w.deps(cur), 7)

	restore := inventory.SetAutoDeployBatch(1)
	defer restore()
	d, dcur := w.issued("api.example.test")
	e, ecur := w.issued("api.example.test")
	w.bind(d, true, w.loc5)
	w.bind(e, true, w.loc2)
	assert.Equal(t, 1, w.plan().Created, "one deployment in all per run")
	assert.Equal(t, 1, w.plan().Created)
	assert.Len(t, append(w.deps(dcur), w.deps(ecur)...), 2)
}

// Three failed automatic deployments stop the wave with one audit row and one e-mail; a failed location waits an hour
// (no tight loop) and is marked attention; neutral reasons count nothing.
func TestACMEAutoDeployStopsAfterThreeFailures(t *testing.T) {
	w := newACMEDeployWorld(t)
	c, cur := w.issued("www.example.test")
	w.bind(c, true, w.loc1)
	codes := []string{"deployment.reload_failed", "deployment.config_test_failed", "deployment.verify_failed"}
	for i, code := range codes {
		require.Equal(t, 1, w.plan().Created, "attempt %d", i+1)
		w.finishAll(cur, inventory.DeployStatusFailed, code)
		if i == len(codes)-1 {
			break
		}
		assert.Zero(t, w.plan().Created, "attempt %d: no retry at once", i+1)
		assert.Equal(t, map[uuid.UUID]string{w.loc1: code}, w.attention(c), "attempt %d", i+1)
		w.h.clock.Advance(59 * time.Minute)
		assert.Zero(t, w.plan().Created, "attempt %d: not within the hour", i+1)
		w.h.clock.Advance(time.Minute)
	}
	run := w.plan()
	assert.Equal(t, inventory.ACMEDeployRun{Stopped: 1}, run, "the third failure stops the wave at the next run")
	assert.Equal(t, map[uuid.UUID]string{w.loc1: "deployment.verify_failed"}, w.attention(c))
	assert.Len(t, w.deps(cur), 3)
	stopped := w.h.auditDetails("acme.auto_deploy.stopped")
	require.Len(t, stopped, 1)
	assert.Equal(t, "3", stopped[0]["failed_count"])
	assert.Equal(t, "deployment.verify_failed", stopped[0]["error_code"])
	assert.Equal(t, cur.String(), stopped[0]["certificate_id"])
	assert.Equal(t, 1, w.h.emails(inventory.TemplateACMEAutoDeployStopped))
	w.h.clock.Advance(3 * time.Hour)
	assert.Equal(t, inventory.ACMEDeployRun{}, w.plan())
	assert.Equal(t, 1, w.h.emails(inventory.TemplateACMEAutoDeployStopped), "once")
	assert.Len(t, w.deps(cur), 3, "stopped: no fourth attempt")
	assert.Equal(t, inventory.ACMEStateActive, w.get(c.ID).State, "the ACME certificate itself stays issued")

	// A person's Deploy now still works; its success clears the attention mark.
	got, err := w.h.svc.DeployACMENow(w.h.ctx, w.operator, c.ID, inventory.ACMEDeployInput{})
	require.NoError(t, err)
	require.Len(t, got, 1)
	w.finish(got[0].ID, inventory.DeployStatusSucceeded, "")
	w.plan()
	assert.Empty(t, w.attention(c))

	// The next certificate starts a new wave.
	w.h.clock.Advance(time.Hour)
	next := w.issue(c)
	assert.Equal(t, 1, w.plan().Created)
	assert.Len(t, w.deps(next), 1)
}

func TestACMEAutoDeployNeutralReasonsDoNotStop(t *testing.T) {
	w := newACMEDeployWorld(t)
	c, cur := w.issued("www.example.test")
	w.bind(c, true, w.loc1)
	for range 4 {
		require.Equal(t, 1, w.plan().Created)
		w.finishAll(cur, inventory.DeployStatusFailed, inventory.ReasonChainUnconfirmed)
		w.h.clock.Advance(time.Hour)
	}
	assert.Zero(t, w.h.audits("acme.auto_deploy.stopped"))
	assert.Empty(t, w.attention(c), "a neutral reason is not the location's failure")
}

// In lock the planner writes nothing and creates nothing; the scheduler's task is paused too (acmejobs).
func TestACMEAutoDeployInLockDoesNothing(t *testing.T) {
	w := newACMEDeployWorld(t)
	c, cur := w.issued("www.example.test")
	w.bind(c, true, w.loc1, w.loc2)
	lock := &lockableLicense{LicenseGate: w.h.lic}
	lock.locked.Store(true)
	svc := inventory.New(inventory.Config{Pool: w.h.db.App, Keyring: w.h.keyring, Audit: w.h.audit, Clock: w.h.clock, License: lock,
		Registry: w.h.svc.Registry(), Jobs: w.h.jobs, Notifier: notify.ServiceNotifier{Clock: w.h.clock}})
	audits, jobsBefore := w.h.count("SELECT count(*) FROM audit_log"), len(w.h.jobs.requests())
	run, err := svc.PlanACMEAutoDeploy(w.h.ctx)
	require.NoError(t, err)
	assert.Equal(t, inventory.ACMEDeployRun{}, run)
	assert.Empty(t, w.deps(cur))
	assert.Equal(t, audits, w.h.count("SELECT count(*) FROM audit_log"))
	assert.Equal(t, jobsBefore, len(w.h.jobs.requests()))

	// The gate is read again inside each certificate's transaction: a lock between the run's check and the certificate.
	lock.locked.Store(false)
	restore := inventory.SetACMEDeployHook(func(uuid.UUID) { lock.locked.Store(true) })
	defer restore()
	run, err = svc.PlanACMEAutoDeploy(w.h.ctx)
	require.NoError(t, err)
	assert.Equal(t, inventory.ACMEDeployRun{}, run)
	assert.Empty(t, w.deps(cur))

	// Deploy now in lock is the licence refusal of RequestDeployment.
	_, err = svc.DeployACMENow(w.h.ctx, w.operator, c.ID, inventory.ACMEDeployInput{})
	assert.ErrorIs(t, err, license.ErrLocked)
}

// A certificate issued before the licence gate last reopened is held for an Administrator (one audit row, one e-mail),
// not deployed unseen; released, it is deployed. One issued after the reopening is deployed at once.
func TestACMEAutoDeployHoldsACertificateIssuedBeforeTheReopening(t *testing.T) {
	w := newACMEDeployWorldLicensed(t, false)
	c, cur := w.issued("www.example.test")
	w.bind(c, true, w.loc1)
	// The 30-day evaluation ends: the gate locks; a licence reopens it (the certificate is still valid).
	w.h.clock.Advance(40 * 24 * time.Hour)
	require.NoError(t, w.h.lic.Tick(w.h.ctx))
	require.Error(t, w.h.lic.Allow(license.ClassChange), "locked")
	w.h.installLicense("LIC-AGAIN", 5, 3650)
	require.NoError(t, w.h.lic.Allow(license.ClassChange))

	run := w.plan()
	assert.Equal(t, inventory.ACMEDeployRun{Held: 1}, run)
	assert.Empty(t, w.deps(cur))
	held := w.h.auditDetails("acme.auto_deploy.held")
	require.Len(t, held, 1)
	assert.Equal(t, inventory.ACMEHoldLicense, held[0]["reason"])
	assert.Equal(t, inventory.HoldRuleDetectedBeforeReopening, held[0]["hold_rule"])
	assert.Equal(t, 1, w.h.emails(inventory.TemplateACMEAutoDeployHeldLicense))
	assert.Equal(t, inventory.ACMEDeployRun{}, w.plan())
	assert.Equal(t, 1, w.h.emails(inventory.TemplateACMEAutoDeployHeldLicense), "once")

	require.NoError(t, w.h.svc.ReleaseACMEDeployHold(w.h.ctx, w.admin, c.ID))
	assert.Equal(t, 1, w.h.audits("acme.auto_deploy.released"))
	require.NoError(t, w.h.svc.ReleaseACMEDeployHold(w.h.ctx, w.admin, c.ID), "not held: nothing")
	assert.Equal(t, 1, w.h.audits("acme.auto_deploy.released"))
	assert.Equal(t, 1, w.plan().Created)
	w.finishAll(cur, inventory.DeployStatusSucceeded, "")

	// A renewal after the reopening is deployed at once.
	w.h.clock.Advance(time.Hour)
	next := w.issue(c)
	assert.Equal(t, 1, w.plan().Created)
	assert.Len(t, w.deps(next), 1)
	assert.Equal(t, 1, w.h.audits("acme.auto_deploy.held"))
}

// A3 and the chain rule: with the provider's bundle holding its root the chain is complete and deployed; without it the
// chain is incomplete and held (one e-mail), never confirmed by the planner; only an Administrator's Deploy now with
// the confirmation deploys it, and the hold cannot be released.
func TestACMEAutoDeployHoldsAnIncompleteChain(t *testing.T) {
	w := newACMEDeployWorld(t)
	noRoot := w.newProvider("No root CA", false)
	c := w.define(noRoot, "www.example.test")
	cur := w.issue(c)
	var complete bool
	require.NoError(t, w.h.db.Owner.QueryRow(w.h.ctx, "SELECT chain_complete FROM certificates WHERE id = $1", cur).Scan(&complete))
	require.False(t, complete, "the issuing root is not in this provider's bundle")
	w.bind(w.get(c.ID), true, w.loc1)
	assert.Equal(t, inventory.ACMEDeployRun{Held: 1}, w.plan())
	assert.Empty(t, w.deps(cur))
	assert.Equal(t, inventory.ACMEHoldChainIncomplete, w.h.auditDetails("acme.auto_deploy.held")[0]["reason"])
	assert.Equal(t, 1, w.h.emails(inventory.TemplateACMEAutoDeployHeldChain))
	assert.Equal(t, inventory.ACMEDeployRun{}, w.plan())
	assert.ErrorIs(t, w.h.svc.ReleaseACMEDeployHold(w.h.ctx, w.admin, c.ID), inventory.ErrChainUnconfirmed)

	_, err := w.h.svc.DeployACMENow(w.h.ctx, w.operator, c.ID, inventory.ACMEDeployInput{ConfirmIncompleteChain: true})
	assert.ErrorIs(t, err, inventory.ErrChainUnconfirmed, "an Operator cannot confirm")
	got, err := w.h.svc.DeployACMENow(w.h.ctx, w.admin, c.ID, inventory.ACMEDeployInput{ConfirmIncompleteChain: true})
	require.NoError(t, err)
	require.Len(t, got, 1)
	ds := w.deps(cur)
	require.Len(t, ds, 1)
	assert.Equal(t, "manual", ds[0].Trigger)

	// The main provider's certificate (root in the bundle) is complete.
	ok, okCur := w.issued("api.example.test")
	require.NoError(t, w.h.db.Owner.QueryRow(w.h.ctx, "SELECT chain_complete FROM certificates WHERE id = $1", okCur).Scan(&complete))
	assert.True(t, complete, "A3: the provider's bundle completes the chain")
	w.bind(ok, true, w.loc2)
	assert.Equal(t, 1, w.plan().Created)
}

// Deploy now is RequestDeployment: only bound locations, every bound location when none is named, trigger manual.
func TestACMEDeployNow(t *testing.T) {
	w := newACMEDeployWorld(t)
	pending := w.define(w.provider, "api.example.test")
	_, err := w.h.svc.DeployACMENow(w.h.ctx, w.operator, pending.ID, inventory.ACMEDeployInput{})
	assert.ErrorIs(t, err, inventory.ErrACMENotIssued)
	_, err = w.h.svc.DeployACMENow(w.h.ctx, w.operator, uuid.New(), inventory.ACMEDeployInput{})
	assert.ErrorIs(t, err, inventory.ErrNotFound)

	c, cur := w.issued("www.example.test")
	w.bind(c, false, w.loc1, w.loc2)
	_, err = w.h.svc.DeployACMENow(w.h.ctx, w.operator, c.ID, inventory.ACMEDeployInput{LocationIDs: []uuid.UUID{w.loc1, w.loc5}})
	assert.ErrorIs(t, err, inventory.ErrACMELocationNotBound)
	var lr *inventory.LocationRefusalError
	require.ErrorAs(t, err, &lr)
	assert.Equal(t, w.loc5, lr.LocationID)
	assert.Empty(t, w.deps(cur))

	got, err := w.h.svc.DeployACMENow(w.h.ctx, w.operator, c.ID, inventory.ACMEDeployInput{LocationIDs: []uuid.UUID{w.loc2}})
	require.NoError(t, err)
	require.Len(t, got, 1)
	w.finishAll(cur, inventory.DeployStatusSucceeded, "")
	got, err = w.h.svc.DeployACMENow(w.h.ctx, w.operator, c.ID, inventory.ACMEDeployInput{})
	require.NoError(t, err)
	assert.Len(t, got, 2, "every bound location")
	for _, d := range w.deps(cur) {
		assert.Equal(t, "manual", d.Trigger)
	}
	assert.Equal(t, 3, w.h.count("SELECT count(*) FROM audit_log WHERE action = 'deployment.requested' AND actor_id = $1", w.operator.UserID))
}

// Several planners at once (several processes): exactly one deployment per location.
func TestACMEAutoDeployConcurrentPlanners(t *testing.T) {
	w := newACMEDeployWorld(t)
	extra := w.moreLocations(3)
	var certs []uuid.UUID
	for i, loc := range append([]uuid.UUID{w.loc1, w.loc2}, extra...) {
		c, cur := w.issued(fmt.Sprintf("n%d.example.test", i))
		w.bind(c, true, loc)
		certs = append(certs, cur)
	}
	require.NoError(t, w.h.lic.Tick(w.h.ctx))
	var wg sync.WaitGroup
	for range 4 {
		svc := inventory.New(inventory.Config{Pool: w.h.db.App, Keyring: w.h.keyring, Audit: w.h.audit, Clock: w.h.clock, License: w.h.lic,
			Registry: w.h.svc.Registry(), Jobs: w.h.jobs, Notifier: notify.ServiceNotifier{Clock: w.h.clock}})
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 3 {
				_, err := svc.PlanACMEAutoDeploy(w.h.ctx)
				assert.NoError(t, err)
			}
		}()
	}
	wg.Wait()
	for _, cur := range certs {
		assert.Len(t, w.deps(cur), 1)
	}
	assert.Equal(t, 5, w.h.count("SELECT count(*) FROM deployments WHERE trigger = 'acme_renewal'"))
}

// A location the checks refuse (server not ready, a competing deployment that appears before the insert) is skipped
// without an error and planned at a later run; a certificate another transaction holds is skipped (SKIP LOCKED).
func TestACMEAutoDeploySkipsWhatIsNotReady(t *testing.T) {
	w := newACMEDeployWorld(t)
	c, cur := w.issued("www.example.test")
	w.bind(c, true, w.loc1, w.loc2)
	w.setTargetStatus(w.target2, inventory.StatusAuthFailed)
	assert.Equal(t, 1, w.plan().Created)
	assert.Equal(t, []uuid.UUID{w.loc1}, locationsOf(w.deps(cur)))
	w.setTargetStatus(w.target2, inventory.StatusOK)

	// A person's deployment of loc2 appears between the checks and the insert: the savepoint keeps the run going.
	restore := inventory.SetACMEDeployInsertHook(func(loc uuid.UUID) {
		if loc != w.loc2 {
			return
		}
		_, err := w.h.db.Owner.Exec(w.h.ctx, `INSERT INTO deployments (id, certificate_id, location_id, target_id, trigger, state, status,
new_fingerprint, cert_path, key_path, created_at)
SELECT gen_random_uuid(), $2, l.id, l.target_id, 'manual', 'queued', 'pending', $3, l.cert_path, l.key_path, now() FROM certificate_locations l
WHERE l.id = $1`, loc, w.cert.ID, w.cert.Fingerprint)
		require.NoError(t, err)
	})
	assert.Zero(t, w.plan().Created)
	restore()
	assert.Equal(t, []uuid.UUID{w.loc1}, locationsOf(w.deps(cur)))

	// The certificate's row is held by someone else: skipped at once, no wait.
	_, err := w.h.db.Owner.Exec(w.h.ctx, "UPDATE deployments SET state = 'done', status = 'failed', error_code = 'deployment.reload_failed', finished_at = now() WHERE certificate_id = $1", w.cert.ID)
	require.NoError(t, err)
	tx, err := w.h.db.Owner.Begin(w.h.ctx)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback(w.h.ctx) }() // a planner that waits is released when the test fails
	_, err = tx.Exec(w.h.ctx, "SELECT 1 FROM acme_certificates WHERE id = $1 FOR UPDATE", c.ID)
	require.NoError(t, err)
	require.NoError(t, w.h.lic.Tick(w.h.ctx))
	done := make(chan inventory.ACMEDeployRun)
	go func() {
		run, _ := w.h.svc.PlanACMEAutoDeploy(w.h.ctx)
		done <- run
	}()
	select {
	case run := <-done:
		assert.Zero(t, run.Created)
	case <-time.After(10 * time.Second):
		t.Fatal("the planner waited for the row")
	}
	require.NoError(t, tx.Rollback(w.h.ctx))
	assert.Equal(t, 1, w.plan().Created)
	assert.ElementsMatch(t, []uuid.UUID{w.loc1, w.loc2}, locationsOf(w.deps(cur)))
}

// The candidates are read page by page: certificates with nothing to do do not hide the later ones.
func TestACMEAutoDeployPagesThroughCandidates(t *testing.T) {
	w := newACMEDeployWorld(t)
	restore := inventory.SetACMEDeployPage(1)
	defer restore()
	var curs []uuid.UUID
	for i, loc := range []uuid.UUID{w.loc1, w.loc5, w.loc2} {
		c, cur := w.issued(fmt.Sprintf("p%d.example.test", i))
		w.bind(c, true, loc)
		curs = append(curs, cur)
	}
	assert.Equal(t, 3, w.plan().Created)
	for _, cur := range curs {
		assert.Len(t, w.deps(cur), 1)
	}
}

// A deleted server's locations are not planned; a deleted ACME certificate is not planned.
func TestACMEAutoDeployIgnoresDeletedThings(t *testing.T) {
	w := newACMEDeployWorld(t)
	c, cur := w.issued("www.example.test")
	w.bind(c, true, w.loc2)
	_, err := w.h.db.Owner.Exec(w.h.ctx, "UPDATE targets SET deleted_at = now() WHERE id = $1", w.target2)
	require.NoError(t, err)
	assert.Equal(t, inventory.ACMEDeployRun{}, w.plan())
	d, dcur := w.issued("api.example.test")
	w.bind(d, true, w.loc1)
	restore := inventory.SetACMEDeployHook(func(id uuid.UUID) {
		if id == d.ID {
			_, err := w.h.db.Owner.Exec(w.h.ctx, "UPDATE acme_certificates SET deleted_at = now() WHERE id = $1", id)
			require.NoError(t, err)
		}
	})
	defer restore()
	assert.Equal(t, inventory.ACMEDeployRun{}, w.plan())
	assert.Empty(t, w.deps(cur))
	assert.Empty(t, w.deps(dcur))
}

// Fix round 1, I1, the case the engine test cannot build: the location of a queued automatic deployment was released and
// now follows a vault certificate. DeploymentMaterial refuses before any key is opened (acme.binding_gone); a person's
// manual deployment of the same certificate is not judged by the ACME rules.
func TestACMEQueuedDeploymentOfALocationNowBoundToAVault(t *testing.T) {
	w := newACMEDeployWorld(t)
	c, cur := w.issued("www.example.test")
	w.bind(c, true, w.loc1)
	require.Equal(t, 1, w.plan().Created)
	queued := w.deps(cur)[0].ID
	require.NoError(t, w.h.svc.RemoveACMEBinding(w.h.ctx, w.operator, c.ID, w.loc1))
	vault := w.h.vault("prod")
	leaf := w.ca.Issue(pki.Opts{CommonName: "web.example.test", SANs: []string{"web.example.test"}}, w.h.clock.Now())
	w.h.reconcile(vault, kvResult(w.h.kvc("web-cert", leaf, ver(1), w.h.clock.Now(), true)))
	_, err := w.h.svc.CreateBinding(w.h.ctx, w.admin, inventory.BindingInput{KVCertificateID: w.h.certRow(vault, "web-cert").ID,
		LocationIDs: []uuid.UUID{w.loc1}})
	require.NoError(t, err)
	_, err = w.h.svc.DeploymentMaterial(w.h.ctx, queued, true)
	assert.ErrorIs(t, err, inventory.ErrACMEBindingGone)
	_, err = w.h.svc.DeploymentMaterial(w.h.ctx, queued, false)
	require.NoError(t, err, "only the first send (with the key) is judged again")

	// Every refusal in turn, through the same read (the engine maps each to its neutral reason).
	d, dcur := w.issued("api.example.test")
	w.bind(d, true, w.loc5)
	require.Equal(t, 1, w.plan().Created)
	id := w.deps(dcur)[0].ID
	mat := func() error { _, err := w.h.svc.DeploymentMaterial(w.h.ctx, id, true); return err }
	require.NoError(t, mat())
	exec := func(sql string, args ...any) {
		_, err := w.h.db.Owner.Exec(w.h.ctx, sql, args...)
		require.NoError(t, err)
	}
	exec("UPDATE acme_bindings SET auto_deploy = false WHERE location_id = $1", w.loc5)
	assert.ErrorIs(t, mat(), inventory.ErrACMEAutoDeployOff)
	exec("UPDATE acme_bindings SET auto_deploy = true WHERE location_id = $1", w.loc5)
	// The view says what the planner's marks mean for the current certificate (the API shows it, Task 13).
	view := func() inventory.ACMECertificate {
		v, err := w.h.svc.GetACMECertificate(w.h.ctx, d.ID)
		require.NoError(t, err)
		return v
	}
	v := view()
	require.NotNil(t, v.Current)
	assert.Equal(t, dcur, v.Current.ID)
	assert.Regexp(t, `^[0-9a-f]{64}$`, v.Current.Fingerprint)
	assert.True(t, v.Current.NotAfter.After(v.Current.NotBefore))
	assert.Empty(t, v.DeployHeldReason)
	assert.False(t, v.DeployStopped)
	exec("UPDATE acme_certificates SET deploy_held_certificate_id = $2, deploy_held_reason = 'license' WHERE id = $1", d.ID, dcur)
	assert.ErrorIs(t, mat(), inventory.ErrACMEDeployHeld)
	assert.Equal(t, inventory.ACMEHoldLicense, view().DeployHeldReason)
	exec("UPDATE acme_certificates SET deploy_released_certificate_id = $2 WHERE id = $1", d.ID, dcur)
	require.NoError(t, mat(), "released from the licence hold")
	assert.Empty(t, view().DeployHeldReason, "released")
	exec("UPDATE acme_certificates SET deploy_held_reason = 'chain_incomplete' WHERE id = $1", d.ID)
	assert.ErrorIs(t, mat(), inventory.ErrACMEDeployHeld, "a chain hold is never released")
	assert.Equal(t, inventory.ACMEHoldChainIncomplete, view().DeployHeldReason)
	exec("UPDATE acme_certificates SET deploy_held_certificate_id = NULL, deploy_held_reason = '', deploy_stopped_certificate_id = $2 WHERE id = $1", d.ID, dcur)
	assert.ErrorIs(t, mat(), inventory.ErrACMEDeployStopped)
	assert.True(t, view().DeployStopped)
	exec("UPDATE acme_certificates SET deploy_stopped_certificate_id = NULL WHERE id = $1", d.ID)
	require.NoError(t, mat())
	w.h.clock.Advance(time.Hour)
	exec("UPDATE acme_certificates SET deploy_held_certificate_id = $2, deploy_held_reason = 'license', deploy_stopped_certificate_id = $2 WHERE id = $1",
		d.ID, dcur)
	newer := w.issue(d)
	require.NotEqual(t, dcur, newer)
	assert.ErrorIs(t, mat(), inventory.ErrACMESuperseded)
	v = view()
	assert.Equal(t, newer, v.Current.ID)
	assert.Empty(t, v.DeployHeldReason, "the marks of an earlier certificate are not the current one's")
	assert.False(t, v.DeployStopped)
	require.NoError(t, w.h.svc.DeleteACMECertificate(w.h.ctx, w.admin, d.ID))
	assert.ErrorIs(t, mat(), inventory.ErrACMEBindingGone)
}

// Fix round 1 of Task 13 (I1): switching unattended deployment on is judged INSIDE the transaction with the strength of
// the caller's session. The API reads the binding before it calls; when another request switches it off in between,
// a request that skipped the step-up because it saw "already on" must not switch it on again.
func TestACMESwitchOnNeedsAStrictSessionInsideTheTransaction(t *testing.T) {
	w := newACMEDeployWorld(t)
	svc, ctx := w.h.svc, w.h.ctx
	c, _ := w.issued("www.example.test")
	auto := func(loc uuid.UUID) (bool, bool) {
		list, err := svc.ListACMEBindings(ctx, c.ID)
		require.NoError(t, err)
		for _, b := range list {
			if b.LocationID == loc {
				return true, b.AutoDeploy
			}
		}
		return false, false
	}
	_, err := svc.AddACMEBindingStrict(ctx, w.admin, c.ID, w.loc1, true, true)
	require.NoError(t, err, "an Administrator with a fresh step-up switches it on")
	// The interleaving: the API saw "on" and skipped the step-up; meanwhile an Operator switches it off.
	_, err = svc.AddACMEBindingStrict(ctx, w.operator, c.ID, w.loc1, false, false)
	require.NoError(t, err, "switching off needs no step-up")
	_, err = svc.AddACMEBindingStrict(ctx, w.admin, c.ID, w.loc1, true, false)
	assert.ErrorIs(t, err, inventory.ErrAutoDeployNeedsStepUp)
	_, on := auto(w.loc1)
	assert.False(t, on, "still off")
	_, err = svc.AddACMEBindingStrict(ctx, w.operator, c.ID, w.loc1, true, true)
	assert.ErrorIs(t, err, inventory.ErrAdminRequired, "an Operator never switches it on, whatever the session")
	// A new binding with automatic deployment on: the same rule; nothing is stored.
	_, err = svc.AddACMEBindingStrict(ctx, w.admin, c.ID, w.loc2, true, false)
	assert.ErrorIs(t, err, inventory.ErrAutoDeployNeedsStepUp)
	bound, _ := auto(w.loc2)
	assert.False(t, bound)
	// Switched on again with the step-up; keeping it on is no switch-on: no step-up, also for an Operator.
	_, err = svc.AddACMEBindingStrict(ctx, w.admin, c.ID, w.loc1, true, true)
	require.NoError(t, err)
	_, err = svc.AddACMEBindingStrict(ctx, w.operator, c.ID, w.loc1, true, false)
	require.NoError(t, err)
	_, on = auto(w.loc1)
	assert.True(t, on)
	assert.Equal(t, 3, w.h.count("SELECT count(*) FROM audit_log WHERE action IN ('acme.binding.added', 'acme.binding.updated') AND object_id = $1",
		c.ID.String()), "added on, switched off, switched on with the step-up; the refused switch-ons and the keep-on wrote nothing")
}

// Fix round 1 of Task 13 (M2): Deploy now without named locations needs at least one and at most MaxDeployLocations
// bound locations; otherwise a refusal of its own, not a validation error on a field the request did not send.
func TestACMEDeployNowWithoutNamedLocations(t *testing.T) {
	w := newACMEDeployWorld(t)
	c, cur := w.issued("www.example.test")
	_, err := w.h.svc.DeployACMENow(w.h.ctx, w.operator, c.ID, inventory.ACMEDeployInput{})
	assert.ErrorIs(t, err, inventory.ErrACMENoBindings)
	w.bind(c, false, w.moreLocations(inventory.MaxDeployLocations+1)...)
	_, err = w.h.svc.DeployACMENow(w.h.ctx, w.operator, c.ID, inventory.ACMEDeployInput{})
	assert.ErrorIs(t, err, inventory.ErrACMETooManyBindings)
	assert.Empty(t, w.deps(cur))
}
