//go:build integration

package inventory_test

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/acme"
	"alice/internal/acme/solver"
	"alice/internal/inventory"
	"alice/internal/license"
	"alice/internal/platform/validate"
	"alice/internal/providers"
	"alice/internal/providers/fake"
	"alice/internal/rbac"
	"alice/internal/secrets"
	"alice/internal/testutil/fakeacme"
)

// lockableLicense is the harness's license service with a switch that puts it in lock.
type lockableLicense struct {
	inventory.LicenseGate
	locked atomic.Bool
	window atomic.Bool // with locked: inside the continuity window, continuity work is allowed
}

func (l *lockableLicense) Allow(c license.Class) error {
	if l.locked.Load() && c != license.ClassAlways && (c != license.ClassContinuity || !l.window.Load()) {
		return license.ErrLocked
	}
	return l.LicenseGate.Allow(c)
}

// certWorld is a registry world with a registered provider (allow-list example.test) and a hook (allow-list
// example.test) for ACME certificate definitions and orders.
type certWorld struct {
	*registryWorld
	lic      *lockableLicense
	provider inventory.ACMEProvider
	account  inventory.ACMEAccount
	hook     inventory.ACMEHook
	operator inventory.Actor
}

func newCertWorld(t *testing.T) *certWorld {
	t.Helper()
	w := newRegistryWorld(t, fakeacme.Options{NoTerms: true})
	w.reg = registryWithNginx(w.reg, append(append([]providers.Capability{}, nginxCaps...), providers.CapHTTP01)...)
	cw := &certWorld{registryWorld: w, lic: &lockableLicense{LicenseGate: w.lic}}
	w.svc = inventory.New(inventory.Config{Pool: w.db.App, Keyring: w.keyring, Audit: w.audit, Clock: w.clock, License: cw.lic,
		Registry: w.reg, Jobs: w.jobs})
	cw.provider = w.provider("Cert CA", false)
	cw.account = w.register(cw.provider)
	var err error
	cw.hook, err = w.svc.CreateACMEHook(w.ctx, w.admin, inventory.ACMEHookInput{Name: "dns", URL: w.fake.Credentials().HookURL,
		CABundlePEM: string(w.fake.CAPEM()), Secret: secrets.NewPlaintext([]byte(w.fake.Credentials().HookSecret)),
		AllowedSuffixes: []string{"example.test"}})
	require.NoError(t, err)
	cw.operator = w.user("otto", rbac.Operator, "")
	return cw
}

// registryWithNginx is a registry holding the harness's linuxssh fake and a fake nginx provider with caps.
func registryWithNginx(old *providers.Registry, caps ...providers.Capability) *providers.Registry {
	ssh, _ := old.Get(providers.KindLinuxSSH)
	reg := providers.NewRegistry()
	reg.Register(ssh)
	reg.Register(fake.New(providers.KindNginx, caps...))
	reg.Freeze()
	return reg
}

// Only a provider that publishes HTTP-01 tokens may be the HTTP-01 server.
func TestACMEHTTP01NeedsAProviderThatPublishes(t *testing.T) {
	w := newRegistryWorld(t, fakeacme.Options{})
	provider := w.provider("Cert CA", false)
	w.register(provider)
	web := w.seedTarget("web-1", "nginx", "web1.example.test")
	in := inventory.ACMECertificateInput{ProviderID: provider.ID, Names: []string{"www.example.test"}, Challenge: inventory.ACMEChallengeHTTP01, HTTPTargetID: &web}
	create := func(caps ...providers.Capability) error {
		svc := inventory.New(inventory.Config{Pool: w.db.App, Keyring: w.keyring, Audit: w.audit, Clock: w.clock, License: w.lic,
			Registry: registryWithNginx(w.reg, caps...), Jobs: w.jobs})
		_, err := svc.CreateACMECertificate(w.ctx, w.admin, in)
		return err
	}
	require.ErrorIs(t, create(nginxCaps...), inventory.ErrACMEChallengeUnavailable)
	require.NoError(t, create(append(append([]providers.Capability{}, nginxCaps...), providers.CapHTTP01)...))
}

func (w *certWorld) dnsInput(names ...string) inventory.ACMECertificateInput {
	hook := w.hook.ID
	return inventory.ACMECertificateInput{ProviderID: w.provider.ID, Names: names, Challenge: inventory.ACMEChallengeDNS01, HookID: &hook}
}

func (w *certWorld) create(in inventory.ACMECertificateInput) inventory.ACMECertificate {
	w.t.Helper()
	c, err := w.svc.CreateACMECertificate(w.ctx, w.admin, in)
	require.NoError(w.t, err)
	return c
}

func fieldList(err error) []string {
	var ve validate.Errors
	if !errors.As(err, &ve) {
		return nil
	}
	out := []string{}
	for _, fe := range ve {
		out = append(out, fe.Field+":"+fe.Code)
	}
	return out
}

func TestACMECertificateLifecycle(t *testing.T) {
	w := newCertWorld(t)
	before := w.requests()
	c := w.create(w.dnsInput("WWW.Example.TEST", "*.example.test"))
	assert.Equal(t, before, w.requests(), "defining a certificate contacts no CA")
	assert.Equal(t, []string{"www.example.test", "*.example.test"}, c.Names, "lower case, in the given order")
	assert.Equal(t, "ecdsa_p256", c.KeyType)
	assert.Equal(t, inventory.DefaultACMERenewBeforeDays, c.RenewBeforeDays)
	assert.True(t, c.AutoRenew)
	assert.False(t, c.AutoDeploy)
	assert.Equal(t, inventory.ACMEStatePending, c.State)
	assert.Equal(t, w.account.ID, c.AccountID)
	assert.Nil(t, c.HTTPTargetID)
	assert.Nil(t, c.RunningOrderID)
	d := w.auditDetails("acme.certificate.created")
	require.Len(t, d, 1)
	assert.Equal(t, []string{"auto_deploy", "auto_renew", "challenge", "hook_id", "names", "names_count", "policy", "provider_id",
		"renew_before_days"}, detailKeys(d[0]))
	assert.Equal(t, "www.example.test,*.example.test", d[0]["names"])

	got, err := w.svc.GetACMECertificate(w.ctx, c.ID)
	require.NoError(t, err)
	assert.Equal(t, c, got)
	list, err := w.svc.ListACMECertificates(w.ctx)
	require.NoError(t, err)
	assert.Equal(t, []inventory.ACMECertificate{c}, list)

	// A patch that changes nothing writes nothing; a change names its fields.
	_, err = w.svc.UpdateACMECertificate(w.ctx, w.admin, c.ID, inventory.ACMECertificatePatch{RenewBeforeDays: ptr(30)})
	require.NoError(t, err)
	assert.Zero(t, w.audits("acme.certificate.updated"))
	u, err := w.svc.UpdateACMECertificate(w.ctx, w.admin, c.ID, inventory.ACMECertificatePatch{RenewBeforeDays: ptr(14),
		AutoDeploy: ptr(true), AutoRenew: ptr(false), KeyType: ptr("rsa_3072")})
	require.NoError(t, err)
	assert.Equal(t, 14, u.RenewBeforeDays)
	assert.True(t, u.AutoDeploy)
	assert.False(t, u.AutoRenew)
	assert.Equal(t, "rsa_3072", u.KeyType)
	d = w.auditDetails("acme.certificate.updated")
	require.Len(t, d, 1)
	assert.Equal(t, "key_type,renew_before_days,auto_renew,auto_deploy", d[0]["fields"])

	// Moving to HTTP-01 drops the hook; the server must be an Nginx server.
	web := w.seedTarget("web-1", "nginx", "web1.example.test")
	_, err = w.svc.UpdateACMECertificate(w.ctx, w.admin, c.ID, inventory.ACMECertificatePatch{Challenge: ptr("http01"), HTTPTargetID: &web})
	require.ErrorIs(t, err, inventory.ErrACMEChallengeUnavailable, "a wildcard needs DNS-01")
	h, err := w.svc.UpdateACMECertificate(w.ctx, w.admin, c.ID, inventory.ACMECertificatePatch{Challenge: ptr("http01"), HTTPTargetID: &web,
		Names: &[]string{"www.example.test"}})
	require.NoError(t, err)
	assert.Nil(t, h.HookID)
	require.NotNil(t, h.HTTPTargetID)
	assert.Equal(t, web, *h.HTTPTargetID)
	hook := w.hook.ID
	back, err := w.svc.UpdateACMECertificate(w.ctx, w.admin, c.ID, inventory.ACMECertificatePatch{Challenge: ptr("dns01"), HookID: &hook})
	require.NoError(t, err)
	assert.Nil(t, back.HTTPTargetID)

	require.NoError(t, w.svc.DeleteACMECertificate(w.ctx, w.admin, c.ID))
	_, err = w.svc.GetACMECertificate(w.ctx, c.ID)
	require.ErrorIs(t, err, inventory.ErrNotFound)
	require.ErrorIs(t, w.svc.DeleteACMECertificate(w.ctx, w.admin, c.ID), inventory.ErrNotFound)
	d = w.auditDetails("acme.certificate.deleted")
	require.Len(t, d, 1)
	assert.Equal(t, "0", d[0]["bindings_count"])
	list, err = w.svc.ListACMECertificates(w.ctx)
	require.NoError(t, err)
	assert.Empty(t, list)
	assert.NotContains(t, w.auditText(), w.fake.Credentials().HookSecret)
}

func TestACMECertificateRefusals(t *testing.T) {
	w := newCertWorld(t)
	web := w.seedTarget("web-2", "nginx", "web2.example.test")
	box := w.seedTarget("box-2", "linux", "box2.example.test")
	many := make([]string, 101)
	for i := range many {
		many[i] = fmt.Sprintf("n%d.example.test", i)
	}
	cases := []struct {
		name string
		mut  func(*inventory.ACMECertificateInput)
		want []string
	}{
		{"no names", func(in *inventory.ACMECertificateInput) { in.Names = nil }, []string{"names:" + validate.Required}},
		{"101 names", func(in *inventory.ACMECertificateInput) { in.Names = many }, []string{"names:" + validate.TooLong}},
		{"a name that is not a DNS name", func(in *inventory.ACMECertificateInput) { in.Names = []string{"bad name.example.test"} },
			[]string{"names:" + validate.Pattern}},
		{"a wildcard below the first label", func(in *inventory.ACMECertificateInput) { in.Names = []string{"a.*.example.test"} },
			[]string{"names:" + validate.Pattern}},
		{"an IP address", func(in *inventory.ACMECertificateInput) { in.Names = []string{"10.0.0.1"} }, []string{"names:" + validate.Pattern}},
		{"duplicates", func(in *inventory.ACMECertificateInput) { in.Names = []string{"a.example.test", "A.example.test"} },
			[]string{"names:" + validate.Pattern}},
		{"key type", func(in *inventory.ACMECertificateInput) { in.KeyType = "rsa_1024" }, []string{"key_type:" + validate.OneOf}},
		{"challenge", func(in *inventory.ACMECertificateInput) { in.Challenge = "tlsalpn01" }, []string{"challenge:" + validate.OneOf}},
		{"renew window", func(in *inventory.ACMECertificateInput) { in.RenewBeforeDays = 61 }, []string{"renew_before_days:" + validate.OutOfRange}},
		{"negative window", func(in *inventory.ACMECertificateInput) { in.RenewBeforeDays = -1 }, []string{"renew_before_days:" + validate.OutOfRange}},
		{"dns-01 without a hook", func(in *inventory.ACMECertificateInput) { in.HookID = nil }, []string{"hook_id:" + validate.Required}},
		{"dns-01 with a server", func(in *inventory.ACMECertificateInput) { in.HTTPTargetID = &web }, []string{"http_target_id:" + validate.Pattern}},
		{"http-01 without a server", func(in *inventory.ACMECertificateInput) { in.Challenge, in.HookID = "http01", nil },
			[]string{"http_target_id:" + validate.Required}},
		{"http-01 with a hook", func(in *inventory.ACMECertificateInput) { in.Challenge, in.HTTPTargetID = "http01", &web },
			[]string{"hook_id:" + validate.Pattern}},
		{"no provider", func(in *inventory.ACMECertificateInput) { in.ProviderID = uuid.Nil }, []string{"provider_id:" + validate.Required}},
		{"unknown provider", func(in *inventory.ACMECertificateInput) { in.ProviderID = uuid.New() }, []string{"provider_id:" + validate.Required}},
		{"unknown hook", func(in *inventory.ACMECertificateInput) { in.HookID = ptr(uuid.New()) }, []string{"hook_id:" + validate.Required}},
		{"unknown server", func(in *inventory.ACMECertificateInput) {
			in.Challenge, in.HookID, in.HTTPTargetID = "http01", nil, ptr(uuid.New())
		}, []string{"http_target_id:" + validate.Required}},
	}
	for _, tc := range cases {
		in := w.dnsInput("ok.example.test")
		tc.mut(&in)
		_, err := w.svc.CreateACMECertificate(w.ctx, w.admin, in)
		assert.Equal(t, tc.want, fieldList(err), tc.name)
	}
	refuse := func(name string, want error, in inventory.ACMECertificateInput) {
		t.Helper()
		_, err := w.svc.CreateACMECertificate(w.ctx, w.admin, in)
		assert.ErrorIs(t, err, want, name)
	}
	refuse("a wildcard over HTTP-01", inventory.ErrACMEChallengeUnavailable, inventory.ACMECertificateInput{ProviderID: w.provider.ID,
		Names: []string{"*.example.test"}, Challenge: "http01", HTTPTargetID: &web})
	refuse("HTTP-01 on a Linux server without Nginx", inventory.ErrACMEChallengeUnavailable, inventory.ACMECertificateInput{
		ProviderID: w.provider.ID, Names: []string{"www.example.test"}, Challenge: "http01", HTTPTargetID: &box})
	refuse("outside the provider's list", inventory.ErrACMENameNotAllowed, w.dnsInput("www.example.org"))
	refuse("one name outside the list refuses the whole certificate", inventory.ErrACMENameNotAllowed,
		w.dnsInput("www.example.test", "www.example.org"))
	refuse("a suffix is matched on label boundaries", inventory.ErrACMENameNotAllowed, w.dnsInput("badexample.test"))

	// The hook's own list applies to DNS-01 too.
	narrow, err := w.svc.CreateACMEHook(w.ctx, w.admin, inventory.ACMEHookInput{Name: "narrow", URL: w.fake.Credentials().HookURL,
		Secret: secrets.NewPlaintext([]byte(w.fake.Credentials().HookSecret)), AllowedSuffixes: []string{".lab.example.test"}})
	require.NoError(t, err)
	in := w.dnsInput("www.example.test")
	in.HookID = &narrow.ID
	refuse("outside the hook's list", inventory.ErrACMENameNotAllowed, in)
	in.Names = []string{"a.lab.example.test"}
	_, err = w.svc.CreateACMECertificate(w.ctx, w.admin, in)
	require.NoError(t, err, "inside both lists")
	// HTTP-01 has no hook: the provider's list alone decides.
	_, err = w.svc.CreateACMECertificate(w.ctx, w.admin, inventory.ACMECertificateInput{ProviderID: w.provider.ID,
		Names: []string{"www.example.test"}, Challenge: "http01", HTTPTargetID: &web})
	require.NoError(t, err)

	// A provider with an empty list refuses every name; one without an account cannot be used.
	empty, err := w.svc.CreateACMEProvider(w.ctx, w.admin, inventory.ACMEProviderInput{Name: "Empty", DirectoryURL: w.fake.DirectoryURL()})
	require.NoError(t, err)
	in = w.dnsInput("www.example.test")
	in.ProviderID = empty.ID
	refuse("a provider without an account", inventory.ErrACMEAccountState, in)
	noList, err := w.svc.CreateACMEProvider(w.ctx, w.admin, inventory.ACMEProviderInput{Name: "No list", DirectoryURL: w.fake.DirectoryURL(),
		CABundlePEM: string(w.fake.CAPEM())})
	require.NoError(t, err)
	w.register(noList)
	in.ProviderID = noList.ID
	refuse("an empty allow-list", inventory.ErrACMENameNotAllowed, in)

	// A deleted hook is not there.
	gone, err := w.svc.CreateACMEHook(w.ctx, w.admin, inventory.ACMEHookInput{Name: "gone", URL: w.fake.Credentials().HookURL,
		Secret: secrets.NewPlaintext([]byte(w.fake.Credentials().HookSecret)), AllowedSuffixes: []string{"example.test"}})
	require.NoError(t, err)
	require.NoError(t, w.svc.DeleteACMEHook(w.ctx, w.admin, gone.ID))
	in = w.dnsInput("www.example.test")
	in.HookID = &gone.ID
	_, err = w.svc.CreateACMECertificate(w.ctx, w.admin, in)
	assert.Equal(t, []string{"hook_id:" + validate.Required}, fieldList(err))
	assert.Equal(t, 2, w.audits("acme.certificate.created"), "only the two accepted definitions")
}

// The key policy of a certificate with bound locations cannot change (A13/M2); what an order uses cannot change while
// one runs; a delete removes the bindings.
func TestACMECertificateLocks(t *testing.T) {
	w := newCertWorld(t)
	c := w.create(w.dnsInput("lock.example.test"))
	web := w.seedTarget("web-3", "nginx", "web3.example.test")
	loc := uuid.New()
	_, err := w.db.Owner.Exec(w.ctx, `INSERT INTO certificate_locations (id, target_id, kind, cert_path, supported, first_seen_at, last_seen_at)
VALUES ($1, $2, 'server_file', '/etc/nginx/ssl/lock.crt', true, now(), now())`, loc, web)
	require.NoError(t, err)
	_, err = w.db.App.Exec(w.ctx, "INSERT INTO acme_bindings (acme_certificate_id, location_id, created_at) VALUES ($1, $2, now())", c.ID, loc)
	require.NoError(t, err)
	got, err := w.svc.GetACMECertificate(w.ctx, c.ID)
	require.NoError(t, err)
	assert.Equal(t, 1, got.Bindings)
	_, err = w.svc.UpdateACMECertificate(w.ctx, w.admin, c.ID, inventory.ACMECertificatePatch{KeyType: ptr("rsa_2048")})
	require.ErrorIs(t, err, inventory.ErrACMEKeyTypeLocked)
	_, err = w.svc.UpdateACMECertificate(w.ctx, w.admin, c.ID, inventory.ACMECertificatePatch{RenewBeforeDays: ptr(10)})
	require.NoError(t, err, "other settings still change")

	o, err := w.svc.RequestOrder(w.ctx, w.operator, c.ID, inventory.ACMEOrderTest)
	require.NoError(t, err)
	for name, p := range map[string]inventory.ACMECertificatePatch{
		"names":    {Names: &[]string{"other.example.test"}},
		"provider": {ProviderID: ptr(uuid.New())},
		"method":   {Challenge: ptr("http01"), HTTPTargetID: &web},
	} {
		_, err = w.svc.UpdateACMECertificate(w.ctx, w.admin, c.ID, p)
		assert.ErrorIs(t, err, inventory.ErrACMEOrderRunning, name)
	}
	_, err = w.svc.UpdateACMECertificate(w.ctx, w.admin, c.ID, inventory.ACMECertificatePatch{AutoDeploy: ptr(true)})
	require.NoError(t, err, "a setting no order uses changes while one runs")
	require.ErrorIs(t, w.svc.DeleteACMECertificate(w.ctx, w.admin, c.ID), inventory.ErrACMEOrderRunning)

	require.NoError(t, w.svc.FailACMEOrder(w.ctx, o.ID, "acme.hook_refused", 0))
	require.NoError(t, w.svc.DeleteACMECertificate(w.ctx, w.admin, c.ID))
	assert.Zero(t, w.count("SELECT count(*) FROM acme_bindings"))
	assert.Equal(t, "1", w.auditDetails("acme.certificate.deleted")[0]["bindings_count"])
}

func TestACMERequestOrder(t *testing.T) {
	w := newCertWorld(t)
	c := w.create(w.dnsInput("order.example.test"))
	before := w.requests()

	o, err := w.svc.RequestOrder(w.ctx, w.operator, c.ID, inventory.ACMEOrderIssue)
	require.NoError(t, err)
	assert.Equal(t, inventory.ACMEOrderRunning, o.State)
	assert.Equal(t, inventory.ACMEOrderIssue, o.Kind)
	assert.Equal(t, w.operator.UserID, *o.RequestedBy)
	assert.Equal(t, before, w.requests(), "requesting contacts no CA: the job does")
	reqs := w.jobs.requests()
	require.Len(t, reqs, 1)
	assert.Equal(t, inventory.JobACMEIssue, reqs[0].Type)
	assert.Equal(t, map[string]string{"order_id": o.ID.String(), "acme_certificate_id": c.ID.String()}, reqs[0].Payload, "ids only")
	assert.Equal(t, "acme.issue:"+c.ID.String(), reqs[0].DedupeKey)
	assert.Equal(t, "user", reqs[0].Kind)
	assert.Equal(t, string(rbac.Operator), reqs[0].CreatedByRole)
	d := w.auditDetails("acme.order.started")
	require.Len(t, d, 1)
	assert.Equal(t, map[string]string{"order_id": o.ID.String(), "acme_certificate_id": c.ID.String(), "kind": "issue",
		"provider_id": w.provider.ID.String(), "trigger": "manual"}, d[0])
	assert.Equal(t, inventory.ACMETriggerManual, o.Trigger)
	got, err := w.svc.GetACMECertificate(w.ctx, c.ID)
	require.NoError(t, err)
	assert.Equal(t, inventory.ACMEStateIssuing, got.State)
	assert.Equal(t, o.ID, *got.RunningOrderID)

	_, err = w.svc.RequestOrder(w.ctx, w.operator, c.ID, inventory.ACMEOrderTest)
	require.ErrorIs(t, err, inventory.ErrACMEOrderRunning)
	_, err = w.svc.RequestOrder(w.ctx, w.operator, c.ID, "renew")
	assert.Equal(t, []string{"kind:" + validate.OneOf}, fieldList(err))
	_, err = w.svc.RequestOrder(w.ctx, w.operator, uuid.New(), inventory.ACMEOrderIssue)
	require.ErrorIs(t, err, inventory.ErrNotFound)

	list, err := w.svc.ListACMEOrders(w.ctx, c.ID, 0)
	require.NoError(t, err)
	require.Len(t, list, 1)
	assert.Equal(t, o, list[0])
	g, err := w.svc.GetACMEOrder(w.ctx, o.ID)
	require.NoError(t, err)
	assert.Equal(t, o, g)
	_, err = w.svc.ListACMEOrders(w.ctx, uuid.New(), 0)
	require.ErrorIs(t, err, inventory.ErrNotFound)

	// The job of the previous order still finishing holds the dedupe key: the same answer.
	require.NoError(t, w.svc.FailACMEOrder(w.ctx, o.ID, "acme.hook_refused", 0))
	w.jobs.fail = inventory.ErrJobConflict
	_, err = w.svc.RequestOrder(w.ctx, w.operator, c.ID, inventory.ACMEOrderIssue)
	require.ErrorIs(t, err, inventory.ErrACMEOrderRunning)
}

// In lock nothing is recorded and no CA is contacted; a provider without an active account or with an unsettled key
// change cannot order.
func TestACMERequestOrderRefusals(t *testing.T) {
	w := newCertWorld(t)
	c := w.create(w.dnsInput("refuse.example.test"))
	w.fake.ClearRequests()
	before := w.requests()
	w.lic.locked.Store(true)
	_, err := w.svc.RequestOrder(w.ctx, w.operator, c.ID, inventory.ACMEOrderIssue)
	require.ErrorIs(t, err, license.ErrLocked)
	assert.Zero(t, w.count("SELECT count(*) FROM acme_orders"))
	assert.Empty(t, w.jobs.requests())
	assert.Equal(t, before, w.requests())
	assert.Empty(t, w.fake.Requests())
	w.lic.locked.Store(false)

	_, err = w.db.Owner.Exec(w.ctx, `INSERT INTO acme_accounts (id, provider_id, key_ct, key_nonce, key_wrapped_dek, key_version, state,
pending_since, created_at, updated_at) VALUES ($1, $2, '\x01', decode(repeat('00', 12), 'hex'), '\x02', 1, 'pending_rollover', now(), now(), now())`,
		uuid.New(), w.provider.ID)
	require.NoError(t, err)
	_, err = w.svc.RequestOrder(w.ctx, w.operator, c.ID, inventory.ACMEOrderIssue)
	require.ErrorIs(t, err, inventory.ErrACMERolloverPending)
	_, err = w.db.Owner.Exec(w.ctx, "DELETE FROM acme_accounts WHERE state = 'pending_rollover'")
	require.NoError(t, err)

	_, err = w.svc.DeactivateACMEAccount(w.ctx, w.admin, w.account.ID)
	require.NoError(t, err)
	_, err = w.svc.RequestOrder(w.ctx, w.operator, c.ID, inventory.ACMEOrderIssue)
	require.ErrorIs(t, err, inventory.ErrACMEAccountState)
	assert.Zero(t, w.count("SELECT count(*) FROM acme_orders"))
}

// Many concurrent requests for one certificate start one order (the certificate's row lock and the unique index).
func TestACMEConcurrentRequestsMakeOneOrder(t *testing.T) {
	w := newCertWorld(t)
	c := w.create(w.dnsInput("race.example.test"))
	var wg sync.WaitGroup
	var ok, running atomic.Int32
	for range 12 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := w.svc.RequestOrder(w.ctx, w.operator, c.ID, inventory.ACMEOrderIssue)
			switch {
			case err == nil:
				ok.Add(1)
			case errors.Is(err, inventory.ErrACMEOrderRunning):
				running.Add(1)
			default:
				t.Errorf("unexpected error: %v", err)
			}
		}()
	}
	wg.Wait()
	assert.EqualValues(t, 1, ok.Load())
	assert.EqualValues(t, 11, running.Load())
	assert.Equal(t, 1, w.count("SELECT count(*) FROM acme_orders"))
	assert.Equal(t, 1, w.audits("acme.order.started"))
}

// FailACMEOrder writes the failure state the renewal planner reads: failures, the error, the attempt and the next
// attempt by the backoff table or the CA's Retry-After (capped at 24 h); a test run only honours a Retry-After.
func TestACMEFailureState(t *testing.T) {
	w := newCertWorld(t)
	c := w.create(w.dnsInput("fail.example.test"))
	state := func() inventory.ACMECertificate {
		got, err := w.svc.GetACMECertificate(w.ctx, c.ID)
		require.NoError(t, err)
		return got
	}
	fail := func(kind, code string, after time.Duration) {
		t.Helper()
		o, err := w.svc.RequestOrder(w.ctx, w.operator, c.ID, kind)
		require.NoError(t, err)
		require.NoError(t, w.svc.FailACMEOrder(w.ctx, o.ID, code, after))
		require.NoError(t, w.svc.FailACMEOrder(w.ctx, o.ID, code, after), "failing it again changes nothing")
	}
	now := w.clock.Now().UTC()
	fail(inventory.ACMEOrderIssue, "acme.validation_failed_dns", 0)
	s := state()
	assert.Equal(t, 1, s.Failures)
	assert.Equal(t, inventory.ACMEStateFailing, s.State)
	assert.Equal(t, "acme.validation_failed_dns", s.LastErrorCode)
	assert.Equal(t, now, *s.LastAttemptAt)
	assert.Equal(t, now.Add(time.Hour), *s.NextAttemptAt)
	fail(inventory.ACMEOrderIssue, "acme.hook_refused", 0)
	assert.Equal(t, now.Add(2*time.Hour), *state().NextAttemptAt)
	fail(inventory.ACMEOrderIssue, "acme.ca_rate_limited", 5*time.Hour)
	s = state()
	assert.Equal(t, 3, s.Failures)
	assert.Equal(t, now.Add(5*time.Hour), *s.NextAttemptAt, "the CA's Retry-After when it is longer than the backoff")
	fail(inventory.ACMEOrderIssue, "acme.ca_rate_limited", 72*time.Hour)
	assert.Equal(t, now.Add(24*time.Hour), *state().NextAttemptAt, "capped at 24 h")

	// A test run: no failure counted; a Retry-After only pushes the next attempt later.
	fail(inventory.ACMEOrderTest, "acme.validation_failed_dns", 0)
	s = state()
	assert.Equal(t, 4, s.Failures)
	assert.Equal(t, "acme.ca_rate_limited", s.LastErrorCode)
	fail(inventory.ACMEOrderTest, "acme.ca_rate_limited", time.Hour)
	assert.Equal(t, now.Add(24*time.Hour), *state().NextAttemptAt, "never earlier than it was")
	_, err := w.db.Owner.Exec(w.ctx, "UPDATE acme_certificates SET next_attempt_at = NULL, state = 'stopped' WHERE id = $1", c.ID)
	require.NoError(t, err)
	fail(inventory.ACMEOrderTest, "acme.ca_rate_limited", 3*time.Hour)
	assert.Equal(t, now.Add(3*time.Hour), *state().NextAttemptAt)
	fail(inventory.ACMEOrderIssue, "acme.hook_refused", 0)
	assert.Equal(t, inventory.ACMEStateStopped, state().State, "a stopped certificate stays stopped")

	assert.Equal(t, 5, w.audits("acme.order.failed"))
	assert.Equal(t, 3, w.audits("acme.order.test_failed"))
	require.ErrorIs(t, w.svc.FailACMEOrder(w.ctx, uuid.New(), "acme.hook_refused", 0), inventory.ErrNotFound)
	require.ErrorIs(t, w.svc.FailACMEOrder(w.ctx, uuid.New(), "not a code", 0), inventory.ErrACMEErrorCode)
}

// The presented list: a record is persisted before it is published and taken out once it is removed; an ended order
// with records left gets one cleanup job, and the cleanup's outcome is recorded with its audit rows.
func TestACMEPresentedRecordsAndCleanupBookkeeping(t *testing.T) {
	w := newCertWorld(t)
	c := w.create(w.dnsInput("rec.example.test"))
	o, err := w.svc.RequestOrder(w.ctx, w.operator, c.ID, inventory.ACMEOrderTest)
	require.NoError(t, err)
	hook := w.hook.ID
	rec := func(v string) inventory.ACMEPresented {
		return inventory.ACMEPresented{Challenge: solver.Challenge{Type: solver.DNS01, Domain: "rec.example.test", Token: "tok",
			DNSName: "_acme-challenge.rec.example.test", DNSValue: v}, HookID: &hook}
	}
	require.NoError(t, w.svc.RecordACMEOrderURL(w.ctx, o.ID, "https://ca.example.test/order/1"))
	require.NoError(t, w.svc.AddACMEPresented(w.ctx, o.ID, rec("a")))
	require.NoError(t, w.svc.AddACMEPresented(w.ctx, o.ID, rec("b")))
	require.NoError(t, w.svc.AddACMEPresented(w.ctx, o.ID, rec("c")))
	require.NoError(t, w.svc.RemoveACMEPresented(w.ctx, o.ID, rec("b")))
	require.NoError(t, w.svc.RemoveACMEPresented(w.ctx, o.ID, rec("zz")), "a record that is not listed changes nothing")
	work, err := w.svc.ACMECleanupWork(w.ctx, o.ID)
	require.NoError(t, err)
	assert.True(t, work.Running)
	assert.Empty(t, work.Records, "a running order is its job's to clean up")
	require.NoError(t, w.svc.EnqueueACMECleanup(w.ctx, o.ID))
	assert.Len(t, w.jobs.requests(), 1, "no cleanup for a running order")

	require.NoError(t, w.svc.FailACMEOrder(w.ctx, o.ID, "acme.hook_refused", 0))
	reqs := w.jobs.requests()
	require.Len(t, reqs, 2)
	assert.Equal(t, inventory.JobACMECleanup, reqs[1].Type)
	assert.Equal(t, map[string]string{"order_id": o.ID.String()}, reqs[1].Payload)
	assert.Equal(t, "acme.cleanup:"+o.ID.String(), reqs[1].DedupeKey)
	require.ErrorIs(t, w.svc.AddACMEPresented(w.ctx, o.ID, rec("d")), inventory.ErrACMEOrderNotRunning, "an ended order never gains one")
	require.ErrorIs(t, w.svc.RecordACMEOrderURL(w.ctx, o.ID, "https://x"), inventory.ErrACMEOrderNotRunning)

	work, err = w.svc.ACMECleanupWork(w.ctx, o.ID)
	require.NoError(t, err)
	assert.False(t, work.Running)
	assert.Equal(t, []inventory.ACMEPresented{rec("a"), rec("c")}, work.Records)
	g, err := w.svc.GetACMEOrder(w.ctx, o.ID)
	require.NoError(t, err)
	assert.Equal(t, 2, g.Presented)

	require.NoError(t, w.svc.RecordACMECleanup(w.ctx, o.ID, "acme.hook_refused", false))
	assert.Zero(t, w.audits("acme.order.cleanup_failed"), "an intermediate failure is only recorded on the order")
	require.NoError(t, w.svc.RecordACMECleanup(w.ctx, o.ID, "acme.hook_refused", true))
	d := w.auditDetails("acme.order.cleanup_failed")
	require.Len(t, d, 1)
	assert.Equal(t, map[string]string{"order_id": o.ID.String(), "acme_certificate_id": c.ID.String(), "records_count": "2",
		"error_code": "acme.hook_refused"}, d[0])
	g, err = w.svc.GetACMEOrder(w.ctx, o.ID)
	require.NoError(t, err)
	assert.Equal(t, "acme.hook_refused", g.CleanupErrorCode)
	require.NotNil(t, g.CleanupAt)

	// The sweep queues a cleanup again only after the retry wait.
	n, err := w.svc.EnqueueACMECleanups(w.ctx, time.Hour, 7*24*time.Hour)
	require.NoError(t, err)
	assert.Zero(t, n)
	w.clock.Advance(61 * time.Minute)
	n, err = w.svc.EnqueueACMECleanups(w.ctx, time.Hour, 7*24*time.Hour)
	require.NoError(t, err)
	assert.Equal(t, 1, n)
	n, err = w.svc.EnqueueACMECleanups(w.ctx, time.Hour, time.Hour)
	require.NoError(t, err)
	assert.Zero(t, n, "given up on an order that ended longer ago than the limit")

	require.NoError(t, w.svc.RemoveACMEPresented(w.ctx, o.ID, rec("a")))
	require.NoError(t, w.svc.RemoveACMEPresented(w.ctx, o.ID, rec("c")))
	require.NoError(t, w.svc.RecordACMECleanup(w.ctx, o.ID, "", true))
	assert.Equal(t, 1, w.audits("acme.order.cleaned_up"))
	g, err = w.svc.GetACMEOrder(w.ctx, o.ID)
	require.NoError(t, err)
	assert.Zero(t, g.Presented)
	assert.Empty(t, g.CleanupErrorCode)
	require.ErrorIs(t, w.svc.RecordACMECleanup(w.ctx, o.ID, "not a code", true), inventory.ErrACMEErrorCode)
	_, err = w.svc.ACMECleanupWork(w.ctx, uuid.New())
	require.ErrorIs(t, err, inventory.ErrNotFound)
}

// A running order no job holds is stale once it is older than the bound; a test run is succeeded with its audit row.
func TestACMEStaleOrdersAndTestSuccess(t *testing.T) {
	w := newCertWorld(t)
	c := w.create(w.dnsInput("stale.example.test"))
	o, err := w.svc.RequestOrder(w.ctx, w.operator, c.ID, inventory.ACMEOrderTest)
	require.NoError(t, err)
	stale, err := w.svc.StaleACMEOrders(w.ctx, 20*time.Minute)
	require.NoError(t, err)
	assert.Empty(t, stale)
	w.clock.Advance(21 * time.Minute)
	stale, err = w.svc.StaleACMEOrders(w.ctx, 20*time.Minute)
	require.NoError(t, err)
	require.Len(t, stale, 1)
	assert.Equal(t, o.ID, stale[0].ID)
	assert.Equal(t, []string{"stale.example.test"}, stale[0].Names)
	assert.False(t, stale[0].HasKey)

	require.NoError(t, w.svc.SucceedACMETestOrder(w.ctx, o.ID))
	require.ErrorIs(t, w.svc.SucceedACMETestOrder(w.ctx, o.ID), inventory.ErrACMEOrderNotRunning)
	require.ErrorIs(t, w.svc.SucceedACMETestOrder(w.ctx, uuid.New()), inventory.ErrNotFound)
	d := w.auditDetails("acme.order.test_succeeded")
	require.Len(t, d, 1)
	assert.Equal(t, map[string]string{"order_id": o.ID.String(), "acme_certificate_id": c.ID.String(), "kind": "test"}, d[0])
	got, err := w.svc.GetACMECertificate(w.ctx, c.ID)
	require.NoError(t, err)
	assert.Equal(t, inventory.ACMEStatePending, got.State, "a test run is not a renewal")
	assert.Zero(t, got.Failures)
	stale, err = w.svc.StaleACMEOrders(w.ctx, 20*time.Minute)
	require.NoError(t, err)
	assert.Empty(t, stale)

	issue, err := w.svc.RequestOrder(w.ctx, w.operator, c.ID, inventory.ACMEOrderIssue)
	require.NoError(t, err)
	require.ErrorIs(t, w.svc.SucceedACMETestOrder(w.ctx, issue.ID), inventory.ErrACMEOrderNotRunning, "an issue order is finished with its certificate")
}

// ACMEOrderClient signs with the provider's CURRENT active account: a certificate that still names an older account
// is moved to it; without an active account the order cannot run. The e2e trust seam (Config.ACMERoots) replaces the
// system roots for every CA connection.
func TestACMEOrderClientAndTrustSeam(t *testing.T) {
	w := newCertWorld(t)
	c := w.create(w.dnsInput("client.example.test"))
	o, err := w.svc.RequestOrder(w.ctx, w.operator, c.ID, inventory.ACMEOrderTest)
	require.NoError(t, err)
	client, err := w.svc.ACMEOrderClient(w.ctx, o.ID)
	require.NoError(t, err)
	assert.Equal(t, w.account.AccountURL, client.AccountURL())

	// A rollover moved the certificate already; an old row reference is repointed here too.
	other := uuid.New()
	_, err = w.db.Owner.Exec(w.ctx, `INSERT INTO acme_accounts (id, provider_id, key_ct, key_nonce, key_wrapped_dek, key_version, state, created_at,
updated_at) VALUES ($1, $2, '\x01', decode(repeat('00', 12), 'hex'), '\x02', 1, 'retired', now(), now())`, other, w.provider.ID)
	require.NoError(t, err)
	_, err = w.db.Owner.Exec(w.ctx, "UPDATE acme_certificates SET account_id = $2 WHERE id = $1", c.ID, other)
	require.NoError(t, err)
	_, err = w.svc.ACMEOrderClient(w.ctx, o.ID)
	require.NoError(t, err)
	got, err := w.svc.GetACMECertificate(w.ctx, c.ID)
	require.NoError(t, err)
	assert.Equal(t, w.account.ID, got.AccountID)

	_, err = w.svc.ACMEOrderClient(w.ctx, uuid.New())
	require.ErrorIs(t, err, inventory.ErrNotFound)
	require.NoError(t, w.svc.FailACMEOrder(w.ctx, o.ID, "acme.hook_refused", 0))
	_, err = w.svc.ACMEOrderClient(w.ctx, o.ID)
	require.ErrorIs(t, err, inventory.ErrACMEOrderNotRunning)

	// The seam: a provider with no bundle is trusted through Config.ACMERoots only.
	block, _ := pem.Decode(w.fake.CAPEM())
	ca, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	var calls atomic.Int32
	seamed := inventory.New(inventory.Config{Pool: w.db.App, Keyring: w.keyring, Audit: w.audit, Clock: w.clock, License: w.lic,
		Registry: w.reg, Jobs: w.jobs, ACMERoots: func() (*x509.CertPool, error) { calls.Add(1); return pool, nil }})
	bare, err := seamed.CreateACMEProvider(w.ctx, w.admin, inventory.ACMEProviderInput{Name: "Bare", DirectoryURL: w.fake.DirectoryURL(),
		AllowedSuffixes: []string{"example.test"}})
	require.NoError(t, err)
	_, err = w.svc.RegisterACMEAccount(w.ctx, w.admin, bare.ID, "", true)
	assert.Equal(t, acme.ReasonTLSTrustFailed, reasonOf(err), "without the seam the fake CA is not trusted")
	_, err = seamed.RegisterACMEAccount(w.ctx, w.admin, bare.ID, "", true)
	require.NoError(t, err)
	assert.Positive(t, calls.Load())
	cfg, err := seamed.ACMEHookSolverConfig(w.ctx, w.hook.ID)
	require.NoError(t, err)
	cfg.Secret.Zero()
	assert.Same(t, pool, cfg.BaseRoots, "the hook's transport gets the same trust")
	broken := inventory.New(inventory.Config{Pool: w.db.App, Keyring: w.keyring, Audit: w.audit, Clock: w.clock, License: w.lic,
		Registry: w.reg, Jobs: w.jobs, ACMERoots: func() (*x509.CertPool, error) { return nil, errors.New("no file") }})
	_, err = broken.ACMEHookSolverConfig(w.ctx, w.hook.ID)
	assert.Equal(t, acme.ReasonTLSTrustFailed, reasonOf(err), "an unreadable trust file fails closed")
	assert.False(t, strings.Contains(fmt.Sprint(err), "no file"))
}

// What the acme.issue job reads: the order with its names, method and the allow-lists in force now; the order's key
// in its own transaction; a deleted hook's configuration for the cleanup of what it published.
func TestACMEOrderWorkAndKey(t *testing.T) {
	w := newCertWorld(t)
	c := w.create(w.dnsInput("work.example.test"))
	o, err := w.svc.RequestOrder(w.ctx, w.operator, c.ID, inventory.ACMEOrderIssue)
	require.NoError(t, err)
	work, err := w.svc.ACMEOrderWork(w.ctx, o.ID)
	require.NoError(t, err)
	assert.Equal(t, o, work.Order)
	assert.Equal(t, []string{"work.example.test"}, work.Names)
	assert.Equal(t, inventory.ACMEChallengeDNS01, work.Challenge)
	assert.Equal(t, w.hook.ID, *work.HookID)
	assert.Equal(t, w.provider.ID, work.ProviderID)
	assert.False(t, work.HasKey)
	assert.Empty(t, work.OrderURL)
	assert.True(t, work.NamesAllowed())
	work.HookSuffixes = []string{"other.test"}
	assert.False(t, work.NamesAllowed(), "the hook's list applies to DNS-01")
	work.Challenge = inventory.ACMEChallengeHTTP01
	assert.True(t, work.NamesAllowed(), "and only to DNS-01")
	work.ProviderSuffixes = nil
	assert.False(t, work.NamesAllowed())
	_, err = w.svc.ACMEOrderWork(w.ctx, uuid.New())
	require.ErrorIs(t, err, inventory.ErrNotFound)

	signer, err := w.svc.NewACMEOrderKey(w.ctx, o.ID)
	require.NoError(t, err)
	assert.NotNil(t, signer)
	work, err = w.svc.ACMEOrderWork(w.ctx, o.ID)
	require.NoError(t, err)
	assert.True(t, work.HasKey)
	_, err = w.svc.NewACMEOrderKey(w.ctx, o.ID)
	require.ErrorIs(t, err, inventory.ErrACMEPendingKey)
	_, err = w.svc.NewACMEOrderKey(w.ctx, uuid.New())
	require.ErrorIs(t, err, inventory.ErrNotFound)
	require.ErrorIs(t, w.svc.RecordACMEOrderURL(w.ctx, o.ID, "https://"+strings.Repeat("a", 2100)), inventory.ErrACMEOrderNotRunning)
	stale, err := w.svc.StaleACMEOrders(w.ctx, -time.Minute)
	require.NoError(t, err)
	require.Len(t, stale, 1)
	assert.True(t, stale[0].HasKey)
	require.NoError(t, w.svc.FailACMEOrder(w.ctx, o.ID, "acme.hook_refused", 0))
	assert.Zero(t, w.count("SELECT count(*) FROM acme_orders WHERE pending_key_ct IS NOT NULL"))

	// The cleanup reads a deleted hook; an order reads only a live one.
	require.NoError(t, w.svc.DeleteACMECertificate(w.ctx, w.admin, c.ID))
	require.NoError(t, w.svc.DeleteACMEHook(w.ctx, w.admin, w.hook.ID))
	_, err = w.svc.ACMEHookSolverConfig(w.ctx, w.hook.ID)
	require.ErrorIs(t, err, inventory.ErrNotFound)
	cfg, err := w.svc.ACMEHookCleanupConfig(w.ctx, w.hook.ID)
	require.NoError(t, err)
	assert.Equal(t, w.fake.Credentials().HookSecret, string(cfg.Secret.Bytes()))
	cfg.Secret.Zero()
	_, err = w.svc.ACMEHookCleanupConfig(w.ctx, uuid.New())
	require.ErrorIs(t, err, inventory.ErrNotFound)
}

// waitForLockWaiter waits until a session of the database waits for a row lock (the other side of an interleaving).
func (w *certWorld) waitForLockWaiter() {
	w.t.Helper()
	deadline := time.Now().Add(10 * time.Second) //nolint:forbidigo // a wall-clock bound for a database wait
	for time.Now().Before(deadline) {            //nolint:forbidigo // see above
		if w.count("SELECT count(*) FROM pg_stat_activity WHERE wait_event_type = 'Lock' AND datname = current_database()") > 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	w.t.Fatal("no session waited for the row lock")
}

// I1: an Update or Delete that waits for the certificate's row lock while a RequestOrder transaction (or a binding)
// commits sees that order (or binding): the change is refused, never both.
func TestACMEChangesSeeAConcurrentOrder(t *testing.T) {
	w := newCertWorld(t)
	web := w.seedTarget("web-race", "nginx", "race.example.test")
	for _, tc := range []struct {
		name    string
		binding bool
		change  func(id uuid.UUID) error
		want    error
	}{
		{"names change vs order", false, func(id uuid.UUID) error {
			_, err := w.svc.UpdateACMECertificate(w.ctx, w.admin, id, inventory.ACMECertificatePatch{Names: &[]string{"other.example.test"}})
			return err
		}, inventory.ErrACMEOrderRunning},
		{"delete vs order", false, func(id uuid.UUID) error { return w.svc.DeleteACMECertificate(w.ctx, w.admin, id) }, inventory.ErrACMEOrderRunning},
		{"key type vs binding", true, func(id uuid.UUID) error {
			_, err := w.svc.UpdateACMECertificate(w.ctx, w.admin, id, inventory.ACMECertificatePatch{KeyType: ptr("rsa_2048")})
			return err
		}, inventory.ErrACMEKeyTypeLocked},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := w.create(w.dnsInput(strings.ReplaceAll(tc.name, " ", "-") + ".example.test"))
			tx, err := w.db.App.Begin(w.ctx)
			require.NoError(t, err)
			defer func() { _ = tx.Rollback(w.ctx) }()
			_, err = tx.Exec(w.ctx, "SELECT 1 FROM acme_certificates WHERE id = $1 FOR UPDATE", c.ID)
			require.NoError(t, err)
			if tc.binding {
				loc := uuid.New()
				_, err = w.db.Owner.Exec(w.ctx, `INSERT INTO certificate_locations (id, target_id, kind, cert_path, supported, first_seen_at, last_seen_at)
VALUES ($1, $2, 'server_file', $3, true, now(), now())`, loc, web, "/etc/nginx/ssl/"+loc.String()+".crt")
				require.NoError(t, err)
				_, err = tx.Exec(w.ctx, "INSERT INTO acme_bindings (acme_certificate_id, location_id, created_at) VALUES ($1, $2, now())", c.ID, loc)
			} else {
				_, err = tx.Exec(w.ctx, "INSERT INTO acme_orders (id, acme_certificate_id, kind, state, started_at) VALUES ($1, $2, 'issue', 'running', now())",
					uuid.New(), c.ID)
			}
			require.NoError(t, err)
			done := make(chan error, 1)
			go func() { done <- tc.change(c.ID) }()
			w.waitForLockWaiter()
			require.NoError(t, tx.Commit(w.ctx))
			require.ErrorIs(t, <-done, tc.want)
			got, err := w.svc.GetACMECertificate(w.ctx, c.ID)
			require.NoError(t, err, "not deleted")
			assert.Equal(t, c.Names, got.Names)
			assert.Equal(t, c.KeyType, got.KeyType)
		})
	}
}

// M6: an order's key is generated with no database connection held (the slot wait and the generation run outside
// any transaction), so a pool of one connection is never starved by key generation.
func TestACMEOrderKeyHoldsNoConnectionWhileGenerating(t *testing.T) {
	w := newCertWorld(t)
	cfg := w.db.App.Config().Copy()
	cfg.MaxConns = 1
	tiny, err := pgxpool.NewWithConfig(w.ctx, cfg)
	require.NoError(t, err)
	t.Cleanup(tiny.Close)
	svc := inventory.New(inventory.Config{Pool: tiny, Keyring: w.keyring, Audit: w.audit, Clock: w.clock, License: w.lic,
		Registry: w.reg, Jobs: w.jobs})
	var held []int32
	var mu sync.Mutex
	inventory.SetKeygenSeam(svc, func() {
		mu.Lock()
		held = append(held, tiny.Stat().AcquiredConns())
		mu.Unlock()
	})
	var orders []uuid.UUID
	for i := range 3 {
		c := w.create(w.dnsInput(fmt.Sprintf("tiny%d.example.test", i)))
		_, err := w.db.Owner.Exec(w.ctx, "UPDATE acme_certificates SET key_type = 'rsa_3072' WHERE id = $1", c.ID)
		require.NoError(t, err)
		o, err := w.svc.RequestOrder(w.ctx, w.operator, c.ID, inventory.ACMEOrderIssue)
		require.NoError(t, err)
		orders = append(orders, o.ID)
	}
	_, err = svc.NewACMEOrderKey(w.ctx, orders[0])
	require.NoError(t, err)
	require.Equal(t, []int32{0}, held, "no connection is held while the key is generated")

	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for _, id := range orders[1:] {
		wg.Add(1)
		go func() { defer wg.Done(); _, err := svc.NewACMEOrderKey(w.ctx, id); errs <- err }()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err, "two keys on a one-connection pool")
	}
	assert.Equal(t, 3, w.count("SELECT count(*) FROM acme_orders WHERE pending_key_ct IS NOT NULL"))
}

// A database that cannot be reached: every ACME read and write answers with an error (never a panic, never a
// half-written row), and nothing reaches a CA.
func TestACMEWithoutADatabase(t *testing.T) {
	w := newCertWorld(t)
	cfg := w.db.App.Config().Copy()
	cfg.ConnConfig.Host, cfg.ConnConfig.Port = "127.0.0.1", 1
	cfg.ConnConfig.ConnectTimeout = time.Second
	gone, err := pgxpool.NewWithConfig(w.ctx, cfg)
	require.NoError(t, err)
	t.Cleanup(gone.Close)
	svc := inventory.New(inventory.Config{Pool: gone, Keyring: w.keyring, Audit: w.audit, Clock: w.clock, License: w.lic,
		Registry: w.reg, Jobs: w.jobs})
	before := w.requests()
	id := uuid.New()
	hook := w.hook.ID
	in := w.dnsInput("gone.example.test")
	ctx := w.ctx
	calls := map[string]func() error{
		"get certificate":   func() error { _, err := svc.GetACMECertificate(ctx, id); return err },
		"list certificates": func() error { _, err := svc.ListACMECertificates(ctx); return err },
		"create":            func() error { _, err := svc.CreateACMECertificate(ctx, w.admin, in); return err },
		"update": func() error {
			_, err := svc.UpdateACMECertificate(ctx, w.admin, id, inventory.ACMECertificatePatch{AutoDeploy: ptr(true)})
			return err
		},
		"delete":        func() error { return svc.DeleteACMECertificate(ctx, w.admin, id) },
		"request":       func() error { _, err := svc.RequestOrder(ctx, w.operator, id, inventory.ACMEOrderIssue); return err },
		"plan renewals": func() error { _, err := svc.PlanACMERenewals(ctx); return err },
		"get order":     func() error { _, err := svc.GetACMEOrder(ctx, id); return err },
		"list orders":   func() error { _, err := svc.ListACMEOrders(ctx, id, 5); return err },
		"order work":    func() error { _, err := svc.ACMEOrderWork(ctx, id); return err },
		"order client":  func() error { _, err := svc.ACMEOrderClient(ctx, id); return err },
		"order url":     func() error { return svc.RecordACMEOrderURL(ctx, id, "https://ca.example.test/o") },
		"add record":    func() error { return svc.AddACMEPresented(ctx, id, inventory.ACMEPresented{HookID: &hook}) },
		"remove record": func() error {
			return svc.RemoveACMEPresented(ctx, id, inventory.ACMEPresented{HookID: &hook})
		},
		"test success":   func() error { return svc.SucceedACMETestOrder(ctx, id) },
		"fail":           func() error { return svc.FailACMEOrder(ctx, id, "acme.hook_refused", 0) },
		"abort":          func() error { return svc.AbortACMEOrder(ctx, id, "acme.hook_refused") },
		"cleanup":        func() error { return svc.EnqueueACMECleanup(ctx, id) },
		"cleanup work":   func() error { _, err := svc.ACMECleanupWork(ctx, id); return err },
		"record cleanup": func() error { return svc.RecordACMECleanup(ctx, id, "", true) },
		"stale":          func() error { _, err := svc.StaleACMEOrders(ctx, time.Minute); return err },
		"cleanups":       func() error { _, err := svc.EnqueueACMECleanups(ctx, time.Hour, time.Hour); return err },
		"new key":        func() error { _, err := svc.NewACMEOrderKey(ctx, id); return err },
		"load key":       func() error { _, err := svc.LoadPendingKey(ctx, id); return err },
		"finish":         func() error { _, err := svc.FinishACMEOrder(ctx, id, [][]byte{{1}}); return err },
		"hook config":    func() error { _, err := svc.ACMEHookSolverConfig(ctx, hook); return err },
		"hook cleanup":   func() error { _, err := svc.ACMEHookCleanupConfig(ctx, hook); return err },
		"get account":    func() error { _, err := svc.GetACMEAccount(ctx, id); return err },
		"list accounts":  func() error { _, err := svc.ListACMEAccounts(ctx, id); return err },
		"signer":         func() error { _, _, err := svc.ACMEAccountSigner(ctx, id); return err },
		"list hooks":     func() error { _, err := svc.ListACMEHooks(ctx); return err },
		"get hook":       func() error { _, err := svc.GetACMEHook(ctx, id); return err },
		"list providers": func() error { _, err := svc.ListACMEProviders(ctx); return err },
		"get provider":   func() error { _, err := svc.GetACMEProvider(ctx, id); return err },
		"delete hook":    func() error { return svc.DeleteACMEHook(ctx, w.admin, id) },
		"delete provider": func() error {
			return svc.DeleteACMEProvider(ctx, w.admin, id)
		},
		"register": func() error { _, err := svc.RegisterACMEAccount(ctx, w.admin, id, "", true); return err },
		"rollover": func() error { _, err := svc.RolloverACMEAccount(ctx, w.admin, id); return err },
		"recover":  func() error { _, err := svc.RecoverACMERollover(ctx, w.admin, id); return err },
		"deactivate": func() error {
			_, err := svc.DeactivateACMEAccount(ctx, w.admin, id)
			return err
		},
	}
	for name, call := range calls {
		err := call()
		assert.Error(t, err, name)
		assert.NotErrorIs(t, err, inventory.ErrNotFound, name)
	}
	assert.Equal(t, before, w.requests(), "no CA was contacted")
}

// The provider or account an order needs went away after the definition was made.
func TestACMEOrderWithoutItsProvider(t *testing.T) {
	w := newCertWorld(t)
	c := w.create(w.dnsInput("noprov.example.test"))
	require.ErrorIs(t, w.svc.DeleteACMEHook(w.ctx, w.admin, w.hook.ID), inventory.ErrACMEHookInUse)
	_, err := w.svc.CreateACMEHook(w.ctx, w.admin, inventory.ACMEHookInput{Name: "DNS", URL: w.fake.Credentials().HookURL,
		Secret: secrets.NewPlaintext([]byte(w.fake.Credentials().HookSecret)), AllowedSuffixes: []string{"example.test"}})
	require.ErrorIs(t, err, inventory.ErrACMENameTaken, "hook names are unique, case-insensitively")

	o, err := w.svc.RequestOrder(w.ctx, w.operator, c.ID, inventory.ACMEOrderTest)
	require.NoError(t, err)
	_, err = w.db.Owner.Exec(w.ctx, "UPDATE acme_accounts SET state = 'retired' WHERE id = $1", w.account.ID)
	require.NoError(t, err)
	_, err = w.svc.ACMEOrderClient(w.ctx, o.ID)
	require.ErrorIs(t, err, inventory.ErrACMEAccountState, "no active account")
	_, err = w.db.Owner.Exec(w.ctx, "UPDATE acme_providers SET deleted_at = now() WHERE id = $1", w.provider.ID)
	require.NoError(t, err)
	_, err = w.svc.ACMEOrderClient(w.ctx, o.ID)
	require.ErrorIs(t, err, inventory.ErrACMEAccountState, "a deleted provider")
	require.NoError(t, w.svc.FailACMEOrder(w.ctx, o.ID, "acme.account_state", 0))
	_, err = w.svc.RequestOrder(w.ctx, w.operator, c.ID, inventory.ACMEOrderIssue)
	require.ErrorIs(t, err, inventory.ErrACMEAccountState)

	// A deleted definition: the order's client is refused, and the job's work says so.
	_, err = w.db.Owner.Exec(w.ctx, "UPDATE acme_certificates SET deleted_at = now() WHERE id = $1", c.ID)
	require.NoError(t, err)
	_, err = w.svc.ACMEOrderClient(w.ctx, o.ID)
	require.ErrorIs(t, err, inventory.ErrNotFound)
	work, err := w.svc.ACMEOrderWork(w.ctx, o.ID)
	require.NoError(t, err)
	assert.True(t, work.Deleted)
}

// An interrupted order is abandoned without counting a failure: its key goes, the certificate's state returns to what
// it was, failures and the next attempt are untouched, the cleanup is queued when records are left (R1).
func TestACMEAbandonCountsNoFailure(t *testing.T) {
	w := newCertWorld(t)
	c := w.create(w.dnsInput("abandon.example.test"))
	o, err := w.svc.RequestOrder(w.ctx, w.operator, c.ID, inventory.ACMEOrderIssue)
	require.NoError(t, err)
	_, err = w.svc.NewACMEOrderKey(w.ctx, o.ID)
	require.NoError(t, err)
	hook := w.hook.ID
	require.NoError(t, w.svc.AddACMEPresented(w.ctx, o.ID, inventory.ACMEPresented{HookID: &hook,
		Challenge: solver.Challenge{Type: solver.DNS01, Domain: "abandon.example.test", DNSValue: "v"}}))
	require.ErrorIs(t, w.svc.AbandonACMEOrder(w.ctx, o.ID, "not a code"), inventory.ErrACMEErrorCode)
	require.NoError(t, w.svc.AbandonACMEOrder(w.ctx, o.ID, inventory.ACMEOrderAbandoned))
	g, err := w.svc.GetACMEOrder(w.ctx, o.ID)
	require.NoError(t, err)
	assert.Equal(t, inventory.ACMEOrderFailed, g.State)
	assert.Equal(t, inventory.ACMEOrderAbandoned, g.ErrorCode)
	assert.Zero(t, w.count("SELECT count(*) FROM acme_orders WHERE pending_key_ct IS NOT NULL"))
	got, err := w.svc.GetACMECertificate(w.ctx, c.ID)
	require.NoError(t, err)
	assert.Equal(t, inventory.ACMEStatePending, got.State)
	assert.Zero(t, got.Failures)
	assert.Nil(t, got.NextAttemptAt)
	assert.Empty(t, got.LastErrorCode)
	reqs := w.jobs.requests()
	assert.Equal(t, inventory.JobACMECleanup, reqs[len(reqs)-1].Type)
	require.NoError(t, w.svc.AbandonACMEOrder(w.ctx, o.ID, inventory.ACMEOrderAbandoned), "again: nothing changes")

	// A certificate with earlier failures goes back to failing; one with a current certificate to active.
	_, err = w.db.Owner.Exec(w.ctx, "UPDATE acme_certificates SET failures = 2 WHERE id = $1", c.ID)
	require.NoError(t, err)
	o, err = w.svc.RequestOrder(w.ctx, w.operator, c.ID, inventory.ACMEOrderIssue)
	require.NoError(t, err)
	require.NoError(t, w.svc.AbandonACMEOrder(w.ctx, o.ID, "job.lease_expired"))
	got, err = w.svc.GetACMECertificate(w.ctx, c.ID)
	require.NoError(t, err)
	assert.Equal(t, inventory.ACMEStateFailing, got.State)
	assert.Equal(t, 2, got.Failures)
}

// Final review finding 5: a definition being created reads its provider, hook and HTTP-01 server FOR SHARE, so a delete
// that holds the row (DeleteACMEProvider, DeleteACMEHook: FOR UPDATE) and commits meanwhile is seen: the create is
// refused, never a live certificate referring to a deleted row.
func TestACMECertificateCreateSeesAConcurrentDelete(t *testing.T) {
	w := newCertWorld(t)
	for _, tc := range []struct {
		name  string
		table string
		row   func() uuid.UUID
		in    func(names string) inventory.ACMECertificateInput
		want  []string
	}{
		{"server", "targets", func() uuid.UUID { return w.seedTarget("web-del", "nginx", "del.example.test") },
			func(n string) inventory.ACMECertificateInput {
				return inventory.ACMECertificateInput{ProviderID: w.provider.ID, Names: []string{n}, Challenge: inventory.ACMEChallengeHTTP01,
					HTTPTargetID: ptr(w.seedTarget("unused", "nginx", "unused.example.test"))}
			}, []string{"http_target_id:" + validate.Required}},
		{"provider", "acme_providers", func() uuid.UUID { p := w.registryWorld.provider("Deleted CA", false); w.register(p); return p.ID },
			func(n string) inventory.ACMECertificateInput { return w.dnsInput(n) }, []string{"provider_id:" + validate.Required}},
		{"hook", "acme_hooks", func() uuid.UUID { return w.hook.ID }, func(n string) inventory.ACMECertificateInput { return w.dnsInput(n) },
			[]string{"hook_id:" + validate.Required}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			id := tc.row()
			in := tc.in(tc.name + "-race.example.test")
			switch tc.table {
			case "targets":
				in.HTTPTargetID = &id
			case "acme_providers":
				in.ProviderID = id
			}
			tx, err := w.db.Owner.Begin(w.ctx)
			require.NoError(t, err)
			defer func() { _ = tx.Rollback(w.ctx) }()
			_, err = tx.Exec(w.ctx, "SELECT 1 FROM "+tc.table+" WHERE id = $1 FOR UPDATE", id)
			require.NoError(t, err)
			_, err = tx.Exec(w.ctx, "UPDATE "+tc.table+" SET deleted_at = now() WHERE id = $1", id)
			require.NoError(t, err)
			done := make(chan error, 1)
			go func() { _, err := w.svc.CreateACMECertificate(w.ctx, w.admin, in); done <- err }()
			w.waitForLockWaiter()
			require.NoError(t, tx.Commit(w.ctx))
			err = <-done
			assert.Equal(t, tc.want, fieldList(err), "%v", err)
			assert.Zero(t, w.count("SELECT count(*) FROM acme_certificates WHERE $1 = ANY(names)", in.Names[0]))
		})
	}
}
