//go:build integration

package inventory_test

import (
	"context"
	"crypto"
	"encoding/base64"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/acme"
	"alice/internal/acme/solver/dns01"
	"alice/internal/acme/transport"
	"alice/internal/inventory"
	"alice/internal/license"
	"alice/internal/platform/validate"
	"alice/internal/rbac"
	"alice/internal/secrets"
	"alice/internal/testutil/fakeacme"
)

// registryWorld is a harness with a running fake CA and an Administrator.
type registryWorld struct {
	*harness
	fake  *fakeacme.Server
	admin inventory.Actor
}

func newRegistryWorld(t *testing.T, opts fakeacme.Options) *registryWorld {
	t.Helper()
	h := newHarness(t)
	opts.Now = h.clock.Now
	fake, err := fakeacme.New(opts)
	require.NoError(t, err)
	require.NoError(t, fake.Start())
	t.Cleanup(fake.Close)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	t.Cleanup(cancel)
	h.ctx = ctx
	return &registryWorld{harness: h, fake: fake, admin: h.user("ada", rbac.Admin, "ada@example.test")}
}

// provider creates a provider of the fake (its CA bundle, allow-list example.test), with the fake's EAB when eab.
func (w *registryWorld) provider(name string, eab bool) inventory.ACMEProvider {
	w.t.Helper()
	in := inventory.ACMEProviderInput{Name: name, DirectoryURL: w.fake.DirectoryURL(), CABundlePEM: string(w.fake.CAPEM()),
		AllowedSuffixes: []string{"example.test"}}
	if eab {
		c := w.fake.Credentials()
		in.EAB = &inventory.ACMEEABInput{KID: c.EABKID, HMAC: secrets.NewPlaintext([]byte(c.EABHMAC))}
	}
	p, err := w.svc.CreateACMEProvider(w.ctx, w.admin, in)
	require.NoError(w.t, err)
	return p
}

func (w *registryWorld) register(p inventory.ACMEProvider) inventory.ACMEAccount {
	w.t.Helper()
	a, err := w.svc.RegisterACMEAccount(w.ctx, w.admin, p.ID, "Ops@Example.TEST", true)
	require.NoError(w.t, err)
	return a
}

func (w *registryWorld) requests() int { return w.fake.Counters()["requests"] }

// lookup asks the fake which account the signer's key belongs to.
func (w *registryWorld) lookup(signer crypto.Signer) (string, error) {
	hc, err := transport.New(string(w.fake.CAPEM()))
	require.NoError(w.t, err)
	c, err := acme.New(acme.Config{DirectoryURL: w.fake.DirectoryURL(), Key: signer, HTTPClient: hc})
	require.NoError(w.t, err)
	return c.Lookup(w.ctx)
}

// agePending makes the provider's pending key older than ACMERolloverSettleAge (database time), as if the CA call
// that inserted it ended long ago.
func (w *registryWorld) agePending(provider uuid.UUID) {
	w.t.Helper()
	tag, err := w.db.Owner.Exec(w.ctx, `UPDATE acme_accounts SET pending_since = now() - make_interval(secs => $2)
WHERE provider_id = $1 AND state = 'pending_rollover'`, provider, (inventory.ACMERolloverSettleAge + time.Minute).Seconds())
	require.NoError(w.t, err)
	require.Equal(w.t, int64(1), tag.RowsAffected())
}

// otherProcess is a second Service on the same database: another Alice process with its own memory.
func (w *registryWorld) otherProcess() *inventory.Service {
	return inventory.New(inventory.Config{Pool: w.db.App, Keyring: w.keyring, Audit: w.audit, Clock: w.clock, License: w.lic,
		Registry: w.reg, Jobs: w.jobs})
}

func reasonOf(err error) string {
	var ae *inventory.ACMEError
	if errors.As(err, &ae) {
		return ae.Reason
	}
	return ""
}

func detailKeys(d map[string]string) []string {
	keys := make([]string, 0, len(d))
	for k := range d {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

// accountStates is provider p's accounts as id -> state.
func (w *registryWorld) accountStates(p uuid.UUID) map[uuid.UUID]string {
	w.t.Helper()
	list, err := w.svc.ListACMEAccounts(w.ctx, p)
	require.NoError(w.t, err)
	out := map[uuid.UUID]string{}
	for _, a := range list {
		out[a.ID] = a.State
	}
	return out
}

// auditText is every audit row as JSON text.
func (w *registryWorld) auditText() string {
	w.t.Helper()
	var s string
	require.NoError(w.t, w.db.Owner.QueryRow(w.ctx, "SELECT coalesce(string_agg(row_to_json(a)::text, E'\\n'), '') FROM audit_log a").Scan(&s))
	return s
}

// allRows is every row of the ACME tables and the audit log as JSON text (the leak scans).
func (w *registryWorld) allRows() string {
	w.t.Helper()
	var b strings.Builder
	for _, tbl := range []string{"acme_providers", "acme_accounts", "acme_hooks", "audit_log"} {
		rows, err := w.db.Owner.Query(w.ctx, "SELECT row_to_json(t)::text FROM "+tbl+" t")
		require.NoError(w.t, err)
		for rows.Next() {
			var s string
			require.NoError(w.t, rows.Scan(&s))
			b.WriteString(s)
			b.WriteByte('\n')
		}
		rows.Close()
		require.NoError(w.t, rows.Err())
	}
	return b.String()
}

func TestACMEProviderLifecycle(t *testing.T) {
	w := newRegistryWorld(t, fakeacme.Options{})
	bundle := string(w.fake.CAPEM())
	before := w.requests()
	p, err := w.svc.CreateACMEProvider(w.ctx, w.admin, inventory.ACMEProviderInput{Name: "Corp CA", DirectoryURL: w.fake.DirectoryURL(),
		Preset: inventory.ACMEPresetCustom, CABundlePEM: bundle, AllowedSuffixes: []string{"Example.TEST", ".corp.example.test"}})
	require.NoError(t, err)
	assert.Equal(t, before, w.requests(), "creating a provider contacts nobody")
	assert.Equal(t, "Corp CA", p.Name)
	assert.Equal(t, []string{"example.test", ".corp.example.test"}, p.AllowedSuffixes)
	assert.False(t, p.EABConfigured)
	assert.Nil(t, p.ActiveAccountID)
	assert.Equal(t, w.admin.UserID, *p.CreatedBy)
	assert.Equal(t, start, p.CreatedAt)
	assert.Contains(t, p.CABundlePEM, "-----BEGIN CERTIFICATE-----")

	got, err := w.svc.GetACMEProvider(w.ctx, p.ID)
	require.NoError(t, err)
	assert.Equal(t, p, got)
	list, err := w.svc.ListACMEProviders(w.ctx)
	require.NoError(t, err)
	assert.Equal(t, []inventory.ACMEProvider{p}, list)

	d := w.auditDetails("acme.provider.created")
	require.Len(t, d, 1)
	assert.Equal(t, []string{"allowed_suffixes", "ca_bundle", "directory_host", "eab_configured", "name", "preset"}, detailKeys(d[0]))
	assert.Equal(t, urlHostOf(w.fake.DirectoryURL()), d[0]["directory_host"])
	assert.Equal(t, "false", d[0]["eab_configured"])

	_, err = w.svc.CreateACMEProvider(w.ctx, w.admin, inventory.ACMEProviderInput{Name: "corp ca", DirectoryURL: w.fake.DirectoryURL()})
	assert.ErrorIs(t, err, inventory.ErrACMENameTaken, "names are unique, case-insensitively")
	_, err = w.svc.CreateACMEProvider(w.ctx, w.admin, inventory.ACMEProviderInput{Name: "x", DirectoryURL: "http://ca.example/dir"})
	var verrs validate.Errors
	require.ErrorAs(t, err, &verrs)
	assert.Equal(t, 1, w.audits("acme.provider.created"))

	// A patch that changes nothing writes nothing; a real one names the fields.
	same := "Corp CA"
	_, err = w.svc.UpdateACMEProvider(w.ctx, w.admin, p.ID, inventory.ACMEProviderPatch{Name: &same})
	require.NoError(t, err)
	assert.Equal(t, 0, w.audits("acme.provider.updated"))
	w.clock.Advance(time.Minute)
	name, preset, suffixes := "Corp CA 2", inventory.ACMEPresetLetsEncryptStaging, []string{"corp.example.test"}
	c := w.fake.Credentials()
	up, err := w.svc.UpdateACMEProvider(w.ctx, w.admin, p.ID, inventory.ACMEProviderPatch{Name: &name, Preset: &preset, AllowedSuffixes: &suffixes,
		EAB: &inventory.ACMEEABInput{KID: c.EABKID, HMAC: secrets.NewPlaintext([]byte(c.EABHMAC))}})
	require.NoError(t, err)
	assert.Equal(t, "Corp CA 2", up.Name)
	assert.True(t, up.EABConfigured)
	assert.Equal(t, c.EABKID, up.EABKID)
	assert.Equal(t, start.Add(time.Minute), up.UpdatedAt)
	d = w.auditDetails("acme.provider.updated")
	require.Len(t, d, 1)
	assert.Equal(t, "name,preset,allowed_suffixes,eab", d[0]["fields"])
	assert.Equal(t, []string{"allowed_suffixes", "directory_host", "eab_configured", "fields", "name"}, detailKeys(d[0]))

	// Remove the binding; the directory may change while there is no account.
	other := "https://ca.other.example/acme/directory"
	up, err = w.svc.UpdateACMEProvider(w.ctx, w.admin, p.ID, inventory.ACMEProviderPatch{RemoveEAB: true, DirectoryURL: &other})
	require.NoError(t, err)
	assert.False(t, up.EABConfigured)
	assert.Empty(t, up.EABKID)
	assert.Equal(t, other, up.DirectoryURL)
	kid, hmac, err := w.svc.OpenACMEEAB(w.ctx, p.ID)
	require.NoError(t, err)
	assert.Empty(t, kid)
	assert.Empty(t, hmac.Bytes())

	_, err = w.svc.UpdateACMEProvider(w.ctx, w.admin, uuid.New(), inventory.ACMEProviderPatch{Name: &name})
	assert.ErrorIs(t, err, inventory.ErrNotFound)

	require.NoError(t, w.svc.DeleteACMEProvider(w.ctx, w.admin, p.ID))
	_, err = w.svc.GetACMEProvider(w.ctx, p.ID)
	assert.ErrorIs(t, err, inventory.ErrNotFound)
	assert.ErrorIs(t, w.svc.DeleteACMEProvider(w.ctx, w.admin, p.ID), inventory.ErrNotFound)
	d = w.auditDetails("acme.provider.deleted")
	require.Len(t, d, 1)
	assert.Equal(t, map[string]string{"name": "Corp CA 2", "directory_host": "ca.other.example"}, d[0])
	_, err = w.svc.CreateACMEProvider(w.ctx, w.admin, inventory.ACMEProviderInput{Name: "Corp CA 2", DirectoryURL: w.fake.DirectoryURL()})
	require.NoError(t, err, "a deleted provider's name is free again")
}

func urlHostOf(u string) string {
	u = strings.TrimPrefix(u, "https://")
	return u[:strings.IndexByte(u, '/')]
}

// The EAB HMAC key is sealed (AAD acme_providers/<id>/eab_hmac), opens again, never appears in a row or an audit row,
// and a ciphertext copied to another provider does not open.
func TestACMEProviderEABIsSealed(t *testing.T) {
	w := newRegistryWorld(t, fakeacme.Options{RequireEAB: true})
	p := w.provider("Sealed CA", true)
	assert.True(t, p.EABConfigured)
	c := w.fake.Credentials()
	kid, hmac, err := w.svc.OpenACMEEAB(w.ctx, p.ID)
	require.NoError(t, err)
	assert.Equal(t, c.EABKID, kid)
	assert.Equal(t, c.EABHMAC, string(hmac.Bytes()))
	hmac.Zero()

	rows := w.allRows()
	assert.NotContains(t, rows, c.EABHMAC)
	raw, err := base64.RawURLEncoding.DecodeString(c.EABHMAC)
	require.NoError(t, err)
	assert.NotContains(t, rows, base64.StdEncoding.EncodeToString(raw))
	assert.NotContains(t, strings.Join(detailValues(w.auditDetails("acme.provider.created")), ","), c.EABKID,
		"the key id is not audited either")

	q := w.provider("Second CA", false)
	_, err = w.db.Owner.Exec(w.ctx, `UPDATE acme_providers SET (eab_kid, eab_hmac_ct, eab_hmac_nonce, eab_hmac_wrapped_dek, eab_hmac_key_version) =
(SELECT eab_kid, eab_hmac_ct, eab_hmac_nonce, eab_hmac_wrapped_dek, eab_hmac_key_version FROM acme_providers WHERE id = $2) WHERE id = $1`, q.ID, p.ID)
	require.NoError(t, err)
	_, _, err = w.svc.OpenACMEEAB(w.ctx, q.ID)
	assert.ErrorIs(t, err, inventory.ErrACMESecretUnreadable, "the AAD binds the key to its row")
	_, err = w.svc.RegisterACMEAccount(w.ctx, w.admin, q.ID, "", true)
	assert.ErrorIs(t, err, inventory.ErrACMESecretUnreadable)
}

func detailValues(ds []map[string]string) []string {
	var out []string
	for _, d := range ds {
		for _, v := range d {
			out = append(out, v)
		}
	}
	return out
}

func TestACMERegisterWithoutEAB(t *testing.T) {
	w := newRegistryWorld(t, fakeacme.Options{})
	p := w.provider("LE staging", false)
	terms := w.fake.Credentials().TermsURL

	before := w.requests()
	_, err := w.svc.RegisterACMEAccount(w.ctx, w.admin, p.ID, "ops@example.test", false)
	assert.Equal(t, acme.ReasonTermsNotAccepted, reasonOf(err), "%v", err)
	assert.Equal(t, 0, w.fake.Counters()["new-account"], "nothing is registered without the terms")
	assert.Greater(t, w.requests(), before, "the directory was read to show the terms")
	assert.Empty(t, w.accountStates(p.ID))

	a, err := w.svc.RegisterACMEAccount(w.ctx, w.admin, p.ID, "mailto:Ops@Example.TEST", true)
	require.NoError(t, err)
	assert.Equal(t, inventory.ACMEAccountActive, a.State)
	assert.Equal(t, "Ops@example.test", a.ContactEmail)
	assert.Equal(t, terms, a.TermsURL)
	assert.Equal(t, w.admin.UserID, *a.TermsAcceptedBy)
	assert.Equal(t, start, *a.TermsAcceptedAt)
	assert.True(t, strings.HasPrefix(a.AccountURL, w.fake.BaseURL()+"/acme/acct/"), a.AccountURL)
	got, err := w.svc.GetACMEProvider(w.ctx, p.ID)
	require.NoError(t, err)
	assert.Equal(t, a.ID, *got.ActiveAccountID)

	d := w.auditDetails("acme.account.registered")
	require.Len(t, d, 1)
	assert.Equal(t, map[string]string{"provider_id": p.ID.String(), "eab_used": "false", "tos_url": terms}, d[0])
	assert.NotContains(t, w.auditText(), "Ops@example.test", "the contact is not audited")
	assert.NotContains(t, w.auditText(), "@", "no address at all")

	// The sealed key is the account's key at the CA.
	signer, kid, err := w.svc.ACMEAccountSigner(w.ctx, a.ID)
	require.NoError(t, err)
	assert.Equal(t, a.AccountURL, kid)
	u, err := w.lookup(signer)
	require.NoError(t, err)
	assert.Equal(t, a.AccountURL, u)
	assert.NotContains(t, w.allRows(), "PRIVATE KEY")

	// One active account per provider: refused before the CA is asked.
	before = w.requests()
	_, err = w.svc.RegisterACMEAccount(w.ctx, w.admin, p.ID, "", true)
	assert.ErrorIs(t, err, inventory.ErrACMEAccountExists)
	assert.Equal(t, before, w.requests())

	_, err = w.svc.RegisterACMEAccount(w.ctx, w.admin, uuid.New(), "", true)
	assert.ErrorIs(t, err, inventory.ErrNotFound)
	_, _, err = w.svc.ACMEAccountSigner(w.ctx, uuid.New())
	assert.ErrorIs(t, err, inventory.ErrNotFound)
}

func TestACMERegisterWithEAB(t *testing.T) {
	w := newRegistryWorld(t, fakeacme.Options{RequireEAB: true, NoTerms: true})
	missing := w.provider("No binding", false)
	_, err := w.svc.RegisterACMEAccount(w.ctx, w.admin, missing.ID, "", false)
	assert.Equal(t, acme.ReasonAccountRejected, reasonOf(err), "the CA requires a binding")

	c := w.fake.Credentials()
	wrong, err := w.svc.CreateACMEProvider(w.ctx, w.admin, inventory.ACMEProviderInput{Name: "Wrong binding", DirectoryURL: w.fake.DirectoryURL(),
		CABundlePEM: string(w.fake.CAPEM()), EAB: &inventory.ACMEEABInput{KID: c.EABKID,
			HMAC: secrets.NewPlaintext([]byte(base64.RawURLEncoding.EncodeToString([]byte("an entirely different hmac key!!"))))}})
	require.NoError(t, err)
	_, err = w.svc.RegisterACMEAccount(w.ctx, w.admin, wrong.ID, "", false)
	assert.Equal(t, acme.ReasonAccountRejected, reasonOf(err), "ALC-ACM-0004: %v", err)
	assert.Empty(t, w.accountStates(wrong.ID))

	p := w.provider("Bound", true)
	a, err := w.svc.RegisterACMEAccount(w.ctx, w.admin, p.ID, "", false)
	require.NoError(t, err, "a CA without terms needs no acceptance")
	assert.Empty(t, a.TermsURL)
	assert.Nil(t, a.TermsAcceptedBy)
	assert.Nil(t, a.TermsAcceptedAt)
	assert.Empty(t, a.ContactEmail)
	d := w.auditDetails("acme.account.registered")
	require.Len(t, d, 1)
	assert.Equal(t, map[string]string{"provider_id": p.ID.String(), "eab_used": "true"}, d[0])
	assert.NotContains(t, w.allRows(), c.EABHMAC)
}

func TestACMERegisterFailures(t *testing.T) {
	w := newRegistryWorld(t, fakeacme.Options{})
	// Nothing listens on port 1: the CA is unreachable (ALC-ACM-0001).
	down, err := w.svc.CreateACMEProvider(w.ctx, w.admin, inventory.ACMEProviderInput{Name: "Down", DirectoryURL: "https://127.0.0.1:1/directory"})
	require.NoError(t, err)
	_, err = w.svc.RegisterACMEAccount(w.ctx, w.admin, down.ID, "", true)
	assert.Equal(t, acme.ReasonProviderUnreachable, reasonOf(err), "%v", err)

	// Without the fake's CA in the bundle its TLS certificate is not trusted (ALC-ACM-0013).
	untrusted, err := w.svc.CreateACMEProvider(w.ctx, w.admin, inventory.ACMEProviderInput{Name: "Untrusted", DirectoryURL: w.fake.DirectoryURL()})
	require.NoError(t, err)
	_, err = w.svc.RegisterACMEAccount(w.ctx, w.admin, untrusted.ID, "", true)
	assert.Equal(t, acme.ReasonTLSTrustFailed, reasonOf(err), "%v", err)

	// Rate limited: the reason and the CA's Retry-After.
	p := w.provider("Busy", false)
	require.NoError(t, w.fake.AddFault(fakeacme.Fault{Endpoint: "new-account", Kind: fakeacme.FaultRateLimited, Times: 1, RetryAfter: time.Hour}))
	_, err = w.svc.RegisterACMEAccount(w.ctx, w.admin, p.ID, "", true)
	var ae *inventory.ACMEError
	require.ErrorAs(t, err, &ae)
	assert.Equal(t, acme.ReasonCARateLimited, ae.Reason)
	assert.Equal(t, time.Hour, ae.RetryAfter)
	assert.NotContains(t, err.Error(), w.fake.BaseURL())
	assert.Empty(t, w.accountStates(p.ID))
	assert.Equal(t, 0, w.audits("acme.account.registered"))
}

// In lock nothing is sent to the CA: registration, rollover, recovery and deactivation answer the license error.
func TestACMEAccountOperationsInLockSendNothing(t *testing.T) {
	w := newRegistryWorld(t, fakeacme.Options{})
	p := w.provider("Locked CA", false)
	a := w.register(p)
	w.clock.Advance(31 * 24 * time.Hour)
	require.NoError(t, w.lic.Tick(w.ctx))
	require.ErrorIs(t, w.lic.Allow(license.ClassChange), license.ErrLocked)
	w.fake.ClearRequests()
	q, err := w.svc.CreateACMEProvider(w.ctx, w.admin, inventory.ACMEProviderInput{Name: "Second", DirectoryURL: w.fake.DirectoryURL(),
		CABundlePEM: string(w.fake.CAPEM())})
	require.NoError(t, err, "settings that contact nobody stay possible (the route's class decides)")
	_, err = w.svc.RegisterACMEAccount(w.ctx, w.admin, q.ID, "", true)
	assert.ErrorIs(t, err, license.ErrLocked)
	_, err = w.svc.RolloverACMEAccount(w.ctx, w.admin, a.ID)
	assert.ErrorIs(t, err, license.ErrLocked)
	_, err = w.svc.RecoverACMERollover(w.ctx, w.admin, a.ID)
	assert.ErrorIs(t, err, license.ErrLocked)
	_, err = w.svc.DeactivateACMEAccount(w.ctx, w.admin, a.ID)
	assert.ErrorIs(t, err, license.ErrLocked)
	assert.Equal(t, 0, w.requests(), "the CA was not contacted")
	assert.Empty(t, w.fake.Requests())
	assert.Equal(t, map[uuid.UUID]string{a.ID: inventory.ACMEAccountActive}, w.accountStates(p.ID))
}

func TestACMERolloverSwitched(t *testing.T) {
	w := newRegistryWorld(t, fakeacme.Options{})
	p := w.provider("Roll CA", false)
	a := w.register(p)
	oldSigner, _, err := w.svc.ACMEAccountSigner(w.ctx, a.ID)
	require.NoError(t, err)
	w.clock.Advance(time.Hour)
	certs := []uuid.UUID{uuid.New(), uuid.New()}
	web := w.seedTarget("roll-web", "nginx", "web.example.test")
	for i, id := range certs {
		_, err = w.db.Owner.Exec(w.ctx, `INSERT INTO acme_certificates (id, provider_id, account_id, names, key_type, challenge, http_target_id, deleted_at,
created_at, updated_at) VALUES ($1, $2, $3, '{www.example.test}', 'ecdsa_p256', 'http01', $5, CASE WHEN $4 THEN now() END, now(), now())`,
			id, p.ID, a.ID, i == 1, web)
		require.NoError(t, err)
	}

	n, err := w.svc.RolloverACMEAccount(w.ctx, w.admin, a.ID)
	require.NoError(t, err)
	assert.Equal(t, 2, w.count("SELECT count(*) FROM acme_certificates WHERE account_id = $1", n.ID),
		"the certificates (deleted ones too) follow the account to its new key (I3)")
	assert.Equal(t, 0, w.count("SELECT count(*) FROM acme_certificates WHERE account_id = $1", a.ID))
	assert.NotEqual(t, a.ID, n.ID, "a rollover is a new row")
	assert.Equal(t, inventory.ACMEAccountActive, n.State)
	assert.Equal(t, a.AccountURL, n.AccountURL)
	assert.Equal(t, a.ContactEmail, n.ContactEmail)
	assert.Equal(t, a.TermsURL, n.TermsURL)
	assert.Equal(t, map[uuid.UUID]string{a.ID: inventory.ACMEAccountRetired, n.ID: inventory.ACMEAccountActive}, w.accountStates(p.ID))
	d := w.auditDetails("acme.account.rolled_over")
	require.Len(t, d, 1)
	assert.Equal(t, map[string]string{"provider_id": p.ID.String(), "previous_account_id": a.ID.String(), "recovered": "false"}, d[0])

	newSigner, kid, err := w.svc.ACMEAccountSigner(w.ctx, n.ID)
	require.NoError(t, err)
	assert.Equal(t, a.AccountURL, kid)
	u, err := w.lookup(newSigner)
	require.NoError(t, err)
	assert.Equal(t, a.AccountURL, u, "the CA knows the new key")
	_, err = w.lookup(oldSigner)
	assert.ErrorIs(t, err, acme.ErrNoAccount, "and no longer the old one")
	_, _, err = w.svc.ACMEAccountSigner(w.ctx, a.ID)
	assert.ErrorIs(t, err, inventory.ErrACMEAccountState, "a retired key signs nothing")
	_, err = w.svc.RolloverACMEAccount(w.ctx, w.admin, a.ID)
	assert.ErrorIs(t, err, inventory.ErrACMEAccountState)
}

func TestACMERolloverUnsupportedAndRefused(t *testing.T) {
	w := newRegistryWorld(t, fakeacme.Options{NoKeyChange: true})
	p := w.provider("No keyChange", false)
	a := w.register(p)
	_, err := w.svc.RolloverACMEAccount(w.ctx, w.admin, a.ID)
	assert.Equal(t, acme.ReasonRolloverUnsupported, reasonOf(err), "ALC-ACM-0014: %v", err)
	assert.Equal(t, map[uuid.UUID]string{a.ID: inventory.ACMEAccountActive}, w.accountStates(p.ID), "the pending key was discarded")
	assert.Equal(t, 0, w.count("SELECT count(*) FROM acme_accounts WHERE state = 'pending_rollover'"))
	d := w.auditDetails("acme.account.rollover_discarded")
	require.Len(t, d, 1, "the discarded pending key is audited")
	assert.Equal(t, map[string]string{"provider_id": p.ID.String(), "account_id": a.ID.String(), "pending_account_id": d[0]["pending_account_id"],
		"recovered": "false", "reason": acme.ReasonRolloverUnsupported}, d[0])

	w2 := newRegistryWorld(t, fakeacme.Options{})
	p2 := w2.provider("Refusing", false)
	a2 := w2.register(p2)
	require.NoError(t, w2.fake.AddFault(fakeacme.Fault{Endpoint: "key-change", Kind: fakeacme.FaultRateLimited, Times: 1, RetryAfter: time.Minute}))
	_, err = w2.svc.RolloverACMEAccount(w2.ctx, w2.admin, a2.ID)
	assert.Equal(t, acme.ReasonCARateLimited, reasonOf(err), "a definite refusal (NotSwitched): %v", err)
	assert.Equal(t, map[uuid.UUID]string{a2.ID: inventory.ACMEAccountActive}, w2.accountStates(p2.ID))
	assert.Equal(t, 0, w2.audits("acme.account.rolled_over"))
	_, err = w2.svc.RecoverACMERollover(w2.ctx, w2.admin, a2.ID)
	assert.ErrorIs(t, err, inventory.ErrACMEAccountState, "nothing to recover")
}

// A6 crash simulation: the CA switched but Alice never learned it (the answer lost, or a crash before step 3). The
// pending key stays, everything else waits, and the recovery finds the new key at the CA and settles it.
func TestACMERolloverUnknownThenSwitched(t *testing.T) {
	w := newRegistryWorld(t, fakeacme.Options{})
	p := w.provider("Crash CA", false)
	a := w.register(p)
	w.svc.SetACMERolloverSeam(func(o acme.RolloverOutcome) acme.RolloverOutcome {
		require.Equal(t, acme.RolloverSwitched, o, "the CA did switch")
		return acme.RolloverUnknown
	})
	_, err := w.svc.RolloverACMEAccount(w.ctx, w.admin, a.ID)
	assert.ErrorIs(t, err, inventory.ErrACMERolloverPending)
	w.svc.SetACMERolloverSeam(nil)
	states := w.accountStates(p.ID)
	require.Len(t, states, 2)
	var pending uuid.UUID
	for id, st := range states {
		if id != a.ID {
			pending = id
			assert.Equal(t, inventory.ACMEAccountPendingRollover, st)
		}
	}
	got, err := w.svc.GetACMEProvider(w.ctx, p.ID)
	require.NoError(t, err)
	assert.True(t, got.PendingRollover)
	_, _, err = w.svc.ACMEAccountSigner(w.ctx, a.ID)
	assert.ErrorIs(t, err, inventory.ErrACMERolloverPending, "nothing is signed with a key the CA may no longer accept (M10)")

	// Everything else waits for the settlement.
	_, err = w.svc.RolloverACMEAccount(w.ctx, w.admin, a.ID)
	assert.ErrorIs(t, err, inventory.ErrACMERolloverPending)
	_, err = w.svc.RolloverACMEAccount(w.ctx, w.admin, pending)
	assert.ErrorIs(t, err, inventory.ErrACMERolloverPending)
	_, err = w.svc.DeactivateACMEAccount(w.ctx, w.admin, a.ID)
	assert.ErrorIs(t, err, inventory.ErrACMERolloverPending)
	_, err = w.svc.RegisterACMEAccount(w.ctx, w.admin, p.ID, "", true)
	assert.ErrorIs(t, err, inventory.ErrACMERolloverPending)
	dir := "https://ca.elsewhere.example/dir"
	_, err = w.svc.UpdateACMEProvider(w.ctx, w.admin, p.ID, inventory.ACMEProviderPatch{DirectoryURL: &dir, ConfirmDirectoryChange: true})
	assert.ErrorIs(t, err, inventory.ErrACMERolloverPending)
	assert.ErrorIs(t, w.svc.DeleteACMEProvider(w.ctx, w.admin, p.ID), inventory.ErrACMEProviderInUse)

	// A recovery right away is refused: the pending key is young (its keyChange may still be in flight).
	_, err = w.svc.RecoverACMERollover(w.ctx, w.admin, pending)
	assert.ErrorIs(t, err, inventory.ErrACMERolloverPending)
	assert.Len(t, w.accountStates(p.ID), 2)

	// Once it is old, a new Service (a restart) recovers it.
	w.agePending(p.ID)
	n, err := w.otherProcess().RecoverACMERollover(w.ctx, w.admin, pending)
	require.NoError(t, err)
	assert.Equal(t, pending, n.ID)
	assert.Equal(t, inventory.ACMEAccountActive, n.State)
	assert.Equal(t, map[uuid.UUID]string{a.ID: inventory.ACMEAccountRetired, pending: inventory.ACMEAccountActive}, w.accountStates(p.ID))
	d := w.auditDetails("acme.account.rolled_over")
	require.Len(t, d, 1)
	assert.Equal(t, "true", d[0]["recovered"])
	newSigner, _, err := w.svc.ACMEAccountSigner(w.ctx, pending)
	require.NoError(t, err)
	u, err := w.lookup(newSigner)
	require.NoError(t, err)
	assert.Equal(t, a.AccountURL, u)
}

// The CA's answer was lost and the CA did NOT switch (a 500): the recovery finds the old key still in charge and
// discards the pending key.
func TestACMERolloverUnknownThenNotSwitched(t *testing.T) {
	w := newRegistryWorld(t, fakeacme.Options{})
	p := w.provider("Flaky CA", false)
	a := w.register(p)
	require.NoError(t, w.fake.AddFault(fakeacme.Fault{Endpoint: "key-change", Kind: fakeacme.FaultServerInternal, Times: 1}))
	_, err := w.svc.RolloverACMEAccount(w.ctx, w.admin, a.ID)
	assert.ErrorIs(t, err, inventory.ErrACMERolloverPending, "a 5xx leaves the outcome unknown")
	require.Len(t, w.accountStates(p.ID), 2)

	w.agePending(p.ID)
	// While the CA is unreachable the recovery changes nothing.
	require.NoError(t, w.fake.AddFault(fakeacme.Fault{Endpoint: "*", Kind: fakeacme.FaultServerInternal, Times: 0}))
	_, err = w.svc.RecoverACMERollover(w.ctx, w.admin, a.ID)
	assert.Equal(t, acme.ReasonProviderUnreachable, reasonOf(err), "%v", err)
	require.Len(t, w.accountStates(p.ID), 2)
	w.fake.ClearFaults()

	got, err := w.svc.RecoverACMERollover(w.ctx, w.admin, a.ID)
	require.NoError(t, err)
	assert.Equal(t, a.ID, got.ID)
	assert.Equal(t, map[uuid.UUID]string{a.ID: inventory.ACMEAccountActive}, w.accountStates(p.ID), "the pending key is gone")
	assert.Equal(t, 0, w.audits("acme.account.rolled_over"))
	// Final review finding 2: the discarded key is in the audit log, written with its delete in one transaction.
	d := w.auditDetails("acme.account.rollover_discarded")
	require.Len(t, d, 1)
	assert.Equal(t, p.ID.String(), d[0]["provider_id"])
	assert.Equal(t, a.ID.String(), d[0]["account_id"])
	assert.NotEmpty(t, d[0]["pending_account_id"])
	assert.NotEqual(t, a.ID.String(), d[0]["pending_account_id"])
	assert.Equal(t, "true", d[0]["recovered"])

	// And a normal rollover works afterwards.
	n, err := w.svc.RolloverACMEAccount(w.ctx, w.admin, a.ID)
	require.NoError(t, err)
	assert.Equal(t, inventory.ACMEAccountActive, n.State)
}

func TestACMEDeactivateAndProviderInUse(t *testing.T) {
	w := newRegistryWorld(t, fakeacme.Options{})
	p := w.provider("Deact CA", false)
	a := w.register(p)
	assert.ErrorIs(t, w.svc.DeleteACMEProvider(w.ctx, w.admin, p.ID), inventory.ErrACMEProviderInUse, "an active account")

	signer, _, err := w.svc.ACMEAccountSigner(w.ctx, a.ID)
	require.NoError(t, err)
	d, err := w.svc.DeactivateACMEAccount(w.ctx, w.admin, a.ID)
	require.NoError(t, err)
	assert.Equal(t, inventory.ACMEAccountDeactivated, d.State)
	assert.Equal(t, []map[string]string{{"provider_id": p.ID.String(), "already_deactivated": "false"}}, w.auditDetails("acme.account.deactivated"))
	hc, err := transport.New(string(w.fake.CAPEM()))
	require.NoError(t, err)
	c, err := acme.New(acme.Config{DirectoryURL: w.fake.DirectoryURL(), Key: signer, AccountURL: a.AccountURL, HTTPClient: hc})
	require.NoError(t, err)
	assert.Equal(t, acme.ReasonAccountRejected, acme.ReasonOf(c.Deactivate(w.ctx)), "the CA refuses a deactivated account")
	_, err = w.svc.DeactivateACMEAccount(w.ctx, w.admin, a.ID)
	assert.ErrorIs(t, err, inventory.ErrACMEAccountState)
	_, _, err = w.svc.ACMEAccountSigner(w.ctx, a.ID)
	assert.ErrorIs(t, err, inventory.ErrACMEAccountState)

	// Live ACME certificates keep the provider (and the hook) in use.
	hook := w.hook("in-use hook")
	cert := uuid.New()
	_, err = w.db.Owner.Exec(w.ctx, `INSERT INTO acme_certificates (id, provider_id, account_id, names, key_type, challenge, hook_id, created_at, updated_at)
VALUES ($1, $2, $3, '{www.example.test}', 'ecdsa_p256', 'dns01', $4, now(), now())`, cert, p.ID, a.ID, hook.ID)
	require.NoError(t, err)
	assert.ErrorIs(t, w.svc.DeleteACMEProvider(w.ctx, w.admin, p.ID), inventory.ErrACMEProviderInUse, "a live certificate")
	assert.ErrorIs(t, w.svc.DeleteACMEHook(w.ctx, w.admin, hook.ID), inventory.ErrACMEHookInUse)
	_, err = w.db.Owner.Exec(w.ctx, "UPDATE acme_certificates SET deleted_at = now() WHERE id = $1", cert)
	require.NoError(t, err)
	require.NoError(t, w.svc.DeleteACMEProvider(w.ctx, w.admin, p.ID))
	require.NoError(t, w.svc.DeleteACMEHook(w.ctx, w.admin, hook.ID))
	_, err = w.svc.ListACMEAccounts(w.ctx, p.ID)
	assert.ErrorIs(t, err, inventory.ErrNotFound)
}

func TestACMEDirectoryChangeNeedsConfirmation(t *testing.T) {
	w := newRegistryWorld(t, fakeacme.Options{})
	p := w.provider("Moving CA", false)
	a := w.register(p)
	dir := "https://ca.elsewhere.example/directory"
	_, err := w.svc.UpdateACMEProvider(w.ctx, w.admin, p.ID, inventory.ACMEProviderPatch{DirectoryURL: &dir})
	assert.ErrorIs(t, err, inventory.ErrACMEDirectoryChange)
	got, err := w.svc.GetACMEProvider(w.ctx, p.ID)
	require.NoError(t, err)
	assert.Equal(t, w.fake.DirectoryURL(), got.DirectoryURL, "nothing changed")
	assert.Equal(t, 0, w.audits("acme.provider.updated"))

	// Other fields change freely under an account.
	bundle := ""
	_, err = w.svc.UpdateACMEProvider(w.ctx, w.admin, p.ID, inventory.ACMEProviderPatch{CABundlePEM: &bundle})
	require.NoError(t, err)

	up, err := w.svc.UpdateACMEProvider(w.ctx, w.admin, p.ID, inventory.ACMEProviderPatch{DirectoryURL: &dir, ConfirmDirectoryChange: true})
	require.NoError(t, err)
	assert.Equal(t, dir, up.DirectoryURL)
	assert.Nil(t, up.ActiveAccountID)
	assert.Equal(t, map[uuid.UUID]string{a.ID: inventory.ACMEAccountRetired}, w.accountStates(p.ID))
	d := w.auditDetails("acme.provider.updated")
	require.Len(t, d, 2)
	assert.Equal(t, a.ID.String(), d[1]["retired_account_id"])
	assert.Equal(t, "ca.elsewhere.example", d[1]["directory_host"])
	assert.Equal(t, "directory_url", d[1]["fields"])
}

func (w *registryWorld) hook(name string) inventory.ACMEHook {
	w.t.Helper()
	h, err := w.svc.CreateACMEHook(w.ctx, w.admin, inventory.ACMEHookInput{Name: name, URL: w.fake.Credentials().HookURL,
		CABundlePEM: string(w.fake.CAPEM()), Secret: secrets.NewPlaintext([]byte(w.fake.Credentials().HookSecret)), AllowedSuffixes: []string{"example.test"}})
	require.NoError(w.t, err)
	return h
}

func TestACMEHookLifecycle(t *testing.T) {
	w := newRegistryWorld(t, fakeacme.Options{})
	secret := w.fake.Credentials().HookSecret
	require.GreaterOrEqual(t, len(secret), 16)
	before := w.requests()
	wait := 0
	h, err := w.svc.CreateACMEHook(w.ctx, w.admin, inventory.ACMEHookInput{Name: "DNS hook", URL: w.fake.Credentials().HookURL,
		CABundlePEM: string(w.fake.CAPEM()), Secret: secrets.NewPlaintext([]byte(secret)),
		AllowedSuffixes: []string{"Example.TEST"}, PropagationWaitSeconds: &wait, PollTimeoutSeconds: 30})
	require.NoError(t, err)
	assert.Equal(t, before, w.requests(), "creating a hook contacts nobody")
	assert.True(t, h.SecretConfigured)
	assert.Equal(t, []string{"example.test"}, h.AllowedSuffixes)
	assert.Equal(t, 0, h.PropagationWaitSeconds)
	assert.Equal(t, 30, h.PollTimeoutSeconds)
	list, err := w.svc.ListACMEHooks(w.ctx)
	require.NoError(t, err)
	assert.Equal(t, []inventory.ACMEHook{h}, list)
	d := w.auditDetails("acme.hook.created")
	require.Len(t, d, 1)
	assert.Equal(t, []string{"allowed_suffixes", "ca_bundle", "name", "poll_timeout_seconds", "propagation_wait_seconds", "url_host"},
		detailKeys(d[0]))

	// The sealed secret opens into a working dns01 configuration.
	cfg, err := w.svc.ACMEHookSolverConfig(w.ctx, h.ID)
	require.NoError(t, err)
	assert.Equal(t, inventory.ACMEHookKindWebhook, cfg.Kind)
	assert.Equal(t, secret, string(cfg.Hook.Secret.Bytes()))
	assert.Equal(t, time.Duration(-1), cfg.Hook.PropagationWait, "0 s is no wait (dns01 reads 0 as its default)")
	assert.Equal(t, 30*time.Second, cfg.Hook.PollTimeout)
	assert.Equal(t, []string{"example.test"}, cfg.Hook.AllowedSuffixes)
	_, err = dns01.New(cfg.Hook)
	require.NoError(t, err)
	cfg.Zero()
	assert.NotContains(t, w.allRows(), secret)

	_, err = w.svc.CreateACMEHook(w.ctx, w.admin, inventory.ACMEHookInput{Name: "dns HOOK", URL: "https://dns.example/hook",
		Secret: secrets.NewPlaintext([]byte("0123456789abcdef"))})
	assert.ErrorIs(t, err, inventory.ErrACMENameTaken)
	_, err = w.svc.CreateACMEHook(w.ctx, w.admin, inventory.ACMEHookInput{Name: "x", URL: "https://u:p@dns.example/hook",
		Secret: secrets.NewPlaintext([]byte("0123456789abcdef")), PollTimeoutSeconds: 101})
	var verrs validate.Errors
	require.ErrorAs(t, err, &verrs)
	assert.Len(t, verrs, 2)

	// Rotate the secret and move the waits; the audit names the fields only.
	newSecret := "a-brand-new-hook-secret-value"
	poll := 100
	wait = 20
	up, err := w.svc.UpdateACMEHook(w.ctx, w.admin, h.ID, inventory.ACMEHookPatch{Secret: secrets.NewPlaintext([]byte(newSecret)),
		PollTimeoutSeconds: &poll, PropagationWaitSeconds: &wait})
	require.NoError(t, err)
	assert.Equal(t, 100, up.PollTimeoutSeconds)
	d = w.auditDetails("acme.hook.updated")
	require.Len(t, d, 1)
	assert.Equal(t, "propagation_wait_seconds,poll_timeout_seconds,secret", d[0]["fields"])
	cfg, err = w.svc.ACMEHookSolverConfig(w.ctx, h.ID)
	require.NoError(t, err)
	assert.Equal(t, newSecret, string(cfg.Hook.Secret.Bytes()))
	cfg.Zero()
	wait = 21
	_, err = w.svc.UpdateACMEHook(w.ctx, w.admin, h.ID, inventory.ACMEHookPatch{PropagationWaitSeconds: &wait})
	require.ErrorAs(t, err, &verrs, "21 + 100 is over the 120 s budget")
	name := "DNS hook"
	_, err = w.svc.UpdateACMEHook(w.ctx, w.admin, h.ID, inventory.ACMEHookPatch{Name: &name})
	require.NoError(t, err)
	assert.Equal(t, 1, w.audits("acme.hook.updated"), "no change, no row")
	rows := w.allRows()
	assert.NotContains(t, rows, newSecret)
	assert.NotContains(t, rows, secret)

	// AAD: a secret copied to another hook does not open.
	other := w.hook("other hook")
	_, err = w.db.Owner.Exec(w.ctx, `UPDATE acme_hooks SET (secret_ct, secret_nonce, secret_wrapped_dek, secret_key_version) =
(SELECT secret_ct, secret_nonce, secret_wrapped_dek, secret_key_version FROM acme_hooks WHERE id = $2) WHERE id = $1`, other.ID, h.ID)
	require.NoError(t, err)
	_, err = w.svc.ACMEHookSolverConfig(w.ctx, other.ID)
	assert.ErrorIs(t, err, inventory.ErrACMESecretUnreadable)

	require.NoError(t, w.svc.DeleteACMEHook(w.ctx, w.admin, h.ID))
	_, err = w.svc.GetACMEHook(w.ctx, h.ID)
	assert.ErrorIs(t, err, inventory.ErrNotFound)
	_, err = w.svc.ACMEHookSolverConfig(w.ctx, h.ID)
	assert.ErrorIs(t, err, inventory.ErrNotFound)
	assert.Equal(t, []map[string]string{{"name": "DNS hook", "url_host": urlHostOf(w.fake.Credentials().HookURL)}}, w.auditDetails("acme.hook.deleted"))
	_, err = w.svc.UpdateACMEHook(w.ctx, w.admin, h.ID, inventory.ACMEHookPatch{Name: &name})
	assert.ErrorIs(t, err, inventory.ErrNotFound)
}

// Two registrations racing for one provider: exactly one account is stored; the other caller gets a clean error.
func TestACMEConcurrentRegistrations(t *testing.T) {
	w := newRegistryWorld(t, fakeacme.Options{})
	p := w.provider("Race CA", false)
	second := w.otherProcess()
	errs := make(chan error, 2)
	for _, svc := range []*inventory.Service{w.svc, second} {
		go func() {
			_, err := svc.RegisterACMEAccount(w.ctx, w.admin, p.ID, "", true)
			errs <- err
		}()
	}
	var ok, exists int
	for range 2 {
		switch err := <-errs; {
		case err == nil:
			ok++
		case errors.Is(err, inventory.ErrACMEAccountExists):
			exists++
		default:
			t.Errorf("unexpected error %v", err)
		}
	}
	assert.Equal(t, 1, ok)
	assert.Equal(t, 1, exists)
	assert.Len(t, w.accountStates(p.ID), 1)
	assert.Equal(t, 1, w.audits("acme.account.registered"))
}

// I1: a second process can neither recover nor otherwise touch a provider's account while the first one is in the
// middle of a rollover (the advisory lock is held across the CA call), and after the first one ended with an unknown
// outcome it does not discard the young pending key; only an old pending key is settled.
func TestACMERolloverIsSerializedAcrossProcesses(t *testing.T) {
	w := newRegistryWorld(t, fakeacme.Options{})
	p := w.provider("Two processes", false)
	a := w.register(p)
	b := w.otherProcess()

	inCall, proceed := make(chan struct{}), make(chan struct{})
	w.svc.SetACMERolloverSeam(func(o acme.RolloverOutcome) acme.RolloverOutcome {
		close(inCall)
		<-proceed
		return acme.RolloverUnknown // the CA switched, process A never learned it
	})
	done := make(chan error, 1)
	go func() {
		_, err := w.svc.RolloverACMEAccount(w.ctx, w.admin, a.ID)
		done <- err
	}()
	<-inCall
	// Process A holds the provider's lock with its pending key committed and the CA already switched.
	for name, call := range map[string]func(ctx context.Context) error{
		"recover":    func(ctx context.Context) error { _, err := b.RecoverACMERollover(ctx, w.admin, a.ID); return err },
		"deactivate": func(ctx context.Context) error { _, err := b.DeactivateACMEAccount(ctx, w.admin, a.ID); return err },
		"rollover":   func(ctx context.Context) error { _, err := b.RolloverACMEAccount(ctx, w.admin, a.ID); return err },
		"register": func(ctx context.Context) error {
			_, err := b.RegisterACMEAccount(ctx, w.admin, p.ID, "", true)
			return err
		},
	} {
		began := time.Now()
		err := call(w.ctx)
		assert.ErrorIs(t, err, inventory.ErrACMEProviderBusy, "%s: process A holds the provider's lock", name)
		assert.Less(t, time.Since(began), 5*time.Second, "%s gives up after a bounded wait", name)
	}
	ctx, cancel := context.WithTimeout(w.ctx, 150*time.Millisecond)
	_, err := b.RecoverACMERollover(ctx, w.admin, a.ID)
	cancel()
	assert.ErrorIs(t, err, context.DeadlineExceeded, "a caller's own deadline ends the wait")
	assert.Len(t, w.accountStates(p.ID), 2, "the pending key is untouched")
	close(proceed)
	require.ErrorIs(t, <-done, inventory.ErrACMERolloverPending)
	w.svc.SetACMERolloverSeam(nil)

	// Process A is done; its pending key is young: process B refuses to decide, whatever the CA says now.
	_, err = b.RecoverACMERollover(w.ctx, w.admin, a.ID)
	assert.ErrorIs(t, err, inventory.ErrACMERolloverPending)
	_, _, err = b.ACMEAccountSigner(w.ctx, a.ID)
	assert.ErrorIs(t, err, inventory.ErrACMERolloverPending)
	states := w.accountStates(p.ID)
	require.Len(t, states, 2, "B never discards A's young pending key")

	// Old enough: B settles it to the key the CA holds, and the account keeps working.
	w.agePending(p.ID)
	n, err := b.RecoverACMERollover(w.ctx, w.admin, a.ID)
	require.NoError(t, err)
	assert.NotEqual(t, a.ID, n.ID)
	signer, _, err := b.ACMEAccountSigner(w.ctx, n.ID)
	require.NoError(t, err)
	u, err := w.lookup(signer)
	require.NoError(t, err)
	assert.Equal(t, a.AccountURL, u)
}

// M1: a deactivation whose answer was lost is finished by a retry (the CA says the account is gone).
func TestACMEDeactivateRetryAfterLostAnswer(t *testing.T) {
	w := newRegistryWorld(t, fakeacme.Options{})
	p := w.provider("Retry CA", false)
	a := w.register(p)
	signer, _, err := w.svc.ACMEAccountSigner(w.ctx, a.ID)
	require.NoError(t, err)
	hc, err := transport.New(string(w.fake.CAPEM()))
	require.NoError(t, err)
	c, err := acme.New(acme.Config{DirectoryURL: w.fake.DirectoryURL(), Key: signer, AccountURL: a.AccountURL, HTTPClient: hc})
	require.NoError(t, err)
	require.NoError(t, c.Deactivate(w.ctx), "the CA deactivated it; Alice never heard")

	d, err := w.svc.DeactivateACMEAccount(w.ctx, w.admin, a.ID)
	require.NoError(t, err)
	assert.Equal(t, inventory.ACMEAccountDeactivated, d.State)
	assert.Equal(t, []map[string]string{{"provider_id": p.ID.String(), "already_deactivated": "true"}}, w.auditDetails("acme.account.deactivated"))

	// Another failure is not taken for a deactivation.
	q := w.provider("Retry CA 2", false)
	b := w.register(q)
	require.NoError(t, w.fake.AddFault(fakeacme.Fault{Endpoint: "account", Kind: fakeacme.FaultServerInternal, Times: 0}))
	_, err = w.svc.DeactivateACMEAccount(w.ctx, w.admin, b.ID)
	assert.Equal(t, acme.ReasonProviderUnreachable, reasonOf(err), "%v", err)
	assert.Equal(t, map[uuid.UUID]string{b.ID: inventory.ACMEAccountActive}, w.accountStates(q.ID))
}

// Many callers on one provider at once (double clicks, retries) never deadlock the pool: a waiter holds no connection
// while it waits, so with a pool of 3 connections every caller returns quickly with success or a clean refusal.
func TestACMEProviderLockDoesNotStarveThePool(t *testing.T) {
	w := newRegistryWorld(t, fakeacme.Options{})
	p := w.provider("Crowded CA", false)
	cfg, err := pgxpool.ParseConfig(w.db.AppURL)
	require.NoError(t, err)
	cfg.MaxConns = 3
	small, err := pgxpool.NewWithConfig(w.ctx, cfg)
	require.NoError(t, err)
	t.Cleanup(small.Close)
	svc := inventory.New(inventory.Config{Pool: small, Keyring: w.keyring, Audit: w.audit, Clock: w.clock, License: w.lic,
		Registry: w.reg, Jobs: w.jobs})

	const n = 12
	ctx, cancel := context.WithTimeout(w.ctx, 30*time.Second)
	defer cancel()
	stop := make(chan struct{})
	maxHeld := make(chan int32, 1)
	go func() {
		var peak int32
		for {
			select {
			case <-stop:
				maxHeld <- peak
				return
			default:
			}
			if a := small.Stat().AcquiredConns(); a > peak {
				peak = a
			}
			time.Sleep(time.Millisecond)
		}
	}()
	began := time.Now()
	results := make(chan error, n)
	for range n {
		go func() {
			_, err := svc.RegisterACMEAccount(ctx, w.admin, p.ID, "", true)
			results <- err
		}()
	}
	var ok, refused int
	for range n {
		switch err := <-results; {
		case err == nil:
			ok++
		case errors.Is(err, inventory.ErrACMEProviderBusy), errors.Is(err, inventory.ErrACMEAccountExists):
			refused++
		default:
			t.Errorf("unexpected error %v", err)
		}
	}
	close(stop)
	assert.Equal(t, 1, ok, "exactly one account")
	assert.Equal(t, n-1, refused)
	assert.Less(t, time.Since(began), 15*time.Second, "no deadlock: everyone returns well before the deadline")
	assert.NoError(t, ctx.Err())
	assert.LessOrEqual(t, <-maxHeld, int32(3))
	assert.Len(t, w.accountStates(p.ID), 1)
}

// Task 13 fix round 2: the registration form reads the CA's directory first (no account, no record, no lock) and shows
// its terms; the registration is then bound to the terms that were shown.
func TestACMEProviderPreview(t *testing.T) {
	w := newRegistryWorld(t, fakeacme.Options{RequireEAB: true})
	p := w.provider("Preview CA", true)
	before := w.audits("acme.account.registered")
	got, err := w.svc.PreviewACMEProvider(w.ctx, p.ID)
	require.NoError(t, err)
	assert.Equal(t, inventory.ACMEProviderPreview{TermsOfServiceURL: w.fake.Credentials().TermsURL, ExternalAccountRequired: true,
		KeyChangeSupported: true, RenewalInfoSupported: true, Website: w.fake.BaseURL()}, got)
	assert.Equal(t, 2, w.fake.Counters()["directory"], "Discover: its own GET (renewalInfo) and the library's")
	assert.Equal(t, 2, w.requests(), "nothing but the directory")
	assert.Zero(t, w.fake.Counters()["new-account"]+w.fake.Counters()["new-nonce"], "no nonce, no registration")
	assert.Empty(t, w.accountStates(p.ID))
	assert.Equal(t, before, w.audits("acme.account.registered"))

	// Unsafe terms (http): not passed on, flagged; no terms at all: empty, not flagged.
	require.NoError(t, w.fake.Advertise("termsOfService", "http://ca.example.test/terms"))
	got, err = w.svc.PreviewACMEProvider(w.ctx, p.ID)
	require.NoError(t, err)
	assert.Empty(t, got.TermsOfServiceURL)
	assert.True(t, got.TermsURLUnsafe)
	require.NoError(t, w.fake.Advertise("termsOfService", "off"))
	got, err = w.svc.PreviewACMEProvider(w.ctx, p.ID)
	require.NoError(t, err)
	assert.Empty(t, got.TermsOfServiceURL)
	assert.False(t, got.TermsURLUnsafe)
	require.NoError(t, w.fake.Advertise("termsOfService", ""))

	// A provider that is unknown or deleted: ErrNotFound, nothing sent.
	gone := w.provider("Gone", false)
	require.NoError(t, w.svc.DeleteACMEProvider(w.ctx, w.admin, gone.ID))
	sent := w.requests()
	_, err = w.svc.PreviewACMEProvider(w.ctx, gone.ID)
	assert.ErrorIs(t, err, inventory.ErrNotFound)
	_, err = w.svc.PreviewACMEProvider(w.ctx, uuid.New())
	assert.ErrorIs(t, err, inventory.ErrNotFound)
	assert.Equal(t, sent, w.requests())

	// The CA's failures keep their closed reasons.
	down, err := w.svc.CreateACMEProvider(w.ctx, w.admin, inventory.ACMEProviderInput{Name: "Down", DirectoryURL: "https://127.0.0.1:1/directory"})
	require.NoError(t, err)
	_, err = w.svc.PreviewACMEProvider(w.ctx, down.ID)
	assert.Equal(t, acme.ReasonProviderUnreachable, reasonOf(err), "%v", err)
	untrusted, err := w.svc.CreateACMEProvider(w.ctx, w.admin, inventory.ACMEProviderInput{Name: "Untrusted", DirectoryURL: w.fake.DirectoryURL()})
	require.NoError(t, err)
	_, err = w.svc.PreviewACMEProvider(w.ctx, untrusted.ID)
	assert.Equal(t, acme.ReasonTLSTrustFailed, reasonOf(err), "%v", err)

	// In lock: the licence refusal, the CA is not contacted.
	w.clock.Advance(31 * 24 * time.Hour)
	require.NoError(t, w.lic.Tick(w.ctx))
	w.fake.ClearRequests()
	sent = w.requests()
	_, err = w.svc.PreviewACMEProvider(w.ctx, p.ID)
	assert.ErrorIs(t, err, license.ErrLocked)
	assert.Equal(t, sent, w.requests())
	assert.Empty(t, w.fake.Requests())
}

// The registration is refused when the CA's terms changed since they were shown (ALC-ACM-0003); the accepted URL is
// the one recorded.
func TestACMERegisterIsBoundToTheShownTerms(t *testing.T) {
	w := newRegistryWorld(t, fakeacme.Options{})
	p := w.provider("Terms CA", false)
	shown := w.fake.Credentials().TermsURL
	require.NoError(t, w.fake.Advertise("termsOfService", w.fake.BaseURL()+"/terms-v2"))
	_, err := w.svc.RegisterACMEAccountTerms(w.ctx, w.admin, p.ID, "", true, shown)
	assert.Equal(t, acme.ReasonTermsNotAccepted, reasonOf(err), "the terms changed after they were shown")
	assert.Zero(t, w.fake.Counters()["new-account"])
	require.NoError(t, w.fake.Advertise("termsOfService", "off"))
	_, err = w.svc.RegisterACMEAccountTerms(w.ctx, w.admin, p.ID, "", true, shown)
	assert.Equal(t, acme.ReasonTermsNotAccepted, reasonOf(err), "the CA has no terms any more: not what was shown")
	require.NoError(t, w.fake.Advertise("termsOfService", ""))
	a, err := w.svc.RegisterACMEAccountTerms(w.ctx, w.admin, p.ID, "", true, shown)
	require.NoError(t, err)
	assert.Equal(t, shown, a.TermsURL)
	assert.Equal(t, shown, w.auditDetails("acme.account.registered")[0]["tos_url"])
}

// Final review finding 4: a key rollover is refused while an order of a certificate of the provider runs (the order signs
// with the account key the rollover replaces); nothing is stored and the CA is not asked. Once the order ended, the
// rollover works.
func TestACMERolloverRefusedWhileAnOrderRuns(t *testing.T) {
	w := newRegistryWorld(t, fakeacme.Options{})
	p := w.provider("Busy CA", false)
	a := w.register(p)
	web := w.seedTarget("busy-web", "nginx", "web.example.test")
	cert, order := uuid.New(), uuid.New()
	_, err := w.db.Owner.Exec(w.ctx, `INSERT INTO acme_certificates (id, provider_id, account_id, names, key_type, challenge, http_target_id, state,
created_at, updated_at) VALUES ($1, $2, $3, '{www.example.test}', 'ecdsa_p256', 'http01', $4, 'issuing', now(), now())`, cert, p.ID, a.ID, web)
	require.NoError(t, err)
	_, err = w.db.Owner.Exec(w.ctx, `INSERT INTO acme_orders (id, acme_certificate_id, kind, state, started_at) VALUES ($1, $2, 'issue', 'running', now())`,
		order, cert)
	require.NoError(t, err)
	w.fake.ClearRequests()

	_, err = w.svc.RolloverACMEAccount(w.ctx, w.admin, a.ID)
	assert.ErrorIs(t, err, inventory.ErrACMEOrderRunning)
	assert.Equal(t, map[uuid.UUID]string{a.ID: inventory.ACMEAccountActive}, w.accountStates(p.ID), "no pending key is stored")
	assert.Empty(t, w.fake.Requests(), "the CA is not asked")

	_, err = w.db.Owner.Exec(w.ctx, "UPDATE acme_orders SET state = 'failed', finished_at = now(), error_code = 'job.lease_expired' WHERE id = $1", order)
	require.NoError(t, err)
	n, err := w.svc.RolloverACMEAccount(w.ctx, w.admin, a.ID)
	require.NoError(t, err)
	assert.Equal(t, inventory.ACMEAccountActive, n.State)
}
