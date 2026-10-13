//go:build integration

package inventory_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/acme"
	"alice/internal/acme/keygen"
	"alice/internal/acme/solver"
	"alice/internal/acme/transport"
	"alice/internal/inventory"
	"alice/internal/platform/db"
	"alice/internal/rbac"
	"alice/internal/testutil/fakeacme"
)

// acmeWorld is a harness with a running fake ACME CA, a registered client and the rows an order needs.
type acmeWorld struct {
	*harness
	fake       *fakeacme.Server
	client     *acme.Client
	ctx        context.Context
	httpTarget uuid.UUID // the Nginx server of the HTTP-01 certificates (seeded on first use)
}

func newACMEWorld(t *testing.T) *acmeWorld {
	t.Helper()
	h := newHarness(t)
	fake, err := fakeacme.New(fakeacme.Options{Now: h.clock.Now, NoTerms: true})
	require.NoError(t, err)
	require.NoError(t, fake.Start())
	t.Cleanup(fake.Close)
	hc, err := transport.New(string(fake.CAPEM()))
	require.NoError(t, err)
	accountKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	client, err := acme.New(acme.Config{DirectoryURL: fake.DirectoryURL(), Key: accountKey, HTTPClient: hc})
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	t.Cleanup(cancel)
	_, err = client.RegisterAccount(ctx, "admin@example.test", nil, false)
	require.NoError(t, err)
	return &acmeWorld{harness: h, fake: fake, client: client, ctx: ctx}
}

// provider inserts a provider (with the CA bundle) and its active account; it returns the provider and account.
func (w *acmeWorld) provider(bundle string) (uuid.UUID, uuid.UUID) {
	w.t.Helper()
	pid, aid := uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7())
	now := w.clock.Now()
	_, err := w.db.Owner.Exec(w.ctx, `INSERT INTO acme_providers (id, name, directory_url, ca_bundle_pem, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $5)`, pid, "CA "+pid.String()[:13], w.fake.DirectoryURL(), bundle, now)
	require.NoError(w.t, err)
	_, err = w.db.Owner.Exec(w.ctx, `INSERT INTO acme_accounts (id, provider_id, key_ct, key_nonce, key_wrapped_dek, key_version, state, created_at, updated_at)
VALUES ($1, $2, '\x01', '\x000000000000000000000000', '\x01', 1, 'active', $3, $3)`, aid, pid, now)
	require.NoError(w.t, err)
	return pid, aid
}

// certificate inserts an ACME certificate of the provider for names and policy.
func (w *acmeWorld) certificate(provider, account uuid.UUID, policy keygen.KeyPolicy, names ...string) uuid.UUID {
	w.t.Helper()
	id := uuid.Must(uuid.NewV7())
	if w.httpTarget == uuid.Nil {
		w.httpTarget = w.seedTarget("acme-web", "nginx", "web.example.test")
	}
	_, err := w.db.Owner.Exec(w.ctx, `INSERT INTO acme_certificates (id, provider_id, account_id, names, key_type, challenge, http_target_id, state,
    failures, last_error_code, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, 'http01', $7, 'issuing', 2, 'acme.hook_refused', $6, $6)`, id, provider, account, names, string(policy), w.clock.Now(),
		w.httpTarget)
	require.NoError(w.t, err)
	return id
}

// order inserts a running order of the ACME certificate; requestedBy may be uuid.Nil.
func (w *acmeWorld) order(acmeCertificate uuid.UUID, kind string, requestedBy uuid.UUID) uuid.UUID {
	w.t.Helper()
	id := uuid.Must(uuid.NewV7())
	var by *uuid.UUID
	if requestedBy != uuid.Nil {
		by = &requestedBy
	}
	_, err := w.db.Owner.Exec(w.ctx, `INSERT INTO acme_orders (id, acme_certificate_id, kind, state, started_at, requested_by)
VALUES ($1, $2, $3, 'running', $4, $5)`, id, acmeCertificate, kind, w.clock.Now(), by)
	require.NoError(w.t, err)
	return id
}

// begin runs BeginACMEOrderKey in its own committed transaction (as the job's NewACMEOrderKey does) and checks
// that the key has the policy the test expects: the ACME certificate's key_type, read from the database.
func (w *acmeWorld) begin(order uuid.UUID, policy keygen.KeyPolicy) (crypto.Signer, error) {
	var signer crypto.Signer
	err := db.InTx(w.ctx, w.db.App, func(tx pgx.Tx) error {
		var err error
		signer, err = w.svc.BeginACMEOrderKey(w.ctx, tx, order)
		return err
	})
	if err == nil {
		got, perr := keygen.PolicyOf(signer.Public())
		require.NoError(w.t, perr)
		require.Equal(w.t, policy, got, "the key policy is the ACME certificate's")
	}
	return signer, err
}

// issue orders names from the fake with a CSR of signer (DNS-01 published straight into the fake's DNS).
func (w *acmeWorld) issue(signer crypto.Signer, names ...string) [][]byte {
	w.t.Helper()
	csr, err := keygen.NewCSR(signer, names)
	require.NoError(w.t, err)
	sol := solver.NewMemory(solver.DNS01)
	sol.AfterPresent = func(_ context.Context, ch solver.Challenge) error { w.fake.DNSSet(ch.DNSName, ch.DNSValue); return nil }
	sol.AfterCleanUp = func(_ context.Context, ch solver.Challenge) error {
		w.fake.DNSClear(ch.DNSName, ch.DNSValue)
		return nil
	}
	chain, err := w.client.Order(w.ctx, names, csr, sol)
	require.NoError(w.t, err)
	return chain
}

type orderRow struct {
	State, ErrorCode string
	CertificateID    *uuid.UUID
	FinishedAt       *time.Time
	KeyColumns       int // pending_key_* columns that are not NULL
}

func (w *acmeWorld) orderRow(id uuid.UUID) orderRow {
	w.t.Helper()
	var r orderRow
	require.NoError(w.t, w.db.Owner.QueryRow(w.ctx, `SELECT state, error_code, certificate_id, finished_at,
    (pending_key_ct IS NOT NULL)::int + (pending_key_nonce IS NOT NULL)::int + (pending_key_wrapped_dek IS NOT NULL)::int
    + (pending_key_version IS NOT NULL)::int FROM acme_orders WHERE id = $1`, id).Scan(&r.State, &r.ErrorCode, &r.CertificateID, &r.FinishedAt, &r.KeyColumns))
	return r
}

func samePublic(t *testing.T, a, b crypto.PublicKey) bool {
	t.Helper()
	k, ok := a.(interface{ Equal(crypto.PublicKey) bool })
	require.True(t, ok)
	return k.Equal(b)
}

// The whole record of an issued certificate, for every key policy, with a real chain from the fake CA.
func TestACMEFinishEveryKeyPolicy(t *testing.T) {
	w := newACMEWorld(t)
	pid, aid := w.provider(string(w.fake.IssuerRootPEM()))
	requester := w.user("acme-operator", rbac.Operator, "")
	for _, policy := range keygen.Policies() {
		t.Run(string(policy), func(t *testing.T) {
			name := strings.ReplaceAll(string(policy), "_", "-") + ".example.test"
			cid := w.certificate(pid, aid, policy, name)
			oid := w.order(cid, "issue", requester.UserID)
			signer, err := w.begin(oid, policy)
			require.NoError(t, err)
			assert.Equal(t, 4, w.orderRow(oid).KeyColumns, "the pending key is sealed into the order")
			got, err := keygen.PolicyOf(signer.Public())
			require.NoError(t, err)
			assert.Equal(t, policy, got)

			chain := w.issue(signer, name)
			issued, err := w.svc.FinishACMEOrder(w.ctx, oid, chain)
			require.NoError(t, err)
			assert.False(t, issued.Reused)
			assert.True(t, issued.ChainComplete, "the provider's bundle completes the private chain (A3)")
			assert.Empty(t, issued.Warnings)
			leaf, err := x509.ParseCertificate(chain[0])
			require.NoError(t, err)

			c, err := w.svc.GetCertificate(w.ctx, issued.CertificateID)
			require.NoError(t, err)
			assert.Equal(t, "acme", c.Source)
			assert.Equal(t, issued.Fingerprint, c.Fingerprint)
			assert.True(t, c.ChainComplete)
			assert.Equal(t, []string{name}, c.SANs)
			var keyID uuid.UUID
			var owner, alg string
			var bits int
			var createdBy *uuid.UUID
			require.NoError(t, w.db.Owner.QueryRow(w.ctx, `SELECT k.id, k.owner_type, k.algorithm, k.bits, c.created_by FROM certificates c
JOIN managed_private_keys k ON k.id = c.private_key_id WHERE c.id = $1`, issued.CertificateID).Scan(&keyID, &owner, &alg, &bits, &createdBy))
			wantAlg, wantBits, err := policy.Algorithm()
			require.NoError(t, err)
			assert.Equal(t, "certificate", owner)
			assert.Equal(t, wantAlg, alg)
			assert.Equal(t, wantBits, bits)
			require.NotNil(t, createdBy)
			assert.Equal(t, requester.UserID, *createdBy)
			der, err := w.svc.LoadKey(w.ctx, keyID)
			require.NoError(t, err)
			stored, err := keygen.ParsePKCS8(der)
			require.NoError(t, err)
			assert.True(t, samePublic(t, stored.Signer.Public(), leaf.PublicKey), "the stored key is the leaf's")
			der.Zero()

			var current *uuid.UUID
			var state, lastError string
			var failures int
			var next *time.Time
			require.NoError(t, w.db.Owner.QueryRow(w.ctx, `SELECT current_certificate_id, state, failures, last_error_code, next_attempt_at
FROM acme_certificates WHERE id = $1`, cid).Scan(&current, &state, &failures, &lastError, &next))
			require.NotNil(t, current)
			assert.Equal(t, issued.CertificateID, *current)
			assert.Equal(t, "active", state)
			assert.Zero(t, failures)
			assert.Empty(t, lastError)
			assert.Nil(t, next)

			r := w.orderRow(oid)
			assert.Equal(t, "succeeded", r.State)
			assert.Zero(t, r.KeyColumns, "the pending key is gone")
			require.NotNil(t, r.CertificateID)
			assert.Equal(t, issued.CertificateID, *r.CertificateID)
			assert.NotNil(t, r.FinishedAt)

			// A finished order cannot get a key or be finished again.
			_, err = w.begin(oid, policy)
			require.ErrorIs(t, err, inventory.ErrACMEOrderNotRunning)
			_, err = w.svc.FinishACMEOrder(w.ctx, oid, chain)
			require.ErrorIs(t, err, inventory.ErrACMEOrderNotRunning)
			_, err = w.svc.LoadPendingKey(w.ctx, oid)
			require.ErrorIs(t, err, inventory.ErrACMEOrderNotRunning)
			require.ErrorIs(t, w.svc.AbortACMEOrder(w.ctx, oid, "acme.directory_invalid"), inventory.ErrACMEOrderNotRunning)
		})
	}
	details := w.auditDetails("acme.order.succeeded")
	require.Len(t, details, len(keygen.Policies()))
	d := details[0]
	assert.Equal(t, "ecdsa-p256.example.test", d["names"])
	assert.Equal(t, "1", d["names_count"])
	assert.Equal(t, "ecdsa", d["algorithm"])
	assert.Equal(t, "256", d["bits"])
	assert.Equal(t, "true", d["chain_complete"])
	assert.Equal(t, "false", d["reused"])
	for _, k := range []string{"order_id", "acme_certificate_id", "certificate_id", "fingerprint"} {
		assert.NotEmpty(t, d[k], k)
	}
	assert.Len(t, d, 11, "nothing else is audited")

	// The certificate list filters the ACME certificates (A4).
	page, err := w.svc.ListCertificates(w.ctx, inventory.CertificateFilter{Source: "acme", Limit: 50})
	require.NoError(t, err)
	assert.Len(t, page.Items, len(keygen.Policies()))
	for _, c := range page.Items {
		assert.Equal(t, "acme", c.Source)
	}
	page, err = w.svc.ListCertificates(w.ctx, inventory.CertificateFilter{Source: "uploaded", Limit: 50})
	require.NoError(t, err)
	assert.Empty(t, page.Items)
}

// A3: a private CA's chain (leaf + intermediate, the root left out as CAs do) is complete with the provider's CA
// bundle and incomplete without it; the service's own roots do not change.
func TestACMEPrivateChainIsCompleteOnlyWithTheProviderBundle(t *testing.T) {
	w := newACMEWorld(t)
	withBundle, a1 := w.provider(string(w.fake.IssuerRootPEM()))
	without, a2 := w.provider("")
	for _, c := range []struct {
		provider, account uuid.UUID
		name              string
		complete          bool
	}{{withBundle, a1, "bundle.example.test", true}, {without, a2, "nobundle.example.test", false}, {withBundle, a1, "again.example.test", true}} {
		cid := w.certificate(c.provider, c.account, keygen.ECDSAP256, c.name)
		oid := w.order(cid, "issue", uuid.Nil)
		signer, err := w.begin(oid, keygen.ECDSAP256)
		require.NoError(t, err)
		issued, err := w.svc.FinishACMEOrder(w.ctx, oid, w.issue(signer, c.name))
		require.NoError(t, err)
		assert.Equal(t, c.complete, issued.ChainComplete, c.name)
		got, err := w.svc.GetCertificate(w.ctx, issued.CertificateID)
		require.NoError(t, err)
		assert.Equal(t, c.complete, got.ChainComplete, c.name)
		if c.complete {
			assert.Empty(t, issued.Warnings)
		} else {
			assert.Equal(t, []string{"chain_incomplete"}, issued.Warnings)
		}
		var by *uuid.UUID
		require.NoError(t, w.db.Owner.QueryRow(w.ctx, "SELECT created_by FROM certificates WHERE id = $1", issued.CertificateID).Scan(&by))
		assert.Nil(t, by, "a renewal nobody requested has no creator")
	}
}

func TestACMEFinishWildcard(t *testing.T) {
	w := newACMEWorld(t)
	pid, aid := w.provider(string(w.fake.IssuerRootPEM()))
	names := []string{"*.wild.example.test", "wild.example.test"}
	cid := w.certificate(pid, aid, keygen.ECDSAP384, names...)
	oid := w.order(cid, "issue", uuid.Nil)
	signer, err := w.begin(oid, keygen.ECDSAP384)
	require.NoError(t, err)
	issued, err := w.svc.FinishACMEOrder(w.ctx, oid, w.issue(signer, names...))
	require.NoError(t, err)
	c, err := w.svc.GetCertificate(w.ctx, issued.CertificateID)
	require.NoError(t, err)
	assert.ElementsMatch(t, names, c.SANs)
	assert.Equal(t, "*.wild.example.test,wild.example.test", w.auditDetails("acme.order.succeeded")[0]["names"])
}

// counts of everything a refused FinishACMEOrder must not have written.
func (w *acmeWorld) stored() [4]int {
	return [4]int{w.count("SELECT count(*) FROM certificates"), w.count("SELECT count(*) FROM managed_private_keys"),
		w.count("SELECT count(*) FROM audit_log WHERE action LIKE 'acme.%'"),
		w.count("SELECT count(*) FROM acme_certificates WHERE current_certificate_id IS NOT NULL")}
}

func TestACMEFinishRefusesAnotherKeyOrOtherNames(t *testing.T) {
	w := newACMEWorld(t)
	pid, aid := w.provider(string(w.fake.IssuerRootPEM()))
	cid := w.certificate(pid, aid, keygen.ECDSAP256, "mine.example.test")
	oid := w.order(cid, "issue", uuid.Nil)
	signer, err := w.begin(oid, keygen.ECDSAP256)
	require.NoError(t, err)
	before := w.stored()

	other, err := keygen.Generate(keygen.ECDSAP256)
	require.NoError(t, err)
	other.Zero()
	for name, chain := range map[string][][]byte{
		"a leaf of another key":           w.issue(other.Signer, "mine.example.test"),
		"a leaf without the ordered name": w.issue(signer, "other.example.test"),
		"the right leaf not first": func() [][]byte {
			c := w.issue(signer, "mine.example.test")
			return [][]byte{c[1], c[0]}
		}(),
		"no chain":    nil,
		"empty leaf":  {{}},
		"not a chain": {[]byte("not a certificate")},
	} {
		_, err := w.svc.FinishACMEOrder(w.ctx, oid, chain)
		require.Error(t, err, name)
		if name == "not a chain" {
			require.ErrorIs(t, err, inventory.ErrCertificateInvalid, name)
		} else {
			require.ErrorIs(t, err, inventory.ErrACMEChainMismatch, name)
		}
		assert.Equal(t, before, w.stored(), "%s: nothing is stored", name)
		r := w.orderRow(oid)
		assert.Equal(t, "running", r.State, name)
		assert.Equal(t, 4, r.KeyColumns, "%s: the pending key is kept for a retry or an abort", name)
	}
	// The order still finishes with the right chain.
	_, err = w.svc.FinishACMEOrder(w.ctx, oid, w.issue(signer, "mine.example.test"))
	require.NoError(t, err)
}

// A8: the process stops after the CA issued (or before it was asked); the pending key is recovered from the
// order and the order finishes.
func TestACMECrashRecovery(t *testing.T) {
	w := newACMEWorld(t)
	pid, aid := w.provider("")
	cid := w.certificate(pid, aid, keygen.RSA2048, "crash.example.test")
	oid := w.order(cid, "issue", uuid.Nil)
	first, err := w.begin(oid, keygen.RSA2048)
	require.NoError(t, err)
	chain := w.issue(first, "crash.example.test") // the CA issued; then the process died before FinishACMEOrder

	// A new service (a restarted process) on the same database and master key.
	restarted := inventory.New(inventory.Config{Pool: w.db.App, Keyring: w.keyring, Audit: w.audit, Clock: w.clock, License: w.lic,
		Registry: w.reg, Jobs: w.jobs})
	signer, err := restarted.LoadPendingKey(w.ctx, oid)
	require.NoError(t, err)
	leaf, err := x509.ParseCertificate(chain[0])
	require.NoError(t, err)
	assert.True(t, samePublic(t, signer.Public(), leaf.PublicKey), "the recovered key is the order's")
	// It signs: a fresh CSR works too.
	_, err = keygen.NewCSR(signer, []string{"crash.example.test"})
	require.NoError(t, err)
	issued, err := restarted.FinishACMEOrder(w.ctx, oid, chain)
	require.NoError(t, err)
	assert.Equal(t, "succeeded", w.orderRow(oid).State)
	assert.Zero(t, w.orderRow(oid).KeyColumns)
	assert.NotEqual(t, uuid.Nil, issued.CertificateID)
}

func TestACMEAbortDeletesThePendingKey(t *testing.T) {
	w := newACMEWorld(t)
	pid, aid := w.provider("")
	cid := w.certificate(pid, aid, keygen.ECDSAP256, "abort.example.test")
	oid := w.order(cid, "issue", uuid.Nil)
	_, err := w.begin(oid, keygen.ECDSAP256)
	require.NoError(t, err)

	require.ErrorIs(t, w.svc.AbortACMEOrder(w.ctx, oid, ""), inventory.ErrACMEErrorCode)
	require.ErrorIs(t, w.svc.AbortACMEOrder(w.ctx, oid, "the CA said: no"), inventory.ErrACMEErrorCode)
	require.ErrorIs(t, w.svc.AbortACMEOrder(w.ctx, oid, strings.Repeat("a", 101)), inventory.ErrACMEErrorCode)
	require.ErrorIs(t, w.svc.AbortACMEOrder(w.ctx, uuid.New(), "acme.hook_refused"), inventory.ErrNotFound)

	require.NoError(t, w.svc.AbortACMEOrder(w.ctx, oid, "acme.hook_refused"))
	r := w.orderRow(oid)
	assert.Equal(t, "failed", r.State)
	assert.Equal(t, "acme.hook_refused", r.ErrorCode)
	assert.Zero(t, r.KeyColumns, "all four pending key columns are NULL")
	assert.NotNil(t, r.FinishedAt)
	assert.Nil(t, r.CertificateID)
	_, err = w.svc.LoadPendingKey(w.ctx, oid)
	require.ErrorIs(t, err, inventory.ErrACMEOrderNotRunning)

	d := w.auditDetails("acme.order.failed")
	require.Len(t, d, 1)
	assert.Equal(t, map[string]string{"order_id": oid.String(), "acme_certificate_id": cid.String(), "kind": "issue",
		"error_code": "acme.hook_refused"}, d[0])

	// Again: nothing changes, no second row.
	require.NoError(t, w.svc.AbortACMEOrder(w.ctx, oid, "acme.directory_invalid"))
	assert.Equal(t, "acme.hook_refused", w.orderRow(oid).ErrorCode)
	assert.Equal(t, 1, w.audits("acme.order.failed"))

	// A finished order is history (Z1017); only its pending key may go.
	_, err = w.db.App.Exec(w.ctx, "UPDATE acme_orders SET error_code = 'x' WHERE id = $1", oid)
	var pgErr *pgconn.PgError
	require.True(t, errors.As(err, &pgErr))
	assert.Equal(t, "Z1017", pgErr.Code)

	// A new order of the same certificate may start now (one running order per certificate).
	next := w.order(cid, "issue", uuid.Nil)
	_, err = w.begin(next, keygen.ECDSAP256)
	require.NoError(t, err)

	// A test run that fails has its own action.
	pid2, aid2 := w.provider("")
	cid2 := w.certificate(pid2, aid2, keygen.ECDSAP256, "test.example.test")
	test := w.order(cid2, "test", uuid.Nil)
	require.NoError(t, w.svc.AbortACMEOrder(w.ctx, test, "acme.validation_failed_dns"))
	d = w.auditDetails("acme.order.test_failed")
	require.Len(t, d, 1)
	assert.Equal(t, "test", d[0]["kind"])
}

// A failed order whose key was left behind (an abort that crashed between its two writes cannot happen: one
// transaction; this is a row damaged by hand) is cleaned by aborting again: the freeze trigger lets the key go.
func TestACMEAbortAgainRemovesALeftoverKey(t *testing.T) {
	w := newACMEWorld(t)
	pid, aid := w.provider("")
	cid := w.certificate(pid, aid, keygen.ECDSAP256, "left.example.test")
	oid := w.order(cid, "issue", uuid.Nil)
	_, err := w.begin(oid, keygen.ECDSAP256)
	require.NoError(t, err)
	_, err = w.db.Owner.Exec(w.ctx, "UPDATE acme_orders SET state = 'failed', finished_at = $2, error_code = 'internal' WHERE id = $1", oid, w.clock.Now())
	require.NoError(t, err)
	require.Equal(t, 4, w.orderRow(oid).KeyColumns)
	require.NoError(t, w.svc.AbortACMEOrder(w.ctx, oid, "acme.directory_invalid"))
	assert.Zero(t, w.orderRow(oid).KeyColumns)
	assert.Zero(t, w.audits("acme.order.failed"))
}

func TestACMEOrderKeyRefusals(t *testing.T) {
	w := newACMEWorld(t)
	pid, aid := w.provider("")
	cid := w.certificate(pid, aid, keygen.ECDSAP256, "refuse.example.test")
	oid := w.order(cid, "issue", uuid.Nil)

	_, err := w.begin(uuid.New(), keygen.ECDSAP256)
	require.ErrorIs(t, err, inventory.ErrNotFound)
	assert.Zero(t, w.orderRow(oid).KeyColumns)

	_, err = w.svc.LoadPendingKey(w.ctx, oid)
	require.ErrorIs(t, err, inventory.ErrACMEPendingKey, "no key yet")
	_, err = w.svc.FinishACMEOrder(w.ctx, oid, [][]byte{{1}})
	require.ErrorIs(t, err, inventory.ErrACMEPendingKey)
	_, err = w.svc.LoadPendingKey(w.ctx, uuid.New())
	require.ErrorIs(t, err, inventory.ErrNotFound)
	_, err = w.svc.FinishACMEOrder(w.ctx, uuid.New(), [][]byte{{1}})
	require.ErrorIs(t, err, inventory.ErrNotFound)

	_, err = w.begin(oid, keygen.ECDSAP256)
	require.NoError(t, err)
	_, err = w.begin(oid, keygen.ECDSAP256)
	require.ErrorIs(t, err, inventory.ErrACMEPendingKey, "a second key is never generated over the first")

	// Only one running order per ACME certificate (acme_orders_one_running).
	_, err = w.db.App.Exec(w.ctx, `INSERT INTO acme_orders (id, acme_certificate_id, kind, state, started_at) VALUES ($1, $2, 'issue', 'running', $3)`,
		uuid.New(), cid, w.clock.Now())
	var pgErr *pgconn.PgError
	require.True(t, errors.As(err, &pgErr))
	assert.Equal(t, "23505", pgErr.Code)

	// A test run has no key.
	pid2, aid2 := w.provider("")
	test := w.order(w.certificate(pid2, aid2, keygen.ECDSAP256, "t.example.test"), "test", uuid.Nil)
	_, err = w.begin(test, keygen.ECDSAP256)
	require.ErrorIs(t, err, inventory.ErrACMEOrderNotRunning)
	_, err = w.svc.LoadPendingKey(w.ctx, test)
	require.ErrorIs(t, err, inventory.ErrACMEOrderNotRunning)
	_, err = w.svc.FinishACMEOrder(w.ctx, test, [][]byte{{1}})
	require.ErrorIs(t, err, inventory.ErrACMEOrderNotRunning)

	// The rolled-back transaction of a failed BeginACMEOrderKey left nothing: a new order of another
	// certificate whose insert transaction fails keeps no key.
	pid3, aid3 := w.provider("")
	cid3 := w.certificate(pid3, aid3, keygen.ECDSAP256, "rollback.example.test")
	oid3 := w.order(cid3, "issue", uuid.Nil)
	boom := errors.New("the job's transaction failed later")
	err = db.InTx(w.ctx, w.db.App, func(tx pgx.Tx) error {
		if _, err := w.svc.BeginACMEOrderKey(w.ctx, tx, oid3); err != nil {
			return err
		}
		return boom
	})
	require.ErrorIs(t, err, boom)
	assert.Zero(t, w.orderRow(oid3).KeyColumns)
}

// The CA returns a certificate Alice already holds: with its key (uploaded meanwhile) it is reused without a
// second key row; its incomplete chain is completed by the provider's bundle.
func TestACMEFinishReusesAHeldCertificate(t *testing.T) {
	w := newACMEWorld(t)
	pid, aid := w.provider(string(w.fake.IssuerRootPEM()))
	cid := w.certificate(pid, aid, keygen.ECDSAP256, "held.example.test")
	oid := w.order(cid, "issue", uuid.Nil)
	signer, err := w.begin(oid, keygen.ECDSAP256)
	require.NoError(t, err)
	chain := w.issue(signer, "held.example.test")

	// Someone uploads the very same leaf with its key, without the chain (Alice's roots lack the fake's root).
	keyDER, err := x509.MarshalPKCS8PrivateKey(signer)
	require.NoError(t, err)
	admin := w.user("acme-admin", rbac.Admin, "")
	up, _, err := w.svc.UploadCertificate(w.ctx, admin, inventory.UploadInput{
		CertificatePEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: chain[0]})),
		PrivateKeyPEM:  string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})),
	})
	require.NoError(t, err)
	require.False(t, up.ChainComplete)
	keys := w.count("SELECT count(*) FROM managed_private_keys")

	issued, err := w.svc.FinishACMEOrder(w.ctx, oid, chain)
	require.NoError(t, err)
	assert.True(t, issued.Reused)
	assert.Equal(t, up.ID, issued.CertificateID)
	assert.True(t, issued.ChainComplete)
	assert.Equal(t, keys, w.count("SELECT count(*) FROM managed_private_keys"), "no second key row")
	got, err := w.svc.GetCertificate(w.ctx, up.ID)
	require.NoError(t, err)
	assert.True(t, got.ChainComplete, "the bundle completed the held chain")
	assert.Equal(t, "uploaded", got.Source, "the held certificate keeps its source")
	assert.Equal(t, "true", w.auditDetails("acme.order.succeeded")[0]["reused"])
	assert.Zero(t, w.orderRow(oid).KeyColumns)

	// A held certificate with a complete chain (uploaded with the root) is reused as it is.
	cid2 := w.certificate(pid, aid, keygen.ECDSAP256, "held2.example.test")
	oid2 := w.order(cid2, "issue", uuid.Nil)
	signer2, err := w.begin(oid2, keygen.ECDSAP256)
	require.NoError(t, err)
	chain2 := w.issue(signer2, "held2.example.test")
	keyDER2, err := x509.MarshalPKCS8PrivateKey(signer2)
	require.NoError(t, err)
	var full []byte
	for _, der := range chain2 {
		full = append(full, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	full = append(full, w.fake.IssuerRootPEM()...)
	up2, _, err := w.svc.UploadCertificate(w.ctx, admin, inventory.UploadInput{CertificatePEM: string(full),
		PrivateKeyPEM: string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER2}))})
	require.NoError(t, err)
	require.True(t, up2.ChainComplete)
	keys = w.count("SELECT count(*) FROM managed_private_keys")
	issued2, err := w.svc.FinishACMEOrder(w.ctx, oid2, chain2)
	require.NoError(t, err)
	assert.True(t, issued2.Reused)
	assert.Equal(t, up2.ID, issued2.CertificateID)
	assert.True(t, issued2.ChainComplete)
	assert.Equal(t, keys, w.count("SELECT count(*) FROM managed_private_keys"))
}

// No form of a generated private key reaches a table other than as the sealed columns, a log line, an audit
// row or a returned value; no PEM private key header is stored anywhere.
func TestACMENoPrivateKeyLeaks(t *testing.T) {
	w := newACMEWorld(t)
	pid, aid := w.provider(string(w.fake.IssuerRootPEM()))
	var markers []string
	var values []string
	for i, policy := range []keygen.KeyPolicy{keygen.ECDSAP256, keygen.RSA2048} {
		name := []string{"leak-a.example.test", "leak-b.example.test"}[i]
		cid := w.certificate(pid, aid, policy, name)
		oid := w.order(cid, "issue", uuid.Nil)
		signer, err := w.begin(oid, policy)
		require.NoError(t, err)
		markers = append(markers, secretMarkers(t, signer)...)
		der, err := x509.MarshalPKCS8PrivateKey(signer)
		require.NoError(t, err)
		markers = append(markers, base64.StdEncoding.EncodeToString(der)[:64])
		// While the order runs, its row holds the key sealed only.
		var ct []byte
		require.NoError(t, w.db.Owner.QueryRow(w.ctx, "SELECT pending_key_ct FROM acme_orders WHERE id = $1", oid).Scan(&ct))
		assert.NotContains(t, string(ct), string(der[len(der)-32:]))
		chain := w.issue(signer, name)
		recovered, err := w.svc.LoadPendingKey(w.ctx, oid)
		require.NoError(t, err)
		issued, err := w.svc.FinishACMEOrder(w.ctx, oid, chain)
		require.NoError(t, err)
		values = append(values, sprintAll(issued, recovered != nil))
	}
	// A failed order too.
	cid := w.certificate(pid, aid, keygen.ECDSAP256, "leak-c.example.test")
	oid := w.order(cid, "issue", uuid.Nil)
	signer, err := w.begin(oid, keygen.ECDSAP256)
	require.NoError(t, err)
	markers = append(markers, secretMarkers(t, signer)...)
	require.NoError(t, w.svc.AbortACMEOrder(w.ctx, oid, "acme.not_issued_in_time"))
	_, err = w.svc.FinishACMEOrder(w.ctx, oid, [][]byte{{1}})
	values = append(values, sprintAll(err))

	rows, err := w.db.Owner.Query(w.ctx, "SELECT table_name FROM information_schema.tables WHERE table_schema = 'public' AND table_type = 'BASE TABLE'")
	require.NoError(t, err)
	tables, err := pgx.CollectRows(rows, pgx.RowTo[string])
	require.NoError(t, err)
	haystacks := append([]string{w.logs.String()}, values...)
	for _, name := range tables {
		var dump string
		require.NoError(t, w.db.Owner.QueryRow(w.ctx, "SELECT coalesce(string_agg(t::text, E'\\n'), '') FROM "+pgx.Identifier{name}.Sanitize()+" t").
			Scan(&dump))
		haystacks = append(haystacks, dump)
	}
	require.Equal(t, 2, w.audits("acme.order.succeeded"))
	for _, hay := range haystacks {
		flat := strings.NewReplacer("\n", "", "\r", "").Replace(hay)
		assert.NotContains(t, flat, "PRIVATE KEY")
		for _, m := range markers {
			require.NotContains(t, flat, m, "a private key leaked")
		}
	}
}

func sprintAll(vs ...any) string {
	var b strings.Builder
	for _, v := range vs {
		fmt.Fprintf(&b, "%v %+v %#v ", v, v, v)
	}
	return b.String()
}
