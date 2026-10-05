//go:build integration

package inventory_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/certs"
	"alice/internal/inventory"
	"alice/internal/jobs"
	"alice/internal/license"
	"alice/internal/platform/azureid"
	"alice/internal/providers"
	"alice/internal/providers/fake"
	"alice/internal/rbac"
	"alice/internal/testutil/pki"
)

// ver is the n-th version ID.
func ver(n int) string { return fmt.Sprintf("%032x", n) }

// kvLeaf issues a leaf for a vault certificate.
func (h *harness) kvLeaf(cn string) pki.Leaf {
	return pki.NewCA("KV CA "+cn, pki.ECDSA256, h.clock.Now()).Issue(pki.Opts{CommonName: cn, SANs: []string{cn}}, h.clock.Now())
}

func thumbOf(l pki.Leaf) string { return azureid.ThumbprintOf(l.Cert.Raw) }

// kvc is one listed certificate whose current version is version (with the details a provider reads
// when the pair changed) or, without details, only the listing's view.
func (h *harness) kvc(name string, l pki.Leaf, version string, updated time.Time, details bool, older ...string) providers.KVCertificate {
	th := thumbOf(l)
	nb, exp, created := l.Cert.NotBefore.UTC(), l.Cert.NotAfter.UTC(), updated
	c := providers.KVCertificate{Name: name, Thumbprint: th, Enabled: true, NotBefore: &nb, Expires: &exp, Created: &created, Updated: &updated}
	if details {
		c.Details = &providers.KVCertificateDetails{Version: version, Thumbprint: th, Updated: &updated, CER: l.Cert.Raw,
			Exportable: ptr(true), KeyType: "ecdsa", KeySize: 256, ContentType: "pkcs12", IssuerName: "Unknown", AutoRenew: true}
		c.Versions = []providers.KVCertificateVersion{{Version: version, Thumbprint: th, Enabled: true, NotBefore: &nb, Expires: &exp, Created: &created}}
		for i, v := range older {
			old := created.Add(-time.Duration(i+1) * time.Hour)
			c.Versions = append(c.Versions, providers.KVCertificateVersion{Version: v, Thumbprint: fmt.Sprintf("%040x", i+1), Enabled: true,
				NotBefore: &nb, Expires: &exp, Created: &old})
		}
	}
	return c
}

func kvResult(cs ...providers.KVCertificate) providers.DiscoveryResult {
	return providers.DiscoveryResult{KV: &providers.KVInventory{Certificates: cs}}
}

func kvKey(name string, managed bool, updated time.Time, details bool) providers.KVKey {
	k := providers.KVKey{Name: name, Enabled: true, Managed: managed, Updated: &updated, Created: &updated}
	if details {
		k.Details = &providers.KVKeyDetails{Version: ver(7), KeyType: "rsa", Size: 2048}
	}
	return k
}

func kvSecret(name string, updated time.Time) providers.KVSecret {
	return providers.KVSecret{Name: name, ContentType: "text/plain", Enabled: true, Updated: &updated, Created: &updated}
}

func (h *harness) vault(name string) uuid.UUID {
	h.t.Helper()
	return h.seedTarget(name, "azure_key_vault", name+".vault.azure.net")
}

func (h *harness) reconcile(vault uuid.UUID, res providers.DiscoveryResult) inventory.KVSummary {
	h.t.Helper()
	sum, err := h.svc.ReconcileKV(h.ctx, vault, res)
	require.NoError(h.t, err)
	return sum
}

type certRow struct {
	ID                                  uuid.UUID
	Name, Version, Thumb, ListedThumb   string
	Enabled, Pending                    bool
	KVUpdated, Missing, RemovedNotified *time.Time
	LastSeen, FirstSeen                 time.Time
	Exportable                          *bool
	KeyType, ContentType, Issuer        string
	KeySize                             int
	AutoRenew                           bool
}

func (h *harness) certRow(vault uuid.UUID, name string) certRow {
	h.t.Helper()
	var r certRow
	require.NoError(h.t, h.db.Owner.QueryRow(h.ctx, `SELECT id, name, current_version, current_thumbprint, listed_thumbprint, enabled, details_pending,
kv_updated_at, missing_since, removed_notified_at, last_seen_at, first_seen_at, exportable, key_type, content_type, issuer_name, key_size, auto_renew
FROM kv_certificates WHERE target_id = $1 AND lower(name COLLATE "C") = lower($2 COLLATE "C")`, vault, name).Scan(&r.ID, &r.Name, &r.Version, &r.Thumb,
		&r.ListedThumb, &r.Enabled, &r.Pending, &r.KVUpdated, &r.Missing, &r.RemovedNotified, &r.LastSeen, &r.FirstSeen, &r.Exportable, &r.KeyType,
		&r.ContentType, &r.Issuer, &r.KeySize, &r.AutoRenew))
	return r
}

type versionRow struct {
	Version, Thumb, HeldReason string
	CertID                     *uuid.UUID
	Held                       bool
	Detected                   time.Time
	Created                    *time.Time
	Notified                   *time.Time
}

func (h *harness) versionRows(cert uuid.UUID) map[string]versionRow {
	h.t.Helper()
	rows, err := h.db.Owner.Query(h.ctx, `SELECT version, thumbprint, held_reason, certificate_id, held, detected_at, kv_created_at, notified_at
FROM kv_certificate_versions WHERE kv_certificate_id = $1`, cert)
	require.NoError(h.t, err)
	defer rows.Close()
	out := map[string]versionRow{}
	for rows.Next() {
		var v versionRow
		require.NoError(h.t, rows.Scan(&v.Version, &v.Thumb, &v.HeldReason, &v.CertID, &v.Held, &v.Detected, &v.Created, &v.Notified))
		out[v.Version] = v
	}
	require.NoError(h.t, rows.Err())
	return out
}

type vaultRow struct {
	Status, Code               string
	LastSuccess, LastDiscovery *time.Time
	PollFailures               int
	Facts                      inventory.Facts
}

func (h *harness) vaultRow(id uuid.UUID) vaultRow {
	h.t.Helper()
	var r vaultRow
	var raw []byte
	require.NoError(h.t, h.db.Owner.QueryRow(h.ctx, `SELECT status, last_error_code, last_success_at, last_discovery_at, poll_failures, facts
FROM targets WHERE id = $1`, id).Scan(&r.Status, &r.Code, &r.LastSuccess, &r.LastDiscovery, &r.PollFailures, &raw))
	require.NoError(h.t, json.Unmarshal(raw, &r.Facts))
	return r
}

// removalEmails counts the one-certificate removal mails (either text).
func (h *harness) removalEmails() int {
	return h.emails("kv.certificate_removed") + h.emails("kv.certificate_removed_bound")
}

func (h *harness) emails(template string) int {
	return h.count("SELECT count(*) FROM notifications_outbox WHERE template_key = $1", template)
}

// bindCertificate binds a vault certificate (no locations needed for the checks of a poll).
func (h *harness) bindCertificate(cert, vault uuid.UUID) uuid.UUID {
	h.t.Helper()
	id := uuid.Must(uuid.NewV7())
	_, err := h.db.Owner.Exec(h.ctx, "INSERT INTO bindings (id, kv_certificate_id, kv_target_id, created_at) VALUES ($1, $2, $3, $4)", id, cert, vault, h.clock.Now())
	require.NoError(h.t, err)
	return id
}

func TestFirstPollImportsInventoryOnly(t *testing.T) {
	h := newHarness(t, withAzure())
	h.user("ada", rbac.Admin, "ada@example.com")
	vault := h.vault("prod")
	la, lb := h.kvLeaf("a.example.test"), h.kvLeaf("b.example.test")
	now := h.clock.Now()
	res := kvResult(h.kvc("Web-Cert", la, ver(3), now, true, ver(2), ver(1)), h.kvc("api", lb, ver(9), now, true))
	res.KV.Keys = []providers.KVKey{kvKey("signing", false, now, true), kvKey("backing-key", true, now, false)}
	res.KV.KeysListed = true
	res.KV.Secrets = []providers.KVSecret{kvSecret("db-password", now), kvSecret("api-token", now), kvSecret("zzz", now)}
	res.KV.SecretsListed = true

	sum := h.reconcile(vault, res)
	assert.Equal(t, 2, sum.Certificates)
	assert.Equal(t, 2, sum.NewCertificates)
	assert.Zero(t, sum.NewVersions, "first sight is not a new version (§11.6 item 7)")
	assert.Equal(t, 2, sum.Keys)
	assert.Equal(t, 3, sum.Secrets)
	assert.Equal(t, inventory.StatusOK, sum.Status)

	a := h.certRow(vault, "web-cert")
	assert.Equal(t, "Web-Cert", a.Name, "the first spelling is kept")
	assert.Equal(t, ver(3), a.Version)
	assert.Equal(t, thumbOf(la), a.Thumb)
	assert.Equal(t, thumbOf(la), a.ListedThumb)
	assert.False(t, a.Pending)
	assert.True(t, a.Enabled)
	require.NotNil(t, a.Exportable)
	assert.True(t, *a.Exportable)
	assert.Equal(t, "ecdsa", a.KeyType)
	assert.Equal(t, 256, a.KeySize)
	assert.Equal(t, "pkcs12", a.ContentType)
	assert.Equal(t, "Unknown", a.Issuer)
	assert.True(t, a.AutoRenew)
	require.NotNil(t, a.KVUpdated)
	assert.True(t, now.Equal(*a.KVUpdated))
	assert.Nil(t, a.Missing)

	vs := h.versionRows(a.ID)
	require.Len(t, vs, 3)
	require.NotNil(t, vs[ver(3)].CertID, "the current version has its leaf")
	assert.Nil(t, vs[ver(2)].CertID, "older versions have none")
	assert.Nil(t, vs[ver(1)].CertID)
	assert.False(t, vs[ver(3)].Held)
	assert.True(t, now.Equal(vs[ver(3)].Detected))
	require.NotNil(t, vs[ver(3)].Created, "kv_created_at is stored (S14)")
	assert.Equal(t, 0, h.audits("kv.certificate.new_version"))

	var source, pem string
	var complete bool
	require.NoError(t, h.db.Owner.QueryRow(h.ctx, "SELECT source, pem_chain, chain_complete FROM certificates WHERE id = $1", *vs[ver(3)].CertID).Scan(&source, &pem, &complete))
	assert.Equal(t, "azure_kv", source)
	assert.Equal(t, string(la.CertPEM), pem, "the leaf only")
	parsed, err := certs.ParseChainPEM(la.CertPEM)
	require.NoError(t, err)
	assert.Equal(t, certs.ChainComplete(parsed, certs.SystemRoots(), now), complete, "chain_complete is ChainComplete's answer for the leaf alone")
	assert.Equal(t, 2, h.count("SELECT count(*) FROM certificates WHERE source = 'azure_kv'"))
	assert.Equal(t, 4, h.count("SELECT count(*) FROM kv_certificate_versions"))

	assert.Equal(t, 2, h.count("SELECT count(*) FROM kv_keys WHERE target_id = $1", vault))
	var typ string
	var size int
	var managed bool
	require.NoError(t, h.db.Owner.QueryRow(h.ctx, "SELECT key_type, key_size, managed FROM kv_keys WHERE name = 'signing'").Scan(&typ, &size, &managed))
	assert.Equal(t, "rsa", typ)
	assert.Equal(t, 2048, size)
	assert.False(t, managed)
	require.NoError(t, h.db.Owner.QueryRow(h.ctx, "SELECT managed FROM kv_keys WHERE name = 'backing-key'").Scan(&managed))
	assert.True(t, managed)
	assert.Equal(t, 3, h.count("SELECT count(*) FROM kv_secrets WHERE target_id = $1", vault))

	v := h.vaultRow(vault)
	assert.Equal(t, inventory.StatusOK, v.Status)
	assert.Empty(t, v.Code)
	require.NotNil(t, v.LastSuccess)
	assert.True(t, now.Equal(*v.LastSuccess))
	require.NotNil(t, v.LastDiscovery)
	assert.True(t, now.Equal(*v.LastDiscovery))
	assert.Zero(t, v.PollFailures)
	require.NotNil(t, v.Facts.KVMetadataAt, "keys and secrets were read")
	require.NotNil(t, v.Facts.KVPoll)
	assert.Empty(t, v.Facts.KVPoll.Failures)
	d := h.auditDetails("target.discovered")
	require.Len(t, d, 1)
	assert.Equal(t, map[string]string{"certificate_count": "2", "item_count": "5", "new_version_count": "0", "new_certificate_count": "2",
		"missing_count": "0", "removed_count": "0", "audited_count": "0", "notified_count": "0", "partial": "false"}, d[0])
	assert.Equal(t, 0, h.audits("target.status_changed"), "ok stays ok")
}

func TestNewVersionIsDetectedByVersionAndThumbprint(t *testing.T) {
	h := newHarness(t, withAzure())
	h.user("ada", rbac.Admin, "")
	vault := h.vault("prod")
	l1 := h.kvLeaf("www.example.test")
	t0 := h.clock.Now()
	h.reconcile(vault, kvResult(h.kvc("web-cert", l1, ver(1), t0, true)))
	c := h.certRow(vault, "web-cert")

	// The same (x5t, updated) without details: nothing changes but the sighting.
	h.clock.Advance(15 * time.Minute)
	sum := h.reconcile(vault, kvResult(h.kvc("web-cert", l1, "", t0, false)))
	assert.Zero(t, sum.NewVersions)
	got := h.certRow(vault, "web-cert")
	assert.Equal(t, ver(1), got.Version)
	assert.False(t, got.Pending)
	assert.True(t, h.clock.Now().Equal(got.LastSeen), "last_seen_at moved")
	assert.True(t, t0.Equal(got.FirstSeen))
	assert.Len(t, h.versionRows(c.ID), 1)

	// Same version, new updated (attributes edited): details refresh, no new version.
	h.clock.Advance(15 * time.Minute)
	t2 := h.clock.Now()
	edited := h.kvc("web-cert", l1, ver(1), t2, true)
	edited.Enabled = false
	sum = h.reconcile(vault, kvResult(edited))
	assert.Zero(t, sum.NewVersions)
	got = h.certRow(vault, "web-cert")
	assert.False(t, got.Enabled)
	require.NotNil(t, got.KVUpdated)
	assert.True(t, t2.Equal(*got.KVUpdated))
	vs := h.versionRows(c.ID)
	require.Len(t, vs, 1)
	assert.False(t, vs[ver(1)].Held)
	assert.Equal(t, 0, h.audits("kv.certificate.new_version"))

	// Listing differs but the details wait: the current version stays, the pending flag is set.
	h.clock.Advance(15 * time.Minute)
	l2 := h.kvLeaf("www.example.test")
	t3 := h.clock.Now()
	h.reconcile(vault, kvResult(h.kvc("web-cert", l2, "", t3, false)))
	got = h.certRow(vault, "web-cert")
	assert.Equal(t, ver(1), got.Version)
	assert.Equal(t, thumbOf(l2), got.ListedThumb)
	assert.True(t, got.Pending)
	assert.Equal(t, 0, h.audits("kv.certificate.new_version"))

	// The details arrive: a new version.
	h.clock.Advance(15 * time.Minute)
	t4 := h.clock.Now()
	renewed := h.kvc("web-cert", l2, ver(2), t4, true, ver(1))
	sum = h.reconcile(vault, kvResult(renewed))
	assert.Equal(t, 1, sum.NewVersions)
	assert.Zero(t, sum.HeldVersions)
	got = h.certRow(vault, "web-cert")
	assert.Equal(t, ver(2), got.Version)
	assert.Equal(t, thumbOf(l2), got.Thumb)
	assert.False(t, got.Pending)
	vs = h.versionRows(c.ID)
	require.Len(t, vs, 2, "the old version is kept as history")
	assert.True(t, t4.Equal(vs[ver(2)].Detected))
	require.NotNil(t, vs[ver(2)].CertID)
	require.NotNil(t, vs[ver(1)].CertID, "the old version keeps its leaf")
	assert.False(t, vs[ver(2)].Held)
	assert.Nil(t, vs[ver(2)].Notified, "the poll writes no notification mark: the planner owns it")
	ev := h.auditDetails("kv.certificate.new_version")
	require.Len(t, ev, 1)
	fp := ""
	require.NoError(t, h.db.Owner.QueryRow(h.ctx, "SELECT fingerprint_sha256 FROM certificates WHERE id = $1", *vs[ver(2)].CertID).Scan(&fp))
	assert.Equal(t, map[string]string{"kv_certificate_id": c.ID.String(), "certificate_name": "web-cert", "version": ver(2),
		"thumbprint": thumbOf(l2), "fingerprint": fp, "held": "false", "vault_url": "https://prod.vault.azure.net"}, ev[0])
	assert.Equal(t, 0, h.count("SELECT count(*) FROM jobs"), "a poll queues nothing")

	// The same result again (a repeated poll): nothing is written twice.
	h.clock.Advance(15 * time.Minute)
	sum = h.reconcile(vault, kvResult(renewed))
	assert.Zero(t, sum.NewVersions)
	assert.Equal(t, 1, h.audits("kv.certificate.new_version"))
	again := h.versionRows(c.ID)
	assert.True(t, t4.Equal(again[ver(2)].Detected), "first-seen time is written once")
}

func TestNewVersionInLockIsHeld(t *testing.T) {
	h := newHarness(t, withAzure())
	h.user("ada", rbac.Admin, "")
	vault := h.vault("prod")
	l1 := h.kvLeaf("www.example.test")
	h.reconcile(vault, kvResult(h.kvc("web-cert", l1, ver(1), h.clock.Now(), true)))
	c := h.certRow(vault, "web-cert")
	jobsBefore := len(h.jobs.requests())

	h.clock.Advance(31 * 24 * time.Hour)
	require.NoError(t, h.lic.Tick(h.ctx))
	require.ErrorIs(t, h.lic.Allow(license.ClassChange), license.ErrLocked, "the gate is closed")
	l2 := h.kvLeaf("www.example.test")
	sum := h.reconcile(vault, kvResult(h.kvc("web-cert", l2, ver(2), h.clock.Now(), true, ver(1))))
	assert.Equal(t, 1, sum.NewVersions)
	assert.Equal(t, 1, sum.HeldVersions)
	vs := h.versionRows(c.ID)
	assert.True(t, vs[ver(2)].Held)
	assert.Equal(t, "license", vs[ver(2)].HeldReason)
	assert.False(t, vs[ver(1)].Held)
	ev := h.auditDetails("kv.certificate.new_version")
	require.Len(t, ev, 1)
	assert.Equal(t, "true", ev[0]["held"])
	assert.Equal(t, "gate_closed", ev[0]["hold_rule"])
	assert.Equal(t, jobsBefore, len(h.jobs.requests()), "nothing is queued")
	assert.Equal(t, ver(2), h.certRow(vault, "web-cert").Version, "the metadata is stored")

	// A certificate first seen in lock: its version is held too, with no new-version audit.
	l3 := h.kvLeaf("new.example.test")
	h.reconcile(vault, kvResult(h.kvc("web-cert", l2, "", h.clock.Now(), false), h.kvc("fresh", l3, ver(5), h.clock.Now(), true)))
	fresh := h.versionRows(h.certRow(vault, "fresh").ID)
	assert.True(t, fresh[ver(5)].Held)
	assert.Equal(t, "license", fresh[ver(5)].HeldReason)
	assert.Equal(t, 1, h.audits("kv.certificate.new_version"))

	// The license comes back: a later poll with the gate open never releases a held version, and a
	// version first seen now is not held.
	h.clock.Advance(time.Minute) // the gate opens after the polls of the lock
	h.installLicense("LIC-HELD", 5, 365)
	require.NoError(t, h.lic.Allow(license.ClassChange), "the gate is open again")
	h.clock.Advance(15 * time.Minute)
	sum = h.reconcile(vault, kvResult(h.kvc("web-cert", l2, ver(2), h.clock.Now(), true, ver(1)), h.kvc("fresh", l3, ver(5), h.clock.Now(), true)))
	assert.Zero(t, sum.NewVersions)
	vs = h.versionRows(c.ID)
	assert.True(t, vs[ver(2)].Held, "a held version stays held (an Administrator releases it)")
	assert.Equal(t, "license", vs[ver(2)].HeldReason)
	assert.True(t, h.versionRows(h.certRow(vault, "fresh").ID)[ver(5)].Held)
	l4 := h.kvLeaf("www.example.test")
	sum = h.reconcile(vault, kvResult(h.kvc("web-cert", l4, ver(6), h.clock.Now(), true, ver(2), ver(1)), h.kvc("fresh", l3, "", h.clock.Now(), false)))
	assert.Equal(t, 1, sum.NewVersions)
	assert.Zero(t, sum.HeldVersions)
	assert.False(t, h.versionRows(c.ID)[ver(6)].Held)
}

// A version Azure created between the provider's read of the certificate's details and its read of the
// version list is first stored as history (no leaf). When it is the current version at the next poll it is a
// new version like any other: the hold rule applies and it gets its kv.certificate.new_version row (final
// review B M-1).
func TestAVersionFirstListedAsHistoryIsNewWhenItBecomesCurrent(t *testing.T) {
	h := newHarness(t, withAzure())
	h.user("ada", rbac.Admin, "")
	vault := h.vault("prod")
	l1 := h.kvLeaf("www.example.test")
	h.reconcile(vault, kvResult(h.kvc("web-cert", l1, ver(1), h.clock.Now(), true)))
	c := h.certRow(vault, "web-cert")

	h.clock.Advance(31 * 24 * time.Hour)
	require.NoError(t, h.lic.Tick(h.ctx))
	require.ErrorIs(t, h.lic.Allow(license.ClassChange), license.ErrLocked, "the gate is closed")
	l2 := h.kvLeaf("www.example.test")
	t1 := h.clock.Now()
	racing := h.kvc("web-cert", l1, ver(1), t1, true)
	nb, exp := l2.Cert.NotBefore.UTC(), l2.Cert.NotAfter.UTC()
	racing.Versions = append(racing.Versions, providers.KVCertificateVersion{Version: ver(2), Thumbprint: thumbOf(l2), Enabled: true,
		NotBefore: &nb, Expires: &exp, Created: &t1})
	sum := h.reconcile(vault, kvResult(racing))
	assert.Zero(t, sum.NewVersions)
	vs := h.versionRows(c.ID)
	require.Contains(t, vs, ver(2))
	assert.Nil(t, vs[ver(2)].CertID, "stored as history")
	assert.False(t, vs[ver(2)].Held)
	assert.Equal(t, 0, h.audits("kv.certificate.new_version"))

	h.clock.Advance(15 * time.Minute)
	sum = h.reconcile(vault, kvResult(h.kvc("web-cert", l2, ver(2), t1, true)))
	assert.Equal(t, 1, sum.NewVersions)
	assert.Equal(t, 1, sum.HeldVersions)
	vs = h.versionRows(c.ID)
	require.NotNil(t, vs[ver(2)].CertID, "the leaf is stored now")
	assert.True(t, vs[ver(2)].Held, "the hold rule of a new version applies")
	assert.Equal(t, "license", vs[ver(2)].HeldReason)
	ev := h.auditDetails("kv.certificate.new_version")
	require.Len(t, ev, 1)
	assert.Equal(t, ver(2), ev[0]["version"])
	assert.Equal(t, "gate_closed", ev[0]["hold_rule"])

	// A repeated poll writes nothing twice.
	h.clock.Advance(15 * time.Minute)
	sum = h.reconcile(vault, kvResult(h.kvc("web-cert", l2, ver(2), t1, true)))
	assert.Zero(t, sum.NewVersions)
	assert.Equal(t, 1, h.audits("kv.certificate.new_version"))
}

func TestMissingMarkingNeedsACompleteListing(t *testing.T) {
	h := newHarness(t, withAzure(), withNginxProvider())
	admin := h.user("ada", rbac.Admin, "ada@example.com")
	vault := h.vault("prod")
	web := nginxTarget(t, h, admin, "web-01")
	now := h.clock.Now()
	la, lb := h.kvLeaf("a.example.test"), h.kvLeaf("b.example.test")
	full := func() providers.DiscoveryResult {
		r := kvResult(h.kvc("alpha", la, ver(1), now, true), h.kvc("beta", lb, ver(2), now, true))
		r.KV.Keys = []providers.KVKey{kvKey("k1", false, now, true), kvKey("k2", false, now, true)}
		r.KV.KeysListed = true
		r.KV.Secrets = []providers.KVSecret{kvSecret("s1", now), kvSecret("s2", now)}
		r.KV.SecretsListed = true
		return r
	}
	h.reconcile(vault, full())
	alpha := h.certRow(vault, "alpha")
	binding := h.bindCertificate(alpha.ID, vault)
	ca := pki.NewCA("Bind", pki.ECDSA256, h.clock.Now())
	_, err := h.svc.Reconcile(h.ctx, web.ID, providers.DiscoveryResult{Nginx: nginxOK, Certificates: []providers.DiscoveredCertificate{
		dc(cl("/etc/nginx/ssl/www.crt", "/etc/nginx/ssl/www.key"), ca.Issue(pki.Opts{CommonName: "www.example.test"}, now))}})
	require.NoError(t, err)
	loc := byPath(t, h, web.ID, false)["/etc/nginx/ssl/www.crt"]
	_, err = h.db.Owner.Exec(h.ctx, "UPDATE certificate_locations SET binding_id = $2 WHERE id = $1", loc.ID, binding)
	require.NoError(t, err)

	onlyBeta := func() providers.DiscoveryResult {
		r := full()
		r.KV.Certificates = r.KV.Certificates[1:]
		return r
	}
	// A truncated listing, a failed one and a poll that did not ask for a kind mark nothing.
	h.clock.Advance(time.Minute)
	r := onlyBeta()
	r.KV.Truncated = []string{"certificates"}
	h.reconcile(vault, r)
	r = onlyBeta()
	r.KV.Certificates = nil
	r.KV.Failures = []providers.KVListFailure{{Object: "certificates", Err: providers.NewError("azure.forbidden", false, nil, nil)}}
	h.reconcile(vault, r)
	assert.Nil(t, h.certRow(vault, "alpha").Missing)
	assert.Nil(t, h.certRow(vault, "beta").Missing)
	r = full()
	r.KV.Keys, r.KV.KeysListed, r.KV.Secrets, r.KV.SecretsListed = nil, false, nil, false // keys and secrets not asked
	r.KV.Certificates = r.KV.Certificates[:1]                                             // beta is absent from a listing that asked for certificates only
	r.KV.Failures = nil
	h.reconcile(vault, r)
	assert.Equal(t, 0, h.count("SELECT count(*) FROM kv_keys WHERE missing_since IS NOT NULL"))
	assert.Equal(t, 0, h.count("SELECT count(*) FROM kv_secrets WHERE missing_since IS NOT NULL"))
	assert.Equal(t, 1, h.count("SELECT count(*) FROM kv_certificates WHERE missing_since IS NOT NULL"), "only beta, from the one complete certificate listing")
	assert.NotNil(t, h.certRow(vault, "beta").Missing)
	h.reconcile(vault, full()) // beta returns
	assert.Nil(t, h.certRow(vault, "beta").Missing)
	assert.Equal(t, 1, h.audits("kv.certificate.removed"), "beta's removal was reported once")
	assert.Equal(t, 1, h.removalEmails())

	// F-42: alpha disappears from a complete listing.
	h.clock.Advance(time.Minute)
	removedAt := h.clock.Now()
	sum := h.reconcile(vault, onlyBeta())
	assert.Equal(t, 1, sum.MissingCertificates)
	a := h.certRow(vault, "alpha")
	require.NotNil(t, a.Missing)
	assert.True(t, removedAt.Equal(*a.Missing))
	require.NotNil(t, a.RemovedNotified)
	assert.Equal(t, 2, h.audits("kv.certificate.removed"))
	ev := h.auditDetails("kv.certificate.removed")
	assert.Equal(t, map[string]string{"kv_certificate_id": alpha.ID.String(), "certificate_name": "alpha", "vault_url": "https://prod.vault.azure.net", "binding": "yes"}, ev[1])
	assert.Equal(t, 2, h.removalEmails())
	var params string
	require.NoError(t, h.db.Owner.QueryRow(h.ctx, "SELECT params::text FROM notifications_outbox WHERE template_key = 'kv.certificate_removed_bound' AND params->>'certificate_name' = 'alpha'").Scan(&params))
	assert.JSONEq(t, `{"target_name":"prod","certificate_name":"alpha"}`, params, "a bound certificate has its own text and no yes/no value")
	assert.Equal(t, 1, h.emails("kv.certificate_removed"), "beta was not bound")
	// The bound website is untouched.
	assert.Equal(t, 1, h.count("SELECT count(*) FROM bindings WHERE id = $1 AND deleted_at IS NULL", binding))
	assert.Equal(t, 1, h.count("SELECT count(*) FROM certificate_locations WHERE id = $1 AND binding_id = $2 AND missing_since IS NULL", loc.ID, binding))

	// Absent again: no second email, the time is not rewritten.
	h.clock.Advance(time.Minute)
	sum = h.reconcile(vault, onlyBeta())
	assert.Zero(t, sum.MissingCertificates)
	assert.Equal(t, 2, h.removalEmails())
	assert.True(t, removedAt.Equal(*h.certRow(vault, "alpha").Missing))
	// It returns: the mark clears. A later removal is a new episode (a second email, binding yes).
	h.clock.Advance(time.Minute)
	h.reconcile(vault, full())
	a = h.certRow(vault, "alpha")
	assert.Nil(t, a.Missing)
	assert.Nil(t, a.RemovedNotified)
	h.clock.Advance(time.Minute)
	h.reconcile(vault, onlyBeta())
	assert.Equal(t, 3, h.removalEmails())
	assert.Equal(t, 3, h.audits("kv.certificate.removed"))

	// An unbound certificate says binding "no".
	h.clock.Advance(time.Minute)
	h.reconcile(vault, full())
	// An empty complete listing is believed on the second poll in a row only (defence in depth).
	h.clock.Advance(time.Minute)
	h.reconcile(vault, kvResult())
	assert.Zero(t, h.count("SELECT count(*) FROM kv_certificates WHERE missing_since IS NOT NULL"), "the first empty listing marks nothing")
	assert.Equal(t, 1, h.vaultRow(vault).Facts.KVEmptyPolls)
	require.Len(t, h.vaultRow(vault).Facts.Warnings, 1)
	assert.Equal(t, inventory.WarnKVListingEmpty, h.vaultRow(vault).Facts.Warnings[0].Code)
	h.clock.Advance(time.Minute)
	h.reconcile(vault, full()) // a non-empty answer resets the count
	assert.Zero(t, h.vaultRow(vault).Facts.KVEmptyPolls)
	h.clock.Advance(time.Minute)
	h.reconcile(vault, kvResult())
	h.clock.Advance(time.Minute)
	h.reconcile(vault, kvResult())
	assert.Equal(t, 2, h.count("SELECT count(*) FROM kv_certificates WHERE missing_since IS NOT NULL"), "the second one in a row marks both")
	assert.Zero(t, h.vaultRow(vault).Facts.KVEmptyPolls)
	assert.Empty(t, h.vaultRow(vault).Facts.Warnings)
	assert.Equal(t, 2, h.emails("kv.certificate_removed"), "beta's second removal is a mail without the websites text")
	assert.Equal(t, 3, h.emails("kv.certificate_removed_bound"))

	// Keys and secrets: a complete list marks, a truncated or failed one does not.
	h.clock.Advance(time.Minute)
	h.reconcile(vault, full())
	k := full()
	k.KV.Keys = k.KV.Keys[1:]
	k.KV.Truncated = []string{"keys"}
	k.KV.KeysListed = false
	k.KV.Secrets = k.KV.Secrets[1:]
	k.KV.Failures = []providers.KVListFailure{{Object: "secrets", Err: providers.NewError("azure.forbidden", false, nil, nil)}}
	k.KV.SecretsListed = false
	h.reconcile(vault, k)
	assert.Zero(t, h.count("SELECT count(*) FROM kv_keys WHERE missing_since IS NOT NULL"))
	assert.Zero(t, h.count("SELECT count(*) FROM kv_secrets WHERE missing_since IS NOT NULL"))
	k = full()
	k.KV.Keys, k.KV.Secrets = k.KV.Keys[1:], k.KV.Secrets[1:]
	h.reconcile(vault, k)
	assert.Equal(t, 1, h.count("SELECT count(*) FROM kv_keys WHERE missing_since IS NOT NULL AND name = 'k1'"))
	assert.Equal(t, 1, h.count("SELECT count(*) FROM kv_secrets WHERE missing_since IS NOT NULL AND name = 's1'"))
	h.reconcile(vault, full())
	assert.Zero(t, h.count("SELECT count(*) FROM kv_keys WHERE missing_since IS NOT NULL"), "a key that returns is present again")
}

func TestPartialListingsAndThrottling(t *testing.T) {
	h := newHarness(t, withAzure())
	h.user("ada", rbac.Admin, "ada@example.com")
	vault := h.vault("prod")
	now := h.clock.Now()
	l := h.kvLeaf("a.example.test")
	clean := func() providers.DiscoveryResult {
		r := kvResult(h.kvc("alpha", l, ver(1), now, true))
		r.KV.Keys = []providers.KVKey{kvKey("k1", false, now, true)}
		r.KV.KeysListed = true
		return r
	}
	h.reconcile(vault, clean())
	before := h.certRow(vault, "alpha")

	// F-40: the certificate list is forbidden, keys are stored, certificates untouched.
	h.clock.Advance(time.Minute)
	r := providers.DiscoveryResult{KV: &providers.KVInventory{
		Keys: []providers.KVKey{kvKey("k1", false, now, true), kvKey("k2", false, now, true)}, KeysListed: true,
		Failures: []providers.KVListFailure{{Object: "certificates", Err: providers.NewError("azure.forbidden", false, nil,
			map[string]string{"role": providers.RoleKeyVaultReader, "model": "rbac", "azure_request_id": "0190f5a0-0000-7000-8000-00000000abcd",
				"azure_code": "ForbiddenByRbac", "message": "CANARY-AZURE-TEXT"})}}}}
	h.reconcile(vault, r)
	v := h.vaultRow(vault)
	assert.Equal(t, inventory.StatusDegraded, v.Status)
	assert.Equal(t, "azure.forbidden", v.Code)
	assert.Equal(t, 0, v.PollFailures, "forbidden is a configuration state: polled at the normal interval (M7)")
	require.NotNil(t, v.LastSuccess)
	assert.True(t, now.Equal(*v.LastSuccess), "last_success_at only moves with an answered listing")
	require.NotNil(t, v.Facts.KVPoll)
	assert.Equal(t, []inventory.KVPollFailure{{Object: "certificates", Reason: "azure.forbidden", Role: providers.RoleKeyVaultReader, Model: "rbac",
		RequestID: "0190f5a0-0000-7000-8000-00000000abcd", AzureCode: "ForbiddenByRbac"}}, v.Facts.KVPoll.Failures)
	assert.Equal(t, 2, h.count("SELECT count(*) FROM kv_keys"))
	assert.Equal(t, before, h.certRow(vault, "alpha"), "certificates untouched")
	sc := h.auditDetails("target.status_changed")
	require.Len(t, sc, 1)
	assert.Equal(t, map[string]string{"from_status": "ok", "to_status": "degraded", "reason": "azure.forbidden"}, sc[0])
	assert.NotContains(t, h.dump(t), "CANARY-AZURE-TEXT")

	// A list failure other than forbidden (a keys list answered badly) degrades too, with its reason.
	h.clock.Advance(time.Minute)
	h.reconcile(vault, providers.DiscoveryResult{KV: &providers.KVInventory{Certificates: clean().KV.Certificates,
		Failures: []providers.KVListFailure{{Object: "keys", Err: providers.NewError("azure.firewall", false, nil, map[string]string{"client_address": "203.0.113.7"})}}}})
	v = h.vaultRow(vault)
	assert.Equal(t, inventory.StatusDegraded, v.Status)
	assert.Equal(t, "azure.firewall", v.Code)
	assert.Equal(t, 0, v.PollFailures, "the certificate listing answered")
	assert.Equal(t, "203.0.113.7", v.Facts.KVPoll.Failures[0].ClientAddress)

	// A clean poll recovers.
	h.clock.Advance(time.Minute)
	h.reconcile(vault, clean())
	v = h.vaultRow(vault)
	assert.Equal(t, inventory.StatusOK, v.Status)
	assert.Empty(t, v.Code)
	assert.Empty(t, v.Facts.KVPoll.Failures)
	sc = h.auditDetails("target.status_changed")
	assert.Equal(t, map[string]string{"from_status": "degraded", "to_status": "ok", "reason": "kv_poll_ok"}, sc[len(sc)-1])

	// F-44: throttled lists count cycles; the vault degrades at the third, a clean poll resets.
	throttled := func(object string) providers.DiscoveryResult {
		r := clean()
		f := providers.KVListFailure{Object: object, Err: providers.NewError("azure.throttled", true, nil, nil)}
		if object == "certificates" {
			r.KV.Certificates = nil
		} else {
			r.KV.Keys, r.KV.KeysListed = nil, false
		}
		r.KV.Failures = []providers.KVListFailure{f}
		return r
	}
	for i, object := range []string{"certificates", "keys", "certificates"} {
		h.clock.Advance(time.Minute)
		h.reconcile(vault, throttled(object))
		v = h.vaultRow(vault)
		assert.Equal(t, i+1, v.Facts.KVThrottledCycles)
		if i < 2 {
			assert.Equal(t, inventory.StatusOK, v.Status, "cycle %d does not degrade", i+1)
			assert.Empty(t, v.Code)
		} else {
			assert.Equal(t, inventory.StatusDegraded, v.Status)
			assert.Equal(t, "azure.throttled", v.Code)
		}
	}
	h.clock.Advance(time.Minute)
	h.reconcile(vault, clean())
	v = h.vaultRow(vault)
	assert.Equal(t, inventory.StatusOK, v.Status)
	assert.Zero(t, v.Facts.KVThrottledCycles)
	assert.Zero(t, v.PollFailures)

	// Two throttled cycles, a clean poll, then two more: never three in a row.
	for _, clean1 := range []bool{false, false, true, false, false} {
		h.clock.Advance(time.Minute)
		if clean1 {
			h.reconcile(vault, clean())
		} else {
			h.reconcile(vault, throttled("certificates"))
		}
	}
	assert.Equal(t, inventory.StatusOK, h.vaultRow(vault).Status)
	assert.Equal(t, 2, h.vaultRow(vault).Facts.KVThrottledCycles)
}

func TestKVFailureTransitions(t *testing.T) {
	h := newHarness(t, withAzure())
	h.user("ada", rbac.Admin, "ada@example.com")
	vault := h.vault("prod")
	canary := map[string]string{"message": "CANARY-AZURE-TEXT", "aadsts": "7000215", "azure_request_id": "not-a-guid", "role": "Evil Role"}
	fail := func(code string) error {
		h.clock.Advance(time.Minute)
		return h.svc.RecordKVFailure(h.ctx, vault, providers.NewError(code, false, errors.New("CANARY-CAUSE"), canary))
	}
	statuses := func() []string {
		var out []string
		for _, d := range h.auditDetails("target.status_changed") {
			out = append(out, d["from_status"]+">"+d["to_status"]+":"+d["reason"])
		}
		return out
	}

	// azure.auth_failed: auth_failed from the first failure, the email at the third, once.
	require.NoError(t, fail("azure.auth_failed"))
	v := h.vaultRow(vault)
	assert.Equal(t, inventory.StatusAuthFailed, v.Status)
	assert.Equal(t, "azure.auth_failed", v.Code)
	assert.Equal(t, 1, v.PollFailures)
	assert.Equal(t, 0, h.emails("kv.auth_failed"))
	require.NoError(t, fail("azure.auth_failed"))
	assert.Equal(t, 0, h.emails("kv.auth_failed"))
	require.NoError(t, fail("azure.auth_failed"))
	v = h.vaultRow(vault)
	assert.Equal(t, 3, v.PollFailures)
	assert.Equal(t, 3, v.Facts.KVAuthFailures)
	assert.Equal(t, 1, h.emails("kv.auth_failed"))
	require.NoError(t, fail("azure.auth_failed"))
	assert.Equal(t, 1, h.emails("kv.auth_failed"), "once per episode")
	var params string
	require.NoError(t, h.db.Owner.QueryRow(h.ctx, "SELECT params::text FROM notifications_outbox WHERE template_key = 'kv.auth_failed'").Scan(&params))
	assert.JSONEq(t, `{"target_name":"prod"}`, params, "no raw reason code in the mail")
	assert.Equal(t, []string{"ok>auth_failed:azure.auth_failed"}, statuses(), "one status_changed row per transition")
	require.NotNil(t, v.Facts.KVPoll)
	assert.Equal(t, []inventory.KVPollFailure{{Object: "vault", Reason: "azure.auth_failed", Aadsts: "7000215"}}, v.Facts.KVPoll.Failures,
		"only allowlisted params are kept: the malformed request id, the role and the text are dropped")

	// azure.credentials_expired: still auth_failed, its own code.
	require.NoError(t, fail("azure.credentials_expired"))
	v = h.vaultRow(vault)
	assert.Equal(t, inventory.StatusAuthFailed, v.Status)
	assert.Equal(t, "azure.credentials_expired", v.Code)
	assert.Equal(t, 1, h.emails("kv.auth_failed"))
	assert.Len(t, statuses(), 1)

	// azure.unreachable: unreachable (F-50); the sign-in streak is over.
	require.NoError(t, fail("azure.unreachable"))
	v = h.vaultRow(vault)
	assert.Equal(t, inventory.StatusUnreachable, v.Status)
	assert.Zero(t, v.Facts.KVAuthFailures)
	// azure.unexpected_response: the status stays, the failure is counted (F-52).
	pf := v.PollFailures
	require.NoError(t, fail("azure.unexpected_response"))
	v = h.vaultRow(vault)
	assert.Equal(t, inventory.StatusUnreachable, v.Status)
	assert.Equal(t, "azure.unexpected_response", v.Code)
	assert.Equal(t, pf+1, v.PollFailures)
	// a foreign error is internal.unexpected, its text is not stored
	h.clock.Advance(time.Minute)
	require.NoError(t, h.svc.RecordKVFailure(h.ctx, vault, errors.New("CANARY-FOREIGN")))
	assert.Equal(t, "internal.unexpected", h.vaultRow(vault).Code)
	require.NoError(t, h.svc.RecordKVFailure(h.ctx, vault, nil))

	// Throttled poll errors: unchanged until the third cycle.
	require.NoError(t, fail("azure.throttled"))
	require.NoError(t, fail("azure.throttled"))
	assert.Equal(t, inventory.StatusUnreachable, h.vaultRow(vault).Status)
	require.NoError(t, fail("azure.throttled"))
	v = h.vaultRow(vault)
	assert.Equal(t, inventory.StatusDegraded, v.Status)
	assert.Equal(t, "azure.throttled", v.Code)
	assert.Equal(t, 3, v.Facts.KVThrottledCycles)
	require.NoError(t, fail("azure.forbidden"))
	assert.Equal(t, "azure.forbidden", h.vaultRow(vault).Code)
	assert.Equal(t, inventory.StatusDegraded, h.vaultRow(vault).Status)
	assert.Zero(t, h.vaultRow(vault).Facts.KVThrottledCycles, "another kind of failure ends the throttling streak")

	// A successful poll: ok, every counter reset, the audit row says so.
	h.clock.Advance(time.Minute)
	h.reconcile(vault, kvResult(h.kvc("alpha", h.kvLeaf("a.example.test"), ver(1), h.clock.Now(), true)))
	v = h.vaultRow(vault)
	assert.Equal(t, inventory.StatusOK, v.Status)
	assert.Empty(t, v.Code)
	assert.Zero(t, v.PollFailures)
	assert.Zero(t, v.Facts.KVAuthFailures)
	assert.Zero(t, v.Facts.KVThrottledCycles)
	require.NotNil(t, v.LastSuccess)
	assert.True(t, h.clock.Now().Equal(*v.LastSuccess))
	got := statuses()
	assert.Equal(t, "degraded>ok:kv_poll_ok", got[len(got)-1])
	assert.Equal(t, []string{"ok>auth_failed:azure.auth_failed", "auth_failed>unreachable:azure.unreachable", "unreachable>degraded:azure.throttled",
		"degraded>ok:kv_poll_ok"}, got)
	d := h.dump(t)
	for _, needle := range []string{"CANARY-AZURE-TEXT", "CANARY-CAUSE", "CANARY-FOREIGN", "Evil Role", "not-a-guid"} {
		assert.NotContains(t, d, needle)
		assert.Zero(t, h.count("SELECT count(*) FROM notifications_outbox WHERE params::text LIKE '%' || $1 || '%'", needle))
	}

	// The sign-in streak must be unbroken: two failures, another failure, two more: no email.
	other := h.vault("second")
	for _, code := range []string{"azure.auth_failed", "azure.auth_failed", "azure.unreachable", "azure.auth_failed", "azure.auth_failed"} {
		require.NoError(t, h.svc.RecordKVFailure(h.ctx, other, providers.NewError(code, false, nil, nil)))
	}
	assert.Equal(t, 1, h.emails("kv.auth_failed"), "no new email: the streak never reached three")
	require.NoError(t, h.svc.RecordKVFailure(h.ctx, other, providers.NewError("azure.clock_skew", false, nil, nil)))
	assert.Equal(t, 2, h.emails("kv.auth_failed"), "the sign-in family counts together")

	// The counter is bounded; a disabled or deleted vault is left alone; a server is not a vault.
	_, err := h.db.Owner.Exec(h.ctx, "UPDATE targets SET poll_failures = 1000000 WHERE id = $1", other)
	require.NoError(t, err)
	require.NoError(t, h.svc.RecordKVFailure(h.ctx, other, providers.NewError("azure.unreachable", false, nil, nil)))
	assert.Equal(t, 1000000, h.vaultRow(other).PollFailures)
	_, err = h.db.Owner.Exec(h.ctx, "UPDATE targets SET status = 'disabled' WHERE id = $1", other)
	require.NoError(t, err)
	require.NoError(t, h.svc.RecordKVFailure(h.ctx, other, providers.NewError("azure.auth_failed", false, nil, nil)))
	assert.Equal(t, inventory.StatusDisabled, h.vaultRow(other).Status)
	_, err = h.db.Owner.Exec(h.ctx, "UPDATE targets SET status = 'ok', deleted_at = $2 WHERE id = $1", other, h.clock.Now())
	require.NoError(t, err)
	require.NoError(t, h.svc.RecordKVFailure(h.ctx, other, providers.NewError("azure.auth_failed", false, nil, nil)))
	assert.Equal(t, inventory.StatusOK, h.vaultRow(other).Status)
	web := h.seedTarget("web", "linux", "web.example.com")
	require.ErrorIs(t, h.svc.RecordKVFailure(h.ctx, web, providers.NewError("azure.auth_failed", false, nil, nil)), inventory.ErrNotAVault)
	require.ErrorIs(t, h.svc.RecordKVFailure(h.ctx, uuid.New(), providers.NewError("azure.auth_failed", false, nil, nil)), inventory.ErrNotFound)
}

func TestReconcileIsFencedAndBounded(t *testing.T) {
	h := newHarness(t, withAzure())
	h.jobs.next = jobs.NewQueue(jobs.QueueConfig{Pool: h.db.App, Keyring: h.keyring, Audit: h.audit, Clock: h.clock, Gate: h.lic})
	admin := h.user("ada", rbac.Admin, "")
	vault := h.vault("prod")
	job, err := h.svc.RequestDiscovery(h.ctx, admin, vault)
	require.NoError(t, err)
	_, err = h.db.Owner.Exec(h.ctx, "UPDATE jobs SET status = 'running', attempts = 2 WHERE id = $1", job)
	require.NoError(t, err)
	res := kvResult(h.kvc("alpha", h.kvLeaf("a.example.test"), ver(1), h.clock.Now(), true))

	stale := inventory.WithClaim(h.ctx, inventory.Claim{JobID: job, Attempt: 1})
	_, err = h.svc.ReconcileKV(stale, vault, res)
	require.ErrorIs(t, err, inventory.ErrClaimLost)
	assert.Zero(t, h.count("SELECT count(*) FROM kv_certificates"))
	assert.Zero(t, h.audits("target.discovered"))
	require.ErrorIs(t, h.svc.RecordKVFailure(stale, vault, providers.NewError("azure.auth_failed", false, nil, nil)), inventory.ErrClaimLost)
	assert.Zero(t, h.vaultRow(vault).PollFailures)
	live := inventory.WithClaim(h.ctx, inventory.Claim{JobID: job, Attempt: 2})
	_, err = h.svc.ReconcileKV(live, vault, res)
	require.NoError(t, err)
	assert.Equal(t, 1, h.count("SELECT count(*) FROM kv_certificates"))

	// A result above the provider's bounds and one without a vault half are refused as
	// internal.unexpected before anything is written.
	big := providers.DiscoveryResult{KV: &providers.KVInventory{}}
	for i := range 5001 {
		big.KV.Certificates = append(big.KV.Certificates, providers.KVCertificate{Name: fmt.Sprintf("c%d", i), Thumbprint: fmt.Sprintf("%040x", i), Enabled: true})
	}
	for _, bad := range []providers.DiscoveryResult{big, {}, {KV: &providers.KVInventory{Keys: make([]providers.KVKey, 5001)}},
		{KV: &providers.KVInventory{Secrets: make([]providers.KVSecret, 10001)}}} {
		_, err = h.svc.ReconcileKV(h.ctx, vault, bad)
		var pe *providers.Error
		require.ErrorAs(t, err, &pe)
		assert.Equal(t, "internal.unexpected", pe.Code)
	}
	assert.Equal(t, 1, h.count("SELECT count(*) FROM kv_certificates"))
	assert.Equal(t, 5000, func() int { // exactly at the bound is stored
		r := providers.DiscoveryResult{KV: &providers.KVInventory{Certificates: big.KV.Certificates[:5000]}}
		sum, err := h.svc.ReconcileKV(h.ctx, vault, r)
		require.NoError(t, err)
		return sum.Certificates
	}())
	assert.Equal(t, 5000, h.count("SELECT count(*) FROM kv_certificates WHERE missing_since IS NULL AND details_pending"))

	// A server and an unknown id are not vaults.
	web := h.seedTarget("web", "nginx", "web.example.com")
	_, err = h.svc.ReconcileKV(h.ctx, web, res)
	require.ErrorIs(t, err, inventory.ErrNotAVault)
	_, err = h.svc.ReconcileKV(h.ctx, uuid.New(), res)
	require.ErrorIs(t, err, inventory.ErrNotFound)
}

func TestReconcileDropsAResultForAGoneVault(t *testing.T) {
	h := newHarness(t, withAzure())
	h.user("ada", rbac.Admin, "ada@example.com")
	res := func() providers.DiscoveryResult {
		return kvResult(h.kvc("alpha", h.kvLeaf("a.example.test"), ver(1), h.clock.Now(), true))
	}
	disabled := h.vault("one")
	_, err := h.db.Owner.Exec(h.ctx, "UPDATE targets SET status = 'disabled' WHERE id = $1", disabled)
	require.NoError(t, err)
	sum, err := h.svc.ReconcileKV(h.ctx, disabled, res())
	require.NoError(t, err)
	assert.Equal(t, "disabled", sum.Dropped)
	deleted := h.vault("two")
	_, err = h.db.Owner.Exec(h.ctx, "UPDATE targets SET deleted_at = $2 WHERE id = $1", deleted, h.clock.Now())
	require.NoError(t, err)
	sum, err = h.svc.ReconcileKV(h.ctx, deleted, res())
	require.NoError(t, err)
	assert.Equal(t, "deleted", sum.Dropped)
	assert.Zero(t, h.count("SELECT count(*) FROM kv_certificates"))
	assert.Equal(t, inventory.StatusDisabled, h.vaultRow(disabled).Status)
	assert.Zero(t, h.audits("target.discovered"))

	// A vault deleted between two batches: the rest of the result is dropped, what was stored stays.
	vault := h.vault("three")
	restore := inventory.SetKVBatchSizes(1, 1, 1)
	defer restore()
	calls := 0
	defer inventory.SetKVBatchHook(func(kind string, batch int) {
		calls++
		if calls == 1 {
			_, err := h.db.Owner.Exec(h.ctx, "UPDATE targets SET deleted_at = $2 WHERE id = $1", vault, h.clock.Now())
			require.NoError(t, err)
		}
	})()
	r := kvResult(h.kvc("a", h.kvLeaf("a.example.test"), ver(1), h.clock.Now(), true), h.kvc("b", h.kvLeaf("b.example.test"), ver(2), h.clock.Now(), true))
	sum, err = h.svc.ReconcileKV(h.ctx, vault, r)
	require.NoError(t, err)
	assert.Equal(t, "deleted", sum.Dropped)
	assert.Equal(t, 1, h.count("SELECT count(*) FROM kv_certificates WHERE target_id = $1", vault))
}

func TestBatchedStoringAndWhatAReaderSees(t *testing.T) {
	h := newHarness(t, withAzure())
	h.user("ada", rbac.Admin, "ada@example.com")
	vault := h.vault("prod")
	restore := inventory.SetKVBatchSizes(2, 2, 3)
	defer restore()
	now := h.clock.Now()
	var cs []providers.KVCertificate
	for i := range 5 {
		cs = append(cs, h.kvc(fmt.Sprintf("cert-%d", i), h.kvLeaf(fmt.Sprintf("c%d.example.test", i)), ver(i+1), now, true))
	}
	res := kvResult(cs...)
	for i := range 5 {
		res.KV.Keys = append(res.KV.Keys, kvKey(fmt.Sprintf("key-%d", i), false, now, true))
	}
	for i := range 7 {
		res.KV.Secrets = append(res.KV.Secrets, kvSecret(fmt.Sprintf("sec-%d", i), now))
	}
	res.KV.KeysListed, res.KV.SecretsListed = true, true
	h.reconcile(vault, res) // the first poll stores the whole inventory

	// Second poll: one certificate renewed, one removed; the reader looks between the batches.
	h.clock.Advance(15 * time.Minute)
	renewed := h.kvLeaf("c0.example.test")
	res2 := kvResult(h.kvc("cert-0", renewed, ver(10), h.clock.Now(), true, ver(1)))
	for _, c := range cs[1:4] { // unchanged: the listing alone
		c.Details, c.Versions = nil, nil
		res2.KV.Certificates = append(res2.KV.Certificates, c)
	}
	res2.KV.Keys, res2.KV.KeysListed = res.KV.Keys[:3], true
	res2.KV.Secrets, res2.KV.SecretsListed = res.KV.Secrets[:6], true
	var seen []string
	defer inventory.SetKVBatchHook(func(kind string, batch int) {
		seen = append(seen, fmt.Sprintf("%s%d", kind, batch))
		// Never a current version without its version row, never a version row without its certificate.
		assert.Zero(t, h.count(`SELECT count(*) FROM kv_certificates c WHERE c.current_version <> ''
AND NOT EXISTS (SELECT 1 FROM kv_certificate_versions v WHERE v.kv_certificate_id = c.id AND v.version = c.current_version)`), "after %s%d", kind, batch)
		assert.Zero(t, h.count(`SELECT count(*) FROM kv_certificates c JOIN kv_certificate_versions v ON v.kv_certificate_id = c.id
WHERE c.current_version = v.version AND v.certificate_id IS NULL`), "after %s%d", kind, batch)
		// Status, last success and every "missing" mark wait for the end of the poll.
		v := h.vaultRow(vault)
		assert.False(t, h.clock.Now().Equal(*v.LastSuccess), "last_success_at moves last (after %s%d)", kind, batch)
		assert.Zero(t, h.count("SELECT count(*) FROM kv_certificates WHERE missing_since IS NOT NULL"))
		assert.Zero(t, h.count("SELECT count(*) FROM kv_keys WHERE missing_since IS NOT NULL"))
		assert.Zero(t, h.count("SELECT count(*) FROM kv_secrets WHERE missing_since IS NOT NULL"))
	})()
	sum := h.reconcile(vault, res2)
	assert.Equal(t, []string{"certificates1", "certificates2", "keys1", "keys2", "secrets1", "secrets2"}, seen, "4 certificates, 3 keys and 6 secrets in batches of 2, 2 and 3")
	assert.Equal(t, 1, sum.NewVersions)
	assert.Equal(t, 1, sum.MissingCertificates)
	assert.Equal(t, 2, sum.MissingKeys)
	assert.Equal(t, 1, sum.MissingSecrets)
	assert.Equal(t, 1, h.count("SELECT count(*) FROM kv_certificates WHERE missing_since IS NOT NULL"))
	assert.Equal(t, ver(10), h.certRow(vault, "cert-0").Version)
	v := h.vaultRow(vault)
	assert.True(t, h.clock.Now().Equal(*v.LastSuccess))
}

func TestReconcileIsExactlyOnceUnderConcurrentPolls(t *testing.T) {
	h := newHarness(t, withAzure())
	h.user("ada", rbac.Admin, "ada@example.com")
	vault := h.vault("prod")
	l1 := h.kvLeaf("www.example.test")
	h.reconcile(vault, kvResult(h.kvc("web-cert", l1, ver(1), h.clock.Now(), true)))
	c := h.certRow(vault, "web-cert")
	h.clock.Advance(15 * time.Minute)
	l2 := h.kvLeaf("www.example.test")
	res := kvResult(h.kvc("web-cert", l2, ver(2), h.clock.Now(), true, ver(1)), h.kvc("fresh", h.kvLeaf("f.example.test"), ver(3), h.clock.Now(), true))
	const polls = 8
	var wg sync.WaitGroup
	sums := make([]inventory.KVSummary, polls)
	errs := make([]error, polls)
	for i := range polls {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sums[i], errs[i] = h.svc.ReconcileKV(h.ctx, vault, res)
		}()
	}
	wg.Wait()
	newVersions, newCerts := 0, 0
	for i := range polls {
		require.NoError(t, errs[i])
		newVersions += sums[i].NewVersions
		newCerts += sums[i].NewCertificates
	}
	assert.Equal(t, 1, newVersions, "exactly one poll detected the version")
	assert.Equal(t, 1, newCerts)
	assert.Equal(t, 1, h.audits("kv.certificate.new_version"))
	assert.Len(t, h.versionRows(c.ID), 2)
	assert.Equal(t, 1, h.count("SELECT count(*) FROM kv_certificates WHERE lower(name) = 'fresh'"))
	assert.Equal(t, ver(2), h.certRow(vault, "web-cert").Version)

	// Polls that only bring new certificates (nothing to lock but the vault): still one row each.
	brand := kvResult(h.kvc("brand-new", h.kvLeaf("n.example.test"), ver(7), h.clock.Now(), true), h.kvc("also-new", h.kvLeaf("m.example.test"), "", h.clock.Now(), false))
	newCerts = 0
	for i := range polls {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sums[i], errs[i] = h.svc.ReconcileKV(h.ctx, vault, brand)
		}()
	}
	wg.Wait()
	for i := range polls {
		require.NoError(t, errs[i])
		newCerts += sums[i].NewCertificates
	}
	assert.Equal(t, 2, newCerts)
	assert.Equal(t, 1, h.count("SELECT count(*) FROM kv_certificate_versions v JOIN kv_certificates c ON c.id = v.kv_certificate_id WHERE c.name = 'brand-new'"))
}

func TestStaleResultNeverOverwritesNewerKnowledge(t *testing.T) {
	h := newHarness(t, withAzure())
	h.user("ada", rbac.Admin, "ada@example.com")
	vault := h.vault("prod")
	la, lb := h.kvLeaf("a.example.test"), h.kvLeaf("b.example.test")
	t0 := h.clock.Now()
	stale := kvResult(h.kvc("alpha", la, ver(1), t0, true), h.kvc("beta", lb, ver(2), t0, true))
	h.reconcile(vault, stale)
	// A newer poll (clock later) sees alpha gone and beta edited.
	h.clock.Advance(time.Hour)
	edited := h.kvc("beta", lb, ver(2), h.clock.Now(), true)
	edited.Enabled = false
	h.reconcile(vault, kvResult(edited))
	require.NotNil(t, h.certRow(vault, "alpha").Missing)

	// The older result arrives late (its time was taken before): it must not resurrect or revert.
	h.clock.Set(t0.Add(time.Minute))
	h.reconcile(vault, stale)
	assert.NotNil(t, h.certRow(vault, "alpha").Missing, "a stale sighting does not bring it back")
	assert.False(t, h.certRow(vault, "beta").Enabled, "a stale listing does not revert attributes")
	h.clock.Set(t0.Add(2 * time.Minute))
	h.reconcile(vault, kvResult(h.kvc("beta", lb, "", t0, false)))
	assert.False(t, h.certRow(vault, "beta").Enabled, "nor does a stale listing without details")
	assert.NotNil(t, h.certRow(vault, "alpha").Missing)
}

func TestVersionThumbprintConflictKeepsTheStoredRow(t *testing.T) {
	h := newHarness(t, withAzure())
	h.user("ada", rbac.Admin, "ada@example.com")
	vault := h.vault("prod")
	l1 := h.kvLeaf("www.example.test")
	t0 := h.clock.Now()
	h.reconcile(vault, kvResult(h.kvc("web-cert", l1, ver(1), t0, true)))
	c := h.certRow(vault, "web-cert")

	// Azure reports the stored version ID with another thumbprint: not a silent update.
	h.clock.Advance(15 * time.Minute)
	other := h.kvLeaf("www.example.test")
	sum := h.reconcile(vault, kvResult(h.kvc("web-cert", other, ver(1), h.clock.Now(), true)))
	assert.Equal(t, 1, sum.VersionConflicts)
	assert.Zero(t, sum.NewVersions)
	got := h.certRow(vault, "web-cert")
	assert.Equal(t, ver(1), got.Version)
	assert.Equal(t, thumbOf(l1), got.Thumb, "the stored thumbprint is kept")
	assert.Equal(t, thumbOf(other), got.ListedThumb, "the listing is recorded as listed")
	vs := h.versionRows(c.ID)
	require.Len(t, vs, 1)
	assert.Equal(t, thumbOf(l1), vs[ver(1)].Thumb)
	assert.Equal(t, 1, h.audits("kv.certificate.version_conflict"))
	ev := h.auditDetails("kv.certificate.version_conflict")
	assert.Equal(t, map[string]string{"kv_certificate_id": c.ID.String(), "certificate_name": "web-cert", "version": ver(1),
		"thumbprint": thumbOf(l1), "reported_thumbprint": thumbOf(other), "vault_url": "https://prod.vault.azure.net"}, ev[0])
	v := h.vaultRow(vault)
	require.Len(t, v.Facts.Warnings, 1)
	assert.Equal(t, providers.Warning{Code: inventory.WarnKVVersionConflict, Params: map[string]string{"object": "certificates", "count": "1"}}, v.Facts.Warnings[0])
	assert.Equal(t, inventory.StatusOK, v.Status)

	// The same answer on the next poll: still kept, still no second audit row.
	h.clock.Advance(15 * time.Minute)
	h.reconcile(vault, kvResult(h.kvc("web-cert", other, ver(1), h.clock.Now(), true)))
	assert.Equal(t, 1, h.audits("kv.certificate.version_conflict"))
	assert.Equal(t, thumbOf(l1), h.certRow(vault, "web-cert").Thumb)

	// An older version listed with another thumbprint is kept too (counted and warned, not audited again).
	h.clock.Advance(15 * time.Minute)
	l2 := h.kvLeaf("www.example.test")
	r := h.kvc("web-cert", l2, ver(2), h.clock.Now(), true, ver(1))
	r.Versions[1].Thumbprint = fmt.Sprintf("%040x", 99)
	sum = h.reconcile(vault, kvResult(r))
	assert.Equal(t, 1, sum.VersionConflicts)
	assert.Equal(t, 1, sum.NewVersions)
	assert.Equal(t, thumbOf(l1), h.versionRows(c.ID)[ver(1)].Thumb)
}

func TestResultsAreClampedAndUnusableItemsDropped(t *testing.T) {
	h := newHarness(t, withAzure())
	h.user("ada", rbac.Admin, "ada@example.com")
	vault := h.vault("prod")
	now := h.clock.Now()
	good := h.kvLeaf("a.example.test")
	l2 := h.kvLeaf("b.example.test")
	c := h.kvc("good", good, ver(1), now, true)
	c.Details.KeyType, c.Details.ContentType, c.Details.KeySize, c.Details.IssuerName = "dsa", "weird/type", 999999, strings.Repeat("i", 200)
	bad1 := h.kvc("bad name", good, ver(1), now, true) // invalid name
	bad2 := h.kvc("badthumb", good, ver(1), now, true) // thumbprint not hex
	bad2.Thumbprint = "XYZ"
	unparsable := h.kvc("unparsable", l2, ver(2), now, true) // the leaf does not parse
	unparsable.Details.CER = []byte("not a certificate")
	mismatch := h.kvc("mismatch", l2, ver(3), now, true) // details thumbprint is not the leaf's
	mismatch.Details.Thumbprint = fmt.Sprintf("%040x", 5)
	dupA, dupB := h.kvc("Dup", good, ver(4), now, true), h.kvc("dup", good, ver(4), now, true)
	longTime := time.Date(12000, 1, 1, 0, 0, 0, 0, time.UTC)
	timed := h.kvc("timed", good, ver(5), now, true)
	timed.Expires = &longTime
	res := kvResult(c, bad1, bad2, unparsable, mismatch, dupA, dupB, timed)
	res.KV.Keys = []providers.KVKey{kvKey("ok-key", false, now, true), kvKey("bad_key", false, now, true), kvKey("Ok-Key", false, now, true)}
	res.KV.Keys[0].Details.KeyType, res.KV.Keys[0].Details.Curve = "ec", "P-999"
	res.KV.KeysListed = true
	res.KV.Secrets = []providers.KVSecret{{Name: "s1", ContentType: strings.Repeat("a", 300), Enabled: true}, {Name: "", Enabled: true}}
	res.KV.SecretsListed = true
	res.Warnings = []providers.Warning{{Code: providers.WarnKVItemUnreadable, Params: map[string]string{"object": "keys", "count": "2"}},
		{Code: "something_else", Params: map[string]string{"x": "y"}}}
	h.reconcile(vault, res)

	g := h.certRow(vault, "good")
	assert.Equal(t, "other", g.KeyType)
	assert.Equal(t, "other", g.ContentType)
	assert.Zero(t, g.KeySize)
	assert.Empty(t, g.Issuer)
	assert.Equal(t, 0, h.count("SELECT count(*) FROM kv_certificates WHERE lower(name) IN ('bad name', 'badthumb')"))
	// The unparsable and mismatching details are left out: the certificate is listed, its details wait.
	for _, n := range []string{"unparsable", "mismatch"} {
		r := h.certRow(vault, n)
		assert.Empty(t, r.Version, n)
		assert.True(t, r.Pending, n)
		assert.Empty(t, h.versionRows(r.ID), n)
	}
	assert.Equal(t, 1, h.count("SELECT count(*) FROM kv_certificates WHERE lower(name) = 'dup'"))
	assert.Equal(t, "Dup", h.certRow(vault, "dup").Name, "the first of two folded-equal names is kept")
	tm := h.certRow(vault, "timed")
	assert.Equal(t, ver(5), tm.Version)
	assert.Equal(t, 1, h.count("SELECT count(*) FROM kv_certificates WHERE name = 'timed' AND expires IS NULL"), "a time outside years 1-9999 is dropped")
	assert.Equal(t, 1, h.count("SELECT count(*) FROM kv_keys WHERE name = 'ok-key'"))
	assert.Equal(t, 0, h.count("SELECT count(*) FROM kv_keys WHERE name = 'bad_key'"))
	assert.Equal(t, "other", func() string {
		var c string
		require.NoError(t, h.db.Owner.QueryRow(h.ctx, "SELECT curve FROM kv_keys WHERE name = 'ok-key'").Scan(&c))
		return c
	}())
	assert.Equal(t, 1, h.count("SELECT count(*) FROM kv_secrets WHERE name = 's1' AND content_type = ''"), "a content type that does not fit is dropped")
	assert.Equal(t, 1, h.count("SELECT count(*) FROM kv_secrets"))
	first := map[string]string{}
	for _, w := range h.vaultRow(vault).Facts.Warnings {
		assert.Equal(t, providers.WarnKVItemUnreadable, w.Code, "only the closed warning is kept")
		first[w.Params["object"]] = w.Params["count"]
	}
	assert.Equal(t, map[string]string{"certificates": "5", "keys": "4", "secrets": "1"}, first,
		"the provider's count and Alice's own are merged by object (3 items dropped, 2 details unusable)")

	// Items that could not be stored make their kind incomplete: nothing of it is marked missing,
	// even by a later listing that omits it while the unusable item is still being sent.
	h.clock.Advance(time.Minute)
	r2 := kvResult(c, bad1)
	r2.KV.Keys, r2.KV.Secrets = []providers.KVKey{kvKey("bad_key", false, now, true)}, []providers.KVSecret{{Name: "", Enabled: true}}
	r2.KV.KeysListed, r2.KV.SecretsListed = true, true
	h.reconcile(vault, r2)
	assert.Zero(t, h.count("SELECT count(*) FROM kv_certificates WHERE missing_since IS NOT NULL"))
	assert.Zero(t, h.count("SELECT count(*) FROM kv_keys WHERE missing_since IS NOT NULL"))
	assert.Zero(t, h.count("SELECT count(*) FROM kv_secrets WHERE missing_since IS NOT NULL"))

	// The warnings are the closed ones: the provider's kv_item_unreadable and the ones inventory made, merged by object.
	v := h.vaultRow(vault)
	got := map[string]string{}
	for _, w := range v.Facts.Warnings {
		assert.Equal(t, providers.WarnKVItemUnreadable, w.Code)
		got[w.Params["object"]] = w.Params["count"]
	}
	assert.Equal(t, map[string]string{"certificates": "1", "keys": "1", "secrets": "1"}, got)
}

func TestPollSlotsAreTwo(t *testing.T) {
	h := newHarness(t, withAzure())
	assert.Equal(t, 2, inventory.MaxConcurrentKVPolls)
	r1, err := h.svc.AcquireKVPoll(h.ctx)
	require.NoError(t, err)
	r2, err := h.svc.AcquireKVPoll(h.ctx)
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(h.ctx, 50*time.Millisecond)
	defer cancel()
	_, err = h.svc.AcquireKVPoll(ctx)
	require.Error(t, err, "a third poll waits")
	r1()
	r1() // releasing twice frees one slot only
	r3, err := h.svc.AcquireKVPoll(h.ctx)
	require.NoError(t, err)
	ctx2, cancel2 := context.WithTimeout(h.ctx, 50*time.Millisecond)
	defer cancel2()
	_, err = h.svc.AcquireKVPoll(ctx2)
	require.Error(t, err)
	r2()
	r3()
}

// pollOnce is what the poll job does: ask inventory what to read, read it through the provider and
// store the answer. It returns the request the provider saw.
func (h *harness) pollOnce(vault uuid.UUID) (providers.DiscoverRequest, inventory.KVSummary) {
	h.t.Helper()
	req, err := h.svc.KVPollRequest(h.ctx, vault)
	require.NoError(h.t, err)
	sess, err := h.azure.Open(h.ctx, providers.TargetRef{ID: vault, Kind: providers.KindAzureKV}, nil, providers.Env{})
	require.NoError(h.t, err)
	defer sess.Close()
	res, err := sess.Discover(h.ctx, req)
	require.NoError(h.t, err)
	return req, h.reconcile(vault, res)
}

func (h *harness) lastDiscover() providers.DiscoverRequest {
	h.t.Helper()
	calls := h.azure.Calls()
	for i := len(calls) - 1; i >= 0; i-- {
		if calls[i].Method == "Discover" {
			return calls[i].Discover
		}
	}
	h.t.Fatal("no Discover call")
	return providers.DiscoverRequest{}
}

func TestKVPollRequestAsksForKeysAndSecretsEveryFourthInterval(t *testing.T) {
	h := newHarness(t, withAzure())
	h.user("ada", rbac.Admin, "")
	vault := h.vault("prod")
	l := h.kvLeaf("a.example.test")
	now := h.clock.Now()
	inv := &providers.KVInventory{Certificates: []providers.KVCertificate{h.kvc("web-cert", l, ver(1), now, true)},
		Keys: []providers.KVKey{kvKey("k1", false, now, true), kvKey("managed", true, now, false)}, KeysListed: true,
		Secrets: []providers.KVSecret{kvSecret("s1", now)}, SecretsListed: true}
	h.azure.Configure(func(c *fake.Config) { c.Discovery = providers.DiscoveryResult{KV: inv} })

	req, _ := h.pollOnce(vault) // never read: everything is asked for
	assert.True(t, req.Certificates)
	assert.True(t, req.KVKeys)
	assert.True(t, req.KVSecrets)
	assert.Empty(t, req.KVKnown, "nothing is known yet")
	// A certificate stored from its listing alone (unusable details) is never "known".
	h.reconcile(vault, kvResult(inv.Certificates[0], h.kvc("listed-only", h.kvLeaf("l.example.test"), "", now, false)))
	req2, err := h.svc.KVPollRequest(h.ctx, vault)
	require.NoError(t, err)
	assert.NotContains(t, req2.KVKnown, "listed-only", "list-only values are not recorded as known")
	h.clock.Advance(time.Minute)
	assert.Empty(t, req.KVKnownKeys)
	assert.False(t, req.SSHKeys)
	for i := 1; i <= 3; i++ { // the next three polls (15, 30, 45 minutes later) read certificates only
		h.clock.Advance(15 * time.Minute)
		req, sum := h.pollOnce(vault)
		assert.True(t, req.Certificates)
		assert.False(t, req.KVKeys, "poll %d", i)
		assert.False(t, req.KVSecrets, "poll %d", i)
		assert.Empty(t, req.KVKnownKeys, "no key is asked for, none is passed")
		require.Len(t, req.KVKnown, 1)
		assert.Equal(t, providers.KVKnown{Version: ver(1), Thumbprint: thumbOf(l), Updated: now}, req.KVKnown["web-cert"])
		assert.Zero(t, sum.MissingKeys)
		assert.Zero(t, sum.MissingSecrets)
	}
	assert.Equal(t, 0, h.count("SELECT count(*) FROM kv_keys WHERE missing_since IS NOT NULL"))
	h.clock.Advance(15 * time.Minute) // the fifth poll: four intervals after the last metadata read
	req, _ = h.pollOnce(vault)
	assert.True(t, req.KVKeys)
	assert.True(t, req.KVSecrets)
	assert.Equal(t, map[string]time.Time{"k1": now}, req.KVKnownKeys, "keys whose details were read; a managed key has none")
	assert.Equal(t, req, h.lastDiscover(), "the provider saw exactly this request")

	// A poll that asked for keys but whose key list failed still counts as the read (the next try is
	// four intervals later); a poll that failed as a whole does not move the time.
	h.clock.Advance(time.Hour)
	failed := &providers.KVInventory{Certificates: inv.Certificates,
		Failures: []providers.KVListFailure{{Object: "keys", Err: providers.NewError("azure.forbidden", false, nil, nil)}}}
	h.azure.Configure(func(c *fake.Config) { c.Discovery = providers.DiscoveryResult{KV: failed} })
	h.pollOnce(vault)
	at := h.vaultRow(vault).Facts.KVMetadataAt
	require.NotNil(t, at)
	assert.True(t, h.clock.Now().Equal(*at))
	h.clock.Advance(time.Hour)
	require.NoError(t, h.svc.RecordKVFailure(h.ctx, vault, providers.NewError("azure.unreachable", false, nil, nil)))
	assert.True(t, at.Equal(*h.vaultRow(vault).Facts.KVMetadataAt))

	// A disabled vault is not polled; a deleted one, a server and an unknown id are refused.
	_, err = h.db.Owner.Exec(h.ctx, "UPDATE targets SET status = 'disabled' WHERE id = $1", vault)
	require.NoError(t, err)
	_, err = h.svc.KVPollRequest(h.ctx, vault)
	require.ErrorIs(t, err, inventory.ErrTargetNotReady)
	_, err = h.db.Owner.Exec(h.ctx, "UPDATE targets SET status = 'ok', deleted_at = $2 WHERE id = $1", vault, h.clock.Now())
	require.NoError(t, err)
	_, err = h.svc.KVPollRequest(h.ctx, vault)
	require.ErrorIs(t, err, inventory.ErrNotFound)
	_, err = h.svc.KVPollRequest(h.ctx, h.seedTarget("web", "nginx", "web.example.com"))
	require.ErrorIs(t, err, inventory.ErrNotAVault)
}

func TestScheduleKVPolls(t *testing.T) {
	h := newHarness(t, withAzure())
	h.user("ada", rbac.Admin, "")
	vault := h.vault("prod") // interval 15 minutes
	web := h.seedTarget("web", "nginx", "web.example.com")
	_, err := h.db.Owner.Exec(h.ctx, "UPDATE targets SET status = 'ok' WHERE id = $1", web)
	require.NoError(t, err)
	slow := h.vault("slow")
	_, err = h.db.Owner.Exec(h.ctx, "UPDATE targets SET discovery_interval_seconds = 7200 WHERE id = $1", slow)
	require.NoError(t, err)
	off := h.vault("off")
	_, err = h.db.Owner.Exec(h.ctx, "UPDATE targets SET status = 'disabled' WHERE id = $1", off)
	require.NoError(t, err)
	gone := h.vault("gone")
	_, err = h.db.Owner.Exec(h.ctx, "UPDATE targets SET deleted_at = $2 WHERE id = $1", gone, h.clock.Now())
	require.NoError(t, err)
	scheduled := func() map[uuid.UUID]int {
		out := map[uuid.UUID]int{}
		for _, r := range h.jobs.requests() {
			out[r.TargetID]++
		}
		return out
	}

	// Never scheduled: due at once; servers, disabled and deleted vaults never.
	n, err := h.svc.ScheduleKVPolls(h.ctx)
	require.NoError(t, err)
	assert.Equal(t, 2, n)
	assert.Equal(t, map[uuid.UUID]int{vault: 1, slow: 1}, scheduled())
	for _, r := range h.jobs.requests() {
		assert.Equal(t, inventory.JobRequest{Type: inventory.JobKVPoll, TargetID: r.TargetID, Payload: map[string]string{}, Kind: "scheduled",
			DedupeKey: "kv.poll:" + r.TargetID.String()}, r)
	}
	var stamped time.Time
	require.NoError(t, h.db.Owner.QueryRow(h.ctx, "SELECT last_scheduled_at FROM targets WHERE id = $1", vault).Scan(&stamped))
	assert.True(t, h.clock.Now().Equal(stamped), "stamped in the same transaction as the job")

	_, err = h.db.Owner.Exec(h.ctx, "UPDATE targets SET last_scheduled_at = $2 WHERE id = $1", slow, h.clock.Now().Add(100*24*time.Hour)) // parked
	require.NoError(t, err)
	tick := func(after time.Duration) int {
		h.clock.Advance(after)
		n, err := h.svc.ScheduleKVPolls(h.ctx)
		require.NoError(t, err)
		return n
	}
	// Healthy vault: not before 15 minutes.
	assert.Equal(t, 0, tick(14*time.Minute))
	assert.Equal(t, 1, tick(time.Minute), "15 minutes: the 15 minute vault")
	assert.Equal(t, 1, scheduled()[vault]-1)
	// One failure: 30 minutes; two or more: 60 minutes (the cap is max(interval, 1 h)).
	setFailures := func(id uuid.UUID, n int) {
		_, err := h.db.Owner.Exec(h.ctx, "UPDATE targets SET poll_failures = $2 WHERE id = $1", id, n)
		require.NoError(t, err)
	}
	setFailures(vault, 1)
	assert.Equal(t, 0, tick(29*time.Minute))
	assert.Equal(t, 1, tick(time.Minute), "30 minutes after one failure")
	setFailures(vault, 2)
	assert.Equal(t, 0, tick(59*time.Minute))
	assert.Equal(t, 1, tick(time.Minute), "60 minutes after two failures")
	setFailures(vault, 1000000)
	assert.Equal(t, 0, tick(59*time.Minute))
	assert.Equal(t, 1, tick(time.Minute), "never more than an hour for a 15 minute vault")
	// The slow vault (2 h) was due again after 2 hours, whatever its failures: 2 h stays 2 h.
	before := scheduled()[slow]
	setFailures(slow, 5)
	_, err = h.db.Owner.Exec(h.ctx, "UPDATE targets SET last_scheduled_at = $2 WHERE id = $1", slow, h.clock.Now())
	require.NoError(t, err)
	_, err = h.db.Owner.Exec(h.ctx, "UPDATE targets SET last_scheduled_at = $2 WHERE id = $1", vault, h.clock.Now().Add(100*24*time.Hour)) // parked
	require.NoError(t, err)
	assert.Equal(t, 0, tick(119*time.Minute))
	assert.Equal(t, 1, tick(time.Minute))
	assert.Equal(t, before+1, scheduled()[slow])
	_, err = h.db.Owner.Exec(h.ctx, "UPDATE targets SET last_scheduled_at = $2 WHERE id = $1", vault, h.clock.Now().Add(-2*time.Hour)) // due again
	require.NoError(t, err)
	for id, count := range scheduled() {
		assert.Contains(t, []uuid.UUID{vault, slow}, id, "only live, enabled vaults")
		assert.Positive(t, count)
	}

	// A vault that never answered a listing (degraded from birth, last_success_at NULL) is scheduled
	// like any other.
	_, err = h.db.Owner.Exec(h.ctx, "UPDATE targets SET status = 'degraded', last_error_code = 'azure.forbidden', last_success_at = NULL WHERE id = $1", vault)
	require.NoError(t, err)
	h.clock.Advance(time.Minute)
	n, err = h.svc.ScheduleKVPolls(h.ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, n, "a NULL last_success_at changes nothing")
	setFailures(vault, 2)
	assert.Equal(t, 0, tick(59*time.Minute))
	assert.Equal(t, 1, tick(time.Minute), "and its backoff is the same")

	// A refused enqueue rolls the stamp back with it.
	setFailures(vault, 0)
	h.clock.Advance(time.Hour)
	h.jobs.fail = errors.New("queue is down")
	_, err = h.svc.ScheduleKVPolls(h.ctx)
	require.Error(t, err)
	var after time.Time
	require.NoError(t, h.db.Owner.QueryRow(h.ctx, "SELECT last_scheduled_at FROM targets WHERE id = $1", vault).Scan(&after))
	assert.True(t, after.Before(h.clock.Now()), "the stamp was rolled back")
	n, err = h.svc.ScheduleKVPolls(h.ctx)
	require.NoError(t, err)
	assert.Equal(t, 2, n, "both are due again; the failed enqueue left the vault due")
}
