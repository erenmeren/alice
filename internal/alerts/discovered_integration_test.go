//go:build integration

package alerts_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/alerts"
	"alice/internal/platform/clock"
	"alice/internal/platform/settings"
	"alice/internal/testutil/pgtest"
	"alice/internal/testutil/seed"
)

func seedScope(t *testing.T, d *pgtest.DB, name string, alert bool) uuid.UUID {
	t.Helper()
	id, err := seed.DiscoveryScope(context.Background(), d.Owner, name, alert)
	require.NoError(t, err)
	return id
}

func seedFound(t *testing.T, d *pgtest.DB, fp, cn string, notAfter time.Time, sans ...string) {
	t.Helper()
	require.NoError(t, seed.DiscoveredCertificate(context.Background(), d.Owner, fp, cn, notAfter, sans...))
}

func seedEndpoint(t *testing.T, d *pgtest.DB, scope uuid.UUID, addr string, port int, host, fp, state string) {
	t.Helper()
	_, err := seed.DiscoveredEndpoint(context.Background(), d.Owner, scope, addr, port, host, fp, state)
	require.NoError(t, err)
}

func fingerprintOf(t *testing.T, d *pgtest.DB, cert uuid.UUID) string {
	t.Helper()
	var fp string
	require.NoError(t, d.Owner.QueryRow(context.Background(), `SELECT fingerprint_sha256 FROM certificates WHERE id = $1`, cert).Scan(&fp))
	return fp
}

// Decision 5, A7: a discovered leaf alerts when it is unmanaged (its fingerprint is not in certificates) and a present
// endpoint of a live scope with alert_on_expiry presents it; with the existing thresholds and ledger, once per level.
// Managed and known certificates, scopes without the flag and gone endpoints never alert as discovered. A discovered
// item has no location, no server and no vault: the scan handles it.
func TestDiscoveredCertificatesAlertOnlyWhenUnmanagedOnAnAlertingScope(t *testing.T) {
	d := pgtest.New(t)
	ctx := context.Background()
	clk := clock.NewFake(t0)
	r := &recorder{}
	s := newService(t, d, clk, lic{}, r)
	require.NoError(t, settings.Set(ctx, d.App, settings.GeneralKey,
		settings.General{PublicURL: "https://alice.example.com/", RetiredKeyRetentionDays: 30, Version: 1}, t0))
	dc, lab := seedScope(t, d, "Data centre", true), seedScope(t, d, "Lab", false)
	web := seedTarget(t, d, "web-01", "nginx", nil)
	managed := seedCert(t, d, "www.example.com", t0.Add(5*day), []uuid.UUID{web}, "www.example.com")
	known := seedCert(t, d, "spare.example.com", t0.Add(5*day), nil)

	legacy, onlyLab, gone, far, expired := seed.Hex("legacy"), seed.Hex("lab"), seed.Hex("gone"), seed.Hex("far"), seed.Hex("expired")
	seedFound(t, d, legacy, "legacy.example.com", t0.Add(5*day))
	seedFound(t, d, onlyLab, "lab.example.com", t0.Add(5*day))
	seedFound(t, d, gone, "gone.example.com", t0.Add(5*day))
	seedFound(t, d, far, "far.example.com", t0.Add(200*day))
	seedFound(t, d, expired, "", t0.Add(-day), "old.example.com", "www.old.example.com")
	seedFound(t, d, fingerprintOf(t, d, managed), "www.example.com", t0.Add(5*day))
	seedFound(t, d, fingerprintOf(t, d, known), "spare.example.com", t0.Add(5*day))
	seedEndpoint(t, d, dc, "10.0.0.5", 443, "", legacy, "present")
	seedEndpoint(t, d, dc, "10.0.0.6", 8443, "legacy.example.com", legacy, "present")
	seedEndpoint(t, d, dc, "2001:db8::1", 443, "", legacy, "present")
	seedEndpoint(t, d, lab, "10.0.0.7", 443, "", legacy, "present") // a non-alerting scope's endpoint is not listed
	seedEndpoint(t, d, lab, "10.0.1.1", 443, "", onlyLab, "present")
	seedEndpoint(t, d, dc, "10.0.0.8", 443, "", gone, "gone")
	seedEndpoint(t, d, dc, "10.0.0.9", 443, "", far, "present")
	seedEndpoint(t, d, dc, "10.0.0.10", 443, "", expired, "present")
	seedEndpoint(t, d, dc, "10.0.0.11", 443, "", fingerprintOf(t, d, managed), "present")
	seedEndpoint(t, d, dc, "10.0.0.12", 443, "", fingerprintOf(t, d, known), "present")

	items, err := s.Items(ctx, []alerts.Kind{alerts.KindDiscoveredCertificate}, t0.Add(60*day), 0)
	require.NoError(t, err)
	require.Len(t, items, 2)
	assert.Equal(t, alerts.Item{Kind: alerts.KindDiscoveredCertificate, ObjectID: alerts.DiscoveredObjectID(expired), Name: "old.example.com",
		ExpiresAt: t0.Add(-day), Fingerprint: expired, Endpoints: []string{"10.0.0.10:443"}, Scopes: []string{"Data centre"}}, items[0],
		"no CN: the first name; no location, server or vault")
	assert.Equal(t, alerts.DiscoveredObjectID(legacy), items[1].ObjectID)
	assert.Equal(t, "legacy.example.com", items[1].Name)
	assert.Equal(t, []string{"10.0.0.5:443", "[2001:db8::1]:443", "legacy.example.com:8443"}, items[1].Endpoints,
		"the host name where the scope named one, IPv6 in brackets, the alerting scopes' endpoints only")

	_, err = s.Scan(ctx)
	require.NoError(t, err)
	assert.Equal(t, map[string]int{"discovered_certificate_expiry:0": 1, "discovered_certificate_expiry:7": 1, "certificate_expiry:7": 1},
		ledger(t, d), "the managed one alerts as a managed certificate, once; the known one not at all")
	byTpl := map[string]map[string]string{}
	for _, q := range r.got {
		byTpl[q.template] = q.params
	}
	require.Contains(t, byTpl, "alert.discovered_certificate_expiring")
	require.Contains(t, byTpl, "alert.discovered_certificate_expired")
	p := byTpl["alert.discovered_certificate_expiring"]
	assert.Equal(t, map[string]string{"name": "legacy.example.com", "expires_at": "2026-10-12 09:00 UTC", "days": "5", "fingerprint": legacy,
		"endpoints": "10.0.0.5:443, [2001:db8::1]:443, legacy.example.com:8443", "scopes": "Data centre",
		"discovery_url": "https://alice.example.com/discovery?view=unmanaged"}, p)
	for _, q := range r.got {
		for _, v := range q.params {
			assert.NotContains(t, v, "BEGIN CERTIFICATE", "no certificate body in an e-mail")
		}
	}
	var objType, objID string
	require.NoError(t, d.Owner.QueryRow(ctx, `SELECT object_type, object_id FROM audit_log WHERE action = 'alert.sent'
AND object_type = 'discovered_certificate_expiry' AND details->>'threshold_days' = '7'`).Scan(&objType, &objID))
	assert.Equal(t, alerts.DiscoveredObjectID(legacy).String(), objID)

	n := len(r.got)
	clk.Advance(time.Hour)
	_, err = s.Scan(ctx)
	require.NoError(t, err)
	assert.Len(t, r.got, n, "once per level")
}

// A discovered certificate that becomes managed (its fingerprint enters certificates), whose scope turns
// alert_on_expiry off, or whose scope is deleted stops alerting; the ledger keeps what was sent (append-only, like
// every kind) and nothing fails. Turning the flag on again resumes at the next level, never resending one.
func TestDiscoveredAlertsStopWhenManagedOrTheScopeStopsAlerting(t *testing.T) {
	d := pgtest.New(t)
	ctx := context.Background()
	clk := clock.NewFake(t0)
	r := &recorder{}
	s := newService(t, d, clk, lic{}, r)
	adopted, flagged, deleted := seed.Hex("adopted"), seed.Hex("flagged"), seed.Hex("deleted")
	a, b, c := seedScope(t, d, "a", true), seedScope(t, d, "b", true), seedScope(t, d, "c", true)
	for i, x := range []struct {
		scope uuid.UUID
		fp    string
	}{{a, adopted}, {b, flagged}, {c, deleted}} {
		seedFound(t, d, x.fp, x.fp[:8]+".example.com", t0.Add(40*day))
		seedEndpoint(t, d, x.scope, "10.0.0."+string(rune('1'+i)), 443, "", x.fp, "present")
	}
	_, err := s.Scan(ctx)
	require.NoError(t, err)
	assert.Equal(t, map[string]int{"discovered_certificate_expiry:60": 3}, ledger(t, d))

	// The adopted one is now in the inventory (uploaded, on no server yet: "known"); b's flag is off; c is deleted.
	_, err = d.Owner.Exec(ctx, `INSERT INTO certificates (id, fingerprint_sha256, subject_cn, not_before, not_after, key_algorithm,
public_key_sha256, pem_chain, source, first_seen_at, last_seen_at, created_at)
VALUES ($1, $2, 'adopted', $3::timestamptz - interval '90 days', $3, 'ecdsa', $2, '', 'uploaded', now(), now(), now())`,
		uuid.New(), adopted, t0.Add(40*day))
	require.NoError(t, err)
	_, err = d.Owner.Exec(ctx, `UPDATE discovery_scopes SET alert_on_expiry = false WHERE id = $1`, b)
	require.NoError(t, err)
	_, err = d.Owner.Exec(ctx, `UPDATE discovery_scopes SET deleted_at = now() WHERE id = $1`, c)
	require.NoError(t, err)
	clk.Set(t0.Add(20 * day)) // 20 days left: the 30-day level is due for each, were they still alerting
	items, err := s.Items(ctx, alerts.Kinds(), t0.Add(60*day), 0)
	require.NoError(t, err)
	assert.Empty(t, items)
	res, err := s.Scan(ctx)
	require.NoError(t, err)
	assert.Zero(t, res.Failed)
	assert.Equal(t, map[string]int{"discovered_certificate_expiry:60": 3}, ledger(t, d), "nothing new, nothing removed")

	_, err = d.Owner.Exec(ctx, `UPDATE discovery_scopes SET alert_on_expiry = true WHERE id = $1`, b)
	require.NoError(t, err)
	_, err = s.Scan(ctx)
	require.NoError(t, err)
	assert.Equal(t, map[string]int{"discovered_certificate_expiry:60": 3, "discovered_certificate_expiry:30": 1}, ledger(t, d))
	assert.Equal(t, "alert.discovered_certificate_expiring", r.got[len(r.got)-1].template)
	assert.Equal(t, flagged, r.got[len(r.got)-1].params["fingerprint"])
}

// A7: the managed kinds' Items and the Overview counts are byte-identical with and without discovery rows, also when a
// discovered certificate is a managed one and when the managed kinds are read beside the new one.
func TestManagedItemsAndCountsIgnoreDiscovery(t *testing.T) {
	d := pgtest.New(t)
	ctx := context.Background()
	clk := clock.NewFake(t0)
	s := newService(t, d, clk, lic{}, &recorder{})
	web := seedTarget(t, d, "web-01", "nginx", nil)
	secretExp := t0.Add(20 * day)
	vault := seedTarget(t, d, "prod-vault", "azure_key_vault", &secretExp)
	var certs []uuid.UUID
	for cn, left := range map[string]time.Duration{"a": -day, "b": 3 * day, "c": 7 * day, "d": 8 * day, "e": 30 * day, "f": 45 * day} {
		certs = append(certs, seedCert(t, d, cn+".example.com", t0.Add(left), []uuid.UUID{web}, cn+".example.com"))
	}
	spare := seedCert(t, d, "spare.example.com", t0.Add(2*day), nil)
	seedKV(t, d, vault, "kv-cert", t0.Add(10*day), nil, "kv-key", t0.Add(3*day))
	read := func() (alerts.Counts, []alerts.Item, []alerts.Item) {
		c, err := s.Counts(ctx)
		require.NoError(t, err)
		managed, err := s.Items(ctx, alerts.ManagedKinds(), t0.Add(60*day), 0)
		require.NoError(t, err)
		all, err := s.Items(ctx, alerts.Kinds(), t0.Add(60*day), 0)
		require.NoError(t, err)
		var onlyManaged []alerts.Item
		for _, it := range all {
			if it.Kind != alerts.KindDiscoveredCertificate {
				onlyManaged = append(onlyManaged, it)
			}
		}
		return c, managed, onlyManaged
	}
	c0, m0, a0 := read()
	require.Len(t, m0, 9)
	assert.Equal(t, m0, a0)

	scope := seedScope(t, d, "dc", true)
	for i, fp := range []string{fingerprintOf(t, d, certs[0]), fingerprintOf(t, d, spare), seed.Hex("x1"), seed.Hex("x2")} {
		seedFound(t, d, fp, "found.example.com", t0.Add(time.Duration(i)*day))
		seedEndpoint(t, d, scope, "10.0.0."+string(rune('1'+i)), 443, "", fp, "present")
	}
	c1, m1, a1 := read()
	assert.Equal(t, c0, c1, "Overview counts")
	assert.Equal(t, m0, m1, "managed Items")
	assert.Equal(t, m0, a1, "managed Items read beside the discovered kind")
	all, err := s.Items(ctx, alerts.Kinds(), t0.Add(60*day), 0)
	require.NoError(t, err)
	require.Len(t, all, 11, "the two unmanaged ones are the only discovered items: the managed and the known one are not")
	var found []string
	for _, it := range all {
		if it.Kind == alerts.KindDiscoveredCertificate {
			found = append(found, it.Fingerprint)
		}
	}
	assert.Equal(t, []string{seed.Hex("x1"), seed.Hex("x2")}, found)
}
