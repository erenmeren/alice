//go:build integration && perf

package api

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/discovery"
	"alice/internal/discovery/discoverysvc"
	"alice/internal/discovery/tlsprobe"
)

// TestPerfNetdiscoScan is the network discovery budget (plan 2026-10-13-network-discovery, decision 6, amendment A8):
// 5,000 endpoints presenting 5,000 leaf certificates and 1,000 shared intermediates, written by the scanner's own store
// path (CreateScan, BeginScan, PrepareScan, Ingest, FinishScan) in 20 scans of 20 scopes of 250 endpoints, so the caps
// on new certificates (1,000 per scan, 5,000 per scope a day) are never reached and nothing is cut; 5,000 managed
// inventory certificates, 750 of them with a discovered fingerprint (500 on a live location: managed; 250 without:
// known) and 500 live targets whose host is an endpoint's address or host name. Then:
//
//   - the read API through the whole HTTP stack: list pages p95 < 300 ms (R32's list budget), the summary p95 < 500 ms
//     (R32's dashboard budget);
//   - the CSV export of the 5,000 under 3 s and of a synthetic 50,000 (the export cap) under 30 s: half the server's
//     60 s WriteTimeout, which an export must finish within (no export budget existed before; ruling in the task-12
//     report);
//   - the ingest of the 5,000 endpoints (measured), which with the dial side (computed from discovery.DefaultRate, never
//     measured: 5,000 at 20 a second is 250 s, the token bucket's spacing pinned by TestBucketSpacesConnections) must
//     fit the 5-minute scan budget;
//   - memory flat: the live heap after a second identical round of scans is within a bound of the heap before it;
//   - EXPLAIN (ANALYZE, BUFFERS) of every read query on the seeded data, logged (the report quotes them).
func TestPerfNetdiscoScan(t *testing.T) {
	s, admin, _ := installed(t)
	ctx := context.Background()
	fleet := buildPerfFleet(s.clock.Now())

	// Round 1: the seeding scans, timed.
	ingest := runPerfRound(t, s, fleet)
	total := time.Duration(0)
	for _, d := range ingest {
		total += d
	}
	var leaves, intermediates, endpoints, churn int
	require.NoError(t, s.db.Owner.QueryRow(ctx, `SELECT count(*) FILTER (WHERE is_leaf), count(*) FILTER (WHERE NOT is_leaf),
    (SELECT count(*) FROM discovery_endpoints WHERE state = 'present'), (SELECT coalesce(sum(cert_churn), 0) FROM discovery_scans)
FROM discovery_certificates`).Scan(&leaves, &intermediates, &endpoints, &churn))
	require.Equal(t, perfLeaves, leaves, "every leaf stored: no cap reached")
	require.Equal(t, perfIntermediates, intermediates)
	require.Equal(t, perfLeaves, endpoints)
	require.Zero(t, churn, "nothing was only counted as churn")
	// The dial side is computed from the default rate, never measured: the token bucket lets one connection through every
	// 1/DefaultRate s (pinned on a fake clock by TestBucketSpacesConnections); a real scan would only measure the wait.
	dial := time.Duration(perfLeaves) * (time.Second / time.Duration(discovery.DefaultRate))
	t.Logf("NETDISCO ingest of %d endpoints in %d scans: total %v, per scan p50 %.1f ms p95 %.1f ms; dial side at %d/s (computed) %v; "+
		"serial bound %v (budget 5m0s)", perfLeaves, len(ingest), total.Round(time.Millisecond), ms(percentile(ingest, 0.5)),
		ms(percentile(ingest, 0.95)), discovery.DefaultRate, dial, (dial + total).Round(time.Millisecond))
	assert.Less(t, dial+total, 5*time.Minute, "5,000 endpoints in at most 5 minutes at the default rate")

	// Round 2: the same scans again (every certificate known); the live heap must not grow with the data scanned.
	before := liveHeap() // (the clock moves 1 s a scan: the admin's session stays live)
	again := runPerfRound(t, s, fleet)
	after := liveHeap()
	var total2 time.Duration
	for _, d := range again {
		total2 += d
	}
	growth := int64(after) - int64(before)
	t.Logf("NETDISCO memory: live heap before round 2 %.1f MiB, after %.1f MiB, growth %+.2f MiB (bound %d MiB); round 2 ingest %v",
		mib(before), mib(after), float64(growth)/(1<<20), perfHeapBound>>20, total2.Round(time.Millisecond))
	assert.Less(t, growth, int64(perfHeapBound), "the live heap is flat across a second identical scan")

	scopeID := seedPerfInventory(t, s, fleet)

	// Cursors deep in the lists (keyset pages from the middle).
	certCursor := walkCursor(t, s, admin, "/api/v1/discovery/certificates?current=true&limit=200", 13)
	epCursor := walkCursor(t, s, admin, "/api/v1/discovery/endpoints?limit=200", 13)
	scopeEPCursor := walkCursor(t, s, admin, "/api/v1/discovery/endpoints?limit=100&scope_id="+scopeID.String(), 1)
	fp := fleet.leafFP[perfLeaves/2]

	list, summary := 300*time.Millisecond, 500*time.Millisecond
	budgets := []struct {
		name, path string
		budget     time.Duration
	}{
		{"results default (still found)", "/api/v1/discovery/certificates?status=all&current=true", list},
		{"results keyset page 14", "/api/v1/discovery/certificates?status=all&current=true&cursor=" + url.QueryEscape(certCursor), list},
		{"results unmanaged", "/api/v1/discovery/certificates?status=unmanaged&current=true", list},
		{"results managed", "/api/v1/discovery/certificates?status=managed&current=true", list},
		{"results known", "/api/v1/discovery/certificates?status=known&current=true", list},
		{"results known page 2", "/api/v1/discovery/certificates?status=known&current=true&cursor=" + url.QueryEscape(certCursor), list},
		{"results q=CN", "/api/v1/discovery/certificates?current=true&q=svc-0042", list},
		{"results q=SAN only", "/api/v1/discovery/certificates?current=true&q=alt-1234", list},
		{"results q=no match", "/api/v1/discovery/certificates?current=true&q=no-such-name", list},
		{"results expiring 30 d", "/api/v1/discovery/certificates?current=true&expiring_within_days=30", list},
		{"results expired", "/api/v1/discovery/certificates?current=true&expired=true", list},
		{"results self-signed", "/api/v1/discovery/certificates?current=true&self_signed=true", list},
		{"results of one scope", "/api/v1/discovery/certificates?current=true&scope_id=" + scopeID.String(), list},
		{"certificate detail", "/api/v1/discovery/certificates/" + fp, list},
		{"endpoints", "/api/v1/discovery/endpoints", list},
		{"endpoints keyset page 14", "/api/v1/discovery/endpoints?cursor=" + url.QueryEscape(epCursor), list},
		{"endpoints of one scope", "/api/v1/discovery/endpoints?scope_id=" + scopeID.String(), list},
		{"endpoints of one scope p2", "/api/v1/discovery/endpoints?scope_id=" + scopeID.String() + "&cursor=" + url.QueryEscape(scopeEPCursor), list},
		{"endpoints of one leaf", "/api/v1/discovery/endpoints?fingerprint=" + fp, list},
		{"scans", "/api/v1/discovery/scans", list},
		{"scopes", "/api/v1/discovery/scopes", list},
		{"settings", "/api/v1/discovery/settings", list},
		{"summary (Overview metric)", "/api/v1/discovery/summary", summary},
	}
	for _, b := range budgets {
		times := timeGET(t, s, admin, b.path, perfWarmup, perfRequests)
		got := percentile(times, 0.95)
		t.Logf("NETDISCO %-32s p50 %6.1f ms  p95 %6.1f ms  max %6.1f ms  (budget %v, p95 at %3.0f %%)", b.name, ms(percentile(times, 0.5)),
			ms(got), ms(times[len(times)-1]), b.budget, 100*float64(got)/float64(b.budget))
		assert.Less(t, got, b.budget, b.name)
	}

	// The CSV export of the 5,000 (the default view's filter).
	rows := 0
	exp := timeExport(t, s, admin, "/api/v1/discovery/certificates/export?current=true", 5, &rows)
	require.Equal(t, perfLeaves+1, rows, "header and every leaf")
	t.Logf("NETDISCO export of %d rows: p50 %.0f ms, max %.0f ms over %d runs (budget 3 s)", perfLeaves, ms(percentile(exp, 0.5)),
		ms(exp[len(exp)-1]), len(exp))
	assert.Less(t, exp[len(exp)-1], 3*time.Second)

	explainNetdisco(t, s, scopeID, fp)

	// The synthetic 50,000: 45,000 more leaves, each presented by one endpoint of one more scope, written as the owner
	// (reaching them through scans would take nine days of the per-scope cap: they measure the export, not the ingest).
	seedSynthetic(t, s)
	exp = timeExport(t, s, admin, "/api/v1/discovery/certificates/export?current=true", 2, &rows)
	require.Equal(t, 50000+1, rows, "header and the export cap of rows")
	t.Logf("NETDISCO export of 50,000 rows: p50 %.0f ms, max %.0f ms over %d runs (budget 30 s)", ms(percentile(exp, 0.5)),
		ms(exp[len(exp)-1]), len(exp))
	assert.Less(t, exp[len(exp)-1], 30*time.Second)
	// The results and the summary at 50,000 leaves: ten times the budgeted size, logged only (the budget is R32's 5,000).
	for _, b := range append(budgets[:13:13], budgets[len(budgets)-1]) {
		times := timeGET(t, s, admin, b.path, 3, 20)
		t.Logf("NETDISCO at 50,000 leaves %-32s p50 %6.1f ms  p95 %6.1f ms", b.name, ms(percentile(times, 0.5)), ms(percentile(times, 0.95)))
	}
	for _, c := range []struct {
		name string
		f    discovery.CertificateFilter
	}{
		{"export page at 50,000 leaves", discovery.CertificateFilter{Current: true, Limit: 200}},
		{"results unmanaged at 50,000 leaves", discovery.CertificateFilter{Current: true, Status: discovery.StatusUnmanaged}},
		{"results managed at 50,000 leaves", discovery.CertificateFilter{Current: true, Status: discovery.StatusManaged}},
	} {
		explainOne(t, s, c.name, func(svc *discoverysvc.Service) error {
			_, _, err := svc.ListCertificates(ctx, c.f)
			return err
		})
	}
	explainOne(t, s, "summary at 50,000 leaves", func(svc *discoverysvc.Service) error {
		_, err := svc.Summary(ctx)
		return err
	})
}

const (
	perfScopes        = 20
	perfPerScope      = 250
	perfLeaves        = perfScopes * perfPerScope
	perfIntermediates = 1000
	perfSelfSignedAt  = 4900 // leaves from here on are self-signed (no intermediate)
	// perfHeapBound: the live heap (after two collections) may grow this much across a second identical round. Measured
	// growth is 0.00-0.01 MiB; one round writes ~7 MiB of PEM and statement arguments, so retaining a round's batches
	// would exceed it.
	perfHeapBound = 3 << 20
)

// perfFleet is what the fleet presents: per scope its endpoints and their results (built once; a round re-sends them).
type perfFleet struct {
	endpoints [][]discovery.Endpoint
	results   [][]discovery.Result
	leafFP    []string
	scopes    []uuid.UUID
}

// perfDER is a deterministic stand-in for a certificate's DER (about 900 bytes, like a small ECDSA certificate); the
// read side never parses the stored body.
func perfDER(kind string, n int) []byte {
	b := bytes.Repeat([]byte{byte(n), byte(n >> 8), 0x30, 0x82}, 225)
	copy(b, fmt.Sprintf("perf-%s-%d|", kind, n))
	return b
}

func fingerprintOf(der []byte) string {
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}

func perfCert(der []byte, cn, issuer string, sans []string, nb, na time.Time, selfSigned, ca bool) tlsprobe.Certificate {
	return tlsprobe.Certificate{Raw: der, FingerprintSHA256: fingerprintOf(der), SubjectCN: cn, IssuerCN: issuer, DNSNames: sans,
		NotBefore: nb, NotAfter: na, KeyAlgorithm: "ecdsa", KeyBits: 256, SelfSigned: selfSigned, IsCA: ca, SignatureAlgorithm: "ECDSA-SHA256"}
}

// buildPerfFleet: endpoint i (0..4999) is 10.77.<i/250>.<i%250+1>:443 in scope i/250; every fifth sends its leaf's name
// as SNI and every tenth was resolved from a host name. Leaf i expires (7i mod 400) - 20 days from now (5 % expired)
// and is signed by intermediate i mod 1000, except the last 100, which are self-signed.
func buildPerfFleet(now time.Time) *perfFleet {
	f := &perfFleet{endpoints: make([][]discovery.Endpoint, perfScopes), results: make([][]discovery.Result, perfScopes),
		leafFP: make([]string, perfLeaves)}
	ints := make([]tlsprobe.Certificate, perfIntermediates)
	intDER := make([][]byte, perfIntermediates)
	for k := range ints {
		intDER[k] = perfDER("int", k)
		ints[k] = perfCert(intDER[k], fmt.Sprintf("Perf Intermediate %d", k), "Perf Root", nil, now.AddDate(-2, 0, 0), now.AddDate(5, 0, 0), false, true)
	}
	for i := range perfLeaves {
		sc := i / perfPerScope
		cn := fmt.Sprintf("svc-%04d.perf.example.test", i)
		e := discovery.Endpoint{Address: netip.AddrFrom4([4]byte{10, 77, byte(sc), byte(i%perfPerScope + 1)}), Port: 443}
		if i%5 == 0 {
			e.SNI = cn
		}
		if i%10 == 0 {
			e.Host = fmt.Sprintf("h-%04d.perf.example.test", i)
		}
		leafDER := perfDER("leaf", i)
		na := now.AddDate(0, 0, (7*i)%400-20)
		sans := []string{cn, fmt.Sprintf("alt-%04d.perf.example.test", i), fmt.Sprintf("www-%04d.perf.example.test", i)}
		var der [][]byte
		var chain tlsprobe.Chain
		if i >= perfSelfSignedAt {
			leaf := perfCert(leafDER, cn, cn, sans, now.AddDate(0, 0, -300), na, true, false)
			der, chain = [][]byte{leafDER}, tlsprobe.Chain{Certificates: []tlsprobe.Certificate{leaf}}
		} else {
			k := i % perfIntermediates
			leaf := perfCert(leafDER, cn, ints[k].SubjectCN, sans, now.AddDate(0, 0, -300), na, false, false)
			der, chain = [][]byte{leafDER, intDER[k]}, tlsprobe.Chain{Certificates: []tlsprobe.Certificate{leaf, ints[k]}}
		}
		f.leafFP[i] = chain.Certificates[0].FingerprintSHA256
		f.endpoints[sc] = append(f.endpoints[sc], e)
		f.results[sc] = append(f.results[sc], discovery.PresentedResult(e, der, chain, "TLS 1.3", "TLS_AES_128_GCM_SHA256"))
	}
	return f
}

// runPerfRound scans every scope once through the scanner's store (creating the scopes on the first round) and returns
// the time of each scan from BeginScan to FinishScan.
func runPerfRound(t *testing.T, s *stack, f *perfFleet) []time.Duration {
	t.Helper()
	ctx := context.Background()
	if f.scopes == nil {
		for sc := range perfScopes {
			id := uuid.New()
			_, err := s.db.App.Exec(ctx, `INSERT INTO discovery_scopes (id, name, entries, ports, created_at, updated_at)
VALUES ($1, $2, $3, '{443}', $4, $4)`, id, fmt.Sprintf("perf-scope-%02d", sc), []string{fmt.Sprintf("10.77.%d.0/24", sc)}, s.clock.Now())
			require.NoError(t, err)
			f.scopes = append(f.scopes, id)
		}
	}
	store := discovery.NewStore(s.db.App)
	out := make([]time.Duration, 0, perfScopes)
	for sc, scope := range f.scopes {
		s.clock.Advance(time.Second)
		now := s.clock.Now()
		id, err := store.CreateScan(ctx, scope, "manual", nil, now)
		require.NoError(t, err)
		start := time.Now()
		st, err := store.BeginScan(ctx, id, now, discovery.DefaultLease)
		require.NoError(t, err)
		require.True(t, st.Run)
		x := &discovery.Expansion{Dial: f.endpoints[sc], Addresses: perfPerScope, Endpoints: perfPerScope}
		require.NoError(t, store.PrepareScan(ctx, id, scope, x, now))
		for b := 0; b < len(f.results[sc]); b += discovery.BatchSize {
			part := f.results[sc][b:min(b+discovery.BatchSize, len(f.results[sc]))]
			require.NoError(t, store.Ingest(ctx, discovery.Batch{ScanID: id, ScopeID: scope, Now: now, Results: part}))
		}
		require.NoError(t, store.FinishScan(ctx, discovery.Finish{ScanID: id, ScopeID: scope, Now: now, State: discovery.ScanDone, Probed: true}))
		out = append(out, time.Since(start))
	}
	return out
}

// liveHeap is the heap in use after two collections.
func liveHeap() uint64 {
	runtime.GC()
	runtime.GC()
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return m.HeapAlloc
}

func mib(n uint64) float64 { return float64(n) / (1 << 20) }

// seedPerfInventory adds the managed side: 500 live targets (250 whose host is an endpoint's address, 250 whose host is
// an endpoint's host name), 5,000 inventory certificates of which 500 have a discovered leaf's fingerprint and a live
// location (managed) and 250 have one without a location (known); then ANALYZE. It returns the first scope.
func seedPerfInventory(t *testing.T, s *stack, f *perfFleet) uuid.UUID {
	t.Helper()
	ctx := context.Background()
	var cred string
	require.NoError(t, s.db.Owner.QueryRow(ctx, `SELECT id::text FROM credentials WHERE purpose = 'platform_ssh'`).Scan(&cred))
	var hosts, managed, known []string
	for i := range perfLeaves {
		switch i % 20 {
		case 1:
			hosts = append(hosts, f.endpoints[i/perfPerScope][i%perfPerScope].Address.String())
		case 10:
			hosts = append(hosts, f.endpoints[i/perfPerScope][i%perfPerScope].Host)
		}
		switch {
		case i%10 == 1:
			managed = append(managed, f.leafFP[i])
		case i%20 == 3:
			known = append(known, f.leafFP[i])
		}
	}
	require.Len(t, hosts, 500)
	for _, q := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO targets (id, name, type, config, credential_id, status, created_at, updated_at)
SELECT gen_random_uuid(), 'perf-' || n, 'nginx', jsonb_build_object('host', h, 'port', 22, 'username', 'alice-svc'), $2::uuid, 'ok', now(), now()
FROM unnest($1::text[]) WITH ORDINALITY AS u(h, n)`, []any{hosts, cred}},
		{`INSERT INTO certificates (id, fingerprint_sha256, subject_cn, not_before, not_after, key_algorithm, public_key_sha256, pem_chain,
source, first_seen_at, last_seen_at, created_at)
SELECT gen_random_uuid(), coalesce(m.fp, md5('c' || i) || md5('d' || i)), 'site' || i || '.example.test', now() - interval '300 days',
now() + ((i % 400) - 20) * interval '1 day', 'ecdsa', md5('k' || i) || md5('l' || i), '', 'discovered', now(), now(), now()
FROM generate_series(1, 5000) AS i LEFT JOIN unnest($1::text[] || $2::text[]) WITH ORDINALITY AS m(fp, n) ON m.n = i`, []any{managed, known}},
		{`INSERT INTO certificate_locations (id, target_id, kind, cert_path, key_path, certificate_id, supported, servers, first_seen_at, last_seen_at)
SELECT gen_random_uuid(), t.id, 'nginx_file', '/etc/nginx/ssl/' || c.subject_cn || '.crt', '/etc/nginx/ssl/' || c.subject_cn || '.key', c.id, true,
'[]'::jsonb, now(), now()
FROM (SELECT id, subject_cn, row_number() OVER (ORDER BY fingerprint_sha256) AS n FROM certificates WHERE fingerprint_sha256 = ANY ($1::text[])) c
JOIN (SELECT id, row_number() OVER (ORDER BY name) AS n FROM targets WHERE name LIKE 'perf-%') t ON t.n = c.n`, []any{managed}},
		{`ANALYZE`, nil},
	} {
		_, err := s.db.Owner.Exec(ctx, q.sql, q.args...)
		require.NoError(t, err)
	}
	var m, k, linked int
	require.NoError(t, s.db.Owner.QueryRow(ctx, `SELECT
    count(*) FILTER (WHERE EXISTS (SELECT 1 FROM certificate_locations l WHERE l.certificate_id = c.id)),
    count(*) FILTER (WHERE NOT EXISTS (SELECT 1 FROM certificate_locations l WHERE l.certificate_id = c.id)),
    (SELECT count(*) FROM discovery_endpoints e WHERE EXISTS (SELECT 1 FROM targets t WHERE t.deleted_at IS NULL
        AND (lower(t.config->>'host') = host(e.address) OR (e.host <> '' AND lower(t.config->>'host') = e.host))))
FROM certificates c JOIN discovery_certificates d USING (fingerprint_sha256)`).Scan(&m, &k, &linked))
	require.Equal(t, 500, m)
	require.Equal(t, 250, k)
	require.Equal(t, 500, linked, "every target links one endpoint")
	return f.scopes[0]
}

// seedSynthetic writes 45,000 more leaves and one present endpoint for each, in one more scope, as the owner; ANALYZE.
func seedSynthetic(t *testing.T, s *stack) {
	t.Helper()
	ctx := context.Background()
	scope := uuid.New()
	pemBody := "-----BEGIN CERTIFICATE-----\n" + strings.Repeat("MIIB", 300) + "\n-----END CERTIFICATE-----\n"
	for _, q := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO discovery_scopes (id, name, entries, ports, created_at, updated_at) VALUES ($1, 'perf-synthetic', '["10.80.0.0/16"]', '{443}', $2, $2)`,
			[]any{scope, s.clock.Now()}},
		{`INSERT INTO discovery_certificates (fingerprint_sha256, is_leaf, subject_cn, sans, issuer_cn, not_before, not_after, key_algorithm, pem,
first_seen, last_seen)
SELECT md5('s' || i) || md5('t' || i), true, 'bulk-' || i || '.perf.example.test', ARRAY['bulk-' || i || '.perf.example.test'], 'Perf Intermediate 1',
$1::timestamptz - interval '300 days', $1::timestamptz + (i % 700) * interval '1 day', 'rsa', $2, $1, $1 FROM generate_series(1, 45000) AS i`,
			[]any{s.clock.Now(), pemBody}},
		{`INSERT INTO discovery_endpoints (id, scope_id, address, port, fingerprint_sha256, state, first_seen, last_seen, last_scanned_at)
SELECT gen_random_uuid(), $1, '10.80.0.0'::inet + i, 443, md5('s' || i) || md5('t' || i), 'present', $2, $2, $2 FROM generate_series(1, 45000) AS i`,
			[]any{scope, s.clock.Now()}},
		{`ANALYZE`, nil},
	} {
		_, err := s.db.Owner.Exec(ctx, q.sql, q.args...)
		require.NoError(t, err)
	}
}

// timeGET times n requests of path after warm ones (sorted on return).
func timeGET(t *testing.T, s *stack, c *client, path string, warm, n int) []time.Duration {
	t.Helper()
	var times []time.Duration
	for i := 0; i < warm+n; i++ {
		s.api.ResetLimits() // the general limit is not what is measured
		start := time.Now()
		rec := c.do(http.MethodGet, path, nil)
		elapsed := time.Since(start)
		require.Equal(t, http.StatusOK, rec.Code, "%s: %s", path, rec.Body.String())
		if i >= warm {
			times = append(times, elapsed)
		}
	}
	percentile(times, 0.5) // sorts
	return times
}

// timeExport times n exports of path (sorted on return) and reports the CSV's record count.
func timeExport(t *testing.T, s *stack, c *client, path string, n int, records *int) []time.Duration {
	t.Helper()
	var times []time.Duration
	for range n {
		s.api.ResetLimits()
		start := time.Now()
		rec := c.do(http.MethodGet, path, nil)
		times = append(times, time.Since(start))
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		all, err := csv.NewReader(rec.Body).ReadAll()
		require.NoError(t, err)
		*records = len(all)
	}
	percentile(times, 0.5)
	return times
}

// walkCursor follows next_cursor pages times from path and returns the cursor of the page after them.
func walkCursor(t *testing.T, s *stack, c *client, path string, pages int) string {
	t.Helper()
	cursor := ""
	for range pages {
		s.api.ResetLimits()
		p := path
		if cursor != "" {
			p += "&cursor=" + url.QueryEscape(cursor)
		}
		rec := c.do(http.MethodGet, p, nil)
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		var page struct {
			NextCursor *string `json:"next_cursor"`
		}
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &page))
		require.NotNil(t, page.NextCursor, path)
		cursor = *page.NextCursor
	}
	return cursor
}

// sqlCapture records every statement a pool sends, with its arguments (a pgx query tracer).
type sqlCapture struct {
	mu sync.Mutex
	q  []capturedQuery
}

type capturedQuery struct {
	sql  string
	args []any
}

func (c *sqlCapture) TraceQueryStart(ctx context.Context, _ *pgx.Conn, d pgx.TraceQueryStartData) context.Context {
	c.mu.Lock()
	c.q = append(c.q, capturedQuery{sql: d.SQL, args: d.Args})
	c.mu.Unlock()
	return ctx
}

func (c *sqlCapture) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}

func (c *sqlCapture) take() []capturedQuery {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := c.q
	c.q = nil
	return out
}

// explainOne runs fn against a discovery service on a traced pool and logs EXPLAIN (ANALYZE, BUFFERS) of every
// statement it sent, with the same arguments (custom plans: the arguments are known); it returns the plans' text.
func explainOne(t *testing.T, s *stack, name string, fn func(svc *discoverysvc.Service) error) string {
	t.Helper()
	ctx := context.Background()
	cfg, err := pgxpool.ParseConfig(s.db.AppURL)
	require.NoError(t, err)
	capture := &sqlCapture{}
	cfg.ConnConfig.Tracer = capture
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	require.NoError(t, err)
	defer pool.Close()
	require.NoError(t, fn(discoverysvc.New(discoverysvc.Config{Pool: pool, Audit: s.auditLog, Clock: s.clock})))
	var all strings.Builder
	for _, q := range capture.take() {
		rows, err := s.db.App.Query(ctx, "EXPLAIN (ANALYZE, BUFFERS) "+q.sql, q.args...)
		require.NoError(t, err)
		lines, err := pgx.CollectRows(rows, pgx.RowTo[string])
		require.NoError(t, err)
		plan := strings.Join(lines, "\n")
		all.WriteString(plan + "\n")
		t.Logf("EXPLAIN %s:\n%s\n%s", name, q.sql, plan)
	}
	return all.String()
}

// explainNetdisco logs the plans of the read queries of the carry list (Task 9) and checks the target link's index.
func explainNetdisco(t *testing.T, s *stack, scopeID uuid.UUID, fp string) {
	t.Helper()
	ctx := context.Background()
	now := s.clock.Now()
	for _, c := range []struct {
		name string
		f    discovery.CertificateFilter
	}{
		{"results default", discovery.CertificateFilter{Current: true}},
		{"results unmanaged", discovery.CertificateFilter{Current: true, Status: discovery.StatusUnmanaged}},
		{"results managed", discovery.CertificateFilter{Current: true, Status: discovery.StatusManaged}},
		{"results known", discovery.CertificateFilter{Current: true, Status: discovery.StatusKnown}},
		{"results q no match", discovery.CertificateFilter{Current: true, Query: "no-such-name"}},
		{"results expiring 30 d", discovery.CertificateFilter{Current: true, Now: now, ExpiringBy: now.AddDate(0, 0, 30)}},
		{"results of one scope", discovery.CertificateFilter{Current: true, ScopeID: scopeID}},
		{"export page", discovery.CertificateFilter{Current: true, Limit: 200}},
	} {
		explainOne(t, s, c.name, func(svc *discoverysvc.Service) error {
			_, _, err := svc.ListCertificates(ctx, c.f)
			return err
		})
	}
	explainOne(t, s, "certificate detail", func(svc *discoverysvc.Service) error {
		_, _, _, err := svc.Certificate(ctx, fp)
		return err
	})
	plan := explainOne(t, s, "endpoints (target link)", func(svc *discoverysvc.Service) error {
		_, _, err := svc.ListEndpoints(ctx, discovery.EndpointFilter{})
		return err
	})
	assert.Contains(t, plan, "discovery_targets_host", "the endpoint -> target link looks targets up by their host index")
	explainOne(t, s, "endpoints of one scope", func(svc *discoverysvc.Service) error {
		_, _, err := svc.ListEndpoints(ctx, discovery.EndpointFilter{ScopeID: scopeID})
		return err
	})
	explainOne(t, s, "summary", func(svc *discoverysvc.Service) error {
		_, err := svc.Summary(ctx)
		return err
	})
	explainOne(t, s, "scope list", func(svc *discoverysvc.Service) error {
		_, _, err := svc.ListScopes(ctx, discoverysvc.ScopeFilter{})
		return err
	})
	explainOne(t, s, "scan list", func(svc *discoverysvc.Service) error {
		_, _, err := svc.ListScans(ctx, discoverysvc.ScanFilter{})
		return err
	})
}
