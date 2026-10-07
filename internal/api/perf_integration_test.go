//go:build integration && perf

package api

import (
	"context"
	"math"
	"net/http"
	"sort"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/audit"
)

const (
	perfWarmup   = 10
	perfRequests = 100
)

// seedR32 inserts 500 Nginx targets, 5,000 certificates in use (ten per target, expiries spread over 400 days, 5 %
// expired), 500 finished deployments and 5,000 audit rows, as the owner role, in a few set-based statements.
func seedR32(t *testing.T, s *stack) {
	t.Helper()
	ctx := context.Background()
	var cred string
	require.NoError(t, s.db.Owner.QueryRow(ctx, `SELECT id::text FROM credentials WHERE purpose = 'platform_ssh'`).Scan(&cred))
	for _, q := range []string{
		`INSERT INTO targets (id, name, type, config, credential_id, status, created_at, updated_at)
SELECT gen_random_uuid(), 'perf-' || i, 'nginx', jsonb_build_object('host', 'perf-' || i || '.example.test', 'port', 22,
'username', 'alice-svc'), '` + cred + `'::uuid, CASE WHEN i % 50 = 0 THEN 'unreachable' ELSE 'ok' END, now(), now()
FROM generate_series(1, 500) AS i`,
		`INSERT INTO certificates (id, fingerprint_sha256, subject_cn, not_before, not_after, key_algorithm, public_key_sha256, pem_chain,
source, first_seen_at, last_seen_at, created_at)
SELECT gen_random_uuid(), md5('c' || i) || md5('d' || i), 'site' || i || '.example.test', now() - interval '300 days',
now() + ((i % 400) - 20) * interval '1 day', 'ecdsa', md5('k' || i) || md5('l' || i), '', 'discovered', now(), now(), now()
FROM generate_series(1, 5000) AS i`,
		`INSERT INTO certificate_locations (id, target_id, kind, cert_path, key_path, certificate_id, supported, servers, first_seen_at,
last_seen_at)
SELECT gen_random_uuid(), t.id, 'nginx_file', '/etc/nginx/ssl/' || c.subject_cn || '.crt', '/etc/nginx/ssl/' || c.subject_cn || '.key',
c.id, true, jsonb_build_array(jsonb_build_object('names', jsonb_build_array(c.subject_cn), 'listens', '[]'::jsonb,
'file', '/etc/nginx/conf.d/site.conf', 'line', 1)), now(), now()
FROM (SELECT id, subject_cn, row_number() OVER (ORDER BY subject_cn) AS n FROM certificates WHERE subject_cn LIKE 'site%') c
JOIN (SELECT id, row_number() OVER (ORDER BY name) AS n FROM targets WHERE name LIKE 'perf-%') t ON t.n = (c.n - 1) % 500 + 1`,
		`INSERT INTO deployments (id, certificate_id, location_id, target_id, trigger, state, status, new_fingerprint, cert_path, key_path,
error_code, created_at, finished_at)
SELECT gen_random_uuid(), l.certificate_id, l.id, l.target_id, 'manual', 'done', CASE WHEN n % 10 = 0 THEN 'failed' ELSE 'succeeded' END,
c.fingerprint_sha256, l.cert_path, l.key_path, CASE WHEN n % 10 = 0 THEN 'ngx.reload_failed' ELSE '' END,
now() - (n % 14) * interval '1 day', now() - (n % 14) * interval '1 day'
FROM (SELECT l.*, row_number() OVER (ORDER BY l.cert_path) AS n FROM certificate_locations l) l
JOIN certificates c ON c.id = l.certificate_id WHERE l.n <= 500`,
	} {
		_, err := s.db.Owner.Exec(ctx, q)
		require.NoError(t, err)
	}
	for i := 0; i < 5000; i++ { // audit rows through the real chain (the list of the audit page is a measured list)
		require.NoError(t, s.auditSvc.Write(ctx, auditEventForPerf(i)))
	}
	_, err := s.db.Owner.Exec(ctx, `ANALYZE`)
	require.NoError(t, err)
}

func auditEventForPerf(i int) audit.Event {
	return audit.Event{Actor: audit.SystemActor("perf"), Action: "perf.row", Result: audit.Success,
		Details: map[string]string{"n": strconv.Itoa(i)}}
}

// percentile is the nearest-rank percentile q (0 < q <= 1) of d; it sorts d.
func percentile(d []time.Duration, q float64) time.Duration {
	sort.Slice(d, func(i, j int) bool { return d[i] < d[j] })
	return d[int(math.Ceil(q*float64(len(d))))-1]
}

func ms(d time.Duration) float64 { return float64(d.Microseconds()) / 1000 }

// R32: dashboard API p95 < 500 ms, list pages p95 < 300 ms at 5,000 certificates and 500 targets, through the whole HTTP
// stack (authentication, authorization, rate limits, JSON).
func TestR32DashboardAndListBudgets(t *testing.T) {
	s, admin, _ := installed(t)
	seedR32(t, s)
	budgets := []struct {
		path   string
		budget time.Duration
	}{
		{"/api/v1/dashboard/summary", 500 * time.Millisecond},
		{"/api/v1/dashboard/expiring?days=30&limit=50", 500 * time.Millisecond},
		{"/api/v1/alerts", 500 * time.Millisecond},
		{"/api/v1/certificates", 300 * time.Millisecond},
		{"/api/v1/certificates?expiry=30", 300 * time.Millisecond},
		{"/api/v1/certificates?q=site42", 300 * time.Millisecond},
		{"/api/v1/targets", 300 * time.Millisecond},
		{"/api/v1/deployments", 300 * time.Millisecond},
		{"/api/v1/ssh-keys", 300 * time.Millisecond},
		{"/api/v1/audit", 300 * time.Millisecond},
	}
	for _, b := range budgets {
		var times []time.Duration
		for i := 0; i < perfWarmup+perfRequests; i++ {
			s.api.ResetLimits() // the general limit (300/min) is not what is measured
			start := time.Now()
			rec := admin.do(http.MethodGet, b.path, nil)
			elapsed := time.Since(start)
			require.Equal(t, http.StatusOK, rec.Code, "%s: %s", b.path, rec.Body.String())
			if i >= perfWarmup {
				times = append(times, elapsed)
			}
		}
		got := percentile(times, 0.95)
		// The share of the budget is what R42 row 26 decides on (perf joins make ci only at <= 60 % over three runs).
		t.Logf("R32 %-48s p50 %6.1f ms  p95 %6.1f ms  max %6.1f ms  (budget %v, p95 at %3.0f %%)", b.path, ms(percentile(times, 0.5)),
			ms(got), ms(times[len(times)-1]), b.budget, 100*float64(got)/float64(b.budget))
		assert.Less(t, got, b.budget, b.path)
	}
}
