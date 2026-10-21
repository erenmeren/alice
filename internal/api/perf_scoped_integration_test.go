//go:build integration && perf

package api

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/authz"
)

// R53 (design §10, "Performance as availability"): reading a person's grants, which every request does with its
// session or token, stays under 2 ms at p95 with 500 services in 50 environments and a person holding 200 role
// bindings (the bound), half of them on environments.
func TestR53GrantsReadBudget(t *testing.T) {
	s := newStack(t)
	ctx := context.Background()
	person := uuid.New()
	for _, q := range []string{
		`INSERT INTO environments (id, key, name, sort, created_at, updated_at)
SELECT gen_random_uuid(), 'perf-' || i, 'Perf ' || i, 100 + i, now(), now() FROM generate_series(1, 46) AS i`,
		`INSERT INTO services (id, name, environment_id, created_at, updated_at)
SELECT gen_random_uuid(), 'perf-' || i, (SELECT id FROM environments ORDER BY sort, key OFFSET (i % 50) LIMIT 1), now(), now()
FROM generate_series(1, 499) AS i`,
	} {
		_, err := s.db.Owner.Exec(ctx, q)
		require.NoError(t, err)
	}
	_, err := s.db.Owner.Exec(ctx, `INSERT INTO users (id, username, display_name, password_hash, created_at, updated_at)
VALUES ($1, 'perf', 'Perf', '$argon2id$x', now(), now())`, person)
	require.NoError(t, err)
	for _, q := range []string{
		`INSERT INTO role_bindings (id, user_id, role, service_id, created_at)
SELECT gen_random_uuid(), $1, (ARRAY['admin', 'operator', 'auditor'])[1 + n % 3], id, now()
FROM (SELECT id, row_number() OVER (ORDER BY id) AS n FROM services) s WHERE n <= 150`,
		`INSERT INTO role_bindings (id, user_id, role, environment_id, created_at)
SELECT gen_random_uuid(), $1, r, e.id, now() FROM environments e, (VALUES ('operator'), ('auditor')) AS roles(r) LIMIT 50`,
	} {
		_, err := s.db.Owner.Exec(ctx, q, person)
		require.NoError(t, err)
	}
	_, err = s.db.Owner.Exec(ctx, `ANALYZE`)
	require.NoError(t, err)

	var times []time.Duration
	for i := 0; i < perfWarmup+perfRequests; i++ {
		start := time.Now()
		grants, err := authz.LoadGrants(ctx, s.db.App, person)
		elapsed := time.Since(start)
		require.NoError(t, err)
		require.NotEmpty(t, grants)
		if i >= perfWarmup {
			times = append(times, elapsed)
		}
	}
	got := percentile(times, 0.95)
	t.Logf("R53 grants read: p50 %.2f ms  p95 %.2f ms  max %.2f ms (budget 2 ms)", ms(percentile(times, 0.5)), ms(got), ms(times[len(times)-1]))
	assert.Less(t, got, 2*time.Millisecond)
}
