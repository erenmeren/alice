package seed

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// DashboardAnswer is the dashboard the seeded data must show (contract C17).
type DashboardAnswer struct {
	Certificates map[string]int `json:"certificates"`
	Targets      map[string]int `json:"targets"`
	Deployments  map[string]int `json:"deployments"`
	Expiring30   []string       `json:"expiring_30"`
	ServerFilter *ServerFilter  `json:"server_filter"`
}

// ServerFilter is the certificate page filtered by one server and the 30-day window.
type ServerFilter struct {
	Target   string   `json:"target"`
	Expiry30 []string `json:"expiry_30"`
}

// Dashboard inserts C17's data set through the owner pool with now as the reference time and returns what the
// dashboard and the certificate list must show for it. The certificate counts are the dashboard's cumulative windows
// over every certificate row, with the certificate list's predicates (expired: not_after <= now; a window of n days:
// not_after < now + n days, expired ones included), so each count equals the rows its link opens: spare.seed.test,
// on no server, is counted by the windows but is not monitored, so it is neither in "monitored" nor in the expiring
// list (and the scan never e-mails it).
func Dashboard(ctx context.Context, owner *pgxpool.Pool, now time.Time) (DashboardAnswer, error) {
	day := 24 * time.Hour
	ids := map[string]uuid.UUID{}
	for _, t := range []struct{ name, status string }{{"seed-web-1", "ok"}, {"seed-web-2", "ok"}, {"seed-web-3", "host_key_changed"}} {
		id, err := Target(ctx, owner, t.name, "linux", t.status, nil)
		if err != nil {
			return DashboardAnswer{}, err
		}
		ids[t.name] = id
	}
	certs := []struct {
		cn     string
		left   time.Duration
		target string
		sites  []string
	}{
		{"www.seed.test", 7*day - time.Hour, "seed-web-1", []string{"www.seed.test"}}, {"api.seed.test", 5 * day, "seed-web-1", nil},
		{"old.seed.test", -2 * day, "seed-web-1", nil}, {"shop.seed.test", 20 * day, "seed-web-1", nil},
		{"mail.seed.test", 25 * day, "seed-web-2", nil}, {"docs.seed.test", 45 * day, "seed-web-2", nil},
		{"blog.seed.test", 200 * day, "seed-web-2", nil}, {"intra.seed.test", 29 * day, "seed-web-3", nil},
		{"spare.seed.test", 3 * day, "", nil},
	}
	var api uuid.UUID
	for _, c := range certs {
		var on []uuid.UUID
		if c.target != "" {
			on = []uuid.UUID{ids[c.target]}
		}
		id, err := Certificate(ctx, owner, c.cn, now.Add(c.left), on, c.sites...)
		if err != nil {
			return DashboardAnswer{}, err
		}
		if c.cn == "api.seed.test" {
			api = id
		}
	}
	for _, at := range []time.Time{now.Add(-day), now.Add(-8 * day)} {
		if _, err := Deployment(ctx, owner, api, ids["seed-web-1"], "failed", "ngx.reload_failed", at); err != nil {
			return DashboardAnswer{}, err
		}
	}
	return DashboardAnswer{
		// expired: old; 7 days: + spare, api, www; 30 days: + shop, mail, intra; 60 days: + docs.
		Certificates: map[string]int{"monitored": 8, "expired": 1, "within_7": 4, "within_30": 7, "within_60": 8},
		Targets:      map[string]int{"total": 3, "ok": 2, "host_key_changed": 1},
		Deployments:  map[string]int{"failed_7d": 1},
		Expiring30:   []string{"old.seed.test", "api.seed.test", "www.seed.test", "shop.seed.test", "mail.seed.test", "intra.seed.test"},
		ServerFilter: &ServerFilter{Target: "seed-web-1", Expiry30: []string{"old.seed.test", "api.seed.test", "www.seed.test", "shop.seed.test"}},
	}, nil
}
