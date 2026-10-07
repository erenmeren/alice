package api

import (
	"net/http"
	"strconv"

	"alice/internal/platform/validate"
	"alice/internal/rbac"
	"alice/internal/reports"
)

// dashboardRoutes are the Dashboard's reads (C13, Phase 7): the summary, the expiring list, the conditions that need
// attention and the delivery state behind the "E-mails could not be sent" banner. Every one is read: the service
// fills only what the caller's role may see (R42 row 13). Reads work in lock.
func (s *server) dashboardRoutes() []route {
	return []route{
		{method: http.MethodGet, pattern: "/api/v1/dashboard/summary", perm: rbac.Read, handler: s.dashboardSummary},
		{method: http.MethodGet, pattern: "/api/v1/dashboard/expiring", perm: rbac.Read, handler: s.dashboardExpiring},
		{method: http.MethodGet, pattern: "/api/v1/alerts", perm: rbac.Read, handler: s.listAlerts},
		{method: http.MethodGet, pattern: "/api/v1/notifications/status", perm: rbac.Read, handler: s.notificationStatus},
	}
}

// viewer is the caller as the dashboard filters for it.
func viewer(r *http.Request) reports.Viewer {
	p := principalFrom(r.Context())
	return reports.Viewer{UserID: p.UserID, Role: p.Role}
}

func (s *server) dashboardSummary(w http.ResponseWriter, r *http.Request) {
	sum, err := s.deps.Reports.Summary(r.Context(), viewer(r))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, summaryJSON(sum))
}

// Bounds of the expiring list (C13): ?days 1..365 (default 30), ?limit 1..200 (default 50).
const (
	defaultExpiringDays = 30
	maxExpiringDays     = 365
)

func (s *server) dashboardExpiring(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	var v validate.Errors
	days := defaultExpiringDays
	if raw := q.Get("days"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 || n > maxExpiringDays {
			v.Add("days", validate.OutOfRange, map[string]string{"min": "1", "max": strconv.Itoa(maxExpiringDays)})
		}
		days = n
	}
	limit := pageLimit(q.Get("limit"), &v)
	if err := v.Err(); err != nil {
		s.fail(w, r, err)
		return
	}
	items, err := s.deps.Reports.Expiring(r.Context(), days, limit)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	now := s.deps.Clock.Now()
	out := make([]expiringItemDTO, 0, len(items))
	for _, it := range items {
		out = append(out, expiringItemJSON(it, now))
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": out})
}

// listAlerts lists the conditions that need attention, filtered for the caller's role as reports.Attention does.
func (s *server) listAlerts(w http.ResponseWriter, r *http.Request) {
	conds, err := s.deps.Reports.Attention(r.Context(), viewer(r))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out := make([]conditionDTO, 0, len(conds))
	for _, c := range conds {
		out = append(out, conditionJSON(c))
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": out})
}

// notificationStatus is the source of the failing banner: the delivery state for Administrators, {"failing": false}
// for every other role, which never learns about the mail server (R42 row 13).
func (s *server) notificationStatus(w http.ResponseWriter, r *http.Request) {
	if principalFrom(r.Context()).Role != rbac.Admin {
		writeJSON(w, http.StatusOK, map[string]bool{"failing": false})
		return
	}
	d, err := s.deps.Mail.Delivery(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, deliveryJSON(d))
}
