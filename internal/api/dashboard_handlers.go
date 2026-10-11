package api

import (
	"net/http"
	"strconv"

	"alice/internal/license"
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

// phase8SummaryDTO is the summary with the Phase 8 sections (R43 row 18): the backup state for Administrators and
// Auditors, the "Finish setting up" checklist for Administrators, both in a signed-in browser session only; absent for
// every other role and for every API token, and absent while the Phase 8 services are not wired (Deps.Backup,
// Deps.TLSStore nil).
type phase8SummaryDTO struct {
	dashboardSummaryDTO
	Backup         *backupStatusDTO   `json:"backup,omitempty"`
	SetupChecklist []checklistItemDTO `json:"setup_checklist,omitempty"`
}

func (s *server) dashboardSummary(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	sum, err := s.deps.Reports.Summary(ctx, viewer(r))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out := phase8SummaryDTO{dashboardSummaryDTO: summaryJSON(sum)}
	// The sections are for people (C12: Administrators and Auditors, Administrators): an API token never gets them,
	// whatever its owner's role, as backup.manage and settings.manage, which show the same facts, have no token scope.
	p := principalFrom(ctx)
	role := p.Role
	if p.Kind != rbac.UserSession {
		role = ""
	}
	if s.deps.Backup != nil && (role == rbac.Admin || role == rbac.Auditor) {
		st, err := s.deps.Backup.State(ctx)
		if err != nil {
			s.fail(w, r, err)
			return
		}
		configured, err := s.backupsConfigured(ctx)
		if err != nil {
			s.fail(w, r, err)
			return
		}
		b := backupStatusJSON(st, configured, s.deps.Clock.Now())
		out.Backup = &b
	}
	if s.deps.TLSStore != nil && role == rbac.Admin {
		if out.SetupChecklist, err = s.setupChecklist(r, sum); err != nil {
			s.fail(w, r, err)
			return
		}
	}
	writeJSON(w, http.StatusOK, out)
}

// setupChecklist is "Finish setting up" (R43 row 18, §18.5): the recovery passphrase and the HTTPS certificate are
// required; a mail server, a license and a first server are recommended. A step skipped in the wizard (the temporary
// certificate kept, mail skipped) stays open here.
func (s *server) setupChecklist(r *http.Request, sum reports.Summary) ([]checklistItemDTO, error) {
	ctx := r.Context()
	st, err := s.deps.Setup.Status(ctx)
	if err != nil {
		return nil, err
	}
	httpsDone := s.deps.TLSStore != nil && !s.deps.TLSStore.Info().Temporary
	mailDone := false
	if s.deps.Mail != nil {
		if _, mailDone, err = s.deps.Mail.SMTP(ctx); err != nil {
			return nil, err
		}
	}
	phase := license.Phase(sum.License.Phase)
	return []checklistItemDTO{
		{Item: "passphrase", Done: st.RecoveryPassphraseSet, Required: true},
		{Item: "https", Done: httpsDone, Required: true},
		{Item: "mail", Done: mailDone},
		{Item: "license", Done: phase != "" && phase != license.PhaseEvaluation && phase != license.PhaseEvaluationExpired},
		{Item: "target", Done: sum.Targets.Total > 0},
	}, nil
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
		} else {
			days = n
		}
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
