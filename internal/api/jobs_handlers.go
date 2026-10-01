package api

import (
	"context"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"github.com/google/uuid"

	"alice/internal/audit"
	"alice/internal/jobs"
	"alice/internal/license"
	"alice/internal/platform/validate"
	"alice/internal/rbac"
)

// jobRoutes show background work and let an Administrator run or discard work that the license
// paused (R29, L-81). Both actions start or stop external work, so they are refused in lock.
func (s *server) jobRoutes() []route {
	return []route{
		{method: http.MethodGet, pattern: "/api/v1/jobs", perm: rbac.Read, handler: s.listJobs},
		{method: http.MethodGet, pattern: "/api/v1/jobs/{id}", perm: rbac.Read, handler: s.getJob},
		{method: http.MethodPost, pattern: "/api/v1/jobs/{id}/actions/confirm", perm: rbac.JobsConfirm, lic: license.ClassChange, handler: s.confirmJob},
		{method: http.MethodPost, pattern: "/api/v1/jobs/{id}/actions/discard", perm: rbac.JobsConfirm, lic: license.ClassChange, handler: s.discardJob},
	}
}

var jobStatuses = []string{"queued", "running", "succeeded", "failed", "cancelled", "dead", "blocked_license"}

func (s *server) listJobs(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	var v validate.Errors
	f := jobs.ListFilter{
		Status:   jobs.Status(q.Get("status")),
		TargetID: optionalUUID(q.Get("target_id"), "target_id", &v),
		Cursor:   q.Get("cursor"),
		Limit:    pageLimit(q.Get("limit"), &v),
	}
	if f.Status != "" && !slices.Contains(jobStatuses, string(f.Status)) {
		v.Add("status", validate.OneOf, map[string]string{"values": strings.Join(jobStatuses, ", ")})
	}
	if len(f.Cursor) > maxCursorBytes {
		v.Add("cursor", validate.TooLong, map[string]string{"max": strconv.Itoa(maxCursorBytes)})
	}
	if err := v.Err(); err != nil {
		s.fail(w, r, err)
		return
	}
	views, next, err := s.deps.Jobs.List(r.Context(), f)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	items := make([]jobDTO, 0, len(views))
	for _, jv := range views {
		items = append(items, jobJSON(jv))
	}
	var nextCursor any
	if next != "" {
		nextCursor = next
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "next_cursor": nextCursor})
}

func (s *server) getJob(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(r, "id")
	if !ok {
		s.writeError(w, r, ErrNotFound)
		return
	}
	jv, err := s.deps.Jobs.Get(r.Context(), id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, jobJSON(jv))
}

func (s *server) confirmJob(w http.ResponseWriter, r *http.Request) {
	s.jobAction(w, r, s.deps.Jobs.Confirm)
}

func (s *server) discardJob(w http.ResponseWriter, r *http.Request) {
	s.jobAction(w, r, s.deps.Jobs.Discard)
}

// jobAction runs confirm or discard as the caller and answers with the job's new state. When the
// action succeeded but the job cannot be read back, it answers 202 with the job's address: the
// action happened, and an error would invite a second, refused attempt.
func (s *server) jobAction(w http.ResponseWriter, r *http.Request, act func(ctx context.Context, actor audit.Actor, by, id uuid.UUID) error) {
	id, ok := pathUUID(r, "id")
	if !ok {
		s.writeError(w, r, ErrNotFound)
		return
	}
	p := principalFrom(r.Context())
	if err := act(r.Context(), p.Actor(s.meta(r)), p.UserID, id); err != nil {
		s.fail(w, r, err)
		return
	}
	jv, err := s.deps.Jobs.Get(r.Context(), id)
	if err != nil {
		s.deps.Log.Warn("job read back failed after an action", append([]any{"request_id", RequestID(r.Context()), "job_id", id.String()}, errorAttrs(err)...)...)
		writeJSON(w, http.StatusAccepted, accepted(id))
		return
	}
	writeJSON(w, http.StatusOK, jobJSON(jv))
}
