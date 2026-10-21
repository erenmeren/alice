package api

import (
	"net/http"
	"regexp"
	"strconv"

	"github.com/google/uuid"

	"alice/internal/authz/services"
	"alice/internal/license"
	"alice/internal/platform/validate"
	"alice/internal/rbac"
	"alice/internal/sshkeys"
)

// rotationRoutes are the rotation policies and runs (C13; R41 rows 24, 25 as amended by S2). Administrators prepare,
// change, preview, switch off and delete policies, and stop a run (Stop and undo): rotation.manage, operate tokens
// allowed. Everything that starts or decides changes on servers needs an Administrator's browser session with step-up
// and never a token (rotation.operate): switching a policy on (S2: an edit of a policy that is on switches it off),
// Run now, Continue, Finish now and Keep the old key. Every change is refused in lock (ClassChange); reads stay. The
// service checks every id against the run or policy it belongs to.
func (s *server) rotationRoutes() []route {
	const p = "/api/v1/rotation/policies"
	const r = "/api/v1/rotation/runs"
	change := license.ClassChange
	return []route{
		{method: http.MethodGet, pattern: p, scope: scopeList, perm: rbac.Read, handler: s.listPolicies},
		{method: http.MethodPost, pattern: p, scope: scopeCreate, perm: rbac.RotationManage, lic: change, handler: s.createPolicy},
		{method: http.MethodGet, pattern: p + "/{id}", scope: scopeResource, resolve: by(services.KindRotationPolicy, "id"), perm: rbac.Read, handler: s.getPolicy},
		{method: http.MethodPatch, pattern: p + "/{id}", scope: scopeResource, resolve: by(services.KindRotationPolicy, "id"), perm: rbac.RotationManage, lic: change, handler: s.updatePolicy},
		{method: http.MethodDelete, pattern: p + "/{id}", scope: scopeResource, resolve: &resolver{kind: services.KindRotationReach, param: "id", allVisible: true}, perm: rbac.RotationManage, lic: change, handler: s.deletePolicy},
		{method: http.MethodPost, pattern: p + "/{id}/actions/enable", scope: scopeCross, resolve: by(services.KindRotationPolicy, "id"), perm: rbac.RotationOperate, lic: change, handler: s.setPolicyEnabled(true)},
		{method: http.MethodPost, pattern: p + "/{id}/actions/disable", scope: scopeResource, resolve: by(services.KindRotationPolicy, "id"), perm: rbac.RotationManage, lic: change, handler: s.setPolicyEnabled(false)},
		{method: http.MethodPost, pattern: p + "/{id}/actions/preview", scope: scopeResource, resolve: &resolver{kind: services.KindRotationReach, param: "id", allVisible: true}, perm: rbac.RotationManage, lic: change, handler: s.previewPolicy},
		{method: http.MethodPost, pattern: p + "/{id}/actions/run", scope: scopeCross, resolve: by(services.KindRotationPolicy, "id"), perm: rbac.RotationOperate, lic: change, handler: s.runPolicy},
		{method: http.MethodGet, pattern: r, scope: scopeList, perm: rbac.Read, handler: s.listRotations},
		{method: http.MethodGet, pattern: r + "/{id}", scope: scopeResource, resolve: &resolver{kind: services.KindRotationRun, param: "id", allVisible: true}, perm: rbac.Read, handler: s.getRotation},
		{method: http.MethodPost, pattern: r + "/{id}/actions/continue", scope: scopeCross, resolve: &resolver{kind: services.KindRotationRun, param: "id", allVisible: true}, perm: rbac.RotationOperate, lic: change, handler: s.decideRotation(s.continueRotation)},
		{method: http.MethodPost, pattern: r + "/{id}/actions/finish-now", scope: scopeCross, resolve: &resolver{kind: services.KindRotationRun, param: "id", allVisible: true}, perm: rbac.RotationOperate, lic: change, handler: s.decideRotation(s.finishRotation)},
		{method: http.MethodPost, pattern: r + "/{id}/actions/keep-old", scope: scopeCross, resolve: by(services.KindRotationRun, "id"), perm: rbac.RotationOperate, lic: change, handler: s.keepOld},
		// Stop and undo is accepted in lock: it only takes back what the run added, and its undo follows L-86.
		{method: http.MethodPost, pattern: r + "/{id}/actions/abort", scope: scopeResource, resolve: by(services.KindRotationRun, "id"), perm: rbac.RotationManage, lic: license.ClassAlways,
			handler: s.decideRotation(s.abortRotation)},
	}
}

// Body limits of the rotation routes: a policy is a few short fields; keep-old names up to 10 000 ids.
const (
	maxPolicyBody  = 16 << 10
	maxKeepOldBody = 512 << 10
	maxKeepOld     = 10000
	// defaultOverlapDays is a new policy's overlap when the request leaves it out (R41: 7 days).
	defaultOverlapDays = 7
)

var planDigestRE = regexp.MustCompile(`^[0-9a-f]{64}$`)

// newKeyTypeValues is the OneOf text of new_key_type.
func newKeyTypeValues() string { return "same, " + keyTypeValues() }

// checkExplicitPolicyFields refuses a notice time of 0 and an empty new key type that a request names: the service
// reads 0 and "" as "the default", so only an absent field may mean that (review M4).
func checkExplicitPolicyFields(notify *int, newType *string, v *validate.Errors) {
	if notify != nil && *notify == 0 {
		v.Add("notify_before_hours", validate.OutOfRange, map[string]string{"min": "1", "max": "168"})
	}
	if newType != nil && *newType == "" {
		v.Add("new_key_type", validate.OneOf, map[string]string{"values": newKeyTypeValues()})
	}
}

// writePolicy answers a policy with its strong validator.
func writePolicy(w http.ResponseWriter, status int, p sshkeys.Policy) {
	w.Header().Set("ETag", etag(p.Version))
	writeJSON(w, status, policyJSON(p))
}

func (s *server) listPolicies(w http.ResponseWriter, r *http.Request) {
	ps, err := s.deps.SSHKeys.Policies(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	items := make([]policyDTO, 0, len(ps))
	for _, p := range ps {
		items = append(items, policyJSON(p))
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *server) getPolicy(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(r, "id")
	if !ok {
		s.writeError(w, r, ErrNotFound)
		return
	}
	p, err := s.deps.SSHKeys.Policy(r.Context(), id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writePolicy(w, http.StatusOK, p)
}

// createPolicy creates a policy for a key Alice generated, switched off (§13.6). The service refuses Alice's own
// key, a key Alice holds no private key for, a retired key and the new key of a running rotation.
func (s *server) createPolicy(w http.ResponseWriter, r *http.Request) {
	var req struct {
		SSHKeyID          string  `json:"ssh_key_id"`
		Name              string  `json:"name"`
		IntervalDays      int     `json:"interval_days"`
		OverlapDays       *int    `json:"overlap_days"`
		NotifyBeforeHours *int    `json:"notify_before_hours"`
		NewKeyType        *string `json:"new_key_type"`
	}
	if !s.decodeExact(w, r, &req, maxPolicyBody, "ssh_key_id", "name", "interval_days", "overlap_days", "notify_before_hours", "new_key_type") {
		return
	}
	var v validate.Errors
	keyID := requiredUUID(req.SSHKeyID, "ssh_key_id", &v)
	checkExplicitPolicyFields(req.NotifyBeforeHours, req.NewKeyType, &v)
	if err := v.Err(); err != nil {
		s.fail(w, r, err)
		return
	}
	overlap := defaultOverlapDays
	if req.OverlapDays != nil {
		overlap = *req.OverlapDays
	}
	in := sshkeys.PolicyInput{SSHKeyID: keyID, Name: req.Name, IntervalDays: req.IntervalDays, OverlapDays: overlap}
	if req.NotifyBeforeHours != nil {
		in.NotifyBeforeHours = *req.NotifyBeforeHours
	}
	if req.NewKeyType != nil {
		in.NewKeyType = *req.NewKeyType
	}
	p, err := s.deps.SSHKeys.CreatePolicy(r.Context(), s.actor(r), in)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writePolicy(w, http.StatusCreated, p)
}

// updatePolicy changes a policy (If-Match: its version). A change to the interval, the overlap, the notice or the new
// key type of a policy that is on switches it off in the same transaction (S2, the service's rule): switching it on
// again is the enable route, an Administrator's with step-up. So no token and no session without step-up can leave a
// re-shaped policy running.
func (s *server) updatePolicy(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(r, "id")
	if !ok {
		s.writeError(w, r, ErrNotFound)
		return
	}
	version, ok := ifMatch(r)
	if !ok {
		s.writeError(w, r, ErrPreconditionFailed)
		return
	}
	var req struct {
		Name              *string `json:"name"`
		IntervalDays      *int    `json:"interval_days"`
		OverlapDays       *int    `json:"overlap_days"`
		NotifyBeforeHours *int    `json:"notify_before_hours"`
		NewKeyType        *string `json:"new_key_type"`
	}
	if !s.decodeExact(w, r, &req, maxPolicyBody, "name", "interval_days", "overlap_days", "notify_before_hours", "new_key_type") {
		return
	}
	var v validate.Errors
	checkExplicitPolicyFields(req.NotifyBeforeHours, req.NewKeyType, &v)
	if err := v.Err(); err != nil {
		s.fail(w, r, err)
		return
	}
	p, err := s.deps.SSHKeys.UpdatePolicy(r.Context(), s.actor(r), id, version, sshkeys.PolicyPatch{Name: req.Name,
		IntervalDays: req.IntervalDays, OverlapDays: req.OverlapDays, NotifyBeforeHours: req.NotifyBeforeHours, NewKeyType: req.NewKeyType})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writePolicy(w, http.StatusOK, p)
}

// deletePolicy deletes a policy (If-Match); a previewed run is cancelled, a started run refuses the deletion.
func (s *server) deletePolicy(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(r, "id")
	if !ok {
		s.writeError(w, r, ErrNotFound)
		return
	}
	version, ok := ifMatch(r)
	if !ok {
		s.writeError(w, r, ErrPreconditionFailed)
		return
	}
	if err := s.deps.SSHKeys.DeletePolicy(r.Context(), s.actor(r), id, version); err != nil {
		s.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// setPolicyEnabled switches a policy on (rotation.operate: the first run plan.FirstRun from now) or off
// (rotation.manage: no next run; a previewed run is cancelled, a started run continues). If-Match: its version.
func (s *server) setPolicyEnabled(enabled bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := pathUUID(r, "id")
		if !ok {
			s.writeError(w, r, ErrNotFound)
			return
		}
		version, ok := ifMatch(r)
		if !ok {
			s.writeError(w, r, ErrPreconditionFailed)
			return
		}
		if !s.decodeExactOptional(w, r, &struct{}{}, maxPolicyBody) {
			return
		}
		p, err := s.deps.SSHKeys.SetPolicyEnabled(r.Context(), s.actor(r), id, version, enabled)
		if err != nil {
			s.fail(w, r, err)
			return
		}
		writePolicy(w, http.StatusOK, p)
	}
}

// previewPolicy plans the policy's next run as it would be now and mails it (at most once per key in 10 minutes). It
// creates no run; Run now must carry the digest it answers.
func (s *server) previewPolicy(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(r, "id")
	if !ok {
		s.writeError(w, r, ErrNotFound)
		return
	}
	if !s.decodeExactOptional(w, r, &struct{}{}, maxPolicyBody) {
		return
	}
	p, err := s.deps.SSHKeys.Preview(r.Context(), s.actor(r), id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, previewJSON(p))
}

// runPolicy starts a rotation now with the plan the Administrator previewed: plan_digest must be that preview's
// digest; when the plan built now differs, nothing is created or started (409 ALC-ROT-0003). Run now needs no
// delivered notice (an Administrator with step-up is present, S1); a scheduled run never starts without one.
func (s *server) runPolicy(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(r, "id")
	if !ok {
		s.writeError(w, r, ErrNotFound)
		return
	}
	var req struct {
		PlanDigest string `json:"plan_digest"`
	}
	if !s.decodeExact(w, r, &req, maxPolicyBody, "plan_digest") {
		return
	}
	if !planDigestRE.MatchString(req.PlanDigest) {
		var v validate.Errors
		if req.PlanDigest == "" {
			v.Add("plan_digest", validate.Required, nil)
		} else {
			v.Add("plan_digest", validate.Pattern, nil)
		}
		s.fail(w, r, v)
		return
	}
	run, err := s.deps.SSHKeys.RunNow(r.Context(), s.actor(r), id, req.PlanDigest)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]string{"rotation_id": run.ID.String(), "status_url": "/api/v1/rotation/runs/" + run.ID.String()})
}

// gateOK is the license gate's answer for changes: the run DTO offers only decisions the service would accept.
func (s *server) gateOK() bool { return s.licenseGate(license.ClassChange) == nil }

// actionRoutes are the decision route of each action AllowedActions names.
var actionRoutes = map[string]string{
	sshkeys.ActionContinue: "/api/v1/rotation/runs/{id}/actions/continue", sshkeys.ActionFinishNow: "/api/v1/rotation/runs/{id}/actions/finish-now",
	sshkeys.ActionKeepOld: "/api/v1/rotation/runs/{id}/actions/keep-old", sshkeys.ActionAbort: "/api/v1/rotation/runs/{id}/actions/abort",
}

// callerActions cuts the service's allowed decisions to those the caller may take on their routes, decided by the
// routes' own permissions (the route table) and rbac.Decide: a browser session counts as able to step up (the page
// asks for the code), a token never is. Operators, Auditors and read tokens get none.
func (s *server) callerActions(r *http.Request, allowed []string) []string {
	perms := map[string]rbac.Permission{}
	for _, rt := range s.rotationRoutes() {
		perms[rt.pattern] = rt.perm
	}
	sub := principalFrom(r.Context()).Subject(s.deps.Clock.Now())
	if sub.Kind == rbac.UserSession {
		sub.StepUp = true
	}
	out := []string{}
	for _, a := range allowed {
		if perm, ok := perms[actionRoutes[a]]; ok && rbac.Decide(perm, sub) == rbac.Allow {
			out = append(out, a)
		}
	}
	return out
}

func (s *server) listRotations(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	var v validate.Errors
	f := sshkeys.RotationFilter{
		PolicyID: optionalUUID(q.Get("policy_id"), "policy_id", &v),
		KeyID:    optionalUUID(q.Get("ssh_key_id"), "ssh_key_id", &v),
		Cursor:   q.Get("cursor"),
		Limit:    pageLimit(q.Get("limit"), &v),
	}
	if len(f.Cursor) > maxCursorBytes {
		v.Add("cursor", validate.TooLong, map[string]string{"max": strconv.Itoa(maxCursorBytes)})
	}
	if err := v.Err(); err != nil {
		s.fail(w, r, err)
		return
	}
	runs, next, err := s.deps.SSHKeys.RotationSummaries(r.Context(), f)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	items := make([]rotationSummaryDTO, 0, len(runs))
	for _, run := range runs {
		items = append(items, rotationSummaryJSON(run))
	}
	var cursor any
	if next != "" {
		cursor = next
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "next_cursor": cursor})
}

func (s *server) getRotation(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(r, "id")
	if !ok {
		s.writeError(w, r, ErrNotFound)
		return
	}
	run, err := s.deps.SSHKeys.Rotation(r.Context(), id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	gate := s.gateOK()
	writeJSON(w, http.StatusOK, rotationJSON(run, s.callerActions(r, sshkeys.AllowedActions(run, gate))))
}

// decision is one of the Administrator's decisions on a run without a body.
type decision func(r *http.Request, id uuid.UUID) error

func (s *server) continueRotation(r *http.Request, id uuid.UUID) error {
	return s.deps.SSHKeys.Continue(r.Context(), s.actor(r), id)
}

func (s *server) finishRotation(r *http.Request, id uuid.UUID) error {
	return s.deps.SSHKeys.FinishNow(r.Context(), s.actor(r), id)
}

func (s *server) abortRotation(r *http.Request, id uuid.UUID) error {
	return s.deps.SSHKeys.Abort(r.Context(), s.actor(r), id)
}

// decideRotation answers 204 when the service took the decision.
func (s *server) decideRotation(d decision) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := pathUUID(r, "id")
		if !ok {
			s.writeError(w, r, ErrNotFound)
			return
		}
		if !s.decodeExactOptional(w, r, &struct{}{}, maxPolicyBody) {
			return
		}
		if err := d(r, id); err != nil {
			s.fail(w, r, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

// keepOld keeps the old key where Alice could not test the new one: every id must be an untestable place of this run
// (the service refuses any other with 409 ALC-ROT-0005, before it changes anything).
func (s *server) keepOld(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(r, "id")
	if !ok {
		s.writeError(w, r, ErrNotFound)
		return
	}
	var req struct {
		LocationIDs []string `json:"location_ids"`
	}
	if !s.decodeExact(w, r, &req, maxKeepOldBody, "location_ids") {
		return
	}
	var v validate.Errors
	ids := make([]uuid.UUID, 0, len(req.LocationIDs))
	seen := make(map[uuid.UUID]bool, len(req.LocationIDs))
	switch n := len(req.LocationIDs); {
	case n == 0:
		v.Add("location_ids", validate.Required, nil)
	case n > maxKeepOld:
		v.Add("location_ids", validate.OutOfRange, map[string]string{"min": "1", "max": strconv.Itoa(maxKeepOld)})
	}
	for _, raw := range req.LocationIDs {
		lid, err := uuid.Parse(raw)
		if err != nil {
			v.Add("location_ids", validate.Pattern, nil)
			break
		}
		if seen[lid] {
			v.Add("location_ids", validate.Duplicate, nil)
			break
		}
		seen[lid] = true
		ids = append(ids, lid)
	}
	if err := v.Err(); err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.deps.SSHKeys.KeepOld(r.Context(), s.actor(r), id, ids); err != nil {
		s.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
