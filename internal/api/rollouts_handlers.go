package api

import (
	"net/http"
	"regexp"
	"strconv"
	"time"

	"github.com/google/uuid"

	"alice/internal/authz/services"
	"alice/internal/inventory"
	"alice/internal/license"
	"alice/internal/rbac"
)

// rolloutRoutes are the canary rollouts (R65, design §13.2, §13.3, §17.1): a rollout is read like a deployment; Continue
// now releases wave 1 before the hold ends (certificates.operate on the source service and on every wave-2 website's,
// a fresh step-up in a browser session; refused in lock), Abort reverts wave 1 (certificates.operate on the source
// service, no step-up: a safety action that works in lock).
func (s *server) rolloutRoutes() []route {
	return []route{
		{method: http.MethodGet, pattern: "/api/v1/deployment-rollouts/{id}", scope: scopeResource, resolve: by(services.KindRollout, "id"),
			perm: rbac.Read, handler: s.getRollout},
		{method: http.MethodPost, pattern: "/api/v1/deployment-rollouts/{id}/actions/continue", scope: scopeCross,
			resolve: by(services.KindRollout, "id"), perm: rbac.CertificatesOperate, lic: license.ClassChange, handler: s.continueRollout},
		{method: http.MethodPost, pattern: "/api/v1/deployment-rollouts/{id}/actions/abort", scope: scopeResource,
			resolve: by(services.KindRollout, "id"), perm: rbac.CertificatesOperate, lic: license.ClassAlways, handler: s.abortRollout},
	}
}

// rolloutRefDTO is a deployment's rollout in a deployment answer.
type rolloutRefDTO struct {
	ID    string `json:"id"`
	Wave  int    `json:"wave"`
	State string `json:"state"`
}

func rolloutRefJSON(d inventory.Deployment) *rolloutRefDTO {
	if d.RolloutID == nil {
		return nil
	}
	return &rolloutRefDTO{ID: d.RolloutID.String(), Wave: d.Wave, State: codeOrBlank(d.RolloutState)}
}

// canaryDTO is the latest observation of a wave-1 hold.
type canaryDTO struct {
	Rounds              int        `json:"rounds"`
	Passes              int        `json:"passes"`
	ConsecutiveFailures int        `json:"consecutive_failures"`
	LastAt              *time.Time `json:"last_at"`
	LastResult          string     `json:"last_result"`
	LastReason          string     `json:"last_reason"`
	LastTLS             string     `json:"last_tls"`
	LastHTTPStatus      *int       `json:"last_http_status"`
	LastLatencyMS       *int       `json:"last_latency_ms"`
	NextCheckAt         time.Time  `json:"next_check_at"`
}

func canaryJSON(c *inventory.CanaryView) *canaryDTO {
	if c == nil {
		return nil
	}
	return &canaryDTO{Rounds: c.Rounds, Passes: c.Passes, ConsecutiveFailures: c.ConsecutiveFailures, LastAt: c.LastAt,
		LastResult: codeOrBlank(c.LastResult), LastReason: reasonOrBlank(c.LastReason), LastTLS: codeOrBlank(c.LastTLS),
		LastHTTPStatus: c.LastHTTPStatus, LastLatencyMS: c.LastLatencyMS, NextCheckAt: c.NextCheckAt.UTC()}
}

// rolloutSettingsDTO is the policy snapshot a rollout runs with (durations as the policy writes them).
type rolloutSettingsDTO struct {
	Count           int              `json:"count"`
	Percent         int              `json:"percent"`
	Hold            string           `json:"hold"`
	Interval        string           `json:"interval"`
	Failures        int              `json:"failures"`
	Check           *rolloutCheckDTO `json:"check"`
	OverrideAllowed bool             `json:"override_allowed"`
}

type rolloutCheckDTO struct {
	Path         string `json:"path"`
	Host         string `json:"host"`
	Port         int    `json:"port"`
	ExpectStatus []int  `json:"expect_status"`
	Timeout      string `json:"timeout"`
}

func rolloutSettingsJSON(r inventory.Rollout) rolloutSettingsDTO {
	s := r.Settings
	out := rolloutSettingsDTO{Count: s.Count, Percent: s.Percent, Hold: durationText(s.Hold), Interval: durationText(s.Interval),
		Failures: s.Failures, OverrideAllowed: s.OverrideAllowed}
	if c := s.Check; c != nil {
		out.Check = &rolloutCheckDTO{Path: c.Path, Host: c.Host, Port: c.Port, ExpectStatus: nonNilInts(c.ExpectStatus), Timeout: durationText(s.Timeout)}
	}
	return out
}

func nonNilInts(v []int) []int {
	if v == nil {
		return []int{}
	}
	return v
}

// durationText writes a whole duration in its largest unit (as the policy stores it).
func durationText(d time.Duration) string {
	sec := int64(d / time.Second)
	switch {
	case sec != 0 && sec%3600 == 0:
		return strconv.FormatInt(sec/3600, 10) + "h"
	case sec != 0 && sec%60 == 0:
		return strconv.FormatInt(sec/60, 10) + "m"
	}
	return strconv.FormatInt(sec, 10) + "s"
}

// requestedRolloutDTO is the rollout a deploy request created (202 answer).
type requestedRolloutDTO struct {
	ID       string             `json:"id"`
	State    string             `json:"state"`
	Wave1    []string           `json:"wave1"`
	Wave2    []string           `json:"wave2"`
	Settings rolloutSettingsDTO `json:"settings"`
}

func requestedRolloutJSON(r *inventory.Rollout) *requestedRolloutDTO {
	if r == nil {
		return nil
	}
	return &requestedRolloutDTO{ID: r.ID.String(), State: r.State, Wave1: idStrings(r.Wave1), Wave2: idStrings(r.Wave2), Settings: rolloutSettingsJSON(*r)}
}

func idStrings(ids []uuid.UUID) []string {
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		out = append(out, id.String())
	}
	return out
}

// deployAnswer is the 202 answer of the three deploy routes: the deployments created now (wave 1 only for a rollout)
// and the rollout (null when none).
func deployAnswer(got []inventory.RequestedDeployment, r *inventory.Rollout) map[string]any {
	items := make([]requestedDeploymentDTO, 0, len(got))
	for _, d := range got {
		items = append(items, requestedDeploymentJSON(d))
	}
	return map[string]any{"deployments": items, "rollout": requestedRolloutJSON(r)}
}

type rolloutLocationDTO struct {
	LocationID       string     `json:"location_id"`
	TargetID         string     `json:"target_id"`
	TargetName       string     `json:"target_name"`
	Site             string     `json:"site"`
	DeploymentID     *string    `json:"deployment_id"`
	DeploymentState  *string    `json:"deployment_state"`
	DeploymentStatus *string    `json:"deployment_status"`
	Canary           *canaryDTO `json:"canary"`
}

type rolloutWaveDTO struct {
	Wave      int                  `json:"wave"`
	Locations []rolloutLocationDTO `json:"locations"`
}

type rolloutSkipDTO struct {
	LocationID string `json:"location_id"`
	Reason     string `json:"reason"`
}

type rolloutDTO struct {
	ID             string             `json:"id"`
	State          string             `json:"state"`
	Reason         string             `json:"reason"`
	ReasonParams   map[string]string  `json:"reason_params"`
	Origin         string             `json:"origin"`
	Certificate    namedRefDTO        `json:"certificate"`
	Service        *rolloutServiceDTO `json:"service"`
	PolicyVersion  int                `json:"policy_version"`
	Settings       rolloutSettingsDTO `json:"settings"`
	HoldStartedAt  *time.Time         `json:"hold_started_at"`
	HoldUntil      *time.Time         `json:"hold_until"`
	Now            time.Time          `json:"now"`
	Waves          []rolloutWaveDTO   `json:"waves"`
	Skipped        []rolloutSkipDTO   `json:"skipped"`
	AllowedActions []string           `json:"allowed_actions"`
	HiddenCount    int                `json:"hidden_count"`
	CreatedAt      time.Time          `json:"created_at"`
	FinishedAt     *time.Time         `json:"finished_at"`
}

type namedRefDTO struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// rolloutServiceDTO is the source service as the caller may see it: its name, or only {outside: true}.
type rolloutServiceDTO struct {
	ID      string `json:"id,omitempty"`
	Name    string `json:"name,omitempty"`
	Outside bool   `json:"outside,omitempty"`
}

func (s *server) getRollout(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(r, "id")
	if !ok {
		s.writeError(w, r, ErrDeployRolloutNotFound)
		return
	}
	d, err := s.deps.Inventory.RolloutDetail(r.Context(), id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, s.rolloutJSON(r, d))
}

// rolloutJSON is the rollout as the caller sees it (design §5.8: websites on servers outside the caller's reach are
// counted in hidden_count, never shown; allowed_actions are those the state and the caller's rights allow, step-up not
// considered).
func (s *server) rolloutJSON(r *http.Request, d inventory.RolloutDetail) rolloutDTO {
	read := s.reachOf(r, rbac.Read)
	operate := s.reachOf(r, rbac.CertificatesOperate)
	out := rolloutDTO{ID: d.ID.String(), State: d.State, Reason: reasonOrBlank(d.Reason), ReasonParams: d.ReasonParams, Origin: d.Origin,
		Certificate: namedRefDTO{ID: d.CertificateID.String(), Name: d.CertificateName}, PolicyVersion: d.PolicyVersion,
		Settings: rolloutSettingsJSON(d.Rollout), HoldStartedAt: d.HoldStartedAt, HoldUntil: d.HoldUntil, Now: d.Now.UTC(),
		Waves:   []rolloutWaveDTO{{Wave: 1, Locations: []rolloutLocationDTO{}}, {Wave: 2, Locations: []rolloutLocationDTO{}}},
		Skipped: []rolloutSkipDTO{}, AllowedActions: []string{}, CreatedAt: d.CreatedAt.UTC(), FinishedAt: d.FinishedAt}
	if d.ServiceID != nil {
		if read.Contains(*d.ServiceID) {
			out.Service = &rolloutServiceDTO{ID: d.ServiceID.String(), Name: d.ServiceName}
		} else {
			out.Service = &rolloutServiceDTO{Outside: true}
		}
	}
	for _, l := range d.Locations {
		if !read.Contains(l.ServiceID) {
			out.HiddenCount++
			continue
		}
		row := rolloutLocationDTO{LocationID: l.LocationID.String(), TargetID: l.TargetID.String(), TargetName: l.TargetName, Site: l.Site,
			Canary: canaryJSON(l.Canary)}
		if l.DeploymentID != nil {
			id, st, status := l.DeploymentID.String(), codeOrBlank(l.DeploymentState), codeOrBlank(l.DeploymentStatus)
			row.DeploymentID, row.DeploymentState, row.DeploymentStatus = &id, &st, &status
		}
		out.Waves[l.Wave-1].Locations = append(out.Waves[l.Wave-1].Locations, row)
	}
	for _, sk := range d.Skipped {
		out.Skipped = append(out.Skipped, rolloutSkipDTO{LocationID: sk.LocationID.String(), Reason: reasonOrBlank(sk.Reason)})
	}
	if out.ReasonParams == nil {
		out.ReasonParams = map[string]string{}
	}
	source := uuid.Nil
	if d.ServiceID != nil {
		source = *d.ServiceID
	}
	mayOperate := operate.All() || (source != uuid.Nil && operate.Contains(source))
	if mayOperate {
		out.AllowedActions = d.AllowedRolloutActions()
	}
	return out
}

func (s *server) continueRollout(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(r, "id")
	if !ok {
		s.writeError(w, r, ErrDeployRolloutNotFound)
		return
	}
	// Bypassing the remaining hold is a person's deliberate act: a fresh step-up in a browser session, never a token
	// (design decision 3, §20.4).
	if !s.strictActionFor(w, r, rbac.SessionStepUp) {
		return
	}
	cur, err := s.deps.Inventory.RolloutDetail(r.Context(), id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	// Design R49 §5.6 (b): certificates.operate on every wave-2 website's service.
	if !s.checkDestinationsOf(w, r, rbac.CertificatesOperate, services.KindLocation, cur.Wave2) {
		return
	}
	if _, err := s.deps.Inventory.ContinueRollout(r.Context(), s.actor(r), id); err != nil {
		s.fail(w, r, err)
		return
	}
	s.answerRollout(w, r, id)
}

func (s *server) abortRollout(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(r, "id")
	if !ok {
		s.writeError(w, r, ErrDeployRolloutNotFound)
		return
	}
	if _, err := s.deps.Inventory.AbortRollout(r.Context(), s.actor(r), id); err != nil {
		s.fail(w, r, err)
		return
	}
	s.answerRollout(w, r, id)
}

func (s *server) answerRollout(w http.ResponseWriter, r *http.Request, id uuid.UUID) {
	d, err := s.deps.Inventory.RolloutDetail(r.Context(), id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, s.rolloutJSON(r, d))
}

// canaryOverrideAllowed asks for the override's strict session (design §13.1): a fresh step-up in a browser session,
// never a token. It writes the refusal and answers false.
func (s *server) canaryOverrideAllowed(w http.ResponseWriter, r *http.Request, override bool) bool {
	return !override || s.strictActionFor(w, r, rbac.SessionStepUp)
}

// rolloutReasonRE is the shape of a rollout or round reason (canary.http_status, deployment.verify_failed, lock_due).
var rolloutReasonRE = regexp.MustCompile(`^[a-z][a-z0-9_]{0,39}(\.[a-z0-9_]{1,60}){0,2}$`)

// reasonOrBlank is a reason code of Alice's own, or "" for anything else.
func reasonOrBlank(v string) string {
	if rolloutReasonRE.MatchString(v) {
		return v
	}
	return ""
}
