package api

import (
	"time"

	"alice/internal/sshkeys"
	"alice/internal/sshkeys/plan"
)

// minutesPerDay converts a policy's overlap (stored in minutes) to the days the form shows.
const minutesPerDay = 1440

// policyDTO is a rotation policy (C13). last_run_* is the policy's latest finished run, so the page can say why a
// planned run did not happen (review M4); last_run_result is null when that run had no result.
type policyDTO struct {
	ID                string       `json:"id"`
	SSHKeyID          string       `json:"ssh_key_id"`
	Name              string       `json:"name"`
	Enabled           bool         `json:"enabled"`
	IntervalDays      int          `json:"interval_days"`
	OverlapDays       int          `json:"overlap_days"`
	OverlapMinutes    int          `json:"overlap_minutes"`
	NotifyBeforeHours int          `json:"notify_before_hours"`
	NewKeyType        string       `json:"new_key_type"`
	NextRunAt         *time.Time   `json:"next_run_at"`
	OpenRotationID    *string      `json:"open_rotation_id"`
	LastRunID         *string      `json:"last_run_id"`
	LastRunStatus     *string      `json:"last_run_status"`
	LastRunResult     *errorRefDTO `json:"last_run_result"`
	Version           int          `json:"version"`
	CreatedAt         time.Time    `json:"created_at"`
	UpdatedAt         time.Time    `json:"updated_at"`
}

func policyJSON(p sshkeys.Policy) policyDTO {
	var status *string
	if p.LastRunStatus != "" {
		v := p.LastRunStatus
		status = &v
	}
	return policyDTO{
		ID: p.ID.String(), SSHKeyID: p.SSHKeyID.String(), Name: p.Name, Enabled: p.Enabled, IntervalDays: p.IntervalDays,
		OverlapDays: p.OverlapMinutes / minutesPerDay, OverlapMinutes: p.OverlapMinutes, NotifyBeforeHours: p.NotifyBeforeHours,
		NewKeyType: p.NewKeyType, NextRunAt: utcPtr(p.NextRunAt), OpenRotationID: idPtr(p.OpenRotationID),
		LastRunID: idPtr(p.LastRunID), LastRunStatus: status, LastRunResult: errorRef(p.LastRunResult, nil),
		Version: p.Version, CreatedAt: p.CreatedAt.UTC(), UpdatedAt: p.UpdatedAt.UTC(),
	}
}

// actionDTO is one decision of a plan. skip_reason is "" when the place changes, otherwise a plan.Skip* code (texts:
// rotation.skip.<reason>). The lines are public: the old key's line and the new line with the new key shown by its
// type. Users, paths, options and comments come from servers: they are data, rendered as text.
type actionDTO struct {
	N          int    `json:"n"`
	LocationID string `json:"location_id"`
	TargetID   string `json:"target_id"`
	TargetName string `json:"target_name"`
	OSUser     string `json:"os_user"`
	FilePath   string `json:"file_path"`
	Options    string `json:"options"`
	SkipReason string `json:"skip_reason"`
	Verify     bool   `json:"verify"`
	VerifyNote string `json:"verify_note"`
	RemoveLine string `json:"remove_line"`
	AddLine    string `json:"add_line"`
}

func actionsJSON(in []plan.Action) []actionDTO {
	out := make([]actionDTO, 0, len(in))
	for _, a := range in {
		out = append(out, actionDTO{
			N: a.N, LocationID: a.LocationID.String(), TargetID: a.TargetID.String(), TargetName: a.TargetName, OSUser: a.OSUser,
			FilePath: a.FilePath, Options: a.Options, SkipReason: a.Skip, Verify: a.Verify, VerifyNote: a.VerifyNote,
			RemoveLine: a.RemoveLine, AddLine: a.AddLine,
		})
	}
	return out
}

// previewDTO is a plan as the Administrator sees it before a run (C13). Run now must send plan_digest back.
type previewDTO struct {
	PolicyID       string      `json:"policy_id"`
	SSHKeyID       string      `json:"ssh_key_id"`
	Fingerprint    string      `json:"fingerprint"`
	PlanDigest     string      `json:"plan_digest"`
	PlannedFor     time.Time   `json:"planned_for"`
	NewKeyType     string      `json:"new_key_type"`
	OverlapMinutes int         `json:"overlap_minutes"`
	ChangeCount    int         `json:"change_count"`
	SkipCount      int         `json:"skip_count"`
	Emailed        bool        `json:"emailed"`
	Actions        []actionDTO `json:"actions"`
}

func previewJSON(p sshkeys.Preview) previewDTO {
	return previewDTO{
		PolicyID: p.PolicyID.String(), SSHKeyID: p.Plan.KeyID.String(), Fingerprint: p.Plan.Fingerprint, PlanDigest: p.Digest,
		PlannedFor: p.PlannedFor.UTC(), NewKeyType: p.Plan.NewKeyType, OverlapMinutes: p.Plan.Overlap, ChangeCount: p.Plan.Changes,
		SkipCount: p.Plan.Skips, Emailed: p.Emailed, Actions: actionsJSON(p.Plan.Actions),
	}
}

// rotationLocationDTO is one place of a run. error is the location's stored reason as an errorRef (F4); skip_reason
// a plan.Skip* code; a kept place is state kept_old.
type rotationLocationDTO struct {
	ID            string       `json:"id"`
	N             int          `json:"n"`
	TargetID      string       `json:"target_id"`
	TargetName    string       `json:"target_name"`
	OSUser        string       `json:"os_user"`
	FilePath      string       `json:"file_path"`
	Options       string       `json:"options"`
	State         string       `json:"state"`
	SkipReason    string       `json:"skip_reason"`
	VerifyNote    string       `json:"verify_note"`
	Error         *errorRefDTO `json:"error"`
	Backup        string       `json:"backup"`
	VerifiedAt    *time.Time   `json:"verified_at"`
	ReverifiedAt  *time.Time   `json:"reverified_at"`
	RemovedAt     *time.Time   `json:"removed_at"`
	NewLocationID *string      `json:"new_location_id"`
}

type rotationStepDTO struct {
	N          int               `json:"n"`
	LocationID *string           `json:"location_id"`
	Name       string            `json:"name"`
	Status     string            `json:"status"`
	At         time.Time         `json:"at"`
	Params     map[string]string `json:"params"`
}

// rotationDTO is one run (C13 with F4 and S11): result is the run's result reason as an errorRef (null while it has
// none); kept_count is where the old key stays (skipped and kept places); actions_allowed are the decisions the page
// may offer now. steps is left out of list items.
type rotationDTO struct {
	ID               string                `json:"id"`
	PolicyID         string                `json:"policy_id"`
	OldSSHKeyID      string                `json:"old_ssh_key_id"`
	NewSSHKeyID      *string               `json:"new_ssh_key_id"`
	OldFingerprint   string                `json:"old_fingerprint"`
	NewFingerprint   string                `json:"new_fingerprint"`
	Trigger          string                `json:"trigger"`
	Status           string                `json:"status"`
	PausedLicense    bool                  `json:"paused_license"`
	AwaitingDecision bool                  `json:"awaiting_decision"`
	DecisionDueAt    *time.Time            `json:"decision_due_at"`
	PlannedFor       time.Time             `json:"planned_for"`
	NotifiedAt       time.Time             `json:"notified_at"`
	StartedAt        *time.Time            `json:"started_at"`
	VerifiedAt       *time.Time            `json:"verified_at"`
	OverlapUntil     *time.Time            `json:"overlap_until"`
	FinishedAt       *time.Time            `json:"finished_at"`
	Result           *errorRefDTO          `json:"result"`
	PlanDigest       string                `json:"plan_digest"`
	NewKeyType       string                `json:"new_key_type"`
	OverlapMinutes   int                   `json:"overlap_minutes"`
	ChangeCount      int                   `json:"change_count"`
	SkipCount        int                   `json:"skip_count"`
	KeptCount        int                   `json:"kept_count"`
	ActionsAllowed   []string              `json:"actions_allowed"`
	Locations        []rotationLocationDTO `json:"locations"`
	Steps            *[]rotationStepDTO    `json:"steps,omitempty"`
	Version          int                   `json:"version"`
}

// rotationJSON renders a run; gateOK is the license gate's answer for changes (AllowedActions), withSteps adds the
// steps (always an array then).
func rotationJSON(r sshkeys.Rotation, gateOK, withSteps bool) rotationDTO {
	d := rotationDTO{
		ID: r.ID.String(), PolicyID: r.PolicyID.String(), OldSSHKeyID: r.OldKeyID.String(), NewSSHKeyID: idPtr(r.NewKeyID),
		OldFingerprint: r.OldFingerprint, NewFingerprint: r.NewFingerprint, Trigger: r.Trigger, Status: r.Status,
		PausedLicense: r.PausedLicense, AwaitingDecision: r.AwaitingDecision, DecisionDueAt: utcPtr(r.DecisionDueAt),
		PlannedFor: r.PlannedFor.UTC(), NotifiedAt: r.NotifiedAt.UTC(), StartedAt: utcPtr(r.StartedAt), VerifiedAt: utcPtr(r.VerifiedAt),
		OverlapUntil: utcPtr(r.OverlapUntil), FinishedAt: utcPtr(r.FinishedAt), Result: errorRef(r.ResultCode, nil),
		PlanDigest: r.Digest, NewKeyType: r.NewKeyType, OverlapMinutes: r.OverlapMinutes, ChangeCount: r.Plan.Changes,
		SkipCount: r.Plan.Skips, KeptCount: r.KeptCount, ActionsAllowed: nonNil(sshkeys.AllowedActions(r, gateOK)),
		Locations: make([]rotationLocationDTO, 0, len(r.Locations)), Version: r.Version,
	}
	for _, l := range r.Locations {
		d.Locations = append(d.Locations, rotationLocationDTO{
			ID: l.ID.String(), N: l.N, TargetID: l.TargetID.String(), TargetName: l.TargetName, OSUser: l.OSUser, FilePath: l.FilePath,
			Options: l.Options, State: l.State, SkipReason: l.SkipReason, VerifyNote: l.VerifyNote, Error: errorRef(l.ErrorCode, nil),
			Backup: l.Backup, VerifiedAt: utcPtr(l.VerifiedAt), ReverifiedAt: utcPtr(l.ReverifiedAt), RemovedAt: utcPtr(l.RemovedAt),
			NewLocationID: idPtr(l.NewLocationID),
		})
	}
	if withSteps {
		steps := make([]rotationStepDTO, 0, len(r.Steps))
		for _, st := range r.Steps {
			params := st.Params
			if params == nil {
				params = map[string]string{}
			}
			steps = append(steps, rotationStepDTO{N: st.N, LocationID: idPtr(st.LocationID), Name: st.Name, Status: st.Status,
				At: st.At.UTC(), Params: params})
		}
		d.Steps = &steps
	}
	return d
}
