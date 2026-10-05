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

// locationCountsDTO counts a run's places by what happened to them (the list shows counts, not places).
type locationCountsDTO struct {
	Total    int `json:"total"`
	Verified int `json:"verified"`
	Removed  int `json:"removed"`
	Skipped  int `json:"skipped"`
	Kept     int `json:"kept"`
	Failed   int `json:"failed"` // add, verify, removal or undo failed
}

// locationCounts counts a run's places in the service's buckets (sshkeys.LocationCounts): verified includes the places
// whose old key is being or was removed; kept is kept_old plus a place cancelled at send time with a reason.
func locationCounts(locs []sshkeys.RotationLocation) locationCountsDTO {
	c := locationCountsDTO{Total: len(locs)}
	for _, l := range locs {
		switch l.State {
		case sshkeys.LocVerified, sshkeys.LocRemoving:
			c.Verified++
		case sshkeys.LocRemoved:
			c.Verified++
			c.Removed++
		case sshkeys.LocSkipped:
			c.Skipped++
		case sshkeys.LocKeptOld:
			c.Kept++
		case sshkeys.LocCancelled:
			if l.ErrorCode != "" {
				c.Kept++
			}
		case sshkeys.LocAddFailed, sshkeys.LocVerifyFailed, sshkeys.LocRemoveFailed, sshkeys.LocUndoFailed:
			c.Failed++
		}
	}
	return c
}

func summaryCounts(c sshkeys.LocationCounts) locationCountsDTO {
	return locationCountsDTO{Total: c.Total, Verified: c.Verified, Removed: c.Removed, Skipped: c.Skipped, Kept: c.Kept, Failed: c.Failed}
}

// rotationSummaryDTO is a run in the list: its scalar fields and the counts of its places (sshkeys.RotationSummary);
// no plan, places, steps or decisions (those are on GET /rotation/runs/{id}).
type rotationSummaryDTO struct {
	ID               string            `json:"id"`
	PolicyID         string            `json:"policy_id"`
	OldSSHKeyID      string            `json:"old_ssh_key_id"`
	NewSSHKeyID      *string           `json:"new_ssh_key_id"`
	OldFingerprint   string            `json:"old_fingerprint"`
	NewFingerprint   string            `json:"new_fingerprint"`
	Trigger          string            `json:"trigger"`
	Status           string            `json:"status"`
	PausedLicense    bool              `json:"paused_license"`
	AwaitingDecision bool              `json:"awaiting_decision"`
	NewKeyType       string            `json:"new_key_type"`
	PlannedFor       time.Time         `json:"planned_for"`
	NotifiedAt       time.Time         `json:"notified_at"`
	StartedAt        *time.Time        `json:"started_at"`
	VerifiedAt       *time.Time        `json:"verified_at"`
	OverlapUntil     *time.Time        `json:"overlap_until"`
	FinishedAt       *time.Time        `json:"finished_at"`
	Result           *errorRefDTO      `json:"result"`
	KeptCount        int               `json:"kept_count"`
	LocationCounts   locationCountsDTO `json:"location_counts"`
	Version          int               `json:"version"`
}

func rotationSummaryJSON(r sshkeys.RotationSummary) rotationSummaryDTO {
	return rotationSummaryDTO{
		ID: r.ID.String(), PolicyID: r.PolicyID.String(), OldSSHKeyID: r.OldKeyID.String(), NewSSHKeyID: idPtr(r.NewKeyID),
		OldFingerprint: r.OldFingerprint, NewFingerprint: r.NewFingerprint, Trigger: r.Trigger, Status: r.Status,
		PausedLicense: r.PausedLicense, AwaitingDecision: r.AwaitingDecision, NewKeyType: r.NewKeyType, PlannedFor: r.PlannedFor.UTC(),
		NotifiedAt: r.NotifiedAt.UTC(), StartedAt: utcPtr(r.StartedAt), VerifiedAt: utcPtr(r.VerifiedAt), OverlapUntil: utcPtr(r.OverlapUntil),
		FinishedAt: utcPtr(r.FinishedAt), Result: errorRef(r.ResultCode, nil), KeptCount: r.KeptCount,
		LocationCounts: summaryCounts(r.Counts), Version: r.Version,
	}
}

// rotationDTO is one run as GET /rotation/runs/{id} answers it (C13 with F4 and S11): result is the run's result reason
// as an errorRef (null while it has none); kept_count is where the old key stays; actions_allowed are the decisions
// this caller may take now; notice_state / notice_error say why Continue waits (S6). The list has rotationSummaryDTO.
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
	NoticeState      *errorRefDTO          `json:"notice_state"`
	NoticeError      *errorRefDTO          `json:"notice_error"`
	LocationCounts   locationCountsDTO     `json:"location_counts"`
	Locations        []rotationLocationDTO `json:"locations"`
	Steps            []rotationStepDTO     `json:"steps"`
	Version          int                   `json:"version"`
}

// rotationJSON renders one run with its places and steps; actions are the decisions this caller may take now
// (callerActions); notice_state shows only while the license allows changes (otherwise Continue waits for the license).
func rotationJSON(r sshkeys.Rotation, gateOK bool, actions []string) rotationDTO {
	d := rotationDTO{
		ID: r.ID.String(), PolicyID: r.PolicyID.String(), OldSSHKeyID: r.OldKeyID.String(), NewSSHKeyID: idPtr(r.NewKeyID),
		OldFingerprint: r.OldFingerprint, NewFingerprint: r.NewFingerprint, Trigger: r.Trigger, Status: r.Status,
		PausedLicense: r.PausedLicense, AwaitingDecision: r.AwaitingDecision, DecisionDueAt: utcPtr(r.DecisionDueAt),
		PlannedFor: r.PlannedFor.UTC(), NotifiedAt: r.NotifiedAt.UTC(), StartedAt: utcPtr(r.StartedAt), VerifiedAt: utcPtr(r.VerifiedAt),
		OverlapUntil: utcPtr(r.OverlapUntil), FinishedAt: utcPtr(r.FinishedAt), Result: errorRef(r.ResultCode, nil),
		PlanDigest: r.Digest, NewKeyType: r.NewKeyType, OverlapMinutes: r.OverlapMinutes, ChangeCount: r.Plan.Changes,
		SkipCount: r.Plan.Skips, KeptCount: r.KeptCount, ActionsAllowed: nonNil(actions), NoticeError: errorRef(r.NoticeError, nil),
		LocationCounts: locationCounts(r.Locations), Version: r.Version,
	}
	if gateOK {
		d.NoticeState = errorRef(r.NoticeState, nil)
	}
	locs := make([]rotationLocationDTO, 0, len(r.Locations))
	for _, l := range r.Locations {
		locs = append(locs, rotationLocationDTO{
			ID: l.ID.String(), N: l.N, TargetID: l.TargetID.String(), TargetName: l.TargetName, OSUser: l.OSUser, FilePath: l.FilePath,
			Options: l.Options, State: l.State, SkipReason: l.SkipReason, VerifyNote: l.VerifyNote, Error: errorRef(l.ErrorCode, nil),
			Backup: l.Backup, VerifiedAt: utcPtr(l.VerifiedAt), ReverifiedAt: utcPtr(l.ReverifiedAt), RemovedAt: utcPtr(l.RemovedAt),
			NewLocationID: idPtr(l.NewLocationID),
		})
	}
	d.Locations = locs
	{ // the steps
		steps := make([]rotationStepDTO, 0, len(r.Steps))
		for _, st := range r.Steps {
			params := st.Params
			if params == nil {
				params = map[string]string{}
			}
			steps = append(steps, rotationStepDTO{N: st.N, LocationID: idPtr(st.LocationID), Name: st.Name, Status: st.Status,
				At: st.At.UTC(), Params: params})
		}
		d.Steps = steps
	}
	return d
}
