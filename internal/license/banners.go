package license

import (
	"strconv"
	"time"
)

// Severity is the color of a banner: info (blue), warning (yellow), caution (orange), danger (red).
type Severity string

// Banner severities.
const (
	SeverityInfo    Severity = "info"
	SeverityWarning Severity = "warning"
	SeverityCaution Severity = "caution"
	SeverityDanger  Severity = "danger"
)

// Banner is one license message for the page header. Kind selects the translated text
// (license.banner.<kind>); Params are its values (RFC 3339 times and decimal numbers).
type Banner struct {
	Kind     string
	Severity Severity
	Params   map[string]string
}

// Banners returns what a viewer sees (spec §19.3). Everyone sees the evaluation, grace, lock
// and evaluation-ended banners; only Administrators see expiry warnings (L-15), clock
// problems, damaged license data, pending licenses and the target limit.
func (s Snapshot) Banners(admin bool) []Banner {
	e := s.Eval
	ts := func(t time.Time) string { return t.UTC().Format(time.RFC3339) }
	itoa := strconv.Itoa
	var out []Banner
	switch e.Phase {
	case PhaseEvaluation:
		sev := SeverityInfo
		if admin && e.Threshold > 0 {
			sev = SeverityWarning
			if e.Threshold <= 3 {
				sev = SeverityCaution
			}
		}
		out = append(out, Banner{Kind: "evaluation", Severity: sev, Params: map[string]string{
			"days_left": itoa(e.DaysLeft), "max_targets": itoa(e.MaxTargets), "ends_at": ts(e.EndsAt)}})
	case PhaseEvaluationExpired:
		out = append(out, Banner{Kind: "evaluation_ended", Severity: SeverityDanger, Params: map[string]string{"ended_at": ts(e.EndsAt)}})
	case PhaseActive:
		if admin && e.Threshold > 0 {
			sev := SeverityWarning
			if e.Threshold <= 7 {
				sev = SeverityCaution // at 7 and 1 days the banner turns orange (§19.3)
			}
			out = append(out, Banner{Kind: "expiry_warning", Severity: sev, Params: map[string]string{
				"days_left": itoa(e.DaysLeft), "valid_until": ts(e.EndsAt)}})
		}
	case PhaseGrace:
		out = append(out, Banner{Kind: "grace", Severity: SeverityDanger, Params: map[string]string{
			"valid_until": ts(e.EndsAt), "locks_at": ts(e.LocksAt), "grace_day": itoa(e.GraceDay)}})
	case PhaseLocked:
		out = append(out, Banner{Kind: "locked", Severity: SeverityDanger, Params: map[string]string{"valid_until": ts(e.EndsAt)}})
	}
	if !admin {
		return out
	}
	if s.Tampered {
		out = append(out, Banner{Kind: "tampered", Severity: SeverityDanger, Params: map[string]string{}})
	}
	if s.Reading.Behind {
		out = append(out, Banner{Kind: "clock_behind", Severity: SeverityCaution, Params: map[string]string{
			"system_time": ts(s.Reading.Wall), "last_seen": ts(s.Reading.Trusted)}})
	}
	if s.Reading.Jump != nil {
		out = append(out, Banner{Kind: "clock_jump", Severity: SeverityCaution, Params: map[string]string{
			"jump_days": itoa(int(s.Reading.Jump.By / day)), "system_time": ts(s.Reading.Wall)}})
	}
	if e.Pending != nil {
		out = append(out, Banner{Kind: "pending", Severity: SeverityInfo, Params: map[string]string{
			"valid_from": ts(e.Pending.ValidFrom), "license_id": e.Pending.LicenseID}})
	}
	switch {
	case e.OverLimit(s.Targets):
		out = append(out, Banner{Kind: "over_limit", Severity: SeverityWarning, Params: map[string]string{
			"used": itoa(s.Targets), "max": itoa(e.MaxTargets)}})
	case !e.Locked() && s.Targets > 0 && s.Targets == e.MaxTargets:
		out = append(out, Banner{Kind: "limit_reached", Severity: SeverityInfo, Params: map[string]string{"max": itoa(e.MaxTargets)}})
	}
	return out
}
