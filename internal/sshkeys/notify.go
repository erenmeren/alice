package sshkeys

import (
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"alice/internal/sshkeys/plan"
)

// Email templates of the module (C10; texts in locales/common under email.<template>).
const (
	TemplatePreview             = "rotation.preview"
	TemplatePreviewAfterLicense = "rotation.preview_after_license"
	TemplateOverlapStarted      = "rotation.overlap_started"
	TemplateOverlapEnding       = "rotation.overlap_ending"
	TemplateCompleted           = "rotation.completed"
	TemplateCompletedPartial    = "rotation.completed_partial" // S11: the old key stays somewhere
	TemplateLateResult          = "rotation.late_result"       // a server's answer after the run gave up on it
	TemplateNothingToRotate     = "rotation.nothing_to_rotate" // a scheduled plan in which every place is skipped
	TemplateAborted             = "rotation.aborted"
	TemplateNeedsAttention      = "rotation.needs_attention"
	TemplatePausedLicense       = "rotation.paused_license"
	TemplateDecisionNeeded      = "rotation.decision_needed"
)

// Templates returns every email template of this module, in C10's order (render tests).
func Templates() []string {
	return []string{TemplatePreview, TemplatePreviewAfterLicense, TemplateOverlapStarted, TemplateOverlapEnding, TemplateCompleted,
		TemplateAborted, TemplateNeedsAttention, TemplatePausedLicense, TemplateDecisionNeeded, TemplateCompletedPartial, TemplateLateResult, TemplateNothingToRotate}
}

// mailTime is the time format of every email parameter (C10).
func mailTime(t time.Time) string { return t.UTC().Format("2006-01-02 15:04 UTC") }

// previewParams are the parameters of rotation.preview. rotationID is the run the notice announces
// (uuid.Nil for an on-demand preview): S1 counts a run's notice delivered by it.
func previewParams(key keyRow, p plan.Plan, plannedFor time.Time, rotationID uuid.UUID) map[string]string {
	m := map[string]string{"key_label": key.label, "fingerprint": key.fingerprint, "planned_for": mailTime(plannedFor),
		"change_count": strconv.Itoa(p.Changes), "skip_count": strconv.Itoa(p.Skips)}
	if rotationID != uuid.Nil {
		m["rotation_id"] = rotationID.String()
	}
	return m
}

// nothingToRotateParams are the parameters of rotation.nothing_to_rotate: key_label, fingerprint,
// skip_count, skips ("<server>: <skip reason>" per place, "; "-separated, at most 10 then "…") and
// next_run_at (the next interval's run).
func nothingToRotateParams(key keyRow, p plan.Plan, next time.Time) map[string]string {
	var skips []string
	for _, a := range p.Actions {
		if a.Skip == "" {
			continue
		}
		if len(skips) == 10 {
			skips = append(skips, "…")
			break
		}
		skips = append(skips, a.TargetName+": "+a.Skip)
	}
	return map[string]string{"key_label": key.label, "fingerprint": key.fingerprint, "skip_count": strconv.Itoa(p.Skips),
		"skips": dashIfEmpty(strings.Join(skips, "; ")), "next_run_at": mailTime(next)}
}

func dashIfEmpty(v string) string {
	if v == "" {
		return "—"
	}
	return v
}
