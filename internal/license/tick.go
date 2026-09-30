package license

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"

	"alice/internal/audit"
	"alice/internal/platform/db"
)

// Email templates sent to Administrators (rendered by notify from email.<template>.* in
// locales/common).
const (
	TemplateExpiryWarning     = "license.expiry_warning"
	TemplateEvaluationWarning = "license.evaluation_warning"
	TemplateEvaluationEnded   = "license.evaluation_ended"
	TemplateGrace             = "license.grace"
	TemplateLocked            = "license.locked"
	TemplateClockJump         = "license.clock_jump"
)

// Templates lists every email template of the license module.
func Templates() []string {
	return []string{TemplateExpiryWarning, TemplateEvaluationWarning, TemplateEvaluationEnded,
		TemplateGrace, TemplateLocked, TemplateClockJump}
}

// mailTime is how times appear in emails: unambiguous and language-neutral.
func mailTime(t time.Time) string { return t.UTC().Format("2006-01-02 15:04 UTC") }

// Tick observes the clock, re-verifies the stored files and recomputes the state. In one
// transaction that first takes the license row lock it then records a phase change, sends
// every due notice once, records clock events and damaged files, saves the time record and
// finally writes the audit rows. The guard and the snapshot are published only after the
// commit, so a failed Tick changes nothing and the next one repeats its work.
// It runs at start, hourly (job license.evaluate), after each upload and after the e2e
// demo clock moves.
func (s *Service) Tick(ctx context.Context) error {
	s.evalMu.Lock()
	defer s.evalMu.Unlock()
	g := s.working()
	var snap Snapshot
	err := db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := loadInstallation(ctx, tx, true); err != nil {
			return err
		}
		reading, clockEvents := g.Observe(s.clock.Now(), s.uptime.Elapsed())
		c, err := s.compute(ctx, tx, reading, false)
		if err != nil {
			return err
		}
		now := s.clock.Now().UTC()
		var audits []audit.Event
		for _, step := range []func() ([]audit.Event, error){
			func() ([]audit.Event, error) { return s.recordTransition(ctx, tx, c, now) },
			func() ([]audit.Event, error) { return s.sendNotices(ctx, tx, c, now) },
			func() ([]audit.Event, error) { return s.recordClockEvents(ctx, tx, c, reading, clockEvents, now) },
			func() ([]audit.Event, error) { return s.recordTampered(ctx, tx, c, now) },
		} {
			evs, err := step()
			if err != nil {
				return err
			}
			audits = append(audits, evs...)
		}
		if err := s.persistHWM(ctx, tx, &g); err != nil {
			return err
		}
		for _, ev := range audits {
			if _, err := s.audit.Append(ctx, tx, ev); err != nil {
				return err
			}
		}
		snap = c.snap
		return nil
	})
	if err != nil {
		return err
	}
	s.publish(g, snap)
	return nil
}

// recordTransition stores a phase change once: the cached state column, a history row and
// an audit event (license.expired when grace begins, L-20; license.locked, L-24).
func (s *Service) recordTransition(ctx context.Context, tx pgx.Tx, c computed, now time.Time) ([]audit.Event, error) {
	from, to := c.row.State, c.snap.Eval.Phase
	if from == to {
		return nil, nil
	}
	if _, err := tx.Exec(ctx, "UPDATE license SET state = $1, updated_at = $2 WHERE id = 1", string(to), now); err != nil {
		return nil, fmt.Errorf("update the license state: %w", err)
	}
	key := c.snap.Eval.Key()
	details := map[string]string{"from_state": string(from), "to_state": string(to), "license_id": key}
	if _, err := insertHistory(ctx, tx, now, "state_change", key, string(from), string(to), "", details); err != nil {
		return nil, err
	}
	action := "license.state_changed"
	switch to {
	case PhaseGrace:
		action = "license.expired"
	case PhaseLocked:
		action = "license.locked"
	case PhaseEvaluationExpired:
		action = "license.evaluation_ended"
	}
	return []audit.Event{{Actor: systemActor, Action: action, ObjectType: "license",
		ObjectID: key, Result: audit.Success, Details: details}}, nil
}

type notice struct {
	key      string
	template string
	params   map[string]string
}

// dueNotice returns the notice of the current state, if any. Only the current threshold is
// due, so after downtime no burst of older warnings is sent (L-16).
func dueNotice(snap Snapshot) (notice, bool) {
	e := snap.Eval
	params := map[string]string{
		"installation_id": snap.InstallationID,
		"days_left":       strconv.Itoa(e.DaysLeft),
		"ends_at":         mailTime(e.EndsAt),
		"locks_at":        mailTime(e.LocksAt),
	}
	if e.Current != nil {
		params["customer"], params["license_id"] = e.Current.Customer, e.Current.LicenseID
	}
	switch {
	case e.Phase == PhaseEvaluation && e.Threshold > 0:
		return notice{"evaluation:" + strconv.Itoa(e.Threshold), TemplateEvaluationWarning, params}, true
	case e.Phase == PhaseEvaluationExpired:
		return notice{"evaluation_ended", TemplateEvaluationEnded, params}, true
	case e.Phase == PhaseActive && e.Threshold > 0:
		return notice{"expiry:" + strconv.Itoa(e.Threshold), TemplateExpiryWarning, params}, true
	case e.Phase == PhaseGrace:
		params["grace_day"] = strconv.Itoa(e.GraceDay)
		return notice{"grace:" + strconv.Itoa(e.GraceDay), TemplateGrace, params}, true // a daily email (§19.3)
	case e.Phase == PhaseLocked:
		return notice{"locked", TemplateLocked, params}, true
	}
	return notice{}, false
}

// sendNotices sends the due notice once per license: the unique history index decides, so
// hourly ticks, restarts and two processes never send it twice (L-12, L-14).
func (s *Service) sendNotices(ctx context.Context, tx pgx.Tx, c computed, now time.Time) ([]audit.Event, error) {
	n, ok := dueNotice(c.snap)
	if !ok {
		return nil, nil
	}
	key := c.snap.Eval.Key()
	inserted, err := insertHistory(ctx, tx, now, "notice", key, "", "", n.key, map[string]string{"template": n.template})
	if err != nil || !inserted {
		return nil, err
	}
	if s.notifier != nil {
		if err := s.notifier.NotifyAdmins(ctx, tx, n.template, n.params); err != nil {
			return nil, fmt.Errorf("queue license email: %w", err)
		}
	}
	return []audit.Event{{Actor: systemActor, Action: "license.warning.sent", ObjectType: "license",
		ObjectID: key, Result: audit.Success, Details: map[string]string{"notice": n.key, "template": n.template}}}, nil
}

// recordClockEvents records what the guard noticed: a clock set back (once per day of the
// system clock, L-51), a forward jump (history, audit, email, persisted hold; L-59), and
// the end of a hold (accepted after 24 h, or the clock was corrected).
func (s *Service) recordClockEvents(ctx context.Context, tx pgx.Tx, c computed, r Reading, events []ClockEvent, now time.Time) ([]audit.Event, error) {
	var out []audit.Event
	for _, ev := range events {
		switch ev {
		case EventRollback:
			d := map[string]string{"system_time": r.Wall.Format(time.RFC3339), "last_seen": r.Trusted.Format(time.RFC3339)}
			inserted, err := insertHistory(ctx, tx, now, "notice", "", "", "", "clock_behind:"+r.Wall.Format("2006-01-02"), d)
			if err != nil {
				return nil, err
			}
			if inserted {
				out = append(out, audit.Event{Actor: systemActor, Action: "clock.rollback_detected",
					ObjectType: "license", Result: audit.Failure, Details: d})
			}
		case EventJumpDetected:
			if r.Jump == nil {
				continue
			}
			raw, err := json.Marshal(jumpRecord{Expected: r.Jump.Expected, Detected: r.Jump.Detected})
			if err != nil {
				return nil, err
			}
			if _, err := tx.Exec(ctx, "UPDATE license SET clock_jump = $1, updated_at = $2 WHERE id = 1", raw, now); err != nil {
				return nil, fmt.Errorf("store the clock jump: %w", err)
			}
			d := map[string]string{"problem": "forward_jump", "jump_days": strconv.Itoa(int(r.Jump.By / day)),
				"system_time": r.Wall.Format(time.RFC3339)}
			if _, err := insertHistory(ctx, tx, now, "clock_anomaly", "", "", "", "", d); err != nil {
				return nil, err
			}
			if s.notifier != nil {
				params := map[string]string{"installation_id": c.snap.InstallationID, "jump_days": d["jump_days"], "system_time": mailTime(r.Wall)}
				if err := s.notifier.NotifyAdmins(ctx, tx, TemplateClockJump, params); err != nil {
					return nil, fmt.Errorf("queue clock email: %w", err)
				}
			}
			out = append(out, audit.Event{Actor: systemActor, Action: "clock.forward_jump",
				ObjectType: "license", Result: audit.Failure, Details: d})
		case EventJumpAccepted, EventJumpCleared:
			problem, action := "jump_accepted", "clock.jump_accepted"
			if ev == EventJumpCleared {
				problem, action = "jump_cleared", "clock.jump_cleared"
			}
			if _, err := tx.Exec(ctx, "UPDATE license SET clock_jump = NULL, updated_at = $1 WHERE id = 1", now); err != nil {
				return nil, fmt.Errorf("clear the clock jump: %w", err)
			}
			d := map[string]string{"problem": problem, "system_time": r.Wall.Format(time.RFC3339)}
			if _, err := insertHistory(ctx, tx, now, "clock_anomaly", "", "", "", "", d); err != nil {
				return nil, err
			}
			out = append(out, audit.Event{Actor: systemActor, Action: action,
				ObjectType: "license", Result: audit.Success, Details: d})
		}
	}
	return out, nil
}

// recordTampered records each stored file whose content no longer verifies, once (L-49).
// The details name the file and the reason, never its content.
func (s *Service) recordTampered(ctx context.Context, tx pgx.Tx, c computed, now time.Time) ([]audit.Event, error) {
	var out []audit.Event
	for _, df := range c.damaged {
		id := df.file.ID.String()
		d := map[string]string{"file_id": id, "seq": strconv.FormatInt(df.file.Seq, 10), "reason": RejectReason(df.err)}
		inserted, err := insertHistory(ctx, tx, now, "notice", "", "", "", "tampered:"+id, d)
		if err != nil {
			return nil, err
		}
		if inserted {
			out = append(out, audit.Event{Actor: systemActor, Action: "license.tampered",
				ObjectType: "license", ObjectID: id, Result: audit.Failure, Details: d})
		}
	}
	return out, nil
}
