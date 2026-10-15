package notify

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Preview is what a notify run at the same instant would create.
type Preview struct {
	// Reminders is the number of reminders that would be created.
	Reminders int
	// Summary reports whether a weekly summary is due.
	Summary bool
	// Notices are the notifications that would be created, in the order the run creates them:
	// the reminder notices, then the summary and its unusual-activity alert. A notice whose dedupe
	// key already exists would be skipped by the run and is still listed here.
	Notices []Notice
}

// PreviewRun runs the selection and composition of CreateReminders and WeeklySummary without
// changing anything. It uses a READ ONLY transaction that is rolled back, so the database itself
// refuses any write, should one ever slip in. The result is what a run at now would see, not a
// promise: a concurrent run or a change in between can make it differ.
func PreviewRun(ctx context.Context, pool *pgxpool.Pool, now time.Time) (Preview, error) {
	var p Preview
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
	if err != nil {
		return p, fmt.Errorf("notify: preview: begin: %w", err)
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()

	cands, err := reminderCandidates(ctx, tx, now)
	if err != nil {
		return p, err
	}
	p.Reminders = len(cands)
	for _, c := range cands {
		for _, n := range reminderNotices(c, threshold(c.validUntil, now), now) {
			if n, err = checkNotice(n); err != nil {
				return p, err
			}
			p.Notices = append(p.Notices, n)
		}
	}

	settings, err := readSettings(ctx, tx)
	if err != nil {
		return p, err
	}
	due, ns, err := composeSummary(ctx, tx, settings, now)
	if err != nil {
		return p, err
	}
	p.Summary = due
	for _, n := range ns {
		if n, err = checkNotice(n); err != nil {
			return p, err
		}
		p.Notices = append(p.Notices, n)
	}
	return p, nil
}
