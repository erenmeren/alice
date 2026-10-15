package notify

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Preview is what a notify run at the same instant would do, as counts.
type Preview struct {
	// Resolved is the number of waiting messages that would get the owner address.
	Resolved int
	// Reminders is the number of reminders that would be created.
	Reminders int
	// Summary reports whether a weekly summary is due.
	Summary bool
	// Due is the number of messages already in the outbox that would be sent (or tried), counting
	// the ones Resolved would fill; the new reminders and the summary come on top.
	Due int
	// Waiting is the number of messages that would still have no recipient.
	Waiting int
}

// PreviewRun runs the selection queries of ResolveEmptyRecipients, CreateReminders, WeeklySummary
// and SendPending without changing anything. It uses a READ ONLY transaction that is rolled back,
// so the database itself refuses any write, should one ever slip in. The counts are what a run at
// now would see, not a promise: a concurrent run or a change in between can make them differ.
func PreviewRun(ctx context.Context, pool *pgxpool.Pool, now time.Time) (Preview, error) {
	var p Preview
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
	if err != nil {
		return p, fmt.Errorf("notify: preview: begin: %w", err)
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()

	settings, err := readSettings(ctx, tx)
	if err != nil {
		return p, err
	}
	haveOwner := settings["owner_email"] != ""
	var waiting, waitingDue, due int
	if err := tx.QueryRow(ctx, `SELECT
			count(*) FILTER (WHERE cardinality(to_addrs) = 0),
			count(*) FILTER (WHERE cardinality(to_addrs) = 0 AND next_attempt_at <= $1),
			count(*) FILTER (WHERE cardinality(to_addrs) > 0 AND next_attempt_at <= $1)
		FROM mail_outbox WHERE sent_at IS NULL AND failed_at IS NULL`, now).Scan(&waiting, &waitingDue, &due); err != nil {
		return p, fmt.Errorf("notify: preview: count outbox: %w", err)
	}
	p.Due, p.Waiting = due, waiting
	if haveOwner {
		p.Resolved, p.Due, p.Waiting = waiting, due+waitingDue, 0
	}

	cands, err := reminderCandidates(ctx, tx, now)
	if err != nil {
		return p, err
	}
	p.Reminders = len(cands)

	last, haveLast := parseLastSummary(settings["last_summary_at"])
	p.Summary = !haveLast || !last.After(now.Add(-summaryEvery))
	return p, nil
}
