// Package notify fills and drains the vendor console mail outbox (mail_outbox). Messages are
// written by the database (the issuance trigger) or by the notify run (reminders, the weekly
// summary) and sent later over a mail.Sender, so a mail server that is down never blocks issuing.
// The package never sees SMTP credentials: those live inside the mail.Sender.
package notify

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"alice/internal/vconsole/audit"
	"alice/internal/vconsole/mail"
)

const (
	// MaxAttempts is the number of failed sends after which a message is marked failed and
	// left for the owner to see in the summary, instead of being retried forever.
	MaxAttempts = 10
	// maxBackoff caps the retry delay so a message still goes out within hours of the mail
	// server coming back.
	maxBackoff = 6 * time.Hour
	// sendTimeout bounds one message, above the sender's own 10 s dial and 30 s message limits,
	// so a hung server cannot hold a row lock (and the run) indefinitely.
	sendTimeout = 45 * time.Second
	// maxErrorRunes keeps last_error short enough to show in a list; SMTP replies that matter
	// fit easily.
	maxErrorRunes = 300
	// markTimeout bounds recording the outcome of a send, which runs even after a cancel.
	markTimeout = 5 * time.Second
)

// SendResult counts what one SendPending call did. Waiting is the number of unsent messages that
// still have no recipient (no owner address configured yet).
type SendResult struct{ Sent, Retry, Failed, Waiting int }

// Enqueue inserts a message (used by reminders and the summary) and returns its id. The table's
// checks refuse line breaks in subject and addresses, so a bad value fails here, not at send time.
func Enqueue(ctx context.Context, q audit.Q, kind string, to []string, subject, body string) (int64, error) {
	if to == nil {
		to = []string{} // to_addrs is NOT NULL; an empty list means "wait for the owner address"
	}
	var id int64
	if err := q.QueryRow(ctx,
		`INSERT INTO mail_outbox (kind, to_addrs, subject, body) VALUES ($1, $2, $3, $4) RETURNING id`,
		kind, to, subject, body).Scan(&id); err != nil {
		return 0, fmt.Errorf("notify: enqueue %s: %w", kind, err)
	}
	return id, nil
}

// ResolveEmptyRecipients fills empty to_addrs of unsent messages from the owner_email setting and
// returns how many messages it changed. Call it at the start of every run: a license issued before
// the owner address was configured is then reported as soon as it is.
func ResolveEmptyRecipients(ctx context.Context, q audit.Q) (int64, error) {
	tag, err := q.Exec(ctx, `UPDATE mail_outbox SET to_addrs = ARRAY[s.value]
		FROM vendor_settings s
		WHERE s.key = 'owner_email' AND s.value <> ''
		  AND cardinality(mail_outbox.to_addrs) = 0
		  AND mail_outbox.sent_at IS NULL AND mail_outbox.failed_at IS NULL`)
	if err != nil {
		return 0, fmt.Errorf("notify: resolve recipients: %w", err)
	}
	return tag.RowsAffected(), nil
}

// SendPending sends every message due at now. from goes into mail.Message.From; empty means the
// sender's configured From address.
//
// Each message is claimed in its own transaction with SELECT ... FOR UPDATE SKIP LOCKED and marked
// in that same transaction after the send, so the row lock is held during the SMTP exchange (at
// most 45 s). That is what makes two concurrent runs send each message once: the second run skips
// the locked row, and once the first commits the row is no longer due. Delivery is at-least-once,
// not exactly-once: if the process dies or the database connection drops after the server accepted
// the message but before the commit, the row is still pending and the next run sends it again.
//
// Rows with an empty recipient list are counted as Waiting and left untouched. A send error
// records attempts+1, last_error (the first 300 characters; the SMTP password never reaches this
// package, so it cannot be in it) and next_attempt_at = now + min(2^attempts minutes, 6 hours);
// the MaxAttempts-th failure sets failed_at instead. A message the sender refuses locally
// (mail.ErrInvalidMessage: a malformed address or header) is marked failed at once, since no retry
// can fix it. One failing message does not stop the others.
// A database error or a cancelled ctx stops the run; the result counts what was done until then.
func SendPending(ctx context.Context, pool *pgxpool.Pool, s mail.Sender, from string, now time.Time) (SendResult, error) {
	var res SendResult
	for {
		if err := ctx.Err(); err != nil {
			return res, fmt.Errorf("notify: send pending: %w", err)
		}
		o, err := sendOne(ctx, pool, s, from, now)
		if err != nil {
			return res, err
		}
		switch o {
		case outcomeNone:
			n, err := countWaiting(ctx, pool)
			res.Waiting = n
			return res, err
		case outcomeSent:
			res.Sent++
		case outcomeRetry:
			res.Retry++
		case outcomeFailed:
			res.Failed++
		}
	}
}

type outcome int

const (
	outcomeNone outcome = iota // nothing due
	outcomeSent
	outcomeRetry
	outcomeFailed
)

// sendOne claims, sends and marks the lowest-id due message.
func sendOne(ctx context.Context, pool *pgxpool.Pool, s mail.Sender, from string, now time.Time) (outcome, error) {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return outcomeNone, fmt.Errorf("notify: begin: %w", err)
	}
	// After a commit this is a no-op; otherwise it releases the row lock even if ctx is cancelled.
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()

	var (
		id       int64
		attempts int
		m        = mail.Message{From: from}
	)
	err = tx.QueryRow(ctx, `SELECT id, to_addrs, subject, body, attempts FROM mail_outbox
		WHERE sent_at IS NULL AND failed_at IS NULL AND next_attempt_at <= $1 AND cardinality(to_addrs) > 0
		ORDER BY id LIMIT 1 FOR UPDATE SKIP LOCKED`, now).Scan(&id, &m.To, &m.Subject, &m.Body, &attempts)
	if errors.Is(err, pgx.ErrNoRows) {
		return outcomeNone, nil
	}
	if err != nil {
		return outcomeNone, fmt.Errorf("notify: claim message: %w", err)
	}

	sctx, cancel := context.WithTimeout(ctx, sendTimeout)
	sendErr := s.Send(sctx, m, now)
	cancel()

	// The send is the point of no return: once the server accepted the message, the mark and the
	// commit must happen even if the run is cancelled now (a SIGTERM right after the 250 reply),
	// otherwise the row stays pending and the next run sends the mail again. So they use a context
	// that ignores the run's cancellation but is still bounded.
	mctx, mcancel := context.WithTimeout(context.WithoutCancel(ctx), markTimeout)
	defer mcancel()
	o := outcomeSent
	switch {
	case sendErr == nil:
		_, err = tx.Exec(mctx, `UPDATE mail_outbox SET sent_at = $2 WHERE id = $1`, id, now)
	case errors.Is(sendErr, mail.ErrInvalidMessage):
		// Checked before ctx: the message was refused locally, a cancel cannot have caused it, and
		// no retry can fix a malformed address or header.
		o = outcomeFailed
		_, err = tx.Exec(mctx, `UPDATE mail_outbox SET attempts = attempts + 1, last_error = $2, failed_at = $3 WHERE id = $1`,
			id, truncateError(sendErr.Error()), now)
	case ctx.Err() != nil:
		// The run was cancelled, not the message: leave the row as it was.
		return outcomeNone, fmt.Errorf("notify: send message %d: %w", id, ctx.Err())
	default:
		attempts++
		msg := truncateError(sendErr.Error())
		if attempts >= MaxAttempts {
			o = outcomeFailed
			_, err = tx.Exec(mctx, `UPDATE mail_outbox SET attempts = $2, last_error = $3, failed_at = $4 WHERE id = $1`,
				id, attempts, msg, now)
		} else {
			o = outcomeRetry
			_, err = tx.Exec(mctx, `UPDATE mail_outbox SET attempts = $2, last_error = $3, next_attempt_at = $4 WHERE id = $1`,
				id, attempts, msg, now.Add(backoff(attempts)))
		}
	}
	if err != nil {
		return outcomeNone, fmt.Errorf("notify: mark message %d: %w", id, err)
	}
	if err := tx.Commit(mctx); err != nil {
		return outcomeNone, fmt.Errorf("notify: commit message %d: %w", id, err)
	}
	return o, nil
}

func countWaiting(ctx context.Context, q audit.Q) (int, error) {
	var n int
	if err := q.QueryRow(ctx, `SELECT count(*) FROM mail_outbox
		WHERE sent_at IS NULL AND failed_at IS NULL AND cardinality(to_addrs) = 0`).Scan(&n); err != nil {
		return 0, fmt.Errorf("notify: count waiting: %w", err)
	}
	return n, nil
}

// backoff is min(2^attempts minutes, 6 hours): 2 min after the first failure, then 4, 8, ...
func backoff(attempts int) time.Duration {
	if attempts >= 9 { // 2^9 min = 512 min, already past the cap; also avoids shift overflow
		return maxBackoff
	}
	return min(time.Duration(1<<attempts)*time.Minute, maxBackoff)
}

// truncateError keeps the first maxErrorRunes runes, made valid UTF-8 without NUL bytes, because
// PostgreSQL text rejects both and a server reply may contain either.
func truncateError(s string) string {
	s = strings.ReplaceAll(strings.ToValidUTF8(s, "�"), "\x00", "")
	if utf8.RuneCountInString(s) > maxErrorRunes {
		s = string([]rune(s)[:maxErrorRunes])
	}
	return s
}
