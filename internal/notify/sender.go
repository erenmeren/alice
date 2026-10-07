package notify

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"alice/internal/i18n"
	"alice/internal/platform/clock"
	"alice/internal/platform/db"
)

// Message is one email.
type Message struct {
	To      string
	Subject string
	Body    string
}

// Mailer delivers a message.
type Mailer interface {
	Send(ctx context.Context, m Message) error
}

// Retry policy (F-60, R42 row 7): 30 s, doubling up to 1 hour, until 24 hours after the message was queued; then the
// message is failed. Each attempt is one send to one recipient (F-61).
const (
	GiveUpAfter  = 24 * time.Hour
	FailingAfter = 3
	baseBackoff  = 30 * time.Second
	maxBackoff   = time.Hour
	sendTimeout  = 60 * time.Second
)

// Sender drains the outbox.
type Sender struct {
	Pool   *pgxpool.Pool
	Mailer Mailer // nil = SMTP is not configured: emails are recorded as skipped_no_smtp (L-18)
	// Source, when set, is asked for the mailer of the current mail settings at every Drain and is preferred over
	// Mailer (Phase 7).
	Source  MailerSource
	Catalog *i18n.Catalog
	Clock   clock.Clock
	Log     *slog.Logger
}

// Drain handles every due email (sent, skipped, retried or given up) and returns how many.
// Rows are claimed with FOR UPDATE SKIP LOCKED, so parallel drains never send twice.
func (s *Sender) Drain(ctx context.Context) (int, error) {
	mailer := s.Mailer
	if s.Source != nil {
		m, release, err := s.Source.Mailer(ctx)
		if err != nil {
			return 0, err // nothing was claimed, so nothing is marked
		}
		defer release()
		mailer = m
	}
	n := 0
	for {
		handled, err := s.one(ctx, mailer)
		if err != nil {
			return n, err
		}
		if !handled {
			return n, nil
		}
		n++
	}
}

func (s *Sender) one(ctx context.Context, mailer Mailer) (bool, error) {
	handled := false
	err := db.InTx(ctx, s.Pool, func(tx pgx.Tx) error {
		now := s.Clock.Now().UTC()
		var (
			id              uuid.UUID
			to, tpl, locale string
			raw             []byte
			attempts        int
			createdAt       time.Time
		)
		err := tx.QueryRow(ctx, `SELECT id, to_address, template_key, params, locale, attempts, created_at FROM notifications_outbox
WHERE status = 'pending' AND next_attempt_at <= $1 ORDER BY next_attempt_at, id LIMIT 1 FOR UPDATE SKIP LOCKED`, now).
			Scan(&id, &to, &tpl, &raw, &locale, &attempts, &createdAt)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("notify: read the outbox: %w", err)
		}
		handled = true
		if mailer == nil {
			_, err := tx.Exec(ctx, `UPDATE notifications_outbox SET status = 'skipped_no_smtp', last_error_code = 'smtp.not_configured'
WHERE id = $1`, id)
			return err
		}
		var params map[string]string
		if err := json.Unmarshal(raw, &params); err != nil {
			_, err := tx.Exec(ctx, `UPDATE notifications_outbox SET status = 'failed', last_error_code = 'template.params' WHERE id = $1`, id)
			return err
		}
		sendCtx, cancel := context.WithTimeout(ctx, sendTimeout)
		sendErr := mailer.Send(sendCtx, s.Render(to, tpl, locale, params))
		cancel()
		attempts++
		if sendErr == nil {
			if _, err := tx.Exec(ctx, `UPDATE notifications_outbox SET status = 'sent', sent_at = $2, attempts = $3, last_error_code = ''
WHERE id = $1`, id, now, attempts); err != nil {
				return err
			}
			return recordDelivery(ctx, tx, true, "", now)
		}
		code := ErrorCode(sendErr)
		status := "pending"
		if now.Sub(createdAt) >= GiveUpAfter {
			status = "failed"
			s.log().Error("email not sent after "+strconv.Itoa(attempts)+" attempts; giving up",
				"outbox_id", id.String(), "attempt", attempts, "reason", code)
		} else {
			s.log().Warn("email not sent; it will be retried", "outbox_id", id.String(), "attempt", attempts, "reason", code)
		}
		if _, err = tx.Exec(ctx, `UPDATE notifications_outbox SET status = $2, attempts = $3, next_attempt_at = $4, last_error_code = $5
WHERE id = $1`, id, status, attempts, now.Add(backoff(attempts)), code); err != nil {
			return err
		}
		return recordDelivery(ctx, tx, false, code, now)
	})
	return handled, err
}

func (s *Sender) log() *slog.Logger {
	if s.Log == nil {
		return slog.New(slog.DiscardHandler)
	}
	return s.Log
}

func backoff(attempt int) time.Duration {
	d := baseBackoff
	for i := 1; i < attempt && d < maxBackoff; i++ {
		d *= 2
	}
	return min(d, maxBackoff)
}

// Render builds the email for template in locale (falling back to English). Every
// parameter is flattened to one line, so a value can never add a header or a paragraph.
func (s *Sender) Render(to, template, locale string, params map[string]string) Message {
	clean := make(map[string]string, len(params))
	for k, v := range params {
		clean[k] = oneLine(v)
	}
	subject := oneLine(s.Catalog.T(locale, "email."+template+".subject", clean))
	body := strings.TrimSpace(s.Catalog.T(locale, "email."+template+".body", clean))
	// The license note sits before the footer (L-28); the param that asks for it is not rendered.
	switch params["license_note"] {
	case "true":
		body += "\n\n" + s.Catalog.T(locale, "email.license_note", map[string]string{"license_url": clean["license_url"]})
	case "kv":
		body += "\n\n" + s.Catalog.T(locale, "email.license_note_kv", map[string]string{"license_url": clean["license_url"]})
	}
	body += "\n\n" + s.Catalog.T(locale, "email.footer", nil)
	return Message{To: to, Subject: subject, Body: body}
}
