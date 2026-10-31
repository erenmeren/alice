package notify

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
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
	// sendLease is how long a claimed e-mail is not due while it is sent: longer than sendTimeout, so a send that is
	// still running is never taken by another drain.
	sendLease = sendTimeout + time.Minute
	// finishTimeout bounds storing a send's outcome.
	finishTimeout = 10 * time.Second
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

// claimed is an outbox row taken for one send: leased (not due) until the send is finished.
type claimed struct {
	id              uuid.UUID
	to, tpl, locale string
	params          map[string]string
	attempts        int // including this one
	createdAt       time.Time
}

// one handles the next due e-mail, if any. The row is claimed and leased in one short transaction, the message is
// sent with no transaction open and no pooled connection held, and the outcome is stored in a second short
// transaction (review L-6). A send whose outcome cannot be stored (the process dies, the database is gone) is retried
// once the lease ends: delivery is at least once, as the server may have accepted the message.
func (s *Sender) one(ctx context.Context, mailer Mailer) (bool, error) {
	c, handled, err := s.claim(ctx, mailer)
	if err != nil || c == nil {
		return handled, err
	}
	sendCtx, cancel := context.WithTimeout(ctx, sendTimeout)
	sendErr := mailer.Send(sendCtx, s.Render(c.to, c.tpl, c.locale, c.params))
	cancel()
	// The message may be out: store that even when ctx ended meanwhile (shutdown), so it is not sent twice.
	finishCtx, cancelFinish := context.WithTimeout(context.WithoutCancel(ctx), finishTimeout)
	defer cancelFinish()
	return true, s.finish(finishCtx, c, sendErr)
}

// claim takes the next due row. Without a mailer it is recorded as skipped, with parameters that do not parse as
// failed; both are handled without a claim. Otherwise its attempt is counted and it is leased for sendLease.
func (s *Sender) claim(ctx context.Context, mailer Mailer) (*claimed, bool, error) {
	var (
		c       *claimed
		handled bool
	)
	err := db.InTx(ctx, s.Pool, func(tx pgx.Tx) error {
		now := s.Clock.Now().UTC()
		var (
			row claimed
			raw []byte
		)
		err := tx.QueryRow(ctx, `SELECT id, to_address, template_key, params, locale, attempts, created_at FROM notifications_outbox
WHERE status = 'pending' AND next_attempt_at <= $1 ORDER BY next_attempt_at, id LIMIT 1 FOR UPDATE SKIP LOCKED`, now).
			Scan(&row.id, &row.to, &row.tpl, &raw, &row.locale, &row.attempts, &row.createdAt)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("notify: read the outbox: %w", err)
		}
		handled = true
		if mailer == nil {
			_, err := tx.Exec(ctx, `UPDATE notifications_outbox SET status = 'skipped_no_smtp', last_error_code = 'smtp.not_configured'
WHERE id = $1`, row.id)
			return err
		}
		if err := json.Unmarshal(raw, &row.params); err != nil {
			_, err := tx.Exec(ctx, `UPDATE notifications_outbox SET status = 'failed', last_error_code = 'template.params' WHERE id = $1`, row.id)
			return err
		}
		row.attempts++
		if _, err := tx.Exec(ctx, `UPDATE notifications_outbox SET attempts = $2, next_attempt_at = $3 WHERE id = $1`,
			row.id, row.attempts, now.Add(sendLease)); err != nil {
			return fmt.Errorf("notify: lease the e-mail: %w", err)
		}
		c = &row
		return nil
	})
	if err != nil {
		return nil, handled, err
	}
	return c, handled, nil
}

// finish stores the outcome of c's send. The update is fenced on the attempt count: when the lease ran out and
// another drain took the row meanwhile, that drain's outcome is the one kept.
func (s *Sender) finish(ctx context.Context, c *claimed, sendErr error) error {
	return db.InTx(ctx, s.Pool, func(tx pgx.Tx) error {
		now := s.Clock.Now().UTC()
		if sendErr == nil {
			tag, err := tx.Exec(ctx, `UPDATE notifications_outbox SET status = 'sent', sent_at = $2, last_error_code = ''
WHERE id = $1 AND status = 'pending' AND attempts = $3`, c.id, now, c.attempts)
			if err != nil || tag.RowsAffected() == 0 {
				return err
			}
			return recordDelivery(ctx, tx, true, "", now)
		}
		code := ErrorCode(sendErr)
		status := "pending"
		if now.Sub(c.createdAt) >= GiveUpAfter {
			status = "failed"
		}
		tag, err := tx.Exec(ctx, `UPDATE notifications_outbox SET status = $2, next_attempt_at = $3, last_error_code = $4
WHERE id = $1 AND status = 'pending' AND attempts = $5`, c.id, status, now.Add(backoff(c.attempts)), code, c.attempts)
		if err != nil || tag.RowsAffected() == 0 {
			return err
		}
		if status == "failed" {
			s.log().Error("email not sent after "+strconv.Itoa(c.attempts)+" attempts; giving up",
				"event", "notify.gave_up",
				"outbox_id", c.id.String(), "attempt", c.attempts, "reason", code)
		} else {
			s.log().Warn("email not sent; it will be retried", "outbox_id", c.id.String(), "attempt", c.attempts, "reason", code)
		}
		return recordDelivery(ctx, tx, false, code, now)
	})
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
// parameter is flattened to one line, so a value can never add a header or a paragraph. A param
// error_reason (a closed error code such as acme.ca_rate_limited) is rendered as param reason: the
// plain title of that code in the reader's language (errors.<code>.title; an unknown code reads as
// internal.unexpected's title), so no raw code reaches the reader. A param reason_variant selects
// errors.<code>.title_<variant> where that key exists (else the plain title) and is dropped from the
// rendered params; then a param transport (winrm: a WinRM Windows server's ssh.* reasons, R71 Ruling 13)
// selects errors.<code>.title_<transport> the same way.
func (s *Sender) Render(to, template, locale string, params map[string]string) Message {
	clean := make(map[string]string, len(params))
	for k, v := range params {
		clean[k] = oneLine(v)
	}
	if code, ok := params["error_reason"]; ok {
		delete(clean, "error_reason")
		clean["reason"] = s.reasonTitle(locale, code, params["reason_variant"], params["transport"])
	}
	delete(clean, "reason_variant") // the variant of the reason's title (W6 final review M2); never rendered itself
	subject := oneLine(s.Catalog.T(locale, "email."+template+".subject", clean))
	body := strings.TrimSpace(s.Catalog.T(locale, "email."+template+".body", clean))
	// The license note sits before the footer (L-28); the param that asks for it is not rendered.
	switch params["license_note"] {
	case "true":
		body += "\n\n" + s.Catalog.T(locale, "email.license_note", map[string]string{"license_url": clean["license_url"]})
	case "kv":
		body += "\n\n" + s.Catalog.T(locale, "email.license_note_kv", map[string]string{"license_url": clean["license_url"]})
	}
	// A Windows server's AutoCertRebind task (R62 Ruling 16): the sentence that it may have re-pointed the binding; the
	// param that asks for it is not rendered.
	switch params["windows_note"] {
	case "autocertrebind":
		body += "\n\n" + s.Catalog.T(locale, "email.windows_note_autocertrebind", nil)
	case "rdp": // the Remote Desktop listener (W6 Ruling 20)
		body += "\n\n" + s.Catalog.T(locale, "email.windows_note_rdp", nil)
	case "rdp_autoenroll": // the listener, whose certificate a policy autoenrols
		body += "\n\n" + s.Catalog.T(locale, "email.windows_note_rdp", nil) + " " + s.Catalog.T(locale, "email.windows_note_rdp_autoenroll", nil)
	}
	// An RDP restore that left NETWORK SERVICE's read access to the key in place (W6 Ruling 10).
	if params["rdp_key_acl_left"] == "true" {
		body += "\n\n" + s.Catalog.T(locale, "email.windows_note_rdp_key_acl_left", nil)
	} else if params["rdp_key_granted"] == "true" { // the RDP manual-action texts: no restore took the access back
		body += "\n\n" + s.Catalog.T(locale, "email.windows_note_rdp_key_granted", nil)
	}
	body += "\n\n" + s.Catalog.T(locale, "email.footer", nil)
	return Message{To: to, Subject: subject, Body: body}
}

// reasonCode is the form of a closed error code (internal/api errors.go reasons).
var reasonCode = regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$`)

// reasonVariant is the form of a title variant (reason_variant: "rdp", the Remote Desktop listener's titles).
var reasonVariant = regexp.MustCompile(`^[a-z]+$`)

// reasonTitle is the plain title of an error code in locale (see Render): errors.<code>.title_<variant> for the
// first variant that is a word and whose key exists (W6 final review M2: the listener's titles; R71: the WinRM
// transport's), else errors.<code>.title.
func (s *Sender) reasonTitle(locale, code string, variants ...string) string {
	if reasonCode.MatchString(code) {
		title := "errors." + code + ".title"
		var keys []string
		for _, v := range variants {
			if reasonVariant.MatchString(v) {
				keys = append(keys, title+"_"+v)
			}
		}
		for _, key := range append(keys, title) {
			if t := s.Catalog.T(locale, key, nil); t != key {
				return oneLine(t)
			}
		}
	}
	return oneLine(s.Catalog.T(locale, "errors.internal.unexpected.title", nil))
}
