package web

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"

	"alice/internal/vconsole/webuser"
)

// Notifications are read and marked only through the database functions web_notifications,
// web_unread_count, web_mark_read and web_mark_all_read. They decide what a person may see; this
// file passes the signed-in user's id inside inActorTx (the functions return nothing unless
// vendor.actor names that same user) and never filters by audience itself.

const (
	notificationsLimit = 100
	homeUnreadLimit    = 3
)

// requestSubject is the subject of a notification about a license request.
var requestSubject = regexp.MustCompile(`^request:([1-9][0-9]{0,17})$`)

// notification is one row of web_notifications, cleaned for display.
type notification struct {
	ID        int64
	Severity  string
	Title     string
	Body      string
	Subject   string
	CreatedAt time.Time
	ReadAt    *time.Time
}

// Unread reports whether the signed-in person has not marked it read.
func (n notification) Unread() bool { return n.ReadAt == nil }

// Level is the severity label shown as text: one of info, warning, alert.
func (n notification) Level() string {
	switch n.Severity {
	case "warning", "alert":
		return n.Severity
	}
	return "info"
}

// When is the creation time in UTC, like every time the console shows.
func (n notification) When() string { return n.CreatedAt.UTC().Format("2006-01-02 15:04") }

// SubjectURL is where the subject links to: the request page for "request:<id>", the license list
// for a license ID, nothing otherwise (the subject is then plain text).
func (n notification) SubjectURL() string {
	if m := requestSubject.FindStringSubmatch(n.Subject); m != nil {
		return "/requests/" + m[1]
	}
	if licenseIDPattern.MatchString(n.Subject) {
		return "/licenses"
	}
	return ""
}

// dropForDisplay reports the runes never shown: control characters, format characters (bidi
// overrides, zero-width marks), line and paragraph separators and the replacement character. The
// writers already clean their text; this is the second guard, so a row written some other way
// cannot make the page read differently than it is.
func dropForDisplay(r rune) bool {
	return unicode.IsControl(r) || unicode.In(r, unicode.Cf, unicode.Zl, unicode.Zp) || r == utf8.RuneError
}

// displayLine makes s one line: every run of dropped runes becomes one space.
func displayLine(s string) string {
	var b strings.Builder
	gap := false
	for _, r := range strings.ToValidUTF8(s, string(utf8.RuneError)) {
		if dropForDisplay(r) {
			if !gap {
				b.WriteByte(' ')
			}
			gap = true
			continue
		}
		gap = false
		b.WriteRune(r)
	}
	return b.String()
}

// displayText keeps line breaks (the body is several lines) and drops the other runes dropForDisplay reports.
func displayText(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '\n' {
			return r
		}
		if dropForDisplay(r) {
			return -1
		}
		return r
	}, strings.ToValidUTF8(s, ""))
}

// listNotifications returns the newest notifications the user may see, at most limit.
func listNotifications(ctx context.Context, tx pgx.Tx, userID int64, limit int, unreadOnly bool) ([]notification, error) {
	rows, err := tx.Query(ctx, `SELECT id, severity, title, body, subject, created_at, read_at
		FROM web_notifications($1, $2, $3)`, userID, limit, unreadOnly)
	if err != nil {
		return nil, fmt.Errorf("web: list notifications: %w", err)
	}
	defer rows.Close()
	var out []notification
	for rows.Next() {
		var n notification
		if err := rows.Scan(&n.ID, &n.Severity, &n.Title, &n.Body, &n.Subject, &n.CreatedAt, &n.ReadAt); err != nil {
			return nil, fmt.Errorf("web: list notifications: %w", err)
		}
		n.Title, n.Subject, n.Body = displayLine(n.Title), displayLine(n.Subject), displayText(n.Body)
		out = append(out, n)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("web: list notifications: %w", err)
	}
	return out, nil
}

// unreadCount is the number for the bell. Zero when it cannot be read: the bell is a convenience
// and must never take a page down, so the error is logged and the page shows no count.
func (s *Server) unreadCount(ctx context.Context, u webuser.User) int64 {
	var n int64
	err := s.inActorTx(ctx, u, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT web_unread_count($1)`, u.ID).Scan(&n)
	})
	if err != nil {
		s.log.Warn("web: unread count", "err", err)
		return 0
	}
	return n
}

type notificationsData struct {
	Items      []notification
	UnreadOnly bool
}

func (s *Server) notificationsPage(w http.ResponseWriter, r *http.Request, u webuser.User) {
	d := notificationsData{UnreadOnly: r.URL.Query().Get("unread") == "1"}
	err := s.inActorTx(r.Context(), u, func(tx pgx.Tx) (err error) {
		d.Items, err = listNotifications(r.Context(), tx, u.ID, notificationsLimit, d.UnreadOnly)
		return err
	})
	if err != nil {
		s.serverError(w, "list notifications", err)
		return
	}
	s.renderUser(w, r, http.StatusOK, "notifications", u, d)
}

// notificationRead marks one notification read. Whether it was visible is deliberately ignored:
// an invisible, unknown or already read ID gets the same redirect, so the answer says nothing
// about other people's notifications.
func (s *Server) notificationRead(w http.ResponseWriter, r *http.Request, u webuser.User) {
	id, ok := pathID(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	err := s.inActorTx(r.Context(), u, func(tx pgx.Tx) error {
		var visible bool
		return tx.QueryRow(r.Context(), `SELECT web_mark_read($1, $2)`, u.ID, id).Scan(&visible)
	})
	if err != nil {
		s.serverError(w, "mark notification read", err)
		return
	}
	http.Redirect(w, r, "/notifications", http.StatusSeeOther)
}

func (s *Server) notificationsReadAll(w http.ResponseWriter, r *http.Request, u webuser.User) {
	err := s.inActorTx(r.Context(), u, func(tx pgx.Tx) error {
		var marked int64
		return tx.QueryRow(r.Context(), `SELECT web_mark_all_read($1)`, u.ID).Scan(&marked)
	})
	if err != nil {
		s.serverError(w, "mark all notifications read", err)
		return
	}
	http.Redirect(w, r, "/notifications", http.StatusSeeOther)
}
