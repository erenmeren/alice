// Package notify writes the vendor console's in-app notifications (the notifications table) for
// expiry reminders and the weekly summary, and prunes old read ones. The issuance notification is
// written by the database itself (a trigger on licenses). The web service shows them; nothing is
// sent anywhere, so there is no delivery to retry.
package notify

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"

	"alice/internal/vconsole/audit"
)

// Audience says who sees a notification: web users with the role owner, every web user, or the
// one web user named in Notice.Target.
type Audience string

// The audiences the notifications table accepts.
const (
	AudienceOwner Audience = "owner"
	AudienceSales Audience = "sales"
	AudienceUser  Audience = "user"
)

// Severities the notifications table accepts.
const (
	SeverityInfo    = "info"
	SeverityWarning = "warning"
	SeverityAlert   = "alert"
)

const (
	day = 24 * time.Hour

	// The limits below are the CHECKs of the notifications table, counted in characters (runes)
	// as PostgreSQL's length() counts them.
	maxKindRunes    = 40
	maxTitleRunes   = 200
	maxBodyRunes    = 4000
	maxSubjectRunes = 64
	maxDedupeRunes  = 200

	// truncatedMarker ends a body that had to be cut to fit maxBodyRunes.
	truncatedMarker = "... (truncated)"

	// pruneAfter is how long a read notification is kept (ruling 4); unread ones stay forever.
	pruneAfter = 180 * day
)

var (
	// targetRe is the notifications.target_user CHECK (the web_users.name rule).
	targetRe = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)
	// keyIDRe is a license id that may appear verbatim in a dedupe key (see licenseKey).
	keyIDRe = regexp.MustCompile(`^[A-Za-z0-9._-]{1,180}$`)
)

// Notice is one notification to create.
type Notice struct {
	Kind      string // e.g. "license.ending", "summary.weekly", "activity.unusual"
	Severity  string // info | warning | alert
	Title     string
	Body      string
	Audience  Audience
	Target    string // web user name when Audience is user, empty otherwise
	Subject   string // what the notice is about (a license id), for display
	DedupeKey string
}

// Notify inserts the notice unless a notification with its DedupeKey exists, and reports whether
// a row was created.
//
// The notice is checked and cleaned here first, so a bad value fails with a clear error instead of
// a CHECK violation: the title becomes one line of at most 200 characters, a body over 4000
// characters is cut at a character boundary and ends with "... (truncated)", and the subject is
// cleaned and cut to 64 characters. Kind, severity, audience, target and dedupe key are refused,
// not repaired, when invalid: guessing them could show a notice to the wrong person or make two
// notices share a key.
//
// Callers must clean free text (customer and user names, ids) themselves before putting it into
// the body: Notify makes the title and subject one line, but the body is multi-line by design and
// gets only UTF-8, NUL and length handling, so an uncleaned value could forge a line of its own.
//
// ON CONFLICT DO NOTHING makes concurrent writers of the same key create one row: the second
// insert waits for the first transaction and then inserts nothing (or inserts if it rolled back).
func Notify(ctx context.Context, q audit.Q, n Notice) (bool, error) {
	n, err := checkNotice(n)
	if err != nil {
		return false, err
	}
	var target *string
	if n.Audience == AudienceUser {
		target = &n.Target
	}
	var id int64
	err = q.QueryRow(ctx, `INSERT INTO notifications (kind, severity, title, body, audience, target_user, subject, dedupe_key)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		ON CONFLICT (dedupe_key) DO NOTHING RETURNING id`,
		n.Kind, n.Severity, n.Title, n.Body, string(n.Audience), target, n.Subject, n.DedupeKey).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("notify: create %s notification: %w", n.Kind, err)
	}
	return true, nil
}

// checkNotice validates n and returns it cleaned as Notify stores it.
func checkNotice(n Notice) (Notice, error) {
	if k := utf8.RuneCountInString(n.Kind); k < 1 || k > maxKindRunes || !utf8.ValidString(n.Kind) {
		return n, fmt.Errorf("notify: notification kind must be 1 to %d characters", maxKindRunes)
	}
	switch n.Severity {
	case SeverityInfo, SeverityWarning, SeverityAlert:
	default:
		return n, fmt.Errorf("notify: %s: unknown severity %q", n.Kind, oneLine(n.Severity))
	}
	switch n.Audience {
	case AudienceOwner, AudienceSales:
		if n.Target != "" {
			return n, fmt.Errorf("notify: %s: a target user is only allowed with the audience user", n.Kind)
		}
	case AudienceUser:
		if !targetRe.MatchString(n.Target) {
			return n, fmt.Errorf("notify: %s: the audience user needs a valid target user name", n.Kind)
		}
	default:
		return n, fmt.Errorf("notify: %s: unknown audience %q", n.Kind, oneLine(string(n.Audience)))
	}
	if k := utf8.RuneCountInString(n.DedupeKey); k < 1 || k > maxDedupeRunes || !utf8.ValidString(n.DedupeKey) ||
		strings.ContainsRune(n.DedupeKey, 0) {
		return n, fmt.Errorf("notify: %s: dedupe key must be 1 to %d characters", n.Kind, maxDedupeRunes)
	}
	n.Title = oneLine(n.Title)
	if strings.TrimSpace(n.Title) == "" {
		return n, fmt.Errorf("notify: %s: empty title", n.Kind)
	}
	n.Subject = cut(oneLine(n.Subject), maxSubjectRunes)
	n.Body = fitBody(n.Body)
	return n, nil
}

// fitBody makes the body storable: valid UTF-8 without NUL bytes (PostgreSQL text refuses both)
// and at most maxBodyRunes characters, cutting at a character boundary and marking the cut.
func fitBody(s string) string {
	s = strings.ReplaceAll(strings.ToValidUTF8(s, string(utf8.RuneError)), "\x00", "")
	if utf8.RuneCountInString(s) <= maxBodyRunes {
		return s
	}
	return cut(s, maxBodyRunes-utf8.RuneCountInString(truncatedMarker)) + truncatedMarker
}

// Prune removes the notifications created more than 180 days before now that some web user has
// read (notify_prune; unread ones are kept whatever their age) and returns how many it removed.
func Prune(ctx context.Context, q audit.Q, now time.Time) (int64, error) {
	var n int64
	if err := q.QueryRow(ctx, `SELECT notify_prune($1)`, now.Add(-pruneAfter)).Scan(&n); err != nil {
		return 0, fmt.Errorf("notify: prune: %w", err)
	}
	return n, nil
}

// licenseKey builds the dedupe key prefix:<license>[:suffix...]. The license id is used verbatim
// only when it matches keyIDRe (no ':' and at most 180 characters, the issuance trigger's length
// rule) and the whole key fits the column's 200 characters; otherwise the key is
// prefix-sha256:<hex of its UTF-8 bytes>[:suffix...]. Without ':' in a verbatim id the parts can
// always be told apart (license "X:30" can never produce the key of license "X" for a user "30"),
// and the hashed form has its own prefix, so it can never equal a verbatim key.
func licenseKey(prefix, licenseID string, suffix ...string) string {
	tail := ""
	if len(suffix) > 0 {
		tail = ":" + strings.Join(suffix, ":")
	}
	k := prefix + ":" + licenseID + tail
	if keyIDRe.MatchString(licenseID) && utf8.RuneCountInString(k) <= maxDedupeRunes {
		return k
	}
	sum := sha256.Sum256([]byte(licenseID))
	return prefix + "-sha256:" + hex.EncodeToString(sum[:]) + tail
}

// oneLine is clean with the title limit of 200 characters.
func oneLine(s string) string { return clean(s, maxTitleRunes) }

// clean is the one cleaning rule for every free-text value shown in a title or a line (customer
// and user names, license ids, signers): every run of control, format and line/paragraph
// separator characters (line breaks, escape sequences, bidi overrides, zero-width marks) and
// invalid UTF-8 becomes one space, as vendor_clean_line does in the database, so "Acme\nCorp"
// reads "Acme Corp" everywhere. Spaces at either end are trimmed and the first n runes kept. A
// cleaned value can never start a new line, read differently than it is, or fail the
// notifications title CHECK.
func clean(s string, n int) string {
	var b strings.Builder
	gap := false
	for _, r := range strings.ToValidUTF8(s, string(utf8.RuneError)) {
		if dropRune(r) {
			if !gap {
				b.WriteByte(' ')
			}
			gap = true
			continue
		}
		gap = false
		b.WriteRune(r)
	}
	return cut(strings.TrimSpace(b.String()), n)
}

// dropRune reports the runes no line may contain: control characters, format characters (bidi
// overrides and zero-width marks), the line and paragraph separators, and the replacement
// character left by invalid UTF-8.
func dropRune(r rune) bool {
	return unicode.IsControl(r) || unicode.In(r, unicode.Cf, unicode.Zl, unicode.Zp) || r == utf8.RuneError
}

// cut keeps the first n runes of s.
func cut(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	return string([]rune(s)[:n])
}
