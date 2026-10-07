package notify

import (
	"context"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"

	"alice/internal/audit"
	"alice/internal/platform/db"
	"alice/internal/platform/settings"
	"alice/internal/platform/validate"
)

var publicHostPattern = regexp.MustCompile(`^[A-Za-z0-9.\-]+$|^\[[0-9A-Fa-f:.]+\]$`)

// General reads Alice's own address and the retired-key retention (defaults when never saved).
func (s *Settings) General(ctx context.Context) (settings.General, error) {
	return settings.GetGeneral(ctx, s.pool)
}

// SaveGeneral validates and stores the general settings at version (0 = never saved).
func (s *Settings) SaveGeneral(ctx context.Context, a audit.Actor, version int, g settings.General) (settings.General, error) {
	var v validate.Errors
	g.PublicURL = strings.TrimSuffix(g.PublicURL, "/")
	if g.PublicURL != "" && !validPublicURL(g.PublicURL) {
		v.Add("public_url", validate.Pattern, nil)
	}
	if g.RetiredKeyRetentionDays < 1 || g.RetiredKeyRetentionDays > 3650 {
		v.Add("retired_key_retention_days", validate.OutOfRange, map[string]string{"min": "1", "max": "3650"})
	}
	if err := v.Err(); err != nil {
		return settings.General{}, err
	}
	var out settings.General
	err := db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, settings.GeneralKey); err != nil {
			return err
		}
		cur, err := settings.GetGeneral(ctx, tx)
		if err != nil {
			return err
		}
		if cur.Version != version {
			return ErrVersion
		}
		g.Version = version + 1
		if err := settings.Set(ctx, tx, settings.GeneralKey, g, s.clock.Now()); err != nil {
			return err
		}
		out = g
		_, err = s.audit.Append(ctx, tx, audit.Event{Actor: a, Action: "settings.general_changed", ObjectType: settingObject,
			ObjectID: settings.GeneralKey, Result: audit.Success,
			Details: map[string]string{"public_url": g.PublicURL, "days": strconv.Itoa(g.RetiredKeyRetentionDays)}})
		return err
	})
	return out, err
}

// validPublicURL accepts https://host[:port] only: no user info, path, query or fragment.
func validPublicURL(raw string) bool {
	if strings.ContainsAny(raw, "?#@ \t\r\n") || !strings.HasPrefix(raw, "https://") {
		return false
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Path != "" || u.User != nil || u.Hostname() == "" {
		return false
	}
	if p := u.Port(); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 65535 {
			return false
		}
	}
	return publicHostPattern.MatchString(u.Hostname()) || publicHostPattern.MatchString("["+u.Hostname()+"]")
}
