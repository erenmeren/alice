package reports

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"alice/internal/platform/db"
	"alice/internal/platform/validate"
)

// View is a saved filter of one of the two list pages, private to its user.
type View struct {
	ID        uuid.UUID
	Page      string
	Name      string
	Query     map[string]string
	CreatedAt time.Time
}

const (
	maxViewNameRunes  = 60
	maxViewValueRunes = 200
)

// ViewQueryKeys lists the filter keys a view of page may hold (nil for an unknown page).
func ViewQueryKeys(page string) []string {
	switch page {
	case PageCertificates:
		return []string{"target_id", "source", "q", "expiry"}
	case PageSSHKeys:
		return []string{"target_id", "os_user", "q", "flag", "missing"}
	}
	return nil
}

func validViewName(name string) bool {
	if !utf8.ValidString(name) {
		return false
	}
	for _, r := range name {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return false
		}
	}
	return true
}

// CreateView stores a view for the user: at most MaxViewsPerUser, names unique per user and page (any letter case).
func (s *Service) CreateView(ctx context.Context, userID uuid.UUID, page, name string, query map[string]string) (View, error) {
	var v validate.Errors
	keys := ViewQueryKeys(page)
	if keys == nil {
		v.Add("page", validate.OneOf, map[string]string{"values": PageCertificates + ", " + PageSSHKeys})
	}
	name = strings.TrimSpace(name)
	switch n := utf8.RuneCountInString(name); {
	case n == 0:
		v.Add("name", validate.Required, nil)
	case n > maxViewNameRunes:
		v.Add("name", validate.TooLong, map[string]string{"max": fmt.Sprint(maxViewNameRunes)})
	case !validViewName(name):
		v.Add("name", validate.Pattern, nil)
	}
	clean := map[string]string{}
	for k, val := range query {
		switch {
		case !slices.Contains(keys, k):
			v.Add("query."+k, validate.OneOf, map[string]string{"values": strings.Join(keys, ", ")})
		case utf8.RuneCountInString(val) > maxViewValueRunes:
			v.Add("query."+k, validate.TooLong, map[string]string{"max": fmt.Sprint(maxViewValueRunes)})
		case !validate.StorableText(val):
			v.Add("query."+k, validate.Pattern, nil)
		default:
			clean[k] = val
		}
	}
	if err := v.Err(); err != nil {
		return View{}, err
	}
	raw, err := json.Marshal(clean)
	if err != nil {
		return View{}, err
	}
	out := View{ID: uuid.New(), Page: page, Name: name, Query: clean, CreatedAt: s.clock.Now().UTC()}
	err = db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		// Locking the user row serialises one user's creations, so the limit cannot be passed by a race.
		var one int
		if err := tx.QueryRow(ctx, `SELECT 1 FROM users WHERE id = $1 FOR UPDATE`, userID).Scan(&one); err != nil {
			return fmt.Errorf("reports: lock the user: %w", err)
		}
		var n int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM saved_views WHERE user_id = $1`, userID).Scan(&n); err != nil {
			return fmt.Errorf("reports: count the saved views: %w", err)
		}
		if n >= MaxViewsPerUser {
			return ErrViewLimit
		}
		_, err := tx.Exec(ctx, `INSERT INTO saved_views (id, user_id, page, name, query, created_at) VALUES ($1, $2, $3, $4, $5, $6)`,
			out.ID, userID, page, name, raw, out.CreatedAt)
		var pg *pgconn.PgError
		if errors.As(err, &pg) && pg.Code == "23505" && pg.ConstraintName == "saved_views_name" {
			return ErrViewName
		}
		if err != nil {
			return fmt.Errorf("reports: store the saved view: %w", err)
		}
		return nil
	})
	if err != nil {
		return View{}, err
	}
	return out, nil
}

// Views lists the user's views of page ordered by name.
func (s *Service) Views(ctx context.Context, userID uuid.UUID, page string) ([]View, error) {
	rows, err := s.pool.Query(ctx, `SELECT id, page, name, query, created_at FROM saved_views WHERE user_id = $1 AND page = $2
ORDER BY lower(name), id`, userID, page)
	if err != nil {
		return nil, fmt.Errorf("reports: list the saved views: %w", err)
	}
	defer rows.Close()
	out := []View{}
	for rows.Next() {
		var v View
		var raw []byte
		if err := rows.Scan(&v.ID, &v.Page, &v.Name, &raw, &v.CreatedAt); err != nil {
			return nil, fmt.Errorf("reports: read a saved view: %w", err)
		}
		if err := json.Unmarshal(raw, &v.Query); err != nil {
			return nil, fmt.Errorf("reports: read a saved view: %w", err)
		}
		if v.Query == nil {
			v.Query = map[string]string{}
		}
		v.CreatedAt = v.CreatedAt.UTC()
		out = append(out, v)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("reports: list the saved views: %w", err)
	}
	return out, nil
}

// DeleteView removes the user's own view; another user's view is ErrNotFound too.
func (s *Service) DeleteView(ctx context.Context, userID, id uuid.UUID) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM saved_views WHERE id = $1 AND user_id = $2`, id, userID)
	if err != nil {
		return fmt.Errorf("reports: delete the saved view: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}
