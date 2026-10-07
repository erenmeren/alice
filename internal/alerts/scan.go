package alerts

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"alice/internal/alerts/expiry"
	"alice/internal/audit"
	"alice/internal/platform/db"
	"alice/internal/platform/settings"
)

const (
	timeLayout     = "2006-01-02 15:04 UTC"
	maxSubjectRune = 300
)

// licenseNote says whether the license is locked and where the license page is (L-28).
type licenseNote struct {
	locked bool
	url    string
}

func noteFor(locked bool, publicURL string) licenseNote {
	return licenseNote{locked: locked, url: strings.TrimSuffix(publicURL, "/") + "/license"}
}

// ledgerKey identifies one expiry instant of one object: a renewal (a new instant) starts a new series, and the
// levels sent for an old instant never block it.
type ledgerKey struct {
	kind      Kind
	object    uuid.UUID
	expiresAt int64
}

func keyOf(it Item) ledgerKey { return ledgerKey{it.Kind, it.ObjectID, it.ExpiresAt.UnixMicro()} }

// Scan sends the due expiry notices (R42 rows 3-5, 12): for every monitored item that reaches a threshold within the
// largest threshold, the most urgent due level is recorded in the ledger; the transaction that inserted the row is the
// only one that queues the email, at most MaxEmailsPerScan per kind, and one summary per kind for the rest. It runs in
// every license state (class always): in lock the emails carry the license note (L-28). One item that cannot be
// recorded or queued is logged and skipped; the others proceed (S-3).
func (s *Service) Scan(ctx context.Context) (ScanResult, error) {
	res := ScanResult{Queued: map[Kind]int{}, Suppressed: map[Kind]int{}}
	th, err := s.Thresholds(ctx)
	if err != nil {
		return res, err
	}
	now := s.clock.Now().UTC()
	items, err := s.Items(ctx, Kinds(), now.Add(expiry.Horizon(th.Days)), 0)
	if err != nil {
		return res, err
	}
	sent, err := s.sentLevels(ctx, items)
	if err != nil {
		return res, err
	}
	g, err := settings.GetGeneral(ctx, s.pool)
	if err != nil {
		return res, err
	}
	note := noteFor(s.license.Snapshot().Eval.Locked(), g.PublicURL)
	for _, it := range items {
		level, due := expiry.Due(it.ExpiresAt, now, th.Days, sent[keyOf(it)])
		if !due {
			continue
		}
		emailed := res.Queued[it.Kind] < MaxEmailsPerScan
		inserted, err := s.record(ctx, it, level, now, note, emailed)
		if err != nil {
			if ctx.Err() != nil {
				return res, ctx.Err()
			}
			res.Failed++
			s.log.Error("alerts: an expiry notice could not be recorded; the item is skipped", "kind", string(it.Kind),
				"object_id", it.ObjectID.String(), "threshold_days", level, "error", err.Error())
			continue
		}
		switch {
		case !inserted: // another scan recorded this level first
		case emailed:
			res.Queued[it.Kind]++
		default:
			res.Suppressed[it.Kind]++
		}
	}
	for _, k := range Kinds() {
		if n := res.Suppressed[k]; n > 0 {
			if err := s.summarize(ctx, k, n, now, note); err != nil {
				if ctx.Err() != nil {
					return res, ctx.Err()
				}
				res.Failed++
				s.log.Error("alerts: the summary of suppressed notices could not be queued", "kind", string(k), "error", err.Error())
			}
		}
	}
	return res, nil
}

// sentLevels reads the levels already recorded for the items, by expiry instant.
func (s *Service) sentLevels(ctx context.Context, items []Item) (map[ledgerKey][]int, error) {
	out := map[ledgerKey][]int{}
	if len(items) == 0 {
		return out, nil
	}
	ids := make([]string, len(items))
	for i, it := range items {
		ids[i] = it.ObjectID.String()
	}
	rows, err := s.pool.Query(ctx, `SELECT kind, object_id, expires_at, threshold_days FROM alerts WHERE object_id = ANY ($1::uuid[])`, ids)
	if err != nil {
		return nil, fmt.Errorf("alerts: read the ledger: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var (
			kind string
			id   uuid.UUID
			exp  time.Time
			days int
		)
		if err := rows.Scan(&kind, &id, &exp, &days); err != nil {
			return nil, fmt.Errorf("alerts: read the ledger: %w", err)
		}
		k := ledgerKey{Kind(kind), id, exp.UnixMicro()}
		out[k] = append(out[k], days)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("alerts: read the ledger: %w", err)
	}
	return out, nil
}

// record writes the ledger row and, only in the transaction that inserted it, queues the email and the audit row.
func (s *Service) record(ctx context.Context, it Item, level int, now time.Time, note licenseNote, emailed bool) (bool, error) {
	inserted := false
	err := db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		var id uuid.UUID
		err := tx.QueryRow(ctx, `INSERT INTO alerts (id, kind, object_id, subject, expires_at, threshold_days, license_locked, emailed, created_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
ON CONFLICT (kind, object_id, expires_at, threshold_days) DO NOTHING RETURNING id`,
			uuid.Must(uuid.NewV7()), string(it.Kind), it.ObjectID, subjectOf(it), it.ExpiresAt, level, note.locked, emailed, now).Scan(&id)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("alerts: record the notice: %w", err)
		}
		inserted = true
		if emailed {
			if err := s.notifier.NotifyAdmins(ctx, tx, templateFor(it.Kind, level), paramsOf(it, now, level, note)); err != nil {
				return fmt.Errorf("alerts: queue the notice: %w", err)
			}
		}
		_, err = s.audit.Append(ctx, tx, audit.Event{Actor: audit.SystemActor("alerts"), Action: "alert.sent", ObjectType: string(it.Kind),
			ObjectID: it.ObjectID.String(), Result: audit.Success, Details: map[string]string{
				"kind": string(it.Kind), "object_id": it.ObjectID.String(), "threshold_days": strconv.Itoa(level),
				"expires_at": it.ExpiresAt.Format(time.RFC3339), "locked": strconv.FormatBool(note.locked),
				"emailed": strconv.FormatBool(emailed)}})
		return err
	})
	if err != nil {
		return false, err
	}
	return inserted, nil
}

// summarize queues the one "and N more" email of a kind.
func (s *Service) summarize(ctx context.Context, k Kind, n int, _ time.Time, note licenseNote) error {
	return db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		params := map[string]string{"count": strconv.Itoa(n), "kind": string(k)}
		addNote(params, k, note)
		if err := s.notifier.NotifyAdmins(ctx, tx, "alert.more", params); err != nil {
			return err
		}
		_, err := s.audit.Append(ctx, tx, audit.Event{Actor: audit.SystemActor("alerts"), Action: "alert.summarized",
			ObjectType: string(k), Result: audit.Success,
			Details: map[string]string{"kind": string(k), "suppressed_count": strconv.Itoa(n)}})
		return err
	})
}

// subjectOf is the item's name cut to the ledger's 300 runes (S-3); never empty.
func subjectOf(it Item) string {
	name := strings.TrimSpace(it.Name)
	if name == "" {
		return it.ObjectID.String()
	}
	if r := []rune(name); len(r) > maxSubjectRune {
		return string(r[:maxSubjectRune])
	}
	return name
}

func templateFor(k Kind, level int) string {
	base := strings.TrimSuffix(string(k), "_expiry")
	if level == expiry.Expired {
		return "alert." + base + "_expired"
	}
	return "alert." + base + "_expiring"
}

func addNote(params map[string]string, k Kind, note licenseNote) {
	if !note.locked {
		return
	}
	params["license_note"] = "kv"
	if k == KindCertificate {
		params["license_note"] = "true"
	}
	params["license_url"] = note.url
}

func joined(list []string, more bool) string {
	if len(list) == 0 {
		return "-"
	}
	out := strings.Join(list, ", ")
	if more {
		out += ", …"
	}
	return out
}

// paramsOf are the template parameters of C14.
func paramsOf(it Item, now time.Time, level int, note licenseNote) map[string]string {
	p := map[string]string{"name": subjectOf(it), "expires_at": it.ExpiresAt.UTC().Format(timeLayout)}
	if level != expiry.Expired {
		p["days"] = strconv.Itoa(expiry.DaysLeft(it.ExpiresAt, now))
	}
	if it.Kind == KindCertificate {
		p["fingerprint"] = it.Fingerprint
		p["websites"] = joined(it.Websites, it.moreWebsites)
		p["servers"] = joined(it.Servers, it.moreServers)
	} else {
		p["vault"] = it.Vault
	}
	addNote(p, it.Kind, note)
	return p
}
