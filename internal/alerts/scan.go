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

// licenseNote says whether the license is locked and where the license page is (L-28); base is Alice's public address
// without the trailing slash ("" when none is set), for the other links of a notice.
type licenseNote struct {
	locked bool
	url    string
	base   string
}

func noteFor(locked bool, publicURL string) licenseNote {
	base := strings.TrimSuffix(publicURL, "/")
	return licenseNote{locked: locked, url: base + "/license", base: base}
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
	// The license note says automatic deployment waits for a renewal: not true inside the continuity window of a lock,
	// where certificates already managed keep renewing and deploying (owner decision 2026-10-20).
	ev := s.license.Snapshot().Eval
	note := noteFor(ev.Locked() && !ev.InContinuity(), g.PublicURL)
	dueByKind := map[Kind][]dueItem{}
	for _, it := range items {
		if level, due := expiry.Due(it.ExpiresAt, now, th.Days, sent[keyOf(it)]); due {
			dueByKind[it.Kind] = append(dueByKind[it.Kind], dueItem{it, level})
		}
	}
	for _, k := range Kinds() {
		list := dueByKind[k]
		if len(list) > MaxEmailsPerScan {
			// The notices over the cap and their one summary commit together, before anything of this kind is sent: if
			// that fails, nothing of the kind is recorded and the next scan offers the same split again.
			n, err := s.recordSuppressed(ctx, k, list[MaxEmailsPerScan:], now, note)
			if err != nil {
				if ctx.Err() != nil {
					return res, ctx.Err()
				}
				res.Failed++
				s.log.Error("alerts: the suppressed notices and their summary could not be recorded; the kind is retried by the next scan",
					"kind", string(k), "count", len(list)-MaxEmailsPerScan, "error", err.Error())
				continue
			}
			res.Suppressed[k] = n
			list = list[:MaxEmailsPerScan]
		}
		for _, d := range list {
			inserted, err := s.record(ctx, d.it, d.level, now, note, true)
			if err != nil {
				if ctx.Err() != nil {
					return res, ctx.Err()
				}
				res.Failed++
				s.log.Error("alerts: an expiry notice could not be recorded; the item is skipped", "kind", string(d.it.Kind),
					"object_id", d.it.ObjectID.String(), "threshold_days", d.level, "error", err.Error())
				continue
			}
			if inserted { // else another scan recorded this level first
				res.Queued[k]++
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

type dueItem struct {
	it    Item
	level int
}

// record writes the ledger row and, only in the transaction that inserted it, queues the email and the audit row.
func (s *Service) record(ctx context.Context, it Item, level int, now time.Time, note licenseNote, emailed bool) (bool, error) {
	inserted := false
	err := db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		var err error
		inserted, err = s.insertNotice(ctx, tx, it, level, now, note, emailed)
		return err
	})
	if err != nil {
		return false, err
	}
	return inserted, nil
}

// insertNotice is the ledger insert (ON CONFLICT DO NOTHING RETURNING) with its email and audit row, inside tx.
func (s *Service) insertNotice(ctx context.Context, tx pgx.Tx, it Item, level int, now time.Time, note licenseNote, emailed bool) (bool, error) {
	var id uuid.UUID
	err := tx.QueryRow(ctx, `INSERT INTO alerts (id, kind, object_id, subject, expires_at, threshold_days, license_locked, emailed, created_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
ON CONFLICT (kind, object_id, expires_at, threshold_days) DO NOTHING RETURNING id`,
		uuid.Must(uuid.NewV7()), string(it.Kind), it.ObjectID, subjectOf(it), it.ExpiresAt, level, note.locked, emailed, now).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("alerts: record the notice: %w", err)
	}
	if emailed {
		if err := s.notifier.NotifyAdmins(ctx, tx, templateFor(it.Kind, level), paramsOf(it, now, level, note)); err != nil {
			return false, fmt.Errorf("alerts: queue the notice: %w", err)
		}
	}
	_, err = s.audit.Append(ctx, tx, audit.Event{Actor: audit.SystemActor("alerts"), Action: "alert.sent", ObjectType: string(it.Kind),
		ObjectID: it.ObjectID.String(), Result: audit.Success, Details: map[string]string{
			"kind": string(it.Kind), "object_id": it.ObjectID.String(), "threshold_days": strconv.Itoa(level),
			"expires_at": it.ExpiresAt.Format(time.RFC3339), "locked": strconv.FormatBool(note.locked),
			"emailed": strconv.FormatBool(emailed)}})
	return err == nil, err
}

// recordSuppressed records the over-cap notices of a kind (not e-mailed one by one) and queues the one "and N more"
// email with the number actually inserted, all in one transaction.
func (s *Service) recordSuppressed(ctx context.Context, k Kind, due []dueItem, now time.Time, note licenseNote) (int, error) {
	n := 0
	err := db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		n = 0
		for _, d := range due {
			ok, err := s.insertNotice(ctx, tx, d.it, d.level, now, note, false)
			if err != nil {
				return err
			}
			if ok {
				n++
			}
		}
		if n == 0 {
			return nil
		}
		params := map[string]string{"count": strconv.Itoa(n), "kind": string(k)}
		template := "alert.more"
		if k == KindDiscoveredCertificate {
			// The Overview does not list unmanaged certificates: this summary sends its reader to the discovery page.
			template = "alert.more_discovered"
			params["discovery_url"] = discoveryURL(note)
		}
		addNote(params, k, note)
		if err := s.notifier.NotifyAdmins(ctx, tx, template, params); err != nil {
			return fmt.Errorf("alerts: queue the summary: %w", err)
		}
		_, err := s.audit.Append(ctx, tx, audit.Event{Actor: audit.SystemActor("alerts"), Action: "alert.summarized",
			ObjectType: string(k), Result: audit.Success,
			Details: map[string]string{"kind": string(k), "suppressed_count": strconv.Itoa(n)}})
		return err
	})
	if err != nil {
		return 0, err
	}
	return n, nil
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

// discoveryURL is the discovery page's list of unmanaged certificates at Alice's public address.
func discoveryURL(note licenseNote) string { return note.base + "/discovery?view=unmanaged" }

func addNote(params map[string]string, k Kind, note licenseNote) {
	if !note.locked {
		return
	}
	params["license_note"] = "true"
	if k == KindKVCertificate || k == KindKVKey || k == KindKVCredential {
		params["license_note"] = "kv"
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
	switch it.Kind {
	case KindCertificate:
		p["fingerprint"] = it.Fingerprint
		p["websites"] = joined(it.Websites, it.moreWebsites)
		p["servers"] = joined(it.Servers, it.moreServers)
	case KindDiscoveredCertificate:
		// Public facts only (a certificate Alice does not manage has no secret of Alice's): where it was found, by which
		// scope, its fingerprint and the page that lists it.
		p["fingerprint"] = it.Fingerprint
		p["endpoints"] = joined(it.Endpoints, it.moreWebsites)
		p["scopes"] = joined(it.Scopes, it.moreServers)
		p["discovery_url"] = discoveryURL(note)
	default:
		p["vault"] = it.Vault
	}
	addNote(p, it.Kind, note)
	return p
}
