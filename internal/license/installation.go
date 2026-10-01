package license

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"

	"alice/internal/audit"
	"alice/internal/platform/db"
	"alice/internal/secrets"
)

// The installation row (installation ID and timestamp, spec §16.4) carries a seal:
// HMAC-SHA256 under the HKDF sub-key alice/installation/v1 over both values. A row whose seal
// does not match is never trusted (spec §16.1(a)): changing the timestamp would restart the
// evaluation and changing the ID would let a license issued for another installation work.

// Installation problems, as audited in license.installation_tampered.
const (
	problemSealMismatch        = "seal_mismatch"        // the ID or the timestamp no longer matches the seal
	problemSealMissing         = "seal_missing"         // the seal was removed after it had been written
	problemInstallationMissing = "installation_missing" // the row was removed from an existing installation
)

// settingSetupCompleted is the setup module's completion marker (setup.completed_at): its
// presence proves that an installation existed before.
const settingSetupCompleted = "setup.completed_at"

type installationRow struct {
	ID          string
	InstalledAt time.Time
	State       Phase
	ClockJump   []byte
	Tampered    string // "" or the problem; such a row is not trusted
	unsealed    bool   // created before the seal existed and not sealed yet (sealed at Start)
}

// seal computes the installation seal. The key is derived for this purpose only and cleared
// after use; neither the key nor the seal is ever logged or audited.
func (s *Service) seal(id string, installedAt time.Time) []byte {
	key := s.keyring.Derive(secrets.LabelInstallation)
	defer clear(key)
	m := hmac.New(sha256.New, key)
	m.Write([]byte("alice-installation-v1\n" + id + "\n" + strconv.FormatInt(installedAt.UTC().UnixMicro(), 10)))
	return m.Sum(nil)
}

// everSealed reports whether an installation of this database was sealed on the first start
// after the upgrade that introduced the seal (the audit chain records it).
func everSealed(ctx context.Context, q db.Querier) (bool, error) {
	var ok bool
	if err := q.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM audit_log WHERE action = 'license.installation_sealed')").Scan(&ok); err != nil {
		return false, fmt.Errorf("read the installation seal record: %w", err)
	}
	return ok, nil
}

// loadInstallation reads the installation row. forUpdate takes the license row lock that
// serializes uploads, evaluations and time record saves. A stored ID that is not in
// canonical form, or a zero installation time, is refused rather than used. A row that does
// not match its seal is returned with Tampered set; it is evaluated as an ended evaluation.
func (s *Service) loadInstallation(ctx context.Context, q db.Querier, forUpdate bool) (installationRow, error) {
	sql := "SELECT installation_id, installed_at, state, clock_jump, installation_seal FROM license WHERE id = 1"
	if forUpdate {
		sql += " FOR UPDATE"
	}
	var r installationRow
	var state string
	var stored []byte
	err := q.QueryRow(ctx, sql).Scan(&r.ID, &r.InstalledAt, &state, &r.ClockJump, &stored)
	if errors.Is(err, pgx.ErrNoRows) {
		return installationRow{}, ErrNoInstallation
	}
	if err != nil {
		return installationRow{}, fmt.Errorf("read the installation: %w", err)
	}
	if id, err := ParseInstallationID(r.ID); err != nil || id != r.ID {
		return installationRow{}, errors.New("license: the stored installation ID is damaged")
	}
	if r.InstalledAt.IsZero() {
		return installationRow{}, errors.New("license: the stored installation time is damaged")
	}
	r.State, r.InstalledAt = Phase(state), r.InstalledAt.UTC()
	switch {
	case stored == nil:
		sealed, err := everSealed(ctx, q)
		if err != nil {
			return installationRow{}, err
		}
		if sealed {
			r.Tampered = problemSealMissing
		} else {
			r.unsealed = true
		}
	case !hmac.Equal(stored, s.seal(r.ID, r.InstalledAt)): // constant time
		r.Tampered = problemSealMismatch
	}
	return r, nil
}

// ensureInstallation creates the installation row on the first start (spec §16.4) and reports
// whether it did. A missing row is a new installation only when nothing shows that one
// existed: with a valid time record or a completed setup, the row was removed, and the new
// row's evaluation has already ended (audited as license.installation_tampered), so removing
// the row never grants a fresh evaluation.
func (s *Service) ensureInstallation(ctx context.Context) (bool, error) {
	now := later(s.clock.Now().UTC(), s.buildTime).Truncate(time.Microsecond)
	if now.IsZero() {
		return false, errors.New("license: the system clock is not set")
	}
	var exists bool
	if err := s.pool.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM license WHERE id = 1)").Scan(&exists); err != nil {
		return false, fmt.Errorf("read the installation: %w", err)
	}
	if exists {
		return false, nil
	}
	evidence, latest, err := s.priorInstallation(ctx)
	if err != nil {
		return false, err
	}
	id, installedAt := NewInstallationID(), now
	if evidence != "" {
		installedAt = later(now, latest).Add(-EvaluationPeriod).Truncate(time.Microsecond)
	}
	fresh := false
	err = db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `INSERT INTO license (id, installation_id, installed_at, state, updated_at, installation_seal)
VALUES (1, $1, $2, 'evaluation', $3, $4) ON CONFLICT (id) DO NOTHING`, id, installedAt, now, s.seal(id, installedAt))
		if err != nil {
			return fmt.Errorf("create the installation: %w", err)
		}
		if tag.RowsAffected() == 0 {
			return nil // another process created it
		}
		if evidence == "" {
			fresh = true
			return nil
		}
		_, err = s.audit.Append(ctx, tx, audit.Event{Actor: systemActor, Action: "license.installation_tampered",
			ObjectType: "license", ObjectID: id, Result: audit.Failure,
			Details: map[string]string{"problem": problemInstallationMissing, "evidence": evidence, "installation_id": id}})
		return err
	})
	if err != nil {
		return false, err
	}
	switch {
	case fresh:
		s.log.Info("new installation created; the 30-day evaluation starts now")
	case evidence != "":
		s.log.Error("the installation record was removed; a new Installation ID was created and its evaluation has "+
			"already ended. Upload a license issued for the new Installation ID", "evidence", evidence)
	}
	return fresh, nil
}

// priorInstallation reports what shows that an installation existed on this database: a
// valid time record ("time_record", with its time) or a completed setup ("setup_completed").
func (s *Service) priorInstallation(ctx context.Context) (string, time.Time, error) {
	hwm, _, err := s.readHWM(ctx)
	if err != nil {
		return "", time.Time{}, err
	}
	if hwm.best != nil {
		return "time_record", hwm.best.At, nil
	}
	var completed bool
	if err := s.pool.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM settings WHERE key = $1)", settingSetupCompleted).Scan(&completed); err != nil {
		return "", time.Time{}, fmt.Errorf("read the setup state: %w", err)
	}
	if completed {
		return "setup_completed", time.Time{}, nil
	}
	return "", time.Time{}, nil
}

// sealUnsealed seals an installation created before the seal existed, once: on the first
// start after the upgrade (audited as license.installation_sealed). A seal removed after
// that is tampering and is never written again.
func (s *Service) sealUnsealed(ctx context.Context) error {
	return db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		row, err := s.loadInstallation(ctx, tx, true)
		if err != nil || !row.unsealed {
			return err
		}
		if _, err := tx.Exec(ctx, "UPDATE license SET installation_seal = $1 WHERE id = 1", s.seal(row.ID, row.InstalledAt)); err != nil {
			return fmt.Errorf("seal the installation: %w", err)
		}
		_, err = s.audit.Append(ctx, tx, audit.Event{Actor: systemActor, Action: "license.installation_sealed",
			ObjectType: "license", ObjectID: row.ID, Result: audit.Success,
			Details: map[string]string{"reason": "upgrade", "installation_id": row.ID}})
		return err
	})
}

// Notice kinds of the installation record episodes: "<kind>:<installation id>:<n>". Phase 2 wrote
// "installation_tampered:<installation id>" without a number; it counts as episode 1.
const (
	noticeInstallationTampered = "installation_tampered"
	noticeInstallationRestored = "installation_restored"
)

// episodes counts the notices of kind for installation id: the Phase 2 key "<kind>:<id>" and every
// "<kind>:<id>:<n>". The prefix is compared exactly (no LIKE), so another ID never matches.
func episodes(ctx context.Context, tx pgx.Tx, kind, id string) (int, error) {
	prefix := kind + ":" + id
	var n int
	err := tx.QueryRow(ctx, `SELECT count(*) FROM license_history
WHERE event = 'notice' AND license_id = '' AND (notice = $1::text OR left(notice, length($1::text) + 1) = $1::text || ':')`,
		prefix).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("read the installation notices: %w", err)
	}
	return n, nil
}

// recordInstallationEpisode audits each tamper episode of the installation row once: an untrusted
// row with no open episode opens the next one (license.installation_tampered); a trusted row with
// an open episode closes it (license.installation_restored). The caller holds the license row
// lock, so two evaluations cannot both open the same episode; the unique notice index makes it
// exactly-once even across processes.
func (s *Service) recordInstallationEpisode(ctx context.Context, tx pgx.Tx, c computed, now time.Time) ([]audit.Event, error) {
	id := c.row.ID
	tampered, err := episodes(ctx, tx, noticeInstallationTampered, id)
	if err != nil {
		return nil, err
	}
	restored, err := episodes(ctx, tx, noticeInstallationRestored, id)
	if err != nil {
		return nil, err
	}
	open := tampered > restored
	switch {
	case c.row.Tampered != "" && !open:
		n := strconv.Itoa(tampered + 1)
		d := map[string]string{"problem": c.row.Tampered, "installation_id": id, "episode": n}
		inserted, err := insertHistory(ctx, tx, now, "notice", "", "", "", noticeInstallationTampered+":"+id+":"+n, d)
		if err != nil || !inserted {
			return nil, err
		}
		s.log.Error("the installation record was changed outside Alice; the evaluation counts as ended and no license "+
			"file is used until the original record is restored", "problem", c.row.Tampered, "episode", n)
		return []audit.Event{{Actor: systemActor, Action: "license.installation_tampered", ObjectType: "license",
			ObjectID: id, Result: audit.Failure, Details: d}}, nil
	case c.row.Tampered == "" && open:
		n := strconv.Itoa(tampered)
		d := map[string]string{"installation_id": id, "episode": n}
		inserted, err := insertHistory(ctx, tx, now, "notice", "", "", "", noticeInstallationRestored+":"+id+":"+n, d)
		if err != nil || !inserted {
			return nil, err
		}
		s.log.Info("the installation record matches its seal again; licenses count again", "episode", n)
		return []audit.Event{{Actor: systemActor, Action: "license.installation_restored", ObjectType: "license",
			ObjectID: id, Result: audit.Success, Details: d}}, nil
	}
	return nil, nil
}

// evaluateInstallation is Evaluate for the stored installation. An untrusted row counts as an
// ended evaluation (no earlier than its stored timestamp), and no license file counts.
func evaluateInstallation(now time.Time, row installationRow, installed []Installed) Evaluation {
	if row.Tampered == "" {
		return Evaluate(now, row.InstalledAt, installed)
	}
	start := row.InstalledAt
	if limit := now.Add(-EvaluationPeriod); start.After(limit) {
		start = limit
	}
	return Evaluate(now, start, nil)
}
