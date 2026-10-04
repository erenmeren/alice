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
// HMAC-SHA256 under the HKDF sub-key alice/installation/v1 over both values, written in the
// transaction that creates the row. A row whose seal does not match, or has no seal, is never
// trusted (spec §16.1(a), AUD-18): changing the timestamp would restart the evaluation and
// changing the ID would let a license issued for another installation work. Nothing ever seals
// an existing row: the only row that gets a seal is a new one, and a new row starts a fresh
// evaluation only when nothing shows that an installation existed (see ensureInstallation).

// Installation problems, as audited in license.installation_tampered.
const (
	problemSealMismatch        = "seal_mismatch"        // the ID or the timestamp no longer matches the seal
	problemSealMissing         = "seal_missing"         // the seal was removed (every row is sealed when it is created)
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

// loadInstallation reads the installation row. forUpdate takes the license row lock that
// serializes uploads, evaluations and time record saves, waiting at most rowLockTimeout (q must
// then be a transaction). A stored ID that is not in
// canonical form, or a zero installation time, is refused rather than used. A row that does
// not match its seal is returned with Tampered set; it is evaluated as an ended evaluation.
func (s *Service) loadInstallation(ctx context.Context, q db.Querier, forUpdate bool) (installationRow, error) {
	sql := "SELECT installation_id, installed_at, state, clock_jump, installation_seal FROM license WHERE id = 1"
	if forUpdate {
		// AUD-02: a session holding the license row must not stop evaluations, uploads and the
		// shutdown save for ever. The bound holds for every lock wait of the rest of the
		// transaction; the gate fails closed on its own after MaxEvaluationAge.
		timeout := strconv.FormatInt(s.rowLockTimeout.Milliseconds(), 10) + "ms"
		if _, err := q.Exec(ctx, "SELECT set_config('lock_timeout', $1, true)", timeout); err != nil {
			return installationRow{}, fmt.Errorf("set the license lock timeout: %w", err)
		}
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
		// Every row is sealed in the transaction that creates it. There is no "not sealed yet"
		// (AUD-18): the upgrade path that sealed such a row let the database owner restart the
		// evaluation by clearing the seal.
		r.Tampered = problemSealMissing
	case !hmac.Equal(stored, s.seal(r.ID, r.InstalledAt)): // constant time
		r.Tampered = problemSealMismatch
	}
	return r, nil
}

// ensureInstallation creates the installation row on the first start (spec §16.4) and reports
// whether it did. A missing row is a new installation only when nothing shows that one
// existed (see priorInstallation): otherwise the row was removed, and the new row's evaluation
// has already ended (audited as license.installation_tampered), so removing the row never
// grants a fresh evaluation.
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

// priorInstallation reports what shows that an installation existed on this database or this
// state volume, when the installation row is missing (AUD-18):
//   - "time_record" (with its time): a valid time record in the database or in the state
//     directory. The state directory's copy survives a database recreated empty.
//   - "time_record_damaged": a copy that was read but does not verify. A new installation has
//     none; a leftover one means a database recreated next to an old state volume whose key
//     was replaced too. A file that cannot be read at all is no evidence either way: when
//     nothing else is evidence, the start fails with ErrTimeRecordUnreadable and creates nothing.
//   - "setup_completed": the setup module's completion marker.
//   - "audit_log": an audit event that only a started installation writes (the platform key,
//     created right after the first start, or any license event).
//   - "users", "credentials", "targets": a row in one of them. serve starts the license before
//     it creates the platform key (credentials), and users and targets come from the setup
//     wizard and the API afterwards, so a genuine first start finds all three empty.
//
// A database and a state directory emptied of every one of these is indistinguishable from a
// new installation (accepted, R36 addendum (j)).
func (s *Service) priorInstallation(ctx context.Context) (string, time.Time, error) {
	hwm, _, err := s.readHWM(ctx)
	if err != nil {
		return "", time.Time{}, err
	}
	if hwm.best != nil {
		return "time_record", hwm.best.At, nil
	}
	if len(hwm.undecodable) > 0 {
		return "time_record_damaged", time.Time{}, nil
	}
	var completed, audited bool
	if err := s.pool.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM settings WHERE key = $1)", settingSetupCompleted).Scan(&completed); err != nil {
		return "", time.Time{}, fmt.Errorf("read the setup state: %w", err)
	}
	if completed {
		return "setup_completed", time.Time{}, nil
	}
	if err := s.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM audit_log WHERE action = $1 OR object_type = 'license')`,
		auditPlatformKeyCreated).Scan(&audited); err != nil {
		return "", time.Time{}, fmt.Errorf("read the audit log: %w", err)
	}
	if audited {
		return "audit_log", time.Time{}, nil
	}
	// The first start runs before the platform key (credentials) and the setup wizard (users)
	// exist, and targets need both: a row in any of them is an installation that ran.
	for _, table := range []string{"users", "credentials", "targets"} {
		var found bool
		if err := s.pool.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM "+table+")").Scan(&found); err != nil {
			return "", time.Time{}, fmt.Errorf("read %s: %w", table, err)
		}
		if found {
			return table, time.Time{}, nil
		}
	}
	if hwm.unreadable != nil {
		// Nothing else shows an installation and nothing is known about the file: deciding now
		// would either grant a fresh evaluation to a removed installation or end the evaluation
		// of a new one for good (the new row is sealed as it is created). The start stops
		// instead and creates nothing; the operator fixes the volume and starts again.
		return "", time.Time{}, fmt.Errorf("%w: %w; make the state directory readable by Alice and start again",
			ErrTimeRecordUnreadable, hwm.unreadable)
	}
	return "", time.Time{}, nil
}

// ErrTimeRecordUnreadable stops a start on a database without an installation record when
// nothing in the database shows an earlier installation and the time record file cannot be
// read (wrong owner or mode of the state volume, an I/O error, not a regular file): Alice cannot
// tell a new installation from a removed one until it can read it. An existing installation is
// not stopped by it: the file copy then counts as damaged (clock.hwm_damaged) and the database
// copy is used, as in Phase 2.
var ErrTimeRecordUnreadable = errors.New("license: no installation in the database and the time record file cannot be read")

// auditPlatformKeyCreated is the inventory's audit action for the platform SSH key, which serve
// creates right after the license service's first start (cmd/alice): every installation that
// ever served has it.
const auditPlatformKeyCreated = "platform_key.created"

// Notice kinds of the installation record episodes: "<kind>:<installation id>:<n>". They only feed
// the license page; the episode state comes from the audit log (see lastEpisode).
const (
	noticeInstallationTampered = "installation_tampered"
	noticeInstallationRestored = "installation_restored"
)

// lastEpisode reads the latest tamper or restore audit event of installation id from the
// append-only, hash-chained audit log and returns whether an episode is open and its number
// (0 when there is none). The license_history notices are not used: the application role can
// insert there, so a forged notice must never suppress an audit. An event without an episode
// number was written by Phase 2 and counts as episode 1. The "record removed" event of a new
// installation is not an episode.
func lastEpisode(ctx context.Context, tx pgx.Tx, id string) (open bool, n int, legacy bool, err error) {
	var action string
	var episode *string
	err = tx.QueryRow(ctx, `SELECT action, details->>'episode' FROM audit_log
WHERE object_type = 'license' AND object_id = $1
  AND action IN ('license.installation_tampered', 'license.installation_restored')
  AND details->>'problem' IS DISTINCT FROM $2::text
ORDER BY seq DESC LIMIT 1`, id, problemInstallationMissing).Scan(&action, &episode)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, 0, false, nil
	}
	if err != nil {
		return false, 0, false, fmt.Errorf("read the installation episodes: %w", err)
	}
	n = 1
	legacy = episode == nil
	if episode != nil {
		if v, perr := strconv.Atoi(*episode); perr == nil && v > 0 {
			n = v
		}
	}
	return action == "license.installation_tampered", n, legacy, nil
}

// recordInstallationEpisode audits each tamper episode of the installation row once: an untrusted
// row with no open episode opens the next one (license.installation_tampered); a trusted row with
// an open episode closes it (license.installation_restored). The caller holds the license row
// lock, so two evaluations cannot both decide the same episode. The audit event is always
// written; the history notice (display only) may already exist, which is logged and ignored.
func (s *Service) recordInstallationEpisode(ctx context.Context, tx pgx.Tx, c computed, now time.Time) ([]audit.Event, error) {
	id := c.row.ID
	open, last, legacy, err := lastEpisode(ctx, tx, id)
	if err != nil {
		return nil, err
	}
	switch {
	case c.row.Tampered != "" && !open:
		n := strconv.Itoa(last + 1)
		d := map[string]string{"problem": c.row.Tampered, "installation_id": id, "episode": n}
		if err := s.insertEpisodeNotice(ctx, tx, now, noticeInstallationTampered, id, n, d); err != nil {
			return nil, err
		}
		s.log.Error("the installation record was changed outside Alice; the evaluation counts as ended and no license "+
			"file is used until the original record is restored", "problem", c.row.Tampered, "episode", n)
		return []audit.Event{{Actor: systemActor, Action: "license.installation_tampered", ObjectType: "license",
			ObjectID: id, Result: audit.Failure, Details: d}}, nil
	case c.row.Tampered == "" && open:
		n := strconv.Itoa(last)
		d := map[string]string{"installation_id": id, "episode": n}
		if legacy {
			// The episode was opened before the upgrade, by Phase 2 (its audit event has no episode
			// number). reason=upgrade says where the open episode came from, not why the record
			// matches again: the restore itself is the same as any other.
			d["reason"] = "upgrade"
		}
		if err := s.insertEpisodeNotice(ctx, tx, now, noticeInstallationRestored, id, n, d); err != nil {
			return nil, err
		}
		s.log.Info("the installation record matches its seal again; licenses count again", "episode", n)
		return []audit.Event{{Actor: systemActor, Action: "license.installation_restored", ObjectType: "license",
			ObjectID: id, Result: audit.Success, Details: d}}, nil
	}
	return nil, nil
}

// insertEpisodeNotice writes the display notice of an episode. An existing notice (a forged or
// repeated one) is logged and does not stop the audit event.
func (s *Service) insertEpisodeNotice(ctx context.Context, tx pgx.Tx, now time.Time, kind, id, n string, d map[string]string) error {
	inserted, err := insertHistory(ctx, tx, now, "notice", "", "", "", kind+":"+id+":"+n, d)
	if err != nil {
		return err
	}
	if !inserted {
		s.log.Warn("the installation notice already exists; the audit event is written anyway", "kind", kind, "episode", n)
	}
	return nil
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
