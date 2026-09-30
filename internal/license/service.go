package license

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"alice/internal/audit"
	"alice/internal/platform/clock"
	"alice/internal/platform/db"
	"alice/internal/secrets"
)

// Notifier queues an email to every Administrator inside the caller's transaction. It is
// implemented by notify.AdminNotifier (license may not import notify, spec §5.4).
type Notifier interface {
	NotifyAdmins(ctx context.Context, tx pgx.Tx, template string, params map[string]string) error
}

// TargetCounter counts managed targets. Phase 3 implements it over the targets table.
type TargetCounter interface {
	CountTargets(ctx context.Context, q db.Querier) (int, error)
}

// NoTargets is the Phase 2 counter: there is no targets table yet (spec §26.4 stub).
type NoTargets struct{}

// CountTargets implements TargetCounter.
func (NoTargets) CountTargets(context.Context, db.Querier) (int, error) { return 0, nil }

// ErrNoInstallation means Alice has never started on this database.
var ErrNoInstallation = errors.New("license: Alice has not been started on this database yet")

// targetLimitLock serializes "count targets, then insert one" across transactions (L-74).
const targetLimitLock int64 = 7160927315633811302

var systemActor = audit.SystemActor("license")

// Config holds the service dependencies.
type Config struct {
	Pool      *pgxpool.Pool
	Keyring   *secrets.Keyring
	Audit     *audit.Log
	Clock     clock.Clock
	Uptime    clock.Monotonic
	Keys      KeySet
	StateDir  string    // directory of the HWM file; "" = settings only (tests)
	BuildTime time.Time // the HWM never falls below the build time; zero when unknown
	Notifier  Notifier  // nil = no emails
	Targets   TargetCounter
	Log       *slog.Logger
}

// Snapshot is the license state as of the last evaluation. The API and the gate read it
// without touching the database.
type Snapshot struct {
	InstallationID string
	InstalledAt    time.Time
	Eval           Evaluation
	Reading        Reading
	Tampered       bool // a stored file no longer verifies (L-49)
	Targets        int
	Ready          bool // Start has completed
}

// Service is the license module. Every path that changes the license state (upload, Tick,
// Shutdown) holds evalMu and then the license row lock, so evaluations, snapshot updates and
// time record saves happen in one order, within this process and across processes.
type Service struct {
	pool      *pgxpool.Pool
	keyring   *secrets.Keyring
	audit     *audit.Log
	clock     clock.Clock
	uptime    clock.Monotonic
	keys      KeySet
	buildTime time.Time
	notifier  Notifier
	targets   TargetCounter
	log       *slog.Logger
	codec     HWMCodec
	hwmFile   *FileHWMStore // nil without a state directory

	// evalMu is held by Tick, uploads and Shutdown from before their transaction until the
	// guard and the snapshot are published after the commit, so no other evaluation in this
	// process sees a guard its transaction may still roll back.
	evalMu sync.Mutex

	mu    sync.Mutex // guards guard and snap
	guard Guard
	snap  Snapshot
}

// New builds the service. Call Start before using it.
func New(c Config) *Service {
	s := &Service{
		pool: c.Pool, keyring: c.Keyring, audit: c.Audit, clock: c.Clock, uptime: c.Uptime, keys: c.Keys,
		buildTime: c.BuildTime.UTC(), notifier: c.Notifier, targets: c.Targets, log: c.Log, codec: NewHWMCodec(c.Keyring),
	}
	if s.targets == nil {
		s.targets = NoTargets{}
	}
	if s.log == nil {
		s.log = slog.New(slog.DiscardHandler)
	}
	if c.StateDir != "" {
		s.hwmFile = &FileHWMStore{Path: filepath.Join(c.StateDir, HWMFileName)}
	}
	return s
}

// hwmStores returns the stores of the time record; the settings copy is read and written
// through q, so a caller's transaction covers it.
func (s *Service) hwmStores(q db.Querier) []HWMStore {
	stores := []HWMStore{SettingsHWMStore{Q: q, Clock: s.clock}}
	if s.hwmFile != nil {
		stores = append(stores, *s.hwmFile)
	}
	return stores
}

// Snapshot returns the state as of the last evaluation.
func (s *Service) Snapshot() Snapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.snap
}

// working returns a copy of the guard for one evaluation. The caller holds evalMu and
// publishes the copy with publishGuard once its transaction has committed.
func (s *Service) working() Guard {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.guard
}

// publishGuard installs the guard of a committed evaluation. The caller holds evalMu.
func (s *Service) publishGuard(g Guard) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.guard = g
}

// publish installs the guard and the snapshot of a committed evaluation. The caller holds evalMu.
func (s *Service) publish(g Guard, snap Snapshot) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.guard, s.snap = g, snap
}

// Allow is the single lock-mode gate (spec §8.6, R9): the API guard calls it for routes of
// ClassChange, the scheduler before every task, and CheckCanAddTarget before every target
// insert. It returns ErrLocked while the license or the evaluation has ended,
// ErrUnclassified for work without a class, and fails closed before Start has completed.
func (s *Service) Allow(c Class) error {
	if !c.Valid() {
		return ErrUnclassified
	}
	if c == ClassAlways {
		return nil
	}
	snap := s.Snapshot()
	if !snap.Ready || snap.Eval.Locked() {
		return ErrLocked
	}
	return nil
}

// CheckCanAddTarget must be called in the transaction that inserts a target, before the
// insert (spec L-74, L-79): it serializes concurrent adds, asks Allow, counts the targets
// and refuses with ErrLocked or a *TargetLimitError. Exceeding the limit never locks (R30).
func (s *Service) CheckCanAddTarget(ctx context.Context, tx pgx.Tx) error {
	if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1)", targetLimitLock); err != nil {
		return fmt.Errorf("lock the target count: %w", err)
	}
	if err := s.Allow(ClassChange); err != nil {
		return err
	}
	n, err := s.targets.CountTargets(ctx, tx)
	if err != nil {
		return fmt.Errorf("count targets: %w", err)
	}
	if limit := s.Snapshot().Eval.MaxTargets; n >= limit {
		return &TargetLimitError{Max: limit, Used: n}
	}
	return nil
}

// Installed reports whether any license file was ever accepted (the wizard's license step).
func (s *Service) Installed(ctx context.Context) (bool, error) {
	var ok bool
	if err := s.pool.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM license_files)").Scan(&ok); err != nil {
		return false, fmt.Errorf("read license files: %w", err)
	}
	return ok, nil
}

// Start creates the installation on the first start (installation ID and timestamp, spec
// §16.4), loads the time record from both stores, restores a held clock jump, and runs the
// first evaluation. Problems with the time record of an existing installation are audited.
func (s *Service) Start(ctx context.Context) error {
	fresh, err := s.ensureInstallation(ctx)
	if err != nil {
		return err
	}
	row, err := loadInstallation(ctx, s.pool, false)
	if err != nil {
		return err
	}
	hwm, damaged, err := s.readHWM(ctx)
	if err != nil {
		return err
	}
	var g Guard
	g.SetHWM(s.floor(hwm))
	if j, ok := decodeJump(row.ClockJump); ok {
		g.RestoreJump(j.Expected, j.Detected, s.uptime.Elapsed())
	}
	s.evalMu.Lock()
	s.publishGuard(g)
	s.evalMu.Unlock()
	if !fresh && (len(damaged) > 0 || hwm.best == nil) {
		if err := s.recordTimeRecordProblem(ctx, damaged, hwm.best == nil); err != nil {
			return err
		}
	}
	if s.keys.Len() == 0 {
		s.log.Error("this build embeds no license verification key, so no license file can be installed; " +
			"the evaluation still works (see docs/vendor/licensing-vendor.md)")
	}
	return s.Tick(ctx)
}

// Shutdown observes the clock and saves the time record (spec §16.5: also on graceful shutdown).
func (s *Service) Shutdown(ctx context.Context) error {
	s.evalMu.Lock()
	defer s.evalMu.Unlock()
	g := s.working()
	err := db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := loadInstallation(ctx, tx, true); err != nil {
			return err
		}
		g.Observe(s.clock.Now(), s.uptime.Elapsed())
		return s.persistHWM(ctx, tx, &g)
	})
	if err != nil {
		return err
	}
	s.publishGuard(g)
	return nil
}

// Inspect computes the current state without writing anything (alice license status).
func (s *Service) Inspect(ctx context.Context) (Snapshot, error) {
	if _, err := loadInstallation(ctx, s.pool, false); err != nil {
		return Snapshot{}, err
	}
	hwm, _, err := s.readHWM(ctx)
	if err != nil {
		return Snapshot{}, err
	}
	var g Guard
	g.SetHWM(s.floor(hwm))
	reading, _ := g.Observe(s.clock.Now(), s.uptime.Elapsed())
	c, err := s.compute(ctx, s.pool, reading, false)
	if err != nil {
		return Snapshot{}, err
	}
	return c.snap, nil
}

func (s *Service) ensureInstallation(ctx context.Context) (bool, error) {
	now := later(s.clock.Now().UTC(), s.buildTime).Truncate(time.Microsecond)
	if now.IsZero() {
		return false, errors.New("license: the system clock is not set")
	}
	tag, err := s.pool.Exec(ctx, `INSERT INTO license (id, installation_id, installed_at, state, updated_at)
VALUES (1, $1, $2, 'evaluation', $2) ON CONFLICT (id) DO NOTHING`, NewInstallationID(), now)
	if err != nil {
		return false, fmt.Errorf("create the installation: %w", err)
	}
	if tag.RowsAffected() == 1 {
		s.log.Info("new installation created; the 30-day evaluation starts now")
		return true, nil
	}
	return false, nil
}

// storedHWM is what the stores hold: the best valid record and the highest sequence seen.
type storedHWM struct {
	best   *HWMRecord // the later time, then the higher sequence; nil = no valid record
	maxSeq uint64     // the highest sequence of any valid record
}

// readHWM loads and decodes both stores (spec §16.5: the larger valid record wins; a
// replayed older copy loses, L-55). A copy that does not decode, or a file that cannot be
// read (a symlink, a special file), counts as damaged and the other copy is used; its
// store name is returned. Only a database error is fatal.
func (s *Service) readHWM(ctx context.Context) (storedHWM, []string, error) {
	var out storedHWM
	var damaged []string
	for _, st := range s.hwmStores(s.pool) {
		raw, err := st.Load(ctx)
		if err != nil {
			if _, isFile := st.(FileHWMStore); !isFile {
				return storedHWM{}, nil, err
			}
			s.log.Error("the time record file cannot be read; check the state volume", "error_type", fmt.Sprintf("%T", err))
			damaged = append(damaged, st.Name())
			continue
		}
		if raw == nil {
			continue
		}
		rec, err := s.codec.Decode(raw)
		if err != nil {
			damaged = append(damaged, st.Name())
			continue
		}
		out.maxSeq = max(out.maxSeq, rec.Seq)
		if out.best == nil || rec.At.After(out.best.At) || (rec.At.Equal(out.best.At) && rec.Seq > out.best.Seq) {
			out.best = &rec
		}
	}
	return out, damaged, nil
}

// floor is the starting HWM: the best record, never below the build time. Its sequence is
// the highest seen, so the next saved record outnumbers both copies.
func (s *Service) floor(h storedHWM) HWMRecord {
	if h.best == nil {
		return HWMRecord{At: s.buildTime, Seq: h.maxSeq}
	}
	return HWMRecord{At: later(h.best.At, s.buildTime), Seq: h.maxSeq}
}

// recordTimeRecordProblem audits damaged copies (L-54) and a lost time reference (L-53).
func (s *Service) recordTimeRecordProblem(ctx context.Context, damaged []string, missing bool) error {
	if missing {
		s.log.Warn("no valid time record was found; time starts again from the system clock (never before the build time)")
	}
	now := s.clock.Now().UTC()
	return db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		var events []audit.Event
		if len(damaged) > 0 {
			d := map[string]string{"problem": "hwm_damaged", "stores": strings.Join(damaged, ",")}
			if _, err := insertHistory(ctx, tx, now, "clock_anomaly", "", "", "", "", d); err != nil {
				return err
			}
			events = append(events, audit.Event{Actor: systemActor, Action: "clock.hwm_damaged",
				ObjectType: "license", Result: audit.Failure, Details: d})
		}
		if missing {
			d := map[string]string{"problem": "time_reference_reset"}
			if _, err := insertHistory(ctx, tx, now, "clock_anomaly", "", "", "", "", d); err != nil {
				return err
			}
			events = append(events, audit.Event{Actor: systemActor, Action: "clock.time_reference_reset",
				ObjectType: "license", Result: audit.Failure, Details: d})
		}
		for _, ev := range events {
			if _, err := s.audit.Append(ctx, tx, ev); err != nil {
				return err
			}
		}
		return nil
	})
}

// persistHWM saves the next record of g to every store; q carries the settings copy. A
// failing settings store is an error; a failing file is logged (the settings copy still
// protects the license). The caller holds the license row lock, so records are saved in order.
func (s *Service) persistHWM(ctx context.Context, q db.Querier, g *Guard) error {
	rec := g.NextRecord()
	raw, err := s.codec.Encode(rec)
	if err != nil {
		return err
	}
	for _, st := range s.hwmStores(q) {
		if err := st.Save(ctx, raw); err != nil {
			if _, isFile := st.(FileHWMStore); isFile {
				s.log.Error("the time record file cannot be written; check the state volume", "error_type", fmt.Sprintf("%T", err))
				continue
			}
			return fmt.Errorf("save the time record: %w", err)
		}
	}
	return nil
}

// peek computes a reading without changing the guard. With acceptJump, a held jump is
// treated as accepted (a correction license, L-61).
func (s *Service) peek(acceptJump bool) Reading {
	s.mu.Lock()
	g := s.guard
	s.mu.Unlock()
	if acceptJump {
		g.AcceptJump()
	}
	r, _ := g.Observe(s.clock.Now(), s.uptime.Elapsed())
	return r
}

type installationRow struct {
	ID          string
	InstalledAt time.Time
	State       Phase
	ClockJump   []byte
}

// loadInstallation reads the installation row. forUpdate takes the license row lock that
// serializes uploads, evaluations and time record saves. A stored ID that is not in
// canonical form, or a zero installation time, is refused rather than used.
func loadInstallation(ctx context.Context, q db.Querier, forUpdate bool) (installationRow, error) {
	sql := "SELECT installation_id, installed_at, state, clock_jump FROM license WHERE id = 1"
	if forUpdate {
		sql += " FOR UPDATE"
	}
	var r installationRow
	var state string
	err := q.QueryRow(ctx, sql).Scan(&r.ID, &r.InstalledAt, &state, &r.ClockJump)
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
	return r, nil
}

// jumpRecord is the persisted form of a held clock jump (license.clock_jump).
type jumpRecord struct {
	Expected time.Time `json:"expected"`
	Detected time.Time `json:"detected"`
}

func decodeJump(raw []byte) (jumpRecord, bool) {
	var j jumpRecord
	if len(raw) == 0 || json.Unmarshal(raw, &j) != nil || j.Expected.IsZero() {
		return jumpRecord{}, false
	}
	return j, true
}

type storedFile struct {
	ID         uuid.UUID
	Seq        int64
	SHA256     []byte
	Raw        []byte
	UploadedAt time.Time
}

func loadFiles(ctx context.Context, q db.Querier) ([]storedFile, error) {
	rows, err := q.Query(ctx, "SELECT id, seq, sha256, raw_file, uploaded_at FROM license_files ORDER BY seq")
	if err != nil {
		return nil, fmt.Errorf("read license files: %w", err)
	}
	defer rows.Close()
	var out []storedFile
	for rows.Next() {
		var f storedFile
		if err := rows.Scan(&f.ID, &f.Seq, &f.SHA256, &f.Raw, &f.UploadedAt); err != nil {
			return nil, fmt.Errorf("read license files: %w", err)
		}
		f.UploadedAt = f.UploadedAt.UTC()
		out = append(out, f)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read license files: %w", err)
	}
	return out, nil
}

// checkFile runs spec §16.3 steps 1-5 on a file: signature, payload and installation.
// installationID comes from loadInstallation (canonical), and Check validated the file's
// ID, so both values given to IDSuffix are canonical.
func (s *Service) checkFile(raw []byte, installationID string) (File, error) {
	if installationID == "" {
		return File{}, ErrNoInstallation // Start has not run: there is no ID to compare with
	}
	f, err := Check(raw, s.keys)
	if err != nil {
		return File{}, err
	}
	if f.Payload.InstallationID != installationID {
		return File{}, &WrongInstallationError{Expected: IDSuffix(installationID), Got: IDSuffix(f.Payload.InstallationID)}
	}
	return f, nil
}

// verifyStored re-verifies a stored file (L-49).
func (s *Service) verifyStored(f storedFile, installationID string) (Installed, error) {
	file, err := s.checkFile(f.Raw, installationID)
	if err != nil {
		return Installed{}, err
	}
	return Installed{Seq: f.Seq, KeyID: file.KeyID, Payload: file.Payload}, nil
}

// tamperedBy reports whether a stored file failing verification means its content was
// changed. A key this build no longer trusts is not tampering.
func tamperedBy(err error) bool {
	return !errors.Is(err, ErrUnknownKey) && !errors.Is(err, ErrRevokedKey)
}

// computed is one evaluation with the data it was made from.
type computed struct {
	snap      Snapshot
	row       installationRow
	files     []storedFile
	installed []Installed
	damaged   []damagedFile // stored files whose content no longer verifies
}

// damagedFile is a stored file that fails verification because its content changed.
type damagedFile struct {
	file storedFile
	err  error
}

// compute reads the installation and the files, re-verifies every file and evaluates the
// state at reading.Effective. Files that fail verification are left out; changed content
// (not a key this build no longer trusts) marks the snapshot as tampered.
func (s *Service) compute(ctx context.Context, q db.Querier, reading Reading, forUpdate bool) (computed, error) {
	row, err := loadInstallation(ctx, q, forUpdate)
	if err != nil {
		return computed{}, err
	}
	files, err := loadFiles(ctx, q)
	if err != nil {
		return computed{}, err
	}
	var installed []Installed
	var damaged []damagedFile
	for _, f := range files {
		in, err := s.verifyStored(f, row.ID)
		if err != nil {
			if tamperedBy(err) {
				damaged = append(damaged, damagedFile{file: f, err: err})
			}
			continue
		}
		installed = append(installed, in)
	}
	targets, err := s.targets.CountTargets(ctx, q)
	if err != nil {
		return computed{}, fmt.Errorf("count targets: %w", err)
	}
	return computed{
		snap: Snapshot{
			InstallationID: row.ID,
			InstalledAt:    row.InstalledAt,
			Eval:           Evaluate(reading.Effective, row.InstalledAt, installed),
			Reading:        reading,
			Tampered:       len(damaged) > 0,
			Targets:        targets,
			Ready:          true,
		},
		row: row, files: files, installed: installed, damaged: damaged,
	}, nil
}

// insertHistory writes one history row. A notice that exists already for the license is
// skipped (unique index); inserted reports whether the row was written.
func insertHistory(ctx context.Context, tx pgx.Tx, at time.Time, event, licenseID, from, to, notice string, details map[string]string) (bool, error) {
	if details == nil {
		details = map[string]string{}
	}
	raw, err := json.Marshal(details)
	if err != nil {
		return false, err
	}
	var n *string
	if notice != "" {
		n = &notice
	}
	tag, err := tx.Exec(ctx, `INSERT INTO license_history (id, at, event, license_id, from_state, to_state, notice, details)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8) ON CONFLICT DO NOTHING`, uuid.Must(uuid.NewV7()), at, event, licenseID, from, to, n, raw)
	if err != nil {
		return false, fmt.Errorf("write license history: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}
