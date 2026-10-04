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
	"sync/atomic"
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

// Bounds of the lock gate and of each evaluation (AUD-02, R39 item 2).
const (
	// MaxEvaluationAge is how long the gate trusts the last successful evaluation, in process
	// uptime: after it, gated work is refused with ErrUnverified until an evaluation succeeds.
	// The evaluation runs hourly and a failed one is retried after 1, 2, 4, 8 minutes, then every
	// 10 minutes (jobs.MaxRetryGap); a failed hourly run never postpones a pending retry. So the
	// first success comes at most 10 minutes after a failure ends, and a failure never stops
	// changes when it ends within 2 h 50 min of the last successful evaluation (an outage of up
	// to 2 h 40 min right after one, of up to 1 h 50 min anywhere). A stalled evaluation is
	// visible the same morning.
	MaxEvaluationAge = 3 * time.Hour
	// defaultRowLockTimeout bounds every wait for the license row lock (lock_timeout), so a
	// session holding the row cannot stop evaluations, uploads and the shutdown save for ever.
	defaultRowLockTimeout = 30 * time.Second
	// tickTimeout bounds one evaluation, upload or shutdown save as a whole.
	tickTimeout = 2 * time.Minute
	// kickMinGap and kickMaxGap bound how often the gate starts an evaluation of its own when it
	// refuses on its own clock (ErrLockDue, ErrUnverified): at most once a minute, doubling after
	// each failed one up to 10 minutes.
	kickMinGap = time.Minute
	kickMaxGap = 10 * time.Minute
)

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
	// RowLockTimeout bounds each wait for the license row lock; 0 = 30 s (AUD-02). Tests lower it.
	RowLockTimeout time.Duration
}

// Snapshot is the license state as of the last evaluation. The API and the gate read it
// without touching the database.
type Snapshot struct {
	InstallationID string
	InstalledAt    time.Time
	Eval           Evaluation
	Reading        Reading
	Tampered       bool // a stored file no longer verifies (L-49)
	// InstallationTampered: the installation row does not match its seal, so it is not
	// trusted: the evaluation counts as ended and no license file counts (B1, spec §16.1).
	InstallationTampered bool
	Targets              int
	Ready                bool // Start has completed
	// EvaluatedUptime is the process uptime (Config.Uptime) when this snapshot was evaluated; the
	// gate measures the time since the evaluation with it, never with the wall clock (AUD-02).
	EvaluatedUptime time.Duration
	// Unverified is set by Service.Snapshot when no evaluation has succeeded for MaxEvaluationAge:
	// the evaluated fields describe the state at the last successful evaluation.
	Unverified bool
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

	// evalMu (a semaphore, taken with lockEval so a waiter can give up with its context) is held
	// by Tick, uploads and Shutdown from before their transaction until the guard and the
	// snapshot are published after the commit, so no other evaluation in this process sees a
	// guard its transaction may still roll back.
	evalMu chan struct{}

	mu    sync.Mutex // guards guard and snap
	guard Guard
	snap  Snapshot

	rowLockTimeout time.Duration
	staleLogged    atomic.Bool // the "could not be checked" error was logged for the current stale period

	// The gate's own evaluation (kick): single-flight, rate-limited on uptime, with backoff.
	kickMu      sync.Mutex
	kickRunning bool
	kickClosed  bool
	kickNext    time.Duration // uptime before which no kick starts
	kickGap     time.Duration // the gap after the next kick; 0 = kickMinGap
	kickWG      sync.WaitGroup

	uploadCommitted func() // tests only: runs between an upload's commit and its evaluation
}

// New builds the service. Call Start before using it.
func New(c Config) *Service {
	s := &Service{
		pool: c.Pool, keyring: c.Keyring, audit: c.Audit, clock: c.Clock, uptime: c.Uptime, keys: c.Keys,
		buildTime: c.BuildTime.UTC(), notifier: c.Notifier, targets: c.Targets, log: c.Log, codec: NewHWMCodec(c.Keyring),
		rowLockTimeout: c.RowLockTimeout, evalMu: make(chan struct{}, 1),
	}
	if s.rowLockTimeout <= 0 {
		s.rowLockTimeout = defaultRowLockTimeout
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

// Snapshot returns the state as of the last successful evaluation, with Unverified computed now.
func (s *Service) Snapshot() Snapshot {
	s.mu.Lock()
	snap := s.snap
	s.mu.Unlock()
	snap.Unverified = snap.Ready && s.sinceEvaluation(snap) > MaxEvaluationAge
	return snap
}

// sinceEvaluation is the process uptime since snap was evaluated (never negative). Uptime is
// monotonic: setting the wall clock back or forward does not move it.
func (s *Service) sinceEvaluation(snap Snapshot) time.Duration {
	return max(0, s.uptime.Elapsed()-snap.EvaluatedUptime)
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

// Allow is the single lock-mode gate (spec §8.6, R9): the API guard calls it for gated routes,
// the scheduler before every task, the job runner before every claim and run, and
// CheckCanAddTarget before every target insert. It does not trust the last evaluation blindly
// (AUD-02): see allowIn.
func (s *Service) Allow(c Class) error {
	snap := s.Snapshot()
	err := allowIn(snap, c, s.sinceEvaluation(snap))
	s.afterRefusal(snap, err)
	return err
}

// afterRefusal logs the first ErrUnverified of a stale period and, for a refusal no evaluation
// decided (ErrUnverified, ErrLockDue), starts an evaluation so a healthy system confirms or
// refutes it within seconds instead of at the next hourly run.
func (s *Service) afterRefusal(snap Snapshot, err error) {
	if !snap.Ready || err == nil || ConfirmedLock(err) || !errors.Is(err, ErrLocked) {
		return
	}
	if errors.Is(err, ErrUnverified) && s.staleLogged.CompareAndSwap(false, true) {
		s.log.Error("the license could not be checked for more than "+MaxEvaluationAge.String()+
			"; changes to managed systems are paused until an evaluation succeeds (check the database and "+
			"sessions holding the license row)", "last_checked", snap.Reading.Wall.Format(time.RFC3339))
	}
	s.kick()
}

// kick starts one evaluation in the background unless one it started is still running, the
// service is closed, or the last one started less than the current gap ago (one minute, doubled
// after each failure up to an hour; reset by any successful evaluation). The evaluation does not
// depend on the request that caused it and is bounded like every Tick.
func (s *Service) kick() {
	s.kickMu.Lock()
	now := s.uptime.Elapsed()
	if s.kickClosed || s.kickRunning || now < s.kickNext {
		s.kickMu.Unlock()
		return
	}
	gap := max(s.kickGap, kickMinGap)
	s.kickRunning, s.kickNext = true, now+gap
	s.kickWG.Add(1)
	s.kickMu.Unlock()
	go func() {
		defer s.kickWG.Done()
		err := s.Tick(context.Background())
		s.kickMu.Lock()
		defer s.kickMu.Unlock()
		s.kickRunning = false
		if err != nil {
			s.kickGap = min(2*gap, kickMaxGap)
			s.log.Warn("the license evaluation started by the gate failed; it is tried again later",
				"error_type", fmt.Sprintf("%T", err))
		}
	}()
}

// evaluated resets the kick's backoff after a successful evaluation.
func (s *Service) evaluated() {
	s.staleLogged.Store(false)
	s.kickMu.Lock()
	s.kickGap = 0
	s.kickMu.Unlock()
}

// stopKicks stops the gate from starting evaluations of its own.
func (s *Service) stopKicks() {
	s.kickMu.Lock()
	s.kickClosed = true
	s.kickMu.Unlock()
}

// Close stops the gate's own evaluations and waits for a running one (at most tickTimeout).
func (s *Service) Close() {
	s.stopKicks()
	s.kickWG.Wait()
}

// allowIn is the gate decision: a pure function of the last successfully evaluated snapshot,
// the uptime since that evaluation and the bounds. Work of ClassAlways is never refused;
// otherwise, in this order:
//   - not started (no evaluation yet), or no evaluation for more than MaxEvaluationAge:
//     ErrUnverified. Nothing about the state is known, so nothing is decided from it: the job
//     runner pauses queued work and resumes it after the next successful evaluation.
//   - the evaluated phase locks: ErrLocked (a confirmed lock).
//   - the evaluated effective time advanced by the uptime since reaches LocksAt: ErrLockDue.
//     This is the gate's own estimate and can be wrong: a pending license may have started in
//     between, or a renewal may have been uploaded in another process. Gated work is refused
//     (fail closed), but nothing lasting is decided until an evaluation confirms the lock.
func allowIn(snap Snapshot, c Class, since time.Duration) error {
	if !c.Valid() {
		return ErrUnclassified
	}
	if c == ClassAlways {
		return nil
	}
	if !snap.Ready || since > MaxEvaluationAge {
		return ErrUnverified
	}
	if snap.Eval.Locked() {
		return ErrLocked
	}
	if !snap.Eval.LocksAt.IsZero() && !snap.Reading.Effective.Add(since).Before(snap.Eval.LocksAt) {
		return ErrLockDue
	}
	return nil
}

// CheckCanAddTarget must be called in the transaction that inserts a target, before the
// insert (spec L-74, L-79): it serializes concurrent adds, counts the targets and then
// decides from one snapshot, read after the count: ErrLocked through the gate, or a
// *TargetLimitError. Exceeding the limit never locks (R30).
func (s *Service) CheckCanAddTarget(ctx context.Context, tx pgx.Tx) error {
	if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1)", targetLimitLock); err != nil {
		return fmt.Errorf("lock the target count: %w", err)
	}
	n, err := s.targets.CountTargets(ctx, tx)
	if err != nil {
		return fmt.Errorf("count targets: %w", err)
	}
	snap := s.Snapshot()
	if err := allowIn(snap, ClassChange, s.sinceEvaluation(snap)); err != nil {
		s.afterRefusal(snap, err)
		return err
	}
	if limit := snap.Eval.MaxTargets; n >= limit {
		return &TargetLimitError{Max: limit, Used: n}
	}
	return nil
}

// Installed reports whether any license file was ever accepted (the wizard's license step).
// It reads through q, so the caller's transaction covers the answer.
func (s *Service) Installed(ctx context.Context, q db.Querier) (bool, error) {
	var ok bool
	if err := q.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM license_files)").Scan(&ok); err != nil {
		return false, fmt.Errorf("read license files: %w", err)
	}
	return ok, nil
}

// Start creates the installation on the first start (installation ID and timestamp, spec
// §16.4), loads the time record from both stores, restores a held clock jump, and runs the
// first evaluation. Problems with the time record of an existing installation are audited.
func (s *Service) Start(ctx context.Context) error {
	if err := s.lockEval(ctx); err != nil {
		return err
	}
	defer s.unlockEval()
	return s.startLocked(ctx)
}

// lockEval takes evalMu, or gives up when ctx ends first.
func (s *Service) lockEval(ctx context.Context) error {
	select {
	case s.evalMu <- struct{}{}:
		return nil
	case <-ctx.Done():
		return fmt.Errorf("license: wait for a running evaluation: %w", ctx.Err())
	}
}

func (s *Service) unlockEval() { <-s.evalMu }

// Restart runs reset while no evaluation, upload or shutdown is in flight, then starts the
// service again (a fresh installation if reset emptied the license tables). It exists for
// the e2e full reset: an evaluation in flight could otherwise write the old time record back
// after reset removed it. Nothing else may evaluate between reset and the restart.
func (s *Service) Restart(ctx context.Context, reset func(context.Context) error) error {
	if err := s.lockEval(ctx); err != nil {
		return err
	}
	defer s.unlockEval()
	if err := reset(ctx); err != nil {
		return err
	}
	return s.startLocked(ctx)
}

// startLocked is Start with evalMu held by the caller.
func (s *Service) startLocked(ctx context.Context) error {
	fresh, err := s.ensureInstallation(ctx)
	if err != nil {
		return err
	}
	if err := s.sealUnsealed(ctx); err != nil {
		return err
	}
	row, err := s.loadInstallation(ctx, s.pool, false)
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
	s.publishGuard(g)
	if !fresh && (len(damaged) > 0 || hwm.best == nil) {
		if err := s.recordTimeRecordProblem(ctx, damaged, hwm.best == nil); err != nil {
			return err
		}
	}
	if s.keys.Len() == 0 {
		s.log.Error("this build embeds no license verification key, so no license file can be installed; " +
			"the evaluation still works (see docs/vendor/licensing-vendor.md)")
	}
	return s.tickLocked(ctx)
}

// Shutdown observes the clock and saves the time record (spec §16.5: also on graceful shutdown).
// The gate starts no evaluation of its own afterwards. When an evaluation still runs when ctx
// ends, Shutdown returns without saving: that evaluation saves the time record itself, and
// otherwise the record of the last evaluation (at most an hour old) stays.
func (s *Service) Shutdown(ctx context.Context) error {
	s.stopKicks()
	if err := s.lockEval(ctx); err != nil {
		return err
	}
	defer s.unlockEval()
	ctx, cancel := context.WithTimeout(ctx, tickTimeout) // evalMu is never held without a bound
	defer cancel()
	g := s.working()
	err := db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := s.loadInstallation(ctx, tx, true); err != nil {
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
	if _, err := s.loadInstallation(ctx, s.pool, false); err != nil {
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
// (not a key this build no longer trusts) marks the snapshot as tampered. An installation row
// that does not match its seal is evaluated as an ended evaluation without any file.
func (s *Service) compute(ctx context.Context, q db.Querier, reading Reading, forUpdate bool) (computed, error) {
	row, err := s.loadInstallation(ctx, q, forUpdate)
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
		if row.Tampered != "" {
			break // no file counts for an untrusted installation, and none is reported as changed
		}
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
			InstallationID:       row.ID,
			InstalledAt:          row.InstalledAt,
			Eval:                 evaluateInstallation(reading.Effective, row, installed),
			Reading:              reading,
			Tampered:             len(damaged) > 0,
			InstallationTampered: row.Tampered != "",
			Targets:              targets,
			Ready:                true,
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
