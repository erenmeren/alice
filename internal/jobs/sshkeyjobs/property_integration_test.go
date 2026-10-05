//go:build integration

package sshkeyjobs_test

import (
	"fmt"
	"math/rand/v2"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/providers"
	"alice/internal/providers/fake"
	"alice/internal/sshkeys"
)

// The §26.8 exit criterion: for any failure injected at any step, the old key remains wherever the new key
// was not freshly verified. A scenario is a rotation of a key placed at 1, 2 or 3 locations on two servers
// (web-01: deploy, app; db-01: deploy), plus a file shared by two users of web-01 that the planner skips
// (S10), overlap 60 minutes. A schedule injects events at world calls (Add, Remove and VerifyKeyLogin of
// the fake key world, numbered from 1): a fault of every kind (FaultLateWrite included, S3), a license
// lock (renewed later), a process kill, a lost lease (the job is reaped and run again while its first run
// is still in its call), an Administrator's Continue, Finish now, Keep old or Stop and undo, and a
// forward clock step (S13). After the schedule the system settles and invariants I1-I6 are checked
// against the world's files and event log, never the store's belief.
//
// The default run covers every event kind at every call index of the fault-free runs of 1, 2 and 3
// locations, plus randomSchedules random multi-event schedules from the seed. ALICE_PROPERTY_SEED sets
// the seed, ALICE_PROPERTY_RANDOM the number of random schedules (a longer mode: e.g. 2000).

const sharedFile = "/etc/ssh/keys/shared"

// defaultRandomSchedules is the number of random schedules of the default run.
const defaultRandomSchedules = 60

// faultKinds are the world faults by name.
var faultKinds = map[string]fake.Fault{
	"refuse": fake.FaultRefuse, "unreachable": fake.FaultUnreachable, "after_write": fake.FaultAfterWrite,
	"file_changed": fake.FaultFileChanged, "unprovable": fake.FaultUnprovable, "hang": fake.FaultHang, "late_write": fake.FaultLateWrite,
}

// eventKinds are every kind a schedule injects at a call.
var eventKinds = []string{"refuse", "unreachable", "after_write", "file_changed", "unprovable", "hang", "late_write",
	"lock", "kill", "lease", "continue", "finish_now", "keep_old", "abort", "clock"}

// event happens when the world answers its at-th call (before the call's own effect, which then follows;
// a kill happens right after the call returned).
type event struct {
	at   int
	kind string
}

type schedule struct {
	locs       int
	events     []event
	renewAfter time.Duration                                   // how long a lock lasts before the renewal
	step       time.Duration                                   // a "clock" event moves the clock forward this far
	keepOld    bool                                            // a waiting decision is answered with Keep old (else its deadline passes)
	killAt     string                                          // a kill at this point of the killer (crash tests)
	fault      func(p fake.FaultPoint, s *scenario) fake.Fault // a fault of every matching call (crash tests)
}

func (s schedule) String() string {
	parts := make([]string, 0, len(s.events))
	for _, ev := range s.events {
		parts = append(parts, ev.kind+"@"+strconv.Itoa(ev.at))
	}
	return fmt.Sprintf("locs=%d %s renew=%s step=%s keep_old=%t", s.locs, strings.Join(parts, ","), s.renewAfter, s.step, s.keepOld)
}

// fileKey is one world file.
type fileKey struct {
	target uuid.UUID
	path   string
}

// scenario is one run of a schedule and what the invariants need.
type scenario struct {
	e         *env
	sched     schedule
	runID     uuid.UUID
	old       sshkeys.ManagedKey
	web, db   uuid.UUID
	files     []fileKey
	startFile map[fileKey][]string
}

// placements are the scenario's rotated locations, in the order runs of 1, 2 and 3 locations use them.
func (s *scenario) placements() []struct {
	target uuid.UUID
	user   string
} {
	return []struct {
		target uuid.UUID
		user   string
	}{{s.web, "deploy"}, {s.db, "deploy"}, {s.web, "app"}}[:s.sched.locs]
}

// runScenario builds the world, starts the rotation, applies the schedule and settles.
func runScenario(t *testing.T, sched schedule) *scenario {
	t.Helper()
	e := newEnv(t)
	s := &scenario{e: e, sched: sched, startFile: map[fileKey][]string{}}
	shared := []providers.UserKeyFiles{{OSUser: "deploy2", Files: []string{sharedFile}, Complete: true},
		{OSUser: "backup", Files: []string{sharedFile}, Complete: true}}
	s.web, s.db = e.server("web-01", shared...), e.server("db-01")
	for _, target := range []uuid.UUID{s.web, s.db} {
		for _, u := range serverUsers {
			s.files = append(s.files, fileKey{target, keyFile(u)})
			if u != fake.ConnectionAccount {
				e.world.Put(target, u, keyFile(u), e.otherKeyLine(t)) // a key nobody rotates, in every file
			}
		}
	}
	e.world.Put(s.web, "deploy2", sharedFile, e.otherKeyLine(t)) // the owner first
	e.world.Put(s.web, "backup", sharedFile, e.world.Lines(s.web, sharedFile)...)
	s.files = append(s.files, fileKey{s.web, sharedFile})
	s.old = e.generate("ci")
	for _, pl := range s.placements() {
		e.place(s.old, pl.target, pl.user)
	}
	e.placeIn(s.old, s.web, "deploy2", sharedFile, "")
	e.placeIn(s.old, s.web, "backup", sharedFile, "")
	p := e.policy(s.old.ID, 0)
	_, err := e.db.Owner.Exec(e.ctx, "UPDATE rotation_policies SET overlap_minutes = 60 WHERE id = $1", p.ID)
	require.NoError(t, err)
	for _, f := range s.files {
		s.startFile[f] = e.world.Lines(f.target, f.path)
	}
	s.install()
	r := e.runNow(e.reloadPolicy(p.ID))
	s.runID = r.ID
	for _, l := range r.Locations {
		if l.FilePath == sharedFile {
			require.Equal(t, sshkeys.LocSkipped, l.State, "S10: a shared file is skipped")
		}
	}
	s.settle()
	return s
}

func (e *env) reloadPolicy(id uuid.UUID) sshkeys.Policy {
	e.t.Helper()
	p, err := e.keys.Policy(e.ctx, id)
	require.NoError(e.t, err)
	return p
}

// install puts the schedule's events into the world's fault hook (and arms the killer).
func (s *scenario) install() {
	e := s.e
	done := make([]bool, len(s.sched.events))
	if s.sched.killAt != "" {
		e.setKiller(newKiller(s.sched.killAt))
	}
	for _, ev := range s.sched.events {
		if ev.kind == "kill" {
			e.setKiller(&killer{points: map[string]bool{}, afterCall: ev.at})
		}
	}
	e.world.SetFault(func(p fake.FaultPoint) fake.Fault {
		f := fake.FaultNone
		for i, ev := range s.sched.events {
			if ev.at != p.N || done[i] {
				continue
			}
			done[i] = true
			switch ev.kind {
			case "lock":
				e.gate.lock()
			case "lease":
				s.loseLease()
			case "continue":
				_ = e.keys.Continue(e.ctx, e.admin, s.runID)
			case "finish_now":
				_ = e.keys.FinishNow(e.ctx, e.admin, s.runID)
			case "abort":
				_ = e.keys.Abort(e.ctx, e.admin, s.runID)
			case "keep_old":
				s.keepOld()
			case "clock":
				e.clock.Advance(s.sched.step)
			case "kill":
			default:
				f = faultKinds[ev.kind]
			}
		}
		if f == fake.FaultNone && s.sched.fault != nil {
			f = s.sched.fault(p, s)
		}
		return f
	})
}

// loseLease: the job's lease expires while its call is still running; the reaper takes the job back and a
// second run of it (with whatever else is due) goes to the end before the first run's call returns.
func (s *scenario) loseLease() {
	e := s.e
	e.clock.Advance(46 * time.Second)
	_, err := e.runner.Reap(e.ctx)
	require.NoError(e.t, err)
	e.drain()
}

// keepOld answers a waiting decision with Keep old for every location Alice could not test.
func (s *scenario) keepOld() {
	e := s.e
	r, err := e.keys.Rotation(e.ctx, s.runID)
	if err != nil {
		return
	}
	var ids []uuid.UUID
	for _, l := range r.Locations {
		if l.State == sshkeys.LocUnverifiable {
			ids = append(ids, l.ID)
		}
	}
	if len(ids) > 0 {
		_ = e.keys.KeepOld(e.ctx, e.admin, s.runID, ids)
	}
}

// settle drives the system until the run ended (F9, A11): jobs run (in a dying process while a kill is
// armed, then Alice restarts), a lock lasts renewAfter of clock and is then renewed, a paused run is
// continued after the sweep announced the renewal, a waiting decision is answered or its deadline is
// reached, and otherwise the clock moves an hour and the sweep runs.
func (s *scenario) settle() {
	e := s.e
	for range 400 {
		if k := e.killer.Load(); k != nil {
			e.drainDying()
			if k.firedAt() != "" {
				e.setKiller(nil)
				e.restart()
				continue
			}
		} else {
			e.drain()
		}
		r := e.run(s.runID)
		if finished(r.Status) && e.liveLocationJobs() == 0 && e.killer.Load() == nil {
			break
		}
		switch {
		case e.gate.locked.Load():
			e.sweep() // the run pauses (L-83, L-85) where it must
			e.drain()
			e.clock.Advance(s.sched.renewAfter)
			e.gate.unlock()
		case r.PausedLicense:
			e.sweep() // the renewal notice first (S6)
			_ = e.keys.Continue(e.ctx, e.admin, s.runID)
		case r.AwaitingDecision && r.DecisionDueAt != nil:
			if s.sched.keepOld {
				s.keepOld()
			}
			if r := e.run(s.runID); r.AwaitingDecision && r.DecisionDueAt != nil && e.clock.Now().Before(*r.DecisionDueAt) {
				e.clock.Set(*r.DecisionDueAt)
			}
			e.sweep()
		default:
			e.clock.Advance(time.Hour)
			e.sweep()
		}
	}
	// Late writes that are still due land now (a stalled helper writes until its budget ends).
	e.clock.Advance(time.Hour)
	e.world.PendingLate()
}

// assertInvariants checks I1-I6 against the world.
func (s *scenario) assertInvariants(t *testing.T) {
	t.Helper()
	e := s.e
	r := e.run(s.runID)
	oldFP, newFP := s.old.Fingerprint, r.NewFingerprint
	// I6: the run ended (every lock was renewed and every decision answered).
	require.True(t, finished(r.Status), "I6: the run ends; it is %s", r.Status)
	t.Logf("outcome %s %s", r.Status, r.ResultCode)
	// I1: every removal of the old key followed an accepted login with the new key.
	e.assertEveryRemovalFollowedAFreshLogin(t, oldFP, newFP)
	// I2, I3: only the new key is added, only the old or the new key is removed, never Alice's own key,
	// the new key only where this run added it; only the rotated locations' files change.
	rotated := map[fileKey]bool{}
	for _, l := range r.Locations {
		if l.State != sshkeys.LocSkipped {
			rotated[fileKey{l.TargetID, l.FilePath}] = true
		}
	}
	added := map[fileKey]bool{}
	for _, ev := range e.world.Events() {
		if !ev.Changed {
			continue
		}
		fk := fileKey{ev.Target, ev.FilePath}
		assert.True(t, rotated[fk], "I3: %s changed %s, which is no rotated location", ev.Method, ev.FilePath)
		switch ev.Method {
		case "AddAuthorizedKey":
			assert.Equal(t, newFP, ev.Fingerprint, "I3: only the new key is added")
			added[fk] = true
		case "RemoveAuthorizedKey":
			assert.NotEqual(t, e.platform.Fingerprint, ev.Fingerprint, "I2: Alice's own key is never removed")
			assert.Contains(t, []string{oldFP, newFP}, ev.Fingerprint, "I3: no other key is removed")
			if ev.Fingerprint == newFP {
				assert.True(t, added[fk], "I3: the new key is removed only where this run added it")
			}
		}
	}
	for _, f := range s.files {
		assert.Equal(t, others(t, s.startFile[f], oldFP, newFP), others(t, e.world.Lines(f.target, f.path), oldFP, newFP),
			"I2: every line holding neither key is byte-equal in %s", f.path)
		if f.path == keyFile(fake.ConnectionAccount) || !rotated[f] {
			assert.Equal(t, s.startFile[f], e.world.Lines(f.target, f.path), "I2: %s is untouched", f.path)
		}
	}
	// I4, I5: the record matches the files.
	for _, l := range r.Locations {
		oldHere, newHere := e.world.Has(l.TargetID, l.FilePath, oldFP), e.world.Has(l.TargetID, l.FilePath, newFP)
		if l.State == sshkeys.LocRemoved {
			assert.False(t, oldHere, "I5: %s removed, but the old key is in %s", l.OSUser, l.FilePath)
		} else {
			assert.True(t, oldHere, "I4: the old key stays at %s:%s (%s, %s)", l.TargetName, l.FilePath, l.State, l.ErrorCode)
		}
		if l.State == sshkeys.LocUndone || l.State == sshkeys.LocCancelled || l.State == sshkeys.LocSkipped || l.State == sshkeys.LocPlanned {
			assert.False(t, newHere, "I5: %s is %s, but the new key is in %s", l.OSUser, l.State, l.FilePath)
		}
		if newHere {
			assert.True(t, l.NewLocationID != nil || l.State == sshkeys.LocUndoFailed,
				"I4: the new key at %s:%s (%s) has no record", l.TargetName, l.FilePath, l.State)
		}
		if l.VerifiedAt != nil {
			assert.NotNil(t, l.NewLocationID, "I5 (S4): a verified line is recorded in the inventory")
		}
		if r.Status == sshkeys.StatusCompleted && l.State != sshkeys.LocSkipped {
			assert.True(t, newHere, "a completed run left the new key at %s:%s", l.TargetName, l.FilePath)
		}
		if r.Status == sshkeys.StatusAborted {
			assert.False(t, newHere, "an aborted run left the new key at %s:%s", l.TargetName, l.FilePath)
		}
	}
}

// others are the lines that hold neither key.
func others(t *testing.T, lines []string, fps ...string) []string {
	out := []string{}
	for _, l := range lines {
		if !slices.Contains(fps, lineFP(t, l)) {
			out = append(out, l)
		}
	}
	return out
}

// baselineCalls are the world calls of the fault-free run of 1, 2 and 3 locations (4 per location: add,
// login, re-check, removal).
func baselineCalls(locs int) int { return 4 * locs }

// schedules are every event kind at every call index for 1, 2 and 3 locations, then random schedules of up
// to three events (call indexes up to two past the fault-free run's) from the seed.
func schedules(seed uint64, random int) []schedule {
	var out []schedule
	for locs := 1; locs <= 3; locs++ {
		for at := 1; at <= baselineCalls(locs); at++ {
			for _, kind := range eventKinds {
				renew := time.Hour
				if at%2 == 0 {
					renew = 20 * 24 * time.Hour // L-84: a renewal after 20 days
				}
				out = append(out, schedule{locs: locs, events: []event{{at, kind}}, renewAfter: renew, step: 2 * time.Hour, keepOld: at%2 == 1})
			}
		}
	}
	rng := rand.New(rand.NewPCG(seed, seed^0x9e3779b97f4a7c15))
	for range random {
		locs := 1 + rng.IntN(3)
		s := schedule{locs: locs, renewAfter: []time.Duration{time.Hour, 20 * 24 * time.Hour}[rng.IntN(2)],
			step: []time.Duration{2 * time.Hour, 30 * 24 * time.Hour}[rng.IntN(2)], keepOld: rng.IntN(2) == 0}
		for range 1 + rng.IntN(3) {
			s.events = append(s.events, event{at: 1 + rng.IntN(baselineCalls(locs)+2), kind: eventKinds[rng.IntN(len(eventKinds))]})
		}
		out = append(out, s)
	}
	return out
}

func propertySeed(t *testing.T) (uint64, int) {
	seed, random := uint64(20261005), defaultRandomSchedules
	if v := os.Getenv("ALICE_PROPERTY_SEED"); v != "" {
		n, err := strconv.ParseUint(v, 10, 64)
		require.NoError(t, err)
		seed = n
	}
	if v := os.Getenv("ALICE_PROPERTY_RANDOM"); v != "" {
		n, err := strconv.Atoi(v)
		require.NoError(t, err)
		random = n
	}
	return seed, random
}

func TestOldKeyRemainsUnderAnyInjectedFailure(t *testing.T) {
	seed, random := propertySeed(t)
	t.Logf("seed %d, %d random schedules (ALICE_PROPERTY_SEED, ALICE_PROPERTY_RANDOM)", seed, random)
	for locs := 1; locs <= 3; locs++ {
		base := runScenario(t, schedule{locs: locs, renewAfter: time.Hour, step: time.Hour})
		require.Equal(t, sshkeys.StatusCompleted, base.e.run(base.runID).Status, "the fault-free run completes")
		require.Equal(t, baselineCalls(locs), base.e.worldCalls(), "the fault-free run's calls")
		base.assertInvariants(t)
	}
	for i, sched := range schedules(seed, random) {
		t.Run(fmt.Sprintf("%03d/%s", i, strings.ReplaceAll(sched.String(), " ", "_")), func(t *testing.T) {
			t.Parallel()
			t.Cleanup(func() {
				if t.Failed() {
					t.Logf("reproduce: ALICE_PROPERTY_SEED=%d, schedule %d: %s", seed, i, sched)
				}
			})
			runScenario(t, sched).assertInvariants(t)
		})
	}
}
