//go:build integration

package sshkeyjobs_test

import (
	"fmt"
	"math/rand/v2"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
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
// (web-01: deploy, app; db-01: deploy), or a "from" variant (web-01: deploy, db-01: deploy, and db-01: app
// whose line holds from= so its login is refused: the run waits for a decision), plus a file shared by
// two users of web-01 that the planner skips (S10), overlap 60 minutes.
//
// A schedule injects events at world calls (Add, Remove, VerifyKeyLogin and ListKeys of the fake key
// world, numbered from 1): every world fault (FaultLateWrite of S3 and the listing's FaultUnread and
// FaultPartial included), a licence lock (renewed after 1 hour or 20 days), a process kill, a lost lease
// (the job is reaped and run again while its first run is still in its call), an Administrator's Stop and
// undo, and a clock step forward or back (S13, G14). Administrator decisions that need a settled state
// (Continue, Finish now, Keep old, Stop and undo) are injected at settle rounds, where they can take
// effect; the test counts where each one was accepted and fails unless each is accepted in the phases it
// exists for (review I4). Half of the schedules run on a clock that moves on every read (M11).
//
// Schedules: every call kind at every call index of the fault-free runs (1 and 2 locations and the from
// variant; 3 locations too in the full mode); a rollback trigger (the last verification refused) paired
// with every call kind at each following call (the undo path, review I6); a late write on an add paired
// with an unreachable call, a lock, Stop and undo or a kill at the next call; each decision at each of the
// first settle rounds; random schedules from the seed. After the schedule the system settles and the
// invariants are checked against the world's files and event log (and the harness's call log: time and
// licence state of every call), never the store's belief.
//
// ALICE_PROPERTY_SEED sets the seed, ALICE_PROPERTY_RANDOM the number of random schedules,
// ALICE_PROPERTY_FULL=1 adds the 3-location singles and the pairs of every variant.

const sharedFile = "/etc/ssh/keys/shared"

// defaultRandomSchedules is the number of random schedules of the default run.
const defaultRandomSchedules = 20

// parallelScenarios bounds the scenarios that run at once (each has its own database): the suite stays
// stable on a loaded machine (review I8).
const parallelScenarios = 4

// faultKinds are the world faults by name.
var faultKinds = map[string]fake.Fault{
	"refuse": fake.FaultRefuse, "unreachable": fake.FaultUnreachable, "after_write": fake.FaultAfterWrite,
	"file_changed": fake.FaultFileChanged, "unprovable": fake.FaultUnprovable, "hang": fake.FaultHang, "late_write": fake.FaultLateWrite,
	"unread": fake.FaultUnread, "partial": fake.FaultPartial,
}

// callKinds are the kinds a schedule injects at a world call.
var callKinds = []string{"refuse", "unreachable", "after_write", "file_changed", "unprovable", "hang", "late_write", "unread", "partial",
	"lock", "kill", "lease", "abort", "clock", "clock_back"}

// roundKinds are the Administrator's decisions a schedule injects at a settle round.
var roundKinds = []string{"continue", "finish_now", "keep_old", "abort"}

// event happens when the world answers its at-th call (before the call's own effect, which then follows;
// a kill happens right after the call returned), or, for a decision, after the jobs of settle round at.
type event struct {
	at   int
	kind string
}

// variant is the placement of the old key.
type variant string

const (
	oneLoc    variant = "1"
	twoLocs   variant = "2"
	threeLocs variant = "3"
	withFrom  variant = "from"
)

type schedule struct {
	v          variant
	events     []event                                         // at world calls
	rounds     []event                                         // decisions at settle rounds
	renewAfter time.Duration                                   // how long a lock lasts before the renewal
	step       time.Duration                                   // a "clock" event moves the clock forward this far
	keepOld    bool                                            // a waiting decision is answered with Keep old (else its deadline passes)
	ticking    bool                                            // the services' clock moves on every read
	killAt     string                                          // a kill at this point of the killer (crash tests)
	fault      func(p fake.FaultPoint, s *scenario) fake.Fault // a fault of every matching call (crash tests)
}

func (s schedule) String() string {
	parts := []string{}
	for _, ev := range s.events {
		parts = append(parts, ev.kind+"@"+strconv.Itoa(ev.at))
	}
	for _, ev := range s.rounds {
		parts = append(parts, ev.kind+"@r"+strconv.Itoa(ev.at))
	}
	return fmt.Sprintf("v=%s %s renew=%s step=%s keep_old=%t tick=%t", s.v, strings.Join(parts, ","), s.renewAfter, s.step, s.keepOld, s.ticking)
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
	accepted  []string // "<decision>@<run status>" of every decision that took effect
}

type placement struct {
	target  uuid.UUID
	user    string
	options string
}

// placements are the scenario's rotated locations.
func (s *scenario) placements() []placement {
	all := []placement{{s.web, "deploy", ""}, {s.db, "deploy", ""}, {s.web, "app", ""}}
	switch s.sched.v {
	case oneLoc:
		return all[:1]
	case twoLocs:
		return all[:2]
	case withFrom:
		return []placement{all[0], all[1], {s.db, "app", `from="10.0.0.0/8"`}}
	}
	return all
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
		e.placeWithOptions(s.old, pl.target, pl.user, pl.options)
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
	e.tick.on.Store(sched.ticking)
	r := e.runNow(e.reloadPolicy(p.ID))
	s.runID = r.ID
	for _, f := range s.files {
		// The run's new key is in no file before its first add: an undo can only ever remove a line the
		// run's own add put there (ruling on ownership, rotation side).
		require.False(t, e.world.Has(f.target, f.path, r.NewFingerprint), "the new key is nowhere before the run's add")
	}
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

// install puts the schedule's call events into the world's fault hook (and arms the killer).
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
	e.setFault(func(p fake.FaultPoint) fake.Fault {
		f := fake.FaultNone
		for i, ev := range s.sched.events {
			listing := ev.kind == "unread" || ev.kind == "partial"
			switch {
			case done[i]:
				continue
			case listing && (p.N < ev.at || p.Method != "ListKeys"):
				continue // a listing fault fires at the first listing from its call on (N-m6)
			case !listing && ev.at != p.N:
				continue
			}
			done[i] = true
			switch ev.kind {
			case "lock":
				e.lockNow(true)
			case "lease":
				s.loseLease()
			case "abort":
				s.decide("abort", true)
			case "clock":
				e.clock.Advance(s.sched.step)
			case "clock_back":
				e.clock.Set(e.clock.Now().Add(-2 * time.Hour)) // G14
			case "kill":
			default:
				f = faultKinds[ev.kind]
			}
		}
		if f == fake.FaultNone && s.sched.v == withFrom && p.Method == "VerifyKeyLogin" && p.Target == s.db && p.OSUser == "app" {
			f = fake.FaultRefuse // from= excludes Alice's address
		}
		if f == fake.FaultNone && s.sched.fault != nil {
			f = s.sched.fault(p, s)
		}
		return f
	})
}

// scheduledAfter reports whether the schedule makes the decision at a later round.
func (s *scenario) scheduledAfter(kind string, round int) bool {
	for _, ev := range s.sched.rounds {
		if ev.kind == kind && ev.at > round {
			return true
		}
	}
	return false
}

// decide makes an Administrator's decision and notes where it was accepted when the schedule asked for it
// (the harness's own settling decisions do not count as coverage, N-m6).
func (s *scenario) decide(kind string, scheduled bool) {
	e := s.e
	r, err := e.keys.Rotation(e.ctx, s.runID)
	if err != nil {
		return
	}
	switch kind {
	case "continue":
		err = e.keys.Continue(e.ctx, e.admin, s.runID)
	case "finish_now":
		err = e.keys.FinishNow(e.ctx, e.admin, s.runID)
	case "abort":
		err = e.keys.Abort(e.ctx, e.admin, s.runID)
	case "keep_old":
		var ids []uuid.UUID
		for _, l := range r.Locations {
			if l.State == sshkeys.LocUnverifiable {
				ids = append(ids, l.ID)
			}
		}
		err = e.keys.KeepOld(e.ctx, e.admin, s.runID, ids)
	}
	if err == nil && scheduled {
		s.accepted = append(s.accepted, kind+"@"+r.Status)
	}
}

// loseLease: the job's lease expires while its call is still running; the reaper takes the job back and a
// second run of it (with whatever else is due) goes to the end before the first run's call returns.
func (s *scenario) loseLease() {
	e := s.e
	e.clock.Advance(46 * time.Second)
	_, err := e.runner.Reap(e.ctx)
	require.NoError(e.t, err)
	outer := e.cancelJob.Load()
	e.drain()
	e.cancelJob.Store(outer) // a hang later in the first run ends the first run's context
}

// settle drives the system until the run ended (F9, A11): jobs run (in a dying process while a kill is
// armed, then Alice restarts); the decisions of this round are made; a lock lasts renewAfter of clock and
// is then renewed; a paused run is continued after the sweep announced the renewal; a waiting decision is
// answered or its deadline is reached; otherwise the clock moves an hour and the sweep runs.
func (s *scenario) settle() {
	e := s.e
	for round := 0; round < 400; round++ {
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
		for _, ev := range s.sched.rounds {
			if ev.at == round {
				if ev.kind == "lock" {
					e.lockNow(false) // a lock between two calls (in the overlap, while a decision waits)
					continue
				}
				s.decide(ev.kind, true)
				e.drain()
			}
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
			e.sweep() // a deadline that passed in lock pauses too (an overlap's end, L-83)
			e.drain()
			e.gate.unlock()
		case r.PausedLicense:
			e.sweep() // the renewal notice first (S6)
			if !s.scheduledAfter("continue", round) {
				s.decide("continue", false)
			}
		case r.AwaitingDecision && r.DecisionDueAt != nil:
			if s.sched.keepOld {
				s.decide("keep_old", false)
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
	e.tick.on.Store(false)
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
	// I1: every removal of the old key followed the verification and a fresh, later re-check (two accepted
	// logins with the new key, the second at most 15 minutes before the send).
	e.assertEveryRemovalFollowedAFreshLogin(t, oldFP, newFP)
	// L (review I5, T14-D2, L-29): while the licence is locked no command at all (listing, login, add,
	// removal) reaches a server, except from a job whose sends were in flight when the lock began (L-85)
	// and the undo of the run's own additions (L-86).
	for _, ev := range e.world.Events() {
		c := e.call(ev.N)
		if ev.Landed || !c.locked {
			continue
		}
		assert.True(t, e.allowedInLock(c), "L: %s reached a server while the licence was locked (call %d)", ev.Method, ev.N)
		assert.False(t, ev.Method == "RemoveAuthorizedKey" && ev.Fingerprint == oldFP && !e.lockJobs[c.job],
			"L: a removal of the old key was sent while the licence was locked (call %d)", ev.N)
	}
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
	// I4, I5: the record matches the files; every location of a finished run is in a final state that
	// agrees with the world (review I5).
	for _, l := range r.Locations {
		assert.NotContains(t, []string{sshkeys.LocPlanned, sshkeys.LocAdding, sshkeys.LocAdded, sshkeys.LocVerified,
			sshkeys.LocUnverifiable, sshkeys.LocRemoving, sshkeys.LocUndoing}, l.State,
			"a finished run left %s:%s in flight", l.TargetName, l.FilePath)
		switch l.State {
		case sshkeys.LocRemoved:
			assert.True(t, e.world.Has(l.TargetID, l.FilePath, newFP), "removed: the new key is in %s", l.FilePath)
		case sshkeys.LocUndone:
			assert.True(t, e.world.Has(l.TargetID, l.FilePath, oldFP), "undone: the old key is in %s", l.FilePath)
		case sshkeys.LocKeptOld:
			assert.True(t, e.world.Has(l.TargetID, l.FilePath, newFP), "kept: both keys are in %s", l.FilePath)
		}
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

// baseline is the fault-free run of a variant: its world calls, and the call index of its last add's login.
type baseline struct {
	calls, lastAddLogin int
	removes             []int // call indexes of the removals of the old key
}

// schedules builds the schedules from the fault-free runs (see the comment at the top).
func schedules(seed uint64, random int, full bool, base map[variant]baseline) []schedule {
	var out []schedule
	renew := func(at int) time.Duration {
		if at%2 == 0 {
			return 20 * 24 * time.Hour // L-84: a renewal after 20 days
		}
		return time.Hour
	}
	singles := []variant{oneLoc, twoLocs, withFrom}
	pairs := []variant{twoLocs}
	if full {
		singles, pairs = append(singles, threeLocs), []variant{oneLoc, twoLocs, threeLocs, withFrom}
	}
	for _, v := range singles {
		for at := 1; at <= base[v].calls; at++ {
			for _, kind := range callKinds {
				out = append(out, schedule{v: v, events: []event{{at, kind}}, renewAfter: renew(at), step: 2 * time.Hour,
					keepOld: at%2 == 1, ticking: len(out)%2 == 1})
			}
		}
	}
	for _, v := range pairs {
		// The last verification is refused: the run rolls back; every kind at each call of the undo path.
		trigger := event{base[v].lastAddLogin, "refuse"}
		for at := trigger.at + 1; at <= 2*trigger.at+2; at++ { // the undo lists and removes per added location
			for _, kind := range callKinds {
				out = append(out, schedule{v: v, events: []event{trigger, {at, kind}}, renewAfter: renew(at), step: 2 * time.Hour,
					ticking: len(out)%2 == 1})
			}
		}
	}
	for _, v := range []variant{oneLoc, twoLocs} {
		// A late write on each add (S3), and what may follow it at the next call.
		for add := 1; add < base[v].lastAddLogin; add += 2 {
			for _, kind := range []string{"unreachable", "lock", "abort", "kill"} {
				out = append(out, schedule{v: v, events: []event{{add, "late_write"}, {add + 1, kind}}, renewAfter: time.Hour,
					step: 2 * time.Hour, ticking: len(out)%2 == 1})
			}
		}
	}
	for _, v := range []variant{twoLocs, withFrom} {
		for round := range 3 {
			for _, kind := range roundKinds {
				// The harness answers a waiting decision itself only when no Keep old is scheduled.
				out = append(out, schedule{v: v, rounds: []event{{round, kind}}, renewAfter: time.Hour, step: 2 * time.Hour,
					keepOld: kind != "keep_old", ticking: len(out)%2 == 1})
			}
		}
		// A lock between calls at each of the first rounds (the overlap, a waiting decision), then Continue.
		for round := range 3 {
			out = append(out, schedule{v: v, rounds: []event{{round, "lock"}}, renewAfter: []time.Duration{time.Hour, 20 * 24 * time.Hour}[round%2],
				step: 2 * time.Hour, keepOld: true})
		}
		// Continue right after a lock at each add, before and after the renewal notice.
		for at := 1; at <= base[v].lastAddLogin; at++ {
			out = append(out, schedule{v: v, events: []event{{at, "lock"}}, rounds: []event{{0, "continue"}, {1, "continue"}, {2, "continue"},
				{3, "continue"}}, renewAfter: time.Hour, step: 2 * time.Hour, keepOld: true})
		}
	}
	for _, v := range []variant{oneLoc, twoLocs} {
		// The re-list of a removal whose answer was lost (or that hung), under a listing that does not
		// read the file (review C1, N-m6): nothing is recorded removed on its word.
		for _, rm := range base[v].removes {
			for _, lost := range []string{"hang", "after_write", "late_write"} {
				for _, listing := range []string{"unread", "partial"} {
					out = append(out, schedule{v: v, events: []event{{rm, lost}, {rm + 1, listing}}, renewAfter: time.Hour,
						step: 2 * time.Hour, ticking: len(out)%2 == 1})
				}
			}
		}
	}
	rng := rand.New(rand.NewPCG(seed, seed^0x9e3779b97f4a7c15))
	vs := []variant{oneLoc, twoLocs, threeLocs, withFrom}
	for range random {
		v := vs[rng.IntN(len(vs))]
		s := schedule{v: v, renewAfter: []time.Duration{time.Hour, 20 * 24 * time.Hour}[rng.IntN(2)],
			step: []time.Duration{2 * time.Hour, 30 * 24 * time.Hour}[rng.IntN(2)], keepOld: rng.IntN(2) == 0, ticking: rng.IntN(2) == 0}
		for range 1 + rng.IntN(3) {
			s.events = append(s.events, event{at: 1 + rng.IntN(base[v].calls+4), kind: callKinds[rng.IntN(len(callKinds))]})
		}
		if rng.IntN(2) == 0 {
			s.rounds = append(s.rounds, event{at: rng.IntN(3), kind: roundKinds[rng.IntN(len(roundKinds))]})
		}
		out = append(out, s)
	}
	return out
}

func propertySeed(t *testing.T) (uint64, int, bool) {
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
	return seed, random, os.Getenv("ALICE_PROPERTY_FULL") == "1"
}

// baselineOf runs a variant without faults and reads its calls from the world.
func baselineOf(t *testing.T, v variant) baseline {
	t.Helper()
	s := runScenario(t, schedule{v: v, renewAfter: time.Hour, step: time.Hour, keepOld: true})
	r := s.e.run(s.runID)
	want := sshkeys.StatusCompleted
	require.Equal(t, want, r.Status, "the fault-free run of %s completes", v)
	s.assertInvariants(t)
	b := baseline{calls: s.e.worldCalls()}
	for _, ev := range s.e.world.Events() {
		if ev.Method == "AddAuthorizedKey" && !ev.Landed {
			b.lastAddLogin = ev.N + 1
		}
		if ev.Method == "RemoveAuthorizedKey" && !ev.Landed {
			b.removes = append(b.removes, ev.N)
		}
	}
	return b
}

func TestOldKeyRemainsUnderAnyInjectedFailure(t *testing.T) {
	seed, random, full := propertySeed(t)
	base := map[variant]baseline{}
	for _, v := range []variant{oneLoc, twoLocs, threeLocs, withFrom} {
		base[v] = baselineOf(t, v)
	}
	all := schedules(seed, random, full, base)
	t.Logf("seed %d, %d schedules (full=%t, %d random; ALICE_PROPERTY_SEED, ALICE_PROPERTY_RANDOM, ALICE_PROPERTY_FULL)", seed, len(all), full, random)
	var (
		mu       sync.Mutex
		accepted = map[string]int{}
	)
	slots := make(chan struct{}, parallelScenarios)
	t.Run("schedules", func(t *testing.T) {
		for i, sched := range all {
			t.Run(fmt.Sprintf("%03d/%s", i, strings.ReplaceAll(sched.String(), " ", "_")), func(t *testing.T) {
				t.Parallel()
				slots <- struct{}{}
				defer func() { <-slots }()
				t.Cleanup(func() {
					if t.Failed() {
						t.Logf("reproduce: ALICE_PROPERTY_SEED=%d, schedule %d: %s", seed, i, sched)
					}
				})
				s := runScenario(t, sched)
				s.assertInvariants(t)
				mu.Lock()
				for _, a := range s.accepted {
					accepted[a]++
				}
				mu.Unlock()
			})
		}
	})
	t.Logf("decisions accepted (decision@status: schedules): %v", accepted)
	// Review I4: each decision took effect in the phases it exists for.
	for _, want := range []string{"finish_now@overlap", "keep_old@verifying_new", "abort@adding_new", "abort@verifying_new",
		"abort@overlap", "continue@adding_new", "continue@overlap"} {
		assert.Positive(t, accepted[want], "no schedule had %s take effect", want)
	}
}
