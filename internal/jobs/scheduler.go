package jobs

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"alice/internal/license"
	"alice/internal/platform/clock"
)

// Gate decides whether work of a license class may start now (license.Service.Allow).
type Gate interface {
	Allow(c license.Class) error
}

// Task is periodic work.
type Task struct {
	Type  Type
	Every time.Duration
	Run   func(ctx context.Context) error
	// Retry, when positive, runs a failed run again after Retry, then after twice as long and so
	// on up to Every, until a run succeeds (the license evaluation: AUD-02). 0 = wait for the
	// next interval. A run the license gate refused is not a failure.
	Retry time.Duration
}

type task struct {
	Task
	sem chan struct{} // capacity 1: one run at a time
}

// Scheduler runs periodic tasks in-process. Every run passes the license gate first
// (spec §8.6); a run that has started is never cancelled by the lock (§8.7).
type Scheduler struct {
	clock  clock.Clock
	gate   Gate
	log    *slog.Logger
	tasks  map[string]*task
	order  []*task
	leader *Leader // nil: always run (tests, single process)
}

// WithLeader makes ticks run only while this process holds the scheduling lock, so two
// processes against one database never both run periodic work (P2-06). RunNow is an explicit
// request (the e2e demo clock, an operator command) and runs regardless. license.evaluate runs
// in every process regardless (AUD-02): the license gate of each process trusts only its own
// recent evaluations, and a session holding the scheduling lock must not stop them. Its writes
// are serialized by the license row lock and recorded once. Call it before Run.
//
// Leadership is checked once per tick, before the run starts: a run that has started finishes
// even when the lock is lost meanwhile, and the new leader may start the same task then. Tasks
// must therefore tolerate an occasional overlap with another process (make their writes
// idempotent or serialize them in the database).
func (s *Scheduler) WithLeader(l *Leader) *Scheduler {
	s.leader = l
	return s
}

// NewScheduler validates tasks. External-change work (ClassChange) is refused: after a
// renewal it must wait for an Administrator's confirmation (R29), which only the job queue
// can provide.
func NewScheduler(clk clock.Clock, gate Gate, log *slog.Logger, tasks ...Task) *Scheduler {
	s := &Scheduler{clock: clk, gate: gate, log: log, tasks: map[string]*task{}}
	for _, t := range tasks {
		reg, ok := lookup(t.Type.Name)
		switch {
		case !ok || reg != t.Type:
			panic(fmt.Sprintf("jobs: task %q does not use a registered job type", t.Type.Name))
		case t.Type.Class == license.ClassChange:
			panic(fmt.Sprintf("jobs: %q changes managed systems and cannot be a periodic task", t.Type.Name))
		case t.Every <= 0 || t.Run == nil:
			panic(fmt.Sprintf("jobs: task %q needs an interval and a function", t.Type.Name))
		}
		if _, dup := s.tasks[t.Type.Name]; dup {
			panic(fmt.Sprintf("jobs: task %q is scheduled twice", t.Type.Name))
		}
		tk := &task{Task: t, sem: make(chan struct{}, 1)}
		s.tasks[t.Type.Name] = tk
		s.order = append(s.order, tk)
	}
	return s
}

// Schedules reports whether t is one of the scheduler's tasks (serve refuses to start when a
// periodic job type is not scheduled: cmd/alice checkWiring).
func (s *Scheduler) Schedules(t Type) bool {
	tk, ok := s.tasks[t.Name]
	return ok && tk.Type == t
}

// Run runs every task on its interval until ctx ends. A tick that finds the task still
// running is skipped.
func (s *Scheduler) Run(ctx context.Context) {
	var wg sync.WaitGroup
	for _, t := range s.order {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.loop(ctx, t)
		}()
	}
	wg.Wait()
}

func (s *Scheduler) loop(ctx context.Context, t *task) {
	ticker := s.clock.NewTicker(t.Every)
	defer ticker.Stop()
	s.loopWith(ctx, t, ticker.C())
}

func (s *Scheduler) loopWith(ctx context.Context, t *task, ticks <-chan time.Time) {
	var retry <-chan time.Time // nil: no retry pending
	backoff := t.Retry
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticks:
		case <-retry:
		}
		if ctx.Err() != nil {
			return
		}
		if s.leader != nil && t.Type != LicenseEvaluate && !s.leader.IsLeader(ctx) {
			continue // another process schedules (P2-06)
		}
		select {
		case t.sem <- struct{}{}:
			err := s.run(ctx, t)
			<-t.sem
			switch {
			case t.Retry <= 0:
			case err == nil || errors.Is(err, license.ErrLocked) || errors.Is(err, license.ErrUnclassified):
				retry, backoff = nil, t.Retry
			default:
				retry = s.clock.After(backoff)
				backoff = min(2*backoff, t.Every)
			}
		default: // still running: skip this tick
		}
	}
}

// RunNow runs a task at once (waiting while it runs), after the gate. It returns
// license.ErrLocked when the task is paused.
func (s *Scheduler) RunNow(ctx context.Context, name string) error {
	t, ok := s.tasks[name]
	if !ok {
		return fmt.Errorf("jobs: no task %q", name)
	}
	select {
	case t.sem <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	}
	defer func() { <-t.sem }()
	return s.run(ctx, t)
}

func (s *Scheduler) run(ctx context.Context, t *task) (err error) {
	if err := s.gate.Allow(t.Type.Class); err != nil {
		switch {
		case errors.Is(err, license.ErrUnverified):
			s.log.Info("scheduled task paused until the license can be checked", "job_type", t.Type.Name)
		case errors.Is(err, license.ErrLocked):
			s.log.Info("scheduled task paused while the license is expired", "job_type", t.Type.Name)
		default:
			s.log.Error("scheduled task refused by the license gate", "job_type", t.Type.Name, "error_type", fmt.Sprintf("%T", err))
		}
		return err
	}
	defer func() {
		if p := recover(); p != nil {
			// The panic value is not logged: it may hold data from the task.
			s.log.Error("scheduled task panicked", "job_type", t.Type.Name)
			err = fmt.Errorf("jobs: task %s panicked", t.Type.Name)
		}
	}()
	if err := t.Run(ctx); err != nil {
		s.log.Error("scheduled task failed", "job_type", t.Type.Name, "error_type", fmt.Sprintf("%T", err))
		return err
	}
	return nil
}
