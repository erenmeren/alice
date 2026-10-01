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
// request (the e2e demo clock, an operator command) and runs regardless. Call it before Run.
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
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticks:
			if ctx.Err() != nil {
				return
			}
			if s.leader != nil && !s.leader.IsLeader(ctx) {
				continue // another process schedules (P2-06)
			}
			select {
			case t.sem <- struct{}{}:
				_ = s.run(ctx, t)
				<-t.sem
			default: // still running: skip this tick
			}
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
		if errors.Is(err, license.ErrLocked) {
			s.log.Info("scheduled task paused while the license is expired", "job_type", t.Type.Name)
		} else {
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
