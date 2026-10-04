package main

import (
	"bytes"
	"context"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/audit"
	"alice/internal/auth"
	"alice/internal/inventory"
	"alice/internal/jobs"
	"alice/internal/jobs/deployjobs"
	"alice/internal/license"
	"alice/internal/platform/clock"
	"alice/internal/platform/config"
	"alice/internal/platform/db"
	"alice/internal/providers"
	"alice/internal/setup"
)

func env(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

func TestVersionCommand(t *testing.T) {
	var out, errOut bytes.Buffer
	code := run([]string{"version"}, env(nil), &out, &errOut)
	assert.Equal(t, 0, code)
	assert.Contains(t, out.String(), "alice dev")
}

func TestUnknownCommand(t *testing.T) {
	var out, errOut bytes.Buffer
	code := run([]string{"frobnicate"}, env(nil), &out, &errOut)
	assert.Equal(t, 2, code)
	assert.Contains(t, errOut.String(), "unknown command")
	assert.Contains(t, errOut.String(), "serve")
}

func TestMigrateNeedsDatabaseURL(t *testing.T) {
	var out, errOut bytes.Buffer
	code := run([]string{"migrate"}, env(nil), &out, &errOut)
	assert.Equal(t, 1, code)
	assert.Contains(t, errOut.String(), "ALICE_DATABASE_URL")
}

func TestHealthcheck(t *testing.T) {
	ok := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ok.Close()
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer bad.Close()

	var out, errOut bytes.Buffer
	assert.Equal(t, 0, run([]string{"healthcheck"}, env(map[string]string{"ALICE_HEALTH_ADDR": strings.TrimPrefix(ok.URL, "http://")}), &out, &errOut))
	assert.Equal(t, 1, run([]string{"healthcheck"}, env(map[string]string{"ALICE_HEALTH_ADDR": strings.TrimPrefix(bad.URL, "http://")}), &out, &errOut))
	assert.Equal(t, 1, run([]string{"healthcheck"}, env(map[string]string{"ALICE_HEALTH_ADDR": "127.0.0.1:1"}), &out, &errOut))
}

func TestDBStartupErrorMentionsWaitOnlyForUnreachable(t *testing.T) {
	err := dbStartupError(fmt.Errorf("x: %w", db.ErrUnreachable), time.Minute)
	assert.Contains(t, err.Error(), "database not ready after 1m0s")
	assert.ErrorIs(t, err, db.ErrUnreachable)

	auth := fmt.Errorf("the database server at postgres:5432 rejected the user name or password; check the database URL: %w", db.ErrAuthFailed)
	err = dbStartupError(auth, time.Minute)
	assert.Equal(t, auth, err, "a rejected password is final and reported unchanged")
}

// Every service serve builds reaches the API; a missing License would make every gated
// route fail closed (license.locked) instead of working, and a missing Inventory, Jobs or
// Providers would answer every Phase 3 route with a 500.
func TestAPIDepsCarryEveryService(t *testing.T) {
	svc := &services{auth: &auth.Service{}, setup: &setup.Service{}, audit: &audit.Service{}, license: &license.Service{},
		inventory: &inventory.Service{}, queue: &jobs.Queue{}, registry: providers.NewRegistry()}
	d := newAPIDeps(config.Config{}, svc, nil, nil, clock.Real{}, slog.New(slog.DiscardHandler), nil)
	assert.Same(t, svc.license, d.License)
	assert.Same(t, svc.setup, d.Setup)
	assert.Same(t, svc.auth, d.Auth)
	assert.Same(t, svc.audit, d.Audit)
	assert.Same(t, svc.inventory, d.Inventory)
	assert.Same(t, svc.queue, d.Jobs)
	assert.Same(t, svc.registry, d.Providers)
	assert.NotNil(t, d.Clock)
	assert.NotNil(t, d.Log)
}

// At shutdown serve waits for the job runner only until the shutdown deadline (spec §8.8: the
// runner itself releases the leases of jobs that did not end within its grace).
func TestWaitForJobsIsBounded(t *testing.T) {
	var logs bytes.Buffer
	log := slog.New(slog.NewTextHandler(&logs, nil))

	done := make(chan struct{})
	close(done)
	assert.True(t, waitForJobs(context.Background(), done, log))
	assert.Empty(t, logs.String())

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	start := time.Now()
	assert.False(t, waitForJobs(ctx, make(chan struct{}), log), "workers that never stop do not block shutdown")
	assert.Less(t, time.Since(start), 5*time.Second)
	assert.Contains(t, logs.String(), "level=WARN")
	assert.Contains(t, logs.String(), "background jobs did not stop")
}

// closeWithin gives up on a close that hangs (a stuck job holding a database connection) so the
// process still exits before Docker kills it.
func TestCloseWithinIsBounded(t *testing.T) {
	var logs bytes.Buffer
	log := slog.New(slog.NewTextHandler(&logs, nil))
	closed := false
	closeWithin("quick", func() { closed = true }, time.Second, log)
	assert.True(t, closed)
	assert.Empty(t, logs.String())

	block := make(chan struct{})
	defer close(block)
	start := time.Now()
	closeWithin("the database pool", func() { <-block }, 20*time.Millisecond, log)
	assert.Less(t, time.Since(start), 5*time.Second)
	assert.Contains(t, logs.String(), "level=WARN")
	assert.Contains(t, logs.String(), "the database pool")
}

// Every shutdown step is bounded and together they end before Docker's stop_grace_period sends
// SIGKILL (I-2): the HTTP drain, scheduler and job wait share one deadline from the signal, which
// also covers the runner's own grace; the leader, SSH pool, time record and database pool each
// have a small budget after it. The sum is taken over every constant of the shutdown block in
// main.go, so a wait added there counts without editing this test.
//
// A running deployment is not waited for beyond the runner's grace (a deploy command may take up
// to 240 s): the runner lets running jobs end for half of it, then cancels them and gives them the
// second half to record what they know; jobs that still run are handed back (releaseAll) and the
// deployment recovery sweep finishes them after the restart. Recording an outcome after the
// cancellation (deployjobs: the write and its re-read, each bounded by RecordTimeout) fits in that
// second half.
func TestShutdownFitsTheStopGracePeriod(t *testing.T) {
	grace, err := time.ParseDuration(readCompose(t, "../../deploy/docker-compose.yml").Services["alice"].StopGracePeriod)
	require.NoError(t, err)
	budgets := shutdownBudgetConstants(t)
	require.Equal(t, []string{"serveShutdownBudget", "jobsShutdownGrace", "leaderCloseBudget", "sshPoolCloseBudget",
		"timeRecordSaveBudget", "dbCloseBudget"}, budgetNames(budgets), "the shutdown constants of main.go")
	values := map[string]time.Duration{"serveShutdownBudget": serveShutdownBudget, "jobsShutdownGrace": jobsShutdownGrace,
		"leaderCloseBudget": leaderCloseBudget, "sshPoolCloseBudget": sshPoolCloseBudget,
		"timeRecordSaveBudget": timeRecordSaveBudget, "dbCloseBudget": dbCloseBudget}
	var total time.Duration
	for _, name := range budgetNames(budgets) {
		if name == "jobsShutdownGrace" {
			continue // inside serveShutdownBudget (asserted below)
		}
		total += values[name]
	}
	assert.Equal(t, 83*time.Second, total)
	assert.Less(t, total, grace, "worst-case shutdown %s must end before stop_grace_period %s", total, grace)
	assert.Less(t, jobsShutdownGrace, serveShutdownBudget, "running jobs get their grace inside the shutdown deadline")
	assert.LessOrEqual(t, 2*deployjobs.RecordTimeout, jobsShutdownGrace/2,
		"a deployment cut off by the shutdown can record its outcome inside the runner's grace")
}

// shutdownBudgetConstants returns the names of the constants declared in main.go's shutdown block
// (the const block that declares serveShutdownBudget), in order.
func shutdownBudgetConstants(t *testing.T) []*ast.Ident {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), "main.go", nil, 0)
	require.NoError(t, err)
	for _, decl := range f.Decls {
		gd, ok := decl.(*ast.GenDecl)
		if !ok || gd.Tok != token.CONST {
			continue
		}
		var names []*ast.Ident
		found := false
		for _, spec := range gd.Specs {
			for _, n := range spec.(*ast.ValueSpec).Names {
				names = append(names, n)
				found = found || n.Name == "serveShutdownBudget"
			}
		}
		if found {
			return names
		}
	}
	t.Fatal("main.go has no shutdown const block")
	return nil
}

func budgetNames(ids []*ast.Ident) []string {
	out := make([]string, len(ids))
	for i, id := range ids {
		out[i] = id.Name
	}
	return out
}

// At shutdown serve waits for running scheduled tasks only until the shutdown deadline.
func TestWaitForSchedulerIsBounded(t *testing.T) {
	var logs bytes.Buffer
	log := slog.New(slog.NewTextHandler(&logs, nil))

	done := make(chan struct{})
	close(done)
	assert.True(t, waitForScheduler(context.Background(), done, log))
	assert.Empty(t, logs.String())

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	assert.False(t, waitForScheduler(ctx, make(chan struct{}), log), "a task that never returns does not block shutdown")
	assert.Contains(t, logs.String(), "level=WARN")
	assert.Contains(t, logs.String(), "scheduled tasks did not stop")
}
