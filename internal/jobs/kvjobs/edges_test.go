package kvjobs

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/inventory"
	"alice/internal/jobs"
	"alice/internal/providers"
	"alice/internal/providers/fake"
)

// Failures that are not the provider's: a plain error from a provider call is an unreachable vault
// with no text, a failed bookkeeping write is logged by type, and a session that fails to close is
// logged by type.
func TestUnclassifiedFailuresCarryNoText(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, true)
	f.prov.Configure(func(c *fake.Config) { c.DiscoverErr = errors.New(canary) })
	f.inv.failErr = errors.New(canary + " from the database")
	f.prov.closeErr = errors.New(canary + " on close")
	_, err := f.h.poll(ctx, f.job(jobs.KVPoll, nil), noSteps{})
	fl := failureWith(t, err, jobs.Retryable, "azure.unreachable")
	assert.NotContains(t, fl.Error(), canary)
	require.Len(t, f.inv.failures, 1)
	var pe *providers.Error
	require.ErrorAs(t, f.inv.failures[0], &pe)
	assert.Equal(t, "azure.unreachable", pe.Code, "recorded as a closed code, never as the text")
	assert.NotContains(t, f.logs.String(), canary)
	assert.Contains(t, f.logs.String(), "error_type")
	assert.Equal(t, 1, f.prov.Count("Close"))
}

// The secret read of the access check when the job's context ends, and when the provider's error is
// not a provider error.
func TestSecretReadOfTheAccessCheckEdges(t *testing.T) {
	ctx := context.Background()
	f, _, payload := readSecretFixture(t)
	jobCtx, cancel := context.WithCancel(ctx)
	f.prov.hook = func(m string) {
		if m == "ReadCertificateSecret" {
			cancel()
		}
	}
	f.prov.Configure(func(c *fake.Config) {
		c.SecretErr = providers.NewError("azure.unreachable", true, context.Canceled, nil)
	})
	_, err := f.h.testConnection(jobCtx, f.job(jobs.KVTestConnection, payload), noSteps{})
	requireFailure(t, err, jobs.Retryable, "job.lease_expired")
	assert.Equal(t, 1, f.prov.Count("Close"))

	f, _, payload = readSecretFixture(t)
	f.prov.Configure(func(c *fake.Config) { c.SecretErr = errors.New(canary) })
	_, err = f.h.testConnection(ctx, f.job(jobs.KVTestConnection, payload), noSteps{})
	requireFailure(t, err, jobs.Retryable, "azure.unreachable")
	assert.NotContains(t, f.logs.String(), canary)

	// A provider that answers the check with no rows is a bug, not a vault state.
	f = newFixture(t, true)
	f.prov.Configure(func(c *fake.Config) { c.Report = providers.ConnectionReport{} })
	_, err = f.h.testConnection(ctx, f.job(jobs.KVTestConnection, nil), noSteps{})
	requireFailure(t, err, jobs.Permanent, "internal.unexpected")
	assert.Zero(t, f.inv.count("RecordKVConnection"))

	// The check's own report may lack the read_secret row: it is added.
	f, _, payload = readSecretFixture(t)
	f.prov.Configure(func(c *fake.Config) {
		c.Report = providers.ConnectionReport{Azure: &providers.AzureFacts{Checks: okChecks()[:2]}}
	})
	_, err = f.h.testConnection(ctx, f.job(jobs.KVTestConnection, payload), noSteps{})
	require.NoError(t, err)
	rows := f.inv.connections[0].Azure.Checks
	assert.Equal(t, providers.AzureCheckReadSecret, rows[len(rows)-1].Name)
	assert.Equal(t, providers.AzureResultOK, rows[len(rows)-1].Result)
}

// The bookkeeping writes of an import that fail, one by one.
func TestImportBookkeepingFailures(t *testing.T) {
	ctx := context.Background()
	t.Run("the vault is gone: ending the queued import fails", func(t *testing.T) {
		for err, want := range map[error]string{inventory.ErrClaimLost: "job.lease_expired", errors.New(canary): "internal.unexpected"} {
			f, _ := importFixture(t)
			f.inv.targetErr = inventory.ErrNotFound
			f.inv.failQErr = err
			_, e := f.h.importToKV(ctx, importJob(f), noSteps{})
			requireFailure(t, e, jobs.Retryable, want)
			assert.NotContains(t, f.logs.String(), canary)
		}
		f, _ := importFixture(t)
		f.inv.targetErr = inventory.ErrNotFound
		f.inv.failQErr = inventory.ErrImportState
		_, e := f.h.importToKV(ctx, importJob(f), noSteps{})
		requireFailure(t, e, jobs.Permanent, "system.not_found")
	})
	t.Run("refusing fails", func(t *testing.T) {
		for err, class := range map[error]jobs.FailureClass{inventory.ErrClaimLost: jobs.Retryable, errors.New(canary): jobs.Retryable,
			inventory.ErrImportState: jobs.Permanent} {
			f, _ := importFixture(t)
			f.prov.Configure(func(c *fake.Config) { c.OpenErr = providers.NewError("azure.auth_failed", false, nil, nil) })
			f.inv.finishErr = err
			_, e := f.h.importToKV(ctx, importJob(f), noSteps{})
			fl := failure(t, e)
			assert.Equal(t, class, fl.Class)
			assert.NotContains(t, f.logs.String(), canary)
		}
	})
	t.Run("the import is no longer queued when the material is asked for", func(t *testing.T) {
		f, _ := importFixture(t)
		f.inv.materialErr = inventory.ErrImportState
		f.inv.importErrs = []error{nil, errors.New(canary)}
		res, err := f.h.importToKV(ctx, importJob(f), noSteps{})
		require.NoError(t, err)
		assert.Equal(t, inventory.ImportRunning, res["state"], "the record cannot be read again: the state is not guessed as finished")
	})
	t.Run("the job's context ends while opening", func(t *testing.T) {
		f, _ := importFixture(t)
		jobCtx, cancel := context.WithCancel(ctx)
		f.prov.hook = func(m string) {
			if m == "Open" {
				cancel()
			}
		}
		f.prov.Configure(func(c *fake.Config) { c.OpenErr = providers.NewError("azure.unreachable", true, context.Canceled, nil) })
		j := importJob(f)
		j.Attempt = j.MaxAttempts
		_, err := f.h.importToKV(jobCtx, j, noSteps{})
		requireFailure(t, err, jobs.Retryable, "job.lease_expired")
		assert.Zero(t, f.inv.count("FinishImport"), "a shutdown does not end the import: it runs again")
	})
	t.Run("a refused result without a provider error is no refusal", func(t *testing.T) {
		f, _ := importFixture(t)
		f.reg = providers.NewRegistry()
		f.reg.Register(violating{spyProvider: f.prov, res: providers.ImportResult{Outcome: providers.ImportRefused}})
		f.reg.Freeze()
		f.h.d.Registry = f.reg
		f.inv.finishState = inventory.ImportFailed
		_, err := f.h.importToKV(ctx, importJob(f), noSteps{})
		requireFailure(t, err, jobs.Permanent, "internal.unexpected")
	})
	t.Run("the mark commits but the answer is lost: the last attempt ends it refused", func(t *testing.T) {
		f, _ := importFixture(t)
		f.inv.markErr = errors.New(canary)
		j := importJob(f)
		j.Attempt = j.MaxAttempts
		_, err := f.h.importToKV(ctx, j, noSteps{})
		requireFailure(t, err, jobs.Permanent, "internal.unexpected")
		assert.Zero(t, f.prov.Count("ImportCertificate"))
	})
}

func TestAutoDeployTaskStopsWithItsContext(t *testing.T) {
	var logs bytes.Buffer
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	plan := &fakePlanner{err: errors.New(canary)}
	err := AutoDeployTask(plan, time.Minute, slog.New(slog.NewTextHandler(&logs, nil))).Run(ctx)
	require.Error(t, err)
	assert.ErrorIs(t, err, plan.err, "a cancelled context ends the run as it is")
	assert.NotContains(t, logs.String(), canary)
	quiet := AutoDeployTask(&fakePlanner{created: 1, err: errors.New(canary)}, time.Minute, nil)
	assert.NotPanics(t, func() { _ = quiet.Run(context.Background()) }, "no logger is fine")
	assert.Equal(t, "*errors.errorString", typesOf(errors.Join(errors.New("a"), errors.New("b"))), "one entry per distinct type")
	many := errors.Join(errors.New("x"), fmt.Errorf("w: %w", errors.New("y")), providers.NewError("a.b", false, nil, nil), context.DeadlineExceeded,
		&net.OpError{}, &os.PathError{}, &strconv.NumError{})
	assert.Len(t, strings.Split(typesOf(many), ","), 5, "at most five types are logged")
}
