//go:build integration

package audit_test

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/audit"
	"alice/internal/platform/clock"
	"alice/internal/testutil/pgtest"
)

var errBoom = errors.New("boom")

// failingQuerier fails every statement, standing in for a database that went away.
type failingQuerier struct{}

func (failingQuerier) Exec(context.Context, string, ...any) (pgconn.CommandTag, error) {
	return pgconn.CommandTag{}, errBoom
}

func (failingQuerier) Query(context.Context, string, ...any) (pgx.Rows, error) { return nil, errBoom }

func (failingQuerier) QueryRow(context.Context, string, ...any) pgx.Row { return errRow{} }

type errRow struct{}

func (errRow) Scan(...any) error { return errBoom }

func TestReadersSurfaceDatabaseErrors(t *testing.T) {
	ctx := context.Background()
	var q failingQuerier

	_, _, err := audit.List(ctx, q, audit.Filter{})
	require.ErrorIs(t, err, errBoom)
	assert.ErrorContains(t, err, "audit: list")

	err = audit.Iterate(ctx, q, func(audit.Entry) error { return nil })
	require.ErrorIs(t, err, errBoom)
	assert.ErrorContains(t, err, "audit: iterate")

	_, err = audit.Verify(ctx, q)
	require.ErrorIs(t, err, errBoom)
	assert.ErrorContains(t, err, "read checkpoint")

	_, _, err = audit.LastCheckpoint(ctx, q)
	require.ErrorIs(t, err, errBoom)
	assert.ErrorContains(t, err, "read checkpoint")
}

func TestUnreadableStoredValuesAreReportedNotIgnored(t *testing.T) {
	d := pgtest.New(t)
	ctx := context.Background()
	svc := audit.NewService(audit.New(clock.NewFake(start)), d.App)
	require.NoError(t, svc.Write(ctx, audit.Event{Actor: audit.SystemActor("test"), Action: "test.one", Result: audit.Success}))

	// A checkpoint whose timestamp is not RFC 3339 cannot be trusted.
	ownerExec(t, d, `INSERT INTO settings (key, value, updated_at) VALUES ('audit.checkpoint', '{"seq":1,"hash":"00","at":"yesterday"}', now())
		ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value`)
	_, ok, err := audit.LastCheckpoint(ctx, d.App)
	require.Error(t, err)
	assert.False(t, ok)
	assert.ErrorContains(t, err, "read checkpoint")

	// Details that are not a JSON object of strings fail to decode instead of yielding an empty map.
	ownerExec(t, d, `UPDATE audit_log SET details = '[1]'::jsonb WHERE seq = 1`)
	_, _, err = audit.List(ctx, d.App, audit.Filter{})
	require.Error(t, err)
	assert.ErrorContains(t, err, "decode details of entry 1")
	err = audit.Iterate(ctx, d.App, func(audit.Entry) error { return nil })
	require.Error(t, err)
	_, err = audit.Verify(ctx, d.App)
	require.Error(t, err)
}
