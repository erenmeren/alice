//go:build integration

package audit_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/audit"
	"alice/internal/platform/clock"
	"alice/internal/testutil/pgtest"
)

func TestLastCheckpoint(t *testing.T) {
	d := pgtest.New(t)
	ctx := context.Background()
	_, ok, err := audit.LastCheckpoint(ctx, d.App)
	require.NoError(t, err)
	assert.False(t, ok)
	clk := clock.NewFake(time.Date(2026, 10, 7, 9, 0, 0, 0, time.UTC))
	svc := audit.NewService(audit.New(clk), d.App)
	require.NoError(t, svc.Write(ctx, audit.Event{Actor: audit.SystemActor("test"), Action: "test.one", Result: audit.Success}))
	rep, err := svc.Verify(ctx, audit.SystemActor("test"))
	require.NoError(t, err)
	cp, ok, err := audit.LastCheckpoint(ctx, d.App)
	require.NoError(t, err)
	require.True(t, ok)
	assert.Equal(t, rep.HeadSeq, cp.Seq)
	assert.Regexp(t, `^[0-9a-f]{64}$`, cp.Hash)
	assert.Equal(t, clk.Now(), cp.At)
}
