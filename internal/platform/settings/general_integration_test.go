//go:build integration

package settings_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/platform/settings"
	"alice/internal/testutil/pgtest"
)

func TestMain(m *testing.M) { os.Exit(pgtest.Main(m)) }

func TestGeneralDefaultsAndStoredValues(t *testing.T) {
	d := pgtest.New(t)
	ctx := context.Background()
	g, err := settings.GetGeneral(ctx, d.App)
	require.NoError(t, err)
	assert.Equal(t, settings.General{RetiredKeyRetentionDays: settings.DefaultRetiredKeyRetentionDays}, g)
	require.NoError(t, settings.Set(ctx, d.App, settings.GeneralKey,
		settings.General{PublicURL: "https://alice.example.com", RetiredKeyRetentionDays: 90, Version: 2}, time.Now()))
	g, err = settings.GetGeneral(ctx, d.App)
	require.NoError(t, err)
	assert.Equal(t, settings.General{PublicURL: "https://alice.example.com", RetiredKeyRetentionDays: 90, Version: 2}, g)
}

func TestGeneralRepairsAnOutOfRangeRetentionAndReportsBadJSON(t *testing.T) {
	d := pgtest.New(t)
	ctx := context.Background()
	require.NoError(t, settings.Set(ctx, d.App, settings.GeneralKey, map[string]any{"public_url": "https://a.example.com", "retired_key_retention_days": 0}, time.Now()))
	g, err := settings.GetGeneral(ctx, d.App)
	require.NoError(t, err)
	assert.Equal(t, settings.DefaultRetiredKeyRetentionDays, g.RetiredKeyRetentionDays)
	assert.Equal(t, "https://a.example.com", g.PublicURL)
	require.NoError(t, settings.Set(ctx, d.App, settings.GeneralKey, []int{1}, time.Now()))
	_, err = settings.GetGeneral(ctx, d.App)
	assert.Error(t, err)
}
