//go:build integration

package reports_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/platform/validate"
	"alice/internal/reports"
)

func addUser(t *testing.T, w world, name string) uuid.UUID {
	t.Helper()
	id := uuid.New()
	_, err := w.d.Owner.Exec(context.Background(), `INSERT INTO users (id, username, display_name, password_hash, role, created_at, updated_at)
VALUES ($1, $2::text, $2::text, '$argon2id$x', 'operator', now(), now())`, id, name)
	require.NoError(t, err)
	return id
}

// Review Focus 5, R42 row 15: views are private, bounded, named uniquely, and hold only the page's filter keys.
func TestViewsArePrivateAndBounded(t *testing.T) {
	w := newWorld(t, false)
	ctx := context.Background()
	ada, bob := addUser(t, w, "ada"), addUser(t, w, "bob")
	v, err := w.svc.CreateView(ctx, ada, reports.PageCertificates, "Expiring on web-1",
		map[string]string{"expiry": "30", "target_id": w.web1.String()})
	require.NoError(t, err)
	_, err = w.svc.CreateView(ctx, ada, reports.PageCertificates, "EXPIRING on WEB-1", map[string]string{})
	assert.ErrorIs(t, err, reports.ErrViewName)
	list, err := w.svc.Views(ctx, bob, reports.PageCertificates)
	require.NoError(t, err)
	assert.Empty(t, list, "another user's views are invisible")
	assert.ErrorIs(t, w.svc.DeleteView(ctx, bob, v.ID), reports.ErrNotFound)
	for _, bad := range []map[string]string{{"cursor": "x"}, {"os_user": "root"}, {"q": strings.Repeat("x", 201)}, {"q": "a\x00b"}} {
		_, err := w.svc.CreateView(ctx, ada, reports.PageCertificates, "bad", bad)
		var verrs validate.Errors
		assert.True(t, errors.As(err, &verrs), "%v", bad)
	}
	_, err = w.svc.CreateView(ctx, ada, "targets", "x", nil)
	assert.Error(t, err)
	for i := 1; i < reports.MaxViewsPerUser; i++ {
		_, err := w.svc.CreateView(ctx, ada, reports.PageSSHKeys, "v"+uuid.NewString()[:8], map[string]string{"os_user": "root"})
		require.NoError(t, err)
	}
	_, err = w.svc.CreateView(ctx, ada, reports.PageSSHKeys, "one too many", nil)
	assert.ErrorIs(t, err, reports.ErrViewLimit)
	require.NoError(t, w.svc.DeleteView(ctx, ada, v.ID))
	assert.Equal(t, []string{"target_id", "source", "q", "expiry"}, reports.ViewQueryKeys(reports.PageCertificates))
	assert.Equal(t, []string{"target_id", "os_user", "q", "flag", "missing"}, reports.ViewQueryKeys(reports.PageSSHKeys))
}
