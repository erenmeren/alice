//go:build integration && unix

package secrets_test

import (
	"context"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/secrets"
	"alice/internal/testutil/pgtest"
)

// A directory or a FIFO in place of the key file is refused; the FIFO case needs mkfifo (Unix).
func TestKeyFileNonRegularIsRefused(t *testing.T) {
	d := pgtest.New(t)
	ctx := context.Background()

	asDir := t.TempDir()
	require.NoError(t, os.Mkdir(filepath.Join(asDir, secrets.MasterKeyFile), 0o700))
	_, err := secrets.LoadOrCreateMasterKey(ctx, d.App, asDir, now)
	require.ErrorIs(t, err, secrets.ErrMasterKeyInvalid)
	assert.Contains(t, err.Error(), "regular file")

	asFifo := t.TempDir()
	require.NoError(t, syscall.Mkfifo(filepath.Join(asFifo, secrets.MasterKeyFile), 0o400))
	_, err = secrets.LoadOrCreateMasterKey(ctx, d.App, asFifo, now) // must not block on open
	require.ErrorIs(t, err, secrets.ErrMasterKeyInvalid)
	assert.Equal(t, 0, versionRows(t, d))
}
