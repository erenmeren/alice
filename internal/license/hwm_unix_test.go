//go:build unix

package license_test

import (
	"context"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"alice/internal/license"
)

// The record file must be a regular file: a symlink or a FIFO is refused, never followed
// or waited on.
func TestFileHWMStoreRefusesSpecialFiles(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	target := filepath.Join(dir, "elsewhere")
	require.NoError(t, os.WriteFile(target, []byte(`{"v":1}`), 0o600))
	link := filepath.Join(dir, "link.dat")
	require.NoError(t, os.Symlink(target, link))
	_, err := license.FileHWMStore{Path: link}.Load(ctx)
	require.Error(t, err, "symlink")

	fifo := filepath.Join(dir, "fifo.dat")
	require.NoError(t, syscall.Mkfifo(fifo, 0o600))
	done := make(chan error, 1)
	go func() { _, err := license.FileHWMStore{Path: fifo}.Load(ctx); done <- err }()
	select {
	case err := <-done:
		require.Error(t, err, "FIFO")
	case <-time.After(5 * time.Second):
		t.Fatal("Load blocked on a FIFO")
	}
}
