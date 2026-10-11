package main

import (
	"bytes"
	"os"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// openPTY opens a pseudo-terminal pair: the controlling side and the path of the terminal side.
func openPTY(t *testing.T) (*os.File, string) {
	t.Helper()
	ptmx, err := os.OpenFile("/dev/ptmx", os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		t.Skipf("no pseudo-terminal: %v", err)
	}
	t.Cleanup(func() { _ = ptmx.Close() })
	fd := int(ptmx.Fd()) //nolint:gosec // G115: a file descriptor fits an int
	require.NoError(t, unix.IoctlSetPointerInt(fd, unix.TIOCSPTLCK, 0))
	n, err := unix.IoctlGetUint32(fd, unix.TIOCGPTN)
	require.NoError(t, err)
	return ptmx, "/dev/pts/" + strconv.FormatUint(uint64(n), 10)
}

// On a terminal the passphrase is read from the terminal with echo off, the prompt on stderr, and the terminal's
// settings are restored afterwards.
func TestPassphraseFromTheTerminal(t *testing.T) {
	ptmx, pts := openPTY(t)
	old := ttyPath
	ttyPath = pts
	t.Cleanup(func() { ttyPath = old })
	term, err := os.OpenFile(pts, os.O_RDWR|unix.O_NOCTTY, 0)
	require.NoError(t, err)
	defer func() { _ = term.Close() }()
	assert.True(t, stdinIsTerminal(term))
	r, w, err := os.Pipe()
	require.NoError(t, err)
	defer func() { _ = r.Close(); _ = w.Close() }()
	assert.False(t, stdinIsTerminal(r), "a pipe is no terminal")
	before, err := unix.IoctlGetTermios(int(term.Fd()), unix.TCGETS) //nolint:gosec // G115
	require.NoError(t, err)

	var stderr bytes.Buffer
	src, ok := newPassphraseSource(false, nil, term, &stderr)
	require.True(t, ok)
	_, err = ptmx.WriteString("kırmızı kedi\n")
	require.NoError(t, err)
	got, err := src.read()
	require.NoError(t, err)
	assert.Equal(t, "kırmızı kedi", string(got))
	assert.Equal(t, "Recovery passphrase: \n", stderr.String())
	after, err := unix.IoctlGetTermios(int(term.Fd()), unix.TCGETS) //nolint:gosec // G115
	require.NoError(t, err)
	assert.Equal(t, before.Lflag, after.Lflag, "echo is back on")

	ttyPath = "/nonexistent/tty"
	_, err = readFromTTY(&stderr)
	assert.Error(t, err)
}
