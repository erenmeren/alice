//go:build windows

package main

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"golang.org/x/sys/windows"

	"alice/internal/providers/windows/winproto"
)

// appcmdTimeout bounds one appcmd run (within winproto.HelperBudget).
const appcmdTimeout = 30 * time.Second

var (
	errAppcmdMissing  = errors.New("appcmd.exe is missing")
	errAppcmdTooLarge = errors.New("appcmd's output is over its bound")
	errAppcmdFailed   = errors.New("appcmd failed")
)

// appcmdSites runs "%windir%\system32\inetsrv\appcmd.exe list site /config /xml" (W0 F6: it works with
// Web-Server alone and follows shared configuration) as the Linux helper runs its programs: a fixed
// absolute path from the system directory (never PATH), fixed arguments, no cmd.exe, an environment of
// SystemRoot only, a timeout, stdout capped at winproto.MaxAppcmdOutput and stderr discarded. It is
// called only when IIS is installed, so a missing appcmd is an error (Ruling 12).
func appcmdSites(ctx context.Context) ([]byte, error) {
	sys, err := windows.GetSystemDirectory()
	if err != nil {
		return nil, err
	}
	root, err := windows.GetSystemWindowsDirectory()
	if err != nil {
		return nil, err
	}
	path := filepath.Join(sys, "inetsrv", "appcmd.exe")
	if st, err := os.Stat(path); err != nil || !st.Mode().IsRegular() {
		return nil, errAppcmdMissing
	}
	ctx, cancel := context.WithTimeout(ctx, appcmdTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, "list", "site", "/config", "/xml") //nolint:gosec // G204: a fixed absolute program with fixed arguments
	cmd.Env = []string{"SystemRoot=" + root}
	cmd.Dir = sys
	cmd.Stdin = nil  // the null device
	cmd.Stderr = nil // discarded
	out := &capWriter{max: winproto.MaxAppcmdOutput}
	cmd.Stdout = out
	cmd.WaitDelay = time.Second // a child that keeps the pipe open does not hold the helper
	err = cmd.Run()
	switch {
	case out.over:
		return nil, errAppcmdTooLarge
	case ctx.Err() != nil, err != nil:
		return nil, errAppcmdFailed
	}
	return out.buf, nil
}

// capWriter keeps at most max bytes and notes that more came (cmd/alice-helper's capWriter).
type capWriter struct {
	max  int
	buf  []byte
	over bool
}

func (w *capWriter) Write(p []byte) (int, error) {
	if len(w.buf)+len(p) > w.max {
		w.over = true
		return len(p), nil
	}
	w.buf = append(w.buf, p...)
	return len(p), nil
}
