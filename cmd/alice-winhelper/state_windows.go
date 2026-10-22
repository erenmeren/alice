//go:build windows

package main

// The helper's state on disk (W2 Global Constraints, Ruling 8): the data directory winproto.DataDir
// (made by the setup script, Administrators and SYSTEM only), its journal\ and bindings\ directories
// (made here, inheriting its ACL), imports.json and helper.lock.
//
//	https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-lockfileex
//	https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-movefileexw
//	https://learn.microsoft.com/en-us/windows/win32/api/aclapi/nf-aclapi-getnamedsecurityinfow
//
// Every state file is written as <name>.tmp, flushed, then renamed over the file with
// MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH. Reads and writes never follow a reparse point.

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/windows"

	"alice/internal/providers/windows/winhelper"
	"alice/internal/providers/windows/winproto"
)

const (
	lockFile = "helper.lock"
	// lockPoll is how often Lock tries again while another process holds the lock.
	lockPoll = 200 * time.Millisecond
	// maxStateFile is winhelper's bound on a state file; ReadState reads one byte more, so winhelper
	// sees a longer file and refuses it.
	maxStateFile = 512 << 10
)

// lockWait bounds Lock's wait (tests lower it).
var lockWait = winproto.LockWait

// stateDirs are the data directory's subdirectories a state name may name.
var stateDirs = []string{"journal", "bindings"}

var (
	stateNameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,127}$`)
	errState    = errors.New("a state file cannot be read or written")
)

// statePath turns a state name ("journal/<op>.json", "bindings/<hash>.json", "imports.json") into its
// path under the data directory; false for any other shape.
func (h host) statePath(name string) (string, bool) {
	parts := strings.Split(name, "/")
	if len(parts) > 2 {
		return "", false
	}
	for _, p := range parts {
		if !stateNameRE.MatchString(p) || strings.Contains(p, "..") || strings.HasSuffix(p, ".tmp") {
			return "", false
		}
	}
	if len(parts) == 2 {
		known := false
		for _, d := range stateDirs {
			known = known || parts[0] == d
		}
		if !known {
			return "", false
		}
	}
	return filepath.Join(append([]string{h.dataDir}, parts...)...), true
}

// ReadState reads a state file: at most maxStateFile+1 bytes, never through a reparse point and never
// anything but a regular file.
func (h host) ReadState(name string) ([]byte, bool, error) {
	path, ok := h.statePath(name)
	if !ok {
		return nil, false, errState
	}
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, false, errState
	}
	// Every share mode: a reader (iis-status runs without the lock) must never make a writer's
	// replace-rename fail.
	fh, err := windows.CreateFile(p, windows.GENERIC_READ,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING,
		windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) || errors.Is(err, windows.ERROR_PATH_NOT_FOUND) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, errState
	}
	f := os.NewFile(uintptr(fh), path)
	defer func() { _ = f.Close() }()
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(fh, &info); err != nil ||
		info.FileAttributes&(windows.FILE_ATTRIBUTE_REPARSE_POINT|windows.FILE_ATTRIBUTE_DIRECTORY) != 0 {
		return nil, false, errState
	}
	data, err := io.ReadAll(io.LimitReader(f, maxStateFile+1))
	if err != nil {
		return nil, false, errState
	}
	return data, true, nil
}

// WriteState replaces a state file durably: <name>.tmp written and flushed, then renamed over the
// file, write through.
func (h host) WriteState(name string, data []byte) error {
	path, ok := h.statePath(name)
	if !ok {
		return errState
	}
	if dir := filepath.Dir(path); dir != h.dataDir {
		if err := os.Mkdir(dir, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
			return errState
		}
	}
	tmp := path + ".tmp"
	if err := os.Remove(tmp); err != nil && !errors.Is(err, os.ErrNotExist) {
		return errState
	}
	if err := writeFlushed(tmp, data); err != nil {
		_ = os.Remove(tmp)
		return errState
	}
	from, err := windows.UTF16PtrFromString(tmp)
	if err != nil {
		return errState
	}
	to, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return errState
	}
	if err := replaceFile(from, to); err != nil {
		_ = os.Remove(tmp)
		return errState
	}
	return nil
}

// Retries of the replace-rename while another process (a scanner, a backup agent) has the file open
// without FILE_SHARE_DELETE.
const (
	moveTries = 5
	moveWait  = 50 * time.Millisecond
)

// replaceFile renames from over to, write through, retrying a sharing violation or access denial a
// few times.
func replaceFile(from, to *uint16) error {
	var err error
	for i := range moveTries {
		err = windows.MoveFileEx(from, to, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH)
		if err == nil || !errors.Is(err, windows.ERROR_SHARING_VIOLATION) && !errors.Is(err, windows.ERROR_ACCESS_DENIED) {
			return err
		}
		if i < moveTries-1 {
			time.Sleep(moveWait)
		}
	}
	return err
}

// writeFlushed creates path (it must not exist) and writes data with FlushFileBuffers before closing.
func writeFlushed(path string, data []byte) error {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	fh, err := windows.CreateFile(p, windows.GENERIC_WRITE, 0, nil, windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return err
	}
	for len(data) > 0 {
		var n uint32
		if err := windows.WriteFile(fh, data, &n, nil); err != nil || n == 0 {
			_ = windows.CloseHandle(fh)
			return errState
		}
		data = data[n:]
	}
	if err := windows.FlushFileBuffers(fh); err != nil {
		_ = windows.CloseHandle(fh)
		return err
	}
	return windows.CloseHandle(fh)
}

// DataDirSafe refuses (winhelper.ErrJournal) a data directory that is missing, not a directory, a
// reparse point, not owned by Administrators or SYSTEM, or not writable; journal\ and bindings\ are
// made when missing (inheriting its ACL) and checked the same way.
func (h host) DataDirSafe() error {
	if err := trustedDir(h.dataDir); err != nil {
		return err
	}
	for _, d := range stateDirs {
		dir := filepath.Join(h.dataDir, d)
		err := os.Mkdir(dir, 0o700)
		switch {
		case err == nil:
			// The new directory's owner is the token's default owner, Administrators for an elevated
			// token by the Server default; set it explicitly so another policy does not refuse it below.
			if err := ownByAdministrators(dir); err != nil {
				return winhelper.ErrJournal
			}
		case !errors.Is(err, os.ErrExist):
			return winhelper.ErrJournal
		}
		// Made now or before: re-checked (owner Administrators or SYSTEM, no reparse point).
		if err := trustedDir(dir); err != nil {
			return err
		}
	}
	probe := filepath.Join(h.dataDir, "journal", "write-probe.tmp")
	p, err := windows.UTF16PtrFromString(probe)
	if err != nil {
		return winhelper.ErrJournal
	}
	fh, err := windows.CreateFile(p, windows.GENERIC_WRITE, 0, nil, windows.CREATE_ALWAYS,
		windows.FILE_ATTRIBUTE_TEMPORARY|windows.FILE_FLAG_DELETE_ON_CLOSE, 0)
	if err != nil {
		return winhelper.ErrJournal
	}
	_ = windows.CloseHandle(fh)
	return nil
}

// ownByAdministrators makes BUILTIN\Administrators the owner of a directory the helper made.
func ownByAdministrators(dir string) error {
	admins, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION, admins, nil, nil, nil)
}

// trustedDir checks one directory: a directory, no reparse point, owned by Administrators or SYSTEM.
func trustedDir(dir string) error {
	p, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		return winhelper.ErrJournal
	}
	attrs, err := windows.GetFileAttributes(p)
	if err != nil || attrs&windows.FILE_ATTRIBUTE_DIRECTORY == 0 || attrs&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return winhelper.ErrJournal
	}
	sd, err := windows.GetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return winhelper.ErrJournal
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil ||
		!owner.IsWellKnown(windows.WinBuiltinAdministratorsSid) && !owner.IsWellKnown(windows.WinLocalSystemSid) {
		return winhelper.ErrJournal
	}
	return nil
}

// openLock opens (creating when create is set) helper.lock, never through a reparse point.
func (h host) openLock(create bool) (windows.Handle, error) {
	p, err := windows.UTF16PtrFromString(filepath.Join(h.dataDir, lockFile))
	if err != nil {
		return 0, err
	}
	disposition := uint32(windows.OPEN_EXISTING)
	if create {
		disposition = windows.OPEN_ALWAYS
	}
	return windows.CreateFile(p, windows.GENERIC_READ|windows.GENERIC_WRITE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, disposition,
		windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
}

// tryLock takes the exclusive lock of the file's first byte without waiting; held is true when
// another handle holds it.
func tryLock(fh windows.Handle) (ol *windows.Overlapped, held bool, err error) {
	ol = new(windows.Overlapped)
	err = windows.LockFileEx(fh, windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, ol)
	if errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
		return nil, true, nil
	}
	if err != nil {
		return nil, false, err
	}
	return ol, false, nil
}

// Lock takes helper.lock (LockFileEx, exclusive), trying every lockPoll for at most lockWait, then
// winhelper.ErrBusy. The release unlocks and closes once.
func (h host) Lock(ctx context.Context) (func(), error) {
	fh, err := h.openLock(true)
	if err != nil {
		return nil, errState
	}
	deadline := h.now().Add(lockWait)
	for {
		ol, held, err := tryLock(fh)
		if err != nil {
			_ = windows.CloseHandle(fh)
			return nil, errState
		}
		if !held {
			var once sync.Once
			return func() {
				once.Do(func() {
					_ = windows.UnlockFileEx(fh, 0, 1, 0, ol)
					_ = windows.CloseHandle(fh)
				})
			}, nil
		}
		if !h.now().Before(deadline) {
			_ = windows.CloseHandle(fh)
			return nil, winhelper.ErrBusy
		}
		t := time.NewTimer(lockPoll)
		select {
		case <-ctx.Done():
			t.Stop()
			_ = windows.CloseHandle(fh)
			return nil, ctx.Err()
		case <-t.C:
		}
	}
}

// LockHeld reports whether another handle holds helper.lock now (a status's Active); a missing or
// unreadable lock file is not held.
func (h host) LockHeld() bool {
	fh, err := h.openLock(false)
	if err != nil {
		return false
	}
	defer func() { _ = windows.CloseHandle(fh) }()
	ol, held, err := tryLock(fh)
	if err != nil {
		return false
	}
	if !held {
		_ = windows.UnlockFileEx(fh, 0, 1, 0, ol)
	}
	return held
}
