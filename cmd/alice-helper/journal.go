//go:build linux

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"slices"

	"golang.org/x/sys/unix"

	"alice/internal/providers/linuxssh/helperproto"
)

// errBusy: another nginx-deploy or nginx-restore holds the lock.
var errBusy = errors.New("another certificate change is running")

// errKilled is what a test's afterDeployStep returns to simulate the helper dying at that point:
// the helper stops there without any cleanup (sys.killed), as a SIGKILL would stop it.
var errKilled = errors.New("killed (test)")

// errBadJournal: a journal that cannot be decoded or does not describe its own operation.
var errBadJournal = errors.New("the journal is not valid")

const (
	journalName   = "journal.json"
	journalTmp    = "journal.tmp"
	journalLimit  = 64 << 10
	certBackup    = "cert.bak"
	keyBackup     = "key.bak"
	nginxLockName = "nginx.lock"
	// maxSteps bounds the steps a journal keeps (its validation refuses more): repeated restores
	// of one operation keep its deployment's steps and its latest attempts (trimSteps).
	maxSteps = 64
	// keptHead is how many of the first steps (the deployment's own) trimSteps never drops.
	keptHead = 12
)

// trimSteps leaves room for one more restore (a few steps) under maxSteps: it keeps the first
// keptHead steps and the most recent ones.
func trimSteps(steps []helperproto.NginxStep) []helperproto.NginxStep {
	limit := maxSteps - 8
	if len(steps) <= limit {
		return steps
	}
	return append(append([]helperproto.NginxStep{}, steps[:keptHead]...), steps[len(steps)-(limit-keptHead):]...)
}

// fileMeta is the owner, group and mode a replaced file had; nginx-restore puts them back.
type fileMeta struct {
	Mode uint32 `json:"mode"`
	UID  int    `json:"uid"`
	GID  int    `json:"gid"`
}

// journal is the on-disk record of one nginx-deploy operation, <BackupRoot>/<op>/journal.json
// (0600 in the 0700 root-only operation directory). nginx-status and nginx-restore read it after
// any interruption. It holds paths, hashes, owners and modes, never key material.
type journal struct {
	Op           string                  `json:"op"`
	Phase        string                  `json:"phase"`
	CertPath     string                  `json:"cert_path"`
	KeyPath      string                  `json:"key_path"`
	CertResolved string                  `json:"cert_resolved"`
	KeyResolved  string                  `json:"key_resolved"`
	OldCertSHA   string                  `json:"old_cert_sha256"`
	OldKeySHA    string                  `json:"old_key_sha256"`
	NewCertSHA   string                  `json:"new_cert_sha256"`
	NewKeySHA    string                  `json:"new_key_sha256"`
	CertMeta     fileMeta                `json:"cert_meta"`
	KeyMeta      fileMeta                `json:"key_meta"`
	FailedStep   string                  `json:"failed_step"`
	Error        string                  `json:"error"`
	Steps        []helperproto.NginxStep `json:"steps"`
}

var journalPhases = []string{helperproto.PhasePrepared, helperproto.PhaseWriting, helperproto.PhaseCommitted,
	helperproto.PhaseUnchanged, helperproto.PhaseRestoring, helperproto.PhaseRestored, helperproto.PhaseRestoreFailed}

// valid reports a journal that describes operation op with paths the helper accepts.
func (j journal) valid(op string) bool {
	paths := []string{j.CertPath, j.KeyPath, j.CertResolved, j.KeyResolved}
	for _, p := range paths {
		if !helperproto.ValidPath(p) || p == "/" {
			return false
		}
	}
	return j.Op == op && slices.Contains(journalPhases, j.Phase) && len(j.Steps) <= maxSteps
}

// opDir opens (with create: makes) <BackupRoot>/<op>, root-only (0700), never through a link. op
// passed helperproto.ValidOpID.
func (s *sys) opDir(op string, create bool) (*os.File, error) {
	root, err := s.openBackupRoot(create)
	if err != nil {
		return nil, err
	}
	defer func() { _ = root.Close() }()
	return subdir(root, op, create)
}

// readJournal reads the journal of operation op from its directory; found is false when there is
// none.
func readJournal(dir *os.File, op string) (j journal, found bool, err error) {
	fd, err := unix.Openat(int(dir.Fd()), journalName, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0) //nolint:gosec // G115: a descriptor fits an int
	if errors.Is(err, unix.ENOENT) {
		return j, false, nil
	}
	if err != nil {
		return j, false, err
	}
	f := os.NewFile(uintptr(fd), journalName)
	defer func() { _ = f.Close() }()
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil || st.Mode&unix.S_IFMT != unix.S_IFREG {
		return j, false, errBadJournal
	}
	data, err := io.ReadAll(io.LimitReader(f, journalLimit+1))
	if err != nil || len(data) > journalLimit {
		return j, false, errBadJournal
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&j); err != nil || dec.More() || !j.valid(op) {
		return journal{}, false, errBadJournal
	}
	return j, true, nil
}

// writeJournal replaces the journal atomically and durably: journal.tmp (O_EXCL, 0600) written and
// synced, renamed over journal.json, then the directory synced. A crash at any point leaves the
// previous journal or the new one, never a mix; a stale journal.tmp is removed by the next write.
func (s *sys) writeJournal(dir *os.File, j journal) error {
	if j.Steps == nil {
		j.Steps = []helperproto.NginxStep{}
	}
	raw, err := json.Marshal(j)
	if err != nil {
		return err
	}
	dfd := int(dir.Fd()) //nolint:gosec // G115: a descriptor fits an int
	_ = unix.Unlinkat(dfd, journalTmp, 0)
	if err := writeNewAt(dir, journalTmp, raw); err != nil {
		return err
	}
	s.point("journal " + j.Phase + " staged")
	if err := unix.Renameat(dfd, journalTmp, dfd, journalName); err != nil {
		return err
	}
	s.point("journal " + j.Phase + " renamed")
	return dir.Sync()
}

// nginxLock serializes nginx-deploy, nginx-restore and the sweep of Nginx operations on a server:
// <state>/locks/nginx.lock, a root-private file, held for the whole operation. The wait is bounded
// by lockWait (errBusy). Closing the returned file releases the lock; so does the helper's death.
func (s *sys) nginxLock(ctx context.Context) (*os.File, error) {
	locks, err := s.openStateDir(lockDirName, true)
	if err != nil {
		return nil, err
	}
	defer func() { _ = locks.Close() }()
	f, err := openLockFile(int(locks.Fd()), nginxLockName, true) //nolint:gosec // G115: a descriptor fits an int
	if err != nil {
		return nil, err
	}
	wctx, cancel := context.WithTimeout(ctx, lockWait)
	defer cancel()
	if err := flockWait(wctx, int(f.Fd())); err != nil { //nolint:gosec // G115: a descriptor fits an int
		_ = f.Close()
		return nil, errBusy
	}
	return f, nil
}

// tryNginxLock takes the Nginx lock without waiting (nil when another process holds it).
func (s *sys) tryNginxLock() *os.File {
	locks, err := s.openStateDir(lockDirName, true)
	if err != nil {
		return nil
	}
	defer func() { _ = locks.Close() }()
	f, err := openLockFile(int(locks.Fd()), nginxLockName, true) //nolint:gosec // G115: a descriptor fits an int
	if err != nil {
		return nil
	}
	if unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB) != nil { //nolint:gosec // G115: a descriptor fits an int
		_ = f.Close()
		return nil
	}
	return f
}

// nginxLockHeld reports whether a helper process holds the Nginx lock now (nginx-status).
func (s *sys) nginxLockHeld() bool {
	locks, err := s.openStateDir(lockDirName, false)
	if err != nil {
		return false
	}
	defer func() { _ = locks.Close() }()
	f, err := openLockFile(int(locks.Fd()), nginxLockName, false) //nolint:gosec // G115: a descriptor fits an int
	if err != nil {
		return false
	}
	defer func() { _ = f.Close() }()
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil { //nolint:gosec // G115: a descriptor fits an int
		return true
	}
	_ = unix.Flock(int(f.Fd()), unix.LOCK_UN) //nolint:gosec // G115: a descriptor fits an int
	return false
}

// point runs the test hook at a named point of nginx-deploy or nginx-restore. A hook that returns
// an error kills the helper there: sys.killed stops every cleanup and the panic unwinds to the
// subcommand, which answers like a dead process would not (tests only; nil in production).
func (s *sys) point(name string) {
	if s.afterDeployStep == nil {
		return
	}
	if err := s.afterDeployStep(name); err != nil {
		s.killed = true
		panic(errKilled)
	}
}

// survive turns the test kill (errKilled) into an IO_ERROR answer; any other panic goes on.
func survive(r any) error {
	if err, ok := r.(error); ok && errors.Is(err, errKilled) {
		return failed(helperproto.CodeIOError, "the helper was stopped (test)")
	}
	panic(r)
}
