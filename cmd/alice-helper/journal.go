//go:build linux

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"reflect"
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

// fileID identifies a file by inode and size, so the sweep can tell a key it installed without
// opening it.
type fileID struct {
	Dev  uint64 `json:"dev"`
	Ino  uint64 `json:"ino"`
	Size int64  `json:"size"`
}

func idOf(st unix.Stat_t) fileID { return fileID{Dev: st.Dev, Ino: st.Ino, Size: st.Size} }

// keyIDs are the key file's inodes the operation knows: the one it replaced, the one it installed,
// and the one a restore put back.
type keyIDs struct {
	Old      fileID `json:"old"`
	New      fileID `json:"new"`
	Restored fileID `json:"restored"`
}

// journal is the on-disk record of one nginx-deploy operation, <BackupRoot>/<op>/journal.json
// (0600 in the 0700 root-only operation directory). nginx-status and nginx-restore read it after
// any interruption. It holds paths, hashes, owners and modes, never key material.
type journal struct {
	Op           string   `json:"op"`
	Phase        string   `json:"phase"`
	CertPath     string   `json:"cert_path"`
	KeyPath      string   `json:"key_path"`
	CertResolved string   `json:"cert_resolved"`
	KeyResolved  string   `json:"key_resolved"`
	OldCertSHA   string   `json:"old_cert_sha256"`
	OldKeySHA    string   `json:"old_key_sha256"`
	NewCertSHA   string   `json:"new_cert_sha256"`
	NewKeySHA    string   `json:"new_key_sha256"`
	CertMeta     fileMeta `json:"cert_meta"`
	KeyMeta      fileMeta `json:"key_meta"`
	FailedStep   string   `json:"failed_step"`
	CauseStep    string   `json:"cause_step"`
	// Partial: this operation's own rollback found a file of the pair changed by someone else; it
	// puts back only the files it wrote (also when nginx-restore finishes it later).
	Partial bool `json:"partial"`
	// PrevRecord is the pair record (latest operation) before this operation took it over: a
	// refusal before the first rename puts it back, also on a re-run after a crash.
	PrevRecord string                  `json:"prev_record"`
	KeyIDs     keyIDs                  `json:"key_ids"`
	Error      string                  `json:"error"`
	Steps      []helperproto.NginxStep `json:"steps"`
	// ForbiddenSPKI and ForbiddenLeaf are the rollback guard nginx-deploy received (protocol 10,
	// R48): no restore of this operation puts back a backup that holds one of them.
	ForbiddenSPKI []string `json:"forbidden_spki_sha256,omitempty"`
	ForbiddenLeaf []string `json:"forbidden_leaf_sha256,omitempty"`
}

var journalPhases = []string{helperproto.PhasePrepared, helperproto.PhaseWriting, helperproto.PhaseCommitted,
	helperproto.PhaseUnchanged, helperproto.PhaseRestoring, helperproto.PhaseRestored, helperproto.PhaseRestoreFailed, helperproto.PhaseRestoreForbidden}

// valid reports a journal that describes operation op with paths the helper accepts. A fence's
// tombstone (PhaseFenced) carries nothing but its operation and the pair record it may have handed
// back (a prepared journal it replaced).
func (j journal) valid(op string) bool {
	if j.Phase == helperproto.PhaseFenced {
		tomb := journal{Op: j.Op, Phase: j.Phase, PrevRecord: j.PrevRecord, Steps: j.Steps}
		return j.Op == op && len(j.Steps) == 0 && reflect.DeepEqual(tomb, j) && (j.PrevRecord == "" || helperproto.ValidOpID(j.PrevRecord))
	}
	paths := []string{j.CertPath, j.KeyPath, j.CertResolved, j.KeyResolved}
	for _, p := range paths {
		if !helperproto.ValidPath(p) || p == "/" {
			return false
		}
	}
	return j.Op == op && slices.Contains(journalPhases, j.Phase) && len(j.Steps) <= maxSteps &&
		(j.PrevRecord == "" || helperproto.ValidOpID(j.PrevRecord)) && helperproto.ValidForbidden(j.ForbiddenSPKI) &&
		helperproto.ValidForbidden(j.ForbiddenLeaf)
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
//
// A journal readJournal would refuse (A1-I1: a path outside the vocabulary, too many steps, an
// unknown phase) is never written: errBadJournal, and the previous journal stays.
func (s *sys) writeJournal(dir *os.File, j journal) error {
	if j.Steps == nil {
		j.Steps = []helperproto.NginxStep{}
	}
	if !j.valid(j.Op) || !helperproto.ValidOpID(j.Op) || dir.Name() != j.Op {
		return errBadJournal // dir is <BackupRoot>/<op> (opDir): its journal is read as op's
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
	if err := s.pointErr("journal " + j.Phase + " staged"); err != nil {
		return err
	}
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

// pointErr is point for the places where a test injects a failure: an error other than errKilled
// is returned to the caller as if the operation there had failed.
func (s *sys) pointErr(name string) error {
	if s.afterDeployStep == nil {
		return nil
	}
	err := s.afterDeployStep(name)
	if errors.Is(err, errKilled) {
		s.killed = true
		panic(errKilled)
	}
	return err
}

// pairsDirName holds one record per resolved (certificate, key) pair: the operation that last
// started replacing its files. nginx-restore rolls back only that operation (no walking back
// through retained operations to an older key). Records are tiny, one per pair ever deployed, and
// never swept: a record must outlive every operation directory it makes unrestorable.
const pairsDirName = "pairs"

// pairName is a pair's record file name: the hex SHA-256 of its two resolved paths.
func pairName(j journal) string { return hexSHA([]byte(j.CertResolved + "\x00" + j.KeyResolved)) }

// pairRecord returns the operation recorded for j's pair ("" when there is none).
func (s *sys) pairRecord(j journal) (string, error) {
	dir, err := s.openStateDir(pairsDirName, false)
	if errors.Is(err, unix.ENOENT) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	defer func() { _ = dir.Close() }()
	data, err := readBackup(dir, pairName(j))
	if errors.Is(err, unix.ENOENT) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	op := string(bytes.TrimSpace(data))
	if !helperproto.ValidOpID(op) {
		return "", errBadJournal
	}
	return op, nil
}

// setPairRecord records op for j's pair (op "" removes the record), atomically and durably: a
// crash leaves the old record or the new one.
func (s *sys) setPairRecord(j journal, op string) error {
	dir, err := s.openStateDir(pairsDirName, true)
	if err != nil {
		return err
	}
	defer func() { _ = dir.Close() }()
	dfd := int(dir.Fd()) //nolint:gosec // G115: a descriptor fits an int
	name := pairName(j)
	if op == "" {
		if err := unix.Unlinkat(dfd, name, 0); err != nil && !errors.Is(err, unix.ENOENT) {
			return err
		}
		return dir.Sync()
	}
	tmp := name + ".tmp"
	_ = unix.Unlinkat(dfd, tmp, 0)
	if err := writeNewAt(dir, tmp, []byte(op+"\n")); err != nil {
		return err
	}
	if err := s.pointErr("pair record staged"); err != nil {
		return err
	}
	if err := unix.Renameat(dfd, tmp, dfd, name); err != nil {
		return err
	}
	s.point("pair record renamed")
	return dir.Sync()
}

// maxRecordChain bounds the walk from a pair record through operations that changed nothing.
const maxRecordChain = 64

// latestOp resolves j's pair record to the operation that last actually replaced files: an
// operation whose journal says prepared or unchanged changed nothing, so the record falls through
// to its prev_record; so does a fence's tombstone (it replaced nothing and never takes a record,
// AUD-05). ok is false when that cannot be decided (a record naming an operation
// without a directory or a journal — removed by cleanup or the sweep — an unreadable journal, a
// loop, or a chain longer than maxRecordChain): the caller then treats every other operation as
// superseded. op "" with ok means no operation ever replaced the pair's files.
func (s *sys) latestOp(j journal) (op string, ok bool, err error) {
	op, err = s.pairRecord(j)
	if err != nil {
		return "", false, err
	}
	seen := map[string]bool{}
	for range maxRecordChain {
		if op == "" || op == j.Op || seen[op] {
			return op, !seen[op], nil
		}
		seen[op] = true
		dir, err := s.opDir(op, false)
		if err != nil {
			return op, false, nil
		}
		other, found, err := readJournal(dir, op)
		_ = dir.Close()
		if err != nil || !found {
			return op, false, nil
		}
		if other.Phase != helperproto.PhasePrepared && other.Phase != helperproto.PhaseUnchanged && other.Phase != helperproto.PhaseFenced {
			return op, true, nil
		}
		op = other.PrevRecord
	}
	return op, false, nil
}

// superseded reports that j is not the operation that last actually replaced its pair's files
// (or that this cannot be established). Once the pair's latest operation is cleaned up or swept,
// no older retained operation of that pair can be restored.
func (s *sys) superseded(j journal) (bool, error) {
	op, ok, err := s.latestOp(j)
	if err != nil {
		return false, err
	}
	return !ok || (op != "" && op != j.Op), nil
}

// releaseRecord hands the pair record back to prev_record before an operation that changed
// nothing (prepared, unchanged) is removed while the record names it, so removing a no-op never
// makes the operation before it unrestorable. false: the record could not be updated (the
// operation is then kept).
func (s *sys) releaseRecord(j journal) bool {
	if j.Phase != helperproto.PhasePrepared && j.Phase != helperproto.PhaseUnchanged && j.Phase != helperproto.PhaseFenced {
		return true
	}
	if j.CertResolved == "" {
		return true // a tombstone that never replaced a prepared journal has no pair
	}
	rec, err := s.pairRecord(j)
	if err != nil {
		return false
	}
	return rec != j.Op || s.setPairRecord(j, j.PrevRecord) == nil
}

// survive turns the test kill (errKilled) into an IO_ERROR answer; any other panic goes on.
func survive(r any) error {
	if err, ok := r.(error); ok && errors.Is(err, errKilled) {
		return failed(helperproto.CodeIOError, "the helper was stopped (test)")
	}
	panic(r)
}
