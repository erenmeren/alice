//go:build linux

package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"time"

	"golang.org/x/sys/unix"

	"alice/internal/providers/linuxssh/helperproto"
)

// stepTimeout bounds nginx -t, and the reload with is-active, once the transaction can no longer
// stop (runProgram bounds each program run as well).
const stepTimeout = 30 * time.Second

// maxNginxOps bounds the Nginx operation directories kept on a server (each holds a certificate
// and a key backup of at most MaxCertFileSize): a caller that loops deployments cannot fill the
// disk with backups. Tests lower it.
var maxNginxOps = 1000

const (
	kindCert = "cert"
	kindKey  = "key"
)

var (
	errBadName         = errors.New("the file name has no certificate or key extension")
	errBadContent      = errors.New("the new content is not a certificate chain and its private key")
	errChangedByOthers = errors.New("the file was changed by someone else")
	errUnstable        = errors.New("the file changed while it was read")
	errDeadline        = errors.New("the time budget ended before the file was replaced")
)

// stagedName is the deterministic name of the staged file of one operation and one file of the
// pair (S2): a staged file a dead helper left behind is found again and removed by nginx-restore,
// a new run of the operation and the backup sweep. It has no certificate extension, so it is never
// a file the helper reads or replaces as part of a pair.
func stagedName(op, kind string) string { return ".alice-" + op + "-" + kind }

// target is a certificate or key file found under the lock, with the descriptors it was resolved
// and read through.
type target struct {
	rf   rootFile
	f    *os.File
	st   unix.Stat_t
	data []byte
}

func (t *target) close() {
	clear(t.data)
	_ = t.f.Close()
	t.rf.close()
}

// readTarget resolves and reads one existing file of the pair through the root-controlled walk:
// every directory and link root's, a certificate or key file name, a regular file with one link on
// a normal file system, at most MaxCertFileSize. It is read into one buffer of its size (a key is
// never copied by a growing read), cleared by close.
func (s *sys) readTarget(p string) (*target, error) {
	rf, err := s.resolveRoot(p)
	if err != nil {
		return nil, err
	}
	if !certName(rf.name) {
		rf.close()
		return nil, errBadName
	}
	f, st, err := rf.open()
	if err != nil {
		rf.close()
		return nil, err
	}
	t := &target{rf: rf, f: f, st: st}
	if st.Size > helperproto.MaxCertFileSize {
		t.close()
		return nil, errTooLarge
	}
	buf := make([]byte, st.Size+1)
	n, err := io.ReadFull(f, buf)
	if !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF) {
		clear(buf)
		t.close()
		return nil, errUnstable // a read error, or the file grew since fstat
	}
	t.data = buf[:n]
	return t, nil
}

// targetError maps a readTarget error to the answer (nothing has changed yet).
func targetError(err error) error {
	switch {
	case errors.Is(err, unix.ENOENT):
		return precondition(helperproto.CodeNotFound, "the certificate or key file does not exist")
	case errors.Is(err, errUnsafe):
		return refused(helperproto.CodeUnsafeFile, "the certificate or key file is hard-linked")
	case errors.Is(err, errNotRegular), errors.Is(err, unix.ENOTDIR), errors.Is(err, unix.ELOOP), errors.Is(err, errTooManyLinks):
		return refused(helperproto.CodeNotRegularFile, "the certificate or key path is not a regular file")
	case errors.Is(err, errTooLarge):
		return refused(helperproto.CodeTooLarge, "the certificate or key file is too large")
	case errors.Is(err, errUnstable):
		return failed(helperproto.CodeIOError, "the certificate or key file changed while it was read")
	case errors.Is(err, errSpecialFS):
		return refused(helperproto.CodePathNotAllowed, "the certificate or key file is on a special file system")
	default:
		return refused(helperproto.CodePathNotAllowed, "the certificate or key path leaves the directories root controls or has no certificate name")
	}
}

// keyMode is the mode of a new key (R38 item 3, F-13, S10): a 0640 key (an ssl-cert style group)
// stays 0640, every other key becomes 0600. Nothing is ever opened wider than it was, except the
// owner's own write bit (a 0400 key becomes 0600).
func keyMode(old uint32) uint32 {
	if old&0o777 == 0o640 {
		return 0o640
	}
	return 0o600
}

// certMode keeps a certificate's mode without write or execute bits for anyone but the owner's
// read and write (at most 0644, never wider than before).
func certMode(old uint32) uint32 { return old & 0o644 }

func stepOK(name string) helperproto.NginxStep {
	return helperproto.NginxStep{Name: name, Status: "ok"}
}

func stepFailed(name, class string) helperproto.NginxStep {
	return helperproto.NginxStep{Name: name, Status: "failed", Error: class}
}

// deployRequest is one validated nginx-deploy call; cert and key are the new content (cleared by
// the caller).
type deployRequest struct {
	op, certPath, keyPath, expect string
	cert, key                     []byte
}

// cmdNginxDeploy replaces a certificate and key pair of the current Nginx configuration as one
// journaled transaction (R38 item 1). Argument vector (exact): --op <id> --cert <path> --key <path>
// --expect-cert-sha256 <sha256> --content-sha256 <sha256>; stdin: helperproto.NginxDeployInput.
//
// Every answer before the key file is replaced is a refusal (exit 2, 3 or 4 with a code) and
// nothing changed; from the first rename on, the answer is the operation's outcome (exit 0, phase
// committed, restored or restore_failed) and the journal records it.
func cmdNginxDeploy(ctx context.Context, s *sys, args []string) (out any, err error) {
	if len(args) != 10 || args[0] != "--op" || args[2] != "--cert" || args[4] != "--key" ||
		args[6] != "--expect-cert-sha256" || args[8] != "--content-sha256" {
		return nil, refused(helperproto.CodeUsage, "usage: nginx-deploy --op <id> --cert <path> --key <path> --expect-cert-sha256 <sha256> --content-sha256 <sha256>")
	}
	d := deployRequest{op: args[1], certPath: args[3], keyPath: args[5], expect: args[7]}
	want := args[9]
	if !helperproto.ValidOpID(d.op) || !helperproto.ValidPath(d.certPath) || !helperproto.ValidPath(d.keyPath) ||
		d.certPath == "/" || d.keyPath == "/" || d.certPath == d.keyPath || !helperproto.ValidSHA256(d.expect) || d.expect == helperproto.AbsentSHA256 ||
		!helperproto.ValidSHA256(want) || want == helperproto.AbsentSHA256 {
		return nil, refused(helperproto.CodeInvalidArgument, "an argument is not allowed")
	}
	s.syslog(helperproto.SubNginxDeploy, d.certPath)
	defer func() {
		if r := recover(); r != nil {
			out, err = nil, survive(r)
		}
	}()
	// S6: the lock is taken before stdin is read, so a deployment that has its content always
	// shows as active in nginx-status until it has answered.
	lock, err := s.nginxLock(ctx)
	if err != nil {
		return nil, failed(helperproto.CodeBusy, "another certificate change is running on this server")
	}
	defer func() { _ = lock.Close() }()
	raw, err := readInput(ctx, s.stdin, helperproto.MaxDeployInput)
	defer clear(raw)
	switch {
	case err != nil:
		return nil, failed(helperproto.CodeIOError, "the new content cannot be read")
	case len(raw) > helperproto.MaxDeployInput:
		return nil, refused(helperproto.CodeTooLarge, "the new content is too large")
	case hexSHA(raw) != want:
		return nil, precondition(helperproto.CodeContentMismatch, "the new content arrived incomplete")
	}
	d.cert, d.key, err = parseDeployInput(raw)
	defer clear(d.key)
	defer clear(d.cert)
	switch {
	case err != nil:
		return nil, refused(helperproto.CodeBadContent, "the new content is not a certificate chain and a private key")
	case len(d.cert) > helperproto.MaxCertFileSize || len(d.key) > helperproto.MaxCertFileSize:
		return nil, refused(helperproto.CodeTooLarge, "the new certificate or key is too large")
	}
	if err := checkDeployContent(d.cert, d.key); err != nil {
		return nil, refused(helperproto.CodeBadContent, "the new content is not a certificate chain and its private key")
	}
	return s.deploy(ctx, d)
}

// deploy runs the transaction under the lock.
func (s *sys) deploy(ctx context.Context, d deployRequest) (any, error) {
	newCertSHA, newKeySHA := hexSHA(d.cert), hexSHA(d.key)
	var dir *os.File
	defer func() {
		if dir != nil {
			_ = dir.Close()
		}
	}()
	// One operation, one outcome: a journal of an earlier run of this operation answers it; an
	// interrupted one (the helper that wrote it died) is rolled back first; a prepared one replaced
	// nothing and starts again.
	switch od, err := s.opDir(d.op, false); {
	case errors.Is(err, unix.ENOENT):
	case err != nil:
		return nil, failed(helperproto.CodeIOError, "the backup directory cannot be opened")
	default:
		dir = od
		j, found, err := readJournal(dir, d.op)
		if err != nil {
			return nil, failed(helperproto.CodeIOError, "the journal of this operation cannot be read")
		}
		if found {
			if j.CertPath != d.certPath || j.KeyPath != d.keyPath || j.NewCertSHA != newCertSHA || j.NewKeySHA != newKeySHA {
				return nil, refused(helperproto.CodeInvalidArgument, "the operation id belongs to another deployment")
			}
			switch j.Phase {
			case helperproto.PhaseWriting, helperproto.PhaseRestoring:
				j, _ = s.restoreOp(context.WithoutCancel(ctx), dir, j)
				return deployAnswer(j), nil
			case helperproto.PhasePrepared:
			default:
				return deployAnswer(j), nil
			}
		}
	}

	// The target comes only from the authenticated configuration (nginx -T, every section compared
	// with its root-controlled file): the pair must be a supported pair of it now.
	cfg, meta, err := s.nginxConfig(ctx)
	switch {
	case errors.Is(err, errNginxMissing):
		return nil, precondition(helperproto.CodeNginxNotFound, "nginx is not installed at /usr/sbin/nginx")
	case err != nil:
		return nil, failed(helperproto.CodeIOError, "nginx could not be run to the end")
	case !meta.valid:
		return nil, precondition(helperproto.CodeConfigInvalid, "the nginx configuration has an error or cannot be trusted")
	case !cfg.HasPair(d.certPath, d.keyPath):
		return nil, precondition(helperproto.CodeConfigChanged, "the files are not a supported certificate and key pair of the current configuration")
	}
	cert, err := s.readTarget(d.certPath)
	if err != nil {
		return nil, targetError(err)
	}
	defer cert.close()
	key, err := s.readTarget(d.keyPath)
	if err != nil {
		return nil, targetError(err)
	}
	defer key.close()
	if cert.rf.resolved == key.rf.resolved || sameFile(cert.st, key.st) {
		return nil, refused(helperproto.CodePathNotAllowed, "the certificate and the key are one file")
	}
	if hexSHA(cert.data) != d.expect {
		return nil, precondition(helperproto.CodeHashMismatch, "the certificate file changed since it was read")
	}
	j := journal{Op: d.op, Phase: helperproto.PhasePrepared, CertPath: d.certPath, KeyPath: d.keyPath,
		CertResolved: cert.rf.resolved, KeyResolved: key.rf.resolved, OldCertSHA: hexSHA(cert.data), OldKeySHA: hexSHA(key.data),
		NewCertSHA: newCertSHA, NewKeySHA: newKeySHA,
		CertMeta: fileMeta{Mode: cert.st.Mode & 0o777, UID: int(cert.st.Uid), GID: int(cert.st.Gid)},
		KeyMeta:  fileMeta{Mode: key.st.Mode & 0o777, UID: int(key.st.Uid), GID: int(key.st.Gid)},
		Steps:    []helperproto.NginxStep{}}
	if bytes.Equal(cert.data, d.cert) && bytes.Equal(key.data, d.key) {
		// §12.9 "Same cert already deployed": no write, no reload.
		j.Phase = helperproto.PhaseUnchanged
		if dir == nil {
			if dir, err = s.opDir(d.op, true); err != nil {
				return nil, failed(helperproto.CodeIOError, "the backup directory cannot be created")
			}
		}
		if err := s.writeJournal(dir, j); err != nil {
			return nil, failed(helperproto.CodeIOError, "the journal cannot be written")
		}
		return deployAnswer(j), nil
	}
	need := int64(len(d.cert)+len(d.key)) + helperproto.MinFreeBytes
	if !s.spaceFor(cert.rf.dirfd, need) || !s.spaceFor(key.rf.dirfd, need) {
		return nil, precondition(helperproto.CodeNoSpace, "the server has not enough free disk space for the new files")
	}
	if dir == nil {
		if s.nginxOps() >= maxNginxOps {
			return nil, precondition(helperproto.CodeNoSpace, "too many deployment backups are kept on this server")
		}
		if dir, err = s.opDir(d.op, true); err != nil {
			return nil, failed(helperproto.CodeIOError, "the backup directory cannot be created")
		}
	}
	if !s.spaceFor(int(dir.Fd()), int64(len(cert.data)+len(key.data))+helperproto.MinFreeBytes) { //nolint:gosec // G115: a descriptor fits an int
		return nil, precondition(helperproto.CodeNoSpace, "the server has not enough free disk space for the backup")
	}
	if ctx.Err() != nil {
		return nil, failed(helperproto.CodeIOError, "the time budget ended before anything was changed")
	}

	// 1. The journal, then the backups (nothing is replaced yet: a failure is a refusal).
	s.cleanStaged(j)
	if err := s.writeJournal(dir, j); err != nil {
		return nil, failed(helperproto.CodeIOError, "the journal cannot be written")
	}
	if err := s.writeBackups(dir, cert.data, key.data); err != nil {
		if errors.Is(err, unix.ENOSPC) || errors.Is(err, unix.EDQUOT) {
			return nil, precondition(helperproto.CodeNoSpace, "the server has no free disk space for the backup")
		}
		return nil, failed(helperproto.CodeIOError, "the backup cannot be written")
	}
	j.Steps = append(j.Steps, stepOK(helperproto.StepBackup))
	s.point(helperproto.StepBackup)

	// From here on the transaction runs to its end whatever happens to the caller (the helper
	// ignores SIGHUP and SIGPIPE), and every outcome is recorded: the journal says "writing" before
	// the first rename, so a helper killed between the two renames leaves a mixed pair that
	// nginx-status reports and nginx-restore repairs.
	tctx := context.WithoutCancel(ctx)
	j.Phase = helperproto.PhaseWriting
	if err := s.writeJournal(dir, j); err != nil {
		return deployAnswer(s.fail(tctx, dir, j, helperproto.StepJournal, "")), nil
	}

	// 2. The key, then the certificate (spec §12.6 steps 3-4).
	renamed, err := s.replaceFile(key, d.key, keyMode(j.KeyMeta.Mode), j.KeyMeta, stagedName(d.op, kindKey), ctx)
	if err != nil && !renamed {
		// Nothing was replaced: the operation goes back to prepared and the answer is a refusal.
		back := j
		back.Phase = helperproto.PhasePrepared
		back.Steps = append(append([]helperproto.NginxStep{}, j.Steps...), stepFailed(helperproto.StepWriteKey, ""))
		if s.writeJournal(dir, back) == nil {
			return nil, replaceError(err)
		}
		return deployAnswer(s.fail(tctx, dir, j, helperproto.StepWriteKey, "")), nil
	}
	if err != nil {
		return deployAnswer(s.fail(tctx, dir, j, helperproto.StepWriteKey, "")), nil
	}
	j.Steps = append(j.Steps, stepOK(helperproto.StepWriteKey))
	s.point(helperproto.StepWriteKey)
	if _, err := s.replaceFile(cert, d.cert, certMode(j.CertMeta.Mode), j.CertMeta, stagedName(d.op, kindCert), nil); err != nil {
		return deployAnswer(s.fail(tctx, dir, j, helperproto.StepWriteCert, "")), nil
	}
	j.Steps = append(j.Steps, stepOK(helperproto.StepWriteCert))
	s.point(helperproto.StepWriteCert)

	// 3. nginx -t (F-01).
	if class, err := s.configTest(tctx); err != nil {
		return deployAnswer(s.fail(tctx, dir, j, helperproto.StepConfigTest, class)), nil
	}
	j.Steps = append(j.Steps, stepOK(helperproto.StepConfigTest))
	s.point(helperproto.StepConfigTest)

	// 4. Reload and is-active (F-03).
	if err := s.reload(tctx); err != nil {
		return deployAnswer(s.fail(tctx, dir, j, helperproto.StepReload, "")), nil
	}
	j.Steps = append(j.Steps, stepOK(helperproto.StepReload))
	s.point(helperproto.StepReload)
	j.Phase = helperproto.PhaseCommitted
	if err := s.writeJournal(dir, j); err != nil {
		// The journal must not say "writing" while the answer says "committed": roll back.
		j.Phase = helperproto.PhaseWriting
		return deployAnswer(s.fail(tctx, dir, j, helperproto.StepJournal, "")), nil
	}
	return deployAnswer(j), nil
}

// replaceError is the refusal when the first file could not be replaced (nothing changed).
func replaceError(err error) error {
	switch {
	case errors.Is(err, unix.ENOSPC), errors.Is(err, unix.EDQUOT):
		return precondition(helperproto.CodeNoSpace, "the server has no free disk space for the new key")
	case errors.Is(err, errChangedByOthers):
		return precondition(helperproto.CodeHashMismatch, "the key file changed since it was read")
	case errors.Is(err, errDeadline):
		return failed(helperproto.CodeIOError, "the time budget ended before anything was changed")
	}
	return failed(helperproto.CodeIOError, "the key file cannot be written")
}

// fail records the failed step and rolls back.
func (s *sys) fail(ctx context.Context, dir *os.File, j journal, step, class string) journal {
	j.Steps = append(j.Steps, stepFailed(step, class))
	j.FailedStep, j.Error = step, class
	j, _ = s.restoreOp(ctx, dir, j)
	return j
}

func (s *sys) spaceFor(fd int, need int64) bool {
	free, err := s.statfs(fd)
	return err == nil && free >= need
}

// nginxOps counts the operation directories that hold a journal.
func (s *sys) nginxOps() int {
	root, err := s.openBackupRoot(false)
	if err != nil {
		return 0
	}
	defer func() { _ = root.Close() }()
	names, err := root.Readdirnames(-1)
	if err != nil {
		return 0
	}
	n := 0
	for _, name := range names {
		var st unix.Stat_t
		if helperproto.ValidOpID(name) && unix.Fstatat(int(root.Fd()), name+"/"+journalName, &st, unix.AT_SYMLINK_NOFOLLOW) == nil { //nolint:gosec // G115: a descriptor fits an int
			n++
		}
	}
	return n
}

// writeBackups stores both old files, 0600 in the 0700 root-only operation directory, and syncs
// them and the directory. Files of an earlier run of the operation are replaced.
func (s *sys) writeBackups(dir *os.File, cert, key []byte) error {
	dfd := int(dir.Fd()) //nolint:gosec // G115: a descriptor fits an int
	for _, name := range []string{certBackup, keyBackup} {
		_ = unix.Unlinkat(dfd, name, 0)
	}
	if err := writeNewAt(dir, certBackup, cert); err != nil {
		return err
	}
	s.point("backup " + kindCert)
	if err := writeNewAt(dir, keyBackup, key); err != nil {
		return err
	}
	s.point("backup " + kindKey)
	return dir.Sync()
}

// configTest runs nginx -t; on failure it returns the error class. A run that timed out or was
// killed, or a missing nginx, says nothing about the configuration: its class is "" (never
// "syntax"), and it fails the step all the same.
func (s *sys) configTest(ctx context.Context) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, stepTimeout)
	defer cancel()
	_, stderr, err := s.runNginx(ctx, "-t")
	switch {
	case err == nil:
		return "", nil
	case errors.Is(err, errProgramKilled), missingProgram(err), errors.Is(err, errTooLarge):
		return "", err
	}
	return classifyNginxError(stderr), err
}

// reload runs systemctl reload nginx, then systemctl is-active nginx.
func (s *sys) reload(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, stepTimeout)
	defer cancel()
	if err := s.runSystemctl(ctx, "reload", "nginx"); err != nil {
		return err
	}
	return s.runSystemctl(ctx, "is-active", "--quiet", "nginx")
}

// replaceFile stages content next to t's file under the operation's deterministic name (created
// O_EXCL, 0600, root's, before any content is written), sets owner, group, mode and the SELinux
// label of the replaced file, syncs, and renames it over the file in the directory the walk
// opened; then it syncs the directory. Right before the rename it checks that the name still
// refers to the file that was read and backed up and that the file still holds the same bytes
// (errChangedByOthers), and, when deadline is not nil, that the helper's budget has not ended
// (errDeadline). renamed reports whether the rename happened.
func (s *sys) replaceFile(t *target, content []byte, mode uint32, meta fileMeta, staged string, deadline context.Context) (renamed bool, err error) {
	dfd := t.rf.dirfd
	_ = unix.Unlinkat(dfd, staged, 0) // left by a helper that died (S2)
	fd, err := unix.Openat(dfd, staged, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return false, err
	}
	f := os.NewFile(uintptr(fd), staged)
	defer func() {
		_ = f.Close()
		if !renamed && !s.killed {
			_ = unix.Unlinkat(dfd, staged, 0)
		}
	}()
	s.point("stage " + staged)
	if _, err := f.Write(content); err != nil {
		return false, err
	}
	if err := s.chown(f, meta.UID, meta.GID); err != nil {
		return false, err
	}
	if err := unix.Fchmod(fd, mode); err != nil {
		return false, err
	}
	copySELinux(int(t.f.Fd()), fd) //nolint:gosec // G115: a descriptor fits an int
	if err := f.Sync(); err != nil {
		return false, err
	}
	s.point("staged " + staged)
	if s.beforeRename != nil {
		if err := s.beforeRename(); err != nil {
			return false, err
		}
	}
	if !t.unchanged() {
		return false, errChangedByOthers
	}
	if deadline != nil && deadline.Err() != nil {
		return false, errDeadline
	}
	if err := unix.Renameat(dfd, staged, dfd, t.rf.name); err != nil {
		return false, err
	}
	renamed = true
	s.point("renamed " + staged)
	return true, unix.Fsync(dfd)
}

// unchanged reports, right before a rename, that the name still refers to the inode that was read
// and that the inode still holds the bytes that were hashed and backed up.
func (t *target) unchanged() bool {
	var now unix.Stat_t
	if err := unix.Fstatat(t.rf.dirfd, t.rf.name, &now, unix.AT_SYMLINK_NOFOLLOW); err != nil || !sameFile(now, t.st) {
		return false
	}
	buf := make([]byte, len(t.data)+1)
	defer clear(buf)
	n, err := io.ReadFull(io.NewSectionReader(t.f, 0, int64(len(buf))), buf)
	return (errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF)) && bytes.Equal(buf[:n], t.data)
}

// cleanStaged removes the staged files of an operation (S2) in the directories of both files,
// found again through the root-controlled walk. Only the operation's own deterministic names are
// removed.
func (s *sys) cleanStaged(j journal) {
	for _, x := range []struct{ resolved, kind string }{{j.CertResolved, kindCert}, {j.KeyResolved, kindKey}} {
		rf, err := s.resolveRoot(x.resolved)
		if err != nil {
			continue
		}
		_ = unix.Unlinkat(rf.dirfd, stagedName(j.Op, x.kind), 0)
		rf.close()
	}
}

// restoreOp puts the backups back for both files, tests and reloads. Both files are checked first:
// each must still be the file the journal resolved and hold either the deployed content (it is
// restored) or the backed-up content (it is left); anything else was changed by someone else and
// nothing at all is restored (errChangedByOthers, recorded as restore_failed / file_changed), so a
// restore never leaves a mixed pair behind and never clobbers a newer deployment. A restore of a
// restore is a no-op. The certificate is restored first, then the key (the reverse of the writes).
func (s *sys) restoreOp(ctx context.Context, dir *os.File, j journal) (journal, error) {
	failRestore := func(err error) (journal, error) {
		j.Steps = append(j.Steps, stepFailed(helperproto.StepRestore, ""))
		j.Phase = helperproto.PhaseRestoreFailed
		if errors.Is(err, errChangedByOthers) {
			j.Error = helperproto.RestoreErrFileChanged
		}
		if j.FailedStep == "" {
			j.FailedStep = helperproto.StepRestore
		}
		_ = s.writeJournal(dir, j)
		return j, err
	}
	type file struct {
		t                *target
		restore          bool
		backup, kind     string
		oldSHA, path     string
		meta             fileMeta
		resolved, newSHA string
	}
	files := []*file{
		{backup: certBackup, kind: kindCert, path: j.CertPath, resolved: j.CertResolved, oldSHA: j.OldCertSHA, newSHA: j.NewCertSHA, meta: j.CertMeta},
		{backup: keyBackup, kind: kindKey, path: j.KeyPath, resolved: j.KeyResolved, oldSHA: j.OldKeySHA, newSHA: j.NewKeySHA, meta: j.KeyMeta},
	}
	defer func() {
		for _, f := range files {
			if f.t != nil {
				f.t.close()
			}
		}
	}()
	for _, f := range files {
		t, err := s.readTarget(f.path)
		switch {
		case errors.Is(err, unix.ENOENT):
			return failRestore(errChangedByOthers)
		case err != nil:
			return failRestore(err)
		}
		f.t = t
		switch sum := hexSHA(t.data); {
		case t.rf.resolved != f.resolved:
			return failRestore(errChangedByOthers) // a link now leads elsewhere
		case sum == f.oldSHA:
		case sum == f.newSHA:
			f.restore = true
		default:
			return failRestore(errChangedByOthers)
		}
	}
	j.Phase = helperproto.PhaseRestoring
	_ = s.writeJournal(dir, j)
	s.cleanStaged(j)
	for _, f := range files {
		if !f.restore {
			continue
		}
		data, err := readBackup(dir, f.backup)
		if err == nil && hexSHA(data) != f.oldSHA {
			err = errBadJournal // the backup does not match its journal
		}
		if err == nil {
			_, err = s.replaceFile(f.t, data, f.meta.Mode, f.meta, stagedName(j.Op, f.kind), nil)
		}
		clear(data)
		if err != nil {
			return failRestore(err)
		}
	}
	j.Steps = append(j.Steps, stepOK(helperproto.StepRestore))
	s.point(helperproto.StepRestore)
	if class, err := s.configTest(ctx); err != nil {
		j.Steps = append(j.Steps, stepFailed(helperproto.StepRollbackConfigTest, class))
		j.Phase, j.FailedStep, j.Error = helperproto.PhaseRestoreFailed, helperproto.StepRollbackConfigTest, class
		_ = s.writeJournal(dir, j)
		return j, nil
	}
	j.Steps = append(j.Steps, stepOK(helperproto.StepRollbackConfigTest))
	s.point(helperproto.StepRollbackConfigTest)
	if err := s.reload(ctx); err != nil {
		j.Steps = append(j.Steps, stepFailed(helperproto.StepRollbackReload, ""))
		j.Phase, j.FailedStep = helperproto.PhaseRestoreFailed, helperproto.StepRollbackReload
		_ = s.writeJournal(dir, j)
		return j, nil
	}
	j.Steps = append(j.Steps, stepOK(helperproto.StepRollbackReload))
	s.point(helperproto.StepRollbackReload)
	j.Phase = helperproto.PhaseRestored
	_ = s.writeJournal(dir, j)
	return j, nil
}

// readBackup reads a backup of the operation directory (regular, at most MaxCertFileSize) into one
// buffer of its size; the caller clears it.
func readBackup(dir *os.File, name string) ([]byte, error) {
	fd, err := unix.Openat(int(dir.Fd()), name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0) //nolint:gosec // G115: a descriptor fits an int
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), name)
	defer func() { _ = f.Close() }()
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Size > helperproto.MaxCertFileSize {
		return nil, errBadJournal
	}
	buf := make([]byte, st.Size+1)
	n, err := io.ReadFull(f, buf)
	if !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF) {
		clear(buf)
		return nil, errBadJournal
	}
	return buf[:n], nil
}

func deployAnswer(j journal) helperproto.NginxDeployResponse {
	return helperproto.NginxDeployResponse{OK: true, Phase: j.Phase, FailedStep: j.FailedStep, Error: j.Error,
		Steps: append([]helperproto.NginxStep{}, j.Steps...), BackupDir: helperproto.BackupRoot + "/" + j.Op}
}

// cmdNginxRestore puts the backed-up pair of an operation back (nginx-restore --op <id>): after an
// interrupted deployment (journal writing or restoring), or to undo a committed one.
func cmdNginxRestore(ctx context.Context, s *sys, args []string) (out any, err error) {
	if len(args) != 2 || args[0] != "--op" {
		return nil, refused(helperproto.CodeUsage, "usage: nginx-restore --op <operation id>")
	}
	op := args[1]
	if !helperproto.ValidOpID(op) {
		return nil, refused(helperproto.CodeInvalidArgument, "the operation id is not allowed")
	}
	s.syslog(helperproto.SubNginxRestore, helperproto.BackupRoot+"/"+op)
	defer func() {
		if r := recover(); r != nil {
			out, err = nil, survive(r)
		}
	}()
	lock, err := s.nginxLock(ctx)
	if err != nil {
		return nil, failed(helperproto.CodeBusy, "another certificate change is running on this server")
	}
	defer func() { _ = lock.Close() }()
	dir, err := s.opDir(op, false)
	if errors.Is(err, unix.ENOENT) {
		return nil, precondition(helperproto.CodeUnknownOp, "there is no deployment with this operation id")
	}
	if err != nil {
		return nil, failed(helperproto.CodeIOError, "the backup directory cannot be opened")
	}
	defer func() { _ = dir.Close() }()
	j, found, err := readJournal(dir, op)
	switch {
	case err != nil:
		return nil, failed(helperproto.CodeIOError, "the journal cannot be read")
	case !found:
		return nil, precondition(helperproto.CodeUnknownOp, "there is no deployment with this operation id")
	}
	switch j.Phase {
	case helperproto.PhasePrepared, helperproto.PhaseUnchanged, helperproto.PhaseRestored:
		s.cleanStaged(j)
		return helperproto.NginxRestoreResponse{OK: true, Phase: j.Phase, Steps: []helperproto.NginxStep{}}, nil
	}
	before := len(j.Steps)
	j, err = s.restoreOp(context.WithoutCancel(ctx), dir, j)
	if errors.Is(err, errChangedByOthers) {
		return nil, precondition(helperproto.CodeHashMismatch, "a file was changed after the deployment; it is left as it is")
	}
	return helperproto.NginxRestoreResponse{OK: true, Phase: j.Phase, Error: j.Error,
		Steps: append([]helperproto.NginxStep{}, j.Steps[before:]...)}, nil
}

// cmdNginxStatus reports an operation's journal (nginx-status --op <id>): phase "none" when there
// is none, and whether a helper holds the Nginx lock right now (active). It takes no lock and
// changes nothing.
func cmdNginxStatus(_ context.Context, s *sys, args []string) (any, error) {
	if len(args) != 2 || args[0] != "--op" {
		return nil, refused(helperproto.CodeUsage, "usage: nginx-status --op <operation id>")
	}
	op := args[1]
	if !helperproto.ValidOpID(op) {
		return nil, refused(helperproto.CodeInvalidArgument, "the operation id is not allowed")
	}
	resp := helperproto.NginxStatusResponse{OK: true, Phase: helperproto.PhaseNone, Active: s.nginxLockHeld(),
		BackupDir: helperproto.BackupRoot + "/" + op}
	dir, err := s.opDir(op, false)
	if errors.Is(err, unix.ENOENT) {
		return resp, nil
	}
	if err != nil {
		return nil, failed(helperproto.CodeIOError, "the backup directory cannot be opened")
	}
	defer func() { _ = dir.Close() }()
	j, found, err := readJournal(dir, op)
	if err != nil {
		return nil, failed(helperproto.CodeIOError, "the journal cannot be read")
	}
	if !found {
		return resp, nil
	}
	resp.Phase, resp.NewCertSHA256 = j.Phase, j.NewCertSHA
	if t, err := s.readTarget(j.CertPath); err == nil {
		resp.CurrentCertSHA256 = hexSHA(t.data)
		t.close()
	}
	return resp, nil
}
