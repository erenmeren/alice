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
	errBadName         = errors.New("the file name has no certificate or key extension, or resolves to a path the vocabulary cannot carry")
	errBadContent      = errors.New("the new content is not a certificate chain and its private key")
	errChangedByOthers = errors.New("the file was changed by someone else")
	errUnstable        = errors.New("the file changed while it was read")
	errDeadline        = errors.New("the time budget ended before the file was replaced")
	// errJournalUnwritten: the restoring journal could not be written, so nothing was put back.
	errJournalUnwritten = errors.New("the journal cannot be written")
)

// stagedName is the deterministic name of the staged file of one operation and one file of the
// pair (S2): a staged file a dead helper left behind is found again and removed by nginx-restore,
// a new run of the operation and the backup sweep. It has no certificate extension, so it is never
// a file the helper reads or replaces as part of a pair.
func stagedName(op, kind string) string { return ".alice-" + op + "-" + kind }

// target is a certificate or key file found under the lock, with the descriptors it was resolved
// and read through.
type target struct {
	rf        rootFile
	f         *os.File
	st        unix.Stat_t
	data      []byte
	installed fileID // the inode replaceFile put in its place
}

func (t *target) close() {
	clear(t.data)
	_ = t.f.Close()
	t.rf.close()
}

// readTarget resolves and reads one existing file of the pair through the root-controlled walk.
// Key files are opened (read) only by nginx-deploy (the backup and the compare-and-swap),
// nginx-restore (whether a file holds the deployed or the backed-up content) and an explicit
// cleanup --op (whether the operation is still needed for recovery). nginx-dump, nginx-test,
// nginx-status and the backup sweep that runs before every privileged subcommand never open a
// key file (they use fstatat only).
//
// The walk:
// every directory and link root's, a certificate or key file name, a regular file with one link on
// a normal file system, at most MaxCertFileSize. It is read into one buffer of its size (a key is
// never copied by a growing read), cleared by close.
func (s *sys) readTarget(p string) (*target, error) {
	rf, err := s.resolveRoot(p)
	if err != nil {
		return nil, err
	}
	// A1-I1: a resolved path outside the argument vocabulary (an acme.sh "*.example.com" directory)
	// could not be journaled (readJournal would refuse the journal): such a file is never read or
	// replaced (PATH_NOT_ALLOWED before anything is written).
	if !certName(rf.name) || !helperproto.ValidPath(rf.resolved) {
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
	s.renamed = false
	out, err = s.deploy(ctx, d)
	return out, s.afterRename(err)
}

// afterRename is the typed-error guard of nginx-deploy and nginx-restore: once this call renamed a
// file, an error must never read as a refusal ("nothing changed"; reply would also turn an untyped
// error into IO_ERROR, which Alice's tables hold as one). Every path after the first rename answers
// the journal's outcome; anything else that reaches here becomes OUTCOME_UNKNOWN (uncertain for
// Alice, which then reads nginx-status).
func (s *sys) afterRename(err error) error {
	if err == nil || !s.renamed {
		return err
	}
	return failed(helperproto.CodeOutcomeUnknown, "files were changed and the outcome could not be reported; read nginx-status")
}

// deploy runs the transaction under the lock.
func (s *sys) deploy(ctx context.Context, d deployRequest) (any, error) {
	newCertSHA, newKeySHA := hexSHA(d.cert), hexSHA(d.key)
	var (
		dir   *os.File
		prior *journal // a prepared journal of an earlier run of this operation
	)
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
		if found && j.Phase == helperproto.PhaseFenced {
			// AUD-05: recovery fenced this operation and recorded that it wrote nothing (a helper
			// that started late, after a sudo or PAM stall): it never runs.
			return nil, precondition(helperproto.CodeFenced, "this deployment was ended by Alice's recovery; it is not carried out")
		}
		if found {
			if j.CertPath != d.certPath || j.KeyPath != d.keyPath || j.NewCertSHA != newCertSHA || j.NewKeySHA != newKeySHA {
				return nil, refused(helperproto.CodeInvalidArgument, "the operation id belongs to another deployment")
			}
			switch j.Phase {
			case helperproto.PhaseWriting, helperproto.PhaseRestoring:
				switch sup, err := s.superseded(j); {
				case err != nil:
					return nil, failed(helperproto.CodeIOError, "the record of the latest deployment cannot be read")
				case sup:
					return nil, precondition(helperproto.CodeSuperseded, "a later deployment replaced these files; this one is not rolled back")
				}
				j, _ = s.restoreOp(context.WithoutCancel(ctx), dir, j, false)
				return deployAnswer(j), nil
			case helperproto.PhasePrepared:
				prior = &j
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
		KeyIDs:   keyIDs{Old: idOf(key.st)},
		Steps:    []helperproto.NginxStep{}}
	// The pair record before this operation (New-3): a re-run after a crash between taking the
	// record and the writing journal finds itself there and keeps the previous value it saved (an
	// unchanged re-run keeps it too, so the record resolves through it).
	rec, err := s.pairRecord(j)
	if err != nil {
		return nil, failed(helperproto.CodeIOError, "the record of the latest deployment cannot be read")
	}
	j.PrevRecord = rec
	if prior != nil && rec == d.op {
		j.PrevRecord = prior.PrevRecord
	}
	// m1: the pair's latest operation may not be an interrupted one (writing, restoring): this one
	// would supersede it, and nginx-restore could then never repair the pair. The invariant does not
	// rest on Alice's own recovery check alone.
	switch pending, err := s.interruptedLatest(j); {
	case err != nil:
		return nil, failed(helperproto.CodeIOError, "the record of the latest deployment cannot be read")
	case pending:
		return nil, precondition(helperproto.CodeRecoveryPending, "the latest deployment of these files was interrupted; restore it first")
	}
	if bytes.Equal(cert.data, d.cert) && bytes.Equal(key.data, d.key) {
		// §12.9 "Same cert already deployed": no write, no reload.
		j.Phase = helperproto.PhaseUnchanged
		if dir == nil {
			if dir, err = s.newOpDir(d.op); err != nil {
				return nil, err
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
	created := dir == nil
	if created {
		if dir, err = s.newOpDir(d.op); err != nil {
			return nil, err
		}
	}
	// refuse answers a refusal before anything was replaced; an operation directory this run
	// created goes again (a refusal leaves nothing behind).
	refuse := func(e error) (any, error) {
		if created {
			s.dropOpDir(d.op)
		}
		return nil, e
	}
	if !s.spaceFor(int(dir.Fd()), int64(len(cert.data)+len(key.data))+helperproto.MinFreeBytes) { //nolint:gosec // G115: a descriptor fits an int
		return refuse(precondition(helperproto.CodeNoSpace, "the server has not enough free disk space for the backup"))
	}
	// m3: the reload at the end needs systemctl and a running Nginx; without them the transaction
	// would replace the files and then fail its reload and its rollback's reload. Refused first.
	switch err := s.nginxActive(ctx); {
	case errors.Is(err, errProgramKilled):
		return refuse(failed(helperproto.CodeIOError, "systemctl could not be run to the end"))
	case err != nil:
		return refuse(precondition(helperproto.CodeNginxNotRunning, "systemctl is missing or nginx is not running"))
	}
	if ctx.Err() != nil {
		return refuse(failed(helperproto.CodeIOError, "the time budget ended before anything was changed"))
	}

	// 1. The journal, then the backups (nothing is replaced yet: a failure is a refusal).
	s.cleanStaged(j)
	if err := s.writeJournal(dir, j); err != nil {
		return refuse(failed(helperproto.CodeIOError, "the journal cannot be written"))
	}
	if err := s.writeBackups(dir, cert.data, key.data); err != nil {
		if errors.Is(err, unix.ENOSPC) || errors.Is(err, unix.EDQUOT) {
			return refuse(precondition(helperproto.CodeNoSpace, "the server has no free disk space for the backup"))
		}
		return refuse(failed(helperproto.CodeIOError, "the backup cannot be written"))
	}
	j.Steps = append(j.Steps, stepOK(helperproto.StepBackup))
	s.point(helperproto.StepBackup)

	// 2. This operation becomes the pair's latest (Important 3): written before the journal says
	// writing, so every operation that may replace files is the pair's record until a later one
	// starts. A refusal before the first rename puts the previous record back.
	if err := s.setPairRecord(j, d.op); err != nil {
		if s.setPairRecord(j, j.PrevRecord) == nil {
			return refuse(failed(helperproto.CodeIOError, "the record of the latest deployment cannot be written"))
		}
		return nil, failed(helperproto.CodeIOError, "the record of the latest deployment cannot be written") // keep the prepared journal: the record may name it
	}
	// back undoes the record and the journal when nothing was replaced, and answers the refusal.
	// When the record cannot be put back the operation stays, prepared, so the record names an
	// operation that supersedes nothing (never a dropped one).
	back := func(e error, steps ...helperproto.NginxStep) (any, error) {
		if s.setPairRecord(j, j.PrevRecord) == nil && created {
			s.dropOpDir(d.op)
			return nil, e
		}
		b := j
		b.Phase = helperproto.PhasePrepared
		b.Steps = append(append([]helperproto.NginxStep{}, j.Steps...), steps...)
		_ = s.writeJournal(dir, b)
		return nil, e
	}

	// From here on the transaction runs to its end whatever happens to the caller (the helper
	// ignores SIGHUP and SIGPIPE), and every outcome is recorded: the journal says "writing" before
	// the first rename, so a helper killed between the two renames leaves a mixed pair that
	// nginx-status reports and nginx-restore repairs.
	tctx := context.WithoutCancel(ctx)
	j.Phase = helperproto.PhaseWriting
	if err := s.writeJournal(dir, j); err != nil {
		// Nothing was replaced (minor 2): a refusal, no nginx -t, no reload.
		return back(failed(helperproto.CodeIOError, "the journal cannot be written"))
	}

	// 3. The key, then the certificate (spec §12.6 steps 3-4). Right before the key's rename both
	// files must still be what was read (Important 1): a certificate changed by someone else is
	// found before anything is replaced.
	renamed, err := s.replaceFile(key, d.key, keyMode(j.KeyMeta.Mode), j.KeyMeta, stagedName(d.op, kindKey), ctx, cert.unchanged)
	if err != nil && !renamed {
		return back(replaceError(err), stepFailed(helperproto.StepWriteKey, ""))
	}
	if err != nil {
		return deployAnswer(s.fail(tctx, dir, j, helperproto.StepWriteKey, "")), nil
	}
	j.KeyIDs.New = key.installed
	j.Steps = append(j.Steps, stepOK(helperproto.StepWriteKey))
	s.point(helperproto.StepWriteKey)
	if _, err := s.replaceFile(cert, d.cert, certMode(j.CertMeta.Mode), j.CertMeta, stagedName(d.op, kindCert), nil, nil); err != nil {
		// A certificate changed since the key's rename is left as it is; the rollback puts the key
		// back (restore_failed, failed_step write_cert, error file_changed).
		return deployAnswer(s.fail(tctx, dir, j, helperproto.StepWriteCert, "")), nil
	}
	j.Steps = append(j.Steps, stepOK(helperproto.StepWriteCert))
	s.point(helperproto.StepWriteCert)

	// 4. nginx -t (F-01).
	if class, err := s.configTest(tctx); err != nil {
		return deployAnswer(s.fail(tctx, dir, j, helperproto.StepConfigTest, class)), nil
	}
	j.Steps = append(j.Steps, stepOK(helperproto.StepConfigTest))
	s.point(helperproto.StepConfigTest)

	// 5. Reload and is-active (F-03).
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

// dropOpDir removes the directory of an operation that changed nothing.
func (s *sys) dropOpDir(op string) {
	root, err := s.openBackupRoot(false)
	if err != nil {
		return
	}
	defer func() { _ = root.Close() }()
	_ = removeAt(root, op)
}

// replaceError is the refusal when the first file could not be replaced (nothing changed).
func replaceError(err error) error {
	switch {
	case errors.Is(err, unix.ENOSPC), errors.Is(err, unix.EDQUOT):
		return precondition(helperproto.CodeNoSpace, "the server has no free disk space for the new key")
	case errors.Is(err, errChangedByOthers):
		return precondition(helperproto.CodeHashMismatch, "the certificate or key file changed since it was read")
	case errors.Is(err, errDeadline):
		return failed(helperproto.CodeIOError, "the time budget ended before anything was changed")
	}
	return failed(helperproto.CodeIOError, "the key file cannot be written")
}

// fail records the failed step and rolls back within the transaction (partial: a file someone
// else changed meanwhile is left, the files this transaction wrote are put back).
func (s *sys) fail(ctx context.Context, dir *os.File, j journal, step, class string) journal {
	j.Steps = append(j.Steps, stepFailed(step, class))
	j.FailedStep, j.CauseStep, j.Error = step, step, class
	j, _ = s.restoreOp(ctx, dir, j, true)
	return j
}

func (s *sys) spaceFor(fd int, need int64) bool {
	free, err := s.statfs(fd)
	return err == nil && free >= need
}

// newOpDir creates the operation directory of a new operation, unless maxNginxOps operations
// are kept already (the answer is then a refusal).
func (s *sys) newOpDir(op string) (*os.File, error) {
	if s.nginxOps() >= maxNginxOps {
		return nil, precondition(helperproto.CodeNoSpace, "too many deployment backups are kept on this server")
	}
	dir, err := s.opDir(op, true)
	if err != nil {
		return nil, failed(helperproto.CodeIOError, "the backup directory cannot be created")
	}
	return dir, nil
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
	if err := s.pointErr("backup " + kindCert); err != nil {
		return err
	}
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

// nginxActive runs systemctl is-active nginx (bounded by stepTimeout): nil when Nginx runs.
func (s *sys) nginxActive(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, stepTimeout)
	defer cancel()
	return s.runSystemctl(ctx, "is-active", "--quiet", "nginx")
}

// interruptedLatest reports that the pair's latest operation (the one that last replaced its
// files) is another one whose journal says writing or restoring.
func (s *sys) interruptedLatest(j journal) (bool, error) {
	op, ok, err := s.latestOp(j)
	if err != nil || !ok || op == "" || op == j.Op {
		return false, err
	}
	dir, err := s.opDir(op, false)
	if err != nil {
		return false, nil //nolint:nilerr // latestOp read it a moment ago; gone now: not pending
	}
	defer func() { _ = dir.Close() }()
	other, found, err := readJournal(dir, op)
	if err != nil || !found {
		return false, nil //nolint:nilerr // as above
	}
	return other.Phase == helperproto.PhaseWriting || other.Phase == helperproto.PhaseRestoring, nil
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
// (errChangedByOthers; also checks another file the same way), and, when deadline is not nil, that the helper's budget has not ended
// (errDeadline). renamed reports whether the rename happened.
func (s *sys) replaceFile(t *target, content []byte, mode uint32, meta fileMeta, staged string, deadline context.Context,
	also func() bool,
) (renamed bool, err error) {
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
	var sst unix.Stat_t
	if err := unix.Fstat(fd, &sst); err != nil {
		return false, err
	}
	s.point("staged " + staged)
	if s.beforeRename != nil {
		if err := s.beforeRename(); err != nil {
			return false, err
		}
	}
	if !t.unchanged() || (also != nil && !also()) {
		return false, errChangedByOthers
	}
	if deadline != nil && deadline.Err() != nil {
		return false, errDeadline
	}
	if err := unix.Renameat(dfd, staged, dfd, t.rf.name); err != nil {
		return false, err
	}
	renamed = true
	s.renamed = true
	t.installed = idOf(sst)
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

// restoreOp puts the backups back for both files, tests and reloads. Each file is checked first:
// it must still be the file the journal resolved and hold either the deployed content (it is
// restored) or the backed-up content (it is left).
//
// A file holding anything else was changed by someone else. For nginx-restore (partial false)
// nothing at all is restored then (errChangedByOthers, recorded as restore_failed / file_changed;
// not rewritten when the journal already says so), so a restore never leaves a mixed pair and never
// clobbers a newer deployment. Within the deployment's own transaction (partial true: under the
// lock, nothing newer exists) the files this transaction wrote are put back and the changed one is
// left; the outcome is restore_failed / file_changed with failed_step the step that started the
// rollback, without nginx -t or reload (the pair is now the other party's).
//
// A failure of the restore itself sets failed_step to restore (the pair may be mixed; another
// nginx-restore can finish it); cause_step keeps the step that started the rollback. The
// certificate is restored first, then the key (the reverse of the writes).
func (s *sys) restoreOp(ctx context.Context, dir *os.File, j journal, partial bool) (journal, error) {
	j.Steps = trimSteps(j.Steps)
	partial = partial || j.Partial // the transaction's own finding holds for a later nginx-restore too
	failRestore := func(err error) (journal, error) {
		if !partial && errors.Is(err, errChangedByOthers) && j.Phase == helperproto.PhaseRestoreFailed &&
			j.Error == helperproto.RestoreErrFileChanged {
			return j, err // the same refusal again: nothing changed, nothing rewritten
		}
		j.Steps = append(j.Steps, stepFailed(helperproto.StepRestore, ""))
		j.Phase, j.FailedStep = helperproto.PhaseRestoreFailed, helperproto.StepRestore
		if errors.Is(err, errChangedByOthers) {
			j.Error = helperproto.RestoreErrFileChanged
		}
		_ = s.writeJournal(dir, j)
		return j, err
	}
	type file struct {
		t                *target
		restore, foreign bool
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
	foreign := false
	for _, f := range files {
		state, t, err := s.fileState(f.path, f.resolved, f.oldSHA, f.newSHA)
		switch {
		case errors.Is(err, errChangedByOthers) && partial:
			f.foreign, foreign = true, true
			continue
		case err != nil:
			return failRestore(err)
		}
		f.t, f.restore = t, state == stateNew
	}
	if foreign {
		j.Partial = true
		if !files[0].restore && !files[1].restore {
			// Nothing of this operation is left on disk: the outcome is final.
			if j.Phase == helperproto.PhaseRestoreFailed && j.Error == helperproto.RestoreErrFileChanged && j.FailedStep == j.CauseStep {
				return j, errChangedByOthers // already recorded: nothing rewritten
			}
			j.Phase, j.Error, j.FailedStep = helperproto.PhaseRestoreFailed, helperproto.RestoreErrFileChanged, j.CauseStep
			_ = s.writeJournal(dir, j)
			return j, errChangedByOthers
		}
	}
	j.Phase = helperproto.PhaseRestoring
	if err := s.writeJournal(dir, j); err != nil {
		// m6: nothing is renamed while the journal does not say restoring: a helper that died during
		// the restore would otherwise leave a journal (committed) that does not describe a mixed pair.
		return failRestore(errJournalUnwritten)
	}
	s.cleanStaged(j)
	renamedAny := false
	for _, f := range files {
		if !f.restore {
			continue
		}
		data, err := readBackup(dir, f.backup)
		if err == nil && hexSHA(data) != f.oldSHA {
			err = errBadJournal // the backup does not match its journal
		}
		renamed := false
		if err == nil {
			renamed, err = s.replaceFile(f.t, data, f.meta.Mode, f.meta, stagedName(j.Op, f.kind), nil, nil)
		}
		clear(data)
		if err != nil {
			if renamedAny || renamed {
				// A1-I2: something was already put back, so this is the restore's outcome (restore_failed,
				// failed_step restore; error file_changed when the other file was changed meanwhile), never
				// a refusal that reads "nothing was restored".
				j, _ = failRestore(err)
				return j, nil
			}
			return failRestore(err)
		}
		renamedAny = true
		if f.kind == kindKey {
			j.KeyIDs.Restored = f.t.installed
		}
	}
	j.Steps = append(j.Steps, stepOK(helperproto.StepRestore))
	s.point(helperproto.StepRestore)
	if foreign {
		j.Phase, j.Error, j.FailedStep = helperproto.PhaseRestoreFailed, helperproto.RestoreErrFileChanged, j.CauseStep
		_ = s.writeJournal(dir, j)
		return j, nil
	}
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
	j.Phase, j.FailedStep = helperproto.PhaseRestored, j.CauseStep
	if j.CauseStep == "" {
		j.Error = "" // a restore of a committed operation: no class of an earlier failure applies
	}
	_ = s.writeJournal(dir, j)
	return j, nil
}

const (
	stateOld = iota
	stateNew
)

// fileState reads one file of an operation's pair: stateOld or stateNew, or errChangedByOthers when
// it is missing, resolves elsewhere now, or holds anything else. The caller closes the target.
func (s *sys) fileState(path, resolved, oldSHA, newSHA string) (int, *target, error) {
	t, err := s.readTarget(path)
	switch {
	case errors.Is(err, unix.ENOENT):
		return 0, nil, errChangedByOthers
	case err != nil:
		return 0, nil, err
	}
	switch sum := hexSHA(t.data); {
	case t.rf.resolved != resolved:
	case sum == oldSHA:
		return stateOld, t, nil
	case sum == newSHA:
		return stateNew, t, nil
	}
	t.close()
	return 0, nil, errChangedByOthers
}

// fileUnknown: a file of the pair cannot be read (or stat'ed) right now, so its state is not known.
const fileUnknown = -1

// stateForeign: a file of the pair holds neither content, is missing or resolves elsewhere.
const stateForeign = -2

// stateOf is fileState's verdict as stateOld, stateNew, stateForeign or fileUnknown.
func (s *sys) stateOf(path, resolved, oldSHA, newSHA string) int {
	state, t, err := s.fileState(path, resolved, oldSHA, newSHA)
	if t != nil {
		t.close()
	}
	switch {
	case errors.Is(err, errChangedByOthers):
		return stateForeign
	case err != nil:
		return fileUnknown
	}
	return state
}

// keyStateByStat is the key's state from fstatat alone (the sweep never opens a key file): the
// inode and size this operation installed is new; the one it replaced or a restore put back is
// old; anything else counts as someone else's.
func (s *sys) keyStateByStat(j journal) int {
	rf, err := s.resolveRoot(j.KeyPath)
	if errors.Is(err, unix.ENOENT) {
		return stateForeign
	}
	if err != nil {
		return fileUnknown
	}
	defer rf.close()
	var st unix.Stat_t
	if err := unix.Fstatat(rf.dirfd, rf.name, &st, unix.AT_SYMLINK_NOFOLLOW); errors.Is(err, unix.ENOENT) {
		return stateForeign
	} else if err != nil {
		return fileUnknown
	}
	id := idOf(st)
	switch {
	case rf.resolved != j.KeyResolved || st.Mode&unix.S_IFMT != unix.S_IFREG:
		return stateForeign
	case id == j.KeyIDs.New && id.Ino != 0:
		return stateNew
	case id == j.KeyIDs.Old && id.Ino != 0, id == j.KeyIDs.Restored && id.Ino != 0:
		return stateOld
	}
	return stateForeign
}

// restorable reports whether nginx-restore could still act on a restore_failed operation (so its
// backups are kept for recovery): not superseded, and a file of the pair cannot be read now, or a
// file still holds the deployed content (different from the old) while no file is someone else's
// — for an operation whose own rollback found someone else's file (Partial), a file holding the
// deployed content is enough, since nginx-restore then puts back only its own files. readKeys
// false decides the key by fstatat only (the sweep).
func (s *sys) restorable(j journal, readKeys bool) bool {
	if sup, err := s.superseded(j); err != nil || sup {
		return err != nil
	}
	cert := s.stateOf(j.CertPath, j.CertResolved, j.OldCertSHA, j.NewCertSHA)
	key := s.keyStateByStat(j)
	if readKeys {
		key = s.stateOf(j.KeyPath, j.KeyResolved, j.OldKeySHA, j.NewKeySHA)
	}
	if cert == fileUnknown || key == fileUnknown {
		return true
	}
	anyNew := (cert == stateNew && j.NewCertSHA != j.OldCertSHA) || (key == stateNew && j.NewKeySHA != j.OldKeySHA)
	anyForeign := cert == stateForeign || key == stateForeign
	if j.Partial {
		return anyNew
	}
	return anyNew && !anyForeign
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
	return helperproto.NginxDeployResponse{OK: true, Phase: j.Phase, FailedStep: j.FailedStep, CauseStep: j.CauseStep, Error: j.Error,
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
	case helperproto.PhasePrepared, helperproto.PhaseUnchanged, helperproto.PhaseRestored, helperproto.PhaseFenced:
		s.cleanStaged(j)
		return helperproto.NginxRestoreResponse{OK: true, Phase: j.Phase, FailedStep: j.FailedStep, CauseStep: j.CauseStep,
			Error: j.Error, Steps: []helperproto.NginxStep{}}, nil
	}
	// Important 3: only the pair's latest operation is rolled back (never a walk back to an older
	// key through retained operations).
	switch sup, err := s.superseded(j); {
	case err != nil:
		return nil, failed(helperproto.CodeIOError, "the record of the latest deployment cannot be read")
	case sup:
		return nil, precondition(helperproto.CodeSuperseded, "a later deployment replaced these files; this one is not rolled back")
	}
	j.Steps = trimSteps(j.Steps) // as restoreOp does: the steps it adds follow
	before := len(j.Steps)
	s.renamed = false
	j, err = s.restoreOp(context.WithoutCancel(ctx), dir, j, false)
	if s.renamed && err != nil {
		err = nil // restoreOp answers its outcome once it renamed (A1-I2); the journal says it
	}
	switch {
	case errors.Is(err, errChangedByOthers):
		// Only before any rename (A1-I2): restoreOp answers a later change as its outcome.
		return nil, precondition(helperproto.CodeHashMismatch, "a file was changed after the deployment; it is left as it is")
	case errors.Is(err, errJournalUnwritten):
		return nil, failed(helperproto.CodeIOError, "the journal cannot be written; nothing was restored")
	}
	return helperproto.NginxRestoreResponse{OK: true, Phase: j.Phase, FailedStep: j.FailedStep, CauseStep: j.CauseStep, Error: j.Error,
		Steps: append([]helperproto.NginxStep{}, j.Steps[min(before, len(j.Steps)):]...)}, nil
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
	return s.statusOf(j, resp), nil
}

// statusOf fills an nginx-status answer from a journal (a tombstone names no file).
func (s *sys) statusOf(j journal, resp helperproto.NginxStatusResponse) helperproto.NginxStatusResponse {
	resp.Phase, resp.NewCertSHA256 = j.Phase, j.NewCertSHA
	resp.FailedStep, resp.CauseStep, resp.Error = j.FailedStep, j.CauseStep, j.Error
	if j.Phase == helperproto.PhaseFenced {
		return resp
	}
	if t, err := s.readTarget(j.CertPath); err == nil {
		resp.CurrentCertSHA256 = hexSHA(t.data)
		t.close()
	}
	return resp
}
