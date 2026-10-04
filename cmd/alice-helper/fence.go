//go:build linux

package main

import (
	"context"
	"errors"

	"golang.org/x/sys/unix"

	"alice/internal/providers/linuxssh/helperproto"
)

// cmdNginxFence fences an operation (nginx-fence --op <id>, AUD-05). Alice's recovery calls it
// before it records that an operation without a journal wrote nothing: a helper that starts late
// (a sudo or PAM stall, then a dropped connection) must not carry that operation out afterwards.
//
// Under the Nginx lock (so no nginx-deploy of any operation runs meanwhile):
//
//	no directory or no journal      a tombstone journal (phase fenced) is written; answer fenced
//	journal fenced                  nothing changes; answer fenced (idempotent)
//	journal prepared (nothing       the pair record is handed back to the operation before it,
//	  was replaced)                 staged files and backups go, the tombstone replaces the
//	                                journal; answer fenced
//	any other journal               nothing changes; the answer is nginx-status's for it
//	journal unreadable              IO_ERROR, nothing changes
//
// nginx-deploy of a fenced operation refuses (FENCED) before reading its input. The answer is an
// NginxStatusResponse; Active is false (the fence holds the lock). Nothing depends on a clock: the
// tombstone is permanent until the sweep removes it after NginxBackupKeep like a finished
// operation (cleanup --op keeps it). A crash leaves either the earlier state or the tombstone
// (journals are replaced atomically), and the caller, which saw no answer, fences again.
func cmdNginxFence(ctx context.Context, s *sys, args []string) (out any, err error) {
	if len(args) != 2 || args[0] != "--op" {
		return nil, refused(helperproto.CodeUsage, "usage: nginx-fence --op <operation id>")
	}
	op := args[1]
	if !helperproto.ValidOpID(op) {
		return nil, refused(helperproto.CodeInvalidArgument, "the operation id is not allowed")
	}
	s.syslog(helperproto.SubNginxFence, helperproto.BackupRoot+"/"+op)
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
	resp := helperproto.NginxStatusResponse{OK: true, Phase: helperproto.PhaseFenced, BackupDir: helperproto.BackupRoot + "/" + op}
	dir, err := s.opDir(op, false)
	if errors.Is(err, unix.ENOENT) {
		// The tombstone needs no space beyond its journal: maxNginxOps (a bound on backups) does
		// not apply.
		dir, err = s.opDir(op, true)
	}
	if err != nil {
		return nil, failed(helperproto.CodeIOError, "the backup directory cannot be opened")
	}
	defer func() { _ = dir.Close() }()
	j, found, err := readJournal(dir, op)
	if err != nil {
		return nil, failed(helperproto.CodeIOError, "the journal cannot be read")
	}
	tomb := journal{Op: op, Phase: helperproto.PhaseFenced, Steps: []helperproto.NginxStep{}}
	if found {
		switch j.Phase {
		case helperproto.PhaseFenced:
			return resp, nil
		case helperproto.PhasePrepared:
			// Nothing was replaced (the journal says writing before the first rename). The record
			// goes back first, so a crash before the tombstone leaves a consistent prepared one.
			if !s.releaseRecord(j) {
				return nil, failed(helperproto.CodeIOError, "the record of the latest deployment cannot be updated")
			}
			s.cleanStaged(j)
			tomb.PrevRecord = j.PrevRecord
		default:
			return s.statusOf(j, helperproto.NginxStatusResponse{OK: true, BackupDir: resp.BackupDir}), nil
		}
	}
	if err := s.writeJournal(dir, tomb); err != nil {
		return nil, failed(helperproto.CodeIOError, "the journal cannot be written")
	}
	dfd := int(dir.Fd()) //nolint:gosec // G115: a descriptor fits an int
	for _, name := range []string{certBackup, keyBackup, journalTmp} {
		_ = unix.Unlinkat(dfd, name, 0)
	}
	_ = dir.Sync()
	return resp, nil
}
