//go:build linux

package main

import (
	"context"
	"errors"

	"golang.org/x/sys/unix"
)

// errProgramUntrusted: a web-server program, or a file it loads before reading its configuration,
// can be changed by a user other than root (Ruling 15, Phase B carry of Apache Ruling 7). The
// helper never runs it as root.
var errProgramUntrusted = errors.New("the program or a file it loads can be changed by a user other than root")

// programError names the file that failed the root-control pre-check (a guest path). It maps to an
// untrusted configuration, reason not_root_controlled, naming the file (the dumps), to "untrusted"
// (nginx-test), and to class "" (the deploy step's configTest).
type programError struct{ path string }

func (e *programError) Error() string { return e.path + ": " + errProgramUntrusted.Error() }
func (e *programError) Unwrap() error { return errProgramUntrusted }

// trustedProgram checks each path in order (Ruling 15): one that exists must walk (walkRoot:
// every directory and link from "/" root's and not writable by group or others, no pseudo or FUSE
// file system) and be a regular file owned by root with no group or other write bit, on a normal
// file system. A missing path passes (also a missing or non-directory parent), so the "not
// installed" logic is unchanged: nobody but root can create it there. Hard links are allowed and
// the file is never opened for reading. The first failing path is returned as a *programError.
func (s *sys) trustedProgram(paths ...string) error {
	for _, p := range paths {
		if !s.programOK(p) {
			return &programError{path: p}
		}
	}
	return nil
}

// programOK is one path's check.
func (s *sys) programOK(p string) bool {
	missing := func(err error) bool { return errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ENOTDIR) }
	rf, err := s.walkRoot(p)
	if err != nil {
		return missing(err)
	}
	defer rf.close()
	var st unix.Stat_t
	if err := unix.Fstatat(rf.dirfd, rf.name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return errors.Is(err, unix.ENOENT)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || int(st.Uid) != s.rootUID || st.Mode&0o022 != 0 {
		return false
	}
	// The file's own file system: FUSE mounted over it reports whatever owner and mode its daemon
	// chooses (the walk checked only the directories).
	return rf.checkFS(st) == nil
}

// runGuarded runs program (a guest path) through runProgram, by its real path under s.root, once
// program and every file of also pass trustedProgram. Nothing runs otherwise.
func (s *sys) runGuarded(ctx context.Context, program string, also []string, outLimit int, args ...string) ([]byte, []byte, error) {
	if err := s.trustedProgram(append([]string{program}, also...)...); err != nil {
		return nil, nil, err
	}
	return runProgram(ctx, s.host(program), outLimit, args...)
}
