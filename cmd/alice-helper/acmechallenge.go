//go:build linux

package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"

	"golang.org/x/sys/unix"

	"alice/internal/providers/linuxssh/helperproto"
)

// The HTTP-01 webroot commands (protocol 7, ACME Task 7). The administrator publishes
// helperproto.ACMEWebroot on port 80 with a location block of their own and creates
// helperproto.ACMEChallengeDir (root's, 0755); Alice never edits the Nginx configuration. The helper
// only writes and removes ONE token file there:
//
//	acme-challenge-put --token T   stdin: the key authorization of T (exactly T "." thumbprint)
//	acme-challenge-rm  --token T
//
// Rules: the token is checked (helperproto.ValidACMEToken: 22..128 of [A-Za-z0-9_-]) before any
// path is built, so it is always one plain name; the directory is reached from "/" one element at a
// time with O_NOFOLLOW, every element must be a real directory, root's, not writable by group or
// others and on a normal file system, and the opened inode must be the checked one; no directory is
// ever created. put writes a fresh temporary file (O_CREAT|O_EXCL|O_NOFOLLOW, a random name that can
// never be a token), syncs it and renames it over the token name, so Nginx serves either the old or
// the new content; an existing token name that is not a regular file is refused. rm unlinks only a
// regular file of that name; a missing file (or a missing directory) is success. No program is run,
// no lock or journal is needed (the file is public, and a failed put leaves the previous state).

// acmeTempPrefix starts every temporary file name: the "." can never be part of a token.
const acmeTempPrefix = ".alice-acme-"

// acmeTempName is a fresh temporary name (replaceable in tests).
var acmeTempName = func() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return acmeTempPrefix + hex.EncodeToString(b[:]), nil
}

// acmeTempAttempts bounds the O_EXCL retries of put when a temporary name exists already.
const acmeTempAttempts = 8

// acmeTokenArg parses "--token T" and checks T before anything else happens.
func acmeTokenArg(sub string, args []string) (string, error) {
	if len(args) != 2 || args[0] != "--token" {
		return "", refused(helperproto.CodeUsage, "usage: "+sub+" --token <token>")
	}
	if !helperproto.ValidACMEToken(args[1]) {
		return "", refused(helperproto.CodeInvalidArgument, "the token is not allowed")
	}
	return args[1], nil
}

func cmdACMEChallengePut(ctx context.Context, s *sys, args []string) (any, error) {
	token, err := acmeTokenArg(helperproto.SubACMEChallengePut, args)
	if err != nil {
		return nil, err
	}
	path := helperproto.ACMEChallengePath(token)
	s.syslog(helperproto.SubACMEChallengePut, path)
	// Bounded by the helper's budget too: a caller that never closes stdin cannot keep a root process.
	body, err := readInput(ctx, s.stdin, helperproto.MaxACMEBody)
	if err != nil {
		return nil, failed(helperproto.CodeIOError, "the key authorization could not be read")
	}
	if len(body) > helperproto.MaxACMEBody {
		return nil, refused(helperproto.CodeTooLarge, "the key authorization is too large")
	}
	if !helperproto.ValidKeyAuthorization(token, body) {
		return nil, refused(helperproto.CodeBadContent, "the content is not the key authorization of the token")
	}
	dirfd, err := s.openChallengeDir()
	if err != nil {
		return nil, challengeDirError(err)
	}
	defer func() { _ = unix.Close(dirfd) }()
	exists, err := tokenEntry(dirfd, token)
	if err != nil {
		return nil, tokenError(err)
	}
	if err := s.writeToken(dirfd, token, body); err != nil {
		return nil, failed(helperproto.CodeIOError, "the token file could not be written")
	}
	return helperproto.ACMEChallengePutResponse{OK: true, Path: path, Replaced: exists}, nil
}

func cmdACMEChallengeRm(_ context.Context, s *sys, args []string) (any, error) {
	token, err := acmeTokenArg(helperproto.SubACMEChallengeRm, args)
	if err != nil {
		return nil, err
	}
	path := helperproto.ACMEChallengePath(token)
	s.syslog(helperproto.SubACMEChallengeRm, path)
	resp := helperproto.ACMEChallengeRmResponse{OK: true, Path: path}
	dirfd, err := s.openChallengeDir()
	if errors.Is(err, unix.ENOENT) {
		return resp, nil // no directory: the file cannot exist (nothing is created to find out)
	}
	if err != nil {
		return nil, challengeDirError(err)
	}
	defer func() { _ = unix.Close(dirfd) }()
	exists, err := tokenEntry(dirfd, token)
	if err != nil {
		return nil, tokenError(err)
	}
	if !exists {
		return resp, nil
	}
	if err := unix.Unlinkat(dirfd, token, 0); err != nil {
		if errors.Is(err, unix.ENOENT) {
			return resp, nil
		}
		return nil, failed(helperproto.CodeIOError, "the token file could not be removed")
	}
	_ = unix.Fsync(dirfd)
	resp.Removed = true
	return resp, nil
}

// openChallengeDir opens helperproto.ACMEChallengeDir from "/" element by element: each must be a
// directory (a link of any owner is refused: errEscaped), root's and not writable by group or
// others (errNotRootControlled), on a normal file system (errSpecialFS), and the opened descriptor
// must be the inode that was checked (errEscaped). A missing element is unix.ENOENT. The caller
// closes the descriptor.
func (s *sys) openChallengeDir() (int, error) {
	fd, err := unix.Open(s.host("/"), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	if err := s.checkOpenedDir(fd, nil); err != nil {
		_ = unix.Close(fd)
		return -1, err
	}
	for _, name := range helperproto.ACMEChallengeDirElems() {
		next, err := s.openChildDir(fd, name)
		_ = unix.Close(fd)
		if err != nil {
			return -1, err
		}
		fd = next
	}
	return fd, nil
}

// openChildDir opens the directory name below dirfd without following a link (see openChallengeDir).
func (s *sys) openChildDir(dirfd int, name string) (int, error) {
	var st unix.Stat_t
	if err := unix.Fstatat(dirfd, name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return -1, err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFDIR {
		return -1, errEscaped
	}
	if !s.dirOK(st) {
		return -1, errNotRootControlled
	}
	if s.walkHook != nil {
		s.walkHook(name)
	}
	fd, err := unix.Openat(dirfd, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		if errors.Is(err, unix.ELOOP) || errors.Is(err, unix.ENOTDIR) {
			return -1, errEscaped // replaced by a link or a file since the check
		}
		return -1, err
	}
	if err := s.checkOpenedDir(fd, &st); err != nil {
		_ = unix.Close(fd)
		return -1, err
	}
	return fd, nil
}

// checkOpenedDir checks an opened directory: the checked inode (when checked is set), root's and not
// writable by group or others, on a normal file system.
func (s *sys) checkOpenedDir(fd int, checked *unix.Stat_t) error {
	var got unix.Stat_t
	if err := unix.Fstat(fd, &got); err != nil {
		return err
	}
	if checked != nil && !sameFile(got, *checked) {
		return errEscaped
	}
	if !s.dirOK(got) {
		return errNotRootControlled
	}
	return s.normalFS(fd)
}

// tokenEntry reports whether the token name exists in the challenge directory; anything there that
// is not a regular file (a link, a directory, a FIFO) is errNotRegular.
func tokenEntry(dirfd int, token string) (bool, error) {
	var st unix.Stat_t
	err := unix.Fstatat(dirfd, token, &st, unix.AT_SYMLINK_NOFOLLOW)
	switch {
	case errors.Is(err, unix.ENOENT):
		return false, nil
	case err != nil:
		return false, err
	case st.Mode&unix.S_IFMT != unix.S_IFREG:
		return false, errNotRegular
	}
	return true, nil
}

// writeToken publishes body as the token file: a new temporary file in the same directory (mode
// 0644 whatever the umask, synced), renamed over the token name, then the directory synced. On any
// failure the temporary file is removed and the token name keeps what it had.
func (s *sys) writeToken(dirfd int, token string, body []byte) error {
	var (
		tmp string
		fd  = -1
		err error
	)
	for range acmeTempAttempts {
		if tmp, err = acmeTempName(); err != nil {
			return err
		}
		fd, err = unix.Openat(dirfd, tmp, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NOCTTY, 0o644)
		if !errors.Is(err, unix.EEXIST) {
			break
		}
	}
	if err != nil {
		return err
	}
	renamed := false
	defer func() {
		if !renamed {
			_ = unix.Unlinkat(dirfd, tmp, 0)
		}
	}()
	f := os.NewFile(uintptr(fd), tmp) //nolint:gosec // G115: a descriptor is never negative
	defer func() { _ = f.Close() }()
	if err := f.Chmod(0o644); err != nil { // the helper's umask is 077: Nginx's workers must read it
		return err
	}
	if _, err := f.Write(body); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if s.beforeRename != nil {
		if err := s.beforeRename(); err != nil {
			return err
		}
	}
	if err := unix.Renameat(dirfd, tmp, dirfd, token); err != nil {
		return err
	}
	renamed = true
	_ = unix.Fsync(dirfd)
	return nil
}

// challengeDirError maps an openChallengeDir failure to the answer.
func challengeDirError(err error) error {
	switch {
	case errors.Is(err, unix.ENOENT):
		return precondition(helperproto.CodeNotFound, "the challenge directory does not exist; prepare it as the host preparation guide says")
	case errors.Is(err, errNotRootControlled):
		return refused(helperproto.CodeInsecurePermissions, "a directory of the challenge path is not root's or is writable by others")
	case errors.Is(err, errEscaped), errors.Is(err, errSpecialFS), errors.Is(err, unix.ENOTDIR), errors.Is(err, unix.ELOOP):
		return refused(helperproto.CodePathNotAllowed, "the challenge path holds a link, a file or a special file system")
	default:
		return failed(helperproto.CodeIOError, "the challenge directory could not be opened")
	}
}

// tokenError maps a tokenEntry failure to the answer.
func tokenError(err error) error {
	if errors.Is(err, errNotRegular) {
		return refused(helperproto.CodeNotRegularFile, "the token name is not a regular file")
	}
	return failed(helperproto.CodeIOError, "the token file could not be checked")
}
