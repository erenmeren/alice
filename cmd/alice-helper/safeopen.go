//go:build linux

package main

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"

	"alice/internal/providers/linuxssh/helperproto"
)

var (
	// errEscaped means the path leaves its allowed directory (or crosses a symlink the fallback refuses).
	errEscaped = errors.New("path leaves the allowed directory")
	// errUnsafe means the file is hard-linked or owned by someone other than its user and root (spec §13.3).
	errUnsafe = errors.New("unsafe file")
)

// useOpenat2 lets tests force the component-wise fallback; openat2 is replaceable so tests can
// inject the errors a sandbox or an old kernel returns.
var (
	useOpenat2 = true
	openat2    = unix.Openat2
)

// useFallback reports whether an openat2 failure means "unsupported here" (old kernel, seccomp
// filter, odd flags) rather than a refusal: only then the component-wise walk runs.
func useFallback(err error) bool {
	return errors.Is(err, unix.ENOSYS) || errors.Is(err, unix.EPERM) || errors.Is(err, unix.EINVAL)
}

// openCandidate opens a candidate file race-free: the allowed directory is opened first, then the
// parent directory of the file is resolved beneath that descriptor (openat2 with RESOLVE_BENEATH,
// or a walk that follows no symlink where openat2 is unavailable), and the file is opened with
// openat relative to that parent descriptor with O_NOFOLLOW. A component swapped for a symlink
// after the scan can never lead outside the allowed directory. Symlinks that stay beneath it are
// followed by openat2 (A-13); the fallback refuses every symlink component. The parent's fstat is
// returned for fileOK; the caller checks the file with fstat too.
func (s *sys) openCandidate(c candidate) (*os.File, unix.Stat_t, error) {
	var parent unix.Stat_t
	rel := strings.TrimPrefix(strings.TrimPrefix(c.real, c.dir), "/")
	if !within(c.real, c.dir) || rel == "" {
		return nil, parent, errEscaped
	}
	dirRel, base := "", rel
	if i := strings.LastIndex(rel, "/"); i >= 0 {
		dirRel, base = rel[:i], rel[i+1:]
	}
	dirfd, err := unix.Open(s.host(c.dir), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, parent, err
	}
	defer func() { _ = unix.Close(dirfd) }()
	parentfd := dirfd
	if dirRel != "" {
		pfd := -1
		if useOpenat2 {
			pfd, err = openat2(dirfd, dirRel, &unix.OpenHow{
				Flags:   unix.O_PATH | unix.O_DIRECTORY | unix.O_CLOEXEC,
				Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_XDEV,
			})
			if errors.Is(err, unix.EXDEV) {
				return nil, parent, errEscaped
			}
		}
		if !useOpenat2 || (err != nil && useFallback(err)) {
			pfd, err = walkDirs(dirfd, dirRel)
		}
		if err != nil {
			return nil, parent, err
		}
		defer func() { _ = unix.Close(pfd) }()
		parentfd = pfd
	}
	if err := unix.Fstat(parentfd, &parent); err != nil {
		return nil, parent, err
	}
	fd, err := unix.Openat(parentfd, base, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, parent, err
	}
	return os.NewFile(uintptr(fd), "authorized_keys"), parent, nil
}

// walkDirs opens a directory path one component at a time without following any symlink.
func walkDirs(dirfd int, rel string) (int, error) {
	cur, own := dirfd, false
	for _, p := range strings.Split(rel, "/") {
		fd, err := unix.Openat(cur, p, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if own {
			_ = unix.Close(cur)
		}
		if err != nil {
			if errors.Is(err, unix.ELOOP) || errors.Is(err, unix.ENOTDIR) {
				return -1, errEscaped
			}
			return -1, err
		}
		cur, own = fd, true
	}
	return cur, nil
}

// fileOK checks an opened candidate: a regular file with one link that is owned by its user, or by
// root when that is credible: the user is root, or the file sits in a root-owned directory that
// group and others cannot write. A root-owned file in a user-controlled directory is refused: it
// can be a stale inode of a file root replaced (a hard link made to /etc/shadow before passwd
// rewrote it).
func fileOK(st fs.FileInfo, parent unix.Stat_t, acct account) error {
	if !st.Mode().IsRegular() {
		return errNotRegular
	}
	stat, ok := st.Sys().(*syscall.Stat_t)
	if !ok || stat.Nlink != 1 {
		return errUnsafe
	}
	return ownerOK(int(stat.Uid), int(parent.Uid), parent.Mode, acct)
}

func ownerOK(fileUID, parentUID int, parentMode uint32, acct account) error {
	switch {
	case fileUID == acct.uid:
		return nil
	case fileUID == 0 && parentUID == 0 && parentMode&0o022 == 0:
		return nil
	}
	return errUnsafe
}

// readCandidate opens, checks and reads a candidate from one descriptor.
func (s *sys) readCandidate(c candidate) ([]byte, error) {
	f, parent, err := s.openCandidate(c)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if err := fileOK(st, parent, c.acct); err != nil {
		return nil, err
	}
	if st.Size() > helperproto.MaxAuthorizedKeysSize {
		return nil, errTooLarge
	}
	data, err := io.ReadAll(io.LimitReader(f, helperproto.MaxAuthorizedKeysSize+1))
	if err != nil {
		return nil, err
	}
	if len(data) > helperproto.MaxAuthorizedKeysSize {
		return nil, errTooLarge
	}
	return data, nil
}
