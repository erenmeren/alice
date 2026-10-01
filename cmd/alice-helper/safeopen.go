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

// useOpenat2 lets tests force the component-wise fallback.
var useOpenat2 = true

// openCandidate opens a candidate file race-free: the allowed directory is opened first, then the
// rest of the path is resolved beneath that descriptor, so a component swapped for a symlink after
// the scan can never lead outside it. Symlinks that stay beneath the directory are followed
// (A-13); where openat2 is unavailable the fallback walks the path one openat at a time and refuses
// every symlink component. The caller checks the returned file with fstat (fileOK).
func (s *sys) openCandidate(c candidate) (*os.File, error) {
	rel := strings.TrimPrefix(strings.TrimPrefix(c.real, c.dir), "/")
	if !within(c.real, c.dir) || rel == "" {
		return nil, errEscaped
	}
	dirfd, err := unix.Open(s.host(c.dir), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer func() { _ = unix.Close(dirfd) }()
	fd := -1
	if useOpenat2 {
		fd, err = unix.Openat2(dirfd, rel, &unix.OpenHow{
			Flags:   unix.O_RDONLY | unix.O_NONBLOCK | unix.O_CLOEXEC | unix.O_NOFOLLOW,
			Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_XDEV,
		})
		if errors.Is(err, unix.EXDEV) {
			return nil, errEscaped
		}
	}
	if !useOpenat2 || errors.Is(err, unix.ENOSYS) {
		fd, err = walkOpen(dirfd, rel)
	}
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), "authorized_keys"), nil
}

// walkOpen is the openat2-less fallback: no symlink component is followed.
func walkOpen(dirfd int, rel string) (int, error) {
	parts := strings.Split(rel, "/")
	cur, own := dirfd, false
	closeCur := func() {
		if own {
			_ = unix.Close(cur)
		}
	}
	for i, p := range parts {
		flags := unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_CLOEXEC
		last := i == len(parts)-1
		if last {
			flags |= unix.O_NONBLOCK
		} else {
			flags |= unix.O_DIRECTORY
		}
		fd, err := unix.Openat(cur, p, flags, 0)
		closeCur()
		if err != nil {
			if !last && (errors.Is(err, unix.ELOOP) || errors.Is(err, unix.ENOTDIR)) {
				return -1, errEscaped
			}
			return -1, err
		}
		cur, own = fd, true
	}
	return cur, nil
}

// fileOK checks an opened candidate: a regular file with one link, owned by its user or root.
func fileOK(st fs.FileInfo, acct account) error {
	if !st.Mode().IsRegular() {
		return errNotRegular
	}
	stat, ok := st.Sys().(*syscall.Stat_t)
	if !ok || stat.Nlink != 1 || (int(stat.Uid) != acct.uid && stat.Uid != 0) {
		return errUnsafe
	}
	return nil
}

// readCandidate opens, checks and reads a candidate from one descriptor.
func (s *sys) readCandidate(c candidate) ([]byte, error) {
	f, err := s.openCandidate(c)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if err := fileOK(st, c.acct); err != nil {
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
