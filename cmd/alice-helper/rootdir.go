//go:build linux

package main

import (
	"errors"
	"slices"

	"golang.org/x/sys/unix"

	"alice/internal/providers/haproxyconf"
	"alice/internal/providers/linuxssh/helperproto"
)

var (
	// errNotDirectory: the path names something that is not a directory.
	errNotDirectory = errors.New("not a directory")
	// errTooManyEntries: a directory holds more than haproxyconf.MaxDirEntries entries.
	errTooManyEntries = errors.New("the directory has too many entries")
	// errTooManyDirLinks: the listings of one dump hold more than maxDirLinks links together.
	errTooManyDirLinks = errors.New("the directories hold too many links")
)

// maxDirLinks bounds the links the listings of one dump walk together (final review M5): each is a
// walk from "/", and 256 directories of 4096 links would otherwise run past the helper's time
// limit and fail as IO_ERROR without a reason. Past it the listing is errTooManyDirLinks, which
// haproxy-dump reports as unsupported too_complex. sys.dirLinks counts them; cmdHAProxyDump resets
// it.
const maxDirLinks = 4096

// openRootDir opens the directory dir (a helper path, not "/") the way walkRoot reaches a file
// (C9): the walk to its parent, every directory and link on the way root's and not writable by
// group or others, no pseudo or FUSE file system; a root-owned link as the last element is
// followed too. The directory itself is then checked (dirOK) before it is opened with O_DIRECTORY
// and O_NOFOLLOW, and again on the descriptor, which must be the inode that was checked, on a
// normal file system. It returns the descriptor and the resolved guest path. A missing path is an
// ENOENT or ENOTDIR error, a path that is not a directory errNotDirectory.
func (s *sys) openRootDir(dir string) (int, string, error) {
	if !helperproto.ValidPath(dir) || dir == "/" {
		return -1, "", errEscaped
	}
	rf, err := s.walk(dir, true)
	if err != nil {
		return -1, "", err
	}
	defer rf.close()
	var before unix.Stat_t
	if err := unix.Fstatat(rf.dirfd, rf.name, &before, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return -1, "", err
	}
	switch {
	case before.Mode&unix.S_IFMT != unix.S_IFDIR:
		return -1, "", errNotDirectory
	case !s.dirOK(before):
		return -1, "", errNotRootControlled
	}
	if s.walkHook != nil {
		s.walkHook(rf.name)
	}
	fd, err := unix.Openat(rf.dirfd, rf.name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		if errors.Is(err, unix.ELOOP) || errors.Is(err, unix.ENOTDIR) {
			return -1, "", errNotRootControlled // replaced since the check
		}
		return -1, "", err
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil || !sameFile(st, before) || !s.dirOK(st) {
		_ = unix.Close(fd)
		return -1, "", errNotRootControlled
	}
	if err := s.normalFS(fd); err != nil {
		_ = unix.Close(fd)
		return -1, "", err
	}
	return fd, rf.resolved, nil
}

// listRootDir lists a crt directory of haproxy-dump (Rulings 4 and 10): the names of its regular
// entries, and of its links HAProxy may load (linkLoadable), in bytewise order. Links and
// directories inside are never followed for listing. isDir is false, with no error, when dir is
// not a directory or its walk fails (openRootDir): haproxy-dump then describes it as a file, and
// describeCert reports its problem. An error means a directory that walked but cannot be listed:
// more than haproxyconf.MaxDirEntries entries of any kind (errTooManyEntries), more than
// maxDirLinks links in this dump's listings together (errTooManyDirLinks), or a read error.
// At most MaxDirEntries names (each at most NAME_MAX bytes) are returned; the caller bounds the
// names of all listings together.
func (s *sys) listRootDir(dir string) (names []string, isDir bool, err error) {
	fd, resolved, err := s.openRootDir(dir)
	if err != nil {
		return nil, false, nil
	}
	defer func() { _ = unix.Close(fd) }()
	names, err = s.rootDirNames(fd, resolved)
	if err != nil {
		return nil, true, err
	}
	slices.Sort(names)
	return names, true, nil
}

// rootDirNames reads the entries of the opened directory fd (resolved is its guest path) and keeps
// the regular files and the links HAProxy may load (linkLoadable). Entries are counted whatever
// their type: more than haproxyconf.MaxDirEntries is errTooManyEntries, so the work is bounded
// however the directory is filled; links are counted across listings in s.dirLinks: more than
// maxDirLinks is errTooManyDirLinks. An entry removed meanwhile is skipped.
func (s *sys) rootDirNames(fd int, resolved string) ([]string, error) {
	buf := make([]byte, 32<<10)
	var names, batch []string
	scanned := 0
	for {
		n, err := unix.ReadDirent(fd, buf)
		if err != nil {
			return nil, err
		}
		if n <= 0 {
			return names, nil
		}
		_, _, batch = unix.ParseDirent(buf[:n], -1, batch[:0])
		for _, name := range batch {
			if scanned++; scanned > haproxyconf.MaxDirEntries {
				return nil, errTooManyEntries
			}
			var st unix.Stat_t
			if err := unix.Fstatat(fd, name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
				if errors.Is(err, unix.ENOENT) {
					continue
				}
				return nil, err
			}
			switch st.Mode & unix.S_IFMT {
			case unix.S_IFREG:
				names = append(names, name)
			case unix.S_IFLNK:
				if s.dirLinks++; s.dirLinks > maxDirLinks {
					return nil, errTooManyDirLinks
				}
				if s.linkLoadable(resolved + "/" + name) {
					names = append(names, name)
				}
			}
		}
	}
}

// linkLoadable reports whether a link entry of a listed directory is kept (final review I2).
// HAProxy stat()s every entry, following links, and loads each regular file, so a link is dropped
// only when it certainly leads to nothing HAProxy loads: its walk ends in a missing file (ENOENT,
// ENOTDIR), or reaches through root-controlled directories something that is not a regular file.
// A link the walk cannot follow safely (a directory or link that is not root-controlled, a pseudo
// or FUSE file system, a loop) is kept: describeCert then reports its problem, as it does for the
// same path named by crt, instead of the certificate disappearing without a word.
func (s *sys) linkLoadable(p string) bool {
	rf, err := s.walkRoot(p)
	switch {
	case errors.Is(err, unix.ENOENT), errors.Is(err, unix.ENOTDIR):
		return false
	case errors.Is(err, errNotRegular):
		return false // a directory, reached through root-controlled directories
	case err != nil:
		return true
	}
	defer rf.close()
	var st unix.Stat_t
	if err := unix.Fstatat(rf.dirfd, rf.name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return !errors.Is(err, unix.ENOENT)
	}
	return st.Mode&unix.S_IFMT == unix.S_IFREG
}
