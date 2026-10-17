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
)

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
// entries, and of its links that walkRoot resolves to a regular file, in bytewise order. Links and
// directories inside are never followed for listing. isDir is false, with no error, when dir is
// not a directory or its walk fails (openRootDir): haproxy-dump then describes it as a file, and
// describeCert reports its problem. An error means a directory that walked but cannot be listed:
// more than haproxyconf.MaxDirEntries entries of any kind (errTooManyEntries), or a read error.
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
// the regular files and the links that walk to a regular file. Entries are counted whatever their
// type: more than haproxyconf.MaxDirEntries is errTooManyEntries, so the work is bounded however
// the directory is filled. An entry removed meanwhile is skipped.
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
				if s.walksToRegular(resolved + "/" + name) {
					names = append(names, name)
				}
			}
		}
	}
}

// walksToRegular reports whether walkRoot resolves p to an existing regular file.
func (s *sys) walksToRegular(p string) bool {
	rf, err := s.walkRoot(p)
	if err != nil {
		return false
	}
	defer rf.close()
	var st unix.Stat_t
	return unix.Fstatat(rf.dirfd, rf.name, &st, unix.AT_SYMLINK_NOFOLLOW) == nil && st.Mode&unix.S_IFMT == unix.S_IFREG
}
