//go:build linux

package main

import (
	"errors"
	"os"
	"strings"

	"golang.org/x/sys/unix"

	"alice/internal/providers/linuxssh/helperproto"
)

var (
	// errNotRootControlled: a directory or link on the path can be changed by a user other than root.
	errNotRootControlled = errors.New("a directory or link on the path is not controlled by root")
	// errTooManyLinks: more than maxRootLinks links (a loop).
	errTooManyLinks = errors.New("too many symbolic links")
	// errSpecialFS: a directory or file on the path is on a pseudo file system (procfs, sysfs, ...)
	// or on FUSE, whose owners and modes a user's daemon reports.
	errSpecialFS = errors.New("a pseudo or FUSE file system on the path")
)

// specialFS are the file systems the walk never trusts: pseudo file systems whose files are not
// configuration or certificates (reading them can disclose kernel or process state), and FUSE,
// whose owner and mode bits come from a daemon a user may run (user_allow_other). devtmpfs reports
// TMPFS_MAGIC and cannot be told from tmpfs; device nodes are refused as not regular anyway.
var specialFS = map[int64]bool{
	unix.PROC_SUPER_MAGIC: true, unix.SYSFS_MAGIC: true, unix.FUSE_SUPER_MAGIC: true, unix.DEBUGFS_MAGIC: true,
	unix.TRACEFS_MAGIC: true, unix.SECURITYFS_MAGIC: true, unix.CGROUP_SUPER_MAGIC: true, unix.CGROUP2_SUPER_MAGIC: true,
	unix.BPF_FS_MAGIC: true, configfsMagic: true, unix.EFIVARFS_MAGIC: true, unix.PSTOREFS_MAGIC: true,
	unix.DEVPTS_SUPER_MAGIC: true, unix.HUGETLBFS_MAGIC: true, mqueueMagic: true, unix.SELINUX_MAGIC: true,
	unix.SMACK_MAGIC: true, unix.NSFS_MAGIC: true, unix.BINFMTFS_MAGIC: true, unix.RDTGROUP_SUPER_MAGIC: true,
	unix.BINDERFS_SUPER_MAGIC: true, unix.ANON_INODE_FS_MAGIC: true, unix.PID_FS_MAGIC: true,
	unix.OPENPROM_SUPER_MAGIC: true, unix.XENFS_SUPER_MAGIC: true, unix.USBDEVICE_SUPER_MAGIC: true,
}

// File system types x/sys/unix does not name (linux/magic.h).
const (
	configfsMagic = 0x62656570
	mqueueMagic   = 0x19800202
)

// normalFS refuses a descriptor on a special file system (errSpecialFS), or whose file system
// cannot be read.
func (s *sys) normalFS(fd int) error {
	magic, err := s.fsMagic(fd)
	if err != nil || specialFS[magic] {
		return errSpecialFS
	}
	return nil
}

// rootFile is a file whose every directory and link, from "/" down, belongs to root and cannot be
// changed by anyone else: nothing a user can change redirects an operation on it. dirfd is the
// directory that holds it; name is its name there. Operations use dirfd (openat, renameat), never
// the path again.
type rootFile struct {
	dirfd     int
	name      string
	resolved  string // the guest path with every link resolved
	symlinked bool   // a link was followed on the way
}

func (f rootFile) close() { _ = unix.Close(f.dirfd) }

// open opens the file for reading without following a link. It must be a regular file with
// exactly one link (a hard link could be another name of /etc/shadow). The type is checked before
// the open, so a device or a FIFO is never opened (opening a device can have side effects), and
// again on the descriptor, which must be the inode that was checked.
func (f rootFile) open() (*os.File, unix.Stat_t, error) { return f.openLinked(false) }

// openLinked is open; with anyLinks a file with more than one link is accepted (only for reads
// that are compared and never returned: the configuration sections). Certificate reads and every
// write keep open's one-link rule.
func (f rootFile) openLinked(anyLinks bool) (*os.File, unix.Stat_t, error) {
	var before, st unix.Stat_t
	if err := unix.Fstatat(f.dirfd, f.name, &before, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return nil, st, err
	}
	if before.Mode&unix.S_IFMT != unix.S_IFREG {
		return nil, before, errNotRegular
	}
	fd, err := unix.Openat(f.dirfd, f.name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC|unix.O_NOCTTY, 0)
	if err != nil {
		return nil, st, err
	}
	if err := unix.Fstat(fd, &st); err != nil {
		_ = unix.Close(fd)
		return nil, st, err
	}
	switch {
	case st.Mode&unix.S_IFMT != unix.S_IFREG || !sameFile(st, before):
		_ = unix.Close(fd)
		return nil, st, errNotRegular
	case st.Nlink != 1 && !anyLinks:
		_ = unix.Close(fd)
		return nil, st, errUnsafe
	}
	return os.NewFile(uintptr(fd), f.name), st, nil
}

// dirOK: a directory nobody but root can change (root's, not writable by group or others; a
// sticky world-writable directory such as /tmp is refused too: its entries are other users').
func (s *sys) dirOK(st unix.Stat_t) bool { return int(st.Uid) == s.rootUID && st.Mode&0o022 == 0 }

// resolveRoot resolves the absolute, clean guest path p (helperproto.ValidPath) by descriptor, from
// "/": every directory it passes must be root's and not writable by group or others, every link
// must be root's (its directory was checked, so nobody else can replace it either). A link's target
// is resolved the same way, component by component, as the kernel does: ".." steps back to the
// previous directory descriptor (the real parent of where the walk is, never a textual join) and
// never above "/"; an absolute target restarts at "/". The last element is not opened (the caller
// opens it relative to dirfd with O_NOFOLLOW); a missing last element is returned as such and
// fails at the open with ENOENT.
//
// It is stricter than rootControlled (Phase 3) in one way and looser in one: the walk holds
// descriptors (every directory is opened with O_NOFOLLOW and must be the inode that was checked),
// and a root-owned link may contain ".." (certbot's live -> ../../archive links), which is safe
// here because ".." is resolved against the descriptors actually walked.
func (s *sys) resolveRoot(p string) (rootFile, error) {
	if !helperproto.ValidPath(p) || p == "/" {
		return rootFile{}, errEscaped
	}
	return s.walkRoot(p)
}

// walkRoot is resolveRoot for any absolute path without a ".." element: "." and empty elements
// (as nginx may print a file name, "/etc/nginx/./x" or "/etc/nginx//x") are skipped, as the
// kernel does.
func (s *sys) walkRoot(p string) (rootFile, error) {
	if !strings.HasPrefix(p, "/") || !helperproto.ValidArg(p) {
		return rootFile{}, errEscaped
	}
	rootfd, err := unix.Open(s.host("/"), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return rootFile{}, err
	}
	var st unix.Stat_t
	if err := unix.Fstat(rootfd, &st); err != nil || !s.dirOK(st) {
		_ = unix.Close(rootfd)
		return rootFile{}, errNotRootControlled
	}
	if err := s.normalFS(rootfd); err != nil {
		_ = unix.Close(rootfd)
		return rootFile{}, err
	}
	stack := []int{rootfd}
	var names []string
	fail := func(err error) (rootFile, error) {
		for _, fd := range stack {
			_ = unix.Close(fd)
		}
		return rootFile{}, err
	}
	pending := strings.Split(strings.TrimPrefix(p, "/"), "/")
	links, symlinked := 0, false
	for len(pending) > 0 {
		c := pending[0]
		pending = pending[1:]
		switch c {
		case "", ".":
			continue
		case "..":
			if len(stack) > 1 {
				_ = unix.Close(stack[len(stack)-1])
				stack, names = stack[:len(stack)-1], names[:len(names)-1]
			}
			continue
		}
		cur := stack[len(stack)-1]
		last := len(pending) == 0
		var cst unix.Stat_t
		if err := unix.Fstatat(cur, c, &cst, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			if last && errors.Is(err, unix.ENOENT) {
				return keepLast(stack, names, c, symlinked), nil
			}
			return fail(err)
		}
		switch cst.Mode & unix.S_IFMT {
		case unix.S_IFLNK:
			if int(cst.Uid) != s.rootUID {
				return fail(errNotRootControlled)
			}
			if links++; links > maxRootLinks {
				return fail(errTooManyLinks)
			}
			target, err := readlinkAt(cur, c)
			if err != nil {
				return fail(errEscaped)
			}
			symlinked = true
			if strings.HasPrefix(target, "/") {
				for _, fd := range stack[1:] {
					_ = unix.Close(fd)
				}
				stack, names = stack[:1], nil
			}
			pending = append(strings.Split(target, "/"), pending...)
		case unix.S_IFDIR:
			if last {
				return fail(errNotRegular)
			}
			if !s.dirOK(cst) {
				return fail(errNotRootControlled)
			}
			if s.walkHook != nil {
				s.walkHook(c)
			}
			fd, err := unix.Openat(cur, c, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
			if err != nil {
				if errors.Is(err, unix.ELOOP) || errors.Is(err, unix.ENOTDIR) {
					return fail(errNotRootControlled) // replaced since the check
				}
				return fail(err)
			}
			var got unix.Stat_t
			if err := unix.Fstat(fd, &got); err != nil || !sameFile(got, cst) || !s.dirOK(got) {
				_ = unix.Close(fd)
				return fail(errNotRootControlled)
			}
			if err := s.normalFS(fd); err != nil { // checked on the opened directory: owner and mode
				_ = unix.Close(fd) //                    of a FUSE directory are what its daemon says
				return fail(err)
			}
			stack, names = append(stack, fd), append(names, c)
		default:
			if !last {
				return fail(unix.ENOTDIR)
			}
			return keepLast(stack, names, c, symlinked), nil
		}
	}
	return fail(errEscaped) // the path ended at a directory ("x/." or a link to a directory)
}

// keepLast keeps the current directory open for the file c and closes the others.
func keepLast(stack []int, names []string, c string, symlinked bool) rootFile {
	for _, fd := range stack[:len(stack)-1] {
		_ = unix.Close(fd)
	}
	parts := append(append([]string{}, names...), c)
	return rootFile{dirfd: stack[len(stack)-1], name: c, resolved: "/" + strings.Join(parts, "/"), symlinked: symlinked}
}

func readlinkAt(dirfd int, name string) (string, error) {
	buf := make([]byte, 4096)
	n, err := unix.Readlinkat(dirfd, name, buf)
	if err != nil {
		return "", err
	}
	if n == 0 || n >= len(buf) {
		return "", errEscaped
	}
	return string(buf[:n]), nil
}

// certExtensions are the file name endings the helper reads or writes as certificates or keys
// (spec §12.3 rule 4): a link that resolves to /etc/shadow or a configuration file never qualifies.
var certExtensions = []string{".pem", ".crt", ".cer", ".cert", ".key", ".chained", ".fullchain"}

// certName reports whether a (resolved) file name has a certificate or key extension.
func certName(name string) bool {
	for _, ext := range certExtensions {
		if len(name) > len(ext) && strings.HasSuffix(name, ext) {
			return true
		}
	}
	return false
}

// problemOf maps a resolve or open error to a helperproto.File* code.
func problemOf(err error) string {
	switch {
	case errors.Is(err, unix.ENOENT):
		return helperproto.FileMissing
	case errors.Is(err, errNotRootControlled), errors.Is(err, errEscaped), errors.Is(err, errSpecialFS):
		return helperproto.FileNotRootControlled
	case errors.Is(err, errUnsafe):
		return helperproto.FileHardLinked
	case errors.Is(err, errNotRegular), errors.Is(err, unix.ENOTDIR), errors.Is(err, unix.ELOOP), errors.Is(err, errTooManyLinks):
		return helperproto.FileNotRegular
	case errors.Is(err, errTooLarge):
		return helperproto.FileTooLarge
	default:
		return helperproto.FileUnreadable
	}
}
