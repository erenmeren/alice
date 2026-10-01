//go:build linux

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
)

var (
	errTooLarge   = errors.New("file too large")
	errNotRegular = errors.New("not a regular file")
)

// readRegular reads a regular file of at most limit bytes. It never follows a symlink in the last
// path element and never blocks on a FIFO or device.
func (s *sys) readRegular(guest string, limit int) ([]byte, error) {
	f, err := os.OpenFile(s.host(guest), os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0) //nolint:gosec // G304: the path is computed and validated by the helper
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, errNotRegular
	}
	data, err := io.ReadAll(io.LimitReader(f, int64(limit)+1))
	if err != nil {
		return nil, err
	}
	if len(data) > limit {
		return nil, errTooLarge
	}
	return data, nil
}

// resolveNearest resolves every symlink of an absolute guest path. Missing trailing elements are
// kept as they are (a file or a .ssh directory that does not exist yet). It reports false when the
// path resolves outside the filesystem root or cannot be resolved.
func (s *sys) resolveNearest(guest string) (string, bool) {
	cur := filepath.Clean(guest)
	var rest []string
	for {
		real, err := filepath.EvalSymlinks(s.host(cur))
		if err == nil {
			g, ok := s.guest(real)
			if !ok {
				return "", false
			}
			parts := []string{g}
			for i := len(rest) - 1; i >= 0; i-- {
				parts = append(parts, rest[i])
			}
			return filepath.Join(parts...), true
		}
		if !errors.Is(err, fs.ErrNotExist) || cur == "/" {
			return "", false
		}
		rest = append(rest, filepath.Base(cur))
		cur = filepath.Dir(cur)
	}
}

// within reports whether p is dir or lies below it.
func within(p, dir string) bool {
	return dir == "/" || p == dir || len(p) > len(dir) && p[:len(dir)] == dir && p[len(dir)] == '/'
}

// owner returns the uid and gid of a stat result.
func owner(st fs.FileInfo) (int, int) {
	if stat, ok := st.Sys().(*syscall.Stat_t); ok {
		return int(stat.Uid), int(stat.Gid)
	}
	return -1, -1
}

func hexSHA(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
