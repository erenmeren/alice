//go:build unix

package secrets

import (
	"fmt"
	"io/fs"
	"os"
	"syscall"
)

// Open flags for the key file: never follow a symlink, never block on a FIFO.
const (
	oNoFollow = syscall.O_NOFOLLOW
	oNonBlock = syscall.O_NONBLOCK
)

// geteuid is the effective-UID lookup for the owner check; tests replace it.
var geteuid = os.Geteuid

// checkKeyFileOwner refuses a key file owned by someone other than the running user.
func checkKeyFileOwner(path string, info fs.FileInfo) error {
	if st, ok := info.Sys().(*syscall.Stat_t); ok && int(st.Uid) != geteuid() {
		return fmt.Errorf("%w: %s is owned by uid %d, not the running user (uid %d); run: chown %d %s", ErrMasterKeyPermissions, path, st.Uid, geteuid(), geteuid(), path)
	}
	return nil
}
