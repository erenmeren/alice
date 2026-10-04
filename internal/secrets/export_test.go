package secrets

// SetGeteuidForTest replaces the effective-UID lookup used by the master key
// owner check and returns a function that restores it.
func SetGeteuidForTest(f func() int) (restore func()) {
	old := geteuid
	geteuid = f
	return func() { geteuid = old }
}

// SetSyncDirForTest replaces the directory sync of the master key file (AUD-20) and returns a
// function that restores it.
func SetSyncDirForTest(f func(dir string) error) (restore func()) {
	old := syncDir
	syncDir = f
	return func() { syncDir = old }
}
