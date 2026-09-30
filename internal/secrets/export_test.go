package secrets

// SetGeteuidForTest replaces the effective-UID lookup used by the master key
// owner check and returns a function that restores it.
func SetGeteuidForTest(f func() int) (restore func()) {
	old := geteuid
	geteuid = f
	return func() { geteuid = old }
}
