package backup

// WriteFile is the file Create writes, for the disk-full hooks of the tests.
type WriteFile = writeFile

// SetCreate replaces how Create opens its partial files.
func SetCreate(c *Config, f func(path string) (WriteFile, error)) { c.create = f }

// SetStatfs replaces the free-space query of the backups directory.
func SetStatfs(c *Config, f func(dir string) (uint64, error)) { c.statfs = f }

// SetInDump runs f inside Create's snapshot transaction, after the manifest was written.
func SetInDump(s *Service, f func()) { s.inDump = f }

// SetRecordHook runs f inside the transaction that records a successful backup; an error from f fails that state
// write after the file was made.
func SetRecordHook(s *Service, f func() error) { s.recordHook = f }
