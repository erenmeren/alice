package backup

// SetHashed runs f each time the service hashes a whole backup file for its shallow check.
func SetHashed(s *Service, f func(name string)) { s.hashed = f }
