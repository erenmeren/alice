package sign

import "time"

// SetTimeout replaces the signing time limit (2 minutes) so a test need not wait for it.
func SetTimeout(s *OpenPGPSigner, d time.Duration) { s.timeout = d }

// Timeout returns the signing time limit.
func Timeout(s *OpenPGPSigner) time.Duration { return s.timeout }
