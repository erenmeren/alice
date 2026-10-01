package license

// SetUploadCommittedHook runs f after an upload has committed and before the evaluation
// that follows it (tests only: it lets a test end the request at that moment).
func SetUploadCommittedHook(s *Service, f func()) { s.uploadCommitted = f }
