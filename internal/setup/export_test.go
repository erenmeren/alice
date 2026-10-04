package setup

// SetBeforeBootstrap runs f between CreateAdmin's session check and the creation (AUD-21).
func SetBeforeBootstrap(s *Service, f func()) { s.beforeBootstrap = f }

// SetInBootstrapTx runs f inside the creating transaction, after it holds the users lock and
// has consumed its wizard session (AUD-21).
func SetInBootstrapTx(s *Service, f func()) { s.inBootstrapTx = f }

// SetAfterCodeCheck runs f inside StartSession's transaction, after the code matched (AUD-21).
func SetAfterCodeCheck(s *Service, f func()) { s.afterCodeCheck = f }

// SetAfterCodeRead runs f in StartSession after the stored hash was read, before the comparison.
func SetAfterCodeRead(s *Service, f func()) { s.afterCodeRead = f }
