package notify

import "context"

// MailerSource gives the sender the mailer of the current settings at every drain.
type MailerSource interface {
	Mailer(ctx context.Context) (Mailer, func(), error) // nil Mailer: not configured
}

// Mailer builds the mailer of the stored settings; without settings it is the fallback (the e2e mailbox, or nil in a
// release build: the sender records skipped_no_smtp, L-18). The returned func zeroes the unsealed password.
func (s *Settings) Mailer(ctx context.Context) (Mailer, func(), error) {
	rec, ok, err := s.load(ctx, s.pool)
	if err != nil {
		return nil, func() {}, err
	}
	if !ok {
		return s.fallback, func() {}, nil
	}
	cfg, release, err := s.config(ctx, s.pool, rec)
	if err != nil {
		return nil, func() {}, err
	}
	m, err := NewSMTPMailer(cfg, s.clock)
	if err != nil {
		release()
		return nil, func() {}, err
	}
	return m, release, nil
}
