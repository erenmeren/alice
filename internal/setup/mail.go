package setup

import (
	"context"

	"alice/internal/auth"
)

// SkipMail finishes the optional mail step without a mail server (setup.mail_choice = skipped, audited
// setup.mail_skipped). Configured mail settings already finish the step, so skipping then changes nothing. It is
// idempotent, and after the wizard finished it changes nothing and returns the status (S-39).
func (s *Service) SkipMail(ctx context.Context, p auth.Principal, m auth.Meta) (Status, error) {
	if err := s.authorize(p); err != nil {
		return Status{}, err
	}
	configured, err := s.mailConfigured(ctx)
	if err != nil {
		return Status{}, err
	}
	if configured {
		return s.Status(ctx)
	}
	return s.choose(ctx, p, m, keyMailChoice, mailSkipped, "setup.mail_skipped")
}

func (s *Service) mailConfigured(ctx context.Context) (bool, error) {
	if s.mail == nil {
		return false, nil
	}
	_, ok, err := s.mail.SMTP(ctx)
	return ok, err
}

// mailChosen reports whether the mail step is done: mail settings exist or the step was skipped.
func (s *Service) mailChosen(ctx context.Context) (bool, error) {
	if chosen, err := hasSetting(ctx, s.pool, keyMailChoice); err != nil || chosen {
		return chosen, err
	}
	return s.mailConfigured(ctx)
}
