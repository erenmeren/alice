package setup

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"

	"alice/internal/audit"
	"alice/internal/auth"
	"alice/internal/platform/db"
	"alice/internal/platform/settings"
)

// licenseChosen reports whether the license step is done: the evaluation was chosen or a
// license file was installed (spec §18.5 step 6).
func (s *Service) licenseChosen(ctx context.Context, q db.Querier) (bool, error) {
	set, err := hasSetting(ctx, q, keyLicenseChoice)
	if err != nil || set {
		return set, err
	}
	if s.license == nil {
		return false, nil
	}
	return s.license.Installed(ctx)
}

// ChooseEvaluation completes the license step with the 30-day evaluation. Nothing starts
// here: the evaluation runs from the installation timestamp, and a restore does not reset
// it (R27). It needs the recovery passphrase first and is idempotent.
func (s *Service) ChooseEvaluation(ctx context.Context, p auth.Principal, m auth.Meta) (Status, error) {
	if err := s.authorize(p); err != nil {
		return Status{}, err
	}
	err := db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1)", passphraseLock); err != nil {
			return err
		}
		if set, err := hasSetting(ctx, tx, keyBackupKey); err != nil || !set {
			if err == nil {
				err = ErrIncomplete
			}
			return err
		}
		if chosen, err := hasSetting(ctx, tx, keyLicenseChoice); err != nil || chosen {
			return err
		}
		now := s.clock.Now().UTC()
		if err := settings.Set(ctx, tx, keyLicenseChoice, map[string]string{"choice": "evaluation", "at": now.Format(time.RFC3339)}, now); err != nil {
			return err
		}
		_, err := s.audit.Append(ctx, tx, audit.Event{Actor: p.Actor(m), Action: "setup.evaluation_chosen", ObjectType: "setting",
			ObjectID: keyLicenseChoice, Result: audit.Success})
		return err
	})
	if err != nil {
		return Status{}, err
	}
	return s.Status(ctx)
}
