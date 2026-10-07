package notify

import (
	"bytes"
	"context"
	"fmt"
	"strconv"

	"github.com/jackc/pgx/v5"

	"alice/internal/audit"
	"alice/internal/platform/config"
	"alice/internal/platform/db"
	"alice/internal/secrets"
)

// ImportEnv imports ALICE_SMTP_* once, when no mail settings ever existed (S-12): a tombstone left by DeleteSMTP
// blocks it too. It reports whether it imported.
func (s *Settings) ImportEnv(ctx context.Context, c config.SMTP, readFile func(string) ([]byte, error)) (bool, error) {
	if !c.Configured() {
		return false, nil
	}
	imported := false
	err := db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, smtpKey); err != nil {
			return fmt.Errorf("notify: lock the mail settings: %w", err)
		}
		var existed bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM settings WHERE key IN ($1, $2))`, smtpKey, tombstoneKey).Scan(&existed); err != nil {
			return fmt.Errorf("notify: read the mail settings: %w", err)
		}
		if existed {
			s.log.Warn("ALICE_SMTP_* is set but the mail settings in Settings are used; remove the variables")
			return nil
		}
		in := SMTPInput{Host: c.Host, Port: c.Port, TLSMode: c.TLSMode, From: c.From, Username: c.Username}
		if in.TLSMode == "" {
			in.TLSMode = TLSModeSTARTTLS
		}
		if c.PasswordFile != "" {
			raw, err := readFile(c.PasswordFile)
			if err != nil {
				return fmt.Errorf("notify: read the SMTP password file: %w", err)
			}
			p := secrets.NewPlaintext(bytes.TrimSuffix(bytes.TrimSuffix(raw, []byte("\n")), []byte("\r")))
			defer clear(raw)
			in.Password = &p
		}
		if c.CAFile != "" {
			raw, err := readFile(c.CAFile)
			if err != nil {
				return fmt.Errorf("notify: read the SMTP CA file: %w", err)
			}
			in.CAPEM = string(raw)
		}
		if in.Password != nil && len(in.Password.Bytes()) == 0 {
			in.Password = nil
		}
		if in.Username != "" && in.Password == nil {
			// The same rule as SaveSMTP: never a record that authenticates with an empty password.
			s.log.Warn("ALICE_SMTP_USERNAME is set without a password file; the SMTP settings were not imported")
			return nil
		}
		_, verrs := validateSMTP(in)
		if err := verrs.Err(); err != nil {
			return fmt.Errorf("notify: ALICE_SMTP_* are not valid: %w", err)
		}
		if _, _, err := s.store(ctx, tx, smtpRecord{}, in); err != nil {
			return err
		}
		imported = true
		return s.record(ctx, tx, audit.Event{Actor: audit.SystemActor("startup"), Action: "settings.smtp_imported",
			Details: map[string]string{"host": in.Host, "port": strconv.Itoa(in.Port), "tls_mode": in.TLSMode}})
	})
	return imported, err
}
