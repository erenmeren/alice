package notify

import (
	"context"
	"fmt"
	"net/mail"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"

	"alice/internal/audit"
	"alice/internal/platform/db"
	"alice/internal/platform/settings"
	"alice/internal/platform/validate"
)

const (
	recipientsKey = "notify.recipients"
	// MaxExtraRecipients is the most extra addresses the recipients setting holds.
	MaxExtraRecipients = 20
)

// Address is one extra recipient and the language of what is sent to it.
type Address struct {
	Email  string `json:"email"`
	Locale string `json:"locale"` // "en" or "tr"
}

// Recipients decides where every e-mail Alice sends to Administrators goes (R42 row 6).
type Recipients struct {
	Administrators bool      `json:"administrators"`
	Addresses      []Address `json:"addresses"`
	Version        int       `json:"version"`
}

// Recipients reads the setting; never saved, it is every Administrator.
func (s *Settings) Recipients(ctx context.Context) (Recipients, error) {
	return readRecipients(ctx, s.pool)
}

func readRecipients(ctx context.Context, q db.Querier) (Recipients, error) {
	r := Recipients{Administrators: true}
	ok, err := settings.Get(ctx, q, recipientsKey, &r)
	if err != nil {
		return Recipients{}, err
	}
	if !ok {
		return Recipients{Administrators: true}, nil
	}
	return r, nil
}

// SaveRecipients validates and stores the setting at version (0 = never saved). The audit row names the addresses
// (S-4) and commits with the change.
func (s *Settings) SaveRecipients(ctx context.Context, a audit.Actor, version int, r Recipients) (Recipients, error) {
	if err := validateRecipients(r).Err(); err != nil {
		return Recipients{}, err
	}
	var out Recipients
	err := db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, recipientsKey); err != nil {
			return fmt.Errorf("notify: lock the recipients: %w", err)
		}
		var cur Recipients
		if _, err := settings.Get(ctx, tx, recipientsKey, &cur); err != nil {
			return err
		}
		if cur.Version != version {
			return ErrVersion
		}
		out = Recipients{Administrators: r.Administrators, Addresses: append([]Address(nil), r.Addresses...), Version: version + 1}
		if out.Addresses == nil {
			out.Addresses = []Address{}
		}
		if err := settings.Set(ctx, tx, recipientsKey, out, s.clock.Now()); err != nil {
			return err
		}
		emails := make([]string, len(out.Addresses))
		for i, ad := range out.Addresses {
			emails[i] = ad.Email
		}
		_, err := s.audit.Append(ctx, tx, audit.Event{Actor: a, Action: "settings.recipients_changed", ObjectType: settingObject,
			ObjectID: recipientsKey, Result: audit.Success, Details: map[string]string{
				"administrators": strconv.FormatBool(out.Administrators), "address_count": strconv.Itoa(len(out.Addresses)),
				"addresses": strings.Join(emails, ", ")}})
		return err
	})
	return out, err
}

func validateRecipients(r Recipients) validate.Errors {
	var v validate.Errors
	if len(r.Addresses) > MaxExtraRecipients {
		v.Add("addresses", validate.TooLong, map[string]string{"max": strconv.Itoa(MaxExtraRecipients)})
		return v
	}
	if !r.Administrators && len(r.Addresses) == 0 {
		v.Add("addresses", validate.Required, nil)
	}
	for i, ad := range r.Addresses {
		field := "addresses." + strconv.Itoa(i)
		if !bareAddress(ad.Email) {
			v.Add(field+".email", validate.Email, nil)
		} else if repeated(r.Addresses[:i], ad.Email) {
			v.Add(field+".email", validate.Duplicate, nil)
		}
		if ad.Locale != "en" && ad.Locale != "tr" {
			v.Add(field+".locale", validate.OneOf, map[string]string{"values": "en, tr"})
		}
	}
	return v
}

// bareAddress accepts only the plain form local@domain: no display name, no angle brackets, so that the address in
// the audit row and the one the mailer uses are the same text.
func bareAddress(s string) bool {
	if !validAddress(s) {
		return false
	}
	a, err := mail.ParseAddress(s)
	return err == nil && a.Name == "" && a.Address == s
}

// sameMailbox compares the parsed addresses, ignoring case, so that no form of one address is delivered twice.
func sameMailbox(a, b string) bool {
	return strings.EqualFold(mailbox(a), mailbox(b))
}

func mailbox(s string) string {
	if a, err := mail.ParseAddress(s); err == nil {
		return a.Address
	}
	return s
}

func repeated(before []Address, email string) bool {
	for _, b := range before {
		if sameMailbox(b.Email, email) {
			return true
		}
	}
	return false
}

type recipient struct{ email, locale string }

// recipientsFor lists who an Administrator e-mail goes to: the enabled Administrators with an address (when the
// setting includes them), then every extra address not already present.
func recipientsFor(ctx context.Context, tx pgx.Tx) ([]recipient, error) {
	cfg, err := readRecipients(ctx, tx)
	if err != nil {
		return nil, err
	}
	var out []recipient
	if cfg.Administrators {
		rows, err := tx.Query(ctx, `SELECT email::text, locale FROM users
WHERE role = 'admin' AND disabled_at IS NULL AND email <> '' ORDER BY username`)
		if err != nil {
			return nil, fmt.Errorf("notify: read administrators: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var r recipient
			if err := rows.Scan(&r.email, &r.locale); err != nil {
				return nil, fmt.Errorf("notify: read administrators: %w", err)
			}
			out = append(out, r)
		}
		if err := rows.Err(); err != nil {
			return nil, fmt.Errorf("notify: read administrators: %w", err)
		}
		rows.Close()
	}
	for _, ad := range cfg.Addresses {
		dup := false
		for _, r := range out {
			if sameMailbox(r.email, ad.Email) {
				dup = true
				break
			}
		}
		if !dup {
			out = append(out, recipient{email: ad.Email, locale: ad.Locale})
		}
	}
	return out, nil
}
