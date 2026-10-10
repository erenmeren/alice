package notify

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/mail"
	"regexp"
	"strconv"
	"time"
	"unicode"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"alice/internal/audit"
	"alice/internal/i18n"
	"alice/internal/platform/clock"
	"alice/internal/platform/db"
	"alice/internal/platform/settings"
	"alice/internal/platform/validate"
	"alice/internal/secrets"
)

// The two TLS modes of the mail server (spec §7.5).
const (
	TLSModeSTARTTLS = "starttls"
	TLSModeTLS      = "tls"
)

const (
	// TestMailTimeout bounds one test e-mail, DNS, TLS and the exchange included.
	TestMailTimeout = 30 * time.Second
	// SeenCertValidFor is how long a certificate a failed test saw can still be trusted (F-62).
	SeenCertValidFor = time.Hour
	// TemplateTestMail is the template of the test e-mail (email.notify.test.*).
	TemplateTestMail = "notify.test"
)

// Errors of the mail settings.
var (
	ErrNotConfigured = errors.New("notify: no mail settings")
	ErrVersion       = errors.New("notify: the mail settings changed since they were read")
	ErrCertNotSeen   = errors.New("notify: no failed test saw that certificate for this server in the last hour")
)

const (
	smtpKey       = "notify.smtp"
	seenKey       = "notify.smtp_seen_cert"
	tombstoneKey  = "notify.smtp.deleted"  // S-12: written by DeleteSMTP, blocks the re-import of ALICE_SMTP_*
	passwordKey   = "notify.smtp.password" //nolint:gosec // G101: the setting_secrets key of the SMTP password, not a credential
	settingObject = "setting"
)

const (
	maxHost     = 253
	maxAddress  = 254
	maxUsername = 255
	maxPassword = 1024
	maxCAPEM    = 64 << 10
	maxCACerts  = 20
)

var (
	hostPattern        = regexp.MustCompile(`^[A-Za-z0-9._:\[\]-]+$`)
	fingerprintPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// TrustedCert is the certificate an Administrator pinned.
type TrustedCert struct {
	CertInfo
	TrustedBy string
	TrustedAt time.Time
}

// SMTPSettings is the stored mail configuration; the password is never part of it.
type SMTPSettings struct {
	Host        string
	Port        int
	TLSMode     string
	From        string
	Username    string
	HasPassword bool
	CAPEM       string
	Trusted     *TrustedCert
	Version     int
	UpdatedAt   time.Time
}

// SMTPInput is a request to set the mail configuration.
type SMTPInput struct {
	Host, TLSMode, From, Username, CAPEM string
	Port                                 int
	Password                             *secrets.Plaintext // nil: keep; an empty Plaintext: remove; else replace
}

// SettingsConfig wires Settings.
type SettingsConfig struct {
	Pool     *pgxpool.Pool
	Keyring  *secrets.Keyring
	Audit    *audit.Log
	Clock    clock.Clock
	Catalog  *i18n.Catalog
	Dial     func(ctx context.Context, network, addr string) (net.Conn, error) // nil: netaddr.DialContext
	Fallback Mailer                                                            // no mail settings: the e2e mailbox; nil in release (L-18)
	Log      *slog.Logger                                                      // nil: discard
}

// Settings stores the mail configuration (the password as an envelope in setting_secrets) and builds the mailer.
type Settings struct {
	pool     *pgxpool.Pool
	keyring  *secrets.Keyring
	audit    *audit.Log
	clock    clock.Clock
	catalog  *i18n.Catalog
	dial     func(ctx context.Context, network, addr string) (net.Conn, error)
	fallback Mailer
	log      *slog.Logger
}

// NewSettings builds the store.
func NewSettings(c SettingsConfig) *Settings {
	lg := c.Log
	if lg == nil {
		lg = slog.New(slog.DiscardHandler)
	}
	return &Settings{pool: c.Pool, keyring: c.Keyring, audit: c.Audit, clock: c.Clock, catalog: c.Catalog,
		dial: c.Dial, fallback: c.Fallback, log: lg}
}

type trustedRecord struct {
	Fingerprint string    `json:"fingerprint"`
	Subject     string    `json:"subject"`
	NotAfter    time.Time `json:"not_after"`
	TrustedBy   string    `json:"trusted_by"`
	TrustedAt   time.Time `json:"trusted_at"`
}

type smtpRecord struct {
	Host      string         `json:"host"`
	Port      int            `json:"port"`
	TLSMode   string         `json:"tls_mode"`
	From      string         `json:"from"`
	Username  string         `json:"username"`
	CAPEM     string         `json:"ca_pem"`
	Trusted   *trustedRecord `json:"trusted,omitempty"`
	Version   int            `json:"version"`
	UpdatedAt time.Time      `json:"updated_at"`
}

// seenRecord is the leaf a failed test saw, bound to the host and port it was seen on (S-6).
type seenRecord struct {
	Fingerprint string    `json:"fingerprint"`
	Subject     string    `json:"subject"`
	NotAfter    time.Time `json:"not_after"`
	SeenAt      time.Time `json:"seen_at"`
	Host        string    `json:"host"`
	Port        int       `json:"port"`
}

func (s *Settings) load(ctx context.Context, q db.Querier) (smtpRecord, bool, error) {
	var rec smtpRecord
	ok, err := settings.Get(ctx, q, smtpKey, &rec)
	return rec, ok, err
}

func (s *Settings) hasPassword(ctx context.Context, q db.Querier) (bool, error) {
	var has bool
	if err := q.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM setting_secrets WHERE key = $1)`, passwordKey).Scan(&has); err != nil {
		return false, fmt.Errorf("notify: read the mail password state: %w", err)
	}
	return has, nil
}

func (s *Settings) view(ctx context.Context, q db.Querier, rec smtpRecord) (SMTPSettings, error) {
	has, err := s.hasPassword(ctx, q)
	if err != nil {
		return SMTPSettings{}, err
	}
	out := SMTPSettings{Host: rec.Host, Port: rec.Port, TLSMode: rec.TLSMode, From: rec.From, Username: rec.Username,
		HasPassword: has, CAPEM: rec.CAPEM, Version: rec.Version, UpdatedAt: rec.UpdatedAt}
	if t := rec.Trusted; t != nil {
		out.Trusted = &TrustedCert{CertInfo: CertInfo{Fingerprint: t.Fingerprint, Subject: t.Subject, NotAfter: t.NotAfter},
			TrustedBy: t.TrustedBy, TrustedAt: t.TrustedAt}
	}
	return out, nil
}

// SMTP returns the stored mail settings; ok is false when none exist.
func (s *Settings) SMTP(ctx context.Context) (SMTPSettings, bool, error) {
	rec, ok, err := s.load(ctx, s.pool)
	if err != nil || !ok {
		return SMTPSettings{}, false, err
	}
	v, err := s.view(ctx, s.pool, rec)
	return v, err == nil, err
}

// mutate runs fn in one transaction holding the settings lock, after the version check. version 0 means "no record".
func (s *Settings) mutate(ctx context.Context, version int, fn func(tx pgx.Tx, rec smtpRecord, exists bool) error) error {
	return db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, smtpKey); err != nil {
			return fmt.Errorf("notify: lock the mail settings: %w", err)
		}
		rec, ok, err := s.load(ctx, tx)
		if err != nil {
			return err
		}
		if version != rec.Version {
			return ErrVersion
		}
		return fn(tx, rec, ok)
	})
}

func (s *Settings) record(ctx context.Context, tx pgx.Tx, e audit.Event) error {
	e.ObjectType, e.ObjectID, e.Result = settingObject, smtpKey, audit.Success
	_, err := s.audit.Append(ctx, tx, e)
	return err
}

// SaveSMTP validates and stores the mail settings at version (0 = none yet). The caller zeroes in.Password too; it
// is zeroed here on every path.
func (s *Settings) SaveSMTP(ctx context.Context, a audit.Actor, version int, in SMTPInput) (SMTPSettings, error) {
	if in.Password != nil {
		defer in.Password.Zero()
	}
	var out SMTPSettings
	caCount, verrs := validateSMTP(in)
	err := s.mutate(ctx, version, func(tx pgx.Tx, rec smtpRecord, _ bool) error {
		has, err := s.hasPassword(ctx, tx)
		if err != nil {
			return err
		}
		// A stored password is never sent to another server: a new host or port needs the password again, so an
		// Administrator (or a stepped-up session) cannot redirect it to a server they control.
		moved := rec.Host != in.Host || rec.Port != in.Port
		if in.Username != "" && ((in.Password == nil && (!has || moved)) || (in.Password != nil && len(in.Password.Bytes()) == 0)) {
			verrs.Add("password", validate.Required, nil)
		}
		if err := verrs.Err(); err != nil {
			return err
		}
		next, authChanged, err := s.store(ctx, tx, rec, in)
		if err != nil {
			return err
		}
		out, err = s.view(ctx, tx, next)
		if err != nil {
			return err
		}
		return s.record(ctx, tx, audit.Event{Actor: a, Action: "settings.smtp_changed", Details: map[string]string{
			"host": in.Host, "port": strconv.Itoa(in.Port), "tls_mode": in.TLSMode, "from": in.From, "username": in.Username,
			"auth_changed": strconv.FormatBool(authChanged), "ca_count": strconv.Itoa(caCount)}})
	})
	return out, err
}

// store writes the record and the password envelope of an already validated input.
func (s *Settings) store(ctx context.Context, tx pgx.Tx, old smtpRecord, in SMTPInput) (smtpRecord, bool, error) {
	now := s.clock.Now().UTC()
	next := smtpRecord{Host: in.Host, Port: in.Port, TLSMode: in.TLSMode, From: in.From, Username: in.Username,
		CAPEM: in.CAPEM, Version: old.Version + 1, UpdatedAt: now}
	if old.Host == in.Host && old.Port == in.Port {
		next.Trusted = old.Trusted // the pin belongs to that server
	} else if err := settings.Delete(ctx, tx, seenKey); err != nil { // S-6
		return smtpRecord{}, false, err
	}
	authChanged := false
	switch {
	case in.Username == "":
		// No user name, no authentication: an envelope would be unused (and a stale one is dropped).
		had, err := s.hasPassword(ctx, tx)
		if err != nil {
			return smtpRecord{}, false, err
		}
		authChanged = had
		if err := secrets.DeleteSetting(ctx, tx, passwordKey); err != nil {
			return smtpRecord{}, false, err
		}
	case in.Password == nil:
	case len(in.Password.Bytes()) == 0:
		authChanged = true
		if err := secrets.DeleteSetting(ctx, tx, passwordKey); err != nil {
			return smtpRecord{}, false, err
		}
	default:
		authChanged = true
		if err := s.keyring.PutSetting(ctx, tx, passwordKey, *in.Password, now); err != nil {
			return smtpRecord{}, false, err
		}
	}
	if err := settings.Set(ctx, tx, smtpKey, next, now); err != nil {
		return smtpRecord{}, false, err
	}
	return next, authChanged, nil
}

// DeleteSMTP removes the mail settings, the certificate a test saw and the password, and leaves a tombstone so that
// ALICE_SMTP_* are not imported again (S-12).
func (s *Settings) DeleteSMTP(ctx context.Context, a audit.Actor, version int) error {
	return s.mutate(ctx, version, func(tx pgx.Tx, _ smtpRecord, exists bool) error {
		if !exists {
			return ErrNotConfigured
		}
		now := s.clock.Now().UTC()
		for _, key := range []string{smtpKey, seenKey} {
			if err := settings.Delete(ctx, tx, key); err != nil {
				return err
			}
		}
		if err := secrets.DeleteSetting(ctx, tx, passwordKey); err != nil {
			return err
		}
		if err := settings.Set(ctx, tx, tombstoneKey, map[string]time.Time{"deleted_at": now}, now); err != nil {
			return err
		}
		return s.record(ctx, tx, audit.Event{Actor: a, Action: "settings.smtp_removed"})
	})
}

// validateSMTP checks the fields that need no database. It returns the number of CA certificates.
func validateSMTP(in SMTPInput) (int, validate.Errors) {
	var v validate.Errors
	switch {
	case in.Host == "":
		v.Add("host", validate.Required, nil)
	case len(in.Host) > maxHost:
		v.Add("host", validate.TooLong, map[string]string{"max": strconv.Itoa(maxHost)})
	case !hostPattern.MatchString(in.Host):
		v.Add("host", validate.Pattern, nil)
	}
	if in.Port < 1 || in.Port > 65535 {
		v.Add("port", validate.OutOfRange, map[string]string{"min": "1", "max": "65535"})
	}
	if in.TLSMode != TLSModeSTARTTLS && in.TLSMode != TLSModeTLS {
		v.Add("tls_mode", validate.OneOf, map[string]string{"values": TLSModeSTARTTLS + ", " + TLSModeTLS})
	}
	if !validAddress(in.From) {
		v.Add("from", validate.Email, nil)
	}
	if len(in.Username) > maxUsername {
		v.Add("username", validate.TooLong, map[string]string{"max": strconv.Itoa(maxUsername)})
	} else if hasControl(in.Username) {
		v.Add("username", validate.Pattern, nil)
	}
	if in.Password != nil && len(in.Password.Bytes()) > maxPassword {
		v.Add("password", validate.TooLong, map[string]string{"max": strconv.Itoa(maxPassword)})
	}
	n, code := parseCAPEM(in.CAPEM)
	switch code {
	case "":
	case validate.TooLong:
		v.Add("ca_pem", code, map[string]string{"max": strconv.Itoa(maxCAPEM)})
	default:
		v.Add("ca_pem", code, nil)
	}
	return n, v
}

func validAddress(s string) bool {
	if s == "" || len(s) > maxAddress {
		return false
	}
	a, err := mail.ParseAddress(s)
	return err == nil && a.Address != ""
}

func hasControl(s string) bool {
	for _, r := range s {
		if unicode.IsControl(r) {
			return true
		}
	}
	return false
}

// parseCAPEM counts the certificates of a bundle: only CERTIFICATE blocks that parse, 1 to maxCACerts of them;
// "" is no bundle. The code is a validate code, "" when the bundle is fine.
func parseCAPEM(text string) (int, string) {
	if text == "" {
		return 0, ""
	}
	if len(text) > maxCAPEM {
		return 0, validate.TooLong
	}
	rest, n := []byte(text), 0
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			return 0, validate.Pattern
		}
		if _, err := x509.ParseCertificate(block.Bytes); err != nil {
			return 0, validate.Pattern
		}
		n++
	}
	if len(bytes.TrimSpace(rest)) != 0 || n == 0 {
		return 0, validate.Pattern
	}
	if n > maxCACerts {
		return 0, validate.TooLong
	}
	return n, ""
}

// config builds the mailer configuration of rec. The returned func zeroes the unsealed password.
func (s *Settings) config(ctx context.Context, q db.Querier, rec smtpRecord) (SMTPConfig, func(), error) {
	cfg := SMTPConfig{Host: rec.Host, Port: rec.Port, From: rec.From, Username: rec.Username, TLSMode: rec.TLSMode, Dial: s.dial}
	if rec.Trusted != nil {
		cfg.Pin = rec.Trusted.Fingerprint
	}
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	if rec.CAPEM != "" {
		pool.AppendCertsFromPEM([]byte(rec.CAPEM))
	}
	cfg.RootCAs = pool
	release := func() {}
	if rec.Username != "" {
		p, ok, err := s.keyring.GetSetting(ctx, q, passwordKey)
		if err != nil {
			return SMTPConfig{}, release, fmt.Errorf("notify: open the mail password: %w", err)
		}
		if ok {
			cfg.Password = p
			release = p.Zero
		}
	}
	return cfg, release, nil
}
