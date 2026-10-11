package forward

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/netip"
	"regexp"
	"strconv"

	"github.com/jackc/pgx/v5"

	"alice/internal/audit"
	"alice/internal/platform/db"
	"alice/internal/platform/netaddr"
	"alice/internal/platform/settings"
	"alice/internal/platform/validate"
)

// Settings keys (C1).
const (
	settingsKey = "audit.forwarding"
	stateKey    = "audit.forwarding.state"
)

// DefaultPort is the syslog-over-TLS port of RFC 5425.
const DefaultPort = 6514

const (
	maxHost    = 253
	maxCAPEM   = 64 << 10
	maxCACerts = 20
)

var hostPattern = regexp.MustCompile(`^[A-Za-z0-9._:-]+$`)

// record is the stored form of Settings; the CA bundle is kept here (a trust anchor, not a secret) and never
// returned to a reader.
type record struct {
	Enabled   bool      `json:"enabled"`
	Host      string    `json:"host"`
	Port      int       `json:"port"`
	Transport Transport `json:"transport"`
	CAPEM     string    `json:"ca_pem,omitempty"`
	Version   int       `json:"version"`
}

func defaults() record { return record{Port: DefaultPort, Transport: TransportTLS} }

// view is what a reader gets: CAPEM is write-only, CASet tells whether a bundle is stored.
func (r record) view() Settings {
	return Settings{Enabled: r.Enabled, Host: r.Host, Port: r.Port, Transport: r.Transport, CASet: r.CAPEM != "",
		Version: r.Version}
}

func load(ctx context.Context, q db.Querier) (record, error) {
	r := defaults()
	if _, err := settings.Get(ctx, q, settingsKey, &r); err != nil {
		return record{}, fmt.Errorf("forward: %w", err)
	}
	return r, nil
}

func loadState(ctx context.Context, q db.Querier) (State, error) {
	var st State
	if _, err := settings.Get(ctx, q, stateKey, &st); err != nil {
		return State{}, fmt.Errorf("forward: %w", err)
	}
	return st, nil
}

// normalize fills the defaults of a disabled or partial input and validates it. A host that is an address
// Alice never connects to is ErrAddressRefused; field problems are validate.Errors.
func normalize(in Settings) (Settings, error) {
	if in.Transport == "" {
		in.Transport = TransportTLS
	}
	if in.Port == 0 && !in.Enabled {
		in.Port = DefaultPort
	}
	var v validate.Errors
	switch {
	case in.Host == "":
		if in.Enabled {
			v.Add("host", validate.Required, nil)
		}
	case len(in.Host) > maxHost:
		v.Add("host", validate.TooLong, map[string]string{"max": strconv.Itoa(maxHost)})
	case !hostPattern.MatchString(in.Host):
		v.Add("host", validate.Pattern, nil)
	}
	if in.Port < 1 || in.Port > 65535 {
		v.Add("port", validate.OutOfRange, map[string]string{"min": "1", "max": "65535"})
	}
	switch in.Transport {
	case TransportTLS, TransportTCP, TransportUDP:
	default:
		v.Add("transport", validate.OneOf, map[string]string{"values": "tls, tcp, udp"})
	}
	switch code := checkCAPEM(in.CAPEM); code {
	case "":
	case validate.TooLong:
		v.Add("ca_pem", code, map[string]string{"max": strconv.Itoa(maxCAPEM), "count": strconv.Itoa(maxCACerts)})
	default:
		v.Add("ca_pem", code, nil)
	}
	if err := v.Err(); err != nil {
		return Settings{}, err
	}
	if a, err := netip.ParseAddr(in.Host); err == nil && !netaddr.Allowed(a) {
		return Settings{}, ErrAddressRefused
	}
	return in, nil
}

// checkCAPEM accepts "" or 1..maxCACerts parsable CERTIFICATE blocks and nothing else; it returns a validate code.
func checkCAPEM(text string) string {
	if text == "" {
		return ""
	}
	if len(text) > maxCAPEM {
		return validate.TooLong
	}
	rest, n := []byte(text), 0
	for {
		var block *pem.Block
		if block, rest = pem.Decode(rest); block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			return validate.Pattern
		}
		if _, err := x509.ParseCertificate(block.Bytes); err != nil {
			return validate.Pattern
		}
		n++
	}
	switch {
	case len(bytes.TrimSpace(rest)) != 0 || n == 0:
		return validate.Pattern
	case n > maxCACerts:
		return validate.TooLong
	}
	return ""
}

// Save validates and stores the forwarding settings at version (0 = never saved) and audits
// audit.forwarding_changed. in.CAPEM replaces the CA bundle; an empty CAPEM keeps the stored one when in.CASet
// is true and removes it otherwise. The bundle never appears in the audit row or the answer.
func (f *Forwarder) Save(ctx context.Context, in Settings, version int, actor audit.Actor) (Settings, error) {
	in, err := normalize(in)
	if err != nil {
		return Settings{}, err
	}
	var out Settings
	err = db.InTx(ctx, f.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, settingsKey); err != nil {
			return fmt.Errorf("forward: lock the settings: %w", err)
		}
		old, err := load(ctx, tx)
		if err != nil {
			return err
		}
		if version != old.Version {
			return ErrVersion
		}
		next := record{Enabled: in.Enabled, Host: in.Host, Port: in.Port, Transport: in.Transport, CAPEM: in.CAPEM,
			Version: old.Version + 1}
		if in.CAPEM == "" && in.CASet {
			next.CAPEM = old.CAPEM
		}
		if err := settings.Set(ctx, tx, settingsKey, next, f.clock.Now()); err != nil {
			return fmt.Errorf("forward: %w", err)
		}
		out = next.view()
		_, err = f.audit.Append(ctx, tx, audit.Event{Actor: actor, Action: "audit.forwarding_changed",
			ObjectType: "setting", ObjectID: settingsKey, Result: audit.Success, Details: map[string]string{
				"enabled": strconv.FormatBool(next.Enabled), "host": next.Host, "port": strconv.Itoa(next.Port),
				"transport": string(next.Transport), "ca_set": strconv.FormatBool(next.CAPEM != "")}})
		return err
	})
	if err != nil {
		return Settings{}, err
	}
	return out, nil
}
