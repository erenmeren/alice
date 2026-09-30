// Package secrets implements Alice's secret store: envelope encryption with
// per-secret data keys (DEKs) wrapped by the master key, sub-key derivation,
// and the recovery-passphrase backup key. Only this package decrypts secrets.
package secrets

import (
	"fmt"
	"io"
	"log/slog"
)

const redacted = "[redacted]"

// Plaintext holds decrypted secret material. Every formatting, JSON and
// logging path renders it as "[redacted]"; call Bytes to use the value and
// Zero when done.
type Plaintext struct {
	b []byte
}

// NewPlaintext wraps b without copying it.
func NewPlaintext(b []byte) Plaintext { return Plaintext{b: b} }

// Bytes returns the secret bytes. The caller must not log them.
func (p Plaintext) Bytes() []byte { return p.b }

// Zero overwrites the secret bytes in place.
func (p Plaintext) Zero() { clear(p.b) }

// String implements fmt.Stringer.
func (Plaintext) String() string { return redacted }

// GoString implements fmt.GoStringer.
func (Plaintext) GoString() string { return redacted }

// Format implements fmt.Formatter so every verb (%v, %+v, %#v, %s, %x, %q) is redacted.
func (Plaintext) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, redacted) }

// MarshalJSON implements json.Marshaler.
func (Plaintext) MarshalJSON() ([]byte, error) { return []byte(`"` + redacted + `"`), nil }

// LogValue implements slog.LogValuer.
func (Plaintext) LogValue() slog.Value { return slog.StringValue(redacted) }
