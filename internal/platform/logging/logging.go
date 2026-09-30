// Package logging builds Alice's structured logger. Every record passes a
// redacting handler so secret values never reach stdout (SEC-050).
package logging

import (
	"context"
	"io"
	"log/slog"
	"strings"
)

// Redacted replaces every value whose attribute key looks secret.
const Redacted = "[redacted]"

// New returns a JSON logger writing to w at level, with redaction applied.
func New(w io.Writer, level slog.Leveler) *slog.Logger {
	return slog.New(NewRedactingHandler(slog.NewJSONHandler(w, &slog.HandlerOptions{Level: level})))
}

// NewRedactingHandler wraps h so that attributes with secret-looking keys are
// replaced by Redacted, including inside groups and attributes added with With.
func NewRedactingHandler(h slog.Handler) slog.Handler {
	return &redactingHandler{next: h}
}

type redactingHandler struct {
	next slog.Handler
}

func (h *redactingHandler) Enabled(ctx context.Context, l slog.Level) bool {
	return h.next.Enabled(ctx, l)
}

func (h *redactingHandler) Handle(ctx context.Context, r slog.Record) error {
	out := slog.NewRecord(r.Time, r.Level, r.Message, r.PC)
	r.Attrs(func(a slog.Attr) bool {
		out.AddAttrs(redact(a))
		return true
	})
	return h.next.Handle(ctx, out)
}

func (h *redactingHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	clean := make([]slog.Attr, len(attrs))
	for i, a := range attrs {
		clean[i] = redact(a)
	}
	return &redactingHandler{next: h.next.WithAttrs(clean)}
}

func (h *redactingHandler) WithGroup(name string) slog.Handler {
	return &redactingHandler{next: h.next.WithGroup(name)}
}

// redact resolves LogValuers first, so a type that renders itself as a group
// is still inspected key by key.
func redact(a slog.Attr) slog.Attr {
	a.Value = a.Value.Resolve()
	if secretKey(a.Key) {
		return slog.String(a.Key, Redacted)
	}
	if a.Value.Kind() == slog.KindGroup {
		group := a.Value.Group()
		clean := make([]any, len(group))
		for i, g := range group {
			clean[i] = redact(g)
		}
		return slog.Group(a.Key, clean...)
	}
	return a
}

var secretParts = []string{"password", "secret", "token", "authorization", "cookie", "passphrase", "totp"}

// secretKey matches on the ASCII-folded key (strings.ToLower is banned
// repo-wide because of Turkish casing; keys are ASCII identifiers).
func secretKey(key string) bool {
	k := foldASCII(key)
	for _, p := range secretParts {
		if strings.Contains(k, p) {
			return true
		}
	}
	return strings.HasPrefix(k, "private") || k == "key" || strings.HasSuffix(k, "_key")
}

func foldASCII(s string) string {
	b := []byte(s)
	for i, c := range b {
		if 'A' <= c && c <= 'Z' {
			b[i] = c + ('a' - 'A')
		}
	}
	return string(b)
}
