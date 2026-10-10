package secrets_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/secrets"
)

func testKey(b byte) []byte { return bytes.Repeat([]byte{b}, secrets.KeySize) }

func keyring(t *testing.T) *secrets.Keyring {
	t.Helper()
	k, err := secrets.NewKeyring(1, testKey(7))
	require.NoError(t, err)
	return k
}

var loc = secrets.Location{Table: "user_mfa", RowID: "0192e0a0-0000-7000-8000-000000000001", Column: "totp_secret"}

func TestNewKeyringValidatesInput(t *testing.T) {
	_, err := secrets.NewKeyring(1, make([]byte, 16))
	assert.ErrorContains(t, err, "32 bytes")
	_, err = secrets.NewKeyring(0, testKey(1))
	assert.ErrorContains(t, err, "version")
	k, err := secrets.NewKeyring(3, testKey(1))
	require.NoError(t, err)
	assert.Equal(t, 3, k.Version())
}

func TestSealOpenRoundTrip(t *testing.T) {
	k := keyring(t)
	env, err := k.Seal(loc, []byte("CANARY-totp-seed"))
	require.NoError(t, err)
	assert.Len(t, env.Nonce, 12)
	assert.Equal(t, 1, env.KeyVersion)
	assert.NotContains(t, string(env.Ciphertext), "CANARY")
	assert.NotContains(t, string(env.WrappedDEK), "CANARY")

	pt, err := k.Open(loc, env)
	require.NoError(t, err)
	assert.Equal(t, "CANARY-totp-seed", string(pt.Bytes()))
}

func TestIdenticalPlaintextsGiveDifferentCiphertextsAndDEKs(t *testing.T) {
	k := keyring(t)
	a, err := k.Seal(loc, []byte("same"))
	require.NoError(t, err)
	b, err := k.Seal(loc, []byte("same"))
	require.NoError(t, err)
	assert.NotEqual(t, a.Ciphertext, b.Ciphertext)
	assert.NotEqual(t, a.Nonce, b.Nonce)
	assert.NotEqual(t, a.WrappedDEK, b.WrappedDEK)
}

func flip(b []byte, i int) []byte {
	c := append([]byte(nil), b...)
	c[i] ^= 0x01
	return c
}

func TestTamperingAnyFieldFails(t *testing.T) {
	k := keyring(t)
	env, err := k.Seal(loc, []byte("secret value"))
	require.NoError(t, err)

	cases := map[string]secrets.Envelope{
		"ciphertext first byte": {Ciphertext: flip(env.Ciphertext, 0), Nonce: env.Nonce, WrappedDEK: env.WrappedDEK, KeyVersion: 1},
		"ciphertext tag":        {Ciphertext: flip(env.Ciphertext, len(env.Ciphertext)-1), Nonce: env.Nonce, WrappedDEK: env.WrappedDEK, KeyVersion: 1},
		"nonce":                 {Ciphertext: env.Ciphertext, Nonce: flip(env.Nonce, 3), WrappedDEK: env.WrappedDEK, KeyVersion: 1},
		"wrapped DEK nonce":     {Ciphertext: env.Ciphertext, Nonce: env.Nonce, WrappedDEK: flip(env.WrappedDEK, 0), KeyVersion: 1},
		"wrapped DEK body":      {Ciphertext: env.Ciphertext, Nonce: env.Nonce, WrappedDEK: flip(env.WrappedDEK, 20), KeyVersion: 1},
		"truncated wrapped DEK": {Ciphertext: env.Ciphertext, Nonce: env.Nonce, WrappedDEK: env.WrappedDEK[:12], KeyVersion: 1},
		"short nonce":           {Ciphertext: env.Ciphertext, Nonce: env.Nonce[:8], WrappedDEK: env.WrappedDEK, KeyVersion: 1},
		"unknown key version":   {Ciphertext: env.Ciphertext, Nonce: env.Nonce, WrappedDEK: env.WrappedDEK, KeyVersion: 2},
	}
	for name, bad := range cases {
		_, err := k.Open(loc, bad)
		assert.ErrorIs(t, err, secrets.ErrDecrypt, name)
	}
}

func TestCiphertextBoundToLocation(t *testing.T) {
	k := keyring(t)
	env, err := k.Seal(loc, []byte("row one secret"))
	require.NoError(t, err)
	for name, other := range map[string]secrets.Location{
		"other row":    {Table: loc.Table, RowID: "0192e0a0-0000-7000-8000-000000000002", Column: loc.Column},
		"other column": {Table: loc.Table, RowID: loc.RowID, Column: "other"},
		"other table":  {Table: "setup_sessions", RowID: loc.RowID, Column: loc.Column},
	} {
		_, err := k.Open(other, env)
		assert.ErrorIs(t, err, secrets.ErrDecrypt, name)
	}
}

func TestOtherMasterKeyCannotOpen(t *testing.T) {
	env, err := keyring(t).Seal(loc, []byte("x"))
	require.NoError(t, err)
	other, err := secrets.NewKeyring(1, testKey(8))
	require.NoError(t, err)
	_, err = other.Open(loc, env)
	assert.ErrorIs(t, err, secrets.ErrDecrypt)
}

func TestKeyCheck(t *testing.T) {
	k := keyring(t)
	check, err := k.KeyCheck()
	require.NoError(t, err)
	require.NoError(t, k.VerifyKeyCheck(check))

	other, err := secrets.NewKeyring(1, testKey(9))
	require.NoError(t, err)
	assert.ErrorIs(t, other.VerifyKeyCheck(check), secrets.ErrMasterKeyMismatch)
	v2, err := secrets.NewKeyring(2, testKey(7))
	require.NoError(t, err)
	assert.ErrorIs(t, v2.VerifyKeyCheck(check), secrets.ErrMasterKeyMismatch, "check is bound to the version")
	assert.ErrorIs(t, k.VerifyKeyCheck([]byte("short")), secrets.ErrMasterKeyMismatch)
}

func TestDeriveIsDeterministicAndLabelSeparated(t *testing.T) {
	k := keyring(t)
	labels := []string{secrets.LabelHWM, secrets.LabelJob, secrets.LabelAuditHMAC, secrets.LabelCSRF}
	seen := map[string]bool{}
	for _, l := range labels {
		a, b := k.Derive(l), k.Derive(l)
		assert.Len(t, a, 32)
		assert.Equal(t, a, b, l)
		assert.NotEqual(t, testKey(7), a, "sub-key must differ from the master key")
		seen[string(a)] = true
	}
	assert.Len(t, seen, len(labels), "each label yields a distinct key")

	other, err := secrets.NewKeyring(1, testKey(8))
	require.NoError(t, err)
	assert.NotEqual(t, k.Derive(secrets.LabelCSRF), other.Derive(secrets.LabelCSRF))
}

func TestPlaintextIsRedactedEverywhere(t *testing.T) {
	p := secrets.NewPlaintext([]byte("CANARY-plain"))
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x"} {
		out := fmt.Sprintf(verb, p)
		assert.Equal(t, "[redacted]", out, verb)
	}
	assert.NotContains(t, fmt.Sprintf("%v", struct{ P secrets.Plaintext }{p}), "CANARY")
	assert.Equal(t, "[redacted]", p.String())

	b, err := json.Marshal(map[string]any{"p": p})
	require.NoError(t, err)
	assert.JSONEq(t, `{"p":"[redacted]"}`, string(b))

	var buf bytes.Buffer
	slog.New(slog.NewJSONHandler(&buf, nil)).Info("x", "value", p)
	assert.NotContains(t, buf.String(), "CANARY")
	assert.Contains(t, buf.String(), "[redacted]")
}

func TestPlaintextZero(t *testing.T) {
	raw := []byte("CANARY-zero")
	p := secrets.NewPlaintext(raw)
	p.Zero()
	assert.Equal(t, make([]byte, len(raw)), raw)
	assert.Equal(t, make([]byte, len(raw)), p.Bytes())
}

func TestKeyringIsRedactedEverywhere(t *testing.T) {
	k, err := secrets.NewKeyring(1, bytes.Repeat([]byte{0x5a}, secrets.KeySize))
	require.NoError(t, err)
	leaks := func(s string) bool {
		return strings.Contains(s, "90 90 90") || strings.Contains(s, "5a5a5a") || strings.Contains(s, "ZZZZ")
	}
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x"} {
		assert.Equal(t, "secrets.Keyring{version:1 key:[redacted]}", fmt.Sprintf(verb, k), verb)
		assert.Equal(t, "secrets.Keyring{version:1 key:[redacted]}", fmt.Sprintf(verb, *k), verb)
	}
	assert.False(t, leaks(fmt.Sprintf("%+v", struct{ K *secrets.Keyring }{k})))
	assert.Contains(t, fmt.Sprintf("%+v", struct{ K *secrets.Keyring }{k}), "[redacted]")

	b, err := json.Marshal(map[string]any{"k": k})
	require.NoError(t, err)
	assert.False(t, leaks(string(b)))
	assert.Contains(t, string(b), "[redacted]")

	var buf bytes.Buffer
	slog.New(slog.NewJSONHandler(&buf, nil)).Info("x", "kr", k)
	slog.New(slog.NewTextHandler(&buf, nil)).Info("x", "kr", k)
	assert.False(t, leaks(buf.String()))
	assert.Contains(t, buf.String(), "[redacted]")
}

func TestWrapBoundToKeyVersion(t *testing.T) {
	env, err := keyring(t).Seal(loc, []byte("x"))
	require.NoError(t, err)
	env.KeyVersion = 2
	v2, err := secrets.NewKeyring(2, testKey(7))
	require.NoError(t, err)
	_, err = v2.Open(loc, env)
	assert.ErrorIs(t, err, secrets.ErrDecrypt)
}

func TestPlaintextZeroValueAndUnexportedFields(t *testing.T) {
	var zero secrets.Plaintext
	assert.Nil(t, zero.Bytes())
	zero.Zero() // must not panic

	holder := struct{ p secrets.Plaintext }{secrets.NewPlaintext([]byte("PLAIN-CANARY"))}
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%d", "%x", "%q"} {
		out := fmt.Sprintf(verb, holder)
		assert.NotContains(t, out, "PLAIN-CANARY", verb)
		assert.NotContains(t, out, "80 76 65 73 78", verb, verb) // decimal bytes of "PLAIN"
		assert.NotContains(t, out, fmt.Sprintf("%x", "PLAIN-CANARY"), verb)
	}
}

func TestRedactionMethodsCalledDirectly(t *testing.T) {
	k := keyring(t)
	want := "secrets.Keyring{version:1 key:[redacted]}"
	assert.Equal(t, want, k.String())
	assert.Equal(t, want, k.GoString())

	p := secrets.NewPlaintext([]byte("CANARY-direct"))
	assert.Equal(t, "[redacted]", p.GoString())
	assert.Equal(t, "[redacted]", p.String())
}

func TestVerifyKeyCheckRejectsMalformedValues(t *testing.T) {
	k := keyring(t)
	check, err := k.KeyCheck()
	require.NoError(t, err)
	require.NoError(t, k.VerifyKeyCheck(check))

	assert.ErrorIs(t, k.VerifyKeyCheck(nil), secrets.ErrMasterKeyMismatch)
	assert.ErrorIs(t, k.VerifyKeyCheck(check[:12]), secrets.ErrMasterKeyMismatch)

	tampered := bytes.Clone(check)
	tampered[len(tampered)-1] ^= 0xff
	assert.ErrorIs(t, k.VerifyKeyCheck(tampered), secrets.ErrMasterKeyMismatch)

	other, err := secrets.NewKeyring(1, testKey(9))
	require.NoError(t, err)
	assert.ErrorIs(t, other.VerifyKeyCheck(check), secrets.ErrMasterKeyMismatch)
}
