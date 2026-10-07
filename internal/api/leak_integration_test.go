//go:build integration

package api

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.yaml.in/yaml/v3"

	apispec "alice/api"
	"alice/internal/auth"
	"alice/internal/license/licensetest"
	"alice/internal/secrets"
)

// Secret-leak suite (spec §25.2, S-01..S-05, S-07 (handler panics), S-08, S-10).

// canary returns a recognizable secret value that is unique per run.
func canary(label string) string {
	return "CANARY-" + rand.Text() + "-" + label
}

// secretValue is one secret the tests planted or received, and the responses
// (method + path) in which it may legitimately appear.
type secretValue struct {
	name    string
	value   string
	allowed map[string]bool
	// forms, when set, replaces variants(value) as the spellings to look for
	// (binary keys: hex, base64 and base64url).
	forms []string
	// bounded matches only when the spelling is not part of a longer
	// alphanumeric run (6-digit TOTP codes would otherwise match hex dumps).
	bounded bool
	// storedHashed marks derived values (hashes) that the database stores by
	// design; they are scanned in logs and responses only.
	storedHashed bool
}

func only(keys ...string) map[string]bool {
	m := map[string]bool{}
	for _, k := range keys {
		m[k] = true
	}
	return m
}

// variants are the spellings of a secret that must not appear: as typed,
// without dashes (recovery codes), hex-encoded (bytea columns in to_jsonb) and
// base64 in every alphabet (encoding/json and slog render []byte as base64).
func variants(v string) []string {
	out := []string{v}
	if stripped := strings.ReplaceAll(v, "-", ""); stripped != v {
		out = append(out, stripped)
	}
	return append(out, binaryForms([]byte(v))[1:]...)
}

// totpSeedForms are the spellings of the raw 20-byte seed behind a base32 TOTP secret.
func totpSeedForms(t *testing.T, secret string) []string {
	t.Helper()
	seed, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.TrimRight(secret, "="))
	require.NoError(t, err)
	require.Len(t, seed, 20)
	return binaryForms(seed)[1:]
}

// binaryForms are the text spellings of key material.
func binaryForms(b []byte) []string {
	return []string{
		string(b),
		hex.EncodeToString(b),
		base64.StdEncoding.EncodeToString(b),
		base64.RawStdEncoding.EncodeToString(b),
		base64.URLEncoding.EncodeToString(b),
		base64.RawURLEncoding.EncodeToString(b),
	}
}

// leakedIn reports the first spelling of sec found in text.
func (sec secretValue) leakedIn(text string) (int, bool) {
	forms := sec.forms
	if forms == nil {
		forms = variants(sec.value)
	}
	for i, f := range forms {
		if f == "" {
			continue
		}
		if sec.bounded {
			if regexp.MustCompile(`(?:^|[^0-9A-Za-z])` + regexp.QuoteMeta(f) + `(?:[^0-9A-Za-z]|$)`).MatchString(text) {
				return i, true
			}
		} else if strings.Contains(text, f) {
			return i, true
		}
	}
	return 0, false
}

// assertNoSecret fails for every secret found in text. It never prints text
// itself (it can be megabytes long).
func assertNoSecret(t *testing.T, where, text string, secs []secretValue) {
	t.Helper()
	for _, sec := range secs {
		if i, found := sec.leakedIn(text); found {
			t.Errorf("%s leaked in %s (spelling #%d)", sec.name, where, i)
		}
	}
}

// "openssh-key-v1" opens every OpenSSH private key blob; "b3BlbnNzaC1rZXktdjE" is its base64, the
// start of every OpenSSH PEM body.
var privateKeyMarkers = []string{"PRIVATE KEY-----", "OPENSSH PRIVATE KEY", "PuTTY-User-Key-File", "openssh-key-v1",
	"b3BlbnNzaC1rZXktdjE"}

// dumpTables lists every Alice table (all of schema public except goose's bookkeeping).
func (s *stack) dumpTables() []string {
	s.t.Helper()
	rows, err := s.db.Owner.Query(context.Background(), `SELECT table_name::text FROM information_schema.tables
		WHERE table_schema = 'public' AND table_type = 'BASE TABLE' AND table_name <> 'goose_db_version' ORDER BY 1`)
	require.NoError(s.t, err)
	tables, err := pgx.CollectRows(rows, pgx.RowTo[string])
	require.NoError(s.t, err)
	require.Contains(s.t, tables, "audit_log")
	return tables
}

// dump renders every row of every Alice table as JSON text (bytea as hex).
func (s *stack) dump() string {
	s.t.Helper()
	var b strings.Builder
	for _, table := range s.dumpTables() {
		var rows string
		require.NoError(s.t, s.db.Owner.QueryRow(context.Background(),
			"SELECT coalesce(string_agg(to_jsonb(t)::text, E'\\n'), '') FROM "+pgx.Identifier{table}.Sanitize()+" t").Scan(&rows))
		b.WriteString(table + ":\n" + rows + "\n")
	}
	return b.String()
}

// masterKey returns the raw master key from the stack's key file.
func (s *stack) masterKey() []byte {
	s.t.Helper()
	raw, err := os.ReadFile(filepath.Join(s.keysDir, secrets.MasterKeyFile))
	require.NoError(s.t, err)
	key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
	require.NoError(s.t, err)
	require.Len(s.t, key, secrets.KeySize)
	return key
}

// masterKeySecret is the master key file content and the key in every text spelling.
func (s *stack) masterKeySecret() secretValue {
	s.t.Helper()
	return masterKeySecretOf(s.masterKey())
}

// masterKeySecretOf is a master key in every text spelling (TestKeyScannerFlagsEverySpelling checks
// this constructor).
func masterKeySecretOf(key []byte) secretValue {
	return secretValue{name: "master key", forms: binaryForms(key)}
}

// unwrapDEK recovers the plaintext data-encryption key of an envelope the way
// secrets.Keyring.Open does (wrap AAD = table/row_id/column/key_version).
func unwrapDEK(t *testing.T, master []byte, loc secrets.Location, env secrets.Envelope) []byte {
	t.Helper()
	block, err := aes.NewCipher(master)
	require.NoError(t, err)
	gcm, err := cipher.NewGCM(block)
	require.NoError(t, err)
	aad := loc.Table + "/" + loc.RowID + "/" + loc.Column + "/" + strconv.Itoa(env.KeyVersion)
	dek, err := gcm.Open(nil, env.WrappedDEK[:gcm.NonceSize()], env.WrappedDEK[gcm.NonceSize():], []byte(aad))
	require.NoError(t, err)
	require.Len(t, dek, secrets.KeySize)
	return dek
}

// storedDEK is the DEK of the user's stored TOTP secret.
func (s *stack) storedDEK(userID string) []byte {
	s.t.Helper()
	var env secrets.Envelope
	require.NoError(s.t, s.db.Owner.QueryRow(context.Background(),
		`SELECT totp_wrapped_dek, totp_key_version FROM user_mfa WHERE user_id = $1`, userID).Scan(&env.WrappedDEK, &env.KeyVersion))
	return unwrapDEK(s.t, s.masterKey(), secrets.Location{Table: "user_mfa", RowID: userID, Column: "totp_secret"}, env)
}

// dbPasswords are the passwords of both database roles the stack connects with.
func (s *stack) dbPasswords() []secretValue {
	s.t.Helper()
	var out []secretValue
	for name, raw := range map[string]string{"owner": s.db.OwnerURL, "app": s.db.AppURL} {
		u, err := url.Parse(raw)
		require.NoError(s.t, err)
		pw, ok := u.User.Password()
		require.True(s.t, ok, "the %s URL carries a password", name)
		out = append(out, secretValue{name: "database password (" + name + ")", value: pw})
	}
	return out
}

func sha256Forms(v string) []string {
	h := sha256.Sum256([]byte(v))
	return binaryForms(h[:])[1:] // raw bytes are not text
}

// csrfRoutes are the responses that hand the caller its CSRF token.
var csrfRoutes = only(
	"POST /api/v1/setup/session", "POST /api/v1/auth/login", "POST /api/v1/setup/admin",
	"POST /api/v1/auth/mfa/verify", "GET /api/v1/auth/session", "POST /api/v1/auth/stepup", "POST /api/v1/auth/password",
)

func TestSecretsNeverLeak(t *testing.T) {
	s := newStack(t)
	ctx := context.Background()

	adminPW := canary("admin-password")
	newAdminPW := canary("admin-new-password")
	passphrase := canary("recovery-passphrase")
	operatorPW := canary("operator-password")
	resetPW := canary("reset-password")
	wrongPW := canary("wrong-password")
	junk := canary("junk")

	// A wrong setup code before the wizard starts (S-03).
	anon := s.client("198.51.100.99")
	rec := anon.do(http.MethodPost, "/api/v1/setup/session", map[string]string{"code": junk})
	assert.GreaterOrEqual(t, rec.Code, 400)

	admin := &account{username: "ada", password: adminPW}
	var duringWizard string
	adminBrowser := s.setupAdmin(admin, passphrase, func() { duringWizard = s.dump() })
	bootstrapCodes := admin.recovery

	// Sign in again, step up, and regenerate recovery codes.
	browser := s.client("198.51.100.11")
	s.signIn(browser, admin)
	s.stepUp(browser, admin)
	rec = browser.do(http.MethodPost, "/api/v1/auth/recovery-codes", nil)
	requireStatus(t, rec, http.StatusOK)
	regenerated := decodeBody[map[string][]string](t, rec)["recovery_codes"]
	require.Len(t, regenerated, 10)

	// Create and use an API token.
	rec = browser.do(http.MethodPost, "/api/v1/tokens", map[string]any{"name": "ci", "scope": "read", "expires_in_days": 30})
	requireStatus(t, rec, http.StatusCreated)
	token := decodeBody[map[string]any](t, rec)["token"].(string)
	require.True(t, strings.HasPrefix(token, "alice_"))
	api := s.client("198.51.100.12")
	api.bearer = token
	requireStatus(t, api.do(http.MethodGet, "/api/v1/version", nil), http.StatusOK)

	// Create an operator who enrolls TOTP at first sign-in.
	operator := s.createUser(adminBrowser, admin, "otto", "operator", operatorPW)
	s.firstSignIn(s.client("198.51.100.13"), operator)

	// Sign in with a recovery code.
	rc := s.client("198.51.100.14")
	s.clock.Advance(31 * time.Second)
	requireStatus(t, rc.do(http.MethodPost, "/api/v1/auth/login", map[string]string{"username": "ada", "password": adminPW}), http.StatusOK)
	requireStatus(t, rc.do(http.MethodPost, "/api/v1/auth/mfa/verify", map[string]string{"recovery_code": regenerated[0]}), http.StatusOK)

	// Failure paths (S-03): wrong password, unknown user, wrong code, bad JSON, oversized body.
	requireError(t, s.login("ada", wrongPW), http.StatusUnauthorized, "ALC-AUTH-0005")
	requireError(t, s.login("nobody-"+junk, wrongPW), http.StatusUnauthorized, "ALC-AUTH-0005")
	bad := s.freshClient()
	requireStatus(t, bad.do(http.MethodPost, "/api/v1/auth/login", map[string]string{"username": "otto", "password": operatorPW}), http.StatusOK)
	requireError(t, bad.do(http.MethodPost, "/api/v1/auth/mfa/verify", map[string]string{"code": "000000"}), http.StatusUnauthorized, "ALC-AUTH-0006")
	requireError(t, s.freshClient().do(http.MethodPost, "/api/v1/auth/login",
		`{"username":"ada","password":"`+junk+`","extra":"`+junk+`"}`), http.StatusBadRequest, "ALC-SYS-0004")
	requireError(t, s.freshClient().do(http.MethodPost, "/api/v1/auth/login",
		`{"username":"ada","password":"`+junk), http.StatusBadRequest, "ALC-SYS-0004")
	big := `{"username":"ada","password":"` + strings.Repeat(junk, (2<<20)/len(junk)) + `"}`
	requireError(t, s.freshClient().do(http.MethodPost, "/api/v1/auth/login", big), http.StatusRequestEntityTooLarge, "ALC-SYS-0007")
	rec = browser.do(http.MethodPost, "/api/v1/setup/recovery-passphrase", map[string]string{"passphrase": junk, "passphrase_confirm": junk + "x"})
	assert.GreaterOrEqual(t, rec.Code, 400)

	// An administrator resets the operator's password (B20), and the
	// administrator changes their own password (wrong current password first).
	s.stepUp(adminBrowser, admin)
	requireStatus(t, adminBrowser.do(http.MethodPost, "/api/v1/users/"+operator.id+"/actions/reset-password",
		map[string]string{"password": resetPW}), http.StatusNoContent)
	requireError(t, browser.do(http.MethodPost, "/api/v1/auth/password",
		map[string]string{"current_password": wrongPW, "new_password": newAdminPW}), http.StatusUnprocessableEntity, "ALC-AUTH-0011")
	requireStatus(t, browser.do(http.MethodPost, "/api/v1/auth/password",
		map[string]string{"current_password": adminPW, "new_password": newAdminPW}), http.StatusOK)
	require.Equal(t, http.StatusOK, s.login("otto", resetPW).Code, "the reset password works")

	adminDEK := s.storedDEK(admin.id)
	operatorDEK := s.storedDEK(operator.id)
	// Taken before the operator's MFA is reset below.
	var mfaRows, distinctDEKs, distinctCT int
	require.NoError(t, s.db.Owner.QueryRow(ctx,
		`SELECT count(*), count(DISTINCT totp_wrapped_dek), count(DISTINCT totp_secret_ct) FROM user_mfa`).Scan(&mfaRows, &distinctDEKs, &distinctCT))

	// Every read endpoint that returns rows of secret-bearing tables, and the
	// remaining mutations, so their responses are scanned too.
	s.stepUp(browser, admin)
	opPath := "/api/v1/users/" + operator.id
	requireStatus(t, browser.do(http.MethodGet, "/api/v1/users", nil), http.StatusOK)
	requireStatus(t, browser.do(http.MethodGet, opPath, nil), http.StatusOK)
	rec = browser.do(http.MethodGet, "/api/v1/tokens", nil)
	requireStatus(t, rec, http.StatusOK)
	tokens := decodeBody[map[string][]map[string]any](t, rec)["items"]
	require.Len(t, tokens, 1)
	requireStatus(t, browser.do(http.MethodGet, "/api/v1/audit", nil), http.StatusOK)
	requireStatus(t, browser.do(http.MethodGet, "/api/v1/audit/export?format=csv", nil), http.StatusOK)
	requireStatus(t, browser.do(http.MethodGet, "/api/v1/audit/export?format=json", nil), http.StatusOK)
	requireStatus(t, browser.do(http.MethodGet, "/api/v1/auth/session", nil), http.StatusOK)
	requireStatus(t, browser.do(http.MethodPatch, opPath, map[string]string{"display_name": "Otto Operator"}), http.StatusOK)
	requireStatus(t, browser.do(http.MethodPost, opPath+"/actions/reset-mfa", nil), http.StatusNoContent)
	requireStatus(t, browser.do(http.MethodPost, opPath+"/actions/revoke-sessions", nil), http.StatusNoContent)
	requireStatus(t, browser.do(http.MethodDelete, "/api/v1/tokens/"+tokens[0]["id"].(string), nil), http.StatusNoContent)

	// License endpoints: status, detail, preview, upload and a refused upload.
	requireStatus(t, browser.do(http.MethodGet, "/api/v1/license/status", nil), http.StatusOK)
	requireStatus(t, browser.do(http.MethodGet, "/api/v1/license", nil), http.StatusOK)
	licFile := string(licensetest.Sign(licensetest.Payload(s.license.Snapshot().InstallationID, s.clock.Now(), s.clock.Now().AddDate(1, 0, 0), 10)))
	requireStatus(t, browser.do(http.MethodPost, "/api/v1/license/preview", map[string]string{"license": licFile}), http.StatusOK)
	requireStatus(t, browser.do(http.MethodPost, "/api/v1/license", map[string]string{"license": licFile}), http.StatusOK)
	requireError(t, browser.do(http.MethodPost, "/api/v1/license", map[string]string{"license": junk}), http.StatusUnprocessableEntity, "ALC-LIC-0002")

	// More failure paths: a revoked and a made-up bearer token, a wrong
	// recovery code, a wrong step-up code.
	requireError(t, api.do(http.MethodGet, "/api/v1/version", nil), http.StatusUnauthorized, "ALC-AUTH-0001")
	forged := s.client("198.51.100.15")
	forged.bearer = "alice_" + strings.ReplaceAll(junk, "-", "")
	requireError(t, forged.do(http.MethodGet, "/api/v1/version", nil), http.StatusUnauthorized, "ALC-AUTH-0001")
	pending := s.freshClient()
	requireStatus(t, pending.do(http.MethodPost, "/api/v1/auth/login", map[string]string{"username": "ada", "password": newAdminPW}), http.StatusOK)
	requireError(t, pending.do(http.MethodPost, "/api/v1/auth/mfa/verify", map[string]string{"recovery_code": junk}), http.StatusUnauthorized, "ALC-AUTH-0006")
	requireError(t, browser.do(http.MethodPost, "/api/v1/auth/stepup", map[string]string{"code": "000000"}), http.StatusUnauthorized, "ALC-AUTH-0006")
	requireStatus(t, browser.do(http.MethodPost, "/api/v1/auth/logout", nil), http.StatusNoContent)

	// The installation seal paths (B1): the one-time upgrade seal, then a changed seal. Their
	// logs, history and audit rows are scanned for the installation MAC key below.
	_, err := s.db.Owner.Exec(ctx, "UPDATE license SET installation_seal = NULL")
	require.NoError(t, err)
	require.NoError(t, s.license.Restart(ctx, func(context.Context) error { return nil }))
	_, err = s.db.Owner.Exec(ctx, "UPDATE license SET installation_seal = decode(repeat('00', 32), 'hex')")
	require.NoError(t, err)
	require.NoError(t, s.license.Tick(ctx))
	require.True(t, s.license.Snapshot().InstallationTampered)

	secretsUnderTest := []secretValue{
		{name: "admin password", value: adminPW},
		{name: "admin new password", value: newAdminPW},
		{name: "operator password", value: operatorPW},
		{name: "operator reset password", value: resetPW},
		{name: "wrong password", value: wrongPW},
		{name: "junk request data", value: junk},
		{name: "recovery passphrase", value: passphrase},
		{name: "setup code", value: s.setupCode},
		{name: "admin TOTP secret", value: admin.secret, allowed: only("POST /api/v1/setup/admin/enrollment")},
		{name: "operator TOTP secret", value: operator.secret, allowed: only("POST /api/v1/auth/mfa/enroll")},
		{name: "admin TOTP seed bytes", forms: totpSeedForms(t, admin.secret), allowed: only("POST /api/v1/setup/admin/enrollment")},
		{name: "operator TOTP seed bytes", forms: totpSeedForms(t, operator.secret), allowed: only("POST /api/v1/auth/mfa/enroll")},
		{name: "API token", value: token, allowed: only("POST /api/v1/tokens")},
		{name: "API token hash", forms: sha256Forms(token), storedHashed: true},
		{name: "Argon2id hash", forms: []string{"$argon2id$"}, storedHashed: true},
		s.masterKeySecret(),
		{name: "admin TOTP DEK", forms: binaryForms(adminDEK)},
		{name: "operator TOTP DEK", forms: binaryForms(operatorDEK)},
		{name: "HWM MAC key", forms: binaryForms(s.keyring.Derive(secrets.LabelHWM))},
		{name: "HWM encryption key", forms: binaryForms(s.keyring.Derive(secrets.LabelHWMEnc))},
		{name: "installation MAC key", forms: binaryForms(s.keyring.Derive(secrets.LabelInstallation))},
	}
	secretsUnderTest = append(secretsUnderTest, s.dbPasswords()...)
	s.mu.Lock()
	codes := append([]string(nil), s.totpCodes...)
	s.mu.Unlock()
	require.NotEmpty(t, codes)
	for _, c := range codes {
		secretsUnderTest = append(secretsUnderTest, secretValue{name: "TOTP code", value: c, bounded: true})
	}
	for _, c := range bootstrapCodes {
		secretsUnderTest = append(secretsUnderTest, secretValue{name: "bootstrap recovery code", value: c, allowed: only("POST /api/v1/setup/admin")})
	}
	for _, c := range regenerated {
		secretsUnderTest = append(secretsUnderTest, secretValue{name: "regenerated recovery code", value: c, allowed: only("POST /api/v1/auth/recovery-codes")})
	}
	for _, c := range operator.recovery {
		secretsUnderTest = append(secretsUnderTest, secretValue{name: "operator recovery code", value: c, allowed: only("POST /api/v1/auth/mfa/verify")})
	}
	// Session cookie values may only travel in Set-Cookie headers, never in a
	// body, log or row; their SHA-256 (the stored id_hash) never leaves the database.
	// CSRF tokens appear only in the responses that hand them out.
	cookies, csrf := 0, 0
	for _, e := range s.recorded() {
		for _, line := range e.header.Values("Set-Cookie") {
			if ck, err := http.ParseSetCookie(line); err == nil && ck.Value != "" {
				cookies++
				secretsUnderTest = append(secretsUnderTest,
					secretValue{name: "cookie " + ck.Name, value: ck.Value},
					secretValue{name: "hash of cookie " + ck.Name, forms: sha256Forms(ck.Value), storedHashed: true})
			}
		}
		var probe struct {
			CSRFToken string `json:"csrf_token"`
		}
		if json.Unmarshal(e.body, &probe) == nil && probe.CSRFToken != "" {
			csrf++
			secretsUnderTest = append(secretsUnderTest, secretValue{name: "CSRF token", value: probe.CSRFToken, allowed: csrfRoutes})
		}
	}
	require.Positive(t, cookies)
	require.Positive(t, csrf)

	t.Run("S-01 logs contain no secret", func(t *testing.T) {
		logs := s.logs.String()
		require.NotEmpty(t, logs, "the stack logs at DEBUG level")
		assertNoSecret(t, "logs", logs, secretsUnderTest)
	})

	t.Run("S-02 S-03 responses contain secrets only where documented", func(t *testing.T) {
		exchanges := s.recorded()
		require.NotEmpty(t, exchanges)
		for _, e := range exchanges {
			headers := e.header.Clone()
			headers.Del("Set-Cookie")
			var hdr strings.Builder
			_ = headers.Write(&hdr)
			text := string(e.body) + "\n" + hdr.String()
			var applicable []secretValue
			for _, sec := range secretsUnderTest {
				if !sec.allowed[e.key()] {
					applicable = append(applicable, sec)
				}
			}
			assertNoSecret(t, fmt.Sprintf("%s (status %d)", e.key(), e.status), text, applicable)
			for _, m := range privateKeyMarkers {
				assert.NotContains(t, text, m, e.key())
			}
		}
	})

	t.Run("S-04 S-05 database and audit rows hold no plaintext secret", func(t *testing.T) {
		assert.Contains(t, duringWizard, "$argon2id$", "the snapshot must include the pending administrator")
		var plain []secretValue
		for _, sec := range secretsUnderTest {
			if !sec.storedHashed {
				plain = append(plain, sec)
			}
		}
		assertNoSecret(t, "database during the wizard", duringWizard, plain)
		assertNoSecret(t, "database", s.dump(), plain)
		var auditRows string
		require.NoError(t, s.db.Owner.QueryRow(ctx,
			`SELECT coalesce(string_agg(to_jsonb(t)::text, E'\n'), '') FROM audit_log t`).Scan(&auditRows))
		require.NotEmpty(t, auditRows)
		// Audit rows carry no secret in any form, not even a hash.
		assertNoSecret(t, "audit_log", auditRows, secretsUnderTest)
		all := duringWizard + "\n" + s.dump()
		for _, m := range privateKeyMarkers {
			assert.NotContains(t, all, m)
		}

		rows, err := s.db.Owner.Query(ctx, `SELECT password_hash FROM users`)
		require.NoError(t, err)
		for rows.Next() {
			var h string
			require.NoError(t, rows.Scan(&h))
			assert.True(t, strings.HasPrefix(h, "$argon2id$v=19$"), h)
		}
		require.NoError(t, rows.Err())
		rows.Close()

		var hashes, distinct int
		require.NoError(t, s.db.Owner.QueryRow(ctx,
			`SELECT count(*), count(DISTINCT code_hash) FROM recovery_codes WHERE code_hash LIKE '$argon2id$%'`).Scan(&hashes, &distinct))
		assert.Equal(t, hashes, distinct)
		assert.Equal(t, s.count("recovery_codes"), hashes, "every recovery code is stored as an Argon2id hash")

		assert.Equal(t, 2, mfaRows)
		assert.Equal(t, mfaRows, distinctDEKs, "every secret has its own DEK")
		assert.Equal(t, mfaRows, distinctCT)
		assert.NotEqual(t, adminDEK, operatorDEK, "every secret has its own DEK")

		loc := secrets.Location{Table: "user_mfa", RowID: admin.id, Column: "totp_secret"}
		one, err := s.keyring.Seal(loc, []byte(adminPW))
		require.NoError(t, err)
		two, err := s.keyring.Seal(loc, []byte(adminPW))
		require.NoError(t, err)
		assert.NotEqual(t, one.Ciphertext, two.Ciphertext, "identical secrets encrypt differently")
		assert.NotEqual(t, one.WrappedDEK, two.WrappedDEK)
		assert.NotEqual(t, one.Nonce, two.Nonce)

		var failures int
		require.NoError(t, s.db.Owner.QueryRow(ctx,
			`SELECT count(*) FROM audit_log WHERE action = 'auth.login' AND result = 'failure'`).Scan(&failures))
		assert.GreaterOrEqual(t, failures, 2, "failed sign-ins are audited (without the typed password)")
	})

	t.Run("S-10 test endpoints are absent", func(t *testing.T) {
		for _, m := range []string{http.MethodGet, http.MethodPost} {
			requireError(t, s.freshClient().do(m, "/test/clock", nil), http.StatusNotFound, "ALC-SYS-0001")
		}
	})
}

// panickingAuth is the real auth service whose Login panics with the
// submitted password and key material in the panic value.
type panickingAuth struct {
	AuthService
	panicValue func(password string) any
}

func (p panickingAuth) Login(_ context.Context, _, password string, _ auth.Meta) (auth.LoginResult, error) {
	panic(p.panicValue(password))
}

// S-07: a handler panic carrying secrets in its value leaves no secret in the
// logs or the response.
func TestHandlerPanicLeaksNoSecret(t *testing.T) {
	s := newStack(t)
	master := s.masterKeySecret()
	loc := secrets.Location{Table: "user_mfa", RowID: uuid.NewString(), Column: "totp_secret"}
	env, err := s.keyring.Seal(loc, []byte("seed"))
	require.NoError(t, err)
	dek := unwrapDEK(t, s.masterKey(), loc, env)
	keyText := base64.StdEncoding.EncodeToString(s.masterKey())

	for name, value := range map[string]func(string) any{
		"string": func(pw string) any {
			return fmt.Sprintf("boom: password=%s master=%s dek=%x", pw, keyText, dek)
		},
		"error": func(pw string) any {
			return fmt.Errorf("boom: %w", errors.New("password="+pw+" master="+keyText+" dek="+hex.EncodeToString(dek)))
		},
	} {
		t.Run(name, func(t *testing.T) {
			d := s.deps()
			d.Auth = panickingAuth{AuthService: s.auth, panicValue: value}
			s.handler = New(d).Handler()
			before := len(s.logs.String())

			pw := canary("panic-password")
			rec := s.freshClient().do(http.MethodPost, "/api/v1/auth/login", map[string]string{"username": "ada", "password": pw})
			requireError(t, rec, http.StatusInternalServerError, "ALC-SYS-0003")

			logs := s.logs.String()[before:]
			require.Contains(t, logs, "request handler panicked")
			var hdr strings.Builder
			_ = rec.Header().Write(&hdr)
			secs := []secretValue{
				{name: "password", value: pw},
				master,
				{name: "DEK", forms: binaryForms(dek)},
			}
			assertNoSecret(t, "logs", logs, secs)
			assertNoSecret(t, "response", rec.Body.String()+"\n"+hdr.String(), secs)
		})
	}
}

// fail() must log a fixed label, never an error's text: driver messages can
// carry column values (Task 13 review carry-in). A trigger rejects the new
// user with the row in its message and detail, so the error text holds the
// password hash.
func TestUnexpectedErrorsAreLoggedWithoutTheirText(t *testing.T) {
	s := newStack(t)
	ctx := context.Background()
	admin := &account{username: "ada", password: canary("admin-password")}
	adminBrowser := s.setupAdmin(admin, canary("recovery-passphrase"), nil)
	_, err := s.db.Owner.Exec(ctx, `
		CREATE FUNCTION leak_row() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN
			RAISE EXCEPTION 'rejected row %', NEW::text USING DETAIL = NEW::text;
		END $$;
		CREATE TRIGGER leak_row BEFORE INSERT ON users FOR EACH ROW EXECUTE FUNCTION leak_row();`)
	require.NoError(t, err)
	s.stepUp(adminBrowser, admin)
	before := len(s.logs.String())

	pw := canary("new-user-password")
	rec := adminBrowser.do(http.MethodPost, "/api/v1/users", map[string]string{
		"username": "otto", "display_name": "Otto", "email": "", "role": "operator", "password": pw,
	})
	requireError(t, rec, http.StatusInternalServerError, "ALC-SYS-0003")

	logs := s.logs.String()[before:]
	require.Contains(t, logs, "request failed")
	assert.Contains(t, logs, `"sqlstate":"P0001"`, "the log still says what kind of error it was")
	assertNoSecret(t, "logs", logs, []secretValue{
		{name: "password", value: pw},
		{name: "password hash", forms: []string{"$argon2id$", "argon2id"}},
		{name: "row text", forms: []string{"rejected row"}},
	})
	assertNoSecret(t, "response", rec.Body.String(), []secretValue{{name: "password hash", forms: []string{"argon2id"}}})
}

// --- S-08: response schemas in the OpenAPI document ---

// forbiddenResponseFields may never appear in any response schema.
var forbiddenResponseFields = []string{
	"password", "current_password", "new_password", "password_hash", "passphrase", "passphrase_confirm",
	"private_key", "token_hash", "totp_secret", "code_hash", "master_key", "client_secret",
}

// oneTimeFields may appear only in the responses of the listed operations.
var oneTimeFields = map[string]map[string]bool{
	"secret":         only("POST /api/v1/setup/admin/enrollment", "POST /api/v1/auth/mfa/enroll"),
	"otpauth_uri":    only("POST /api/v1/setup/admin/enrollment", "POST /api/v1/auth/mfa/enroll"),
	"qr_png":         only("POST /api/v1/setup/admin/enrollment", "POST /api/v1/auth/mfa/enroll"),
	"token":          only("POST /api/v1/tokens"),
	"recovery_codes": only("POST /api/v1/setup/admin", "POST /api/v1/auth/mfa/verify", "POST /api/v1/auth/recovery-codes"),
}

// identityProviderEndpointOps answer an identity provider, whose endpoints.token is the provider's token endpoint
// address (C13), not an API token: in these operations "token" is accepted when endpoints is its only parent.
var identityProviderEndpointOps = only("GET /api/v1/sso/providers", "POST /api/v1/sso/providers", "GET /api/v1/sso/providers/{id}",
	"PATCH /api/v1/sso/providers/{id}", "POST /api/v1/sso/providers/{id}/actions/refresh")

// asMap accepts both map shapes yaml.v3 produces (unquoted numeric keys such
// as 200: decode as ints, so their keys are rendered with fmt.Sprint).
func asMap(v any) map[string]any {
	switch m := v.(type) {
	case map[string]any:
		return m
	case map[any]any:
		out := make(map[string]any, len(m))
		for k, val := range m {
			out[fmt.Sprint(k)] = val
		}
		return out
	}
	return nil
}

// schemaProperties collects every property name reachable from schema.
func schemaProperties(schema any, schemas map[string]any, seen map[string]bool, out map[string]bool) {
	schemaPropertiesIn(schema, schemas, seen, out, "")
}

// schemaPropertiesIn also records each property as "name@parent" (parent: the property whose object holds it, "" at the
// top), so a rule can tell endpoints.token apart from a token field anywhere else.
func schemaPropertiesIn(schema any, schemas map[string]any, seen map[string]bool, out map[string]bool, parent string) {
	m := asMap(schema)
	if m == nil {
		return
	}
	if ref, ok := m["$ref"].(string); ok {
		name := path.Base(ref)
		if strings.Contains(ref, "/schemas/") && !seen[name] {
			seen[name] = true
			schemaPropertiesIn(schemas[name], schemas, seen, out, parent)
		}
		return
	}
	for name, prop := range asMap(m["properties"]) {
		out[name] = true
		out[name+"@"+parent] = true
		schemaPropertiesIn(prop, schemas, seen, out, name)
	}
	for _, key := range []string{"items", "additionalProperties"} {
		schemaPropertiesIn(m[key], schemas, seen, out, parent)
	}
	for _, key := range []string{"allOf", "oneOf", "anyOf"} {
		if list, ok := m[key].([]any); ok {
			for _, sub := range list {
				schemaPropertiesIn(sub, schemas, seen, out, parent)
			}
		}
	}
}

// responseFields maps "METHOD path" to the property names of its 2xx responses.
func responseFields(t *testing.T) map[string]map[string]bool {
	t.Helper()
	var doc map[string]any
	require.NoError(t, yaml.Unmarshal(apispec.YAML, &doc))
	components := asMap(doc["components"])
	schemas := asMap(components["schemas"])
	sharedResponses := asMap(components["responses"])
	out := map[string]map[string]bool{}
	for p, item := range asMap(doc["paths"]) {
		for method, op := range asMap(item) {
			hm := httpMethod(method)
			if hm == "" {
				continue
			}
			fields := map[string]bool{}
			for status, resp := range asMap(asMap(op)["responses"]) {
				if !strings.HasPrefix(status, "2") {
					continue
				}
				r := asMap(resp)
				if ref, ok := r["$ref"].(string); ok {
					r = asMap(sharedResponses[path.Base(ref)])
				}
				for _, media := range asMap(r["content"]) {
					schemaProperties(asMap(media)["schema"], schemas, map[string]bool{}, fields)
				}
			}
			out[hm+" "+p] = fields
		}
	}
	return out
}

func TestOpenAPIResponsesExposeNoSecretFields(t *testing.T) {
	fields := responseFields(t)
	require.True(t, fields["GET /api/v1/auth/session"]["csrf_token"], "the walker must see real response schemas")

	var ops []string
	for op := range fields {
		ops = append(ops, op)
	}
	sort.Strings(ops)
	for _, op := range ops {
		for _, f := range forbiddenResponseFields {
			assert.False(t, fields[op][f], "%s exposes %q in a response", op, f)
		}
		for f, allowed := range oneTimeFields {
			if fields[op][f] && (f != "token" || !identityProviderEndpointOps[op] || !onlyUnder(fields[op], "token", "endpoints")) {
				assert.True(t, allowed[op], "%s exposes the one-time field %q", op, f)
			}
		}
	}
	for f, allowed := range oneTimeFields {
		for op := range allowed {
			assert.True(t, fields[op][f], "%s should document %q in its response", op, f)
		}
	}
	for op := range identityProviderEndpointOps {
		assert.True(t, fields[op]["token@endpoints"], "%s documents the provider's endpoints", op)
	}
	assert.False(t, onlyUnder(map[string]bool{"token@endpoints": true, "token@": true}, "token", "endpoints"), "a top-level token is seen")
}

// onlyUnder reports whether every occurrence of the property name in fields has the given parent.
func onlyUnder(fields map[string]bool, name, parent string) bool {
	for k := range fields {
		if strings.HasPrefix(k, name+"@") && k != name+"@"+parent {
			return false
		}
	}
	return true
}
