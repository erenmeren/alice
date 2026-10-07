//go:build integration

package migrations_test

import (
	"context"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/testutil/pgtest"
	"alice/migrations"
)

func seedUser(t *testing.T, d *pgtest.DB, name, email string) uuid.UUID {
	t.Helper()
	id := uuid.Must(uuid.NewV7())
	require.NoError(t, exec(t, d.App, `INSERT INTO users (id, username, display_name, email, password_hash, role, created_at, updated_at)
VALUES ($1, $2::text, $2::text, $3, '$argon2id$x', 'admin', now(), now())`, id, name, email))
	return id
}

func seedProvider(t *testing.T, d *pgtest.DB, name string) uuid.UUID {
	t.Helper()
	id := uuid.Must(uuid.NewV7())
	require.NoError(t, exec(t, d.App, `INSERT INTO oidc_providers (id, name, issuer_url, client_id, scopes, groups_claim,
authorization_endpoint, token_endpoint, jwks_uri, enabled, created_at, updated_at)
VALUES ($1, $2, 'https://idp.example.com/realms/corp', 'alice', '{openid,email}', 'groups', 'https://idp.example.com/a',
'https://idp.example.com/t', 'https://idp.example.com/j', true, now(), now())`, id, name))
	return id
}

func TestAlertsLedgerIsUniqueAndAppendOnly(t *testing.T) {
	d := pgtest.New(t)
	obj := uuid.New()
	insert := func(threshold int) error {
		return exec(t, d.App, `INSERT INTO alerts (id, kind, object_id, subject, expires_at, threshold_days, license_locked, emailed, created_at)
VALUES ($1, 'certificate_expiry', $2, 'www.example.com', '2026-12-01T00:00:00Z', $3, false, true, now())`, uuid.New(), obj, threshold)
	}
	require.NoError(t, insert(30))
	assert.Equal(t, "23505", sqlState(insert(30)), "one notice per kind, object, expiry instant and threshold")
	require.NoError(t, insert(0))
	assert.Equal(t, "23514", sqlState(insert(366)))
	assert.Equal(t, "23514", sqlState(exec(t, d.App, `INSERT INTO alerts (id, kind, object_id, subject, expires_at, threshold_days,
license_locked, emailed, created_at) VALUES ($1, 'license_expiry', $2, 'x', now(), 1, false, true, now())`, uuid.New(), obj)))
	assert.Equal(t, "42501", sqlState(exec(t, d.App, `UPDATE alerts SET emailed = false`)), "append-only for the application")
	assert.Equal(t, "42501", sqlState(exec(t, d.App, `DELETE FROM alerts`)))
}

func TestSettingSecretsHoldOnlyKnownKeys(t *testing.T) {
	d := pgtest.New(t)
	put := func(key string) error {
		return exec(t, d.App, `INSERT INTO setting_secrets (key, ciphertext, nonce, wrapped_dek, key_version, updated_at)
VALUES ($1, '\x01', decode(repeat('00', 12), 'hex'), '\x02', 1, now())`, key)
	}
	require.NoError(t, put("notify.smtp.password"))
	require.NoError(t, put("sso.provider."+uuid.NewString()+".client_secret"))
	for _, bad := range []string{"notify.smtp.user", "sso.provider.x.client_secret", "general", "NOTIFY.SMTP.PASSWORD"} {
		assert.Equal(t, "23514", sqlState(put(bad)), bad)
	}
}

func TestSSOUsersAreNeverLocal(t *testing.T) {
	d := pgtest.New(t)
	p := seedProvider(t, d, "Corp IdP")
	local := seedUser(t, d, "ada", "ada@example.com")
	ssoUser := func(name, sub string, password any, breakGlass bool, roleSource string) error {
		return exec(t, d.App, `INSERT INTO users (id, username, display_name, auth_source, password_hash, role, role_source, is_break_glass,
oidc_provider_id, oidc_issuer, oidc_subject, created_at, updated_at)
VALUES ($1, $2::text, $2::text, 'oidc', $3, 'operator', $6, $4, $5, 'https://idp.example.com/realms/corp', $7, now(), now())`,
			uuid.New(), name, password, breakGlass, p, roleSource, sub)
	}
	require.NoError(t, ssoUser("ada-sso", "sub-1", nil, false, "oidc_mapping"))
	assert.Equal(t, "23505", sqlState(ssoUser("other", "sub-1", nil, false, "oidc_mapping")), "one user per (issuer, subject)")
	assert.Equal(t, "23514", sqlState(ssoUser("pw", "sub-2", "$argon2id$x", false, "oidc_mapping")), "no password")
	assert.Equal(t, "23514", sqlState(ssoUser("bg", "sub-3", nil, true, "oidc_mapping")), "never break-glass")
	assert.Equal(t, "23514", sqlState(ssoUser("manual", "sub-4", nil, false, "manual")), "role from the mapping")
	assert.Equal(t, "23514", sqlState(exec(t, d.App, `UPDATE users SET oidc_issuer = 'https://idp.example.com/realms/corp',
oidc_subject = 'x', oidc_provider_id = $2 WHERE id = $1`, local, p)), "a local user has no SSO identity")
	assert.Equal(t, "23514", sqlState(exec(t, d.App, `INSERT INTO users (id, username, display_name, auth_source, role, role_source,
created_at, updated_at) VALUES ($1, 'half', 'half', 'oidc', 'auditor', 'oidc_mapping', now(), now())`, uuid.New())), "all three columns")
	assert.Equal(t, "23503", sqlState(exec(t, d.App, `DELETE FROM oidc_providers WHERE id = $1`, p)), "a provider with users stays")
}

func TestMappingsRefuseEmptyAndInvisibleGroups(t *testing.T) {
	d := pgtest.New(t)
	p := seedProvider(t, d, "Corp IdP")
	put := func(group, role string) error {
		return exec(t, d.App, `INSERT INTO oidc_group_mappings (id, provider_id, group_claim_value, role, created_at)
VALUES ($1, $2, $3, $4, now())`, uuid.New(), p, group, role)
	}
	require.NoError(t, put("ops", "operator"))
	assert.Equal(t, "23505", sqlState(put("ops", "auditor")))
	for _, bad := range []string{"", " ops", "ops ", "o\tps", "o\nps"} {
		assert.Equal(t, "23514", sqlState(put(bad, "auditor")), "%q", bad)
	}
	assert.Equal(t, "23514", sqlState(put("x", "owner")))
	require.NoError(t, exec(t, d.App, `DELETE FROM oidc_providers WHERE id = $1`, p), "mappings go with their provider")
}

func TestLoginStatesAreShortLivedAndSingleUse(t *testing.T) {
	d := pgtest.New(t)
	p := seedProvider(t, d, "Corp IdP")
	u := seedUser(t, d, "ada", "")
	put := func(purpose string, session []byte, user any, lifetime string) error {
		return exec(t, d.App, `INSERT INTO oidc_login_states (state_hash, provider_id, binding_hash, nonce, code_verifier, purpose,
session_hash, user_id, next_path, created_at, expires_at)
VALUES (decode(md5(random()::text) || md5(random()::text), 'hex'), $1, decode(repeat('ab', 32), 'hex'), repeat('n', 43),
repeat('v', 43), $2, $3, $4, '/', now(), now() + $5::interval)`, p, purpose, session, user, lifetime)
	}
	require.NoError(t, put("login", nil, nil, "10 minutes"))
	assert.Equal(t, "23514", sqlState(put("login", nil, nil, "11 minutes")))
	assert.Equal(t, "23514", sqlState(put("stepup", nil, nil, "5 minutes")), "a step-up names its session and user")
	require.NoError(t, put("stepup", make([]byte, 32), u, "5 minutes"))
	assert.Equal(t, "42501", sqlState(exec(t, d.App, `UPDATE oidc_login_states SET next_path = '/x'`)), "never changed")
	require.NoError(t, exec(t, d.App, `DELETE FROM oidc_login_states`))
}

func TestSavedViewsArePerUserAndPage(t *testing.T) {
	d := pgtest.New(t)
	u := seedUser(t, d, "ada", "")
	put := func(page, name string) error {
		return exec(t, d.App, `INSERT INTO saved_views (id, user_id, page, name, query, created_at) VALUES ($1, $2, $3, $4, '{}', now())`,
			uuid.New(), u, page, name)
	}
	require.NoError(t, put("certificates", "Expiring"))
	assert.Equal(t, "23505", sqlState(put("certificates", "EXPIRING")), "names are unique per user and page, ignoring case")
	require.NoError(t, put("ssh_keys", "Expiring"))
	assert.Equal(t, "23514", sqlState(put("targets", "x")))
	assert.Equal(t, "23514", sqlState(put("certificates", "")))
}

func TestMigration00011DownRefusesPhase7DataAndIsCleanWithout(t *testing.T) {
	d := pgtest.New(t)
	ctx := context.Background()
	p, err := goose.NewProvider(goose.DialectPostgres, stdlib.OpenDBFromPool(d.Owner), migrations.FS)
	require.NoError(t, err)
	_, err = p.DownTo(ctx, 10)
	require.NoError(t, err, "no Phase 7 data: the Down runs")
	for _, tbl := range []string{"alerts", "setting_secrets", "saved_views", "oidc_providers", "oidc_group_mappings", "oidc_login_states"} {
		assert.False(t, tableExists(t, d, tbl), tbl)
	}
	assert.Empty(t, grantProblems(t, d))
	_, err = p.Up(ctx)
	require.NoError(t, err)
	assert.Empty(t, grantProblems(t, d))
	seedProvider(t, d, "Corp IdP")
	_, err = p.DownTo(ctx, 10)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Z1015")
	assert.True(t, tableExists(t, d, "oidc_providers"), "nothing changed")
}

func TestAlertsSubjectLimitIsInCharacters(t *testing.T) {
	d := pgtest.New(t)
	insert := func(subject string) error {
		return exec(t, d.App, `INSERT INTO alerts (id, kind, object_id, subject, expires_at, threshold_days, license_locked, emailed, created_at)
VALUES ($1, 'kv_key_expiry', $2, $3, '2026-12-01T00:00:00Z', 7, false, true, now())`, uuid.New(), uuid.New(), subject)
	}
	require.NoError(t, insert(strings.Repeat("ç", 300)), "300 runes is the cap Task 8 truncates to (S-3)")
	assert.Equal(t, "23514", sqlState(insert(strings.Repeat("ç", 301))))
}

func TestOneProviderPerSubjectIdentity(t *testing.T) {
	d := pgtest.New(t)
	a := seedProvider(t, d, "Provider A")
	b := uuid.Must(uuid.NewV7())
	require.NoError(t, exec(t, d.App, `INSERT INTO oidc_providers (id, name, issuer_url, client_id, scopes, groups_claim,
authorization_endpoint, token_endpoint, jwks_uri, enabled, created_at, updated_at)
VALUES ($1, 'Provider B', 'https://idp.example.com/realms/corp', 'alice-2', '{openid}', 'groups', 'https://idp.example.com/a',
'https://idp.example.com/t', 'https://idp.example.com/j', true, now(), now())`, b))
	ssoUser := func(name string, provider uuid.UUID) error {
		return exec(t, d.App, `INSERT INTO users (id, username, display_name, auth_source, role, role_source,
oidc_provider_id, oidc_issuer, oidc_subject, created_at, updated_at)
VALUES ($1, $2::text, $2::text, 'oidc', 'auditor', 'oidc_mapping', $3, 'https://idp.example.com/realms/corp', 'same-sub', now(), now())`,
			uuid.New(), name, provider)
	}
	require.NoError(t, ssoUser("via-a", a))
	require.NoError(t, ssoUser("via-b", b), "the same subject under another provider is another user (S-8)")
	assert.Equal(t, "23505", sqlState(ssoUser("again-a", a)), "one user per (provider, subject)")
}
