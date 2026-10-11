//go:build integration

package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/audit"
	"alice/internal/auth"
	"alice/internal/notify"
	"alice/internal/secrets"
	"alice/internal/testutil/pgtest"
	"alice/internal/testutil/seed"
)

// The support bundle holds C9's sections and none of the secrets a backup protects (the canaries of
// TestF87NoPlaintextInTheFile), no database password, no Installation ID and no host of a managed system.
func TestSupportBundleHasNoSecrets(t *testing.T) {
	i := newCLIInstall(t)
	i.listening()
	svc := i.services()
	smtpPassword := "smtp-canary-" + uuid.NewString()
	pw := secrets.NewPlaintext([]byte(smtpPassword))
	_, err := svc.notifySettings.SaveSMTP(i.ctx, audit.SystemActor("test"), 0, notify.SMTPInput{Host: "mail.example.com", Port: 587,
		TLSMode: notify.TLSModeSTARTTLS, From: "alice@example.com", Username: "alice", Password: &pw})
	require.NoError(t, err)
	oidcSecret := "oidc-canary-" + uuid.NewString()
	require.NoError(t, svc.keyring.PutSetting(i.ctx, i.d.App, "sso.provider."+uuid.NewString()+".client_secret",
		secrets.NewPlaintext([]byte(oidcSecret)), time.Now()))
	senderPT, ok, err := svc.keyring.GetSetting(i.ctx, i.d.App, "backup.sender")
	require.NoError(t, err)
	require.True(t, ok)
	sender := append([]byte(nil), senderPT.Bytes()...)
	masterRaw, err := os.ReadFile(filepath.Join(i.keys, secrets.MasterKeyFile))
	require.NoError(t, err)
	master, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(masterRaw)))
	require.NoError(t, err)
	_, err = seed.Target(i.ctx, i.d.Owner, "canary-target-7q", "linux", "ok", nil)
	require.NoError(t, err)
	ownerURL, err := url.Parse(i.d.OwnerURL)
	require.NoError(t, err)
	ownerPassword, ok := ownerURL.User.Password()
	require.True(t, ok, "the owner URL carries its password")
	// A live setup code and its wizard session (the cookie), then a user with a signed-in session and an API token,
	// stored as the services store them (SHA-256 of the secret).
	setupCode, err := svc.setup.ResetToken(i.ctx)
	require.NoError(t, err)
	wizardCookie, err := svc.setup.StartSession(i.ctx, setupCode, auth.Meta{IP: netip.MustParseAddr("192.0.2.7")})
	require.NoError(t, err)
	sessionCookie := "session-canary-" + uuid.NewString()
	apiToken := auth.TokenPrefix + "tokencanary" + strings.ReplaceAll(uuid.NewString(), "-", "")
	userID := uuid.Must(uuid.NewV7())
	now := time.Now().UTC()
	_, err = i.d.Owner.Exec(i.ctx, `INSERT INTO users (id, username, display_name, password_hash, role, created_at, updated_at)
VALUES ($1, 'canary-user', 'Canary User', 'not-a-real-hash', 'operator', $2, $2)`, userID, now)
	require.NoError(t, err)
	sessionHash := sha256.Sum256([]byte(sessionCookie))
	_, err = i.d.Owner.Exec(i.ctx, `INSERT INTO sessions (id_hash, user_id, kind, created_at, last_seen_at, expires_at, idle_expires_at)
VALUES ($1, $2, 'full', $3, $3, $4, $4)`, sessionHash[:], userID, now, now.Add(time.Hour))
	require.NoError(t, err)
	tokenHash := sha256.Sum256([]byte(apiToken))
	_, err = i.d.Owner.Exec(i.ctx, `INSERT INTO api_tokens (id, user_id, name, token_hash, token_prefix, scopes, expires_at, created_at)
VALUES ($1, $2, 'canary', $3, $4, '{read}', $5, $6)`, uuid.Must(uuid.NewV7()), userID, tokenHash[:], apiToken[:12], now.Add(time.Hour), now)
	require.NoError(t, err)
	setupHash := sha256.Sum256([]byte(setupCode))
	wizardHash := sha256.Sum256([]byte(wizardCookie))
	stop := i.serve()
	defer stop()

	code, out, errOut := i.run("", "support-bundle")
	require.Equal(t, 0, code, errOut)
	var b map[string]any
	require.NoError(t, json.Unmarshal([]byte(out), &b), out)
	for _, k := range []string{"version", "config", "selfcheck", "schema_version", "tables", "license", "jobs", "backup", "forwarding"} {
		assert.Contains(t, b, k)
	}
	assert.NotContains(t, b, "errors", out)
	assert.Len(t, b["selfcheck"], 7)
	assert.Equal(t, "evaluation", b["license"].(map[string]any)["phase"])
	assert.EqualValues(t, 1, b["tables"].(map[string]any)["targets"])
	assert.EqualValues(t, 1, b["tables"].(map[string]any)["api_tokens"], "the canary rows are in the database the bundle reads")
	assert.Contains(t, b["jobs"], "failed_24h")
	assert.Contains(t, b["backup"], "failing")
	assert.Contains(t, b["forwarding"], "backlog")

	canaries := map[string][]byte{"smtp password": []byte(smtpPassword), "oidc secret": []byte(oidcSecret), "master key": master,
		"passphrase": []byte(cliPassphrase), "sender key": sender, "app database password": []byte(pgtest.AppPassword),
		"owner database password": []byte(ownerPassword), "setup code": []byte(setupCode), "setup code hash": setupHash[:],
		"wizard session cookie": []byte(wizardCookie), "wizard session hash": wizardHash[:], "session cookie": []byte(sessionCookie),
		"session hash": sessionHash[:], "api token": []byte(apiToken), "api token hash": tokenHash[:]}
	for name, c := range canaries {
		for form, enc := range map[string]string{"raw": string(c), "base64": base64.StdEncoding.EncodeToString(c),
			"base64url": base64.RawURLEncoding.EncodeToString(c), "hex": hex.EncodeToString(c)} {
			assert.NotContains(t, out, enc, "%s (%s) in the support bundle", name, form)
		}
	}
	assert.NotContains(t, out, i.installationID)
	assert.NotContains(t, out, strings.TrimPrefix(i.installationID, "ALICE-"))
	assert.NotContains(t, out, "canary-target-7q")
	assert.NotContains(t, out, "ustomer", "no customer name or field")
	assert.NotContains(t, out, "-----BEGIN")
}
