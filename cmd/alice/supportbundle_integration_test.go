//go:build integration

package main

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/audit"
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
	assert.Contains(t, b["jobs"], "failed_24h")
	assert.Contains(t, b["backup"], "failing")
	assert.Contains(t, b["forwarding"], "backlog")

	canaries := map[string][]byte{"smtp password": []byte(smtpPassword), "oidc secret": []byte(oidcSecret), "master key": master,
		"passphrase": []byte(cliPassphrase), "sender key": sender, "database password": []byte(pgtest.AppPassword)}
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
