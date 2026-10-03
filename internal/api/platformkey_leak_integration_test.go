//go:build integration

package api

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

	"alice/internal/i18n"
	"alice/internal/notify"
	"alice/internal/providers/linuxssh/linuxsshtest"
	"alice/internal/secrets"
	"alice/locales"
)

// platformSeed decrypts the stored platform key (test-only, with the stack's keyring) and checks
// it is the key Alice presents.
func (s *stack) platformSeed() ([]byte, []byte) {
	s.t.Helper()
	ctx := context.Background()
	var id uuid.UUID
	var env secrets.Envelope
	require.NoError(s.t, s.db.Owner.QueryRow(ctx,
		`SELECT id, ciphertext, nonce, wrapped_dek, key_version FROM credentials WHERE purpose = 'platform_ssh'`).
		Scan(&id, &env.Ciphertext, &env.Nonce, &env.WrappedDEK, &env.KeyVersion))
	pt, err := s.keyring.Open(secrets.Location{Table: "credentials", RowID: id.String(), Column: "ciphertext"}, env)
	require.NoError(s.t, err)
	seed := append([]byte(nil), pt.Bytes()...)
	pt.Zero()
	require.Len(s.t, seed, ed25519.SeedSize)
	pub, err := ssh.NewPublicKey(ed25519.NewKeyFromSeed(seed).Public())
	require.NoError(s.t, err)
	pk, err := s.inv.PlatformKey(ctx)
	require.NoError(s.t, err)
	require.Equal(s.t, pk.Fingerprint, ssh.FingerprintSHA256(pub), "the decrypted seed is Alice's platform key")
	return seed, env.Ciphertext
}

// platformDEK unwraps the data-encryption key of the stored platform key with the raw master key.
func (s *stack) platformDEK() []byte {
	s.t.Helper()
	var id uuid.UUID
	var env secrets.Envelope
	require.NoError(s.t, s.db.Owner.QueryRow(context.Background(),
		`SELECT id, wrapped_dek, key_version FROM credentials WHERE purpose = 'platform_ssh'`).Scan(&id, &env.WrappedDEK, &env.KeyVersion))
	return unwrapDEK(s.t, s.masterKey(), secrets.Location{Table: "credentials", RowID: id.String(), Column: "ciphertext"}, env)
}

// §25.2 with SSH keys (S-01..S-04): Alice's private key, in every spelling, never appears in logs,
// responses or any table other than as its envelope; hostile helper output is not echoed.
func TestPlatformKeyNeverLeaks(t *testing.T) {
	s, admin, adminAcct := installed(t)
	f := s.sshFixture()
	hostile := canary("hostile-helper")

	targetID, _ := s.addServer(admin, "web-01", f)
	s.runJobs()
	observed := withStatus(s.hostKeys(admin, targetID), "observed")
	require.Len(t, observed, 1)
	confirm := "/api/v1/targets/" + targetID + "/host-keys/" + observed[0]["id"].(string) + "/actions/confirm"
	requireError(t, admin.do(http.MethodPost, confirm, map[string]string{"fingerprint": "SHA256:" + strings.Repeat("B", 43)}), http.StatusConflict, "ALC-TGT-0003")
	requireStatus(t, admin.do(http.MethodPost, confirm, map[string]string{"fingerprint": observed[0]["fingerprint"].(string)}), http.StatusAccepted)
	s.runJobs()

	// A hostile or broken helper (SC-4): a refusal whose message and stderr carry a PEM marker and a canary.
	normal := f.emu.Handler()
	f.server.SetHandler(func(cmd string, stdin []byte) linuxsshtest.Response {
		if strings.Contains(cmd, " authkeys-list") {
			return linuxsshtest.Response{
				Exit:   4,
				Stdout: []byte(`{"ok":false,"code":"IO_ERROR","message":"` + hostile + ` -----BEGIN OPENSSH PRIVATE KEY-----"}`),
				Stderr: []byte("-----BEGIN OPENSSH PRIVATE KEY-----\n" + hostile + "\n-----END OPENSSH PRIVATE KEY-----\n"),
			}
		}
		return normal(cmd, stdin)
	})
	rec := admin.do(http.MethodPost, "/api/v1/targets/"+targetID+"/actions/discover", nil)
	requireStatus(t, rec, http.StatusAccepted)
	failedJob := decodeBody[map[string]string](t, rec)["job_id"]
	s.runJobs()
	assert.NotEqual(t, "succeeded", s.job(admin, failedJob)["status"])
	f.server.SetHandler(normal)
	requireStatus(t, admin.do(http.MethodPost, "/api/v1/targets/"+targetID+"/actions/discover", nil), http.StatusAccepted)
	s.runJobs()

	// Own-key refusal and a real removal.
	locs := s.targetLocations(admin, targetID, false)
	own := locationOf(t, locs, "alice-svc", f.platformFP)
	requireError(t, admin.do(http.MethodPost, "/api/v1/ssh-keys/locations/"+own["id"].(string)+"/actions/remove", nil), http.StatusConflict, "ALC-KEY-0001")
	laptop := locationOf(t, locs, "deploy", f.laptop.fp)
	requireStatus(t, admin.do(http.MethodPost, "/api/v1/ssh-keys/locations/"+laptop["id"].(string)+"/actions/remove", nil), http.StatusAccepted)
	s.runJobs()

	// Phase 3 emails (C-10): a changed host key on this server and a refused sign-in on a second one,
	// for an administrator with an address. Their rendered bodies are scanned below.
	s.stepUp(admin, adminAcct)
	requireStatus(t, admin.do(http.MethodPatch, "/api/v1/users/"+adminAcct.id, map[string]string{"email": "ada@example.com"}), http.StatusOK)
	f2 := s.sshFixture()
	target2, _ := s.addServer(admin, "web-02", f2)
	s.pinServer(admin, target2)
	f2.server.DisablePublicKeyAuth()
	requireStatus(t, admin.do(http.MethodPost, "/api/v1/targets/"+target2+"/actions/test", nil), http.StatusAccepted)
	s.runJobs()
	require.Equal(t, "auth_failed", s.target(admin, target2)["status"])
	f.server.SetHostKey(linuxsshtest.NewHostKey(t))
	requireStatus(t, admin.do(http.MethodPost, "/api/v1/targets/"+targetID+"/actions/test", nil), http.StatusAccepted)
	s.runJobs()
	require.Equal(t, "host_key_changed", s.target(admin, targetID)["status"])

	// Every read that returns Phase 3 data, so its response is scanned too.
	rec = admin.do(http.MethodGet, "/api/v1/ssh-keys/platform-key", nil)
	requireStatus(t, rec, http.StatusOK)
	pk, err := s.inv.PlatformKey(context.Background())
	require.NoError(t, err)
	require.Contains(t, rec.Body.String(), strings.Fields(pk.PublicKey)[1], "the scan sees the real platform-key response")
	for _, path := range []string{"/api/v1/targets", "/api/v1/targets/" + targetID, "/api/v1/targets/" + targetID + "/host-keys",
		"/api/v1/targets/" + targetID + "/ssh-keys?missing=true", "/api/v1/ssh-keys", "/api/v1/ssh-keys/" + laptop["ssh_key_id"].(string),
		"/api/v1/jobs", "/api/v1/jobs/" + failedJob, "/api/v1/providers", "/api/v1/audit", "/api/v1/audit/export?format=json"} {
		requireStatus(t, admin.do(http.MethodGet, path, nil), http.StatusOK)
	}

	seed, ciphertext := s.platformSeed()
	priv := ed25519.NewKeyFromSeed(seed)
	block, err := ssh.MarshalPrivateKey(priv, "")
	require.NoError(t, err)
	pemText := string(pem.EncodeToMemory(block))
	pkcs8, err := x509.MarshalPKCS8PrivateKey(priv)
	require.NoError(t, err)
	secs := []secretValue{
		{name: "platform key seed", forms: binaryForms(seed)},
		{name: "platform private key", forms: binaryForms(priv)},
		{name: "platform key (OpenSSH PEM)", forms: []string{pemText, base64.StdEncoding.EncodeToString(block.Bytes)}},
		{name: "platform key (PKCS#8)", forms: append(binaryForms(pkcs8),
			string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})))},
		{name: "hostile helper output", value: hostile},
		s.masterKeySecret(),
		{name: "platform key DEK", forms: binaryForms(s.platformDEK())},
	}
	for _, label := range []string{secrets.LabelHWM, secrets.LabelHWMEnc, secrets.LabelJob, secrets.LabelAuditHMAC,
		secrets.LabelCSRF, secrets.LabelInstallation} {
		secs = append(secs, secretValue{name: "keyring key " + label, forms: binaryForms(s.keyring.Derive(label))})
	}
	sessionIDs := f.server.SessionIDs()
	require.NotEmpty(t, sessionIDs, "Alice opened SSH sessions to the server")
	for i, id := range sessionIDs {
		secs = append(secs, secretValue{name: fmt.Sprintf("SSH session %d identifier", i), forms: binaryForms(id)})
	}

	logs := s.logs.String()
	assertNoSecret(t, "logs", logs, secs)
	for _, m := range privateKeyMarkers {
		assert.NotContains(t, logs, m, "logs")
	}
	for _, ex := range s.recorded() {
		text := string(ex.body) + fmt.Sprint(ex.header)
		assertNoSecret(t, "response "+ex.key(), text, secs)
		for _, m := range privateKeyMarkers {
			assert.NotContains(t, text, m, "response %s", ex.key())
		}
	}
	dump := s.dump()
	assertNoSecret(t, "database", dump, secs)
	for _, m := range privateKeyMarkers {
		assert.NotContains(t, dump, m, "database")
	}

	// The emails as the sender renders them (the outbox stores only template keys and parameters).
	catalog, err := i18n.Load(locales.FS)
	require.NoError(t, err)
	sender := notify.Sender{Catalog: catalog}
	rows, err := s.db.Owner.Query(context.Background(), `SELECT to_address, template_key, locale, params FROM notifications_outbox`)
	require.NoError(t, err)
	templates := map[string]bool{}
	for rows.Next() {
		var to, tpl, locale string
		var params map[string]string
		require.NoError(t, rows.Scan(&to, &tpl, &locale, &params))
		templates[tpl] = true
		msg := sender.Render(to, tpl, locale, params)
		text := msg.Subject + "\n" + msg.Body
		assertNoSecret(t, "email "+tpl, text, secs)
		for _, m := range privateKeyMarkers {
			assert.NotContains(t, text, m, "email %s", tpl)
		}
	}
	require.NoError(t, rows.Err())
	assert.True(t, templates["target.host_key_changed"], "the scan saw the host-key email")
	assert.True(t, templates["target.auth_failed"], "the scan saw the refused sign-in email")

	// S-04: the stored key is ciphertext with its own DEK; another installation's differs.
	assert.False(t, bytes.Contains(ciphertext, seed), "the seed is not stored in clear")
	other := newStack(t)
	otherSeed, otherCiphertext := other.platformSeed()
	assert.NotEqual(t, seed, otherSeed, "every installation generates its own key")
	assert.NotEqual(t, ciphertext, otherCiphertext)
}
