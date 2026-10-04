package api

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/inventory"
	"alice/internal/license"
	"alice/internal/platform/logging"
	"alice/internal/platform/validate"
)

// secretInput is a private key and a PFX password as a client sends them, with every form a leak
// could take: the key's base64 body and its hex, the password as text, hex and base64.
type secretInput struct {
	keyPEM, password string
	markers          []string
}

func newSecretInput(t *testing.T) secretInput {
	t.Helper()
	raw := make([]byte, 48)
	_, err := rand.Read(raw)
	require.NoError(t, err)
	body := base64.StdEncoding.EncodeToString(raw)
	pw := "pw-" + hex.EncodeToString(raw[:6])
	keyPEM := "-----BEGIN " + "PRIVATE KEY-----\n" + body + "\n-----END " + "PRIVATE KEY-----\n"
	return secretInput{keyPEM: keyPEM, password: pw, markers: []string{
		body, body[:24], hex.EncodeToString(raw), base64.StdEncoding.EncodeToString([]byte(keyPEM)),
		pw, hex.EncodeToString([]byte(pw)), base64.StdEncoding.EncodeToString([]byte(pw)),
	}}
}

func jsonString(s string) string {
	return strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`).Replace(s)
}

// Neither an upload nor a signing request's completion ever shows the private key or the PFX
// password it was sent: not in the answer (success or any refusal), its headers, the logs or the
// audit events the API writes. The fake service even returns errors whose text quotes the
// secrets, as a careless service might: fail never prints error text.
func TestUploadAndCompletionNeverEchoTheirSecrets(t *testing.T) {
	sec := newSecretInput(t)
	leakyErr := fmt.Errorf("parse %s with %s: %w", sec.keyPEM, sec.password, inventory.ErrCertificateInvalid)
	unknownErr := fmt.Errorf("db failed on %s / %s", sec.keyPEM, sec.password)
	answers := []error{nil, leakyErr, unknownErr,
		validate.Errors{{Field: "private_key_pem", Code: validate.Required}},
		inventory.ErrKeyMismatch, inventory.ErrCertificateExpired, inventory.ErrKeyEncrypted, inventory.ErrPFXPassword,
		inventory.ErrWeakCertificate, inventory.ErrUnsupportedKey, inventory.ErrCertificateDuplicate, inventory.ErrPFXBusy,
		inventory.ErrCertificateTooLarge, inventory.ErrCSRMismatch, inventory.ErrCSRNotPending, inventory.ErrNotFound, license.ErrLocked,
	}
	uploadBodies := []string{
		`{"certificate_pem":"-----BEGIN CERTIFICATE-----\nAA\n-----END CERTIFICATE-----\n","private_key_pem":"` + jsonString(sec.keyPEM) + `"}`,
		`{"pfx_base64":"` + base64.StdEncoding.EncodeToString([]byte(sec.keyPEM)) + `","pfx_password":"` + sec.password + `"}`,
		// A key pasted into the certificate field (the service refuses it as a field error).
		`{"certificate_pem":"` + jsonString(sec.keyPEM) + `","private_key_pem":"` + jsonString(sec.keyPEM) + `"}`,
	}
	completion := `{"certificate_pem":"` + jsonString(sec.keyPEM) + `","label":"` + sec.password + `"}`
	// Malformed and refused requests: an unknown field holding the key, broken JSON, an oversized
	// body, a forbidden role, no session, the license lock.
	broken := []string{
		`{"private_key_pem":"` + jsonString(sec.keyPEM) + `","pfx_password":"` + sec.password + `","extra":"` + sec.password + `"}`,
		`{"private_key_pem":"` + jsonString(sec.keyPEM) + `","pfx_password":"` + sec.password,
		`{"pfx_password":"` + sec.password + `","pfx_base64":"` + strings.Repeat("A", maxUploadBody) + `"}`,
	}

	var logs bytes.Buffer
	d, inv := inventoryDeps(t)
	d.Log = logging.New(&logs, slog.LevelDebug)
	var answer error
	inv.UploadCertificateFn = func(context.Context, inventory.Actor, inventory.UploadInput) (inventory.Certificate, []string, error) {
		if answer != nil {
			return inventory.Certificate{}, nil, answer
		}
		return sampleCertificate(), []string{"chain_incomplete"}, nil
	}
	inv.CompleteCSRFn = func(context.Context, inventory.Actor, uuid.UUID, string, string) (inventory.Certificate, []string, error) {
		if answer != nil {
			return inventory.Certificate{}, nil, answer
		}
		return sampleCertificate(), nil, nil
	}
	h := NewHandler(d)
	completePath := "/api/v1/certificates/csr/" + csrID.String() + "/actions/complete"

	var seen []string
	check := func(name string, rec interface {
		Header() http.Header
	}, body string) {
		t.Helper()
		var hdr strings.Builder
		for k, vs := range rec.Header() {
			hdr.WriteString(k + ": " + strings.Join(vs, ",") + "\n")
		}
		for _, m := range sec.markers {
			assert.NotContains(t, body, m, "%s: answer", name)
			assert.NotContains(t, hdr.String(), m, "%s: headers", name)
		}
		seen = append(seen, name)
	}
	for _, err := range answers {
		answer = err
		for i, b := range uploadBodies {
			rec := call(h, http.MethodPost, "/api/v1/certificates/upload", "operator", b)
			check(fmt.Sprintf("upload %d answer %v", i, err), rec, rec.Body.String())
		}
		rec := call(h, http.MethodPost, completePath, "operator", completion)
		check(fmt.Sprintf("completion answer %v", err), rec, rec.Body.String())
	}
	answer = nil
	for _, path := range []string{"/api/v1/certificates/upload", completePath} {
		for i, b := range broken {
			rec := call(h, http.MethodPost, path, "operator", b)
			assert.Contains(t, []int{http.StatusBadRequest, http.StatusRequestEntityTooLarge}, rec.Code)
			check(fmt.Sprintf("%s broken %d", path, i), rec, rec.Body.String())
		}
		for _, id := range []string{"auditor", "", "alice_read_admin"} {
			rec := call(h, http.MethodPost, path, id, uploadBodies[1])
			assert.Contains(t, []int{http.StatusUnauthorized, http.StatusForbidden}, rec.Code)
			check(path+" as "+id, rec, rec.Body.String())
		}
	}
	d.License.(*fakeLicense).set(license.ErrLocked)
	for _, path := range []string{"/api/v1/certificates/upload", completePath} {
		rec := call(h, http.MethodPost, path, "operator", uploadBodies[1])
		assert.Equal(t, http.StatusForbidden, rec.Code)
		check(path+" in lock", rec, rec.Body.String())
	}

	require.Greater(t, len(seen), 60, "every case ran")
	assert.Contains(t, logs.String(), `"msg":"request failed"`, "the unknown error was logged (as its type only)")
	for _, m := range sec.markers {
		assert.NotContains(t, logs.String(), m, "logs")
	}
	events := d.Audit.(*fakeAudit).Events()
	assert.NotEmpty(t, events, "denials were audited")
	for _, e := range events {
		dump := fmt.Sprintf("%+v", e)
		for _, m := range sec.markers {
			assert.NotContains(t, dump, m, "audit %s", e.Action)
		}
	}
}
