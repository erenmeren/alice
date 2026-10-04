package api

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/inventory"
)

// Every allowlisted param has a value rule, whichever producer wrote the value: hostile values of
// the older keys are dropped too, well-formed ones pass.
func TestProviderParamsApplyValueRulesToEveryKey(t *testing.T) {
	good := map[string]string{
		"helper_code": "IO_ERROR", "subcommand": "nginx-deploy", "exit_code": "3", "reason": "protected_fingerprint",
		"field": "owner", "attempts": "5", "wait": "connection_slot", "fingerprint": "SHA256:" + strings.Repeat("A", 43),
		"old_fingerprint": strings.Repeat("a", 64), "new_fingerprint": "SHA256:x", "helper_protocol": "4", "required_protocol": "4",
		"port": "443", "failed_step": "verify", "profile": "nginx", "phase": "restored", "mode": "remote", "expected": "rsa",
		"actual": "ecdsa", "backup_dir": "/var/lib/alice-helper/backups/x", "directory": "/etc/nginx/ssl",
	}
	assert.Equal(t, good, providerParams(good))
	for k := range providerParamKeys {
		_, ok := providerParamRules[k]
		assert.True(t, ok, "%s has no value rule", k)
	}
	hostile := map[string]string{
		"helper_code": "io error", "subcommand": "nginx-deploy; rm -rf /", "exit_code": "3x", "reason": "<script>",
		"field": "a b", "attempts": "many", "wait": "Wait!", "fingerprint": "-----BEGIN " + "PRIVATE KEY-----",
		"old_fingerprint": "SHA256:a b", "new_fingerprint": strings.Repeat("z", 300), "helper_protocol": "four",
		"required_protocol": "", "reason2": "x",
	}
	assert.Nil(t, providerParams(hostile))
}

// A step's reason is shown only when it is a registered reason, never as a raw key.
func TestStepReasonMustBeRegistered(t *testing.T) {
	assert.Equal(t, map[string]string{"reason": "deployment.verify_failed"}, stepParams(map[string]string{"reason": "deployment.verify_failed"}))
	assert.Empty(t, stepParams(map[string]string{"reason": "deployment.made_up"}))
}

// countingBody records how many bytes a handler read.
type countingBody struct {
	r    io.Reader
	read int
}

func (c *countingBody) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.read += n
	return n, err
}

func (c *countingBody) Close() error { return nil }

// A body whose declared length is over the route's cap is refused with 413 before a byte is read.
func TestDeclaredOversizedBodyIsRefusedUnread(t *testing.T) {
	d, inv := inventoryDeps(t)
	inv.UploadCertificateFn = func(context.Context, inventory.Actor, inventory.UploadInput) (inventory.Certificate, []string, error) {
		t.Fatal("reached the service")
		return inventory.Certificate{}, nil, nil
	}
	h := NewHandler(d)
	for _, tc := range []struct {
		path string
		size int64
	}{
		{"/api/v1/certificates/upload", 768<<10 + 1},
		{"/api/v1/certificates/csr/" + csrID.String() + "/actions/complete", 384<<10 + 1},
		{"/api/v1/certificates/" + certID.String() + "/deploy", 8<<10 + 1},
		{"/api/v1/certificates/csr/" + csrID.String() + "/actions/cancel", 4<<10 + 1},
	} {
		body := &countingBody{r: strings.NewReader(`{"label":"` + strings.Repeat("A", int(tc.size)) + `"}`)}
		req := as(httptest.NewRequest(http.MethodPost, tc.path, nil), "admin")
		req.Body, req.ContentLength = body, tc.size
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusRequestEntityTooLarge, rec.Code, tc.path)
		assert.Zero(t, body.read, "%s: the body was read", tc.path)
	}
	// The cancel body may only be empty or {}: a 5 KiB padded {} is too large.
	rec := call(h, http.MethodPost, "/api/v1/certificates/csr/"+csrID.String()+"/actions/cancel", "admin", "{"+strings.Repeat(" ", 5<<10)+"}")
	assert.Equal(t, http.StatusRequestEntityTooLarge, rec.Code)
}

// Upload and completion bodies take their documented lower-case keys exactly once: another case or
// a repeated key is refused (encoding/json alone would accept both).
func TestSecretBodiesNeedExactUniqueKeys(t *testing.T) {
	d, inv := inventoryDeps(t)
	calls := 0
	inv.UploadCertificateFn = func(context.Context, inventory.Actor, inventory.UploadInput) (inventory.Certificate, []string, error) {
		calls++
		return sampleCertificate(), nil, nil
	}
	inv.CompleteCSRFn = func(context.Context, inventory.Actor, uuid.UUID, string, string) (inventory.Certificate, []string, error) {
		calls++
		return sampleCertificate(), nil, nil
	}
	h := NewHandler(d)
	complete := "/api/v1/certificates/csr/" + csrID.String() + "/actions/complete"
	for _, tc := range []struct{ path, body string }{
		{"/api/v1/certificates/upload", `{"Private_Key_PEM":"k","certificate_pem":"c"}`},
		{"/api/v1/certificates/upload", `{"private_key_pem":"k","private_key_pem":"k2","certificate_pem":"c"}`},
		{"/api/v1/certificates/upload", `{"LABEL":"x","pfx_base64":"AAAA"}`},
		{"/api/v1/certificates/upload", `["pfx_base64"]`},
		{complete, `{"Certificate_PEM":"c"}`},
		{complete, `{"certificate_pem":"c","label":"a","label":"b"}`},
	} {
		rec := call(h, http.MethodPost, tc.path, "admin", tc.body)
		assert.Equal(t, http.StatusBadRequest, rec.Code, tc.body)
	}
	assert.Zero(t, calls)
	require.Equal(t, http.StatusCreated, call(h, http.MethodPost, "/api/v1/certificates/upload", "admin", `{"label":"x","pfx_base64":"AAAA","pfx_password":"p"}`).Code)
	require.Equal(t, http.StatusCreated, call(h, http.MethodPost, complete, "admin", ` { "certificate_pem" : "c" } `).Code)
}
