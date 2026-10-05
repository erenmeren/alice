package api

import (
	"context"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/inventory"
	"alice/internal/providers"
)

// watch records every slice a secret field or a decoded PFX was copied into (onSecretBytes).
type watch struct {
	mu     sync.Mutex
	slices [][]byte
}

func watchSecrets(t *testing.T) *watch {
	t.Helper()
	w := &watch{}
	onSecretBytes = func(b []byte) {
		w.mu.Lock()
		defer w.mu.Unlock()
		w.slices = append(w.slices, b)
	}
	t.Cleanup(func() { onSecretBytes = nil })
	return w
}

// requireZeroed fails when a recorded slice still holds a byte; it also demands that something was recorded.
func (w *watch) requireZeroed(t *testing.T, name string, want int) {
	t.Helper()
	w.mu.Lock()
	defer w.mu.Unlock()
	require.Len(t, w.slices, want, "%s: the secret slices seen", name)
	for i, b := range w.slices {
		assert.Equal(t, make([]byte, len(b)), b, "%s: secret slice %d is not zeroed", name, i)
	}
	w.slices = nil
}

// observedBody hands out the body and keeps every slice it was asked to fill: those alias the buffer
// decodeExact reads the body into, which must be zero when the handler is done.
type observedBody struct {
	r      io.Reader
	filled [][]byte
}

func (o *observedBody) Read(p []byte) (int, error) {
	n, err := o.r.Read(p)
	o.filled = append(o.filled, p)
	return n, err
}

func callObserved(h http.Handler, method, target, id, body string, hdr map[string]string) (*httptest.ResponseRecorder, *observedBody) {
	o := &observedBody{r: strings.NewReader(body)}
	req := httptest.NewRequest(method, target, o)
	req.ContentLength = int64(len(body))
	req.Header.Set("Content-Type", "application/json")
	req = as(req, id)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec, o
}

func (o *observedBody) requireZeroed(t *testing.T, name string) {
	t.Helper()
	require.NotEmpty(t, o.filled, name)
	for _, p := range o.filled {
		assert.Equal(t, make([]byte, len(p)), p, "%s: the body buffer still holds the request", name)
	}
}

// Every path of the routes that carry secrets leaves the handler's copies and the body buffer zeroed: success, a
// refusal of the inventory, a validation error before inventory was called, a body that does not decode.
func TestRequestSecretsAreZeroedOnEveryPath(t *testing.T) {
	h, inv, _ := vaultDeps(t)
	w := watchSecrets(t)
	okCreate := func(context.Context, inventory.Actor, inventory.NewVault) (inventory.Target, providers.ConnectionReport, uuid.UUID, error) {
		return sampleVault(), providers.ConnectionReport{}, jobID, nil
	}
	refuseCreate := func(context.Context, inventory.Actor, inventory.NewVault) (inventory.Target, providers.ConnectionReport, uuid.UUID, error) {
		return inventory.Target{}, providers.ConnectionReport{}, uuid.Nil, inventory.ErrDuplicateTarget
	}
	pfx := base64.StdEncoding.EncodeToString([]byte("pfx-bytes"))
	secretBody := `"client_secret":"fake-0123456789abcdef"`
	pfxBody := `"pfx_base64":"` + pfx + `","pfx_password":"pw-1"`
	keyBody := `"certificate_pem":"cert\n","private_key_pem":"line1\nline2\n"`
	common := `"name":"v","auth":"certificate","tenant_id":"` + vaultTenant + `","client_id":"` + vaultClient + `",`
	create := "/api/v1/key-vaults"
	creds := "/api/v1/targets/" + vaultID.String() + "/vault-credentials"
	type tc struct {
		name, path, method, body string
		fn                       func()
		hdr                      map[string]string
		slices                   int // what the handler copied: secret fields, plus the decoded PFX
	}
	setCreate := func(f func(context.Context, inventory.Actor, inventory.NewVault) (inventory.Target, providers.ConnectionReport, uuid.UUID, error)) func() {
		return func() { inv.CreateVaultFn = f }
	}
	setReplace := func(err error) func() {
		return func() {
			inv.ReplaceVaultCredentialsFn = func(context.Context, inventory.Actor, uuid.UUID, int, inventory.VaultCredentialInput) (inventory.Target, providers.ConnectionReport, uuid.UUID, error) {
				if err != nil {
					return inventory.Target{}, providers.ConnectionReport{}, uuid.Nil, err
				}
				return sampleVault(), providers.ConnectionReport{}, jobID, nil
			}
		}
	}
	ifm := map[string]string{"If-Match": `"3"`}
	cases := []tc{
		{"create secret ok", create, http.MethodPost, `{` + common + secretBody + `,"vault_url":"contoso"}`, setCreate(okCreate), nil, 1},
		{"create secret refused by inventory", create, http.MethodPost, `{` + common + secretBody + `,"vault_url":"contoso"}`, setCreate(refuseCreate), nil, 1},
		{"create secret, bad vault_url (422 before inventory)", create, http.MethodPost, `{` + common + secretBody + `,"vault_url":"http://x"}`, setCreate(okCreate), nil, 1},
		{"create secret, bad tenant (422 before inventory)", create, http.MethodPost, `{"name":"v","auth":"client_secret","tenant_id":"x","client_id":"` + vaultClient + `",` + secretBody + `,"vault_url":"contoso"}`, setCreate(okCreate), nil, 1},
		{"create key PEM ok", create, http.MethodPost, `{` + common + keyBody + `,"vault_url":"contoso"}`, setCreate(okCreate), nil, 2},
		{"create key PEM, bad vault_url", create, http.MethodPost, `{` + common + keyBody + `,"vault_url":"http://x"}`, setCreate(okCreate), nil, 2},
		{"create PFX ok", create, http.MethodPost, `{` + common + pfxBody + `,"vault_url":"contoso"}`, setCreate(okCreate), nil, 3},
		{"create PFX refused by inventory", create, http.MethodPost, `{` + common + pfxBody + `,"vault_url":"contoso"}`, setCreate(refuseCreate), nil, 3},
		{"create PFX, bad vault_url", create, http.MethodPost, `{` + common + pfxBody + `,"vault_url":"http://x"}`, setCreate(okCreate), nil, 3},
		{"create PFX that is not base64", create, http.MethodPost, `{` + common + `"pfx_base64":"***","pfx_password":"pw-1","vault_url":"contoso"}`, setCreate(okCreate), nil, 2},
		{"create body with an unknown key after the secret", create, http.MethodPost, `{` + common + secretBody + `,"extra":1}`, setCreate(okCreate), nil, 0},
		{"replace secret ok", creds, http.MethodPut, `{` + strings.Replace(common, `"name":"v",`, "", 1) + secretBody + `}`, setReplace(nil), ifm, 1},
		{"replace secret refused", creds, http.MethodPut, `{` + strings.Replace(common, `"name":"v",`, "", 1) + secretBody + `}`, setReplace(inventory.ErrVersionMismatch), ifm, 1},
		{"replace PFX, bad tenant", creds, http.MethodPut, `{"auth":"certificate","tenant_id":"x","client_id":"` + vaultClient + `",` + pfxBody + `}`, setReplace(nil), ifm, 3},
		{"replace key PEM ok", creds, http.MethodPut, `{` + strings.Replace(common, `"name":"v",`, "", 1) + keyBody + `}`, setReplace(nil), ifm, 2},
	}
	for _, c := range cases {
		c.fn()
		rec, body := callObserved(h, c.method, c.path, "admin-stepup", c.body, c.hdr)
		assert.NotEqual(t, http.StatusInternalServerError, rec.Code, c.name)
		w.requireZeroed(t, c.name, c.slices)
		body.requireZeroed(t, c.name)
	}
	// The import route carries no secret, but its body buffer is cleared like the others'.
	inv.RequestImportFn = func(context.Context, inventory.Actor, inventory.ImportInput) (inventory.KVImport, error) {
		return sampleImport(inventory.ImportQueued, ""), nil
	}
	rec, body := callObserved(h, http.MethodPost, "/api/v1/certificates/"+csrID.String()+"/actions/import-to-key-vault", "admin-stepup",
		`{"target_id":"`+vaultID.String()+`","name":"web-cert"}`, nil)
	require.Equal(t, http.StatusAccepted, rec.Code)
	body.requireZeroed(t, "import")
}
