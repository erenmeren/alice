package azurekv

import (
	"context"
	"strings"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/providers"
	"alice/internal/testutil/fakekv"
)

func (w *world) read(ctx context.Context, req providers.SecretRequest) (sec providers.CertificateSecret, err error) {
	err = w.run(func() error {
		var e error
		sec, e = w.sess.ReadCertificateSecret(ctx, req)
		return e
	})
	return sec, err
}

func TestReadCertificateSecretOfAVersion(t *testing.T) {
	w := newWorld(t, fakekv.Options{})
	ver := w.s.AddCertificate("web-cert", fakekv.CertOptions{CommonName: "www.example.test", Exportable: true})
	sec, err := w.read(context.Background(), providers.SecretRequest{Name: "web-cert", Version: ver})
	require.NoError(t, err)
	defer sec.Value.Zero()
	assert.Equal(t, "application/x-pkcs12", sec.ContentType)
	assert.Equal(t, string(w.s.SecretValue("web-cert", ver)), string(sec.Value.Bytes()))
	var paths []string
	for _, r := range w.vaultRequests() {
		if r.HadAuth {
			paths = append(paths, r.Path)
		}
	}
	assert.Equal(t, []string{"/secrets/web-cert/" + ver}, paths, "the exact version, never latest (§11.5 item 2)")

	pem := w.s.AddCertificate("pem-cert", fakekv.CertOptions{CommonName: "p.example.test", Exportable: true, ContentType: "application/x-pem-file"})
	sec2, err := w.read(context.Background(), providers.SecretRequest{Name: "pem-cert", Version: pem})
	require.NoError(t, err)
	defer sec2.Value.Zero()
	assert.Equal(t, "application/x-pem-file", sec2.ContentType)

	// The holder is the caller's: zeroing it does not touch a later read.
	sec.Value.Zero()
	again, err := w.read(context.Background(), providers.SecretRequest{Name: "web-cert", Version: ver})
	require.NoError(t, err)
	defer again.Value.Zero()
	assert.Equal(t, string(w.s.SecretValue("web-cert", ver)), string(again.Value.Bytes()))
}

// A non-exportable certificate's secret answers 200 with the certificates and no private key
// (documented behaviour; the exact container is a guess). The provider hands the value over: the
// caller detects the missing key when it decodes it (certs.ParseKVSecret), the provider never parses.
func TestReadCertificateSecretOfANonExportableCertificate(t *testing.T) {
	w := newWorld(t, fakekv.Options{})
	ver := w.s.AddCertificate("monitor-only", fakekv.CertOptions{CommonName: "m.example.test"})
	sec, err := w.read(context.Background(), providers.SecretRequest{Name: "monitor-only", Version: ver})
	require.NoError(t, err)
	defer sec.Value.Zero()
	assert.Equal(t, string(w.s.SecretValue("monitor-only", ver)), string(sec.Value.Bytes()))
}

func TestReadCertificateSecretRefusals(t *testing.T) {
	good := strings.Repeat("a", 32)
	t.Run("invalid input is refused before anything is sent", func(t *testing.T) {
		w := newWorld(t, fakekv.Options{})
		for _, req := range []providers.SecretRequest{
			{}, {Name: "web-cert"}, {Version: good}, {Name: "web-cert", Version: "latest"}, {Name: "web-cert", Version: strings.Repeat("A", 32)},
			{Name: "web-cert", Version: good[:31]}, {Name: "bad name", Version: good}, {Name: "a/b", Version: good}, {Name: strings.Repeat("a", 128), Version: good},
			{Name: "web-cert", Version: good + "/../x"},
		} {
			_, err := w.sess.ReadCertificateSecret(context.Background(), req)
			pe := asProviderError(t, err)
			assert.Equal(t, codeVersionNotDeployable, pe.Code, "%+v", req)
			assert.False(t, pe.Retryable)
		}
		assert.Empty(t, w.s.Requests(), "nothing was sent, not even a token request")
	})
	t.Run("a cancelled context comes first (D8)", func(t *testing.T) {
		w := newWorld(t, fakekv.Options{})
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		for _, req := range []providers.SecretRequest{{}, {Name: "web-cert", Version: good}} {
			_, err := w.sess.ReadCertificateSecret(ctx, req)
			assert.ErrorIs(t, err, context.Canceled)
			_ = asProviderError(t, err)
		}
		assert.Empty(t, w.s.Requests())
	})
	t.Run("F-41: the secrets role is missing", func(t *testing.T) {
		w := newWorld(t, fakekv.Options{})
		ver := w.s.AddCertificate("web-cert", fakekv.CertOptions{CommonName: "www.example.test", Exportable: true})
		w.s.SetRoles(fakekv.RoleReader)
		_, err := w.read(context.Background(), providers.SecretRequest{Name: "web-cert", Version: ver})
		pe := asProviderError(t, err)
		assert.Equal(t, codeForbidden, pe.Code)
		assert.Equal(t, providers.RoleKeyVaultSecretsUser, pe.Params["role"])
	})
	t.Run("a disabled version", func(t *testing.T) {
		w := newWorld(t, fakekv.Options{})
		ver := w.s.AddCertificate("web-cert", fakekv.CertOptions{CommonName: "www.example.test", Exportable: true})
		w.s.DisableVersion("web-cert", ver)
		_, err := w.read(context.Background(), providers.SecretRequest{Name: "web-cert", Version: ver})
		assert.Equal(t, codeVersionDisabled, asProviderError(t, err).Code)
	})
	t.Run("a deleted certificate and an unknown version", func(t *testing.T) {
		w := newWorld(t, fakekv.Options{})
		ver := w.s.AddCertificate("web-cert", fakekv.CertOptions{CommonName: "www.example.test", Exportable: true})
		_, err := w.read(context.Background(), providers.SecretRequest{Name: "web-cert", Version: good})
		assert.Equal(t, codeCertificateNotFound, asProviderError(t, err).Code)
		w.s.DeleteCertificate("web-cert")
		_, err = w.read(context.Background(), providers.SecretRequest{Name: "web-cert", Version: ver})
		assert.Equal(t, codeCertificateNotFound, asProviderError(t, err).Code)
	})
	t.Run("a vault under pressure is asked twice, within the minute (S3)", func(t *testing.T) {
		w := newWorld(t, fakekv.Options{})
		ver := w.s.AddCertificate("web-cert", fakekv.CertOptions{CommonName: "www.example.test", Exportable: true})
		w.s.FailAll("/secrets/", fakekv.Fault{Status: 503})
		w.s.ClearRequests()
		_, err := w.read(context.Background(), providers.SecretRequest{Name: "web-cert", Version: ver})
		assert.Equal(t, codeUnreachable, asProviderError(t, err).Code)
		assert.Equal(t, 2, w.authed())
	})
}

// What a vault answers that the real fake cannot be made to say.
func TestReadCertificateSecretUnusableAnswers(t *testing.T) {
	ver := strings.Repeat("b", 32)
	secretID := func(name, v string) *azsecrets.ID {
		id := azsecrets.ID("https://" + testVaultHost + "/secrets/" + name + "/" + v)
		return &id
	}
	ok := func() azsecrets.Secret {
		return azsecrets.Secret{ID: secretID("web-cert", ver), ContentType: to.Ptr("application/x-pkcs12"), Value: to.Ptr("c2VjcmV0")}
	}
	old := maxSecretValue
	maxSecretValue = 8
	t.Cleanup(func() { maxSecretValue = old })

	cases := map[string]func(*azsecrets.Secret){
		"no value":              func(s *azsecrets.Secret) { s.Value = nil },
		"an empty value":        func(s *azsecrets.Secret) { s.Value = to.Ptr("") },
		"no content type":       func(s *azsecrets.Secret) { s.ContentType = nil },
		"text/plain":            func(s *azsecrets.Secret) { s.ContentType = to.Ptr("text/plain") },
		"a parameter":           func(s *azsecrets.Secret) { s.ContentType = to.Ptr("application/x-pkcs12; charset=utf-8") },
		"upper case":            func(s *azsecrets.Secret) { s.ContentType = to.Ptr("Application/X-PKCS12") },
		"a value above a bound": func(s *azsecrets.Secret) { s.Value = to.Ptr("123456789") },
		"another version":       func(s *azsecrets.Secret) { s.ID = secretID("web-cert", strings.Repeat("c", 32)) },
		"another certificate":   func(s *azsecrets.Secret) { s.ID = secretID("other", ver) },
		"no id":                 func(s *azsecrets.Secret) { s.ID = nil },
		"an id without version": func(s *azsecrets.Secret) {
			id := azsecrets.ID("https://" + testVaultHost + "/secrets/web-cert")
			s.ID = &id
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			api := &stubAPI{secret: func(string, string) (azsecrets.Secret, error) { s := ok(); mutate(&s); return s, nil }}
			sess, _ := stubSession(api)
			sec, err := sess.ReadCertificateSecret(context.Background(), providers.SecretRequest{Name: "web-cert", Version: ver})
			pe := asProviderError(t, err)
			assert.Equal(t, codeSecretUnreadable, pe.Code)
			assert.False(t, pe.Retryable)
			assert.Empty(t, sec.Value.Bytes())
			assert.Empty(t, sec.ContentType)
			assertCauseChainIsOurs(t, pe)
			assert.NotContains(t, pe.Error(), "c2VjcmV0")
		})
	}
	t.Run("the good answer, a name in another case", func(t *testing.T) {
		api := &stubAPI{secret: func(string, string) (azsecrets.Secret, error) { return ok(), nil }}
		sess, _ := stubSession(api)
		sec, err := sess.ReadCertificateSecret(context.Background(), providers.SecretRequest{Name: "WEB-CERT", Version: ver})
		require.NoError(t, err)
		assert.Equal(t, "c2VjcmV0", string(sec.Value.Bytes()))
		sec.Value.Zero()
	})
	t.Run("a vault error comes back as it is", func(t *testing.T) {
		api := &stubAPI{secret: func(string, string) (azsecrets.Secret, error) {
			return azsecrets.Secret{}, providers.NewError(codeForbidden, false, nil, map[string]string{"role": providers.RoleKeyVaultSecretsUser})
		}}
		sess, _ := stubSession(api)
		_, err := sess.ReadCertificateSecret(context.Background(), providers.SecretRequest{Name: "web-cert", Version: ver})
		assert.Equal(t, codeForbidden, asProviderError(t, err).Code)
	})
}
