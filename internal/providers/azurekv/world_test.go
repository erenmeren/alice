package azurekv

import (
	"context"
	"encoding/base64"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azcertificates"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"
	"github.com/stretchr/testify/require"

	"alice/internal/platform/clock"
	"alice/internal/providers"
	"alice/internal/testutil/fakekv"
)

// world is a fake vault and a session of the real provider on a fake clock. run drives the clock so
// that every wait of the retry loop and the limiter ends at once.
type world struct {
	s    *fakekv.Server
	clk  *clock.Fake
	p    *Provider
	sess *session
}

// newWorld opens a session; tune (optional) changes the provider before it opens.
func newWorld(t *testing.T, o fakekv.Options, tune ...func(*fakekv.Server, *Provider)) *world {
	t.Helper()
	clk := nearNow()
	if o.Now == nil {
		o.Now = clk.Now // creation times follow the test's clock, so versions are told apart
	}
	s := fakekv.Start(t, o)
	p := testProvider(s)
	for _, f := range tune {
		f(s, p)
	}
	sess := openSession(t, p, &idSource{id: secretIdentity(s)}, clk)
	return &world{s: s, clk: clk, p: p, sess: sess}
}

func (w *world) run(fn func() error) error { return drive(w.clk, fn) }

func (w *world) discover(req providers.DiscoverRequest) (res providers.DiscoveryResult, err error) {
	err = w.run(func() error {
		var e error
		res, e = w.sess.Discover(context.Background(), req)
		return e
	})
	return res, err
}

func (w *world) check() (rep providers.ConnectionReport, err error) {
	err = w.run(func() error {
		var e error
		rep, e = w.sess.TestConnection(context.Background())
		return e
	})
	return rep, err
}

// vaultRequests returns the requests the vault host answered (the login host excluded).
func (w *world) vaultRequests() []fakekv.Request {
	var out []fakekv.Request
	for _, r := range w.s.Requests() {
		if r.Host == testVaultHost {
			out = append(out, r)
		}
	}
	return out
}

// authed counts the vault requests that carried a token (the SDK's challenge probe carries none).
func (w *world) authed() int {
	n := 0
	for _, r := range w.vaultRequests() {
		if r.HadAuth {
			n++
		}
	}
	return n
}

func asProviderError(t testing.TB, err error) *providers.Error {
	t.Helper()
	var pe *providers.Error
	require.ErrorAs(t, err, &pe)
	return pe
}

// stubAPI is a hand fake of kvAPI: unset functions answer "nothing".
type stubAPI struct {
	certs    func(page func([]*azcertificates.CertificateProperties) error) error
	get      func(name, version string) (azcertificates.Certificate, error)
	versions func(name string, page func([]*azcertificates.CertificateProperties) error) error
	keys     func(page func([]*azkeys.KeyProperties) error) error
	getKey   func(name string) (azkeys.KeyBundle, error)
	secrets  func(page func([]*azsecrets.SecretProperties) error) error
	secret   func(name, version string) (azsecrets.Secret, error)
	token    func() (azcore.AccessToken, error)
	imp      func(name string, p azcertificates.ImportCertificateParameters) (azcertificates.Certificate, error)
	calls    []string
	ctx      context.Context // the context of the last call
}

func (a *stubAPI) Token(ctx context.Context) (azcore.AccessToken, error) {
	a.calls = append(a.calls, "token")
	a.ctx = ctx
	if a.token != nil {
		return a.token()
	}
	return azcore.AccessToken{Token: "x", ExpiresOn: time.Now().Add(time.Hour)}, nil
}

func (a *stubAPI) ListCertificates(ctx context.Context, page func([]*azcertificates.CertificateProperties) error) error {
	a.calls = append(a.calls, "list_certificates")
	a.ctx = ctx
	if a.certs != nil {
		return a.certs(page)
	}
	return nil
}

func (a *stubAPI) GetCertificate(ctx context.Context, name, version string) (azcertificates.Certificate, error) {
	a.calls = append(a.calls, "get_certificate")
	a.ctx = ctx
	if a.get != nil {
		return a.get(name, version)
	}
	return azcertificates.Certificate{}, providers.NewError(codeCertificateNotFound, false, nil, nil)
}

func (a *stubAPI) ListCertificateVersions(ctx context.Context, name string, page func([]*azcertificates.CertificateProperties) error) error {
	a.calls = append(a.calls, "list_versions")
	a.ctx = ctx
	if a.versions != nil {
		return a.versions(name, page)
	}
	return nil
}

func (a *stubAPI) ListKeys(ctx context.Context, page func([]*azkeys.KeyProperties) error) error {
	a.calls = append(a.calls, "list_keys")
	a.ctx = ctx
	if a.keys != nil {
		return a.keys(page)
	}
	return nil
}

func (a *stubAPI) GetKey(ctx context.Context, name string) (azkeys.KeyBundle, error) {
	a.calls = append(a.calls, "get_key")
	a.ctx = ctx
	if a.getKey != nil {
		return a.getKey(name)
	}
	return azkeys.KeyBundle{}, providers.NewError(codeCertificateNotFound, false, nil, nil)
}

func (a *stubAPI) ListSecrets(ctx context.Context, page func([]*azsecrets.SecretProperties) error) error {
	a.calls = append(a.calls, "list_secrets")
	a.ctx = ctx
	if a.secrets != nil {
		return a.secrets(page)
	}
	return nil
}

func (a *stubAPI) GetSecret(ctx context.Context, name, version string) (azsecrets.Secret, error) {
	a.calls = append(a.calls, "get_secret")
	a.ctx = ctx
	if a.secret != nil {
		return a.secret(name, version)
	}
	return azsecrets.Secret{}, providers.NewError(codeCertificateNotFound, false, nil, nil)
}

func (a *stubAPI) ImportCertificate(ctx context.Context, name string, p azcertificates.ImportCertificateParameters) (azcertificates.Certificate, error) {
	a.calls = append(a.calls, "import")
	a.ctx = ctx
	if a.imp != nil {
		return a.imp(name, p)
	}
	return azcertificates.Certificate{}, providers.NewError(codeUnexpected, true, nil, nil)
}

// stubSession is a session over a stub api on a fake clock.
func stubSession(api kvAPI) (*session, *clock.Fake) {
	clk := nearNow()
	return &session{api: api, clock: clk, log: nopLogger()}, clk
}

func base64RawURL(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// dialFailingTune makes every connection to a host that starts with hostPrefix fail with err; the
// others reach the fake.
func dialFailingTune(hostPrefix string, err error) func(*fakekv.Server, *Provider) {
	return func(s *fakekv.Server, p *Provider) {
		p.o.dial = func(ctx context.Context, network, addr string) (net.Conn, error) {
			if strings.HasPrefix(addr, hostPrefix) {
				return nil, err
			}
			return (&net.Dialer{}).DialContext(ctx, network, s.DialAddr(addr))
		}
	}
}

var netDNS = net.DNSError{Err: "no such host", Name: testVaultHost, IsNotFound: true}

var _ kvAPI = (*stubAPI)(nil)
