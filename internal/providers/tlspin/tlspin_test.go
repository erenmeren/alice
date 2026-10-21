package tlspin_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/providers"
	"alice/internal/providers/tlspin"
)

// store is a HostKeyStore in memory: one pinned key and the sightings it was told about.
type store struct {
	mu       sync.Mutex
	pinned   *providers.HostKey
	pinErr   error
	seen     []sighting
	observed func(ctx context.Context) error
}

type sighting struct {
	key     providers.HostKey
	changed bool
}

func (s *store) Pinned(context.Context, uuid.UUID) (providers.HostKey, error) {
	if s.pinErr != nil {
		return providers.HostKey{}, s.pinErr
	}
	if s.pinned == nil {
		return providers.HostKey{}, providers.ErrNoPinnedKey
	}
	return *s.pinned, nil
}

func (s *store) Observed(ctx context.Context, _ uuid.UUID, k providers.HostKey, changed bool) error {
	if s.observed != nil {
		if err := s.observed(ctx); err != nil {
			return err
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.seen = append(s.seen, sighting{k, changed})
	return nil
}

// server starts a TLS server with a fresh self-signed certificate for example.com and 127.0.0.1 (every call another key).
func server(t *testing.T) (*httptest.Server, providers.HostKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "example.com"}, DNSNames: []string{"example.com"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) }))
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, MinVersion: tls.VersionTLS12}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv, providers.TLSIdentity(srv.Certificate().RawSubjectPublicKeyInfo)
}

func get(t *testing.T, v *tlspin.Verifier, url string) error {
	t.Helper()
	c := &http.Client{Transport: &http.Transport{TLSClientConfig: v.TLSConfig()}, Timeout: 5 * time.Second}
	defer c.CloseIdleConnections()
	resp, err := c.Get(url)
	if err == nil {
		_ = resp.Body.Close()
	}
	return err
}

func code(t *testing.T, err error) (string, map[string]string) {
	t.Helper()
	var pe *providers.Error
	require.ErrorAs(t, err, &pe)
	return pe.Code, pe.Params
}

func TestPinnedIdentityConnects(t *testing.T) {
	srv, id := server(t)
	st := &store{pinned: &id}
	v, err := tlspin.New(context.Background(), tlspin.Options{Target: uuid.New(), Store: st})
	require.NoError(t, err)
	assert.True(t, v.PinMode())
	cfg := v.TLSConfig()
	assert.Equal(t, uint16(0x0303), cfg.MinVersion, "TLS 1.2 or later")
	require.NoError(t, get(t, v, srv.URL), "a self-signed certificate with the pinned key is the server")
	assert.Empty(t, st.seen, "nothing to record")
	assert.NoError(t, v.Refusal(context.Background(), nil))
}

func TestUnpinnedIdentityIsRecordedAndRefused(t *testing.T) {
	srv, id := server(t)
	st := &store{}
	target := uuid.New()
	v, err := tlspin.New(context.Background(), tlspin.Options{Target: target, Store: st})
	require.NoError(t, err)
	err = get(t, v, srv.URL)
	require.ErrorIs(t, err, tlspin.ErrIdentityRefused, "no request is sent before the identity is confirmed")
	c, params := code(t, v.Refusal(context.Background(), err))
	assert.Equal(t, tlspin.CodeUnconfirmed, c)
	assert.Equal(t, map[string]string{"fingerprint": id.Fingerprint}, params)
	require.Len(t, st.seen, 1)
	assert.Equal(t, id, st.seen[0].key, "the candidate an Administrator confirms")
	assert.False(t, st.seen[0].changed)
	assert.True(t, providers.ValidTLSIdentity(st.seen[0].key), "the inventory's check accepts it")
}

func TestChangedIdentityIsRecordedAsAChange(t *testing.T) {
	srv, id := server(t)
	other, otherID := server(t)
	require.NotEqual(t, id.Fingerprint, otherID.Fingerprint)
	_ = other
	st := &store{pinned: &otherID}
	v, err := tlspin.New(context.Background(), tlspin.Options{Target: uuid.New(), Store: st})
	require.NoError(t, err)
	err = get(t, v, srv.URL)
	require.ErrorIs(t, err, tlspin.ErrIdentityRefused)
	c, params := code(t, v.Refusal(context.Background(), err))
	assert.Equal(t, tlspin.CodeChanged, c)
	assert.Equal(t, map[string]string{"old_fingerprint": otherID.Fingerprint, "new_fingerprint": id.Fingerprint}, params)
	require.Len(t, st.seen, 1)
	assert.True(t, st.seen[0].changed)
}

func TestRefusalOfOtherErrors(t *testing.T) {
	_, id := server(t)
	v, err := tlspin.New(context.Background(), tlspin.Options{Target: uuid.New(), Store: &store{pinned: &id}})
	require.NoError(t, err)
	assert.NoError(t, v.Refusal(context.Background(), errors.New("connection refused")), "not about the identity: the caller maps it")
	c, _ := code(t, v.Refusal(context.Background(), tlspin.ErrIdentityRefused))
	assert.Equal(t, "internal.unexpected", c, "a refusal without a presented certificate")
}

func TestSightingThatCannotBeRecorded(t *testing.T) {
	srv, _ := server(t)
	st := &store{observed: func(context.Context) error { return errors.New("database down") }}
	v, err := tlspin.New(context.Background(), tlspin.Options{Target: uuid.New(), Store: st})
	require.NoError(t, err)
	err = v.Refusal(context.Background(), get(t, v, srv.URL))
	var pe *providers.Error
	require.ErrorAs(t, err, &pe)
	assert.Equal(t, "internal.unexpected", pe.Code)
	assert.True(t, pe.Retryable, "a later connection records it again")

	// A store that ignores its context does not hang the caller.
	hang := &store{observed: func(context.Context) error { select {} }}
	v, err = tlspin.New(context.Background(), tlspin.Options{Target: uuid.New(), Store: hang, ObserveTimeout: 50 * time.Millisecond})
	require.NoError(t, err)
	start := time.Now()
	err = v.Refusal(context.Background(), get(t, v, srv.URL))
	require.ErrorIs(t, err, context.DeadlineExceeded)
	assert.Less(t, time.Since(start), 2*time.Second)
}

func TestCABundleMode(t *testing.T) {
	srv, _ := server(t)
	bundle := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	st := &store{}
	v, err := tlspin.New(context.Background(), tlspin.Options{Target: uuid.New(), ServerName: "example.com", CABundlePEM: bundle, Store: st})
	require.NoError(t, err)
	assert.False(t, v.PinMode())
	require.NoError(t, get(t, v, srv.URL), "a chain that verifies for the server name")
	assert.Empty(t, st.seen, "nothing is pinned or recorded in CA mode")

	v, err = tlspin.New(context.Background(), tlspin.Options{Target: uuid.New(), ServerName: "other.example", CABundlePEM: bundle})
	require.NoError(t, err)
	err = get(t, v, srv.URL)
	require.Error(t, err, "another name")
	assert.NoError(t, v.Refusal(context.Background(), err), "a verification failure is the caller's to map")

	other, _ := server(t)
	otherBundle := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: other.Certificate().Raw})
	v, err = tlspin.New(context.Background(), tlspin.Options{Target: uuid.New(), ServerName: "example.com", CABundlePEM: otherBundle})
	require.NoError(t, err)
	require.Error(t, get(t, v, srv.URL), "only the bundle's roots are trusted")

	_, err = tlspin.New(context.Background(), tlspin.Options{CABundlePEM: []byte("not pem")})
	assert.ErrorIs(t, err, tlspin.ErrNoCertificates)
}

func TestNewRefusesWhatIsNotAnAPITarget(t *testing.T) {
	ssh := providers.HostKey{Type: "ssh-ed25519", PublicKey: []byte{1}, Fingerprint: "SHA256:x"}
	_, err := tlspin.New(context.Background(), tlspin.Options{Target: uuid.New(), Store: &store{pinned: &ssh}})
	c, _ := code(t, err)
	assert.Equal(t, "internal.unexpected", c, "an SSH host key is never a TLS identity")

	_, err = tlspin.New(context.Background(), tlspin.Options{Target: uuid.New()})
	c, _ = code(t, err)
	assert.Equal(t, "internal.unexpected", c, "pin mode needs a store")

	_, err = tlspin.New(context.Background(), tlspin.Options{Target: uuid.New(), Store: &store{pinErr: errors.New("db")}})
	var pe *providers.Error
	require.ErrorAs(t, err, &pe)
	assert.True(t, pe.Retryable)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = tlspin.New(ctx, tlspin.Options{Target: uuid.New(), Store: &store{pinErr: context.Canceled}})
	require.ErrorIs(t, err, context.Canceled)
}
