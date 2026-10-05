//go:build integration

package azurekv

import (
	"context"
	"crypto/x509"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/providers"
	"alice/internal/testutil/fakekv"
)

// addressesOf is the fake's fixed listeners: the TLS one (login host and vault host) and IMDS.
func addressesOf(s *fakekv.Server) FixedAddresses {
	return FixedAddresses{
		Login: s.DialAddr("login.microsoftonline.com:443"),
		Vault: s.DialAddr(testVaultHost + ":443"),
		IMDS:  s.DialAddr("169.254.169.254:80"),
	}
}

func fixedOptions(t *testing.T, s *fakekv.Server) Options {
	t.Helper()
	o, err := WithFixedAddresses(Options{RootCAs: func() (*x509.CertPool, error) { return s.CAPool(), nil }}, addressesOf(s))
	require.NoError(t, err)
	o.jitter = func(d time.Duration) time.Duration { return d }
	return o
}

// The real provider reaches the fake through fixed listener addresses while the request URL, the
// host rule and the TLS server name stay the real ones: the fake's log shows the real host names.
func TestFixedAddressesReachTheFakeUnderTheRealNames(t *testing.T) {
	s := fakekv.Start(t, fakekv.Options{VaultName: "alice-test"})
	clk := nearNow()
	sess := openSession(t, New(fixedOptions(t, s)), &idSource{id: secretIdentity(s)}, clk)
	var rep providers.ConnectionReport
	require.NoError(t, drive(clk, func() (err error) { rep, err = sess.TestConnection(context.Background()); return err }))
	require.NotNil(t, rep.Azure)
	hosts := map[string]bool{}
	for _, r := range s.Requests() {
		hosts[r.Host] = true
	}
	assert.Equal(t, map[string]bool{"login.microsoftonline.com": true, testVaultHost: true}, hosts)
}

// A mapped dial never combines with the system roots: no root function, and one that answers no
// pool, are refused; the second at Open as an untrusted TLS chain, never as a fallback.
func TestFixedAddressesRefuseSystemRoots(t *testing.T) {
	s := fakekv.Start(t, fakekv.Options{})
	_, err := WithFixedAddresses(Options{}, addressesOf(s))
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrFixedAddressesNeedRoots)

	o, err := WithFixedAddresses(Options{RootCAs: func() (*x509.CertPool, error) { return nil, nil }}, addressesOf(s))
	require.NoError(t, err)
	_, err = New(o).Open(context.Background(), target(), &idSource{id: secretIdentity(s)}, providers.Env{})
	assert.Equal(t, "azure.tls_untrusted", codeOfErr(t, err))
	assert.Empty(t, s.Requests(), "nothing was sent")

	o, err = WithFixedAddresses(Options{RootCAs: func() (*x509.CertPool, error) { return nil, errors.New("no file") }}, addressesOf(s))
	require.NoError(t, err)
	_, err = New(o).Open(context.Background(), target(), &idSource{id: secretIdentity(s)}, providers.Env{})
	assert.Equal(t, "azure.tls_untrusted", codeOfErr(t, err))
}

// TLS still verifies the real names, against the roots given: another CA is not trusted.
func TestFixedAddressesStillVerifyTheServerName(t *testing.T) {
	s := fakekv.Start(t, fakekv.Options{})
	other := fakekv.Start(t, fakekv.Options{})
	o, err := WithFixedAddresses(Options{RootCAs: func() (*x509.CertPool, error) { return other.CAPool(), nil }}, addressesOf(s))
	require.NoError(t, err)
	sess, err := New(o).Open(context.Background(), target(), &idSource{id: secretIdentity(s)}, providers.Env{Clock: nearNow()})
	require.NoError(t, err)
	t.Cleanup(func() { _ = sess.Close() })
	_, err = sess.TestConnection(context.Background())
	require.Error(t, err)
	assert.Equal(t, "azure.tls_untrusted", codeOfErr(t, err))
}

// The mapping touches only the three allowed endpoints; every other address stays as it was (the
// guards refuse it before any dial), and a malformed fixed address is refused when it is set.
func TestFixedAddressesMapOnlyTheAllowedEndpoints(t *testing.T) {
	roots := func() (*x509.CertPool, error) { return x509.NewCertPool(), nil }
	o, err := WithFixedAddresses(Options{RootCAs: roots}, FixedAddresses{Login: "127.0.0.1:1001", Vault: "127.0.0.1:1002", IMDS: "127.0.0.1:1003"})
	require.NoError(t, err)
	for in, want := range map[string]string{
		"login.microsoftonline.com:443":  "127.0.0.1:1001",
		"LOGIN.microsoftonline.com:443":  "127.0.0.1:1001",
		"contoso.vault.azure.net:443":    "127.0.0.1:1002",
		"169.254.169.254:80":             "127.0.0.1:1003",
		"evil.test:443":                  "evil.test:443",
		"contoso.vault.azure.net:8443":   "contoso.vault.azure.net:8443",
		"login.microsoftonline.com:8443": "login.microsoftonline.com:8443",
		"vault.azure.net.evil.test:443":  "vault.azure.net.evil.test:443",
		"169.254.169.254:443":            "169.254.169.254:443",
		"127.0.0.1:22":                   "127.0.0.1:22",
		"not an address":                 "not an address",
	} {
		assert.Equal(t, want, o.dialAddr(in), in)
	}

	for name, a := range map[string]FixedAddresses{
		"no login":         {Vault: "127.0.0.1:1"},
		"no vault":         {Login: "127.0.0.1:1"},
		"no port":          {Login: "127.0.0.1", Vault: "127.0.0.1:1"},
		"a host name":      {Login: "login.microsoftonline.com:443", Vault: "127.0.0.1:1"},
		"a bad port":       {Login: "127.0.0.1:0", Vault: "127.0.0.1:1"},
		"the metadata ip":  {Login: "169.254.169.254:80", Vault: "127.0.0.1:1"},
		"a bad imds":       {Login: "127.0.0.1:1", Vault: "127.0.0.1:1", IMDS: "nope"},
		"unspecified addr": {Login: "0.0.0.0:1", Vault: "127.0.0.1:1"},
		"a public ip":      {Login: "8.8.8.8:443", Vault: "127.0.0.1:1"},
		"a private ip":     {Login: "127.0.0.1:1", Vault: "10.0.0.5:443"},
		"a public imds":    {Login: "127.0.0.1:1", Vault: "127.0.0.1:1", IMDS: "1.1.1.1:80"},
	} {
		_, err := WithFixedAddresses(Options{RootCAs: roots}, a)
		assert.ErrorIs(t, err, ErrFixedAddresses, name)
	}
	// IMDS is optional: without it the metadata address is left alone.
	o, err = WithFixedAddresses(Options{RootCAs: roots}, FixedAddresses{Login: "127.0.0.1:1", Vault: "127.0.0.1:1"})
	require.NoError(t, err)
	assert.Equal(t, "169.254.169.254:80", o.dialAddr("169.254.169.254:80"))
}

// The managed identity reaches the fake's IMDS endpoint through the fixed address, while the
// transport's dialer still checks the metadata address before the mapping.
func TestFixedAddressesReachTheFakeIMDS(t *testing.T) {
	mi := fakekv.UniqueClientID()
	s := fakekv.Start(t, fakekv.Options{ManagedIdentity: true, MIClientID: mi})
	clk := nearNow()
	id := providers.AzureIdentity{Auth: providers.AzureAuthManagedIdentity, ClientID: mi}
	sess := openSession(t, New(fixedOptions(t, s)), &idSource{id: id}, clk)
	var rep providers.ConnectionReport
	require.NoError(t, drive(clk, func() (err error) { rep, err = sess.TestConnection(context.Background()); return err }))
	require.NotNil(t, rep.Azure)
	assert.NotEmpty(t, rep.Azure.ObjectID)
}

func codeOfErr(t *testing.T, err error) string {
	t.Helper()
	var pe *providers.Error
	require.ErrorAs(t, err, &pe)
	return pe.Code
}
