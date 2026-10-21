package azuredns_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/acme/solver/dnsapi"
	"alice/internal/acme/solver/dnsapi/azuredns"
	"alice/internal/secrets"
	"alice/internal/testutil/fakekv"
	"alice/internal/testutil/pki"
)

func TestNewValidates(t *testing.T) {
	leaf, keyDER := spLeaf(t)
	_, otherKey := spLeaf(t)
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ecDER, err := x509.MarshalPKCS8PrivateKey(ec)
	require.NoError(t, err)
	tenant, client, sub := uuid.NewString(), uuid.NewString(), uuid.NewString()
	pt := func(b []byte) secrets.Plaintext { return secrets.NewPlaintext(append([]byte(nil), b...)) }
	secret := []byte(fakekv.NewClientSecret())

	base := func(auth string) azuredns.Config {
		c := azuredns.Config{Auth: auth, SubscriptionID: sub, ResourceGroup: "dns-rg"}
		switch auth {
		case azuredns.AuthClientSecret:
			c.TenantID, c.ClientID, c.ClientSecret = tenant, client, pt(secret)
		case azuredns.AuthCertificate:
			c.TenantID, c.ClientID, c.CertificateDER, c.PrivateKeyDER = tenant, client, leaf.Cert.Raw, pt(keyDER)
		}
		return c
	}
	good := map[string]azuredns.Config{
		"client secret":            base(azuredns.AuthClientSecret),
		"certificate":              base(azuredns.AuthCertificate),
		"system-assigned identity": base(azuredns.AuthManagedIdentity),
		"user-assigned identity":   func() azuredns.Config { c := base(azuredns.AuthManagedIdentity); c.ClientID = client; return c }(),
		"upper-case GUIDs and spaces": func() azuredns.Config {
			c := base(azuredns.AuthClientSecret)
			c.TenantID = " " + upper(tenant) + " "
			c.SubscriptionID = upper(sub)
			return c
		}(),
		"resource group characters": func() azuredns.Config {
			c := base(azuredns.AuthClientSecret)
			c.ResourceGroup = "My.RG_(1)-x"
			return c
		}(),
		"resource group of 90": func() azuredns.Config {
			c := base(azuredns.AuthClientSecret)
			c.ResourceGroup = strings.Repeat("r", 90)
			return c
		}(),
	}
	for name, c := range good {
		t.Run("good "+name, func(t *testing.T) {
			p, err := azuredns.New(c)
			require.NoError(t, err)
			assert.Equal(t, dnsapi.KindAzureDNS, p.Kind())
		})
	}

	mut := func(auth string, f func(*azuredns.Config)) azuredns.Config { c := base(auth); f(&c); return c }
	bad := map[string]struct {
		c   azuredns.Config
		err error
	}{
		"no auth":                {mut(azuredns.AuthClientSecret, func(c *azuredns.Config) { c.Auth = "" }), azuredns.ErrIdentity},
		"unknown auth":           {mut(azuredns.AuthClientSecret, func(c *azuredns.Config) { c.Auth = "password" }), azuredns.ErrIdentity},
		"tenant not a GUID":      {mut(azuredns.AuthClientSecret, func(c *azuredns.Config) { c.TenantID = "contoso.onmicrosoft.com" }), azuredns.ErrIdentity},
		"no tenant":              {mut(azuredns.AuthCertificate, func(c *azuredns.Config) { c.TenantID = "" }), azuredns.ErrIdentity},
		"client not a GUID":      {mut(azuredns.AuthClientSecret, func(c *azuredns.Config) { c.ClientID = "app" }), azuredns.ErrIdentity},
		"no secret":              {mut(azuredns.AuthClientSecret, func(c *azuredns.Config) { c.ClientSecret = secrets.Plaintext{} }), azuredns.ErrIdentity},
		"secret too long":        {mut(azuredns.AuthClientSecret, func(c *azuredns.Config) { c.ClientSecret = pt(make([]byte, 1025)) }), azuredns.ErrIdentity},
		"secret with a key":      {mut(azuredns.AuthClientSecret, func(c *azuredns.Config) { c.PrivateKeyDER = pt(keyDER) }), azuredns.ErrIdentity},
		"secret with a cert":     {mut(azuredns.AuthClientSecret, func(c *azuredns.Config) { c.CertificateDER = leaf.Cert.Raw }), azuredns.ErrIdentity},
		"cert with a secret":     {mut(azuredns.AuthCertificate, func(c *azuredns.Config) { c.ClientSecret = pt(secret) }), azuredns.ErrIdentity},
		"cert without key":       {mut(azuredns.AuthCertificate, func(c *azuredns.Config) { c.PrivateKeyDER = secrets.Plaintext{} }), azuredns.ErrIdentity},
		"key without cert":       {mut(azuredns.AuthCertificate, func(c *azuredns.Config) { c.CertificateDER = nil }), azuredns.ErrIdentity},
		"cert garbage":           {mut(azuredns.AuthCertificate, func(c *azuredns.Config) { c.CertificateDER = []byte("garbage") }), azuredns.ErrIdentity},
		"key garbage":            {mut(azuredns.AuthCertificate, func(c *azuredns.Config) { c.PrivateKeyDER = pt([]byte("garbage")) }), azuredns.ErrIdentity},
		"key not RSA":            {mut(azuredns.AuthCertificate, func(c *azuredns.Config) { c.PrivateKeyDER = pt(ecDER) }), azuredns.ErrIdentity},
		"key of another cert":    {mut(azuredns.AuthCertificate, func(c *azuredns.Config) { c.PrivateKeyDER = pt(otherKey) }), azuredns.ErrIdentity},
		"cert not RSA":           {mut(azuredns.AuthCertificate, func(c *azuredns.Config) { c.CertificateDER = ecCert(t) }), azuredns.ErrIdentity},
		"identity with tenant":   {mut(azuredns.AuthManagedIdentity, func(c *azuredns.Config) { c.TenantID = tenant }), azuredns.ErrIdentity},
		"identity with secret":   {mut(azuredns.AuthManagedIdentity, func(c *azuredns.Config) { c.ClientSecret = pt(secret) }), azuredns.ErrIdentity},
		"identity with key":      {mut(azuredns.AuthManagedIdentity, func(c *azuredns.Config) { c.PrivateKeyDER = pt(keyDER) }), azuredns.ErrIdentity},
		"identity with cert":     {mut(azuredns.AuthManagedIdentity, func(c *azuredns.Config) { c.CertificateDER = leaf.Cert.Raw }), azuredns.ErrIdentity},
		"identity client bad":    {mut(azuredns.AuthManagedIdentity, func(c *azuredns.Config) { c.ClientID = "x" }), azuredns.ErrIdentity},
		"subscription not GUID":  {mut(azuredns.AuthClientSecret, func(c *azuredns.Config) { c.SubscriptionID = "prod" }), azuredns.ErrSubscription},
		"no subscription":        {mut(azuredns.AuthManagedIdentity, func(c *azuredns.Config) { c.SubscriptionID = "" }), azuredns.ErrSubscription},
		"no resource group":      {mut(azuredns.AuthClientSecret, func(c *azuredns.Config) { c.ResourceGroup = "" }), azuredns.ErrResourceGroup},
		"resource group of 91":   {mut(azuredns.AuthClientSecret, func(c *azuredns.Config) { c.ResourceGroup = strings.Repeat("r", 91) }), azuredns.ErrResourceGroup},
		"resource group dot end": {mut(azuredns.AuthClientSecret, func(c *azuredns.Config) { c.ResourceGroup = "rg." }), azuredns.ErrResourceGroup},
		"resource group slash":   {mut(azuredns.AuthClientSecret, func(c *azuredns.Config) { c.ResourceGroup = "rg/../x" }), azuredns.ErrResourceGroup},
		"resource group query":   {mut(azuredns.AuthClientSecret, func(c *azuredns.Config) { c.ResourceGroup = "rg?x" }), azuredns.ErrResourceGroup},
		"resource group unicode": {mut(azuredns.AuthClientSecret, func(c *azuredns.Config) { c.ResourceGroup = "rgİ" }), azuredns.ErrResourceGroup},
		"mapping without roots":  {azuredns.WithMapAddr(base(azuredns.AuthClientSecret), func(s string) string { return s }), dnsapi.ErrMapNeedsRoots},
	}
	for name, c := range bad {
		t.Run("bad "+name, func(t *testing.T) {
			p, err := azuredns.New(c.c)
			assert.Nil(t, p)
			assert.ErrorIs(t, err, c.err)
		})
	}
}

func TestNewCopiesTheSecret(t *testing.T) {
	w := secretWorld(t, fakekv.Options{})
	w.cfg.ClientSecret.Zero() // the caller zeroes its own copy after New
	require.NoError(t, w.solverOf(t).Present(ctx5(t), chal("example.test", "v")))
}

func TestNewCopiesTheKey(t *testing.T) {
	w, _ := certWorld(t, fakekv.Options{})
	w.cfg.PrivateKeyDER.Zero()
	require.NoError(t, w.solverOf(t).Present(ctx5(t), chal("example.test", "v")))
}

func ecCert(t *testing.T) []byte {
	t.Helper()
	return pki.NewCA("t", pki.ECDSA256, time.Now()).Issue(pki.Opts{CommonName: "ec", KeyType: pki.ECDSA256}, time.Now()).Cert.Raw
}

// upper upper-cases ASCII letters (strings.ToUpper is banned).
func upper(s string) string {
	b := []byte(s)
	for i, c := range b {
		if 'a' <= c && c <= 'z' {
			b[i] = c - ('a' - 'A')
		}
	}
	return string(b)
}
