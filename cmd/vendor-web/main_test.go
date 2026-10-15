package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const goodDB = "postgres://web:s3cretpw@127.0.0.1:5432/vendor?sslmode=disable"

func runWith(env map[string]string, args ...string) (int, string) {
	var out, errOut bytes.Buffer
	old := serve
	serve = func(config, io.Writer, io.Writer) int { panic("a configuration error must not start the server") }
	defer func() { serve = old }()
	code := run(args, func(k string) string { return env[k] }, &out, &errOut)
	return code, errOut.String() + out.String()
}

func TestConfigurationErrorsExitTwoWithoutLeakingThePassword(t *testing.T) {
	good := map[string]string{"VENDOR_WEB_DATABASE_URL": goodDB, "VENDOR_WEB_ORIGIN": "https://licenses.example.com"}
	with := func(k, v string) map[string]string {
		m := map[string]string{}
		for a, b := range good {
			m[a] = b
		}
		if v == "" {
			delete(m, k)
		} else {
			m[k] = v
		}
		return m
	}
	for name, c := range map[string]struct {
		env  map[string]string
		args []string
		want string
	}{
		"no database url":  {with("VENDOR_WEB_DATABASE_URL", ""), nil, "VENDOR_WEB_DATABASE_URL"},
		"no origin":        {with("VENDOR_WEB_ORIGIN", ""), nil, "VENDOR_WEB_ORIGIN"},
		"http origin":      {with("VENDOR_WEB_ORIGIN", "http://licenses.example.com"), nil, "localhost"},
		"rpid mismatch":    {with("VENDOR_WEB_RPID", "other.example.com"), nil, "RP ID"},
		"only cert":        {good, []string{"--tls-cert", "c.pem"}, "--tls-key"},
		"only key":         {good, []string{"--tls-key", "k.pem"}, "--tls-cert"},
		"insecure db":      {with("VENDOR_WEB_DATABASE_URL", "postgres://web:s3cretpw@db.example.com/vendor?sslmode=disable"), nil, "verify-full"},
		"unknown flag":     {good, []string{"--nope"}, "nope"},
		"stray argument":   {good, []string{"extra"}, "extra"},
		"unparsable dburl": {with("VENDOR_WEB_DATABASE_URL", "postgres://web:s3cretpw@db.example.com:xx/vendor"), nil, "VENDOR_WEB_DATABASE_URL"},
	} {
		code, msg := runWith(c.env, c.args...)
		assert.Equal(t, 2, code, name)
		assert.Contains(t, msg, c.want, name)
		assert.NotContains(t, msg, "s3cretpw", name)
	}
}

func TestTheRPIDDefaultsToTheOriginHost(t *testing.T) {
	var got config
	old := serve
	serve = func(c config, _, _ io.Writer) int { got = c; return 0 }
	defer func() { serve = old }()
	var out, errOut bytes.Buffer
	env := map[string]string{"VENDOR_WEB_DATABASE_URL": goodDB, "VENDOR_WEB_ORIGIN": "https://licenses.example.com:8443"}
	code := run([]string{"--listen", "127.0.0.1:0"}, func(k string) string { return env[k] }, &out, &errOut)
	assert.Equal(t, 0, code, errOut.String())
	assert.Equal(t, "licenses.example.com", got.rpid)
	assert.Equal(t, "127.0.0.1:0", got.listen)
}

// writeCertPair writes a self-signed certificate and its key to dir and returns their paths.
func writeCertPair(t *testing.T, dir string) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "licenses.example.com"},
		DNSNames: []string{"licenses.example.com"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	kder, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)
	certPath, keyPath := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	require.NoError(t, os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600))
	require.NoError(t, os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kder}), 0o600))
	return certPath, keyPath
}

func TestTLSPairIsLoadedDuringValidation(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := writeCertPair(t, dir)
	env := map[string]string{"VENDOR_WEB_DATABASE_URL": goodDB, "VENDOR_WEB_ORIGIN": "https://licenses.example.com"}

	missing := filepath.Join(dir, "missing.pem")
	junk := filepath.Join(dir, "junk.pem")
	require.NoError(t, os.WriteFile(junk, []byte("secret-junk-contents"), 0o600))
	for name, args := range map[string][]string{
		"missing cert": {"--tls-cert", missing, "--tls-key", keyPath},
		"missing key":  {"--tls-cert", certPath, "--tls-key", missing},
		"junk cert":    {"--tls-cert", junk, "--tls-key", keyPath},
		"junk key":     {"--tls-cert", certPath, "--tls-key", junk},
		"swapped":      {"--tls-cert", keyPath, "--tls-key", certPath},
	} {
		code, msg := runWith(env, args...)
		assert.Equal(t, 2, code, name)
		assert.Contains(t, msg, "TLS certificate", name)
		assert.NotContains(t, msg, "secret-junk-contents", name)
		assert.NotContains(t, msg, "BEGIN", name)
	}

	var got config
	old := serve
	serve = func(c config, _, _ io.Writer) int { got = c; return 0 }
	defer func() { serve = old }()
	var out, errOut bytes.Buffer
	code := run([]string{"--tls-cert", certPath, "--tls-key", keyPath}, func(k string) string { return env[k] }, &out, &errOut)
	require.Equal(t, 0, code, errOut.String())
	require.NotNil(t, got.cert)
	assert.NotContains(t, errOut.String(), "plain http")
}

func TestHelpExitsZero(t *testing.T) {
	for _, arg := range []string{"--help", "-h"} {
		code, msg := runWith(nil, arg)
		assert.Equal(t, 0, code, arg)
		assert.Contains(t, msg, "Usage: vendor-web", arg)
	}
}

// TestTheBinaryCannotSign checks the whole dependency graph, not only direct imports: no path from
// vendor-web reaches the signing, issuing or migration code.
func TestTheBinaryCannotSign(t *testing.T) {
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("go is not on PATH")
	}
	cmd := exec.Command(goBin, "list", "-deps", ".")
	out, err := cmd.Output()
	require.NoError(t, err)
	deps := map[string]bool{}
	for _, l := range strings.Split(string(out), "\n") {
		deps[strings.TrimSpace(l)] = true
	}
	require.True(t, deps["alice/internal/vconsole/web"], "the listing looks wrong:\n%s", out)
	for _, forbidden := range []string{"alice/internal/vconsole/sign", "alice/internal/vconsole/issue", "alice/internal/vconsole/migrations"} {
		assert.False(t, deps[forbidden], "vendor-web depends on %s", forbidden)
	}
}
