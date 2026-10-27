package providers_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/providers"
)

func TestLocationKinds(t *testing.T) {
	for _, k := range []providers.LocationKind{providers.LocationServerFile, providers.LocationWinSSLBinding, providers.LocationF5ClientSSL,
		providers.LocationK8sTLSSecret, providers.LocationWinCCSFile} {
		assert.True(t, k.Known(), k)
	}
	assert.Equal(t, providers.LocationKind("win_ccs_file"), providers.LocationWinCCSFile)
	assert.False(t, providers.LocationWinCCSFile.IsFile(), "a CCS file has a locator and no key path (W5 Ruling 21)")
	assert.Equal(t, "write_file", providers.StepNameWriteFile)
	for _, k := range []providers.LocationKind{"", "nginx_file", "SERVER_FILE"} {
		assert.False(t, k.Known(), k)
	}
	assert.True(t, providers.LocationKind("").IsFile(), "a web-server provider leaves the kind empty")
	assert.True(t, providers.LocationServerFile.IsFile())
	assert.False(t, providers.LocationK8sTLSSecret.IsFile())
	assert.Equal(t, providers.LocationServerFile, providers.LocationKind("").OrFile())
	assert.Equal(t, providers.LocationF5ClientSSL, providers.LocationF5ClientSSL.OrFile())
}

func TestLocatorCanonical(t *testing.T) {
	a := providers.Locator{"type": "hostnameport", "host": "www.example.com", "port": 443, "app_id": "{4dc3e181-e14b-4a21-b022-59fc669b0914}"}
	got, err := a.Canonical()
	require.NoError(t, err)
	assert.Equal(t, `{"app_id":"{4dc3e181-e14b-4a21-b022-59fc669b0914}","host":"www.example.com","port":443,"type":"hostnameport"}`, string(got),
		"keys sorted, no white space, no HTML escaping")

	// The stored form reads back as the same location, whatever number type it went through.
	back, err := providers.ParseLocator(got)
	require.NoError(t, err)
	assert.True(t, back.Equal(a))
	var viaJSON providers.Locator
	require.NoError(t, json.Unmarshal(got, &viaJSON)) // float64 numbers
	assert.True(t, viaJSON.Equal(a))
	assert.False(t, a.Equal(providers.Locator{"type": "hostnameport", "host": "www.example.com", "port": 8443,
		"app_id": "{4dc3e181-e14b-4a21-b022-59fc669b0914}"}))
	assert.True(t, providers.Locator{"immutable": true, "n": int64(3)}.Equal(providers.Locator{"n": 3, "immutable": true}))

	nilLoc, err := providers.ParseLocator(nil)
	require.NoError(t, err)
	assert.Nil(t, nilLoc, "SQL NULL is a file location")
	nullLoc, err := providers.ParseLocator([]byte("null"))
	require.NoError(t, err)
	assert.Nil(t, nullLoc)

	many := providers.Locator{}
	for i := range providers.MaxLocatorKeys + 1 {
		many[fmt.Sprintf("k%d", i)] = "v"
	}
	long := providers.Locator{}
	for i := range 8 {
		long[fmt.Sprintf("k%d", i)] = strings.Repeat("x", providers.MaxLocatorText)
	}
	for name, l := range map[string]providers.Locator{
		"empty":             {},
		"nil":               nil,
		"too many keys":     many,
		"too long overall":  long,
		"an upper-case key": {"Name": "x"},
		"a key with a dot":  {"a.b": "x"},
		"an empty value":    {"name": ""},
		"a long value":      {"name": strings.Repeat("x", providers.MaxLocatorText+1)},
		"a control char":    {"name": "a\nb"},
		"a bidi control":    {"name": "a\u202eb"},
		"a fraction":        {"port": 1.5},
		"a huge number":     {"port": float64(1 << 60)},
		"a nested object":   {"spec": map[string]any{"a": 1}},
		"a list":            {"names": []string{"a"}},
		"a null":            {"name": nil},
		"invalid utf-8":     {"name": "a\xffb"},
		"a bad json number": {"port": json.Number("1e400")},
	} {
		_, err := l.Canonical()
		assert.ErrorIs(t, err, providers.ErrLocator, name)
		assert.False(t, l.Equal(l), "an invalid locator equals nothing: %s", name)
	}
	for _, raw := range []string{`[1]`, `{"a":`, `{"a":{"b":1}}`, `"x"`} {
		_, err := providers.ParseLocator([]byte(raw))
		assert.ErrorIs(t, err, providers.ErrLocator, raw)
	}
}

func TestCanonicalDetails(t *testing.T) {
	empty, err := providers.CanonicalDetails(nil)
	require.NoError(t, err)
	assert.Equal(t, "{}", string(empty))
	got, err := providers.CanonicalDetails(map[string]any{"resource_version": "12", "owners": []string{"cert-manager"}, "immutable": false,
		"note": "<a>&"})
	require.NoError(t, err)
	assert.Equal(t, `{"immutable":false,"note":"<a>&","owners":["cert-manager"],"resource_version":"12"}`, string(got))

	_, err = providers.CanonicalDetails(map[string]any{"Resource": 1})
	assert.ErrorIs(t, err, providers.ErrDetails, "keys are lower-case words")
	_, err = providers.CanonicalDetails(map[string]any{"x": strings.Repeat("a", providers.MaxDetailsBytes)})
	assert.ErrorIs(t, err, providers.ErrDetails, "bounded")
	_, err = providers.CanonicalDetails(map[string]any{"x": make(chan int)})
	assert.ErrorIs(t, err, providers.ErrDetails, "not JSON")
	// The bound is PostgreSQL's text, which has a space after every ':' and ','.
	list := make([]int, 0, 6000)
	for range 6000 {
		list = append(list, 1)
	}
	raw, err := json.Marshal(map[string]any{"x": list})
	require.NoError(t, err)
	require.Less(t, len(raw), providers.MaxDetailsBytes)
	_, err = providers.CanonicalDetails(map[string]any{"x": list})
	assert.ErrorIs(t, err, providers.ErrDetails, "%d bytes in Go, more in PostgreSQL", len(raw))
}

func TestRollbackTraits(t *testing.T) {
	require.NoError(t, providers.DefaultRollbackTraits.Validate())
	assert.Equal(t, providers.RollbackTraits{Backup: providers.BackupOnTarget, SelfRestores: true}, providers.DefaultRollbackTraits)
	require.NoError(t, providers.RollbackTraits{Backup: providers.BackupHeldByAlice}.Validate())
	require.NoError(t, providers.RollbackTraits{Backup: providers.BackupOnTarget}.Validate())
	assert.ErrorIs(t, providers.RollbackTraits{Backup: providers.BackupHeldByAlice, SelfRestores: true}.Validate(), providers.ErrRollbackTraits)
	assert.ErrorIs(t, providers.RollbackTraits{}.Validate(), providers.ErrRollbackTraits)

	assert.Equal(t, providers.DefaultRollbackTraits, providers.TraitsOf(stubProvider{}), "a provider that declares nothing")
	held := providers.RollbackTraits{Backup: providers.BackupHeldByAlice}
	assert.Equal(t, held, providers.TraitsOf(tracedProvider{traits: held}))

	required := providers.RollbackGuard{ForbiddenSPKI: []string{strings.Repeat("a", 64)}, Required: true}
	for _, c := range []struct {
		g            providers.RollbackGuard
		t            providers.RollbackTraits
		serverChecks bool
		want         bool
	}{
		{providers.RollbackGuard{}, providers.DefaultRollbackTraits, false, true},
		{required, providers.DefaultRollbackTraits, false, false}, // R48: the server would restore the backup by itself
		{required, providers.DefaultRollbackTraits, true, true},   // protocol 10: it checks the guard itself
		{required, held, false, true},                             // only Alice restores, after checking the guard
		{required, providers.RollbackTraits{Backup: providers.BackupOnTarget}, false, true},
	} {
		assert.Equal(t, c.want, c.g.SatisfiedBy(c.t, c.serverChecks), "%+v %+v %v", c.g, c.t, c.serverChecks)
	}
}

type stubProvider struct{ providers.Provider }

type tracedProvider struct {
	providers.Provider
	traits providers.RollbackTraits
}

func (p tracedProvider) RollbackTraits() providers.RollbackTraits { return p.traits }

func TestHeldBackupAndTargetSecretNeverPrint(t *testing.T) {
	key := "-----BEGIN " + "PRIVATE KEY-----canary-" + strings.Repeat("cd", 8)
	password, token := "pw-"+strings.Repeat("ef", 10), "tok-"+strings.Repeat("12", 10)
	b := providers.HeldBackup{CertificatePEM: []byte("cert"), PrivateKeyPEM: providers.NewSecret([]byte(key))}
	s := providers.TargetSecret{Kind: providers.TargetSecretPassword, Username: "alice-svc", Password: providers.NewSecret([]byte(password)),
		Token: providers.NewSecret([]byte(token)), ClientKeyPEM: providers.NewSecret([]byte(key))}
	for _, v := range []any{b, &b, s, &s} {
		var buf bytes.Buffer
		slog.New(slog.NewJSONHandler(&buf, nil)).Info("x", "v", v)
		raw, err := json.Marshal(v)
		require.NoError(t, err)
		for _, out := range []string{fmt.Sprintf("%v", v), fmt.Sprintf("%+v", v), fmt.Sprintf("%#v", v), fmt.Sprintf("%s", v), fmt.Sprintf("%x", v),
			buf.String(), string(raw)} {
			assert.NotContains(t, out, "canary")
			assert.NotContains(t, out, password)
			assert.NotContains(t, out, token)
		}
	}
	assert.Contains(t, fmt.Sprint(s), "alice-svc", "the user name is not a secret")
	b.Zero()
	s.Zero()
	assert.Equal(t, bytes.Repeat([]byte{0}, len(key)), b.PrivateKeyPEM.Bytes())
	assert.Equal(t, bytes.Repeat([]byte{0}, len(password)), s.Password.Bytes())
	assert.Equal(t, bytes.Repeat([]byte{0}, len(token)), s.Token.Bytes())
	assert.Equal(t, bytes.Repeat([]byte{0}, len(key)), s.ClientKeyPEM.Bytes())
}

func TestDeployRequestBackupsHaveNoJSON(t *testing.T) {
	req := providers.DeployRequest{Backups: memBackups{}}
	raw, err := json.Marshal(struct {
		R providers.RollbackRequest
	}{providers.RollbackRequest{Backups: memBackups{}}})
	require.NoError(t, err)
	assert.NotContains(t, string(raw), "Backups")
	assert.NotContains(t, fmt.Sprintf("%+v", req), "memBackups")
}

type memBackups struct{}

func (memBackups) Hold(context.Context, providers.HeldBackup) error { return nil }
func (memBackups) Load(context.Context) (providers.HeldBackup, error) {
	return providers.HeldBackup{}, providers.ErrNoHeldBackup
}

func TestTLSIdentity(t *testing.T) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	spki, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	require.NoError(t, err)
	id := providers.TLSIdentity(spki)
	assert.Equal(t, providers.HostKeyTypeTLSSPKI, id.Type)
	assert.Regexp(t, `^SHA256:[A-Za-z0-9+/]{43}$`, id.Fingerprint, "host_keys' fingerprint CHECK")
	assert.Equal(t, spki, id.PublicKey)
	spki[0] ^= 0xff
	assert.NotEqual(t, spki, id.PublicKey, "a copy")
	assert.True(t, providers.ValidTLSIdentity(id))

	other := id
	other.Fingerprint = providers.TLSIdentity([]byte("other")).Fingerprint
	assert.False(t, providers.ValidTLSIdentity(other), "a fingerprint of another key")
	assert.False(t, providers.ValidTLSIdentity(providers.TLSIdentity([]byte("not a key"))), "not a SubjectPublicKeyInfo")
	ssh := id
	ssh.Type = "ssh-ed25519"
	assert.False(t, providers.ValidTLSIdentity(ssh), "another key type")
	assert.False(t, providers.ValidTLSIdentity(providers.HostKey{Type: providers.HostKeyTypeTLSSPKI}))
}
