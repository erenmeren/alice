//go:build integration

package inventory_test

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

	"alice/internal/inventory"
	"alice/internal/platform/validate"
	"alice/internal/providers"
	"alice/internal/providers/fake"
)

// knownSeed makes the generated platform key predictable so the tests can search for it.
var knownSeed = bytes.Repeat([]byte{0x5a}, ed25519.SeedSize)

func withSeed(c *inventory.Config) { c.Rand = bytes.NewReader(knownSeed) }

func TestEnsurePlatformKeyCreatesOneSealedKey(t *testing.T) {
	h := newHarness(t, withSeed)
	pk, err := h.svc.EnsurePlatformKey(h.ctx)
	require.NoError(t, err)

	want, err := ssh.NewPublicKey(ed25519.NewKeyFromSeed(knownSeed).Public())
	require.NoError(t, err)
	assert.Equal(t, strings.TrimSpace(string(ssh.MarshalAuthorizedKey(want)))+" alice-platform", pk.PublicKey)
	assert.Equal(t, ssh.FingerprintSHA256(want), pk.Fingerprint)

	again, err := h.svc.EnsurePlatformKey(h.ctx)
	require.NoError(t, err)
	assert.Equal(t, pk, again, "a second call returns the same key")
	assert.Equal(t, 1, h.count("SELECT count(*) FROM credentials"))
	assert.Equal(t, 1, h.audits("platform_key.created"))
	assert.Equal(t, []map[string]string{{"fingerprint": pk.Fingerprint, "credential_id": pk.ID.String()}}, h.auditDetails("platform_key.created"))

	// S-04: the stored row is ciphertext; no form of the seed or private key is anywhere.
	var ct, nonce, wrapped, info []byte
	require.NoError(t, h.db.Owner.QueryRow(h.ctx, "SELECT ciphertext, nonce, wrapped_dek, public_info::text FROM credentials").Scan(&ct, &nonce, &wrapped, &info))
	priv := ed25519.NewKeyFromSeed(knownSeed)
	for _, form := range [][]byte{knownSeed, priv, []byte(hex.EncodeToString(knownSeed)), []byte(base64.StdEncoding.EncodeToString(knownSeed))} {
		for _, stored := range [][]byte{ct, nonce, wrapped, info} {
			assert.False(t, bytes.Contains(stored, form), "the seed must not be stored in clear")
		}
		assert.NotContains(t, h.logs.String(), string(form))
	}
	assert.Equal(t, 0, h.count("SELECT count(*) FROM audit_log WHERE details::text LIKE '%' || $1 || '%'", hex.EncodeToString(knownSeed)))
}

func TestPlatformKeyIsCreatedOnceUnderConcurrency(t *testing.T) {
	h := newHarness(t)
	var wg sync.WaitGroup
	got := make([]inventory.PlatformKey, 8)
	errs := make([]error, 8)
	for i := range got {
		wg.Add(1)
		go func() {
			defer wg.Done()
			got[i], errs[i] = h.svc.EnsurePlatformKey(h.ctx)
		}()
	}
	wg.Wait()
	for i := range got {
		require.NoError(t, errs[i])
		assert.Equal(t, got[0], got[i])
	}
	assert.Equal(t, 1, h.count("SELECT count(*) FROM credentials"))
	assert.Equal(t, 1, h.audits("platform_key.created"))
}

func TestPlatformKeyBeforeEnsureIsMissing(t *testing.T) {
	h := newHarness(t)
	_, err := h.svc.PlatformKey(h.ctx)
	require.ErrorIs(t, err, inventory.ErrNoPlatformKey)
}

func TestCredentialsSignWithThePlatformKey(t *testing.T) {
	h := newHarness(t, withSeed)
	pk, err := h.svc.EnsurePlatformKey(h.ctx)
	require.NoError(t, err)
	signer, release, err := h.svc.Credentials().SSHSigner(h.ctx)
	require.NoError(t, err)
	defer release()
	assert.Equal(t, pk.Fingerprint, ssh.FingerprintSHA256(signer.PublicKey()))
	sig, err := signer.Sign(nil, []byte("challenge"))
	require.NoError(t, err)
	require.NoError(t, signer.PublicKey().Verify([]byte("challenge"), sig))
}

// SEC-041: the ciphertext is bound to its row; a copy under another id does not decrypt, and
// the error says nothing about the key.
func TestCredentialsRefuseAMovedCiphertext(t *testing.T) {
	h := newHarness(t, withSeed)
	_, err := h.svc.EnsurePlatformKey(h.ctx)
	require.NoError(t, err)
	_, err = h.db.Owner.Exec(h.ctx, "UPDATE credentials SET id = $1", uuid.Must(uuid.NewV7()))
	require.NoError(t, err)
	_, _, err = h.svc.Credentials().SSHSigner(h.ctx)
	require.Error(t, err)
	assert.NotContains(t, err.Error(), hex.EncodeToString(knownSeed))
	assert.NotContains(t, err.Error(), "ciphertext")
}

// guideProvider is the fake provider plus the SetupGuide methods, recording the line it got.
type guideProvider struct {
	*fake.Provider
	line string
}

func (g *guideProvider) SetupSnippets(line string) map[string]providers.SetupSnippet {
	g.line = line
	return map[string]providers.SetupSnippet{
		"linux": {Profile: "linux", Sudoers: "linux sudoers", Script: "linux script " + line},
		"nginx": {Profile: "nginx", Sudoers: "nginx sudoers", Script: "nginx script " + line},
	}
}

func (g *guideProvider) HelperInfo() (string, int) { return "/usr/local/libexec/alice-helper", 1 }

func TestSetupGuide(t *testing.T) {
	g := &guideProvider{Provider: fake.New(providers.KindLinuxSSH)}
	h := newHarness(t, withSeed, func(c *inventory.Config) {
		reg := providers.NewRegistry()
		reg.Register(g)
		reg.Freeze()
		c.Registry = reg
	})
	pk, err := h.svc.EnsurePlatformKey(h.ctx)
	require.NoError(t, err)

	guide, err := h.svc.SetupGuide(h.ctx, "")
	require.NoError(t, err)
	assert.Equal(t, pk, guide.PlatformKey)
	assert.Equal(t, "no-agent-forwarding,no-port-forwarding,no-X11-forwarding,no-pty,no-user-rc "+pk.PublicKey, guide.AuthorizedKeysLine)
	assert.Equal(t, guide.AuthorizedKeysLine, g.line)
	assert.Equal(t, "/usr/local/libexec/alice-helper", guide.HelperPath)
	assert.Equal(t, 1, guide.HelperProtocol)
	assert.Equal(t, "linux script "+guide.AuthorizedKeysLine, guide.Profiles["linux"].Script)
	assert.Len(t, guide.Profiles, 2)

	guide, err = h.svc.SetupGuide(h.ctx, "10.0.0.9")
	require.NoError(t, err)
	assert.Equal(t, `from="10.0.0.9",no-agent-forwarding,no-port-forwarding,no-X11-forwarding,no-pty,no-user-rc `+pk.PublicKey, guide.AuthorizedKeysLine)

	for _, bad := range []string{"web-01", `10.0.0.9",command="id`, "10.0.0.0/8", "fe80::1%eth0", " 10.0.0.9"} {
		_, err := h.svc.SetupGuide(h.ctx, bad)
		var verrs validate.Errors
		require.ErrorAs(t, err, &verrs, bad)
		assert.Equal(t, "from", verrs[0].Field)
	}
}

func TestSetupGuideWithoutGuideProviderFails(t *testing.T) {
	h := newHarness(t) // the plain fake provider does not implement providers.SetupGuide
	_, err := h.svc.EnsurePlatformKey(h.ctx)
	require.NoError(t, err)
	_, err = h.svc.SetupGuide(h.ctx, "")
	require.Error(t, err)
}
