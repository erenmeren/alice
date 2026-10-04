package azureid_test

import (
	"crypto/sha1" //nolint:gosec // G505: x5t is SHA-1 by Azure's definition (test reference)
	"encoding/hex"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/platform/azureid"
)

func TestParseVaultTable(t *testing.T) {
	ok := map[string]string{
		"contoso-prod":                          "https://contoso-prod.vault.azure.net",
		"Contoso-Prod":                          "https://contoso-prod.vault.azure.net",
		"contoso-prod.vault.azure.net":          "https://contoso-prod.vault.azure.net",
		"https://contoso-prod.vault.azure.net":  "https://contoso-prod.vault.azure.net",
		"https://contoso-prod.vault.azure.net/": "https://contoso-prod.vault.azure.net",
		" HTTPS://KV1.VAULT.AZURE.NET ":         "https://kv1.vault.azure.net",
		"\tkv1.vault.azure.net\r\n":             "https://kv1.vault.azure.net",
		"abc":                                   "https://abc.vault.azure.net",
		"a23456789012345678901234":              "https://a23456789012345678901234.vault.azure.net",
		"a-1":                                   "https://a-1.vault.azure.net",
		"a1-b2-c3-d4-e5-f6-g7-h8":               "https://a1-b2-c3-d4-e5-f6-g7-h8.vault.azure.net",
		"ab9":                                   "https://ab9.vault.azure.net",
	}
	for in, want := range ok {
		v, err := azureid.ParseVault(in)
		if assert.NoError(t, err, in) {
			assert.Equal(t, want, v.URL, in)
			assert.Equal(t, strings.TrimPrefix(want, "https://"), v.Host, in)
			assert.Equal(t, strings.TrimSuffix(strings.TrimPrefix(want, "https://"), ".vault.azure.net"), v.Name, in)
		}
	}
	bad := []string{
		// name length and character clauses
		"", " ", "/", "ab", "a234567890123456789012345", "1abc", "-abc", "abc-", "ab--c", "a---b", "ab_c", "ab.c",
		"abc\x00", "ab c", "con toso", "kontosö", "contosİ", "\u212Aeyvault", "ｃｏｎｔｏｓｏ", "a\u200Bbc",
		"abc\n.vault.azure.net", "ab\nc", "xn--contoso-9ya", "xn--80ak6aa92e.vault.azure.net",
		// scheme
		"http://contoso.vault.azure.net", "ftp://contoso.vault.azure.net", "//contoso.vault.azure.net",
		"https:/contoso.vault.azure.net", "https:///contoso.vault.azure.net", "https://https://contoso.vault.azure.net",
		"https://contoso", "https://", "https://.vault.azure.net", "https://vault.azure.net", "vault.azure.net",
		".vault.azure.net", "https://contoso.vault.azure.net\\", "https:\\\\contoso.vault.azure.net",
		// port, path, query, fragment, userinfo
		"https://contoso.vault.azure.net:443", "https://contoso.vault.azure.net:8443", "contoso.vault.azure.net:443",
		"https://contoso.vault.azure.net:", "https://contoso.vault.azure.net/secrets", "https://contoso.vault.azure.net//",
		"https://contoso.vault.azure.net/.", "https://contoso.vault.azure.net/..",
		"https://contoso.vault.azure.net?x=1", "https://contoso.vault.azure.net/?x=1", "https://contoso.vault.azure.net#x",
		"https://contoso.vault.azure.net/#", "https://user@contoso.vault.azure.net", "https://x@evil/",
		"https://contoso.vault.azure.net@evil.test", "https://contoso.vault.azure.net:x@evil.test",
		"https://contoso.vault.azure.net%2f@evil.test", "https://contoso%2evault.azure.net",
		// dots, case-folded look-alikes, other suffixes and clouds
		"contoso.vault.azure.net.", "https://contoso.vault.azure.net.", "https://contoso.vault.azure.net..",
		"https://contoso.vault.azure.net.evil.test", "contoso.vault.azure.net.evil.com",
		"https://evil.test/contoso.vault.azure.net", "https://evil.test#.vault.azure.net", "evil.test?.vault.azure.net",
		"sub.contoso.vault.azure.net", "contoso.vault.azure.net.vault.azure.net", "contoso..vault.azure.net",
		"contoso.vault.usgovcloudapi.net", "contoso.vault.azure.cn", "contoso.vault.microsoftazure.de",
		"contoso.managedhsm.azure.net", "contoso.privatelink.vaultcore.azure.net", "contoso.vaultcore.azure.net",
		"contoso.vault-azure.net", "contoso-vault.azure.net", "contoso.vault.azure.net.attacker",
		// IP literals and metadata addresses
		"169.254.169.254", "https://169.254.169.254", "169.254.169.254.vault.azure.net", "127.0.0.1", "https://[::1]",
		"[::1]", "[fe80::1]", "https://[fe80::1]/", "0x7f000001", "2130706433", "local.host", "https://local.host",
	}
	for _, in := range bad {
		v, err := azureid.ParseVault(in)
		assert.ErrorIs(t, err, azureid.ErrVault, in)
		assert.Equal(t, azureid.Vault{}, v, "a refusal returns nothing a URL could be built from: %q", in)
	}
}

func TestParseVaultNameLengthEdges(t *testing.T) {
	for n := 0; n <= 30; n++ {
		name := "a" + strings.Repeat("b", max(n-1, 0))
		if n == 0 {
			name = ""
		}
		_, err := azureid.ParseVault(name)
		if n >= 3 && n <= 24 {
			assert.NoError(t, err, "%d characters", n)
		} else {
			assert.ErrorIs(t, err, azureid.ErrVault, "%d characters", n)
		}
	}
}

var vaultURLShape = regexp.MustCompile(`^https://[a-z](-?[a-z0-9])+\.vault\.azure\.net$`)

// checkVaultInvariant: whatever ParseVault accepts can only name one host of the public cloud.
func checkVaultInvariant(t *testing.T, in string) {
	t.Helper()
	v, err := azureid.ParseVault(in)
	if err != nil {
		assert.Equal(t, azureid.Vault{}, v, "%q", in)
		return
	}
	require.Regexp(t, vaultURLShape, v.URL, "%q", in)
	assert.Equal(t, "https://"+v.Host, v.URL, "%q", in)
	assert.Equal(t, v.Name+azureid.VaultSuffix, v.Host, "%q", in)
	assert.GreaterOrEqual(t, len(v.Name), 3, "%q", in)
	assert.LessOrEqual(t, len(v.Name), 24, "%q", in)
	u, perr := url.Parse(v.URL)
	require.NoError(t, perr, "%q", in)
	assert.Equal(t, "https", u.Scheme)
	assert.Equal(t, v.Host, u.Host, "no user, no port: %q", in)
	assert.Empty(t, u.Port())
	assert.Nil(t, u.User)
	assert.Empty(t, u.Path+u.RawQuery+u.Fragment)
}

func TestParseVaultAcceptsOnlyOneShape(t *testing.T) {
	pieces := []string{"a", "b", "9", "-", ".", "/", ":", "@", "#", "?", "%", " ", "https://", ".vault.azure.net", "evil.test", "\\", "\n", "ö", "[", "]"}
	// A deterministic sweep of two- and three-piece combinations around a valid name.
	for _, x := range pieces {
		for _, y := range pieces {
			for _, z := range []string{"", "abc", "abc.vault.azure.net", "https://abc.vault.azure.net"} {
				checkVaultInvariant(t, x+z+y)
				checkVaultInvariant(t, z+x+y)
				checkVaultInvariant(t, z+y+x)
			}
		}
	}
}

func FuzzParseVault(f *testing.F) {
	for _, s := range []string{"contoso", "https://contoso.vault.azure.net/", "https://x@evil/", "a--b", "ÖÖÖ.vault.azure.net", "169.254.169.254"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) { checkVaultInvariant(t, s) })
}

func TestNormalizeGUID(t *testing.T) {
	g, ok := azureid.NormalizeGUID(" 6B8E2C1A-0F3D-4C2B-9A7E-1D2C3B4A5F60 ")
	assert.True(t, ok)
	assert.Equal(t, "6b8e2c1a-0f3d-4c2b-9a7e-1d2c3b4a5f60", g)
	g, ok = azureid.NormalizeGUID("\t6b8e2c1a-0f3d-4c2b-9a7e-1d2c3b4a5f60\r\n")
	assert.True(t, ok)
	assert.Equal(t, "6b8e2c1a-0f3d-4c2b-9a7e-1d2c3b4a5f60", g)
	for _, in := range []string{"", " ", "contoso.onmicrosoft.com", "6b8e2c1a0f3d4c2b9a7e1d2c3b4a5f60",
		"{6b8e2c1a-0f3d-4c2b-9a7e-1d2c3b4a5f60}", "(6b8e2c1a-0f3d-4c2b-9a7e-1d2c3b4a5f60)",
		"urn:uuid:6b8e2c1a-0f3d-4c2b-9a7e-1d2c3b4a5f60", "6b8e2c1a-0f3d-4c2b-9a7e-1d2c3b4a5f6",
		"6b8e2c1a-0f3d-4c2b-9a7e-1d2c3b4a5f600", "6b8e2c1a-0f3d-4c2b-9a7e-1d2c3b4a5f6g",
		"6b8e2c1a-0f3d-4c2b-9a7e-1d2c3b4a5f60/", "6b8e2c1a-0f3d-4c2b-9a7e-1d2c3b4a5f60\n6b8e2c1a",
		"6b8e2c1a-0f3d-4c2b-9a7e-1d2c3b4a5f60\x00", "6b8e2c1a_0f3d_4c2b_9a7e_1d2c3b4a5f60",
		"6b8e2c1a-0f3d-4c2b-9a7e1d2c3b4a5f60-", "../6b8e2c1a-0f3d-4c2b-9a7e-1d2c3b4a5f", "6b8e2c1a-0f3d-4c2b-9a7e-1d2c3b4a5f6\u0660",
		"6B8E2C1A-0F3D-4C2B-9A7E-1D2C3B4A5F6\u212A"} {
		g, ok := azureid.NormalizeGUID(in)
		assert.False(t, ok, in)
		assert.Empty(t, g, "a refusal returns no text: %q", in)
	}
	assert.True(t, azureid.ValidRequestID("6B8E2C1A-0F3D-4C2B-9A7E-1D2C3B4A5F60"))
	assert.True(t, azureid.ValidRequestID("6b8e2c1a-0f3d-4c2b-9a7e-1d2c3b4a5f60"))
	assert.False(t, azureid.ValidRequestID("not-a-guid"))
	assert.False(t, azureid.ValidRequestID(" 6b8e2c1a-0f3d-4c2b-9a7e-1d2c3b4a5f60"), "a request id is kept as Azure sent it")
	assert.False(t, azureid.ValidRequestID("6b8e2c1a-0f3d-4c2b-9a7e-1d2c3b4a5f60\n"))
}

func TestObjectNamesVersionsThumbprintsCodes(t *testing.T) {
	assert.True(t, azureid.ValidObjectName("web-cert-2026"))
	assert.True(t, azureid.ValidObjectName("A"))
	assert.True(t, azureid.ValidObjectName("-"), "Key Vault lets a name be any run of letters, digits and hyphens")
	assert.True(t, azureid.ValidObjectName(strings.Repeat("a", 127)))
	for _, n := range []string{"", strings.Repeat("a", 128), "web_cert", "web.cert", "web cert", "web/cert", "web\\cert", "ü",
		"web\n", "web\x00", "..", "a:b", "a?b", "a#b", "a%2fb", "a@b", "\u212A"} {
		assert.False(t, azureid.ValidObjectName(n), n)
	}

	assert.True(t, azureid.ValidVersion("0123456789abcdef0123456789abcdef"))
	for _, v := range []string{"", "0123", "0123456789ABCDEF0123456789abcdef", "0123456789abcdef0123456789abcdef0",
		"0123456789abcdef0123456789abcde", "0123456789abcdef0123456789abcdeg", "0123456789abcdef0123456789abcdef\n",
		"latest", "/0123456789abcdef0123456789abcdef"} {
		assert.False(t, azureid.ValidVersion(v), v)
	}

	der := []byte("leaf")
	sum := sha1.Sum(der) //nolint:gosec // G401: reference value
	assert.Equal(t, hex.EncodeToString(sum[:]), azureid.ThumbprintOf(der))
	tp, ok := azureid.Thumbprint(sum[:])
	assert.True(t, ok)
	assert.True(t, azureid.ValidThumbprint(tp))
	assert.Equal(t, tp, azureid.ThumbprintOf(der))
	_, ok = azureid.Thumbprint(sum[:19])
	assert.False(t, ok)
	_, ok = azureid.Thumbprint(append(sum[:], 0))
	assert.False(t, ok)
	_, ok = azureid.Thumbprint(nil)
	assert.False(t, ok)

	// The stored form is 40 lower-case hex digits; ValidThumbprint is strict, NormalizeThumbprint is
	// the one place that folds the upper case the Azure portal shows.
	assert.False(t, azureid.ValidThumbprint("0123456789ABCDEF0123456789ABCDEF01234567"), "upper case is not the stored form")
	for _, in := range []string{"", tp[:39], tp + "0", "g" + tp[1:], tp[:20] + ":" + tp[20:], "0x" + tp[:38]} {
		assert.False(t, azureid.ValidThumbprint(in), in)
		_, ok := azureid.NormalizeThumbprint(in)
		assert.False(t, ok, in)
	}
	assert.False(t, azureid.ValidThumbprint(tp+"\n"), "Valid is strict about every byte")
	n, ok := azureid.NormalizeThumbprint(" 0123456789ABCDEF0123456789ABCDEF01234567\n")
	assert.True(t, ok)
	assert.Equal(t, "0123456789abcdef0123456789abcdef01234567", n)
	n, ok = azureid.NormalizeThumbprint("zz")
	assert.False(t, ok)
	assert.Empty(t, n)

	for _, c := range []string{"ForbiddenByRbac", "A", "CertificateNotFound", "A" + strings.Repeat("b", 63)} {
		assert.True(t, azureid.ValidAzureCode(c), c)
	}
	for _, c := range []string{"", "Forbidden By Rbac", "7000215", "Forbidden-ByRbac", "Forbidden_ByRbac", "A" + strings.Repeat("b", 64), "Ab\n", "Ünder"} {
		assert.False(t, azureid.ValidAzureCode(c), c)
	}
}

func TestEndpointConstants(t *testing.T) {
	assert.Equal(t, "login.microsoftonline.com", azureid.AuthorityHost)
	assert.Equal(t, "https://login.microsoftonline.com/", azureid.AuthorityURL)
	assert.Equal(t, ".vault.azure.net", azureid.VaultSuffix)
	assert.Equal(t, "https://vault.azure.net/.default", azureid.VaultScope)
	assert.Equal(t, "169.254.169.254:80", azureid.IMDSAddr)
}
