package inventory

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/certs"
	"alice/internal/providers"
	"alice/internal/testutil/pki"
)

var unitNow = time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC)

func TestCodeShapes(t *testing.T) {
	assert.Empty(t, code("", "unknown"))
	assert.Equal(t, "variable", code("variable", "unknown"))
	assert.Equal(t, "unknown", code("Variable", "unknown"))
	assert.Equal(t, "unknown", code(strings.Repeat("a", 41), "unknown"))
	assert.Equal(t, "ab", truncRunes("ab", 2))
	assert.Equal(t, "öö", truncRunes("ööö", 2))
}

func TestBoundServersKeepsLeadingBlocksThatFit(t *testing.T) {
	servers := cleanServers([]providers.CertServer{
		{Names: []string{"a.example.test"}, Listens: []providers.CertListen{{Port: 443}}, File: "/etc/nginx/a", Line: 1},
		{Names: []string{"b.example.test"}, File: "/etc/nginx/b"},
		{Names: nil, Listens: nil},
	})
	all, cut := boundServers(servers, maxServersJSON)
	assert.False(t, cut)
	assert.Len(t, all, 3)
	assert.Equal(t, []string{}, all[2].Names, "never null")
	assert.Equal(t, []providers.CertListen{}, all[2].Listens)
	first := 2 + serverTextSize(servers[0])
	got, cut := boundServers(servers, first)
	assert.True(t, cut)
	assert.Len(t, got, 1)
	got, cut = boundServers(servers, first-1)
	assert.True(t, cut)
	assert.Empty(t, got)
}

func TestLocationWarningsAreCodesOnceAndBounded(t *testing.T) {
	assert.Equal(t, []string{}, locationWarnings(nil, nil))
	assert.Equal(t, []string{"a", "san_mismatch"}, locationWarnings([]string{"a", "a", "B", "", "san_mismatch"}, []string{"san_mismatch"}))
	var many []string
	for i := range 40 {
		many = append(many, fmt.Sprintf("w_%c%c", 'a'+i/26, 'a'+i%26))
	}
	got := locationWarnings(many, []string{WarnCertificateExpired, WarnSANMismatch})
	assert.Len(t, got, maxLocationWarnings)
	assert.Equal(t, []string{WarnCertificateExpired, WarnSANMismatch}, got[30:], "the inventory's own warnings are kept")
}

func TestSANMismatch(t *testing.T) {
	sans := []string{"*.example.test", "example.test"}
	srv := func(names ...string) []providers.CertServer { return []providers.CertServer{{Names: names}} }
	assert.False(t, sanMismatch(sans, srv("_", "", "~^(www)\\.x$", "a.example.test", "EXAMPLE.test")))
	assert.True(t, sanMismatch(sans, srv("a.b.example.test")))
	assert.True(t, sanMismatch(nil, srv("example.test")))
	assert.False(t, sanMismatch(nil, nil))
	// Nginx's forms: ".example.test" is example.test and its subdomains, "*.example.test" a
	// leading wildcard, "www.example.*" a trailing one.
	assert.False(t, sanMismatch([]string{"example.test"}, srv(".example.test")))
	assert.True(t, sanMismatch([]string{"www.example.test"}, srv(".example.test")))
	assert.False(t, sanMismatch([]string{"*.example.test"}, srv("*.example.test")))
	assert.True(t, sanMismatch([]string{"www.example.test"}, srv("*.example.test")))
	assert.False(t, sanMismatch([]string{"WWW.example.org"}, srv("www.example.*")))
	assert.True(t, sanMismatch([]string{"api.example.org", "*.example.org"}, srv("www.example.*")))
	assert.False(t, sanMismatch(nil, srv("~^(?<sub>.+)\\.example\\.test$")))
}

func TestPrepareLocation(t *testing.T) {
	ca := pki.NewCA("Unit", pki.ECDSA256, unitNow)
	leaf := ca.Issue(pki.Opts{CommonName: "www.example.test", SANs: []string{"www.example.test"}}, unitNow)
	sum := sha256.Sum256(leaf.FullchainPEM)
	ok := providers.CertLocation{CertPath: "/etc/nginx/ssl/www.crt", KeyPath: "/etc/nginx/ssl/www.key", Supported: true, KeyExists: true,
		Servers: []providers.CertServer{{Names: []string{"www.example.test"}}}}
	d := providers.DiscoveredCertificate{Location: ok, PEMChain: leaf.FullchainPEM, FileSHA256: hex.EncodeToString(sum[:])}

	p, stored := prepareLocation(d, unitNow)
	require.True(t, stored)
	assert.True(t, p.loc.Supported)
	assert.Equal(t, "ecdsa", p.keyType)
	assert.Equal(t, d.FileSHA256, p.fileSHA)
	assert.Equal(t, []string{}, p.warnings)
	assert.JSONEq(t, `[{"names":["www.example.test"],"listens":[],"file":"","line":0}]`, string(p.servers))

	// Expired at the scan time.
	p, _ = prepareLocation(d, leaf.Cert.NotAfter)
	assert.Equal(t, []string{WarnCertificateExpired}, p.warnings)

	// A chain too large for certs is a problem of the file; its content stays unknown.
	big := d
	big.PEMChain = []byte(strings.Repeat("x", 300<<10))
	p, _ = prepareLocation(big, unitNow)
	assert.Equal(t, providers.CertProblemTooLarge, p.loc.Problem)
	assert.Equal(t, providers.UnsupportedFile, p.loc.Unsupported)
	assert.False(t, p.loc.Supported)
	assert.False(t, p.gone)
	assert.Nil(t, p.cert)

	// A problem reported with a chain: the chain is not read.
	withProblem := d
	withProblem.Location.Problem = providers.CertProblemHardLinked
	p, _ = prepareLocation(withProblem, unitNow)
	assert.Nil(t, p.cert)
	assert.False(t, p.gone)
	assert.Equal(t, providers.UnsupportedFile, p.loc.Unsupported)

	// Locations that cannot be stored.
	for _, path := range []string{"", "/" + strings.Repeat("p", maxLocationPath)} {
		bad := d
		bad.Location.CertPath = path
		_, stored = prepareLocation(bad, unitNow)
		assert.False(t, stored)
	}
	assert.Equal(t, "/etc/nginx/ssl/a�.crt", func() string {
		nul := d
		nul.Location.CertPath = "/etc/nginx/ssl/a\x00.crt"
		p, _ := prepareLocation(nul, unitNow)
		return p.loc.CertPath
	}())
}

func TestScanCoverage(t *testing.T) {
	valid := &providers.NginxFacts{Found: true, ConfigValid: true}
	assert.True(t, listsEveryLocation(providers.DiscoveryResult{Nginx: valid}))
	for _, code := range []string{"stream_tls", providers.WarnListTruncated, providers.WarnTooManyFiles} {
		assert.True(t, listsEveryLocation(providers.DiscoveryResult{Nginx: valid, Warnings: []providers.Warning{{Code: code}}}), code)
	}
	assert.True(t, listsEveryLocation(providers.DiscoveryResult{Nginx: valid, Partial: true}), "Partial is about SSH files")
	assert.False(t, listsEveryLocation(providers.DiscoveryResult{}))
	assert.False(t, listsEveryLocation(providers.DiscoveryResult{Nginx: &providers.NginxFacts{Found: true}}))
	assert.False(t, listsEveryLocation(providers.DiscoveryResult{Nginx: valid, Warnings: []providers.Warning{{Code: providers.WarnLocationsDropped}}}))
	assert.False(t, configUsable(&providers.NginxFacts{Found: true}))
	assert.False(t, configUsable(&providers.NginxFacts{ConfigValid: true}))
	assert.False(t, configUsable(&providers.NginxFacts{Found: true, ConfigValid: true, ConfigError: providers.ConfigErrSyntax}))
}

func TestSSHHalfRead(t *testing.T) {
	nginx := &providers.NginxFacts{Found: true, ConfigValid: true}
	assert.True(t, sshHalfRead(providers.DiscoveryResult{}), "a linuxssh result")
	assert.False(t, sshHalfRead(providers.DiscoveryResult{Nginx: nginx}), "certificates only")
	assert.False(t, sshHalfRead(providers.DiscoveryResult{Nginx: nginx, Partial: true}), "Partial is never set without the SSH half")
	for _, r := range []providers.DiscoveryResult{
		{Nginx: nginx, SSHD: providers.SSHDSummary{Read: true}},
		{Nginx: nginx, HostKeys: []providers.DiscoveredHostKey{{}}},
		{Nginx: nginx, SSHKeys: []providers.DiscoveredSSHKey{{}}},
		{Nginx: nginx, ReadFiles: []string{"/root/.ssh/authorized_keys"}},
		{Nginx: nginx, UnreadableLines: []providers.UnreadableLine{{}}},
		{Nginx: nginx, Accounts: []string{"root"}},
		{Nginx: nginx, UID0Users: []string{"root"}},
	} {
		assert.True(t, sshHalfRead(r), "%+v", r)
	}
}

func TestMergeNginxFacts(t *testing.T) {
	old := &providers.NginxFacts{Found: true, ConfigValid: true, Version: "1.22.1", ConfPath: "/etc/nginx/nginx.conf"}
	assert.Equal(t, &providers.NginxFacts{Found: true, Version: "1.22.1", ConfPath: "/etc/nginx/nginx.conf", ConfigError: "syntax"},
		mergeNginxFacts(old, providers.NginxFacts{Found: true, ConfigError: "syntax"}))
	assert.Equal(t, &providers.NginxFacts{}, mergeNginxFacts(old, providers.NginxFacts{}), "Nginx gone: nothing is kept")
	assert.Equal(t, &providers.NginxFacts{Found: true, Version: "1.�"}, mergeNginxFacts(nil, providers.NginxFacts{Found: true, Version: "1.\x00"}))
}

func TestLeafPEMIsTheFirstBlock(t *testing.T) {
	ca := pki.NewCA("Unit", pki.ECDSA256, unitNow)
	leaf := ca.Issue(pki.Opts{CommonName: "www.example.test"}, unitNow)
	p, err := certs.ParseChainPEM(leaf.FullchainPEM)
	require.NoError(t, err)
	require.Len(t, p.Chain, 1)
	assert.Equal(t, string(leaf.CertPEM), leafPEM(p))
}

func TestBoundSANs(t *testing.T) {
	got, dropped := boundSANs([]string{"a.example.test", strings.Repeat("x", maxSANLength+1), "n\x00ul"})
	assert.True(t, dropped)
	assert.Equal(t, []string{"a.example.test", "n�ul"}, got)
	got, dropped = boundSANs(nil)
	assert.False(t, dropped)
	assert.Equal(t, []string{}, got)
	assert.Len(t, []rune(boundText(strings.Repeat("ş", maxCertificateText+5))), maxCertificateText)
}
