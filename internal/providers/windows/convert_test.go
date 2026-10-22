package windows

import (
	"crypto/sha1" //nolint:gosec // G505: Windows names certificates by their SHA-1 thumbprint
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/providers"
	"alice/internal/providers/windows/winproto"
	"alice/internal/testutil/pki"
)

const (
	appWinRM   = "{afebb9ad-9b97-4a91-9ab5-daf4d59122f6}"
	appUnknown = "{5d89a20c-beab-4389-9447-324788eb944a}" // AD FS has no known id (W0 F8)
)

// dumpFixture builds an iis-dump answer the way the helper sends it.
type dumpFixture struct {
	t   *testing.T
	ca  *pki.CA
	now time.Time
	d   winproto.IISDumpResponse
}

func newDump(t *testing.T) *dumpFixture {
	t.Helper()
	now := time.Now()
	return &dumpFixture{t: t, ca: pki.NewCA("Convert CA", pki.ECDSA256, now), now: now,
		d: winproto.IISDumpResponse{OK: true, IIS: winproto.IISFacts{Installed: true, Version: "10.0"}, Bindings: []winproto.SSLBinding{},
			Certificates: []winproto.StoreCertificate{}, Sites: []winproto.Site{}, ExpiredInStore: map[string]int{}, Warnings: []string{}}}
}

func derOf(t *testing.T, p []byte) []byte {
	t.Helper()
	b, _ := pem.Decode(p)
	require.NotNil(t, b)
	return b.Bytes
}

func sha1Hex(der []byte) string {
	s := sha1.Sum(der) //nolint:gosec // G401: a thumbprint
	return hex.EncodeToString(s[:])
}

func derSHA256(der []byte) string {
	s := sha256.Sum256(der)
	return hex.EncodeToString(s[:])
}

// cert lists a certificate of the store, as the helper does, with the intermediate as its chain and
// a usable key. It returns the thumbprint and the leaf's DER.
func (f *dumpFixture) cert(store, cn string, mod ...func(*winproto.StoreCertificate)) (string, []byte) {
	l := f.ca.Issue(pki.Opts{CommonName: cn, SANs: []string{cn}}, f.now)
	der := derOf(f.t, l.CertPEM)
	yes := true
	c := winproto.StoreCertificate{Store: store, SHA1: sha1Hex(der), SHA256: derSHA256(der), DER: base64.StdEncoding.EncodeToString(der),
		Chain: []string{base64.StdEncoding.EncodeToString(derOf(f.t, f.ca.IntermediatePEM))}, FriendlyName: cn,
		NotAfter: l.Cert.NotAfter.UTC().Format(time.RFC3339), HasKey: true, KeyProvider: "Microsoft Software Key Storage Provider",
		KeyUsableBySystem: &yes}
	for _, m := range mod {
		m(&c)
	}
	f.d.Certificates = append(f.d.Certificates, c)
	return sha1Hex(der), der
}

func (f *dumpFixture) bind(b winproto.SSLBinding) { f.d.Bindings = append(f.d.Bindings, b) }

// ipport and sni add an IIS http.sys entry naming a new certificate of My.
func (f *dumpFixture) ipport(ip string, port int) string {
	sha, _ := f.cert("My", fmt.Sprintf("ip-%s-%d", strings.Trim(ip, "[]:"), port))
	f.bind(winproto.SSLBinding{Type: winproto.BindingIPPort, IP: ip, Port: port, AppID: winproto.AppIDIIS, CertSHA1: sha, Store: "My"})
	return sha
}

func (f *dumpFixture) sni(host string, port int) string {
	sha, _ := f.cert("My", foldASCII(host))
	f.bind(winproto.SSLBinding{Type: winproto.BindingHostnamePort, Host: host, Port: port, AppID: winproto.AppIDIIS, CertSHA1: sha, Store: "My"})
	return sha
}

func (f *dumpFixture) ccs(port int) {
	f.bind(winproto.SSLBinding{Type: winproto.BindingCCS, IP: "0.0.0.0", Port: port, AppID: winproto.AppIDIIS})
}

// site adds an https binding to the named site (created when new).
func (f *dumpFixture) site(name, info string, flags int) {
	for i := range f.d.Sites {
		if f.d.Sites[i].Name == name {
			f.d.Sites[i].Bindings = append(f.d.Sites[i].Bindings, winproto.SiteBinding{Protocol: "https", Information: info, SSLFlags: flags})
			return
		}
	}
	f.d.Sites = append(f.d.Sites, winproto.Site{Name: name, ID: int64(len(f.d.Sites) + 1), State: "Started",
		Bindings: []winproto.SiteBinding{{Protocol: "https", Information: info, SSLFlags: flags}}})
}

func (f *dumpFixture) convert() ([]providers.DiscoveredCertificate, []providers.Warning, providers.WebServerFacts) {
	f.t.Helper()
	certs, warns, facts := convert(f.d)
	for _, c := range certs {
		checkStorable(f.t, c)
	}
	return certs, warns, facts
}

// checkStorable is what inventory requires of a location that is not a file.
func checkStorable(t *testing.T, c providers.DiscoveredCertificate) {
	t.Helper()
	l := c.Location
	assert.Equal(t, providers.LocationWinSSLBinding, l.Kind, l.CertPath)
	_, err := l.Locator.Canonical()
	require.NoError(t, err, l.CertPath)
	_, err = providers.CanonicalDetails(l.Details)
	require.NoError(t, err, l.CertPath)
	assert.LessOrEqual(t, len(l.CertPath), providers.MaxCanonicalLength)
	assert.Equal(t, l.Supported, l.Unsupported == "", l.CertPath)
	assert.Empty(t, l.KeyPath)
	assert.NotNil(t, l.Servers)
	for _, s := range l.Servers {
		assert.NotNil(t, s.Names)
		assert.NotNil(t, s.Listens)
	}
}

func byPath(certs []providers.DiscoveredCertificate) map[string]providers.DiscoveredCertificate {
	m := map[string]providers.DiscoveredCertificate{}
	for _, c := range certs {
		m[c.Location.CertPath] = c
	}
	return m
}

func codes(ws []providers.Warning) []string {
	out := []string{}
	for _, w := range ws {
		out = append(out, w.Code)
	}
	return out
}

func TestCanonical(t *testing.T) {
	iis := winproto.AppIDIIS
	for _, tc := range []struct {
		name string
		b    winproto.SSLBinding
		text string
		loc  providers.Locator
	}{
		{"hostnameport folded", winproto.SSLBinding{Type: "hostnameport", Host: "WWW.Example.COM", Port: 443, AppID: iis},
			"http.sys/hostnameport/www.example.com:443", providers.Locator{"type": "hostnameport", "host": "www.example.com", "port": 443, "app_id": iis}},
		{"ipport v4", winproto.SSLBinding{Type: "ipport", IP: "0.0.0.0", Port: 443, AppID: iis},
			"http.sys/ipport/0.0.0.0:443", providers.Locator{"type": "ipport", "ip": "0.0.0.0", "port": 443, "app_id": iis}},
		{"ipport v6", winproto.SSLBinding{Type: "ipport", IP: "::", Port: 443, AppID: iis},
			"http.sys/ipport/[::]:443", providers.Locator{"type": "ipport", "ip": "::", "port": 443, "app_id": iis}},
		{"ipport v6 long form", winproto.SSLBinding{Type: "ipport", IP: "2001:0DB8:0:0:0:0:0:1", Port: 8443, AppID: iis},
			"http.sys/ipport/[2001:db8::1]:8443", providers.Locator{"type": "ipport", "ip": "2001:db8::1", "port": 8443, "app_id": iis}},
		{"ipport mapped", winproto.SSLBinding{Type: "ipport", IP: "::ffff:10.0.0.5", Port: 443, AppID: iis},
			"http.sys/ipport/10.0.0.5:443", providers.Locator{"type": "ipport", "ip": "10.0.0.5", "port": 443, "app_id": iis}},
		{"ccs", winproto.SSLBinding{Type: "ccs", IP: "0.0.0.0", Port: 443, AppID: iis},
			"http.sys/ccs/443", providers.Locator{"type": "ccs", "port": 443, "app_id": iis}},
		{"app id upper case without braces", winproto.SSLBinding{Type: "ccs", Port: 443, AppID: "4DC3E181-E14B-4A21-B022-59FC669B0914"},
			"http.sys/ccs/443", providers.Locator{"type": "ccs", "port": 443, "app_id": iis}},
		{"unicode host", winproto.SSLBinding{Type: "hostnameport", Host: "BÜCHER.example", Port: 443, AppID: iis},
			"http.sys/hostnameport/bÜcher.example:443", providers.Locator{"type": "hostnameport", "host": "bÜcher.example", "port": 443, "app_id": iis}},
		{"wildcard host", winproto.SSLBinding{Type: "hostnameport", Host: "*.Example.com", Port: 443, AppID: iis},
			"http.sys/hostnameport/*.example.com:443", providers.Locator{"type": "hostnameport", "host": "*.example.com", "port": 443, "app_id": iis}},
	} {
		text, loc, ok := canonical(tc.b)
		require.True(t, ok, tc.name)
		assert.Equal(t, tc.text, text, tc.name)
		assert.Equal(t, tc.loc, loc, tc.name)
		_, err := loc.Canonical()
		assert.NoError(t, err, tc.name)
	}
	for _, b := range []winproto.SSLBinding{
		{Type: "ipport", IP: "300.0.0.1", Port: 443, AppID: iis},
		{Type: "ipport", IP: "", Port: 443, AppID: iis},
		{Type: "ipport", IP: "fe80::1%3", Port: 443, AppID: iis},
		{Type: "ipport", IP: "0.0.0.0", Port: 0, AppID: iis},
		{Type: "ipport", IP: "0.0.0.0", Port: 70000, AppID: iis},
		{Type: "ccs", Port: -1, AppID: iis},
		{Type: "hostnameport", Host: "www.example.com/x", Port: 443, AppID: iis},
		{Type: "hostnameport", Host: "www.example.com:443", Port: 443, AppID: iis},
		{Type: "hostnameport", Host: "a b", Port: 443, AppID: iis},
		{Type: "hostnameport", Host: "", Port: 443, AppID: iis},
		{Type: "hostnameport", Host: "evil\u202e.com", Port: 443, AppID: iis},
		{Type: "hostnameport", Host: strings.Repeat("a", 254), Port: 443, AppID: iis},
		{Type: "ipport", IP: "0.0.0.0", Port: 443, AppID: "{BAD}"},
		{Type: "ipport", IP: "0.0.0.0", Port: 443, AppID: ""},
		{Type: "sslcert", IP: "0.0.0.0", Port: 443, AppID: iis},
	} {
		_, _, ok := canonical(b)
		assert.False(t, ok, "%+v", b)
	}
}

func TestParseSiteBinding(t *testing.T) {
	for _, tc := range []struct {
		info  string
		flags int
		want  siteKey
	}{
		{"*:443:www.example.com", 1, siteKey{ip: "*", port: 443, host: "www.example.com", sni: true}},
		{"*:443:WWW.Example.COM", 0, siteKey{ip: "*", port: 443, host: "www.example.com"}},
		{":443:", 0, siteKey{ip: "*", port: 443}},
		{"10.0.0.5:8443:", 0, siteKey{ip: "10.0.0.5", port: 8443}},
		{"[2001:DB8::1]:443:", 0, siteKey{ip: "2001:db8::1", port: 443}},
		{"[::ffff:10.0.0.5]:443:", 0, siteKey{ip: "10.0.0.5", port: 443}},
		{"*:443:www.example.com", 3, siteKey{ip: "*", port: 443, host: "www.example.com", sni: true, ccs: true}},
		{"*:443:", 2, siteKey{ip: "*", port: 443, ccs: true}},
	} {
		got, ok := parseSiteBinding(tc.info, tc.flags)
		require.True(t, ok, tc.info)
		assert.Equal(t, tc.want, got, tc.info)
	}
	for _, tc := range []struct {
		info  string
		flags int
	}{
		{"*:443:", 1}, // SNI without a host: IIS refuses it, a hostile dump
		{"*:443", 0}, {"*:0:", 0}, {"*:70000:", 0}, {"*:x:", 0}, {"10.0.0.300:443:", 0}, {"[::1:443:", 0}, {"[::1]443:", 0},
		{"[nope]:443:", 0}, {"*:443:a/b", 0}, {"*:443:a:b", 0}, {"", 0}, {"[fe80::1%3]:443:", 0},
	} {
		_, ok := parseSiteBinding(tc.info, tc.flags)
		assert.False(t, ok, "%q %d", tc.info, tc.flags)
	}
}

// Review Focus 4: IIS bindings are matched to http.sys entries as http.sys looks them up (Ruling 7).
func TestDiscoverMatchesIISBindings(t *testing.T) {
	type entry struct {
		typ, addr string // addr: ip, host or "" for ccs
		port      int
	}
	v4 := entry{"ipport", "0.0.0.0", 443}
	v6 := entry{"ipport", "::", 443}
	sni := entry{"hostnameport", "www.example.com", 443}
	for _, tc := range []struct {
		name    string
		entries []entry
		info    string
		flags   int
		want    []string // locations whose servers hold the binding
		names   []string
		addr    string
		cut     bool
	}{
		{"sni", []entry{sni, v4}, "*:443:www.example.com", 1, []string{"http.sys/hostnameport/www.example.com:443"}, []string{"www.example.com"}, "*", false},
		{"sni upper case host header", []entry{{"hostnameport", "WWW.Example.com", 443}, v4}, "*:443:WWW.EXAMPLE.COM", 1,
			[]string{"http.sys/hostnameport/www.example.com:443"}, []string{"www.example.com"}, "*", false},
		{"wildcard to both", []entry{v4, v6}, "*:443:", 0, []string{"http.sys/ipport/0.0.0.0:443", "http.sys/ipport/[::]:443"}, []string{}, "*", false},
		{"wildcard to v4 only", []entry{v4}, "*:443:", 0, []string{"http.sys/ipport/0.0.0.0:443"}, []string{}, "*", false},
		{"wildcard to v6 only", []entry{v6}, "*:443:", 0, []string{"http.sys/ipport/[::]:443"}, []string{}, "*", false},
		{"host header without sni", []entry{v4, sni}, "*:443:www.example.com", 0, []string{"http.sys/ipport/0.0.0.0:443"}, []string{"www.example.com"}, "*", false},
		{"specific ip", []entry{{"ipport", "10.0.0.5", 443}, v4}, "10.0.0.5:443:", 0, []string{"http.sys/ipport/10.0.0.5:443"}, []string{}, "10.0.0.5", false},
		{"specific ip falls back", []entry{v4, v6}, "10.0.0.5:443:", 0, []string{"http.sys/ipport/0.0.0.0:443"}, []string{}, "10.0.0.5", false},
		{"ipv6", []entry{{"ipport", "2001:db8::1", 443}, v6, v4}, "[2001:db8::1]:443:", 0, []string{"http.sys/ipport/[2001:db8::1]:443"}, []string{}, "2001:db8::1", false},
		{"ipv6 falls back to [::]", []entry{v6, v4}, "[2001:db8::1]:443:", 0, []string{"http.sys/ipport/[::]:443"}, []string{}, "2001:db8::1", false},
		{"ipv6 falls back to 0.0.0.0", []entry{v4}, "[2001:db8::1]:443:", 0, []string{"http.sys/ipport/0.0.0.0:443"}, []string{}, "2001:db8::1", false},
		{"sni and ccs", []entry{{"ccs", "", 443}, sni, v4}, "*:443:www.example.com", 3, []string{"http.sys/ccs/443"}, []string{"www.example.com"}, "*", false},
		{"other port", []entry{v4, {"ipport", "0.0.0.0", 8443}}, "*:8443:", 0, []string{"http.sys/ipport/0.0.0.0:8443"}, []string{}, "*", false},
		{"sni without host", []entry{sni, v4}, "*:443:", 1, nil, nil, "", true},
	} {
		f := newDump(t)
		for _, e := range tc.entries {
			switch e.typ {
			case "ipport":
				f.ipport(e.addr, e.port)
			case "hostnameport":
				f.sni(e.addr, e.port)
			default:
				f.ccs(e.port)
			}
		}
		f.site("Site A", tc.info, tc.flags)
		certs, warns, _ := f.convert()
		require.Len(t, certs, len(tc.entries), tc.name)
		var used []string
		for _, c := range certs {
			if len(c.Location.Servers) == 0 {
				assert.Equal(t, UnsupportedForeignApp, c.Location.Unsupported, "%s: %s is no IIS binding's", tc.name, c.Location.CertPath)
				continue
			}
			used = append(used, c.Location.CertPath)
			assert.Equal(t, []providers.CertServer{{Names: tc.names, Listens: []providers.CertListen{{Addr: tc.addr, Port: 443 + 8000*boolInt(tc.name == "other port")}},
				Section: "Site A"}}, c.Location.Servers, tc.name)
			assert.NotEqual(t, UnsupportedForeignApp, c.Location.Unsupported, tc.name)
		}
		assert.Equal(t, tc.want, used, tc.name)
		if tc.cut {
			assert.Contains(t, codes(warns), providers.WarnListTruncated, tc.name)
			assert.Contains(t, codes(warns), providers.WarnLocationsDropped, tc.name)
		} else {
			assert.Empty(t, codes(warns), tc.name)
		}
	}
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// Ruling 8, in its order: ccs, foreign application, store, else supported; win_ctl is a warning.
func TestDiscoverSupportedRules(t *testing.T) {
	f := newDump(t)
	f.ccs(443)
	f.site("Web", "*:443:www.example.com", 3)
	winrm, _ := f.cert("My", "winrm")
	f.bind(winproto.SSLBinding{Type: "ipport", IP: "0.0.0.0", Port: 5986, AppID: appWinRM, CertSHA1: winrm, Store: "MY"})
	adfs, _ := f.cert("My", "adfs")
	f.bind(winproto.SSLBinding{Type: "hostnameport", Host: "adfs.example.com", Port: 443, AppID: appUnknown, CertSHA1: adfs, Store: "My"})
	iisx, _ := f.cert("My", "iisexpress")
	f.bind(winproto.SSLBinding{Type: "ipport", IP: "0.0.0.0", Port: 44300, AppID: winproto.AppIDIISExpress, CertSHA1: iisx, Store: "MY"})
	root, _ := f.cert("Root", "rooted")
	f.bind(winproto.SSLBinding{Type: "ipport", IP: "0.0.0.0", Port: 8443, AppID: winproto.AppIDIIS, CertSHA1: root, Store: "Root"})
	f.site("Rooted", "*:8443:", 0)
	hosting, _ := f.cert("webhosting", "hosting")
	f.bind(winproto.SSLBinding{Type: "ipport", IP: "0.0.0.0", Port: 9443, AppID: winproto.AppIDIIS, CertSHA1: hosting, Store: "webhosting"})
	f.site("Hosting", "*:9443:", 0)
	ctl, _ := f.cert("My", "ctl")
	f.bind(winproto.SSLBinding{Type: "ipport", IP: "0.0.0.0", Port: 10443, AppID: winproto.AppIDIIS, CertSHA1: ctl, Store: "My", CTLIdentifier: "Corp CTL", CTLStore: "CA"})
	f.site("Ctl", "*:10443:", 0)
	negotiate, _ := f.cert("My", "negotiate")
	f.bind(winproto.SSLBinding{Type: "ipport", IP: "0.0.0.0", Port: 11443, AppID: winproto.AppIDIIS, CertSHA1: negotiate, Store: "My", Flags: 0x2})
	f.site("Negotiate", "*:11443:", 0)
	mapper, _ := f.cert("My", "mapper")
	f.bind(winproto.SSLBinding{Type: "ipport", IP: "0.0.0.0", Port: 12443, AppID: winproto.AppIDIIS, CertSHA1: mapper, Store: "My", Flags: 0x1})
	f.site("Mapper", "*:12443:", 0)
	http2, _ := f.cert("My", "http2")
	f.bind(winproto.SSLBinding{Type: "ipport", IP: "0.0.0.0", Port: 13443, AppID: winproto.AppIDIIS, CertSHA1: http2, Store: "My", Flags: 0x10})
	f.site("NoHTTP2", "*:13443:", 0)

	certs, _, _ := f.convert()
	m := byPath(certs)
	require.Len(t, m, 10)
	for _, tc := range []struct {
		path, reason, app string
		warns             []string
	}{
		{"http.sys/ccs/443", UnsupportedCCS, "iis", nil},
		{"http.sys/ipport/0.0.0.0:5986", UnsupportedForeignApp, "winrm", nil},
		{"http.sys/hostnameport/adfs.example.com:443", UnsupportedForeignApp, "", nil},
		{"http.sys/ipport/0.0.0.0:44300", UnsupportedForeignApp, "iisexpress", nil},
		{"http.sys/ipport/0.0.0.0:8443", UnsupportedStore, "iis", nil},
		{"http.sys/ipport/0.0.0.0:9443", "", "iis", nil},
		{"http.sys/ipport/0.0.0.0:10443", "", "iis", []string{winproto.WarnCTL}},
		{"http.sys/ipport/0.0.0.0:11443", "", "iis", []string{winproto.WarnCTL}},
		{"http.sys/ipport/0.0.0.0:12443", "", "iis", []string{winproto.WarnCTL}},
		{"http.sys/ipport/0.0.0.0:13443", "", "iis", nil},
	} {
		c, ok := m[tc.path]
		require.True(t, ok, tc.path)
		assert.Equal(t, tc.reason, c.Location.Unsupported, tc.path)
		assert.Equal(t, tc.reason == "", c.Location.Supported, tc.path)
		assert.Equal(t, tc.app, c.Location.Details["application"], tc.path)
		assert.Equal(t, tc.warns, c.Location.Warnings, tc.path)
	}
	assert.Equal(t, appUnknown, m["http.sys/hostnameport/adfs.example.com:443"].Location.Details["app_id"], "the raw id is shown")
	assert.NotEmpty(t, m["http.sys/ipport/0.0.0.0:5986"].PEMChain, "a foreign application's certificate is still read")
	assert.Equal(t, "Corp CTL", m["http.sys/ipport/0.0.0.0:10443"].Location.Details["ctl_identifier"])
	assert.Equal(t, "CA", m["http.sys/ipport/0.0.0.0:10443"].Location.Details["ctl_store"])

	// An IIS Express entry an IIS site binding uses is IIS's (matching is by address, not app id).
	f = newDump(t)
	iisx, _ = f.cert("My", "iisexpress")
	f.bind(winproto.SSLBinding{Type: "ipport", IP: "0.0.0.0", Port: 44300, AppID: winproto.AppIDIISExpress, CertSHA1: iisx, Store: "MY"})
	f.site("Dev", "*:44300:", 0)
	certs, _, _ = f.convert()
	require.Len(t, certs, 1)
	assert.True(t, certs[0].Location.Supported)
	assert.Equal(t, "iisexpress", certs[0].Location.Details["application"])
}

// An http.sys entry with IIS's own application id that no IIS site binding uses is not another application's: the
// reason stays win_foreign_app, the application reads iis_unused (final review M2).
func TestDiscoverUnusedIISBinding(t *testing.T) {
	f := newDump(t)
	f.ipport("0.0.0.0", 8443) // IIS's app id, no site
	f.ipport("0.0.0.0", 443)
	f.site("Web", "*:443:", 0)
	winrm, _ := f.cert("My", "winrm")
	f.bind(winproto.SSLBinding{Type: "ipport", IP: "0.0.0.0", Port: 5986, AppID: appWinRM, CertSHA1: winrm, Store: "MY"})
	m := byPath(must3(f.convert()))
	unused := m["http.sys/ipport/0.0.0.0:8443"].Location
	assert.Equal(t, UnsupportedForeignApp, unused.Unsupported)
	assert.Equal(t, ApplicationIISUnused, unused.Details["application"])
	assert.Equal(t, winproto.AppIDIIS, unused.Details["app_id"])
	assert.Equal(t, "iis", m["http.sys/ipport/0.0.0.0:443"].Location.Details["application"], "a used IIS entry")
	assert.Equal(t, "winrm", m["http.sys/ipport/0.0.0.0:5986"].Location.Details["application"])
	assert.Equal(t, "iis_unused", ApplicationIISUnused)
}

func must3(c []providers.DiscoveredCertificate, _ []providers.Warning, _ providers.WebServerFacts) []providers.DiscoveredCertificate {
	return c
}

// A certificate the store holds but the helper dropped for its bounds is not cert_missing: the dump names it in
// dropped_certificates and the location reads leaf_unreadable (final review M3); a hash the store does not hold
// stays cert_missing.
func TestDiscoverDroppedCertificateIsNotMissing(t *testing.T) {
	f := newDump(t)
	big := strings.Repeat("cd", 20)
	f.bind(winproto.SSLBinding{Type: "ipport", IP: "0.0.0.0", Port: 443, AppID: winproto.AppIDIIS, CertSHA1: big, Store: "My"})
	f.site("Big", "*:443:", 0)
	f.bind(winproto.SSLBinding{Type: "ipport", IP: "0.0.0.0", Port: 8443, AppID: winproto.AppIDIIS, CertSHA1: strings.Repeat("ab", 20), Store: "My"})
	f.site("Gone", "*:8443:", 0)
	f.d.DroppedCertificates = []winproto.CertificateRef{{Store: "MY", SHA1: strings.Repeat("CD", 20)}} // store and hex case vary
	f.d.Truncated, f.d.Warnings = true, []string{winproto.WarnListTruncated}
	certs, warns, _ := f.convert()
	m := byPath(certs)
	dropped := m["http.sys/ipport/0.0.0.0:443"]
	assert.Equal(t, providers.CertProblemLeafUnreadable, dropped.Location.Problem)
	assert.Equal(t, providers.UnsupportedFile, dropped.Location.Unsupported)
	assert.Nil(t, dropped.PEMChain)
	assert.Equal(t, ProblemCertMissing, m["http.sys/ipport/0.0.0.0:8443"].Location.Problem)
	assert.Contains(t, codes(warns), providers.WarnLocationsDropped, "a cut dump still marks nothing missing")
}

// Ruling 9: certificate problems in Problem, key problems in KeyProblem; the certificate of a key
// problem stays linked.
func TestDiscoverProblems(t *testing.T) {
	f := newDump(t)
	f.bind(winproto.SSLBinding{Type: "ipport", IP: "0.0.0.0", Port: 443, AppID: winproto.AppIDIIS, CertSHA1: strings.Repeat("ab", 20), Store: "My"})
	f.site("Gone", "*:443:", 0)
	noKey, _ := f.cert("My", "nokey", func(c *winproto.StoreCertificate) {
		c.HasKey, c.KeyProvider, c.KeyUsableBySystem, c.KeyProblem = false, "", nil, "key_missing"
	})
	f.bind(winproto.SSLBinding{Type: "ipport", IP: "0.0.0.0", Port: 8443, AppID: winproto.AppIDIIS, CertSHA1: noKey, Store: "My"})
	f.site("NoKey", "*:8443:", 0)
	no := false
	locked, _ := f.cert("My", "locked", func(c *winproto.StoreCertificate) { c.KeyUsableBySystem, c.KeyProblem = &no, "key_inaccessible" })
	f.bind(winproto.SSLBinding{Type: "ipport", IP: "0.0.0.0", Port: 9443, AppID: winproto.AppIDIIS, CertSHA1: locked, Store: "My"})
	f.site("Locked", "*:9443:", 0)
	silent, _ := f.cert("My", "silent", func(c *winproto.StoreCertificate) { c.HasKey = false })
	f.bind(winproto.SSLBinding{Type: "ipport", IP: "0.0.0.0", Port: 10443, AppID: winproto.AppIDIIS, CertSHA1: silent, Store: "My"})
	f.site("Silent", "*:10443:", 0)
	odd, _ := f.cert("My", "odd", func(c *winproto.StoreCertificate) { c.KeyProblem = "key_on_fire" })
	f.bind(winproto.SSLBinding{Type: "ipport", IP: "0.0.0.0", Port: 11443, AppID: winproto.AppIDIIS, CertSHA1: odd, Store: "My"})
	f.site("Odd", "*:11443:", 0)
	f.site("Missing", "*:12443:shop.example.com", 1)
	f.site("Missing", "*:12443:SHOP.example.com", 1) // the same server, listed once
	f.site("Other", "*:12443:shop.example.com", 1)
	f.site("MissingCCS", "*:14443:", 2)
	f.site("MissingIP", "10.0.0.9:15443:", 0)
	f.site("MissingAny", "*:16443:", 0)

	certs, warns, _ := f.convert()
	assert.Empty(t, warns)
	m := byPath(certs)
	require.Len(t, m, 9)

	gone := m["http.sys/ipport/0.0.0.0:443"]
	assert.Equal(t, ProblemCertMissing, gone.Location.Problem)
	assert.Equal(t, providers.UnsupportedFile, gone.Location.Unsupported)
	assert.False(t, gone.Location.Supported)
	assert.Nil(t, gone.PEMChain)
	assert.Empty(t, gone.FileSHA256)
	assert.Equal(t, strings.Repeat("ab", 20), gone.Location.Details["cert_sha1"])
	assert.NotContains(t, gone.Location.Details, "friendly_name", "nothing of a certificate that is not there")

	for path, want := range map[string]string{"http.sys/ipport/0.0.0.0:8443": ProblemKeyMissing, "http.sys/ipport/0.0.0.0:9443": ProblemKeyInaccessible,
		"http.sys/ipport/0.0.0.0:10443": ProblemKeyMissing, "http.sys/ipport/0.0.0.0:11443": providers.CertProblemUnknown} {
		c := m[path]
		assert.Equal(t, want, c.Location.KeyProblem, path)
		assert.Empty(t, c.Location.Problem, path)
		assert.Equal(t, providers.UnsupportedFile, c.Location.Unsupported, path)
		assert.NotEmpty(t, c.PEMChain, "%s: the certificate is still linked", path)
		assert.Len(t, c.FileSHA256, 64, path)
	}
	assert.Equal(t, false, m["http.sys/ipport/0.0.0.0:9443"].Location.Details["key_usable_by_system"])

	missing := m["http.sys/hostnameport/shop.example.com:12443"]
	assert.Equal(t, ProblemCertMissing, missing.Location.Problem)
	assert.Equal(t, providers.UnsupportedFile, missing.Location.Unsupported)
	assert.Equal(t, providers.Locator{"type": "hostnameport", "host": "shop.example.com", "port": 12443, "app_id": winproto.AppIDIIS}, missing.Location.Locator,
		"the locator IIS Manager writes when a certificate is chosen")
	assert.Equal(t, map[string]any{"app_id": winproto.AppIDIIS, "application": "iis"}, missing.Location.Details)
	assert.Equal(t, []providers.CertServer{
		{Names: []string{"shop.example.com"}, Listens: []providers.CertListen{{Addr: "*", Port: 12443}}, Section: "Missing"},
		{Names: []string{"shop.example.com"}, Listens: []providers.CertListen{{Addr: "*", Port: 12443}}, Section: "Other"},
	}, missing.Location.Servers, "sorted by site, the same binding once")
	assert.Nil(t, missing.PEMChain)

	ccs := m["http.sys/ccs/14443"]
	assert.Equal(t, UnsupportedCCS, ccs.Location.Unsupported)
	assert.Equal(t, ProblemCertMissing, ccs.Location.Problem)
	assert.Equal(t, providers.Locator{"type": "ccs", "port": 14443, "app_id": winproto.AppIDIIS}, ccs.Location.Locator)
	assert.Equal(t, ProblemCertMissing, m["http.sys/ipport/10.0.0.9:15443"].Location.Problem, "a specific address without an entry or a fallback")
	assert.Equal(t, ProblemCertMissing, m["http.sys/ipport/0.0.0.0:16443"].Location.Problem, "* is 0.0.0.0 when nothing is bound")
}

func TestDiscoverCertificateChainAndToken(t *testing.T) {
	f := newDump(t)
	sha, der := f.cert("My", "www.example.com", func(c *winproto.StoreCertificate) { c.FriendlyName, c.KeyExportable = "Web 2026", true })
	f.bind(winproto.SSLBinding{Type: "hostnameport", Host: "www.example.com", Port: 443, AppID: winproto.AppIDIIS, CertSHA1: sha, Store: "MY",
		Flags: 0x10, CertCheckMode: 4})
	f.site("Web", "*:443:www.example.com", 1)
	certs, _, _ := f.convert()
	require.Len(t, certs, 1)
	c := certs[0]
	assert.True(t, c.Location.Supported)
	assert.Equal(t, derSHA256(der), c.FileSHA256, "the CAS token is the DER's SHA-256")
	var chain []*x509.Certificate
	for rest := c.PEMChain; ; {
		var b *pem.Block
		if b, rest = pem.Decode(rest); b == nil {
			break
		}
		x, err := x509.ParseCertificate(b.Bytes)
		require.NoError(t, err)
		chain = append(chain, x)
	}
	require.Len(t, chain, 2)
	assert.Equal(t, der, chain[0].Raw)
	assert.Equal(t, f.ca.Intermediate.Raw, chain[1].Raw)
	assert.Equal(t, map[string]any{"store": "MY", "cert_sha1": sha, "app_id": winproto.AppIDIIS, "application": "iis", "friendly_name": "Web 2026",
		"key_provider": "Microsoft Software Key Storage Provider", "key_exportable": true, "key_usable_by_system": true, "flags": uint32(0x10),
		"cert_check_mode": uint32(4), "ctl_identifier": "", "ctl_store": ""}, c.Location.Details)
	assert.Equal(t, providers.Locator{"type": "hostnameport", "host": "www.example.com", "port": 443, "app_id": winproto.AppIDIIS}, c.Location.Locator)

	// The store compares case-insensitively; the certificate is looked up by (folded store, sha1).
	f = newDump(t)
	sha, _ = f.cert("WebHosting", "hosting")
	f.bind(winproto.SSLBinding{Type: "ipport", IP: "0.0.0.0", Port: 443, AppID: winproto.AppIDIIS, CertSHA1: sha, Store: "WEBHOSTING"})
	f.bind(winproto.SSLBinding{Type: "ipport", IP: "::", Port: 443, AppID: winproto.AppIDIIS, CertSHA1: sha, Store: "webhosting"})
	f.bind(winproto.SSLBinding{Type: "ipport", IP: "10.0.0.1", Port: 443, AppID: winproto.AppIDIIS, CertSHA1: sha, Store: "My"})
	null, _ := f.cert("MY", "null")
	f.bind(winproto.SSLBinding{Type: "ipport", IP: "10.0.0.2", Port: 443, AppID: winproto.AppIDIIS, CertSHA1: null, Store: ""})
	f.site("Web", "*:443:", 0)
	f.site("Web", "10.0.0.1:443:", 0)
	f.site("Web", "10.0.0.2:443:", 0)
	certs, _, _ = f.convert()
	m := byPath(certs)
	assert.NotEmpty(t, m["http.sys/ipport/10.0.0.2:443"].PEMChain, "a NULL store is MY")
	assert.Equal(t, "MY", m["http.sys/ipport/10.0.0.2:443"].Location.Details["store"])
	assert.True(t, m["http.sys/ipport/10.0.0.2:443"].Location.Supported)
	assert.NotEmpty(t, m["http.sys/ipport/0.0.0.0:443"].PEMChain)
	assert.NotEmpty(t, m["http.sys/ipport/[::]:443"].PEMChain)
	assert.Equal(t, ProblemCertMissing, m["http.sys/ipport/10.0.0.1:443"].Location.Problem, "the same hash in another store is not this certificate")

	// A certificate record that is not the certificate: not_a_certificate, nothing linked.
	for name, mod := range map[string]func(*winproto.StoreCertificate){
		"not base64": func(c *winproto.StoreCertificate) { c.DER = "%%%" },
		"too large": func(c *winproto.StoreCertificate) {
			c.DER = strings.Repeat("A", base64.StdEncoding.EncodedLen(winproto.MaxCertDER)+4)
		},
		"not a certificate": func(c *winproto.StoreCertificate) { c.DER = base64.StdEncoding.EncodeToString([]byte("hello")) },
		"another thumbprint": func(c *winproto.StoreCertificate) {
			c.DER = base64.StdEncoding.EncodeToString(derOf(t, f.ca.IntermediatePEM))
		},
	} {
		f = newDump(t)
		sha, _ = f.cert("My", "bad", mod)
		f.bind(winproto.SSLBinding{Type: "ipport", IP: "0.0.0.0", Port: 443, AppID: winproto.AppIDIIS, CertSHA1: sha, Store: "My"})
		f.site("Web", "*:443:", 0)
		certs, _, _ = f.convert()
		require.Len(t, certs, 1, name)
		assert.Equal(t, providers.CertProblemNotACertificate, certs[0].Location.Problem, name)
		assert.Equal(t, providers.UnsupportedFile, certs[0].Location.Unsupported, name)
		assert.Nil(t, certs[0].PEMChain, name)
		assert.Empty(t, certs[0].FileSHA256, name)
	}

	// A chain certificate that does not parse is dropped and said so; too long a chain is too_large.
	f = newDump(t)
	sha, der = f.cert("My", "chain", func(c *winproto.StoreCertificate) {
		c.Chain = append(c.Chain, "%%%", base64.StdEncoding.EncodeToString([]byte("x")))
	})
	f.bind(winproto.SSLBinding{Type: "ipport", IP: "0.0.0.0", Port: 443, AppID: winproto.AppIDIIS, CertSHA1: sha, Store: "My"})
	f.site("Web", "*:443:", 0)
	long, _ := f.cert("My", "long", func(c *winproto.StoreCertificate) {
		for len(c.Chain) <= winproto.MaxChainCerts {
			c.Chain = append(c.Chain, c.Chain[0])
		}
	})
	f.bind(winproto.SSLBinding{Type: "ipport", IP: "0.0.0.0", Port: 8443, AppID: winproto.AppIDIIS, CertSHA1: long, Store: "My"})
	f.site("Web", "*:8443:", 0)
	certs, _, _ = f.convert()
	m = byPath(certs)
	c = m["http.sys/ipport/0.0.0.0:443"]
	assert.True(t, c.Location.Supported)
	assert.Equal(t, []string{providers.WarnCertificateBlockDropped}, c.Location.Warnings)
	assert.Equal(t, 2, strings.Count(string(c.PEMChain), "BEGIN CERTIFICATE"))
	assert.Equal(t, derSHA256(der), c.FileSHA256)
	assert.Equal(t, providers.CertProblemTooLarge, m["http.sys/ipport/0.0.0.0:8443"].Location.Problem)
	assert.Nil(t, m["http.sys/ipport/0.0.0.0:8443"].PEMChain)
}

// Review Focus 2: a cut dump never lets inventory mark stored locations missing.
func TestDiscoverTruncatedDumpDropsLocations(t *testing.T) {
	f := newDump(t)
	f.ipport("0.0.0.0", 443)
	f.site("Web", "*:443:", 0)
	f.d.Truncated = true
	f.d.Warnings = []string{winproto.WarnListTruncated}
	certs, warns, _ := f.convert()
	assert.Len(t, certs, 1)
	assert.Equal(t, []string{providers.WarnListTruncated, providers.WarnLocationsDropped}, codes(warns))

	// list_truncated alone (a helper that did not set truncated) is read the same way.
	f.d.Truncated = false
	_, warns, _ = f.convert()
	assert.Equal(t, []string{providers.WarnListTruncated, providers.WarnLocationsDropped}, codes(warns))
	f.d.Warnings = []string{}
	f.d.Truncated = true
	_, warns, _ = f.convert()
	assert.Equal(t, []string{providers.WarnListTruncated, providers.WarnLocationsDropped}, codes(warns))
}

func TestDiscoverWarningsAndFacts(t *testing.T) {
	f := newDump(t)
	f.d.IIS = winproto.IISFacts{Installed: true, Version: "10.0\x1b[1m", SharedConfig: true, AutoCertRebind: true}
	f.d.ExpiredInStore = map[string]int{"My": 2, "WebHosting": 3, "Bad": -7}
	f.d.Warnings = []string{winproto.WarnSharedConfig, winproto.WarnAutoCertRebind, winproto.WarnSharedConfig, "Bad Code", "x\x1b", winproto.WarnExpiredInStore,
		strings.Repeat("a", 41)}
	certs, warns, facts := f.convert()
	assert.Empty(t, certs)
	assert.Equal(t, providers.WebServerFacts{Software: "iis", Version: "10.0[1m", Found: true, ConfigValid: true}, facts)
	assert.Equal(t, []providers.Warning{
		{Code: winproto.WarnSharedConfig, Params: map[string]string{}},
		{Code: winproto.WarnAutoCertRebind, Params: map[string]string{}},
		{Code: winproto.WarnExpiredInStore, Params: map[string]string{"count": "5"}},
	}, warns)

	// More distinct codes than kept: the rest are cut, the list said to be cut.
	f.d.Warnings = nil
	for i := range maxDumpWarnings + 3 {
		f.d.Warnings = append(f.d.Warnings, "w_"+strings.Repeat("x", i))
	}
	_, warns, _ = f.convert()
	assert.Len(t, warns, maxDumpWarnings+1)
	assert.Equal(t, providers.WarnListTruncated, warns[len(warns)-1].Code)
	assert.NotContains(t, codes(warns), providers.WarnLocationsDropped, "no location was left out")
}

func TestDiscoverCleansHostileText(t *testing.T) {
	f := newDump(t)
	long := strings.Repeat("é", 300)
	sha, _ := f.cert("My", "hostile", func(c *winproto.StoreCertificate) {
		c.FriendlyName = "\x1b[31mWeb\u202e" + long
		c.KeyProvider = "KSP\x00" + long
	})
	f.bind(winproto.SSLBinding{Type: "ipport", IP: "0.0.0.0", Port: 443, AppID: winproto.AppIDIIS, CertSHA1: sha, Store: "My",
		CTLIdentifier: "\x1b]0;" + long, CTLStore: "C\u202eA"})
	f.d.Sites = append(f.d.Sites, winproto.Site{Name: "\x1b[31mSite\u202e" + long, Bindings: []winproto.SiteBinding{{Protocol: "https", Information: "*:443:", SSLFlags: 0},
		{Protocol: "http", Information: "*:80:", SSLFlags: 0}}})
	// An app id outside the GUID shape: the entry is dropped and the list said to be cut.
	f.bind(winproto.SSLBinding{Type: "ipport", IP: "0.0.0.0", Port: 8443, AppID: "{BAD}", CertSHA1: sha, Store: "My"})
	// A store name outside the vocabulary is shown cleaned and is not a supported store.
	f.bind(winproto.SSLBinding{Type: "ipport", IP: "0.0.0.0", Port: 9443, AppID: winproto.AppIDIIS, CertSHA1: sha, Store: "My\x1b\u202e"})
	f.site("Nine", "*:9443:", 0)
	// The same entry twice is one location; the second is dropped.
	f.bind(winproto.SSLBinding{Type: "ipport", IP: "0.0.0.0", Port: 443, AppID: appWinRM, CertSHA1: sha, Store: "My"})
	certs, warns, _ := f.convert()
	require.Len(t, certs, 2)
	assert.Equal(t, []string{providers.WarnListTruncated, providers.WarnLocationsDropped}, codes(warns))
	c := certs[0]
	assert.Equal(t, "http.sys/ipport/0.0.0.0:443", c.Location.CertPath)
	assert.Equal(t, winproto.AppIDIIS, c.Location.Details["app_id"], "the first entry is kept")
	require.Len(t, c.Location.Servers, 1, "only https bindings")
	assert.Equal(t, "[31mSite"+strings.Repeat("é", maxNameLength-len("[31mSite")), c.Location.Servers[0].Section)
	assert.Equal(t, "[31mWeb"+strings.Repeat("é", winproto.MaxText-len("[31mWeb")), c.Location.Details["friendly_name"])
	assert.Equal(t, "KSP"+strings.Repeat("é", winproto.MaxText-3), c.Location.Details["key_provider"])
	assert.Equal(t, "]0;"+strings.Repeat("é", winproto.MaxText-3), c.Location.Details["ctl_identifier"])
	assert.Equal(t, "CA", c.Location.Details["ctl_store"])
	nine := certs[1]
	assert.Equal(t, UnsupportedStore, nine.Location.Unsupported)
	assert.Equal(t, "My", nine.Location.Details["store"])

	// 1000 entries, 501 IIS bindings on one: its servers are cut at 500 and the location says so.
	f = newDump(t)
	sha, _ = f.cert("My", "many")
	for i := range winproto.MaxBindings {
		f.bind(winproto.SSLBinding{Type: "ipport", IP: "0.0.0.0", Port: 1000 + i, AppID: winproto.AppIDIIS, CertSHA1: sha, Store: "My"})
	}
	for i := range maxServersPerLocation + 1 {
		f.site("Site "+strconv.Itoa(i), "*:1000:", 0)
	}
	certs, warns, _ = f.convert()
	require.Len(t, certs, winproto.MaxBindings)
	assert.Empty(t, warns)
	first := byPath(certs)["http.sys/ipport/0.0.0.0:1000"]
	assert.Len(t, first.Location.Servers, maxServersPerLocation)
	assert.Equal(t, []string{providers.WarnListTruncated}, first.Location.Warnings)
	assert.True(t, first.Location.Supported)
	assert.Equal(t, UnsupportedForeignApp, byPath(certs)["http.sys/ipport/0.0.0.0:1001"].Location.Unsupported)

	// More entries than the helper sends: the rest are dropped.
	f.bind(winproto.SSLBinding{Type: "ipport", IP: "0.0.0.0", Port: 3000, AppID: winproto.AppIDIIS, CertSHA1: sha, Store: "My"})
	certs, warns, _ = f.convert()
	assert.Len(t, certs, winproto.MaxBindings)
	assert.Equal(t, []string{providers.WarnListTruncated, providers.WarnLocationsDropped}, codes(warns))
}

// Locations are sorted by their canonical text, servers by site and binding.
func TestDiscoverIsDeterministic(t *testing.T) {
	f := newDump(t)
	f.ipport("0.0.0.0", 8443)
	f.sni("b.example.com", 443)
	f.ipport("::", 443)
	f.sni("a.example.com", 443)
	f.site("Zeta", "*:8443:", 0)
	f.site("Alpha", "*:8443:z.example.com", 0)
	f.site("Alpha", "*:8443:a.example.com", 0)
	certs, _, _ := f.convert()
	var paths []string
	for _, c := range certs {
		paths = append(paths, c.Location.CertPath)
	}
	assert.Equal(t, []string{"http.sys/hostnameport/a.example.com:443", "http.sys/hostnameport/b.example.com:443", "http.sys/ipport/0.0.0.0:8443",
		"http.sys/ipport/[::]:443"}, paths)
	var sections []string
	for _, s := range byPath(certs)["http.sys/ipport/0.0.0.0:8443"].Location.Servers {
		sections = append(sections, s.Section+"/"+strings.Join(s.Names, ","))
	}
	assert.Equal(t, []string{"Alpha/a.example.com", "Alpha/z.example.com", "Zeta/"}, sections)
}

// The missing-entry locations are bounded like the entries.
func TestDiscoverBoundsMissingLocations(t *testing.T) {
	f := newDump(t)
	for i := range winproto.MaxBindings + 1 {
		f.site("Site", "*:"+strconv.Itoa(1000+i)+":", 0)
	}
	certs, warns, _ := f.convert()
	assert.Len(t, certs, winproto.MaxBindings)
	assert.Equal(t, []string{providers.WarnListTruncated, providers.WarnLocationsDropped}, codes(warns))
}
