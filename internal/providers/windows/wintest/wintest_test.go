package wintest

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"alice/internal/providers/linuxssh/linuxsshtest"
	"alice/internal/providers/windows/winhelper"
	"alice/internal/providers/windows/winproto"
	"alice/internal/testutil/pki"
)

var now = time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)

func call(t *testing.T, m *Model, line string) (linuxsshtest.Response, map[string]any) {
	t.Helper()
	r := m.Handler()(line, nil)
	var v map[string]any
	if len(r.Stdout) > 0 {
		if err := json.Unmarshal(r.Stdout, &v); err != nil {
			t.Fatalf("%q answered %q: %v", line, r.Stdout, err)
		}
	}
	return r, v
}

func sum256(raw []byte) string {
	s := sha256.Sum256(raw)
	return hex.EncodeToString(s[:])
}

func yes(b bool) *bool { return &b }

// fixture is a model with the bindings of the selection tests.
type fixture struct {
	m                     *Model
	ca                    *pki.CA
	sni, wild, ip, nokey  pki.Leaf
	unusable, missingLeaf pki.Leaf
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{m: NewModel(), ca: pki.NewCA("Test", pki.ECDSA256, now)}
	f.m.AddIntermediate(f.ca.IntermediatePEM)
	add := func(store string, cn string, key bool, o CertOptions) (pki.Leaf, string) {
		l := f.ca.Issue(pki.Opts{CommonName: cn, SANs: []string{cn}}, now)
		var k []byte
		if key {
			k = l.KeyPEM
		}
		return l, f.m.AddCertificate(store, l.FullchainPEM, k, o)
	}
	var h string
	f.sni, h = add("My", "www.example.test", true, CertOptions{FriendlyName: "sni"})
	f.m.AddBinding(winproto.SSLBinding{Type: "hostnameport", Host: "WWW.Example.test", Port: 443, AppID: winproto.AppIDIIS, CertSHA1: h, Store: "My"})
	f.wild, h = add("My", "wild.example.test", true, CertOptions{})
	// the binding spells the store MY, the certificate went into My
	f.m.AddBinding(winproto.SSLBinding{Type: "ipport", IP: "0.0.0.0", Port: 443, AppID: winproto.AppIDIIS, CertSHA1: h, Store: "MY"})
	f.ip, h = add("My", "ten.example.test", true, CertOptions{})
	f.m.AddBinding(winproto.SSLBinding{Type: "ipport", IP: "10.0.0.5", Port: 443, AppID: winproto.AppIDIIS, CertSHA1: h}) // NULL store: MY
	f.nokey, h = add("My", "nokey.example.test", false, CertOptions{})
	f.m.AddBinding(winproto.SSLBinding{Type: "ipport", IP: "0.0.0.0", Port: 8443, AppID: winproto.AppIDIIS, CertSHA1: h, Store: "My"})
	f.unusable, h = add("My", "unusable.example.test", true, CertOptions{KeyUsableBySystem: yes(false)})
	f.m.AddBinding(winproto.SSLBinding{Type: "ipport", IP: "0.0.0.0", Port: 9443, AppID: winproto.AppIDIIS, CertSHA1: h, Store: "My"})
	f.missingLeaf, h = add("My", "gone.example.test", true, CertOptions{})
	f.m.RemoveCertificate("my", h)
	f.m.AddBinding(winproto.SSLBinding{Type: "ipport", IP: "0.0.0.0", Port: 6443, AppID: winproto.AppIDIIS, CertSHA1: h, Store: "My"})
	f.m.AddBinding(winproto.SSLBinding{Type: "ccs", IP: "0.0.0.0", Port: 7443, AppID: winproto.AppIDIIS})
	f.m.AddBinding(winproto.SSLBinding{Type: "ipport", IP: "::", Port: 5443, AppID: winproto.AppIDIIS, CertSHA1: h, Store: "My"})
	f.m.AddBinding(winproto.SSLBinding{Type: "ipport", IP: "0.0.0.0", Port: 4443, AppID: winproto.AppIDIIS}) // no hash at all
	return f
}

func TestModelDumpMatchesWhatWasAdded(t *testing.T) {
	m := NewModel()
	ca := pki.NewCA("Dump", pki.ECDSA256, now)
	m.AddIntermediate(ca.IntermediatePEM)
	a := ca.Issue(pki.Opts{CommonName: "a.example.test", SANs: []string{"a.example.test"}}, now)
	b := ca.Issue(pki.Opts{CommonName: "b.example.test", SANs: []string{"b.example.test"}}, now)
	ha := m.AddCertificate("My", a.CertPEM, a.KeyPEM, CertOptions{FriendlyName: "A", Exportable: true})
	hb := m.AddCertificate("WebHosting", b.CertPEM, nil, CertOptions{})
	want := []winproto.SSLBinding{
		{Type: "hostnameport", Host: "a.example.test", Port: 443, AppID: winproto.AppIDIIS, CertSHA1: ha, Store: "My"},
		{Type: "ipport", IP: "0.0.0.0", Port: 8443, AppID: winproto.AppIDIIS, CertSHA1: hb, Store: "WebHosting"},
		{Type: "ipport", IP: "0.0.0.0", Port: 5986, AppID: "{afebb9ad-9b97-4a91-9ab5-daf4d59122f6}", CertSHA1: ha, Store: "My"},
		{Type: "ccs", IP: "0.0.0.0", Port: 443, AppID: winproto.AppIDIIS},
	}
	for _, x := range want {
		m.AddBinding(x)
	}
	m.AddSite(winproto.Site{Name: "Shop & Co", ID: 1, State: "Started", Bindings: []winproto.SiteBinding{
		{Protocol: "https", Information: "*:443:a.example.test", SSLFlags: 1}}})
	m.AddSite(winproto.Site{Name: "Intranet", ID: 2, State: "Stopped", Bindings: []winproto.SiteBinding{
		{Protocol: "https", Information: "*:8443:"}}})
	m.SetExpired("my", 2)

	r, _ := call(t, m, "iis-dump")
	if r.Exit != 0 {
		t.Fatalf("exit %d: %s", r.Exit, r.Stdout)
	}
	var d winproto.IISDumpResponse
	if err := json.Unmarshal(r.Stdout, &d); err != nil {
		t.Fatal(err)
	}
	if !d.OK || !d.IIS.Installed || d.IIS.Version != "10.0" || d.Truncated {
		t.Fatalf("dump %+v", d)
	}
	if len(d.Bindings) != 4 {
		t.Fatalf("bindings %+v", d.Bindings)
	}
	for i, x := range want {
		if !reflect.DeepEqual(d.Bindings[i], x) {
			t.Fatalf("binding %d: got %+v want %+v", i, d.Bindings[i], x)
		}
	}
	if len(d.Certificates) != 2 {
		t.Fatalf("certificates %+v", d.Certificates)
	}
	byHash := map[string]winproto.StoreCertificate{}
	for _, c := range d.Certificates {
		byHash[c.SHA1] = c
	}
	ca1, cb := byHash[ha], byHash[hb]
	if ca1.DER != base64.StdEncoding.EncodeToString(a.Cert.Raw) || ca1.SHA256 != sum256(a.Cert.Raw) || ca1.FriendlyName != "A" ||
		!ca1.HasKey || !ca1.KeyExportable || ca1.KeyProvider != "Microsoft Software Key Storage Provider" ||
		ca1.KeyUsableBySystem == nil || !*ca1.KeyUsableBySystem || ca1.KeyProblem != "" ||
		ca1.NotAfter != a.Cert.NotAfter.UTC().Format(time.RFC3339) {
		t.Fatalf("certificate a: %+v", ca1)
	}
	if len(ca1.Chain) != 1 || ca1.Chain[0] != base64.StdEncoding.EncodeToString(ca.Intermediate.Raw) {
		t.Fatalf("chain a (the intermediate, root excluded): %v", ca1.Chain)
	}
	if cb.HasKey || cb.KeyProblem != "key_missing" || cb.Store != "WebHosting" || cb.KeyUsableBySystem != nil {
		t.Fatalf("certificate b: %+v", cb)
	}
	if len(d.Sites) != 2 || d.Sites[0].Name != "Shop & Co" || d.Sites[0].ID != 1 || d.Sites[0].State != "Started" ||
		d.Sites[0].Bindings[0] != (winproto.SiteBinding{Protocol: "https", Information: "*:443:a.example.test", SSLFlags: 1}) ||
		d.Sites[1].State != "Stopped" {
		t.Fatalf("sites %+v", d.Sites)
	}
	if d.ExpiredInStore["My"] != 2 || len(d.Warnings) != 1 || d.Warnings[0] != winproto.WarnExpiredInStore {
		t.Fatalf("expired %v warnings %v", d.ExpiredInStore, d.Warnings)
	}
	// The same XML the helper's parser reads for the stand-alone check.
	x, err := m.Host().AppcmdSites(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if sites, err := winhelper.ParseAppcmdSites(x); err != nil || len(sites) != 2 {
		t.Fatalf("appcmd xml: %v %v", sites, err)
	}
}

// The emulator runs the helper's dump code, so a certificate over the helper's bounds is named in
// dropped_certificates, and one the store does not hold is not (final review M3).
func TestModelDumpNamesDroppedCertificates(t *testing.T) {
	m := NewModel()
	ca := pki.NewCA("Big", pki.ECDSA256, now)
	sans := make([]string, 0, 3000)
	for i := range 3000 {
		sans = append(sans, fmt.Sprintf("name-%04d.big.example.test", i))
	}
	big := ca.Issue(pki.Opts{CommonName: "big.example.test", SANs: sans}, now)
	if len(big.Cert.Raw) <= winproto.MaxCertDER {
		t.Fatalf("the leaf is %d bytes, not over %d", len(big.Cert.Raw), winproto.MaxCertDER)
	}
	h := m.AddCertificate("My", big.CertPEM, big.KeyPEM, CertOptions{})
	m.AddBinding(winproto.SSLBinding{Type: "ipport", IP: "0.0.0.0", Port: 443, AppID: winproto.AppIDIIS, CertSHA1: h, Store: "MY"})
	m.AddBinding(winproto.SSLBinding{Type: "ipport", IP: "0.0.0.0", Port: 8443, AppID: winproto.AppIDIIS, CertSHA1: strings.Repeat("ab", 20), Store: "My"})
	r, _ := call(t, m, "iis-dump")
	var d winproto.IISDumpResponse
	if err := json.Unmarshal(r.Stdout, &d); err != nil || r.Exit != 0 {
		t.Fatalf("exit %d %v: %s", r.Exit, err, r.Stdout)
	}
	if len(d.Certificates) != 0 || !d.Truncated || len(d.DroppedCertificates) != 1 ||
		d.DroppedCertificates[0] != (winproto.CertificateRef{Store: "MY", SHA1: h}) {
		t.Fatalf("certificates %d truncated %v dropped %+v", len(d.Certificates), d.Truncated, d.DroppedCertificates)
	}
}

func TestModelUnusableKeyIsAProblemInTheDump(t *testing.T) {
	m := NewModel()
	ca := pki.NewCA("Key", pki.ECDSA256, now)
	l := ca.Issue(pki.Opts{CommonName: "k.example.test"}, now)
	h := m.AddCertificate("My", l.CertPEM, l.KeyPEM, CertOptions{KeyUsableBySystem: yes(false), KeyProvider: "Custom KSP"})
	c, ok, err := m.Host().Certificate(context.Background(), "my", h)
	if err != nil || !ok || c.KeyProblem != "key_inaccessible" || c.KeyProvider != "Custom KSP" || len(c.Chain) != 0 {
		t.Fatalf("%+v %v %v", c, ok, err)
	}
	if _, ok, _ := m.Host().Certificate(context.Background(), "My", strings.Repeat("0", 40)); ok {
		t.Fatal("an unknown thumbprint is not found")
	}
	if _, ok, _ := m.Host().Certificate(context.Background(), "NoSuchStore", h); ok {
		t.Fatal("an unknown store has nothing")
	}
}

func TestModelFactsAndStores(t *testing.T) {
	m := NewModel()
	r, v := call(t, m, "win-facts")
	if r.Exit != 0 || v["os_build"] != "10.0.20348.2700" || v["os_product"] != "Windows Server 2022 Datacenter" ||
		v["elevated"] != true || v["installation_type"] != "Server" {
		t.Fatalf("%v", v)
	}
	if got := fmt.Sprint(v["stores"]); got != "[My WebHosting CA Root]" {
		t.Fatalf("stores %s: the real helper's order", got)
	}
	m.SetOS(winhelper.OSFacts{Build: "26100", Product: "Windows Server 2025", InstallationType: "Server Core", OpenSSHVersion: "OpenSSH_9.5"})
	m.SetIIS(winproto.IISFacts{})
	_, v = call(t, m, "win-facts")
	if v["os_build"] != "26100" || v["iis"].(map[string]any)["installed"] != false {
		t.Fatalf("%v", v)
	}
	m.AddCertificate("Remote Desktop", pki.SelfSigned("rdp", pki.ECDSA256, now).CertPEM, nil, CertOptions{})
	m.AddCertificate("Test Store", pki.SelfSigned("x", pki.ECDSA256, now).CertPEM, nil, CertOptions{})
	if _, v = call(t, m, "win-facts"); fmt.Sprint(v["stores"]) != "[My WebHosting CA Root Test Store]" {
		t.Fatalf("a new store is listed after the helper's four, Remote Desktop never (the real helper's): %v", v["stores"])
	}
	// IIS missing: the dump still lists the http.sys entries, with no sites, and appcmd is never run.
	m.AddBinding(winproto.SSLBinding{Type: "ccs", IP: "0.0.0.0", Port: 443, AppID: winproto.AppIDIIS})
	r, v = call(t, m, "iis-dump")
	if r.Exit != 0 || len(v["bindings"].([]any)) != 1 || len(v["sites"].([]any)) != 0 {
		t.Fatalf("%d %v", r.Exit, v)
	}
	if _, err := m.Host().AppcmdSites(context.Background()); err == nil {
		t.Fatal("appcmd without IIS must refuse")
	}
	if _, err := m.Host().IISFacts(context.Background()); err == nil {
		t.Fatal("IISFacts without IIS must refuse")
	}
}

func TestModelElevationAndFaults(t *testing.T) {
	m := NewModel()
	m.SetElevated(false)
	if r, v := call(t, m, "iis-dump"); r.Exit != 2 || v["code"] != "NOT_ELEVATED" {
		t.Fatalf("%d %v", r.Exit, v)
	}
	if r, v := call(t, m, "win-facts"); r.Exit != 0 || v["elevated"] != false {
		t.Fatalf("win-facts runs without elevation: %d %v", r.Exit, v)
	}
	m.SetElevated(true)

	m.FailAppcmd(true)
	if r, v := call(t, m, "iis-dump"); r.Exit != 4 || v["code"] != "IO_ERROR" {
		t.Fatalf("%d %v", r.Exit, v)
	}
	m.FailAppcmd(false)
	if r, _ := call(t, m, "iis-dump"); r.Exit != 0 {
		t.Fatalf("exit %d", r.Exit)
	}

	m.SetProtocol(0)
	if r, v := call(t, m, "version"); r.Exit != 0 || v["protocol"] != float64(0) || v["helper"] != winproto.Version || v["ok"] != true {
		t.Fatalf("%d %v", r.Exit, v)
	}
	m.SetProtocol(winproto.Protocol)
	if _, v := call(t, m, "version"); v["protocol"] != float64(winproto.Protocol) {
		t.Fatalf("%v", v)
	}

	for _, set := range []func(*Model, bool){(*Model).SetHelperMissing, (*Model).SetNoForcedCommand} {
		m2 := NewModel()
		set(m2, true)
		r := m2.Handler()("version", nil)
		if r.Exit != 1 || len(r.Stdout) != 0 || !strings.Contains(string(r.Stderr), "'version' is not recognized") {
			t.Fatalf("%d %q %q", r.Exit, r.Stdout, r.Stderr)
		}
		set(m2, false)
		if r := m2.Handler()("version", nil); r.Exit != 0 {
			t.Fatalf("restored: %d", r.Exit)
		}
	}

	m.Delay("iis-dump", 250*time.Millisecond)
	if r, _ := call(t, m, "iis-dump"); r.Delay != 250*time.Millisecond {
		t.Fatalf("delay %v", r.Delay)
	}
	if r, _ := call(t, m, "version"); r.Delay != 0 {
		t.Fatalf("another subcommand is not delayed: %v", r.Delay)
	}
	if r, v := call(t, m, "no-such-sub"); r.Exit != 2 || v["code"] != "UNKNOWN_SUBCOMMAND" {
		t.Fatalf("%d %v", r.Exit, v)
	}
	if r, v := call(t, m, "version; calc"); r.Exit != 2 || v["code"] != "INVALID_ARGUMENT" {
		t.Fatalf("%d %v", r.Exit, v)
	}
}

func tlsDial(t *testing.T, addr, sni string) (*tls.ConnectionState, error) {
	t.Helper()
	d := &tls.Dialer{Config: &tls.Config{ServerName: sni, InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}} //nolint:gosec // G402: the test compares the served leaf
	c, err := d.DialContext(context.Background(), "tcp", addr)
	if err != nil {
		return nil, err
	}
	defer func() { _ = c.Close() }()
	cs := c.(*tls.Conn).ConnectionState()
	return &cs, nil
}

func TestModelServesHTTPSysSelection(t *testing.T) {
	f := newFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	if err := f.m.Serve(ctx, "127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cancel(); f.m.serving.Wait() })

	leaf := func(l pki.Leaf) string { return sum256(l.Cert.Raw) }
	cases := []struct {
		name, ip, sni string
		port          int
		want          string // "" handshake fails
	}{
		{"SNI entry (host folded)", "127.0.0.1", "www.example.test", 443, leaf(f.sni)},
		{"SNI in capitals", "127.0.0.1", "WWW.EXAMPLE.TEST", 443, leaf(f.sni)},
		{"other SNI falls to the wildcard", "127.0.0.1", "other.example.test", 443, leaf(f.wild)},
		{"no SNI", "127.0.0.1", "", 443, leaf(f.wild)},
		{"ipport entry beats the wildcard", "10.0.0.5", "", 443, leaf(f.ip)},
		{"a hostnameport entry beats the ipport one", "10.0.0.5", "www.example.test", 443, leaf(f.sni)},
		{"key missing", "127.0.0.1", "", 8443, ""},
		{"key not usable by SYSTEM", "127.0.0.1", "", 9443, ""},
		{"certificate missing", "127.0.0.1", "", 6443, ""},
		{"ccs alone serves nothing", "127.0.0.1", "", 7443, ""},
		{"an entry without a hash", "127.0.0.1", "", 4443, ""},
		{"the IPv6 wildcard also serves", "127.0.0.1", "", 5443, ""}, // names the missing certificate
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			gotSHA, n, ok := f.m.Served(c.ip, c.port, c.sni)
			if ok != (c.want != "") || gotSHA != c.want {
				t.Fatalf("Served = %q %d %v, want %q", gotSHA, n, ok, c.want)
			}
			ep := f.m.Endpoint(c.port)
			if ep == "" {
				t.Fatalf("no listener for %d", c.port)
			}
			// The real handshake. A client dial through the host keeps the address it meant (10.0.0.5).
			conn, err := f.m.Host().Dial(context.Background(), "tcp", c.ip+":"+strconv.Itoa(c.port))
			if err != nil {
				t.Fatal(err)
			}
			tc := tls.Client(conn, &tls.Config{ServerName: c.sni, InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}) //nolint:gosec // G402: the test compares the served leaf
			err = tc.HandshakeContext(context.Background())
			if c.want == "" {
				if err == nil {
					t.Fatal("the handshake must fail")
				}
				_ = conn.Close()
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			certs := tc.ConnectionState().PeerCertificates
			_ = conn.Close()
			if sum256(certs[0].Raw) != c.want || len(certs) != n || n != 2 {
				t.Fatalf("dial saw %s with %d certificates; Served said %s %d", sum256(certs[0].Raw), len(certs), c.want, n)
			}
			// And a plain tls.Dial to the listener (no intent): same answer for the SNI/wildcard cases.
			if c.ip == "127.0.0.1" {
				cs, err := tlsDial(t, ep, c.sni)
				if err != nil || sum256(cs.PeerCertificates[0].Raw) != c.want {
					t.Fatalf("plain dial: %v", err)
				}
			}
		})
	}
	// The same wildcard answers an IPv4 connection when only [::] exists? No: 5443 names a removed certificate.
	if _, _, ok := f.m.Served("2001:db8::1", 5443, ""); ok {
		t.Fatal("a missing certificate fails on the IPv6 wildcard too")
	}
	if f.m.Endpoint(12345) != "" {
		t.Fatal("no listener for a port without bindings")
	}
	if _, _, ok := f.m.Served("127.0.0.1", 12345, ""); ok {
		t.Fatal("nothing is served on a port without bindings")
	}
}

func TestModelIPv6WildcardAndMappedAddresses(t *testing.T) {
	m := NewModel()
	ca := pki.NewCA("v6", pki.ECDSA256, now)
	l := ca.Issue(pki.Opts{CommonName: "v6.example.test"}, now)
	h := m.AddCertificate("My", l.CertPEM, l.KeyPEM, CertOptions{})
	m.AddBinding(winproto.SSLBinding{Type: "ipport", IP: "::", Port: 443, AppID: winproto.AppIDIIS, CertSHA1: h, Store: "My"})
	m.AddBinding(winproto.SSLBinding{Type: "ipport", IP: "fe80::1", Port: 444, AppID: winproto.AppIDIIS, CertSHA1: h})
	for _, ip := range []string{"2001:db8::1", "10.1.1.1", "::ffff:10.1.1.1"} {
		if s, n, ok := m.Served(ip, 443, ""); !ok || s != sum256(l.Cert.Raw) || n != 1 {
			t.Fatalf("%s: %q %d %v", ip, s, n, ok)
		}
	}
	if _, _, ok := m.Served("fe80::1", 444, ""); !ok {
		t.Fatal("an exact IPv6 entry serves")
	}
	if _, _, ok := m.Served("fe80::2", 444, ""); ok {
		t.Fatal("another address has no entry")
	}
	if _, _, ok := m.Served("not-an-ip", 444, ""); ok {
		t.Fatal("an unparsable address matches no exact entry")
	}
}

func TestModelTLSProbeThroughTheHelperCode(t *testing.T) {
	f := newFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	if err := f.m.Serve(ctx, "127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cancel(); f.m.serving.Wait() })

	cs, err := tlsDial(t, f.m.Endpoint(443), "www.example.test")
	if err != nil {
		t.Fatal(err)
	}
	r, v := call(t, f.m, "tls-probe --addr 127.0.0.1 --port 443 --sni www.example.test --key-type any")
	if r.Exit != 0 || v["leaf_sha256"] != sum256(cs.PeerCertificates[0].Raw) || v["chain_length"] != float64(len(cs.PeerCertificates)) {
		t.Fatalf("%d %v (direct %s %d)", r.Exit, v, sum256(cs.PeerCertificates[0].Raw), len(cs.PeerCertificates))
	}
	// The probe's address reaches the ipport entry for it.
	_, v = call(t, f.m, "tls-probe --addr 10.0.0.5 --port 443 --sni _ --key-type any")
	if v["leaf_sha256"] != sum256(f.ip.Cert.Raw) {
		t.Fatalf("%v", v)
	}
	// No SNI: the wildcard binding.
	_, v = call(t, f.m, "tls-probe --addr 127.0.0.1 --port 443 --sni _ --key-type ecdsa")
	if v["leaf_sha256"] != sum256(f.wild.Cert.Raw) {
		t.Fatalf("%v", v)
	}
	// A failing handshake and an unserved port are PROBE_FAILED.
	for _, line := range []string{
		"tls-probe --addr 127.0.0.1 --port 8443 --sni _ --key-type any",
		"tls-probe --addr 127.0.0.1 --port 12345 --sni _ --key-type any",
	} {
		if r, v := call(t, f.m, line); r.Exit != 4 || v["code"] != "PROBE_FAILED" {
			t.Fatalf("%s: %d %v", line, r.Exit, v)
		}
	}
	if _, err := f.m.Host().Dial(context.Background(), "tcp", "no-port"); err == nil {
		t.Fatal("an address without a port must fail")
	}
	if _, err := f.m.Host().Dial(context.Background(), "tcp", "127.0.0.1:http"); err == nil {
		t.Fatal("a non-numeric port must fail")
	}
}

func TestServeBindAndErrors(t *testing.T) {
	m := NewModel()
	if err := m.Serve(context.Background(), "127.0.0.1:99"); err == nil {
		t.Fatal("a fixed port in bind is refused")
	}
	l := pki.SelfSigned("x", pki.ECDSA256, now)
	h := m.AddCertificate("My", l.CertPEM, l.KeyPEM, CertOptions{})
	m.AddBinding(winproto.SSLBinding{Type: "ipport", IP: "0.0.0.0", Port: 443, AppID: winproto.AppIDIIS, CertSHA1: h, Store: "My"})
	if err := m.Serve(context.Background(), "256.1.1.1:0"); err == nil {
		t.Fatal("an unusable address fails")
	}
	if m.Endpoint(443) != "" {
		t.Fatal("a failed Serve leaves no endpoint")
	}
	// A bare host listens on the binding port itself; a taken port is an error and leaves nothing behind.
	ctx, cancel := context.WithCancel(context.Background())
	if err := m.Serve(ctx, "127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cancel(); m.serving.Wait() })
	port := m.Endpoint(443)
	_, p, _ := strings.Cut(port, "127.0.0.1:")
	m2 := NewModel()
	m2.AddBinding(winproto.SSLBinding{Type: "ccs", IP: "0.0.0.0", Port: mustAtoi(t, p), AppID: winproto.AppIDIIS})
	m2.AddBinding(winproto.SSLBinding{Type: "ccs", IP: "0.0.0.0", Port: 1, AppID: winproto.AppIDIIS}) // second listener first fails? port 1 is refused or taken
	if err := m2.Serve(context.Background(), "127.0.0.1"); err == nil {
		t.Fatal("a taken or privileged binding port must fail the Serve")
	}
}

func mustAtoi(t *testing.T, s string) int {
	t.Helper()
	n, err := strconv.Atoi(s)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func TestServeBareHostUsesTheBindingPorts(t *testing.T) {
	// Find a free port, then bind to it by name.
	probe := NewModel()
	l := pki.SelfSigned("x", pki.ECDSA256, now)
	h := probe.AddCertificate("My", l.CertPEM, l.KeyPEM, CertOptions{})
	probe.AddBinding(winproto.SSLBinding{Type: "ipport", IP: "0.0.0.0", Port: 1, AppID: winproto.AppIDIIS, CertSHA1: h})
	ctx, cancel := context.WithCancel(context.Background())
	if err := probe.Serve(ctx, "127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	_, portText, _ := strings.Cut(probe.Endpoint(1), "127.0.0.1:")
	cancel()
	probe.serving.Wait()

	m := NewModel()
	m.AddCertificate("My", l.CertPEM, l.KeyPEM, CertOptions{})
	port := mustAtoi(t, portText)
	m.AddBinding(winproto.SSLBinding{Type: "ipport", IP: "0.0.0.0", Port: port, AppID: winproto.AppIDIIS, CertSHA1: h, Store: "My"})
	ctx2, cancel2 := context.WithCancel(context.Background())
	if err := m.Serve(ctx2, "127.0.0.1"); err != nil {
		t.Skipf("the free port was taken meanwhile: %v", err)
	}
	t.Cleanup(func() { cancel2(); m.serving.Wait() })
	if m.Endpoint(port) != "127.0.0.1:"+portText {
		t.Fatalf("endpoint %q", m.Endpoint(port))
	}
	if cs, err := tlsDial(t, "127.0.0.1:"+portText, ""); err != nil || sum256(cs.PeerCertificates[0].Raw) != sum256(l.Cert.Raw) {
		t.Fatalf("%v", err)
	}
}

func TestDemoHost(t *testing.T) {
	m, err := Demo(now)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.CARootPEM()) == 0 {
		t.Fatal("the demo CA root is exposed")
	}
	_, v := call(t, m, "win-facts")
	if v["os_product"] != "Windows Server 2022 Datacenter" || v["os_build"] != "10.0.20348.2700" || v["elevated"] != true ||
		v["iis"].(map[string]any)["version"] != "10.0" {
		t.Fatalf("%v", v)
	}
	r, _ := call(t, m, "iis-dump")
	var d winproto.IISDumpResponse
	if err := json.Unmarshal(r.Stdout, &d); err != nil || r.Exit != 0 {
		t.Fatalf("%v %d", err, r.Exit)
	}
	type bk struct {
		typ, host, ip string
		port          int
		app, store    string
	}
	var got []bk
	for _, b := range d.Bindings {
		got = append(got, bk{b.Type, b.Host, b.IP, b.Port, b.AppID, b.Store})
	}
	wantB := []bk{
		{"hostnameport", "www.win.example.test", "", 443, winproto.AppIDIIS, "My"},
		{"ipport", "", "0.0.0.0", 8443, winproto.AppIDIIS, "WebHosting"},
		{"ipport", "", "0.0.0.0", 5986, "{afebb9ad-9b97-4a91-9ab5-daf4d59122f6}", "My"},
		{"ccs", "", "0.0.0.0", 443, winproto.AppIDIIS, ""},
		{"ipport", "", "0.0.0.0", 9444, winproto.AppIDIIS, "My"},
	}
	if len(got) != len(wantB) {
		t.Fatalf("bindings %+v", got)
	}
	for i := range wantB {
		if got[i] != wantB[i] {
			t.Fatalf("binding %d: %+v want %+v", i, got[i], wantB[i])
		}
	}
	if len(d.Sites) != 4 || d.Sites[3].Name != "WinRM Journey" || d.Sites[3].Bindings[0].Information != "*:9444:" || d.Sites[0].Name != "Default Web Site" || d.Sites[0].Bindings[0].Information != "*:443:www.win.example.test" ||
		d.Sites[0].Bindings[0].SSLFlags != 1 || d.Sites[1].Name != "Intranet" || d.Sites[1].Bindings[0].Information != "*:8443:" ||
		d.Sites[1].Bindings[0].SSLFlags != 0 {
		t.Fatalf("sites %+v", d.Sites)
	}
	if len(d.Certificates) != 4 {
		t.Fatalf("certificates %d", len(d.Certificates))
	}
	for _, c := range d.Certificates {
		if len(c.Chain) != 1 || !c.HasKey || c.KeyProblem != "" {
			t.Fatalf("certificate %s: %+v", c.SHA1, c)
		}
	}
	// Served with a chain of two (leaf and intermediate), WinRM's foreign certificate included.
	for _, c := range []struct {
		port int
		sni  string
	}{{443, "www.win.example.test"}, {8443, ""}, {5986, ""}, {9444, ""}} {
		if _, n, ok := m.Served("0.0.0.0", c.port, c.sni); !ok || n != 2 {
			t.Fatalf("%d: %d %v", c.port, n, ok)
		}
	}
	// Without the SNI the port-443 entries serve nothing: only a ccs entry is left.
	if _, _, ok := m.Served("0.0.0.0", 443, ""); ok {
		t.Fatal("443 without the host name is the ccs entry")
	}
}

func TestSSHServerModelsSingleSessionCommands(t *testing.T) {
	m := NewModel()
	srv := NewServer(t, m)
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := ssh.NewSignerFromKey(priv)
	srv.Authorize(signer.PublicKey())
	host, port := srv.Addr()
	c, err := ssh.Dial("tcp", host+":"+strconv.Itoa(port), &ssh.ClientConfig{User: "alice", Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.FixedHostKey(srv.HostKey())})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	run := func(cmd string) string {
		s, err := c.NewSession()
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = s.Close() }()
		out, err := s.Output(cmd)
		if err != nil {
			t.Fatal(err)
		}
		return string(out)
	}
	first := run("version")
	second := run("win-facts")
	if !strings.Contains(first, `"protocol":1`) || second != first {
		t.Fatalf("the second session on a connection answers as version did:\nfirst  %q\nsecond %q", first, second)
	}
	if cmds := srv.Commands(); len(cmds) != 2 || cmds[1] != "win-facts" {
		t.Fatalf("Commands keeps what was sent: %v", cmds)
	}
	// A fresh connection starts over, and sees its own first command.
	c2, err := ssh.Dial("tcp", host+":"+strconv.Itoa(port), &ssh.ClientConfig{User: "alice", Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.FixedHostKey(srv.HostKey())})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c2.Close() }()
	s, _ := c2.NewSession()
	out, err := s.Output("win-facts")
	_ = s.Close()
	if err != nil || !strings.Contains(string(out), `"os_build"`) {
		t.Fatalf("%v %q", err, out)
	}
	if srv.Connections() != 2 {
		t.Fatalf("connections %d", srv.Connections())
	}
}

func TestNewServerServesTheBindingsItHas(t *testing.T) {
	m, err := Demo(now)
	if err != nil {
		t.Fatal(err)
	}
	NewServer(t, m)
	for _, p := range []int{443, 8443, 5986, 9444} {
		if m.Endpoint(p) == "" {
			t.Fatalf("no listener for %d", p)
		}
	}
	cs, err := tlsDial(t, m.Endpoint(443), "www.win.example.test")
	if err != nil || len(cs.PeerCertificates) != 2 {
		t.Fatalf("%v", err)
	}
}
