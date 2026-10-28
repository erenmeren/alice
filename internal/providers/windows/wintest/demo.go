package wintest

import (
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"time"

	"alice/internal/providers/windows/winproto"
	"alice/internal/testutil/pki"
)

// demoCCSPath is the demo host's CCS folder.
const demoCCSPath = `C:\CCS`

// demoRDPPort is the demo's RDP-Tcp port (W6 Ruling 25: fakewindows:3389 in the container).
const demoRDPPort = 3389

// Demo builds the fixed host of the e2e journey (Task 15): Windows Server 2022 Datacenter
// 10.0.20348.2700 with IIS 10.0; the sites "Default Web Site" (https *:443:www.win.example.test, SNI),
// "Intranet" (https *:8443:) and "CCS Site" (https *:443:ccs.example.test, sslFlags 3: SNI and CCS); the
// http.sys entries hostnameport www.win.example.test:443 (IIS, My), ipport 0.0.0.0:8443 (IIS, WebHosting),
// ipport 0.0.0.0:5986 (WinRM: a foreign application) and ccs 443. The Centralized Certificate Store is on
// at demoCCSPath with ccs.example.test.pfx (linked by the CCS Site binding) and _.unlinked.test.pfx (no
// binding), under a password generated now (CCSPassword; W5 Ruling 25). The RDP-Tcp listener (W6 Ruling
// 25) is on port 3389: enabled, security layer 2, NLA on, the value absent, with one self-signed
// certificate in Remote Desktop whose key NETWORK SERVICE can read. The other certificates come from a
// test CA generated now (leaf and intermediate); CARootPEM is its root.
func Demo(now time.Time) (m *Model, err error) {
	defer func() {
		if r := recover(); r != nil { // pki panics on a crypto failure
			m, err = nil, fmt.Errorf("wintest: demo host: %v", r)
		}
	}()
	ca := pki.NewCA("Win Demo CA", pki.ECDSA256, now)
	m = NewModel()
	m.mu.Lock()
	m.root = ca.RootPEM
	m.mu.Unlock()
	m.AddIntermediate(ca.IntermediatePEM)

	issue := func(store, cn string, friendly string) string {
		l := ca.Issue(pki.Opts{CommonName: cn, SANs: []string{cn}}, now)
		return m.AddCertificate(store, l.CertPEM, l.KeyPEM, CertOptions{FriendlyName: friendly})
	}
	web := issue("My", "www.win.example.test", "www.win.example.test")
	intranet := issue("WebHosting", "intranet.win.example.test", "Intranet")
	winrm := issue("My", "win-demo01", "WinRM")

	const winrmApp = "{afebb9ad-9b97-4a91-9ab5-daf4d59122f6}"
	m.AddBinding(winproto.SSLBinding{Type: winproto.BindingHostnamePort, Host: "www.win.example.test", Port: 443,
		AppID: winproto.AppIDIIS, CertSHA1: web, Store: "My"})
	m.AddBinding(winproto.SSLBinding{Type: winproto.BindingIPPort, IP: "0.0.0.0", Port: 8443,
		AppID: winproto.AppIDIIS, CertSHA1: intranet, Store: "WebHosting"})
	m.AddBinding(winproto.SSLBinding{Type: winproto.BindingIPPort, IP: "0.0.0.0", Port: 5986,
		AppID: winrmApp, CertSHA1: winrm, Store: "My"})
	m.AddBinding(winproto.SSLBinding{Type: winproto.BindingCCS, IP: "0.0.0.0", Port: 443, AppID: winproto.AppIDIIS})

	m.AddSite(winproto.Site{Name: "Default Web Site", ID: 1, State: "Started", Bindings: []winproto.SiteBinding{
		{Protocol: "https", Information: "*:443:www.win.example.test", SSLFlags: 1}}})
	m.AddSite(winproto.Site{Name: "Intranet", ID: 2, State: "Started", Bindings: []winproto.SiteBinding{
		{Protocol: "https", Information: "*:8443:", SSLFlags: 0}}})
	m.AddSite(winproto.Site{Name: "CCS Site", ID: 3, State: "Started", Bindings: []winproto.SiteBinding{
		{Protocol: "https", Information: "*:443:ccs.example.test", SSLFlags: 3}}})

	self := pki.SelfSigned("win-demo01", pki.RSA2048, now) // TermService's own, NETWORK SERVICE reads its key
	m.AddCertificate(winproto.RDPStoreSelfSigned, self.CertPEM, self.KeyPEM, CertOptions{})
	m.SetRDP(RDPConfig{Present: true, Enabled: true, NLA: true, Port: demoRDPPort, SecurityLayer: 2})

	password := "ccs-" + rand.Text() // 30 printable ASCII characters, made at start, never stored
	m.SetCCS(true, demoCCSPath)
	m.SetCCSPassword(password)
	for _, host := range []string{"ccs.example.test", "*.unlinked.test"} {
		l := ca.Issue(pki.Opts{CommonName: host, SANs: []string{host}}, now)
		name, _ := winproto.CCSFileName(host)
		m.PutCCSFile(name, l.Cert, []*x509.Certificate{ca.Intermediate}, l.Key, password)
	}
	return m, nil
}
