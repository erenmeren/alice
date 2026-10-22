package wintest

import (
	"fmt"
	"time"

	"alice/internal/providers/windows/winproto"
	"alice/internal/testutil/pki"
)

// Demo builds the fixed host of the e2e journey (Task 15): Windows Server 2022 Datacenter
// 10.0.20348.2700 with IIS 10.0; the sites "Default Web Site" (https *:443:www.win.example.test, SNI) and
// "Intranet" (https *:8443:); the http.sys entries hostnameport www.win.example.test:443 (IIS, My),
// ipport 0.0.0.0:8443 (IIS, WebHosting), ipport 0.0.0.0:5986 (WinRM: a foreign application) and ccs 443.
// The certificates come from a test CA generated now (leaf and intermediate); CARootPEM is its root.
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
	return m, nil
}
