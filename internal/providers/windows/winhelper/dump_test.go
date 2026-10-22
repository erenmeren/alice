package winhelper

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"alice/internal/providers/windows/winproto"
)

const (
	app1 = "{4dc3e181-e14b-4a21-b022-59fc669b0914}"
	h1   = "1111111111111111111111111111111111111111"
	h2   = "2222222222222222222222222222222222222222"
	h3   = "3333333333333333333333333333333333333333"
)

func dumpHost() *fakeHost {
	return &fakeHost{elevated: true, appcmd: []byte(`<appcmd/>`), iis: winproto.IISFacts{Installed: true, Version: "10.0"}}
}

func cert(store, sha string) winproto.StoreCertificate {
	return winproto.StoreCertificate{Store: store, SHA1: sha, SHA256: strings.Repeat("a", 64),
		DER: base64.StdEncoding.EncodeToString([]byte("der-" + sha)), FriendlyName: "fn", NotAfter: "2030-01-01T00:00:00Z"}
}

func ipb(port int, store, sha string) winproto.SSLBinding {
	return winproto.SSLBinding{Type: winproto.BindingIPPort, IP: "0.0.0.0", Port: port, AppID: app1, CertSHA1: sha, Store: store}
}

func hasWarning(d winproto.IISDumpResponse, w string) bool {
	for _, x := range d.Warnings {
		if x == w {
			return true
		}
	}
	return false
}

func TestBuildDumpReadsEachCertificateOnce(t *testing.T) {
	h := dumpHost()
	h.bindings = []winproto.SSLBinding{ipb(443, "My", h2), ipb(444, "WebHosting", h1), ipb(445, "My", h2)}
	h.certs = map[[2]string]winproto.StoreCertificate{{"My", h2}: cert("My", h2), {"WebHosting", h1}: cert("WebHosting", h1)}
	d, err := BuildDump(context.Background(), h)
	if err != nil {
		t.Fatal(err)
	}
	if len(h.certReads) != 2 || h.certReads[[2]string{"My", h2}] != 1 || h.certReads[[2]string{"WebHosting", h1}] != 1 {
		t.Fatalf("reads %v", h.certReads)
	}
	if len(d.Bindings) != 3 || len(d.Certificates) != 2 {
		t.Fatalf("%+v", d)
	}
	if d.Certificates[0].Store != "My" || d.Certificates[1].Store != "WebHosting" {
		t.Fatalf("not ordered by (store, sha1): %+v", d.Certificates)
	}
	if !d.OK || !d.IIS.Installed || d.Truncated {
		t.Fatalf("%+v", d)
	}
}

func TestBuildDumpMissingCertificateIsNotAnError(t *testing.T) {
	h := dumpHost()
	h.bindings = []winproto.SSLBinding{ipb(443, "My", h1)}
	d, err := BuildDump(context.Background(), h)
	if err != nil || len(d.Bindings) != 1 || len(d.Certificates) != 0 || d.Truncated {
		t.Fatalf("%v %+v", err, d)
	}
}

func TestBuildDumpWithoutIIS(t *testing.T) {
	h := dumpHost()
	h.iisErr = ErrIISNotInstalled
	h.bindings = []winproto.SSLBinding{{Type: winproto.BindingIPPort, IP: "0.0.0.0", Port: 5986,
		AppID: "{afebb9ad-9b97-4a91-9ab5-daf4d59122f6}", CertSHA1: h1, Store: "My"}}
	d, err := BuildDump(context.Background(), h)
	if err != nil {
		t.Fatal(err)
	}
	if d.IIS.Installed || len(d.Sites) != 0 || len(d.Bindings) != 1 || h.appcmdCalls.Load() != 0 {
		t.Fatalf("%+v calls=%d", d, h.appcmdCalls.Load())
	}
}

func TestBuildDumpAppcmdFailureFailsTheDump(t *testing.T) {
	for name, set := range map[string]func(*fakeHost){
		"error":     func(h *fakeHost) { h.appcmdErr = errors.New("exit 1") },
		"bad xml":   func(h *fakeHost) { h.appcmd = []byte("<appcmd><oops>") },
		"doctype":   func(h *fakeHost) { h.appcmd = []byte("<!DOCTYPE x><appcmd/>") },
		"no output": func(h *fakeHost) { h.appcmd = nil },
	} {
		h := dumpHost()
		set(h)
		if _, err := BuildDump(context.Background(), h); err == nil {
			t.Errorf("%s: no error", name)
		}
		code, out := run(t, h, "iis-dump")
		wantError(t, code, out, 4, "IO_ERROR")
	}
}

func TestBuildDumpOtherReadFailures(t *testing.T) {
	boom := errors.New("boom")
	for name, set := range map[string]func(*fakeHost){
		"iis facts": func(h *fakeHost) { h.iisErr = boom },
		"bindings":  func(h *fakeHost) { h.bindingsErr = boom },
		"cert": func(h *fakeHost) {
			h.bindings = []winproto.SSLBinding{ipb(443, "My", h1)}
			h.certErr = boom
		},
	} {
		h := dumpHost()
		set(h)
		if _, err := BuildDump(context.Background(), h); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := BuildDump(ctx, dumpHost()); err == nil {
		t.Error("a finished context did not stop the dump")
	}
}

func TestDumpCutsAtItsBounds(t *testing.T) {
	// 1001 bindings with 1001 distinct certificates: both lists are cut at 1000.
	h := dumpHost()
	h.certs = map[[2]string]winproto.StoreCertificate{}
	for i := 0; i <= winproto.MaxBindings; i++ {
		sha := fmt.Sprintf("%040x", i+1)
		h.bindings = append(h.bindings, ipb(1+i, "My", sha))
		h.certs[[2]string{"My", sha}] = cert("My", sha)
	}
	d, err := BuildDump(context.Background(), h)
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Bindings) != winproto.MaxBindings || len(d.Certificates) != winproto.MaxCertificates || !d.Truncated || !hasWarning(d, winproto.WarnListTruncated) {
		t.Fatalf("%d %d %v %v", len(d.Bindings), len(d.Certificates), d.Truncated, d.Warnings)
	}

	// an oversized DER and a too long chain are dropped, the binding stays
	h = dumpHost()
	h.bindings = []winproto.SSLBinding{ipb(443, "My", h1), ipb(444, "My", h2), ipb(445, "My", h3)}
	big := cert("My", h1)
	big.DER = base64.StdEncoding.EncodeToString(make([]byte, winproto.MaxCertDER+1))
	long := cert("My", h2)
	long.Chain = make([]string, winproto.MaxChainCerts+1)
	bigChain := cert("My", h3)
	bigChain.Chain = []string{big.DER}
	h.certs = map[[2]string]winproto.StoreCertificate{{"My", h1}: big, {"My", h2}: long, {"My", h3}: bigChain}
	d, err = BuildDump(context.Background(), h)
	if err != nil || len(d.Bindings) != 3 || len(d.Certificates) != 0 || !d.Truncated || !hasWarning(d, winproto.WarnListTruncated) {
		t.Fatalf("%v %+v", err, d)
	}
	// exactly at the limits is kept
	ok := cert("My", h1)
	ok.DER = base64.StdEncoding.EncodeToString(make([]byte, winproto.MaxCertDER))
	ok.Chain = make([]string, winproto.MaxChainCerts)
	for i := range ok.Chain {
		ok.Chain[i] = base64.StdEncoding.EncodeToString([]byte("c"))
	}
	h.certs = map[[2]string]winproto.StoreCertificate{{"My", h1}: ok}
	d, err = BuildDump(context.Background(), h)
	if err != nil || len(d.Certificates) != 1 || len(d.Certificates[0].Chain) != winproto.MaxChainCerts {
		t.Fatalf("%v %+v", err, d.Certificates)
	}

	// the encoded answer is bounded: 400 certificates of 64 KiB (base64 87 KiB) are over 16 MiB
	h = dumpHost()
	h.certs = map[[2]string]winproto.StoreCertificate{}
	der := base64.StdEncoding.EncodeToString(make([]byte, winproto.MaxCertDER))
	for i := 0; i < 400; i++ {
		sha := fmt.Sprintf("%040x", i+1)
		h.bindings = append(h.bindings, ipb(1+i, "My", sha))
		c := cert("My", sha)
		c.DER = der
		h.certs[[2]string{"My", sha}] = c
	}
	if _, err = BuildDump(context.Background(), h); err == nil {
		t.Fatal("no error")
	}
	code, out := run(t, h, "iis-dump")
	wantError(t, code, out, 4, "OUTPUT_TOO_LARGE")
}

func TestBuildDumpWarnings(t *testing.T) {
	h := dumpHost()
	h.iis = winproto.IISFacts{Installed: true, SharedConfig: true, AutoCertRebind: true, CCSEnabled: true, CCSPath: `\\fs\ccs`}
	h.expired = map[string]int{"My": 3}
	d, err := BuildDump(context.Background(), h)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{winproto.WarnSharedConfig, winproto.WarnAutoCertRebind, winproto.WarnCCSEnabled, winproto.WarnExpiredInStore}
	if fmt.Sprint(d.Warnings) != fmt.Sprint(want) {
		t.Fatalf("%v", d.Warnings)
	}
	if len(d.ExpiredInStore) != 2 || d.ExpiredInStore["My"] != 3 || d.ExpiredInStore["WebHosting"] != 0 {
		t.Fatalf("%v", d.ExpiredInStore)
	}
	// nothing expired, no facts: no warning
	d, _ = BuildDump(context.Background(), dumpHost())
	if len(d.Warnings) != 0 {
		t.Fatalf("%v", d.Warnings)
	}
}

func TestBuildDumpDropsInvalidRecords(t *testing.T) {
	good := ipb(443, "My", h1)
	mut := func(f func(*winproto.SSLBinding)) winproto.SSLBinding { b := good; f(&b); return b }
	h := dumpHost()
	h.bindings = []winproto.SSLBinding{
		good,
		mut(func(b *winproto.SSLBinding) { b.AppID = "not-a-guid" }),
		mut(func(b *winproto.SSLBinding) { b.CertSHA1 = strings.Repeat("g", 40) }),
		mut(func(b *winproto.SSLBinding) { b.CertSHA1 = "" }),
		mut(func(b *winproto.SSLBinding) { b.Type = "bogus" }),
		mut(func(b *winproto.SSLBinding) { b.Port = 0 }),
		mut(func(b *winproto.SSLBinding) { b.Port = 70000 }),
		mut(func(b *winproto.SSLBinding) { b.Store = "My\x1b[0m/x" }),
		mut(func(b *winproto.SSLBinding) { b.IP = "999.1.1.1" }),
		{Type: winproto.BindingHostnamePort, Host: "", Port: 443, AppID: app1, CertSHA1: h1, Store: "My"},
	}
	d, err := BuildDump(context.Background(), h)
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Bindings) != 1 || !d.Truncated || !hasWarning(d, winproto.WarnListTruncated) {
		t.Fatalf("%+v", d)
	}
}

func TestBuildDumpKeepsAndNormalisesGoodBindings(t *testing.T) {
	h := dumpHost()
	h.bindings = []winproto.SSLBinding{
		// the spike's ccs entry: ip 0.0.0.0, empty hash, empty store
		{Type: winproto.BindingCCS, IP: "0.0.0.0", Port: 443, AppID: strings.ToUpper(app1), CertSHA1: "", Store: ""},
		// http.sys reports the store in upper case; an upper case hash from a host is folded
		{Type: winproto.BindingHostnamePort, Host: "WWW.Example.Test\x1b", Port: 443, AppID: app1, CertSHA1: strings.ToUpper(h1), Store: "MY",
			CTLIdentifier: "ctl\x07", CTLStore: "Root", Flags: 2},
		{Type: winproto.BindingIPPort, IP: "::", Port: 443, AppID: app1, CertSHA1: h2, Store: "WebHosting"},
	}
	h.certs = map[[2]string]winproto.StoreCertificate{{"MY", h1}: cert("MY", h1)}
	d, err := BuildDump(context.Background(), h)
	if err != nil || d.Truncated {
		t.Fatalf("%v %+v", err, d)
	}
	if len(d.Bindings) != 3 {
		t.Fatalf("%+v", d.Bindings)
	}
	ccs := d.Bindings[0]
	if ccs.Type != winproto.BindingCCS || ccs.CertSHA1 != "" || ccs.Store != "" || ccs.AppID != app1 {
		t.Fatalf("%+v", ccs)
	}
	sni := d.Bindings[1]
	if sni.Host != "WWW.Example.Test" || sni.CertSHA1 != h1 || sni.Store != "MY" || sni.CTLIdentifier != "ctl" || sni.Flags != 2 {
		t.Fatalf("%+v", sni)
	}
	if len(d.Certificates) != 1 || d.Certificates[0].Store != "MY" {
		t.Fatalf("%+v", d.Certificates)
	}
}

func TestBuildDumpCleansCertificates(t *testing.T) {
	h := dumpHost()
	h.bindings = []winproto.SSLBinding{ipb(443, "My", h1), ipb(444, "My", h2), ipb(445, "My", h3)}
	c1 := cert("OTHER", "other")
	c1.FriendlyName = "name\x1b[31m" + strings.Repeat("x", 300)
	c1.KeyProvider = "prov\x00"
	c1.HasKey, c1.KeyProblem = true, "key_missing"
	c2 := cert("My", h2)
	c2.KeyProblem = "weird"
	c3 := cert("My", h3)
	c3.KeyProblem = "key_inaccessible"
	c3.DER = "!!!not base64"
	h.certs = map[[2]string]winproto.StoreCertificate{{"My", h1}: c1, {"My", h2}: c2, {"My", h3}: c3}
	d, err := BuildDump(context.Background(), h)
	if err != nil {
		t.Fatal(err)
	}
	// c2 (unknown key problem) and c3 (DER not base64) are dropped
	if len(d.Certificates) != 1 || !d.Truncated {
		t.Fatalf("%+v", d)
	}
	got := d.Certificates[0]
	if got.Store != "My" || got.SHA1 != h1 || len(got.FriendlyName) != winproto.MaxText || got.KeyProvider != "prov" || got.KeyProblem != "key_missing" {
		t.Fatalf("%+v", got)
	}
}

// Alice's decoder sees stable shapes: [] and {} rather than null.
func TestDumpJSONShapes(t *testing.T) {
	h := dumpHost()
	h.iisErr = ErrIISNotInstalled
	code, out := run(t, h, "iis-dump")
	if code != 0 {
		t.Fatal(code, string(out))
	}
	s := string(out)
	for _, want := range []string{`"bindings":[]`, `"certificates":[]`, `"sites":[]`, `"warnings":[]`, `"expired_in_store":{"My":0,"WebHosting":0}`} {
		if !strings.Contains(s, want) {
			t.Errorf("%s missing in %s", want, s)
		}
	}
	if strings.Contains(s, "null") {
		t.Errorf("null in %s", s)
	}

	h = dumpHost()
	h.bindings = []winproto.SSLBinding{ipb(443, "My", h1)}
	h.certs = map[[2]string]winproto.StoreCertificate{{"My", h1}: cert("My", h1)} // Chain is nil; key_usable_by_system null means "unknown"
	_, out = run(t, h, "iis-dump")
	var r struct {
		Certificates []struct {
			Chain *[]string `json:"chain"`
		} `json:"certificates"`
	}
	if err := json.Unmarshal(out, &r); err != nil || len(r.Certificates) != 1 || r.Certificates[0].Chain == nil || !strings.Contains(string(out), `"chain":[]`) {
		t.Fatalf("%v %s", err, out)
	}
}

func TestDumpReportsSites(t *testing.T) {
	h := dumpHost()
	h.appcmd = readFixture(t, "appcmd-ws2022.xml")
	d, err := BuildDump(context.Background(), h)
	if err != nil || len(d.Sites) != 2 || d.Truncated {
		t.Fatalf("%v %+v", err, d)
	}
	// a cut site list is reported
	var b strings.Builder
	b.WriteString("<appcmd>")
	for i := 1; i <= winproto.MaxSites+1; i++ {
		fmt.Fprintf(&b, `<SITE><site name="s%d" id="%d"/></SITE>`, i, i)
	}
	b.WriteString("</appcmd>")
	h.appcmd = []byte(b.String())
	d, err = BuildDump(context.Background(), h)
	if err != nil || len(d.Sites) != winproto.MaxSites || !d.Truncated || !hasWarning(d, winproto.WarnListTruncated) {
		t.Fatalf("%v %d %v", err, len(d.Sites), d.Truncated)
	}
}
