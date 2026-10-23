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
	if err != nil || len(d.Bindings) != 1 || len(d.Certificates) != 0 || d.Truncated || len(d.DroppedCertificates) != 0 {
		t.Fatalf("%v %+v", err, d)
	}
}

// A certificate dropped for the bounds or as malformed is named in dropped_certificates, so Alice can tell it from
// one the store does not hold (final review M3).
func wantDropped(t *testing.T, d winproto.IISDumpResponse, want ...winproto.CertificateRef) {
	t.Helper()
	if want == nil {
		want = []winproto.CertificateRef{}
	}
	if fmt.Sprint(d.DroppedCertificates) != fmt.Sprint(want) || d.DroppedCertificates == nil {
		t.Fatalf("dropped %v, want %v", d.DroppedCertificates, want)
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
		// A store that cannot be opened at all still fails the dump (W2 Ruling 19).
		"store": func(h *fakeHost) {
			h.bindings = []winproto.SSLBinding{ipb(443, "My", h1)}
			h.certErr = fmt.Errorf("open: %w", ErrStore)
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
	wantDropped(t, d, winproto.CertificateRef{Store: "My", SHA1: h1}, winproto.CertificateRef{Store: "My", SHA1: h2},
		winproto.CertificateRef{Store: "My", SHA1: h3})
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
	wantDropped(t, d) // h2 and h3 are not in the store now: absent, not dropped

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
		{Type: winproto.BindingCCS, IP: "0.0.0.0", Port: 443, AppID: strings.ToUpper(app1), CertSHA1: "", Store: ""}, //nolint:forbidigo // ASCII hex
		// http.sys reports the store in upper case; an upper case hash from a host is folded
		{Type: winproto.BindingHostnamePort, Host: "WWW.Example.Test\x1b", Port: 443, AppID: app1, CertSHA1: strings.ToUpper(h1), Store: "MY", //nolint:forbidigo // ASCII hex
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
	wantDropped(t, d, winproto.CertificateRef{Store: "My", SHA1: h2}, winproto.CertificateRef{Store: "My", SHA1: h3})
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
	for _, want := range []string{`"bindings":[]`, `"certificates":[]`, `"sites":[]`, `"warnings":[]`, `"expired_in_store":{"My":0,"WebHosting":0}`, `"dropped_certificates":[]`} {
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

func TestBuildDumpEmptyStoreIsMY(t *testing.T) {
	h := dumpHost()
	h.bindings = []winproto.SSLBinding{ipb(5986, "", h1), ipb(443, "my", h2)}
	h.certs = map[[2]string]winproto.StoreCertificate{{"MY", h1}: cert("MY", h1)}
	d, err := BuildDump(context.Background(), h)
	if err != nil || len(d.Bindings) != 2 {
		t.Fatalf("%v %+v", err, d)
	}
	if d.Bindings[0].Store != "MY" || d.Bindings[1].Store != "my" {
		t.Fatalf("empty store must become MY, others verbatim: %+v", d.Bindings)
	}
	if len(d.Certificates) != 1 || d.Certificates[0].Store != "MY" {
		t.Fatalf("%+v", d.Certificates)
	}
}

func TestBuildDumpFoldsStoreCaseForCertificateReads(t *testing.T) {
	// The certificate is read once and listed under the spelling of the first binding.
	h := dumpHost()
	h.bindings = []winproto.SSLBinding{ipb(443, "MY", h1), ipb(444, "My", h1)}
	h.certs = map[[2]string]winproto.StoreCertificate{{"MY", h1}: cert("MY", h1), {"My", h1}: cert("My", h1)}
	d, err := BuildDump(context.Background(), h)
	if err != nil {
		t.Fatal(err)
	}
	total := 0
	for _, n := range h.certReads {
		total += n
	}
	if total != 1 || len(d.Certificates) != 1 || d.Certificates[0].Store != "MY" {
		t.Fatalf("reads %v certs %+v", h.certReads, d.Certificates)
	}
	if d.Bindings[0].Store != "MY" || d.Bindings[1].Store != "My" {
		t.Fatalf("bindings keep their spelling: %+v", d.Bindings)
	}
}

func TestBuildDumpKeepsIPv6AndCCSZeroIP(t *testing.T) {
	h := dumpHost()
	h.bindings = []winproto.SSLBinding{
		{Type: winproto.BindingIPPort, IP: "::", Port: 443, AppID: app1, CertSHA1: h1, Store: "My"},
		{Type: winproto.BindingIPPort, IP: "2001:0db8:0:0:0:0:0:1", Port: 443, AppID: app1, CertSHA1: h1, Store: "My"},
		{Type: winproto.BindingCCS, IP: "0.0.0.0", Port: 443, AppID: app1},
	}
	d, err := BuildDump(context.Background(), h)
	if err != nil || len(d.Bindings) != 3 || d.Truncated {
		t.Fatalf("%v %+v", err, d)
	}
	if d.Bindings[0].IP != "::" || d.Bindings[1].IP != "2001:db8::1" {
		t.Fatalf("%+v", d.Bindings)
	}
	if c := d.Bindings[2]; c.Type != winproto.BindingCCS || c.IP != "0.0.0.0" || c.CertSHA1 != "" || c.Store != "" {
		t.Fatalf("%+v", c)
	}
}

func TestBuildDumpKeepsNoisyRunnerRecords(t *testing.T) {
	h := dumpHost()
	for i := 0; i < 100; i++ {
		h.bindings = append(h.bindings, winproto.SSLBinding{Type: winproto.BindingIPPort, IP: "0.0.0.0", Port: 44300 + i,
			AppID: winproto.AppIDIISExpress, CertSHA1: h1, Store: "MY"})
	}
	h.bindings = append(h.bindings, winproto.SSLBinding{Type: winproto.BindingIPPort, IP: "0.0.0.0", Port: 5986,
		AppID: "{afebb9ad-9b97-4a91-9ab5-daf4d59122f6}", CertSHA1: h2, Store: ""})
	d, err := BuildDump(context.Background(), h)
	if err != nil || d.Truncated || len(d.Bindings) != 101 {
		t.Fatalf("%v truncated=%v n=%d", err, d.Truncated, len(d.Bindings))
	}
	if w := d.Bindings[100]; w.Port != 5986 || w.Store != "MY" {
		t.Fatalf("%+v", w)
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

// W2 Ruling 19: one certificate that cannot be read is dropped, not a failed dump.
func TestBuildDumpDropsAnUnreadableCertificate(t *testing.T) {
	h := dumpHost()
	h.bindings = []winproto.SSLBinding{ipb(443, "My", h1), ipb(444, "My", h2), ipb(445, "My", h3)}
	h.certs = map[[2]string]winproto.StoreCertificate{{"My", h1}: cert("My", h1), {"My", h2}: cert("My", h2), {"My", h3}: cert("My", h3)}
	h.certErrs = map[[2]string]error{{"My", h2}: errors.New("CRYPT_E_NOT_FOUND secret OS text")}
	d, err := BuildDump(context.Background(), h)
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Bindings) != 3 || len(d.Certificates) != 2 || d.Certificates[0].SHA1 != h1 || d.Certificates[1].SHA1 != h3 ||
		!d.Truncated || !hasWarning(d, winproto.WarnListTruncated) {
		t.Fatalf("%+v", d)
	}
	wantDropped(t, d, winproto.CertificateRef{Store: "My", SHA1: h2})
	b, _ := json.Marshal(d)
	if strings.Contains(string(b), "secret") {
		t.Fatal("OS text in the dump")
	}
}

func TestBuildDumpReadsExtendedParams(t *testing.T) {
	b64 := func(n int) string { return base64.StdEncoding.EncodeToString([]byte(strings.Repeat("x", n))) }
	ext := []winproto.ExtendedParam{{Type: 3, Data: b64(8)}, {Type: 0, Data: b64(24)}}
	withExt := func(port int, e []winproto.ExtendedParam) winproto.SSLBinding {
		b := ipb(port, "My", h1)
		b.Extended = e
		return b
	}
	many := make([]winproto.ExtendedParam, winproto.MaxExtendedParams+1)
	for i := range many {
		many[i] = winproto.ExtendedParam{Type: uint32(i), Data: b64(1)} //nolint:gosec // G115: small
	}
	h := dumpHost()
	h.bindings = []winproto.SSLBinding{withExt(443, ext), withExt(444, nil), withExt(445, many),
		withExt(446, []winproto.ExtendedParam{{Type: 1, Data: b64(winproto.MaxExtendedBytes + 1)}}),
		withExt(447, []winproto.ExtendedParam{{Type: 1, Data: "%%"}})}
	h.certs = map[[2]string]winproto.StoreCertificate{{"My", h1}: cert("My", h1)}
	d, err := BuildDump(context.Background(), h)
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Bindings) != 2 || !d.Truncated || !hasWarning(d, winproto.WarnListTruncated) {
		t.Fatalf("%+v", d.Bindings)
	}
	if fmt.Sprint(d.Bindings[0].Extended) != fmt.Sprint(ext) || d.Bindings[1].Extended != nil {
		t.Fatalf("%+v", d.Bindings)
	}
	// the dump's copy is its own
	h.bindings[0].Extended[0].Data = "changed"
	if d.Bindings[0].Extended[0].Data == "changed" {
		t.Fatal("the dump shares the host's slice")
	}
	b, _ := json.Marshal(d.Bindings[1])
	if strings.Contains(string(b), "extended") {
		t.Fatalf("an empty extended list is sent: %s", b)
	}
}

// aliceName is the friendly name deploy gives a certificate imported by operation op.
func aliceName(op string) string { return "Alice www.example.test 2030-01-01 " + op[:8] }

// importedJournal is a 0.3.0 journal of op that imported sha (existed false) into store.
func importedJournal(op, store, sha string) journal {
	j := sampleJournal(op)
	j.NewSHA1, j.Store, j.Existed, j.AliceImported = sha, store, boolPtr(false), true
	return j
}

// TestDumpShowsAliceImported is Ruling 19.
func TestDumpShowsAliceImported(t *testing.T) {
	setup := func(t *testing.T) *fakeWriteHost {
		h := newWriteHost()
		h.appcmd, h.iis = []byte(`<appcmd/>`), winproto.IISFacts{Installed: true, Version: "10.0"}
		names := map[string]string{h1: aliceName(op1), h2: aliceName(op2), h3: "renamed by another tool"}
		for _, sha := range []string{h1, h2, h3} {
			h.setRecord(ipb(443+len(h.records), "My", sha))
			c := cert("My", sha)
			c.FriendlyName = names[sha]
			h.certs[[2]string{"My", sha}] = c
		}
		// h1 and h3 are in imports.json, h2 only in a 0.3.0 journal that imported it.
		mustWrite(t, h, importedJournal(op2, "MY", h2))
		if err := writeImports(h, importsFile{Imports: []importEntry{
			{Op: op1, Store: "MY", SHA1: h1, SHA256: s256a}, {Op: op3, Store: "My", SHA1: h3, SHA256: s256c}}}); err != nil {
			t.Fatal(err)
		}
		return h
	}
	shown := func(t *testing.T, h *fakeWriteHost) map[string]bool {
		t.Helper()
		d, err := BuildDump(context.Background(), h)
		if err != nil || len(d.Certificates) != 3 {
			t.Fatalf("%v %+v", err, d)
		}
		out := map[string]bool{}
		for _, c := range d.Certificates {
			out[c.SHA1] = c.AliceImported
		}
		return out
	}
	t.Run("rule 1 for each certificate", func(t *testing.T) {
		h := setup(t)
		if got := shown(t, h); !got[h1] || !got[h2] || got[h3] {
			t.Fatalf("%v", got)
		}
	})
	t.Run("an unreadable imports.json reads false", func(t *testing.T) {
		h := setup(t)
		h.state[importsName] = []byte("{")
		if got := shown(t, h); got[h1] || got[h2] || got[h3] {
			t.Fatalf("%v", got)
		}
	})
	t.Run("an unreadable state reads false", func(t *testing.T) {
		h := setup(t)
		h.readStateErr = errors.New("disk")
		if got := shown(t, h); got[h1] || got[h2] || got[h3] {
			t.Fatalf("%v", got)
		}
	})
	t.Run("journals that cannot be listed or read are left out", func(t *testing.T) {
		h := setup(t)
		h.listStateErr = errors.New("disk")
		if got := shown(t, h); !got[h1] || got[h2] || got[h3] {
			t.Fatalf("%v", got)
		}
		h = setup(t)
		h.state[journalName(op2)] = []byte("{")
		h.state[journalDir+"not-an-op.json"] = []byte("{}")
		h.state[journalDir+"README"] = []byte("x")
		if got := shown(t, h); !got[h1] || got[h2] || got[h3] {
			t.Fatalf("%v", got)
		}
	})
	t.Run("a host that cannot change the machine shows none", func(t *testing.T) {
		h := setup(t)
		d, err := BuildDump(context.Background(), readOnly{h})
		if err != nil || len(d.Certificates) != 3 {
			t.Fatal(err)
		}
		for _, c := range d.Certificates {
			if c.AliceImported {
				t.Fatalf("%+v", c)
			}
		}
	})
}

// readOnly hides a fakeWriteHost's write half: only Host.
type readOnly struct{ Host }

// TestAliceImportedRules is Ruling 5.
func TestAliceImportedRules(t *testing.T) {
	h := newWriteHost()
	c := cert("My", h2)
	none := importsFile{Imports: []importEntry{}}
	listed := importsFile{Imports: []importEntry{{Op: op1, Store: "MY", SHA1: h2, SHA256: s256b}}}
	w2 := sampleJournal(op1) // names h2 as new_sha1, no "existed" record
	existed := importedJournal(op1, "MY", h2)
	existed.Existed, existed.AliceImported = boolPtr(true), false
	raced := importedJournal(op1, "MY", h2)
	raced.AliceImported = false // ImportPFX answered existed after the check
	asPrevious := importedJournal(op1, "MY", h1)
	asPrevious.Previous.CertSHA1, asPrevious.PreviousSHA1 = h2, h2
	otherStore := importedJournal(op1, "WebHosting", h2)
	for _, tc := range []struct {
		name     string
		friendly string
		imports  importsFile
		journals []journal
		want     bool
	}{
		{"listed in imports.json", aliceName(op1), listed, nil, true},
		{"listed, the store spelled otherwise", aliceName(op1), importsFile{Imports: []importEntry{{Op: op1, Store: "my", SHA1: h2, SHA256: s256b}}}, nil, true},
		{"listed in another store", aliceName(op1), importsFile{Imports: []importEntry{{Op: op1, Store: "WebHosting", SHA1: h2, SHA256: s256b}}}, nil, false},
		{"listed for another certificate", aliceName(op1), importsFile{Imports: []importEntry{{Op: op1, Store: "MY", SHA1: h3, SHA256: s256b}}}, nil, false},
		{"a 0.3.0 journal that imported it", aliceName(op1), none, []journal{importedJournal(op1, "MY", h2)}, true},
		{"a W2 journal has no existed record", aliceName(op1), none, []journal{w2}, false},
		{"existed true", aliceName(op1), none, []journal{existed}, false},
		{"an import that met a copy", aliceName(op1), none, []journal{raced}, false},
		{"named only as previous", aliceName(op1), none, []journal{asPrevious}, false},
		{"a journal of another store", aliceName(op1), none, []journal{otherStore}, false},
		{"a fence tombstone", aliceName(op1), none, []journal{{Op: op1, Phase: winproto.PhaseFenced}}, false},
		{"friendly name with another op8", aliceName(op2), listed, []journal{importedJournal(op1, "MY", h2)}, false},
		{"friendly name changed", "Default Web Site", listed, nil, false},
		{"no friendly name", "", listed, nil, false},
		{"Alice but no date", "Alice www.example.test " + op1[:8], listed, nil, false},
		{"Alice but a bad date", "Alice www.example.test 2030-13-01 " + op1[:8], listed, nil, false},
		{"Alice but no name", "Alice  2030-01-01 " + op1[:8], listed, nil, false},
		{"Alice only", "Alice " + op1[:8], listed, nil, false},
		{"Alicex", "Alicex www.example.test 2030-01-01 " + op1[:8], listed, nil, false},
		{"lower-case alice", "alice www.example.test 2030-01-01 " + op1[:8], listed, nil, false},
		{"a shorter op8", "Alice www.example.test 2030-01-01 1111111", listed, nil, false},
		{"trailing text", aliceName(op1) + " copy", listed, nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cc := c
			cc.FriendlyName = tc.friendly
			if got := aliceImported(h, cc, tc.imports, tc.journals); got != tc.want {
				t.Fatalf("got %v", got)
			}
		})
	}
	if aliceFriendlyName("Alice www.example.test 2030-01-01 1111", "1111") {
		t.Fatal("an operation shorter than 8")
	}
}
