package winproto_test

import (
	"encoding/json"
	"reflect"
	"sort"
	"strings"
	"testing"

	"alice/internal/providers"
	"alice/internal/providers/linuxssh/helperproto"
	"alice/internal/providers/windows/winproto"
)

func TestExitCodesAndPhasesEqualTheLinuxOnes(t *testing.T) {
	for _, c := range [][2]int{
		{winproto.ExitOK, helperproto.ExitOK}, {winproto.ExitRefused, helperproto.ExitRefused},
		{winproto.ExitPrecondition, helperproto.ExitPrecondition}, {winproto.ExitFailed, helperproto.ExitFailed},
	} {
		if c[0] != c[1] {
			t.Errorf("exit %d != %d", c[0], c[1])
		}
	}
	for _, c := range [][2]string{
		{winproto.PhaseNone, providers.PhaseNone}, {winproto.PhasePrepared, providers.PhasePrepared},
		{winproto.PhaseWriting, providers.PhaseWriting}, {winproto.PhaseCommitted, providers.PhaseCommitted},
		{winproto.PhaseUnchanged, providers.PhaseUnchanged}, {winproto.PhaseRestoring, providers.PhaseRestoring},
		{winproto.PhaseRestored, providers.PhaseRestored}, {winproto.PhaseRestoreFailed, providers.PhaseRestoreFailed},
		{winproto.PhaseFenced, providers.PhaseFenced}, {winproto.PhaseRestoreForbidden, providers.PhaseRestoreForbidden},
	} {
		if c[0] != c[1] {
			t.Errorf("phase %q != %q", c[0], c[1])
		}
	}
	if winproto.MaxChainCerts != helperproto.MaxProbeChainCerts || winproto.DumpOutput != helperproto.ServerDumpOutput {
		t.Error("bounds differ from helperproto")
	}
	if winproto.Protocol < winproto.MinProtocol {
		t.Error("protocol below minimum")
	}
}

var accepted = []string{
	"version",
	"tls-probe --addr 10.0.0.5 --port 443 --sni www.example.com --key-type any",
	"iis-dump",
	"a:b@c+d.e_f-1",
	strings.Repeat("a", 253),
	strings.Join(strings.Split(strings.Repeat("x", 16), ""), " "),
}

func TestSplitCommandLine(t *testing.T) {
	got, ok := winproto.SplitCommandLine(accepted[1])
	if !ok || len(got) != 9 {
		t.Fatalf("tls-probe line: %v %v", got, ok)
	}
	if got, ok := winproto.SplitCommandLine("version"); !ok || !reflect.DeepEqual(got, []string{"version"}) {
		t.Fatalf("version: %v %v", got, ok)
	}
	for _, l := range accepted {
		if _, ok := winproto.SplitCommandLine(l); !ok {
			t.Errorf("%q refused", l)
		}
	}
	refused := []string{
		"", " version", "version ", "a  b", "a\tb", `iis-dump "x"`, "a&b", "a|b", "a%PATH%", "a^b", "a<b",
		strings.Join(strings.Split(strings.Repeat("x", 17), ""), " "),
		strings.Repeat("a", 254), "verçion", "a\x00b",
		strings.Repeat("a", 4097),
	}
	for _, l := range refused {
		if _, ok := winproto.SplitCommandLine(l); ok {
			t.Errorf("%q accepted", l)
		}
	}
}

func TestSplitCommandLineLimitsBytes(t *testing.T) {
	// 16 tokens of 253 bytes and 15 separators is 4063 bytes: within both limits.
	tok := strings.Repeat("a", 253)
	line := strings.TrimSpace(strings.Repeat(tok+" ", 16))
	if len(line) > winproto.MaxLineBytes {
		t.Fatalf("test line is %d bytes", len(line))
	}
	if _, ok := winproto.SplitCommandLine(line); !ok {
		t.Error("16 long tokens refused")
	}
	// Past the byte limit even though every token is valid: caught by the byte limit, not the token rules.
	over := strings.Repeat("a ", 2049) + "a"
	if len(over) <= winproto.MaxLineBytes {
		t.Fatalf("over is %d bytes", len(over))
	}
	if _, ok := winproto.SplitCommandLine(over); ok {
		t.Error("4097+ bytes accepted")
	}
}

func TestJoinCommandLineRoundTrips(t *testing.T) {
	for _, l := range accepted {
		tokens, ok := winproto.SplitCommandLine(l)
		if !ok {
			t.Fatalf("%q refused", l)
		}
		back, ok := winproto.JoinCommandLine(tokens)
		if !ok || back != l {
			t.Errorf("round trip of %q: %q %v", l, back, ok)
		}
	}
	if _, ok := winproto.JoinCommandLine([]string{"a b"}); ok {
		t.Error("token with a space accepted")
	}
	tok := strings.Repeat("a", 253)
	if _, ok := winproto.JoinCommandLine(strings.Split(strings.Repeat(tok+" ", 16)+tok, " ")); ok {
		t.Error("17 tokens accepted")
	}
	if _, ok := winproto.JoinCommandLine([]string{"a", "b&c"}); ok {
		t.Error("bad token accepted")
	}
	if _, ok := winproto.JoinCommandLine(nil); ok {
		t.Error("empty accepted")
	}
}

func TestCanonicalAppID(t *testing.T) {
	for _, in := range []string{"{4DC3E181-E14B-4A21-B022-59FC669B0914}", "4dc3e181-e14b-4a21-b022-59fc669b0914", winproto.AppIDIIS} {
		if got, ok := winproto.CanonicalAppID(in); !ok || got != winproto.AppIDIIS {
			t.Errorf("%q -> %q %v", in, got, ok)
		}
	}
	for _, in := range []string{"{4dc3e181}", "not-a-guid", ""} {
		if _, ok := winproto.CanonicalAppID(in); ok {
			t.Errorf("%q accepted", in)
		}
	}
	if winproto.ValidAppID("{4DC3E181-E14B-4A21-B022-59FC669B0914}") {
		t.Error("upper case is not canonical")
	}
}

func TestKnownAppsAreCanonical(t *testing.T) {
	for id, name := range winproto.KnownApps {
		if !winproto.ValidAppID(id) || name == "" {
			t.Errorf("%q -> %q", id, name)
		}
	}
	if winproto.KnownApps[winproto.AppIDIIS] != "iis" {
		t.Error("iis id")
	}
}

func TestKnownAppsArePinned(t *testing.T) {
	want := map[string]string{
		"{4dc3e181-e14b-4a21-b022-59fc669b0914}": "iis",
		"{214124cd-d05b-4309-9af9-9caa44b2b74a}": "iisexpress",
		"{afebb9ad-9b97-4a91-9ab5-daf4d59122f6}": "winrm",
		"{ba195980-cd49-458b-9e23-c84ee0adcd75}": "sstp",
	}
	if len(winproto.KnownApps) != len(want) {
		t.Fatalf("%v", winproto.KnownApps)
	}
	for id, name := range want {
		if winproto.KnownApps[id] != name {
			t.Errorf("%s -> %q, want %q", id, winproto.KnownApps[id], name)
		}
	}
	if winproto.AppIDIISExpress != "{214124cd-d05b-4309-9af9-9caa44b2b74a}" {
		t.Error("AppIDIISExpress")
	}
}

func TestValidators(t *testing.T) {
	if !winproto.ValidSHA1(strings.Repeat("ab", 20)) || winproto.ValidSHA1(strings.Repeat("AB", 20)) || winproto.ValidSHA1("ab") {
		t.Error("ValidSHA1")
	}
	for _, s := range []string{"My", "WebHosting", "Trusted People", "a.b_c-d"} {
		if !winproto.ValidStore(s) {
			t.Errorf("store %q", s)
		}
	}
	for _, s := range []string{"", "a/b", `a\b`, strings.Repeat("a", 65)} {
		if winproto.ValidStore(s) {
			t.Errorf("store %q accepted", s)
		}
	}
	if !winproto.ValidToken("a") || winproto.ValidToken("") {
		t.Error("ValidToken")
	}
}

func keys(t *testing.T, v any) []string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func TestDumpJSONShape(t *testing.T) {
	yes := true
	cert := winproto.StoreCertificate{Store: "My", SHA1: "x", Chain: []string{"c"}, KeyUsableBySystem: &yes, KeyProblem: "key_missing"}
	d := winproto.IISDumpResponse{
		OK: true, Bindings: []winproto.SSLBinding{{Type: winproto.BindingIPPort, IP: "0.0.0.0", Host: "h", CTLIdentifier: "i", CTLStore: "s"}},
		Certificates: []winproto.StoreCertificate{cert}, Sites: []winproto.Site{{Bindings: []winproto.SiteBinding{{}}}},
		ExpiredInStore: map[string]int{"My": 1}, Warnings: []string{"w"},
	}
	want := func(s string) []string { f := strings.Fields(s); sort.Strings(f); return f }
	check := func(name string, got, exp []string) {
		if !reflect.DeepEqual(got, exp) {
			t.Errorf("%s keys: %v, want %v", name, got, exp)
		}
	}
	check("dump", keys(t, d), want("ok iis bindings certificates dropped_certificates sites expired_in_store warnings truncated"))
	check("certificate ref", keys(t, winproto.CertificateRef{}), want("store sha1"))
	check("binding", keys(t, d.Bindings[0]), want("type ip host port app_id cert_sha1 store flags cert_check_mode revocation_freshness_time url_retrieval_timeout ctl_identifier ctl_store"))
	check("binding bare", keys(t, winproto.SSLBinding{}), want("type port app_id cert_sha1 store flags cert_check_mode revocation_freshness_time url_retrieval_timeout"))
	check("cert", keys(t, cert), want("store sha1 sha256 der chain friendly_name not_after has_key key_provider key_exportable key_usable_by_system key_problem"))
	check("site", keys(t, d.Sites[0]), want("name id state bindings"))
	check("site binding", keys(t, d.Sites[0].Bindings[0]), want("protocol binding_information ssl_flags"))
	check("iis", keys(t, d.IIS), want("installed version shared_config ccs_enabled ccs_path autocertrebind"))
	check("facts", keys(t, winproto.WinFactsResponse{}), want("ok os_build os_product installation_type elevated iis stores openssh_version"))
	check("version", keys(t, winproto.VersionResponse{}), want("ok helper protocol"))
	check("error", keys(t, winproto.ErrorResponse{}), want("ok code message"))

	bare, _ := json.Marshal(winproto.StoreCertificate{})
	if !strings.Contains(string(bare), `"key_usable_by_system":null`) || strings.Contains(string(bare), "key_problem") {
		t.Errorf("bare certificate: %s", bare)
	}
	var tp winproto.TLSProbeResponse = helperproto.TLSProbeResponse{OK: true} //nolint:staticcheck // the explicit type is the point: it proves the alias assigns
	if !tp.OK {
		t.Error("alias")
	}
}
