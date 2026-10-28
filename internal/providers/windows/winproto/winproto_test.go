package winproto_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

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
	check("cert", keys(t, cert), want("store sha1 sha256 der chain friendly_name not_after has_key key_provider key_exportable key_usable_by_system key_problem alice_imported"))
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

func TestStepsEqualTheProviders(t *testing.T) {
	for _, c := range [][2]string{
		{winproto.StepImportChain, providers.StepNameImportChain},
		{winproto.StepImportCertificate, providers.StepNameImportCertificate},
		{winproto.StepBind, providers.StepNameBind},
		{winproto.StepJournal, providers.StepNameJournal},
		{winproto.StepRestore, providers.StepNameRestore},
		{winproto.StepGrantKeyRead, providers.StepNameGrantKeyRead},
		{winproto.StepSetListener, providers.StepNameSetListener},
		{winproto.ErrForbidden, providers.DeployErrForbidden},
		{winproto.ErrFileChanged, providers.DeployErrFileChanged},
	} {
		if c[0] != c[1] {
			t.Errorf("%q != %q", c[0], c[1])
		}
	}
	for got, want := range map[string]string{
		winproto.ErrKeyUnusable: "key_unusable", winproto.ErrReadBack: "read_back", winproto.ErrStore: "store_error",
		winproto.ErrBackupMissing: "backup_missing", winproto.ErrIO: "io_error", winproto.ErrKeyACL: "key_acl",
		winproto.StepWriteFile: "write_file", winproto.StepGrantKeyRead: "grant_key_read", winproto.StepSetListener: "set_listener",
	} {
		if got != want {
			t.Errorf("%q != %q", got, want)
		}
	}
}

func TestWriteSubcommandsAndCodes(t *testing.T) {
	for got, want := range map[string]string{
		winproto.SubIISDeploy: "iis-deploy", winproto.SubIISRestore: "iis-restore", winproto.SubIISStatus: "iis-status",
		winproto.SubIISFence: "iis-fence", winproto.ArgOp: "--op",
		winproto.CodeUnknownOp: "UNKNOWN_OP", winproto.CodeOperationExists: "OPERATION_EXISTS", winproto.CodeBadContent: "BAD_CONTENT",
		winproto.CodeTooLarge: "TOO_LARGE", winproto.CodeIISNotFound: "IIS_NOT_FOUND", winproto.CodeBindingNotFound: "BINDING_NOT_FOUND",
		winproto.CodeBackupMissing: "BACKUP_MISSING", winproto.CodeKeyUnusable: "KEY_UNUSABLE", winproto.CodeJournalFailed: "JOURNAL_FAILED",
	} {
		if got != want {
			t.Errorf("%q != %q", got, want)
		}
	}
	// The codes that mean what the Linux helper's mean carry the Linux names.
	for _, c := range [][2]string{
		{winproto.CodeHashMismatch, helperproto.CodeHashMismatch}, {winproto.CodeFenced, helperproto.CodeFenced},
		{winproto.CodeSuperseded, helperproto.CodeSuperseded}, {winproto.CodeOutcomeUnknown, helperproto.CodeOutcomeUnknown},
		{winproto.CodeBusy, helperproto.CodeBusy}, {winproto.CodeRecoveryPending, helperproto.CodeRecoveryPending},
	} {
		if c[0] != c[1] {
			t.Errorf("%q != %q", c[0], c[1])
		}
	}
	if winproto.Version != "1.2.0" || winproto.WriteMinVersion != "0.2.0" || winproto.Protocol != 1 || winproto.MinProtocol != 1 {
		t.Error("versions")
	}
	if !winproto.VersionAtLeast(winproto.Version, winproto.WriteMinVersion) {
		t.Error("this helper is below its own write minimum")
	}
	if winproto.MaxDeployInput != 256<<10 || winproto.MaxRestoreInput != 32<<10 || winproto.MaxExtendedParams != 16 ||
		winproto.MaxExtendedBytes != 4096 || winproto.MaxForbidden != helperproto.MaxForbidden ||
		winproto.LockWait != 20*time.Second || winproto.WriteGrace != 8*time.Second {
		t.Error("bounds")
	}
	if winproto.WriteGrace >= winproto.HelperBudget {
		t.Error("the grace must end within the budget")
	}
}

func TestVersionAtLeast(t *testing.T) {
	for _, c := range []struct {
		v, min string
		want   bool
	}{
		{"0.2.0", "0.2.0", true}, {"0.10.0", "0.2.0", true}, {"1.0", "0.2.0", true}, {"0.2", "0.2.0", true},
		{"0.2.0.1", "0.2.0", true}, {"99999.0", "0.2.0", true}, {"0.2.0", "0.2", true},
		{"0.1.0", "0.2.0", false}, {"0.1.99", "0.2.0", false}, {"0.2.0", "0.2.0.1", false},
		{"", "0.2.0", false}, {"v0.2.0", "0.2.0", false}, {"0.2.0-rc1", "0.2.0", false}, {"1.2.3.4.5", "0.2.0", false},
		{"123456.0", "0.2.0", false}, {"1..0", "0.2.0", false}, {"1.0.", "0.2.0", false}, {".1", "0.2.0", false},
		{"+1.0", "0.2.0", false}, {"1.0", "", false}, {"1.0", "x", false},
	} {
		if got := winproto.VersionAtLeast(c.v, c.min); got != c.want {
			t.Errorf("VersionAtLeast(%q, %q) = %v", c.v, c.min, got)
		}
	}
}

func TestValidHost(t *testing.T) {
	label63 := strings.Repeat("a", 63)
	name253 := strings.Repeat(label63+".", 3) + strings.Repeat("b", 61)
	if len(name253) != 253 {
		t.Fatalf("name253 is %d", len(name253))
	}
	for _, h := range []string{"www.example.com", "*.example.com", "a-b.c", "xn--bcher-kva.example", "a", "localhost",
		"1.example", label63 + ".example", name253, "*." + label63} {
		if !winproto.ValidHost(h) {
			t.Errorf("%q refused", h)
		}
	}
	for _, h := range []string{"", "WWW.example.com", "bücher.example", "a..b", "-a.b", "a.b-", "a-.b", ".a", "a.",
		strings.Repeat("a", 64) + ".example", name253 + "b", "*", "*.", "a.*.b", "**.a", "*a.b", "a b", "a_b.example",
		"a:443", "a/b", "*.*.a", "a.b\x00"} {
		if winproto.ValidHost(h) {
			t.Errorf("%q accepted", h)
		}
	}
}

func TestLocatorCanonical(t *testing.T) {
	for _, c := range []struct {
		l    winproto.Locator
		want string
	}{
		{winproto.Locator{Type: winproto.BindingHostnamePort, Host: "www.example.com", Port: 443, AppID: winproto.AppIDIIS}, "http.sys/hostnameport/www.example.com:443"},
		{winproto.Locator{Type: winproto.BindingHostnamePort, Host: "*.example.com", Port: 8443, AppID: winproto.AppIDIIS}, "http.sys/hostnameport/*.example.com:8443"},
		{winproto.Locator{Type: winproto.BindingIPPort, IP: "::", Port: 443, AppID: winproto.AppIDIIS}, "http.sys/ipport/[::]:443"},
		{winproto.Locator{Type: winproto.BindingIPPort, IP: "0.0.0.0", Port: 443, AppID: winproto.AppIDIIS}, "http.sys/ipport/0.0.0.0:443"},
		{winproto.Locator{Type: winproto.BindingIPPort, IP: "10.0.0.5", Port: 65535, AppID: winproto.AppIDIISExpress}, "http.sys/ipport/10.0.0.5:65535"},
		{winproto.Locator{Type: winproto.BindingIPPort, IP: "2001:db8::1", Port: 1, AppID: winproto.AppIDIIS}, "http.sys/ipport/[2001:db8::1]:1"},
	} {
		got, ok := c.l.Canonical()
		if !ok || got != c.want {
			t.Errorf("%+v -> %q %v, want %q", c.l, got, ok, c.want)
		}
	}
	iis := winproto.AppIDIIS
	for _, l := range []winproto.Locator{
		{Type: winproto.BindingCCS, Port: 443, AppID: iis},
		{Type: "other", Port: 443, AppID: iis},
		{Type: winproto.BindingHostnamePort, Host: "www.example.com", Port: 443, AppID: "{4DC3E181-E14B-4A21-B022-59FC669B0914}"},
		{Type: winproto.BindingHostnamePort, Host: "www.example.com", Port: 443, AppID: "not-a-guid"},
		{Type: winproto.BindingHostnamePort, Host: "www.example.com", Port: 0, AppID: iis},
		{Type: winproto.BindingHostnamePort, Host: "www.example.com", Port: 65536, AppID: iis},
		{Type: winproto.BindingHostnamePort, Host: "WWW.example.com", Port: 443, AppID: iis},
		{Type: winproto.BindingHostnamePort, Host: "bücher.example", Port: 443, AppID: iis},
		{Type: winproto.BindingHostnamePort, Host: "", Port: 443, AppID: iis},
		{Type: winproto.BindingHostnamePort, Host: "www.example.com", IP: "10.0.0.5", Port: 443, AppID: iis},
		{Type: winproto.BindingIPPort, IP: "::ffff:10.0.0.5", Port: 443, AppID: iis},
		{Type: winproto.BindingIPPort, IP: "010.0.0.5", Port: 443, AppID: iis},
		{Type: winproto.BindingIPPort, IP: "2001:DB8::1", Port: 443, AppID: iis},
		{Type: winproto.BindingIPPort, IP: "fe80::1%eth0", Port: 443, AppID: iis},
		{Type: winproto.BindingIPPort, IP: "", Port: 443, AppID: iis},
		{Type: winproto.BindingIPPort, IP: "10.0.0.5", Host: "www.example.com", Port: 443, AppID: iis},
		{Type: winproto.BindingIPPort, IP: "10.0.0.5", Port: -1, AppID: iis},
	} {
		if got, ok := l.Canonical(); ok || got != "" {
			t.Errorf("%+v accepted: %q", l, got)
		}
	}
}

func TestValidOpID(t *testing.T) {
	if !winproto.ValidOpID("0f8fad5b-d9cb-469f-a165-70867728950e") {
		t.Error("lower-case UUID refused")
	}
	for _, s := range []string{"0F8FAD5B-D9CB-469F-A165-70867728950E", "{0f8fad5b-d9cb-469f-a165-70867728950e}",
		"00000000-0000-0000-0000-000000000000", "", "0f8fad5bd9cb469fa16570867728950e", "0f8fad5b-d9cb-469f-a165-70867728950"} {
		if winproto.ValidOpID(s) {
			t.Errorf("%q accepted", s)
		}
	}
}

func TestValidForbidden(t *testing.T) {
	h := strings.Repeat("ab", 32)
	if !winproto.ValidForbidden(nil) || !winproto.ValidForbidden([]string{h}) {
		t.Error("valid list refused")
	}
	for _, l := range [][]string{{h, h}, {"AB"}, {helperproto.AbsentSHA256}, make([]string, winproto.MaxForbidden+1)} {
		if winproto.ValidForbidden(l) {
			t.Errorf("%v accepted", l)
		}
	}
}

func TestDeployInputIsRedacted(t *testing.T) {
	const pem = "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgSECRETKEYMATERIAL\n-----END PRIVATE KEY-----\n"
	in := winproto.DeployInput{
		Locator:  winproto.Locator{Type: winproto.BindingIPPort, IP: "0.0.0.0", Port: 443, AppID: winproto.AppIDIIS},
		ChainPEM: "-----BEGIN CERTIFICATE-----\nX\n-----END CERTIFICATE-----\n", KeyPEM: pem,
	}
	for _, f := range []string{"%v", "%+v", "%#v", "%s"} {
		for _, v := range []any{in, &in, []winproto.DeployInput{in}, struct{ In winproto.DeployInput }{in}} {
			out := fmt.Sprintf(f, v)
			if strings.Contains(out, "PRIVATE KEY") || strings.Contains(out, "SECRETKEYMATERIAL") {
				t.Errorf("%s printed the key: %s", f, out)
			}
		}
	}
	var buf bytes.Buffer
	slog.New(slog.NewJSONHandler(&buf, nil)).Info("m", "in", in, "ptr", &in)
	slog.New(slog.NewTextHandler(&buf, nil)).Info("m", "in", in, "ptr", &in)
	if strings.Contains(buf.String(), "PRIVATE KEY") || strings.Contains(buf.String(), "SECRETKEYMATERIAL") {
		t.Errorf("slog printed the key: %s", buf.String())
	}
	// The wire form still carries it: the helper reads it from stdin.
	b, err := json.Marshal(in)
	if err != nil || !strings.Contains(string(b), "SECRETKEYMATERIAL") {
		t.Errorf("wire form: %s %v", b, err)
	}
}

func TestWriteShapesJSON(t *testing.T) {
	want := func(s string) []string { f := strings.Fields(s); sort.Strings(f); return f }
	check := func(name string, got, exp []string) {
		if !reflect.DeepEqual(got, exp) {
			t.Errorf("%s keys: %v, want %v", name, got, exp)
		}
	}
	check("deploy input", keys(t, winproto.DeployInput{}), want("locator expect_sha256 chain_pem key_pem forbidden_spki_sha256 forbidden_leaf_sha256"))
	check("locator", keys(t, winproto.Locator{}), want("type port app_id"))
	check("locator full", keys(t, winproto.Locator{IP: "a", Host: "b"}), want("type ip host port app_id"))
	check("step", keys(t, winproto.Step{}), want("name status error"))
	check("deploy", keys(t, winproto.DeployResponse{}), want("ok phase failed_step cause_step error steps new_sha1 new_sha256 previous_sha1 previous_sha256 store alice_imported built_chain_length"))
	check("restore input", keys(t, winproto.RestoreInput{}), want("forbidden_spki_sha256 forbidden_leaf_sha256"))
	check("restore", keys(t, winproto.RestoreResponse{}), want("ok phase failed_step cause_step error steps"))
	check("status", keys(t, winproto.StatusResponse{}), want("ok phase active failed_step cause_step error new_cert_sha256 current_cert_sha256"))
	check("error pending", keys(t, winproto.ErrorResponse{PendingOp: "x"}), want("ok code message pending_op"))
	check("extended param", keys(t, winproto.ExtendedParam{}), want("type data"))
	check("binding extended", keys(t, winproto.SSLBinding{Extended: []winproto.ExtendedParam{{Type: 1, Data: "AA=="}}}),
		want("type port app_id cert_sha1 store flags cert_check_mode revocation_freshness_time url_retrieval_timeout extended"))
	b, err := json.Marshal(winproto.SSLBinding{Extended: []winproto.ExtendedParam{{Type: 3, Data: "AQID"}}})
	if err != nil || !strings.Contains(string(b), `"extended":[{"type":3,"data":"AQID"}]`) {
		t.Errorf("extended: %s %v", b, err)
	}
	// The restore input's lists are required members: an empty list is sent as [], never left out.
	b, err = json.Marshal(winproto.RestoreInput{ForbiddenSPKI: []string{}, ForbiddenLeaf: []string{}})
	if err != nil || string(b) != `{"forbidden_spki_sha256":[],"forbidden_leaf_sha256":[]}` {
		t.Errorf("restore input: %s %v", b, err)
	}
}

func TestValidExtended(t *testing.T) {
	b64 := func(n int) string { return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, n)) }
	many := make([]winproto.ExtendedParam, winproto.MaxExtendedParams)
	for i := range many {
		many[i] = winproto.ExtendedParam{Type: uint32(i), Data: b64(4)} //nolint:gosec // G115: small
	}
	for _, c := range []struct {
		name string
		in   []winproto.ExtendedParam
		want bool
	}{
		{"none", nil, true},
		{"empty", []winproto.ExtendedParam{}, true},
		{"one", []winproto.ExtendedParam{{Type: 3, Data: b64(16)}}, true},
		{"at the byte limit", []winproto.ExtendedParam{{Type: 0, Data: b64(winproto.MaxExtendedBytes)}}, true},
		{"at the count limit", many, true},
		{"over the count limit", append(append([]winproto.ExtendedParam{}, many...), winproto.ExtendedParam{Type: 99, Data: b64(1)}), false},
		{"over the byte limit", []winproto.ExtendedParam{{Type: 0, Data: b64(winproto.MaxExtendedBytes + 1)}}, false},
		{"no bytes", []winproto.ExtendedParam{{Type: 0, Data: ""}}, false},
		{"not base64", []winproto.ExtendedParam{{Type: 0, Data: "!!!!"}}, false},
		{"url base64", []winproto.ExtendedParam{{Type: 0, Data: "-_-_"}}, false},
		{"duplicate type", []winproto.ExtendedParam{{Type: 2, Data: b64(1)}, {Type: 2, Data: b64(2)}}, false},
	} {
		if got := winproto.ValidExtended(c.in); got != c.want {
			t.Errorf("%s: got %v", c.name, got)
		}
	}
}

func TestStepStatuses(t *testing.T) {
	// helperproto.NginxStep documents "ok" | "failed"; the Windows steps use the same words.
	if winproto.StepOK != "ok" || winproto.StepFailed != "failed" {
		t.Fatal(winproto.StepOK, winproto.StepFailed)
	}
}

func TestCleanupShapesJSON(t *testing.T) {
	want := func(s string) []string { f := strings.Fields(s); sort.Strings(f); return f }
	check := func(name string, got, exp []string) {
		if !reflect.DeepEqual(got, exp) {
			t.Errorf("%s keys: %v, want %v", name, got, exp)
		}
	}
	check("ref", keys(t, winproto.CleanupRef{}), want("sha1 sha256"))
	check("plan input", keys(t, winproto.CleanupPlanInput{}), want("watch"))
	check("candidate", keys(t, winproto.CleanupCandidate{}), want("store sha1 sha256 friendly_name not_after unbound_since eligible"))
	check("watched", keys(t, winproto.CleanupWatched{}), want("store sha1 sha256 state reason"))
	check("plan", keys(t, winproto.CleanupPlanResponse{}), want("ok candidates watched pruned warnings truncated"))
	check("item", keys(t, winproto.CleanupItem{}), want("store sha1 sha256 reason"))
	check("apply input", keys(t, winproto.CleanupApplyInput{}), want("remove"))
	check("result", keys(t, winproto.CleanupResult{}), want("sha256 result reason"))
	check("apply", keys(t, winproto.CleanupApplyResponse{}), want("ok results"))
	b, err := json.Marshal(winproto.CleanupPlanInput{Watch: []winproto.CleanupRef{}})
	if err != nil || string(b) != `{"watch":[]}` {
		t.Errorf("plan input: %s %v", b, err)
	}
	b, err = json.Marshal(winproto.StoreCertificate{AliceImported: true})
	if err != nil || !strings.Contains(string(b), `"alice_imported":true`) {
		t.Errorf("alice_imported: %s %v", b, err)
	}
}

func TestCleanupVocabulary(t *testing.T) {
	for _, c := range [][2]string{
		{winproto.SubIISCleanup, "iis-cleanup"}, {winproto.ArgPlan, "--plan"}, {winproto.ArgApply, "--apply"},
		{winproto.CleanupAged, "aged"}, {winproto.CleanupExpired, "expired"}, {winproto.CleanupIncident, "incident"},
		{winproto.KeptBound, "bound"}, {winproto.KeptRDP, "rdp"}, {winproto.KeptWinRM, "winrm"}, {winproto.KeptJournal, "journal"},
		{winproto.KeptNotAlice, "not_alice"}, {winproto.KeptTooYoung, "too_young"}, {winproto.KeptJournalUnreadable, "journal_unreadable"},
		{winproto.CleanupRemoved, "removed"}, {winproto.CleanupKept, "kept"}, {winproto.CleanupAbsent, "absent"},
		{winproto.WatchRemovable, "removable"}, {winproto.WatchKept, "kept"}, {winproto.WatchAbsent, "absent"},
		{winproto.WarnJournalUnreadable, "journal_unreadable"}, {winproto.WarnBindingRecordUnreadable, "binding_record_unreadable"},
	} {
		if c[0] != c[1] {
			t.Errorf("%q != %q", c[0], c[1])
		}
	}
	if winproto.MaxCleanupInput != 64<<10 || winproto.MaxCleanupItems != 256 || winproto.MaxCleanupCandidates != 256 ||
		winproto.CleanupMinAge != 7*24*time.Hour || winproto.JournalKeep != 7*24*time.Hour ||
		winproto.JournalRetention != 30*24*time.Hour || winproto.MaxPrunePerRun != 1000 {
		t.Error("bounds")
	}
}

func TestValidCleanupItem(t *testing.T) {
	sha1 := strings.Repeat("a", 40)
	sha256 := strings.Repeat("b", 64)
	item := func(store, s1, s256, reason string) winproto.CleanupItem {
		return winproto.CleanupItem{Store: store, SHA1: s1, SHA256: s256, Reason: reason}
	}
	for name, c := range map[string]struct {
		in   winproto.CleanupItem
		want bool
	}{
		"aged":              {item("My", sha1, sha256, winproto.CleanupAged), true},
		"expired":           {item("My", sha1, sha256, winproto.CleanupExpired), true},
		"incident":          {item("WebHosting", sha1, sha256, winproto.CleanupIncident), true},
		"upper sha1":        {item("My", strings.Repeat("A", 40), sha256, winproto.CleanupAged), false},
		"upper sha256":      {item("My", sha1, strings.Repeat("B", 64), winproto.CleanupAged), false},
		"39 digit sha1":     {item("My", sha1[:39], sha256, winproto.CleanupAged), false},
		"63 digit sha256":   {item("My", sha1, sha256[:63], winproto.CleanupAged), false},
		"65 digit sha256":   {item("My", sha1, sha256+"b", winproto.CleanupAged), false},
		"non hex sha256":    {item("My", sha1, strings.Repeat("g", 64), winproto.CleanupAged), false},
		"bad store":         {item("My/Root", sha1, sha256, winproto.CleanupAged), false},
		"empty store":       {item("", sha1, sha256, winproto.CleanupAged), false},
		"root-like store":   {item("Root", sha1, sha256, "forced"), false},
		"empty reason":      {item("My", sha1, sha256, ""), false},
		"upper-case reason": {item("My", sha1, sha256, "AGED"), false},
	} {
		if got := winproto.ValidCleanupItem(c.in); got != c.want {
			t.Errorf("%s: %v, want %v", name, got, c.want)
		}
	}
}

func TestVersions(t *testing.T) {
	if winproto.Version != "1.2.0" || winproto.CleanupMinVersion != "0.3.0" || winproto.WriteMinVersion != "0.2.0" {
		t.Error("versions")
	}
	if !winproto.VersionAtLeast(winproto.Version, winproto.CleanupMinVersion) {
		t.Error("this helper is below its own cleanup minimum")
	}
	if winproto.VersionAtLeast("0.2.0", winproto.CleanupMinVersion) {
		t.Error("a 0.2.0 helper does not know iis-cleanup")
	}
	if !winproto.VersionAtLeast("0.2.0", winproto.WriteMinVersion) {
		t.Error("a 0.2.0 helper still writes")
	}
}

func TestCleanupBoundsAreConsistent(t *testing.T) {
	if winproto.JournalKeep >= winproto.JournalRetention {
		t.Error("the journal is kept for less than it is retained")
	}
	if winproto.CleanupMinAge != winproto.JournalKeep {
		t.Error("a certificate is cleaned no sooner than the journal that could restore it is kept")
	}
	if winproto.MaxCleanupItems > winproto.MaxCleanupCandidates {
		t.Error("an apply may not name more than a plan lists")
	}
}

// TestReleasedHelperVersion: 1.2.0 adds the RDP subcommands (R69) and 1.1.0 the CCS subcommands (R68)
// to the first released helper 1.0.0 (R63); the minimums stay, so a W3 0.3.0 helper still cleans and
// a 1.1.0 helper still manages CCS files, and versions compare numerically, not as text.
func TestReleasedHelperVersion(t *testing.T) {
	if winproto.Version != "1.2.0" || winproto.CCSMinVersion != "1.1.0" || winproto.RDPMinVersion != "1.2.0" {
		t.Fatalf("Version = %q, CCSMinVersion = %q, RDPMinVersion = %q", winproto.Version, winproto.CCSMinVersion, winproto.RDPMinVersion)
	}
	if !winproto.VersionAtLeast(winproto.Version, winproto.CCSMinVersion) {
		t.Error("Version below CCSMinVersion")
	}
	if !winproto.VersionAtLeast(winproto.Version, winproto.RDPMinVersion) {
		t.Error("Version below RDPMinVersion")
	}
	if winproto.VersionAtLeast("1.1.0", winproto.RDPMinVersion) {
		t.Error("a 1.1.0 helper has no RDP subcommands")
	}
	if !winproto.VersionAtLeast("1.1.0", winproto.CCSMinVersion) {
		t.Error("a 1.1.0 helper still manages CCS files")
	}
	if winproto.VersionAtLeast("1.0.0", winproto.CCSMinVersion) {
		t.Error("a 1.0.0 helper has no CCS subcommands")
	}
	if !winproto.VersionAtLeast("1.0.0", winproto.CleanupMinVersion) {
		t.Error("a 1.0.0 helper still cleans")
	}
	if !winproto.VersionAtLeast("1.10.0", "1.9.0") || winproto.VersionAtLeast("1.9.0", "1.10.0") {
		t.Error("1.10.0 must compare above 1.9.0 numerically")
	}
	if !winproto.VersionAtLeast(winproto.Version, winproto.WriteMinVersion) {
		t.Error("Version below WriteMinVersion")
	}
	if !winproto.VersionAtLeast(winproto.Version, winproto.CleanupMinVersion) {
		t.Error("Version below CleanupMinVersion")
	}
	if !winproto.VersionAtLeast("0.3.0", winproto.CleanupMinVersion) {
		t.Error("a 0.3.0 helper must still clean")
	}
	if winproto.VersionAtLeast("0.3.0", winproto.Version) {
		t.Error("0.3.0 is below the released version")
	}
	if !winproto.VersionAtLeast("1.0.0", "0.3.0") {
		t.Error("1.0.0 must compare above 0.3.0 numerically")
	}
	// R66: the discriminating case; as text "0.10.0" sorts below "0.9.0".
	if !winproto.VersionAtLeast("0.10.0", "0.9.0") {
		t.Error("0.10.0 must compare above 0.9.0 numerically")
	}
	if winproto.VersionAtLeast("0.9.0", "0.10.0") {
		t.Error("0.9.0 must compare below 0.10.0 numerically")
	}
}

func TestCCSFileNameRule(t *testing.T) {
	for host, file := range map[string]string{"www.example.com": "www.example.com.pfx", "*.example.com": "_.example.com.pfx"} {
		got, ok := winproto.CCSFileName(host)
		if !ok || got != file {
			t.Errorf("CCSFileName(%q) = %q, %v", host, got, ok)
		}
		back, ok := winproto.CCSHost(file)
		if !ok || back != host {
			t.Errorf("CCSHost(%q) = %q, %v", file, back, ok)
		}
	}
	for _, h := range []string{"WWW.example.com", "a..b", `a\b`, "a:b", "..", "*.", "*.*.example.com", strings.Repeat("a", 254), "bücher.example", ""} {
		if f, ok := winproto.CCSFileName(h); ok {
			t.Errorf("CCSFileName(%q) = %q", h, f)
		}
	}
	if h, ok := winproto.CCSHost("WWW.Example.COM.PFX"); !ok || h != "www.example.com" {
		t.Errorf("folded: %q %v", h, ok)
	}
	// The Kelvin sign folds to k under Unicode lower-casing; only ASCII folds.
	for _, n := range []string{"x.pfx.bak", ".alice-" + strings.Repeat("0", 8) + ".tmp", "_..pfx", ".pfx", "pfx", "a.pf\u212a", "www.\u212a.pfx", "bücher.pfx"} {
		if h, ok := winproto.CCSHost(n); ok {
			t.Errorf("CCSHost(%q) = %q", n, h)
		}
	}
}

func TestValidCCSPassword(t *testing.T) {
	for n, want := range map[int]bool{11: false, 12: true, 128: true, 129: false} {
		if got := winproto.ValidCCSPassword([]byte(strings.Repeat("a", n))); got != want {
			t.Errorf("length %d = %v", n, got)
		}
	}
	for _, bad := range []string{"abcdefgh ijkl", "abcdefgh\tijkl", "abcdefghijk\u00e9", "abcdefghijk\x00"} {
		if winproto.ValidCCSPassword([]byte(bad)) {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestValidCCSPath(t *testing.T) {
	for p, want := range map[string]bool{
		`C:\CCS`: true, `D:\Certs\IIS`: true, `C:\CCS\`: true, `c:\ccs`: true,
		`\\srv\certs`: false, `\\?\C:\CCS`: false, `\\.\C:\CCS`: false, `C:CCS`: false, `C:\a\..\b`: false,
		`C:\a*`: false, `C:\a?`: false, `C:\a"b`: false, `C:\a<b`: false, `C:\a>b`: false, `C:\a|b`: false,
		"C:\\a\x01": false, `1:\CCS`: false, `C:/CCS`: false, ``: false, `C:`: false,
		`C:\` + strings.Repeat("a", 237): true, `C:\` + strings.Repeat("a", 238): false,
		`C:\a:b`: false, `C:\a/b`: false, `C:\.\a`: false, `C:\a\.`: false, `C:\.`: false, `C:\..`: false,
		`C:\a.b`: true, `C:\..a\.b`: true, `z:\x`: true, `[:\x`: false, `@:\x`: false,
		`C:\a.`: false, `C:\a.\b`: false, `C:\a `: false, `C:\a \b`: false, `C:\a.b.\`: false, `C:\a. \`: false,
		`C:\ a`: true, `C:\a b`: true, `C:\.a`: true,
	} {
		if got := winproto.ValidCCSPath(p); got != want {
			t.Errorf("ValidCCSPath(%q) = %v", p, got)
		}
	}
}

func TestCCSInputsRedact(t *testing.T) {
	const pw, key = "PASSWORDSECRET1", "KEYSECRETMATERIAL"
	dump := winproto.CCSDumpInput{Password: pw}
	deploy := winproto.CCSDeployInput{Path: `C:\CCS`, Host: "a.example.com", ChainPEM: "x", KeyPEM: key, Password: pw}
	for _, f := range []string{"%v", "%+v", "%#v", "%s"} {
		for _, v := range []any{dump, &dump, deploy, &deploy, []winproto.CCSDeployInput{deploy}, struct{ In winproto.CCSDumpInput }{dump}} {
			if out := fmt.Sprintf(f, v); strings.Contains(out, pw) || strings.Contains(out, key) {
				t.Errorf("%s printed a secret: %s", f, out)
			}
		}
	}
	var buf bytes.Buffer
	slog.New(slog.NewJSONHandler(&buf, nil)).Info("m", "d", dump, "p", &dump, "e", deploy, "q", &deploy)
	if strings.Contains(buf.String(), pw) || strings.Contains(buf.String(), key) {
		t.Errorf("slog printed a secret: %s", buf.String())
	}
	if b, err := json.Marshal(deploy); err != nil || !strings.Contains(string(b), pw) {
		t.Errorf("wire form: %s %v", b, err)
	}
}

func TestCCSShapesJSON(t *testing.T) {
	want := func(s string) []string { f := strings.Fields(s); sort.Strings(f); return f }
	check := func(name string, got, exp []string) {
		if !reflect.DeepEqual(got, exp) {
			t.Errorf("%s keys: %v, want %v", name, got, exp)
		}
	}
	check("dump input", keys(t, winproto.CCSDumpInput{}), want("password"))
	check("file", keys(t, winproto.CCSFile{}), want("name host file_sha256 modified_at leaf_der problem size chain"))
	check("dump", keys(t, winproto.CCSDumpResponse{}), want("ok enabled local path files ignored truncated"))
	check("deploy input", keys(t, winproto.CCSDeployInput{}), want("path host expect_sha256 chain_pem key_pem password forbidden_spki_sha256 forbidden_leaf_sha256"))
}

func TestCCSConstants(t *testing.T) {
	if winproto.SubCCSDump != "ccs-dump" || winproto.SubCCSDeploy != "ccs-deploy" || winproto.StepWriteFile != "write_file" ||
		winproto.JournalKindCCS != "ccs_file" || winproto.LocatorCCSFile != "ccs_file" || winproto.CCSPickupWait != 0 ||
		winproto.MaxCCSFiles != 500 || winproto.MaxCCSFile != 256<<10 || winproto.MaxCCSDumpInput != 4<<10 ||
		winproto.MaxCCSDeployInput != 256<<10 || winproto.MinCCSPassword != 12 || winproto.MaxCCSPassword != 128 || winproto.MaxCCSPath != 240 {
		t.Error("CCS constants")
	}
	for got, want := range map[string]string{
		winproto.CodeCCSDisabled: "CCS_DISABLED", winproto.CodeCCSPathChanged: "CCS_PATH_CHANGED",
		winproto.CodeCCSPathUnsupported: "CCS_PATH_UNSUPPORTED", winproto.CodeCCSPasswordMismatch: "CCS_PASSWORD_MISMATCH",
		winproto.CodeCCSFileNotFound: "CCS_FILE_NOT_FOUND", winproto.CCSProblemPasswordMismatch: "ccs_password_mismatch",
		winproto.CCSProblemNotPFX: "not_a_pfx", winproto.CCSProblemNoKey: "key_missing", winproto.CCSProblemTooLarge: "too_large",
		winproto.WarnCCSRemote: "win_ccs_remote", winproto.WarnCCSPathUnsupported: "win_ccs_path_unsupported",
		winproto.WarnCCSFilesIgnored: "win_ccs_files_ignored",
	} {
		if got != want {
			t.Errorf("%q, want %q", got, want)
		}
	}
}

func TestRDPInputRedacts(t *testing.T) {
	const key = "-----BEGIN PRIVATE KEY-----\nRDPSECRETKEYMATERIAL\n-----END PRIVATE KEY-----\n"
	in := winproto.RDPDeployInput{ExpectSHA256: strings.Repeat("a", 64), ChainPEM: "x", KeyPEM: key}
	for _, f := range []string{"%v", "%+v", "%#v", "%s"} {
		for _, v := range []any{in, &in, []winproto.RDPDeployInput{in}, struct{ In winproto.RDPDeployInput }{in}} {
			if out := fmt.Sprintf(f, v); strings.Contains(out, "RDPSECRETKEYMATERIAL") || strings.Contains(out, "PRIVATE KEY") {
				t.Errorf("%s printed the key: %s", f, out)
			}
		}
	}
	var buf bytes.Buffer
	slog.New(slog.NewJSONHandler(&buf, nil)).Info("m", "in", in, "ptr", &in)
	if strings.Contains(buf.String(), "RDPSECRETKEYMATERIAL") {
		t.Errorf("slog printed the key: %s", buf.String())
	}
	if b, err := json.Marshal(in); err != nil || !strings.Contains(string(b), "RDPSECRETKEYMATERIAL") {
		t.Errorf("wire form: %s %v", b, err)
	}
}

func TestRDPShapesJSON(t *testing.T) {
	want := func(s string) []string { f := strings.Fields(s); sort.Strings(f); return f }
	check := func(name string, got, exp []string) {
		if !reflect.DeepEqual(got, exp) {
			t.Errorf("%s keys: %v, want %v", name, got, exp)
		}
	}
	check("dump", keys(t, winproto.RDPDumpResponse{}), want("ok present enabled nla value_set port security_layer cert_template certificate self_signed_count"))
	check("deploy input", keys(t, winproto.RDPDeployInput{}), want("expect_sha256 chain_pem key_pem forbidden_spki_sha256 forbidden_leaf_sha256"))
}

func TestRDPConstants(t *testing.T) {
	if winproto.RDPPickupWait != 0 {
		t.Error("RDPPickupWait")
	}
	for got, want := range map[string]string{
		winproto.SubRDPDump: "rdp-dump", winproto.SubRDPDeploy: "rdp-deploy", winproto.ArgRDP: "--rdp",
		winproto.CodeRDPDisabled: "RDP_DISABLED", winproto.CodeRDPTLSOff: "RDP_TLS_OFF",
		winproto.JournalKindRDP: "rdp_listener", winproto.LocatorRDP: "rdp", winproto.RDPListenerName: "RDP-Tcp",
		winproto.RDPCanonical: "rdp/RDP-Tcp", winproto.RDPStoreSelfSigned: "Remote Desktop",
		winproto.UnsupportedRDPDisabled: "win_rdp_disabled", winproto.UnsupportedRDPNoTLS: "win_rdp_no_tls",
		winproto.UnsupportedRDPCertUnknown: "win_rdp_cert_unknown", winproto.WarnRDPAutoenroll: "win_rdp_autoenroll",
		winproto.WarnRDPHelperOutdated: "win_rdp_helper_outdated",
	} {
		if got != want {
			t.Errorf("%q, want %q", got, want)
		}
	}
	if !winproto.ValidToken(winproto.SubRDPDump) || !winproto.ValidToken(winproto.SubRDPDeploy) || !winproto.ValidToken(winproto.ArgRDP) {
		t.Error("an RDP command-line token is not a ValidToken")
	}
}
