package winproto_test

import (
	"bytes"
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

func TestStepsEqualTheProviders(t *testing.T) {
	for _, c := range [][2]string{
		{winproto.StepImportChain, providers.StepNameImportChain},
		{winproto.StepImportCertificate, providers.StepNameImportCertificate},
		{winproto.StepBind, providers.StepNameBind},
		{winproto.StepJournal, providers.StepNameJournal},
		{winproto.StepRestore, providers.StepNameRestore},
		{winproto.ErrForbidden, providers.DeployErrForbidden},
		{winproto.ErrFileChanged, providers.DeployErrFileChanged},
	} {
		if c[0] != c[1] {
			t.Errorf("%q != %q", c[0], c[1])
		}
	}
	for got, want := range map[string]string{
		winproto.ErrKeyUnusable: "key_unusable", winproto.ErrReadBack: "read_back", winproto.ErrStore: "store_error",
		winproto.ErrBackupMissing: "backup_missing",
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
	if winproto.Version != "0.2.0" || winproto.WriteMinVersion != "0.2.0" || winproto.Protocol != 1 || winproto.MinProtocol != 1 {
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
