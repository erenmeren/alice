package helperproto

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidArg(t *testing.T) {
	longest := "/" + strings.Repeat("a", 4095) // 4096 bytes: the limit
	for _, tc := range []struct {
		in string
		ok bool
	}{
		{"/home/deploy/.ssh/authorized_keys", true},
		{"deploy@web-01:22", true},
		{"a+b-c_d.e", true},
		{"a..b", true},
		{"...", true},
		{longest, true},
		{"", false},
		{longest + "a", false},
		{"; rm -rf /", false},
		{"`id`", false},
		{"$(id)", false},
		{"a\nb", false},
		{"a\rb", false},
		{"a\tb", false},
		{"a\x00b", false},
		{"kullanıcı", false},
		{"İ", false},
		{"..", false},
		{"/a/../b", false},
		{"../etc/shadow", false},
		{"-rf", false},
		{"--op", false},
		{" a", false},
		{"a ", false},
		{"a'b", false},
		{`a"b`, false},
		{"a|b", false},
		{"a;b", false},
		{"a&b", false},
		{"a>b", false},
		{"*", false},
		{"a?", false},
		{"~root", false},
		{`a\b`, false},
		{"a=b", false},
		{"a,b", false},
	} {
		assert.Equal(t, tc.ok, ValidArg(tc.in), "%q", tc.in)
	}
}

func TestValidPath(t *testing.T) {
	for _, tc := range []struct {
		in string
		ok bool
	}{
		{"/home/deploy/.ssh/authorized_keys", true},
		{"/", true},
		{"/etc/ssh/authorized_keys/deploy", true},
		{"home/deploy", false},
		{"/a//b", false},
		{"/a/b/", false},
		{"/a/./b", false},
		{"/a/../b", false},
		{"/a b", false},
		{"/a;b", false},
	} {
		assert.Equal(t, tc.ok, ValidPath(tc.in), "%q", tc.in)
	}
}

func TestValidUser(t *testing.T) {
	for _, tc := range []struct {
		in string
		ok bool
	}{
		{"deploy", true},
		{"_svc", true},
		{"alice-svc", true},
		{"root", true},
		{strings.Repeat("a", 32), true},
		{strings.Repeat("a", 33), false},
		{"", false},
		{"Root", false},
		{"1abc", false},
		{"-a", false},
		{"a.b", false},
		{"kullanıcı", false},
		{"a b", false},
		{"a;b", false},
		{"a\n", false},
	} {
		assert.Equal(t, tc.ok, ValidUser(tc.in), "%q", tc.in)
	}
}

func TestValidOpID(t *testing.T) {
	for _, tc := range []struct {
		in string
		ok bool
	}{
		{"0190f5a0-0000-7000-8000-000000000001", true},
		{"0190F5A0-0000-7000-8000-000000000001", false},
		{"0190f5a0000070008000000000000001", false},
		{"0190f5a0-0000-7000-8000-00000000000g", false},
		{"0190f5a0-0000-7000-8000-0000000000011", false},
		{"0190f5a00-000-7000-8000-000000000001", false},
		{"------------------------------------", false},
		{"../../../../../../../../../../../etc", false},
		{"", false},
	} {
		assert.Equal(t, tc.ok, ValidOpID(tc.in), "%q", tc.in)
	}
}

func TestValidSHA256(t *testing.T) {
	assert.True(t, ValidSHA256(strings.Repeat("a", 64)))
	assert.True(t, ValidSHA256("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"))
	assert.True(t, ValidSHA256(AbsentSHA256))
	assert.False(t, ValidSHA256(strings.Repeat("a", 63)))
	assert.False(t, ValidSHA256(strings.Repeat("a", 65)))
	assert.False(t, ValidSHA256(strings.Repeat("A", 64)))
	assert.False(t, ValidSHA256(strings.Repeat("g", 64)))
	assert.False(t, ValidSHA256(""))
	assert.False(t, ValidSHA256("Absent"))
}

// The JSON names are the wire protocol; Alice (Task 8) and the helper (Tasks 6–7) must agree.
func TestWireNames(t *testing.T) {
	b, err := json.Marshal(AuthKeysListResponse{OK: true, Users: []UserFiles{{User: "deploy", UID: 1001, Home: "/home/deploy",
		Files: []FileInfo{{Path: "/home/deploy/.ssh/authorized_keys", Exists: true, Size: 3, SHA256: "x", Mode: "0600",
			Owner: "deploy", StrictModesOK: true}}}}, AuthorizedKeysCommand: "none", Warnings: []string{WarnSSHDUnreadable},
		Accounts: []string{"deploy", "root"}, AccountsComplete: true, Unlisted: []UnlistedAccount{}})
	require.NoError(t, err)
	assert.JSONEq(t, `{"ok":true,"users":[{"user":"deploy","uid":1001,"home":"/home/deploy","files":[{"path":"/home/deploy/.ssh/authorized_keys",
		"exists":true,"size":3,"sha256":"x","mode":"0600","owner":"deploy","strict_modes_ok":true,"too_large":false,"unsupported":false,"inline":false}],"sshd_unreadable":false,"authorized_keys_command":""}],
		"authorized_keys_command":"none","warnings":["sshd_unreadable"],"accounts":["deploy","root"],"accounts_complete":true,"unlisted":[],"truncated":false}`, string(b))
	b, err = json.Marshal(ErrorResponse{Code: CodePathNotAllowed, Message: "m"})
	require.NoError(t, err)
	assert.JSONEq(t, `{"ok":false,"code":"PATH_NOT_ALLOWED","message":"m"}`, string(b))
	b, err = json.Marshal(AuthKeysReadResponse{OK: true, Path: "/p", SHA256: "s", ContentB64: "Yw==", Owner: "deploy"})
	require.NoError(t, err)
	assert.JSONEq(t, `{"ok":true,"path":"/p","sha256":"s","content_b64":"Yw==","owner":"deploy","uid":0}`, string(b))
	b, err = json.Marshal(HostKeysResponse{OK: true, Keys: []HostKeyInfo{{Type: "ssh-ed25519", Bits: 256, Fingerprint: "SHA256:x", Path: "/k.pub"}}})
	require.NoError(t, err)
	assert.JSONEq(t, `{"ok":true,"keys":[{"type":"ssh-ed25519","bits":256,"fingerprint":"SHA256:x","path":"/k.pub"}]}`, string(b))
	assert.Equal(t, 7, Protocol)
	assert.Equal(t, "/usr/local/libexec/alice-helper", HelperPath)
	assert.Equal(t, 1<<20, MaxAuthorizedKeysSize)
}

func TestProtocol5(t *testing.T) {
	assert.Equal(t, "nginx-fence", SubNginxFence)
	assert.Equal(t, "fenced", PhaseFenced)
	assert.Equal(t, "FENCED", CodeFenced)
	assert.Equal(t, 20<<20, MaxNginxConfig)
	assert.Equal(t, 7*24*time.Hour, NginxBackupKeep)
}

func TestNginxWarningCodes(t *testing.T) {
	assert.Equal(t, "stream_tls", WarnStreamTLS)
	assert.Equal(t, "mail_tls", WarnMailTLS)
	assert.Equal(t, "config_file_writable", WarnConfigFileWritable)
	assert.Equal(t, "too_many_files", WarnTooManyFiles)
	assert.Equal(t, "certificate_block_dropped", WarnCertificateBlockDropped)
	assert.Equal(t, "OUTPUT_TOO_LARGE", CodeOutputTooLarge)
}

func TestValidPort(t *testing.T) {
	for in, want := range map[string]bool{"1": true, "443": true, "65535": true, "0": false, "65536": false, "0443": false,
		"": false, "-1": false, "4a": false, "443 ": false, "123456": false} {
		assert.Equal(t, want, ValidPort(in), in)
	}
}

func TestValidSNI(t *testing.T) {
	for in, want := range map[string]bool{"www.example.test": true, "alice-check.example.test": true, "localhost": true,
		"WWW.example.test": false, "": false, ".a": false, "a.": false, "a..b": false, "-a.b": false, "a-.b": false,
		"*.a.b": false, "a b": false, "a_b.c": false, strings.Repeat("a", 64) + ".b": false, "ö.example": false,
		"10.0.0.5": false, "127.0.0.1": false,
		strings.Repeat("a", 63) + ".b": true, strings.Repeat("a", 64): false,
		strings.Repeat(strings.Repeat("a", 61)+".", 4) + "bcdef":  true,  // 253 bytes
		strings.Repeat(strings.Repeat("a", 61)+".", 4) + "bcdefg": false, // 254 bytes
		"::1": false, "2001:db8::5": false, NoSNI: false} {
		assert.Equal(t, want, ValidSNI(in), in)
	}
}

func TestValidIP(t *testing.T) {
	for in, want := range map[string]bool{"127.0.0.1": true, "::1": true, "10.0.0.5": true, "2001:db8::5": true,
		"fe80::1%eth0": false, "::ffff:127.0.0.1": true, "2001:DB8::5": false, "localhost": false, "": false, "1.2.3": false} {
		assert.Equal(t, want, ValidIP(in), in)
	}
}

func TestProtocol4WireNames(t *testing.T) {
	b, err := json.Marshal(NginxDeployResponse{OK: true, Phase: PhaseCommitted, Steps: []NginxStep{{Name: StepBackup, Status: "ok"}},
		BackupDir: BackupRoot + "/x"})
	require.NoError(t, err)
	assert.JSONEq(t, `{"ok":true,"phase":"committed","failed_step":"","cause_step":"","error":"","steps":[{"name":"backup","status":"ok","error":""}],
		"backup_dir":"/var/lib/alice-helper/backups/x"}`, string(b))
	b, err = json.Marshal(AuthKeysListResponse{OK: true, Users: []UserFiles{}, Warnings: []string{}, Accounts: []string{"a"}, AccountsComplete: true})
	require.NoError(t, err)
	assert.Contains(t, string(b), `"accounts":["a"],"accounts_complete":true`)
	b, err = json.Marshal(NginxFile{Path: "/p", Kind: "key", Exists: true})
	require.NoError(t, err)
	assert.JSONEq(t, `{"path":"/p","kind":"key","exists":true,"resolved":"","symlinked":false,"mode":"","owner":"","group":"","size":0,
		"sha256":"","pem":"","problem":"","free_bytes":0}`, string(b))
	assert.Equal(t, []string{"missing", "not_root_controlled", "not_regular", "hard_linked", "too_large", "not_a_certificate",
		"unreadable", "bad_name", "special_filesystem", "name_not_allowed"}, []string{FileMissing, FileNotRootControlled, FileNotRegular,
		FileHardLinked, FileTooLarge, FileNotACertificate, FileUnreadable, FileBadName, FileSpecialFS, FileNameNotAllowed})
	assert.Equal(t, "key_group_open", WarnKeyGroupOpen)
	assert.Equal(t, "SUPERSEDED", CodeSuperseded)
	b, err = json.Marshal(NginxStatusResponse{OK: true, Phase: PhaseRestoreFailed, FailedStep: StepRestore, CauseStep: StepConfigTest})
	require.NoError(t, err)
	assert.JSONEq(t, `{"ok":true,"phase":"restore_failed","active":false,"failed_step":"restore","cause_step":"config_test","error":"",
		"new_cert_sha256":"","current_cert_sha256":"","backup_dir":""}`, string(b))
	b, err = json.Marshal(NginxRestoreResponse{OK: true, Phase: PhaseRestored, Steps: []NginxStep{}})
	require.NoError(t, err)
	assert.JSONEq(t, `{"ok":true,"phase":"restored","failed_step":"","cause_step":"","error":"","steps":[]}`, string(b))
}

func TestNginxConfigErrorWireNames(t *testing.T) {
	assert.Equal(t, "untrusted", ConfigErrUntrusted)
	assert.Equal(t, "unsupported", ConfigErrUnsupported)
	assert.Equal(t, []string{"not_root_controlled", "special_filesystem", "missing", "not_regular", "changed",
		"name_not_allowed", "unexpected_text", "wrong_first_file", "duplicate_file", "no_conf_path", "too_large",
		"too_complex", "include_loop", "nul_byte"},
		[]string{ConfigReasonNotRootControlled, ConfigReasonSpecialFS, ConfigReasonMissing, ConfigReasonNotRegular,
			ConfigReasonChanged, ConfigReasonNameNotAllowed, ConfigReasonUnexpectedText, ConfigReasonWrongFirstFile,
			ConfigReasonDuplicateFile, ConfigReasonNoConfPath, ConfigReasonTooLarge, ConfigReasonTooComplex,
			ConfigReasonIncludeLoop, ConfigReasonNULByte})
	b, err := json.Marshal(NginxDumpResponse{OK: true, ConfigError: ConfigErrUntrusted, ConfigErrorReason: ConfigReasonNotRootControlled,
		ConfigErrorFile: "/etc/nginx/conf.d/www.conf", Servers: []NginxServer{}, Files: []NginxFile{}, Warnings: []string{}, Writable: []string{}})
	require.NoError(t, err)
	assert.JSONEq(t, `{"ok":true,"version":"","conf_path":"","config_valid":false,"config_error":"untrusted",
		"config_error_reason":"not_root_controlled","config_error_file":"/etc/nginx/conf.d/www.conf",
		"servers":[],"files":[],"warnings":[],"writable":[]}`, string(b))
}

func TestNginxDeployInputIsNotPrintable(t *testing.T) {
	in := NginxDeployInput{CertPEM: "CERT", KeyPEM: "SECRETKEYMATERIAL"}
	for _, f := range []string{"%v", "%+v", "%#v", "%s"} {
		assert.NotContains(t, fmt.Sprintf(f, in), "SECRETKEYMATERIAL", f)
		assert.NotContains(t, fmt.Sprintf(f, &in), "SECRETKEYMATERIAL", f)
	}
	var buf bytes.Buffer
	slog.New(slog.NewJSONHandler(&buf, nil)).Info("m", "in", in, "ptr", &in)
	assert.NotContains(t, buf.String(), "SECRETKEYMATERIAL")
	b, err := json.Marshal(in) // the wire form still carries both fields
	require.NoError(t, err)
	assert.JSONEq(t, `{"cert_pem":"CERT","key_pem":"SECRETKEYMATERIAL"}`, string(b))
}

func TestProbeTLSConfig(t *testing.T) {
	c := ProbeTLSConfig("www.example.test", ProbeAny)
	assert.True(t, c.InsecureSkipVerify)
	assert.Equal(t, "www.example.test", c.ServerName)
	assert.Equal(t, uint16(tls.VersionTLS12), c.MinVersion)
	assert.Zero(t, c.MaxVersion) // TLS 1.3-only sites stay probeable
	assert.Empty(t, c.CipherSuites)
	assert.Empty(t, ProbeTLSConfig(NoSNI, ProbeAny).ServerName)
	assert.Empty(t, ProbeTLSConfig("", ProbeAny).ServerName)
	r := ProbeTLSConfig("", ProbeRSA)
	assert.Equal(t, uint16(tls.VersionTLS12), r.MaxVersion)
	assert.Contains(t, r.CipherSuites, tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256)
	assert.NotContains(t, r.CipherSuites, tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256)
	e := ProbeTLSConfig("", ProbeECDSA)
	assert.Equal(t, uint16(tls.VersionTLS12), e.MaxVersion)
	assert.Contains(t, e.CipherSuites, tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256)
	assert.NotContains(t, e.CipherSuites, tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256)
}

// AUD-03: the account names the helper lists from /etc/passwd (R39).
func TestValidAccount(t *testing.T) {
	for _, tc := range []struct {
		in string
		ok bool
	}{
		{"deploy", true}, {"john.doe", true}, {"Deploy2", true}, {"_svc", true}, {"1abc", true}, {"a", true}, {"A", true},
		{"a.b-c_d", true}, {"host$", true}, {"user$", true}, {"a..", true}, {"a.", true}, {"_", true}, {"0x10", true},
		{strings.Repeat("a", 32), true}, {strings.Repeat("a", 31) + "$", true}, {"John", true}, {"john", true},
		{"", false}, {"$", false}, {"123", false}, {"123$", false}, {"0", false}, {"-a", false}, {"-x", false},
		{".hidden", false}, {".", false}, {"..", false}, {"a b", false}, {" a", false}, {"a\t", false},
		{"a,b", false}, {"a/b", false}, {"/", false}, {"a:b", false}, {"a=b", false}, {"a'b", false}, {`a"b`, false},
		{"a;b", false}, {"a`b", false}, {"a*", false}, {"a@b", false}, {"a+b", false}, {"a%u", false}, {`a\b`, false},
		{"kullanıcı", false}, {"é", false}, {"İ", false}, {"a\n", false}, {"a\x00", false}, {"a\x7f", false}, {"\x1b[31m", false},
		{strings.Repeat("a", 33), false}, {strings.Repeat("a", 32) + "$", false}, {"a$$", false}, {"a$b", false}, {"$a", false},
	} {
		assert.Equal(t, tc.ok, ValidAccount(tc.in), "%q", tc.in)
	}
	// Every name ValidUser accepts is an account name too.
	for _, n := range []string{"deploy", "_svc", "alice-svc", "root", strings.Repeat("a", 32)} {
		assert.True(t, ValidUser(n) && ValidAccount(n), n)
	}
}

// Wherever an account name travels (an "sshd -T -C user=<name>,host=…" argument, %u in an expanded
// path, JSON, a log line, an SQL parameter, a web page as text), it never carries a byte that has a
// meaning there. Checked over random strings of a hostile alphabet.
func TestValidAccountIsSafeWhereverANameTravels(t *testing.T) {
	alphabet := []byte("aZ09._-$,/:= \t\n\x00\x7f'\"`;|&*?%@+\\\xc3\xa9#!~")
	seed := uint64(42)
	next := func(n int) int { // a fixed linear congruential sequence: the cases are the same on every run
		seed = seed*6364136223846793005 + 1442695040888963407
		return int((seed >> 33) % uint64(n))
	}
	accepted := 0
	for i := 0; i < 200000; i++ {
		b := make([]byte, 1+next(34))
		for j := range b {
			b[j] = alphabet[next(len(alphabet))]
		}
		s := string(b)
		if ValidUser(s) {
			assert.True(t, ValidAccount(s), "%q: a ValidUser name is an account name", s)
		}
		if !ValidAccount(s) {
			continue
		}
		accepted++
		assert.LessOrEqual(t, len(s), 32, "%q", s)
		assert.False(t, strings.ContainsAny(s, ",/:= \t\n\x00\x7f'\"`;|&*?%@+\\#!~"), "%q", s)
		assert.NotContains(t, []string{".", ".."}, s)
		assert.False(t, strings.HasPrefix(s, "-") || strings.HasPrefix(s, "."), "%q would read as an option or a hidden name", s)
		assert.True(t, ValidArg(strings.TrimSuffix(s, "$")), "%q: without its final $ it is a helper argument", s)
		assert.Equal(t, strings.Count(s, "$") == 1, strings.HasSuffix(s, "$"), "%q: a $ only at the end", s)
	}
	assert.Positive(t, accepted, "the generator produces valid names too")
}

func TestCleanHome(t *testing.T) {
	for _, tc := range []struct {
		in, out string
		ok      bool
	}{
		{"/home/x", "/home/x", true}, {"/home/x/", "/home/x", true}, {"/home/x//", "/home/x", true}, {"/home//x", "/home/x", true},
		{"/home/./x", "/home/x", true}, {"/home/x/.", "/home/x", true}, {"/", "/", true}, {"//", "/", true}, {"/root", "/root", true},
		{"/root/", "/root", true}, {"/home/John.Doe", "/home/John.Doe", true},
		{"", "", false}, {"home/x", "", false}, {".", "", false}, {"./x", "", false}, {"/home/x/../y", "", false}, {"/..", "", false},
		{"/home/x/..", "", false}, {"/home/a b", "", false}, {"/home/a;b", "", false}, {"/home/host$", "", false},
		{"/home/x\n", "", false}, {"/home/kullanıcı", "", false}, {"/" + strings.Repeat("a", 4096), "", false},
	} {
		out, ok := CleanHome(tc.in)
		assert.Equal(t, tc.ok, ok, "%q", tc.in)
		assert.Equal(t, tc.out, out, "%q", tc.in)
	}
}

func TestProtocol6WireShapes(t *testing.T) {
	b, err := json.Marshal(AuthKeysListResponse{OK: true, Users: []UserFiles{{User: "john.doe", Files: []FileInfo{
		{Path: "/home/john.doe/.ssh/authorized_keys", Exists: true, SHA256: "ab", Inline: true, ContentB64: "eA=="}, {Path: "/x"}}}},
		Unlisted: []UnlistedAccount{{UID: 1009, Reason: UnlistedName}}, Truncated: true})
	require.NoError(t, err)
	s := string(b)
	assert.Contains(t, s, `"unlisted":[{"uid":1009,"reason":"name"}]`)
	assert.Contains(t, s, `"inline":true,"content_b64":"eA=="`)
	assert.Contains(t, s, `{"path":"/x","exists":false`)
	assert.NotContains(t, s[strings.Index(s, `"/x"`):], "content_b64", "an empty content is omitted")
	assert.Contains(t, s, `"truncated":true`)
	assert.Equal(t, 6, MinProtocol, "protocol 6 stays the minimum for every existing operation (A1)")
	assert.Equal(t, "1.6.0", Version)
	assert.Equal(t, "name", UnlistedName)
	assert.Equal(t, "home", UnlistedHome)
	assert.Equal(t, "account_name_unsupported", WarnAccountNameUnsupported)
	assert.Equal(t, "account_home_unsupported", WarnAccountHomeUnsupported)
	assert.Equal(t, 100, MaxUnlistedAccounts)
	// S8: the inline content, in base64, leaves room for the rest of the answer below its bound,
	// which stays below what Alice reads (linuxssh.DefaultMaxOutput, 8 MiB; checked there).
	assert.Less(t, (MaxListInline+2)/3*4, MaxListOutput)
	assert.Equal(t, 7<<20, MaxListOutput)
}

// Fix round 1: the read answer carries the resolved account's uid (I1), the listing names the
// first user it left out (M5), and the codes of the round.
func TestProtocol6FixRoundWireShapes(t *testing.T) {
	b, err := json.Marshal(AuthKeysReadResponse{OK: true, Path: "/p", SHA256: "s", ContentB64: "", Owner: "Toor", UID: 0})
	require.NoError(t, err)
	assert.Contains(t, string(b), `"owner":"Toor","uid":0`)
	uid := 1500
	b, err = json.Marshal(AuthKeysListResponse{Truncated: true, TruncatedFromUID: &uid})
	require.NoError(t, err)
	assert.Contains(t, string(b), `"truncated":true,"truncated_from_uid":1500`)
	b, err = json.Marshal(AuthKeysListResponse{})
	require.NoError(t, err)
	assert.NotContains(t, string(b), "truncated_from_uid")
	assert.Equal(t, "id", UnlistedID)
	assert.Equal(t, "account_id_unsupported", WarnAccountIDUnsupported)
	assert.Equal(t, "accounts_nul_byte", WarnAccountsNUL)
}

func bigFile(path string, n int) FileInfo {
	return FileInfo{Path: path, Exists: true, SHA256: "x", Inline: true, ContentB64: strings.Repeat("A", n)}
}

// S8: FitList gives up inline content first (the last files first), then users from the end
// (naming the first one left out), then the account names; it always ends.
func TestFitList(t *testing.T) {
	small := AuthKeysListResponse{OK: true, Users: []UserFiles{{User: "root", Files: []FileInfo{bigFile("/a", 10)}}}, AccountsComplete: true}
	assert.Equal(t, small, FitList(small), "an answer within the bound is unchanged")

	inline := AuthKeysListResponse{OK: true, AccountsComplete: true, Users: []UserFiles{
		{User: "root", Files: []FileInfo{bigFile("/a", 3<<20), bigFile("/b", 3<<20)}},
		{User: "deploy", UID: 1001, Files: []FileInfo{{Path: "/c"}, bigFile("/d", 3<<20)}}}}
	out := FitList(inline)
	assert.False(t, out.Truncated)
	assert.True(t, out.AccountsComplete)
	assert.True(t, out.Users[0].Files[0].Inline)
	assert.True(t, out.Users[0].Files[1].Inline)
	assert.False(t, out.Users[1].Files[1].Inline, "the last file gave up its content")
	assert.Empty(t, out.Users[1].Files[1].ContentB64)
	assert.Equal(t, "x", out.Users[1].Files[1].SHA256)

	var users []UserFiles
	for i := 0; i < 9; i++ {
		users = append(users, UserFiles{User: fmt.Sprintf("u%d", i), UID: 2000 + i, Files: []FileInfo{{Path: "/" + strings.Repeat("p", 1<<20)}}})
	}
	out = FitList(AuthKeysListResponse{OK: true, AccountsComplete: true, Users: users})
	assert.True(t, out.Truncated)
	assert.False(t, out.AccountsComplete)
	assert.Len(t, out.Users, 6)
	require.NotNil(t, out.TruncatedFromUID)
	assert.Equal(t, 2006, *out.TruncatedFromUID)
	b, err := json.Marshal(out)
	require.NoError(t, err)
	assert.Less(t, len(b), MaxListOutput)

	out = FitList(AuthKeysListResponse{OK: true, Users: []UserFiles{}, Accounts: []string{strings.Repeat("a", MaxListOutput)}, AccountsComplete: true})
	assert.True(t, out.Truncated)
	assert.False(t, out.AccountsComplete)
	assert.Empty(t, out.Accounts)
	assert.Nil(t, out.TruncatedFromUID)

	// Nothing left to give up: it still ends.
	out = FitList(AuthKeysListResponse{Warnings: []string{strings.Repeat("w", MaxListOutput)}})
	assert.True(t, out.Truncated)

	// An answer that cannot be encoded is returned as it is (writeJSON then answers IO_ERROR).
	marshal = func(any) ([]byte, error) { return nil, errors.New("boom") }
	t.Cleanup(func() { marshal = json.Marshal })
	assert.Equal(t, small, FitList(small))
}
