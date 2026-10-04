package helperproto

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
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
		Accounts: []string{"deploy", "root"}, AccountsComplete: true})
	require.NoError(t, err)
	assert.JSONEq(t, `{"ok":true,"users":[{"user":"deploy","uid":1001,"home":"/home/deploy","files":[{"path":"/home/deploy/.ssh/authorized_keys",
		"exists":true,"size":3,"sha256":"x","mode":"0600","owner":"deploy","strict_modes_ok":true,"too_large":false,"unsupported":false}],"sshd_unreadable":false,"authorized_keys_command":""}],
		"authorized_keys_command":"none","warnings":["sshd_unreadable"],"accounts":["deploy","root"],"accounts_complete":true}`, string(b))
	b, err = json.Marshal(ErrorResponse{Code: CodePathNotAllowed, Message: "m"})
	require.NoError(t, err)
	assert.JSONEq(t, `{"ok":false,"code":"PATH_NOT_ALLOWED","message":"m"}`, string(b))
	b, err = json.Marshal(AuthKeysReadResponse{OK: true, Path: "/p", SHA256: "s", ContentB64: "Yw==", Owner: "deploy"})
	require.NoError(t, err)
	assert.JSONEq(t, `{"ok":true,"path":"/p","sha256":"s","content_b64":"Yw==","owner":"deploy"}`, string(b))
	b, err = json.Marshal(HostKeysResponse{OK: true, Keys: []HostKeyInfo{{Type: "ssh-ed25519", Bits: 256, Fingerprint: "SHA256:x", Path: "/k.pub"}}})
	require.NoError(t, err)
	assert.JSONEq(t, `{"ok":true,"keys":[{"type":"ssh-ed25519","bits":256,"fingerprint":"SHA256:x","path":"/k.pub"}]}`, string(b))
	assert.Equal(t, 4, Protocol)
	assert.Equal(t, "/usr/local/libexec/alice-helper", HelperPath)
	assert.Equal(t, 1<<20, MaxAuthorizedKeysSize)
}

func TestProtocol4(t *testing.T) {
	assert.Equal(t, 4, Protocol)
	assert.Equal(t, "1.3.0", Version)
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
