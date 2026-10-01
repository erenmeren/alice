package helperproto

import (
	"encoding/json"
	"strings"
	"testing"

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
			Owner: "deploy", StrictModesOK: true}}}}, AuthorizedKeysCommand: "none", Warnings: []string{WarnSSHDUnreadable}})
	require.NoError(t, err)
	assert.JSONEq(t, `{"ok":true,"users":[{"user":"deploy","uid":1001,"home":"/home/deploy","files":[{"path":"/home/deploy/.ssh/authorized_keys",
		"exists":true,"size":3,"sha256":"x","mode":"0600","owner":"deploy","strict_modes_ok":true,"too_large":false,"unsupported":false}],"sshd_unreadable":false,"authorized_keys_command":""}],
		"authorized_keys_command":"none","warnings":["sshd_unreadable"]}`, string(b))
	b, err = json.Marshal(ErrorResponse{Code: CodePathNotAllowed, Message: "m"})
	require.NoError(t, err)
	assert.JSONEq(t, `{"ok":false,"code":"PATH_NOT_ALLOWED","message":"m"}`, string(b))
	b, err = json.Marshal(AuthKeysReadResponse{OK: true, Path: "/p", SHA256: "s", ContentB64: "Yw==", Owner: "deploy"})
	require.NoError(t, err)
	assert.JSONEq(t, `{"ok":true,"path":"/p","sha256":"s","content_b64":"Yw==","owner":"deploy"}`, string(b))
	b, err = json.Marshal(HostKeysResponse{OK: true, Keys: []HostKeyInfo{{Type: "ssh-ed25519", Bits: 256, Fingerprint: "SHA256:x", Path: "/k.pub"}}})
	require.NoError(t, err)
	assert.JSONEq(t, `{"ok":true,"keys":[{"type":"ssh-ed25519","bits":256,"fingerprint":"SHA256:x","path":"/k.pub"}]}`, string(b))
	assert.Equal(t, 2, Protocol)
	assert.Equal(t, "/usr/local/libexec/alice-helper", HelperPath)
	assert.Equal(t, 1<<20, MaxAuthorizedKeysSize)
}
