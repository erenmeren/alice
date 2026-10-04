package inventory

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/platform/validate"
)

// Review Focus 2: a server address typed the way people type it.
func TestNormalizeHostTable(t *testing.T) {
	tests := []struct {
		in, want, code string
	}{
		{"web-01.example.com", "web-01.example.com", ""},
		{"  WEB-01.Example.COM. ", "web-01.example.com", ""},
		{"web01", "web01", ""},
		{"sshtarget", "sshtarget", ""},
		{"10.0.0.5", "10.0.0.5", ""},
		{"192.168.10.20", "192.168.10.20", ""},
		{"[2001:db8::5]", "2001:db8::5", ""},
		{"2001:DB8::5", "2001:db8::5", ""},
		{"", "", validate.Required},
		{"   ", "", validate.Required},
		{"web-01:2222", "", CodeHostPort},
		{"10.0.0.5:22", "", CodeHostPort},
		{"[2001:db8::5]:22", "", validate.Pattern},
		{"ssh://web-01", "", validate.Pattern},
		{"web-01/path", "", validate.Pattern},
		{"root@web-01", "", validate.Pattern},
		{"[web-01]", "", validate.Pattern},
		{"-web.example.com", "", validate.Pattern},
		{"web-.example.com", "", validate.Pattern},
		{"a..b", "", validate.Pattern},
		{"web_01", "", validate.Pattern},
		{"web 01", "", validate.Pattern},
		{"web-01\n", "web-01", ""},
		{"web-01;rm -rf /", "", validate.Pattern},
		{"$(reboot)", "", validate.Pattern},
		{"`id`", "", validate.Pattern},
		{"fe80::1%eth0", "", validate.Pattern},
		{"sunucu.örnek.com.tr", "", CodeHostASCII},
		{"İSTANBUL.example.com", "", CodeHostASCII},
		{"169.254.169.254", "", CodeHostNotAllowed},
		{"169.254.1.1", "", CodeHostNotAllowed},
		{"127.0.0.1", "127.0.0.1", ""},
		{"::1", "::1", ""},
		{"localhost", "localhost", ""},
		{"web-3.example.test", "web-3.example.test", ""},
		{"0.0.0.0", "", CodeHostNotAllowed},
		{"::", "", CodeHostNotAllowed},
		{"224.0.0.1", "", CodeHostNotAllowed},
		{"ff02::1", "", CodeHostNotAllowed},
		{"fe80::1", "", CodeHostNotAllowed},
		{"255.255.255.255", "", CodeHostNotAllowed},
		{"::ffff:169.254.169.254", "", CodeHostNotAllowed},
		// The same rule as at connect time (netaddr.Allowed): reserved IPv4 ranges and IPv6 forms
		// that never name a server are refused as typed too.
		{"0.1.2.3", "", CodeHostNotAllowed},
		{"240.0.0.1", "", CodeHostNotAllowed},
		{"::a00:5", "", CodeHostNotAllowed},
		{"::ffff:0:a00:5", "", CodeHostNotAllowed},
		{"[2001::1]", "", CodeHostNotAllowed},
		{"10.0.0.5.", "10.0.0.5", ""},
		{"[::ffff:169.254.169.254]", "", CodeHostNotAllowed},
		{"[::1]", "::1", ""},
		{"LOCALHOST.", "localhost", ""},
		{"web..", "", validate.Pattern},
		{"web-01:", "", validate.Pattern},
		{"\u00a0web-01\u00a0", "web-01", ""},
		{"64:ff9b::a9fe:a9fe", "", CodeHostNotAllowed},
		{"64:ff9b::e000:1", "", CodeHostNotAllowed},
		{"64:ff9b::", "", CodeHostNotAllowed},
		{"64:ff9b::ffff:ffff", "", CodeHostNotAllowed},
		{"64:ff9b::a00:5", "64:ff9b::a00:5", ""},
		{"64:ff9b:1::a9fe:a9fe", "", CodeHostNotAllowed},       // local-use NAT64 (RFC 8215), /96 form
		{"64:ff9b:1:a9fe:a9:fe00::", "", CodeHostNotAllowed},   // /48 form (u-octet skipped)
		{"64:ff9b:1:a9:fe:a9fe::", "", CodeHostNotAllowed},     // /56 form
		{"64:ff9b:1:0:a9:fea9:fe00:0", "", CodeHostNotAllowed}, // /64 form
		{"64:ff9b:1::e000:1", "", CodeHostNotAllowed},
		{"64:ff9b:1::", "", CodeHostNotAllowed},
		{"64:ff9b:1::a00:5", "64:ff9b:1::a00:5", ""},
		{"64:ff9b:1:abcd::a00:5", "64:ff9b:1:abcd::a00:5", ""},
		{"2002:a9fe:a9fe::1", "", CodeHostNotAllowed},
		{"[2002:a9fe:a9fe::1]", "", CodeHostNotAllowed},
		{"2002:a00:5::1", "2002:a00:5::1", ""},
		{"fd00:ec2::254", "", CodeHostNotAllowed},
		{"[FD00:EC2::254]", "", CodeHostNotAllowed},
		{"fd00:ec2::253", "fd00:ec2::253", ""},
		{"10.0.0", "", validate.Pattern},
		{"2852039166", "", validate.Pattern},
		{"0251.0376.0251.0376", "", validate.Pattern},
		{"0xa9fea9fe", "", validate.Pattern},
		{"web.0x1f", "", validate.Pattern},
		{"3com.example", "3com.example", ""},
		{".", "", validate.Pattern},
		{strings.Repeat("a", 64) + ".example.com", "", validate.Pattern},
		{strings.Repeat("abcdefghi.", 26) + "com", "", validate.TooLong},
	}
	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			got, fe := NormalizeHost(tc.in)
			if tc.code == "" {
				require.Nil(t, fe, "unexpected problem %+v", fe)
				assert.Equal(t, tc.want, got)
				return
			}
			require.NotNil(t, fe, "want %s, got host %q", tc.code, got)
			assert.Equal(t, "host", fe.Field)
			assert.Equal(t, tc.code, fe.Code)
			assert.Empty(t, got)
		})
	}
}

func TestValidateNewTarget(t *testing.T) {
	ok := NewTarget{Name: "web-01", Type: "linux", Host: "web-01.example.com"}
	n, errs := validateNewTarget(ok)
	require.Empty(t, errs)
	assert.Equal(t, 22, n.Port, "port 0 means 22")
	assert.Equal(t, "alice-svc", n.Username, "empty user name means alice-svc")

	n, errs = validateNewTarget(NewTarget{Name: "  Çağrı Merkezi Sunucusu  ", Type: "linux", Host: "web-01", Port: 2222, Username: "deploy"})
	require.Empty(t, errs)
	assert.Equal(t, "Çağrı Merkezi Sunucusu", n.Name, "names keep Turkish letters and are trimmed")
	assert.Equal(t, 2222, n.Port)

	n, errs = validateNewTarget(NewTarget{Name: "C\u0327ag\u0306r\u0131 Merkezi", Type: "linux", Host: "web-01"})
	require.Empty(t, errs)
	assert.Equal(t, "\u00c7a\u011fr\u0131 Merkezi", n.Name, "names are stored in NFC")

	bad := []struct {
		in    NewTarget
		field string
		code  string
	}{
		{NewTarget{Name: "", Type: "linux", Host: "web"}, "name", validate.Required},
		{NewTarget{Name: strings.Repeat("ş", 101), Type: "linux", Host: "web"}, "name", validate.TooLong},
		{NewTarget{Name: "web\x00", Type: "linux", Host: "web"}, "name", validate.Pattern},
		{NewTarget{Name: "web\u202e", Type: "linux", Host: "web"}, "name", validate.Pattern},
		{NewTarget{Name: "web\u200b-01", Type: "linux", Host: "web"}, "name", validate.Pattern},
		{NewTarget{Name: "\u2060", Type: "linux", Host: "web"}, "name", validate.Pattern},
		{NewTarget{Name: "\ufeff", Type: "linux", Host: "web"}, "name", validate.Pattern},
		{NewTarget{Name: "web\u00ad01", Type: "linux", Host: "web"}, "name", validate.Pattern},
		{NewTarget{Name: "web", Type: "linux", Host: "web", Port: 70000}, "port", validate.OutOfRange},
		{NewTarget{Name: "web", Type: "linux", Host: "web", Port: -1}, "port", validate.OutOfRange},
		{NewTarget{Name: "web", Type: "linux", Host: "web", Username: "Root"}, "username", validate.Pattern},
		{NewTarget{Name: "web", Type: "linux", Host: "web", Username: "a;b"}, "username", validate.Pattern},
		{NewTarget{Name: "web", Type: "linux", Host: "web", Username: strings.Repeat("a", 33)}, "username", validate.Pattern},
		{NewTarget{Name: "web", Type: "printer", Host: "web"}, "type", validate.OneOf},
		{NewTarget{Name: "web", Type: "linux", Host: "web:22"}, "host", CodeHostPort},
	}
	for _, b := range bad {
		_, errs := validateNewTarget(b.in)
		require.Len(t, errs, 1, "%+v", b.in)
		assert.Equal(t, b.field, errs[0].Field, "%+v", b.in)
		assert.Equal(t, b.code, errs[0].Code, "%+v", b.in)
	}
}

func TestFoldASCIIKeepsNonASCII(t *testing.T) {
	assert.Equal(t, "web-01.example", foldASCII("WEB-01.Example"))
	assert.Equal(t, "İstanbul", foldASCII("İstanbul"), "non-ASCII letters are never case-mapped (Turkish İ)")
}
