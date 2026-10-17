package haproxyconf

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestParseListens(t *testing.T) {
	for name, tc := range map[string]struct {
		in   string
		want []Listen
	}{
		"any":                {"*:443", []Listen{{"", 443}}},
		"empty host":         {":443", []Listen{{"", 443}}},
		"two":                {":443,127.0.0.1:8443", []Listen{{"", 443}, {"127.0.0.1", 8443}}},
		"bracketed v6":       {"[::1]:9443", []Listen{{"::1", 9443}}},
		"bare v6 any":        {":::9443", []Listen{{"", 9443}}},
		"bare v6":            {"2001:db8::1:443", []Listen{{"2001:db8::1", 443}}},
		"bracketed any":      {"[::]:443", []Listen{{"", 443}}},
		"v4 any":             {"0.0.0.0:443", []Listen{{"", 443}}},
		"ipv4 prefix":        {"ipv4@10.0.0.1:443", []Listen{{"10.0.0.1", 443}}},
		"ipv6 prefix":        {"ipv6@[::1]:443", []Listen{{"::1", 443}}},
		"quic4 prefix":       {"quic4@:443", []Listen{{"", 443}}},
		"other prefixes":     {"tcp@:1,tcp4@:2,tcp6@:3,udp@:4,udp4@:5,udp6@:6,quic6@:7", []Listen{{"", 1}, {"", 2}, {"", 3}, {"", 4}, {"", 5}, {"", 6}, {"", 7}}},
		"host name":          {"www.example.test:443", []Listen{{"www.example.test", 443}}},
		"max port":           {":65535", []Listen{{"", 65535}}},
		"leading zero":       {":0443", []Listen{{"", 443}}},
		"bad entry kept out": {"unix@/x,:443,:0", []Listen{{"", 443}}},
	} {
		t.Run(name, func(t *testing.T) {
			got, cut := parseListens(tc.in, MaxListens)
			assert.Equal(t, tc.want, got)
			assert.False(t, cut)
		})
	}
	for _, in := range []string{
		"unix@/run/x.sock", "/run/x.sock", "fd@3", ":443-445", ":${P}", ":0",
		"abns@x", "sockpair@3", "uxst@/x", "uxdg@/x", "foo@:443", "ipv4@unix@:443",
		":65536", ":+443", ":-1", ":", "443", "", ",", "*", ":443a", ":99999999999999999999",
		"${IP}:443", "[::1]443", "[::1:443", "::1]:443", "[[::1]]:443", "a[b:443", "a]b:443",
		"[::1]:", "x@y:443", "\xff\xfe:443", "a\tb:443", "a\x7fb:443", strings.Repeat("a", 254) + ":443",
	} {
		t.Run(in, func(t *testing.T) {
			got, cut := parseListens(in, MaxListens)
			assert.Empty(t, got)
			assert.False(t, cut)
		})
	}
	t.Run("253-byte host", func(t *testing.T) {
		h := strings.Repeat("a", 253)
		got, _ := parseListens(h+":443", MaxListens)
		assert.Equal(t, []Listen{{h, 443}}, got)
	})
	t.Run("hostile list is quick", func(t *testing.T) {
		start := time.Now()
		got, cut := parseListens(strings.Repeat(":443,", MaxLine/5), MaxListens)
		assert.Len(t, got, MaxListens)
		assert.True(t, cut, "the entries past the limit are cut")
		_, _ = parseListens(strings.Repeat(",", MaxLine), MaxListens)
		assert.Less(t, time.Since(start), 2*time.Second*raceSlowdown)
	})
	t.Run("limit", func(t *testing.T) {
		got, cut := parseListens(":1,:2,unix@/x,:3", 2)
		assert.Equal(t, []Listen{{"", 1}, {"", 2}}, got)
		assert.True(t, cut)
		got, cut = parseListens(":1,:2,unix@/x", 2)
		assert.Equal(t, []Listen{{"", 1}, {"", 2}}, got)
		assert.False(t, cut, "an entry that gives no listen is not cut")
		got, cut = parseListens(":1", 0)
		assert.Empty(t, got)
		assert.True(t, cut)
	})
}

func TestBindArityCoversTheProbedKeywords(t *testing.T) {
	zero := "accept-proxy defer-accept tfo transparent v4v6 v6only ssl allow-0rtt force-sslv3 force-tlsv10 force-tlsv11 " +
		"force-tlsv12 force-tlsv13 generate-certificates no-alpn no-ca-names no-sslv3 no-tls-tickets no-tlsv10 no-tlsv11 " +
		"no-tlsv12 no-tlsv13 prefer-client-ciphers strict-sni quic-force-retry"
	one := "accept-netscaler-cip backlog expose-fd gid group id interface level maxconn mode mss name namespace nice process " +
		"proto severity-output shards tcp-ut thread uid user alpn ca-file ca-ignore-err ca-sign-file ca-sign-pass " +
		"ca-verify-file ciphers ciphersuites client-sigalgs crl-file crt crt-ignore-err crt-list curves ecdhe npn sigalgs " +
		"ssl-max-ver ssl-min-ver tls-ticket-keys verify quic-cc-algo quic-socket"
	want := map[string]int{}
	for _, k := range strings.Fields(zero) {
		want[k] = 0
	}
	for _, k := range strings.Fields(one) {
		want[k] = 1
	}
	assert.Equal(t, want, bindArity)
	for _, k := range []string{"crt", "crt-list", "name"} {
		assert.Equal(t, 1, bindArity[k], k)
	}
	assert.Equal(t, 0, bindArity["ssl"])
	_, ok := bindArity["default-crt"]
	assert.False(t, ok, "a 3.0 keyword is unknown")
}
