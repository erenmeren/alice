package web

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClientAddr(t *testing.T) {
	trusted, err := ParseTrustedProxies([]string{"10.0.0.0/8", "2001:db8:ffff::/48"})
	require.NoError(t, err)
	for _, c := range []struct {
		name   string
		remote string
		xff    []string
		want   string
	}{
		{"no header", "10.0.0.1:1", nil, "10.0.0.1"},
		{"untrusted peer, spoofed header ignored", "192.0.2.9:1", []string{"1.2.3.4"}, "192.0.2.9"},
		{"trusted peer one hop", "10.0.0.1:1", []string{"198.51.100.7"}, "198.51.100.7"},
		{"chain, both proxies trusted", "10.0.0.1:1", []string{"198.51.100.7, 10.0.0.2"}, "198.51.100.7"},
		{"chain over several header lines", "10.0.0.1:1", []string{"198.51.100.7", "10.0.0.2"}, "198.51.100.7"},
		{"spoofed left entry", "10.0.0.1:1", []string{"1.2.3.4, 198.51.100.7"}, "198.51.100.7"},
		{"garbage skipped", "10.0.0.1:1", []string{"198.51.100.7, nonsense, , 10.0.0.2"}, "198.51.100.7"},
		{"only garbage falls back to peer", "10.0.0.1:1", []string{"nonsense"}, "10.0.0.1"},
		{"ipv6 peer and client", "[2001:db8:ffff::1]:1", []string{"2001:db8:1::5"}, "2001:db8:1::5"},
		{"ipv6 client zone stripped", "[2001:db8:ffff::1]:1", []string{"fe80::1%eth0"}, "fe80::1"},
		{"mapped peer is normalised", "[::ffff:10.0.0.1]:1", []string{"198.51.100.7"}, "198.51.100.7"},
		{"mapped client is normalised", "10.0.0.1:1", []string{"::ffff:198.51.100.7"}, "198.51.100.7"},
		{"mapped untrusted peer", "[::ffff:192.0.2.9]:1", []string{"1.2.3.4"}, "192.0.2.9"},
		{"all trusted falls back to peer", "10.0.0.1:1", []string{"10.0.0.2, 10.0.0.3"}, "10.0.0.1"},
		{"unparsable remote", "garbage", []string{"1.2.3.4"}, "invalid IP"},
	} {
		got := clientAddr(c.remote, c.xff, trusted)
		assert.Equal(t, c.want, got.String(), c.name)
	}
	assert.Equal(t, netip.MustParseAddr("192.0.2.9"), clientAddr("192.0.2.9:1", []string{"1.2.3.4"}, nil), "no trusted ranges")
}

func TestParseTrustedProxies(t *testing.T) {
	got, err := ParseTrustedProxies([]string{"10.0.0.0/8", "192.0.2.1", "2001:db8::1", "::ffff:10.1.0.0/112", " 172.16.0.0/12 "})
	require.NoError(t, err)
	var s []string
	for _, p := range got {
		s = append(s, p.String())
	}
	assert.Equal(t, []string{"10.0.0.0/8", "192.0.2.1/32", "2001:db8::1/128", "10.1.0.0/16", "172.16.0.0/12"}, s)
	for _, bad := range []string{"", " ", "0.0.0.0/0", "::/0", "::ffff:0.0.0.0/96", "::/0 ", "bad", "10.0.0.0/33", "fe80::1%eth0", "10.0.0.0/8/9", "::ffff:0:0/80"} {
		_, err := ParseTrustedProxies([]string{bad})
		assert.Error(t, err, "%q", bad)
	}
	empty, err := ParseTrustedProxies(nil)
	require.NoError(t, err)
	assert.Empty(t, empty)
}

func TestLimiterUsesTheClientBehindATrustedProxy(t *testing.T) {
	trusted, err := ParseTrustedProxies([]string{"10.0.0.0/8"})
	require.NoError(t, err)
	s, err := New(Config{RPID: "localhost", Origin: "http://localhost:8443", limitN: 2, limitWindow: time.Minute, TrustedProxies: trusted})
	require.NoError(t, err)
	h := s.Handler()
	post := func(remote, xff string) int {
		r := httptest.NewRequest(http.MethodPost, "/webauthn/login/begin", nil)
		r.RemoteAddr = remote
		if xff != "" {
			r.Header.Set("X-Forwarded-For", xff)
		}
		return serve(h, r).Code
	}
	// Two clients behind one proxy have separate buckets.
	require.Equal(t, 200, post("10.0.0.1:1", "198.51.100.1"))
	require.Equal(t, 200, post("10.0.0.1:2", "198.51.100.1"))
	assert.Equal(t, 429, post("10.0.0.1:3", "198.51.100.1"))
	assert.Equal(t, 200, post("10.0.0.1:4", "198.51.100.2"), "another client behind the same proxy")
	// A spoofed left entry does not choose the bucket.
	assert.Equal(t, 429, post("10.0.0.1:5", "203.0.113.50, 198.51.100.1"))
	// An untrusted peer cannot escape the limit by changing the header.
	require.Equal(t, 200, post("192.0.2.9:1", "1.1.1.1"))
	require.Equal(t, 200, post("192.0.2.9:2", "2.2.2.2"))
	assert.Equal(t, 429, post("192.0.2.9:3", "3.3.3.3"))
}
