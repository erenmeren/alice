package haproxyconf

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"alice/internal/providers/linuxssh/helperproto"
)

func TestResolveKeys(t *testing.T) {
	c := Config{Servers: []Server{
		{Pairs: []Pair{
			sup("/c/combined.pem", "/c/combined.pem", "/c/combined.pem.key"),
			sup("/c/beside.pem", "/c/beside.pem", "/c/beside.pem.key"),
			sup("/c/nolookup.pem", "/c/nolookup.pem", ""),
			uns("$X/a.pem", ReasonVariable),
		}},
		{Pairs: []Pair{sup("/c/beside.pem", "beside.pem", "/c/beside.pem.key")}},
	}}
	asked := map[string]int{}
	ResolveKeys(&c, func(cert string) bool {
		asked[cert]++
		return cert == "/c/combined.pem"
	})
	assert.Equal(t, []Pair{
		{Cert: "/c/combined.pem", Key: "/c/combined.pem", CertRaw: "/c/combined.pem", KeyBeside: "/c/combined.pem.key"},
		{Cert: "/c/beside.pem", Key: "/c/beside.pem.key", CertRaw: "/c/beside.pem", KeyBeside: "/c/beside.pem.key"},
		{Cert: "/c/nolookup.pem", Key: "/c/nolookup.pem", CertRaw: "/c/nolookup.pem"},
		uns("$X/a.pem", ReasonVariable),
	}, c.Servers[0].Pairs)
	assert.Equal(t, "/c/beside.pem.key", c.Servers[1].Pairs[0].Key)
	assert.Equal(t, map[string]int{"/c/combined.pem": 1, "/c/beside.pem": 1}, asked,
		"each certificate is read once, and none without a companion or unsupported")
}

func TestMarkWritable(t *testing.T) {
	c := Config{Servers: []Server{{Pairs: []Pair{plain("/c/a.pem"), uns("$X", ReasonVariable)}}}}
	MarkWritable(&c)
	assert.Equal(t, ReasonConfigFileWritable, c.Servers[0].Pairs[0].Unsupported)
	assert.Equal(t, ReasonVariable, c.Servers[0].Pairs[1].Unsupported)
	assert.Empty(t, c.CertPaths())
}

func TestCertAndKeyPaths(t *testing.T) {
	a := Pair{Cert: "/c/a.pem", Key: "/c/a.pem.key", CertRaw: "/c/a.pem", KeyBeside: "/c/a.pem.key"}
	b := plain("/c/b.pem")
	c := Config{Servers: []Server{
		{Pairs: []Pair{b, a, uns("$X", ReasonVariable)}},
		{Pairs: []Pair{a, {CertRaw: "/c/z.pem", Unsupported: ReasonConditional}}},
	}}
	assert.Equal(t, []string{"/c/b.pem", "/c/a.pem"}, c.CertPaths())
	assert.Equal(t, []string{"/c/b.pem", "/c/a.pem.key"}, c.KeyPaths())
	assert.Empty(t, Config{}.CertPaths())
}

func TestToWire(t *testing.T) {
	assert.Equal(t, helperproto.DumpServer{File: cfgPath, Line: 3, Names: []string{}, Listens: []helperproto.DumpListen{}, Pairs: []helperproto.DumpPair{}},
		ToWire(Server{File: cfgPath, Line: 3}), "slices are never nil")

	long := strings.Repeat("é", 300)
	got := ToWire(Server{
		File: cfgPath, Line: 7, Section: "fe\x01_" + strings.Repeat("s", 300),
		Names:   []string{"a.example.test", "b\x00\xff.example.test"},
		Listens: []Listen{{"", 9443}, {"10.0.0.1", 9444}},
		Pairs: []Pair{
			{Cert: "/c/a.pem", Key: "/c/a.pem.key", CertRaw: "a.pem", KeyBeside: "/c/a.pem.key"},
			uns("${D}/a\tb.pem", ReasonVariable),
			uns(long, ReasonPathNotAllowed),
		},
	})
	assert.Equal(t, "fe_"+strings.Repeat("s", 250), got.Section, "cleaned and cut to 253 bytes")
	assert.Equal(t, []string{"a.example.test", "b.example.test"}, got.Names)
	assert.Equal(t, []helperproto.DumpListen{{Addr: "", Port: 9443}, {Addr: "10.0.0.1", Port: 9444}}, got.Listens)
	assert.Equal(t, []helperproto.DumpPair{
		{Cert: "/c/a.pem", Key: "/c/a.pem.key"},
		{Unsupported: ReasonVariable, Raw: "${D}/ab.pem"},
		{Unsupported: ReasonPathNotAllowed, Raw: strings.Repeat("é", 200)},
	}, got.Pairs, "Raw only for an unsupported pair, cleaned and cut to 200 runes")
	assert.False(t, got.Stream)
	for _, l := range got.Listens {
		assert.False(t, l.DefaultServer)
	}
	for _, p := range got.Pairs {
		assert.False(t, p.Inherited)
	}
	_ = long
}
