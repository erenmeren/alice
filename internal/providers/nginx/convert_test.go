package nginx

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/providers"
	"alice/internal/providers/linuxssh/helperproto"
	"alice/internal/testutil/pki"
)

var unitNow = time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC)

type unitCerts struct {
	leaf  pki.Leaf
	chain []byte
}

func newUnitCerts(t *testing.T) unitCerts {
	t.Helper()
	ca := pki.NewCA("Unit", pki.ECDSA256, unitNow)
	l := ca.Issue(pki.Opts{CommonName: "unit.example.test"}, unitNow)
	return unitCerts{leaf: l, chain: l.FullchainPEM}
}

func certFile(path string, pem []byte) helperproto.NginxFile {
	return helperproto.NginxFile{Path: path, Kind: "cert", Exists: true, Resolved: path, Mode: "0644", Owner: "root", Group: "root",
		Size: int64(len(pem)), SHA256: hexSHA(pem), PEM: string(pem), FreeBytes: 1 << 20}
}

func keyFile(path string) helperproto.NginxFile {
	return helperproto.NginxFile{Path: path, Kind: "key", Exists: true, Resolved: path, Mode: "0600", Owner: "root", Group: "root", Size: 200, FreeBytes: 1 << 20}
}

func server(names []string, port int, pairs ...helperproto.NginxPair) helperproto.NginxServer {
	return helperproto.NginxServer{File: "/etc/nginx/conf.d/a.conf", Line: 3, Names: names,
		Listens: []helperproto.NginxListen{{Port: port}}, Pairs: pairs}
}

func pair(cert, key string) helperproto.NginxPair { return helperproto.NginxPair{Cert: cert, Key: key} }

func validDump(servers []helperproto.NginxServer, files ...helperproto.NginxFile) helperproto.NginxDumpResponse {
	return helperproto.NginxDumpResponse{OK: true, Version: "1.22.1", ConfPath: "/etc/nginx/nginx.conf", ConfigValid: true, Servers: servers, Files: files}
}

func TestConvertPairShapes(t *testing.T) {
	u := newUnitCerts(t)
	const c, k = "/etc/nginx/ssl/a.crt", "/etc/nginx/ssl/a.key"
	t.Run("key_missing keeps the certificate path and no key", func(t *testing.T) {
		d := validDump([]helperproto.NginxServer{server([]string{"a"}, 443, helperproto.NginxPair{Cert: c, Unsupported: "key_missing", Raw: c})})
		got, warns := convert(d)
		require.Len(t, got, 1)
		assert.Empty(t, warns)
		assert.Equal(t, c, got[0].Location.CertPath)
		assert.Empty(t, got[0].Location.KeyPath)
		assert.Equal(t, providers.UnsupportedKeyMissing, got[0].Location.Unsupported)
		assert.False(t, got[0].Location.Supported)
		assert.Empty(t, got[0].PEMChain)
	})
	t.Run("an empty certificate with a raw value is unsupported", func(t *testing.T) {
		d := validDump([]helperproto.NginxServer{server([]string{"a"}, 443, helperproto.NginxPair{Unsupported: "variable", Raw: "/x/$host.crt"})})
		got, _ := convert(d)
		require.Len(t, got, 1)
		assert.Equal(t, "/x/$host.crt", got[0].Location.CertPath)
		assert.Equal(t, providers.UnsupportedVariable, got[0].Location.Unsupported)
	})
	t.Run("a pair with neither is dropped", func(t *testing.T) {
		got, _ := convert(validDump([]helperproto.NginxServer{server([]string{"a"}, 443, helperproto.NginxPair{Unsupported: "variable"})}))
		assert.Empty(t, got)
	})
	t.Run("an unknown reason or an unmarked empty certificate is unknown", func(t *testing.T) {
		got, _ := convert(validDump([]helperproto.NginxServer{
			server([]string{"a"}, 443, helperproto.NginxPair{Unsupported: "weird", Raw: "/r1"}),
			server([]string{"b"}, 443, helperproto.NginxPair{Raw: "/r2"}),
			server([]string{"c"}, 443, helperproto.NginxPair{Cert: "/r3", Key: "/r3.key", Unsupported: "weird"}),
		}))
		require.Len(t, got, 3)
		for _, l := range got {
			assert.Equal(t, providers.UnsupportedUnknown, l.Location.Unsupported)
			assert.False(t, l.Location.Supported)
		}
	})
	t.Run("a stream server is unsupported even with a supported-looking pair", func(t *testing.T) {
		s := server([]string{"a"}, 443, pair(c, k))
		s.Stream = true
		got, _ := convert(validDump([]helperproto.NginxServer{s}, certFile(c, u.chain), keyFile(k)))
		assert.Equal(t, providers.UnsupportedStream, got[0].Location.Unsupported)
		assert.False(t, got[0].Location.Supported)
	})
	t.Run("inherited pairs mark the location", func(t *testing.T) {
		p := pair(c, k)
		p.Inherited = true
		got, _ := convert(validDump([]helperproto.NginxServer{server([]string{"a"}, 443, p)}, certFile(c, u.chain), keyFile(k)))
		assert.True(t, got[0].Location.Inherited)
		assert.True(t, got[0].Location.Supported)
	})
	t.Run("a supported pair and an unsupported one of the same certificate", func(t *testing.T) {
		d := validDump([]helperproto.NginxServer{
			server([]string{"a"}, 443, pair(c, k)),
			server([]string{"b"}, 443, helperproto.NginxPair{Cert: c, Unsupported: "key_missing"}),
		}, certFile(c, u.chain), keyFile(k))
		got, _ := convert(d)
		require.Len(t, got, 1)
		assert.Equal(t, providers.UnsupportedKeyMissing, got[0].Location.Unsupported)
		assert.Equal(t, k, got[0].Location.KeyPath)
		assert.NotEmpty(t, got[0].PEMChain, "the supported pair's file is described")
	})
}

func TestConvertServersAreDeduplicatedAndCleaned(t *testing.T) {
	u := newUnitCerts(t)
	const c, k = "/etc/nginx/ssl/a.crt", "/etc/nginx/ssl/a.key"
	s := server([]string{"a.example.test"}, 443, pair(c, k))
	s.Listens = append(s.Listens, helperproto.NginxListen{Addr: "10.0.0.1", Port: 8443, DefaultServer: true})
	d := validDump([]helperproto.NginxServer{s, s, server([]string{"a.example.test"}, 443, pair(c, k))}, certFile(c, u.chain), keyFile(k))
	d.Servers[2].Line = 9
	got, _ := convert(d)
	require.Len(t, got, 1)
	assert.Equal(t, []providers.CertServer{
		{Names: []string{"a.example.test"}, Listens: []providers.CertListen{{Port: 443}, {Addr: "10.0.0.1", Port: 8443, DefaultServer: true}},
			File: "/etc/nginx/conf.d/a.conf", Line: 3},
		{Names: []string{"a.example.test"}, Listens: []providers.CertListen{{Port: 443}}, File: "/etc/nginx/conf.d/a.conf", Line: 9},
	}, got[0].Location.Servers, "identical servers (one per include) collapse, another line is another server")

	// Remote text is data: control characters go, lengths and counts are bounded, bad ports drop.
	hostile := server([]string{"evil\x1b[31m.example.test", strings.Repeat("n", 400), ""}, 443, pair(c, k))
	hostile.File = "/etc/nginx/\x00conf.d/" + strings.Repeat("f", 5000)
	hostile.Listens = []helperproto.NginxListen{{Addr: "1.2.3.4\n", Port: 443}, {Port: 0}, {Port: 70000}, {Port: -1}}
	got, _ = convert(validDump([]helperproto.NginxServer{hostile}, certFile(c, u.chain), keyFile(k)))
	srv := got[0].Location.Servers[0]
	assert.Equal(t, "evil[31m.example.test", srv.Names[0])
	assert.Len(t, srv.Names[1], 253)
	assert.Len(t, srv.Names, 2, "an empty name is dropped")
	assert.Equal(t, []providers.CertListen{{Addr: "1.2.3.4", Port: 443}}, srv.Listens)
	assert.Len(t, srv.File, 4096)
	assert.NotContains(t, srv.File, "\x00")

	many := server(nil, 443, pair(c, k))
	for i := range 200 {
		many.Names = append(many.Names, fmt.Sprintf("n%d.example.test", i))
		many.Listens = append(many.Listens, helperproto.NginxListen{Port: 1000 + i})
	}
	got, _ = convert(validDump([]helperproto.NginxServer{many}, certFile(c, u.chain), keyFile(k)))
	assert.Len(t, got[0].Location.Servers[0].Names, maxNames)
	assert.Len(t, got[0].Location.Servers[0].Listens, maxListens)

	var servers []helperproto.NginxServer
	for i := range maxServersPerLocation + 10 {
		s := server([]string{"a"}, 443, pair(c, k))
		s.Line = i + 1
		servers = append(servers, s)
	}
	got, _ = convert(validDump(servers, certFile(c, u.chain), keyFile(k)))
	assert.Len(t, got[0].Location.Servers, maxServersPerLocation)
}

func TestConvertCertificateFileHandling(t *testing.T) {
	u := newUnitCerts(t)
	const c, k = "/etc/nginx/ssl/a.crt", "/etc/nginx/ssl/a.key"
	one := func(cf helperproto.NginxFile, kf ...helperproto.NginxFile) providers.DiscoveredCertificate {
		got, _ := convert(validDump([]helperproto.NginxServer{server([]string{"a"}, 443, pair(c, k))}, append([]helperproto.NginxFile{cf}, kf...)...))
		require.Len(t, got, 1)
		return got[0]
	}
	bad := "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"

	t.Run("a good file", func(t *testing.T) {
		got := one(certFile(c, u.chain), keyFile(k))
		assert.True(t, got.Location.Supported)
		assert.Equal(t, string(u.chain), string(got.PEMChain))
	})
	t.Run("the chain is rebuilt from what parsed, text around it is not returned", func(t *testing.T) {
		got := one(certFile(c, []byte("junk\n"+string(u.chain)+"trailing\n")), keyFile(k))
		assert.Equal(t, string(u.chain), string(got.PEMChain))
	})
	t.Run("a block that is no certificate is dropped and said so", func(t *testing.T) {
		got := one(certFile(c, []byte(string(u.chain)+bad)), keyFile(k))
		assert.Equal(t, string(u.chain), string(got.PEMChain))
		assert.Equal(t, []string{providers.WarnCertificateBlockDropped}, got.Location.Warnings)
		assert.True(t, got.Location.Supported)
	})
	t.Run("nothing parses", func(t *testing.T) {
		got := one(certFile(c, []byte(bad)), keyFile(k))
		assert.Empty(t, got.PEMChain)
		assert.Empty(t, got.FileSHA256)
		assert.Equal(t, providers.CertProblemNotACertificate, got.Location.Problem)
		assert.Equal(t, providers.UnsupportedFile, got.Location.Unsupported)
		assert.False(t, got.Location.Supported)
	})
	t.Run("a private key block is not a certificate", func(t *testing.T) {
		keyBlock := "-----BEGIN " + "PRIVATE KEY-----\nAAAA\n-----END " + "PRIVATE KEY-----\n"
		got := one(certFile(c, []byte(keyBlock)), keyFile(k))
		assert.Equal(t, providers.CertProblemNotACertificate, got.Location.Problem)
		assert.Empty(t, got.PEMChain)
	})
	t.Run("a dropped first block makes the file a problem, a later one keeps a warning", func(t *testing.T) {
		withHeader := strings.Replace(string(u.chain), "-----BEGIN CERTIFICATE-----\n", "-----BEGIN CERTIFICATE-----\nProc-Type: 4,ENCRYPTED\n\n", 1)
		got := one(certFile(c, []byte(withHeader)), keyFile(k))
		assert.Equal(t, providers.CertProblemNotACertificate, got.Location.Problem, "the intermediate must not become the leaf")
		assert.Empty(t, got.PEMChain)
		assert.False(t, got.Location.Supported)
		first := one(certFile(c, []byte(bad+string(u.chain))), keyFile(k))
		assert.Equal(t, providers.CertProblemNotACertificate, first.Location.Problem)
		assert.False(t, first.Location.Supported)
		later := one(certFile(c, []byte(string(u.chain)+bad)), keyFile(k))
		assert.True(t, later.Location.Supported)
		assert.Equal(t, []string{providers.WarnCertificateBlockDropped}, later.Location.Warnings)
	})
	t.Run("too many certificates", func(t *testing.T) {
		got := one(certFile(c, []byte(strings.Repeat(string(u.leaf.CertPEM), maxChainCerts+1))), keyFile(k))
		assert.Equal(t, providers.CertProblemTooLarge, got.Location.Problem)
		assert.Empty(t, got.PEMChain)
		ok := one(certFile(c, []byte(strings.Repeat(string(u.leaf.CertPEM), maxChainCerts))), keyFile(k))
		assert.Empty(t, ok.Location.Problem)
	})
	t.Run("a file over the helper's limit", func(t *testing.T) {
		got := one(certFile(c, []byte(string(u.chain)+strings.Repeat("\n", helperproto.MaxCertFileSize))), keyFile(k))
		assert.Equal(t, providers.CertProblemTooLarge, got.Location.Problem)
		assert.Empty(t, got.PEMChain)
	})
	t.Run("a hash that is not a hash", func(t *testing.T) {
		cf := certFile(c, u.chain)
		cf.SHA256 = "NOT-A-HASH"
		got := one(cf, keyFile(k))
		assert.Equal(t, providers.CertProblemUnreadable, got.Location.Problem)
		assert.Empty(t, got.PEMChain)
		cf.SHA256 = ""
		assert.Equal(t, providers.CertProblemUnreadable, one(cf, keyFile(k)).Location.Problem)
	})
	t.Run("a file the dump did not describe is unreadable", func(t *testing.T) {
		got, _ := convert(validDump([]helperproto.NginxServer{server([]string{"a"}, 443, pair(c, k))}))
		assert.Equal(t, providers.CertProblemUnreadable, got[0].Location.Problem)
		assert.Equal(t, providers.CertProblemUnreadable, got[0].Location.KeyProblem)
		assert.False(t, got[0].Location.Supported)
		assert.Empty(t, got[0].PEMChain)
	})
	t.Run("a problem that is not in the set is unknown", func(t *testing.T) {
		cf := certFile(c, u.chain)
		cf.Problem = "made_up"
		got := one(cf, keyFile(k))
		assert.Equal(t, providers.CertProblemUnknown, got.Location.Problem)
		assert.False(t, got.Location.Supported)
		kf := keyFile(k)
		kf.Problem = "made_up"
		k2 := one(certFile(c, u.chain), kf)
		assert.Equal(t, providers.CertProblemUnknown, k2.Location.KeyProblem)
		assert.False(t, k2.Location.Supported)
	})
	t.Run("a missing certificate", func(t *testing.T) {
		cf := helperproto.NginxFile{Path: c, Kind: "cert", Problem: "missing"}
		got := one(cf, keyFile(k))
		assert.Equal(t, providers.CertProblemMissing, got.Location.Problem)
		assert.Empty(t, got.PEMChain)
	})
	t.Run("an absent key without a problem is missing", func(t *testing.T) {
		kf := helperproto.NginxFile{Path: k, Kind: "key"}
		got := one(certFile(c, u.chain), kf)
		assert.False(t, got.Location.KeyExists)
		assert.Equal(t, providers.CertProblemMissing, got.Location.KeyProblem)
		assert.False(t, got.Location.Supported)
		assert.Equal(t, providers.UnsupportedFile, got.Location.Unsupported)
	})
	t.Run("file facts are cleaned", func(t *testing.T) {
		cf := certFile(c, u.chain)
		cf.Resolved = "/srv/x/\x1bevil.pem"
		cf.Symlinked = true
		cf.FreeBytes = -5
		kf := keyFile(k)
		kf.Owner, kf.Group, kf.Mode = "own\x00er", strings.Repeat("g", 300), "0600"
		got := one(cf, kf)
		assert.Equal(t, "/srv/x/evil.pem", got.Location.ResolvedCertPath)
		assert.True(t, got.Location.Symlinked)
		assert.True(t, got.Location.CustomLocation)
		assert.Zero(t, got.Location.FreeBytes)
		assert.Equal(t, "owner", got.Location.KeyOwner)
		assert.Len(t, got.Location.KeyGroup, 64)
		assert.Equal(t, []string{providers.WarnKeyGroupOpen, providers.WarnSymlinked, providers.WarnCustomLocation}, got.Location.Warnings)
	})
	t.Run("an unusable resolved path is dropped", func(t *testing.T) {
		cf := certFile(c, u.chain)
		cf.Resolved = "relative/path.pem"
		got := one(cf, keyFile(k))
		assert.Empty(t, got.Location.ResolvedCertPath)
		assert.False(t, got.Location.CustomLocation)
	})
}

func TestConvertKeyConflictAndPrecedence(t *testing.T) {
	u := newUnitCerts(t)
	const c = "/etc/nginx/ssl/a.crt"
	d := validDump([]helperproto.NginxServer{
		server([]string{"a"}, 443, pair(c, "/k1")),
		server([]string{"b"}, 443, pair(c, "/k2")),
	}, certFile(c, u.chain), keyFile("/k1"), keyFile("/k2"))
	got, _ := convert(d)
	assert.Equal(t, providers.UnsupportedKeyConflict, got[0].Location.Unsupported)
	assert.Equal(t, "/k1", got[0].Location.KeyPath, "the first key is kept")

	// A file problem does not hide the conflict, and a pair reason is not replaced by a conflict.
	cf := certFile(c, u.chain)
	cf.Problem = "not_regular"
	got, _ = convert(validDump(d.Servers, cf, keyFile("/k1"), keyFile("/k2")))
	assert.Equal(t, providers.UnsupportedKeyConflict, got[0].Location.Unsupported)
	assert.Equal(t, providers.CertProblemNotRegular, got[0].Location.Problem)
	got, _ = convert(validDump([]helperproto.NginxServer{
		server([]string{"a"}, 443, pair(c, "/k1")),
		server([]string{"b"}, 443, helperproto.NginxPair{Cert: c, Key: "/k2", Unsupported: "config_file_writable"}),
	}, certFile(c, u.chain), keyFile("/k1")))
	assert.Equal(t, providers.UnsupportedConfigFileWritable, got[0].Location.Unsupported)
}

func TestConvertLocationCountIsBounded(t *testing.T) {
	var servers []helperproto.NginxServer
	for i := range helperproto.MaxNginxFiles + 5 {
		servers = append(servers, server([]string{"a"}, 443, helperproto.NginxPair{Unsupported: "variable", Raw: fmt.Sprintf("/v/%d", i)}))
	}
	got, warns := convert(validDump(servers))
	assert.Len(t, got, helperproto.MaxNginxFiles)
	assert.Equal(t, []string{providers.WarnLocationsDropped}, warningCodes(warns), "locations were left out: inventory marks nothing missing")

	// The helper's own too_many_files (its file descriptions cut) is passed on; no location was left out.
	d := validDump(servers[:3])
	d.Warnings = []string{providers.WarnTooManyFiles}
	got, warns = convert(d)
	assert.Len(t, got, 3)
	assert.Equal(t, []string{providers.WarnTooManyFiles}, warningCodes(warns))
}

func TestLocationWarnings(t *testing.T) {
	m := func(mode string) helperproto.NginxFile {
		return helperproto.NginxFile{Mode: mode}
	}
	assert.Equal(t, []string{providers.WarnKeyModeOpen}, locationWarnings(helperproto.NginxFile{}, m("0644")))
	assert.Empty(t, locationWarnings(helperproto.NginxFile{}, m("0640")))
	assert.Empty(t, locationWarnings(helperproto.NginxFile{}, m("0600")))
	assert.Empty(t, locationWarnings(helperproto.NginxFile{}, helperproto.NginxFile{}), "no key description, no warning")
	assert.Equal(t, []string{providers.WarnSymlinked, providers.WarnCustomLocation},
		locationWarnings(helperproto.NginxFile{Symlinked: true, Resolved: "/srv/certs/a.pem"}, m("0600")))
	assert.Empty(t, locationWarnings(helperproto.NginxFile{Symlinked: true, Resolved: "/etc/letsencrypt/archive/a/fullchain1.pem"}, m("0600"))[1:],
		"letsencrypt is a usual folder")
	assert.Empty(t, locationWarnings(helperproto.NginxFile{Resolved: ""}, m("0600")), "D11: an empty resolved path is not a custom location")
	assert.Equal(t, []string{providers.WarnCustomLocation}, locationWarnings(helperproto.NginxFile{Resolved: "/etc/nginxx/a.pem"}, m("0600")),
		"a prefix of a directory name is not the directory")
	assert.Equal(t, []string{providers.WarnCustomLocation}, locationWarnings(helperproto.NginxFile{Resolved: "/etc/ssl/../x/a.pem"}, m("0600")))
	for _, dir := range []string{"/etc/ssl/", "/etc/nginx/", "/etc/pki/", "/etc/letsencrypt/"} {
		assert.Empty(t, locationWarnings(helperproto.NginxFile{Resolved: dir + "a.pem"}, m("0600")), dir)
	}

	key := func(owner, group, mode string) helperproto.NginxFile {
		return helperproto.NginxFile{Exists: true, Owner: owner, Group: group, Mode: mode}
	}
	for _, tc := range []struct {
		name string
		kf   helperproto.NginxFile
		want []string
	}{
		{"root 0600", key("root", "root", "0600"), nil},
		{"root group 0640", key("root", "root", "0640"), nil},
		{"uid 0", key("0", "0", "0640"), nil},
		{"other group 0640", key("root", "ssl-cert", "0640"), []string{providers.WarnKeyGroupOpen}},
		{"other owner", key("www-data", "root", "0600"), []string{providers.WarnKeyGroupOpen}},
		{"others read", key("root", "root", "0604"), []string{providers.WarnKeyModeOpen, providers.WarnKeyGroupOpen}},
		{"other group 0600", key("root", "ssl-cert", "0600"), nil},
		{"unparseable mode", key("root", "root", "rw-r--r--"), []string{providers.WarnKeyModeOpen, providers.WarnKeyGroupOpen}},
		{"key with a problem", helperproto.NginxFile{Exists: true, Problem: "not_regular", Owner: "x", Mode: "0777"}, []string{providers.WarnKeyModeOpen}},
	} {
		assert.Equal(t, tc.want, locationWarnings(helperproto.NginxFile{}, tc.kf), tc.name)
	}
}

func TestConvertWarnings(t *testing.T) {
	u := newUnitCerts(t)
	const c, k = "/etc/nginx/ssl/a.crt", "/etc/nginx/ssl/a.key"
	d := validDump([]helperproto.NginxServer{server([]string{"a"}, 443, pair(c, k))}, certFile(c, u.chain), keyFile(k))
	d.Warnings = []string{"stream_tls", "mail_tls", "stream_tls", "config_file_writable", "too_many_files", "certificate_block_dropped",
		"Not A Code", "x-y", "", strings.Repeat("a", 41), "future_warning"}
	d.Writable = []string{"/etc/nginx/conf.d/w1.conf", "/etc/nginx/conf.d/w\x1b2.conf", "relative.conf", "/etc/nginx/conf.d/w1.conf"}
	_, warns := convert(d)
	assert.Equal(t, []string{"stream_tls", "mail_tls", "too_many_files", "certificate_block_dropped", "future_warning",
		"config_file_writable", "config_file_writable"}, warningCodes(warns))
	w := warningsOf(warns, providers.WarnConfigFileWritable)
	assert.Equal(t, map[string]string{"path": "/etc/nginx/conf.d/w1.conf"}, w[0].Params)
	assert.Equal(t, map[string]string{"path": "/etc/nginx/conf.d/w2.conf"}, w[1].Params)
	for _, x := range warns {
		assert.NotNil(t, x.Params)
	}

	t.Run("writable bound", func(t *testing.T) {
		d := validDump(nil)
		for i := range 200 {
			d.Writable = append(d.Writable, fmt.Sprintf("/etc/nginx/conf.d/w%d.conf", i))
		}
		_, warns := convert(d)
		assert.Len(t, warns, maxWritable+1, "the paths and the truncation warning")
	})

	t.Run("key_group_open: attached to the location, never both", func(t *testing.T) {
		kf := keyFile(k)
		kf.Group = "ssl-cert"
		kf.Mode = "0640"
		d := validDump([]helperproto.NginxServer{server([]string{"a"}, 443, pair(c, k))}, certFile(c, u.chain), kf)
		d.Warnings = []string{helperproto.WarnKeyGroupOpen}
		got, warns := convert(d)
		assert.Equal(t, []string{providers.WarnKeyGroupOpen}, got[0].Location.Warnings)
		assert.Empty(t, warns)
	})
	t.Run("key_group_open that no location explains is kept at server level", func(t *testing.T) {
		d := validDump([]helperproto.NginxServer{server([]string{"a"}, 443, pair(c, k))}, certFile(c, u.chain), keyFile(k))
		d.Warnings = []string{helperproto.WarnKeyGroupOpen}
		got, warns := convert(d)
		assert.Empty(t, got[0].Location.Warnings)
		assert.Equal(t, []string{providers.WarnKeyGroupOpen}, warningCodes(warns), "nothing the helper said is lost")
	})
}

func TestNginxFactsOfTheDump(t *testing.T) {
	d := helperproto.NginxDumpResponse{OK: true, Version: " 1.22.1\x1b ", ConfPath: "/etc/nginx/nginx.conf", ConfigValid: true,
		ConfigError: "syntax", ConfigErrorReason: "changed", ConfigErrorFile: "/etc/nginx/x.conf"}
	assert.Equal(t, providers.NginxFacts{Found: true, Version: "1.22.1", ConfPath: "/etc/nginx/nginx.conf", ConfigValid: true}, nginxFacts(d),
		"a valid configuration carries no error")

	d.ConfigValid = false
	assert.Equal(t, providers.NginxFacts{Found: true, Version: "1.22.1", ConfPath: "/etc/nginx/nginx.conf", ConfigError: "syntax",
		ConfigErrorReason: "changed", ConfigErrorFile: "/etc/nginx/x.conf"}, nginxFacts(d))

	d.ConfigError, d.ConfigErrorReason, d.ConfigErrorFile = "bogus", "bogus", "relative\x1b/x"
	got := nginxFacts(d)
	assert.Empty(t, got.ConfigError, "an unknown class is not passed on")
	assert.Empty(t, got.ConfigErrorReason)
	assert.Empty(t, got.ConfigErrorFile, "a path that is not an absolute clean path is dropped")

	d.ConfigErrorFile = "/etc/nginx/\x1bx.conf"
	assert.Equal(t, "/etc/nginx/x.conf", nginxFacts(d).ConfigErrorFile)
	d.ConfigErrorFile = "/etc/nginx/" + strings.Repeat("a", 5000)
	assert.Empty(t, nginxFacts(d).ConfigErrorFile, "too long")

	d.Version = strings.Repeat("9", 300)
	d.ConfPath = "nginx.conf"
	got = nginxFacts(d)
	assert.Len(t, got.Version, maxVersionLength)
	assert.Empty(t, got.ConfPath)
	// Every class and reason of the framework is accepted.
	for _, cl := range []string{providers.ConfigErrKeyMismatch, providers.ConfigErrFileMissing, providers.ConfigErrCertLoad, providers.ConfigErrKeyLoad,
		providers.ConfigErrSyntax, providers.ConfigErrUntrusted, providers.ConfigErrUnsupported} {
		d.ConfigError = cl
		assert.Equal(t, cl, nginxFacts(d).ConfigError)
	}
	for _, r := range []string{providers.ConfigReasonNotRootControlled, providers.ConfigReasonSpecialFS, providers.ConfigReasonMissing,
		providers.ConfigReasonNotRegular, providers.ConfigReasonChanged, providers.ConfigReasonNameNotAllowed, providers.ConfigReasonUnexpectedText,
		providers.ConfigReasonWrongFirstFile, providers.ConfigReasonDuplicateFile, providers.ConfigReasonNoConfPath, providers.ConfigReasonTooLarge,
		providers.ConfigReasonTooComplex, providers.ConfigReasonIncludeLoop, providers.ConfigReasonNULByte} {
		d.ConfigErrorReason = r
		assert.Equal(t, r, nginxFacts(d).ConfigErrorReason)
	}
}

func TestPairState(t *testing.T) {
	assert.Equal(t, "", pairState(helperproto.NginxPair{Cert: "/a", Key: "/b"}, false))
	assert.Equal(t, providers.UnsupportedStream, pairState(helperproto.NginxPair{Cert: "/a", Key: "/b"}, true))
	assert.Equal(t, providers.UnsupportedKeyMissing, pairState(helperproto.NginxPair{Cert: "/a"}, false), "a certificate without a key is key_missing")
	assert.Equal(t, providers.UnsupportedVariable, pairState(helperproto.NginxPair{Unsupported: "variable", Raw: "/$x"}, true))
	assert.Equal(t, providers.UnsupportedUnknown, pairState(helperproto.NginxPair{Raw: "/x"}, false))
	assert.Equal(t, providers.UnsupportedUnknown, pairState(helperproto.NginxPair{Unsupported: "weird"}, false))
}

// A pair path the helper hands over is validated raw: never rewritten, never supported when invalid.
func TestConvertPairPathsAreValidatedRaw(t *testing.T) {
	u := newUnitCerts(t)
	const good = "/etc/nginx/ssl/a.crt"
	for _, tc := range []struct{ name, cert, key string }{
		{"relative cert", "ssl/a.crt", "/etc/nginx/ssl/a.key"},
		{"dot-dot cert", "/a/../b.crt", "/etc/nginx/ssl/a.key"},
		{"newline cert", "/etc/x\n.crt", "/etc/nginx/ssl/a.key"},
		{"control cert", "/etc/x\x1b.crt", "/etc/nginx/ssl/a.key"},
		{"long cert", "/" + strings.Repeat("a", 5000) + ".crt", "/etc/nginx/ssl/a.key"},
		{"relative key", good, "ssl/a.key"},
		{"dot-dot key", good, "/a/../b.key"},
		{"newline key", good, "/etc/x\n.key"},
		{"long key", good, "/" + strings.Repeat("a", 5000) + ".key"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// The files carry entries for every spelling, cleaned or not, so only validation can refuse.
			files := []helperproto.NginxFile{certFile(tc.cert, u.chain), keyFile(tc.key)}
			cleaned := []helperproto.NginxFile{certFile(clean(tc.cert, maxPathLength), u.chain), keyFile(clean(tc.key, maxPathLength))}
			got, _ := convert(validDump([]helperproto.NginxServer{server([]string{"a"}, 443, pair(tc.cert, tc.key))}, append(files, cleaned...)...))
			require.Len(t, got, 1)
			assert.False(t, got[0].Location.Supported)
			assert.Equal(t, providers.UnsupportedPathNotAllowed, got[0].Location.Unsupported)
			assert.Empty(t, got[0].PEMChain)
			assert.NotContains(t, got[0].Location.CertPath, "\n")
			// The shown paths are the raw values, marked, never a cleaned rewrite of them.
			for _, sh := range []struct{ shown, raw string }{{got[0].Location.CertPath, tc.cert}, {got[0].Location.KeyPath, tc.key}} {
				if helperproto.ValidPath(sh.raw) {
					assert.Equal(t, sh.raw, sh.shown)
					continue
				}
				assert.Equal(t, invalidPath(sh.raw), sh.shown)
				assert.NotEqual(t, clean(sh.raw, maxPathLength), sh.shown, "not a rewrite")
				assert.False(t, strings.HasPrefix(sh.shown, "/"), "never shown as a path")
			}
		})
	}
}

// An invalid spelling of a real path neither hides the real location nor describes its files.
func TestConvertInvalidPathsNeverMergeWithRealOnes(t *testing.T) {
	u := newUnitCerts(t)
	other := newUnitCerts(t)
	const c, k = "/etc/nginx/ssl/a.crt", "/etc/nginx/ssl/a.key"
	d := validDump([]helperproto.NginxServer{
		server([]string{"a"}, 443, pair(c, k)),
		server([]string{"b"}, 443, pair(c+"\n", k)),
	}, certFile(c, u.chain), keyFile(k), certFile(c+"\n", other.chain), keyFile(k+"\t"))
	got, _ := convert(d)
	require.Len(t, got, 2)
	byPath := map[string]providers.DiscoveredCertificate{}
	for _, g := range got {
		byPath[g.Location.CertPath] = g
	}
	real, ok := byPath[c]
	require.True(t, ok)
	assert.True(t, real.Location.Supported, "the real location stays supported")
	assert.Equal(t, string(u.chain), string(real.PEMChain), "described by its own file, not by the invalid spelling's")
	bad, ok := byPath[invalidPath(c+"\n")]
	require.True(t, ok)
	assert.Equal(t, providers.UnsupportedPathNotAllowed, bad.Location.Unsupported)
	assert.Equal(t, k, bad.Location.KeyPath)

	// The file list is keyed by valid raw paths only: a later invalid entry does not replace the real one.
	d = validDump([]helperproto.NginxServer{server([]string{"a"}, 443, pair(c, k))}, certFile(c, u.chain), keyFile(k), certFile(c+" ", other.chain))
	got, _ = convert(d)
	require.Len(t, got, 1)
	assert.Equal(t, string(u.chain), string(got[0].PEMChain))
	assert.Equal(t, hexSHA(u.chain), got[0].FileSHA256)
	assert.Equal(t, `"/a\n\x1b"`, invalidPath("/a\n\x1b"))
	assert.LessOrEqual(t, len(invalidPath(strings.Repeat("\x01", 10000))), 4*maxPathLength+2, "bounded")
}

func TestConvertTruncationIsReported(t *testing.T) {
	u := newUnitCerts(t)
	const c, k = "/etc/nginx/ssl/a.crt", "/etc/nginx/ssl/a.key"
	many := server(nil, 443, pair(c, k))
	for i := range maxNames + 1 {
		many.Names = append(many.Names, fmt.Sprintf("n%d", i))
	}
	_, w := convert(validDump([]helperproto.NginxServer{many}, certFile(c, u.chain), keyFile(k)))
	assert.Equal(t, []string{providers.WarnListTruncated}, warningCodes(w))
	many = server([]string{"a"}, 443, pair(c, k))
	for i := range maxListens + 1 {
		many.Listens = append(many.Listens, helperproto.NginxListen{Port: 1000 + i})
	}
	_, w = convert(validDump([]helperproto.NginxServer{many}, certFile(c, u.chain), keyFile(k)))
	assert.Equal(t, []string{providers.WarnListTruncated}, warningCodes(w))
	var servers []helperproto.NginxServer
	for i := range maxServersPerLocation + 1 {
		s := server([]string{"a"}, 443, pair(c, k))
		s.Line = i + 1
		servers = append(servers, s)
	}
	_, w = convert(validDump(servers, certFile(c, u.chain), keyFile(k)))
	assert.Equal(t, []string{providers.WarnListTruncated}, warningCodes(w))
	d := validDump(nil)
	for i := range maxWritable + 1 {
		d.Writable = append(d.Writable, fmt.Sprintf("/etc/nginx/conf.d/w%d.conf", i))
	}
	_, w = convert(d)
	assert.Len(t, warningsOf(w, providers.WarnListTruncated), 1)
	_, w = convert(validDump([]helperproto.NginxServer{server([]string{"a"}, 443, pair(c, k))}, certFile(c, u.chain), keyFile(k)))
	assert.Empty(t, w, "nothing cut, nothing said")
}

// A1-I1 (Alice side): a file whose resolved path is outside the helper's vocabulary makes the
// location unsupported, even when an older helper did not say so (it would be deployed, and its
// journal could not be read back).
func TestConvertResolvedPathOutsideTheVocabularyIsUnsupported(t *testing.T) {
	u := newUnitCerts(t)
	const c, k = "/etc/nginx/ssl/a.crt", "/etc/nginx/ssl/a.key"
	for name, files := range map[string][]helperproto.NginxFile{
		"certificate": {func() helperproto.NginxFile {
			f := certFile(c, u.chain)
			f.Resolved, f.Symlinked = "/etc/acme/*.example.test/fullchain.cer", true
			return f
		}(), keyFile(k)},
		"key": {certFile(c, u.chain), func() helperproto.NginxFile {
			f := keyFile(k)
			f.Resolved, f.Symlinked = "/etc/acme/*.example.test/key.key", true
			return f
		}()},
		"helper's own problem": {func() helperproto.NginxFile {
			f := certFile(c, nil)
			f.Resolved, f.SHA256, f.PEM, f.Problem = "/etc/acme/a b/fullchain.cer", "", "", helperproto.FileNameNotAllowed
			return f
		}(), keyFile(k)},
	} {
		t.Run(name, func(t *testing.T) {
			got, _ := convert(validDump([]helperproto.NginxServer{server([]string{"a"}, 443, pair(c, k))}, files...))
			require.Len(t, got, 1)
			loc := got[0].Location
			assert.False(t, loc.Supported)
			assert.Equal(t, providers.UnsupportedFile, loc.Unsupported)
			assert.Contains(t, []string{loc.Problem, loc.KeyProblem}, providers.CertProblemNameNotAllowed)
		})
	}
}

// A2-I3: the dump's warnings are bounded: a hostile list of 100,000 distinct codes costs linear
// time, keeps at most maxDumpWarnings of them and reports the cut. The time limit only has to tell
// linear from quadratic (which takes far longer than this for 100,000 codes), so it is generous
// enough for a loaded machine running the race detector.
func TestDumpWarningsAreBounded(t *testing.T) {
	d := validDump(nil)
	d.Warnings = append(d.Warnings, helperproto.WarnStreamTLS, helperproto.WarnStreamTLS, helperproto.WarnMailTLS)
	for i := range 100_000 {
		d.Warnings = append(d.Warnings, "w_"+strings.Repeat("a", i%30)+strings.Map(func(r rune) rune { return 'a' + r - '0' }, fmt.Sprint(i)))
	}
	start := time.Now()
	out, truncated := dumpWarnings(d, nil)
	assert.Less(t, time.Since(start), 10*time.Second)
	assert.True(t, truncated)
	assert.Len(t, out, maxDumpWarnings)
	assert.Equal(t, helperproto.WarnStreamTLS, out[0].Code)
	assert.Equal(t, helperproto.WarnMailTLS, out[1].Code)
	_, warns := convert(d)
	assert.Equal(t, providers.WarnListTruncated, warns[len(warns)-1].Code, "the cut is reported")
}
