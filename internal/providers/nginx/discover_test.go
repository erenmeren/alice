package nginx

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/providers"
	"alice/internal/providers/linuxssh/helperproto"
	"alice/internal/providers/linuxssh/linuxsshtest"
	"alice/internal/providers/nginx/nginxconf"
	"alice/internal/testutil/pki"
)

const authKeysLine = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJ1O1ywhjuNQkuBWbKQ2CbnMFgn8QF0v1kbbmVYh8y8c deploy@laptop"

func discover(t *testing.T, e *env, req providers.DiscoverRequest) providers.DiscoveryResult {
	t.Helper()
	s := e.open(t)
	defer func() { _ = s.Close() }()
	res, err := s.Discover(context.Background(), req)
	require.NoError(t, err)
	return res
}

func TestDiscoverListsWebsitesWithCertificates(t *testing.T) {
	e := newEnv(t)
	e.emu.SetFile("/home/deploy/.ssh/authorized_keys", []byte(authKeysLine+"\n"))
	res := discover(t, e, providers.DiscoverRequest{SSHKeys: true, Certificates: true})
	require.NotNil(t, res.Nginx)
	assert.Equal(t, providers.NginxFacts{Found: true, Version: "1.22.1", ConfPath: "/etc/nginx/nginx.conf", ConfigValid: true}, *res.Nginx)
	require.Len(t, res.Certificates, 1)
	c := res.Certificates[0]
	assert.Equal(t, wwwCert, c.Location.CertPath)
	assert.Equal(t, wwwKey, c.Location.KeyPath)
	assert.Equal(t, wwwCert, c.Location.ResolvedCertPath)
	assert.True(t, c.Location.Supported)
	assert.Empty(t, c.Location.Unsupported)
	assert.Empty(t, c.Location.Problem)
	assert.True(t, c.Location.KeyExists)
	assert.Equal(t, "0600", c.Location.KeyMode)
	assert.Equal(t, "root", c.Location.KeyOwner)
	assert.Equal(t, "root", c.Location.KeyGroup)
	assert.False(t, c.Location.CustomLocation)
	assert.Empty(t, c.Location.Warnings)
	assert.Positive(t, c.Location.FreeBytes)
	assert.Equal(t, []providers.CertServer{{Names: []string{"www.example.test"}, Listens: []providers.CertListen{{Port: 443}},
		File: "/etc/nginx/conf.d/emu.conf", Line: 1}}, c.Location.Servers)
	assert.Equal(t, string(e.leaf.FullchainPEM), string(c.PEMChain))
	assert.Equal(t, hexSHA(e.leaf.FullchainPEM), c.FileSHA256)
	assert.NotEmpty(t, res.SSHKeys, "an Nginx server's SSH keys are discovered too")
	out, err := json.Marshal(res)
	require.NoError(t, err)
	assert.NotContains(t, string(out), string(e.leaf.KeyPEM[30:70]), "key files are never read")
}

// Carry: SSH-key discovery, accounts and UID0Users are linuxssh's own.
func TestDiscoverSSHPartIsLinuxSSHs(t *testing.T) {
	e := newEnv(t)
	e.emu.SetFile("/home/deploy/.ssh/authorized_keys", []byte(authKeysLine+"\n"))
	e.emu.SetAccounts([]string{"root", "deploy", "alice-svc"}, true)
	got := discover(t, e, providers.DiscoverRequest{SSHKeys: true, Certificates: true})

	ls, err := e.prov.ssh.Open(context.Background(), e.ref, e.cred, providers.Env{})
	require.NoError(t, err)
	defer func() { _ = ls.Close() }()
	want, err := ls.Discover(context.Background(), providers.DiscoverRequest{SSHKeys: true})
	require.NoError(t, err)
	require.NotEmpty(t, want.SSHKeys)
	assert.Equal(t, want.SSHKeys, got.SSHKeys)
	assert.Equal(t, want.HostKeys, got.HostKeys)
	assert.Equal(t, want.SSHD, got.SSHD)
	assert.Equal(t, want.Accounts, got.Accounts)
	assert.Equal(t, want.AccountsComplete, got.AccountsComplete)
	assert.True(t, got.AccountsComplete)
	assert.Equal(t, want.UID0Users, got.UID0Users)
	assert.Equal(t, want.ReadFiles, got.ReadFiles)
	assert.Equal(t, want.UnreadableLines, got.UnreadableLines)
	assert.Equal(t, want.Partial, got.Partial)
	assert.ElementsMatch(t, warningCodes(want.Warnings), warningCodes(got.Warnings))
}

func TestDiscoverHonoursTheRequest(t *testing.T) {
	e := newEnv(t)
	e.emu.SetFile("/home/deploy/.ssh/authorized_keys", []byte(authKeysLine+"\n"))

	n := len(e.srv.Commands())
	res := discover(t, e, providers.DiscoverRequest{Certificates: true})
	cmds := e.srv.Commands()[n:]
	for _, line := range cmds {
		assert.NotContains(t, line, "authkeys", "a certificates-only request runs no SSH-key discovery")
	}
	assert.NotEmpty(t, cmds)
	assert.Empty(t, res.SSHKeys)
	assert.Empty(t, res.Accounts)
	assert.Len(t, res.Certificates, 1)
	require.NotNil(t, res.Nginx)

	n = len(e.srv.Commands())
	res = discover(t, e, providers.DiscoverRequest{SSHKeys: true})
	for _, line := range e.srv.Commands()[n:] {
		assert.NotContains(t, line, "nginx-", "an SSH-keys-only request runs no Nginx command")
	}
	assert.NotEmpty(t, res.SSHKeys)
	assert.Empty(t, res.Certificates)
	assert.Nil(t, res.Nginx)

	// Neither flag: linuxssh's own answer (host keys and sshd), no Nginx.
	n = len(e.srv.Commands())
	res = discover(t, e, providers.DiscoverRequest{})
	for _, line := range e.srv.Commands()[n:] {
		assert.NotContains(t, line, "nginx-")
	}
	assert.Nil(t, res.Nginx)
}

func TestDiscoverSharedDualAndUnsupportedLocations(t *testing.T) {
	e := newEnv(t)
	other := e.ca.Issue(pki.Opts{CommonName: "shop.example.test", KeyType: pki.RSA2048}, e.now)
	e.emu.AddSite(linuxsshtest.NginxSite{Names: []string{"api.example.test"}, Port: 8443, CertPath: wwwCert, KeyPath: wwwKey},
		e.leaf.FullchainPEM, e.leaf.KeyPEM)
	e.emu.AddSite(linuxsshtest.NginxSite{Names: []string{"shop.example.test"}, Port: 443, CertPath: "/etc/nginx/ssl/shop-rsa.crt", KeyPath: "/etc/nginx/ssl/shop-rsa.key"},
		other.FullchainPEM, other.KeyPEM)
	e.emu.AddUnsupported([]string{"files.example.test"}, 443, "/etc/nginx/ssl/$ssl_server_name.crt", "variable")
	e.emu.AddUnsupported([]string{"mail.example.test"}, 993, "/etc/ssl/mail.crt", "stream")
	res := discover(t, e, providers.DiscoverRequest{Certificates: true})
	byPath := locationsByPath(res)
	www := byPath[wwwCert].Location
	assert.Len(t, www.Servers, 2, "one file shared by two server blocks is one location")
	assert.Equal(t, []string{"www.example.test"}, www.Servers[0].Names)
	assert.Equal(t, []string{"api.example.test"}, www.Servers[1].Names)
	assert.Equal(t, 8443, www.Servers[1].Listens[0].Port)
	assert.True(t, byPath["/etc/nginx/ssl/shop-rsa.crt"].Location.Supported)
	v := byPath["/etc/nginx/ssl/$ssl_server_name.crt"]
	assert.False(t, v.Location.Supported)
	assert.Equal(t, providers.UnsupportedVariable, v.Location.Unsupported)
	assert.Empty(t, v.PEMChain)
	assert.Empty(t, v.Location.KeyPath)
	assert.Equal(t, providers.UnsupportedStream, byPath["/etc/ssl/mail.crt"].Location.Unsupported)
	assert.Equal(t, []string{"stream_tls"}, warningCodes(res.Warnings), "F-21: a warning, the http websites are still listed")
	assert.True(t, res.Nginx.ConfigValid)
}

// unsupportedRaws gives, per reason of the parser, the directive argument that makes the real
// parser (inside the emulator) arrive at it.
var unsupportedRaws = map[string]string{
	nginxconf.ReasonVariable:           "/etc/nginx/ssl/$host.crt",
	nginxconf.ReasonDataValue:          "data:$ssl_cert",
	nginxconf.ReasonEngineKey:          "/etc/nginx/ssl/u.crt",
	nginxconf.ReasonKeyMissing:         "/etc/nginx/ssl/u.crt",
	nginxconf.ReasonPasswordFile:       "/etc/nginx/ssl/u.crt",
	nginxconf.ReasonPathNotAllowed:     "ssl/",
	nginxconf.ReasonStream:             "/etc/nginx/ssl/u.crt",
	nginxconf.ReasonCombinedFile:       "/etc/nginx/ssl/u.pem",
	nginxconf.ReasonConfigFileWritable: "/etc/nginx/ssl/u.crt",
}

func TestDiscoverEveryUnsupportedReasonIsCarried(t *testing.T) {
	for reason, raw := range unsupportedRaws {
		t.Run(reason, func(t *testing.T) {
			e := newEnv(t)
			e.emu.AddUnsupported([]string{"u.example.test"}, 443, raw, reason)
			res := discover(t, e, providers.DiscoverRequest{Certificates: true})
			require.Len(t, res.Certificates, 2)
			u := res.Certificates[1].Location
			assert.False(t, u.Supported)
			assert.Equal(t, reason, u.Unsupported)
			assert.Equal(t, raw, u.CertPath, "the location key is the certificate path, else the raw value")
			assert.Empty(t, res.Certificates[1].PEMChain)
			assert.True(t, res.Certificates[0].Location.Supported, "the other website is untouched")
		})
	}
}

func TestDiscoverConfigFileWritableIsReportedOnceWithItsPath(t *testing.T) {
	e := newEnv(t)
	e.emu.AddUnsupported([]string{"w.example.test"}, 443, "/etc/nginx/ssl/w.crt", nginxconf.ReasonConfigFileWritable)
	res := discover(t, e, providers.DiscoverRequest{Certificates: true})
	w := warningsOf(res.Warnings, providers.WarnConfigFileWritable)
	require.Len(t, w, 1, "D14: the helper's own warning and the writable list are one warning")
	assert.Equal(t, map[string]string{"path": "/etc/nginx/conf.d/writable.conf"}, w[0].Params)

	// A writable file that holds a supported website makes that location unsupported too.
	e = newEnv(t)
	e.emu.SetNginxFileMode("/etc/nginx/conf.d/emu.conf", "root", "root", 0o664)
	res = discover(t, e, providers.DiscoverRequest{Certificates: true})
	assert.Equal(t, providers.UnsupportedConfigFileWritable, res.Certificates[0].Location.Unsupported)
	assert.False(t, res.Certificates[0].Location.Supported)
	require.Len(t, warningsOf(res.Warnings, providers.WarnConfigFileWritable), 1)
}

// F-20: no Nginx, no partial data: the whole discovery fails.
func TestDiscoverWithoutNginxFails(t *testing.T) {
	e := newEnv(t, withoutNginx())
	res, err := e.open(t).Discover(context.Background(), providers.DiscoverRequest{SSHKeys: true, Certificates: true})
	assert.Equal(t, "nginx.not_found", providerErr(t, err).Code)
	assert.Equal(t, providers.DiscoveryResult{}, res)
}

func TestDiscoverOutputTooLargeAndKilledNginx(t *testing.T) {
	e := newEnv(t)
	e.emu.SetNginxDumpBudget(100)
	_, err := e.open(t).Discover(context.Background(), providers.DiscoverRequest{Certificates: true})
	pe := providerErr(t, err)
	assert.Equal(t, "ssh.output_too_large", pe.Code)
	assert.False(t, pe.Retryable)

	e = newEnv(t)
	e.emu.SetNginxKilled(true)
	_, err = e.open(t).Discover(context.Background(), providers.DiscoverRequest{Certificates: true})
	pe = providerErr(t, err)
	assert.Equal(t, "ssh.helper_refused", pe.Code)
	assert.Equal(t, helperproto.CodeIOError, pe.Params["helper_code"])
	assert.True(t, pe.Retryable, "a killed or timed-out nginx may work next time")

	e = newEnv(t)
	e.emu.SetNginxProfile(false)
	_, err = e.open(t).Discover(context.Background(), providers.DiscoverRequest{Certificates: true})
	pe = providerErr(t, err)
	assert.Equal(t, "nginx.profile_missing", pe.Code)
	assert.Equal(t, map[string]string{"subcommand": "nginx-dump", "profile": "nginx"}, pe.Params)
}

// An invalid, untrusted or unsupported configuration is a successful discovery that says so.
func TestDiscoverConfigurationErrorsAreResults(t *testing.T) {
	const confPath = "/etc/nginx/nginx.conf"
	tests := []struct {
		name         string
		setup        func(e *env)
		class        string
		reason, file string
		confPath     string
	}{
		{"syntax", func(e *env) { e.emu.SetConfigInvalid(helperproto.ConfigErrSyntax) }, providers.ConfigErrSyntax, "", "", confPath},
		{"key mismatch", func(e *env) { e.emu.SetConfigInvalid(helperproto.ConfigErrKeyMismatch) }, providers.ConfigErrKeyMismatch, "", "", confPath},
		{"unbalanced braces", func(e *env) { e.emu.SetNginxConfig(confPath, "http {\n") }, providers.ConfigErrSyntax, "", "", confPath},
		{"no conf path", func(e *env) { e.emu.SetNginxConfPath("") }, providers.ConfigErrUnsupported, providers.ConfigReasonNoConfPath, "", ""},
		{"include loop", func(e *env) {
			e.emu.SetNginxConfig(confPath, "include /etc/nginx/a.conf;\n")
			e.emu.SetNginxConfig("/etc/nginx/a.conf", "include /etc/nginx/nginx.conf;\n")
		}, providers.ConfigErrUnsupported, providers.ConfigReasonIncludeLoop, "", confPath},
		{"nul byte", func(e *env) {
			e.emu.SetNginxDump("# configuration file " + confPath + ":\nhttp {}\x00\n")
		}, providers.ConfigErrUnsupported, providers.ConfigReasonNULByte, "", confPath},
		{"wrong first file", func(e *env) {
			e.emu.SetNginxDump("# configuration file /etc/nginx/other.conf:\nhttp { include /etc/nginx/conf.d/*.conf; }\n\n")
		}, providers.ConfigErrUntrusted, providers.ConfigReasonWrongFirstFile, "/etc/nginx/other.conf", confPath},
		{"changed", func(e *env) {
			e.emu.SetNginxDump(e.emu.NginxDumpText())
			e.emu.SetNginxFile("/etc/nginx/conf.d/emu.conf", append(e.emu.DumpFile("/etc/nginx/conf.d/emu.conf"), '#', '\n'))
		}, providers.ConfigErrUntrusted, providers.ConfigReasonChanged, "/etc/nginx/conf.d/emu.conf", confPath},
		{"special file system", func(e *env) {
			e.emu.SetFileProblem("/etc/nginx/conf.d/emu.conf", helperproto.FileSpecialFS)
		}, providers.ConfigErrUntrusted, providers.ConfigReasonSpecialFS, "/etc/nginx/conf.d/emu.conf", confPath},
		{"not root controlled", func(e *env) {
			e.emu.SetFileProblem("/etc/nginx/conf.d/emu.conf", helperproto.FileNotRootControlled)
		}, providers.ConfigErrUntrusted, providers.ConfigReasonNotRootControlled, "/etc/nginx/conf.d/emu.conf", confPath},
		{"not regular", func(e *env) {
			e.emu.SetFileProblem("/etc/nginx/conf.d/emu.conf", helperproto.FileNotRegular)
		}, providers.ConfigErrUntrusted, providers.ConfigReasonNotRegular, "/etc/nginx/conf.d/emu.conf", confPath},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			tc.setup(e)
			res := discover(t, e, providers.DiscoverRequest{Certificates: true})
			require.NotNil(t, res.Nginx)
			assert.Equal(t, providers.NginxFacts{Found: true, Version: "1.22.1", ConfPath: tc.confPath, ConfigValid: false,
				ConfigError: tc.class, ConfigErrorReason: tc.reason, ConfigErrorFile: tc.file}, *res.Nginx)
			assert.Empty(t, res.Certificates)
			assert.Equal(t, []string{"nginx_config_invalid"}, warningCodes(res.Warnings))
		})
	}
}

func TestDiscoverEmptyVersionAndConfPath(t *testing.T) {
	e := newEnv(t)
	e.emu.EnableNginx("")
	e.emu.SetNginxConfPath("")
	res := discover(t, e, providers.DiscoverRequest{Certificates: true})
	assert.Empty(t, res.Nginx.Version)
	assert.Empty(t, res.Nginx.ConfPath)
	assert.True(t, res.Nginx.Found)
}

// A forged dump is the way to reach what real nginx -T refuses (a pair file that is missing, not a
// certificate): the emulator's own nginx -T fails on such a file unless the dump is forged.
func forge(e *env) { e.emu.SetNginxDump(e.emu.NginxDumpText()) }

func TestDiscoverCertificateFileProblems(t *testing.T) {
	tests := []struct {
		name    string
		setup   func(e *env)
		problem string
	}{
		{"special file system", func(e *env) { e.emu.SetFileProblem(wwwCert, helperproto.FileSpecialFS) }, providers.CertProblemSpecialFS},
		{"not root controlled", func(e *env) { e.emu.SetFileProblem(wwwCert, helperproto.FileNotRootControlled) }, providers.CertProblemNotRootControlled},
		{"not regular", func(e *env) { e.emu.SetFileProblem(wwwCert, helperproto.FileNotRegular) }, providers.CertProblemNotRegular},
		{"hard linked", func(e *env) { e.emu.SetFileProblem(wwwCert, helperproto.FileHardLinked) }, providers.CertProblemHardLinked},
		{"too large", func(e *env) {
			e.emu.SetNginxFile(wwwCert, append(append([]byte{}, e.leaf.FullchainPEM...), []byte(strings.Repeat("\n", helperproto.MaxCertFileSize))...))
		}, providers.CertProblemTooLarge},
		{"missing", func(e *env) { forge(e); e.emu.RemoveNginxFile(wwwCert) }, providers.CertProblemMissing},
		{"not a certificate", func(e *env) { forge(e); e.emu.SetNginxFile(wwwCert, []byte("hello")) }, providers.CertProblemNotACertificate},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			tc.setup(e)
			res := discover(t, e, providers.DiscoverRequest{Certificates: true})
			require.Len(t, res.Certificates, 1)
			c := res.Certificates[0]
			assert.Equal(t, tc.problem, c.Location.Problem)
			assert.False(t, c.Location.Supported)
			assert.Equal(t, providers.UnsupportedFile, c.Location.Unsupported)
			assert.Empty(t, c.PEMChain)
			assert.Empty(t, c.FileSHA256)
			assert.Empty(t, c.Location.KeyProblem)
		})
	}
}

// REM-4 (RA-02): a certificate file whose first block the helper cannot read is leaf_unreadable,
// with no certificate: the intermediate after it never becomes the website's certificate.
func TestDiscoverLeafUnreadableHasNoCertificate(t *testing.T) {
	check := func(t *testing.T, c providers.DiscoveredCertificate) {
		t.Helper()
		assert.Equal(t, providers.CertProblemLeafUnreadable, c.Location.Problem)
		assert.Equal(t, "leaf_unreadable", c.Location.Problem)
		assert.False(t, c.Location.Supported)
		assert.Equal(t, providers.UnsupportedFile, c.Location.Unsupported)
		assert.Empty(t, c.PEMChain)
		assert.Empty(t, c.FileSHA256)
	}
	t.Run("a dump file with the problem", func(t *testing.T) {
		u := newUnitCerts(t)
		const c, k = "/etc/nginx/ssl/a.crt", "/etc/nginx/ssl/a.key"
		cf := certFile(c, u.chain) // a helper that names the problem and still sends blocks: Alice uses none
		cf.Problem = helperproto.FileLeafUnreadable
		got, _ := convert(validDump([]helperproto.DumpServer{server([]string{"a"}, 443, pair(c, k))}, cf, keyFile(k)))
		require.Len(t, got, 1)
		check(t, got[0])
	})
	t.Run("an unreadable first block (emulated helper)", func(t *testing.T) {
		e := newEnv(t)
		forge(e)
		unreadable := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{0x30, 0x03, 0x02, 0x01, 0x01}})
		e.emu.SetNginxFile(wwwCert, append(unreadable, e.leaf.FullchainPEM[len(e.leaf.CertPEM):]...))
		res := discover(t, e, providers.DiscoverRequest{Certificates: true})
		require.Len(t, res.Certificates, 1)
		check(t, res.Certificates[0])
		assert.Equal(t, []string{providers.WarnCertificateBlockDropped}, warningCodes(res.Warnings))
	})
}

func TestDiscoverKeyFileProblems(t *testing.T) {
	tests := []struct {
		name    string
		setup   func(e *env)
		problem string
		exists  bool
	}{
		{"missing", func(e *env) { forge(e); e.emu.RemoveNginxFile(wwwKey) }, providers.CertProblemMissing, false},
		{"special file system", func(e *env) { e.emu.SetFileProblem(wwwKey, helperproto.FileSpecialFS) }, providers.CertProblemSpecialFS, true},
		{"not root controlled", func(e *env) { e.emu.SetFileProblem(wwwKey, helperproto.FileNotRootControlled) }, providers.CertProblemNotRootControlled, true},
		{"not regular", func(e *env) { e.emu.SetFileProblem(wwwKey, helperproto.FileNotRegular) }, providers.CertProblemNotRegular, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			tc.setup(e)
			res := discover(t, e, providers.DiscoverRequest{Certificates: true})
			c := res.Certificates[0]
			assert.Equal(t, tc.problem, c.Location.KeyProblem)
			assert.Equal(t, tc.exists, c.Location.KeyExists)
			assert.False(t, c.Location.Supported)
			assert.Equal(t, providers.UnsupportedFile, c.Location.Unsupported)
			assert.Empty(t, c.Location.Problem, "the certificate file is fine")
			assert.Equal(t, string(e.leaf.FullchainPEM), string(c.PEMChain), "its chain is still listed")
		})
	}
}

func TestDiscoverKeyOwnerGroupAndMode(t *testing.T) {
	e := newEnv(t)
	e.emu.SetNginxFileMode(wwwKey, "root", "ssl-cert", 0o640)
	res := discover(t, e, providers.DiscoverRequest{Certificates: true})
	l := res.Certificates[0].Location
	assert.Equal(t, "0640", l.KeyMode)
	assert.Equal(t, "root", l.KeyOwner)
	assert.Equal(t, "ssl-cert", l.KeyGroup)
	assert.Equal(t, []string{providers.WarnKeyGroupOpen}, l.Warnings, "the response-level warning attaches to its location")
	assert.Empty(t, warningsOf(res.Warnings, providers.WarnKeyGroupOpen), "and is not repeated at server level")
	assert.True(t, l.Supported, "a warning does not make a location unsupported")

	e = newEnv(t)
	e.emu.SetNginxFileMode(wwwKey, "www-data", "root", 0o600)
	l = discover(t, e, providers.DiscoverRequest{Certificates: true}).Certificates[0].Location
	assert.Equal(t, "www-data", l.KeyOwner)
	assert.Equal(t, []string{providers.WarnKeyGroupOpen}, l.Warnings)

	e = newEnv(t)
	e.emu.SetNginxFileMode(wwwKey, "root", "root", 0o644)
	l = discover(t, e, providers.DiscoverRequest{Certificates: true}).Certificates[0].Location
	assert.Equal(t, []string{providers.WarnKeyModeOpen, providers.WarnKeyGroupOpen}, l.Warnings)

	// Only the location whose key is open carries the warning.
	e = newEnv(t)
	e.emu.AddSite(linuxsshtest.NginxSite{Names: []string{"b.example.test"}, Port: 443, CertPath: "/etc/nginx/ssl/b.crt", KeyPath: "/etc/nginx/ssl/b.key"},
		e.leaf.FullchainPEM, e.leaf.KeyPEM)
	e.emu.SetNginxFileMode("/etc/nginx/ssl/b.key", "root", "root", 0o644)
	by := locationsByPath(discover(t, e, providers.DiscoverRequest{Certificates: true}))
	assert.Empty(t, by[wwwCert].Location.Warnings)
	assert.NotEmpty(t, by["/etc/nginx/ssl/b.crt"].Location.Warnings)
}

func TestDiscoverKeyConflicts(t *testing.T) {
	e := newEnv(t)
	e.emu.AddSite(linuxsshtest.NginxSite{Names: []string{"b.example.test"}, Port: 443, CertPath: "/etc/nginx/ssl/b.crt", KeyPath: "/etc/nginx/ssl/b1.key"},
		e.leaf.FullchainPEM, e.leaf.KeyPEM)
	e.emu.AddSite(linuxsshtest.NginxSite{Names: []string{"c.example.test"}, Port: 443, CertPath: "/etc/nginx/ssl/b.crt", KeyPath: "/etc/nginx/ssl/b2.key"},
		e.leaf.FullchainPEM, e.leaf.KeyPEM)
	res := discover(t, e, providers.DiscoverRequest{Certificates: true})
	b := locationsByPath(res)["/etc/nginx/ssl/b.crt"]
	assert.Equal(t, providers.UnsupportedKeyConflict, b.Location.Unsupported)
	assert.False(t, b.Location.Supported)
	assert.Len(t, b.Location.Servers, 2)
	assert.Equal(t, string(e.leaf.FullchainPEM), string(b.PEMChain))
	assert.True(t, locationsByPath(res)[wwwCert].Location.Supported)
}

func TestDiscoverWarningsOfTheDump(t *testing.T) {
	e := newEnv(t)
	forge(e)
	e.emu.SetNginxFile(wwwCert, append(append([]byte{}, e.leaf.FullchainPEM...), []byte("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n")...))
	res := discover(t, e, providers.DiscoverRequest{Certificates: true})
	assert.Equal(t, []string{providers.WarnCertificateBlockDropped}, warningCodes(res.Warnings))
	assert.Equal(t, string(e.leaf.FullchainPEM), string(res.Certificates[0].PEMChain), "the helper dropped the block, the rest is returned")

	e = newEnv(t)
	e.emu.SetNginxConfig("/etc/nginx/nginx.conf",
		"events {}\nhttp { include /etc/nginx/conf.d/*.conf; }\nmail { server { listen 995 ssl; ssl_certificate /x/a.crt; ssl_certificate_key /x/a.key; } }\n")
	res = discover(t, e, providers.DiscoverRequest{Certificates: true})
	assert.Equal(t, []string{providers.WarnMailTLS}, warningCodes(res.Warnings))
	assert.Len(t, res.Certificates, 1)
}

func TestDiscoverTooManyFiles(t *testing.T) {
	e := newEnv(t)
	for i := range helperproto.MaxServerFiles {
		e.emu.AddSite(linuxsshtest.NginxSite{Port: 10000 + i, CertPath: fmt.Sprintf("/etc/nginx/many/%d.crt", i), KeyPath: fmt.Sprintf("/etc/nginx/many/%d.key", i)},
			e.leaf.CertPEM, e.leaf.KeyPEM)
	}
	res := discover(t, e, providers.DiscoverRequest{Certificates: true})
	assert.Len(t, warningsOf(res.Warnings, providers.WarnTooManyFiles), 1)
	assert.Len(t, warningsOf(res.Warnings, providers.WarnLocationsDropped), 1, "the default site makes 1001 locations: one is left out")
	assert.Len(t, res.Certificates, helperproto.MaxServerFiles, "bounded like the helper's file list")
	for _, c := range res.Certificates {
		if c.Location.KeyProblem == providers.CertProblemUnreadable {
			assert.False(t, c.Location.Supported, "a key file the helper did not describe is not usable")
			return
		}
	}
	t.Fatal("some key file was not described")
}

func TestDiscoverDeduplicatesAServerThatAppearsOncePerInclude(t *testing.T) {
	e := newEnv(t)
	e.emu.SetNginxConfig("/etc/nginx/nginx.conf", "events {}\nhttp { include /etc/nginx/conf.d/*.conf; include /etc/nginx/conf.d/emu.conf; }\n")
	res := discover(t, e, providers.DiscoverRequest{Certificates: true})
	require.NotNil(t, res.Nginx)
	if !res.Nginx.ConfigValid {
		t.Skipf("the helper refuses a file included twice (%s)", res.Nginx.ConfigErrorReason)
	}
	require.Len(t, res.Certificates, 1)
	assert.Len(t, res.Certificates[0].Location.Servers, 1)
}
