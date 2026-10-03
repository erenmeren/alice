//go:build linux

package main

import (
	"context"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"alice/internal/providers/linuxssh/helperproto"
	"alice/internal/providers/nginx/nginxconf"
	"alice/internal/testutil/pki"
)

const nginxV = `nginx version: nginx/1.22.1
built with OpenSSL 3.0.11 19 Sep 2023
TLS SNI support enabled
configure arguments: --with-cc-opt='-g -O2' --prefix=/usr/share/nginx --conf-path=/etc/nginx/nginx.conf --http-log-path=/var/log/nginx/access.log
`

const (
	mainConf = "http { include /etc/nginx/conf.d/*.conf; }\n"
	wwwConf  = `server {
    listen 443 ssl;
    server_name www.example.test;
    ssl_certificate /etc/nginx/ssl/www.crt;
    ssl_certificate_key /etc/nginx/ssl/www.key;
}
server {
    listen 443 ssl;
    server_name both.example.test;
    ssl_certificate /etc/nginx/ssl/both.pem;
    ssl_certificate_key /etc/nginx/ssl/both.pem;
}
`
)

// privateKeyMarker is built at run time so the source holds no PEM key marker.
var privateKeyMarker = "PRIVATE" + " KEY"

// confFile is one configuration file as nginx -T prints it.
type confFile struct{ path, content string }

// nginxWorld is a server with Nginx: the configuration files exist on disk and "nginx -T" prints
// them (the tests inline their configuration: the root-only test binary runs without the source
// tree). dump, when set, replaces what nginx -T prints.
type nginxWorld struct {
	f       *fixture
	conf    []confFile
	dump    *string
	version string
	tFails  string // stderr of a failing "nginx -t"/"-T"; "" = success
	missing bool   // /usr/sbin/nginx does not exist
	tooBig  bool   // nginx -T printed more than MaxNginxConfig
	calls   []string
	leaf    pki.Leaf
}

func newNginxWorld(t *testing.T) *nginxWorld {
	f := newFixture(t)
	for _, d := range []string{"/etc/nginx", "/etc/nginx/conf.d", "/etc/nginx/ssl"} {
		f.mkdir(d, 0o755)
	}
	ca := pki.NewCA("Helper Test", pki.ECDSA256, testNow)
	w := &nginxWorld{f: f, version: nginxV, leaf: ca.Issue(pki.Opts{CommonName: "www.example.test"}, testNow)}
	w.setConf(confFile{"/etc/nginx/nginx.conf", mainConf}, confFile{"/etc/nginx/conf.d/www.conf", wwwConf})
	f.write("/etc/nginx/ssl/www.crt", string(w.leaf.FullchainPEM), 0o644)
	f.write("/etc/nginx/ssl/www.key", string(w.leaf.KeyPEM), 0o600)
	f.s.runNginx = func(_ context.Context, args ...string) ([]byte, []byte, error) {
		w.calls = append(w.calls, strings.Join(args, " "))
		if w.missing {
			return nil, nil, &fs.PathError{Op: "fork/exec", Path: nginxPath, Err: fs.ErrNotExist}
		}
		switch args[0] {
		case "-V":
			return nil, []byte(w.version), nil
		case "-T":
			switch {
			case w.tFails != "":
				return nil, []byte(w.tFails), errors.New("exit status 1")
			case w.tooBig:
				return nil, nil, errTooLarge
			}
			return []byte(w.dumpText()), []byte("nginx: the configuration file /etc/nginx/nginx.conf syntax is ok\n"), nil
		case "-t":
			if w.tFails != "" {
				return nil, []byte(w.tFails), errors.New("exit status 1")
			}
			return nil, nil, nil
		}
		return nil, nil, errors.New("unexpected nginx arguments")
	}
	return w
}

// setConf writes the configuration files (0644) and makes nginx -T print them.
func (w *nginxWorld) setConf(files ...confFile) {
	w.f.t.Helper()
	w.conf = files
	for _, c := range files {
		w.f.write(c.path, c.content, 0o644)
	}
}

// dumpText is what nginx -T prints: each file under its marker, followed by a line feed.
func (w *nginxWorld) dumpText() string {
	if w.dump != nil {
		return *w.dump
	}
	var b strings.Builder
	for _, c := range w.conf {
		b.WriteString("# configuration file " + c.path + ":\n" + c.content + "\n")
	}
	return b.String()
}

func (w *nginxWorld) setDump(d string) { w.dump = &d }

func fileOf(t *testing.T, m map[string]any, kind, path string) map[string]any {
	t.Helper()
	for _, x := range m["files"].([]any) {
		fi := x.(map[string]any)
		if fi["kind"] == kind && fi["path"] == path {
			return fi
		}
	}
	t.Fatalf("no %s file %s in %v", kind, path, m["files"])
	return nil
}

// pairsOf returns every pair of the answer as "cert key unsupported".
func pairsOf(m map[string]any) []string {
	var out []string
	for _, s := range m["servers"].([]any) {
		for _, p := range s.(map[string]any)["pairs"].([]any) {
			pm := p.(map[string]any)
			out = append(out, fmt.Sprintf("%v %v %v", pm["cert"], pm["key"], pm["unsupported"]))
		}
	}
	return out
}

func TestNginxDumpDescribesTheReferencedFiles(t *testing.T) {
	w := newNginxWorld(t)
	code, m := w.f.run("nginx-dump")
	require.Equal(t, 0, code, "%v", m)
	assert.Equal(t, "1.22.1", m["version"])
	assert.Equal(t, "/etc/nginx/nginx.conf", m["conf_path"])
	assert.Equal(t, true, m["config_valid"])
	assert.Equal(t, "", m["config_error"])
	assert.Equal(t, []string{"-V", "-T"}, w.calls)
	assert.Equal(t, []any{}, m["warnings"])
	assert.Equal(t, []any{}, m["writable"])
	files := m["files"].([]any)
	require.Len(t, files, 2, "the combined pair is unsupported, so its file is not described")
	cert, key := files[0].(map[string]any), files[1].(map[string]any)
	assert.Equal(t, "cert", cert["kind"])
	assert.Equal(t, "/etc/nginx/ssl/www.crt", cert["path"])
	assert.Equal(t, "/etc/nginx/ssl/www.crt", cert["resolved"])
	assert.Equal(t, true, cert["exists"])
	assert.Equal(t, hexOf(string(w.leaf.FullchainPEM)), cert["sha256"])
	assert.Equal(t, string(w.leaf.FullchainPEM), cert["pem"])
	assert.Equal(t, "", cert["problem"])
	assert.Equal(t, "0644", cert["mode"])
	assert.Equal(t, float64(1<<30), cert["free_bytes"])
	assert.Equal(t, "key", key["kind"])
	assert.Equal(t, "0600", key["mode"])
	assert.Equal(t, true, key["exists"])
	assert.Equal(t, float64(len(w.leaf.KeyPEM)), key["size"])
	assert.Equal(t, "", key["pem"])
	assert.Equal(t, "", key["sha256"], "a key file is never read")
	assert.NotContains(t, w.f.out.String(), string(w.leaf.KeyPEM[30:70]))
	servers := m["servers"].([]any)
	require.Len(t, servers, 2)
	www := servers[0].(map[string]any)
	assert.Equal(t, "/etc/nginx/conf.d/www.conf", www["file"])
	assert.Equal(t, float64(1), www["line"])
	assert.Equal(t, []any{"www.example.test"}, www["names"])
	assert.Equal(t, []any{map[string]any{"addr": "", "port": float64(443), "default_server": false}}, www["listens"])
	pairs := servers[1].(map[string]any)["pairs"].([]any)
	assert.Equal(t, nginxconf.ReasonCombinedFile, pairs[0].(map[string]any)["unsupported"])
	assert.Equal(t, "/etc/nginx/ssl/both.pem", pairs[0].(map[string]any)["raw"])
	assert.Contains(t, w.f.loggedLines(), "nginx-dump ")
}

// A certificate file that also holds a private key: only the CERTIFICATE blocks leave the helper.
func TestNginxDumpNeverOutputsKeyBlocks(t *testing.T) {
	w := newNginxWorld(t)
	w.f.write("/etc/nginx/ssl/www.crt", string(w.leaf.FullchainPEM)+string(w.leaf.KeyPEM), 0o644)
	_, m := w.f.run("nginx-dump")
	out := fileOf(t, m, "cert", "/etc/nginx/ssl/www.crt")["pem"].(string)
	n := 0
	for rest := []byte(out); ; n++ {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			break
		}
		assert.Equal(t, "CERTIFICATE", b.Type)
	}
	assert.Equal(t, 2, n)
	assert.NotContains(t, w.f.out.String(), privateKeyMarker)
	assert.NotContains(t, w.f.out.String(), string(w.leaf.KeyPEM[30:70]))
}

// A private key inside a CERTIFICATE begin line and a broken block are never decoded or returned.
func TestCertBlocksNeverDecodeAKey(t *testing.T) {
	leaf := newNginxWorld(t).leaf
	key := strings.TrimSpace(string(leaf.KeyPEM))
	for name, in := range map[string]string{
		"key after an unterminated certificate": "-----BEGIN CERTIFICATE-----\nAAAA\n" + key,
		"key labelled as a certificate":         strings.ReplaceAll(key, privateKeyMarker, "CERTIFICATE"),
		"certificate with headers":              strings.Replace(string(leaf.CertPEM), "-----\n", "-----\nProc-Type: 4,ENCRYPTED\n\n", 1),
	} {
		blocks, dropped := certBlocks([]byte(in))
		assert.Equal(t, "", blocks, name)
		assert.True(t, dropped, name)
	}
	blocks, dropped := certBlocks(append(append([]byte("\xef\xbb\xbf"), leaf.CertPEM...), leaf.KeyPEM...))
	assert.Equal(t, string(leaf.CertPEM), blocks, "a BOM and a key after the certificate are ignored")
	assert.False(t, dropped)
}

// S9: blocks labelled CERTIFICATE that are not X.509 certificates are dropped with a warning.
func TestNginxDumpDropsBlocksThatAreNotCertificates(t *testing.T) {
	w := newNginxWorld(t)
	junk := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("not a certificate")}))
	w.f.write("/etc/nginx/ssl/www.crt", string(w.leaf.CertPEM)+junk, 0o644)
	_, m := w.f.run("nginx-dump")
	cert := fileOf(t, m, "cert", "/etc/nginx/ssl/www.crt")
	assert.Equal(t, string(w.leaf.CertPEM), cert["pem"])
	assert.Equal(t, "", cert["problem"])
	assert.Contains(t, m["warnings"], helperproto.WarnCertificateBlockDropped)

	w.f.write("/etc/nginx/ssl/www.crt", junk, 0o644)
	_, m = w.f.run("nginx-dump")
	cert = fileOf(t, m, "cert", "/etc/nginx/ssl/www.crt")
	assert.Equal(t, helperproto.FileNotACertificate, cert["problem"])
	assert.Equal(t, "", cert["pem"])
}

// Review Focus 2, A-13: a link to /etc/shadow is resolved (root made it) but its name has no
// certificate extension, so it is never opened.
func TestAttackSymlinkToShadowIsNeverRead(t *testing.T) {
	w := newNginxWorld(t)
	w.f.write("/etc/shadow", "root:$6$secret-hash:19000:0:99999:7:::\n", 0o600)
	require.NoError(t, os.Remove(w.f.host("/etc/nginx/ssl/www.crt")))
	require.NoError(t, os.Symlink("/etc/shadow", w.f.host("/etc/nginx/ssl/www.crt")))
	require.NoError(t, os.Remove(w.f.host("/etc/nginx/ssl/www.key")))
	require.NoError(t, os.Symlink("../../shadow", w.f.host("/etc/nginx/ssl/www.key")))
	_, m := w.f.run("nginx-dump")
	cert := fileOf(t, m, "cert", "/etc/nginx/ssl/www.crt")
	assert.Equal(t, helperproto.FileBadName, cert["problem"])
	assert.Equal(t, "", cert["pem"])
	assert.Equal(t, "", cert["sha256"])
	key := fileOf(t, m, "key", "/etc/nginx/ssl/www.key")
	assert.Equal(t, helperproto.FileBadName, key["problem"], "a key that resolves outside the allowed names")
	assert.Equal(t, "/etc/shadow", key["resolved"])
	assert.NotContains(t, w.f.out.String(), "secret-hash")
}

// A key or certificate path through a writable directory, or a user's link, is not described.
func TestNginxDumpReportsFileProblems(t *testing.T) {
	w := newNginxWorld(t)
	require.NoError(t, os.Chmod(w.f.host("/etc/nginx/ssl"), 0o777))
	_, m := w.f.run("nginx-dump")
	for _, x := range m["files"].([]any) {
		assert.Equal(t, helperproto.FileNotRootControlled, x.(map[string]any)["problem"])
		assert.Equal(t, "", x.(map[string]any)["pem"])
	}
	require.NoError(t, os.Chmod(w.f.host("/etc/nginx/ssl"), 0o755))
	w.f.write("/etc/nginx/ssl/www.crt", "not a certificate", 0o644)
	_, m = w.f.run("nginx-dump")
	assert.Equal(t, helperproto.FileNotACertificate, fileOf(t, m, "cert", "/etc/nginx/ssl/www.crt")["problem"])
	w.f.write("/etc/nginx/ssl/www.crt", strings.Repeat("a", helperproto.MaxCertFileSize+1), 0o644)
	_, m = w.f.run("nginx-dump")
	assert.Equal(t, helperproto.FileTooLarge, fileOf(t, m, "cert", "/etc/nginx/ssl/www.crt")["problem"])
	require.NoError(t, os.Link(w.f.host("/etc/nginx/ssl/www.key"), w.f.host("/etc/nginx/ssl/other.key")))
	_, m = w.f.run("nginx-dump")
	assert.Equal(t, helperproto.FileHardLinked, fileOf(t, m, "key", "/etc/nginx/ssl/www.key")["problem"])
	require.NoError(t, os.Remove(w.f.host("/etc/nginx/ssl/other.key")))
	require.NoError(t, os.Remove(w.f.host("/etc/nginx/ssl/www.key")))
	_, m = w.f.run("nginx-dump")
	key := fileOf(t, m, "key", "/etc/nginx/ssl/www.key")
	assert.Equal(t, false, key["exists"])
	assert.Equal(t, helperproto.FileMissing, key["problem"])
	require.NoError(t, os.Remove(w.f.host("/etc/nginx/ssl/www.crt")))
	_, m = w.f.run("nginx-dump")
	cert := fileOf(t, m, "cert", "/etc/nginx/ssl/www.crt")
	assert.Equal(t, false, cert["exists"])
	assert.Equal(t, helperproto.FileMissing, cert["problem"])
}

// Let's Encrypt's live -> ../../archive links are followed for the certificate and the key.
func TestNginxDumpLetsEncryptLayout(t *testing.T) {
	w := newNginxWorld(t)
	letsEncrypt(w.f)
	w.f.write("/etc/letsencrypt/archive/shop.example.test/fullchain3.pem", string(w.leaf.FullchainPEM), 0o644)
	w.setConf(confFile{"/etc/nginx/nginx.conf", "http { server { listen 443 ssl; server_name shop.example.test;\n" +
		"ssl_certificate /etc/letsencrypt/live/shop.example.test/fullchain.pem;\n" +
		"ssl_certificate_key /etc/letsencrypt/live/shop.example.test/privkey.pem; } }\n"})
	_, m := w.f.run("nginx-dump")
	cert := fileOf(t, m, "cert", "/etc/letsencrypt/live/shop.example.test/fullchain.pem")
	assert.Equal(t, "", cert["problem"])
	assert.Equal(t, true, cert["symlinked"])
	assert.Equal(t, "/etc/letsencrypt/archive/shop.example.test/fullchain3.pem", cert["resolved"])
	assert.Equal(t, string(w.leaf.FullchainPEM), cert["pem"])
	key := fileOf(t, m, "key", "/etc/letsencrypt/live/shop.example.test/privkey.pem")
	assert.Equal(t, "", key["problem"])
	assert.Equal(t, "/etc/letsencrypt/archive/shop.example.test/privkey3.pem", key["resolved"])
}

// Requirement 9: a key file is never opened. A FIFO key would release a blocked writer if it were.
func TestKeyFileIsNeverOpened(t *testing.T) {
	w := newNginxWorld(t)
	require.NoError(t, os.Remove(w.f.host("/etc/nginx/ssl/www.key")))
	require.NoError(t, unix.Mkfifo(w.f.host("/etc/nginx/ssl/www.key"), 0o600))
	opened := make(chan struct{})
	go func() {
		if fd, err := os.OpenFile(w.f.host("/etc/nginx/ssl/www.key"), os.O_WRONLY, 0); err == nil {
			_ = fd.Close()
		}
		close(opened)
	}()
	time.Sleep(100 * time.Millisecond)
	_, m := w.f.run("nginx-dump")
	assert.Equal(t, helperproto.FileNotRegular, fileOf(t, m, "key", "/etc/nginx/ssl/www.key")["problem"])
	select {
	case <-opened:
		t.Fatal("the helper opened the key file")
	case <-time.After(200 * time.Millisecond):
	}
	r, err := os.OpenFile(w.f.host("/etc/nginx/ssl/www.key"), os.O_RDONLY, 0)
	require.NoError(t, err)
	<-opened
	_ = r.Close()
}

func TestNginxDumpInvalidConfiguration(t *testing.T) {
	w := newNginxWorld(t)
	w.tFails = "nginx: [emerg] SSL_CTX_use_PrivateKey(\"/etc/nginx/ssl/www.key\") failed (SSL: error:05800074:x509 certificate routines::key values mismatch)\n"
	code, m := w.f.run("nginx-dump")
	require.Equal(t, 0, code)
	assert.Equal(t, false, m["config_valid"])
	assert.Equal(t, helperproto.ConfigErrKeyMismatch, m["config_error"])
	assert.Equal(t, []any{}, m["servers"])
	assert.Equal(t, []any{}, m["files"])
	assert.NotContains(t, w.f.out.String(), "/etc/nginx/ssl/www.key", "nginx's text never leaves the helper")
}

// Requirement 2: any parse failure, size limit or unknown configuration prefix is reported as an
// invalid configuration, never as a partial or empty one.
func TestNginxDumpUnsupportedConfigurations(t *testing.T) {
	for name, tc := range map[string]func(w *nginxWorld){
		"syntax error": func(w *nginxWorld) { w.setConf(confFile{"/etc/nginx/nginx.conf", "http {\n"}) },
		"NUL byte":     func(w *nginxWorld) { w.setDump("# configuration file /etc/nginx/nginx.conf:\nhttp { }\x00\n") },
		"too many args": func(w *nginxWorld) {
			w.setConf(confFile{"/etc/nginx/nginx.conf", "http { server { server_name" + strings.Repeat(" a", 5000) + "; } }"})
		},
		"include loop": func(w *nginxWorld) { w.setConf(confFile{"/etc/nginx/nginx.conf", "include /etc/nginx/nginx.conf;"}) },
		"duplicate file": func(w *nginxWorld) {
			w.setDump(w.dumpText() + "# configuration file /etc/nginx/nginx.conf:\nhttp { }\n")
		},
		"output too large": func(w *nginxWorld) { w.tooBig = true },
		"relative confpath": func(w *nginxWorld) {
			w.version = strings.Replace(nginxV, "/etc/nginx/nginx.conf", "conf/nginx.conf", 1)
		},
		"no confpath": func(w *nginxWorld) { w.version = strings.Replace(nginxV, "--conf-path=/etc/nginx/nginx.conf ", "", 1) },
		"unclean confpath": func(w *nginxWorld) {
			w.version = strings.Replace(nginxV, "/etc/nginx/nginx.conf", "/etc/nginx//nginx.conf", 1)
		},
	} {
		t.Run(name, func(t *testing.T) {
			w := newNginxWorld(t)
			tc(w)
			code, m := w.f.run("nginx-dump")
			require.Equal(t, 0, code, "%v", m)
			assert.Equal(t, false, m["config_valid"])
			assert.Equal(t, helperproto.ConfigErrSyntax, m["config_error"])
			assert.Equal(t, []any{}, m["servers"])
			assert.Equal(t, []any{}, m["files"])
			assert.Equal(t, []any{}, m["writable"])
		})
	}
}

// Requirement 1: every section must be the exact content of the file it names, read through the
// root-controlled walk; otherwise the whole dump is refused.
func TestAttackUntrustedDumpsAreRefused(t *testing.T) {
	for name, tc := range map[string]func(w *nginxWorld){
		"text before the first marker": func(w *nginxWorld) { w.setDump("http { server { }}\n" + w.dumpText()) },
		"first file is not the configuration": func(w *nginxWorld) {
			w.setConf(confFile{"/etc/nginx/conf.d/www.conf", wwwConf}, confFile{"/etc/nginx/nginx.conf", mainConf})
		},
		"a file changed since nginx read it": func(w *nginxWorld) { w.f.write("/etc/nginx/conf.d/www.conf", wwwConf+"#\n", 0o644) },
		"a file that does not exist":         func(w *nginxWorld) { require.NoError(t, os.Remove(w.f.host("/etc/nginx/conf.d/www.conf"))) },
		"no line feed after the file":        func(w *nginxWorld) { w.setDump(strings.TrimSuffix(w.dumpText(), "\n")) },
		"a name with a space": func(w *nginxWorld) {
			w.f.write("/etc/nginx/conf.d/a b.conf", "", 0o644)
			w.setDump(w.dumpText() + "# configuration file /etc/nginx/conf.d/a b.conf:\n\n")
		},
		"a name with ..": func(w *nginxWorld) {
			w.setDump(w.dumpText() + "# configuration file /etc/nginx/conf.d/../nginx.conf:\n" + mainConf + "\n")
		},
		"a relative name": func(w *nginxWorld) {
			w.setDump(w.dumpText() + "# configuration file conf.d/www.conf:\n" + wwwConf + "\n")
		},
		"a file in a directory others can write": func(w *nginxWorld) {
			require.NoError(t, os.Chmod(w.f.host("/etc/nginx/conf.d"), 0o777))
		},
		"a file reached through a link to a writable directory": func(w *nginxWorld) {
			w.f.mkdir("/srv", 0o777)
			w.f.write("/srv/www.conf", wwwConf, 0o644)
			require.NoError(t, os.Remove(w.f.host("/etc/nginx/conf.d/www.conf")))
			w.f.symlink("/srv/www.conf", "/etc/nginx/conf.d/www.conf")
		},
		"a hard-linked file": func(w *nginxWorld) {
			require.NoError(t, os.Link(w.f.host("/etc/nginx/conf.d/www.conf"), w.f.host("/etc/nginx/www.conf.bak")))
		},
		"an empty dump": func(w *nginxWorld) { w.setDump("") },
	} {
		t.Run(name, func(t *testing.T) {
			w := newNginxWorld(t)
			tc(w)
			code, m := w.f.run("nginx-dump")
			require.Equal(t, 0, code, "%v", m)
			assert.Equal(t, false, m["config_valid"])
			assert.Equal(t, helperproto.ConfigErrSyntax, m["config_error"])
			assert.Equal(t, []any{}, m["servers"])
			assert.Equal(t, []any{}, m["files"])
		})
	}
}

// Root-owned links on the way to a configuration file are fine (Debian's sites-enabled links),
// and "./" or "//" spellings that nginx prints are read as the kernel would.
func TestNginxDumpAcceptsRootLinksAndDotSpellings(t *testing.T) {
	w := newNginxWorld(t)
	w.f.mkdir("/etc/nginx/sites-available", 0o755)
	w.f.mkdir("/etc/nginx/sites-enabled", 0o755)
	w.f.write("/etc/nginx/sites-available/default", wwwConf, 0o644)
	w.f.symlink("/etc/nginx/sites-available/default", "/etc/nginx/sites-enabled/default")
	main := "http { include /etc/nginx/sites-enabled/*; include ./conf.d/x.conf; }\n"
	w.f.write("/etc/nginx/conf.d/x.conf", "", 0o644)
	w.setConf(confFile{"/etc/nginx/nginx.conf", main})
	w.setDump(w.dumpText() + "# configuration file /etc/nginx/sites-enabled/default:\n" + wwwConf + "\n" +
		"# configuration file /etc/nginx/./conf.d/x.conf:\n\n")
	_, m := w.f.run("nginx-dump")
	require.Equal(t, true, m["config_valid"], "%v", m)
	assert.Equal(t, []string{"/etc/nginx/ssl/www.crt /etc/nginx/ssl/www.key ", "/etc/nginx/ssl/both.pem /etc/nginx/ssl/both.pem combined_file"}, pairsOf(m))
}

// The reviewer's proof of concept (Task 3): an attacker who can write one included file forges a
// marker with a fresh name that the include glob matches, so the forged server block looks as if a
// file root controls held it, and re-pairs the bank's certificate with another service's key.
func TestAttackForgedMarkerWithAFreshName(t *testing.T) {
	w := newNginxWorld(t)
	w.f.mkdir("/etc/nginx/sites-enabled", 0o755)
	w.f.mkdir("/etc/ssl", 0o755)
	w.f.mkdir("/etc/ssl/private", 0o700)
	w.f.write("/etc/ssl/private/mail.key", string(w.leaf.KeyPEM), 0o600)
	w.f.write("/etc/nginx/ssl/bank.crt", string(w.leaf.FullchainPEM), 0o644)
	evil := "server { listen 8443 ssl; ssl_certificate /etc/nginx/ssl/own.crt; ssl_certificate_key /etc/nginx/ssl/own.key; }\n" +
		"# configuration file /etc/nginx/sites-enabled/zz-bank:\n" +
		"server { listen 443 ssl; server_name bank.example.test; ssl_certificate /etc/nginx/ssl/bank.crt; ssl_certificate_key /etc/ssl/private/mail.key; }"
	w.setConf(confFile{"/etc/nginx/nginx.conf", "http { include /etc/nginx/sites-enabled/*; }\n"},
		confFile{"/etc/nginx/sites-enabled/evil", evil})
	require.NoError(t, os.Chmod(w.f.host("/etc/nginx/sites-enabled/evil"), 0o666)) // the attacker's file
	code, m := w.f.run("nginx-dump")
	require.Equal(t, 0, code)
	assert.Equal(t, false, m["config_valid"], "the forged section is not a real file: the dump is refused")
	assert.Empty(t, m["servers"])
	assert.NotContains(t, w.f.out.String(), "mail.key")
}

// The same attack with a forged marker that names a real root-owned file and repeats its exact
// content: the forged section passes, but the attacker's own file no longer matches its section.
func TestAttackForgedMarkerNamingARealFile(t *testing.T) {
	w := newNginxWorld(t)
	w.f.mkdir("/etc/nginx/sites-enabled", 0o755)
	w.f.mkdir("/etc/nginx/snippets", 0o755)
	bank := "server { listen 443 ssl; server_name bank.example.test; ssl_certificate /etc/nginx/ssl/www.crt; ssl_certificate_key /etc/nginx/ssl/www.key; }\n"
	w.f.write("/etc/nginx/snippets/bank.conf", bank, 0o644) // root's, not included by nginx itself
	evil := "server { listen 8443 ssl; ssl_certificate /etc/nginx/ssl/own.crt; ssl_certificate_key /etc/nginx/ssl/own.key; }\n" +
		"# configuration file /etc/nginx/snippets/bank.conf:\n" + bank
	w.setConf(confFile{"/etc/nginx/nginx.conf", "http { include /etc/nginx/sites-enabled/*; include /etc/nginx/snippets/b*.conf; }\n"},
		confFile{"/etc/nginx/sites-enabled/evil", strings.TrimSuffix(evil, "\n")})
	require.NoError(t, os.Chmod(w.f.host("/etc/nginx/sites-enabled/evil"), 0o666))
	_, m := w.f.run("nginx-dump")
	assert.Equal(t, false, m["config_valid"])
	assert.Empty(t, m["servers"])
}

// A line that looks like a marker inside a real root-owned file (a comment nginx ignores) splits
// that file's section: the dump is refused rather than misattributed.
func TestMarkerLikeCommentInARealFileIsRefused(t *testing.T) {
	w := newNginxWorld(t)
	w.setConf(confFile{"/etc/nginx/nginx.conf", mainConf + "# configuration file /etc/nginx/conf.d/zz.conf:\n" +
		"server { listen 443 ssl; ssl_certificate /etc/nginx/ssl/www.crt; ssl_certificate_key /etc/nginx/ssl/www.key; }"},
		confFile{"/etc/nginx/conf.d/www.conf", wwwConf})
	_, m := w.f.run("nginx-dump")
	assert.Equal(t, false, m["config_valid"])
}

// S1: a pair is unsupported when the file that holds its server block is writable by others.
func TestNginxDumpFlagsWritableConfigurationFiles(t *testing.T) {
	w := newNginxWorld(t)
	require.NoError(t, os.Chmod(w.f.host("/etc/nginx/conf.d/www.conf"), 0o666))
	_, m := w.f.run("nginx-dump")
	assert.Equal(t, true, m["config_valid"])
	assert.Equal(t, []any{"/etc/nginx/conf.d/www.conf"}, m["writable"])
	assert.Contains(t, m["warnings"], helperproto.WarnConfigFileWritable)
	assert.Equal(t, []string{"/etc/nginx/ssl/www.crt /etc/nginx/ssl/www.key config_file_writable",
		"/etc/nginx/ssl/both.pem /etc/nginx/ssl/both.pem combined_file"}, pairsOf(m))
	assert.Equal(t, []any{}, m["files"], "an unsupported pair's files are not read")
	require.NoError(t, os.Chmod(w.f.host("/etc/nginx/conf.d/www.conf"), 0o664))
	_, m = w.f.run("nginx-dump")
	assert.Equal(t, []any{"/etc/nginx/conf.d/www.conf"}, m["writable"], "group-writable too")
}

// S1: a writable snippet spliced into a root-only server block, or a writable file that holds an
// inherited http-level directive, makes the pair unsupported too; a writable file elsewhere does not.
func TestAttackWritableFileThatContributesToAPair(t *testing.T) {
	for name, tc := range map[string]struct {
		main, snippet string
		want          string
	}{
		"snippet in the server block": {"http { server { listen 443 ssl; ssl_certificate /etc/nginx/ssl/www.crt; include /etc/nginx/snip.conf; } }\n",
			"ssl_certificate_key /etc/nginx/ssl/www.key;\n", "config_file_writable"},
		"snippet with only a listen": {"http { server { ssl_certificate /etc/nginx/ssl/www.crt; ssl_certificate_key /etc/nginx/ssl/www.key; include /etc/nginx/snip.conf; } }\n",
			"listen 443 ssl;\n", "config_file_writable"},
		"inherited http-level key": {"http { include /etc/nginx/snip.conf; server { listen 443 ssl; ssl_certificate /etc/nginx/ssl/www.crt; } }\n",
			"ssl_certificate_key /etc/nginx/ssl/www.key;\n", "config_file_writable"},
		"root snippet included by the writable file at http level": {"http { include /etc/nginx/snip.conf; server { listen 443 ssl; } }\n",
			"include /etc/nginx/rootsnip.conf;\n", "config_file_writable"},
		"root server block activated by the writable file": {"http { include /etc/nginx/snip.conf; }\n",
			"include /etc/nginx/rootserver.conf;\n", "config_file_writable"},
		"unrelated writable file": {"http { include /etc/nginx/snip.conf; server { listen 443 ssl; ssl_certificate /etc/nginx/ssl/www.crt; ssl_certificate_key /etc/nginx/ssl/www.key; } }\n",
			"server_names_hash_bucket_size 64;\n", ""},
	} {
		t.Run(name, func(t *testing.T) {
			w := newNginxWorld(t)
			files := []confFile{{"/etc/nginx/nginx.conf", tc.main}, {"/etc/nginx/snip.conf", tc.snippet}}
			switch {
			case strings.Contains(tc.snippet, "rootsnip"): // root's own file, e.g. Debian's snippets/snakeoil.conf
				files = append(files, confFile{"/etc/nginx/rootsnip.conf", "ssl_certificate /etc/nginx/ssl/www.crt;\nssl_certificate_key /etc/nginx/ssl/www.key;\n"})
			case strings.Contains(tc.snippet, "rootserver"): // a site root wrote but did not enable
				files = append(files, confFile{"/etc/nginx/rootserver.conf", "server { listen 443 ssl; ssl_certificate /etc/nginx/ssl/www.crt; ssl_certificate_key /etc/nginx/ssl/www.key; }\n"})
			}
			w.setConf(files...)
			require.NoError(t, os.Chmod(w.f.host("/etc/nginx/snip.conf"), 0o646))
			_, m := w.f.run("nginx-dump")
			require.Equal(t, true, m["config_valid"], "%v", m)
			assert.Equal(t, []any{"/etc/nginx/snip.conf"}, m["writable"])
			assert.Equal(t, []string{"/etc/nginx/ssl/www.crt /etc/nginx/ssl/www.key " + tc.want}, pairsOf(m))
		})
	}
}

// Root only: a configuration file owned by another user (even 0644) makes its pairs unsupported,
// and one in a directory another user owns makes the dump untrusted.
func TestAttackUserOwnedConfigurationAsRoot(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root (chown)")
	}
	w := newNginxWorld(t)
	w.f.s.rootUID = 0
	require.NoError(t, os.Chown(w.f.host("/etc/nginx/conf.d/www.conf"), 1000, 1000))
	_, m := w.f.run("nginx-dump")
	assert.Equal(t, []any{"/etc/nginx/conf.d/www.conf"}, m["writable"])
	assert.Contains(t, pairsOf(m), "/etc/nginx/ssl/www.crt /etc/nginx/ssl/www.key config_file_writable")
	require.NoError(t, os.Chown(w.f.host("/etc/nginx/conf.d/www.conf"), 0, 0))
	require.NoError(t, os.Chown(w.f.host("/etc/nginx/conf.d"), 1000, 1000))
	_, m = w.f.run("nginx-dump")
	assert.Equal(t, false, m["config_valid"])
}

// S11: the answer never exceeds its budget; a distinct error replaces a truncated answer.
func TestNginxDumpOutputBudget(t *testing.T) {
	w := newNginxWorld(t)
	old := dumpBudget
	t.Cleanup(func() { dumpBudget = old })
	dumpBudget = len(w.leaf.FullchainPEM) - 1
	code, m := w.f.run("nginx-dump")
	assert.Equal(t, helperproto.ExitFailed, code)
	assert.Equal(t, helperproto.CodeOutputTooLarge, m["code"])
	dumpBudget = len(w.leaf.FullchainPEM) + 100
	code, m = w.f.run("nginx-dump")
	assert.Equal(t, helperproto.ExitFailed, code, "the certificates fit, the whole answer does not")
	assert.Equal(t, helperproto.CodeOutputTooLarge, m["code"])
	dumpBudget = old
	code, _ = w.f.run("nginx-dump")
	assert.Equal(t, 0, code)
	assert.Less(t, w.f.out.Len(), helperproto.NginxDumpOutput)
}

func TestNginxDumpTooManyFiles(t *testing.T) {
	w := newNginxWorld(t)
	var b strings.Builder
	b.WriteString("http {\n")
	for i := 0; i < helperproto.MaxNginxFiles/2+1; i++ {
		fmt.Fprintf(&b, "server { listen 443 ssl; ssl_certificate /etc/nginx/ssl/%d.crt; ssl_certificate_key /etc/nginx/ssl/%d.key; }\n", i, i)
	}
	b.WriteString("}\n")
	w.setConf(confFile{"/etc/nginx/nginx.conf", b.String()})
	_, m := w.f.run("nginx-dump")
	assert.Len(t, m["files"], helperproto.MaxNginxFiles)
	assert.Contains(t, m["warnings"], helperproto.WarnTooManyFiles)
}

func TestNginxNotFound(t *testing.T) {
	w := newNginxWorld(t)
	w.missing = true
	for _, sub := range []string{"nginx-dump", "nginx-test"} {
		code, m := w.f.run(sub)
		assert.Equal(t, helperproto.ExitPrecondition, code, sub)
		assert.Equal(t, helperproto.CodeNginxNotFound, m["code"], sub)
	}
}

func TestNginxRunFailure(t *testing.T) {
	w := newNginxWorld(t)
	w.f.s.runNginx = func(context.Context, ...string) ([]byte, []byte, error) {
		return nil, nil, errors.New("exec format error")
	}
	code, m := w.f.run("nginx-dump")
	assert.Equal(t, helperproto.ExitFailed, code)
	assert.Equal(t, helperproto.CodeIOError, m["code"])
}

// Requirement 10: the Nginx subcommands take no argument at all.
func TestNginxSubcommandsTakeNoArguments(t *testing.T) {
	w := newNginxWorld(t)
	for _, sub := range []string{"nginx-dump", "nginx-test"} {
		for _, extra := range [][]string{{"/etc/shadow"}, {"-c", "/tmp/evil.conf"}, {""}, {"-T"}} {
			code, m := w.f.run(append([]string{sub}, extra...)...)
			assert.Equal(t, helperproto.ExitRefused, code, "%s %v", sub, extra)
			assert.Equal(t, helperproto.CodeUsage, m["code"])
		}
	}
	assert.Empty(t, w.calls, "nginx never ran")
	assert.Empty(t, w.f.loggedLines())
}

func TestNginxTest(t *testing.T) {
	w := newNginxWorld(t)
	code, m := w.f.run("nginx-test")
	require.Equal(t, 0, code)
	assert.Equal(t, map[string]any{"ok": true, "valid": true, "error": ""}, m)
	assert.Equal(t, []string{"-t"}, w.calls)
	w.tFails = "nginx: [emerg] unknown directive \"sll_certificate\" in /etc/nginx/conf.d/www.conf:5\n"
	_, m = w.f.run("nginx-test")
	assert.Equal(t, false, m["valid"])
	assert.Equal(t, helperproto.ConfigErrSyntax, m["error"])
	assert.NotContains(t, w.f.out.String(), "www.conf")
	assert.Contains(t, w.f.loggedLines(), "nginx-test ")
}

func TestClassifyNginxError(t *testing.T) {
	for in, want := range map[string]string{
		"SSL_CTX_use_PrivateKey(...) failed (SSL: error:...:key values mismatch)":                            helperproto.ConfigErrKeyMismatch,
		`cannot load certificate "/x.crt": BIO_new_file() failed (SSL: error:...:No such file or directory)`: helperproto.ConfigErrFileMissing,
		`cannot load certificate "/x.crt": PEM_read_bio_X509_AUX() failed`:                                   helperproto.ConfigErrCertLoad,
		`cannot load certificate key "/x.key": PEM_read_bio_PrivateKey() failed`:                             helperproto.ConfigErrKeyLoad,
		`unexpected "}" in /etc/nginx/nginx.conf:9`:                                                          helperproto.ConfigErrSyntax,
	} {
		assert.Equal(t, want, classifyNginxError([]byte(in)), in)
	}
}

func TestParseNginxV(t *testing.T) {
	for in, want := range map[string][2]string{
		nginxV: {"1.22.1", "/etc/nginx/nginx.conf"},
		"nginx version: nginx/1.18.0 (Ubuntu)\nconfigure arguments: --conf-path=/etc/nginx/nginx.conf\n":  {"1.18.0", "/etc/nginx/nginx.conf"},
		"nginx version: openresty/1.21.4.1\nconfigure arguments: --conf-path=/usr/local/openresty/n.conf": {"1.21.4.1", "/usr/local/openresty/n.conf"},
		"nginx version: nginx/1.2<x>\nconfigure arguments: --conf-path=conf/nginx.conf\n":                 {"", ""},
		"nginx version: nginx/1.25.0\n": {"1.25.0", ""},
		"configure arguments: --conf-path=/etc/nginx/nginx.conf --conf-path=/etc/n2/nginx.conf\n": {"", "/etc/n2/nginx.conf"},
	} {
		v, c := parseNginxV([]byte(in))
		assert.Equal(t, want, [2]string{v, c}, in)
	}
}

func TestToWireCleansText(t *testing.T) {
	sv := nginxconf.Server{File: "/etc/nginx/a\x1b.conf", Line: 3, Names: []string{"a\x00b", strings.Repeat("é", 200)},
		Listens: []nginxconf.Listen{{Port: 80}, {Addr: "::1", Port: 443, SSL: true, DefaultServer: true}},
		Pairs:   []nginxconf.Pair{{CertRaw: "$ssl_" + strings.Repeat("x", 300) + "\n", Unsupported: nginxconf.ReasonVariable}}}
	w := toWire(sv)
	assert.Equal(t, "/etc/nginx/a.conf", w.File)
	assert.Equal(t, "ab", w.Names[0])
	assert.LessOrEqual(t, len(w.Names[1]), 253)
	assert.True(t, strings.HasSuffix(w.Names[1], "é"), "cut on a rune boundary")
	assert.Equal(t, []helperproto.NginxListen{{Addr: "::1", Port: 443, DefaultServer: true}}, w.Listens)
	assert.Equal(t, 200, len([]rune(w.Pairs[0].Raw)))
	assert.NotContains(t, w.Pairs[0].Raw, "\n")
	empty := toWire(nginxconf.Server{})
	assert.NotNil(t, empty.Names)
	assert.NotNil(t, empty.Listens)
	assert.NotNil(t, empty.Pairs)
}

// S8: nginx runs by absolute path with a fixed environment, "/" as its directory, umask 022, no
// stdin, bounded output and a bounded run time.
func TestRunProgram(t *testing.T) {
	for _, p := range []string{"/bin/sh", "/bin/sleep"} {
		if _, err := os.Stat(p); err != nil {
			t.Skip("needs /bin/sh and /bin/sleep")
		}
	}
	old := unix.Umask(0o077)
	defer unix.Umask(old)
	t.Setenv("ALICE_SECRET_ENV", "leak")
	out, _, err := runProgram(context.Background(), "/bin/sh", 1<<10, "-c", "umask; pwd; env | sort; cat")
	require.NoError(t, err)
	var lines []string
	for _, l := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if !strings.HasPrefix(l, "PWD=") && !strings.HasPrefix(l, "SHLVL=") && !strings.HasPrefix(l, "_=") && !strings.HasPrefix(l, "OLDPWD=") {
			lines = append(lines, l) // set by the shell itself
		}
	}
	assert.Equal(t, []string{"0022", "/", "LANG=C", "PATH=/usr/sbin:/usr/bin:/sbin:/bin"}, lines)
	assert.Equal(t, 0o077, unix.Umask(0o077), "the helper's own umask is back")

	out, errOut, err := runProgram(context.Background(), "/bin/sh", 100, "-c", "head -c 101 /dev/zero; head -c 70000 /dev/zero >&2")
	assert.ErrorIs(t, err, errTooLarge)
	assert.Nil(t, out)
	assert.LessOrEqual(t, len(errOut), stderrLimit)

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, _, err = runProgram(ctx, "/bin/sleep", 10, "30")
	assert.Error(t, err)
	assert.Less(t, time.Since(start), 5*time.Second)

	_, _, err = runProgram(context.Background(), filepath.Join(t.TempDir(), "nginx"), 10, "-T")
	assert.True(t, missingProgram(err), "%v", err)
}
