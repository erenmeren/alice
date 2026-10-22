//go:build windows

package main

import (
	"context"
	"encoding/binary"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
	"unicode/utf16"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"

	"alice/internal/providers/windows/winhelper"
	"alice/internal/providers/windows/winproto"
	"alice/internal/testutil/pki"
)

// The http.h layouts W0 measured on Windows Server 2022 and 2025 (amd64; arm64 is 64-bit with the same
// alignment rules).
func TestHTTPAPILayouts(t *testing.T) {
	assert.EqualValues(t, 80, unsafe.Sizeof(sslParam{}), "HTTP_SERVICE_CONFIG_SSL_PARAM")
	assert.EqualValues(t, 88, unsafe.Sizeof(sslSet{}), "HTTP_SERVICE_CONFIG_SSL_SET")
	assert.EqualValues(t, 216, unsafe.Sizeof(sslSniSet{}), "HTTP_SERVICE_CONFIG_SSL_SNI_SET")
	assert.EqualValues(t, 208, unsafe.Sizeof(sslCcsSet{}), "HTTP_SERVICE_CONFIG_SSL_CCS_SET")
	assert.EqualValues(t, 24, unsafe.Sizeof(sslQuery{}), "HTTP_SERVICE_CONFIG_SSL_QUERY")
	assert.EqualValues(t, 152, unsafe.Sizeof(sslSniQuery{}), "HTTP_SERVICE_CONFIG_SSL_SNI_QUERY")
	assert.EqualValues(t, 144, unsafe.Sizeof(sslCcsQuery{}), "HTTP_SERVICE_CONFIG_SSL_CCS_QUERY")
	assert.EqualValues(t, 128, unsafe.Sizeof(sockaddrStorage{}), "SOCKADDR_STORAGE")
}

// record is a synthetic output buffer laid out as HttpQueryServiceConfiguration writes one: the
// structure at the start, the data its pointers name after it.
type record struct {
	buf []uint64
	b   []byte
}

func newRecord() *record {
	buf := make([]uint64, 128)
	return &record{buf: buf, b: unsafe.Slice((*byte)(unsafe.Pointer(&buf[0])), len(buf)*8)}
}

func (r *record) addr(off int) uintptr { return uintptr(unsafe.Pointer(&r.b[0])) + uintptr(off) }

func (r *record) putString(off int, s string) uintptr {
	for i, c := range append(utf16.Encode([]rune(s)), 0) {
		binary.LittleEndian.PutUint16(r.b[off+2*i:], c)
	}
	return r.addr(off)
}

func putSockaddr4(b []byte, ip [4]byte, port uint16) {
	binary.LittleEndian.PutUint16(b[0:], windows.AF_INET)
	binary.BigEndian.PutUint16(b[2:], port)
	copy(b[4:8], ip[:])
}

func (r *record) param(p *sslParam, hashOff, storeOff int, store string) {
	for i := range 20 {
		r.b[hashOff+i] = byte(0xa0 + i)
	}
	p.SslHashLength, p.SslHash = 20, r.addr(hashOff)
	if store != "" {
		p.SslCertStoreName = r.putString(storeOff, store)
	}
	g, err := windows.GUIDFromString("{4DC3E181-E14B-4A21-B022-59FC669B0914}")
	if err != nil {
		panic(err)
	}
	p.AppID = g
	p.DefaultCertCheckMode, p.DefaultRevocationFreshnessTime, p.DefaultRevocationURLRetrievalTimeout = 1, 600, 7000
	p.DefaultFlags = 0x42
}

const testHash = "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3"

func TestDecodeRecords(t *testing.T) {
	// ipport 10.0.0.5:443, store My.
	r := newRecord()
	s := (*sslSet)(unsafe.Pointer(&r.b[0]))
	putSockaddr4(r.b[96:], [4]byte{10, 0, 0, 5}, 443)
	s.IPPort = r.addr(96)
	r.param(&s.Param, 128, 160, "My")
	assert.Equal(t, winproto.SSLBinding{Type: winproto.BindingIPPort, IP: "10.0.0.5", Port: 443, AppID: winproto.AppIDIIS,
		CertSHA1: testHash, Store: "My", Flags: 0x42, CertCheckMode: 1, RevocationFreshnessTime: 600, URLRetrievalTimeout: 7000},
		decodeRecord(configSSLCertInfo, r.b))

	// A pointer outside the record, or a string without its terminator, is a record without a type.
	s.IPPort = r.addr(len(r.b) + 64)
	assert.Empty(t, decodeRecord(configSSLCertInfo, r.b).Type)
	s.IPPort = r.addr(96)
	for i := 160; i < len(r.b); i += 2 {
		binary.LittleEndian.PutUint16(r.b[i:], 'x')
	}
	assert.Empty(t, decodeRecord(configSSLCertInfo, r.b).Type)
	assert.Empty(t, decodeRecord(configSSLCertInfo, r.b[:40]).Type, "a buffer shorter than the structure")

	// hostnameport www.example.com:8443 with a NULL store (http.sys's MY).
	r = newRecord()
	sni := (*sslSniSet)(unsafe.Pointer(&r.b[0]))
	putSockaddr4(storageBytes(&sni.IPPort), [4]byte{}, 8443)
	sni.Host = r.putString(232, "www.example.com")
	r.param(&sni.Param, 300, 0, "")
	b := decodeRecord(configSSLSniCertInfo, r.b)
	assert.Equal(t, winproto.BindingHostnamePort, b.Type)
	assert.Equal(t, "www.example.com", b.Host)
	assert.Equal(t, 8443, b.Port)
	assert.Empty(t, b.Store)
	assert.Equal(t, testHash, b.CertSHA1)

	// ccs on [::]:443 without a hash.
	r = newRecord()
	ccs := (*sslCcsSet)(unsafe.Pointer(&r.b[0]))
	la := storageBytes(&ccs.LocalAddress)
	binary.LittleEndian.PutUint16(la[0:], windows.AF_INET6)
	binary.BigEndian.PutUint16(la[2:], 443)
	ccs.Param.AppID = windows.GUID{Data1: 0x4dc3e181, Data2: 0xe14b, Data3: 0x4a21, Data4: [8]byte{0xb0, 0x22, 0x59, 0xfc, 0x66, 0x9b, 0x09, 0x14}}
	b = decodeRecord(configSSLCcsCertInfo, r.b)
	assert.Equal(t, winproto.SSLBinding{Type: winproto.BindingCCS, IP: "::", Port: 443, AppID: winproto.AppIDIIS}, b)
}

// netsh runs "netsh http ..." for a fixture (tests only).
func netsh(t *testing.T, args ...string) {
	t.Helper()
	out, err := exec.Command("netsh", append([]string{"http"}, args...)...).CombinedOutput()
	require.NoError(t, err, "netsh http %v: %s", args, out)
}

// addSSLCert adds an http.sys binding and deletes it when the test ends.
func addSSLCert(t *testing.T, key, thumb, appID string) {
	t.Helper()
	t.Cleanup(func() {
		if out, err := exec.Command("netsh", "http", "delete", "sslcert", key).CombinedOutput(); err != nil {
			t.Logf("cleanup of %s: %v %s", key, err, out)
		}
	})
	netsh(t, "add", "sslcert", key, "certhash="+thumb, "appid="+appID, "certstorename=MY")
}

func findBinding(list []winproto.SSLBinding, typ string, port int) (winproto.SSLBinding, bool) {
	for _, b := range list {
		if b.Type == typ && b.Port == port {
			return b, true
		}
	}
	return winproto.SSLBinding{}, false
}

func TestRealBindingsListAnSNIAndAnIPBinding(t *testing.T) {
	requireReal(t)
	now := time.Now()
	leaf := pki.SelfSigned("alice-w1.test", pki.RSA2048, now)
	thumb := importLeafWithKey(t, leaf)
	addSSLCert(t, "hostnameport=alice-w1.test:45301", thumb, winproto.AppIDIIS)
	addSSLCert(t, "ipport=0.0.0.0:45302", thumb, winproto.AppIDIIS)

	list, err := sslBindings()
	require.NoError(t, err)
	sni, ok := findBinding(list, winproto.BindingHostnamePort, 45301)
	require.True(t, ok, "the SNI binding is listed")
	assert.Equal(t, "alice-w1.test", sni.Host)
	assert.Equal(t, thumb, sni.CertSHA1)
	assert.True(t, sni.Store == "" || equalFoldASCII(sni.Store, "MY"), "store %q", sni.Store)
	assert.Equal(t, winproto.AppIDIIS, sni.AppID)
	ip, ok := findBinding(list, winproto.BindingIPPort, 45302)
	require.True(t, ok, "the IP binding is listed")
	assert.Equal(t, "0.0.0.0", ip.IP)
	assert.Equal(t, thumb, ip.CertSHA1)
	assert.Equal(t, winproto.AppIDIIS, ip.AppID)
	// The runner's own records (IIS Express, WinRM) are listed too; the helper never assumes an empty table.
	assert.Greater(t, len(list), 2)
}

func TestRealForeignBinding(t *testing.T) {
	requireReal(t)
	winrm := ""
	for id, name := range winproto.KnownApps {
		if name == "winrm" {
			winrm = id
		}
	}
	require.NotEmpty(t, winrm)
	leaf := pki.SelfSigned("alice-w1-foreign.test", pki.ECDSA256, time.Now())
	thumb := importLeafWithKey(t, leaf)
	addSSLCert(t, "ipport=0.0.0.0:45303", thumb, winrm)

	list, err := sslBindings()
	require.NoError(t, err)
	b, ok := findBinding(list, winproto.BindingIPPort, 45303)
	require.True(t, ok)
	assert.Equal(t, winrm, b.AppID)
	assert.Equal(t, thumb, b.CertSHA1)
}

// appcmd runs IIS's appcmd for a fixture (tests only).
func appcmd(t *testing.T, args ...string) {
	t.Helper()
	path := filepath.Join(os.Getenv("SystemRoot"), "system32", "inetsrv", "appcmd.exe")
	out, err := exec.Command(path, args...).CombinedOutput()
	require.NoError(t, err, "appcmd %v: %s", args, out)
}

func TestRealAppcmdSites(t *testing.T) {
	requireReal(t)
	t.Cleanup(func() {
		path := filepath.Join(os.Getenv("SystemRoot"), "system32", "inetsrv", "appcmd.exe")
		if out, err := exec.Command(path, "delete", "site", "alice-w1-site").CombinedOutput(); err != nil {
			t.Logf("cleanup of alice-w1-site: %v %s", err, out)
		}
	})
	appcmd(t, "add", "site", "/name:alice-w1-site", "/physicalPath:"+t.TempDir(), "/bindings:https/*:45304:")
	appcmd(t, "set", "site", "/site.name:alice-w1-site",
		"/+bindings.[protocol='https',bindingInformation='*:45301:alice-w1.test',sslFlags='1']")

	data, err := appcmdSites(context.Background())
	require.NoError(t, err)
	sites, err := winhelper.ParseAppcmdSites(data)
	require.NoError(t, err)
	var site *winproto.Site
	for i := range sites {
		if sites[i].Name == "alice-w1-site" {
			site = &sites[i]
		}
	}
	require.NotNil(t, site, "the site is listed")
	assert.Contains(t, site.Bindings, winproto.SiteBinding{Protocol: "https", Information: "*:45301:alice-w1.test", SSLFlags: 1})
	assert.Contains(t, site.Bindings, winproto.SiteBinding{Protocol: "https", Information: "*:45304:", SSLFlags: 0})
}

// equalFoldASCII compares two ASCII names without case.
func equalFoldASCII(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range len(a) {
		x, y := a[i], b[i]
		if 'A' <= x && x <= 'Z' {
			x += 'a' - 'A'
		}
		if 'A' <= y && y <= 'Z' {
			y += 'a' - 'A'
		}
		if x != y {
			return false
		}
	}
	return true
}
