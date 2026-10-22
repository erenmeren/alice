//go:build windows

package main

// The real write half (W2 Task 6): struct layouts on every Windows build, the portable form of the
// extended parameters, and, with ALICE_WIN_REAL=1 on the runners (Task 9), the facts F9 and F10, the
// state files, the helper lock and the Event Log. Fixtures follow W2 Ruling 22: ports 45330-45339, names
// prefixed alice-w2-, a private data directory under C:\ProgramData\Alice\helper-test-<random>, every
// cleanup registered before its fixture is made.

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"

	"alice/internal/providers/windows/winhelper"
	"alice/internal/providers/windows/winproto"
	"alice/internal/testutil/pki"
)

var _ winhelper.WriteHost = host{}

// TestRealStructSizes runs on every Windows build (no ALICE_WIN_REAL): the W0 layouts and the Ex
// layouts of http.h on 64-bit Windows (amd64 and arm64 share the alignment rules: 4-byte DWORD/ULONG/
// enum, 2-byte USHORT, 8-byte pointers and ULONGLONG, SOCKADDR_STORAGE 128 bytes 8-aligned).
func TestRealStructSizes(t *testing.T) {
	sizes := []struct {
		name string
		got  uintptr
		want uintptr
	}{
		// W0 (design §14.1).
		{"HTTP_SERVICE_CONFIG_SSL_PARAM", unsafe.Sizeof(sslParam{}), 80},
		{"HTTP_SERVICE_CONFIG_SSL_SET", unsafe.Sizeof(sslSet{}), 88},
		{"HTTP_SERVICE_CONFIG_SSL_SNI_SET", unsafe.Sizeof(sslSniSet{}), 216},
		{"HTTP_SERVICE_CONFIG_SSL_CCS_SET", unsafe.Sizeof(sslCcsSet{}), 208},
		{"HTTP_SERVICE_CONFIG_SSL_QUERY", unsafe.Sizeof(sslQuery{}), 24},
		{"HTTP_SERVICE_CONFIG_SSL_SNI_QUERY", unsafe.Sizeof(sslSniQuery{}), 152},
		{"HTTP_SERVICE_CONFIG_SSL_CCS_QUERY", unsafe.Sizeof(sslCcsQuery{}), 144},
		// HTTP2_WINDOW_SIZE_PARAM {DWORD} = 4.
		{"HTTP2_WINDOW_SIZE_PARAM", unsafe.Sizeof(http2WindowSizeParam{}), 4},
		// HTTP2_SETTINGS_LIMITS_PARAM {DWORD; DWORD} = 4 + 4 = 8.
		{"HTTP2_SETTINGS_LIMITS_PARAM", unsafe.Sizeof(http2SettingsLimits{}), 8},
		// HTTP_PERFORMANCE_PARAM {enum Type 4; ULONG BufferSize 4; PVOID Buffer 8} = 16.
		{"HTTP_PERFORMANCE_PARAM", unsafe.Sizeof(httpPerformanceParam{}), 16},
		// HTTP_TLS_RESTRICTIONS_PARAM {ULONG 4; pad 4; PVOID 8} = 16.
		{"HTTP_TLS_RESTRICTIONS_PARAM", unsafe.Sizeof(httpTLSRestrictions{}), 16},
		// HTTP_ERROR_HEADERS_PARAM {USHORT 2; USHORT 2; pad 4; PHTTP_UNKNOWN_HEADER 8} = 16.
		{"HTTP_ERROR_HEADERS_PARAM", unsafe.Sizeof(httpErrorHeaders{}), 16},
		// HTTP_TLS_SESSION_TICKET_KEYS_PARAM {ULONG 4; pad 4; PVOID 8} = 16.
		{"HTTP_TLS_SESSION_TICKET_KEYS_PARAM", unsafe.Sizeof(httpTLSSessionTicketKeys{}), 16},
		// HTTP_UNKNOWN_HEADER {USHORT 2; USHORT 2; pad 4; PCSTR 8; PCSTR 8} = 24.
		{"HTTP_UNKNOWN_HEADER", unsafe.Sizeof(httpUnknownHeader{}), 24},
		// HTTP_SERVICE_CONFIG_SSL_PARAM_EX {enum ParamType 4; pad 4; ULONGLONG Flags 8; union of the six
		// above, largest 16} = 32.
		{"HTTP_SERVICE_CONFIG_SSL_PARAM_EX", unsafe.Sizeof(sslParamEx{}), 32},
		// HTTP_SERVICE_CONFIG_SSL_SET_EX {HTTP_SERVICE_CONFIG_SSL_KEY_EX {SOCKADDR_STORAGE 128}; PARAM_EX 32}
		// = 160.
		{"HTTP_SERVICE_CONFIG_SSL_SET_EX", unsafe.Sizeof(sslSetEx{}), 160},
		// HTTP_SERVICE_CONFIG_SSL_SNI_SET_EX {SNI_KEY {SOCKADDR_STORAGE 128; PWSTR 8} 136; PARAM_EX 32} = 168.
		{"HTTP_SERVICE_CONFIG_SSL_SNI_SET_EX", unsafe.Sizeof(sslSniSetEx{}), 168},
		// HTTP_SERVICE_CONFIG_SSL_QUERY_EX {QUERY_TYPE 4; pad 4; KEY_EX 128 @8; DWORD dwToken @136; enum
		// ParamType @140} = 144.
		{"HTTP_SERVICE_CONFIG_SSL_QUERY_EX", unsafe.Sizeof(sslQueryEx{}), 144},
		// HTTP_SERVICE_CONFIG_SSL_SNI_QUERY_EX {QUERY_TYPE 4; pad 4; SNI_KEY 136 @8; DWORD dwToken @144; enum
		// ParamType @148} = 152.
		{"HTTP_SERVICE_CONFIG_SSL_SNI_QUERY_EX", unsafe.Sizeof(sslSniQueryEx{}), 152},
	}
	for _, s := range sizes {
		assert.Equal(t, s.want, s.got, s.name)
	}
	// The offsets the portable form relies on.
	assert.EqualValues(t, 8, unsafe.Offsetof(sslParamEx{}.Flags))
	assert.EqualValues(t, 16, unsafe.Offsetof(sslParamEx{}.Union))
	assert.EqualValues(t, 128, unsafe.Offsetof(sslSetEx{}.Param))
	assert.EqualValues(t, 136, unsafe.Offsetof(sslSniSetEx{}.Param))
	assert.EqualValues(t, 136, unsafe.Offsetof(sslQueryEx{}.Token))
	assert.EqualValues(t, 140, unsafe.Offsetof(sslQueryEx{}.ParamType))
	assert.EqualValues(t, 148, unsafe.Offsetof(sslSniQueryEx{}.ParamType))
	assert.EqualValues(t, 8, unsafe.Offsetof(httpPerformanceParam{}.Buffer))
	assert.EqualValues(t, 8, unsafe.Offsetof(httpErrorHeaders{}.Headers))
	assert.EqualValues(t, 8, unsafe.Offsetof(httpUnknownHeader{}.Name))
	assert.EqualValues(t, 16, unsafe.Offsetof(httpUnknownHeader{}.RawValue))
}

// exRecord is a synthetic Ex query output at a pretend address: PARAM_EX at off, data after it.
type exRecord struct {
	b    []byte
	base uint64
}

func (r exRecord) at(off int) uint64 { return r.base + uint64(off) } //nolint:gosec // G115: test offsets

func TestExParamPortableForm(t *testing.T) {
	const base, off = 0x7ff0_0000_1000, 128
	t.Run("window", func(t *testing.T) {
		r := exRecord{b: make([]byte, 160), base: base}
		binary.LittleEndian.PutUint32(r.b[off:], exHTTP2Window)
		binary.LittleEndian.PutUint64(r.b[off+8:], 0x5)
		binary.LittleEndian.PutUint32(r.b[off+16:], 1<<20)
		data, err := flattenEx(r.b, r.base, off)
		require.NoError(t, err)
		assert.Equal(t, r.b[off:off+paramExSize], data)
		placed, err := relocateEx(data, 0x1234_0000)
		require.NoError(t, err)
		assert.Equal(t, data, placed, "no pointers: placed as is")
	})
	t.Run("performance", func(t *testing.T) {
		r := exRecord{b: make([]byte, 256), base: base}
		binary.LittleEndian.PutUint32(r.b[off:], exHTTPPerformance)
		binary.LittleEndian.PutUint32(r.b[off+16:], 2)
		binary.LittleEndian.PutUint32(r.b[off+20:], 4)
		binary.LittleEndian.PutUint64(r.b[off+24:], r.at(200))
		copy(r.b[200:], []byte{1, 2, 3, 4})
		data, err := flattenEx(r.b, r.base, off)
		require.NoError(t, err)
		require.Len(t, data, 36)
		assert.EqualValues(t, 32, binary.LittleEndian.Uint64(data[24:]), "the offset of the buffer")
		assert.Equal(t, []byte{1, 2, 3, 4}, data[32:])
		placed, err := relocateEx(data, 0x1234_0000)
		require.NoError(t, err)
		assert.EqualValues(t, 0x1234_0000+32, binary.LittleEndian.Uint64(placed[24:]))
	})
	t.Run("error headers", func(t *testing.T) {
		r := exRecord{b: make([]byte, 512), base: base}
		binary.LittleEndian.PutUint32(r.b[off:], exErrorHeaders)
		binary.LittleEndian.PutUint16(r.b[off+16:], 503)
		binary.LittleEndian.PutUint16(r.b[off+18:], 2)
		binary.LittleEndian.PutUint64(r.b[off+24:], r.at(200))
		names := []string{"X-A", "Retry-After"}
		values := []string{"1", "120"}
		pos := 300
		for i := range 2 {
			h := 200 + i*unknownHeaderSize
			binary.LittleEndian.PutUint16(r.b[h:], uint16(len(names[i])))    //nolint:gosec // G115: short
			binary.LittleEndian.PutUint16(r.b[h+2:], uint16(len(values[i]))) //nolint:gosec // G115: short
			binary.LittleEndian.PutUint64(r.b[h+8:], r.at(pos))
			pos += copy(r.b[pos:], names[i])
			binary.LittleEndian.PutUint64(r.b[h+16:], r.at(pos))
			pos += copy(r.b[pos:], values[i])
		}
		data, err := flattenEx(r.b, r.base, off)
		require.NoError(t, err)
		const at = 0x2000_0000
		placed, err := relocateEx(data, at)
		require.NoError(t, err)
		// Read the placed structure back as the kernel would, from the pretend address at.
		read := func(p uint64, n int) string { return string(placed[p-at : p-at+uint64(n)]) } //nolint:gosec // G115: test
		first := binary.LittleEndian.Uint64(placed[24:])
		for i := range 2 {
			h := int(first-at) + i*unknownHeaderSize //nolint:gosec // G115: test
			assert.Equal(t, names[i], read(binary.LittleEndian.Uint64(placed[h+8:]), len(names[i])))
			assert.Equal(t, values[i], read(binary.LittleEndian.Uint64(placed[h+16:]), len(values[i])))
		}
		// A second round trip gives the same portable form.
		again, err := flattenEx(placed, at, 0)
		require.NoError(t, err)
		assert.Equal(t, data, again)
	})
	t.Run("refused", func(t *testing.T) {
		r := exRecord{b: make([]byte, 160), base: base}
		binary.LittleEndian.PutUint32(r.b[off:], exTLSSessionTicketKeys)
		binary.LittleEndian.PutUint64(r.b[off+24:], r.at(150))
		_, err := flattenEx(r.b, r.base, off)
		require.ErrorIs(t, err, errExUnsupported, "a reserved pointer cannot be written back")
		binary.LittleEndian.PutUint32(r.b[off:], exHTTPPerformance)
		binary.LittleEndian.PutUint32(r.b[off+20:], 64) // past the record
		_, err = flattenEx(r.b, r.base, off)
		require.ErrorIs(t, err, errBadValue)
		binary.LittleEndian.PutUint32(r.b[off:], 99)
		_, err = flattenEx(r.b, r.base, off)
		require.ErrorIs(t, err, errExUnsupported, "an unknown type")
		_, err = flattenEx(r.b, r.base, 140)
		require.ErrorIs(t, err, errBadValue, "the structure does not fit")
		bad := make([]byte, 40)
		binary.LittleEndian.PutUint32(bad, exHTTPPerformance)
		binary.LittleEndian.PutUint32(bad[20:], 16)
		binary.LittleEndian.PutUint64(bad[24:], 32) // 16 bytes at 32 run past 40
		_, err = relocateEx(bad, 0x1000)
		require.ErrorIs(t, err, errBadValue)
		_, err = relocateEx(bad[:16], 0x1000)
		require.ErrorIs(t, err, errBadValue)
	})
}

// newTestDataDir makes a private data directory owned by Administrators (as the setup script's) and
// removes it when the test ends.
func newTestDataDir(t *testing.T) string {
	t.Helper()
	b := make([]byte, 8)
	_, err := rand.Read(b)
	require.NoError(t, err)
	parent := `C:\ProgramData\Alice`
	dir := filepath.Join(parent, "helper-test-"+hex.EncodeToString(b))
	t.Cleanup(func() {
		if err := os.RemoveAll(dir); err != nil {
			t.Logf("cleanup of %s: %v", dir, err)
		}
		_ = os.Remove(parent) // only when empty: never another test's or the helper's own directory
	})
	require.NoError(t, os.MkdirAll(dir, 0o700))
	admins, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	require.NoError(t, err)
	require.NoError(t, windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION,
		admins, nil, nil, nil), "the test directory's owner")
	return dir
}

// addSSLCertOpts adds an http.sys record with netsh's options (dropping disabletls13 when this netsh
// does not know it) and deletes it when the test ends.
func addSSLCertOpts(t *testing.T, key, thumb string, opts ...string) {
	t.Helper()
	t.Cleanup(func() {
		if out, err := exec.Command("netsh", "http", "delete", "sslcert", key).CombinedOutput(); err != nil {
			t.Logf("cleanup of %s: %v %s", key, err, out)
		}
	})
	args := append([]string{"http", "add", "sslcert", key, "certhash=" + thumb, "appid=" + winproto.AppIDIIS,
		"certstorename=MY"}, opts...)
	out, err := exec.Command("netsh", args...).CombinedOutput()
	if err != nil {
		kept := []string{}
		for _, a := range args {
			if !strings.HasPrefix(a, "disabletls13=") {
				kept = append(kept, a)
			}
		}
		t.Logf("netsh %v: %v %s; retrying without disabletls13", args, err, out)
		out, err = exec.Command("netsh", kept...).CombinedOutput()
	}
	require.NoError(t, err, "netsh: %s", out)
}

// diffExceptHash names every field of two records that differs, the certificate hash aside.
func diffExceptHash(a, b winproto.SSLBinding) []string {
	a.CertSHA1, b.CertSHA1 = "", ""
	if len(a.Extended) == 0 {
		a.Extended = nil
	}
	if len(b.Extended) == 0 {
		b.Extended = nil
	}
	var diff []string
	va, vb := reflect.ValueOf(a), reflect.ValueOf(b)
	for i := range va.NumField() {
		if !reflect.DeepEqual(va.Field(i).Interface(), vb.Field(i).Interface()) {
			diff = append(diff, va.Type().Field(i).Name)
		}
	}
	return diff
}

// windowParam is an HTTP/2 receive window parameter in the portable form.
func windowParam(size uint32) winproto.ExtendedParam {
	data := make([]byte, paramExSize)
	binary.LittleEndian.PutUint32(data[0:], exHTTP2Window)
	binary.LittleEndian.PutUint32(data[16:], size)
	return winproto.ExtendedParam{Type: exHTTP2Window, Data: base64.StdEncoding.EncodeToString(data)}
}

// TestRealUpdateKeepsTheRecordAndExParams measures F9 and proves UpdateBinding keeps every setting.
func TestRealUpdateKeepsTheRecordAndExParams(t *testing.T) {
	requireReal(t)
	require.Equal(t, exRewrite, exStrategy, "the shipped strategy")
	now := time.Now()
	thumbA := importLeafWithKey(t, pki.SelfSigned("alice-w2-f9-a.test", pki.RSA2048, now))
	thumbB := importLeafWithKey(t, pki.SelfSigned("alice-w2-f9-b.test", pki.ECDSA256, now))
	h := newHost(winproto.DataDir)
	ctx := context.Background()
	for _, loc := range []winproto.Locator{
		{Type: winproto.BindingIPPort, IP: "0.0.0.0", Port: 45330, AppID: winproto.AppIDIIS},
		{Type: winproto.BindingHostnamePort, Host: "alice-w2-f9.test", Port: 45331, AppID: winproto.AppIDIIS},
	} {
		t.Run(loc.Type, func(t *testing.T) {
			netshKey := "ipport=0.0.0.0:45330"
			if loc.Type == winproto.BindingHostnamePort {
				netshKey = "hostnameport=alice-w2-f9.test:45331"
			}
			addSSLCertOpts(t, netshKey, thumbA, "clientcertnegotiation=enable", "verifyclientcertrevocation=disable",
				"disabletls13=enable")
			k, err := keyOf(loc.Type, loc.IP, loc.Host, loc.Port)
			require.NoError(t, err)

			// One extended parameter, set through the helper's own Ex write.
			want := windowParam(1 << 20)
			if err := withHTTP(func() error { return writeEx(k, want) }); err != nil {
				t.Errorf("F9: the Ex write of an HTTP/2 window failed: %v", err)
			}
			var detail []exResult
			require.NoError(t, withHTTP(func() error {
				var err error
				_, detail, err = readExtendedDetail(k)
				return err
			}))
			t.Logf("F9: Ex query answers per type: %+v", detail)

			before, found, err := h.Binding(ctx, loc)
			require.NoError(t, err)
			require.True(t, found, "the test record is read by its key")
			t.Logf("record read: %+v", before)
			assert.Equal(t, thumbA, before.CertSHA1)
			assert.NotZero(t, before.Flags&0x2, "NEGOTIATE_CLIENT_CERT read")
			if assert.Len(t, before.Extended, 1, "the Ex parameter set above is read back") {
				assert.Equal(t, want, before.Extended[0])
			}

			// F9: does a base update alone keep the extended parameters?
			moved := before
			moved.CertSHA1 = thumbB
			require.NoError(t, withHTTP(func() error { return updateBase(k, moved) }), "base-only update")
			afterBase, _, err := h.Binding(ctx, loc)
			require.NoError(t, err)
			assert.Equal(t, thumbB, afterBase.CertSHA1)
			if d := diffExceptHash(before, afterBase); len(d) == 0 {
				t.Logf("F9: Ex kept by base update (%s)", loc.Type)
			} else {
				t.Logf("F9: Ex reset by base update (%s): fields differing %v; read %+v", loc.Type, d, afterBase)
			}

			// The shipped strategy: back to A with everything, then to B; the read-back equals the
			// record before except the hash.
			t.Logf("strategy %q ran, %d Ex parameters rewritten after each base update", exStrategy, len(before.Extended))
			require.NoError(t, h.UpdateBinding(ctx, before))
			back, _, err := h.Binding(ctx, loc)
			require.NoError(t, err)
			assert.Equal(t, before, back, "the whole record restored")
			require.NoError(t, h.UpdateBinding(ctx, moved))
			after, _, err := h.Binding(ctx, loc)
			require.NoError(t, err)
			assert.Equal(t, thumbB, after.CertSHA1)
			assert.Empty(t, diffExceptHash(before, after), "every setting but the hash kept: %+v", after)
		})
	}
	// An absent record: not found, and an update of it is ErrBindingNotFound.
	gone := winproto.Locator{Type: winproto.BindingIPPort, IP: "0.0.0.0", Port: 45339, AppID: winproto.AppIDIIS}
	_, found, err := h.Binding(ctx, gone)
	require.NoError(t, err)
	assert.False(t, found)
	err = h.UpdateBinding(ctx, winproto.SSLBinding{Type: winproto.BindingIPPort, IP: "0.0.0.0", Port: 45339,
		AppID: winproto.AppIDIIS, CertSHA1: thumbA, Store: "MY"})
	assert.ErrorIs(t, err, winhelper.ErrBindingNotFound)
}

var procNCryptExportKey = modncrypt.NewProc("NCryptExportKey")

// exportRefused reports whether a plaintext PKCS #8 export of the certificate's key is refused.
func exportRefused(t *testing.T, store, thumb string) bool {
	t.Helper()
	hash, err := hex.DecodeString(thumb)
	require.NoError(t, err)
	st, err := openStore(store)
	require.NoError(t, err)
	defer func() { _ = windows.CertCloseStore(st, 0) }()
	blob := windows.CryptHashBlob{Size: uint32(len(hash)), Data: &hash[0]} //nolint:gosec // G115: 20
	ctx, err := windows.CertFindCertificateInStore(st, encodingAny, 0, windows.CERT_FIND_SHA1_HASH, unsafe.Pointer(&blob), nil)
	require.NoError(t, err)
	defer func() { _ = windows.CertFreeCertificateContext(ctx) }()
	key, free, err := acquireKey(ctx)
	require.NoError(t, err, "the stored copy reaches its key")
	if free {
		defer func() { _, _, _ = procNCryptFreeObject.Call(uintptr(key)) }()
	}
	blobType, err := windows.UTF16PtrFromString("PKCS8_PRIVATEKEY")
	require.NoError(t, err)
	var n uint32
	r, _, _ := procNCryptExportKey.Call(uintptr(key), 0, uintptr(unsafe.Pointer(blobType)), 0, 0, 0,
		uintptr(unsafe.Pointer(&n)), 0)
	t.Logf("NCryptExportKey: 0x%08x", uint32(r)) //nolint:gosec // G115: a status
	return r != 0
}

// TestRealImportPFX measures F10: the PFX route's key link survives the add to the target store.
func TestRealImportPFX(t *testing.T) {
	requireReal(t)
	now := time.Now()
	h := newHost(winproto.DataDir)
	ctx := context.Background()
	ca := pki.NewCA("alice-w2-f10", pki.ECDSA256, now)
	leaf := ca.Issue(pki.Opts{CommonName: "alice-w2-f10.test", SANs: []string{"alice-w2-f10.test"}, KeyType: pki.ECDSA256}, now)
	thumb := thumbprint(leaf.Cert)
	inter := thumbprint(ca.Intermediate)

	t.Cleanup(func() { removeCertificate(t, "CA", inter, false) })
	added, err := h.AddIntermediate(ctx, ca.Intermediate.Raw)
	require.NoError(t, err)
	assert.True(t, added, "a new intermediate is added to CA")
	added, err = h.AddIntermediate(ctx, ca.Intermediate.Raw)
	require.NoError(t, err)
	assert.False(t, added, "an intermediate in CA is never replaced")

	pkcs8, err := x509.MarshalPKCS8PrivateKey(leaf.Key)
	require.NoError(t, err)
	password := winhelper.NewPFXPassword()
	pfx, err := winhelper.BuildPFX(leaf.Cert.Raw, pkcs8, password)
	require.NoError(t, err)
	t.Cleanup(func() { removeCertificate(t, "My", thumb, true) })
	sha, err := h.ImportPFX(ctx, "My", pfx, password, "alice-w2-f10 first")
	require.NoError(t, err, "F10: the PFX import")
	assert.Equal(t, thumb, sha)

	c, found, err := h.Certificate(ctx, "My", thumb)
	require.NoError(t, err)
	require.True(t, found)
	t.Logf("imported: provider %q exportable %v has_key %v problem %q chain %d", c.KeyProvider, c.KeyExportable,
		c.HasKey, c.KeyProblem, len(c.Chain))
	assert.True(t, c.HasKey)
	assert.Empty(t, c.KeyProblem)
	assert.Equal(t, "Microsoft Software Key Storage Provider", c.KeyProvider)
	assert.False(t, c.KeyExportable)
	assert.Equal(t, "alice-w2-f10 first", c.FriendlyName)
	assert.Len(t, c.Chain, 1, "the intermediate in CA builds the chain")
	assert.True(t, exportRefused(t, "My", thumb), "NCryptExportKey refuses the key")

	// The binding update with the imported hash: no 1312.
	other := importLeafWithKey(t, pki.SelfSigned("alice-w2-f10-a.test", pki.RSA2048, now))
	addSSLCertOpts(t, "ipport=0.0.0.0:45332", other)
	loc := winproto.Locator{Type: winproto.BindingIPPort, IP: "0.0.0.0", Port: 45332, AppID: winproto.AppIDIIS}
	b, found, err := h.Binding(ctx, loc)
	require.NoError(t, err)
	require.True(t, found)
	b.CertSHA1 = thumb
	err = h.UpdateBinding(ctx, b)
	if errors.Is(err, winhelper.ErrKeyUnusable) {
		t.Errorf("F10: http.sys refused the imported certificate (1312): the key link did not survive the add")
	} else {
		require.NoError(t, err)
		t.Logf("F10: the PFX route into a memory store, then CERT_STORE_ADD_NEW into My, keeps the key link: bound without 1312")
	}
	back, _, err := h.Binding(ctx, loc)
	require.NoError(t, err)
	assert.Equal(t, thumb, back.CertSHA1)

	// A second import of the same certificate reports the existing copy and leaves it as it was.
	password2 := winhelper.NewPFXPassword()
	pfx2, err := winhelper.BuildPFX(leaf.Cert.Raw, pkcs8, password2)
	require.NoError(t, err)
	sha, err = h.ImportPFX(ctx, "My", pfx2, password2, "alice-w2-f10 second")
	require.NoError(t, err)
	assert.Equal(t, thumb, sha, "the existing copy")
	c, _, err = h.Certificate(ctx, "My", thumb)
	require.NoError(t, err)
	assert.Equal(t, "alice-w2-f10 first", c.FriendlyName, "the existing copy is not renamed")
	assert.True(t, c.HasKey)
	assert.Empty(t, c.KeyProblem, "the existing copy keeps its key")

	_, err = h.ImportPFX(ctx, "My", pfx2[:len(pfx2)/2], password2, "x")
	assert.Error(t, err, "a cut PFX")
	_, err = h.ImportPFX(ctx, "alice-w2-no-such-store", pfx2, password2, "x")
	assert.ErrorIs(t, err, winhelper.ErrStore)
}

const lockDirEnv = "ALICE_W2_LOCK_DIR"

// TestRealStateFilesLockHolder is the child process of TestRealStateFiles: it holds the helper lock
// of the directory in ALICE_W2_LOCK_DIR until its standard input closes. Without the variable it does
// nothing (and passes).
func TestRealStateFilesLockHolder(t *testing.T) {
	dir := os.Getenv(lockDirEnv)
	if dir == "" {
		return
	}
	release, err := newHost(dir).Lock(context.Background())
	if err != nil {
		t.Fatalf("lock: %v", err)
	}
	defer release()
	_, _ = os.Stdout.WriteString("locked\n")
	_, _ = io.Copy(io.Discard, os.Stdin)
}

func TestRealStateFiles(t *testing.T) {
	requireReal(t)
	dir := newTestDataDir(t)
	h := newHost(dir)
	require.NoError(t, h.DataDirSafe())

	_, found, err := h.ReadState("journal/aaaa.json")
	require.NoError(t, err)
	assert.False(t, found)
	require.NoError(t, h.WriteState("journal/aaaa.json", []byte(`{"a":1}`)))
	require.NoError(t, h.WriteState("journal/aaaa.json", []byte(`{"a":2}`)), "replaced")
	data, found, err := h.ReadState("journal/aaaa.json")
	require.NoError(t, err)
	assert.True(t, found)
	assert.Equal(t, `{"a":2}`, string(data))
	require.NoError(t, h.WriteState("imports.json", []byte(`{}`)))
	_, err = os.Stat(filepath.Join(dir, "journal", "aaaa.json.tmp"))
	assert.ErrorIs(t, err, os.ErrNotExist, "no temporary file left")
	for _, bad := range []string{"../x.json", `journal\x.json`, "journal/../x", "other/x.json", "", "a/b/c"} {
		_, _, err := h.ReadState(bad)
		assert.Error(t, err, bad)
		assert.Error(t, h.WriteState(bad, nil), bad)
	}
	// A directory where a state file should be is not read.
	require.NoError(t, os.Mkdir(filepath.Join(dir, "bindings", "dir.json"), 0o700))
	_, _, err = h.ReadState("bindings/dir.json")
	assert.Error(t, err)

	// A reparse point planted as journal makes the directory untrusted.
	planted := newTestDataDir(t)
	link := filepath.Join(planted, "journal")
	t.Cleanup(func() { _ = os.Remove(link) }) // the junction only, before the directory
	out, err := exec.Command("cmd", "/c", "mklink", "/J", link, t.TempDir()).CombinedOutput()
	require.NoError(t, err, "mklink: %s", out)
	assert.ErrorIs(t, newHost(planted).DataDirSafe(), winhelper.ErrJournal)
	assert.ErrorIs(t, newHost(filepath.Join(planted, "missing")).DataDirSafe(), winhelper.ErrJournal)

	// A second process holding the lock: BUSY after the (lowered) wait, LockHeld true.
	assert.False(t, h.LockHeld())
	saved := lockWait
	lockWait = 600 * time.Millisecond
	t.Cleanup(func() { lockWait = saved })
	child := exec.Command(os.Args[0], "-test.run=^TestRealStateFilesLockHolder$", "-test.count=1")
	child.Env = append(os.Environ(), lockDirEnv+"="+dir)
	stdin, err := child.StdinPipe()
	require.NoError(t, err)
	stdout, err := child.StdoutPipe()
	require.NoError(t, err)
	require.NoError(t, child.Start())
	t.Cleanup(func() { _ = stdin.Close(); _ = child.Wait() })
	locked := make(chan bool, 1)
	go func() {
		s := bufio.NewScanner(stdout)
		for s.Scan() {
			if s.Text() == "locked" {
				locked <- true
				_, _ = io.Copy(io.Discard, stdout)
				return
			}
		}
		locked <- false
	}()
	select {
	case ok := <-locked:
		require.True(t, ok, "the child took the lock")
	case <-time.After(60 * time.Second):
		t.Fatal("the child did not take the lock")
	}
	assert.True(t, h.LockHeld(), "another process holds the lock")
	start := time.Now()
	_, err = h.Lock(context.Background())
	assert.ErrorIs(t, err, winhelper.ErrBusy)
	assert.GreaterOrEqual(t, time.Since(start), 500*time.Millisecond, "it waited")
	require.NoError(t, stdin.Close())
	require.NoError(t, child.Wait(), "the child released the lock and passed")
	assert.False(t, h.LockHeld())
	release, err := h.Lock(context.Background())
	require.NoError(t, err)
	release()
	release() // idempotent
}

func TestRealEvent(t *testing.T) {
	requireReal(t)
	created := false
	t.Cleanup(func() {
		if created {
			if _, err := runPowershell(nil, `Remove-EventLog -Source 'Alice Helper'`); err != nil {
				t.Logf("cleanup of the event source: %v", err)
			}
		}
	})
	out := powershell(t, `if ([System.Diagnostics.EventLog]::SourceExists('Alice Helper')) { 'exists' } `+
		`else { New-EventLog -LogName Application -Source 'Alice Helper'; 'created' }`)
	created = strings.TrimSpace(string(out)) == "created"
	b := make([]byte, 8)
	_, err := rand.Read(b)
	require.NoError(t, err)
	marker := "alice-w2-event " + hex.EncodeToString(b)
	newHost(winproto.DataDir).Event(1001, marker)
	script := `$e = Get-WinEvent -FilterHashtable @{LogName='Application'; ProviderName='Alice Helper'; Id=1001} ` +
		`-MaxEvents 50 -ErrorAction SilentlyContinue | Where-Object { $_.Properties.Count -gt 0 -and ` +
		`$_.Properties[0].Value -eq $env:ALICE_W2_MARKER }; if ($e) { 'found' } else { 'missing' }`
	for range 20 {
		if strings.TrimSpace(string(powershellEnv(t, map[string]string{"ALICE_W2_MARKER": marker}, script))) == "found" {
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatalf("event 1001 with %q not found in the Application log", marker)
}
