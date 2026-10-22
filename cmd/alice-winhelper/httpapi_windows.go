//go:build windows

package main

// A hand-written binding of the HTTP Server API configuration reads (httpapi.dll), design 2026-10-21 §7:
// HttpInitialize, HttpQueryServiceConfiguration and HttpTerminate (the record reads by key, the extended
// parameters and the update are in httpapi_update_windows.go).
// The layouts are the C structs of http.h on 64-bit Windows (amd64 and arm64), with every pointer field
// as a uintptr so that no Go pointer is ever made from what the kernel wrote; W0 (design §14 F2)
// measured their sizes on Windows Server 2022 and 2025 (httpapi_windows_test.go asserts them):
//
//	https://learn.microsoft.com/en-us/windows/win32/api/http/nf-http-httpqueryserviceconfiguration
//	https://learn.microsoft.com/en-us/windows/win32/api/http/ns-http-http_service_config_ssl_param
//	https://learn.microsoft.com/en-us/windows/win32/api/http/ns-http-http_service_config_ssl_set
//	https://learn.microsoft.com/en-us/windows/win32/api/http/ns-http-http_service_config_ssl_sni_set
//	https://learn.microsoft.com/en-us/windows/win32/api/http/ns-http-http_service_config_ssl_ccs_set
//	https://learn.microsoft.com/en-us/windows/win32/api/http/ns-http-http_service_config_ssl_query
//
// Every call returns its error as the ULONG result, never through GetLastError (W0).

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"net/netip"
	"syscall"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"

	"alice/internal/providers/windows/winproto"
)

var (
	modhttpapi                        = windows.NewLazySystemDLL("httpapi.dll")
	procHttpInitialize                = modhttpapi.NewProc("HttpInitialize")
	procHttpTerminate                 = modhttpapi.NewProc("HttpTerminate")
	procHttpQueryServiceConfiguration = modhttpapi.NewProc("HttpQueryServiceConfiguration")
)

const (
	// httpapiVersion2 is HTTPAPI_VERSION_2 {2, 0} passed by value: two USHORTs in one register, the
	// major version in the low half.
	httpapiVersion2      = 2
	httpInitializeConfig = 0x2 // HTTP_INITIALIZE_CONFIG

	// HTTP_SERVICE_CONFIG_ID
	configSSLCertInfo    = 1
	configSSLSniCertInfo = 5
	configSSLCcsCertInfo = 6

	queryNext = 1 // HttpServiceConfigQueryNext

	// maxRecordBytes bounds one record's output buffer: the structure, its address, hash and strings.
	maxRecordBytes = 64 << 10
	// maxGrow bounds the re-sized retries of one record (it may grow between the calls).
	maxGrow = 4
	// maxConfigString bounds a string of a record, in UTF-16 units.
	maxConfigString = 1024
	// maxHashBytes bounds the certificate hash of a record (SHA-1 is 20).
	maxHashBytes = 64
)

// sockaddrStorage is SOCKADDR_STORAGE: 128 bytes, 8-byte aligned.
type sockaddrStorage [16]uint64

// sslParam is HTTP_SERVICE_CONFIG_SSL_PARAM (80 bytes).
type sslParam struct {
	SslHashLength                        uint32
	SslHash                              uintptr // PVOID
	AppID                                windows.GUID
	SslCertStoreName                     uintptr // PWSTR
	DefaultCertCheckMode                 uint32
	DefaultRevocationFreshnessTime       uint32
	DefaultRevocationURLRetrievalTimeout uint32
	DefaultSslCtlIdentifier              uintptr // PWSTR
	DefaultSslCtlStoreName               uintptr // PWSTR
	DefaultFlags                         uint32
}

// sslSet is HTTP_SERVICE_CONFIG_SSL_SET: HTTP_SERVICE_CONFIG_SSL_KEY {PSOCKADDR pIpPort} and the
// parameters (88 bytes).
type sslSet struct {
	IPPort uintptr // PSOCKADDR
	Param  sslParam
}

// sslSniSet is HTTP_SERVICE_CONFIG_SSL_SNI_SET: HTTP_SERVICE_CONFIG_SSL_SNI_KEY {SOCKADDR_STORAGE
// IpPort; PWSTR Host} and the parameters (216 bytes).
type sslSniSet struct {
	IPPort sockaddrStorage
	Host   uintptr // PWSTR
	Param  sslParam
}

// sslCcsSet is HTTP_SERVICE_CONFIG_SSL_CCS_SET: HTTP_SERVICE_CONFIG_SSL_CCS_KEY {SOCKADDR_STORAGE
// LocalAddress} and the parameters (208 bytes).
type sslCcsSet struct {
	LocalAddress sockaddrStorage
	Param        sslParam
}

// sslQuery is HTTP_SERVICE_CONFIG_SSL_QUERY (24 bytes).
type sslQuery struct {
	QueryDesc uint32
	IPPort    uintptr // PSOCKADDR
	Token     uint32
}

// sslSniQuery is HTTP_SERVICE_CONFIG_SSL_SNI_QUERY (152 bytes).
type sslSniQuery struct {
	QueryDesc uint32
	IPPort    sockaddrStorage
	Host      uintptr // PWSTR
	Token     uint32
}

// sslCcsQuery is HTTP_SERVICE_CONFIG_SSL_CCS_QUERY (144 bytes).
type sslCcsQuery struct {
	QueryDesc    uint32
	LocalAddress sockaddrStorage
	Token        uint32
}

var errHTTPAPI = errors.New("an http.sys configuration call failed")

// ulongResult turns a ULONG result into an error (nil for NO_ERROR).
func ulongResult(r uintptr) error {
	if r != 0 {
		return syscall.Errno(r)
	}
	return nil
}

// sslBindings lists every http.sys SSL record: the ipport, hostnameport (SNI) and ccs tables, each
// read with HttpServiceConfigQueryNext and dwToken 0, 1, 2, ... until ERROR_NO_MORE_ITEMS, at most
// MaxBindings+1 records per table (winhelper cuts the list at MaxBindings and marks it truncated). A
// record that cannot be decoded is returned without a type, so winhelper drops it and marks the dump
// truncated rather than reporting the binding as gone. The dump carries no extended parameters (W2
// Task 6 ruling after runner run 1): iis-deploy reads them live by the record's key, and reading them
// for every record dropped readable bindings from discovery on both images.
func sslBindings() ([]winproto.SSLBinding, error) {
	out := []winproto.SSLBinding{}
	err := withHTTP(func() error {
		for _, id := range []uint32{configSSLCertInfo, configSSLSniCertInfo, configSSLCcsCertInfo} {
			for token := uint32(0); token <= winproto.MaxBindings; token++ {
				rec, err := queryRecord(id, token)
				if errors.Is(err, windows.ERROR_NO_MORE_ITEMS) {
					break
				}
				if err != nil {
					return err
				}
				out = append(out, decodeRecord(id, rec))
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// queryRecord reads record token of table id (QueryNext).
func queryRecord(id, token uint32) ([]byte, error) {
	// The query structures differ only in their key, which QueryNext does not read.
	var in unsafe.Pointer
	var inLen uintptr
	switch id {
	case configSSLCertInfo:
		q := &sslQuery{QueryDesc: queryNext, Token: token}
		in, inLen = unsafe.Pointer(q), unsafe.Sizeof(*q)
	case configSSLSniCertInfo:
		q := &sslSniQuery{QueryDesc: queryNext, Token: token}
		in, inLen = unsafe.Pointer(q), unsafe.Sizeof(*q)
	default:
		q := &sslCcsQuery{QueryDesc: queryNext, Token: token}
		in, inLen = unsafe.Pointer(q), unsafe.Sizeof(*q)
	}
	return queryConfig(id, in, inLen)
}

// queryConfig runs one HttpQueryServiceConfiguration of table id with the query structure in, into a
// buffer sized by a first call without one. The buffer is a []uint64, so the structure at its start is
// 8-byte aligned; it holds no Go pointer.
func queryConfig(id uint32, in unsafe.Pointer, inLen uintptr) ([]byte, error) {
	var need uint32
	// unsafe: in and &need are passed for the duration of the call (LazyProc.Call keeps them alive).
	r, _, _ := procHttpQueryServiceConfiguration.Call(0, uintptr(id), uintptr(in), inLen, 0, 0,
		uintptr(unsafe.Pointer(&need)), 0)
	err := ulongResult(r)
	for range maxGrow {
		if err == nil {
			return nil, errHTTPAPI // a record cannot fit an empty buffer
		}
		if !errors.Is(err, windows.ERROR_INSUFFICIENT_BUFFER) {
			return nil, err
		}
		if need == 0 || need > maxRecordBytes {
			return nil, errHTTPAPI
		}
		size := need
		buf := make([]uint64, (size+7)/8)
		// unsafe: the output buffer is buf, of size bytes, alive for the call.
		r, _, _ = procHttpQueryServiceConfiguration.Call(0, uintptr(id), uintptr(in), inLen,
			uintptr(unsafe.Pointer(&buf[0])), uintptr(size), uintptr(unsafe.Pointer(&need)), 0)
		if err = ulongResult(r); err == nil {
			// unsafe: a byte view of buf's own memory, size bytes long.
			return unsafe.Slice((*byte)(unsafe.Pointer(&buf[0])), size), nil
		}
	}
	return nil, errHTTPAPI
}

// recordBase is the address of a record buffer's first byte, which the pointers inside the record are
// compared with (never converted back).
func recordBase(rec []byte) uintptr { return uintptr(unsafe.Pointer(&rec[0])) }

// span returns rec[off:off+n] for a pointer p into rec; false when p is null or the n bytes are not
// all inside rec.
func span(rec []byte, p uintptr, n int) ([]byte, bool) {
	base := recordBase(rec)
	if p == 0 || n < 0 || p < base || p-base > uintptr(len(rec)) || uintptr(n) > uintptr(len(rec))-(p-base) {
		return nil, false
	}
	off := int(p - base) //nolint:gosec // G115: bounded by len(rec) above
	return rec[off : off+n], true
}

// stringAt reads the NUL-terminated UTF-16 string p points to inside rec; "" for a null pointer,
// false when it is not inside rec, misaligned, unterminated or longer than maxConfigString.
func stringAt(rec []byte, p uintptr) (string, bool) {
	if p == 0 {
		return "", true
	}
	base := recordBase(rec)
	if p < base || p-base >= uintptr(len(rec)) || (p-base)%2 != 0 {
		return "", false
	}
	rest := rec[p-base:]
	u := make([]uint16, 0, 64)
	for i := 0; i+1 < len(rest); i += 2 {
		c := binary.LittleEndian.Uint16(rest[i:])
		if c == 0 {
			return string(utf16.Decode(u)), true
		}
		if len(u) == maxConfigString {
			return "", false
		}
		u = append(u, c)
	}
	return "", false
}

// sockaddr decodes a SOCKADDR_IN or SOCKADDR_IN6 (port in network byte order).
func sockaddr(b []byte) (netip.Addr, int, bool) {
	if len(b) < 16 {
		return netip.Addr{}, 0, false
	}
	port := int(binary.BigEndian.Uint16(b[2:4]))
	switch binary.LittleEndian.Uint16(b[0:2]) {
	case windows.AF_INET:
		return netip.AddrFrom4([4]byte(b[4:8])), port, true
	case windows.AF_INET6:
		if len(b) < 28 {
			return netip.Addr{}, 0, false
		}
		return netip.AddrFrom16([16]byte(b[8:24])), port, true
	}
	return netip.Addr{}, 0, false
}

// storageBytes is a byte view of a SOCKADDR_STORAGE inside a record.
func storageBytes(s *sockaddrStorage) []byte {
	// unsafe: s points into a record buffer; the view covers exactly its 128 bytes.
	return unsafe.Slice((*byte)(unsafe.Pointer(s)), unsafe.Sizeof(*s))
}

// decodeRecord turns one record of table id into an SSLBinding; a record that does not decode is a
// binding without a type.
func decodeRecord(id uint32, rec []byte) winproto.SSLBinding {
	var b winproto.SSLBinding
	var param *sslParam
	// unsafe: each overlay is taken only when rec holds the whole structure; the structures hold no Go
	// pointers, and rec is 8-byte aligned (queryRecord).
	switch id {
	case configSSLCertInfo:
		if len(rec) < int(unsafe.Sizeof(sslSet{})) {
			return winproto.SSLBinding{}
		}
		s := (*sslSet)(unsafe.Pointer(&rec[0]))
		addr, ok := span(rec, s.IPPort, 16)
		if !ok {
			return winproto.SSLBinding{}
		}
		if full, ok := span(rec, s.IPPort, 28); ok {
			addr = full
		}
		ip, port, ok := sockaddr(addr)
		if !ok {
			return winproto.SSLBinding{}
		}
		b = winproto.SSLBinding{Type: winproto.BindingIPPort, IP: ip.String(), Port: port}
		param = &s.Param
	case configSSLSniCertInfo:
		if len(rec) < int(unsafe.Sizeof(sslSniSet{})) {
			return winproto.SSLBinding{}
		}
		s := (*sslSniSet)(unsafe.Pointer(&rec[0]))
		_, port, ok := sockaddr(storageBytes(&s.IPPort))
		if !ok {
			return winproto.SSLBinding{}
		}
		host, ok := stringAt(rec, s.Host)
		if !ok {
			return winproto.SSLBinding{}
		}
		b = winproto.SSLBinding{Type: winproto.BindingHostnamePort, Host: host, Port: port}
		param = &s.Param
	case configSSLCcsCertInfo:
		if len(rec) < int(unsafe.Sizeof(sslCcsSet{})) {
			return winproto.SSLBinding{}
		}
		s := (*sslCcsSet)(unsafe.Pointer(&rec[0]))
		ip, port, ok := sockaddr(storageBytes(&s.LocalAddress))
		if !ok {
			return winproto.SSLBinding{}
		}
		b = winproto.SSLBinding{Type: winproto.BindingCCS, IP: ip.String(), Port: port}
		param = &s.Param
	default:
		return winproto.SSLBinding{}
	}
	if !decodeParam(rec, param, &b) {
		return winproto.SSLBinding{}
	}
	return b
}

// decodeParam copies HTTP_SERVICE_CONFIG_SSL_PARAM into b: the hash as lower-case hex, the store
// name as http.sys holds it ("" for NULL: winhelper maps it to MY, W0 F2), the application id in
// winproto's canonical form, and every other setting W2 must preserve.
func decodeParam(rec []byte, p *sslParam, b *winproto.SSLBinding) bool {
	if p.SslHashLength > 0 {
		if p.SslHashLength > maxHashBytes {
			return false
		}
		h, ok := span(rec, p.SslHash, int(p.SslHashLength))
		if !ok {
			return false
		}
		b.CertSHA1 = hex.EncodeToString(h)
	}
	var ok bool
	if b.Store, ok = stringAt(rec, p.SslCertStoreName); !ok {
		return false
	}
	if b.CTLIdentifier, ok = stringAt(rec, p.DefaultSslCtlIdentifier); !ok {
		return false
	}
	if b.CTLStore, ok = stringAt(rec, p.DefaultSslCtlStoreName); !ok {
		return false
	}
	if b.AppID, ok = winproto.CanonicalAppID(p.AppID.String()); !ok {
		return false
	}
	b.CertCheckMode = p.DefaultCertCheckMode
	b.RevocationFreshnessTime = p.DefaultRevocationFreshnessTime
	b.URLRetrievalTimeout = p.DefaultRevocationURLRetrievalTimeout
	b.Flags = p.DefaultFlags
	return true
}
