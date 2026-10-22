//go:build windows

package main

// The write half of the httpapi.dll binding (W2, design 2026-10-21 §6.3 step 7): one record read by
// its key (base and extended parameters), and HttpUpdateServiceConfiguration of the whole record.
//
//	https://learn.microsoft.com/en-us/windows/win32/api/http/nf-http-httpupdateserviceconfiguration
//	https://learn.microsoft.com/en-us/windows/win32/api/http/nf-http-httpsetserviceconfiguration
//	https://learn.microsoft.com/en-us/windows/win32/api/http/ns-http-http_service_config_ssl_set_ex
//	https://learn.microsoft.com/en-us/windows/win32/api/http/ns-http-http_service_config_ssl_sni_set_ex
//	https://learn.microsoft.com/en-us/windows/win32/api/http/ns-http-http_service_config_ssl_query_ex
//	https://learn.microsoft.com/en-us/windows/win32/api/http/ns-http-http_service_config_ssl_param_ex
//
// An input structure is built in one []uint64 arena together with everything its pointer members name
// (address, hash, strings, extended data), so every pointer is an address inside one Go allocation that
// the call keeps alive; nothing the kernel writes becomes a Go pointer.
//
// W0 F2: an update replaces the whole record, so the record sent is always the full record read, with
// only hash and store changed by winhelper. F9 (not measured yet): whether a base update keeps the
// record's extended parameters. exStrategy decides what the helper does about it.
//
// Runner run 1 (windows.yml 39853315055): Windows Server 2025 answers an Ex query of every known type
// with the record's value or the default (types 0-4 "set", type 5 ERROR_INVALID_PARAMETER), the
// performance type as an aggregate of all six performance values (perfParamMax), and kept the HTTP/2
// window a test set across a base update; writing every value read back failed with
// ERROR_INVALID_PARAMETER. Windows Server 2022 answers ERROR_NOT_FOUND (1168) for a type not set.

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"runtime"
	"strconv"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"

	"alice/internal/providers/windows/winhelper"
	"alice/internal/providers/windows/winproto"
)

var (
	procHttpUpdateServiceConfiguration = modhttpapi.NewProc("HttpUpdateServiceConfiguration")
	procHttpSetServiceConfiguration    = modhttpapi.NewProc("HttpSetServiceConfiguration")
)

const (
	// HTTP_SERVICE_CONFIG_ID of the extended records.
	configSSLCertInfoEx    = 8
	configSSLSniCertInfoEx = 9

	queryExact = 0 // HttpServiceConfigQueryExact
)

// sslParamEx is HTTP_SERVICE_CONFIG_SSL_PARAM_EX (32 bytes): the union is two 8-byte words.
type sslParamEx struct {
	ParamType uint32
	Flags     uint64
	Union     [2]uint64
}

// The union members (sizes asserted by TestRealStructSizes; the code reads them through exparam's
// offsets).
type (
	http2WindowSizeParam struct{ Http2ReceiveWindowSize uint32 }
	http2SettingsLimits  struct{ Http2MaxSettingsPerFrame, Http2MaxSettingsPerMinute uint32 }
	httpPerformanceParam struct {
		Type       uint32
		BufferSize uint32
		Buffer     uintptr
	}
	httpTLSRestrictions struct {
		RestrictionCount uint32
		TLSRestrictions  uintptr
	}
	httpErrorHeaders struct {
		StatusCode, HeaderCount uint16
		Headers                 uintptr
	}
	httpTLSSessionTicketKeys struct {
		SessionTicketKeyCount uint32
		SessionTicketKeys     uintptr
	}
	httpUnknownHeader struct {
		NameLength, RawValueLength uint16
		Name, RawValue             uintptr
	}
)

// sslSetEx is HTTP_SERVICE_CONFIG_SSL_SET_EX: HTTP_SERVICE_CONFIG_SSL_KEY_EX {SOCKADDR_STORAGE IpPort}
// (the address by value, unlike the base key) and the parameter (160 bytes).
type sslSetEx struct {
	IPPort sockaddrStorage
	Param  sslParamEx
}

// sslSniSetEx is HTTP_SERVICE_CONFIG_SSL_SNI_SET_EX: the SNI key {SOCKADDR_STORAGE IpPort; PWSTR Host}
// and the parameter (168 bytes).
type sslSniSetEx struct {
	IPPort sockaddrStorage
	Host   uintptr
	Param  sslParamEx
}

// sslQueryEx is HTTP_SERVICE_CONFIG_SSL_QUERY_EX (144 bytes).
type sslQueryEx struct {
	QueryDesc uint32
	IPPort    sockaddrStorage
	Token     uint32
	ParamType uint32
}

// sslSniQueryEx is HTTP_SERVICE_CONFIG_SSL_SNI_QUERY_EX (152 bytes).
type sslSniQueryEx struct {
	QueryDesc uint32
	IPPort    sockaddrStorage
	Host      uintptr
	Token     uint32
	ParamType uint32
}

// The F9 strategies (W2 Task 6 rulings): exRepair (the default) sends the base update, reads the
// extended parameters back and writes again only those that the base update changed or dropped, so a
// world where the base update keeps them makes no Ex call at all and one where it resets them gets
// them back; exRewrite writes every parameter read after the base update (run 1 on 2025: refused for
// the defaults); exBaseOnly trusts the base update.
const (
	exRepair   = "repair"
	exRewrite  = "rewrite"
	exBaseOnly = "base-only"
)

var exStrategy = exRepair

var errHTTPAPIMissing = errors.New("httpapi.dll lacks a configuration call")

// arena is one aligned allocation an input structure and its data live in.
type arena struct {
	buf []uint64
	b   []byte
	n   int
}

// newArena allocates the arena on the heap. It must never be inlined: inlined, a small arena that does
// not escape lives on the goroutine stack (Go puts a make of at most 32 bytes there), and a uintptr
// into it handed to http.sys goes stale when the stack moves between computing it and the call. A heap
// object never moves, and runtime.KeepAlive after the call keeps it alive.
//
//go:noinline
func newArena(size int) *arena {
	buf := make([]uint64, (size+7)/8+1)
	// unsafe: a byte view of buf's own memory.
	return &arena{buf: buf, b: unsafe.Slice((*byte)(unsafe.Pointer(&buf[0])), len(buf)*8)}
}

// alloc reserves n bytes 8-byte aligned and returns their offset.
func (a *arena) alloc(n int) int {
	a.n = (a.n + 7) &^ 7
	off := a.n
	if n < 0 || off+n > len(a.b) {
		panic("alice-winhelper: arena too small") // sizes are computed before; a bug, never input
	}
	a.n += n
	return off
}

func (a *arena) addr(off int) uintptr { return uintptr(unsafe.Pointer(&a.b[0])) + uintptr(off) } //nolint:gosec // G115: off >= 0

// put copies b into the arena and returns its address (0 for an empty b).
func (a *arena) put(b []byte) uintptr {
	if len(b) == 0 {
		return 0
	}
	off := a.alloc(len(b))
	copy(a.b[off:], b)
	return a.addr(off)
}

// putString writes s as a NUL-terminated UTF-16 string; "" is NULL.
func (a *arena) putString(s string) uintptr {
	if s == "" {
		return 0
	}
	u := utf16.Encode([]rune(s))
	off := a.alloc(2 * (len(u) + 1))
	for i, c := range u {
		binary.LittleEndian.PutUint16(a.b[off+2*i:], c)
	}
	return a.addr(off)
}

// stringBytes is the arena room a string takes.
func stringBytes(s string) int { return 2*(len(utf16.Encode([]rune(s)))+1) + 8 }

// key is a record's key: the address (ipport) or the port with the host name (hostnameport).
type key struct {
	typ  string
	addr sockaddrStorage
	host string
}

// putSockaddr writes a SOCKADDR_IN or SOCKADDR_IN6 (port in network byte order).
func putSockaddr(ip netip.Addr, port int) sockaddrStorage {
	var ss sockaddrStorage
	b := storageBytes(&ss)
	binary.BigEndian.PutUint16(b[2:], uint16(port)) //nolint:gosec // G115: 1..65535, checked by the caller
	if ip.Is4() {
		binary.LittleEndian.PutUint16(b[0:], windows.AF_INET)
		a := ip.As4()
		copy(b[4:8], a[:])
		return ss
	}
	binary.LittleEndian.PutUint16(b[0:], windows.AF_INET6)
	a := ip.As16()
	copy(b[8:24], a[:])
	return ss
}

// keyOf is the key of a record of type typ. A hostnameport key's address is 0.0.0.0 with the port
// (the spike's reads and updates of netsh's records, W0 F2).
func keyOf(typ, ip, host string, port int) (key, error) {
	if port < 1 || port > 65535 {
		return key{}, errBadValue
	}
	switch typ {
	case winproto.BindingIPPort:
		a, err := netip.ParseAddr(ip)
		if err != nil || a.Zone() != "" {
			return key{}, errBadValue
		}
		return key{typ: typ, addr: putSockaddr(a.Unmap(), port)}, nil
	case winproto.BindingHostnamePort:
		if host == "" || len(host) > maxConfigString {
			return key{}, errBadValue
		}
		return key{typ: typ, addr: putSockaddr(netip.IPv4Unspecified(), port), host: host}, nil
	}
	return key{}, errBadValue // ccs records are not read or written by key (not deployable)
}

// withHTTP runs f between HttpInitialize and HttpTerminate.
func withHTTP(f func() error) error {
	for _, p := range []*windows.LazyProc{procHttpInitialize, procHttpTerminate, procHttpQueryServiceConfiguration} {
		if p.Find() != nil {
			return errHTTPAPIMissing
		}
	}
	r, _, _ := procHttpInitialize.Call(httpapiVersion2, httpInitializeConfig, 0)
	if err := ulongResult(r); err != nil {
		return err
	}
	defer func() { _, _, _ = procHttpTerminate.Call(httpInitializeConfig, 0) }()
	return f()
}

// lookupBinding reads the record a locator names, base and extended parameters; found is false when
// http.sys holds none. An extended parameter that cannot be read or written back (errExUnsupported,
// errBadValue, any other query error) fails the whole read with that error: the deploy path's Binding
// then fails before winhelper's gate, so iis-deploy answers IO_ERROR and nothing is changed; only the
// dump drops such a record (list_truncated).
func lookupBinding(l winproto.Locator) (winproto.SSLBinding, bool, error) {
	k, err := keyOf(l.Type, l.IP, l.Host, l.Port)
	if err != nil {
		return winproto.SSLBinding{}, false, err
	}
	var b winproto.SSLBinding
	found := false
	err = withHTTP(func() error {
		var err error
		b, found, err = readBase(k)
		if err != nil || !found {
			return err
		}
		b.Extended, err = readExtended(k)
		return err
	})
	if err != nil {
		return winproto.SSLBinding{}, false, err
	}
	return b, found, nil
}

// readBase reads the base record of a key (QueryExact).
func readBase(k key) (winproto.SSLBinding, bool, error) {
	a := newArena(int(unsafe.Sizeof(sockaddrStorage{})) + stringBytes(k.host))
	var id uint32
	var in unsafe.Pointer
	var inLen uintptr
	switch k.typ {
	case winproto.BindingIPPort:
		off := a.alloc(int(unsafe.Sizeof(sockaddrStorage{})))
		copy(a.b[off:], storageBytes(&k.addr))
		q := &sslQuery{QueryDesc: queryExact, IPPort: a.addr(off)}
		id, in, inLen = configSSLCertInfo, unsafe.Pointer(q), unsafe.Sizeof(*q)
	default:
		q := &sslSniQuery{QueryDesc: queryExact, IPPort: k.addr, Host: a.putString(k.host)}
		id, in, inLen = configSSLSniCertInfo, unsafe.Pointer(q), unsafe.Sizeof(*q)
	}
	rec, err := queryConfig(id, in, inLen)
	runtime.KeepAlive(a)
	if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) || errors.Is(err, windows.ERROR_NO_MORE_ITEMS) {
		return winproto.SSLBinding{}, false, nil
	}
	if err != nil {
		return winproto.SSLBinding{}, false, err
	}
	b := decodeRecord(id, rec)
	if b.Type != k.typ {
		return winproto.SSLBinding{}, false, errBadValue
	}
	return b, true, nil
}

// exResult is what the query of one extended parameter type answered (TestReal* logs it for F9).
type exResult struct {
	Type   uint32
	Status string // "set", "not_set" (ERROR_FILE_NOT_FOUND, ERROR_NOT_FOUND), "unsupported" (ERROR_INVALID_PARAMETER, ERROR_NOT_SUPPORTED)
	Err    string // the query's answer when not "set" (diagnostics only, never in a helper answer)
}

// exReadError says which type and stage of an Ex read failed (diagnostics for the runner logs; the
// helper's answers never carry error text). It unwraps to the cause.
type exReadError struct {
	Type  uint32
	Stage string // "query", "decode", "type"
	Err   error
}

func (e *exReadError) Error() string {
	return "ex type " + strconv.FormatUint(uint64(e.Type), 10) + " " + e.Stage + ": " + e.Err.Error()
}

func (e *exReadError) Unwrap() error { return e.Err }

// readExtended reads every extended parameter type of a record, in type order.
func readExtended(k key) ([]winproto.ExtendedParam, error) {
	params, _, err := readExtendedDetail(k)
	return params, err
}

// readExtendedDetail is readExtended with each type's answer. ERROR_FILE_NOT_FOUND or ERROR_NOT_FOUND
// (Windows Server 2022, run 1) is a type not set;
// ERROR_INVALID_PARAMETER (or ERROR_NOT_SUPPORTED) is a type, or the Ex tables, this build does not
// know: not set either.
func readExtendedDetail(k key) ([]winproto.ExtendedParam, []exResult, error) {
	var params []winproto.ExtendedParam
	results := make([]exResult, 0, exTypeCount)
	for t := uint32(0); t < exTypeCount; t++ {
		data, err := readEx(k, t)
		switch {
		case errors.Is(err, windows.ERROR_FILE_NOT_FOUND), errors.Is(err, windows.ERROR_NOT_FOUND),
			errors.Is(err, windows.ERROR_NO_MORE_ITEMS):
			results = append(results, exResult{Type: t, Status: "not_set", Err: err.Error()})
			continue
		case errors.Is(err, windows.ERROR_INVALID_PARAMETER), errors.Is(err, windows.ERROR_NOT_SUPPORTED):
			results = append(results, exResult{Type: t, Status: "unsupported", Err: err.Error()})
			continue
		case err != nil:
			return nil, results, err
		}
		results = append(results, exResult{Type: t, Status: "set"})
		params = append(params, winproto.ExtendedParam{Type: t, Data: base64.StdEncoding.EncodeToString(data)})
	}
	return params, results, nil
}

// readEx queries one extended parameter type of a record (QueryExact) and returns its portable form.
func readEx(k key, t uint32) ([]byte, error) {
	a := newArena(stringBytes(k.host))
	var id uint32
	var in unsafe.Pointer
	var inLen uintptr
	var paramOff int
	switch k.typ {
	case winproto.BindingIPPort:
		q := &sslQueryEx{QueryDesc: queryExact, IPPort: k.addr, ParamType: t}
		id, in, inLen, paramOff = configSSLCertInfoEx, unsafe.Pointer(q), unsafe.Sizeof(*q), int(unsafe.Offsetof(sslSetEx{}.Param))
	default:
		q := &sslSniQueryEx{QueryDesc: queryExact, IPPort: k.addr, Host: a.putString(k.host), ParamType: t}
		id, in, inLen, paramOff = configSSLSniCertInfoEx, unsafe.Pointer(q), unsafe.Sizeof(*q), int(unsafe.Offsetof(sslSniSetEx{}.Param))
	}
	rec, err := queryConfig(id, in, inLen)
	runtime.KeepAlive(a)
	if err != nil {
		return nil, &exReadError{Type: t, Stage: "query", Err: err}
	}
	data, err := flattenEx(rec, uint64(recordBase(rec)), paramOff)
	if err != nil {
		return nil, &exReadError{Type: t, Stage: "decode", Err: err}
	}
	if got := binary.LittleEndian.Uint32(data[0:]); got != t {
		return nil, &exReadError{Type: t, Stage: "type", Err: errBadValue}
	}
	return data, nil
}

// updateRecord sends one HttpUpdateServiceConfiguration of the whole base record b, then (exRepair)
// one write of each extended parameter b carries that the record no longer holds as b has it. 1312 is winhelper.ErrKeyUnusable and 2
// winhelper.ErrBindingNotFound, both from the base update, which then changed nothing. An error after
// the base update leaves the record changed: winhelper reads it back either way.
func updateRecord(b winproto.SSLBinding) error {
	k, err := keyOf(b.Type, b.IP, b.Host, b.Port)
	if err != nil {
		return err
	}
	if procHttpUpdateServiceConfiguration.Find() != nil || procHttpSetServiceConfiguration.Find() != nil {
		return errHTTPAPIMissing
	}
	return withHTTP(func() error {
		if err := updateBase(k, b); err != nil {
			return err
		}
		if exStrategy == exBaseOnly || len(b.Extended) == 0 {
			return nil
		}
		held := map[uint32]string{}
		if exStrategy == exRepair {
			now, err := readExtended(k)
			if err != nil {
				return fmt.Errorf("ex read after the base update: %w", err)
			}
			for _, p := range now {
				held[p.Type] = p.Data
			}
		}
		for _, p := range b.Extended {
			if d, ok := held[p.Type]; ok && d == p.Data {
				continue // kept by the base update
			}
			if err := writeEx(k, p); err != nil {
				return fmt.Errorf("ex write of type %d: %w", p.Type, err)
			}
		}
		return nil
	})
}

// updateBase sends the base record (inside withHTTP).
func updateBase(k key, b winproto.SSLBinding) error {
	a, id, in, inLen, err := encodeBase(k, b)
	if err != nil {
		return err
	}
	r, _, _ := procHttpUpdateServiceConfiguration.Call(0, uintptr(id), in, inLen, 0)
	runtime.KeepAlive(a)
	err = ulongResult(r)
	switch {
	case errors.Is(err, windows.ERROR_NO_SUCH_LOGON_SESSION):
		return winhelper.ErrKeyUnusable
	case errors.Is(err, windows.ERROR_FILE_NOT_FOUND):
		return winhelper.ErrBindingNotFound
	case err != nil:
		return fmt.Errorf("base update: %w", err)
	}
	return nil
}

// encodeBase builds the HTTP_SERVICE_CONFIG_SSL_SET or _SNI_SET of b in one arena.
func encodeBase(k key, b winproto.SSLBinding) (*arena, uint32, uintptr, uintptr, error) {
	hash, err := hex.DecodeString(b.CertSHA1)
	if err != nil || len(hash) == 0 || len(hash) > maxHashBytes {
		return nil, 0, 0, 0, errBadValue
	}
	appID, err := windows.GUIDFromString(b.AppID)
	if err != nil {
		return nil, 0, 0, 0, errBadValue
	}
	for _, s := range []string{b.Store, b.CTLIdentifier, b.CTLStore, k.host} {
		if len(s) > maxConfigString {
			return nil, 0, 0, 0, errBadValue
		}
	}
	size := int(unsafe.Sizeof(sslSniSet{})) + int(unsafe.Sizeof(sockaddrStorage{})) + len(hash) + 8 +
		stringBytes(b.Store) + stringBytes(b.CTLIdentifier) + stringBytes(b.CTLStore) + stringBytes(k.host)
	a := newArena(size)
	var param *sslParam
	var id uint32
	var inLen uintptr
	// unsafe: each structure is laid over the arena's first bytes (aligned, no Go pointers inside).
	switch k.typ {
	case winproto.BindingIPPort:
		off := a.alloc(int(unsafe.Sizeof(sslSet{})))
		s := (*sslSet)(unsafe.Pointer(&a.b[off]))
		addr := a.alloc(int(unsafe.Sizeof(sockaddrStorage{})))
		copy(a.b[addr:], storageBytes(&k.addr))
		s.IPPort = a.addr(addr)
		param, id, inLen = &s.Param, configSSLCertInfo, unsafe.Sizeof(*s)
	default:
		off := a.alloc(int(unsafe.Sizeof(sslSniSet{})))
		s := (*sslSniSet)(unsafe.Pointer(&a.b[off]))
		s.IPPort = k.addr
		s.Host = a.putString(k.host)
		param, id, inLen = &s.Param, configSSLSniCertInfo, unsafe.Sizeof(*s)
	}
	param.SslHashLength = uint32(len(hash)) //nolint:gosec // G115: at most maxHashBytes
	param.SslHash = a.put(hash)
	param.AppID = appID
	param.SslCertStoreName = a.putString(b.Store) // "" (read as NULL) is written back NULL
	param.DefaultCertCheckMode = b.CertCheckMode
	param.DefaultRevocationFreshnessTime = b.RevocationFreshnessTime
	param.DefaultRevocationURLRetrievalTimeout = b.URLRetrievalTimeout
	param.DefaultSslCtlIdentifier = a.putString(b.CTLIdentifier)
	param.DefaultSslCtlStoreName = a.putString(b.CTLStore)
	param.DefaultFlags = b.Flags
	return a, id, a.addr(0), inLen, nil
}

// writeEx writes one extended parameter of a record (inside withHTTP): an update, or a set when the
// record does not hold that type (a base update that reset it, or a test adding one).
func writeEx(k key, p winproto.ExtendedParam) error {
	a, id, in, inLen, err := encodeEx(k, p)
	if err != nil {
		return err
	}
	r, _, _ := procHttpUpdateServiceConfiguration.Call(0, uintptr(id), in, inLen, 0)
	err = ulongResult(r)
	if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) || errors.Is(err, windows.ERROR_NOT_FOUND) {
		r, _, _ = procHttpSetServiceConfiguration.Call(0, uintptr(id), in, inLen, 0)
		err = ulongResult(r)
	}
	runtime.KeepAlive(a)
	return err
}

// encodeEx builds the HTTP_SERVICE_CONFIG_SSL_SET_EX or _SNI_SET_EX of one parameter in one arena:
// the structure, then the parameter's portable form relocated to its place in the arena, whose
// first 32 bytes become the structure's ParamDesc.
func encodeEx(k key, p winproto.ExtendedParam) (*arena, uint32, uintptr, uintptr, error) {
	data, err := base64.StdEncoding.DecodeString(p.Data)
	if err != nil || len(data) < paramExSize || binary.LittleEndian.Uint32(data[0:]) != p.Type {
		return nil, 0, 0, 0, errBadValue
	}
	a := newArena(int(unsafe.Sizeof(sslSniSetEx{})) + len(data) + 8 + stringBytes(k.host))
	var param *sslParamEx
	var id uint32
	var inLen uintptr
	// unsafe: as in encodeBase.
	switch k.typ {
	case winproto.BindingIPPort:
		off := a.alloc(int(unsafe.Sizeof(sslSetEx{})))
		s := (*sslSetEx)(unsafe.Pointer(&a.b[off]))
		s.IPPort = k.addr
		param, id, inLen = &s.Param, configSSLCertInfoEx, unsafe.Sizeof(*s)
	default:
		off := a.alloc(int(unsafe.Sizeof(sslSniSetEx{})))
		s := (*sslSniSetEx)(unsafe.Pointer(&a.b[off]))
		s.IPPort = k.addr
		s.Host = a.putString(k.host)
		param, id, inLen = &s.Param, configSSLSniCertInfoEx, unsafe.Sizeof(*s)
	}
	at := a.alloc(len(data))
	placed, err := relocateEx(data, uint64(a.addr(at)))
	if err != nil {
		return nil, 0, 0, 0, err
	}
	copy(a.b[at:], placed)
	// unsafe: a byte view of the ParamDesc member inside the arena.
	copy(unsafe.Slice((*byte)(unsafe.Pointer(param)), paramExSize), placed[:paramExSize])
	return a, id, a.addr(0), inLen, nil
}

// Binding reads the record a locator names (winhelper.WriteHost).
func (host) Binding(ctx context.Context, l winproto.Locator) (winproto.SSLBinding, bool, error) {
	if err := ctx.Err(); err != nil {
		return winproto.SSLBinding{}, false, err
	}
	return lookupBinding(l)
}

// UpdateBinding sends one update of the whole record (winhelper.WriteHost).
func (host) UpdateBinding(ctx context.Context, b winproto.SSLBinding) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return updateRecord(b)
}
