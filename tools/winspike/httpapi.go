//go:build windows

package main

// A hand-written binding of the HTTP Server API configuration calls (httpapi.dll), as §7 of the design wants for
// alice-helper.exe. Layouts are the C structs of http.h for amd64 (Go's natural alignment matches C's here:
// uint32 4-aligned, pointers and SOCKADDR_STORAGE 8-aligned), from:
//
//	https://learn.microsoft.com/en-us/windows/win32/api/http/nf-http-httpqueryserviceconfiguration
//	https://learn.microsoft.com/en-us/windows/win32/api/http/nf-http-httpsetserviceconfiguration
//	https://learn.microsoft.com/en-us/windows/win32/api/http/nf-http-httpupdateserviceconfiguration
//	https://learn.microsoft.com/en-us/windows/win32/api/http/ns-http-http_service_config_ssl_param
//	https://learn.microsoft.com/en-us/windows/win32/api/http/ns-http-http_service_config_ssl_set
//	https://learn.microsoft.com/en-us/windows/win32/api/http/ns-http-http_service_config_ssl_sni_set
//	https://learn.microsoft.com/en-us/windows/win32/api/http/ns-http-http_service_config_ssl_ccs_set
//	https://learn.microsoft.com/en-us/windows/win32/api/http/ns-http-http_service_config_ssl_query
//	https://learn.microsoft.com/en-us/windows/win32/api/http/ns-http-http_service_config_ssl_sni_query
//	https://learn.microsoft.com/en-us/windows/win32/api/http/ns-http-http_service_config_ssl_ccs_query
//
// Every call returns its error as the ULONG result (not GetLastError).

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modhttpapi                         = windows.NewLazySystemDLL("httpapi.dll")
	procHttpInitialize                 = modhttpapi.NewProc("HttpInitialize")
	procHttpTerminate                  = modhttpapi.NewProc("HttpTerminate")
	procHttpQueryServiceConfiguration  = modhttpapi.NewProc("HttpQueryServiceConfiguration")
	procHttpSetServiceConfiguration    = modhttpapi.NewProc("HttpSetServiceConfiguration")
	procHttpUpdateServiceConfiguration = modhttpapi.NewProc("HttpUpdateServiceConfiguration")
	procHttpDeleteServiceConfiguration = modhttpapi.NewProc("HttpDeleteServiceConfiguration")
	httpapiProcs                       = []*windows.LazyProc{procHttpInitialize, procHttpTerminate,
		procHttpQueryServiceConfiguration, procHttpSetServiceConfiguration, procHttpUpdateServiceConfiguration,
		procHttpDeleteServiceConfiguration}
)

const (
	httpInitializeConfig = 0x2 // HTTP_INITIALIZE_CONFIG

	// HTTP_SERVICE_CONFIG_ID
	configSSLCertInfo    = 1
	configSslSniCertInfo = 5
	configSslCcsCertInfo = 6

	// HTTP_SERVICE_CONFIG_QUERY_TYPE
	queryExact = 0
	queryNext  = 1

	errInsufficientBuffer = syscall.Errno(122) // ERROR_INSUFFICIENT_BUFFER
	errNoMoreItems        = syscall.Errno(259) // ERROR_NO_MORE_ITEMS

	// IIS's application id for its http.sys SSL bindings (what IIS Manager writes).
	iisAppID = "{4dc3e181-e14b-4a21-b022-59fc669b0914}"
)

// sockaddrStorage is SOCKADDR_STORAGE: 128 bytes, 8-byte aligned.
type sockaddrStorage [16]uint64

// sslParam is HTTP_SERVICE_CONFIG_SSL_PARAM (80 bytes on amd64).
type sslParam struct {
	SslHashLength                        uint32
	SslHash                              *byte
	AppID                                windows.GUID
	SslCertStoreName                     *uint16
	DefaultCertCheckMode                 uint32
	DefaultRevocationFreshnessTime       uint32
	DefaultRevocationURLRetrievalTimeout uint32
	DefaultSslCtlIdentifier              *uint16
	DefaultSslCtlStoreName               *uint16
	DefaultFlags                         uint32
}

// sslSet is HTTP_SERVICE_CONFIG_SSL_SET: HTTP_SERVICE_CONFIG_SSL_KEY {PSOCKADDR pIpPort} + param (88 bytes).
type sslSet struct {
	IPPort *byte
	Param  sslParam
}

// sslSniSet is HTTP_SERVICE_CONFIG_SSL_SNI_SET: HTTP_SERVICE_CONFIG_SSL_SNI_KEY {SOCKADDR_STORAGE IpPort; PWSTR Host}
// + param (216 bytes).
type sslSniSet struct {
	IPPort sockaddrStorage
	Host   *uint16
	Param  sslParam
}

// sslCcsSet is HTTP_SERVICE_CONFIG_SSL_CCS_SET: HTTP_SERVICE_CONFIG_SSL_CCS_KEY {SOCKADDR_STORAGE LocalAddress} +
// param (208 bytes).
type sslCcsSet struct {
	LocalAddress sockaddrStorage
	Param        sslParam
}

// sslQuery is HTTP_SERVICE_CONFIG_SSL_QUERY (24 bytes).
type sslQuery struct {
	QueryDesc uint32
	IPPort    *byte
	Token     uint32
}

// sslSniQuery is HTTP_SERVICE_CONFIG_SSL_SNI_QUERY (152 bytes).
type sslSniQuery struct {
	QueryDesc uint32
	IPPort    sockaddrStorage
	Host      *uint16
	Token     uint32
}

// sslCcsQuery is HTTP_SERVICE_CONFIG_SSL_CCS_QUERY (144 bytes).
type sslCcsQuery struct {
	QueryDesc    uint32
	LocalAddress sockaddrStorage
	Token        uint32
}

// structSizes is reported by osinfo so the layouts above are on record.
func structSizes() map[string]uintptr {
	return map[string]uintptr{
		"HTTP_SERVICE_CONFIG_SSL_PARAM":     unsafe.Sizeof(sslParam{}),
		"HTTP_SERVICE_CONFIG_SSL_SET":       unsafe.Sizeof(sslSet{}),
		"HTTP_SERVICE_CONFIG_SSL_SNI_SET":   unsafe.Sizeof(sslSniSet{}),
		"HTTP_SERVICE_CONFIG_SSL_CCS_SET":   unsafe.Sizeof(sslCcsSet{}),
		"HTTP_SERVICE_CONFIG_SSL_QUERY":     unsafe.Sizeof(sslQuery{}),
		"HTTP_SERVICE_CONFIG_SSL_SNI_QUERY": unsafe.Sizeof(sslSniQuery{}),
		"HTTP_SERVICE_CONFIG_SSL_CCS_QUERY": unsafe.Sizeof(sslCcsQuery{}),
	}
}

// Binding is one http.sys SSL record, every field of HTTP_SERVICE_CONFIG_SSL_PARAM kept.
type Binding struct {
	Type                          string   `json:"type"` // ipport, hostnameport, ccs
	IP                            string   `json:"ip,omitempty"`
	Host                          string   `json:"host,omitempty"`
	Port                          int      `json:"port"`
	Hash                          string   `json:"hash"`
	Store                         string   `json:"store"`
	StoreNull                     bool     `json:"store_null,omitempty"`
	AppID                         string   `json:"app_id"`
	CertCheckMode                 uint32   `json:"cert_check_mode"`
	RevocationFreshnessTime       uint32   `json:"revocation_freshness_time"`
	RevocationURLRetrievalTimeout uint32   `json:"revocation_url_retrieval_timeout"`
	CtlIdentifier                 string   `json:"ctl_identifier"`
	CtlStoreName                  string   `json:"ctl_store_name"`
	Flags                         uint32   `json:"flags"`
	FlagNames                     []string `json:"flag_names,omitempty"`
}

// Key is the binding's identity in the netsh text form.
func (b Binding) Key() string {
	switch b.Type {
	case "hostnameport":
		return fmt.Sprintf("hostnameport=%s:%d", b.Host, b.Port)
	case "ccs":
		return fmt.Sprintf("ccs=%d", b.Port)
	default:
		return "ipport=" + net.JoinHostPort(b.IP, strconv.Itoa(b.Port))
	}
}

// sameExceptHash compares every field the design must preserve.
func sameExceptHash(a, b Binding) []string {
	var diff []string
	add := func(name string, x, y any) {
		if fmt.Sprint(x) != fmt.Sprint(y) {
			diff = append(diff, fmt.Sprintf("%s: %v -> %v", name, x, y))
		}
	}
	add("type", a.Type, b.Type)
	add("ip", a.IP, b.IP)
	add("host", a.Host, b.Host)
	add("port", a.Port, b.Port)
	add("store", strings.ToLower(a.Store), strings.ToLower(b.Store))
	add("app_id", a.AppID, b.AppID)
	add("cert_check_mode", a.CertCheckMode, b.CertCheckMode)
	add("revocation_freshness_time", a.RevocationFreshnessTime, b.RevocationFreshnessTime)
	add("revocation_url_retrieval_timeout", a.RevocationURLRetrievalTimeout, b.RevocationURLRetrievalTimeout)
	add("ctl_identifier", a.CtlIdentifier, b.CtlIdentifier)
	add("ctl_store_name", a.CtlStoreName, b.CtlStoreName)
	add("flags", a.Flags, b.Flags)
	return diff
}

// Flag names from http.h (HTTP_SERVICE_CONFIG_SSL_FLAG_*).
var flagNames = []struct {
	bit  uint32
	name string
}{
	{0x1, "USE_DS_MAPPER"}, {0x2, "NEGOTIATE_CLIENT_CERT"}, {0x4, "NO_RAW_FILTER"}, {0x8, "REJECT"},
	{0x10, "DISABLE_HTTP2"}, {0x20, "DISABLE_QUIC"}, {0x40, "DISABLE_TLS13"}, {0x80, "DISABLE_OCSP_STAPLING"},
	{0x100, "ENABLE_TOKEN_BINDING"}, {0x200, "LOG_EXTENDED_EVENTS"}, {0x400, "DISABLE_LEGACY_TLS"},
	{0x800, "ENABLE_SESSION_TICKET"}, {0x1000, "DISABLE_TLS12"}, {0x2000, "ENABLE_CLIENT_CORRELATION"},
	{0x4000, "DISABLE_SESSION_ID"},
}

func names(flags uint32) []string {
	var out []string
	for _, f := range flagNames {
		if flags&f.bit != 0 {
			out = append(out, f.name)
			flags &^= f.bit
		}
	}
	if flags != 0 {
		out = append(out, fmt.Sprintf("0x%x", flags))
	}
	return out
}

func httpCall(p *windows.LazyProc, args ...uintptr) error {
	if err := p.Find(); err != nil {
		return fmt.Errorf("%s not exported: %w", p.Name, err)
	}
	r, _, _ := p.Call(args...)
	if r != 0 {
		return syscall.Errno(r)
	}
	return nil
}

// httpInit calls HttpInitialize(HTTPAPI_VERSION{2,0}, HTTP_INITIALIZE_CONFIG, NULL). HTTPAPI_VERSION is two USHORTs
// passed by value in one register: major in the low half.
func httpInit() error {
	return httpCall(procHttpInitialize, uintptr(2), httpInitializeConfig, 0)
}

func httpTerm() { _ = httpCall(procHttpTerminate, httpInitializeConfig, 0) }

// encodeSockaddr writes a SOCKADDR_IN or SOCKADDR_IN6 (port in network order) into storage.
func encodeSockaddr(ip net.IP, port int) (sockaddrStorage, error) {
	var ss sockaddrStorage
	b := (*[128]byte)(unsafe.Pointer(&ss))[:]
	if v4 := ip.To4(); v4 != nil {
		binary.LittleEndian.PutUint16(b[0:], windows.AF_INET)
		binary.BigEndian.PutUint16(b[2:], uint16(port))
		copy(b[4:8], v4)
		return ss, nil
	}
	if v6 := ip.To16(); v6 != nil {
		binary.LittleEndian.PutUint16(b[0:], windows.AF_INET6)
		binary.BigEndian.PutUint16(b[2:], uint16(port))
		copy(b[8:24], v6)
		return ss, nil
	}
	return ss, fmt.Errorf("bad ip %v", ip)
}

func decodeSockaddr(p unsafe.Pointer) (string, int) {
	if p == nil {
		return "", 0
	}
	b := (*[128]byte)(p)[:]
	fam := binary.LittleEndian.Uint16(b[0:])
	port := int(binary.BigEndian.Uint16(b[2:]))
	switch fam {
	case windows.AF_INET:
		return net.IP(append([]byte(nil), b[4:8]...)).String(), port
	case windows.AF_INET6:
		return net.IP(append([]byte(nil), b[8:24]...)).String(), port
	}
	return fmt.Sprintf("family-%d", fam), port
}

func utf16OrNil(s string) *uint16 {
	if s == "" {
		return nil
	}
	p, _ := windows.UTF16PtrFromString(s)
	return p
}

func goString(p *uint16) string {
	if p == nil {
		return ""
	}
	return windows.UTF16PtrToString(p)
}

func decodeParam(b *Binding, p *sslParam) {
	if p.SslHashLength > 0 && p.SslHash != nil {
		b.Hash = hex.EncodeToString(unsafe.Slice(p.SslHash, p.SslHashLength))
	}
	b.StoreNull = p.SslCertStoreName == nil
	b.Store = goString(p.SslCertStoreName)
	b.AppID = strings.ToLower(p.AppID.String())
	b.CertCheckMode = p.DefaultCertCheckMode
	b.RevocationFreshnessTime = p.DefaultRevocationFreshnessTime
	b.RevocationURLRetrievalTimeout = p.DefaultRevocationURLRetrievalTimeout
	b.CtlIdentifier = goString(p.DefaultSslCtlIdentifier)
	b.CtlStoreName = goString(p.DefaultSslCtlStoreName)
	b.Flags = p.DefaultFlags
	b.FlagNames = names(p.DefaultFlags)
}

// encoded keeps every buffer a set structure points to alive until the call returns.
type encoded struct {
	ptr  unsafe.Pointer
	size uintptr
	keep []any
	id   uint32
}

func (b Binding) encode() (encoded, error) {
	var e encoded
	var param sslParam
	if b.Hash != "" {
		h, err := hex.DecodeString(strings.ToLower(strings.ReplaceAll(b.Hash, " ", "")))
		if err != nil {
			return e, err
		}
		param.SslHashLength = uint32(len(h))
		param.SslHash = &h[0]
		e.keep = append(e.keep, h)
	}
	if b.AppID != "" {
		g, err := windows.GUIDFromString(b.AppID)
		if err != nil {
			return e, err
		}
		param.AppID = g
	}
	param.SslCertStoreName = utf16OrNil(b.Store)
	param.DefaultCertCheckMode = b.CertCheckMode
	param.DefaultRevocationFreshnessTime = b.RevocationFreshnessTime
	param.DefaultRevocationURLRetrievalTimeout = b.RevocationURLRetrievalTimeout
	param.DefaultSslCtlIdentifier = utf16OrNil(b.CtlIdentifier)
	param.DefaultSslCtlStoreName = utf16OrNil(b.CtlStoreName)
	param.DefaultFlags = b.Flags
	e.keep = append(e.keep, param.SslCertStoreName, param.DefaultSslCtlIdentifier, param.DefaultSslCtlStoreName)

	switch b.Type {
	case "ipport":
		ss, err := encodeSockaddr(net.ParseIP(b.IP), b.Port)
		if err != nil {
			return e, err
		}
		ssp := &ss
		s := &sslSet{IPPort: (*byte)(unsafe.Pointer(ssp)), Param: param}
		e.keep = append(e.keep, ssp, s)
		e.ptr, e.size, e.id = unsafe.Pointer(s), unsafe.Sizeof(*s), configSSLCertInfo
	case "hostnameport":
		// The SNI key's address is 0.0.0.0 (IPv4 any) with the port; the name is in Host.
		ss, err := encodeSockaddr(net.IPv4zero, b.Port)
		if err != nil {
			return e, err
		}
		host := utf16OrNil(b.Host)
		s := &sslSniSet{IPPort: ss, Host: host, Param: param}
		e.keep = append(e.keep, host, s)
		e.ptr, e.size, e.id = unsafe.Pointer(s), unsafe.Sizeof(*s), configSslSniCertInfo
	case "ccs":
		ss, err := encodeSockaddr(net.IPv4zero, b.Port)
		if err != nil {
			return e, err
		}
		s := &sslCcsSet{LocalAddress: ss, Param: param}
		e.keep = append(e.keep, s)
		e.ptr, e.size, e.id = unsafe.Pointer(s), unsafe.Sizeof(*s), configSslCcsCertInfo
	default:
		return e, fmt.Errorf("unknown binding type %q", b.Type)
	}
	return e, nil
}

func configCall(p *windows.LazyProc, b Binding) error {
	e, err := b.encode()
	if err != nil {
		return err
	}
	err = httpCall(p, 0, uintptr(e.id), uintptr(e.ptr), e.size, 0)
	runtime.KeepAlive(e.keep)
	return err
}

func setBinding(b Binding) error    { return configCall(procHttpSetServiceConfiguration, b) }
func updateBinding(b Binding) error { return configCall(procHttpUpdateServiceConfiguration, b) }
func deleteBinding(b Binding) error { return configCall(procHttpDeleteServiceConfiguration, b) }

// query runs one HttpQueryServiceConfiguration with the input structure, sizing the output buffer first.
func query(id uint32, in unsafe.Pointer, inLen uintptr) ([]uint64, error) {
	var need uint32
	err := httpCall(procHttpQueryServiceConfiguration, 0, uintptr(id), uintptr(in), inLen, 0, 0,
		uintptr(unsafe.Pointer(&need)), 0)
	if err == nil {
		return nil, errors.New("query with no buffer succeeded")
	}
	if !errors.Is(err, errInsufficientBuffer) {
		return nil, err
	}
	buf := make([]uint64, (need+7)/8) // []uint64 keeps the output 8-byte aligned for the pointers inside it
	err = httpCall(procHttpQueryServiceConfiguration, 0, uintptr(id), uintptr(in), inLen,
		uintptr(unsafe.Pointer(&buf[0])), uintptr(need), uintptr(unsafe.Pointer(&need)), 0)
	if err != nil {
		return nil, err
	}
	return buf, nil
}

func decodeOutput(id uint32, buf []uint64) Binding {
	p := unsafe.Pointer(&buf[0])
	var b Binding
	switch id {
	case configSSLCertInfo:
		s := (*sslSet)(p)
		b.Type = "ipport"
		b.IP, b.Port = decodeSockaddr(unsafe.Pointer(s.IPPort))
		decodeParam(&b, &s.Param)
	case configSslSniCertInfo:
		s := (*sslSniSet)(p)
		b.Type = "hostnameport"
		_, b.Port = decodeSockaddr(unsafe.Pointer(&s.IPPort))
		b.Host = goString(s.Host)
		decodeParam(&b, &s.Param)
	case configSslCcsCertInfo:
		s := (*sslCcsSet)(p)
		b.Type = "ccs"
		b.IP, b.Port = decodeSockaddr(unsafe.Pointer(&s.LocalAddress))
		decodeParam(&b, &s.Param)
	}
	return b
}

// enumerate lists every record of one type (QueryNext with dwToken 0, 1, ... until ERROR_NO_MORE_ITEMS).
func enumerate(id uint32) ([]Binding, error) {
	out := []Binding{}
	for token := uint32(0); token < 10000; token++ {
		var buf []uint64
		var err error
		switch id {
		case configSSLCertInfo:
			q := sslQuery{QueryDesc: queryNext, Token: token}
			buf, err = query(id, unsafe.Pointer(&q), unsafe.Sizeof(q))
		case configSslSniCertInfo:
			q := sslSniQuery{QueryDesc: queryNext, Token: token}
			buf, err = query(id, unsafe.Pointer(&q), unsafe.Sizeof(q))
		case configSslCcsCertInfo:
			q := sslCcsQuery{QueryDesc: queryNext, Token: token}
			buf, err = query(id, unsafe.Pointer(&q), unsafe.Sizeof(q))
		}
		if errors.Is(err, errNoMoreItems) {
			return out, nil
		}
		if err != nil {
			return out, fmt.Errorf("token %d: %w", token, err)
		}
		out = append(out, decodeOutput(id, buf))
	}
	return out, errors.New("more than 10000 records")
}

// getBinding reads one record exactly (QueryExact with the key).
func getBinding(key Binding) (Binding, error) {
	switch key.Type {
	case "ipport":
		ss, err := encodeSockaddr(net.ParseIP(key.IP), key.Port)
		if err != nil {
			return Binding{}, err
		}
		ssp := &ss
		q := sslQuery{QueryDesc: queryExact, IPPort: (*byte)(unsafe.Pointer(ssp))}
		buf, err := query(configSSLCertInfo, unsafe.Pointer(&q), unsafe.Sizeof(q))
		runtime.KeepAlive(ssp)
		if err != nil {
			return Binding{}, err
		}
		return decodeOutput(configSSLCertInfo, buf), nil
	case "hostnameport":
		ss, _ := encodeSockaddr(net.IPv4zero, key.Port)
		host := utf16OrNil(key.Host)
		q := sslSniQuery{QueryDesc: queryExact, IPPort: ss, Host: host}
		buf, err := query(configSslSniCertInfo, unsafe.Pointer(&q), unsafe.Sizeof(q))
		runtime.KeepAlive(host)
		if err != nil {
			return Binding{}, err
		}
		return decodeOutput(configSslSniCertInfo, buf), nil
	case "ccs":
		ss, _ := encodeSockaddr(net.IPv4zero, key.Port)
		q := sslCcsQuery{QueryDesc: queryExact, LocalAddress: ss}
		buf, err := query(configSslCcsCertInfo, unsafe.Pointer(&q), unsafe.Sizeof(q))
		if err != nil {
			return Binding{}, err
		}
		return decodeOutput(configSslCcsCertInfo, buf), nil
	}
	return Binding{}, fmt.Errorf("unknown type %q", key.Type)
}

// enumerateAll lists the three record types of §6.2.
func enumerateAll() map[string]any {
	out := map[string]any{}
	for _, t := range []struct {
		name string
		id   uint32
	}{{"ssl_cert_info", configSSLCertInfo}, {"ssl_sni_cert_info", configSslSniCertInfo},
		{"ssl_ccs_cert_info", configSslCcsCertInfo}} {
		list, err := enumerate(t.id)
		out[t.name] = list
		if err != nil {
			out[t.name+"_error"] = errString(err)
		}
	}
	return out
}

// parseKey turns "ipport=0.0.0.0:443", "hostnameport=name:443" or "ccs=443" into a key binding.
func parseKey(s string) (Binding, error) {
	kind, val, ok := strings.Cut(s, "=")
	if !ok {
		return Binding{}, fmt.Errorf("key %q: want type=value", s)
	}
	if kind == "ccs" {
		p, err := strconv.Atoi(val)
		return Binding{Type: "ccs", Port: p}, err
	}
	h, ps, err := net.SplitHostPort(val)
	if err != nil {
		return Binding{}, err
	}
	p, err := strconv.Atoi(ps)
	if err != nil {
		return Binding{}, err
	}
	switch kind {
	case "ipport":
		return Binding{Type: "ipport", IP: h, Port: p}, nil
	case "hostnameport":
		return Binding{Type: "hostnameport", Host: h, Port: p}, nil
	}
	return Binding{}, fmt.Errorf("unknown key type %q", kind)
}

// repoint reads a binding, changes only its hash (and store when given) and writes it back with one
// HttpUpdateServiceConfiguration call, as §6.3 step 7 does. It returns the entry before and after.
func repoint(key Binding, hash, store string) (before, after Binding, err error) {
	before, err = getBinding(key)
	if err != nil {
		return before, after, fmt.Errorf("read: %w", err)
	}
	next := before
	next.Hash = hash
	if store != "" {
		next.Store = store
	}
	if err = updateBinding(next); err != nil {
		return before, after, fmt.Errorf("update: %w", err)
	}
	after, err = getBinding(key)
	if err != nil {
		return before, after, fmt.Errorf("read back: %w", err)
	}
	return before, after, nil
}
