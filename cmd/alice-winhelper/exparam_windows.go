//go:build windows

package main

// The portable form of an http.sys extended parameter (W2 F9, winproto.ExtendedParam). An Ex query
// writes HTTP_SERVICE_CONFIG_SSL_PARAM_EX into its output buffer, and the data its pointer members name
// after it, as absolute addresses inside that buffer. ExtendedParam.Data must be written back byte for
// byte by a later call in another buffer, so it holds the 32-byte HTTP_SERVICE_CONFIG_SSL_PARAM_EX with
// every pointer member replaced by the offset of its data from the start of Data (0 for NULL), followed
// by that data, each block 8-byte aligned. flattenEx makes it from a query's output, relocateEx turns it
// back into a structure for an input buffer at a given address. Both only read and write bytes: no Go
// pointer is ever made from what the kernel wrote.
//
// http.h (Windows SDK 10.0.26100), 64-bit layouts, offsets inside HTTP_SERVICE_CONFIG_SSL_PARAM_EX:
//
//	0  ParamType (HTTP_SSL_SERVICE_CONFIG_EX_PARAM_TYPE, 4 bytes), 4 padding
//	8  Flags (ULONGLONG)
//	16 the union of the parameter structs (16 bytes, the largest member):
//	   ExParamTypeHttp2Window          HTTP2_WINDOW_SIZE_PARAM        {DWORD Http2ReceiveWindowSize}
//	   ExParamTypeHttp2SettingsLimits  HTTP2_SETTINGS_LIMITS_PARAM    {DWORD Http2MaxSettingsPerFrame; DWORD Http2MaxSettingsPerMinute}
//	   ExParamTypeHttpPerformance      HTTP_PERFORMANCE_PARAM         {Type @16; ULONG BufferSize @20; PVOID Buffer @24}
//	   ExParamTypeTlsRestrictions      HTTP_TLS_RESTRICTIONS_PARAM    {ULONG RestrictionCount @16; PVOID TlsRestrictions @24 (reserved)}
//	   ExParamTypeErrorHeaders         HTTP_ERROR_HEADERS_PARAM       {USHORT StatusCode @16; USHORT HeaderCount @18; PHTTP_UNKNOWN_HEADER Headers @24}
//	   ExParamTypeTlsSessionTicketKeys HTTP_TLS_SESSION_TICKET_KEYS_PARAM {ULONG SessionTicketKeyCount @16; PVOID SessionTicketKeys @24 (reserved)}
//	HTTP_UNKNOWN_HEADER (24 bytes): USHORT NameLength @0; USHORT RawValueLength @2; PCSTR pName @8; PCSTR pRawValue @16
//
// The reserved pointers of the TLS restrictions and session ticket keys have no documented size: a
// record whose reserved pointer is set cannot be written back and is refused (errExUnsupported).

import (
	"encoding/binary"
	"errors"

	"alice/internal/providers/windows/winproto"
)

// HTTP_SSL_SERVICE_CONFIG_EX_PARAM_TYPE values the helper queries and writes back.
const (
	exHTTP2Window          = 0
	exHTTP2SettingsLimits  = 1
	exHTTPPerformance      = 2
	exTLSRestrictions      = 3
	exErrorHeaders         = 4
	exTLSSessionTicketKeys = 5
	exTypeCount            = 6

	paramExSize       = 32 // HTTP_SERVICE_CONFIG_SSL_PARAM_EX
	unknownHeaderSize = 24 // HTTP_UNKNOWN_HEADER
	exPointerOff      = 24 // the pointer member of every union member that has one
)

var errExUnsupported = errors.New("an extended parameter of the record cannot be written back")

// flattenEx turns the HTTP_SERVICE_CONFIG_SSL_PARAM_EX at rec[off:] of a query's output, whose first
// byte is at address base, into its portable form. Every pointer must name bytes inside rec.
func flattenEx(rec []byte, base uint64, off int) ([]byte, error) {
	if off < 0 || off > len(rec) || len(rec)-off < paramExSize {
		return nil, errBadValue
	}
	out := make([]byte, paramExSize, 256)
	copy(out, rec[off:off+paramExSize])
	at := func(p uint64, n int) ([]byte, bool) {
		if p < base || n < 0 || p-base > uint64(len(rec)) || uint64(n) > uint64(len(rec))-(p-base) {
			return nil, false
		}
		o := int(p - base) //nolint:gosec // G115: bounded by len(rec) above
		return rec[o : o+n], true
	}
	// appendBlock appends b 8-byte aligned and returns its offset in out.
	appendBlock := func(b []byte) uint64 {
		for len(out)%8 != 0 {
			out = append(out, 0)
		}
		o := len(out)
		out = append(out, b...)
		return uint64(o) //nolint:gosec // G115: a length
	}
	// pointer replaces the pointer member at out[field:] naming n bytes by the offset of their copy.
	pointer := func(field, n int) error {
		p := binary.LittleEndian.Uint64(out[field:])
		if p == 0 {
			if n != 0 {
				return errBadValue
			}
			return nil
		}
		b, ok := at(p, n)
		if !ok {
			return errBadValue
		}
		binary.LittleEndian.PutUint64(out[field:], appendBlock(b))
		return nil
	}
	switch binary.LittleEndian.Uint32(out[0:]) {
	case exHTTP2Window, exHTTP2SettingsLimits:
	case exHTTPPerformance:
		if err := pointer(exPointerOff, int(binary.LittleEndian.Uint32(out[20:]))); err != nil {
			return nil, err
		}
	case exTLSRestrictions, exTLSSessionTicketKeys:
		if binary.LittleEndian.Uint64(out[exPointerOff:]) != 0 {
			return nil, errExUnsupported
		}
	case exErrorHeaders:
		count := int(binary.LittleEndian.Uint16(out[18:]))
		if err := pointer(exPointerOff, count*unknownHeaderSize); err != nil {
			return nil, err
		}
		first := int(binary.LittleEndian.Uint64(out[exPointerOff:])) //nolint:gosec // G115: an offset into out
		for i := range count {
			h := first + i*unknownHeaderSize
			if err := pointer(h+8, int(binary.LittleEndian.Uint16(out[h:]))); err != nil {
				return nil, err
			}
			if err := pointer(h+16, int(binary.LittleEndian.Uint16(out[h+2:]))); err != nil {
				return nil, err
			}
		}
	default:
		return nil, errExUnsupported
	}
	if len(out) > winproto.MaxExtendedBytes {
		return nil, errExUnsupported
	}
	return out, nil
}

// relocateEx turns a portable parameter into the bytes to place at address at (8-byte aligned): the
// same bytes with every pointer member's offset replaced by at plus that offset. Every offset must
// name bytes after the 32-byte structure inside data.
func relocateEx(data []byte, at uint64) ([]byte, error) {
	if len(data) < paramExSize || len(data) > winproto.MaxExtendedBytes {
		return nil, errBadValue
	}
	out := make([]byte, len(data))
	copy(out, data)
	// target checks the offset at data[field:] naming n bytes; 0 is NULL.
	target := func(field, n int) (int, bool) {
		v := binary.LittleEndian.Uint64(data[field:])
		if v == 0 {
			return 0, n == 0
		}
		if v < paramExSize || v > uint64(len(data)) || n < 0 || uint64(n) > uint64(len(data))-v {
			return 0, false
		}
		return int(v), true //nolint:gosec // G115: bounded by len(data)
	}
	reloc := func(field, n int) error {
		v, ok := target(field, n)
		if !ok {
			return errBadValue
		}
		if v != 0 {
			binary.LittleEndian.PutUint64(out[field:], at+uint64(v)) //nolint:gosec // G115: v >= 0
		}
		return nil
	}
	switch binary.LittleEndian.Uint32(data[0:]) {
	case exHTTP2Window, exHTTP2SettingsLimits:
	case exHTTPPerformance:
		if err := reloc(exPointerOff, int(binary.LittleEndian.Uint32(data[20:]))); err != nil {
			return nil, err
		}
	case exTLSRestrictions, exTLSSessionTicketKeys:
		if binary.LittleEndian.Uint64(data[exPointerOff:]) != 0 {
			return nil, errExUnsupported
		}
	case exErrorHeaders:
		count := int(binary.LittleEndian.Uint16(data[18:]))
		first, ok := target(exPointerOff, count*unknownHeaderSize)
		if !ok {
			return nil, errBadValue
		}
		for i := range count {
			h := first + i*unknownHeaderSize
			if err := reloc(h+8, int(binary.LittleEndian.Uint16(data[h:]))); err != nil {
				return nil, err
			}
			if err := reloc(h+16, int(binary.LittleEndian.Uint16(data[h+2:]))); err != nil {
				return nil, err
			}
		}
		if err := reloc(exPointerOff, count*unknownHeaderSize); err != nil {
			return nil, err
		}
	default:
		return nil, errExUnsupported
	}
	return out, nil
}
