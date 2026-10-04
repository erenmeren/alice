// Package netaddrtest is a test helper: a *net.Resolver that answers from a Go function instead of
// the network, so tests can make a host name resolve to any address (DNS rebinding included).
// Production code never imports it.
package netaddrtest

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"strings"
)

// DNS record types and response codes this resolver uses.
const (
	typeA    = 1
	typeAAAA = 28
	rcodeOK  = 0
	rcodeNX  = 3
)

// Resolver returns a resolver (the pure Go one) whose every DNS query is answered by answer: name is
// the queried name without its trailing dot; the IPv4 addresses answer an A query and the IPv6 ones
// an AAAA query; nil means the name does not exist. answer is called once per query (a lookup asks
// for A and AAAA, possibly concurrently), so a test that changes the answer between lookups should
// switch on its own state rather than count calls. /etc/hosts is still consulted first: use names
// that are not in it (the .test top-level domain).
func Resolver(answer func(name string) []netip.Addr) *net.Resolver {
	return &net.Resolver{PreferGo: true, Dial: func(context.Context, string, string) (net.Conn, error) {
		client, server := net.Pipe() // a stream: the resolver frames messages with a 2-byte length
		go serve(server, answer)
		return client, nil
	}}
}

// serve answers the queries sent on c until the resolver closes it.
func serve(c net.Conn, answer func(string) []netip.Addr) {
	defer func() { _ = c.Close() }()
	for {
		var n [2]byte
		if _, err := io.ReadFull(c, n[:]); err != nil {
			return
		}
		q := make([]byte, binary.BigEndian.Uint16(n[:]))
		if _, err := io.ReadFull(c, q); err != nil {
			return
		}
		resp, err := respond(q, answer)
		if err != nil {
			return
		}
		out := binary.BigEndian.AppendUint16(nil, uint16(len(resp))) //nolint:gosec // G115: a DNS message is far below 64 KiB
		if _, err := c.Write(append(out, resp...)); err != nil {
			return
		}
	}
}

// respond builds the answer to one query: its header and question, then one record per address of
// the queried type.
func respond(q []byte, answer func(string) []netip.Addr) ([]byte, error) {
	if len(q) < 12 {
		return nil, errors.New("netaddrtest: short query")
	}
	labels, end := []string{}, 12
	for {
		if end >= len(q) {
			return nil, errors.New("netaddrtest: malformed question")
		}
		l := int(q[end])
		end++
		if l == 0 {
			break
		}
		if end+l > len(q) {
			return nil, errors.New("netaddrtest: malformed question")
		}
		labels = append(labels, string(q[end:end+l]))
		end += l
	}
	if end+4 > len(q) {
		return nil, errors.New("netaddrtest: malformed question")
	}
	qtype := binary.BigEndian.Uint16(q[end : end+2])
	question := q[12 : end+4]
	addrs := answer(strings.Join(labels, "."))
	rcode := uint16(rcodeOK)
	if addrs == nil {
		rcode = rcodeNX
	}
	var records [][]byte
	for _, a := range addrs {
		switch {
		case qtype == typeA && a.Is4():
			b := a.As4()
			records = append(records, b[:])
		case qtype == typeAAAA && a.Is6() && !a.Is4In6():
			b := a.As16()
			records = append(records, b[:])
		}
	}
	resp := binary.BigEndian.AppendUint16(nil, binary.BigEndian.Uint16(q[0:2])) // the query's ID
	resp = binary.BigEndian.AppendUint16(resp, 0x8180|rcode)                    // a response, recursion desired and available
	resp = binary.BigEndian.AppendUint16(resp, 1)                               // one question
	resp = binary.BigEndian.AppendUint16(resp, uint16(len(records)))            //nolint:gosec // G115: a handful of records
	resp = append(resp, 0, 0, 0, 0)                                             // no authority or additional records
	resp = append(resp, question...)
	for _, r := range records {
		resp = append(resp, 0xc0, 12) // the name: a pointer to the question's
		resp = binary.BigEndian.AppendUint16(resp, qtype)
		resp = binary.BigEndian.AppendUint16(resp, 1)              // class IN
		resp = binary.BigEndian.AppendUint32(resp, 60)             // TTL
		resp = binary.BigEndian.AppendUint16(resp, uint16(len(r))) //nolint:gosec // G115: 4 or 16
		resp = append(resp, r...)
	}
	return resp, nil
}
