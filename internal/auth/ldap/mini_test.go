package ldap

import (
	"crypto/tls"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
	goldap "github.com/go-ldap/ldap/v3"

	"alice/internal/testutil/pki"
)

// miniEntry is one search result entry of the in-process server.
type miniEntry struct {
	dn    string
	attrs map[string][]string
}

// miniServer is an in-process LDAP server over TLS for the cases a real OpenLDAP cannot be made to show: a server
// that never answers, a referral result, a server that ignores the size limit, search references.
type miniServer struct {
	t     *testing.T
	ln    net.Listener
	ca    *pki.CA
	conns atomic.Int64

	mu         sync.Mutex
	silent     bool              // accept, finish TLS and never answer an LDAP request
	noTLS      bool              // accept and never start TLS (the handshake hangs)
	bindCode   map[string]uint16 // bind DN -> result code (default success)
	entries    func(base, filter string) []miniEntry
	references []string
	doneCode   uint16
	endless    bool         // answer a search with an entry whose value never ends
	sent       atomic.Int64 // bytes written by endless
	binds      []string     // bind DNs seen
	filters    []string     // search filters seen
	sizeLimits []int64
}

// startMini listens on 127.0.0.1 with a certificate for localhost and 127.0.0.1 from its own CA.
func startMini(t *testing.T) *miniServer {
	t.Helper()
	now := time.Now()
	ca := pki.NewCA("mini", pki.ECDSA256, now)
	leaf := ca.Issue(pki.Opts{CommonName: "localhost", SANs: []string{"localhost", "127.0.0.1"}}, now)
	cert, err := tls.X509KeyPair(leaf.FullchainPEM, leaf.KeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	m := &miniServer{t: t, ln: ln, ca: ca, bindCode: map[string]uint16{},
		entries: func(string, string) []miniEntry { return nil }}
	cfg := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			m.conns.Add(1)
			go m.serve(c, cfg)
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return m
}

func (m *miniServer) address() string { return "ldaps://" + m.ln.Addr().String() }

func (m *miniServer) set(f func(m *miniServer)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	f(m)
}

func (m *miniServer) serve(raw net.Conn, cfg *tls.Config) {
	defer func() { _ = raw.Close() }()
	m.mu.Lock()
	noTLS, silent := m.noTLS, m.silent
	m.mu.Unlock()
	if noTLS {
		_, _ = io.Copy(io.Discard, raw) // read the client hello and answer nothing, until the client gives up
		return
	}
	c := tls.Server(raw, cfg)
	_ = c.SetDeadline(time.Now().Add(30 * time.Second))
	for {
		p, err := ber.ReadPacket(c)
		if err != nil || len(p.Children) < 2 {
			return
		}
		if silent {
			continue
		}
		id := p.Children[0].Value.(int64)
		op := p.Children[1]
		switch op.Tag {
		case goldap.ApplicationBindRequest:
			dn, _ := op.Children[1].Value.(string)
			m.mu.Lock()
			m.binds = append(m.binds, dn)
			code := m.bindCode[dn]
			m.mu.Unlock()
			m.write(c, id, result(goldap.ApplicationBindResponse, code))
		case goldap.ApplicationSearchRequest:
			base := op.Children[0].Value.(string)
			size := op.Children[3].Value.(int64)
			f, _ := goldap.DecompileFilter(op.Children[6])
			m.mu.Lock()
			m.filters = append(m.filters, f)
			m.sizeLimits = append(m.sizeLimits, size)
			entries, refs, done, endless := m.entries(base, f), m.references, m.doneCode, m.endless
			m.mu.Unlock()
			if endless {
				m.stream(c, id)
				return
			}
			for _, ref := range refs {
				r := ber.Encode(ber.ClassApplication, ber.TypeConstructed, goldap.ApplicationSearchResultReference, nil, "ref")
				r.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, ref, "uri"))
				m.write(c, id, r)
			}
			for _, e := range entries {
				m.write(c, id, entryPacket(e))
			}
			m.write(c, id, result(goldap.ApplicationSearchResultDone, done))
		case goldap.ApplicationUnbindRequest:
			return
		}
	}
}

// stream starts an entry that announces a value of almost 1 GiB and sends zeros until the client goes away.
func (m *miniServer) stream(c net.Conn, id int64) {
	const value = 0x3f000000
	be := func(n int) []byte { return []byte{byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)} }
	head := append([]byte{0x30, 0x84}, be(3+6+6+value)...)
	head = append(head, 0x02, 0x01, byte(id))
	head = append(append(head, 0x64, 0x84), be(6+value)...)
	head = append(append(head, 0x04, 0x84), be(value)...)
	if _, err := c.Write(head); err != nil {
		return
	}
	chunk := make([]byte, 64<<10)
	for {
		n, err := c.Write(chunk)
		m.sent.Add(int64(n))
		if err != nil {
			return
		}
	}
}

func (m *miniServer) write(c net.Conn, id int64, op *ber.Packet) {
	env := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP message")
	env.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, id, "id"))
	env.AppendChild(op)
	_, _ = c.Write(env.Bytes())
}

func result(tag ber.Tag, code uint16) *ber.Packet {
	r := ber.Encode(ber.ClassApplication, ber.TypeConstructed, tag, nil, "result")
	r.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, uint64(code), "code"))
	r.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "matched"))
	r.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "diagnostic"))
	if code == goldap.LDAPResultReferral {
		refs := ber.Encode(ber.ClassContext, ber.TypeConstructed, 3, nil, "referral")
		refs.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "ldaps://elsewhere.example.test/", "uri"))
		r.AppendChild(refs)
	}
	return r
}

func entryPacket(e miniEntry) *ber.Packet {
	r := ber.Encode(ber.ClassApplication, ber.TypeConstructed, goldap.ApplicationSearchResultEntry, nil, "entry")
	r.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, e.dn, "dn"))
	attrs := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "attributes")
	for k, vs := range e.attrs {
		a := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "attribute")
		a.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, k, "type"))
		set := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSet, nil, "values")
		for _, v := range vs {
			set.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, v, "value"))
		}
		a.AppendChild(set)
		attrs.AppendChild(a)
	}
	r.AppendChild(attrs)
	return r
}
