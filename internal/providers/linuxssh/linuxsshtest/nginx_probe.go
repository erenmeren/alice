package linuxsshtest

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"slices"
	"strconv"
	"strings"
	"time"

	"alice/internal/providers/linuxssh/helperproto"
	"alice/internal/providers/nginx/nginxconf"
)

var (
	errKeyLoad  = errors.New("cannot load certificate key")
	errCertLoad = errors.New("cannot load certificate")
)

// tlsPair checks like nginx -t that the certificate chain and the key load and match.
func tlsPair(certPEM, keyPEM []byte) (tls.Certificate, error) {
	c, err := tls.X509KeyPair(certPEM, keyPEM)
	if err == nil {
		return c, nil
	}
	msg := err.Error()
	switch {
	case strings.Contains(msg, "does not match"):
		return c, err
	case strings.Contains(msg, "certificate input"), strings.Contains(msg, "parse certificate"):
		return c, errors.Join(errCertLoad, err)
	}
	return c, errors.Join(errKeyLoad, err)
}

// certDERs returns the DER bytes of every CERTIFICATE block of data (what Nginx would send).
func certDERs(data []byte) [][]byte {
	var out [][]byte
	for rest := data; ; {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			return out
		}
		if b.Type == "CERTIFICATE" {
			out = append(out, b.Bytes)
		}
	}
}

// served is what a TLS handshake with the emulated host shows.
type served struct {
	leafSHA  string
	chain    int
	notAfter string
	ders     [][]byte // the certificates presented, leaf first (nil for ServeOther's, known only by its hash)
}

// otherNotAfter is the expiry reported for ServeOther's certificate, which the emulator knows
// only by its hash.
const otherNotAfter = "2099-12-31T00:00:00Z"

// servedLocked is the leaf Nginx serves for a connection to addr:port with the given SNI (""/NoSNI:
// none) after its last successful reload: the server Nginx selects among those that listen there
// (exact name, wildcard name, the listen's default server, else the first), and of its pairs the
// first whose certificate, as loaded, has the key type asked for (any: the first). A server whose
// pairs have only the other key type fails the handshake, as does one without a loadable pair.
func (h *nginxHost) servedLocked(addr string, port int, sni, keyType string) (served, bool) {
	if sha, ok := h.other[port]; ok {
		return served{leafSHA: sha, chain: 1, notAfter: otherNotAfter}, true
	}
	cfg, ok := h.liveConfig()
	if !ok {
		return served{}, false
	}
	var exact, wild []listener
	for _, sv := range cfg.Servers {
		if sv.Stream {
			continue
		}
		for _, l := range nginxconf.SSLListens(sv) {
			if l.Port != port || (l.Addr != "" && addr != "" && l.Addr != addr) {
				continue
			}
			x := listener{sv: sv, def: l.DefaultServer}
			wild = append(wild, x)
			if addr != "" && l.Addr == addr {
				exact = append(exact, x)
			}
		}
	}
	cands := wild
	if len(exact) > 0 {
		cands = exact
	}
	l, ok := selectServer(cands, sni)
	if !ok {
		return served{}, false
	}
	for _, p := range l.sv.Pairs {
		if p.Cert == "" {
			continue
		}
		ders := certDERs(h.loaded[p.Cert].bytes())
		if len(ders) == 0 {
			continue
		}
		leaf, err := x509.ParseCertificate(ders[0])
		if err != nil {
			continue
		}
		switch keyType {
		case helperproto.ProbeRSA:
			if _, ok := leaf.PublicKey.(*rsa.PublicKey); !ok {
				continue
			}
		case helperproto.ProbeECDSA:
			if _, ok := leaf.PublicKey.(*ecdsa.PublicKey); !ok {
				continue
			}
		}
		return served{leafSHA: sum(leaf.Raw), chain: len(ders), notAfter: leaf.NotAfter.UTC().Format(time.RFC3339), ders: ders}, true
	}
	return served{}, false
}

// listener is one server block as it listens on one address and port.
type listener struct {
	sv  nginxconf.Server
	def bool
}

// selectServer is Nginx's choice among the servers of one listen: an exact server_name, then a
// leading-wildcard one, then the default_server, else the first.
func selectServer(cands []listener, sni string) (listener, bool) {
	if len(cands) == 0 {
		return listener{}, false
	}
	if sni != "" && sni != helperproto.NoSNI {
		for _, c := range cands {
			if slices.Contains(c.sv.Names, sni) {
				return c, true
			}
		}
		for _, c := range cands {
			for _, n := range c.sv.Names {
				if rest, ok := strings.CutPrefix(n, "*"); ok && strings.HasPrefix(rest, ".") && strings.HasSuffix(sni, rest) && len(sni) > len(rest) {
					return c, true
				}
			}
		}
	}
	for _, c := range cands {
		if c.def {
			return c, true
		}
	}
	return cands[0], true
}

// chainProtocol is the first helper protocol whose tls-probe answers the presented chain (R51): an
// emulator set to an older protocol (SetProtocol) answers without it.
const chainProtocol = 11

// tlsProbe answers tls-probe (the helper's cmdTLSProbe), which runs without sudo.
func (e *Emulator) tlsProbe(args []string) Response {
	if len(args) != 8 || args[0] != "--addr" || args[2] != "--port" || args[4] != "--sni" || args[6] != "--key-type" {
		return refuse(helperproto.ExitRefused, helperproto.CodeUsage)
	}
	addr, port, sni, kt := args[1], args[3], args[5], args[7]
	if !helperproto.ValidIP(addr) || !helperproto.ValidPort(port) || (sni != helperproto.NoSNI && !helperproto.ValidSNI(sni)) ||
		(kt != helperproto.ProbeAny && kt != helperproto.ProbeRSA && kt != helperproto.ProbeECDSA) {
		return refuse(helperproto.ExitRefused, helperproto.CodeInvalidArgument)
	}
	n, _ := strconv.Atoi(port)
	e.mu.Lock()
	defer e.mu.Unlock()
	h := e.nginx()
	if h.probeFails {
		return refuse(helperproto.ExitFailed, helperproto.CodeProbeFailed)
	}
	s, ok := h.servedLocked(addr, n, sni, kt)
	if !ok {
		return refuse(helperproto.ExitFailed, helperproto.CodeProbeFailed)
	}
	r := helperproto.TLSProbeResponse{OK: true, LeafSHA256: s.leafSHA, ChainLength: s.chain, NotAfter: s.notAfter}
	if e.protocol >= chainProtocol {
		r.Chain = helperproto.ProbeChain(s.ders)
	}
	return answer(r)
}
