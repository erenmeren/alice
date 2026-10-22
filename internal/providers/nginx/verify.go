package nginx

import (
	"context"
	"net/netip"
	"strconv"

	"alice/internal/providers"
	"alice/internal/providers/linuxssh"
	"alice/internal/providers/linuxssh/helperproto"
	"alice/internal/providers/tlsverify"
)

// maxEndpoints bounds the (port, name) pairs one verification probes.
const maxEndpoints = 10

// Verification reasons (VerifyResult.Reason, and the Reason of a deployment whose verification
// failed): tlsverify's, under the names deploy.go and the tests use.
const (
	reasonVerifyFailed      = tlsverify.ReasonVerifyFailed      // the previous certificate is still served (F-05)
	reasonVerifyOther       = tlsverify.ReasonVerifyOther       // neither the expected nor the previous one (F-06)
	reasonVerifyUnreachable = tlsverify.ReasonVerifyUnreachable // neither Alice nor the server could complete a handshake (param port)
	reasonVerifyChain       = tlsverify.ReasonVerifyChain       // the expected leaf, another chain length (param port)
	reasonVerifyUntrusted   = tlsverify.ReasonVerifyUntrusted   // the expected chain does not verify (params port, trust_error)
)

// Endpoint is one (port, name, listen address) Alice checks after a deployment (tlsverify.Endpoint).
type Endpoint = tlsverify.Endpoint

// SNIFor chooses the server name a probe sends (spec §12.8 item 1; tlsverify.SNIFor): the first
// usable server_name, else the first usable SAN of the certificate.
func SNIFor(names, sans []string) string { return tlsverify.SNIFor(names, sans) }

// asciiLower lower-cases ASCII letters only (tlsverify.ASCIILower).
var asciiLower = tlsverify.ASCIILower

// localAddr is where tls-probe connects on the server for a listen address: the loopback address
// for "any" (IPv6 for "::"), the address itself for a literal, the IPv4 loopback for a host name.
func localAddr(addr string) string {
	a, err := netip.ParseAddr(addr)
	switch {
	case err != nil || a.Zone() != "":
		return "127.0.0.1"
	case a.IsUnspecified() && a.Is6():
		return "::1"
	case a.IsUnspecified():
		return "127.0.0.1"
	}
	if s := a.String(); helperproto.ValidIP(s) {
		return s
	}
	return "127.0.0.1"
}

// listenAddr is a listen address with every "any address" spelling as "".
func listenAddr(addr string) string {
	if a, err := netip.ParseAddr(addr); err == nil && a.IsUnspecified() {
		return ""
	}
	if addr == "*" {
		return ""
	}
	return addr
}

// probeFromAlice reports whether Alice's own probe of host reaches the endpoint's listen
// (tlsverify.ProbeFromAlice).
func probeFromAlice(ep Endpoint, host string) bool { return tlsverify.ProbeFromAlice(ep, host) }

// Endpoints lists the endpoints of a location to verify, deduplicated by port, name and listen
// address (every spelling of "any address" is one), in the order of its servers and listens, at most
// maxEndpoints. The options override the port of every listen and the name of every server.
func Endpoints(loc providers.CertLocation, v providers.VerifyOptions, sans []string) []Endpoint {
	var out []Endpoint
	seen := map[string]bool{}
	for _, srv := range loc.Servers {
		sni := v.SNI
		if sni == "" {
			sni = SNIFor(srv.Names, sans)
		}
		for _, l := range srv.Listens {
			port := l.Port
			if v.Port != 0 {
				port = v.Port
			}
			listen := listenAddr(l.Addr)
			k := strconv.Itoa(port) + "\x00" + sni + "\x00" + listen
			if seen[k] {
				continue
			}
			seen[k] = true
			out = append(out, Endpoint{Port: port, SNI: sni, Addr: localAddr(l.Addr), Listen: listen})
			if len(out) == maxEndpoints {
				return out
			}
		}
	}
	return out
}

// isHexSHA256 is a SHA-256 in lower-case hex (helperproto.ValidSHA256 also accepts its "absent"
// marker, which no probe or journal hash may be).
func isHexSHA256(s string) bool { return s != helperproto.AbsentSHA256 && helperproto.ValidSHA256(s) }

// served is one probe's answer (tlsverify.Served).
type served = tlsverify.Served

// VerifyDeployment checks which certificate the location serves (spec §12.8; R38 item 6) and, with
// a trust policy, whether the served chains verify (R51): the location's endpoints (Endpoints) are
// judged by tlsverify.Verify, with Alice's own probe (the provider's Prober, to the target's
// address), the helper's tls-probe as the server-side probe (serverProbe), the provider's attempts
// and retry wait, the session's clock and logger. See tlsverify.Verify for where each endpoint is
// probed, the retries, the second probe by key type, the reasons, levels and trust.
//
// The error is a *providers.Error for a closed session, a cancelled ctx (ssh.timeout, wrapping the
// context's error) or a failure of the SSH connection during a server-side probe; a website that
// cannot be reached is a result, not an error.
func (s *session) VerifyDeployment(ctx context.Context, req providers.VerifyRequest) (providers.VerifyResult, error) {
	if err := s.Live(); err != nil {
		return providers.VerifyResult{}, err
	}
	return tlsverify.Verify(ctx, s.host, Endpoints(req.Location, req.Verify, req.SANs), req, s.p.prober, s.serverProbe, s.verifyOptions())
}

// verifyOptions are the provider's attempts and retry wait with the session's clock and logger.
func (s *session) verifyOptions() tlsverify.Options {
	return tlsverify.Options{Attempts: s.p.attempts, RetryWait: s.p.retryWait, Clock: s.clock, Log: s.log}
}

// probeOnce probes an endpoint once, from Alice unless *localOnly, then from the server
// (tlsverify.ProbeOnce).
func (s *session) probeOnce(ctx context.Context, ep Endpoint, keyType string, localOnly *bool) (served, bool, error) {
	return tlsverify.ProbeOnce(ctx, s.host, ep, keyType, localOnly, s.p.prober, s.serverProbe, s.verifyOptions())
}

// serverProbe is the server-side probe (tlsverify.ServerProbe): the helper's tls-probe, without
// sudo, against ep.Addr. reached is false for an endpoint not expressible as a tls-probe (a port out
// of range), PROBE_FAILED, or an answer that does not decode; the error is a failure of the SSH
// connection. tlsverify checks the answer (leaf, chain bound, chain against its length).
func (s *session) serverProbe(ctx context.Context, ep Endpoint, keyType string) (served, bool, error) {
	cmd, err := linuxssh.CmdTLSProbe(ep.Addr, ep.Port, ep.SNI, keyType)
	if err != nil {
		return served{}, false, nil // not expressible as a server-side probe (a port out of range): not reached
	}
	out, err := s.Conn().Run(ctx, cmd)
	if err != nil {
		return served{}, false, err
	}
	r, err := linuxssh.DecodeHelper[helperproto.TLSProbeResponse](out, helperproto.SubTLSProbe)
	if err != nil {
		return served{}, false, nil // PROBE_FAILED, or an answer Alice cannot use: not reached
	}
	sv := served{Leaf: r.LeafSHA256, Chain: r.ChainLength}
	if ders, ok := helperproto.DecodeProbeChain(r.Chain); ok {
		sv.DERs = ders
	}
	return sv, true, nil
}
