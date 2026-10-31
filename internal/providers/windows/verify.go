package windows

import (
	"context"
	"encoding/json"
	"net/netip"
	"strconv"

	"alice/internal/providers"
	"alice/internal/providers/linuxssh"
	"alice/internal/providers/linuxssh/helperproto"
	"alice/internal/providers/tlsverify"
	"alice/internal/providers/windows/winproto"
)

// maxEndpoints bounds the (port, name, listen) triples one verification probes (Nginx's bound).
const maxEndpoints = 10

// locatorOf reads a win_sslbinding location's locator into the protocol's Locator (a port stored as
// JSON reads back as a float64, or as the json.Number of providers.ParseLocator: inventory's form). ok is false for a locator that is not one Alice deploys to (W2 Ruling
// 5: winproto.Locator.Canonical: a ccs record, a host that is not an ASCII lower-case name, an IP not in
// its canonical form, a port outside 1-65535, an application id that is not a braced GUID).
func locatorOf(loc providers.CertLocation) (winproto.Locator, bool) {
	l := winproto.Locator{}
	l.Type, _ = loc.Locator["type"].(string)
	l.IP, _ = loc.Locator["ip"].(string)
	l.Host, _ = loc.Locator["host"].(string)
	l.AppID, _ = loc.Locator["app_id"].(string)
	l.Port = locatorPort(loc.Locator["port"])
	_, ok := l.Canonical()
	return l, ok
}

// locatorPort is a locator's port as Go or inventory holds it (an int, a JSON float64, providers.ParseLocator's
// json.Number); 0 for anything outside 1-65535.
func locatorPort(v any) int {
	switch p := v.(type) {
	case int:
		if p > 0 && p <= 65535 {
			return p
		}
	case int64:
		if p > 0 && p <= 65535 {
			return int(p)
		}
	case float64:
		if p == float64(int(p)) && p > 0 && p <= 65535 {
			return int(p)
		}
	case json.Number: // the locator as inventory stored it (providers.ParseLocator)
		if n, err := p.Int64(); err == nil && n > 0 && n <= 65535 {
			return int(n)
		}
	}
	return 0
}

// Endpoints lists the endpoints of a Windows location to verify (W2 Ruling 15), deduplicated by port,
// name and listen address, at most maxEndpoints:
//
//   - hostnameport: the binding's port with SNI = its host (SNIFor: a "*." host becomes alice-check.),
//     listening on every address; the helper's probe connects to 127.0.0.1;
//   - ipport on 0.0.0.0 or [::]: the port, one endpoint per distinct SNI of the IIS sites' host
//     headers that use the record (SNIFor of each server's names, then the certificate's SANs), at
//     least one (the SANs alone when no site names a host); the helper's probe connects to 127.0.0.1
//     or ::1;
//   - ipport on a specific address: as the wildcard, but listening on that address only, so Alice's
//     own probe stands for it only when it connects to that address (tlsverify.ProbeFromAlice); the
//     helper's probe connects to the address itself (tls-probe --addr <ip>).
//
// The Administrator's options apply: v.Port replaces the port, v.SNI every name, and v.Address (the
// probe address) makes Alice's own probe, which then connects there, stand for every endpoint. A locator
// Alice does not deploy to has no endpoints (the verification is then unreachable). A CCS file's endpoints
// are its linked IIS bindings (ccsEndpoints, W5 Ruling 20), the RDP listener's its one port (rdpEndpoints, W6 Ruling 16).
func Endpoints(loc providers.CertLocation, v providers.VerifyOptions, sans []string) []tlsverify.Endpoint {
	switch loc.Kind {
	case providers.LocationWinCCSFile:
		return ccsEndpoints(loc, v, sans)
	case providers.LocationWinRDP:
		return rdpEndpoints(loc, v, sans)
	}
	l, ok := locatorOf(loc)
	if !ok {
		return nil
	}
	port := l.Port
	if v.Port != 0 {
		port = v.Port
	}
	var names [][]string
	addr, listen := "127.0.0.1", ""
	switch l.Type {
	case winproto.BindingHostnamePort:
		names = [][]string{{l.Host}}
	default: // ipport (Canonical refused everything else)
		ip := netip.MustParseAddr(l.IP)
		switch {
		case ip.IsUnspecified() && ip.Is6():
			addr = "::1"
		case !ip.IsUnspecified():
			addr, listen = ip.String(), ip.String()
		}
		for _, srv := range loc.Servers {
			names = append(names, srv.Names)
		}
		if len(names) == 0 {
			names = [][]string{nil}
		}
	}
	if v.Address != "" {
		listen = ""
	}
	var out []tlsverify.Endpoint
	seen := map[string]bool{}
	for _, n := range names {
		sni := v.SNI
		if sni == "" {
			sni = tlsverify.SNIFor(n, sans)
		}
		k := strconv.Itoa(port) + "\x00" + sni
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, tlsverify.Endpoint{Port: port, SNI: sni, Addr: addr, Listen: listen})
		if len(out) == maxEndpoints {
			break
		}
	}
	return out
}

// VerifyDeployment checks which certificate the location serves (spec §12.8, design §6.4) and, with a
// trust policy, whether the served chains verify (R51): the location's endpoints (Endpoints) are judged
// by tlsverify.Verify with Alice's own probe (the provider's Prober, to the target's address or the
// Administrator's probe address), the helper's tls-probe as the server-side probe (serverProbe), the
// provider's attempts and retry wait, the session's clock and logger. Every probe is a fresh handshake
// (tlsverify.TLSProber keeps no session cache); the attempts cover the first handshake after a bind.
//
// The error is a *providers.Error for a closed session, a cancelled ctx (ssh.timeout) or a failure of
// the SSH connection during a server-side probe; a website that cannot be reached is a result.
func (s *session) VerifyDeployment(ctx context.Context, req providers.VerifyRequest) (providers.VerifyResult, error) {
	if !s.caps.Has(providers.CapVerifyDeployment) {
		return providers.VerifyResult{}, providers.ErrUnsupported
	}
	if err := s.open(); err != nil {
		return providers.VerifyResult{}, err
	}
	if unlinkedCCS(req.Location) && !req.Verify.Skip && ctx.Err() == nil {
		// W5 Ruling 8: no IIS binding serves the file; ccs-deploy's read-back is its only check (R51 level 1).
		return providers.VerifyResult{OK: true, Mode: "skipped", Level: providers.LevelInstalled, Params: map[string]string{ccsUnlinkedParam: "true"}}, nil
	}
	host := s.cfg.Host
	if req.Verify.Address != "" {
		host = req.Verify.Address
	}
	// The RDP listener is probed after the RDP negotiation, by Alice and by the helper (W6 Ruling 15).
	prober, server := s.p.prober, s.serverProbe
	if req.Location.Kind == providers.LocationWinRDP {
		prober, server = s.p.rdpProber, s.rdpServerProbe
	}
	// A CCS file's attempts span winproto.CCSPickupWait, the RDP listener's RDPPickupWait (verifyAttempts, F15, F20).
	return tlsverify.Verify(ctx, host, Endpoints(req.Location, req.Verify, req.SANs), req, prober, server,
		tlsverify.Options{Attempts: s.p.verifyAttempts(req.Location.Kind), RetryWait: s.p.retryWait, Clock: s.clock, Log: s.log})
}

// serverProbe is the server-side probe (tlsverify.ServerProbe): the helper's tls-probe against ep.Addr
// on a connection of its own (W1 Ruling 5). reached is false for an endpoint not expressible as a
// tls-probe, a helper refusal (PROBE_FAILED among them) or an answer that does not decode; the error is
// a failure of the SSH connection (it cannot be opened, or the command could not complete). tlsverify
// checks the answer (leaf, chain bound, chain against its length).
func (s *session) serverProbe(ctx context.Context, ep tlsverify.Endpoint, keyType string) (tlsverify.Served, bool, error) {
	return s.probeWith(ctx, ep, keyType)
}

// probeWith is serverProbe with extra trailing arguments of tls-probe (the RDP probe's --rdp).
func (s *session) probeWith(ctx context.Context, ep tlsverify.Endpoint, keyType string, extra ...string) (tlsverify.Served, bool, error) {
	sni := ep.SNI
	if sni == "" {
		sni = helperproto.NoSNI
	}
	c, err := cmd(winproto.SubTLSProbe, nil, append([]string{"--addr", ep.Addr, "--port", strconv.Itoa(ep.Port), "--sni", sni, "--key-type", keyType}, extra...)...)
	if err != nil || !helperproto.ValidIP(ep.Addr) || !helperproto.ValidPort(strconv.Itoa(ep.Port)) ||
		(sni != helperproto.NoSNI && !helperproto.ValidSNI(sni)) {
		return tlsverify.Served{}, false, nil
	}
	conn, release, err := s.pool.AcquireFresh(ctx, s.target, s.cfg.Config, s.cred)
	if err != nil {
		return tlsverify.Served{}, false, err
	}
	res, err := conn.Run(ctx, c)
	release(false)
	if err != nil {
		return tlsverify.Served{}, false, mapHelper(err)
	}
	r, err := linuxssh.DecodeHelper[winproto.TLSProbeResponse](res, winproto.SubTLSProbe)
	if err != nil {
		return tlsverify.Served{}, false, nil
	}
	sv := tlsverify.Served{Leaf: r.LeafSHA256, Chain: r.ChainLength}
	if ders, ok := helperproto.DecodeProbeChain(r.Chain); ok {
		sv.DERs = ders
	}
	return sv, true, nil
}

// unverifiable is the result of a verification that could not be made (Nginx's): the port of the first
// endpoint, else the Administrator's, else 443.
func unverifiable(loc providers.CertLocation, v providers.VerifyOptions, sans []string) providers.VerifyResult {
	port := v.Port
	if eps := Endpoints(loc, v, sans); len(eps) > 0 {
		port = eps[0].Port
	}
	if port == 0 {
		port = 443
	}
	return providers.VerifyResult{Reason: reasonVerifyUnreachable, Params: map[string]string{"port": strconv.Itoa(port)},
		Failure: providers.VerifyFailureNetwork}
}
