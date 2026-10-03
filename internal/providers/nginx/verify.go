package nginx

import (
	"context"
	"errors"
	"net/netip"
	"strconv"
	"strings"

	"alice/internal/providers"
	"alice/internal/providers/linuxssh"
	"alice/internal/providers/linuxssh/helperproto"
)

// maxEndpoints bounds the (port, name) pairs one verification probes.
const maxEndpoints = 10

// Verification reasons (VerifyResult.Reason, and the Reason of a deployment whose verification
// failed). reasonVerifyChain is an addition to the plan's contract (spec §12.8 item 5): the new leaf
// is served, but with another number of certificates than the deployed chain has.
const (
	reasonVerifyFailed      = "deployment.verify_failed"      // the previous certificate is still served (F-05)
	reasonVerifyOther       = "deployment.verify_other"       // neither the expected nor the previous one (F-06)
	reasonVerifyUnreachable = "deployment.verify_unreachable" // neither Alice nor the server could complete a handshake (param port)
	reasonVerifyChain       = "deployment.verify_chain"       // the expected leaf, another chain length (param port)
)

// Endpoint is one (port, name, listen address) Alice checks after a deployment.
type Endpoint struct {
	Port int
	SNI  string // "" = no server name (helperproto.NoSNI on the helper's command line)
	Addr string // where the server-side probe (tls-probe) connects: an IP literal
	// Listen is the listen address ("" for any address: "*", "0.0.0.0", "::", none). It decides
	// whether Alice's own probe stands for the endpoint (probeFromAlice). An addition to the plan's
	// struct.
	Listen string
}

// SNIFor chooses the server name a probe sends (spec §12.8 item 1): the first usable server_name,
// else the first usable SAN of the certificate. Regex names (~…), "_" and "" are skipped; a
// leading wildcard "*.d" becomes "alice-check.d" (any name the wildcard covers selects the same
// server block), a leading dot ".d" becomes "d"; names are lower-cased (ASCII). An IP literal is
// never a server name (RFC 6066; helperproto.ValidSNI refuses it, D18). "" means no SNI.
func SNIFor(names, sans []string) string {
	for _, list := range [][]string{names, sans} {
		for _, n := range list {
			if sni := sniCandidate(n); sni != "" {
				return sni
			}
		}
	}
	return ""
}

func sniCandidate(n string) string {
	n = asciiLower(n)
	switch {
	case n == "" || n == "_" || strings.HasPrefix(n, "~"):
		return ""
	case strings.HasPrefix(n, "*."):
		n = "alice-check." + n[2:]
	case strings.HasPrefix(n, "."):
		n = n[1:]
	}
	if strings.Contains(n, "*") || !helperproto.ValidSNI(n) {
		return ""
	}
	return n
}

// asciiLower lower-cases ASCII letters only (host names; strings.ToLower is forbidden by the lint
// rule for user-visible text and is not needed for DNS names).
func asciiLower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 'a' - 'A'
		}
	}
	return string(b)
}

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

// probeFromAlice reports whether Alice's own probe of host (the target's address) reaches the
// endpoint's listen, so that its answer stands for the endpoint: a listen on any address, or on the
// address Alice connects to (the same IP, or the same host name ignoring case). A listen on another
// specific address, loopback among them, is not reached by a connection to host: another server
// block may answer there, so only the server-side probe against that address is the authority.
func probeFromAlice(ep Endpoint, host string) bool {
	if ep.Listen == "" {
		return true
	}
	l, lerr := netip.ParseAddr(ep.Listen)
	h, herr := netip.ParseAddr(host)
	if lerr == nil || herr == nil {
		return lerr == nil && herr == nil && l.Unmap() == h.Unmap() && l.Zone() == h.Zone()
	}
	return asciiLower(ep.Listen) == asciiLower(host)
}

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

// served is one probe's answer: the leaf's hex SHA-256 and the number of certificates presented.
type served struct {
	leaf  string
	chain int
	local bool // answered by the server-side probe
}

// VerifyDeployment checks which certificate the location serves (spec §12.8; R38 item 6).
//
// Where each endpoint (Endpoints) is probed: Alice's own probe (TLSProber, to the target's address)
// stands for an endpoint only when it reaches that listen (probeFromAlice): a listen on any address
// ("*", "0.0.0.0", "::" or none), or on the address Alice connects to. Then Alice probes first and
// the server itself (tls-probe) when Alice cannot connect or complete a handshake. A listen on
// another specific address, loopback among them, is probed only from the server, against that
// address: a connection to the target's address would be answered by another server block. (Unix
// sockets are not TLS listens of a location; the parser drops them.)
//
// How: every probe uses helperproto.ProbeAny first, so TLS 1.3-only websites answer (D15). When the
// leaf served is not the expected one and req.KeyType is rsa or ecdsa, a second probe of that key
// type (TLS 1.2 with that key type's suites) asks a dual-certificate server for the certificate of
// the deployed type (spec §12.8 item 4); it decides only when it shows the expected leaf. An
// endpoint that does not serve the expected leaf yet is probed again, up to Options.Attempts times
// Options.RetryWait apart (old workers answer for a moment after a graceful reload).
//
// Two uses, told apart by req.Fingerprint:
//   - a verification (Fingerprint set; DeployCertificate always sets it to the deployed leaf, and the
//     deploy engine's pre-check passes the currently deployed fingerprint and key type): every
//     endpoint is compared, the leaf's SHA-256 with Fingerprint and, when req.ChainLength > 0, the
//     number of certificates presented (spec §12.8 item 5); OK only when every endpoint serves it.
//     Reasons: reasonVerifyFailed (the previous leaf is served), reasonVerifyOther,
//     reasonVerifyChain, reasonVerifyUnreachable (no handshake either way; also for a location
//     without endpoints), each with param port of the first endpoint that failed;
//   - a query (Fingerprint ""): nothing is compared. OK means only that every endpoint completed a
//     handshake; Served and ServedChainLength are the first endpoint's answer, and endpoints that
//     serve other leaves are not reported. It is never a pass of a deployment.
//
// Nothing of a probe but the leaf's SHA-256 and the chain length is trusted. The error is a
// *providers.Error for a cancelled ctx (ssh.timeout, wrapping the context's error) or a failure of
// the SSH connection during a server-side probe; a website that cannot be reached is a result, not
// an error.
func (s *session) VerifyDeployment(ctx context.Context, req providers.VerifyRequest) (providers.VerifyResult, error) {
	if err := s.open(); err != nil {
		return providers.VerifyResult{}, err
	}
	if err := ctx.Err(); err != nil {
		return providers.VerifyResult{}, providers.NewError("ssh.timeout", true, err, nil)
	}
	if req.Verify.Skip {
		return providers.VerifyResult{OK: true, Mode: "skipped"}, nil
	}
	eps := Endpoints(req.Location, req.Verify, req.SANs)
	if len(eps) == 0 {
		port := req.Verify.Port
		if port == 0 {
			port = 443
		}
		return providers.VerifyResult{Reason: reasonVerifyUnreachable, Params: map[string]string{"port": strconv.Itoa(port)}}, nil
	}
	res := providers.VerifyResult{OK: true, Mode: "remote"}
	for i, ep := range eps {
		sv, reached, err := s.probeEndpoint(ctx, ep, req)
		if err != nil {
			return providers.VerifyResult{}, err
		}
		params := map[string]string{"port": strconv.Itoa(ep.Port)}
		if !reached {
			return providers.VerifyResult{Reason: reasonVerifyUnreachable, Params: params}, nil
		}
		if sv.local {
			res.Mode = "local"
		}
		if i == 0 {
			res.Served, res.ServedChainLength = sv.leaf, sv.chain
		}
		if req.Fingerprint == "" {
			continue
		}
		if reason := mismatch(sv, req); reason != "" {
			return providers.VerifyResult{Mode: res.Mode, Served: sv.leaf, ServedChainLength: sv.chain, Reason: reason, Params: params}, nil
		}
	}
	return res, nil
}

// mismatch is the reason a served answer is not the expected one ("" when it is).
func mismatch(sv served, req providers.VerifyRequest) string {
	switch {
	case sv.leaf == req.Fingerprint && (req.ChainLength <= 0 || sv.chain == req.ChainLength):
		return ""
	case sv.leaf == req.Fingerprint:
		return reasonVerifyChain
	case req.PreviousFingerprint != "" && sv.leaf == req.PreviousFingerprint:
		return reasonVerifyFailed
	}
	return reasonVerifyOther
}

// probeEndpoint returns what an endpoint serves. reached is false when no attempt completed a
// handshake, from Alice or from the server. Once Alice cannot connect at all (ErrProbeUnreachable)
// the endpoint is probed from the server only. A failed handshake (ErrProbeFailed) is treated like
// a mismatch: the server-side probe is tried in the same attempt, and the endpoint again in the
// next. The error is a cancelled ctx or a failure of the SSH connection.
func (s *session) probeEndpoint(ctx context.Context, ep Endpoint, req providers.VerifyRequest) (last served, reached bool, err error) {
	typed := ""
	if req.KeyType == helperproto.ProbeRSA || req.KeyType == helperproto.ProbeECDSA {
		typed = req.KeyType
	}
	localOnly := !probeFromAlice(ep, s.host)
	for attempt := 1; attempt <= s.p.attempts; attempt++ {
		sv, ok, err := s.probeOnce(ctx, ep, helperproto.ProbeAny, &localOnly)
		if err != nil {
			return served{}, false, err
		}
		if ok {
			last, reached = sv, true
			if req.Fingerprint == "" || mismatch(sv, req) == "" {
				return sv, true, nil
			}
			if typed != "" {
				// A dual-certificate server may have answered the any-probe with its other pair.
				tv, tok, err := s.probeOnce(ctx, ep, typed, &localOnly)
				if err != nil {
					return served{}, false, err
				}
				if tok && mismatch(tv, req) == "" {
					return tv, true, nil
				}
			}
		}
		if attempt == s.p.attempts {
			break
		}
		select {
		case <-ctx.Done():
			return served{}, false, providers.NewError("ssh.timeout", true, ctx.Err(), nil)
		case <-s.clock.After(s.p.retryWait):
		}
	}
	return last, reached, nil
}

// probeOnce probes an endpoint once: from Alice unless *localOnly, then from the server when
// Alice's probe failed (ErrProbeUnreachable sets *localOnly for the next attempts). ok is false
// when neither completed a handshake.
func (s *session) probeOnce(ctx context.Context, ep Endpoint, keyType string, localOnly *bool) (served, bool, error) {
	if !*localOnly {
		pr, err := s.p.prober.Probe(ctx, s.host, ep.Port, ep.SNI, keyType)
		switch {
		case ctx.Err() != nil:
			return served{}, false, providers.NewError("ssh.timeout", true, ctx.Err(), nil)
		case err == nil && isHexSHA256(pr.LeafSHA256) && pr.ChainLength >= 1:
			return served{leaf: pr.LeafSHA256, chain: pr.ChainLength}, true, nil
		case errors.Is(err, ErrProbeUnreachable):
			*localOnly = true
		}
	}
	cmd, err := linuxssh.CmdTLSProbe(ep.Addr, ep.Port, ep.SNI, keyType)
	if err != nil {
		return served{}, false, nil // not expressible as a server-side probe (a port out of range): not reached
	}
	out, err := s.conn.Run(ctx, cmd)
	if err != nil {
		return served{}, false, err
	}
	r, err := linuxssh.DecodeHelper[helperproto.TLSProbeResponse](out, helperproto.SubTLSProbe)
	if err != nil || !isHexSHA256(r.LeafSHA256) || r.ChainLength < 1 || r.ChainLength > maxChainCerts {
		return served{}, false, nil // PROBE_FAILED, or an answer Alice cannot use: not reached
	}
	return served{leaf: r.LeafSHA256, chain: r.ChainLength, local: true}, true, nil
}
