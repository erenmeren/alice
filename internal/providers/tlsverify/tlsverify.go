// Package tlsverify is the platform-neutral judgement of which certificate a deployment's endpoints serve (spec §12.8,
// R38 item 6, R51; Windows design §6.4, W2 Ruling 15): a list of endpoints is probed from Alice (TLSProber) and, where
// Alice's probe does not stand for an endpoint or cannot complete a handshake, by the target's own probe (ServerProbe:
// alice-helper tls-probe on Linux, the Windows helper's on Windows); every answer is compared with the expected leaf and
// chain length and, with a trust policy, its chain is verified. The Nginx provider (internal/providers/nginx) and the
// Windows provider build the endpoint list and delegate everything after it to Verify.
package tlsverify

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"

	"alice/internal/platform/clock"
	"alice/internal/platform/netaddr"
	"alice/internal/providers"
	"alice/internal/providers/linuxssh/helperproto"
)

// Verification reasons (VerifyResult.Reason, and the Reason of a deployment whose verification failed).
// ReasonVerifyChain: the new leaf is served, but with another number of certificates than the deployed chain has
// (spec §12.8 item 5). ReasonVerifyUntrusted (R51): the expected leaf and chain length are served, but the chain does
// not verify against the trust policy's known anchor.
const (
	ReasonVerifyFailed      = "deployment.verify_failed"      // the previous certificate is still served (F-05)
	ReasonVerifyOther       = "deployment.verify_other"       // neither the expected nor the previous one (F-06)
	ReasonVerifyUnreachable = "deployment.verify_unreachable" // neither Alice nor the server could complete a handshake (param port)
	ReasonVerifyChain       = "deployment.verify_chain"       // the expected leaf, another chain length (param port)
	ReasonVerifyUntrusted   = "deployment.verify_untrusted"   // the expected chain does not verify (params port, trust_error)
)

// Endpoint is one (port, name, listen address) Alice checks after a deployment.
type Endpoint struct {
	Port int
	SNI  string // "" = no server name (helperproto.NoSNI on a helper's command line)
	Addr string // where the server-side probe connects: an IP literal
	// Listen is the listen address ("" for any address). It decides whether Alice's own probe stands for the
	// endpoint (ProbeFromAlice).
	Listen string
}

// Prober probes a TLS endpoint from Alice.
type Prober interface {
	Probe(ctx context.Context, host string, port int, sni, keyType string) (Probe, error)
}

// Probe is one TLS answer of Alice's own probe. Chain is the DER of every certificate presented, leaf first (R51: its
// trust is checked against the verification's trust policy; nil when not known).
type Probe struct {
	LeafSHA256  string
	ChainLength int
	NotAfter    time.Time
	Chain       [][]byte
}

// ErrProbeUnreachable wraps every connection failure of a probe (dial, refused, timeout before the handshake); other
// failures (handshake refused) are ErrProbeFailed. ErrProbeNotAllowed is a connection Alice refused to open: the host
// resolves to an address the target rule refuses (netaddr.Allowed, AUD-25 a); it is neither of the others.
var (
	ErrProbeUnreachable = errors.New("tls probe: the endpoint cannot be reached")
	ErrProbeFailed      = errors.New("tls probe: the TLS handshake failed")
	ErrProbeNotAllowed  = errors.New("tls probe: the endpoint's address is not one Alice connects to")
)

// Served is one probe's answer: the leaf's hex SHA-256, the number of certificates presented and the presented chain
// (DER, leaf first; nil when the answer has none: an older helper). Local is set by Verify for an answer of the
// server-side probe.
type Served struct {
	Leaf  string
	Chain int
	DERs  [][]byte
	Local bool
}

// ServerProbe is the target's own probe (alice-helper tls-probe on Linux, the Windows helper's on Windows) of ep.Addr,
// ep.Port and ep.SNI with keyType; nil when there is none. reached is false when it completed no handshake, or when its
// answer cannot be used; err is a failure of the connection to the target (the verification fails with it). Verify
// checks the answer again (a SHA-256, 1 to helperproto.MaxProbeChainCerts certificates, a chain agreeing with its
// length) before it uses it.
type ServerProbe func(ctx context.Context, ep Endpoint, keyType string) (served Served, reached bool, err error)

// Options bound a verification: Attempts per endpoint (0 = 5), RetryWait between them (0 = 2 s), the Clock of the
// waits and of the trust check's now (nil = the real one), and Log for the one warning a refused own probe gives (nil =
// discarded).
type Options struct {
	Attempts  int
	RetryWait time.Duration
	Clock     clock.Clock
	Log       *slog.Logger
}

func (o Options) withDefaults() Options {
	if o.Attempts <= 0 {
		o.Attempts = 5
	}
	if o.RetryWait <= 0 {
		o.RetryWait = 2 * time.Second
	}
	if o.Clock == nil {
		o.Clock = clock.Real{}
	}
	if o.Log == nil {
		o.Log = slog.New(slog.DiscardHandler)
	}
	return o
}

// SNIFor chooses the server name a probe sends (spec §12.8 item 1): the first usable name, else the first usable SAN
// of the certificate. Regex names (~…), "_" and "" are skipped; a leading wildcard "*.d" becomes "alice-check.d" (any
// name the wildcard covers selects the same server block or binding), a leading dot ".d" becomes "d"; names are
// lower-cased (ASCII). An IP literal is never a server name (RFC 6066; helperproto.ValidSNI refuses it, D18). ""
// means no SNI.
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
	n = ASCIILower(n)
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

// ASCIILower lower-cases ASCII letters only (host names, hex; strings.ToLower is forbidden by the lint rule for
// user-visible text and is not needed for DNS names).
func ASCIILower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 'a' - 'A'
		}
	}
	return string(b)
}

// ProbeFromAlice reports whether Alice's own probe of host (the target's address) reaches the endpoint's listen, so
// that its answer stands for the endpoint: a listen on any address, or on the address Alice connects to (the same IP,
// or the same host name ignoring case). A listen on another specific address, loopback among them, is not reached by
// a connection to host: another server block or binding may answer there, so only the server-side probe against that
// address is the authority.
func ProbeFromAlice(ep Endpoint, host string) bool {
	if ep.Listen == "" {
		return true
	}
	l, lerr := netip.ParseAddr(ep.Listen)
	h, herr := netip.ParseAddr(host)
	if lerr == nil || herr == nil {
		return lerr == nil && herr == nil && l.Unmap() == h.Unmap() && l.Zone() == h.Zone()
	}
	return ASCIILower(ep.Listen) == ASCIILower(host)
}

// isHexSHA256 is a SHA-256 in lower-case hex (helperproto.ValidSHA256 also accepts its "absent" marker, which no probe
// may be).
func isHexSHA256(s string) bool { return s != helperproto.AbsentSHA256 && helperproto.ValidSHA256(s) }

// verdict is one answer judged against a verification (judge): reason "" when the endpoint passes; trust and trustErr
// the chain's trust when the request has a trust policy and the expected leaf and chain length are served ("" otherwise).
type verdict struct {
	reason, trust, trustErr string
}

// Verify checks which certificate the endpoints eps serve (spec §12.8; R38 item 6) and, with a trust policy, whether
// the served chains verify (R51). host is the target's address, where Alice's own probe p connects; server is the
// target's own probe (nil: none).
//
// Where each endpoint is probed: Alice's own probe stands for an endpoint only when it reaches that listen
// (ProbeFromAlice). Then Alice probes first and the server itself when Alice cannot connect or complete a handshake.
// A listen on another specific address is probed only from the server, against that address; without a server probe
// such an endpoint is not reached.
//
// How: every probe uses helperproto.ProbeAny first, so TLS 1.3-only websites answer (D15). When the leaf served is not
// the expected one and req.KeyType is rsa or ecdsa, a second probe of that key type (TLS 1.2 with that key type's
// suites) asks a dual-certificate server for the certificate of the deployed type (spec §12.8 item 4); it decides only
// when it shows the expected leaf. An endpoint that does not pass yet is probed again, up to Options.Attempts times
// Options.RetryWait apart (old workers answer for a moment after a graceful reload, a binding's first handshake after
// a bind; a probe that timed out is measured again).
//
// Two uses, told apart by req.Fingerprint:
//   - a verification (Fingerprint set): every endpoint is compared, the leaf's SHA-256 with Fingerprint and, when
//     req.ChainLength > 0, the number of certificates presented (spec §12.8 item 5); with req.Trust, the served chain
//     is verified with crypto/x509 against the policy's roots for the endpoint's server name at the clock's now
//     (providers.CheckServedChain). OK only when every endpoint serves it and, when the policy is enforced, every chain
//     verifies. Reasons: ReasonVerifyFailed (the previous leaf is served), ReasonVerifyOther, ReasonVerifyChain,
//     ReasonVerifyUntrusted (param trust_error), ReasonVerifyUnreachable (no handshake either way; also for no
//     endpoints), each with param port of the first endpoint that failed, and Failure network, certificate or trust. A
//     passed verification reports its Level (installed when skipped, trusted when every chain verified, served
//     otherwise) and Trust: trusted, untrusted (not enforced: a warning, with the first endpoint's reason and port) or
//     unchecked (an answer without the chain);
//   - a query (Fingerprint ""): nothing is compared. OK means only that every endpoint completed a handshake; Served
//     and ServedChainLength are the first endpoint's answer. It is never a pass of a deployment (Level none).
//
// Nothing of a probe but the leaf's SHA-256, the chain length and the chain (checked here, never during the handshake)
// is used. The error is a *providers.Error for a cancelled ctx (ssh.timeout, wrapping the context's error) or the
// server probe's error; a website that cannot be reached is a result, not an error.
func Verify(ctx context.Context, host string, eps []Endpoint, req providers.VerifyRequest, p Prober, server ServerProbe, o Options) (providers.VerifyResult, error) {
	if err := ctx.Err(); err != nil {
		return providers.VerifyResult{}, providers.NewError("ssh.timeout", true, err, nil)
	}
	if req.Verify.Skip {
		return providers.VerifyResult{OK: true, Mode: "skipped", Level: providers.LevelInstalled}, nil
	}
	if len(eps) == 0 {
		port := req.Verify.Port
		if port == 0 {
			port = 443
		}
		return providers.VerifyResult{Reason: ReasonVerifyUnreachable, Params: map[string]string{"port": strconv.Itoa(port)},
			Failure: providers.VerifyFailureNetwork}, nil
	}
	v := verifier{host: host, p: p, server: server, o: o.withDefaults()}
	res := providers.VerifyResult{OK: true, Mode: "remote"}
	var trust providers.Trust
	if req.Trust != nil && req.Fingerprint != "" {
		trust = providers.Trust{Status: providers.TrustTrusted, Store: req.Trust.Store, Enforced: req.Trust.Enforce}
	}
	for i, ep := range eps {
		sv, reached, err := v.probeEndpoint(ctx, ep, req)
		if err != nil {
			return providers.VerifyResult{}, err
		}
		params := map[string]string{"port": strconv.Itoa(ep.Port)}
		if !reached {
			return providers.VerifyResult{Reason: ReasonVerifyUnreachable, Params: params, Failure: providers.VerifyFailureNetwork}, nil
		}
		if sv.Local {
			res.Mode = "local"
		}
		if i == 0 {
			res.Served, res.ServedChainLength = sv.Leaf, sv.Chain
		}
		if req.Fingerprint == "" {
			continue
		}
		vd := v.judge(ep, sv, req)
		if vd.reason == ReasonVerifyUntrusted {
			params["trust_error"] = vd.trustErr
			trust.Status, trust.Error, trust.Port = providers.TrustUntrusted, vd.trustErr, ep.Port
			return providers.VerifyResult{Mode: res.Mode, Served: sv.Leaf, ServedChainLength: sv.Chain, Reason: vd.reason, Params: params,
				Trust: trust, Failure: providers.VerifyFailureTrust}, nil
		}
		if vd.reason != "" {
			return providers.VerifyResult{Mode: res.Mode, Served: sv.Leaf, ServedChainLength: sv.Chain, Reason: vd.reason, Params: params,
				Failure: providers.VerifyFailureCertificate}, nil
		}
		switch {
		case vd.trust == providers.TrustUntrusted && trust.Status != providers.TrustUntrusted:
			trust.Status, trust.Error, trust.Port = providers.TrustUntrusted, vd.trustErr, ep.Port
		case vd.trust == providers.TrustUnchecked && trust.Status == providers.TrustTrusted:
			trust.Status = providers.TrustUnchecked
		}
	}
	if req.Fingerprint != "" {
		res.Trust, res.Level = trust, providers.VerificationLevel(res.Mode, trust.Status)
	}
	return res, nil
}

// ProbeOnce probes an endpoint once, as one attempt of Verify does: from Alice (p, to host) unless *localOnly, then
// from the server when Alice's probe failed. A refused connection (ErrProbeUnreachable other than a timeout) and a
// connection Alice refuses to open (ErrProbeNotAllowed, logged) set *localOnly for the next attempts. ok is false when
// neither completed a handshake with an answer Alice can use.
func ProbeOnce(ctx context.Context, host string, ep Endpoint, keyType string, localOnly *bool, p Prober, server ServerProbe, o Options) (Served, bool, error) {
	v := verifier{host: host, p: p, server: server, o: o.withDefaults()}
	return v.probeOnce(ctx, ep, keyType, localOnly)
}

// verifier is one verification's probes and bounds.
type verifier struct {
	host   string
	p      Prober
	server ServerProbe
	o      Options
}

// mismatch is the reason a served answer is not the expected leaf and chain length ("" when it is).
func mismatch(sv Served, req providers.VerifyRequest) string {
	switch {
	case sv.Leaf == req.Fingerprint && (req.ChainLength <= 0 || sv.Chain == req.ChainLength):
		return ""
	case sv.Leaf == req.Fingerprint:
		return ReasonVerifyChain
	case req.PreviousFingerprint != "" && sv.Leaf == req.PreviousFingerprint:
		return ReasonVerifyFailed
	}
	return ReasonVerifyOther
}

// judge is the verdict on one endpoint's answer: mismatch, then, with a trust policy, the served chain's trust for the
// endpoint's server name at the clock's now (R51). An untrusted chain is ReasonVerifyUntrusted only when the policy
// enforces its reason (the anchor is known; a name mismatch never fails).
func (v verifier) judge(ep Endpoint, sv Served, req providers.VerifyRequest) verdict {
	if r := mismatch(sv, req); r != "" {
		return verdict{reason: r}
	}
	if req.Trust == nil {
		return verdict{}
	}
	status, code := providers.CheckServedChain(sv.DERs, *req.Trust, ep.SNI, v.o.Clock.Now())
	vd := verdict{trust: status, trustErr: code}
	if status == providers.TrustUntrusted && req.Trust.Enforces(code) {
		vd.reason = ReasonVerifyUntrusted
	}
	return vd
}

// probeEndpoint returns what an endpoint serves. reached is false when no attempt completed a handshake, from Alice or
// from the server. Once Alice cannot connect (ErrProbeUnreachable other than a timeout: refused, no route), or refuses
// to (ErrProbeNotAllowed: the target's name now resolves to an address Alice never connects to, AUD-25 a; the
// server-side probe runs on the server and is not concerned), the endpoint is probed from the server only. A
// connection that timed out, and a failed handshake (ErrProbeFailed), are tried from the server in the same attempt and
// from Alice again in the next (R51: one timeout is measured again, never taken for an answer). An answer that does not
// pass (judge) is probed again too. The error is a cancelled ctx or the server probe's error.
func (v verifier) probeEndpoint(ctx context.Context, ep Endpoint, req providers.VerifyRequest) (last Served, reached bool, err error) {
	typed := ""
	if req.KeyType == helperproto.ProbeRSA || req.KeyType == helperproto.ProbeECDSA {
		typed = req.KeyType
	}
	localOnly := !ProbeFromAlice(ep, v.host)
	for attempt := 1; attempt <= v.o.Attempts; attempt++ {
		sv, ok, err := v.probeOnce(ctx, ep, helperproto.ProbeAny, &localOnly)
		if err != nil {
			return Served{}, false, err
		}
		if ok {
			last, reached = sv, true
			if req.Fingerprint == "" || v.judge(ep, sv, req).reason == "" {
				return sv, true, nil
			}
			if typed != "" {
				// A dual-certificate server may have answered the any-probe with its other pair.
				tv, tok, err := v.probeOnce(ctx, ep, typed, &localOnly)
				if err != nil {
					return Served{}, false, err
				}
				if tok && v.judge(ep, tv, req).reason == "" {
					return tv, true, nil
				}
			}
		}
		if attempt == v.o.Attempts {
			break
		}
		select {
		case <-ctx.Done():
			return Served{}, false, providers.NewError("ssh.timeout", true, ctx.Err(), nil)
		case <-v.o.Clock.After(v.o.RetryWait):
		}
	}
	return last, reached, nil
}

// probeOnce probes an endpoint once (ProbeOnce).
func (v verifier) probeOnce(ctx context.Context, ep Endpoint, keyType string, localOnly *bool) (Served, bool, error) {
	if !*localOnly {
		pr, err := v.p.Probe(ctx, v.host, ep.Port, ep.SNI, keyType)
		switch {
		case ctx.Err() != nil:
			return Served{}, false, providers.NewError("ssh.timeout", true, ctx.Err(), nil)
		case err == nil && isHexSHA256(pr.LeafSHA256) && pr.ChainLength >= 1:
			return Served{Leaf: pr.LeafSHA256, Chain: pr.ChainLength, DERs: probeChain(pr)}, true, nil
		case errors.Is(err, ErrProbeNotAllowed):
			// Made visible here: the server-side probe still decides, so the verification does not show it, and the
			// next SSH dial to the same name marks the target.
			v.o.Log.Warn("Alice's own TLS probe was refused: the server's name resolves to an address Alice does not connect to; the server-side probe decides",
				"reason", "ssh.address_not_allowed", "port", ep.Port, "sni", ep.SNI)
			*localOnly = true
		case errors.Is(err, ErrProbeUnreachable) && !timedOut(err):
			*localOnly = true
		}
	}
	if v.server == nil {
		return Served{}, false, nil
	}
	sv, ok, err := v.server(ctx, ep, keyType)
	if err != nil {
		return Served{}, false, err
	}
	if !ok || !isHexSHA256(sv.Leaf) || sv.Chain < 1 || sv.Chain > helperproto.MaxProbeChainCerts {
		return Served{}, false, nil // PROBE_FAILED, or an answer Alice cannot use: not reached
	}
	if len(sv.DERs) != sv.Chain {
		sv.DERs = nil // an answer whose chain disagrees with its own length is not checked (unchecked)
	}
	sv.Local = true
	return sv, true, nil
}

// probeChain is a probe's presented chain when it agrees with its chain length (nil otherwise: the trust is then
// unchecked).
func probeChain(pr Probe) [][]byte {
	if len(pr.Chain) != pr.ChainLength || pr.ChainLength > helperproto.MaxProbeChainCerts {
		return nil
	}
	return pr.Chain
}

// timedOut reports a probe error caused by a timeout (a dial that did not complete in time).
func timedOut(err error) bool {
	var ne net.Error
	return errors.Is(err, os.ErrDeadlineExceeded) || (errors.As(err, &ne) && ne.Timeout())
}

// Bounds of Alice's own probe.
const (
	defaultProbeDialTimeout      = 5 * time.Second
	defaultProbeHandshakeTimeout = 10 * time.Second
)

// TLSProber probes a TLS endpoint from Alice (spec §12.8, R38 item 6). It sends no application data and trusts nothing
// during the handshake: the client configuration is helperproto.ProbeTLSConfig (no certificate verification there)
// without a client session cache and with session tickets disabled, so every probe is a fresh handshake (W2 Ruling
// 15); the served leaf's SHA-256, the number of certificates presented and the presented chain are reported (spec
// §12.8 items 3 and 5); the chain's trust is checked afterwards, against the verification's trust policy (R51). Zero
// timeouts mean 5 s to connect and 10 s for the handshake. The connection goes through netaddr.DialContext: the
// address host resolves to is checked with the target rule on the socket that connects (AUD-25 a).
type TLSProber struct {
	DialTimeout      time.Duration
	HandshakeTimeout time.Duration
	// Resolver resolves host names (nil = the system's); tests set it. The target rule applies to whatever it answers.
	Resolver *net.Resolver
}

var _ Prober = TLSProber{}

// config is the client configuration of one probe: ProbeTLSConfig, never resuming a session.
func (TLSProber) config(sni, keyType string) *tls.Config {
	c := helperproto.ProbeTLSConfig(sni, keyType)
	c.ClientSessionCache = nil
	c.SessionTicketsDisabled = true
	return c
}

// Probe connects to host:port and completes a handshake with sni ("" or helperproto.NoSNI: none) and keyType
// (helperproto.ProbeAny, ProbeRSA or ProbeECDSA; see ProbeTLSConfig). A connection failure wraps ErrProbeUnreachable,
// a failed handshake (or an unknown key type, refused before dialling) ErrProbeFailed, an address the target rule
// refuses ErrProbeNotAllowed (and netaddr.ErrNotAllowed; nothing is sent); a cancelled ctx is in the error chain too.
func (p TLSProber) Probe(ctx context.Context, host string, port int, sni, keyType string) (Probe, error) {
	if keyType != helperproto.ProbeAny && keyType != helperproto.ProbeRSA && keyType != helperproto.ProbeECDSA {
		return Probe{}, fmt.Errorf("%w: unknown key type", ErrProbeFailed)
	}
	if port < 1 || port > 65535 {
		return Probe{}, fmt.Errorf("%w: port out of range", ErrProbeUnreachable)
	}
	dial, handshake := p.DialTimeout, p.HandshakeTimeout
	if dial <= 0 {
		dial = defaultProbeDialTimeout
	}
	if handshake <= 0 {
		handshake = defaultProbeHandshakeTimeout
	}
	conn, err := netaddr.DialContext(ctx, &net.Dialer{Timeout: dial, Resolver: p.Resolver}, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if errors.Is(err, netaddr.ErrNotAllowed) {
		return Probe{}, fmt.Errorf("%w: %w", ErrProbeNotAllowed, err)
	}
	if err != nil {
		return Probe{}, fmt.Errorf("%w: %w", ErrProbeUnreachable, err)
	}
	defer func() { _ = conn.Close() }()
	hctx, cancel := context.WithTimeout(ctx, handshake)
	defer cancel()
	tc := tls.Client(conn, p.config(sni, keyType))
	if err := tc.HandshakeContext(hctx); err != nil {
		return Probe{}, fmt.Errorf("%w: %w", ErrProbeFailed, err)
	}
	cs := tc.ConnectionState()
	if len(cs.PeerCertificates) == 0 {
		return Probe{}, fmt.Errorf("%w: no certificate", ErrProbeFailed)
	}
	leaf := cs.PeerCertificates[0]
	sum := sha256.Sum256(leaf.Raw)
	chain := make([][]byte, 0, len(cs.PeerCertificates))
	for _, c := range cs.PeerCertificates {
		chain = append(chain, c.Raw)
	}
	return Probe{LeafSHA256: hex.EncodeToString(sum[:]), ChainLength: len(cs.PeerCertificates), NotAfter: leaf.NotAfter.UTC(), Chain: chain}, nil
}
