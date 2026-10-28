package windows

import (
	"context"
	"encoding/json"
	"slices"
	"strconv"
	"strings"

	"alice/internal/providers"
	"alice/internal/providers/tlsverify"
	"alice/internal/providers/windows/winproto"
)

// The Remote Desktop listener (design §13 W6, R69): one win_rdp location per server, the RDP-Tcp listener read by
// rdp-dump, written by rdp-deploy (the W2 transaction with a NETWORK SERVICE key grant and the listener's value) and
// verified with a TLS handshake after the RDP negotiation, from Alice or from the helper (tls-probe --rdp).

// rdpKeyACLLeftParam is the restore step's param of a restore that could not take the NETWORK SERVICE grant back (W6
// Ruling 10; the grant step's when the helper's undo of a failed grant failed).
const rdpKeyACLLeftParam = "rdp_key_acl_left"

// rdpKeyGrantedParam is the step param of an RDP answer whose operation gave NETWORK SERVICE read access to the key
// (on the step aclLeftStep picks; security review M2): the manual-action e-mails then say to remove it.
const rdpKeyGrantedParam = "rdp_key_granted"

// rdpReady refuses an RDP subcommand, or tls-probe --rdp, to a helper older than winproto.RDPMinVersion before
// anything is sent (W6 Ruling 2), as ccsReady does for CCS.
func (s *session) rdpReady() error {
	if winproto.VersionAtLeast(s.version.Helper, winproto.RDPMinVersion) {
		return nil
	}
	return providers.NewError(ReasonHelperOutdated, false, nil, map[string]string{
		"helper_version": s.version.Helper, "required_version": winproto.RDPMinVersion})
}

// discoverRDP is the third call of Discover (W6 Ruling 18): rdp-dump on a connection of its own when the helper is at
// least 1.2.0, else the server warning win_rdp_helper_outdated and no location. A failed rdp-dump (an error, its
// budget, an answer that does not decode) keeps the other results and adds list_truncated and locations_dropped, so
// inventory marks nothing missing. Only the end of ctx is an error.
func (s *session) discoverRDP(ctx context.Context) ([]providers.DiscoveredCertificate, []providers.Warning, error) {
	if s.rdpReady() != nil {
		return nil, []providers.Warning{warning(winproto.WarnRDPHelperOutdated)}, nil
	}
	d, _, err := call[winproto.RDPDumpResponse](ctx, s, winproto.SubRDPDump)
	if err != nil {
		if ctx.Err() != nil {
			return nil, nil, err
		}
		return nil, []providers.Warning{warning(providers.WarnListTruncated), warning(providers.WarnLocationsDropped)}, nil
	}
	certs, warns := convertRDP(d)
	return certs, warns, nil
}

// convertRDP turns an rdp-dump answer into the listener's location (W6 Rulings 3-5): none without the RDP-Tcp key;
// one of kind win_rdp otherwise, cert_path rdp/RDP-Tcp, locator {type rdp, listener RDP-Tcp}, no servers, the port in
// details.port (a detail, refreshed by every scan: a port in the stored locator would freeze the location). Its
// certificate is the one the value names in My (absent there: cert_missing; without a usable key: its key problem),
// or while the value is absent the single certificate of Remote Desktop (self_signed; none or two:
// win_rdp_cert_unknown). Remote Desktop off is win_rdp_disabled, security layer 0 win_rdp_no_tls; a policy's
// certificate template warns win_rdp_autoenroll. The token is the leaf DER's SHA-256 and the chain the leaf and its
// chain parsed again (certificateChain). A port Alice cannot use leaves the location out (list_truncated,
// locations_dropped: nothing is marked missing).
func convertRDP(d winproto.RDPDumpResponse) ([]providers.DiscoveredCertificate, []providers.Warning) {
	if !d.Present {
		return nil, nil
	}
	if d.Port < 1 || d.Port > 65535 {
		return nil, []providers.Warning{warning(providers.WarnListTruncated), warning(providers.WarnLocationsDropped)}
	}
	template := cleanValue(d.CertTemplate, winproto.MaxText)
	loc := providers.CertLocation{Kind: providers.LocationWinRDP, CertPath: winproto.RDPCanonical,
		Locator: providers.Locator{"type": winproto.LocatorRDP, "listener": winproto.RDPListenerName},
		Servers: []providers.CertServer{}, Details: map[string]any{"port": d.Port, "enabled": d.Enabled, "security_layer": d.SecurityLayer,
			"nla": d.NLA, "cert_template": template, "self_signed": false}}
	if template != "" {
		loc.Warnings = append(loc.Warnings, winproto.WarnRDPAutoenroll)
	}
	dc := providers.DiscoveredCertificate{}
	var reason string
	switch c := d.Certificate; {
	case c == nil && d.ValueSet:
		loc.Problem = ProblemCertMissing
	case c == nil || (!d.ValueSet && d.SelfSignedCount != 1):
		reason = winproto.UnsupportedRDPCertUnknown // no token could prove what is replaced (Ruling 4)
	default:
		sha := strings.ToLower(c.SHA1) //nolint:forbidigo // hex digits
		loc.Details["store"] = cleanValue(c.Store, maxStoreLength)
		loc.Details["self_signed"] = !d.ValueSet
		if winproto.ValidSHA1(sha) {
			loc.Details["cert_sha1"] = sha
		}
		certDetails(loc.Details, *c)
		var dropped bool
		dc.PEMChain, dc.FileSHA256, dropped, loc.Problem = certificateChain(*c, sha)
		loc.KeyProblem = keyProblem(*c)
		if dropped {
			loc.Warnings = append(loc.Warnings, providers.WarnCertificateBlockDropped)
		}
	}
	switch {
	case !d.Enabled:
		reason = winproto.UnsupportedRDPDisabled // nothing would serve the certificate (Ruling 5)
	case d.SecurityLayer == 0:
		reason = winproto.UnsupportedRDPNoTLS // the certificate is never used
	case reason == "" && (loc.Problem != "" || loc.KeyProblem != ""):
		reason = providers.UnsupportedFile
	}
	if loc.Problem != "" {
		dc.PEMChain, dc.FileSHA256 = nil, ""
	}
	loc.Unsupported, loc.Supported = reason, reason == ""
	dc.Location = loc
	return []providers.DiscoveredCertificate{dc}, nil
}

// rdpPortOf is a win_rdp location's port: details.port, the last scan's (Alice deploys to RDP-Tcp only), 0 for a
// locator Alice does not deploy to or a port outside 1-65535.
func rdpPortOf(loc providers.CertLocation) int {
	typ, _ := loc.Locator["type"].(string)
	listener, _ := loc.Locator["listener"].(string)
	if typ != winproto.LocatorRDP || listener != winproto.RDPListenerName {
		return 0
	}
	return locatorPort(loc.Details["port"])
}

// rdpEndpoints is the listener's endpoint (W6 Ruling 16): details.port (the Administrator's replaces it), SNI the
// Administrator's or tlsverify.SNIFor of the SANs (RDP serves one certificate whatever the SNI; the name is the R51
// trust check's), the helper's probe of 127.0.0.1, listening on every address. None for a locator Alice does not
// deploy to.
func rdpEndpoints(loc providers.CertLocation, v providers.VerifyOptions, sans []string) []tlsverify.Endpoint {
	port := rdpPortOf(loc)
	if port == 0 {
		return nil
	}
	if v.Port != 0 {
		port = v.Port
	}
	sni := v.SNI
	if sni == "" {
		sni = tlsverify.SNIFor(nil, sans)
	}
	return []tlsverify.Endpoint{{Port: port, SNI: sni, Addr: "127.0.0.1"}}
}

// rdpServerProbe is the server-side probe of a win_rdp location: serverProbe with tls-probe's ninth argument --rdp
// (W6 Ruling 15), never sent to a helper below 1.2.0 (not reached: tlsverify then reports the listener unreachable).
func (s *session) rdpServerProbe(ctx context.Context, ep tlsverify.Endpoint, keyType string) (tlsverify.Served, bool, error) {
	if s.rdpReady() != nil {
		return tlsverify.Served{}, false, nil
	}
	return s.probeWith(ctx, ep, keyType, winproto.ArgRDP)
}

// rdpDeployInput is the JSON of winproto.RDPDeployInput (W6 Ruling 8: no locator, no store), built like deployInput:
// one allocation of its final size, no string copy of the key. ok is false for an empty or non-ASCII chain or key.
// The caller clears it.
func rdpDeployInput(expect string, chain, key []byte, g providers.RollbackGuard) ([]byte, bool) {
	cn, ok1 := jsonStringLen(chain)
	kn, ok2 := jsonStringLen(key)
	if !ok1 || !ok2 || len(chain) == 0 || len(key) == 0 {
		return nil, false
	}
	spki, _ := json.Marshal(nonNil(g.ForbiddenSPKI)) // strings: cannot fail
	leaves, _ := json.Marshal(nonNil(g.ForbiddenLeaf))
	const (
		head = `{"expect_sha256":`
		ch   = `,"chain_pem":`
		ky   = `,"key_pem":`
		fs   = `,"forbidden_spki_sha256":`
		fl   = `,"forbidden_leaf_sha256":`
		tail = `}`
	)
	n := len(head) + len(expect) + 2 + len(ch) + cn + len(ky) + kn + len(fs) + len(spki) + len(fl) + len(leaves) + len(tail)
	out := make([]byte, 0, n)
	out = append(out, head...)
	out = strconv.AppendQuote(out, expect) // hex digits
	out = append(out, ch...)
	out = appendJSONString(out, chain)
	out = append(out, ky...)
	out = appendJSONString(out, key)
	out = append(out, fs...)
	out = append(out, spki...)
	out = append(out, fl...)
	out = append(out, leaves...)
	return append(out, tail...), true
}

// deployRDP is DeployCertificate's rdp-deploy (W6 Ruling 9) after the checks every deployment shares: a helper below
// 1.2.0 is refused before anything is sent, then the input (built by hand, the key on standard input only, cleared
// after the send) goes to "rdp-deploy --op <id>", and the answer is mapped exactly as iis-deploy's (d.sent).
func (d *deployment) deployRDP(ctx context.Context) (providers.DeployOutcome, error) {
	s, req := d.s, d.req
	if err := s.rdpReady(); err != nil {
		return d.refuse(asProviderError(err))
	}
	input, ok := rdpDeployInput(req.ExpectCertSHA256, req.CertificatePEM, req.PrivateKeyPEM.Bytes(), req.Guard)
	defer clear(input)
	if inputHook != nil {
		inputHook(input)
	}
	if !ok || len(input) > winproto.MaxDeployInput {
		return d.refuse(providers.NewError(reasonInvalidCertificate, false, nil, nil))
	}
	c := runWrite[winproto.DeployResponse](ctx, s, winproto.SubRDPDeploy, input, rdpDeployRefusals, winproto.ArgOp, req.OperationID.String())
	clear(input)
	return d.sent(ctx, c)
}

// aclLeftStep is the step an RDP answer's rdp_key_acl_left (or rdp_key_granted) is reported on: the restore step when
// the answer has one, else the grant step (the helper's undo of a failed grant), "" when the flag is not set.
func aclLeftStep(left bool, steps []providers.DeployStep) string {
	switch {
	case !left:
		return ""
	case slices.ContainsFunc(steps, func(st providers.DeployStep) bool { return st.Name == winproto.StepRestore }):
		return winproto.StepRestore
	}
	return winproto.StepGrantKeyRead
}
