package windows

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strconv"
	"strings"
	"time"

	"alice/internal/providers"
	"alice/internal/providers/tlsverify"
	"alice/internal/providers/windows/winproto"
)

// The Centralized Certificate Store (design §13 W5, R68): one win_ccs_file location per PFX file of IIS's local CCS
// folder, linked to the IIS https bindings IIS serves from it, written by ccs-deploy with the server's CCS password and
// restored from the backup through iis-restore.

// Warnings of the CCS: server level (the first three) and location level (WarnCCSUnlinked). Codes have no dot, as
// inventory stores only ^[a-z][a-z_]{0,39}$.
const (
	WarnCCSPasswordMissing  = "win_ccs_password_missing"  // Alice holds no CCS password of the server: no files read (Ruling 18)
	WarnCCSHelperOutdated   = "win_ccs_helper_outdated"   // the helper is below CCSMinVersion: no files read (Ruling 2)
	WarnCCSPasswordMismatch = "win_ccs_password_mismatch" // param count: the files Alice's password does not open (Ruling 12)
	WarnCCSUnlinked         = "win_ccs_unlinked"          // no IIS binding uses the file: verified by the read-back only (Ruling 8)
)

// ccsUnlinkedParam is the verify step's param of a file no IIS binding uses (Ruling 8).
const ccsUnlinkedParam = "ccs_unlinked"

// ccsReady refuses a CCS subcommand to a helper older than winproto.CCSMinVersion before anything is sent (W5
// Ruling 2), as writeReady does for the write subcommands.
func (s *session) ccsReady() error {
	if winproto.VersionAtLeast(s.version.Helper, winproto.CCSMinVersion) {
		return nil
	}
	return providers.NewError(ReasonHelperOutdated, false, nil, map[string]string{
		"helper_version": s.version.Helper, "required_version": winproto.CCSMinVersion})
}

// ccsPassword is the server's CCS password for one helper call (W5 Ruling 11): from the platform credential source
// when it is a providers.CCSPasswordSource, for this session's own target only. The error is the source's:
// providers.ErrNoCCSPassword when none is set (also for a source that cannot hold one), providers.ErrCCSPasswordUnusable
// for a stored one that will never open, anything else a failure that says nothing about the password (the database,
// the end of ctx). The caller calls release as soon as the password is copied into the input.
func (s *session) ccsPassword(ctx context.Context) (pw []byte, release func(), err error) {
	src, isSource := s.cred.(providers.CCSPasswordSource)
	if !isSource {
		return nil, nil, providers.ErrNoCCSPassword
	}
	pt, release, err := src.CCSPassword(ctx, s.target)
	if err != nil {
		if release != nil {
			release()
		}
		return nil, nil, err
	}
	if release == nil {
		release = pt.Zero
	}
	return pt.Bytes(), release, nil
}

// ccsPasswordRefusal is a deployment's refusal when the password could not be read (nothing was sent): none set is
// windows.ccs_password_missing, a password that will never open internal.unexpected, both final; the end of ctx is
// ssh.timeout and any other failure windows.io_error, both retryable.
func ccsPasswordRefusal(ctx context.Context, err error) *providers.Error {
	switch {
	case errors.Is(err, providers.ErrNoCCSPassword):
		return providers.NewError(ReasonCCSPasswordMissing, false, nil, nil)
	case ctx.Err() != nil:
		return providers.NewError("ssh.timeout", true, ctx.Err(), map[string]string{"subcommand": winproto.SubCCSDeploy})
	case errors.Is(err, providers.ErrCCSPasswordUnusable):
		return providers.NewError(reasonUnexpected, false, err, nil)
	}
	return providers.NewError(ReasonIOError, true, err, nil)
}

// discoverCCS is the second call of Discover (W5 Ruling 18): ccs-dump on a connection of its own, only when iis-dump
// says CCS is on with a local folder, the helper is at least 1.1.0 and Alice holds the server's password; otherwise a
// server warning says why no file is listed (win_ccs_password_missing only when the source says none is set). A
// password that could not be read for another reason, or a failed ccs-dump (an error, its budget, an answer over the
// output bound or one that does not decode), keeps the iis-dump result and adds list_truncated and locations_dropped,
// so inventory marks nothing missing. Only the end of ctx is an error.
func (s *session) discoverCCS(ctx context.Context, d winproto.IISDumpResponse) ([]providers.DiscoveredCertificate, []providers.Warning, error) {
	switch {
	case !d.IIS.CCSEnabled:
		return nil, nil, nil
	case !winproto.ValidCCSPath(d.IIS.CCSPath):
		return nil, []providers.Warning{ccsPathWarning(d.IIS.CCSPath)}, nil
	case s.ccsReady() != nil:
		return nil, []providers.Warning{warning(WarnCCSHelperOutdated)}, nil
	}
	dropped := []providers.Warning{warning(providers.WarnListTruncated), warning(providers.WarnLocationsDropped)}
	pw, release, err := s.ccsPassword(ctx)
	switch {
	case errors.Is(err, providers.ErrNoCCSPassword):
		return nil, []providers.Warning{warning(WarnCCSPasswordMissing)}, nil
	case ctx.Err() != nil:
		return nil, nil, providers.NewError("ssh.timeout", true, ctx.Err(), map[string]string{"subcommand": winproto.SubCCSDump})
	case err != nil:
		return nil, dropped, nil
	}
	in, ok := ccsDumpInput(pw)
	release()
	defer clear(in)
	if !ok {
		return nil, dropped, nil // a password the helper would refuse: nothing is sent
	}
	if inputHook != nil {
		inputHook(in)
	}
	c, _, err := callIn[winproto.CCSDumpResponse](ctx, s, winproto.SubCCSDump, in)
	if err != nil {
		if ctx.Err() != nil {
			return nil, nil, err
		}
		return nil, dropped, nil
	}
	certs, warns := convertCCS(d, c)
	return certs, warns, nil
}

// ccsPathWarning is the server warning of a CCS folder Alice does not manage (W5 Ruling 3): win_ccs_remote for a UNC
// path, win_ccs_path_unsupported for anything else (a device path, a relative path, a reparse-point folder).
func ccsPathWarning(path string) providers.Warning {
	if strings.HasPrefix(path, `\\`) && !strings.HasPrefix(path, `\\?\`) && !strings.HasPrefix(path, `\\.\`) {
		return warning(winproto.WarnCCSRemote)
	}
	return warning(winproto.WarnCCSPathUnsupported)
}

// ccsDumpInput is the JSON of winproto.CCSDumpInput, built by hand in one allocation (no string copy of the
// password). ok is false for a password that is not winproto.ValidCCSPassword (the helper would refuse it); the
// caller clears the buffer.
func ccsDumpInput(pw []byte) ([]byte, bool) {
	const head, tail = `{"password":`, `}`
	n, ascii := jsonStringLen(pw)
	if !ascii || !winproto.ValidCCSPassword(pw) {
		return nil, false
	}
	out := make([]byte, 0, len(head)+n+len(tail))
	out = append(out, head...)
	out = appendJSONString(out, pw)
	return append(out, tail...), true
}

// ccsFile is one file of the folder while the bindings are linked.
type ccsFile struct {
	f   winproto.CCSFile
	loc location
}

// convertCCS turns a ccs-dump answer into win_ccs_file locations (W5 Rulings 5-8, 12, 19): one per .pfx whose name
// gives a host, linked to the IIS https bindings with the CCS flag that IIS serves from it (ccsFileFor), and one
// cert_missing location per such binding whose host maps to no file. Each location's token is its leaf DER's SHA-256
// and its chain the leaf and the file's intermediates, parsed again (certificateChain's rule). A folder Alice does not
// manage gives its server warning and no location; a folder the helper cut (truncated) or files Alice left out give
// list_truncated and locations_dropped, and then no cert_missing location (a missing file is not proven).
func convertCCS(d winproto.IISDumpResponse, c winproto.CCSDumpResponse) ([]providers.DiscoveredCertificate, []providers.Warning) {
	warns := []providers.Warning{}
	switch {
	case !c.Enabled:
		return nil, warns // turned off between the two calls: no files (Ruling 17)
	case !c.Local || !winproto.ValidCCSPath(c.Path):
		return nil, append(warns, ccsPathWarning(c.Path))
	}
	folder := strings.TrimSuffix(c.Path, `\`)
	dropped := c.Truncated
	ignored := min(max(c.Ignored, 0), 1<<20)
	files := map[string]*ccsFile{}
	for _, f := range c.Files {
		host, ok := winproto.CCSHost(f.Name)
		switch {
		case !ok:
			ignored++
			continue
		case files[host] != nil || len(files) >= winproto.MaxCCSFiles:
			dropped = true
			continue
		}
		files[host] = &ccsFile{f: f}
	}

	missing := map[string]*location{}
	memberships := 0
	for _, site := range d.Sites {
		name := cleanValue(site.Name, maxNameLength)
		for _, sb := range site.Bindings {
			if !strings.EqualFold(sb.Protocol, "https") {
				continue
			}
			k, ok := parseSiteBinding(sb.Information, sb.SSLFlags)
			if !ok || !k.ccs || !winproto.ValidHost(k.host) || memberships >= maxMembershipsPerDump {
				continue // convert counts what it could not read; a CCS binding without a host header names no file
			}
			memberships++
			srv := server{cs: providers.CertServer{Names: []string{k.host}, Listens: []providers.CertListen{{Addr: k.ip, Port: k.port}},
				Section: name}, site: name, info: sb.Information}
			if host, ok := ccsFileFor(k.host, func(h string) bool { return files[h] != nil }); ok {
				files[host].loc.add(srv)
				continue
			}
			if missing[k.host] == nil {
				missing[k.host] = &location{}
			}
			missing[k.host].add(srv)
		}
	}

	certs := make([]providers.DiscoveredCertificate, 0, len(files)+len(missing))
	mismatch := 0
	for host, cf := range files {
		dc := finishCCS(folder, host, cf)
		if dc.Location.Problem == winproto.CCSProblemPasswordMismatch {
			mismatch++
		}
		certs = append(certs, dc)
	}
	if !dropped {
		for host, l := range missing {
			name, _ := winproto.CCSFileName(host)
			loc := ccsLocation(folder, host, l)
			loc.Details["file_name"] = name
			loc.Problem, loc.Unsupported = ProblemCertMissing, providers.UnsupportedFile
			certs = append(certs, providers.DiscoveredCertificate{Location: loc})
		}
	}
	sortByPath(certs)
	if mismatch > 0 {
		w := warning(WarnCCSPasswordMismatch)
		w.Params["count"] = strconv.Itoa(mismatch)
		warns = append(warns, w)
	}
	if ignored > 0 {
		w := warning(winproto.WarnCCSFilesIgnored)
		w.Params["count"] = strconv.Itoa(ignored)
		warns = append(warns, w)
	}
	if dropped {
		warns = append(warns, warning(providers.WarnListTruncated), warning(providers.WarnLocationsDropped))
	}
	return certs, warns
}

// ccsFileFor is the file IIS serves an SNI host from (W5 Ruling 6 as amended by ruling W5-13, F17 measured on
// windows-2022 and windows-2025): the exact host's file, else the nearest wildcard file of a suffix at any depth
// (a.b.example.test is served by *.example.test), the suffix keeping at least two labels, never the wildcard's own
// parent (example.test is not served by *.example.test). Hosts are folded to ASCII lower case already (CCSHost,
// parseSiteBinding), so the comparison ignores case.
// shortcut: the order between two wildcard files that both cover a host (nearest first) is not measured; measure it
// on a runner if a server ever holds both.
func ccsFileFor(host string, has func(string) bool) (string, bool) {
	if has(host) {
		return host, true
	}
	for rest := host; ; {
		_, suffix, ok := strings.Cut(rest, ".")
		if !ok || !strings.Contains(suffix, ".") {
			return "", false
		}
		if has("*." + suffix) {
			return "*." + suffix, true
		}
		rest = suffix
	}
}

// ccsLocation is a CCS file's location without its file facts: the kind, the locator {type ccs_file, path, host},
// cert_path <folder>\<canonical file name> (the name Alice derives from the host, so a file renamed in another case
// stays the same location), the linked bindings sorted.
func ccsLocation(folder, host string, l *location) providers.CertLocation {
	name, _ := winproto.CCSFileName(host)
	slices.SortFunc(l.servers, func(a, b server) int {
		if c := strings.Compare(a.site, b.site); c != 0 {
			return c
		}
		return strings.Compare(a.info, b.info)
	})
	loc := providers.CertLocation{Kind: providers.LocationWinCCSFile, CertPath: folder + `\` + name,
		Locator: providers.Locator{"type": winproto.LocatorCCSFile, "path": folder, "host": host},
		Servers: make([]providers.CertServer, 0, len(l.servers)), Details: map[string]any{"ccs_path": folder}}
	for _, s := range l.servers {
		loc.Servers = append(loc.Servers, s.cs)
	}
	if l.cut {
		loc.Warnings = append(loc.Warnings, providers.WarnListTruncated)
	}
	return loc
}

// finishCCS decides a file's problems, certificate and details (Rulings 6 and 12).
func finishCCS(folder, host string, cf *ccsFile) providers.DiscoveredCertificate {
	f := cf.f
	loc := ccsLocation(folder, host, &cf.loc)
	sum := strings.ToLower(f.FileSHA256) //nolint:forbidigo // hex digits
	if !isHexSHA256(sum) {
		sum = ""
	}
	modified := ""
	if t, err := time.Parse(time.RFC3339, f.ModifiedAt); err == nil {
		modified = t.UTC().Format(time.RFC3339)
	}
	loc.Details["file_name"] = f.Name // CCSHost accepted it: ASCII host characters and .pfx
	loc.Details["file_sha256"] = sum
	loc.Details["file_size"] = max(f.Size, 0)
	loc.Details["modified_at"] = modified
	if len(loc.Servers) == 0 {
		loc.Warnings = append([]string{WarnCCSUnlinked}, loc.Warnings...)
	}
	dc := providers.DiscoveredCertificate{}
	switch f.Problem {
	case "":
		var dropped bool
		dc.PEMChain, dc.FileSHA256, dropped, loc.Problem = ccsChain(f)
		if dropped {
			loc.Warnings = append(loc.Warnings, providers.WarnCertificateBlockDropped)
		}
	case winproto.CCSProblemPasswordMismatch:
		loc.Problem = winproto.CCSProblemPasswordMismatch
	case winproto.CCSProblemNotPFX:
		loc.Problem = providers.CertProblemNotACertificate
	case winproto.CCSProblemTooLarge:
		loc.Problem = providers.CertProblemTooLarge
	case winproto.CCSProblemNoKey:
		loc.KeyProblem = ProblemKeyMissing
	default:
		loc.Problem = providers.CertProblemUnknown
	}
	if loc.Problem != "" || loc.KeyProblem != "" {
		loc.Unsupported, dc.PEMChain, dc.FileSHA256 = providers.UnsupportedFile, nil, ""
	}
	loc.Supported = loc.Unsupported == ""
	dc.Location = loc
	return dc
}

// ccsChain re-encodes a file's leaf and intermediates (certificateChain's rule without a thumbprint to match): a leaf
// that does not parse is not_a_certificate, a chain over MaxChainCerts too_large, an intermediate that does not parse
// is dropped. The token is the leaf DER's SHA-256 (W5 Ruling 13).
func ccsChain(f winproto.CCSFile) (chain []byte, sum string, dropped bool, problem string) {
	if len(f.Chain) > winproto.MaxChainCerts {
		return nil, "", false, providers.CertProblemTooLarge
	}
	leaf, ok := parseDER(f.LeafDER)
	if !ok {
		return nil, "", false, providers.CertProblemNotACertificate
	}
	c := winproto.StoreCertificate{DER: f.LeafDER, Chain: f.Chain}
	return certificateChain(c, thumbprint(leaf))
}

// sortByPath sorts locations by cert_path.
func sortByPath(certs []providers.DiscoveredCertificate) {
	slices.SortFunc(certs, func(a, b providers.DiscoveredCertificate) int {
		return strings.Compare(a.Location.CertPath, b.Location.CertPath)
	})
}

// ccsLocator is a win_ccs_file location's locator: the folder Alice discovered (a compare-and-swap value only, W5
// Ruling 4) and the host the helper derives the file name from.
type ccsLocator struct{ path, host string }

// ccsLocatorOf reads a win_ccs_file locator. ok is false for one Alice does not deploy to: another type, a folder that
// is not a ValidCCSPath, a host that is not a ValidHost.
func ccsLocatorOf(loc providers.CertLocation) (ccsLocator, bool) {
	typ, _ := loc.Locator["type"].(string)
	path, _ := loc.Locator["path"].(string)
	host, _ := loc.Locator["host"].(string)
	_, named := winproto.CCSFileName(host)
	return ccsLocator{path: path, host: host}, typ == winproto.LocatorCCSFile && winproto.ValidCCSPath(path) && named
}

// ccsDeployInput is the JSON of winproto.CCSDeployInput, built like deployInput: one allocation of its final size,
// no string copy of the key or the password. ok is false for an empty or non-ASCII chain or key and a password that
// is not ASCII. The caller clears it.
func ccsDeployInput(l ccsLocator, expect string, chain, key, pw []byte, g providers.RollbackGuard) ([]byte, bool) {
	cn, ok1 := jsonStringLen(chain)
	kn, ok2 := jsonStringLen(key)
	pn, ok3 := jsonStringLen(pw)
	if !ok1 || !ok2 || !ok3 || len(chain) == 0 || len(key) == 0 {
		return nil, false
	}
	path, _ := json.Marshal(l.path) // strings: cannot fail
	host, _ := json.Marshal(l.host)
	spki, _ := json.Marshal(nonNil(g.ForbiddenSPKI))
	leaves, _ := json.Marshal(nonNil(g.ForbiddenLeaf))
	const (
		head = `{"path":`
		hs   = `,"host":`
		exp  = `,"expect_sha256":`
		ch   = `,"chain_pem":`
		ky   = `,"key_pem":`
		pws  = `,"password":`
		fs   = `,"forbidden_spki_sha256":`
		fl   = `,"forbidden_leaf_sha256":`
		tail = `}`
	)
	n := len(head) + len(path) + len(hs) + len(host) + len(exp) + len(expect) + 2 + len(ch) + cn + len(ky) + kn + len(pws) + pn +
		len(fs) + len(spki) + len(fl) + len(leaves) + len(tail)
	out := make([]byte, 0, n)
	out = append(out, head...)
	out = append(out, path...)
	out = append(out, hs...)
	out = append(out, host...)
	out = append(out, exp...)
	out = strconv.AppendQuote(out, expect) // hex digits
	out = append(out, ch...)
	out = appendJSONString(out, chain)
	out = append(out, ky...)
	out = appendJSONString(out, key)
	out = append(out, pws...)
	out = appendJSONString(out, pw)
	out = append(out, fs...)
	out = append(out, spki...)
	out = append(out, fl...)
	out = append(out, leaves...)
	return append(out, tail...), true
}

// deployCCS is DeployCertificate's ccs-deploy (W5 Ruling 14) after the checks every deployment shares: a helper below
// 1.1.0 and a server without a CCS password are refused before anything is sent, then the input (built by hand, the
// key and the password on standard input only, both buffers cleared after the send) goes to "ccs-deploy --op <id>",
// and the answer is mapped exactly as iis-deploy's (d.sent).
func (d *deployment) deployCCS(ctx context.Context, l ccsLocator) (providers.DeployOutcome, error) {
	s, req := d.s, d.req
	if err := s.ccsReady(); err != nil {
		return d.refuse(asProviderError(err))
	}
	pw, release, err := s.ccsPassword(ctx)
	if err != nil {
		return d.refuse(ccsPasswordRefusal(ctx, err))
	}
	input, ok := ccsDeployInput(l, req.ExpectCertSHA256, req.CertificatePEM, req.PrivateKeyPEM.Bytes(), pw, req.Guard)
	release()
	defer clear(input)
	if inputHook != nil {
		inputHook(input)
	}
	if !ok || len(input) > winproto.MaxCCSDeployInput {
		return d.refuse(providers.NewError(reasonInvalidCertificate, false, nil, nil))
	}
	c := runWrite[winproto.DeployResponse](ctx, s, winproto.SubCCSDeploy, input, ccsDeployRefusals, winproto.ArgOp, req.OperationID.String())
	clear(input)
	return d.sent(ctx, c)
}

// ccsEndpoints are a CCS file's endpoints (W5 Ruling 20): one per linked IIS binding, its port and SNI its host header
// (SNIFor: a "*." host becomes alice-check., which IIS serves from the wildcard file), the address by W2's rules ("*"
// and an unspecified address: the helper probes the loopback; a specific address: it listens there only), at most
// maxEndpoints. The Administrator's port, SNI and probe address apply as for a binding. An unlinked file has none.
func ccsEndpoints(loc providers.CertLocation, v providers.VerifyOptions, sans []string) []tlsverify.Endpoint {
	if _, ok := ccsLocatorOf(loc); !ok {
		return nil
	}
	var out []tlsverify.Endpoint
	seen := map[string]bool{}
	for _, srv := range loc.Servers {
		for _, l := range srv.Listens {
			addr, listen := "127.0.0.1", ""
			if l.Addr != "*" {
				ip, ok := address(l.Addr)
				switch {
				case !ok:
					continue
				case ip.IsUnspecified() && ip.Is6():
					addr = "::1"
				case !ip.IsUnspecified():
					addr, listen = ip.String(), ip.String()
				}
			}
			if v.Address != "" {
				listen = ""
			}
			port, sni := l.Port, v.SNI
			if v.Port != 0 {
				port = v.Port
			}
			if sni == "" {
				sni = tlsverify.SNIFor(srv.Names, sans)
			}
			k := strconv.Itoa(port) + "\x00" + sni + "\x00" + listen
			if seen[k] {
				continue
			}
			seen[k] = true
			out = append(out, tlsverify.Endpoint{Port: port, SNI: sni, Addr: addr, Listen: listen})
			if len(out) == maxEndpoints {
				return out
			}
		}
	}
	return out
}

// unlinkedCCS reports a CCS file no IIS binding uses (W5 Ruling 8): its verification is the helper's read-back only.
func unlinkedCCS(loc providers.CertLocation) bool {
	return loc.Kind == providers.LocationWinCCSFile && len(loc.Servers) == 0
}

// comparedChain is the chain length a deployment's served chain is compared with, and the verify step's extra params
// (W2 Ruling 16). A binding: the chain Windows built after the imports when the helper read it (built > 0), with
// chain_differs, deployed_chain and built_chain when it differs from the deployed chain. A CCS file (W5, F18 as
// planned): IIS serves the PFX's own chain, the leaf and the intermediates ccs-deploy wrote, and ccs-deploy builds no
// chain (BuiltChainLength 0), so the deployed chain is compared and nothing is reported as differing. F18's measured
// source changes this function only.
func comparedChain(kind providers.LocationKind, deployed, built int) (int, map[string]string) {
	if kind == providers.LocationWinCCSFile || built <= 0 {
		return deployed, nil
	}
	if built != deployed {
		return built, map[string]string{"chain_differs": "true", "deployed_chain": strconv.Itoa(deployed), "built_chain": strconv.Itoa(built)}
	}
	return built, nil
}

// pickupAttempts are the verification attempts of a CCS file (W5 Ruling 20, F15 route (b)): enough attempts retryWait
// apart to span the pickup wait IIS needs, never fewer than W2's; a zero wait (F15 route (a), or not measured yet)
// keeps W2's attempts.
func pickupAttempts(wait time.Duration, attempts int, retryWait time.Duration) int {
	if wait <= 0 || retryWait <= 0 {
		return attempts
	}
	return max(attempts, int(wait/retryWait)+1)
}

// verifyAttempts are the verification attempts for a location: pickupAttempts with winproto.CCSPickupWait for a CCS
// file, the provider's for a binding.
func (p *Provider) verifyAttempts(kind providers.LocationKind) int {
	if kind != providers.LocationWinCCSFile {
		return p.attempts
	}
	return pickupAttempts(winproto.CCSPickupWait, p.attempts, p.retryWait)
}
