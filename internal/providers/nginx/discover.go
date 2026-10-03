package nginx

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"alice/internal/providers"
	"alice/internal/providers/linuxssh"
	"alice/internal/providers/linuxssh/helperproto"
)

// Bounds on what a remote server can make Alice carry (the server is not trusted).
const (
	maxNames              = 100
	maxListens            = 100
	maxServersPerLocation = 500
	maxChainCerts         = 20
	maxWritable           = 50
	maxVersionLength      = 64
	maxPathLength         = 4096
	maxNameLength         = 253
	maxAccountLength      = 64
)

var warningCodeRE = regexp.MustCompile(`^[a-z][a-z_]{0,39}$`)

// configErrors are the classes of NginxFacts.ConfigError, configReasons those of ConfigErrorReason.
var (
	configErrors = []string{providers.ConfigErrKeyMismatch, providers.ConfigErrFileMissing, providers.ConfigErrCertLoad, providers.ConfigErrKeyLoad,
		providers.ConfigErrSyntax, providers.ConfigErrUntrusted, providers.ConfigErrUnsupported}
	configReasons = []string{providers.ConfigReasonNotRootControlled, providers.ConfigReasonSpecialFS, providers.ConfigReasonMissing,
		providers.ConfigReasonNotRegular, providers.ConfigReasonChanged, providers.ConfigReasonNameNotAllowed, providers.ConfigReasonUnexpectedText,
		providers.ConfigReasonWrongFirstFile, providers.ConfigReasonDuplicateFile, providers.ConfigReasonNoConfPath, providers.ConfigReasonTooLarge,
		providers.ConfigReasonTooComplex, providers.ConfigReasonIncludeLoop, providers.ConfigReasonNULByte}
	// pairReasons are the reasons the helper gives an unsupported pair (nginxconf.Reason*).
	pairReasons = []string{providers.UnsupportedVariable, providers.UnsupportedDataValue, providers.UnsupportedEngineKey, providers.UnsupportedKeyMissing,
		providers.UnsupportedPasswordFile, providers.UnsupportedPathNotAllowed, providers.UnsupportedStream, providers.UnsupportedCombinedFile,
		providers.UnsupportedConfigFileWritable}
	fileProblems = []string{providers.CertProblemMissing, providers.CertProblemNotRootControlled, providers.CertProblemNotRegular,
		providers.CertProblemHardLinked, providers.CertProblemTooLarge, providers.CertProblemNotACertificate, providers.CertProblemUnreadable,
		providers.CertProblemBadName, providers.CertProblemSpecialFS}
	usualFolders = []string{"/etc/ssl/", "/etc/nginx/", "/etc/pki/", "/etc/letsencrypt/"}
)

// Discover is linuxssh's discovery plus, when asked, the certificates of nginx-dump (spec §12.4).
// Each half runs only when requested: a certificates-only request runs no SSH-key discovery, and
// an SSH-keys-only request runs no Nginx command. Nginx missing fails the whole discovery (F-20:
// no partial data); an invalid, untrusted or unsupported configuration is a result that says so.
func (s *session) Discover(ctx context.Context, req providers.DiscoverRequest) (providers.DiscoveryResult, error) {
	if err := s.open(); err != nil {
		return providers.DiscoveryResult{}, err
	}
	if !req.Certificates {
		return s.Session.Discover(ctx, providers.DiscoverRequest{SSHKeys: req.SSHKeys})
	}
	// Nginx first: when it is missing nothing else is worth reading.
	out, err := s.conn.Run(ctx, linuxssh.CmdNginxDump())
	if err != nil {
		return providers.DiscoveryResult{}, err
	}
	d, err := linuxssh.DecodeHelper[helperproto.NginxDumpResponse](out, helperproto.SubNginxDump)
	if err != nil {
		return providers.DiscoveryResult{}, mapHelper(err, helperproto.SubNginxDump)
	}
	var res providers.DiscoveryResult
	if req.SSHKeys {
		if res, err = s.Session.Discover(ctx, providers.DiscoverRequest{SSHKeys: true}); err != nil {
			return providers.DiscoveryResult{}, err
		}
	}
	facts := nginxFacts(d)
	res.Nginx = &facts
	if !d.ConfigValid {
		res.Warnings = append(res.Warnings, warning("nginx_config_invalid"))
		res.Warnings = append(res.Warnings, dumpWarnings(d, nil)...)
		return res, nil
	}
	certs, warns := convert(d)
	res.Certificates = certs
	res.Warnings = append(res.Warnings, warns...)
	return res, nil
}

// clean makes remote text safe to keep: invalid UTF-8, control and format characters go, the
// result is trimmed and at most limit runes.
func clean(v string, limit int) string {
	v = strings.ToValidUTF8(v, "")
	v = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return -1
		}
		return r
	}, v)
	v = strings.TrimSpace(v)
	if utf8.RuneCountInString(v) > limit {
		v = string([]rune(v)[:limit])
	}
	return v
}

// cleanPath is clean for an absolute, already clean path of at most maxPathLength; "" otherwise.
func cleanPath(v string) string {
	c := clean(v, maxPathLength+1)
	if utf8.RuneCountInString(c) > maxPathLength || !strings.HasPrefix(c, "/") || path.Clean(c) != c {
		return ""
	}
	return c
}

func knownOrEmpty(v string, set []string) string {
	if slices.Contains(set, v) {
		return v
	}
	return ""
}

// nginxFacts is what the dump says about Nginx itself. The error fields describe an invalid
// configuration only; an unknown class or reason is not passed on.
func nginxFacts(d helperproto.NginxDumpResponse) providers.NginxFacts {
	f := providers.NginxFacts{Found: true, Version: clean(d.Version, maxVersionLength), ConfPath: cleanPath(d.ConfPath), ConfigValid: d.ConfigValid}
	if !d.ConfigValid {
		f.ConfigError = knownOrEmpty(d.ConfigError, configErrors)
		f.ConfigErrorReason = knownOrEmpty(d.ConfigErrorReason, configReasons)
		f.ConfigErrorFile = cleanPath(d.ConfigErrorFile)
	}
	return f
}

// build is a certificate location while the dump's pairs are folded into it.
type build struct {
	loc         providers.CertLocation
	key         string // the first key path of a pair with a key
	supported   bool   // some pair is a supported pair (its files are described)
	pairReason  string // the first unsupported reason of a pair
	keyConflict bool
}

// pairState classifies one pair: its unsupported reason, "" when the pair is supported. An empty
// certificate with a raw value is unsupported, key_missing keeps its certificate and has no key.
func pairState(p helperproto.NginxPair, stream bool) string {
	switch {
	case p.Unsupported != "":
		return knownOrDefault(p.Unsupported, pairReasons, providers.UnsupportedPathNotAllowed)
	case p.Cert == "":
		return providers.UnsupportedPathNotAllowed // neither a pair nor a reason: not usable
	case p.Key == "":
		return providers.UnsupportedKeyMissing
	case stream:
		return providers.UnsupportedStream
	}
	return ""
}

func knownOrDefault(v string, set []string, def string) string {
	if slices.Contains(set, v) {
		return v
	}
	return def
}

// certServer is a server block as Alice shows it: only its SSL listens, cleaned and bounded.
func certServer(s helperproto.NginxServer) providers.CertServer {
	cs := providers.CertServer{Names: []string{}, Listens: []providers.CertListen{}, File: clean(s.File, maxPathLength), Line: max(s.Line, 0)}
	for _, n := range s.Names {
		if n = clean(n, maxNameLength); n != "" && len(cs.Names) < maxNames {
			cs.Names = append(cs.Names, n)
		}
	}
	for _, l := range s.Listens {
		if l.Port >= 1 && l.Port <= 65535 && len(cs.Listens) < maxListens {
			cs.Listens = append(cs.Listens, providers.CertListen{Addr: clean(l.Addr, maxNameLength), Port: l.Port, DefaultServer: l.DefaultServer})
		}
	}
	return cs
}

func sameServer(a, b providers.CertServer) bool {
	return a.File == b.File && a.Line == b.Line && slices.Equal(a.Names, b.Names) && slices.Equal(a.Listens, b.Listens)
}

// convert turns a valid dump into locations: one per certificate path (the raw value of an
// unsupported pair when it has none), in the order the dump names them, with the server blocks
// that use it. The warnings are the dump's, each once.
func convert(d helperproto.NginxDumpResponse) ([]providers.DiscoveredCertificate, []providers.Warning) {
	files := map[string]helperproto.NginxFile{}
	for _, f := range d.Files {
		files[f.Kind+"\x00"+clean(f.Path, maxPathLength)] = f
	}
	builds := map[string]*build{}
	var order []*build
	tooMany := false
	for _, s := range d.Servers {
		cs := certServer(s)
		for _, p := range s.Pairs {
			certPath := clean(p.Cert, maxPathLength)
			if certPath == "" {
				certPath = clean(p.Raw, maxPathLength)
			}
			if certPath == "" {
				continue
			}
			b := builds[certPath]
			if b == nil {
				if len(order) >= helperproto.MaxNginxFiles {
					tooMany = true
					continue
				}
				b = &build{loc: providers.CertLocation{CertPath: certPath, Servers: []providers.CertServer{}}}
				builds[certPath] = b
				order = append(order, b)
			}
			if !slices.ContainsFunc(b.loc.Servers, func(o providers.CertServer) bool { return sameServer(o, cs) }) &&
				len(b.loc.Servers) < maxServersPerLocation {
				b.loc.Servers = append(b.loc.Servers, cs)
			}
			b.loc.Inherited = b.loc.Inherited || p.Inherited
			reason := pairState(p, s.Stream)
			if reason == "" {
				b.supported = true
			} else if b.pairReason == "" {
				b.pairReason = reason
			}
			if k := clean(p.Key, maxPathLength); k != "" {
				if b.key == "" {
					b.key = k
				} else if b.key != k {
					b.keyConflict = true
				}
			}
		}
	}
	out := make([]providers.DiscoveredCertificate, 0, len(order))
	for _, b := range order {
		out = append(out, finish(b, files))
	}
	warns := dumpWarnings(d, out)
	if tooMany && !slices.ContainsFunc(warns, func(w providers.Warning) bool { return w.Code == providers.WarnTooManyFiles }) {
		warns = append(warns, warning(providers.WarnTooManyFiles))
	}
	return out, warns
}

// finish adds the described files to a location and decides whether it is supported.
func finish(b *build, files map[string]helperproto.NginxFile) providers.DiscoveredCertificate {
	loc := b.loc
	loc.KeyPath = b.key
	dc := providers.DiscoveredCertificate{}
	if b.supported {
		cf, haveCert := files["cert\x00"+loc.CertPath]
		kf, haveKey := files["key\x00"+loc.KeyPath]
		loc.Problem = fileProblem(cf, haveCert)
		if haveCert {
			loc.ResolvedCertPath = cleanPath(cf.Resolved)
			loc.Symlinked = cf.Symlinked
			loc.FreeBytes = max(cf.FreeBytes, 0)
		}
		var dropped bool
		if loc.Problem == "" {
			dc.PEMChain, dc.FileSHA256, dropped, loc.Problem = certificateChain(cf)
		}
		loc.KeyProblem = fileProblem(kf, haveKey)
		if haveKey {
			loc.KeyExists = kf.Exists
			loc.KeyMode = cleanMode(kf.Mode)
			loc.KeyOwner = clean(kf.Owner, maxAccountLength)
			loc.KeyGroup = clean(kf.Group, maxAccountLength)
		}
		loc.CustomLocation = customLocation(loc.ResolvedCertPath)
		loc.Warnings = locationWarnings(descriptionOf(cf, haveCert), descriptionOf(kf, haveKey))
		if dropped {
			loc.Warnings = append(loc.Warnings, providers.WarnCertificateBlockDropped)
		}
	}
	switch {
	case b.pairReason != "":
		loc.Unsupported = b.pairReason
	case b.keyConflict:
		loc.Unsupported = providers.UnsupportedKeyConflict
	case loc.Problem != "" || loc.KeyProblem != "" || !loc.KeyExists:
		loc.Unsupported = providers.UnsupportedFile
		if loc.KeyProblem == "" && !loc.KeyExists {
			loc.KeyProblem = providers.CertProblemMissing
		}
	}
	loc.Supported = loc.Unsupported == ""
	dc.Location = loc
	if loc.Problem != "" {
		dc.PEMChain, dc.FileSHA256 = nil, ""
	}
	return dc
}

// descriptionOf is the file as locationWarnings reads it: a file the dump did not describe
// carries nothing.
func descriptionOf(f helperproto.NginxFile, have bool) helperproto.NginxFile {
	if !have {
		return helperproto.NginxFile{}
	}
	return f
}

// fileProblem is the CertProblem* of a described file: the helper's problem (a value outside the
// set is unreadable), missing for an absent file, unreadable for a file the dump did not describe.
func fileProblem(f helperproto.NginxFile, have bool) string {
	switch {
	case !have:
		return providers.CertProblemUnreadable
	case f.Problem != "":
		return knownOrDefault(f.Problem, fileProblems, providers.CertProblemUnreadable)
	case !f.Exists:
		return providers.CertProblemMissing
	}
	return ""
}

// certificateChain parses the file's CERTIFICATE blocks again (the remote is not trusted): the
// chain is rebuilt from the certificates that parse, in file order, so nothing else of the remote
// text is kept. A block that does not parse is dropped (dropped is true); a file with none, too
// many or a malformed hash reports a problem for its location.
func certificateChain(f helperproto.NginxFile) (chain []byte, sum string, dropped bool, problem string) {
	if !helperproto.ValidSHA256(f.SHA256) || f.SHA256 == helperproto.AbsentSHA256 {
		return nil, "", false, providers.CertProblemUnreadable
	}
	if len(f.PEM) > helperproto.MaxCertFileSize {
		return nil, "", false, providers.CertProblemTooLarge
	}
	rest := []byte(f.PEM)
	n := 0
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		if len(block.Headers) > 0 {
			dropped = true
			continue
		}
		if _, err := x509.ParseCertificate(block.Bytes); err != nil {
			dropped = true
			continue
		}
		if n++; n > maxChainCerts {
			return nil, "", false, providers.CertProblemTooLarge
		}
		chain = append(chain, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: block.Bytes})...)
	}
	if n == 0 {
		return nil, "", false, providers.CertProblemNotACertificate
	}
	return chain, f.SHA256, dropped, ""
}

var modeRE = regexp.MustCompile(`^0?[0-7]{3,4}$`)

// cleanMode is a file mode as octal digits, "" for anything else.
func cleanMode(m string) string {
	if !modeRE.MatchString(m) {
		return ""
	}
	return m
}

// customLocation: a resolved path outside the usual certificate folders (an empty one is unknown,
// not custom).
func customLocation(resolved string) bool {
	if resolved == "" {
		return false
	}
	c := path.Clean(resolved)
	for _, dir := range usualFolders {
		if strings.HasPrefix(c, dir) {
			return false
		}
	}
	return true
}

// locationWarnings derives the location-level warnings, in this order: key_mode_open (a mode with
// a bit outside 0640), key_group_open (the helper's rule applied to this key file: an owner other
// than root, a group other than root's that can read it, or others that can read it), symlinked,
// custom_location. The key rules apply to a key file the helper described and found without a
// problem. nil when there are none.
func locationWarnings(cf, kf helperproto.NginxFile) []string {
	var w []string
	mode, err := strconv.ParseUint(kf.Mode, 8, 32)
	if kf.Mode != "" || kf.Exists {
		if err != nil || mode&^0o640 != 0 {
			w = append(w, providers.WarnKeyModeOpen)
		}
	}
	if kf.Exists && kf.Problem == "" {
		rootOwner := kf.Owner == "root" || kf.Owner == "0"
		rootGroup := kf.Group == "root" || kf.Group == "0"
		if !rootOwner || err != nil || (mode&0o040 != 0 && !rootGroup) || mode&0o004 != 0 {
			w = append(w, providers.WarnKeyGroupOpen)
		}
	}
	if cf.Symlinked {
		w = append(w, providers.WarnSymlinked)
	}
	if customLocation(cf.Resolved) {
		w = append(w, providers.WarnCustomLocation)
	}
	return w
}

// dumpWarnings are the dump's server-level warnings, each once and only with a code of the fixed
// format. config_file_writable comes from the writable list, one per path (the helper's own
// parameterless warning would duplicate it). key_group_open is derived per location; the helper's
// warning is kept at server level only when no location carries it.
func dumpWarnings(d helperproto.NginxDumpResponse, locs []providers.DiscoveredCertificate) []providers.Warning {
	var out []providers.Warning
	var seen []string
	keyGroupOpen := false
	for _, w := range d.Warnings {
		switch {
		case !warningCodeRE.MatchString(w) || slices.Contains(seen, w):
			continue
		case w == providers.WarnConfigFileWritable:
			continue
		case w == providers.WarnKeyGroupOpen:
			keyGroupOpen = true
			continue
		}
		seen = append(seen, w)
		out = append(out, warning(w))
	}
	if keyGroupOpen && !slices.ContainsFunc(locs, func(c providers.DiscoveredCertificate) bool {
		return slices.Contains(c.Location.Warnings, providers.WarnKeyGroupOpen)
	}) {
		out = append(out, warning(providers.WarnKeyGroupOpen))
	}
	var paths []string
	for _, p := range d.Writable {
		if p = cleanPath(p); p != "" && !slices.Contains(paths, p) && len(paths) < maxWritable {
			paths = append(paths, p)
			out = append(out, providers.Warning{Code: providers.WarnConfigFileWritable, Params: map[string]string{"path": p}})
		}
	}
	return out
}
