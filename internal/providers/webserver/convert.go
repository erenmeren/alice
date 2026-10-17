package webserver

import (
	"crypto/x509"
	"encoding/pem"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"alice/internal/platform/validate"
	"alice/internal/providers"
	"alice/internal/providers/linuxssh/helperproto"
)

// MaxChainCerts bounds the chain length of a certificate file and of a probed server (the nginx
// provider's verification uses it too).
const MaxChainCerts = 20

// Bounds on what a remote server can make Alice carry (the server is not trusted).
const (
	maxNames              = 100
	maxListens            = 100
	maxServersPerLocation = 500
	// maxMembershipsPerDump and maxNamesPerDump bound the whole dump (RA-01): the per-location and
	// per-file bounds alone let one 16 MiB dump answer list 500 server blocks under each of
	// 1000 certificate paths, 500,000 server copies (~7 GiB) in memory and in the stored facts. A
	// membership is one server block listed under one location; names counts their server names.
	maxMembershipsPerDump = 20000
	maxNamesPerDump       = 100000
	maxWritable           = 50
	maxVersionLength      = 64
	maxPathLength         = 4096
	maxNameLength         = 253
	maxAccountLength      = 64
	// maxDumpWarnings bounds the distinct server-level warning codes kept from a dump (A2-I3: the
	// list is the remote's; the helper gives at most six today, a newer one may add some).
	maxDumpWarnings = 32
)

var warningCodeRE = regexp.MustCompile(`^[a-z][a-z_]{0,39}$`)

// configErrors are the classes of WebServerFacts.ConfigError, configReasons those of ConfigErrorReason.
var (
	configErrors = []string{providers.ConfigErrKeyMismatch, providers.ConfigErrFileMissing, providers.ConfigErrCertLoad, providers.ConfigErrKeyLoad,
		providers.ConfigErrSyntax, providers.ConfigErrUntrusted, providers.ConfigErrUnsupported}
	configReasons = []string{providers.ConfigReasonNotRootControlled, providers.ConfigReasonSpecialFS, providers.ConfigReasonMissing,
		providers.ConfigReasonNotRegular, providers.ConfigReasonChanged, providers.ConfigReasonNameNotAllowed, providers.ConfigReasonUnexpectedText,
		providers.ConfigReasonWrongFirstFile, providers.ConfigReasonDuplicateFile, providers.ConfigReasonNoConfPath, providers.ConfigReasonTooLarge,
		providers.ConfigReasonTooComplex, providers.ConfigReasonIncludeLoop, providers.ConfigReasonNULByte}
	// pairReasons are the reasons the helper gives an unsupported pair (nginxconf.Reason*, apacheconf.Reason*,
	// haproxyconf.Reason*).
	pairReasons = []string{providers.UnsupportedVariable, providers.UnsupportedDataValue, providers.UnsupportedEngineKey, providers.UnsupportedKeyMissing,
		providers.UnsupportedPasswordFile, providers.UnsupportedPathNotAllowed, providers.UnsupportedStream, providers.UnsupportedCombinedFile,
		providers.UnsupportedConfigFileWritable, providers.UnsupportedConditional, providers.UnsupportedUnknownKeyword}
	fileProblems = []string{providers.CertProblemMissing, providers.CertProblemNotRootControlled, providers.CertProblemNotRegular,
		providers.CertProblemHardLinked, providers.CertProblemTooLarge, providers.CertProblemNotACertificate, providers.CertProblemUnreadable,
		providers.CertProblemBadName, providers.CertProblemSpecialFS, providers.CertProblemNameNotAllowed, providers.CertProblemLeafUnreadable}
)

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

// shownPath is how a pair path of the dump is shown: the raw value when helperproto.ValidPath
// holds (it is then clean already), else invalidPath; "" for "".
func shownPath(raw string) string {
	switch {
	case raw == "":
		return ""
	case helperproto.ValidPath(raw):
		return raw
	}
	return invalidPath(raw)
}

// invalidPath shows a pair path that fails helperproto.ValidPath (the location is path_not_allowed):
// the raw value, cut at maxPathLength bytes, quoted with Go escapes. It is never a cleaned rewrite
// that could read as (or merge with) another, real path, and never starts with "/".
func invalidPath(raw string) string {
	if len(raw) > maxPathLength {
		raw = raw[:maxPathLength]
	}
	return strconv.QuoteToASCII(raw)
}

func knownOrEmpty(v string, set []string) string {
	if slices.Contains(set, v) {
		return v
	}
	return ""
}

// webServerFacts is what the dump says about the web server itself (software is Spec.Software).
// The error fields describe an invalid configuration only; an unknown class or reason is not passed on.
func webServerFacts(software string, d helperproto.ServerDumpResponse) providers.WebServerFacts {
	f := providers.WebServerFacts{Software: software, Found: true, Version: clean(d.Version, maxVersionLength), ConfPath: cleanPath(d.ConfPath), ConfigValid: d.ConfigValid}
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
func pairState(p helperproto.DumpPair, stream bool) string {
	switch {
	case p.Unsupported != "":
		return knownOrDefault(p.Unsupported, pairReasons, providers.UnsupportedUnknown)
	case p.Cert == "":
		return providers.UnsupportedUnknown // neither a pair nor a reason: not usable
	case !helperproto.ValidPath(p.Cert) || (p.Key != "" && !helperproto.ValidPath(p.Key)):
		// The raw paths are validated before any cleaning: a path is never rewritten into another one.
		return providers.UnsupportedPathNotAllowed
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

// certServer is a server block as Alice shows it, cleaned and bounded. The helper lists SSL listens
// only (nginxconf.SSLListens), so none is filtered here; truncated reports a list cut at its bound.
func certServer(s helperproto.DumpServer) (cs providers.CertServer, truncated bool) {
	cs = providers.CertServer{Names: []string{}, Listens: []providers.CertListen{}, File: clean(s.File, maxPathLength), Line: max(s.Line, 0),
		Section: clean(s.Section, maxNameLength)}
	for _, n := range s.Names {
		if n = clean(n, maxNameLength); n != "" {
			if len(cs.Names) >= maxNames {
				truncated = true
				continue
			}
			cs.Names = append(cs.Names, n)
		}
	}
	for _, l := range s.Listens {
		if l.Port >= 1 && l.Port <= 65535 {
			if len(cs.Listens) >= maxListens {
				truncated = true
				continue
			}
			cs.Listens = append(cs.Listens, providers.CertListen{Addr: clean(l.Addr, maxNameLength), Port: l.Port, DefaultServer: l.DefaultServer})
		}
	}
	return cs, truncated
}

// nameCost is what a server adds to the dump's name budget: its names, and one for a section.
func nameCost(s providers.CertServer) int {
	if s.Section != "" {
		return len(s.Names) + 1
	}
	return len(s.Names)
}

func sameServer(a, b providers.CertServer) bool {
	return a.File == b.File && a.Line == b.Line && a.Section == b.Section && slices.Equal(a.Names, b.Names) && slices.Equal(a.Listens, b.Listens)
}

// convert turns a valid dump into locations: one per certificate path (the raw value of an
// unsupported pair when it has none), in the order the dump names them, with the server blocks
// that use it. The warnings are the dump's, each once. A resolved certificate outside folders (the
// web server's usual certificate folders) is a custom location.
func convert(d helperproto.ServerDumpResponse, folders []string) ([]providers.DiscoveredCertificate, []providers.Warning) {
	files := map[string]helperproto.DumpFile{}
	for _, f := range d.Files {
		// Keyed by the raw path, and only a valid one: a spelling that cleaning would turn into a
		// real path never describes that path's file.
		if helperproto.ValidPath(f.Path) {
			files[f.Kind+"\x00"+f.Path] = f
		}
	}
	builds := map[string]*build{}
	var order []*build
	tooMany, truncated := false, false
	memberships, names := 0, 0 // across the dump, bounded by maxMembershipsPerDump and maxNamesPerDump
	for _, s := range d.Servers {
		cs, cut := certServer(s)
		truncated = truncated || cut
		for _, p := range s.Pairs {
			certPath := shownPath(p.Cert)
			if certPath == "" {
				certPath = clean(p.Raw, maxPathLength)
			}
			if certPath == "" {
				continue
			}
			b := builds[certPath]
			if b == nil {
				if len(order) >= helperproto.MaxServerFiles {
					tooMany = true
					continue
				}
				b = &build{loc: providers.CertLocation{CertPath: certPath, Servers: []providers.CertServer{}}}
				builds[certPath] = b
				order = append(order, b)
			}
			if !slices.ContainsFunc(b.loc.Servers, func(o providers.CertServer) bool { return sameServer(o, cs) }) {
				// A server already listed costs nothing; a new one must fit the location's bound and
				// the dump's budget, else it is left out and the list said to be cut.
				if len(b.loc.Servers) >= maxServersPerLocation || memberships >= maxMembershipsPerDump ||
					names+nameCost(cs) > maxNamesPerDump {
					truncated = true
				} else {
					b.loc.Servers = append(b.loc.Servers, cs)
					memberships++
					names += nameCost(cs)
				}
			}
			b.loc.Inherited = b.loc.Inherited || p.Inherited
			reason := pairState(p, s.Stream)
			if reason == "" {
				b.supported = true
			} else if b.pairReason == "" {
				b.pairReason = reason
			}
			if k := shownPath(p.Key); k != "" {
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
		out = append(out, finish(b, files, folders))
	}
	warns, cutWritable := dumpWarnings(d, out)
	truncated = truncated || cutWritable
	if tooMany {
		// Locations were left out: inventory must not read the list as every location of the server.
		warns = append(warns, warning(providers.WarnLocationsDropped))
	}
	if truncated {
		warns = append(warns, warning(providers.WarnListTruncated))
	}
	return out, warns
}

// finish adds the described files to a location and decides whether it is supported.
func finish(b *build, files map[string]helperproto.DumpFile, folders []string) providers.DiscoveredCertificate {
	loc := b.loc
	loc.KeyPath = b.key
	dc := providers.DiscoveredCertificate{}
	if b.supported {
		cf, haveCert := files["cert\x00"+loc.CertPath]
		kf, haveKey := files["key\x00"+loc.KeyPath]
		loc.Problem = fileProblem(cf, haveCert)
		if loc.Problem == "" && resolvedOutsideVocabulary(cf, haveCert) {
			loc.Problem = providers.CertProblemNameNotAllowed
		}
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
		if loc.KeyProblem == "" && resolvedOutsideVocabulary(kf, haveKey) {
			loc.KeyProblem = providers.CertProblemNameNotAllowed
		}
		if haveKey {
			loc.KeyExists = kf.Exists
			loc.KeyMode = cleanMode(kf.Mode)
			loc.KeyOwner = clean(kf.Owner, maxAccountLength)
			loc.KeyGroup = clean(kf.Group, maxAccountLength)
		}
		loc.CustomLocation = customLocation(loc.ResolvedCertPath, folders)
		loc.Warnings = locationWarnings(descriptionOf(cf, haveCert), descriptionOf(kf, haveKey), folders)
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
func descriptionOf(f helperproto.DumpFile, have bool) helperproto.DumpFile {
	if !have {
		return helperproto.DumpFile{}
	}
	return f
}

// resolvedOutsideVocabulary reports a described file whose resolved path the helper's argument
// vocabulary cannot carry (A1-I1): the helper refuses to deploy to it, and a helper before that
// fix would have deployed and then been unable to read its own journal. Alice treats it as
// unsupported whatever the helper said.
func resolvedOutsideVocabulary(f helperproto.DumpFile, have bool) bool {
	return have && f.Resolved != "" && !helperproto.ValidPath(f.Resolved)
}

// fileProblem is the CertProblem* of a described file: the helper's problem (a value outside the
// set is unreadable), missing for an absent file, unreadable for a file the dump did not describe.
func fileProblem(f helperproto.DumpFile, have bool) string {
	switch {
	case !have:
		return providers.CertProblemUnreadable
	case f.Problem != "":
		return knownOrDefault(f.Problem, fileProblems, providers.CertProblemUnknown)
	case !f.Exists:
		return providers.CertProblemMissing
	}
	return ""
}

// certificateChain parses the file's CERTIFICATE blocks again (the remote is not trusted): the
// chain is rebuilt from the certificates that parse, in file order, so nothing else of the remote
// text is kept. A block that does not parse, or whose validity dates lie outside the years 1 to 9999
// in UTC (validate.CertificateTimes, the rule internal/certs applies: AUD-13), is dropped (dropped
// is true); a file with none, too many or a malformed hash reports a problem for its location.
func certificateChain(f helperproto.DumpFile) (chain []byte, sum string, dropped bool, problem string) {
	if !helperproto.ValidSHA256(f.SHA256) || f.SHA256 == helperproto.AbsentSHA256 {
		return nil, "", false, providers.CertProblemUnreadable
	}
	if len(f.PEM) > helperproto.MaxCertFileSize {
		return nil, "", false, providers.CertProblemTooLarge
	}
	rest := []byte(f.PEM)
	n, seen := 0, false
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		first := !seen
		seen = true
		c, perr := x509.ParseCertificate(block.Bytes)
		if len(block.Headers) > 0 || perr != nil || !validate.CertificateTimes(c.NotBefore, c.NotAfter) {
			if first {
				// The next certificate would become the leaf: the file is not usable.
				return nil, "", false, providers.CertProblemNotACertificate
			}
			dropped = true
			continue
		}
		if n++; n > MaxChainCerts {
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
func customLocation(resolved string, folders []string) bool {
	if resolved == "" {
		return false
	}
	c := path.Clean(resolved)
	for _, dir := range folders {
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
func locationWarnings(cf, kf helperproto.DumpFile, folders []string) []string {
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
	if customLocation(cf.Resolved, folders) {
		w = append(w, providers.WarnCustomLocation)
	}
	return w
}

// dumpWarnings are the dump's server-level warnings, each once and only with a code of the fixed
// format. config_file_writable comes from the writable list, one per path (the helper's own
// parameterless warning would duplicate it). key_group_open is derived per location; the helper's
// warning is kept at server level only when no location carries it.
//
// A2-I3: the loop is linear in the helper's list (a set of the codes seen) and at most
// maxDumpWarnings distinct codes are kept; more set truncated (list_truncated).
func dumpWarnings(d helperproto.ServerDumpResponse, locs []providers.DiscoveredCertificate) (out []providers.Warning, truncated bool) {
	seen := map[string]bool{}
	keyGroupOpen := false
	for _, w := range d.Warnings {
		switch {
		case !warningCodeRE.MatchString(w) || seen[w]:
			continue
		case w == providers.WarnConfigFileWritable:
			continue
		case w == providers.WarnKeyGroupOpen:
			keyGroupOpen = true
			continue
		case len(seen) >= maxDumpWarnings:
			truncated = true
			continue
		}
		seen[w] = true
		out = append(out, warning(w))
	}
	if keyGroupOpen && !slices.ContainsFunc(locs, func(c providers.DiscoveredCertificate) bool {
		return slices.Contains(c.Location.Warnings, providers.WarnKeyGroupOpen)
	}) {
		out = append(out, warning(providers.WarnKeyGroupOpen))
	}
	var paths []string
	for _, p := range d.Writable {
		if p = cleanPath(p); p != "" && !slices.Contains(paths, p) {
			if len(paths) >= maxWritable {
				truncated = true
				continue
			}
			paths = append(paths, p)
			out = append(out, providers.Warning{Code: providers.WarnConfigFileWritable, Params: map[string]string{"path": p}})
		}
	}
	return out, truncated
}
