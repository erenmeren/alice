package apacheconf

import (
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"alice/internal/providers/linuxssh/helperproto"
)

// Limits of the evaluated configuration, on top of the lexer's.
const (
	// MaxPairs bounds the pairs of all servers together: every vhost may inherit every
	// certificate of the main server, so without it the output would grow with their product.
	MaxPairs = 1 << 16
	// maxExpansion is the longest value one ${VAR} expansion may produce (Apache's
	// MAX_STRING_LEN); a longer one is treated as an undefined variable.
	maxExpansion = 8192
	// certkeysIdxMax is mod_ssl's CERTKEYS_IDX_MAX: a vhost's first two certificates (and keys)
	// replace the main server's at the same index (modssl_ctx_cfg_merge_certkeys_array).
	certkeysIdxMax = 1
)

// Input is everything Parse reads: the include tree (ParseIncludes), the content of every file it
// names (Files, by path; a path listed twice is read twice), the modules (ParseModules), the run
// configuration (ParseRunConfig) and the version ("-V").
type Input struct {
	Includes []Included
	Files    map[string][]byte
	Modules  Modules
	Run      RunConfig
	Version  string
}

// Config is the evaluated configuration: the TLS servers in read order (the main server first
// when it is one) and the files of the include tree (distinct, in tree order).
type Config struct {
	Servers []Server
	Files   []string
}

// Server is a <VirtualHost> whose effective SSLEngine is on and that has at least one effective
// SSLCertificateFile, or the main server (Main) when it has its own SSLEngine on and certificates.
// File and Line are the <VirtualHost line (the main server's first SSLCertificateFile). Names are
// the ServerName (scheme and port stripped; a vhost without one on a wildcard address takes the
// main server's) and then the ServerAlias arguments.
type Server struct {
	File    string
	Line    int
	Names   []string
	Listens []Listen
	Pairs   []Pair
	Main    bool
}

// Listen is one address of a <VirtualHost>: Addr "" is any address (*, _default_, 0.0.0.0).
// Default is true for _default_ and for the first vhost of an address and port in read order.
type Listen struct {
	Addr    string
	Port    int
	Default bool
}

// Pair is the i-th SSLCertificateFile with the i-th SSLCertificateKeyFile; without the latter
// the key is in the certificate file (Key == Cert). Cert and Key are set only when Unsupported
// is "". CertRaw and KeyRaw are the arguments as written. Inherited is true when either came
// from the main server.
type Pair struct {
	Cert, Key, CertRaw, KeyRaw string
	Inherited                  bool
	Unsupported                string
}

// CertPaths returns the distinct certificate paths of supported pairs, in order.
func (c Config) CertPaths() []string { return c.paths(func(p Pair) string { return p.Cert }) }

// KeyPaths returns the distinct key paths of supported pairs, in order.
func (c Config) KeyPaths() []string { return c.paths(func(p Pair) string { return p.Key }) }

func (c Config) paths(get func(Pair) string) []string {
	var out []string
	seen := map[string]bool{}
	for _, s := range c.Servers {
		for _, p := range s.Pairs {
			if v := get(p); p.Unsupported == "" && !seen[v] {
				seen[v] = true
				out = append(out, v)
			}
		}
	}
	return out
}

// MarkWritable makes every supported pair unsupported config_file_writable. The root helper calls
// it when a loaded configuration file can be changed by a user other than root: Define and
// Include reach the whole configuration, so the rule is not per pair as for nginx.
func MarkWritable(c *Config) {
	for i := range c.Servers {
		for j := range c.Servers[i].Pairs {
			if p := &c.Servers[i].Pairs[j]; p.Unsupported == "" {
				p.Unsupported = ReasonConfigFileWritable
			}
		}
	}
}

// ToWire converts a server for the helper's answer (shared by the helper and its emulator).
// Slices are never nil, text is cleaned of control characters and invalid UTF-8 and cut (file
// 4096 bytes, names and addresses 253 bytes), Raw is CertRaw cut to 200 runes for an unsupported
// pair only, and Stream is false.
func ToWire(s Server) helperproto.DumpServer {
	out := helperproto.DumpServer{File: clean(s.File, 4096), Line: s.Line, Names: []string{}, Listens: []helperproto.DumpListen{},
		Pairs: []helperproto.DumpPair{}}
	for _, n := range s.Names {
		out.Names = append(out.Names, clean(n, 253))
	}
	for _, l := range s.Listens {
		out.Listens = append(out.Listens, helperproto.DumpListen{Addr: clean(l.Addr, 253), Port: l.Port, DefaultServer: l.Default})
	}
	for _, p := range s.Pairs {
		wp := helperproto.DumpPair{Cert: p.Cert, Key: p.Key, Inherited: p.Inherited, Unsupported: p.Unsupported}
		if p.Unsupported != "" {
			wp.Raw = clean(p.CertRaw, len(p.CertRaw))
			if r := []rune(wp.Raw); len(r) > 200 {
				wp.Raw = string(r[:200])
			}
		}
		out.Pairs = append(out.Pairs, wp)
	}
	return out
}

// clean drops control characters and invalid UTF-8 and cuts s to at most maxBytes on a rune
// boundary (the helper's rule for text it returns).
func clean(s string, maxBytes int) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || r == utf8.RuneError {
			return -1
		}
		return r
	}, strings.ToValidUTF8(s, ""))
	for len(s) > maxBytes {
		_, size := utf8.DecodeLastRuneInString(s)
		s = s[:len(s)-size]
	}
	return s
}

// Parse evaluates the configuration the way Apache reads it (Rulings 8-11):
//   - every file of the include tree is lexed; the input of all files together is at most
//     MaxInput bytes and MaxTokens words (a file listed twice counts twice), checked before
//     anything is evaluated;
//   - an Include or IncludeOptional directive whose last physical line is n is replaced by the
//     tree children of its file at line n, in tree order; a child no directive takes, or one
//     under an Include in a false region, is ErrIncludeMismatch;
//   - <IfModule>, <IfDefine> and <IfVersion> are evaluated in read order against the modules,
//     defines and version; every other <If…>/<Else…> section, a regular expression, an unknown
//     module name and a <Macro> body are uncertain; a false region is skipped;
//   - SSLEngine, SSLCertificateFile, SSLCertificateKeyFile, ServerName and ServerAlias are
//     collected at the main level and directly in a <VirtualHost> (through conditions only);
//     other sections are descended for Include only.
//
// The walk is iterative: no recursion follows the input, sections nest at most MaxDepth deep
// across files and includes at most MaxDepth deep. On error the Config is empty.
func Parse(in Input) (Config, error) {
	p, err := newParser(in)
	if err != nil {
		return Config{}, err
	}
	if err := p.walk(); err != nil {
		return Config{}, err
	}
	servers, err := p.servers()
	if err != nil {
		return Config{}, err
	}
	return Config{Servers: servers, Files: p.files()}, nil
}

// region is the state of a part of the configuration: read, maybe read, or skipped. A nested
// region is the strongest of its own and its parents' states.
type region uint8

const (
	active region = iota
	uncertain
	inactive
)

type sectionKind uint8

const (
	kindCond  sectionKind = iota // a condition: transparent for collecting
	kindVhost                    // the <VirtualHost> being collected
	kindOther                    // any other section: descended for Include only
	kindSkip                     // a section inside a false region
)

type section struct {
	kind sectionKind
	eff  region
}

// status of a value after ${VAR} expansion, by strength.
const (
	statusOK uint8 = iota
	statusVariable
	statusConditional
)

// define is one Define in effect. hasValue is false for "Define NAME" (${NAME} is then not
// expanded); tainted means its value held an undefined variable; maybe means it may or may not
// be defined (or hold this value).
type define struct {
	value    string
	hasValue bool
	tainted  bool
	maybe    bool
}

// ref is one SSLCertificateFile or SSLCertificateKeyFile: the argument as written, the path it
// resolves to (when status is statusOK and ok), and where it is.
type ref struct {
	raw    string
	path   string
	ok     bool
	status uint8
	file   string
	line   int
}

// Possible values of SSLEngine in a scope, as a set.
const (
	engineUnset uint8 = 1 << iota
	engineOn
	engineOff
)

// scope is what the main server or one vhost collects.
type scope struct {
	file      string
	line      int
	name      string
	hasName   bool
	aliases   []string
	engine    uint8
	certs     []ref
	keys      []ref
	listens   []Listen
	uncertain bool // the vhost lies in an uncertain region, or a name with "${" was read in the scope
	// nameUncertain: a ServerName or ServerAlias of the scope was read in an uncertain region, so the
	// names shown may not be the ones Apache uses. The rows that show them are conditional, as for
	// uncertain; at the main level only the rows that show the main server's name are.
	nameUncertain bool
}

type listenKey struct {
	addr string
	port int
}

type parser struct {
	in      Input
	lines   [][]line // lexed lines per tree entry
	kids    map[[2]int][]int
	stack   []section
	others  int // kindOther sections on the stack
	cur     int // index of the vhost being collected, -1 at the main level
	main    scope
	vhosts  []scope
	defines map[string]define
	// definesUnknown: a Define or UnDefine named a variable that could not be expanded, so any
	// define may have changed; modulesUnknown: likewise for LoadModule.
	definesUnknown, modulesUnknown bool
	modules                        map[string]region // loaded modules: active (certainly) or uncertain
	version                        [3]int
	versionOK                      bool
	firsts                         map[listenKey]bool
	expanded                       int
	// overBudget is sticky: the expansions produced more than MaxInput bytes. expand then
	// returns at once, and the walk stops with ErrTooComplex after the line.
	overBudget bool
}

func newParser(in Input) (*parser, error) {
	n := len(in.Includes)
	switch {
	case n == 0:
		return nil, fmt.Errorf("%w: no include tree", ErrOutput)
	case n > MaxFiles:
		return nil, ErrTooComplex
	}
	p := &parser{in: in, lines: make([][]line, n), kids: map[[2]int][]int{}, cur: -1,
		main: scope{engine: engineUnset}, defines: map[string]define{}, modules: map[string]region{}, firsts: map[listenKey]bool{}}
	depth := make([]int, n)
	size := 0
	for i, e := range in.Includes {
		if i == 0 {
			if e.Parent != -1 {
				return nil, fmt.Errorf("%w: the root of the include tree has a parent", ErrOutput)
			}
		} else {
			if e.Parent < 0 || e.Parent >= i || e.Line < 1 {
				return nil, fmt.Errorf("%w: include tree entry %d", ErrOutput, i)
			}
			if depth[i] = depth[e.Parent] + 1; depth[i] > MaxDepth {
				return nil, ErrTooDeep
			}
			key := [2]int{e.Parent, e.Line}
			p.kids[key] = append(p.kids[key], i)
		}
		data, ok := in.Files[e.Path]
		if !ok {
			return nil, fmt.Errorf("%w: %s was not read", ErrIncludeMismatch, e.Path)
		}
		if size += len(data); size > MaxInput {
			return nil, ErrTooLarge
		}
	}
	// Lex every entry (a path listed twice is lexed once and counted twice), counting the words
	// of the whole configuration, and note the names Define and UnDefine set.
	cache := map[string][]line{}
	defined, undefined := map[string]bool{}, map[string]bool{}
	tokens := 0
	hiddenDefine := false // a Define or UnDefine name holds "${": any name may be meant
	for i, e := range in.Includes {
		lines, ok := cache[e.Path]
		if !ok {
			var err error
			if lines, err = lex(e.Path, in.Files[e.Path]); err != nil {
				return nil, err
			}
			cache[e.Path] = lines
			for _, l := range lines {
				if len(l.args) > 0 && !l.section && !l.closing {
					switch l.name {
					case "define":
						defined[l.args[0]] = true
					case "undefine":
						undefined[l.args[0]] = true
					default:
						continue
					}
					hiddenDefine = hiddenDefine || strings.Contains(l.args[0], "${")
				}
			}
		}
		for _, l := range lines {
			if tokens += 1 + len(l.args); tokens > MaxTokens {
				return nil, lexErr(ErrTooComplex, e.Path, l.first)
			}
		}
		p.lines[i] = lines
	}
	// The defines Apache started with: those of DUMP_RUN_CFG that no Define of the configuration
	// sets came from the command line. One that a Define also sets, or one the configuration
	// undefines and DUMP_RUN_CFG no longer lists, may or may not have been there at the start.
	for name, v := range in.Run.Defines {
		p.defines[name] = define{value: v, hasValue: v != "", maybe: defined[name] || hiddenDefine}
	}
	for name := range undefined {
		if _, ok := in.Run.Defines[name]; !ok && !defined[name] {
			p.defines[name] = define{maybe: true}
		}
	}
	for name := range in.Modules.Static {
		p.modules[name] = active
	}
	p.version, p.versionOK = parseVersion(leadingVersion(in.Version))
	return p, nil
}

// walk reads the tree entries in Apache's order, splicing children at their Include lines.
func (p *parser) walk() error {
	type frame struct{ entry, pos int }
	frames := []frame{{0, 0}}
	for len(frames) > 0 {
		f := &frames[len(frames)-1]
		if f.pos >= len(p.lines[f.entry]) {
			frames = frames[:len(frames)-1]
			continue
		}
		entry, l := f.entry, p.lines[f.entry][f.pos]
		f.pos++
		kids, err := p.line(entry, l)
		if err != nil {
			return err
		}
		if p.overBudget {
			return lexErr(ErrTooComplex, p.in.Includes[entry].Path, l.first)
		}
		for i := len(kids) - 1; i >= 0; i-- {
			frames = append(frames, frame{kids[i], 0})
		}
	}
	for i, e := range p.in.Includes[1:] {
		if _, left := p.kids[[2]int{e.Parent, e.Line}]; left {
			return fmt.Errorf("%w: entry %d, %s at line %d of %s", ErrIncludeMismatch, i+1, e.Path, e.Line, p.in.Includes[e.Parent].Path)
		}
	}
	return nil
}

func (p *parser) eff() region {
	if len(p.stack) == 0 {
		return active
	}
	return p.stack[len(p.stack)-1].eff
}

// line evaluates one logical line of tree entry entry and returns the entries to splice after it.
func (p *parser) line(entry int, l line) ([]int, error) {
	file := p.in.Includes[entry].Path
	eff := p.eff()
	switch {
	case l.closing:
		top := p.stack[len(p.stack)-1]
		p.stack = p.stack[:len(p.stack)-1]
		switch top.kind {
		case kindVhost:
			p.cur = -1
		case kindOther:
			p.others--
		}
		return nil, nil
	case l.section:
		if len(p.stack) >= MaxDepth {
			return nil, lexErr(ErrTooDeep, file, l.first)
		}
		s := section{kind: kindSkip, eff: inactive}
		if eff != inactive {
			var own region
			p.hiddenName(l.name)
			s.kind, own = p.open(file, l, eff)
			s.eff = max(eff, own)
		}
		if s.kind == kindOther {
			p.others++
		}
		p.stack = append(p.stack, s)
		return nil, nil
	}
	switch l.name {
	case "include", "includeoptional":
		key := [2]int{entry, l.last}
		kids := p.kids[key]
		if len(kids) > 0 && eff == inactive {
			return nil, lexErr(ErrIncludeMismatch, file, l.last)
		}
		delete(p.kids, key)
		return kids, nil
	}
	if eff == inactive {
		return nil, nil
	}
	maybe := eff == uncertain
	switch l.name {
	case "define":
		p.define(l.args, maybe)
	case "undefine":
		p.undefine(l.args, maybe)
	case "loadmodule":
		p.loadModule(l.args, maybe)
	}
	p.hiddenName(l.name)
	if p.others > 0 {
		return nil, nil
	}
	sc := p.scope()
	switch {
	case l.name == "servername" && len(l.args) > 0:
		sc.name, sc.hasName = p.hostName(l.args[0]), true
		sc.nameUncertain = sc.nameUncertain || maybe
	case l.name == "serveralias":
		sc.nameUncertain = sc.nameUncertain || maybe
		for _, a := range l.args {
			if p.overBudget {
				break
			}
			sc.aliases = append(sc.aliases, p.nameArg(a))
		}
	case l.name == "sslengine" && len(l.args) > 0:
		v := engineOn | engineOff // "SSLEngine addr:port …" (newer mod_ssl): on for some addresses
		if len(l.args) == 1 {
			switch asciiLower(l.args[0]) {
			case "on":
				v = engineOn
			case "off", "optional":
				v = engineOff
			}
		}
		if maybe {
			sc.engine |= v
		} else {
			sc.engine = v
		}
	case l.name == "sslcertificatefile" && len(l.args) == 1:
		sc.certs = p.appendRef(sc.certs, l.args[0], file, l.first, maybe)
	case l.name == "sslcertificatekeyfile" && len(l.args) == 1:
		sc.keys = p.appendRef(sc.keys, l.args[0], file, l.first, maybe)
	}
	return nil, nil
}

// scope is the main server or the vhost being collected.
func (p *parser) scope() *scope {
	if p.cur >= 0 {
		return &p.vhosts[p.cur]
	}
	return &p.main
}

// hiddenName handles a directive or section name with "${": Apache expands the whole line before
// it splits it (ap_resolve_env in ap_build_config_sub), so the name may be any directive, such
// as an SSLCertificateKeyFile that would change a pair. The scope being collected becomes
// uncertain.
func (p *parser) hiddenName(name string) {
	if p.others == 0 && strings.Contains(name, "${") {
		p.scope().uncertain = true
	}
}

// open evaluates a section start in a region that is not false.
func (p *parser) open(file string, l line, eff region) (sectionKind, region) {
	switch l.name {
	case "ifmodule":
		return kindCond, p.ifModule(l.args)
	case "ifdefine":
		return kindCond, p.ifDefine(l.args)
	case "ifversion":
		return kindCond, p.ifVersion(l.args)
	case "macro":
		// the body runs only where a Use expands it, which Alice does not do
		return kindOther, uncertain
	case "virtualhost":
		if p.cur >= 0 || p.others > 0 {
			return kindOther, active // Apache refuses a nested vhost: never collected
		}
		p.vhost(file, l, eff)
		return kindVhost, active
	}
	if strings.HasPrefix(l.name, "if") || strings.HasPrefix(l.name, "else") {
		return kindCond, uncertain
	}
	return kindOther, active
}

// vhost starts collecting a <VirtualHost>, with its listens and their default flags.
func (p *parser) vhost(file string, l line, eff region) {
	sc := scope{file: file, line: l.first, engine: engineUnset, uncertain: eff == uncertain}
	for _, a := range l.args {
		v, st := p.expand(a)
		if st != statusOK {
			continue
		}
		ln, isDefault, ok := parseAddr(v)
		if !ok {
			continue
		}
		key := listenKey{ln.Addr, ln.Port}
		ln.Default = isDefault || !p.firsts[key]
		p.firsts[key] = true
		sc.listens = append(sc.listens, ln)
	}
	p.vhosts = append(p.vhosts, sc)
	p.cur = len(p.vhosts) - 1
}

// parseAddr reads a <VirtualHost> address "host:port" or "[v6]:port". A missing or "*" port, or
// one outside 1-65535, drops it. *, _default_ and 0.0.0.0 are any address ("").
func parseAddr(s string) (l Listen, isDefault, ok bool) {
	var host, port string
	if strings.HasPrefix(s, "[") {
		end := strings.IndexByte(s, ']')
		if end < 0 || !strings.HasPrefix(s[end+1:], ":") {
			return Listen{}, false, false
		}
		host, port = s[1:end], s[end+2:]
	} else {
		i := strings.LastIndexByte(s, ':')
		if i < 0 {
			return Listen{}, false, false
		}
		host, port = s[:i], s[i+1:]
		if strings.IndexByte(host, ':') >= 0 {
			return Listen{}, false, false // an IPv6 address without brackets has no port
		}
	}
	n, err := strconv.Atoi(port)
	if err != nil || !digits(port) || n < 1 || n > 65535 || host == "" {
		return Listen{}, false, false
	}
	switch host {
	case "_default_":
		isDefault, host = true, ""
	case "*", "0.0.0.0", "::":
		host = ""
	}
	return Listen{Addr: host, Port: n}, isDefault, true
}

func digits(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return s != ""
}

// appendRef adds one entry to a certificate or key list. Once the list holds a conditional entry,
// every later entry is conditional too: whether that entry exists shifts their index, and so
// the pair they belong to.
func (p *parser) appendRef(list []ref, raw, file string, line int, maybe bool) []ref {
	r := p.ref(raw, file, line, maybe)
	if n := len(list); n > 0 && list[n-1].status == statusConditional {
		r.status = statusConditional
	}
	return append(list, r)
}

// ref expands and resolves one SSLCertificateFile or SSLCertificateKeyFile argument.
func (p *parser) ref(raw, file string, line int, maybe bool) ref {
	v, st := p.expand(raw)
	r := ref{raw: raw, status: st, file: file, line: line}
	if maybe {
		r.status = statusConditional
	}
	if r.status == statusOK {
		r.path, r.ok = resolvePath(v, p.in.Run.ServerRoot)
	}
	return r
}

// resolvePath is nginx's rule: no "." or ".." segment and no trailing "/" in the raw text, a
// relative path joins ServerRoot, and the result must be a valid helper path other than "/".
func resolvePath(raw, root string) (string, bool) {
	segs := strings.Split(raw, "/")
	if segs[len(segs)-1] == "" {
		return "", false
	}
	for _, seg := range segs {
		if seg == "." || seg == ".." {
			return "", false
		}
	}
	p := raw
	if !strings.HasPrefix(p, "/") {
		if !strings.HasPrefix(root, "/") {
			return "", false
		}
		p = filepath.Join(root, p)
	}
	p = filepath.Clean(p)
	return p, helperproto.ValidPath(p) && p != "/"
}

// hostName is a ServerName: the scheme and the port are stripped. A name with an undefined
// variable is kept as written.
func (p *parser) hostName(raw string) string {
	v, st := p.expand(raw)
	if st != statusOK {
		return raw
	}
	if _, rest, ok := strings.Cut(v, "://"); ok {
		v = rest
	}
	if strings.HasPrefix(v, "[") {
		if end := strings.IndexByte(v, ']'); end >= 0 {
			return v[:end+1]
		}
		return v
	}
	if i := strings.LastIndexByte(v, ':'); i >= 0 && digits(v[i+1:]) {
		v = v[:i]
	}
	return v
}

// nameArg is a ServerAlias argument, expanded, or as written when that is not possible.
func (p *parser) nameArg(raw string) string {
	if v, st := p.expand(raw); st == statusOK {
		return v
	}
	return raw
}

// expand is ap_resolve_env: every "${NAME}" with a closing brace is replaced by the value of the
// define NAME. Apache falls back to its environment, which Alice does not know: an undefined
// NAME (or one defined without a value, or whose value held an undefined variable) gives
// statusVariable, a define that may not be in effect statusConditional. A result longer than
// maxExpansion is statusVariable. The bytes produced by all expansions together are counted
// against MaxInput (expanded).
func (p *parser) expand(s string) (string, uint8) {
	if !strings.Contains(s, "${") {
		return s, statusOK
	}
	var b strings.Builder
	st := statusOK
	// write accounts every piece before it is copied: the budget is never exceeded by more than
	// one piece of at most maxExpansion bytes, whatever one line holds.
	write := func(piece string) bool {
		if p.overBudget {
			return false
		}
		if p.expanded += len(piece); p.expanded > MaxInput {
			p.overBudget = true
			return false
		}
		if b.Len()+len(piece) > maxExpansion {
			return false
		}
		b.WriteString(piece)
		return true
	}
	for {
		i := strings.Index(s, "${")
		j := -1
		if i >= 0 {
			j = strings.IndexByte(s[i+2:], '}')
		}
		if i < 0 || j < 0 {
			if !write(s) {
				return "", max(st, statusVariable)
			}
			break
		}
		name := s[i+2 : i+2+j]
		d, ok := p.defines[name]
		switch {
		case ok && d.maybe:
			st = max(st, statusConditional)
		case !ok || !d.hasValue || d.tainted:
			st = max(st, statusVariable)
		}
		value := s[i : i+3+j]
		if ok && d.hasValue {
			value = d.value
		}
		if !write(s[:i]) || !write(value) {
			return "", max(st, statusVariable)
		}
		s = s[i+3+j:]
	}
	return b.String(), st
}

func (p *parser) define(args []string, maybe bool) {
	if len(args) == 0 || len(args) > 2 {
		return
	}
	name, st := p.expand(args[0])
	if st != statusOK {
		p.definesUnknown = true
		return
	}
	d := define{maybe: maybe}
	if len(args) == 2 {
		v, vst := p.expand(args[1])
		d.value, d.hasValue = v, true
		d.tainted = vst == statusVariable
		d.maybe = d.maybe || vst == statusConditional
	}
	p.defines[name] = d
}

func (p *parser) undefine(args []string, maybe bool) {
	if len(args) != 1 {
		return
	}
	name, st := p.expand(args[0])
	switch {
	case st != statusOK:
		p.definesUnknown = true
	case maybe:
		if d, ok := p.defines[name]; ok {
			d.maybe = true
			p.defines[name] = d
		}
	default:
		delete(p.defines, name)
	}
}

func (p *parser) loadModule(args []string, maybe bool) {
	if len(args) == 0 {
		return
	}
	name, st := p.expand(args[0])
	switch {
	case st != statusOK:
		p.modulesUnknown = true
	case maybe:
		if r, ok := p.modules[name]; !ok || r != active {
			p.modules[name] = uncertain
		}
	default:
		p.modules[name] = active
	}
}

// condArg reads the one argument of <IfModule> or <IfDefine>: its name without "!", whether it
// was negated, and false when the argument count is wrong or a variable in it cannot be expanded.
func (p *parser) condArg(args []string) (name string, not, ok bool) {
	if len(args) != 1 {
		return "", false, false
	}
	v, st := p.expand(args[0])
	if st != statusOK {
		return "", false, false
	}
	name, not = strings.CutPrefix(v, "!")
	return name, not, name != ""
}

// negate applies "!" to a condition's state.
func negate(r region, not bool) region {
	switch {
	case !not || r == uncertain:
		return r
	case r == active:
		return inactive
	}
	return active
}

func (p *parser) ifModule(args []string) region {
	arg, not, ok := p.condArg(args)
	if !ok {
		return uncertain
	}
	name, ok := ModuleName(arg)
	if !ok {
		return uncertain
	}
	r, loaded := p.modules[name]
	if !loaded {
		r = inactive
		if p.modulesUnknown {
			r = uncertain
		}
	}
	return negate(r, not)
}

func (p *parser) ifDefine(args []string) region {
	name, not, ok := p.condArg(args)
	if !ok {
		return uncertain
	}
	d, defined := p.defines[name]
	r := inactive
	switch {
	case defined && d.maybe, p.definesUnknown:
		r = uncertain
	case defined:
		r = active
	}
	return negate(r, not)
}

// ifVersion is mod_version: "<IfVersion [[!]op] version>" with op =, ==, <, <=, >, >= (default
// =). A regular expression (~ or /…/), an unknown operator or version, or a server version
// Alice cannot read is uncertain.
func (p *parser) ifVersion(args []string) region {
	op, arg := "=", ""
	switch len(args) {
	case 1:
		arg = args[0]
	case 2:
		op, arg = args[0], args[1]
	default:
		return uncertain
	}
	not := false
	if rest, ok := strings.CutPrefix(op, "!"); ok {
		not, op = true, rest
		if op == "" {
			op = "="
		}
	}
	if !p.versionOK || strings.HasPrefix(arg, "/") {
		return uncertain
	}
	want, ok := parseVersion(arg)
	if !ok {
		return uncertain
	}
	c := 0
	for i := range 3 {
		if p.version[i] != want[i] {
			c = 1
			if p.version[i] < want[i] {
				c = -1
			}
			break
		}
	}
	var res bool
	switch op {
	case "=", "==":
		res = c == 0
	case "<":
		res = c < 0
	case "<=":
		res = c <= 0
	case ">":
		res = c > 0
	case ">=":
		res = c >= 0
	default:
		return uncertain
	}
	if res != not {
		return active
	}
	return inactive
}

// parseVersion reads "major[.minor[.patch]]" (missing parts are 0, as in mod_version), each part
// 1 to 9 digits.
func parseVersion(s string) ([3]int, bool) {
	var v [3]int
	parts := strings.Split(s, ".")
	if len(parts) > 3 {
		return v, false
	}
	for i, part := range parts {
		if !digits(part) || len(part) > 9 {
			return v, false
		}
		v[i], _ = strconv.Atoi(part)
	}
	return v, true
}

// leadingVersion is the "major.minor.patch" prefix of the -V version ("2.4.57" of "2.4.57-dev").
func leadingVersion(s string) string {
	i := 0
	for i < len(s) && (s[i] == '.' || s[i] >= '0' && s[i] <= '9') {
		i++
	}
	return s[:i]
}

// servers resolves mod_ssl's merge of every vhost with the main server and builds the result.
func (p *parser) servers() ([]Server, error) {
	var out []Server
	pairs := 0
	add := func(s Server) error {
		if pairs += len(s.Pairs); pairs > MaxPairs {
			return ErrTooComplex
		}
		out = append(out, s)
		return nil
	}
	mainEngine := p.main.engine
	if p.main.engine&engineOn != 0 && len(p.main.certs) > 0 {
		s := Server{File: p.main.certs[0].file, Line: p.main.certs[0].line, Main: true}
		if p.main.hasName {
			s.Names = []string{p.main.name}
		}
		certs := merge(nil, p.main.certs, len(p.main.certs))
		conditional := p.main.uncertain || p.main.nameUncertain || mainEngine != engineOn
		if err := add(withPairs(s, certs, merge(nil, p.main.keys, len(certs)), conditional)); err != nil {
			return nil, err
		}
	}
	if mainEngine&engineUnset != 0 {
		mainEngine = mainEngine&^engineUnset | engineOff
	}
	for _, v := range p.vhosts {
		engine := v.engine
		if engine&engineUnset != 0 {
			engine = engine&^engineUnset | mainEngine
		}
		// Only a listed vhost merges: the merge costs the main server's lists each time, and the
		// pairs it yields count against MaxPairs, which bounds the total work.
		if engine&engineOn == 0 || len(p.main.certs)+len(v.certs) == 0 {
			continue
		}
		certs := merge(p.main.certs, v.certs, len(p.main.certs)+len(v.certs))
		s := Server{File: v.file, Line: v.line, Listens: v.listens}
		nameUncertain := v.nameUncertain
		switch {
		case v.hasName:
			s.Names = append(s.Names, v.name)
		case p.main.hasName && anyAddress(v.listens):
			// ap_fini_vhost_config: a vhost without a ServerName on a wildcard address takes the
			// main server's (on a specific address Apache asks DNS, which Alice does not).
			s.Names = append(s.Names, p.main.name)
			nameUncertain = nameUncertain || p.main.nameUncertain
		}
		s.Names = append(s.Names, v.aliases...)
		// A hidden directive at the main level (main.uncertain) may be any SSL directive every
		// vhost inherits. A name read in an uncertain region is never shown as certain.
		conditional := v.uncertain || p.main.uncertain || nameUncertain || engine != engineOn
		if err := add(withPairs(s, certs, merge(p.main.keys, v.keys, len(certs)), conditional)); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func anyAddress(listens []Listen) bool {
	for _, l := range listens {
		if l.Addr == "" {
			return true
		}
	}
	return false
}

// merged is one entry of an effective certificate or key list.
type merged struct {
	ref
	inherited bool
}

// merge is modssl_ctx_cfg_merge_certkeys_array: the first CERTKEYS_IDX_MAX+1 entries of add,
// then base from that index on, then the rest of add. It stops after n entries (the keys past
// the last certificate are never used).
func merge(base, add []ref, n int) []merged {
	out := make([]merged, 0, min(n, max(len(base), len(add))))
	i := 0
	for ; i < len(add) && i <= certkeysIdxMax && len(out) < n; i++ {
		out = append(out, merged{ref: add[i]})
	}
	for ; i < len(base) && len(out) < n; i++ {
		out = append(out, merged{ref: base[i], inherited: true})
	}
	for i = certkeysIdxMax + 1; i < len(add) && len(out) < n; i++ {
		out = append(out, merged{ref: add[i]})
	}
	return out
}

// withPairs pairs certs[i] with keys[i]; conditional makes every pair conditional.
func withPairs(s Server, certs, keys []merged, conditional bool) Server {
	for i, c := range certs {
		pr := Pair{CertRaw: c.raw, Inherited: c.inherited}
		st, ok, key := c.status, c.ok, c.path
		if i < len(keys) {
			k := keys[i]
			pr.KeyRaw, pr.Inherited = k.raw, pr.Inherited || k.inherited
			st, ok, key = max(st, k.status), ok && k.ok, k.path
		}
		if conditional {
			st = statusConditional
		}
		switch {
		case st == statusConditional:
			pr.Unsupported = ReasonConditional
		case st == statusVariable:
			pr.Unsupported = ReasonVariable
		case !ok:
			pr.Unsupported = ReasonPathNotAllowed
		default:
			pr.Cert, pr.Key = c.path, key
		}
		s.Pairs = append(s.Pairs, pr)
	}
	return s
}

// files are the distinct paths of the include tree, in tree order.
func (p *parser) files() []string {
	var out []string
	seen := map[string]bool{}
	for _, e := range p.in.Includes {
		if !seen[e.Path] {
			seen[e.Path] = true
			out = append(out, e.Path)
		}
	}
	return out
}
