package haproxyconf

import (
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"

	"alice/internal/providers/linuxssh/helperproto"
)

// Input is everything Parse reads: haproxy.cfg (Path and its text Data), the version of
// "haproxy -v" (ParseV) and two callbacks through which the root helper reads the files the
// configuration names. Parse never does I/O itself.
//
//   - ReadFile returns the text of a crt-list file. Each distinct path is asked for once.
//   - ReadDir says whether path is a directory and, when it is, gives the names of its regular
//     entries (a link counts when it resolves to a regular file). It is asked once per distinct
//     path of a crt argument or crt-list entry; a path that is not a directory (or whose walk
//     fails: the helper then describes the file) answers isDir false.
//
// An error of either callback is returned by Parse, wrapped with %w.
type Input struct {
	Path     string
	Data     []byte
	Version  string
	ReadFile func(path string) ([]byte, error)
	ReadDir  func(path string) (names []string, isDir bool, err error)
}

// Config is the evaluated configuration: the TLS servers in read order, and the server-level
// warnings of the parse (WarnListTruncated). Warnings is the parser's part only: the root
// helper appends its own (config_dir_not_read for a conf.d it does not read, Ruling 2 and C14),
// so an empty Servers list never stands without a reason it could give.
type Config struct {
	Servers  []Server
	Warnings []string
}

// Server is one bind of a frontend or listen section with the keyword ssl (all its crt pairs,
// files and directory entries, Names empty), or one line of a crt-list the bind names (that
// line's SNI filters). File is haproxy.cfg and Line the bind line for all of them (Ruling 13).
// Section is the frontend or listen name, "" when the section is uncertain. The servers of one
// bind share one Listens slice, and the servers of one crt-list line (one per bind naming the
// file) share its Names slice: neither may be changed.
type Server struct {
	File    string
	Line    int
	Section string
	Names   []string
	Listens []Listen
	Pairs   []Pair
}

// Pair is one certificate file. Cert is the path HAProxy loads and Key the file the key is read
// from: Key == Cert until ResolveKeys. KeyBeside is the companion "<cert>.key" HAProxy looks for
// when the PEM holds no key ("" when key lookup is off; Ruling 12). Cert, Key and KeyBeside are
// set only when Unsupported is "" (or config_file_writable, set by MarkWritable). CertRaw is the
// path as written (a directory entry: the crt argument, "/" and the entry name).
type Pair struct {
	Cert, Key, CertRaw, KeyBeside string
	Unsupported                   string
}

// Parse evaluates haproxy.cfg the way HAProxy reads it (Rulings 6-14):
//   - sections: global, defaults, frontend and listen are read, the other sections skipped;
//     a disabled or enabled line in a frontend or listen and in defaults is followed;
//   - .if/.elif/.else/.endif blocks are evaluated when the condition is empty or one integer,
//     and are uncertain otherwise; a pair in an uncertain region is conditional;
//   - crt-base, ssl-load-extra-files and ssl-load-extra-del-ext are followed in read order;
//   - each bind with ssl gives one server for its crt pairs and one per line of each crt-list
//     it names; a crt naming a directory gives one pair per certificate entry. Each crt-list
//     file, directory and certificate is evaluated once, with the settings in effect where it
//     was first named, as HAProxy loads each once.
//
// The walk is iterative. MaxTokens counts the words of haproxy.cfg and of every crt-list
// together; MaxCrtLists, MaxDirs, MaxDirEntries, MaxPairs, MaxServers and MaxNames are
// ErrTooComplex, MaxDepth ErrTooDeep. Listens over MaxListens are cut with WarnListTruncated.
// On error the Config is empty.
func Parse(in Input) (Config, error) {
	lines, used, err := lexBudget(in.Data, MaxTokens)
	if err != nil {
		return Config{}, fmt.Errorf("%s: %w", in.Path, err)
	}
	p := &parser{in: in, tokens: used, keyLookup: true, lists: map[string][]listEntry{}, dirs: map[string]dirInfo{}, keys: map[string]keyInfo{}}
	for _, l := range lines {
		if err := p.line(l); err != nil {
			return Config{}, err
		}
	}
	if len(p.conds) > 0 {
		return Config{}, fmt.Errorf("%s: %w (an .if block is not closed)", in.Path, ErrSyntax)
	}
	p.closeSection()
	c := Config{Servers: p.out}
	if p.truncated {
		c.Warnings = []string{WarnListTruncated}
	}
	return c, nil
}

// region is the state of a part of the configuration, by strength: read, maybe read, skipped.
type region uint8

const (
	active region = iota
	uncertain
	inactive
)

// cond is one open .if block. eff is the state of its current branch, with its parent's;
// taken says a branch was certainly taken, maybe that an uncertain branch was seen.
type cond struct {
	parent, eff            region
	taken, maybe, elseSeen bool
}

// Section kinds, as a set: a header in an uncertain region adds its kind to the current one.
const (
	kindGlobal uint8 = 1 << iota
	kindDefaults
	kindProxy // frontend or listen
	kindOther
)

var sectionKinds = map[string]uint8{
	"global": kindGlobal, "defaults": kindDefaults, "frontend": kindProxy, "listen": kindProxy,
	"backend": kindOther, "peers": kindOther, "log-forward": kindOther, "resolvers": kindOther, "userlist": kindOther,
	"mailers": kindOther, "program": kindOther, "http-errors": kindOther, "ring": kindOther, "cache": kindOther,
	"fcgi-app": kindOther, "crt-store": kindOther, "traces": kindOther, "acme": kindOther,
}

// section is the section being read. uncertain: a header in an uncertain region was read since
// the last certain one, so the lines may belong to more than one section (the kinds). The
// servers are kept until the section ends, because a disabled line after a bind omits them.
type section struct {
	kinds     uint8
	name      string
	uncertain bool
	// defaults: a defaults section had a disabled or enabled line when this section began.
	defaults bool
	// own, disabled: the section's last disabled or enabled line in a certain place, and which;
	// ownUncertain: one was read in an uncertain place.
	own, disabled, ownUncertain bool
	servers                     []Server
}

// setting is a global value and whether it was set in an uncertain place.
type setting struct {
	value     string
	set       bool
	dollar    bool
	uncertain bool
}

// listEntry is one line of a crt-list, evaluated when the file was first named.
type listEntry struct {
	names []string
	pair  Pair
}

// dirInfo is ReadDir's answer for one path: for a directory, the certificate entries in
// bytewise order.
type dirInfo struct {
	isDir bool
	names []string
}

// keyInfo is the companion key file of a certificate, from where it was first named.
type keyInfo struct {
	beside    string
	bad       bool // the companion is not a helper path
	uncertain bool // a setting it depends on was set in an uncertain place
}

type parser struct {
	in    Input
	conds []cond
	sec   section
	out   []Server

	crtBase                 setting
	keyLookup, keyLookupUnc bool
	delExt, delExtUnc       bool
	defaultsTouched         bool

	lists                                  map[string][]listEntry
	dirs                                   map[string]dirInfo
	keys                                   map[string]keyInfo
	nDirs                                  int
	tokens, pairs, servers, names, listens int
	truncated                              bool
}

func (p *parser) eff() region {
	if len(p.conds) == 0 {
		return active
	}
	return p.conds[len(p.conds)-1].eff
}

func (p *parser) errAt(err error, n int) error {
	return fmt.Errorf("%s: %w", p.in.Path, lineErr(err, n))
}

func (p *parser) line(l line) error {
	kw := l.words[0].text
	if strings.HasPrefix(kw, ".") {
		return p.directive(l)
	}
	eff := p.eff()
	if eff == inactive {
		return nil
	}
	if kind, ok := sectionKinds[kw]; ok {
		p.header(kind, l, eff)
		return nil
	}
	maybe := eff == uncertain || p.sec.uncertain
	args := l.words[1:]
	switch {
	case kw == "bind" && p.sec.kinds&kindProxy != 0:
		return p.bind(l, maybe)
	case kw == "disabled" || kw == "enabled":
		if p.sec.kinds&kindDefaults != 0 {
			p.defaultsTouched = true
		}
		if p.sec.kinds&kindProxy != 0 {
			if maybe {
				p.sec.ownUncertain = true
			} else {
				p.sec.own, p.sec.disabled = true, kw == "disabled"
			}
		}
	case p.sec.kinds&kindGlobal == 0:
	case kw == "crt-base" && len(args) > 0:
		p.crtBase = setting{value: args[0].text, set: true, dollar: args[0].dollar, uncertain: maybe}
	case kw == "ssl-load-extra-files" && len(args) > 0:
		p.keyLookup = slices.ContainsFunc(args, func(w word) bool { return w.text == "all" || w.text == "key" })
		p.keyLookupUnc = maybe
	case kw == "ssl-load-extra-del-ext":
		p.delExt, p.delExtUnc = true, maybe
	}
	return nil
}

// directive reads a line starting with ".": the .if block lines; the message lines (.diag,
// .notice, .warning, .alert) and any other are ignored.
func (p *parser) directive(l line) error {
	switch l.words[0].text {
	case ".if":
		if len(p.conds) >= MaxDepth {
			return p.errAt(ErrTooDeep, l.n)
		}
		c := cond{parent: p.eff()}
		if c.parent == inactive {
			c.eff, c.taken = inactive, true
		} else {
			c.branch(evalCond(l.words[1:]))
		}
		p.conds = append(p.conds, c)
	case ".elif", ".else":
		if len(p.conds) == 0 || p.conds[len(p.conds)-1].elseSeen {
			return p.errAt(ErrSyntax, l.n)
		}
		c := &p.conds[len(p.conds)-1]
		value := active
		if l.words[0].text == ".elif" {
			value = evalCond(l.words[1:])
		} else {
			c.elseSeen = true
		}
		if c.taken {
			c.eff = inactive
		} else {
			c.branch(value)
		}
	case ".endif":
		if len(p.conds) == 0 {
			return p.errAt(ErrSyntax, l.n)
		}
		p.conds = p.conds[:len(p.conds)-1]
	}
	return nil
}

// branch enters a branch whose condition is value (active: true, inactive: false), after the
// branches before it, none of which was certainly taken.
func (c *cond) branch(value region) {
	switch {
	case value == inactive:
		c.eff = inactive
	case value == uncertain || c.maybe:
		// an uncertain condition, or a certain one after an uncertain branch that may have been taken
		c.eff = max(c.parent, uncertain)
		c.maybe = true
		c.taken = c.taken || value == active
	default:
		c.eff, c.taken = c.parent, true
	}
}

// evalCond evaluates an .if or .elif condition (Ruling 7): no word is false, one word without
// "$" that is an integer is true unless it is 0, anything else is uncertain.
func evalCond(args []word) region {
	if len(args) == 0 {
		return inactive
	}
	if len(args) > 1 || args[0].dollar {
		return uncertain
	}
	digits := strings.TrimPrefix(args[0].text, "-")
	if digits == "" || strings.Trim(digits, "0123456789") != "" {
		return uncertain
	}
	if strings.Trim(digits, "0") == "" {
		return inactive
	}
	return active
}

// header reads a section header. In an active region it ends the current section and begins a
// new one; in an uncertain one it makes the current section uncertain and adds its kind.
func (p *parser) header(kind uint8, l line, eff region) {
	if eff == uncertain {
		p.sec.kinds |= kind
		p.sec.uncertain = true
		return
	}
	p.closeSection()
	p.sec = section{kinds: kind, defaults: p.defaultsTouched}
	if kind == kindProxy && len(l.words) > 1 {
		p.sec.name = l.words[1].text
	}
}

// closeSection moves the servers of the section to the output: all of them conditional when a
// disabled or enabled line was uncertain, or when a defaults section had one and the section
// sets neither itself; none when it was disabled.
func (p *parser) closeSection() {
	s := &p.sec
	switch {
	case len(s.servers) == 0:
	case s.ownUncertain || !s.own && s.defaults:
		for i := range s.servers {
			for j := range s.servers[i].Pairs {
				unsupport(&s.servers[i].Pairs[j], ReasonConditional)
			}
		}
		p.out = append(p.out, s.servers...)
	case s.own && s.disabled:
	default:
		p.out = append(p.out, s.servers...)
	}
	s.servers = nil
}

// unsupport makes a supported pair unsupported for reason; an unsupported pair keeps its reason.
func unsupport(pair *Pair, reason string) {
	if pair.Unsupported == "" {
		*pair = Pair{CertRaw: pair.CertRaw, Unsupported: reason}
	}
}

// bind reads a bind line (Ruling 8): its arguments by bindArity up to the first unknown
// keyword. A bind without ssl is not listed.
func (p *parser) bind(l line, maybe bool) error {
	words := l.words
	if len(words) < 2 {
		return nil
	}
	type arg struct {
		list bool
		w    word
	}
	var (
		args         []arg
		ssl, unknown bool
	)
	for i := 2; i < len(words); {
		kw := words[i].text
		n, ok := bindArity[kw]
		if !ok {
			// The arguments of an unknown keyword cannot be told from keywords; a later "ssl"
			// may be one, so the bind is listed (unsupported) rather than left out.
			unknown = true
			ssl = ssl || slices.ContainsFunc(words[i+1:], func(w word) bool { return w.text == "ssl" })
			break
		}
		if i+n >= len(words) {
			break // a keyword without its argument: -c refuses it
		}
		switch kw {
		case "ssl":
			ssl = true
		case "crt", "crt-list":
			args = append(args, arg{kw == "crt-list", words[i+1]})
		}
		i += 1 + n
	}
	if !ssl || len(args) == 0 {
		return nil
	}
	listens := p.listensOf(words[1].text)
	section := p.sec.name
	if p.sec.uncertain {
		section = ""
	}
	bindServer := Server{File: p.in.Path, Line: l.n, Section: section, Listens: listens}
	var extra []Server
	for _, a := range args {
		if !a.list {
			if err := p.crt(a.w, &bindServer.Pairs); err != nil {
				return err
			}
			continue
		}
		entries, pair, err := p.crtList(a.w)
		if err != nil {
			return err
		}
		if pair != nil {
			if err := p.addPairs(&bindServer.Pairs, *pair); err != nil {
				return err
			}
			continue
		}
		if p.servers+len(entries) > MaxServers {
			return ErrTooComplex
		}
		for _, e := range entries {
			s := Server{File: p.in.Path, Line: l.n, Section: section, Names: e.names, Listens: listens}
			if err := p.addPairs(&s.Pairs, e.pair); err != nil {
				return err
			}
			if err := p.addServer(s); err != nil {
				return err
			}
			extra = append(extra, s)
		}
	}
	if len(bindServer.Pairs) > 0 {
		if err := p.addServer(bindServer); err != nil {
			return err
		}
		extra = append([]Server{bindServer}, extra...)
	}
	for i := range extra {
		for j := range extra[i].Pairs {
			pair := &extra[i].Pairs[j]
			switch {
			case unknown:
				*pair = Pair{CertRaw: pair.CertRaw, Unsupported: ReasonUnknownKeyword}
			case maybe:
				unsupport(pair, ReasonConditional)
			}
		}
	}
	p.sec.servers = append(p.sec.servers, extra...)
	return nil
}

// listensOf parses a bind address within what is left of MaxListens.
func (p *parser) listensOf(arg string) []Listen {
	listens, cut := parseListens(arg, MaxListens-p.listens)
	p.listens += len(listens)
	p.truncated = p.truncated || cut
	return listens
}

func (p *parser) addServer(s Server) error {
	if p.servers++; p.servers > MaxServers {
		return ErrTooComplex
	}
	if p.names += len(s.Names); p.names > MaxNames {
		return ErrTooComplex
	}
	return nil
}

func (p *parser) addPairs(to *[]Pair, pairs ...Pair) error {
	if p.pairs += len(pairs); p.pairs > MaxPairs {
		return ErrTooComplex
	}
	*to = append(*to, pairs...)
	return nil
}

// crt reads one crt argument into pairs: a file, or the certificate entries of a directory.
func (p *parser) crt(w word, pairs *[]Pair) error {
	raw := w.text
	path, reason := p.resolve(raw, w.dollar)
	if path == "" {
		return p.addPairs(pairs, Pair{CertRaw: raw, Unsupported: reason})
	}
	d, err := p.readDir(path)
	if err != nil {
		return err
	}
	if !d.isDir {
		return p.addPairs(pairs, p.filePair(path, raw, reason))
	}
	// Dotfiles are loaded below 2.6 and skipped from 2.6 on (Ruling 10).
	skipDots, known := minorAtLeast(p.in.Version, 2, 6)
	for _, name := range d.names {
		r := reason
		if name[0] == '.' {
			if skipDots {
				continue
			}
			if !known {
				r = ReasonConditional
			}
		}
		pair := Pair{CertRaw: raw + "/" + name, Unsupported: ReasonPathNotAllowed}
		if helperproto.ValidPath(path + "/" + name) {
			pair = p.filePair(path+"/"+name, raw+"/"+name, r)
		}
		if err := p.addPairs(pairs, pair); err != nil {
			return err
		}
	}
	return nil
}

// resolve makes a crt path absolute (Ruling 9): a relative one is joined to the crt-base in
// effect. It returns the path, or "" and the reason the pair is unsupported: variable for a "$"
// (in the path or the crt-base it needs), path_not_allowed for a path the helper may not use
// (no crt-base or a relative one, a "." or ".." segment, a final "/", not helperproto.ValidPath,
// or "/"), conditional when the crt-base it needs was set in an uncertain place. A path with a
// reason conditional is returned too: the files it names are still described.
func (p *parser) resolve(raw string, dollar bool) (string, string) {
	if dollar {
		return "", ReasonVariable
	}
	if !cleanSegments(raw) {
		return "", ReasonPathNotAllowed
	}
	path, reason := raw, ""
	if !strings.HasPrefix(raw, "/") {
		base := p.crtBase
		switch {
		case base.uncertain && (!base.set || base.dollar || !strings.HasPrefix(base.value, "/") || !cleanSegments(strings.TrimRight(base.value, "/")+"/x")):
			return "", ReasonConditional
		case !base.set:
			return "", ReasonPathNotAllowed
		case base.dollar:
			return "", ReasonVariable
		case !strings.HasPrefix(base.value, "/") || !cleanSegments(strings.TrimRight(base.value, "/")+"/x"):
			return "", ReasonPathNotAllowed
		case base.uncertain:
			reason = ReasonConditional
		}
		path = base.value + "/" + raw
	}
	path = filepath.Clean(path)
	if !helperproto.ValidPath(path) || path == "/" {
		if reason == "" {
			reason = ReasonPathNotAllowed
		}
		return "", reason
	}
	return path, reason
}

// cleanSegments is nginx's resolvePath rule on the raw text: no "." or ".." segment and no
// final "/" (folding them textually could name a different file than the kernel opens).
func cleanSegments(raw string) bool {
	if raw == "" || strings.HasSuffix(raw, "/") {
		return false
	}
	for seg := range strings.SplitSeq(raw, "/") {
		if seg == "." || seg == ".." {
			return false
		}
	}
	return true
}

// filePair is the pair of a certificate file with its companion key (Ruling 12). reason is ""
// or conditional (from the crt-base or the version).
func (p *parser) filePair(path, raw, reason string) Pair {
	k, ok := p.keys[path]
	if !ok {
		if p.keyLookup {
			k.beside = path + ".key"
			if p.delExt {
				if stem, crt := strings.CutSuffix(path, ".crt"); crt {
					k.beside = stem + ".key"
				}
			}
			k.bad = !helperproto.ValidPath(k.beside)
		}
		k.uncertain = p.keyLookupUnc || p.keyLookup && p.delExtUnc && strings.HasSuffix(path, ".crt")
		p.keys[path] = k
	}
	switch {
	case k.bad:
		return Pair{CertRaw: raw, Unsupported: ReasonPathNotAllowed}
	case reason != "" || k.uncertain:
		return Pair{CertRaw: raw, Unsupported: ReasonConditional}
	}
	return Pair{Cert: path, Key: path, CertRaw: raw, KeyBeside: k.beside}
}

// readDir asks ReadDir once per path and keeps the certificate entries of a directory: not a
// key, OCSP, issuer or SCT file (Ruling 10), in bytewise order.
func (p *parser) readDir(path string) (dirInfo, error) {
	if d, ok := p.dirs[path]; ok {
		return d, nil
	}
	if p.in.ReadDir == nil {
		return dirInfo{}, errors.New("haproxyconf: no ReadDir")
	}
	names, isDir, err := p.in.ReadDir(path)
	if err != nil {
		return dirInfo{}, fmt.Errorf("haproxyconf: listing %s: %w", path, err)
	}
	d := dirInfo{isDir: isDir}
	if isDir {
		if p.nDirs++; p.nDirs > MaxDirs || len(names) > MaxDirEntries {
			return dirInfo{}, ErrTooComplex
		}
		for _, n := range names {
			switch {
			case n == "" || n == "." || n == ".." || strings.Contains(n, "/"):
			case strings.HasSuffix(n, ".key"), strings.HasSuffix(n, ".ocsp"), strings.HasSuffix(n, ".issuer"), strings.HasSuffix(n, ".sctl"):
			default:
				d.names = append(d.names, n)
			}
		}
		slices.Sort(d.names)
	}
	p.dirs[path] = d
	return d, nil
}

// crtList reads one crt-list argument. A path that cannot be read (a "$", relative, not a helper
// path; never joined to crt-base) gives the one unsupported pair for the bind's server; else the
// entries, read and evaluated once per path.
func (p *parser) crtList(w word) ([]listEntry, *Pair, error) {
	raw := w.text
	switch {
	case w.dollar:
		return nil, &Pair{CertRaw: raw, Unsupported: ReasonVariable}, nil
	case !strings.HasPrefix(raw, "/") || !cleanSegments(raw) || !helperproto.ValidPath(raw) || raw == "/":
		return nil, &Pair{CertRaw: raw, Unsupported: ReasonPathNotAllowed}, nil
	}
	if entries, ok := p.lists[raw]; ok {
		return entries, nil, nil
	}
	if len(p.lists) >= MaxCrtLists {
		return nil, nil, ErrTooComplex
	}
	if p.in.ReadFile == nil {
		return nil, nil, errors.New("haproxyconf: no ReadFile")
	}
	data, err := p.in.ReadFile(raw)
	if err != nil {
		return nil, nil, fmt.Errorf("haproxyconf: reading %s: %w", raw, err)
	}
	lines, used, err := parseCrtListBudget(data, MaxTokens-p.tokens)
	if err != nil {
		return nil, nil, fmt.Errorf("%s: %w", raw, err)
	}
	p.tokens += used
	// Every line becomes a server of this bind: a list over the bound is refused before its
	// entries are looked at.
	if p.servers+len(lines) > MaxServers {
		return nil, nil, ErrTooComplex
	}
	entries := make([]listEntry, 0, len(lines))
	for _, l := range lines {
		e := listEntry{names: l.names}
		path, reason := p.resolve(l.path, strings.Contains(l.path, "$"))
		if path == "" {
			e.pair = Pair{CertRaw: l.path, Unsupported: reason}
		} else {
			d, err := p.readDir(path)
			if err != nil {
				return nil, nil, err
			}
			if d.isDir {
				// HAProxy refuses a directory in a crt-list (Ruling 10).
				e.pair = Pair{CertRaw: l.path, Unsupported: ReasonPathNotAllowed}
			} else {
				e.pair = p.filePair(path, l.path, reason)
			}
		}
		entries = append(entries, e)
	}
	p.lists[raw] = entries
	return entries, nil, nil
}
