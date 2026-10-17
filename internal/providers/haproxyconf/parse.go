package haproxyconf

import (
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	"alice/internal/providers/linuxssh/helperproto"
)

// MaxWire bounds the encoded size of all servers Parse returns (review C1 and I1 of Task 5): the
// size of their helperproto.DumpServer JSON, estimated from above as they are built, counting
// each server's own copy of the listens, names and pairs it shares with others. It is twice
// the helper's whole answer (helperproto.ServerDumpOutput), so the bounds above, not this one,
// limit an ordinary configuration, while no configuration makes the helper build or encode
// more than this before it refuses the answer.
const MaxWire = 2 * helperproto.ServerDumpOutput

// maxRaw is the longest CertRaw in runes (the wire's Raw).
const maxRaw = 200

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
	wire     int // the estimated size of the servers on the wire (MaxWire)
}

// Server is one bind of a frontend or listen section with the keyword ssl (all its crt pairs,
// files and directory entries, Names empty), or one line of a crt-list the bind names (that
// line's SNI filters). File is haproxy.cfg and Line the bind line for all of them (Ruling 13).
// Section is the frontend or listen name, cleaned and cut as on the wire, "" when the section
// is uncertain. Names are cleaned and cut as on the wire. The servers of one bind share one
// Listens slice (a server past MaxListens has a shorter prefix of it), and the servers of one
// crt-list line (one per bind naming the file) share its Names slice: neither may be changed.
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
// path as written (a directory entry: the crt argument, "/" and the entry name), cleaned and cut
// to 200 runes as the wire's Raw shows it.
//
// Parse returns every pair it can support as pending: conditional, with Cert, Key (== Cert) and
// KeyBeside set, until ResolveKeys decides its key and makes it supported (review R2), so a
// caller that skips ResolveKeys reports no supported pair. When the key settings are not
// stable (see Parse), KeyBeside is "" and ResolveKeys supports the pair only if its certificate
// file holds the key. A crt-store section makes every pair conditional (review R3).
type Pair struct {
	Cert, Key, CertRaw, KeyBeside string
	Unsupported                   string
	pending, keyUnsure            bool
}

// Parse evaluates haproxy.cfg the way HAProxy reads it (Rulings 6-14):
//   - sections: global, defaults, frontend and listen are read, the other sections skipped;
//     a disabled or enabled line in a frontend or listen and in defaults is followed;
//   - .if/.elif/.else/.endif blocks are evaluated when the condition is empty or one integer,
//     and are uncertain otherwise; a pair in an uncertain region is conditional;
//   - crt-base, ssl-load-extra-files and ssl-load-extra-del-ext are followed in read order;
//   - each bind with ssl gives one server for its crt pairs and one per line of each crt-list
//     it names; a crt naming a directory gives one pair per certificate entry.
//
// HAProxy loads each certificate once, with the key settings (ssl-load-extra-files,
// ssl-load-extra-del-ext) in effect where it is first loaded, which Alice cannot always tell
// (a load in an uncertain region, a variable path, a server's crt). So the settings are used
// only when they are stable: every such directive is in a global section, outside any .if
// block, and before the first line that may load a certificate (a bind, or any line with a crt
// or crt-list word), as configurations set them. Then every load used them, and each pair's
// companion follows from them and the path as HAProxy builds it. Otherwise only a key in the
// certificate file itself is known: ResolveKeys makes the other pairs conditional (controller
// ruling for Task 5, fix round 2). A "$" in a global keyword or in a key setting is not stable
// either (review R1). A crt-store section (HAProxy 3.0 on) may give a bind's certificate a key
// file of its own, so it makes every pair conditional (review R3).
//
// Every pair Parse can support is returned pending; ResolveKeys completes it (see Pair).
//
// The walk is iterative. MaxTokens counts the words of haproxy.cfg and of every crt-list
// together; MaxCrtLists, MaxDirs, MaxDirEntries, MaxPairs, MaxServers, MaxNames and MaxWire
// are ErrTooComplex, MaxDepth ErrTooDeep. The listens of all servers together (a bind's listens
// count once per server that carries them) are cut at MaxListens with WarnListTruncated.
// On error the Config is empty.
func Parse(in Input) (Config, error) {
	p := &parser{in: in, keyLookup: true, lists: map[string][]listEntry{}, listFiles: map[string][]listLine{},
		dirs: map[string]dirInfo{}}
	p.skipDots, p.versionKnown = minorAtLeast(in.Version, 2, 6)
	if err := lexEach(in.Data, &p.tokens, MaxTokens, p.line); err != nil {
		return Config{}, fmt.Errorf("%s: %w", in.Path, err)
	}
	if len(p.conds) > 0 {
		return Config{}, fmt.Errorf("%s: %w (an .if block is not closed)", in.Path, ErrSyntax)
	}
	p.closeSection()
	// Every supported pair waits for ResolveKeys as a conditional one (review R2): a caller that
	// forgets it reports no pair as supported, never one with a wrong key.
	for i := range p.out {
		for j := range p.out[i].Pairs {
			pair := &p.out[i].Pairs[j]
			switch {
			case pair.Unsupported != "":
			case p.crtStore:
				*pair = Pair{CertRaw: pair.CertRaw, Unsupported: ReasonConditional}
			default:
				pair.Unsupported, pair.pending = ReasonConditional, true
				if p.unstable {
					pair.KeyBeside, pair.keyUnsure = "", true
				}
			}
		}
	}
	c := Config{Servers: p.out, wire: p.wire}
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
	name      string // cleaned and cut as on the wire
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

// listLine is one line of a crt-list file as read: the path as written, its shown form, and
// the names cleaned and cut as on the wire with their wire size.
type listLine struct {
	path, raw string
	dollar    bool
	names     []string
	namesWire int
}

// listEntry is one line of a crt-list, evaluated where the file was first named. HAProxy loads
// a crt-list once too, with the crt-base of its first load; a naming in an uncertain region
// that HAProxy skipped can only make a later one unsupported, never wrongly supported (crt-base
// is set once).
type listEntry struct {
	line *listLine
	pair Pair
}

// dirInfo is ReadDir's answer for one path: for a directory, the certificate entries in
// bytewise order.
type dirInfo struct {
	isDir bool
	names []string
}

type parser struct {
	in    Input
	conds []cond
	sec   section
	out   []Server

	crtBase           setting
	keyLookup, delExt bool
	defaultsTouched   bool
	// loaded: a line that may load a certificate was read; unstable: a key setting was read
	// after one, outside global or inside an .if block (see Parse).
	loaded, unstable       bool
	crtStore               bool // a crt-store section appears (HAProxy 3.0 on)
	skipDots, versionKnown bool // minorAtLeast(Version, 2, 6)

	lists     map[string][]listEntry // evaluated at the first naming
	listFiles map[string][]listLine  // as read
	dirs      map[string]dirInfo
	nDirs     int

	tokens, pairs, servers, names, listens, wire int
	truncated                                    bool
}

func (p *parser) eff() region {
	if len(p.conds) == 0 {
		return active
	}
	return p.conds[len(p.conds)-1].eff
}

func (p *parser) errAt(err error, n int) error { return lineErr(err, n) }

func (p *parser) line(l line) error {
	kw := l.words[0].text
	if strings.HasPrefix(kw, ".") {
		return p.directive(l)
	}
	// Reviews R1 and S1 (probed on 2.4-3.2): HAProxy expands "${VAR}" (and setenv's) before it
	// reads the keyword, so a keyword with a "$", in any section and even inactive, may be a key
	// setting, "bind" (a hidden load), or a section header such as "global" or "crt-store" (an
	// explicit key Alice never sees). Alice cannot expand it, so it counts as all of them, and
	// every pair is conditional. A key setting with a "$" has a value Alice cannot read.
	if l.words[0].dollar {
		p.loaded, p.unstable, p.crtStore = true, true, true
	}
	if kw == "ssl-load-extra-files" || kw == "ssl-load-extra-del-ext" {
		p.unstable = p.unstable || slices.ContainsFunc(l.words[1:], func(w word) bool { return w.dollar }) ||
			len(p.conds) > 0 || p.loaded || p.sec.kinds != kindGlobal || p.sec.uncertain
	}
	// Review R3 (probed on 3.0): a crt-store's "load crt <path> key <file>" gives a bind's
	// "crt <path>" that key, which Alice does not read.
	if kw == "crt-store" {
		p.crtStore = true
	}
	eff := p.eff()
	if eff == inactive {
		return nil
	}
	if kw == "bind" || slices.ContainsFunc(l.words[1:], func(w word) bool { return w.text == "crt" || w.text == "crt-list" }) {
		p.loaded = true
	}
	if kind, ok := sectionKinds[kw]; ok {
		p.header(kind, l, eff)
		return nil
	}
	maybe := eff == uncertain || p.sec.uncertain
	args := l.words[1:]
	if kw == "bind" && p.sec.kinds&kindProxy != 0 {
		if err := p.bind(l, maybe); err != nil {
			return lineErr(err, l.n) // review M3: every error names its line
		}
		return nil
	}
	switch {
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
	case kw == "ssl-load-extra-del-ext":
		p.delExt = true
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
		p.sec.name = clean(l.words[1].text, maxText) // once per section, not per server (review I1)
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
		p.out = appendServers(p.out, s.servers)
	case s.own && s.disabled:
	default:
		p.out = appendServers(p.out, s.servers)
	}
	s.servers = nil
}

// appendServers appends a section's servers to the output, taking the section's slice as the
// output when it is the first (review R5: one copy less of the largest slice).
func appendServers(out, servers []Server) []Server {
	if len(out) == 0 {
		return servers
	}
	return append(out, servers...)
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
		list, unknown bool
		w             word
	}
	var (
		args         []arg
		ssl, unknown bool
	)
	for i := 2; i < len(words); {
		kw := words[i].text
		n, ok := bindArity[kw]
		if !ok {
			// The arguments of an unknown keyword cannot be told from keywords. A later "ssl"
			// may be one, so the bind is listed, and the word after each later "crt" or
			// "crt-list" may be a certificate: it is listed unsupported, unread (review M1).
			unknown = true
			for j := i + 1; j < len(words); j++ {
				switch words[j].text {
				case "ssl":
					ssl = true
				case "crt", "crt-list":
					if j+1 < len(words) {
						args = append(args, arg{unknown: true, w: words[j+1]})
					}
				}
			}
			break
		}
		if i+n >= len(words) {
			break // a keyword without its argument: -c refuses it
		}
		switch kw {
		case "ssl":
			ssl = true
		case "crt", "crt-list":
			args = append(args, arg{list: kw == "crt-list", w: words[i+1]})
		}
		i += 1 + n
	}
	if len(args) == 0 {
		return nil
	}
	if !ssl {
		return nil
	}
	listens := p.parseListens(words[1].text)
	section := p.sec.name
	if p.sec.uncertain {
		section = ""
	}
	bindServer := Server{File: p.in.Path, Line: l.n, Section: section, Listens: listens}
	// The servers go straight into the section (review R5: no copies): a slot for the bind's
	// own server first, filled or dropped at the end, then one per crt-list line.
	start := len(p.sec.servers)
	p.sec.servers = append(p.sec.servers, Server{})
	lineN := len(strconv.Itoa(l.n))
	for _, a := range args {
		switch {
		case a.unknown:
			if err := p.addPair(&bindServer.Pairs, Pair{CertRaw: shown(a.w.text), Unsupported: ReasonUnknownKeyword}); err != nil {
				return err
			}
		case !a.list:
			if err := p.crt(a.w, &bindServer.Pairs); err != nil {
				return err
			}
		default:
			entries, pair, err := p.crtList(a.w, len(p.sec.servers)-start-1)
			if err != nil {
				return err
			}
			if pair != nil {
				if err := p.addPair(&bindServer.Pairs, *pair); err != nil {
					return err
				}
				continue
			}
			for _, e := range entries {
				s := Server{File: p.in.Path, Line: l.n, Section: section, Names: e.line.names, Listens: listens}
				if err := p.addPair(&s.Pairs, e.pair); err != nil {
					return err
				}
				p.wire += e.line.namesWire
				p.sec.servers = append(p.sec.servers, s)
			}
		}
	}
	if len(bindServer.Pairs) > 0 {
		p.sec.servers[start] = bindServer
	} else {
		p.sec.servers = slices.Delete(p.sec.servers, start, start+1)
	}
	all := p.sec.servers[start:]
	for i := range all {
		if err := p.addServer(&all[i], lineN); err != nil {
			return err
		}
		for j := range all[i].Pairs {
			pair := &all[i].Pairs[j]
			switch {
			case unknown:
				*pair = Pair{CertRaw: pair.CertRaw, Unsupported: ReasonUnknownKeyword}
			case maybe:
				unsupport(pair, ReasonConditional)
			}
		}
	}
	return nil
}

// parseListens parses a bind address within what is left of MaxListens (what every server of
// the bind may still carry).
func (p *parser) parseListens(arg string) []Listen {
	listens, cut := parseListens(arg, MaxListens-p.listens)
	p.truncated = p.truncated || cut
	return listens
}

// addServer counts a server against MaxServers, MaxNames, MaxListens and MaxWire. Its listens,
// shared with the other servers of its bind, count for it again: past MaxListens it carries a
// shorter prefix of them, or none, and the parse warns WarnListTruncated (review C1).
func (p *parser) addServer(s *Server, lineDigits int) error {
	if p.servers++; p.servers > MaxServers {
		return ErrTooComplex
	}
	if p.names += len(s.Names); p.names > MaxNames {
		return ErrTooComplex
	}
	if left := MaxListens - p.listens; len(s.Listens) > left {
		s.Listens = s.Listens[:left:left]
		p.truncated = true
	}
	p.listens += len(s.Listens)
	p.wire += serverWire(s.File, s.Section, lineDigits)
	for _, l := range s.Listens {
		p.wire += listenWire(l)
	}
	if p.wire > MaxWire {
		return ErrTooComplex
	}
	return nil
}

// addPair adds a pair to a server, counting it against MaxPairs and MaxWire.
func (p *parser) addPair(to *[]Pair, pair Pair) error {
	if p.pairs++; p.pairs > MaxPairs {
		return ErrTooComplex
	}
	if p.wire += pairWire(len(pair.Cert), len(pair.KeyBeside), pair.CertRaw); p.wire > MaxWire {
		return ErrTooComplex
	}
	*to = append(*to, pair)
	return nil
}

// crt reads one crt argument into pairs: a file, or the certificate entries of a directory.
func (p *parser) crt(w word, pairs *[]Pair) error {
	raw := shown(w.text)
	path, joined, reason := p.resolve(w.text, w.dollar)
	if path == "" {
		return p.addPair(pairs, Pair{CertRaw: raw, Unsupported: reason})
	}
	d, err := p.readDir(path)
	if err != nil {
		return err
	}
	if !d.isDir {
		return p.addPair(pairs, p.filePair(path, joined, raw, reason))
	}
	for _, name := range d.names {
		r := reason
		if name[0] == '.' && !p.versionKnown {
			r = ReasonConditional // dotfiles are loaded below 2.6 only (Ruling 10)
		}
		// The size is counted before the path is built: a long directory path repeated for
		// every entry is what MaxWire bounds.
		if p.wire+pairWire(len(path)+1+len(name), len(path)+1+len(name)+len(".key"), "") > MaxWire {
			return ErrTooComplex
		}
		entryRaw := shown(raw + "/" + name)
		pair := Pair{CertRaw: entryRaw, Unsupported: ReasonPathNotAllowed}
		if full := path + "/" + name; helperproto.ValidPath(full) {
			pair = p.filePair(full, joined+"/"+name, entryRaw, r)
		}
		if err := p.addPair(pairs, pair); err != nil {
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
// reason conditional is returned too: the files it names are still described. joined is the
// path as HAProxy builds it (the argument, or crt-base, "/" and the argument, uncleaned), from
// which it derives the companion key's name.
//
// A path longer than twice a helper path is refused before it is scanned: a crt-list line of
// 1 MiB costs the same as a short one however often it is named (review N1).
func (p *parser) resolve(raw string, dollar bool) (path, joined, reason string) {
	if dollar {
		return "", "", ReasonVariable
	}
	if len(raw) > 2*maxPath || !cleanSegments(raw) {
		return "", "", ReasonPathNotAllowed
	}
	path = raw
	if !strings.HasPrefix(raw, "/") {
		base := p.crtBase
		baseOK := strings.HasPrefix(base.value, "/") && cleanSegments(strings.TrimRight(base.value, "/")+"/x")
		switch {
		case base.uncertain && (!base.set || base.dollar || !baseOK):
			return "", "", ReasonConditional
		case !base.set:
			return "", "", ReasonPathNotAllowed
		case base.dollar:
			return "", "", ReasonVariable
		case !baseOK:
			return "", "", ReasonPathNotAllowed
		case base.uncertain:
			reason = ReasonConditional
		}
		if len(base.value)+1+len(raw) > 2*maxPath {
			return "", "", ReasonPathNotAllowed // never a helper path; not built
		}
		path = base.value + "/" + raw
	}
	joined = path
	path = filepath.Clean(path)
	if !helperproto.ValidPath(path) || path == "/" {
		if reason == "" {
			reason = ReasonPathNotAllowed
		}
		return "", "", reason
	}
	return path, joined, reason
}

// maxPath is the longest helper path (helperproto's argument limit).
const maxPath = 4096

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

// filePair is the pair of a certificate file with its companion key (Ruling 12): the key
// settings in effect (they are used only when stable, see Parse) applied to joined, the path as
// HAProxy builds it. With ssl-load-extra-del-ext, HAProxy cuts a ".crt" ending of that string
// before adding ".key" (review N4: "/c//a.crt" gives "/c//a.key"). The companion is returned
// cleaned; resolve refused "." and ".." segments, so cleaning only folds repeated "/", which
// names the same file. reason is "" or conditional (from the crt-base or the version).
func (p *parser) filePair(path, joined, raw, reason string) Pair {
	if reason != "" {
		return Pair{CertRaw: raw, Unsupported: reason}
	}
	beside := ""
	if p.keyLookup {
		stem := joined
		if p.delExt {
			stem = strings.TrimSuffix(stem, ".crt")
		}
		if beside = filepath.Clean(stem + ".key"); !helperproto.ValidPath(beside) {
			return Pair{CertRaw: raw, Unsupported: ReasonPathNotAllowed}
		}
	}
	return Pair{Cert: path, Key: path, CertRaw: raw, KeyBeside: beside}
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
			case n[0] == '.' && p.skipDots: // a dotfile from 2.6 on (Ruling 10); not kept (review N6)
			default:
				d.names = append(d.names, n)
			}
		}
		slices.Sort(d.names)
	}
	p.dirs[path] = d
	return d, nil
}

// crtList reads one crt-list argument; pending is the number of servers the bind already
// gives. A path that cannot be read (a "$", relative, not a helper path; never joined to
// crt-base) gives the one unsupported pair for the bind's server; else the entries. The file is
// read, and its entries evaluated, once per path whatever the region of the naming (review N1);
// the bind applies its own region to the copies.
func (p *parser) crtList(w word, pending int) ([]listEntry, *Pair, error) {
	raw := w.text
	switch {
	case w.dollar:
		return nil, &Pair{CertRaw: shown(raw), Unsupported: ReasonVariable}, nil
	case !strings.HasPrefix(raw, "/") || !cleanSegments(raw) || !helperproto.ValidPath(raw) || raw == "/":
		return nil, &Pair{CertRaw: shown(raw), Unsupported: ReasonPathNotAllowed}, nil
	}
	if entries, ok := p.lists[raw]; ok {
		return entries, nil, p.fits(pending, len(entries))
	}
	lines, err := p.readList(raw)
	if err != nil {
		return nil, nil, err
	}
	// Every line becomes a server of this bind: a list over the bound is refused before its
	// entries are looked at.
	if err := p.fits(pending, len(lines)); err != nil {
		return nil, nil, err
	}
	entries := make([]listEntry, 0, len(lines))
	for i := range lines {
		l := &lines[i]
		e := listEntry{line: l}
		path, joined, reason := p.resolve(l.path, l.dollar)
		if path == "" {
			e.pair = Pair{CertRaw: l.raw, Unsupported: reason}
		} else {
			d, err := p.readDir(path)
			if err != nil {
				return nil, nil, err
			}
			if d.isDir {
				// HAProxy refuses a directory in a crt-list (Ruling 10).
				e.pair = Pair{CertRaw: l.raw, Unsupported: ReasonPathNotAllowed}
			} else {
				e.pair = p.filePair(path, joined, l.raw, reason)
			}
		}
		entries = append(entries, e)
	}
	p.lists[raw] = entries
	return entries, nil, nil
}

// fits says whether n more servers, after pending ones of the bind, stay within MaxServers.
func (p *parser) fits(pending, n int) error {
	if p.servers+pending+n > MaxServers {
		return ErrTooComplex
	}
	return nil
}

// readList reads and parses a crt-list file once, within the shared word budget. Names are
// cleaned and cut once here, not per server that carries them (review I1).
func (p *parser) readList(path string) ([]listLine, error) {
	if lines, ok := p.listFiles[path]; ok {
		return lines, nil
	}
	if len(p.listFiles) >= MaxCrtLists {
		return nil, ErrTooComplex
	}
	if p.in.ReadFile == nil {
		return nil, errors.New("haproxyconf: no ReadFile")
	}
	data, err := p.in.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("haproxyconf: reading %s: %w", path, err)
	}
	parsed, used, err := parseCrtListBudget(data, MaxTokens-p.tokens)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	p.tokens += used
	lines := make([]listLine, len(parsed))
	for i, l := range parsed {
		lines[i] = listLine{path: l.path, raw: shown(l.path), dollar: strings.Contains(l.path, "$")}
		if len(l.names) > 0 {
			lines[i].names = make([]string, len(l.names))
			for j, n := range l.names {
				lines[i].names[j] = clean(n, maxText)
				lines[i].namesWire += 3 + jsonLen(lines[i].names[j])
			}
		}
	}
	p.listFiles[path] = lines
	return lines, nil
}

// maxText is the longest section name, SNI name or listen host on the wire, in bytes.
const maxText = 253

// shown is a path as the wire's Raw shows it: cleaned and cut to maxRaw runes. Only a prefix
// is cleaned, so a long argument costs the same as a short one.
func shown(raw string) string {
	s := clean(raw[:min(len(raw), 64<<10)], 64<<10)
	if utf8.RuneCountInString(s) > maxRaw {
		s = string([]rune(s)[:maxRaw])
	}
	return s
}

// The wire size of a server, a listen and a pair: the length of its helperproto JSON with its
// separating comma, from above. A pair counts its raw text and the longest reason even when it
// is supported (MarkWritable may make it unsupported), and its key as the longer of Cert and
// KeyBeside (ResolveKeys picks one).
const (
	serverWireFixed = len(`{"file":"","line":,"names":[],"listens":[],"pairs":[],"section":"","stream":false},`)
	listenWireFixed = len(`{"addr":"","port":65535,"default_server":false},`)
	pairWireFixed   = len(`{"cert":"","key":"","inherited":false,"unsupported":"config_file_writable","raw":""},`)
)

func serverWire(file, section string, lineDigits int) int {
	return serverWireFixed + jsonLen(file) + lineDigits + jsonLen(section)
}

func listenWire(l Listen) int { return listenWireFixed + jsonLen(l.Addr) }

func pairWire(cert, beside int, raw string) int {
	return pairWireFixed + cert + max(cert, beside) + jsonLen(raw)
}

// jsonLen is the length of s inside a JSON string as encoding/json writes it: '"' and '\' take
// two bytes; '<', '>', '&', a control character, an invalid byte, U+2028 and U+2029 six.
func jsonLen(s string) int {
	n := 0
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		switch {
		case r == '"' || r == '\\':
			n += 2
		case r == '<' || r == '>' || r == '&' || r < 0x20 || r == 0x2028 || r == 0x2029 || r == utf8.RuneError && size == 1:
			n += 6
		default:
			n += size
		}
		i += size
	}
	return n
}
