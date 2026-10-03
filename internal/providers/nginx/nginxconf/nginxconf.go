// Package nginxconf parses the output of "nginx -T" into the server blocks and certificate file
// pairs Alice manages (spec §12.4). It is pure (standard library and helperproto for ValidPath):
// the root helper uses it to decide which files it may touch, and it is fuzzed (§25.6). Its input
// is hostile: a compromised server writes it.
//
// "nginx -T" prints every configuration file under a "# configuration file <path>:" marker, one
// after the other, and leaves the include directives in place. Parse splits the dump at the
// markers, parses each file on its own and splices the files back in at their include directives,
// so the tree is the one nginx sees. A file that no include reaches is not part of the
// configuration and is ignored.
//
// The markers are NOT authenticated: any file can contain a line that looks like one. Parse
// refuses a dump that names a file twice under the same raw name (nginx prints each file it
// opened once per name), but a forged marker with a new name still lets its text be spliced
// where an include glob matches it. A caller that acts on the result (the root helper) must
// therefore compare every section, byte for byte, with the real file (Config.Sections gives the
// name and the exact bytes of each) before it relies on the parse. Paths are decided on the raw
// text: a "." or ".." segment is never accepted, so no textual folding can differ from what the
// kernel opens. Server.Files and Pair.Files name every file that holds a server block or a
// directive, or brought it in through an include, so the caller can refuse what a user other than
// root could have written or activated.
package nginxconf

import (
	"bytes"
	"errors"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"alice/internal/providers/linuxssh/helperproto"
)

// Limits (§25.6: deep nesting, huge lines and amplification are refused cleanly). They bound the
// memory (tokens, nodes) and the time (include matching) one dump can cost.
const (
	MaxInput   = 20 << 20 // bytes of the dump
	MaxDepth   = 100      // nesting of blocks, also across included files
	MaxLine    = 1 << 20  // bytes of one line, and of one token
	MaxTokens  = 1 << 20  // tokens of the whole dump
	MaxFiles   = 4096     // "# configuration file" sections
	maxNodes   = 1 << 17  // kept directives in the dump, and visited while splicing includes
	maxArgs    = 4096     // arguments of one kept directive
	maxWork    = 1 << 26  // glob matching effort while splicing includes
	maxSegment = 255      // longest path segment that is glob matched
	maxPath    = 4096     // longest file name in a marker
	maxPattern = 512      // longest include pattern that is matched
)

// Warning codes (the web catalog keys warnings.<code>); helperproto is their single source.
const (
	WarnStreamTLS = helperproto.WarnStreamTLS // TLS in a stream block
	WarnMailTLS   = helperproto.WarnMailTLS   // TLS in a mail block
)

// Errors.
var (
	ErrTooLarge      = errors.New("nginxconf: the configuration dump is larger than 20 MiB")
	ErrTooDeep       = errors.New("nginxconf: blocks are nested deeper than 100 levels")
	ErrLineTooLong   = errors.New("nginxconf: a line or a token is longer than 1 MiB")
	ErrSyntax        = errors.New("nginxconf: unbalanced braces or an unterminated directive or string")
	ErrNUL           = errors.New("nginxconf: the configuration dump contains a NUL byte")
	ErrTooComplex    = errors.New("nginxconf: the configuration has too many tokens, files or includes")
	ErrIncludeLoop   = errors.New("nginxconf: configuration files include each other in a loop")
	ErrDuplicateFile = errors.New("nginxconf: the dump names the same configuration file twice")
)

// Reasons a pair is not supported (spec §12.4 step 4, R38 item 4).
const (
	ReasonVariable       = "variable"
	ReasonDataValue      = "data_value"
	ReasonEngineKey      = "engine_key"
	ReasonKeyMissing     = "key_missing"
	ReasonPasswordFile   = "password_file"
	ReasonPathNotAllowed = "path_not_allowed"
	ReasonStream         = "stream"
	ReasonCombinedFile   = "combined_file"
	// ReasonConfigFileWritable is set by the root helper (not by Parse): a configuration file that
	// holds the server block or one of the pair's directives can be changed by a user other than
	// root (S1), so the pair could name any file of that user's choosing.
	ReasonConfigFileWritable = helperproto.WarnConfigFileWritable
)

// Listen is one listen directive.
type Listen struct {
	Addr          string // "" = any address
	Port          int
	SSL           bool
	DefaultServer bool
}

// Pair is the i-th ssl_certificate with the i-th ssl_certificate_key of a server block.
type Pair struct {
	Cert, Key       string // cleaned absolute paths; "" when the pair is unsupported for a path reason
	CertRaw, KeyRaw string // the directive arguments as written
	Inherited       bool   // either path came from the http block
	Unsupported     string // "" or a Reason*
	// CertFile and KeyFile are the configuration files (raw marker names) of the ssl_certificate
	// and ssl_certificate_key directives ("" when there is no key directive).
	CertFile, KeyFile string
	// Files is every file (raw marker names, sorted) that holds a certificate or key directive at
	// an index up to this pair's (they decide which directive is this pair's), or includes,
	// directly or through other files, a file that holds one.
	Files []string
}

// Server is one server block that serves TLS with at least one certificate.
type Server struct {
	File    string
	Line    int
	Names   []string
	Listens []Listen
	Pairs   []Pair
	Stream  bool
	// Files is every configuration file (raw marker names, sorted) that holds the block or a
	// directive spliced into it, and every file whose include directives brought them in.
	Files []string
}

// Config is the part of the configuration Alice uses.
type Config struct {
	Servers  []Server
	Files    []string
	Warnings []string
	// Sections is every file of the dump with the exact bytes printed for it, so that a caller
	// can compare them with the real files (the markers are not authenticated).
	Sections []Section
}

// Section is one "# configuration file" part of the dump. File is the name as printed (raw
// bytes, "" for text before the first marker); Body is the dump text after the marker line up to
// the next marker line, a sub-slice of the dump.
type Section struct {
	File string
	Body []byte
}

const markerPrefix = "# configuration file "

// token is one word, one quoted string or one of the characters ; { }.
type token struct {
	text  string
	punct bool // ; { or } outside quotes and escapes
	file  string
	line  int // line within file, 1-based
}

// includeLink is one include directive that spliced a file in: the file that holds the directive,
// and the link that brought that file in (nil at the top). Spliced nodes share the chain.
type includeLink struct {
	file string
	next *includeLink
}

type node struct {
	via      *includeLink // the include chain that spliced this node in (set while expanding)
	name     string
	args     []token
	file     string
	line     int
	block    bool
	children []node
}

// section is one file of the dump while it is parsed.
type section struct {
	file  string
	body  []byte
	nodes []node
}

// splitSections splits the dump at the "# configuration file <path>:" marker lines (column 0, as
// nginx prints them), rejects lines longer than MaxLine and a file name that appears twice. Text
// before the first marker is a section without a file name.
func splitSections(dump []byte) ([]section, error) {
	var (
		secs  []section
		seen  = map[string]bool{}
		start int // start of the current section's body
		cur   = -1
	)
	closeSection := func(end int) {
		if cur >= 0 {
			secs[cur].body = dump[start:end]
		}
	}
	for pos := 0; pos < len(dump); {
		end := bytes.IndexByte(dump[pos:], '\n')
		next := len(dump)
		if end < 0 {
			end = len(dump)
		} else {
			end += pos
			next = end + 1
		}
		if end-pos > MaxLine {
			return nil, ErrLineTooLong
		}
		text := bytes.TrimSuffix(dump[pos:end], []byte("\r"))
		if bytes.HasPrefix(text, []byte(markerPrefix)) && bytes.HasSuffix(text, []byte(":")) {
			file := string(text[len(markerPrefix) : len(text)-1])
			if len(file) > maxPath {
				return nil, ErrSyntax
			}
			if len(secs) >= MaxFiles {
				return nil, ErrTooComplex
			}
			// Raw names: nginx prints each file once under the name it opened, and a file reached
			// under two spellings ("conf.d/x" and "./conf.d/x") is printed twice, legitimately.
			if seen[file] {
				return nil, ErrDuplicateFile
			}
			seen[file] = true
			closeSection(pos)
			secs = append(secs, section{file: file})
			cur = len(secs) - 1
			start = next
		} else if cur < 0 && len(bytes.TrimSpace(text)) > 0 {
			// text before any marker: an anonymous first section
			secs = append(secs, section{})
			cur = 0
			start = 0
		}
		pos = next
	}
	closeSection(len(dump))
	return secs, nil
}

// escape writes the character after a backslash the way nginx unescapes it (\" \' \\ \t \r \n);
// any other pair keeps its backslash, so a backslash can never make a different character valid
// in a path. In a word, an escaped ; { } # space or tab loses the backslash (nginx keeps it too,
// but the result is not a valid path either way, and server names read better).
func escape(b *strings.Builder, next byte, inWord bool) {
	switch next {
	case '"', '\'', '\\':
		b.WriteByte(next)
	case 't':
		b.WriteByte('\t')
	case 'r':
		b.WriteByte('\r')
	case 'n':
		b.WriteByte('\n')
	case ';', '{', '}', '#', ' ':
		if !inWord {
			b.WriteByte('\\')
		}
		b.WriteByte(next)
	default:
		b.WriteByte('\\')
		b.WriteByte(next)
	}
}

// lexer reads the tokens of one file, following nginx's ngx_conf_read_token: '#' starts a comment
// where a token could start, "..." and '...' are one token, a backslash escapes the next
// character, a word ends at white space, ';' or '{' (not at "${"), and a closing quote must be
// followed by white space, ';', '{' or ')'. left is the remaining token budget of the dump.
type lexer struct {
	data []byte
	i    int
	line int
	file string
	left *int
}

func isSpace(c byte) bool { return c == ' ' || c == '\t' || c == '\r' || c == '\n' }

// next returns the next token; ok is false at the end of the file.
func (l *lexer) next() (t token, ok bool, err error) {
	d, n := l.data, len(l.data)
	for l.i < n {
		c := d[l.i]
		switch c {
		case '\n':
			l.line++
			l.i++
			continue
		case ' ', '\t', '\r':
			l.i++
			continue
		case '#':
			for l.i < n && d[l.i] != '\n' {
				l.i++
			}
			continue
		}
		if *l.left--; *l.left < 0 {
			return token{}, false, ErrTooComplex
		}
		if c == ';' || c == '{' || c == '}' {
			l.i++
			return token{text: string(c), punct: true, file: l.file, line: l.line}, true, nil
		}
		var b strings.Builder
		startLine := l.line
		if c == '"' || c == '\'' {
			l.i++
			closed := false
			for l.i < n && !closed {
				ch := d[l.i]
				switch {
				case ch == '\\' && l.i+1 < n:
					if d[l.i+1] == '\n' {
						l.line++
					}
					escape(&b, d[l.i+1], false)
					l.i += 2
				case ch == c:
					closed = true
					l.i++
				default:
					if ch == '\n' {
						l.line++
					}
					b.WriteByte(ch)
					l.i++
				}
				if b.Len() > MaxLine {
					return token{}, false, ErrLineTooLong
				}
			}
			if !closed {
				return token{}, false, ErrSyntax
			}
			if l.i < n {
				switch f := d[l.i]; {
				case f == ')':
					l.i++ // nginx treats ')' after a quoted string as white space: if ($a ~ "x") {
				case !isSpace(f) && f != ';' && f != '{':
					return token{}, false, ErrSyntax
				}
			}
		} else {
			variable := false
			for l.i < n {
				ch := d[l.i]
				if ch == '\\' && l.i+1 < n {
					if d[l.i+1] == '\n' {
						l.line++
					}
					escape(&b, d[l.i+1], true)
					l.i += 2
					variable = false
				} else if isSpace(ch) || ch == ';' || (ch == '{' && !variable) {
					break
				} else {
					b.WriteByte(ch)
					l.i++
					if ch != '{' { // "${" keeps the word open, nginx's variable flag
						variable = ch == '$'
					}
				}
				if b.Len() > MaxLine {
					return token{}, false, ErrLineTooLong
				}
			}
		}
		return token{text: b.String(), file: l.file, line: startLine}, true, nil
	}
	return token{}, false, nil
}

// skipLua skips the body of an OpenResty "*_by_lua_block {" directive; the opening brace is
// consumed. OpenResty's own lexer counts braces outside Lua strings ('..', "..", [[..]]) and
// comments (-- and --[[..]]), and so does this.
func (l *lexer) skipLua() error {
	d, n := l.data, len(l.data)
	depth := 1
	for l.i < n {
		c := d[l.i]
		switch {
		case c == '\n':
			l.line++
			l.i++
		case c == '-' && l.i+1 < n && d[l.i+1] == '-':
			l.i += 2
			if lvl, ok := longBracket(d, l.i); ok {
				if err := l.skipLong(lvl); err != nil {
					return err
				}
			} else {
				for l.i < n && d[l.i] != '\n' {
					l.i++
				}
			}
		case c == '[':
			if lvl, ok := longBracket(d, l.i); ok {
				if err := l.skipLong(lvl); err != nil {
					return err
				}
			} else {
				l.i++
			}
		case c == '"' || c == '\'':
			l.i++
			for l.i < n && d[l.i] != c && d[l.i] != '\n' {
				if d[l.i] == '\\' && l.i+1 < n {
					if d[l.i+1] == '\n' {
						l.line++
					}
					l.i++
				}
				l.i++
			}
			if l.i < n && d[l.i] == c {
				l.i++
			}
		case c == '{':
			depth++
			l.i++
		case c == '}':
			depth--
			l.i++
			if depth == 0 {
				return nil
			}
		default:
			l.i++
		}
	}
	return ErrSyntax
}

// longBracket reports whether d[i:] starts a Lua long bracket "[" "="* "[" and its level.
func longBracket(d []byte, i int) (int, bool) {
	if i >= len(d) || d[i] != '[' {
		return 0, false
	}
	lvl := 0
	for j := i + 1; j < len(d); j++ {
		switch d[j] {
		case '=':
			lvl++
		case '[':
			return lvl, true
		default:
			return 0, false
		}
	}
	return 0, false
}

// skipLong skips a Lua long bracket of the given level that starts at l.i.
func (l *lexer) skipLong(lvl int) error {
	closer := "]" + strings.Repeat("=", lvl) + "]"
	rest := l.data[l.i+lvl+2:]
	end := bytes.Index(rest, []byte(closer))
	if end < 0 {
		return ErrSyntax
	}
	l.line += bytes.Count(rest[:end], []byte("\n"))
	l.i += lvl + 2 + end + len(closer)
	return nil
}

// Only these blocks and directives are read later; everything else is lexed for its syntax and
// dropped, so a dump of millions of other directives costs no memory.
var (
	keptBlocks     = map[string]bool{"http": true, "server": true, "stream": true, "mail": true}
	keptDirectives = map[string]bool{"include": true, "listen": true, "server_name": true, "ssl": true,
		"ssl_certificate": true, "ssl_certificate_key": true, "ssl_password_file": true}
)

type parser struct {
	lx    *lexer
	nodes *int // remaining kept directives of the dump
}

// block reads directives until the matching "}" (closing) or the end of input (top level). keep is
// false inside blocks whose content is not read: their directives are checked and dropped. Only
// the first token of a directive that is not kept is held; the others are counted (the lexer's
// token budget bounds them), so one long directive costs no memory. A kept directive has at most
// maxArgs arguments and the dump at most maxNodes kept directives.
func (p *parser) block(depth int, closing, keep bool) ([]node, error) {
	if depth > MaxDepth {
		return nil, ErrTooDeep
	}
	var (
		out     []node
		first   token   // the directive's name
		args    []token // its arguments, when it is kept
		n       int     // tokens of the current directive
		keepCur bool
	)
	add := func(nd node) error {
		if *p.nodes--; *p.nodes < 0 {
			return ErrTooComplex
		}
		if len(out) == cap(out) {
			// Double, but never past the remaining budget: append's 1.25 growth for large slices
			// would allocate five times the final size of a block with a hundred thousand
			// directives.
			grown := make([]node, len(out), min(2*cap(out)+4, len(out)+*p.nodes+1))
			copy(grown, out)
			out = grown
		}
		out = append(out, nd)
		return nil
	}
	for {
		t, ok, err := p.lx.next()
		if err != nil {
			return nil, err
		}
		if !ok {
			break
		}
		if t.punct {
			switch t.text {
			case ";":
				if n > 0 && keep && keptDirectives[first.text] {
					if err := add(node{name: first.text, args: keepArgs(first.text, args), file: first.file, line: first.line}); err != nil {
						return nil, err
					}
				}
				n, args = 0, nil
				continue
			case "{":
				if n == 0 {
					return nil, ErrSyntax
				}
				if strings.HasSuffix(first.text, "_by_lua_block") {
					if err := p.lx.skipLua(); err != nil {
						return nil, err
					}
					n, args = 0, nil
					continue
				}
				kept := keep && keptBlocks[first.text]
				children, err := p.block(depth+1, true, kept)
				if err != nil {
					return nil, err
				}
				if kept {
					if err := add(node{name: first.text, args: keepArgs(first.text, args), file: first.file, line: first.line, block: true, children: children}); err != nil {
						return nil, err
					}
				}
				n, args = 0, nil
				continue
			case "}":
				if !closing || n > 0 {
					return nil, ErrSyntax
				}
				return out, nil
			}
		}
		switch {
		case n == 0:
			first = t
			keepCur = keep && (keptDirectives[t.text] || keptBlocks[t.text])
		case keepCur:
			if len(args) >= maxArgs {
				return nil, ErrTooComplex
			}
			args = append(args, t)
		}
		n++
	}
	if closing || n > 0 {
		return nil, ErrSyntax
	}
	return out, nil
}

// keepArgs prepares the arguments of a kept directive; text that is shown or stored is made valid
// UTF-8, include patterns stay raw bytes (they are compared with the raw marker names).
func keepArgs(name string, args []token) []token {
	if name != "include" {
		for i := range args {
			args[i].text = strings.ToValidUTF8(args[i].text, "\uFFFD")
		}
	}
	return args
}

// expander splices the files of the dump in at their include directives.
type expander struct {
	secs    []section
	byName  map[string][]int // raw file name -> sections
	segs    [][]string       // path segments of each section's file name
	active  []bool           // sections being expanded, to refuse include loops
	confDir string
	nodes   int // remaining directive budget
	work    int // remaining glob matching budget
}

func (e *expander) expand(nodes []node, depth int, via *includeLink) ([]node, error) {
	if depth > MaxDepth {
		return nil, ErrTooDeep
	}
	out := make([]node, 0, len(nodes))
	for _, n := range nodes {
		if e.nodes--; e.nodes < 0 {
			return nil, ErrTooComplex
		}
		n.via = via
		switch {
		case n.block:
			kids, err := e.expand(n.children, depth+1, via)
			if err != nil {
				return nil, err
			}
			n.children = kids
			out = append(out, n)
		case n.name == "include" && len(n.args) > 0:
			idx, err := e.match(n.args[0].text)
			if err != nil {
				return nil, err
			}
			for _, i := range idx {
				if e.nodes--; e.nodes < 0 {
					return nil, ErrTooComplex
				}
				if e.active[i] {
					return nil, ErrIncludeLoop
				}
				e.active[i] = true
				sub, err := e.expand(e.secs[i].nodes, depth, &includeLink{file: n.file, next: via})
				e.active[i] = false
				if err != nil {
					return nil, err
				}
				out = append(out, sub...)
			}
		default:
			out = append(out, n)
		}
	}
	return out, nil
}

// match returns the sections whose file name matches the include pattern, sorted by name like
// glob(3) does. A relative pattern is relative to confDir (nginx's configuration prefix). Names
// are compared as raw text, as nginx prints and opens them.
func (e *expander) match(raw string) ([]int, error) {
	if raw == "" || len(raw) > maxPattern || strings.Contains(raw, "$") {
		return nil, nil
	}
	p := raw
	if !strings.HasPrefix(p, "/") {
		if !filepath.IsAbs(e.confDir) {
			return nil, nil
		}
		p = strings.TrimRight(e.confDir, "/") + "/" + p
	}
	if !strings.ContainsAny(p, "*?[") {
		if e.work -= 32; e.work < 0 {
			return nil, ErrTooComplex
		}
		return e.byName[p], nil
	}
	psegs := strings.Split(p, "/")
	var out []int
	for i, s := range e.secs {
		if s.file == "" {
			continue
		}
		cost, ok := 32, len(e.segs[i]) == len(psegs)
		for k := 0; ok && k < len(psegs); k++ {
			cost += len(psegs[k])*len(e.segs[i][k]) + 1
			if e.work-cost < 0 {
				return nil, ErrTooComplex
			}
			ok = segMatch(psegs[k], e.segs[i][k])
		}
		if e.work -= cost; e.work < 0 {
			return nil, ErrTooComplex
		}
		if ok {
			out = append(out, i)
		}
	}
	slices.SortFunc(out, func(a, b int) int { return strings.Compare(e.secs[a].file, e.secs[b].file) })
	return out, nil
}

// segMatch matches one path segment like glob(3): a leading '.' of the name is matched only by a
// literal '.' of the pattern, never by *, ? or [.
func segMatch(pat, name string) bool {
	if len(pat) > maxSegment || len(name) > maxSegment {
		return false
	}
	if strings.IndexByte("*?[", firstByte(pat)) >= 0 && strings.HasPrefix(name, ".") {
		return false
	}
	ok, err := filepath.Match(pat, name)
	return err == nil && ok
}

func firstByte(s string) byte {
	if s == "" {
		return 0
	}
	return s[0]
}

// Parse parses an "nginx -T" dump. confDir resolves relative certificate and include paths (the
// directory of --conf-path); "" makes relative paths unsupported.
func Parse(dump []byte, confDir string) (Config, error) {
	if len(dump) > MaxInput {
		return Config{}, ErrTooLarge
	}
	if bytes.IndexByte(dump, 0) >= 0 {
		return Config{}, ErrNUL
	}
	secs, err := splitSections(dump)
	if err != nil {
		return Config{}, err
	}
	left, nodes := MaxTokens, maxNodes
	c := Config{}
	for i := range secs {
		p := &parser{lx: &lexer{data: secs[i].body, line: 1, file: secs[i].file, left: &left}, nodes: &nodes}
		if secs[i].nodes, err = p.block(0, false, true); err != nil {
			return Config{}, err
		}
		c.Sections = append(c.Sections, Section{File: secs[i].file, Body: secs[i].body})
		if secs[i].file != "" || i > 0 {
			c.Files = append(c.Files, strings.ToValidUTF8(secs[i].file, "�"))
		}
	}
	if len(secs) == 0 {
		return c, nil
	}
	e := &expander{secs: secs, byName: map[string][]int{}, segs: make([][]string, len(secs)),
		active: make([]bool, len(secs)), confDir: confDir, nodes: maxNodes, work: maxWork}
	for i, s := range secs {
		if s.file != "" {
			e.byName[s.file] = append(e.byName[s.file], i)
			e.segs[i] = strings.Split(s.file, "/")
		}
	}
	e.active[0] = true
	tree, err := e.expand(secs[0].nodes, 0, nil)
	if err != nil {
		return Config{}, err
	}
	for _, n := range tree {
		switch {
		case n.block && n.name == "http":
			c.http(n.children, confDir)
		case n.block && n.name == "stream":
			c.stream(n.children)
		case n.block && n.name == "mail":
			c.mail(n.children)
		}
	}
	return c, nil
}

// directive is the first argument of a directive, the file that holds the directive and the
// include chain that brought it in.
type directive struct {
	arg, file string
	via       *includeLink
}

type sslDirs struct {
	certs, keys []directive
	password    bool
	sslSet      bool // an "ssl on|off" directive is present
	sslOn       bool
}

func collect(nodes []node) sslDirs {
	var d sslDirs
	for _, n := range nodes {
		if n.block || len(n.args) == 0 {
			continue
		}
		switch n.name {
		case "ssl_certificate":
			d.certs = append(d.certs, directive{n.args[0].text, n.file, n.via})
		case "ssl_certificate_key":
			d.keys = append(d.keys, directive{n.args[0].text, n.file, n.via})
		case "ssl_password_file":
			d.password = true
		case "ssl":
			d.sslSet, d.sslOn = true, len(n.args) == 1 && n.args[0].text == "on"
		}
	}
	return d
}

func (c *Config) http(children []node, confDir string) {
	top := collect(children)
	for _, n := range children {
		if !n.block || n.name != "server" {
			continue
		}
		own := collect(n.children)
		sslOn := top.sslOn // nginx merges "ssl" from the enclosing level
		if own.sslSet {
			sslOn = own.sslOn
		}
		s := server(n, sslOn)
		if !hasSSL(s) {
			continue
		}
		certs, inhC := own.certs, false
		if len(certs) == 0 {
			certs, inhC = top.certs, true
		}
		keys, inhK := own.keys, false
		if len(keys) == 0 {
			keys, inhK = top.keys, true
		}
		if len(certs) == 0 {
			continue
		}
		password := own.password || top.password
		for i, cr := range certs {
			pr := Pair{CertRaw: cr.arg, CertFile: cr.file, Inherited: inhC || (inhK && len(top.keys) > 0)}
			if i < len(keys) {
				pr.KeyRaw, pr.KeyFile = keys[i].arg, keys[i].file
			}
			pr.Files = pairFiles(certs, keys, i)
			pr.Cert, pr.Key, pr.Unsupported = resolvePair(pr.CertRaw, pr.KeyRaw, confDir, password)
			s.Pairs = append(s.Pairs, pr)
		}
		c.Servers = append(c.Servers, s)
	}
}

func (c *Config) stream(children []node) {
	top := collect(children)
	for _, n := range children {
		if !n.block || n.name != "server" {
			continue
		}
		own := collect(n.children)
		certs, inhC := own.certs, false
		if len(certs) == 0 {
			certs, inhC = top.certs, true
		}
		keys, inhK := own.keys, false
		if len(keys) == 0 {
			keys, inhK = top.keys, true
		}
		if len(certs) == 0 {
			continue
		}
		sslOn := top.sslOn
		if own.sslSet {
			sslOn = own.sslOn
		}
		s := server(n, sslOn)
		if inhC && !hasSSL(s) {
			continue // certificates inherited by a server that does not listen with ssl are unused
		}
		s.Stream = true
		for i, cr := range certs {
			pr := Pair{CertRaw: cr.arg, CertFile: cr.file, Unsupported: ReasonStream, Inherited: inhC || (inhK && len(top.keys) > 0)}
			if i < len(keys) {
				pr.KeyRaw, pr.KeyFile = keys[i].arg, keys[i].file
			}
			pr.Files = pairFiles(certs, keys, i)
			s.Pairs = append(s.Pairs, pr)
		}
		c.Servers = append(c.Servers, s)
		c.warn(WarnStreamTLS)
	}
}

// mail records only a warning: Alice does not manage certificates of mail proxies.
func (c *Config) mail(children []node) {
	if len(collect(children).certs) > 0 {
		c.warn(WarnMailTLS)
		return
	}
	for _, n := range children {
		if n.block && n.name == "server" && len(collect(n.children).certs) > 0 {
			c.warn(WarnMailTLS)
			return
		}
	}
}

func (c *Config) warn(code string) {
	if !contains(c.Warnings, code) {
		c.Warnings = append(c.Warnings, code)
	}
}

// server reads the names and listens of a server block; sslOn is the effective "ssl on" setting.
func server(n node, sslOn bool) Server {
	s := Server{File: strings.ToValidUTF8(n.file, "\uFFFD"), Line: n.line, Files: blockFiles(n)}
	for _, d := range n.children {
		if d.block {
			continue
		}
		switch d.name {
		case "server_name":
			for _, a := range d.args {
				s.Names = append(s.Names, a.text)
			}
		case "listen":
			if l, ok := parseListen(d.args); ok {
				s.Listens = append(s.Listens, l)
			}
		}
	}
	if len(s.Listens) == 0 {
		s.Listens = []Listen{{Port: 80}}
	}
	if sslOn {
		for i := range s.Listens {
			s.Listens[i].SSL = true
		}
	}
	return s
}

// fileSet collects file names and the files of include chains; a chain shared by many nodes is
// walked once.
type fileSet struct {
	files []string
	seen  map[*includeLink]bool
}

func (f *fileSet) add(file string, via *includeLink) {
	if !slices.Contains(f.files, file) {
		f.files = append(f.files, file)
	}
	for l := via; l != nil && !f.seen[l]; l = l.next {
		if f.seen == nil {
			f.seen = map[*includeLink]bool{}
		}
		f.seen[l] = true
		if !slices.Contains(f.files, l.file) {
			f.files = append(f.files, l.file)
		}
	}
}

func (f *fileSet) sorted() []string {
	slices.Sort(f.files)
	return f.files
}

// blockFiles returns the files of a block and of everything spliced into it, and the files whose
// include directives brought them in, sorted.
func blockFiles(n node) []string {
	var fs fileSet
	fs.add(n.file, n.via)
	var walk func(nodes []node)
	walk = func(nodes []node) {
		for _, c := range nodes {
			fs.add(c.file, c.via)
			walk(c.children)
		}
	}
	walk(n.children)
	return fs.sorted()
}

// pairFiles returns, for the i-th pair, the files of every certificate and key directive at an
// index up to i and of their include chains, sorted. Pairs are drawn by position: a directive
// added before the i-th one (by an include, at the http level) shifts which file is the i-th, so
// every earlier element decides the pair too.
func pairFiles(certs, keys []directive, i int) []string {
	var fs fileSet
	for _, d := range certs[:min(i+1, len(certs))] {
		fs.add(d.file, d.via)
	}
	for _, d := range keys[:min(i+1, len(keys))] {
		fs.add(d.file, d.via)
	}
	return fs.sorted()
}

func hasSSL(s Server) bool { return len(SSLListens(s)) > 0 }

// SSLListens returns the listens of s that serve TLS.
func SSLListens(s Server) []Listen {
	var out []Listen
	for _, l := range s.Listens {
		if l.SSL {
			out = append(out, l)
		}
	}
	return out
}

func parseListen(args []token) (Listen, bool) {
	if len(args) == 0 {
		return Listen{}, false
	}
	a := args[0].text
	if strings.HasPrefix(a, "unix:") {
		return Listen{}, false
	}
	l := Listen{Port: 80}
	port := ""
	switch {
	case strings.HasPrefix(a, "["):
		end := strings.Index(a, "]")
		if end < 0 {
			return Listen{}, false
		}
		l.Addr = a[1:end]
		if rest := a[end+1:]; strings.HasPrefix(rest, ":") {
			port = rest[1:]
		} else if rest != "" {
			return Listen{}, false
		}
	case isDigits(a):
		port = a
	case strings.Contains(a, ":"):
		i := strings.LastIndex(a, ":")
		l.Addr, port = a[:i], a[i+1:]
	default:
		l.Addr = a
	}
	if port != "" {
		v, err := strconv.Atoi(port)
		if err != nil || !isDigits(port) || v < 1 || v > 65535 {
			return Listen{}, false
		}
		l.Port = v
	}
	if l.Addr == "*" {
		l.Addr = ""
	}
	for _, f := range args[1:] {
		switch f.text {
		case "ssl", "quic": // QUIC always needs a certificate
			l.SSL = true
		case "default_server", "default":
			l.DefaultServer = true
		}
	}
	return l, true
}

func isDigits(s string) bool {
	if s == "" || len(s) > 5 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// resolvePair turns the raw arguments into paths or a reason.
func resolvePair(certRaw, keyRaw, confDir string, password bool) (cert, key, reason string) {
	switch {
	case strings.HasPrefix(certRaw, "data:") || strings.HasPrefix(keyRaw, "data:"):
		return "", "", ReasonDataValue
	case strings.Contains(certRaw, "$") || strings.Contains(keyRaw, "$"):
		return "", "", ReasonVariable
	case strings.HasPrefix(keyRaw, "engine:"):
		return "", "", ReasonEngineKey
	case keyRaw == "":
		c, ok := resolvePath(certRaw, confDir)
		if !ok {
			return "", "", ReasonPathNotAllowed
		}
		return c, "", ReasonKeyMissing
	case password:
		return "", "", ReasonPasswordFile
	}
	c, ok1 := resolvePath(certRaw, confDir)
	k, ok2 := resolvePath(keyRaw, confDir)
	switch {
	case !ok1 || !ok2:
		return "", "", ReasonPathNotAllowed
	case c == k:
		return c, k, ReasonCombinedFile
	}
	return c, k, ""
}

func resolvePath(raw, confDir string) (string, bool) {
	// A path that names a directory ("", "ssl/") is never a certificate file, and a "." or ".."
	// segment is refused on the raw text: folding it textually could name a different file than
	// the kernel opens (a symbolic link before the "..").
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
	if !filepath.IsAbs(p) {
		if confDir == "" || !filepath.IsAbs(confDir) {
			return "", false
		}
		p = filepath.Join(confDir, p)
	}
	p = filepath.Clean(p)
	return p, helperproto.ValidPath(p) && p != "/"
}

// HasPair reports whether cert and key are a supported pair of an http server block.
func (c Config) HasPair(cert, key string) bool {
	for _, s := range c.Servers {
		if s.Stream {
			continue
		}
		for _, p := range s.Pairs {
			if p.Unsupported == "" && p.Cert == cert && p.Key == key {
				return true
			}
		}
	}
	return false
}

// CertPaths returns the distinct certificate paths of supported pairs, in order.
func (c Config) CertPaths() []string { return c.paths(func(p Pair) string { return p.Cert }) }

// KeyPaths returns the distinct key paths of supported pairs, in order.
func (c Config) KeyPaths() []string { return c.paths(func(p Pair) string { return p.Key }) }

func (c Config) paths(get func(Pair) string) []string {
	var out []string
	for _, s := range c.Servers {
		for _, p := range s.Pairs {
			if p.Unsupported == "" && !contains(out, get(p)) {
				out = append(out, get(p))
			}
		}
	}
	return out
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
