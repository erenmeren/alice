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
	maxNodes   = 1 << 20  // directives visited while splicing includes
	maxWork    = 1 << 28  // glob matching effort while splicing includes
	maxPath    = 4096     // longest file name in a marker
	maxPattern = 512      // longest include pattern that is matched
)

// WarnStreamTLS is the warning code for TLS in a stream block (the web catalog key warnings.stream_tls).
// helperproto does not define it yet, so it lives here until the protocol task adds it.
const WarnStreamTLS = "stream_tls"

// Errors.
var (
	ErrTooLarge    = errors.New("nginxconf: the configuration dump is larger than 20 MiB")
	ErrTooDeep     = errors.New("nginxconf: blocks are nested deeper than 100 levels")
	ErrLineTooLong = errors.New("nginxconf: a line or a token is longer than 1 MiB")
	ErrSyntax      = errors.New("nginxconf: unbalanced braces or an unterminated directive or string")
	ErrNUL         = errors.New("nginxconf: the configuration dump contains a NUL byte")
	ErrTooComplex  = errors.New("nginxconf: the configuration has too many tokens, files or includes")
	ErrIncludeLoop = errors.New("nginxconf: configuration files include each other in a loop")
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
}

// Server is one server block that serves TLS with at least one certificate.
type Server struct {
	File    string
	Line    int
	Names   []string
	Listens []Listen
	Pairs   []Pair
	Stream  bool
}

// Config is the part of the configuration Alice uses.
type Config struct {
	Servers  []Server
	Files    []string
	Warnings []string
}

const markerPrefix = "# configuration file "

// token is one word, one quoted string or one of the characters ; { }.
type token struct {
	text  string
	punct bool // ; { or } outside quotes and escapes
	file  string
	line  int // line within file, 1-based
}

type node struct {
	name     string
	args     []token
	file     string
	line     int
	block    bool
	children []node
}

// section is one file of the dump.
type section struct {
	file  string
	body  []byte
	nodes []node
}

// splitSections splits the dump at the "# configuration file <path>:" marker lines (column 0, as
// nginx prints them) and rejects lines longer than MaxLine. Text before the first marker is a
// section without a file name.
func splitSections(dump []byte) ([]section, []string, error) {
	var (
		secs  []section
		files []string
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
			return nil, nil, ErrLineTooLong
		}
		text := bytes.TrimSuffix(dump[pos:end], []byte("\r"))
		if bytes.HasPrefix(text, []byte(markerPrefix)) && bytes.HasSuffix(text, []byte(":")) {
			file := string(text[len(markerPrefix) : len(text)-1])
			if len(file) > maxPath {
				return nil, nil, ErrSyntax
			}
			if len(secs) >= MaxFiles {
				return nil, nil, ErrTooComplex
			}
			closeSection(pos)
			file = strings.ToValidUTF8(file, "�")
			secs = append(secs, section{file: file})
			files = append(files, file)
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
	return secs, files, nil
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

// tokenize splits one file into tokens, following nginx's ngx_conf_read_token: '#' starts a
// comment where a token could start, "..." and '...' are one token, a backslash escapes the next
// character, a word ends at white space, ';' or '{' (not at "${"), and a closing quote must be
// followed by white space, ';' or '{'. left is the remaining token budget of the whole dump.
func tokenize(data []byte, file string, left *int) ([]token, error) {
	var toks []token
	line := 1
	add := func(t token) error {
		if *left--; *left < 0 {
			return ErrTooComplex
		}
		t.text = strings.ToValidUTF8(t.text, "�")
		toks = append(toks, t)
		return nil
	}
	n := len(data)
	for i := 0; i < n; {
		c := data[i]
		switch c {
		case '\n':
			line++
			i++
			continue
		case ' ', '\t', '\r':
			i++
			continue
		case '#':
			for i < n && data[i] != '\n' {
				i++
			}
			continue
		case ';', '{', '}':
			if err := add(token{text: string(c), punct: true, file: file, line: line}); err != nil {
				return nil, err
			}
			i++
			continue
		}
		var b strings.Builder
		startLine := line
		if c == '"' || c == '\'' {
			i++
			closed := false
			for i < n && !closed {
				ch := data[i]
				switch {
				case ch == '\\' && i+1 < n:
					if data[i+1] == '\n' {
						line++
					}
					escape(&b, data[i+1], false)
					i += 2
				case ch == c:
					closed = true
					i++
				default:
					if ch == '\n' {
						line++
					}
					b.WriteByte(ch)
					i++
				}
				if b.Len() > MaxLine {
					return nil, ErrLineTooLong
				}
			}
			if !closed {
				return nil, ErrSyntax
			}
			if i < n {
				if f := data[i]; f != ' ' && f != '\t' && f != '\r' && f != '\n' && f != ';' && f != '{' {
					return nil, ErrSyntax
				}
			}
		} else {
			for i < n {
				ch := data[i]
				if ch == '\\' && i+1 < n {
					if data[i+1] == '\n' {
						line++
					}
					escape(&b, data[i+1], true)
					i += 2
				} else if ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n' || ch == ';' ||
					(ch == '{' && data[i-1] != '$') {
					break
				} else {
					b.WriteByte(ch)
					i++
				}
				if b.Len() > MaxLine {
					return nil, ErrLineTooLong
				}
			}
		}
		if err := add(token{text: b.String(), file: file, line: startLine}); err != nil {
			return nil, err
		}
	}
	return toks, nil
}

type parser struct {
	toks []token
	i    int
}

// block reads directives until the matching "}" (closing) or the end of input (top level).
func (p *parser) block(depth int, closing bool) ([]node, error) {
	if depth > MaxDepth {
		return nil, ErrTooDeep
	}
	var out []node
	var cur []token
	for p.i < len(p.toks) {
		t := p.toks[p.i]
		p.i++
		if t.punct {
			switch t.text {
			case ";":
				if len(cur) > 0 {
					out = append(out, node{name: cur[0].text, args: cur[1:], file: cur[0].file, line: cur[0].line})
				}
				cur = nil
				continue
			case "{":
				if len(cur) == 0 {
					return nil, ErrSyntax
				}
				children, err := p.block(depth+1, true)
				if err != nil {
					return nil, err
				}
				out = append(out, node{name: cur[0].text, args: cur[1:], file: cur[0].file, line: cur[0].line, block: true, children: children})
				cur = nil
				continue
			case "}":
				if !closing || len(cur) > 0 {
					return nil, ErrSyntax
				}
				return out, nil
			}
		}
		cur = append(cur, t)
	}
	if closing || len(cur) > 0 {
		return nil, ErrSyntax
	}
	return out, nil
}

// expander splices the files of the dump in at their include directives.
type expander struct {
	secs    []section
	byName  map[string][]int // cleaned file name -> sections
	confDir string
	nodes   int // remaining directive budget
	work    int // remaining glob matching budget
}

func (e *expander) expand(nodes []node, depth int, stack []int) ([]node, error) {
	if depth > MaxDepth {
		return nil, ErrTooDeep
	}
	out := make([]node, 0, len(nodes))
	for _, n := range nodes {
		if e.nodes--; e.nodes < 0 {
			return nil, ErrTooComplex
		}
		switch {
		case n.block:
			kids, err := e.expand(n.children, depth+1, stack)
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
				if slices.Contains(stack, i) {
					return nil, ErrIncludeLoop
				}
				sub, err := e.expand(e.secs[i].nodes, depth, append(stack, i))
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

// match returns the sections whose file name matches the include pattern (a relative pattern is
// relative to confDir, like nginx's configuration prefix).
func (e *expander) match(raw string) ([]int, error) {
	if raw == "" || len(raw) > maxPattern || strings.Contains(raw, "$") {
		return nil, nil
	}
	p := raw
	if !filepath.IsAbs(p) {
		if !filepath.IsAbs(e.confDir) {
			return nil, nil
		}
		p = filepath.Join(e.confDir, p)
	}
	p = filepath.Clean(p)
	if !strings.ContainsAny(p, `*?[\`) {
		if e.work--; e.work < 0 {
			return nil, ErrTooComplex
		}
		return e.byName[p], nil
	}
	var out []int
	for i, s := range e.secs {
		if s.file == "" {
			continue
		}
		if e.work -= len(p) * len(s.file); e.work < 0 {
			return nil, ErrTooComplex
		}
		if ok, err := filepath.Match(p, filepath.Clean(s.file)); err == nil && ok {
			out = append(out, i)
		}
	}
	return out, nil
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
	secs, files, err := splitSections(dump)
	if err != nil {
		return Config{}, err
	}
	left := MaxTokens
	for i := range secs {
		toks, err := tokenize(secs[i].body, secs[i].file, &left)
		if err != nil {
			return Config{}, err
		}
		p := &parser{toks: toks}
		if secs[i].nodes, err = p.block(0, false); err != nil {
			return Config{}, err
		}
		secs[i].body = nil
	}
	c := Config{Files: files}
	if len(secs) == 0 {
		return c, nil
	}
	e := &expander{secs: secs, byName: map[string][]int{}, confDir: confDir, nodes: maxNodes, work: maxWork}
	for i, s := range secs {
		if s.file != "" {
			k := filepath.Clean(s.file)
			e.byName[k] = append(e.byName[k], i)
		}
	}
	tree, err := e.expand(secs[0].nodes, 0, []int{0})
	if err != nil {
		return Config{}, err
	}
	for _, n := range tree {
		switch {
		case n.block && n.name == "http":
			c.http(n.children, confDir)
		case n.block && n.name == "stream":
			c.stream(n.children)
		}
	}
	return c, nil
}

type sslDirs struct {
	certs, keys []string
	password    bool
}

func collect(nodes []node) sslDirs {
	var d sslDirs
	for _, n := range nodes {
		if n.block || len(n.args) == 0 {
			continue
		}
		switch n.name {
		case "ssl_certificate":
			d.certs = append(d.certs, n.args[0].text)
		case "ssl_certificate_key":
			d.keys = append(d.keys, n.args[0].text)
		case "ssl_password_file":
			d.password = true
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
		s := server(n)
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
			pr := Pair{CertRaw: cr, Inherited: inhC || (inhK && len(top.keys) > 0)}
			if i < len(keys) {
				pr.KeyRaw = keys[i]
			}
			pr.Cert, pr.Key, pr.Unsupported = resolvePair(pr.CertRaw, pr.KeyRaw, confDir, password)
			s.Pairs = append(s.Pairs, pr)
		}
		c.Servers = append(c.Servers, s)
	}
}

func (c *Config) stream(children []node) {
	for _, n := range children {
		if !n.block || n.name != "server" {
			continue
		}
		own := collect(n.children)
		if len(own.certs) == 0 {
			continue
		}
		s := server(n)
		s.Stream = true
		for i, cr := range own.certs {
			pr := Pair{CertRaw: cr, Unsupported: ReasonStream}
			if i < len(own.keys) {
				pr.KeyRaw = own.keys[i]
			}
			s.Pairs = append(s.Pairs, pr)
		}
		c.Servers = append(c.Servers, s)
		if !contains(c.Warnings, WarnStreamTLS) {
			c.Warnings = append(c.Warnings, WarnStreamTLS)
		}
	}
}

func server(n node) Server {
	s := Server{File: n.file, Line: n.line}
	sslOn := false
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
		case "ssl":
			sslOn = len(d.args) == 1 && d.args[0].text == "on"
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
		case "ssl":
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
	// A path that names a directory ("", ".", "ssl/", "x/..") is never a certificate file.
	if last := raw[strings.LastIndexByte(raw, '/')+1:]; last == "" || last == "." || last == ".." {
		return "", false
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
