package apacheconf

import (
	"bytes"
	"fmt"
	"strings"
)

// line is one logical configuration line: a directive, a section start ("<Name args>") or a
// section end ("</Name>"). first and last are the physical lines (1-based) it starts and ends on;
// Apache reports the last one for a continued Include. name is ASCII-lowercased (directive and
// section names are case-insensitive) without "<", "</" or ">". A section's args are the words
// before its last ">".
type line struct {
	first, last int
	name        string
	args        []string
	section     bool
	closing     bool
}

// lex splits one configuration file into logical lines the way Apache's reader does
// (ap_cfg_getline, ap_build_config_sub, ap_getword_conf):
//   - a backslash right before the end of a physical line (LF or CRLF) joins the next physical
//     line to it; the backslash and the line end are removed, nothing is inserted;
//   - white space (space, \t, \v, \f, \r) around a logical line is dropped, and a line that is
//     then empty or starts with "#" is skipped ("#" later in a line is an ordinary word);
//   - the first word is the name, the rest are arguments: white space splits words, a word that
//     starts with " or ' runs to the same unescaped quote, and a doubled backslash (in or out of
//     quotes) or a backslash before the quote character inside quotes stands for that character;
//     every other backslash is literal;
//   - "<Name args>" opens a section and "</Name>" closes the innermost one, case-insensitively;
//     sections must balance within the file.
//
// Unlike Apache, an unterminated quote is ErrSyntax (Apache silently runs it to the end of the
// line). file only names the file in errors.
func lex(file string, data []byte) ([]line, error) {
	if len(data) > MaxInput {
		return nil, ErrTooLarge
	}
	if i := bytes.IndexByte(data, 0); i >= 0 {
		return nil, lexErr(ErrNUL, file, bytes.Count(data[:i], []byte("\n"))+1)
	}
	var (
		lines  []line
		open   []string // names of the open sections, innermost last
		tokens int
		buf    []byte
		phys   int
	)
	for pos := 0; pos < len(data); {
		first := phys + 1
		buf = buf[:0]
		for {
			seg := data[pos:]
			newline := false
			if end := bytes.IndexByte(seg, '\n'); end >= 0 {
				seg, newline = seg[:end], true
			}
			pos += len(seg)
			if newline {
				pos++
			}
			phys++
			if len(buf)+len(seg) > MaxLine {
				return nil, lexErr(ErrLineTooLong, file, phys)
			}
			cont := false
			if newline {
				if s := bytes.TrimSuffix(seg, []byte("\r")); len(s) > 0 && s[len(s)-1] == '\\' {
					seg, cont = s[:len(s)-1], true
				}
			}
			buf = append(buf, seg...)
			if !cont || pos >= len(data) {
				break
			}
		}
		text := trimSpace(string(buf))
		if text == "" || text[0] == '#' {
			continue
		}
		l, err := lexLine(text)
		if err != nil {
			return nil, lexErr(err, file, first)
		}
		l.first, l.last = first, phys
		if tokens += 1 + len(l.args); tokens > MaxTokens {
			return nil, lexErr(ErrTooComplex, file, first)
		}
		switch {
		case l.closing:
			if len(open) == 0 || open[len(open)-1] != l.name {
				return nil, lexErr(ErrSyntax, file, first)
			}
			open = open[:len(open)-1]
		case l.section:
			if len(open) >= MaxDepth {
				return nil, lexErr(ErrTooDeep, file, first)
			}
			open = append(open, l.name)
		}
		lines = append(lines, l)
	}
	if len(open) > 0 {
		return nil, lexErr(ErrSyntax, file, phys)
	}
	return lines, nil
}

// lexLine splits one trimmed, non-empty, non-comment logical line.
func lexLine(text string) (line, error) {
	if inner, ok := strings.CutPrefix(text, "</"); ok {
		// Apache matches the raw trimmed line, before any unquoting, against "</Name>".
		inner, ok = strings.CutSuffix(inner, ">")
		if !ok || inner == "" || strings.ContainsAny(inner, " \t\n\v\f\r") {
			return line{}, ErrSyntax
		}
		return line{name: asciiLower(inner), closing: true}, nil
	}
	name, rest, err := word(text)
	if err != nil {
		return line{}, err
	}
	if name == "" || strings.HasPrefix(name, "</") {
		// an empty quoted name, or a quoted closing tag ("</If>"): Apache reads the latter as
		// an unknown directive, never as the end of a section
		return line{}, ErrSyntax
	}
	if inner, ok := strings.CutPrefix(name, "<"); ok {
		// ap_build_config_sub drops a ">" that ends the name and, for "<Name>", gives the
		// section the argument string ">"; the section handler then takes the text up to the
		// last ">" of the argument string (what follows it is ignored).
		inner, closed := strings.CutSuffix(inner, ">")
		if inner == "" {
			return line{}, ErrSyntax
		}
		if closed && rest == "" {
			rest = ">"
		}
		end := strings.LastIndexByte(rest, '>')
		if end < 0 {
			return line{}, ErrSyntax
		}
		args, err := words(rest[:end])
		if err != nil {
			return line{}, err
		}
		return line{name: asciiLower(inner), args: args, section: true}, nil
	}
	args, err := words(rest)
	if err != nil {
		return line{}, err
	}
	return line{name: asciiLower(name), args: args}, nil
}

func words(s string) ([]string, error) {
	var args []string
	for {
		s = trimLeftSpace(s)
		if s == "" {
			return args, nil
		}
		w, rest, err := word(s)
		if err != nil {
			return nil, err
		}
		args = append(args, w)
		s = rest
	}
}

// word is ap_getword_conf: it reads one word from s (leading white space skipped) and returns it
// with the rest of s, white space after the word skipped.
func word(s string) (w, rest string, err error) {
	s = trimLeftSpace(s)
	var quote byte
	end := 0
	if s != "" && (s[0] == '"' || s[0] == '\'') {
		quote, end = s[0], 1
		for end < len(s) && s[end] != quote {
			if s[end] == '\\' && end+1 < len(s) && (s[end+1] == quote || s[end+1] == '\\') {
				end += 2
			} else {
				end++
			}
		}
		if end >= len(s) {
			return "", "", ErrSyntax
		}
		w = unescape(s[1:end], quote)
		end++ // the closing quote
	} else {
		for end < len(s) && !isSpace(s[end]) {
			end++
		}
		w = unescape(s[:end], 0)
	}
	return w, trimLeftSpace(s[end:]), nil
}

// unescape is substring_conf: a backslash before a backslash, or before the quote character of a
// quoted word, stands for that character; every other backslash is kept.
func unescape(s string, quote byte) string {
	if strings.IndexByte(s, '\\') < 0 {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) && (s[i+1] == '\\' || (quote != 0 && s[i+1] == quote)) {
			i++
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// isSpace is apr_isspace in the C locale.
func isSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\v' || c == '\f' || c == '\r'
}

func trimSpace(s string) string {
	s = trimLeftSpace(s)
	for len(s) > 0 && isSpace(s[len(s)-1]) {
		s = s[:len(s)-1]
	}
	return s
}

func trimLeftSpace(s string) string {
	i := 0
	for i < len(s) && isSpace(s[i]) {
		i++
	}
	return s[i:]
}

// asciiLower lowercases A-Z only (Apache compares names with strcasecmp; a non-ASCII byte is
// kept as it is, so no Unicode case rule can make two names equal).
func asciiLower(s string) string {
	for i := 0; i < len(s); i++ {
		if c := s[i]; c >= 'A' && c <= 'Z' {
			b := []byte(s)
			for j := i; j < len(b); j++ {
				if b[j] >= 'A' && b[j] <= 'Z' {
					b[j] += 'a' - 'A'
				}
			}
			return string(b)
		}
	}
	return s
}

func lexErr(err error, file string, line int) error {
	return fmt.Errorf("%w (%s line %d)", err, file, line)
}
