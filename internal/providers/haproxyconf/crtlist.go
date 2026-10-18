package haproxyconf

import "bytes"

// crtListLine is one entry of a crt-list file: n is its 1-based physical line number, path the
// certificate path as written (not joined to crt-base, not checked) and names its SNI filters
// without the negative ("!") ones, in order. override says the option block may name a file of
// the line's own (overrideOption).
type crtListLine struct {
	n        int
	path     string
	names    []string
	override bool
}

// overrideKeywords are the crt-store load keywords a crt-list option block takes from HAProxy 3.0
// on ("sslbindconf also supports the following keywords from the crt-store load keyword"): each
// names a file of the line's own, crt and key the very pair Alice would report (final review I1).
// ocsp-update names no file and is not here.
var overrideKeywords = map[string]bool{"crt": true, "key": true, "ocsp": true, "issuer": true, "sctl": true}

// overrideOption reports whether an option-block word may name a file of the line's own: one of
// overrideKeywords wherever it stands (a keyword's argument that happens to be spelled so counts
// too: fail closed), or a word holding a quote, a backslash or a "$", which this reader does not
// interpret and a newer HAProxy might (the block cannot be read with certainty).
func overrideOption(w []byte) bool {
	return overrideKeywords[string(w)] || bytes.ContainsAny(w, "\"'\\$")
}

// parseCrtList reads a crt-list file the way HAProxy's crtlist_parse_line does (Ruling 11):
//   - a line whose first byte is "#" is a comment (an indented "#" is a path), and a line whose
//     first byte is CR is skipped whatever follows (crtlist_parse_file skips a line starting
//     with "#", "\n" or "\r"; review I3); a line of blanks is skipped;
//   - blanks (C isspace) separate words; there are no quotes (a '"' is part of the word) and no
//     escapes, so a trailing "# x" is three filters, as HAProxy keeps it;
//   - "[" and "]" also separate words, wherever they are, and enclose the option block. Its
//     words are not interpreted, only looked at: one that may name a file of the line's own
//     (overrideOption: HAProxy 3.0's crt, key, ocsp, issuer and sctl) sets override, which makes
//     the line's pair conditional (final review I1). A "[" before the path, a second "[" or "]", or a "]" without "[" is ErrSyntax,
//     as HAProxy refuses them. Two forms HAProxy accepts are refused here to fail closed: a
//     "[" left open (HAProxy reads the words after it as filters, silently) and an option
//     block after a filter (HAProxy warns and drops the filters before the block);
//   - the first word is the path; the words after the option block (or after the path) are
//     the filters.
//
// The input is bounded as lex's is: MaxInput (ErrTooLarge), MaxLine (ErrLineTooLong), MaxTokens
// words including the options (ErrTooComplex), and a NUL is ErrNUL. Errors name the line.
func parseCrtList(data []byte) ([]crtListLine, error) {
	lines, _, err := parseCrtListBudget(data, MaxTokens)
	return lines, err
}

// parseCrtListBudget is parseCrtList with a word budget (see lexEach); it also returns the
// number of words read.
func parseCrtListBudget(data []byte, budget int) ([]crtListLine, int, error) {
	if len(data) > MaxInput {
		return nil, 0, ErrTooLarge
	}
	if i := bytes.IndexByte(data, 0); i >= 0 {
		return nil, 0, lineErr(ErrNUL, bytes.Count(data[:i], []byte("\n"))+1)
	}
	var (
		// Sized once (see lex): the lines that are not skipped and hold a word.
		out = sized[crtListLine](countLines(data, budget, func(text []byte) bool {
			return len(text) > 0 && text[0] != '#' && text[0] != '\r' && len(bytes.TrimLeft(text, " \t\n\v\f\r")) > 0
		}))
		tokens int
	)
	for pos, n := 0, 1; pos < len(data); n++ {
		text := data[pos:]
		if end := bytes.IndexByte(text, '\n'); end >= 0 {
			text = text[:end]
			pos += end + 1
		} else {
			pos = len(data)
		}
		if len(text) > MaxLine {
			return nil, 0, lineErr(ErrLineTooLong, n)
		}
		if len(text) > 0 && (text[0] == '#' || text[0] == '\r') {
			continue
		}
		l, words, err := crtListEntry(text)
		if err != nil {
			return nil, 0, lineErr(err, n)
		}
		if tokens += words; tokens > budget {
			return nil, 0, lineErr(ErrTooComplex, n)
		}
		if l.path != "" {
			l.n = n
			out = append(out, l)
		}
	}
	return out, tokens, nil
}

// crtListEntry reads one non-comment line. It returns the entry (an empty path for a blank
// line) and the number of words the line holds, options included.
func crtListEntry(text []byte) (l crtListLine, words int, err error) {
	var (
		open, closed bool // the option block was opened, closed
		blockAt      int  // index of the word the option block starts at
		start        = -1 // start of the current word, or -1
	)
	end := func(i int) {
		if start < 0 {
			return
		}
		w := text[start:i]
		start = -1
		switch {
		case words == 0:
			l.path = string(w)
		case open && !closed:
			l.override = l.override || overrideOption(w)
		case w[0] != '!':
			l.names = append(l.names, string(w))
		}
		words++
	}
	for i, c := range text {
		switch {
		case c == '[':
			end(i)
			if open || words == 0 {
				return crtListLine{}, 0, ErrSyntax
			}
			open, blockAt = true, words
		case c == ']':
			end(i)
			if closed || !open {
				return crtListLine{}, 0, ErrSyntax
			}
			closed = true
		case isSpace(c):
			end(i)
		case start < 0:
			start = i
		}
	}
	end(len(text))
	if open && (!closed || blockAt > 1) {
		return crtListLine{}, 0, ErrSyntax
	}
	return l, words, nil
}

// isSpace is isspace in the C locale.
func isSpace(c byte) bool { return c == '\n' || isBlank(c) }
