package haproxyconf

import "bytes"

// crtListLine is one entry of a crt-list file: n is its 1-based physical line number, path the
// certificate path as written (not joined to crt-base, not checked) and names its SNI filters
// without the negative ("!") ones, in order.
type crtListLine struct {
	n     int
	path  string
	names []string
}

// parseCrtList reads a crt-list file the way HAProxy's crtlist_parse_line does (Ruling 11):
//   - a line whose first byte is "#" is a comment (an indented "#" is a path); a line of blanks
//     is skipped;
//   - blanks (C isspace) separate words; there are no quotes (a '"' is part of the word) and no
//     escapes, so a trailing "# x" is three filters, as HAProxy keeps it;
//   - "[" and "]" also separate words, wherever they are, and enclose the option block, which is
//     skipped. It must follow the path directly ("filters can't be between filename and
//     options"); a "[" before the path, a second "[" or "]", a "]" without "[" or a "[" left
//     open is ErrSyntax;
//   - the first word is the path; the words after the option block (or after the path) are
//     the filters.
//
// The input is bounded as lex's is: MaxInput (ErrTooLarge), MaxLine (ErrLineTooLong), MaxTokens
// words including the options (ErrTooComplex), and a NUL is ErrNUL. Errors name the line.
func parseCrtList(data []byte) ([]crtListLine, error) {
	if len(data) > MaxInput {
		return nil, ErrTooLarge
	}
	if i := bytes.IndexByte(data, 0); i >= 0 {
		return nil, lineErr(ErrNUL, bytes.Count(data[:i], []byte("\n"))+1)
	}
	var (
		out    []crtListLine
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
			return nil, lineErr(ErrLineTooLong, n)
		}
		if len(text) > 0 && text[0] == '#' {
			continue
		}
		l, words, err := crtListEntry(text)
		if err != nil {
			return nil, lineErr(err, n)
		}
		if tokens += words; tokens > MaxTokens {
			return nil, lineErr(ErrTooComplex, n)
		}
		if l.path != "" {
			l.n = n
			out = append(out, l)
		}
	}
	return out, nil
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
			// an option
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
