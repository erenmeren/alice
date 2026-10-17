package haproxyconf

import "bytes"

// word is one word of a configuration line after quote removal and escapes. dollar says the
// word holds a "$": HAProxy expands "$NAME" and "${NAME}" inside double quotes, and an unquoted
// or single-quoted "$" is a literal one, but Alice never guesses which file is meant, so any
// "$" in a path makes the pair variable (Ruling 5, D4).
type word struct {
	text   string
	dollar bool
}

// line is one configuration line with at least one word; n is its 1-based physical line number
// (blank and comment lines count).
type line struct {
	n     int
	words []word
}

// lex splits haproxy.cfg into lines of words the way HAProxy's parse_line does (Ruling 5):
//   - lines end at LF; there is no continuation, so a backslash before the line end (or the end
//     of the input) is a literal backslash;
//   - outside quotes, blanks (space, \t, \v, \f, \r) separate words and an unescaped "#" starts
//     a comment that runs to the end of the line, even right after a word;
//   - "..." and '...' group text, the quotes are removed, and quoted parts join adjacent text
//     into one word ("" alone is an empty word); a quote that is not closed on its line is
//     ErrSyntax;
//   - outside single quotes, \\ \" \' \# \$ and "\ " stand for the character, \t \r \n for the
//     control character and \xHH for the byte; any other escape is ErrSyntax, and \x00 is
//     ErrNUL; inside single quotes a backslash is literal;
//   - a NUL anywhere is ErrNUL. Case is kept (keywords are case-sensitive).
//
// The input is bounded by MaxInput (ErrTooLarge), each line by MaxLine (ErrLineTooLong) and
// the words of the file by MaxTokens (ErrTooComplex). Errors name the line.
func lex(data []byte) ([]line, error) {
	if len(data) > MaxInput {
		return nil, ErrTooLarge
	}
	if i := bytes.IndexByte(data, 0); i >= 0 {
		return nil, lineErr(ErrNUL, bytes.Count(data[:i], []byte("\n"))+1)
	}
	var (
		lines  []line
		tokens int
		buf    []byte // the word being read; reused
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
		var (
			words          []word
			inWord, dollar bool
			quote          byte // 0, '"' or '\''
		)
		emit := func() error {
			if tokens++; tokens > MaxTokens {
				return ErrTooComplex
			}
			words = append(words, word{text: string(buf), dollar: dollar})
			buf, inWord, dollar = buf[:0], false, false
			return nil
		}
	scan:
		for i := 0; i < len(text); i++ {
			c := text[i]
			switch {
			case quote == '\'':
				if c == '\'' {
					quote = 0
					continue
				}
			case c == '\\':
				r, skip, err := escape(text[i+1:])
				if err != nil {
					return nil, lineErr(err, n)
				}
				c, i = r, i+skip
			case c == '"' && quote == '"':
				quote = 0
				continue
			case quote == '"':
			case c == '"' || c == '\'':
				quote, inWord = c, true
				continue
			case c == '#':
				break scan
			case isBlank(c):
				if inWord {
					if err := emit(); err != nil {
						return nil, lineErr(err, n)
					}
				}
				continue
			}
			buf = append(buf, c)
			inWord = true
			if c == '$' {
				dollar = true
			}
		}
		if quote != 0 {
			return nil, lineErr(ErrSyntax, n)
		}
		if inWord {
			if err := emit(); err != nil {
				return nil, lineErr(err, n)
			}
		}
		if len(words) > 0 {
			lines = append(lines, line{n: n, words: words})
		}
	}
	return lines, nil
}

// escape reads the escape after a backslash; rest is the line after the backslash. It returns
// the byte the escape stands for and how many bytes of rest it used. A backslash at the end of
// the line is a literal backslash (HAProxy has no line continuation).
func escape(rest []byte) (c byte, used int, err error) {
	if len(rest) == 0 || (len(rest) == 1 && rest[0] == '\r') {
		return '\\', 0, nil
	}
	switch rest[0] {
	case '\\', '"', '\'', '#', '$', ' ':
		return rest[0], 1, nil
	case 't':
		return '\t', 1, nil
	case 'r':
		return '\r', 1, nil
	case 'n':
		return '\n', 1, nil
	case 'x':
		if len(rest) < 3 {
			return 0, 0, ErrSyntax
		}
		hi, ok1 := hexValue(rest[1])
		lo, ok2 := hexValue(rest[2])
		if !ok1 || !ok2 {
			return 0, 0, ErrSyntax
		}
		if c = hi<<4 | lo; c == 0 {
			return 0, 0, ErrNUL
		}
		return c, 3, nil
	}
	return 0, 0, ErrSyntax
}

func hexValue(c byte) (byte, bool) {
	switch {
	case isDigit(c):
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

// isBlank is isspace in the C locale, without the line end (lines are already split at LF).
func isBlank(c byte) bool {
	return c == ' ' || c == '\t' || c == '\v' || c == '\f' || c == '\r'
}
