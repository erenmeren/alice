package ldapx

import (
	"errors"
	"strings"
	"unicode/utf8"
)

// ErrFilterTemplate is a filter template that is not one valid RFC 4515 filter, names a placeholder other than
// {login} and {dn}, or names one without a value. Its text never carries a template or a value.
var ErrFilterTemplate = errors.New("ldapx: the filter template is not valid")

// ErrFilterValue is an empty value for a placeholder: next to "*" it would turn a substring filter into a presence
// filter that matches every entry.
var ErrFilterValue = errors.New("ldapx: a filter value is empty")

// Placeholder names a filter template may contain.
const (
	PlaceholderLogin = "login"
	PlaceholderDN    = "dn"
)

const (
	maxTemplate    = 1024 // bytes of a template
	maxFilterDepth = 16   // nesting of ( ) in a template
	// placeholderProbe stands in for a placeholder while the template is checked: an escaped "x" is valid only in an
	// assertion value, so a placeholder in an attribute description, a matching rule or next to a backslash fails.
	placeholderProbe = `\78`
)

type segment struct {
	text        string
	placeholder bool
}

// ExpandFilter replaces {login} and {dn} in an RFC 4515 filter template with the values of vals, each escaped with
// EscapeFilter. The template must be one balanced filter; a placeholder may stand only inside an assertion value; a
// placeholder other than {login} and {dn}, a placeholder without a value, a value name that is not a placeholder and
// any other brace are refused with ErrFilterTemplate; an empty value is refused with ErrFilterValue. A value can never
// change the structure of the filter.
func ExpandFilter(tmpl string, vals map[string]string) (string, error) {
	for name := range vals {
		if name != PlaceholderLogin && name != PlaceholderDN {
			return "", ErrFilterTemplate
		}
	}
	if len(tmpl) > maxTemplate {
		return "", ErrFilterTemplate
	}
	segs, err := splitTemplate(tmpl)
	if err != nil {
		return "", err
	}
	var probe, out strings.Builder
	for _, s := range segs {
		if !s.placeholder {
			probe.WriteString(s.text)
			out.WriteString(s.text)
			continue
		}
		v, ok := vals[s.text]
		if !ok {
			return "", ErrFilterTemplate
		}
		if v == "" {
			// An empty value next to "*" turns (cn={login}*) into the presence filter (cn=*): refused.
			return "", ErrFilterValue
		}
		probe.WriteString(placeholderProbe)
		out.WriteString(EscapeFilter(v))
	}
	// Escaped values contain no byte that ends a value, so the expansion has the structure of the probe; the
	// property test and FuzzExpandFilter compile both with go-ldap and compare their shapes.
	if !validFilter(probe.String()) {
		return "", ErrFilterTemplate
	}
	return out.String(), nil
}

// splitTemplate cuts a template into literal text and placeholder names.
func splitTemplate(tmpl string) ([]segment, error) {
	var segs []segment
	for tmpl != "" {
		open := strings.IndexAny(tmpl, "{}")
		if open < 0 {
			segs = append(segs, segment{text: tmpl})
			break
		}
		if tmpl[open] == '}' {
			return nil, ErrFilterTemplate
		}
		end := strings.IndexAny(tmpl[open+1:], "{}")
		if end < 0 || tmpl[open+1+end] != '}' {
			return nil, ErrFilterTemplate
		}
		name := tmpl[open+1 : open+1+end]
		if name != PlaceholderLogin && name != PlaceholderDN {
			return nil, ErrFilterTemplate
		}
		if open > 0 {
			segs = append(segs, segment{text: tmpl[:open]})
		}
		segs = append(segs, segment{text: name, placeholder: true})
		tmpl = tmpl[open+1+end+1:]
	}
	return segs, nil
}

// validFilter reports whether f is exactly one RFC 4515 filter, read strictly: no surrounding space, no raw control
// characters, valid UTF-8, at least one element in & and |, a dnattrs part only as the lower-case ":dn" (go-ldap
// reads no other spelling) and at most maxFilterDepth levels.
func validFilter(f string) bool {
	p := &filterParser{s: f}
	return p.filter(0) && p.i == len(f)
}

type filterParser struct {
	s string
	i int
}

func (p *filterParser) peek() byte {
	if p.i < len(p.s) {
		return p.s[p.i]
	}
	return 0
}

func (p *filterParser) eat(c byte) bool {
	if p.i < len(p.s) && p.s[p.i] == c {
		p.i++
		return true
	}
	return false
}

// filter = "(" filtercomp ")"
func (p *filterParser) filter(depth int) bool {
	if depth >= maxFilterDepth || !p.eat('(') {
		return false
	}
	var ok bool
	switch p.peek() {
	case '&', '|':
		p.i++
		n := 0
		for p.peek() == '(' {
			if !p.filter(depth + 1) {
				return false
			}
			n++
		}
		ok = n > 0
	case '!':
		p.i++
		ok = p.filter(depth + 1)
	default:
		ok = p.item()
	}
	return ok && p.eat(')')
}

// item = simple / present / substring / extensible
func (p *filterParser) item() bool {
	attr := p.attributeDescription()
	switch {
	case attr != "" && p.eat('='):
		return p.value(true)
	case strings.HasPrefix(p.s[p.i:], "~="), strings.HasPrefix(p.s[p.i:], ">="), strings.HasPrefix(p.s[p.i:], "<="):
		if attr == "" {
			return false
		}
		p.i += 2
		return p.value(false)
	case p.peek() == ':':
		return p.extensible(attr != "")
	}
	return false
}

// extensible = ( attr [":dn"] [":" matchingrule] ":=" value ) / ( [":dn"] ":" matchingrule ":=" value )
func (p *filterParser) extensible(hasAttr bool) bool {
	if strings.HasPrefix(p.s[p.i:], ":dn:") {
		p.i += 3
	}
	hasRule := false
	if !strings.HasPrefix(p.s[p.i:], ":=") {
		p.i++ // the ':' before the matching rule
		if !p.oid() {
			return false
		}
		hasRule = true
	}
	if !strings.HasPrefix(p.s[p.i:], ":=") || (!hasAttr && !hasRule) {
		return false
	}
	p.i += 2
	return p.value(false)
}

// attributeDescription = oid *(";" option); it returns the text read, or "" when there is none (or it is invalid,
// which the caller then refuses at the next character).
func (p *filterParser) attributeDescription() string {
	start := p.i
	if !p.oid() {
		p.i = start
		return ""
	}
	for p.peek() == ';' {
		p.i++
		n := 0
		for isKeyChar(p.peek()) {
			p.i++
			n++
		}
		if n == 0 {
			p.i = start
			return ""
		}
	}
	return p.s[start:p.i]
}

// oid = descr / numericoid; descr = ALPHA *(ALPHA / DIGIT / "-"); numericoid = number 1*("." number).
func (p *filterParser) oid() bool {
	c := p.peek()
	switch {
	case isAlpha(c):
		for isKeyChar(p.peek()) {
			p.i++
		}
		return true
	case isDigit(c):
		for {
			if !p.number() {
				return false
			}
			if !p.eat('.') {
				return true
			}
		}
	}
	return false
}

// number = DIGIT / ( LDIGIT 1*DIGIT )
func (p *filterParser) number() bool {
	if !isDigit(p.peek()) {
		return false
	}
	lead := p.peek()
	p.i++
	if lead == '0' {
		return !isDigit(p.peek())
	}
	for isDigit(p.peek()) {
		p.i++
	}
	return true
}

// value reads an assertion value up to the closing ")": no raw NUL, "(", control character or U+FFFD; "\" only
// before two hex digits; "*" only where a substring or presence filter allows it.
func (p *filterParser) value(starOK bool) bool {
	for p.i < len(p.s) {
		c := p.s[p.i]
		switch {
		case c == ')':
			return true
		case c == '(' || c < 0x20 || c == 0x7f:
			return false
		case c == '*':
			if !starOK {
				return false
			}
		case c == '\\':
			if p.i+2 >= len(p.s) || !isHex(p.s[p.i+1]) || !isHex(p.s[p.i+2]) {
				return false
			}
			p.i += 2
		case c >= utf8.RuneSelf:
			r, size := utf8.DecodeRuneInString(p.s[p.i:])
			if r == utf8.RuneError {
				return false
			}
			p.i += size - 1
		}
		p.i++
	}
	return false
}

func isAlpha(c byte) bool   { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') }
func isDigit(c byte) bool   { return c >= '0' && c <= '9' }
func isKeyChar(c byte) bool { return isAlpha(c) || isDigit(c) || c == '-' }
