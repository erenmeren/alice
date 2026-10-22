package api

import (
	"errors"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"slices"

	"alice/internal/platform/validate"
)

// Text PostgreSQL cannot store (AUD-13) is refused at the edge with 400 ALC-SYS-0004 before it can
// reach a query: PostgreSQL refuses NUL and invalid UTF-8 in text (SQLSTATE 22021), which would
// otherwise be a 500. One place per input class:
//
//   - query keys and values: guard, before authentication, for every route in the table
//     (refuseUnstorableQuery), which also refuses a query that does not parse;
//   - JSON bodies: the decode helpers (readJSON, decodeExact), under the size cap (a body over the
//     cap is 413 whether or not it holds NUL) and before the DTO is decoded, so no body is read before guard's authorization and license gate. encoding/json
//     reads invalid UTF-8 and lone surrogates as U+FFFD, which is storable; the only way a decoded
//     string (key or value) can hold NUL is the escape \u0000, so the check scans the JSON text for
//     it (nulScanner) and is the same for every DTO;
//   - path values: parsed as UUIDs by pathUUID; nothing else reads them;
//   - headers: credentials are compared as hashes, X-Forwarded-For is parsed as addresses, If-Match
//     by a pattern, and the stored User-Agent is cleaned by meta (net/http refuses control
//     characters in header values on HTTP/1 and HTTP/2 anyway).

// errUnstorableText: a request body holds text PostgreSQL cannot store.
var errUnstorableText = errors.New("api: text PostgreSQL cannot store")

// nulScanner finds the JSON escape \u0000 in JSON text fed in any number of pieces. In JSON a
// backslash appears only inside strings, where it starts an escape, so the scanner needs no notion
// of where strings begin: an escaped backslash ("\\") is consumed as one escape, and "\u" followed
// by four zeros is the NUL escape.
type nulScanner struct {
	state int8 // 0 text; 1 after a backslash; 2..5 after "\u" and state-2 zeros
	found bool
}

func (n *nulScanner) scan(b []byte) {
	for _, c := range b {
		if n.found {
			return
		}
		switch {
		case n.state == 1:
			n.state = 0
			if c == 'u' {
				n.state = 2
			}
		case n.state >= 2:
			n.state++
			if c != '0' {
				n.state = 0 // another \uXXXX: its remaining digits are plain text to the scanner
			} else if n.state == 6 {
				n.found = true
			}
		case c == '\\':
			n.state = 1
		}
	}
}

// hasNULEscape reports whether the JSON text b holds the escape \u0000.
func hasNULEscape(b []byte) bool {
	var n nulScanner
	n.scan(b)
	return n.found
}

// textCheck passes a body through nulScanner as it is read. Once the escape is found it answers
// refusal() from then on: the size cap wins (M1), so the rest of the body is read up to the cap
// (never beyond: the reader is the http.MaxBytesReader) to tell a body over the cap (errTooLarge,
// 413) from one within it (errUnstorableText, 400), whatever the reads' sizes.
type textCheck struct {
	r       io.Reader
	sc      nulScanner
	read    int
	refused error
}

// found reports whether the escape was seen in what has been read so far.
func (t *textCheck) found() bool { return t.sc.found }

// refusal is errTooLarge or errUnstorableText once the escape was found, else nil.
func (t *textCheck) refusal() error { return t.refused }

func (t *textCheck) Read(p []byte) (int, error) {
	if t.refused != nil {
		return 0, t.refused
	}
	n, err := t.r.Read(p)
	t.read += n
	t.sc.scan(p[:n])
	if !t.sc.found {
		return n, err
	}
	t.refused = errUnstorableText
	var tooLarge *http.MaxBytesError
	if err == nil {
		var drained int64
		drained, err = io.Copy(io.Discard, t.r)
		t.read += int(drained)
	}
	if errors.As(err, &tooLarge) {
		t.refused = errTooLarge
	}
	return n, t.refused
}

// paramNameRE: a query parameter name the refusal may name (the documented names are of this form);
// any other name is reported as "query", so the answer never echoes text the client chose freely.
var paramNameRE = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)

// unstorableParams returns the names of the query parameters whose key or value is not
// StorableText, sorted ("query" for a key that cannot be named), or nil.
func unstorableParams(q url.Values) []string {
	var bad []string
	for k, vs := range q {
		name := k
		if !validate.StorableText(k) || !paramNameRE.MatchString(k) {
			name = "query"
		}
		ok := validate.StorableText(k)
		for _, v := range vs {
			ok = ok && validate.StorableText(v)
		}
		if !ok && !slices.Contains(bad, name) {
			bad = append(bad, name)
		}
	}
	slices.Sort(bad)
	return bad
}

// refuseUnstorableQuery answers 400 ALC-SYS-0004, naming the parameters, when the query holds text
// PostgreSQL cannot store, and reports whether it did.
// A query that does not parse (a bad percent escape such as "%zz", or a ";" separator) is refused
// the same way, as "query" (M2): r.URL.Query() would silently drop the pair, so a restriction the
// caller meant to set (the setup guide's from=) would not apply.
func (s *server) refuseUnstorableQuery(w http.ResponseWriter, r *http.Request) bool {
	q, err := url.ParseQuery(r.URL.RawQuery)
	bad := unstorableParams(q)
	if err != nil && !slices.Contains(bad, "query") {
		bad = append(bad, "query")
		slices.Sort(bad)
	}
	if bad == nil {
		return false
	}
	details := make([]validate.FieldError, 0, len(bad))
	for _, name := range bad {
		details = append(details, validate.FieldError{Field: name, Code: validate.Pattern})
	}
	s.writeErrorWith(w, r, ErrBadRequest, nil, details)
	return true
}

// refuseBody answers a body the decode helpers could not accept: too large (413), text PostgreSQL
// cannot store (400 naming the body, never the value), or anything else malformed (400).
func (s *server) refuseBody(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, errTooLarge):
		s.writeError(w, r, ErrBodyTooLarge)
	case errors.Is(err, errUnstorableText):
		s.writeErrorWith(w, r, ErrBadRequest, nil, []validate.FieldError{{Field: "body", Code: validate.Pattern}})
	default:
		s.writeError(w, r, ErrBadRequest)
	}
}
