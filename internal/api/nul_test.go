package api

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"testing/iotest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/license"
	"alice/internal/rbac"
)

// AUD-13: the JSON text check finds exactly the escape that decodes to NUL, wherever it is (a value,
// a key, a nested array), and nothing else: an escaped backslash followed by "u0000" is text.
func TestNULEscapeScanner(t *testing.T) {
	for body, want := range map[string]bool{
		`{"name":"a\u0000b"}`:      true,
		`{"a\u0000":1}`:            true,
		`{"x":[{"y":["\u0000"]}]}`: true,
		`"\u0000"`:                 true,
		`{"name":"\\\u0000"}`:      true, // an escaped backslash, then the escape
		`{"name":"\\u0000"}`:       false,
		`{"name":"\\\\u0000"}`:     false,
		`{"name":"\u00000"}`:       true,
		`{"name":"\u0001Āကé"}`:     false,
		`{"name":"\ud800"}`:        false, // a lone surrogate decodes to U+FFFD, which is storable
		`{"pfx_base64":"AAAAAAAA","pem":"-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"}`: false,
		`{"name":"İzmir 🔑 é"}`: false,
		`{"name":"\u0000`:       true, // incomplete JSON is refused anyway; the escape is still seen
	} {
		assert.Equal(t, want, hasNULEscape([]byte(body)), body)
		// The same answer when the text arrives one byte at a time (an escape split across reads).
		var sc nulScanner
		for i := range len(body) {
			sc.scan([]byte{body[i]})
		}
		assert.Equal(t, want, sc.found, "byte by byte: %s", body)
	}
}

// FuzzNULEscape compares the scanner with encoding/json itself: for every valid JSON text, the
// scanner reports an escape exactly when a decoded string (a key or a value) holds NUL.
func FuzzNULEscape(f *testing.F) {
	for _, seed := range []string{`{"a":"\u0000"}`, `{"\u0000":1}`, `["\\u0000"]`, `"\\\u0000"`, `{"a":"\ud800\u0000"}`,
		`{"a":"x\u00001"}`, `{"a":"Ā"}`, `[1,2,{"b":null}]`, `"\u000"`, "\"\xff\"", `{"pfx_base64":"AAAA"}`} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		var v any
		if json.Unmarshal(b, &v) != nil {
			return
		}
		assert.Equal(t, decodedHasNUL(v), hasNULEscape(b), "%q", b)
	})
}

func decodedHasNUL(v any) bool {
	switch x := v.(type) {
	case string:
		return strings.ContainsRune(x, 0)
	case []any:
		for _, e := range x {
			if decodedHasNUL(e) {
				return true
			}
		}
	case map[string]any:
		for k, e := range x {
			if strings.ContainsRune(k, 0) || decodedHasNUL(e) {
				return true
			}
		}
	}
	return false
}

// The query check: NUL or invalid UTF-8 in any key or value; escapes that decode to other text pass.
func TestUnstorableQueryParams(t *testing.T) {
	for raw, want := range map[string][]string{
		"q=a%00b":                     {"q"},
		"q=%ff":                       {"q"},
		"q=%C3%28":                    {"q"},
		"%ff=1":                       {"query"},
		"a%00=1":                      {"query"},
		"q=ok&actor=a%00&action=%fe":  {"action", "actor"},
		"q=ok&q=%00":                  {"q"},
		"Some-Key=%00":                {"query"}, // only plain lower-case parameter names are named
		"q=%2F+a%20b&os_user=d%C4%B1": nil,
		"q=%F0%9F%94%91&x=e%CC%81":    nil,
		"":                            nil,
	} {
		assert.Equal(t, want, unstorableParams(url.Values(mustParseQuery(t, raw))), raw)
	}
}

func mustParseQuery(t *testing.T, raw string) url.Values {
	t.Helper()
	v, err := url.ParseQuery(raw)
	require.NoError(t, err)
	return v
}

type edgeError struct {
	Error struct {
		Code    string `json:"code"`
		Details []struct {
			Field string `json:"field"`
			Code  string `json:"code"`
		} `json:"details"`
	} `json:"error"`
}

func edgeErr(t *testing.T, body []byte) edgeError {
	t.Helper()
	var e edgeError
	require.NoError(t, json.Unmarshal(body, &e), "%s", body)
	return e
}

// unstorableRefusal reports whether an answer is the edge's refusal of unstorable text naming field.
func unstorableRefusal(t *testing.T, code int, body []byte, field string) bool {
	t.Helper()
	if code != http.StatusBadRequest {
		return false
	}
	e := edgeErr(t, body)
	return e.Error.Code == "ALC-SYS-0004" && len(e.Error.Details) == 1 &&
		e.Error.Details[0].Field == field && e.Error.Details[0].Code == "validation.pattern"
}

type nulProbe struct {
	Name  string            `json:"name"`
	PFX   []byte            `json:"pfx_base64"`
	Tags  map[string]string `json:"tags"`
	Items []struct {
		V string `json:"v"`
	} `json:"items"`
}

// probeServer serves the decode helpers on public probe routes and counts the bodies they accepted.
func probeServer(t *testing.T) (http.Handler, *int) {
	t.Helper()
	s := newServer(testDeps(t, nil))
	accepted := 0
	handle := func(decode func(w http.ResponseWriter, r *http.Request, dst any) bool) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			var b nulProbe
			if !decode(w, r, &b) {
				return
			}
			accepted++
			writeJSON(w, http.StatusOK, b)
		}
	}
	h := s.handler([]route{
		{method: http.MethodPost, pattern: "/api/v1/probe", perm: rbac.Public, lic: license.ClassAlways, handler: handle(s.decode)},
		{method: http.MethodPost, pattern: "/api/v1/probe-optional", perm: rbac.Public, lic: license.ClassAlways, handler: handle(s.decodeOptional)},
		{method: http.MethodPost, pattern: "/api/v1/probe-exact", perm: rbac.Public, lic: license.ClassAlways, handler: handle(func(w http.ResponseWriter, r *http.Request, dst any) bool {
			return s.decodeExact(w, r, dst, 1<<20, "name", "pfx_base64", "tags", "items")
		})},
	})
	return h, &accepted
}

var probePaths = []string{"/api/v1/probe", "/api/v1/probe-optional", "/api/v1/probe-exact"}

// AUD-13: every decode helper refuses a body whose decoded text would hold NUL, naming the body and
// never echoing the value; the same body without the NUL is accepted (D18: the NUL decides).
func TestDecodeHelpersRefuseNULText(t *testing.T) {
	h, accepted := probeServer(t)
	for _, path := range probePaths {
		for _, body := range []string{
			`{"name":"a\u0000b"}`, `{"tags":{"k\u0000":"v"}}`, `{"tags":{"k":"\u0000"}}`, `{"items":[{"v":"x\u0000"}]}`,
		} {
			rec := call(h, http.MethodPost, path, "", body)
			assert.True(t, unstorableRefusal(t, rec.Code, rec.Body.Bytes(), "body"), "%s %s: %d %s", path, body, rec.Code, rec.Body)
			assert.NotContains(t, rec.Body.String(), `\u0000`, path)
			clean := strings.ReplaceAll(body, `\u0000`, "")
			before := *accepted
			rec = call(h, http.MethodPost, path, "", clean)
			assert.Equal(t, http.StatusOK, rec.Code, "%s %s", path, clean)
			assert.Equal(t, before+1, *accepted, path)
		}
	}
}

// Legitimate content is not refused: binary in base64 (NUL bytes once decoded), PEM text, Turkish
// letters, emoji, combining marks, an escaped backslash before "u0000", a lone surrogate (U+FFFD)
// and invalid UTF-8 in a JSON string (encoding/json reads it as U+FFFD).
func TestDecodeHelpersAcceptLegitimateText(t *testing.T) {
	h, _ := probeServer(t)
	for _, path := range probePaths {
		for body, want := range map[string]string{
			`{"name":"İzmir ığüşöç 🔑 é"}`:                                              "İzmir ığüşöç 🔑 é",
			`{"name":"-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"}`: "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n",
			`{"name":"\\u0000"}`:    `\u0000`,
			`{"name":"\ud800"}`:     "�",
			"{\"name\":\"a\xffb\"}": "a�b",
		} {
			rec := call(h, http.MethodPost, path, "", body)
			require.Equal(t, http.StatusOK, rec.Code, "%s %s: %s", path, body, rec.Body)
			var got nulProbe
			require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &got))
			assert.Equal(t, want, got.Name, path)
		}
		rec := call(h, http.MethodPost, path, "", `{"pfx_base64":"AAAAAP8A"}`)
		require.Equal(t, http.StatusOK, rec.Code, path)
		var got nulProbe
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &got))
		assert.Equal(t, []byte{0, 0, 0, 0, 0xff, 0}, got.PFX, "NUL bytes in decoded binary are content")
	}
}

// Order at the edge: the size cap comes first (a body over the cap is refused as too large whatever
// it holds), the text check reads nothing beyond the cap, and an empty optional body is still fine.
func TestNULCheckRunsAfterTheSizeCap(t *testing.T) {
	h, _ := probeServer(t)
	big := `{"name":"\u0000` + strings.Repeat("a", maxBody) + `"}`
	for _, path := range probePaths {
		rec := call(h, http.MethodPost, path, "", big)
		assert.Equal(t, http.StatusRequestEntityTooLarge, rec.Code, path)
	}
	rec := call(h, http.MethodPost, "/api/v1/probe-optional", "", "")
	assert.Equal(t, http.StatusOK, rec.Code)
}

// M1: a chunked body (no declared length) over the cap is 413 even when a NUL escape lies within
// the cap, on every helper, whatever the read sizes; within the cap the same body is the NUL refusal.
func TestChunkedBodyOverTheCapIsTooLargeEvenWithNUL(t *testing.T) {
	h, _ := probeServer(t)
	send := func(path, body string, oneByte bool) *httptest.ResponseRecorder {
		var r io.Reader = strings.NewReader(body)
		if oneByte {
			r = iotest.OneByteReader(r)
		}
		req := httptest.NewRequest(http.MethodPost, path, io.NopCloser(r))
		req.ContentLength = -1
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
	big := `{"name":"\u0000` + strings.Repeat("a", maxBody) + `"}`
	small := `{"name":"\u0000` + strings.Repeat("a", 1000) + `"}`
	for _, path := range probePaths {
		for _, oneByte := range []bool{false, true} {
			rec := send(path, big, oneByte)
			assert.Equal(t, http.StatusRequestEntityTooLarge, rec.Code, "%s one byte at a time: %v", path, oneByte)
			rec = send(path, small, oneByte)
			assert.True(t, unstorableRefusal(t, rec.Code, rec.Body.Bytes(), "body"), "%s: %d %s", path, rec.Code, rec.Body)
		}
	}
}

// The streaming check sees an escape split across reads; once found it answers the refusal.
func TestNULCheckOnSplitReads(t *testing.T) {
	body := `{"name":"x\u0000` + strings.Repeat("y", 4096) + `"}`
	r := &textCheck{r: iotest.OneByteReader(strings.NewReader(body))}
	var probe nulProbe
	err := json.NewDecoder(r).Decode(&probe)
	require.ErrorIs(t, err, errUnstorableText)
	assert.True(t, r.found())
	assert.Equal(t, len(body), r.read, "the rest is read once to tell the size cap, then nothing more")
	n, err := r.Read(make([]byte, 8))
	assert.Zero(t, n)
	assert.ErrorIs(t, err, errUnstorableText)
	assert.False(t, hasNULEscape(bytes.Repeat([]byte(`\\u0000`), 3)))
}
