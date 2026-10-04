package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/inventory"
)

// Every allowlisted param has a value rule, whichever producer wrote the value: hostile values of
// the older keys are dropped too, well-formed ones pass.
func TestProviderParamsApplyValueRulesToEveryKey(t *testing.T) {
	good := map[string]string{
		"helper_code": "IO_ERROR", "subcommand": "nginx-deploy", "exit_code": "3", "reason": "protected_fingerprint",
		"field": "owner", "attempts": "5", "wait": "connection_slot", "fingerprint": "SHA256:" + strings.Repeat("A", 43),
		"old_fingerprint": strings.Repeat("a", 64), "new_fingerprint": "SHA256:x", "helper_protocol": "4", "required_protocol": "4",
		"port": "443", "failed_step": "verify", "profile": "nginx", "phase": "restored", "mode": "remote", "expected": "rsa",
		"actual": "ecdsa", "backup_dir": "/var/lib/alice-helper/backups/x", "directory": "/etc/nginx/ssl",
	}
	assert.Equal(t, good, providerParams(good))
	for k := range providerParamKeys {
		_, ok := providerParamRules[k]
		assert.True(t, ok, "%s has no value rule", k)
	}
	hostile := map[string]string{
		"helper_code": "io error", "subcommand": "nginx-deploy; rm -rf /", "exit_code": "3x", "reason": "<script>",
		"field": "a b", "attempts": "many", "wait": "Wait!", "fingerprint": "-----BEGIN " + "PRIVATE KEY-----",
		"old_fingerprint": "SHA256:a b", "new_fingerprint": strings.Repeat("z", 300), "helper_protocol": "four",
		"required_protocol": "", "reason2": "x",
		"directory": "relative/dir", "profile": "Nginx Profile", "failed_step": "verify;", "mode": "re mote", "phase": "../x",
		"actual": "RSA", "expected": "rsa\n", "port": "0", "backup_dir": "/x y",
	}
	assert.Nil(t, providerParams(hostile))
	// Each rule on its own: one hostile value among good ones drops exactly that key.
	for k, bad := range hostile {
		if !providerParamKeys[k] {
			continue
		}
		in := maps.Clone(good)
		in[k] = bad
		want := maps.Clone(good)
		delete(want, k)
		assert.Equal(t, want, providerParams(in), "rule of %s", k)
	}
}

// A step's reason is shown only when it is a registered reason, never as a raw key.
func TestStepReasonMustBeRegistered(t *testing.T) {
	assert.Equal(t, map[string]string{"reason": "deployment.verify_failed"}, stepParams(map[string]string{"reason": "deployment.verify_failed"}))
	assert.Empty(t, stepParams(map[string]string{"reason": "deployment.made_up"}))
}

// countingBody records how many bytes a handler read.
type countingBody struct {
	r    io.Reader
	read int
}

func (c *countingBody) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.read += n
	return n, err
}

func (c *countingBody) Close() error { return nil }

// A body whose declared length is over the route's cap is refused with 413 before a byte is read.
func TestDeclaredOversizedBodyIsRefusedUnread(t *testing.T) {
	d, inv := inventoryDeps(t)
	inv.UploadCertificateFn = func(context.Context, inventory.Actor, inventory.UploadInput) (inventory.Certificate, []string, error) {
		t.Fatal("reached the service")
		return inventory.Certificate{}, nil, nil
	}
	h := NewHandler(d)
	for _, tc := range []struct {
		path string
		size int64
	}{
		{"/api/v1/certificates/upload", 768<<10 + 1},
		{"/api/v1/certificates/csr/" + csrID.String() + "/actions/complete", 384<<10 + 1},
		{"/api/v1/certificates/" + certID.String() + "/deploy", 8<<10 + 1},
		{"/api/v1/certificates/csr/" + csrID.String() + "/actions/cancel", 4<<10 + 1},
	} {
		body := &countingBody{r: strings.NewReader(`{"label":"` + strings.Repeat("A", int(tc.size)) + `"}`)}
		req := as(httptest.NewRequest(http.MethodPost, tc.path, nil), "admin")
		req.Body, req.ContentLength = body, tc.size
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusRequestEntityTooLarge, rec.Code, tc.path)
		assert.Zero(t, body.read, "%s: the body was read", tc.path)
	}
	// Unknown length (chunked): the read itself is bounded. A 5 KiB padded {} to cancel and an
	// oversized upload and completion are refused with 413 without reaching the service.
	for _, tc := range []struct{ path, body string }{
		{"/api/v1/certificates/csr/" + csrID.String() + "/actions/cancel", "{" + strings.Repeat(" ", 5<<10) + "}"},
		{"/api/v1/certificates/upload", `{"pfx_base64":"` + strings.Repeat("A", 768<<10) + `"}`},
		{"/api/v1/certificates/csr/" + csrID.String() + "/actions/complete", `{"certificate_pem":"` + strings.Repeat("A", 384<<10) + `"}`},
	} {
		req := as(httptest.NewRequest(http.MethodPost, tc.path, nil), "admin")
		req.Body, req.ContentLength = io.NopCloser(strings.NewReader(tc.body)), -1
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusRequestEntityTooLarge, rec.Code, "chunked %s", tc.path)
	}
}

// readBounded reads a body into one buffer: with a known length it allocates exactly once; with an
// unknown length it grows and clears every array it drops. Over the limit is errTooLarge.
func TestReadBoundedClearsWhatItDrops(t *testing.T) {
	body := strings.Repeat("s", 5000)
	buf, err := readBounded(io.NopCloser(strings.NewReader(body)), int64(len(body)), 8000)
	require.NoError(t, err)
	assert.Equal(t, body, string(buf))
	assert.Equal(t, len(body)+1, cap(buf), "one allocation for a known length")
	var dropped [][]byte
	buf, err = readBoundedObserved(io.NopCloser(strings.NewReader(body)), -1, 8000, func(old []byte) { dropped = append(dropped, old) })
	require.NoError(t, err)
	assert.Equal(t, body, string(buf))
	require.NotEmpty(t, dropped, "the buffer grew")
	for _, old := range dropped {
		assert.Equal(t, strings.Repeat("\x00", len(old)), string(old), "a dropped array was cleared")
	}
	_, err = readBounded(io.NopCloser(strings.NewReader(body)), -1, 4000)
	assert.ErrorIs(t, err, errTooLarge)
	_, err = readBounded(io.NopCloser(strings.NewReader(body)), 100, 8000)
	assert.Error(t, err, "longer than declared")
}

// The key scanner agrees with encoding/json on which top-level keys a body has, and never needs to
// allocate a value.
func TestTopLevelKeysAgreeWithEncodingJSON(t *testing.T) {
	for _, body := range []string{
		`{"label":"a\"b\\","pfx_base64":"x"}`,
		`{"label":"\"private_key_pem\":\"k\"","certificate_pem":"c"}`,
		`{"label":{"private_key_pem":"x","n":[1,{"a":"]"}]},"pfx_password":null}`,
		`{"label":-1.5e3,"pfx_base64":true,"pfx_password":false}`,
		`{"\u006cabel":"x"}`,
		` { "label" : "\u0022}" } `,
		"{\"label\":\"\xff\xfe\",\"pfx_base64\":\"x\"}",
		"{\"la\xffbel\":\"x\"}",
		`{}`,
	} {
		keys, ok := topLevelKeys([]byte(body))
		require.True(t, ok, body)
		var m map[string]json.RawMessage
		require.NoError(t, json.Unmarshal([]byte(body), &m), body)
		want := make([]string, 0, len(m))
		for k := range m {
			want = append(want, k)
		}
		assert.ElementsMatch(t, want, keys, body)
		b := []byte(body)
		assert.Zero(t, testing.AllocsPerRun(5, func() { skipJSONValue(b, skipSpace(b, 0), 0) }), "values are skipped without allocating")
	}
	for _, body := range []string{``, `[]`, `"x"`, `{"label":"x"`, `{"label":"x"} {}`, `{"label" "x"}`, `{"label":"x",}`,
		`{label:"x"}`, `{"label":"unterminated}`, `{"label":` + strings.Repeat("[", 100) + strings.Repeat("]", 100) + `}`} {
		_, ok := topLevelKeys([]byte(body))
		assert.False(t, ok, "%.40s", body)
	}
	keys, ok := topLevelKeys([]byte(`{"label":"a","label":"b"}`))
	require.True(t, ok)
	assert.Equal(t, []string{"label", "label"}, keys, "a repeated key is reported twice")
}

// Upload and completion bodies take their documented lower-case keys exactly once: another case or
// a repeated key is refused (encoding/json alone would accept both).
func TestSecretBodiesNeedExactUniqueKeys(t *testing.T) {
	d, inv := inventoryDeps(t)
	calls := 0
	inv.UploadCertificateFn = func(context.Context, inventory.Actor, inventory.UploadInput) (inventory.Certificate, []string, error) {
		calls++
		return sampleCertificate(), nil, nil
	}
	inv.CompleteCSRFn = func(context.Context, inventory.Actor, uuid.UUID, string, string) (inventory.Certificate, []string, error) {
		calls++
		return sampleCertificate(), nil, nil
	}
	h := NewHandler(d)
	complete := "/api/v1/certificates/csr/" + csrID.String() + "/actions/complete"
	for _, tc := range []struct{ path, body string }{
		{"/api/v1/certificates/upload", `{"Private_Key_PEM":"k","certificate_pem":"c"}`},
		{"/api/v1/certificates/upload", `{"private_key_pem":"k","private_key_pem":"k2","certificate_pem":"c"}`},
		{"/api/v1/certificates/upload", `{"LABEL":"x","pfx_base64":"AAAA"}`},
		{"/api/v1/certificates/upload", `["pfx_base64"]`},
		{complete, `{"Certificate_PEM":"c"}`},
		{complete, `{"certificate_pem":"c","label":"a","label":"b"}`},
	} {
		rec := call(h, http.MethodPost, tc.path, "admin", tc.body)
		assert.Equal(t, http.StatusBadRequest, rec.Code, tc.body)
	}
	assert.Zero(t, calls)
	require.Equal(t, http.StatusCreated, call(h, http.MethodPost, "/api/v1/certificates/upload", "admin", `{"label":"x","pfx_base64":"AAAA","pfx_password":"p"}`).Code)
	require.Equal(t, http.StatusCreated, call(h, http.MethodPost, complete, "admin", ` { "certificate_pem" : "c" } `).Code)
}

// The exact-key check runs while the keys are scanned: a body is refused at its first key that is
// not allowed or repeats, and a junk key without an escape is neither unescaped nor copied.
func TestExactKeysAreCheckedWhileScanning(t *testing.T) {
	allowed := []string{"certificate_pem", "label"}
	check := func(raw []byte, earlier []string) (string, bool) { return exactKey(raw, allowed, earlier) }
	for body, want := range map[string]bool{
		`{"label":"a","certificate_pem":"b"}`: true, `{"\u006cabel":"a"}`: true, `{}`: true,
		`{"Label":"a"}`: false, `{"label":"a","label":"b"}`: false, `{"x":1,"label":"a"}`: false, `{"lab\u0065l":1,"label":2}`: false,
	} {
		_, ok := scanKeys([]byte(body), check)
		assert.Equal(t, want, ok, body)
	}
	junk := []byte(`{"` + strings.Repeat("j", 4096) + `":1}`)
	assert.Zero(t, testing.AllocsPerRun(5, func() { scanKeys(junk, check) }), "a junk key is refused without a copy")
}

// FuzzTopLevelKeys compares the key scanner with encoding/json's own token walk (Task 17 ledger
// item): for every valid JSON object within the nesting bound, the scanner reports the same keys in
// the same order, repeats included. (The scanner may accept some invalid bodies; json.Unmarshal
// refuses those afterwards.)
func FuzzTopLevelKeys(f *testing.F) {
	for _, seed := range []string{`{"label":"a\"b\\","pfx_base64":"x"}`, `{"label":{"private_key_pem":"x","n":[1,{"a":"]"}]},"pfx_password":null}`,
		`{"label":"x"}`, ` { "label" : ""}" } `, "{\"la\xffbel\":\"x\"}", `{"label":"a","label":"b"}`, `{}`, `[]`, `{"a":1e5,"b":-0.5}`} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		want, ok := tokenKeys(b)
		if !ok {
			return
		}
		got, scanned := topLevelKeys(b)
		require.True(t, scanned, "%q", b)
		assert.Equal(t, want, got, "%q", b)
	})
}

// tokenKeys is the top-level keys of b by encoding/json's decoder, when b is exactly one valid
// object whose nesting stays within maxJSONDepth.
func tokenKeys(b []byte) ([]string, bool) {
	if !json.Valid(b) {
		return nil, false
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	keys := []string{}
	depth, deepest, isKey := 0, 0, false
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, false
		}
		d, delim := tok.(json.Delim)
		switch {
		case delim && (d == '{' || d == '['):
			if depth == 0 && d != '{' {
				return nil, false
			}
			depth++
			deepest = max(deepest, depth)
			isKey = depth == 1
		case delim:
			depth--
			isKey = depth == 1
		case depth == 0:
			return nil, false
		case depth == 1 && isKey:
			keys = append(keys, tok.(string))
			isKey = false
		case depth == 1:
			isKey = true
		}
	}
	return keys, deepest <= maxJSONDepth
}
