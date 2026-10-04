package license

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// Limits of the file format (spec §16.2, §16.3).
const (
	MaxFileSize     = 64 << 10
	FormatVersion   = 1
	MaxTargetsLimit = 100000

	signingPrefix = "ALICE-LICENSE-v1\n"
	maxDepth      = 3 // file object > payload object > features array
	// maxNewerDepth bounds the nesting of a file in a newer format, which this version reads
	// only far enough to verify its signature (AUD-19).
	maxNewerDepth    = maxCanonicalDepth
	maxCustomerRunes = 200
	maxFeatures      = 32
)

var (
	keyIDPattern   = regexp.MustCompile(`^vk-[a-z0-9]{1,8}(-[a-z0-9]{1,8}){0,3}$`)
	idPattern      = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
	featurePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
	earliestDate   = time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
	latestDate     = time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC)

	// Exact key sets. encoding/json matches field names case-insensitively (with Unicode
	// folding), so the structure walk compares bytes against these instead.
	fileKeys    = map[string]bool{"format": true, "key_id": true, "payload": true, "signature": true}
	payloadKeys = map[string]bool{
		"license_id": true, "customer": true, "installation_id": true, "issued_at": true, "valid_from": true,
		"valid_until": true, "max_targets": true, "features": true, "format": true, "replaces": true,
	}
	byteOrderMark = []byte{0xEF, 0xBB, 0xBF}
)

// Payload is the signed content of a license file (spec §16.2).
type Payload struct {
	LicenseID      string
	Customer       string
	InstallationID string
	IssuedAt       time.Time
	ValidFrom      time.Time
	ValidUntil     time.Time
	MaxTargets     int
	Features       []string
	Format         int
	Replaces       string // license ID that a correction license supersedes (R7); "" = none
}

// File is a parsed license file. Nothing in it is trusted before Verify.
type File struct {
	Format    int
	KeyID     string
	Payload   Payload
	Signature []byte
}

// SignedBytes are the bytes the vendor signs: a domain separator and the canonical payload.
func SignedBytes(p Payload) []byte {
	return append([]byte(signingPrefix), CanonicalPayload(p)...)
}

// SignedBytesFor are the signed bytes of a payload object of any format, given as JSON: the
// domain separator and its RFC 8785 form, unknown members included (spec §16.2). For a format 1
// payload they equal SignedBytes. Every format keeps this envelope (format, key_id, payload,
// signature) and this signature, so a build can tell a genuine license in a newer format from a
// forged or damaged file (AUD-19).
func SignedBytesFor(payload []byte) ([]byte, error) {
	canon, err := CanonicalJSON(payload)
	if err != nil {
		return nil, err
	}
	return append([]byte(signingPrefix), canon...), nil
}

// Sign validates p and signs it with priv (used by licensectl and test signers).
func Sign(priv ed25519.PrivateKey, keyID string, p Payload) (File, error) {
	if !keyIDPattern.MatchString(keyID) {
		return File{}, invalid("key_id")
	}
	p.IssuedAt, p.ValidFrom, p.ValidUntil = wholeSecondsUTC(p.IssuedAt), wholeSecondsUTC(p.ValidFrom), wholeSecondsUTC(p.ValidUntil)
	if err := p.Validate(); err != nil {
		return File{}, err
	}
	return File{Format: p.Format, KeyID: keyID, Payload: p, Signature: ed25519.Sign(priv, SignedBytes(p))}, nil
}

// wholeSecondsUTC is the instant as the file format stores it.
func wholeSecondsUTC(t time.Time) time.Time { return t.UTC().Truncate(time.Second) }

// EncodeFile renders f as the pretty-printed UTF-8 JSON file sent to customers.
func EncodeFile(f File) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	err := enc.Encode(struct {
		Format    int             `json:"format"`
		KeyID     string          `json:"key_id"`
		Payload   json.RawMessage `json:"payload"`
		Signature string          `json:"signature"`
	}{f.Format, f.KeyID, CanonicalPayload(f.Payload), base64.RawURLEncoding.EncodeToString(f.Signature)})
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

type wireFile struct {
	Format    *int64          `json:"format"`
	KeyID     *string         `json:"key_id"`
	Payload   json.RawMessage `json:"payload"`
	Signature *string         `json:"signature"`
}

type wirePayload struct {
	LicenseID      *string         `json:"license_id"`
	Customer       *string         `json:"customer"`
	InstallationID *string         `json:"installation_id"`
	IssuedAt       *string         `json:"issued_at"`
	ValidFrom      *string         `json:"valid_from"`
	ValidUntil     *string         `json:"valid_until"`
	MaxTargets     *int64          `json:"max_targets"`
	Features       *[]string       `json:"features"`
	Format         *int64          `json:"format"`
	Replaces       json.RawMessage `json:"replaces"`
}

// ProblemNewerFormat is the InvalidError problem of a file whose outer format is newer than
// FormatVersion. ParseFile cannot tell a
// genuine newer license from a forged one, so it reports the file as invalid; Check verifies the
// signature and only then answers ErrUnsupportedFormat (AUD-19).
const ProblemNewerFormat = "newer_format"

// ParseFile parses a license file of the current format strictly (spec §16.3 step 1): at most
// 64 KiB, UTF-8 (a leading byte-order mark is ignored), exactly one JSON object, no duplicate
// keys, no unknown fields, integers as JSON integers, timestamps as RFC 3339 UTC with "Z" and
// whole seconds. A file whose outer format is newer is an *InvalidError with Problem
// "newer_format": nothing in it is verified yet (Check does that). The payload is not validated
// here: callers verify the signature first, then call Payload.Validate.
func ParseFile(raw []byte) (File, error) {
	raw, outer, err := readEnvelope(raw)
	if err != nil {
		return File{}, err
	}
	if outer > FormatVersion {
		return File{}, invalid(ProblemNewerFormat)
	}
	if outer != FormatVersion {
		return File{}, invalid("format")
	}
	// The current format knows every field: an unknown one is refused (spec §16.2), also when
	// the signature would cover it.
	if err := checkStructure(raw, true); err != nil {
		return File{}, err
	}

	var w wireFile
	if err := strictDecode(raw, &w); err != nil {
		return File{}, invalid("fields")
	}
	if w.Format == nil || w.KeyID == nil || w.Signature == nil {
		return File{}, invalid("fields")
	}
	if !keyIDPattern.MatchString(*w.KeyID) {
		return File{}, invalid("key_id")
	}
	var wp wirePayload
	if len(w.Payload) == 0 {
		return File{}, invalid("missing_field")
	}
	if err := strictDecode(w.Payload, &wp); err != nil {
		return File{}, invalid("fields")
	}
	p, err := wp.payload()
	if err != nil {
		return File{}, err
	}
	if int64(p.Format) != outer {
		return File{}, invalid("format")
	}
	sig, err := decodeSignature(*w.Signature)
	if err != nil {
		return File{}, err
	}
	return File{Format: int(outer), KeyID: *w.KeyID, Payload: p, Signature: sig}, nil
}

// readEnvelope runs the checks every format shares and reads the outer format: size, encoding,
// one JSON object, no duplicate keys at any level, bounded nesting, an integer "format". It
// returns raw without its byte-order mark.
func readEnvelope(raw []byte) ([]byte, int64, error) {
	if len(raw) == 0 {
		return nil, 0, invalid("empty")
	}
	if len(raw) > MaxFileSize {
		return nil, 0, invalid("too_large")
	}
	raw = bytes.TrimPrefix(raw, byteOrderMark)
	if !utf8.Valid(raw) {
		return nil, 0, invalid("encoding")
	}
	if err := checkStructure(raw, false); err != nil {
		return nil, 0, err
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(raw, &top); err != nil {
		return nil, 0, invalid("not_json")
	}
	var outer int64
	if err := json.Unmarshal(top["format"], &outer); err != nil {
		return nil, 0, invalid("format")
	}
	return raw, outer, nil
}

// checkNewer answers a file whose outer format is newer than FormatVersion. The signature is
// verified over the canonical payload first; only a file genuinely signed by a trusted key gets
// ErrUnsupportedFormat ("update Alice", L-45). Everything else gets the error a file of the
// current format would get: ErrUnknownKey, an *InvalidError (a forged or damaged file, whatever
// fields it carries), or ErrRevokedKey.
func checkNewer(raw []byte, keys KeySet) error {
	raw, outer, err := readEnvelope(raw)
	if err != nil {
		return err
	}
	// The envelope every format keeps, read by exact key (encoding/json would match struct
	// fields case-insensitively). The payload is only canonicalized, never interpreted, except
	// "format" (bound to the outer format, spec §16.2) and "issued_at" (a revoked key's cut-off).
	var top map[string]json.RawMessage
	var keyID, signature string
	if json.Unmarshal(raw, &top) != nil || json.Unmarshal(top["key_id"], &keyID) != nil ||
		json.Unmarshal(top["signature"], &signature) != nil || len(top["payload"]) == 0 {
		return invalid("fields")
	}
	if !keyIDPattern.MatchString(keyID) {
		return invalid("key_id")
	}
	sig, err := decodeSignature(signature)
	if err != nil {
		return err
	}
	pk, ok := keys.keys[keyID]
	if !ok || len(pk.Key) != ed25519.PublicKeySize {
		return ErrUnknownKey
	}
	signed, err := SignedBytesFor(top["payload"])
	if err != nil || !ed25519.Verify(pk.Key, signed, sig) {
		return invalid("signature")
	}
	// Signed from here on. The inner format must be the outer one, so a genuine older file
	// relabelled outside its signature is not reported as newer.
	var inner map[string]json.RawMessage
	var format int64
	if json.Unmarshal(top["payload"], &inner) != nil || json.Unmarshal(inner["format"], &format) != nil || format != outer {
		return invalid("format")
	}
	if pk.Status == KeyRevoked {
		// Trusted only when issued before the key's cut-off; an issued_at this version cannot
		// read is not.
		var at string
		_ = json.Unmarshal(inner["issued_at"], &at) // not a string: at stays "", which does not parse
		issued, err := time.Parse(time.RFC3339, at)
		if pk.RevokedFrom.IsZero() || err != nil || !issued.Before(pk.RevokedFrom) {
			return ErrRevokedKey
		}
	}
	return ErrUnsupportedFormat
}

// decodeSignature reads the base64url signature (padding accepted) of 64 bytes.
func decodeSignature(s string) ([]byte, error) {
	sig, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		sig, err = base64.URLEncoding.DecodeString(s)
	}
	if err != nil || len(sig) != ed25519.SignatureSize {
		return nil, invalid("signature_encoding")
	}
	return sig, nil
}

func (w wirePayload) payload() (Payload, error) {
	if w.LicenseID == nil || w.Customer == nil || w.InstallationID == nil || w.IssuedAt == nil ||
		w.ValidFrom == nil || w.ValidUntil == nil || w.MaxTargets == nil || w.Features == nil || w.Format == nil {
		return Payload{}, invalid("missing_field")
	}
	var times [3]time.Time
	for i, s := range []string{*w.IssuedAt, *w.ValidFrom, *w.ValidUntil} {
		t, err := time.Parse(time.RFC3339, s)
		if err != nil || formatTime(t) != s {
			return Payload{}, invalid("timestamp")
		}
		times[i] = t.UTC()
	}
	if *w.MaxTargets < 0 || *w.MaxTargets > MaxTargetsLimit {
		return Payload{}, invalid("max_targets")
	}
	if *w.Format < 0 || *w.Format > 1000 {
		return Payload{}, invalid("format")
	}
	p := Payload{
		LicenseID:      *w.LicenseID,
		Customer:       *w.Customer,
		InstallationID: *w.InstallationID,
		IssuedAt:       times[0],
		ValidFrom:      times[1],
		ValidUntil:     times[2],
		MaxTargets:     int(*w.MaxTargets),
		Features:       append([]string{}, (*w.Features)...),
		Format:         int(*w.Format),
	}
	if w.Replaces != nil {
		// The canonical form omits an empty or null value, so writing one would be unsigned.
		var s string
		if string(w.Replaces) == "null" || json.Unmarshal(w.Replaces, &s) != nil || s == "" {
			return Payload{}, invalid("replaces")
		}
		p.Replaces = s
	}
	return p, nil
}

func strictDecode(data []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

// frame is one open JSON object or array during checkStructure.
type frame struct {
	keys    map[string]bool // nil for arrays
	allowed map[string]bool // exact key names accepted at this level
	wantKey bool
}

// checkStructure walks the tokens once: exactly one JSON value and no object with the same key
// twice (encoding/json keeps the last one silently, which would let a file show one value and
// sign another). strict is the current format: only its keys, nesting at most maxDepth. Without
// strict (reading the format, or a newer format), any key and nesting up to maxNewerDepth.
func checkStructure(raw []byte, strict bool) error {
	depth := maxNewerDepth
	if strict {
		depth = maxDepth
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var stack []*frame
	values := 0
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return invalid("not_json")
		}
		if n := len(stack); n > 0 && stack[n-1].keys != nil && stack[n-1].wantKey {
			if tok == json.Delim('}') {
				stack = stack[:n-1]
				values = closeValue(stack, values)
				continue
			}
			key, _ := tok.(string)
			if stack[n-1].keys[key] {
				return invalid("duplicate_key")
			}
			if strict && !stack[n-1].allowed[key] {
				return invalid("fields")
			}
			stack[n-1].keys[key] = true
			stack[n-1].wantKey = false
			continue
		}
		switch tok {
		case json.Delim('{'), json.Delim('['):
			if len(stack) == depth {
				return invalid("too_deep")
			}
			f := &frame{}
			if tok == json.Delim('{') {
				f.keys, f.wantKey = map[string]bool{}, true
				f.allowed = fileKeys
				if len(stack) > 0 {
					f.allowed = payloadKeys
				}
			}
			stack = append(stack, f)
		case json.Delim(']'):
			stack = stack[:len(stack)-1]
			values = closeValue(stack, values)
		default:
			values = closeValue(stack, values)
		}
	}
	if values != 1 || len(stack) != 0 {
		return invalid("not_json")
	}
	return nil
}

// closeValue records that a complete value ended: inside an object the next token is
// a key; at the top level one more document was read.
func closeValue(stack []*frame, values int) int {
	if n := len(stack); n > 0 {
		if stack[n-1].keys != nil {
			stack[n-1].wantKey = true
		}
		return values
	}
	return values + 1
}

// Validate checks the payload rules of spec §16.3 step 5 plus field syntax. It returns
// an *InvalidError naming the first problem.
func (p Payload) Validate() error {
	switch {
	case p.Format != FormatVersion:
		return invalid("format")
	case !idPattern.MatchString(p.LicenseID):
		return invalid("license_id")
	case p.Replaces != "" && (!idPattern.MatchString(p.Replaces) || p.Replaces == p.LicenseID):
		return invalid("replaces")
	case !validCustomer(p.Customer):
		return invalid("customer")
	case p.MaxTargets < 1 || p.MaxTargets > MaxTargetsLimit:
		return invalid("max_targets")
	case p.IssuedAt.Before(earliestDate) || p.ValidFrom.Before(earliestDate) || p.ValidUntil.Before(earliestDate) ||
		p.IssuedAt.After(latestDate) || p.ValidFrom.After(latestDate) || p.ValidUntil.After(latestDate):
		return invalid("dates")
	case p.ValidUntil.Before(p.ValidFrom):
		return invalid("validity")
	case p.IssuedAt.After(p.ValidFrom.Add(24 * time.Hour)):
		return invalid("issued_at")
	case len(p.Features) > maxFeatures:
		return invalid("features")
	}
	for _, f := range p.Features {
		if !featurePattern.MatchString(f) {
			return invalid("features")
		}
	}
	if id, err := ParseInstallationID(p.InstallationID); err != nil || id != p.InstallationID {
		return invalid("installation_id")
	}
	return nil
}

func validCustomer(s string) bool {
	if s == "" || !utf8.ValidString(s) || strings.TrimSpace(s) != s || utf8.RuneCountInString(s) > maxCustomerRunes {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return false
		}
	}
	return true
}
