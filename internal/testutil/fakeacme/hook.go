package fakeacme

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
)

const maxHookBody = 4 << 10

// normFQDN lowercases a name and drops the trailing dot.
func normFQDN(n string) string { return strings.TrimSuffix(asciiLower(strings.TrimSpace(n)), ".") }

type hookRequest struct {
	Action string `json:"action"`
	FQDN   string `json:"fqdn"`
	Value  string `json:"value"`
	TTL    int    `json:"ttl"`
}

// handleHook is the authenticated DNS hook (see the package comment for the contract).
func (s *Server) handleHook(w http.ResponseWriter, r *http.Request, _ *jwsReq) {
	hookErr := func(status int, msg string) { writeJSON(w, status, map[string]any{"ok": false, "error": msg}) }
	if r.Method != http.MethodPost {
		hookErr(http.StatusMethodNotAllowed, "POST only")
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxHookBody))
	var tooBig *http.MaxBytesError
	if errors.As(err, &tooBig) {
		hookErr(http.StatusRequestEntityTooLarge, "the body is over 4 KiB")
		return
	}
	if err != nil {
		hookErr(http.StatusBadRequest, "the body could not be read")
		return
	}
	token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || subtle.ConstantTimeCompare([]byte(token), []byte(s.opts.HookSecret)) != 1 {
		hookErr(http.StatusUnauthorized, "missing or wrong bearer token")
		return
	}
	sig, err := hex.DecodeString(strings.TrimPrefix(r.Header.Get("X-Alice-Signature"), "sha256="))
	m := hmac.New(sha256.New, []byte(s.opts.HookSecret))
	m.Write(body)
	if err != nil || !hmac.Equal(m.Sum(nil), sig) {
		hookErr(http.StatusUnauthorized, "missing or wrong signature")
		return
	}
	var hr hookRequest
	if err := json.Unmarshal(body, &hr); err != nil {
		hookErr(http.StatusBadRequest, "the body is not the hook JSON")
		return
	}
	fqdn := normFQDN(hr.FQDN)
	if fqdn == "" || len(fqdn) > 253 || hr.TTL < 0 || hr.TTL > 86400 {
		hookErr(http.StatusBadRequest, "fqdn is empty or ttl is out of range")
		return
	}
	switch hr.Action {
	case "present":
		if hr.Value == "" || len(hr.Value) > 512 {
			hookErr(http.StatusBadRequest, "value is required")
			return
		}
		s.DNSSet(fqdn, hr.Value)
		s.count("hook-present")
	case "cleanup":
		s.DNSClear(fqdn, hr.Value)
		s.count("hook-cleanup")
	default:
		hookErr(http.StatusBadRequest, "action must be present or cleanup")
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}
