package api

import (
	"encoding/json"
	"net/http"
)

// ErrorCode is a stable, documented API error. Codes are never reused.
type ErrorCode struct {
	Code      string
	Reason    string
	Status    int
	Retryable bool
}

var (
	ErrNotFound    = ErrorCode{Code: "ALC-SYS-0001", Reason: "system.not_found", Status: http.StatusNotFound}
	ErrUnavailable = ErrorCode{Code: "ALC-SYS-0002", Reason: "system.unavailable", Status: http.StatusServiceUnavailable, Retryable: true}
	ErrUnexpected  = ErrorCode{Code: "ALC-SYS-0003", Reason: "internal.unexpected", Status: http.StatusInternalServerError}
)

// AllErrorCodes lists every registered code; tests check format, uniqueness and translations.
func AllErrorCodes() []ErrorCode {
	return []ErrorCode{ErrNotFound, ErrUnavailable, ErrUnexpected}
}

type errorPayload struct {
	Code       string `json:"code"`
	Reason     string `json:"reason"`
	MessageKey string `json:"message_key"`
	Message    string `json:"message"`
	RequestID  string `json:"request_id"`
	Retryable  bool   `json:"retryable"`
}

func (s *server) writeError(w http.ResponseWriter, r *http.Request, ec ErrorCode) {
	lang := s.deps.Catalog.Negotiate(r.Header.Get("Accept-Language"))
	key := "errors." + ec.Reason
	msg := s.deps.Catalog.T(lang, key+".title", nil) + " " + s.deps.Catalog.T(lang, key+".action", nil)
	writeJSON(w, ec.Status, map[string]errorPayload{"error": {
		Code:       ec.Code,
		Reason:     ec.Reason,
		MessageKey: key,
		Message:    msg,
		RequestID:  RequestID(r.Context()),
		Retryable:  ec.Retryable,
	}})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
