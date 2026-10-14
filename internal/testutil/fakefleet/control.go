package fakefleet

import (
	"context"
	"encoding/json"
	"net/http"
	"time"
)

// ControlHandler is the fleet's control API (cmd/alice-fakefleet serves it on loopback only):
//
//	GET  /ping        {"ok":true}
//	GET  /fleet       Info: every server's kind, address, name and default chain fingerprints
//	GET  /ca          the root certificate (PEM)
//	GET  /log         the access log ([]Access); ?settle=1 waits for WaitIdle first (at most 10 s)
//	POST /log/clear   ClearLog
//	GET  /counters    Counters
func (f *Fleet) ControlHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /ping", func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, map[string]bool{"ok": true}) })
	mux.HandleFunc("GET /fleet", func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, f.Info()) })
	mux.HandleFunc("GET /ca", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/x-pem-file")
		_, _ = w.Write(f.RootPEM())
	})
	mux.HandleFunc("GET /log", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("settle") == "1" {
			ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
			err := f.WaitIdle(ctx)
			cancel()
			if err != nil {
				w.WriteHeader(http.StatusServiceUnavailable)
				writeJSON(w, map[string]string{"error": "the fleet did not settle: " + err.Error()})
				return
			}
		}
		writeJSON(w, f.Log())
	})
	mux.HandleFunc("POST /log/clear", func(w http.ResponseWriter, _ *http.Request) {
		f.ClearLog()
		writeJSON(w, map[string]bool{"ok": true})
	})
	mux.HandleFunc("GET /counters", func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, f.Counters()) })
	return mux
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
