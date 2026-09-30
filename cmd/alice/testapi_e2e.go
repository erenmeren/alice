//go:build e2e

package main

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"alice/internal/platform/clock"
	"alice/internal/platform/db"
)

// e2eClock is the server clock in the e2e build; POST /test/clock moves it.
var e2eClock = clock.NewOffset(clock.Real{})

func newClock() clock.Clock { return e2eClock }

// resetTables are emptied by POST /test/reset. master_key_versions is kept
// because the master key file on the volume stays the same.
const resetSQL = `TRUNCATE users, user_mfa, recovery_codes, sessions, api_tokens, setup_sessions, settings, audit_log`

// testHandler serves the test-only endpoints of the e2e build (never shipped).
func testHandler(d testDeps) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /test/clock", func(w http.ResponseWriter, _ *http.Request) {
		writeTestJSON(w, http.StatusOK, map[string]string{"now": e2eClock.Now().Format(time.RFC3339Nano)})
	})
	mux.HandleFunc("POST /test/clock", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			AdvanceSeconds float64 `json:"advance_seconds"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.AdvanceSeconds < 0 {
			writeTestJSON(w, http.StatusBadRequest, map[string]string{"error": "advance_seconds must be a number >= 0"})
			return
		}
		e2eClock.Advance(time.Duration(body.AdvanceSeconds * float64(time.Second)))
		writeTestJSON(w, http.StatusOK, map[string]string{"now": e2eClock.Now().Format(time.RFC3339Nano)})
	})
	mux.HandleFunc("POST /test/reset", func(w http.ResponseWriter, r *http.Request) {
		if err := resetInstall(r.Context(), d.OwnerURL); err != nil {
			d.Log.Error("test reset failed", "error", err.Error())
			writeTestJSON(w, http.StatusInternalServerError, map[string]string{"error": "reset failed"})
			return
		}
		e2eClock.Reset()
		d.Setup.ResetLockouts()
		d.ResetLimits()
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("POST /test/setup-token", func(w http.ResponseWriter, r *http.Request) {
		code, err := d.Setup.ResetToken(r.Context())
		if err != nil {
			writeTestJSON(w, http.StatusConflict, map[string]string{"error": err.Error()})
			return
		}
		writeTestJSON(w, http.StatusOK, map[string]string{"code": code})
	})
	mux.HandleFunc("/test/", func(w http.ResponseWriter, _ *http.Request) {
		writeTestJSON(w, http.StatusNotFound, map[string]string{"error": "unknown test endpoint"})
	})
	return mux
}

// resetInstall empties every application table as the owner role. The audit
// triggers forbid TRUNCATE, so they are disabled inside the transaction only.
func resetInstall(ctx context.Context, ownerURL string) error {
	pool, err := pgxpool.New(ctx, ownerURL)
	if err != nil {
		return err
	}
	defer pool.Close()
	return db.InTx(ctx, pool, func(tx pgx.Tx) error {
		for _, stmt := range []string{
			`ALTER TABLE audit_log DISABLE TRIGGER USER`,
			resetSQL,
			`ALTER TABLE audit_log ENABLE TRIGGER USER`,
		} {
			if _, err := tx.Exec(ctx, stmt); err != nil {
				return err
			}
		}
		return nil
	})
}

func writeTestJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
