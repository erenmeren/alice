//go:build e2e

package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"alice/internal/api"
	"alice/internal/jobs"
	"alice/internal/license"
	"alice/internal/license/licensetest"
	"alice/internal/notify"
	"alice/internal/platform/clock"
	"alice/internal/platform/db"
)

// versionSuffix marks the e2e build in "alice version" and /api/v1/version.
const versionSuffix = "+e2e"

// maxTestBody is the request body limit of the API (SEC-023), applied to /test too.
const maxTestBody = 1 << 20

// maxClockMove bounds one POST /test/clock step (10 years of 365 days) in either direction.
const maxClockMove = 10 * 365 * 24 * time.Hour

// maxLicenseDays bounds the term of a test license (100 years).
const maxLicenseDays = 36500

// e2eClock is the server clock in the e2e build; POST /test/clock moves it.
var e2eClock = clock.NewOffset(clock.Real{})

func newClock() serverClock { return e2eClock }

// testMailbox keeps the emails of the e2e build instead of sending them (GET /test/mail).
type testMailbox struct {
	mu   sync.Mutex
	msgs []notify.Message
}

func (b *testMailbox) Send(_ context.Context, m notify.Message) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.msgs = append(b.msgs, m)
	return nil
}

func (b *testMailbox) all() []notify.Message {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]notify.Message(nil), b.msgs...)
}

func (b *testMailbox) reset() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.msgs = nil
}

var e2eMailbox = &testMailbox{}

// testMailer makes serve use the mailbox instead of SMTP.
var testMailer notify.Mailer = e2eMailbox

// resetSQL empties every application table. master_key_versions is kept because the master
// key file on the volume stays the same.
const resetSQL = `TRUNCATE users, user_mfa, recovery_codes, sessions, api_tokens, setup_sessions, settings, audit_log,
license, license_files, license_history, notifications_outbox`

// decodeTest reads a JSON body strictly; an empty body is an empty object.
func decodeTest(w http.ResponseWriter, r *http.Request, dst any) bool {
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxTestBody))
	if err != nil {
		writeTestJSON(w, http.StatusRequestEntityTooLarge, map[string]string{"error": "request body too large"})
		return false
	}
	if len(bytes.TrimSpace(raw)) == 0 {
		return true
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		writeTestJSON(w, http.StatusBadRequest, map[string]string{"error": "body must be a JSON object with the documented fields"})
		return false
	}
	return true
}

// afterClockChange runs the license evaluation and the email sender at once, so the effects
// of a demo-clock move are visible immediately instead of at the next hourly tick.
func afterClockChange(ctx context.Context, d testDeps) {
	if d.Scheduler == nil {
		return
	}
	for _, task := range []string{jobs.LicenseEvaluate.Name, jobs.NotifySend.Name} {
		if err := d.Scheduler.RunNow(ctx, task); err != nil && !errors.Is(err, license.ErrLocked) {
			d.Log.Error("test clock: task failed", "job_type", task, "error_type", fmt.Sprintf("%T", err))
		}
	}
}

// testHandler serves the test-only endpoints of the e2e build (never shipped).
func testHandler(d testDeps) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /test/clock", func(w http.ResponseWriter, _ *http.Request) {
		writeTestJSON(w, http.StatusOK, map[string]string{"now": e2eClock.Now().Format(time.RFC3339Nano)})
	})
	mux.HandleFunc("POST /test/clock", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			AdvanceSeconds float64 `json:"advance_seconds"`
			WallOnly       bool    `json:"wall_only"`
		}
		if !decodeTest(w, r, &body) {
			return
		}
		if body.AdvanceSeconds < -maxClockMove.Seconds() || body.AdvanceSeconds > maxClockMove.Seconds() {
			writeTestJSON(w, http.StatusUnprocessableEntity, map[string]string{"error": "advance_seconds must be between -315360000 and 315360000 (10 years)"})
			return
		}
		step := time.Duration(body.AdvanceSeconds * float64(time.Second))
		if body.WallOnly {
			e2eClock.JumpWall(step)
		} else {
			e2eClock.Advance(step)
		}
		afterClockChange(r.Context(), d)
		writeTestJSON(w, http.StatusOK, map[string]string{"now": e2eClock.Now().Format(time.RFC3339Nano)})
	})
	mux.HandleFunc("POST /test/license", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			InstallationID string  `json:"installation_id"`
			LicenseID      string  `json:"license_id"`
			Customer       string  `json:"customer"`
			MaxTargets     int     `json:"max_targets"`
			ValidFrom      string  `json:"valid_from"`
			ValidDays      float64 `json:"valid_days"`
			Replaces       string  `json:"replaces"`
		}
		body.MaxTargets, body.ValidDays = 10, 365
		if !decodeTest(w, r, &body) {
			return
		}
		if !(body.ValidDays > 0 && body.ValidDays <= maxLicenseDays) {
			writeTestJSON(w, http.StatusUnprocessableEntity, map[string]string{"error": "valid_days must be between 0 and 36500"})
			return
		}
		installation := body.InstallationID
		if installation == "" {
			if d.License == nil {
				writeTestJSON(w, http.StatusConflict, map[string]string{"error": "no installation: give installation_id"})
				return
			}
			installation = d.License.Snapshot().InstallationID
		}
		from := e2eClock.Now().UTC().Truncate(time.Second)
		if body.ValidFrom != "" {
			t, err := time.Parse(time.RFC3339, body.ValidFrom)
			if err != nil {
				writeTestJSON(w, http.StatusUnprocessableEntity, map[string]string{"error": "valid_from must be RFC 3339"})
				return
			}
			from = t.UTC()
		}
		p := licensetest.Payload(installation, from, from.Add(time.Duration(body.ValidDays*24*float64(time.Hour))), body.MaxTargets)
		p.LicenseID = "LIC-E2E-" + rand.Text()[:10]
		if body.LicenseID != "" {
			p.LicenseID = body.LicenseID
		}
		if body.Customer != "" {
			p.Customer = body.Customer
		}
		p.Replaces = body.Replaces
		if err := p.Validate(); err != nil {
			writeTestJSON(w, http.StatusUnprocessableEntity, map[string]string{"error": err.Error()})
			return
		}
		writeTestJSON(w, http.StatusOK, map[string]string{"license": string(licensetest.Sign(p)), "license_id": p.LicenseID})
	})
	mux.HandleFunc("GET /test/mail", func(w http.ResponseWriter, _ *http.Request) {
		type message struct {
			To      string `json:"to"`
			Subject string `json:"subject"`
			Body    string `json:"body"`
		}
		out := []message{}
		for _, m := range e2eMailbox.all() {
			out = append(out, message{To: m.To, Subject: m.Subject, Body: m.Body})
		}
		writeTestJSON(w, http.StatusOK, map[string]any{"messages": out})
	})
	mux.HandleFunc("POST /test/reset", func(w http.ResponseWriter, r *http.Request) {
		reset := func(ctx context.Context) error {
			if err := resetInstall(ctx, d.OwnerURL); err != nil {
				return err
			}
			if d.StateDir != "" {
				if err := os.Remove(filepath.Join(d.StateDir, license.HWMFileName)); err != nil && !errors.Is(err, os.ErrNotExist) {
					return fmt.Errorf("remove the time record: %w", err)
				}
			}
			e2eClock.Reset()
			e2eMailbox.reset()
			d.Setup.ResetLockouts()
			d.ResetLimits()
			return nil
		}
		// The license service runs the reset while no evaluation is in flight (an in-flight
		// Tick could write the old time record back) and starts again on the emptied tables:
		// a fresh installation row, time record and evaluation.
		var err error
		if d.License != nil {
			err = d.License.Restart(r.Context(), reset)
		} else {
			err = reset(r.Context())
		}
		if err != nil {
			d.Log.Error("test reset failed", "error", err.Error())
			writeTestJSON(w, http.StatusInternalServerError, map[string]string{"error": "reset failed"})
			return
		}
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
	// The endpoints change server state, so a cross-site page must not reach them
	// through a visitor's browser: unsafe methods get the API guard's same-origin check.
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead && !api.SameOrigin(r) {
			writeTestJSON(w, http.StatusForbidden, map[string]string{"error": "cross-site request refused"})
			return
		}
		mux.ServeHTTP(w, r)
	})
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
