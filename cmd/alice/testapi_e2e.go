//go:build e2e

package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"alice/internal/api"
	"alice/internal/jobs"
	"alice/internal/license"
	"alice/internal/license/licensetest"
	"alice/internal/notify"
	"alice/internal/platform/clock"
	"alice/internal/platform/db"
	"alice/internal/platform/tlscert"
	"alice/internal/testutil/seed"
)

// versionSuffix marks the e2e build in "alice version" and /api/v1/version.
const versionSuffix = "+e2e"

// startJobWorkers is false in the e2e build: serve does not run the job workers, so a queued job
// stays queued until a test runs it with POST /test/jobs/drain (the scheduler still enqueues
// periodic work). The journeys then see every job state deterministically instead of racing a
// background worker.
const startJobWorkers = false

// sweepEvery is the deployment recovery sweep's interval in the e2e build: in effect never. The
// demo clock is an offset of the wall clock, so a sweep ticking every real minute would requeue
// recoveries, count attempts and end deployments between two Playwright steps; tests run it with
// POST /test/scheduler/run instead. The task stays scheduled (checkWiring, RunNow).
const sweepEvery = 100 * 365 * 24 * time.Hour

// kvScheduleEvery and kvAutoDeployEvery are the intervals of the Key Vault poll scheduler and the
// automatic deployment planner in the e2e build: in effect never, like the sweep (the demo clock
// would otherwise poll and deploy between two Playwright steps). The tasks stay scheduled
// (checkWiring, RunNow): tests run them with POST /test/scheduler/run.
const (
	kvScheduleEvery   = 100 * 365 * 24 * time.Hour
	kvAutoDeployEvery = 100 * 365 * 24 * time.Hour
)

// acmeSweepEvery is the ACME sweep's interval in the e2e build: in effect never, like the deployment sweep (the demo
// clock would otherwise abandon orders and queue cleanups between two Playwright steps). The task stays scheduled
// (checkWiring, RunNow): the journeys run it with POST /test/scheduler/run.
const acmeSweepEvery = 100 * 365 * 24 * time.Hour

// acmeScheduleEvery is the ACME renewal planner's interval in the e2e build: in effect never, like the Key Vault
// planners (the demo clock would otherwise order renewals between two Playwright steps). The task stays scheduled
// (checkWiring, RunNow): the journeys move the demo clock (POST /test/clock) and run it with POST /test/scheduler/run
// {"task": "acme.schedule"}.
const acmeScheduleEvery = 100 * 365 * 24 * time.Hour

// acmeAutoDeployEvery is the ACME automatic deployment planner's interval in the e2e build: in effect never, like the
// Key Vault planner (the demo clock would otherwise deploy between two Playwright steps). The task stays scheduled
// (checkWiring, RunNow): the journeys run it with POST /test/scheduler/run {"task": "acme.auto_deploy"}.
const acmeAutoDeployEvery = 100 * 365 * 24 * time.Hour

// netdiscoScheduleEvery and netdiscoRetentionEvery are the intervals of the network discovery schedule and retention
// in the e2e build: in effect never, like the ACME planners (the demo clock would otherwise queue scans or remove rows
// between two Playwright steps). The tasks stay scheduled (checkWiring, RunNow): the journeys start scans by hand and
// run netdisco.schedule and netdisco.retention with POST /test/scheduler/run.
const (
	netdiscoScheduleEvery  = 100 * 365 * 24 * time.Hour
	netdiscoRetentionEvery = 100 * 365 * 24 * time.Hour
)

// rotationPlanEvery, rotationSweepEvery and destroyRetiredEvery are the intervals of the SSH key
// rotation tasks in the e2e build: in effect never, like the sweep (the demo clock would otherwise
// plan, advance or finish a run between two Playwright steps). The tasks stay scheduled (checkWiring,
// RunNow): the journeys run them with POST /test/scheduler/run.
const (
	rotationPlanEvery   = 100 * 365 * 24 * time.Hour
	rotationSweepEvery  = 100 * 365 * 24 * time.Hour
	destroyRetiredEvery = 100 * 365 * 24 * time.Hour
)

// alertsScanEvery is the expiry scan's interval in the e2e build: in effect never. The demo clock would otherwise send
// expiry notices between two Playwright steps; the journeys run alerts.scan with POST /test/scheduler/run.
const alertsScanEvery = 100 * 365 * 24 * time.Hour

// backupScheduleEvery is the daily backup check's interval in the e2e build: in effect never. The demo clock would
// otherwise make automatic backups between two Playwright steps; the journeys run backup.schedule with POST
// /test/scheduler/run.
const backupScheduleEvery = 100 * 365 * 24 * time.Hour

// azureCAFile is where the fake Azure service (cmd/alice-fakeazure, compose service fakeazure) writes
// its CA; compose shares the volume read-only with alice (R40 row 35). A variable only so the unit
// tests can point it at a file of their own.
var azureCAFile = "/run/alice-e2e-azure/ca.pem"

// maxAzureCAFile bounds what azureRoots accepts (a PEM root is about 1 KB); a longer file is refused,
// never truncated.
const maxAzureCAFile = 64 << 10

// azureRoots is the trust of Azure's TLS certificates in the e2e build: ONLY the fake's CA, never
// the system roots (ruling S10: a real Azure certificate is not trusted here, and no host name of
// the e2e stack is trusted by a release build). The file must be one regular file (a symlink, even
// to the system bundle, is refused), at most maxAzureCAFile bytes, holding exactly one CERTIFICATE
// block and nothing else, and that certificate must be a CA. The file is read at each session, so a
// fake that starts after Alice, or regenerates its CA, is trusted at once. Anything else fails the
// provider's session closed (azure.tls_untrusted, visible in the journey): Alice itself still
// starts, because the fake is a separate container whose CA may change while Alice runs, and a
// start-up failure would crash-loop it for a reason that is not Alice's.
func azureRoots() (*x509.CertPool, error) {
	return fakeCARoots(azureCAFile, maxAzureCAFile, "Azure")
}

// fakeCARoots reads the one-certificate CA file a fake service wrote (what names the service in the errors).
func fakeCARoots(path string, limit int, what string) (*x509.CertPool, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0) //nolint:gosec // G304: the e2e build's fixed trust file (a variable only for unit tests)
	if err != nil {
		return nil, fmt.Errorf("the fake %s CA is not readable: %w", what, err)
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil, fmt.Errorf("the fake %s CA is not a regular file", what)
	}
	raw, err := io.ReadAll(io.LimitReader(f, int64(limit)+1))
	if err != nil {
		return nil, fmt.Errorf("the fake %s CA is not readable: %w", what, err)
	}
	if len(raw) > limit {
		return nil, fmt.Errorf("the fake %s CA file is too large", what)
	}
	trimmed := bytes.TrimSpace(raw)
	block, rest := pem.Decode(trimmed)
	if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 || !bytes.HasPrefix(trimmed, []byte("-----BEGIN ")) ||
		len(bytes.TrimSpace(rest)) != 0 {
		return nil, fmt.Errorf("the fake %s CA file must hold exactly one certificate and nothing else", what)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("the fake %s CA file holds no valid certificate", what)
	}
	if !cert.BasicConstraintsValid || !cert.IsCA {
		return nil, fmt.Errorf("the fake %s CA file holds a certificate that is not a CA", what)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return pool, nil
}

// acmeCAFile is where the fake ACME CA (cmd/alice-fakeacme, compose service fakeacme) writes its TLS CA;
// compose shares the volume read-only with alice. A variable only so the unit tests can point it at a file
// of their own.
var acmeCAFile = "/run/alice-e2e-acme/ca.pem"

// maxACMECAFile bounds what acmeRoots accepts, like maxAzureCAFile.
const maxACMECAFile = 64 << 10

// acmeRoots is the trust of the fake ACME CA's TLS certificate in the e2e build: ONLY the fake's CA
// (same rules as azureRoots: one regular file, one CA certificate, nothing else, read at each call). The
// release build has no such hook (testapi_release.go): it verifies a CA with the system roots and the
// provider's own bundle only. The inventory calls it (inventory.Config.ACMERoots) whenever it builds the transport of
// an ACME client or a DNS hook, for the API's account operations and the ACME jobs alike.
func acmeRoots() (*x509.CertPool, error) {
	return fakeCARoots(acmeCAFile, maxACMECAFile, "ACME")
}

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

// testMailer makes serve use the mailbox instead of SMTP while no mail settings exist. Never set ALICE_SMTP_* in the e2e
// compose: serve would import them as the mail settings and the mailbox would no longer receive anything.
var testMailer notify.Mailer = e2eMailbox

// resetSQL empties every application table. master_key_versions is kept because the master
// key file on the volume stays the same. Every table that references users (targets, host_keys,
// jobs, the certificate tables) must be in the same TRUNCATE, and so must every table of the SSH key
// rotation (migration 00010), which references ssh_keys, targets and users.  The ACME tables (00013) reference users, certificates and certificate_locations.
// The network discovery tables (00014) reference users and each other.
const resetSQL = `TRUNCATE users, user_mfa, recovery_codes, sessions, api_tokens, setup_sessions, settings, audit_log,
license, license_files, license_history, notifications_outbox,
target_locks, job_attempts, jobs,
acme_bindings, acme_orders, acme_certificates, acme_hooks, acme_accounts, acme_providers,
discovery_endpoints, discovery_certificates, discovery_scans, discovery_scopes,
rotation_op_ids, rotation_steps, rotation_locations, rotations, rotation_policies,
ssh_key_locations, ssh_keys, host_keys,
deployment_steps, deployments, certificate_locations, csr_requests, certificates, managed_private_keys,
kv_imports, bindings, kv_certificate_versions, kv_certificates, kv_keys, kv_secrets,
oidc_login_states, oidc_group_mappings, oidc_providers, setting_secrets, saved_views, alerts,
targets, credentials`

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
			if err := removeBackupFiles(d.BackupDir); err != nil {
				return err
			}
			e2eClock.Reset()
			if err := resetTemporaryCertificate(d.TLS, d.KeysDir, d.TLSHosts, e2eClock.Now()); err != nil {
				return err
			}
			e2eMailbox.reset()
			d.Setup.ResetLockouts()
			d.ResetLimits()
			return nil
		}
		// The license service runs the reset while no evaluation is in flight (an in-flight
		// Tick could write the old time record back) and starts again on the emptied tables and
		// time record: a new installation, sealed when it is created, with a fresh evaluation.
		// The platform key comes after, as at serve: its audit event shows that an installation
		// existed, so a license start after it would find the installation removed (AUD-18).
		var err error
		if d.License != nil {
			err = d.License.Restart(r.Context(), reset)
		} else {
			err = reset(r.Context())
		}
		if err == nil && d.Inventory != nil {
			// The credentials table was emptied: the new installation gets a new platform key.
			if _, kerr := d.Inventory.EnsurePlatformKey(r.Context()); kerr != nil {
				err = fmt.Errorf("create the platform key: %w", kerr)
			}
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
	mux.HandleFunc("POST /test/license/tamper", func(w http.ResponseWriter, r *http.Request) {
		if d.OwnerURL == "" {
			writeTestJSON(w, http.StatusConflict, map[string]string{"error": "no database"})
			return
		}
		seq, err := tamperNewestLicenseFile(r.Context(), d.OwnerURL)
		if errors.Is(err, errNoLicenseFile) {
			writeTestJSON(w, http.StatusConflict, map[string]string{"error": "no stored license file"})
			return
		}
		if err != nil {
			d.Log.Error("test license tamper failed", "error_type", fmt.Sprintf("%T", err))
			writeTestJSON(w, http.StatusInternalServerError, map[string]string{"error": "tamper failed"})
			return
		}
		if d.Scheduler != nil {
			if err := d.Scheduler.RunNow(r.Context(), jobs.LicenseEvaluate.Name); err != nil && !errors.Is(err, license.ErrLocked) {
				d.Log.Error("test license tamper: evaluation failed", "error_type", fmt.Sprintf("%T", err))
			}
		}
		writeTestJSON(w, http.StatusOK, map[string]int64{"tampered_seq": seq})
	})
	mux.HandleFunc("POST /test/jobs/drain", func(w http.ResponseWriter, r *http.Request) {
		if d.Runner == nil {
			writeTestJSON(w, http.StatusConflict, map[string]string{"error": "no job runner"})
			return
		}
		if !drainMu.TryLock() {
			writeTestJSON(w, http.StatusConflict, map[string]string{"error": "a drain is already running; drain again when it has ended"})
			return
		}
		defer drainMu.Unlock()
		// The drain is detached from the request: a client that gives up (its own timeout) must
		// not cancel the job it runs, which would send a deployment to recovery.
		res, err := drainJobs(context.WithoutCancel(r.Context()), d.Runner)
		if err != nil {
			d.Log.Error("test job drain failed", "error_type", fmt.Sprintf("%T", err))
			writeTestJSON(w, http.StatusInternalServerError, map[string]string{"error": "drain failed"})
			return
		}
		writeTestJSON(w, http.StatusOK, res)
	})
	mux.HandleFunc("POST /test/scheduler/run", func(w http.ResponseWriter, r *http.Request) {
		if d.Scheduler == nil {
			writeTestJSON(w, http.StatusConflict, map[string]string{"error": "no scheduler"})
			return
		}
		var body struct {
			Task string `json:"task"`
		}
		if !decodeTest(w, r, &body) {
			return
		}
		if body.Task == "" {
			writeTestJSON(w, http.StatusBadRequest, map[string]string{"error": "task is required"})
			return
		}
		status, msg := runScheduledTask(r.Context(), d, body.Task)
		if status != http.StatusOK {
			writeTestJSON(w, status, map[string]string{"error": msg})
			return
		}
		writeTestJSON(w, http.StatusOK, map[string]string{"task": body.Task})
	})
	mux.Handle("POST /test/rotation/overlap", rotationOverlapHandler(func(ctx context.Context, policy uuid.UUID, minutes int) (bool, error) {
		if d.OwnerURL == "" {
			return false, errNoTestDatabase
		}
		return setPolicyOverlap(ctx, d.OwnerURL, policy, minutes)
	}, d.Log))
	mux.Handle("POST /test/seed/dashboard", seedDashboardHandler(func(ctx context.Context) (seed.DashboardAnswer, error) {
		if d.OwnerURL == "" {
			return seed.DashboardAnswer{}, errNoTestDatabase
		}
		pool, err := pgxpool.New(ctx, d.OwnerURL)
		if err != nil {
			return seed.DashboardAnswer{}, err
		}
		defer pool.Close()
		return seed.Dashboard(ctx, pool, e2eClock.Now().UTC())
	}, d.Log))
	// GET /test/acme/ca tells a journey whether this build can trust the fake ACME CA yet (its CA file is
	// there and valid), so it waits for the fake instead of sleeping. It answers 200 {"trusted":true} or
	// 503 {"trusted":false}, never the certificate and never the file's content in an error.
	mux.HandleFunc("GET /test/acme/ca", func(w http.ResponseWriter, _ *http.Request) {
		if pool, err := acmeRoots(); err != nil || pool == nil {
			writeTestJSON(w, http.StatusServiceUnavailable, map[string]bool{"trusted": false})
			return
		}
		writeTestJSON(w, http.StatusOK, map[string]bool{"trusted": true})
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

// removeBackupFiles empties the backups directory (files only; the directory is a volume): a reset installation has
// no backups.
func removeBackupFiles(dir string) error {
	if dir == "" {
		return nil
	}
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read the backups directory: %w", err)
	}
	for _, en := range entries {
		if !en.Type().IsRegular() {
			continue
		}
		if err := os.Remove(filepath.Join(dir, en.Name())); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove a backup file: %w", err)
		}
	}
	return nil
}

// resetTemporaryCertificate makes the store serve a new temporary HTTPS certificate when it serves an uploaded one: a
// reset installation has Alice's own certificate, as a new one does (Phase 8 journeys upload certificates in the wizard
// and in Settings). The uploaded pair and any replacement leftovers are removed, EnsureSelfSigned writes the temporary
// pair with its mark, and Renew loads it (it re-reads the files and keeps a temporary certificate that is not due).
// A temporary certificate is left as it is.
func resetTemporaryCertificate(store *tlscert.Store, dir string, hosts []string, now time.Time) error {
	if store == nil || store.Info().Temporary {
		return nil
	}
	for _, name := range []string{"tls.crt.new", "tls.key.new", "tls.crt.prev", "tls.key.prev", "tls.crt", "tls.key"} {
		if err := os.Remove(filepath.Join(dir, name)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove the uploaded HTTPS certificate: %w", err)
		}
	}
	if _, err := tlscert.EnsureSelfSigned(dir, hosts, now); err != nil {
		return fmt.Errorf("create the temporary HTTPS certificate: %w", err)
	}
	if _, err := store.Renew(); err != nil {
		return fmt.Errorf("load the temporary HTTPS certificate: %w", err)
	}
	return nil
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

// maxDrain, drainClaimWindow and drainBudget bound one POST /test/jobs/drain: a handler that
// enqueues follow-up jobs (a connection test enqueues discovery) must not loop forever, and the
// answer must come before the server's 60 s WriteTimeout. A drain claims jobs only during the
// claim window and lets the job it claimed last run until drainBudget, so a certificate deployment
// claimed late in a drain still gets at least drainBudget - drainClaimWindow to finish its
// verification and record its outcome. A test that needs more calls drain again. (Variables only
// so the unit tests can shorten them.)
const maxDrain = 20

var (
	drainClaimWindow = 20 * time.Second
	drainBudget      = 50 * time.Second
)

// drainResult is the answer of POST /test/jobs/drain: the jobs that ran to the end, and CutOff
// when the budget ended while a job still ran (it is retried like any interrupted job; a
// deployment goes to recovery).
type drainResult struct {
	Ran    int  `json:"ran"`
	CutOff bool `json:"cut_off,omitempty"`
}

// drainMu lets one drain run at a time. A drain that cuts a job off waits for the job to record
// its outcome, which can outlast the client's timeout; a client that retries then gets 409
// instead of a second drain claiming jobs beside the first.
var drainMu sync.Mutex

// errDrainBudget is the cause a drain gives the context of a job it cuts off.
var errDrainBudget = errors.New("the drain's budget ended while the job ran")

// drainJobs runs due jobs one after the other (the e2e build has no workers). ctx must not end
// with the HTTP request (serve passes it detached); the drain's own budgets bound it.
func drainJobs(ctx context.Context, runner jobRunner) (drainResult, error) {
	claimCtx, stopClaiming := context.WithTimeout(ctx, drainClaimWindow)
	defer stopClaiming()
	budget := time.NewTimer(drainBudget)
	defer budget.Stop()
	var res drainResult
	for res.Ran < maxDrain && claimCtx.Err() == nil {
		run := runWithinBudget(ctx, runner, budget.C)
		if run.cutOff {
			// Only a claimed job counts as cut off; a claim the budget ended is no job.
			res.CutOff = run.ok
			break
		}
		if run.err != nil {
			return res, run.err
		}
		if !run.ok {
			break
		}
		res.Ran++
		if run.budgetEnded {
			break
		}
	}
	return res, nil
}

// drainRun is one RunOnce of a drain: cutOff says the drain cancelled the job's context before
// RunOnce returned; budgetEnded that the budget ended after it returned (the job is counted, the
// drain stops).
type drainRun struct {
	ok, cutOff, budgetEnded bool
	err                     error
}

// runWithinBudget runs one job and cancels its context only if the budget ends before the job
// returns. Whether the job returned and whether its context is cancelled are decided under one
// lock, so cut_off is reported exactly when the job's context was cancelled while it ran: a job
// that returns just before the budget ends is counted, not cut off (a check of the context after
// RunOnce returned reported it cut off and left it out of "ran").
func runWithinBudget(ctx context.Context, runner jobRunner, budgetEnded <-chan time.Time) drainRun {
	jobCtx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	var (
		mu       sync.Mutex
		returned bool
		out      drainRun
	)
	done := make(chan struct{})
	go func() {
		defer close(done)
		ok, err := runner.RunOnce(jobCtx)
		mu.Lock()
		defer mu.Unlock()
		returned = true
		out.ok, out.err = ok, err
	}()
	select {
	case <-done:
	case <-budgetEnded:
		mu.Lock()
		if returned {
			out.budgetEnded = true
		} else {
			out.cutOff = true
			cancel(errDrainBudget)
		}
		mu.Unlock()
		<-done
	}
	mu.Lock()
	defer mu.Unlock()
	return out
}

// runScheduledTask runs one periodic task of serve at once (the e2e build's scheduler still ticks
// on the wall clock; a test that needs the deployment recovery sweep now calls it here after
// moving the demo clock). It answers the HTTP status and an error text.
func runScheduledTask(ctx context.Context, d testDeps, task string) (int, string) {
	if !scheduled(d.Scheduler, task) {
		return http.StatusNotFound, "no scheduled task " + task
	}
	err := d.Scheduler.RunNow(ctx, task)
	switch {
	case err == nil:
		return http.StatusOK, ""
	case errors.Is(err, license.ErrLocked):
		return http.StatusConflict, "the task is paused while the license is expired"
	default:
		d.Log.Error("test scheduler run failed", "job_type", task, "error_type", fmt.Sprintf("%T", err))
		return http.StatusInternalServerError, "the task failed"
	}
}

// scheduled reports whether name is a task of the scheduler.
func scheduled(s *jobs.Scheduler, name string) bool {
	for _, t := range jobs.Types() {
		if t.Name == name {
			return s.Schedules(t)
		}
	}
	return false
}

// maxOverlapMinutes is the largest overlap the schema accepts (rotation_policies.overlap_minutes,
// 90 days).
const maxOverlapMinutes = 129600

// errNoTestDatabase: the test handler was built without the owner role's URL.
var errNoTestDatabase = errors.New("no database")

// overlapWriter sets a policy's overlap; it reports false for a policy that does not exist (or was
// deleted).
type overlapWriter func(ctx context.Context, policy uuid.UUID, minutes int) (bool, error)

// rotationOverlapHandler serves POST /test/rotation/overlap {"policy_id": "<uuid>", "minutes": 0..129600}:
// it sets the policy's overlap in minutes, so a journey can run a rotation whose overlap ends after one
// minute of demo clock instead of a day (the API takes whole days). It answers {"overlap_minutes": n};
// 404 for an unknown policy, 400 for any other body. Test-only, so not audited.
//
// It changes the policy only: a run's overlap is fixed when the run is created (rotations.overlap_minutes
// has no update grant and the run guard keeps it), so a run already under way keeps its own, and only a
// run planned after the call (Preview, Run now) takes the new value. A short or zero overlap shortens the
// wait and nothing else: whatever the overlap, the old key is removed from a file only after the run
// reached removing_old with removal_allowed and a login with the new key as that location's user
// succeeded no more than 15 minutes before the removal is sent. The store checks it (BeginRemove) and the
// database refuses any other removal regardless (rotation_locations_guard and the
// rotation_locations_removal_fresh CHECK; TestZeroOverlapStillNeedsTheRecheck).
func rotationOverlapHandler(set overlapWriter, log *slog.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { serveRotationOverlap(w, r, set, log) })
}

// serveRotationOverlap is the body of rotationOverlapHandler: a function of its own (too large to be
// inlined), so make release-symcheck finds its symbol (E2E_SYMBOLS) in the e2e build and refuses it in a
// release build.
func serveRotationOverlap(w http.ResponseWriter, r *http.Request, set overlapWriter, log *slog.Logger) {
	var body struct {
		PolicyID string `json:"policy_id"`
		Minutes  *int   `json:"minutes"`
	}
	if !decodeTest(w, r, &body) {
		return
	}
	policy, err := uuid.Parse(body.PolicyID)
	if err != nil || policy == uuid.Nil || body.Minutes == nil || *body.Minutes < 0 || *body.Minutes > maxOverlapMinutes {
		writeTestJSON(w, http.StatusBadRequest, map[string]string{"error": "policy_id must be a policy id and minutes a whole number from 0 to 129600"})
		return
	}
	found, err := set(r.Context(), policy, *body.Minutes)
	switch {
	case errors.Is(err, errNoTestDatabase):
		writeTestJSON(w, http.StatusConflict, map[string]string{"error": "no database"})
	case err != nil:
		log.Error("test rotation overlap failed", "error_type", fmt.Sprintf("%T", err))
		writeTestJSON(w, http.StatusInternalServerError, map[string]string{"error": "the overlap could not be set"})
	case !found:
		writeTestJSON(w, http.StatusNotFound, map[string]string{"error": "no such rotation policy"})
	default:
		writeTestJSON(w, http.StatusOK, map[string]int{"overlap_minutes": *body.Minutes})
	}
}

// setPolicyOverlap writes the overlap of a policy that is not deleted, as the owner role (the test
// endpoint bypasses the service on purpose), and bumps the policy's version so an edit made with the
// previous ETag is refused (412) instead of silently undoing it.
func setPolicyOverlap(ctx context.Context, ownerURL string, policy uuid.UUID, minutes int) (bool, error) {
	pool, err := pgxpool.New(ctx, ownerURL)
	if err != nil {
		return false, err
	}
	defer pool.Close()
	tag, err := pool.Exec(ctx, `UPDATE rotation_policies SET overlap_minutes = $2, version = version + 1, updated_at = $3
WHERE id = $1 AND deleted_at IS NULL`, policy, minutes, e2eClock.Now().UTC())
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, nil
}

// seedDashboardHandler serves POST /test/seed/dashboard (body {}): it inserts contract C17's data set (seed.Dashboard)
// as the owner role at the demo clock's now and answers what the dashboard and the certificate page must show for it,
// so a journey asserts true numbers. 409 without a database; 400 for any other body. Test-only, so not audited.
func seedDashboardHandler(run func(context.Context) (seed.DashboardAnswer, error), log *slog.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { serveSeedDashboard(w, r, run, log) })
}

// serveSeedDashboard is the body of seedDashboardHandler: a function of its own so make release-symcheck finds its
// symbol (E2E_SYMBOLS) in the e2e build and refuses it in a release build.
func serveSeedDashboard(w http.ResponseWriter, r *http.Request, run func(context.Context) (seed.DashboardAnswer, error), log *slog.Logger) {
	var body struct{}
	if !decodeTest(w, r, &body) {
		return
	}
	a, err := run(r.Context())
	switch {
	case errors.Is(err, errNoTestDatabase):
		writeTestJSON(w, http.StatusConflict, map[string]string{"error": "no database"})
	case err != nil:
		log.Error("test seed failed", "error_type", fmt.Sprintf("%T", err))
		writeTestJSON(w, http.StatusInternalServerError, map[string]string{"error": "the seed failed"})
	default:
		writeTestJSON(w, http.StatusOK, a)
	}
}

var (
	errNoLicenseFile = errors.New("no stored license file")
	customerField    = regexp.MustCompile(`"customer"\s*:\s*"`)
)

// damageLicenseFile prefixes the signed customer name with "tampered-": the file still parses,
// but its signature no longer matches (spec L-49).
func damageLicenseFile(raw []byte) ([]byte, error) {
	loc := customerField.FindIndex(raw)
	if loc == nil {
		return nil, errors.New("the license file has no customer field")
	}
	out := append([]byte{}, raw[:loc[1]]...)
	out = append(out, "tampered-"...)
	return append(out, raw[loc[1]:]...), nil
}

// tamperNewestLicenseFile damages the newest stored license file as the owner role (the
// application role cannot update license_files) and returns its sequence number.
func tamperNewestLicenseFile(ctx context.Context, ownerURL string) (int64, error) {
	pool, err := pgxpool.New(ctx, ownerURL)
	if err != nil {
		return 0, err
	}
	defer pool.Close()
	var seq int64
	err = db.InTx(ctx, pool, func(tx pgx.Tx) error {
		var raw []byte
		err := tx.QueryRow(ctx, "SELECT seq, raw_file FROM license_files ORDER BY seq DESC LIMIT 1 FOR UPDATE").Scan(&seq, &raw)
		if errors.Is(err, pgx.ErrNoRows) {
			return errNoLicenseFile
		}
		if err != nil {
			return err
		}
		damaged, err := damageLicenseFile(raw)
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, "UPDATE license_files SET raw_file = $1 WHERE seq = $2", damaged, seq)
		return err
	})
	return seq, err
}
