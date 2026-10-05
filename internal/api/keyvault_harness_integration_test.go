//go:build integration

package api

import (
	"context"
	"crypto/x509"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"alice/internal/jobs"
	"alice/internal/jobs/kvjobs"
	"alice/internal/platform/logging"
	"alice/internal/providers"
	"alice/internal/providers/azurekv"
	"alice/internal/providers/linuxssh/linuxsshtest"
	"alice/internal/testutil/fakekv"
	"alice/internal/testutil/pki"
)

// The Key Vault side of the API stack. What is REAL here: the HTTP router with authn, permissions, step-up,
// licence and CSRF; the inventory, the job queue and runner with the real kvjobs and deployjobs handlers; the
// deployment engine; the azurekv provider (its Azure SDK, its guarded transports, its retry loop and its error
// mapping); PostgreSQL. What is FAKE: Azure itself (internal/testutil/fakekv, an in-process TLS service with its own
// CA), the customer's Nginx servers (the fake SSH server of Phases 3-4) and the clock. The provider reaches the fake
// through the integration-only dial seam (azurekv.WithFixedAddresses): requests still address
// login.microsoftonline.com and <name>.vault.azure.net, the host rules and the TLS server name checks run as in
// production, and only the dialled address is mapped to the fake's loopback listener; the provider trusts only the
// fake's CA.

// kvVaultHost is the host name of the fake's vault.
func kvVaultHost(kv *fakekv.Server) string { return strings.TrimPrefix(kv.VaultURL(), "https://") }

// azureProvider is the real provider wired to the stack's fake Azure service.
func (s *stack) azureProvider() providers.Provider {
	kv := s.kv
	o, err := azurekv.WithFixedAddresses(azurekv.Options{RootCAs: func() (*x509.CertPool, error) { return kv.CAPool(), nil }},
		azurekv.FixedAddresses{
			Login: kv.DialAddr("login.microsoftonline.com:443"),
			Vault: kv.DialAddr(kvVaultHost(kv) + ":443"),
			IMDS:  kv.DialAddr("169.254.169.254:80"),
		})
	require.NoError(s.t, err)
	return azurekv.New(o)
}

// kvStackNow is the real time, to the second: the fake CA's certificates are valid from the real time, so the stack's
// clock (which the inventory builds certificate chains with) must not start before it.
func kvStackNow() time.Time { return time.Now().UTC().Truncate(time.Second) }

// kvnj is a stack with a fake Azure service, an Administrator, an Operator and one Nginx server.
type kvnj struct {
	*nj
	kv *fakekv.Server
}

// newKVNJ installs Alice with a fake Azure service (o configures it; Now is the stack's clock) and the first
// Nginx server with the given sites, as newNJ does.
func newKVNJ(t *testing.T, o fakekv.Options, sites ...linuxsshtest.NginxSite) *kvnj {
	t.Helper()
	return newKVNJSkew(t, o, nil, sites...)
}

// newKVNJSkew is newKVNJ where Azure's clock runs skew (read at every request; nil: none) ahead of Alice's.
func newKVNJSkew(t *testing.T, o fakekv.Options, skew *atomic.Int64, sites ...linuxsshtest.NginxSite) *kvnj {
	t.Helper()
	s := newStackWith(t, kvStackNow(), func(now func() time.Time) *fakekv.Server {
		o.Now = now
		if skew != nil {
			o.Now = func() time.Time { return now().Add(time.Duration(skew.Load())) }
		}
		return fakekv.Start(t, o)
	})
	adminAcct := &account{username: "ada", password: adminPassword}
	admin := s.setupAdmin(adminAcct, backupPassphrase, nil)
	s.stepUp(admin, adminAcct)
	requireStatus(t, admin.do(http.MethodPatch, "/api/v1/users/"+adminAcct.id, map[string]string{"email": "ada@example.com"}), http.StatusOK)
	operator := s.createUser(admin, adminAcct, "otto", "operator", "operator-password-2026")
	oc := s.freshClient()
	s.firstSignIn(oc, operator)
	n := &nj{stack: s, admin: admin, op: oc, adminAcct: adminAcct, opAcct: operator}
	if len(sites) > 0 {
		n.f, n.targetID, n.locs = n.addNginxRSA("web-01", nil, sites...)
	}
	return &kvnj{nj: n, kv: s.kv}
}

// webCert is the certificate every journey binds: exportable ECDSA for the two sites' names.
func (k *kvnj) addWebCert(name string) string {
	return k.kv.AddCertificate(name, fakekv.CertOptions{CommonName: wwwName, SANs: []string{wwwName, apiName}, Exportable: true})
}

// vaultBody is the add-vault request for the fake's vault with its client secret.
func (k *kvnj) vaultBody(name string) map[string]any {
	return map[string]any{"name": name, "vault_url": k.kv.VaultURL(), "auth": "client_secret", "tenant_id": k.kv.TenantID(),
		"client_id": k.kv.ClientID(), "client_secret": k.kv.Secret()}
}

// addVaultRaw sends the add request as the stepped-up Administrator and returns the answer.
func (k *kvnj) addVaultRaw(body map[string]any) *httptest.ResponseRecorder {
	k.stepUp(k.admin, k.adminAcct)
	return k.admin.do(http.MethodPost, "/api/v1/key-vaults", body)
}

// addVault adds the fake's vault (201), runs its first poll and returns the vault's target id.
func (k *kvnj) addVault(name string) string {
	t := k.t
	t.Helper()
	rec := k.addVaultRaw(k.vaultBody(name))
	requireStatus(t, rec, http.StatusCreated)
	id := decodeBody[map[string]any](t, rec)["target"].(map[string]any)["id"].(string)
	k.runKV()
	return id
}

// runKV drives the due jobs (the harness's own runJobs).
func (s *stack) runKV() int { return s.runKVDriven() }

// runKVDriven drives the due jobs. The provider waits on the stack's clock (its per-vault limiter between
// requests, a throttled answer's Retry-After), so while a job runs a goroutine moves the clock one second whenever
// the fake Azure service saw no new request for a few milliseconds (the provider is waiting, not working).
// Deployments never go through it (settle), so their timing stays under the test's control.
func (s *stack) runKVDriven() int {
	s.t.Helper()
	total := 0
	for range 20 {
		done := make(chan struct{})
		var ran bool
		var err error
		go func() {
			defer close(done)
			ran, err = s.runner.RunOnce(context.Background())
		}()
		tick := time.NewTicker(2 * time.Millisecond)
		last, still := -1, 0
	wait:
		for {
			select {
			case <-done:
				break wait
			case <-tick.C:
				n := 0
				if s.kv != nil {
					n = len(s.kv.Requests())
				}
				if n == last {
					still++
				} else {
					last, still = n, 0
				}
				if still >= 3 {
					s.clock.Advance(time.Second)
					still = 0
				}
			}
		}
		tick.Stop()
		require.NoError(s.t, err)
		if !ran {
			return total
		}
		total++
	}
	s.t.Fatal("jobs did not settle after 20 runs")
	return total
}

// scheduler is the periodic work of serve for Key Vault: kv.schedule and kv.auto_deploy, run on demand through
// the real scheduler (its gate included).
func (s *stack) kvScheduler() *jobs.Scheduler {
	log := logging.New(s.logs, slog.LevelDebug)
	return jobs.NewScheduler(s.clock, s.license, log,
		kvjobs.ScheduleTask(s.inv, time.Minute, log), kvjobs.AutoDeployTask(s.inv, time.Minute, log))
}

// schedule runs kv.schedule once and drains the jobs it queued.
func (s *stack) schedule() error {
	s.t.Helper()
	err := s.kvScheduler().RunNow(context.Background(), "kv.schedule")
	s.runKV()
	return err
}

// plan runs the planner (kv.auto_deploy) once and returns the scheduler's answer.
func (s *stack) plan() error {
	s.t.Helper()
	return s.kvScheduler().RunNow(context.Background(), "kv.auto_deploy")
}

// kvItems lists a vault's items of one kind over the API.
func (s *stack) kvItems(c *client, vault, kind string) []map[string]any {
	s.t.Helper()
	rec := c.do(http.MethodGet, "/api/v1/targets/"+vault+"/kv/"+kind, nil)
	requireStatus(s.t, rec, http.StatusOK)
	return decodeBody[struct {
		Items []map[string]any `json:"items"`
	}](s.t, rec).Items
}

// kvCertByName finds a vault certificate in the listing.
func (s *stack) kvCertByName(c *client, vault, name string) map[string]any {
	s.t.Helper()
	for _, it := range s.kvItems(c, vault, "certificates") {
		if it["name"] == name {
			return it
		}
	}
	s.t.Fatalf("no vault certificate %q listed", name)
	return nil
}

// kvDetail reads one certificate with its versions and binding.
func (s *stack) kvDetail(c *client, vault, id string) map[string]any {
	s.t.Helper()
	rec := c.do(http.MethodGet, "/api/v1/targets/"+vault+"/kv/certificates/"+id, nil)
	requireStatus(s.t, rec, http.StatusOK)
	return decodeBody[map[string]any](s.t, rec)
}

// versionsOf returns the version records of a detail, newest detected first as the API lists them.
func versionsOf(detail map[string]any) []map[string]any {
	var out []map[string]any
	for _, v := range detail["versions"].([]any) {
		out = append(out, v.(map[string]any))
	}
	return out
}

// bind connects a vault certificate to websites as c (201) and returns the binding.
func (s *stack) bind(c *client, kvCertID string, locationIDs ...string) map[string]any {
	s.t.Helper()
	rec := c.do(http.MethodPost, "/api/v1/bindings", map[string]any{"kv_certificate_id": kvCertID, "location_ids": locationIDs})
	requireStatus(s.t, rec, http.StatusCreated)
	return decodeBody[map[string]any](s.t, rec)
}

// autoDeploy switches automatic deployment (an Administrator's, with step-up) and returns the answer.
func (k *kvnj) autoDeploy(bindingID string, version int, on bool) *httptest.ResponseRecorder {
	k.stepUp(k.admin, k.adminAcct)
	return k.admin.do(http.MethodPut, "/api/v1/bindings/"+bindingID+"/auto-deploy", map[string]any{"enabled": on}, ifMatchOf(itoa(version)))
}

func itoa(n int) string { return strconv.Itoa(n) }

// bindingVersion reads a binding's ETag version.
func (s *stack) bindingVersion(c *client, id string) int {
	s.t.Helper()
	rec := c.do(http.MethodGet, "/api/v1/bindings/"+id, nil)
	requireStatus(s.t, rec, http.StatusOK)
	return int(decodeBody[map[string]any](s.t, rec)["version"].(float64))
}

// deploymentsOf lists the deployments of a location (newest first as the API lists them).
func (s *stack) deploymentsOfLocation(c *client, locationID string) []depView {
	s.t.Helper()
	rec := c.do(http.MethodGet, "/api/v1/deployments?location_id="+locationID, nil)
	requireStatus(s.t, rec, http.StatusOK)
	return decodeBody[struct {
		Items []depView `json:"items"`
	}](s.t, rec).Items
}

// vaultRequests are the requests the fake logged for the vault host (the login host excluded).
func vaultRequests(kv *fakekv.Server) []fakekv.Request {
	var out []fakekv.Request
	for _, r := range kv.Requests() {
		if r.Host == kvVaultHost(kv) {
			out = append(out, r)
		}
	}
	return out
}

// secretReads counts the authenticated reads of a vault secret (a certificate's key material).
func secretReads(kv *fakekv.Server) int {
	n := 0
	for _, r := range kv.Requests() {
		if r.Host == kvVaultHost(kv) && r.HadAuth && r.Method == http.MethodGet && strings.HasPrefix(r.Path, "/secrets/") {
			n++
		}
	}
	return n
}

// kvDep is a deployment as the history shows it, with the Key Vault fields.
type kvDep struct {
	depView
	Trigger   string  `json:"trigger"`
	Source    string  `json:"source"`
	BindingID *string `json:"binding_id"`
	KVVersion string  `json:"kv_version"`
	VaultName string  `json:"vault_name"`
}

// kvDeployments lists a location's deployments over the API (newest first).
func (s *stack) kvDeployments(c *client, locationID string) []kvDep {
	s.t.Helper()
	rec := c.do(http.MethodGet, "/api/v1/deployments?location_id="+locationID, nil)
	requireStatus(s.t, rec, http.StatusOK)
	return decodeBody[struct {
		Items []kvDep `json:"items"`
	}](s.t, rec).Items
}

// settleKV is settle with the provider's waits on the clock driven (the deployment reads the vault).
func (s *stack) settleKV(c *client, id string) depView {
	s.t.Helper()
	for range 80 {
		_, err := s.inv.SweepDeployments(context.Background())
		require.NoError(s.t, err)
		s.runKV()
		if d := s.deployment(c, id); d.State == "done" {
			return d
		}
		s.clock.Advance(time.Minute)
	}
	s.t.Fatalf("deployment %s did not end", id)
	return depView{}
}

// checkNow is the "Check now" button: a manual poll, drained.
func (k *kvnj) checkNow(vault string) string {
	k.t.Helper()
	rec := k.op.do(http.MethodPost, "/api/v1/targets/"+vault+"/actions/discover", nil)
	requireStatus(k.t, rec, http.StatusAccepted)
	k.runKV()
	return decodeBody[map[string]any](k.t, rec)["job_id"].(string)
}

// leafFingerprint is the fingerprint of the vault certificate version the way the fake served it.
func (k *kvnj) leafFingerprint(name, version string) string {
	return pki.Fingerprint(k.kv.Leaf(name, version))
}

func itemNames(items []map[string]any) []string {
	var out []string
	for _, it := range items {
		out = append(out, it["name"].(string))
	}
	return out
}

// importRaw requests an import of an uploaded certificate (an Administrator's, with step-up).
func (k *kvnj) importRaw(certID, vault, name string, confirm bool) *httptest.ResponseRecorder {
	k.stepUp(k.admin, k.adminAcct)
	return k.admin.do(http.MethodPost, "/api/v1/certificates/"+certID+"/actions/import-to-key-vault",
		map[string]any{"target_id": vault, "name": name, "confirm_new_version": confirm})
}

// importView is an import record as the API shows it.
type importView struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	State      string `json:"state"`
	Version    string `json:"version"`
	Thumbprint string `json:"thumbprint"`
	NewVersion bool   `json:"new_version"`
	CanRetry   bool   `json:"can_retry"`
	Error      *struct {
		Code   string            `json:"code"`
		Reason string            `json:"reason"`
		Params map[string]string `json:"params"`
	} `json:"error"`
}

func (v importView) errCode() string {
	if v.Error == nil {
		return ""
	}
	return v.Error.Code
}

// requestImport asks for an import, asserts 202, runs the jobs and returns the import as it ended.
func (k *kvnj) requestImport(certID, vault, name string, confirm bool) importView {
	t := k.t
	t.Helper()
	rec := k.importRaw(certID, vault, name, confirm)
	requireStatus(t, rec, http.StatusAccepted)
	id := decodeBody[struct {
		Import importView `json:"import"`
	}](t, rec).Import.ID
	k.runKV()
	return k.importOf(vault, id)
}

func (k *kvnj) importOf(vault, id string) importView {
	k.t.Helper()
	rec := k.admin.do(http.MethodGet, "/api/v1/targets/"+vault+"/kv/imports/"+id, nil)
	requireStatus(k.t, rec, http.StatusOK)
	return decodeBody[importView](k.t, rec)
}

// importPosts counts the authenticated POSTs of imports the fake saw (the proof of what was sent).
func importPosts(kv *fakekv.Server) int {
	n := 0
	for _, r := range kv.Requests() {
		if r.Method == http.MethodPost && r.HadAuth && strings.HasSuffix(r.Path, "/import") {
			n++
		}
	}
	return n
}

// touch keeps both browsers' sessions alive across a long advance of the clock (the idle timeout), signing in again
// where one ended.
func (k *kvnj) touch() {
	k.t.Helper()
	for _, who := range []struct {
		c *client
		a *account
	}{{k.admin, k.adminAcct}, {k.op, k.opAcct}} {
		if who.c.do(http.MethodGet, "/api/v1/auth/session", nil).Code == http.StatusUnauthorized {
			k.signIn(who.c, who.a) // the session ended with the long advance of the clock
		}
	}
}

// tokenRequests counts the token requests the fake saw (one per sign-in: a poll of a vault whose sign-in fails sends one).
func tokenRequests(kv *fakekv.Server) int {
	n := 0
	for _, r := range kv.Requests() {
		if r.Method == http.MethodPost && strings.HasSuffix(r.Path, "/oauth2/v2.0/token") {
			n++
		}
	}
	return n
}

// settleAll settles every deployment of a location that is not done.
// jobError reads a job's error (code, reason, params) over the API.
func (s *stack) jobError(c *client, id string) (code, reason string, params map[string]any) {
	s.t.Helper()
	e, _ := s.job(c, id)["error"].(map[string]any)
	code, _ = e["code"].(string)
	reason, _ = e["reason"].(string)
	params, _ = e["params"].(map[string]any)
	return code, reason, params
}

func (k *kvnj) settleAll(t *testing.T, locationID string) {
	t.Helper()
	for _, d := range k.kvDeployments(k.op, locationID) {
		if d.State != "done" {
			k.settleKV(k.op, d.ID)
		}
	}
}

// transportTrap replaces http.DefaultTransport by one that records every request and refuses it, for the length of the
// test: the provider must never use the process-wide default transport, and the API stack must not either.
type transportTrap struct {
	mu   sync.Mutex
	urls []string
}

func (tt *transportTrap) RoundTrip(r *http.Request) (*http.Response, error) {
	tt.mu.Lock()
	tt.urls = append(tt.urls, r.URL.Scheme+"://"+r.URL.Host)
	tt.mu.Unlock()
	return nil, errors.New("trap: the default transport must not be used")
}

func (tt *transportTrap) seen() []string {
	tt.mu.Lock()
	defer tt.mu.Unlock()
	return append([]string(nil), tt.urls...)
}

func trapDefaultTransport(t *testing.T) *transportTrap {
	t.Helper()
	tt := &transportTrap{}
	old := http.DefaultTransport
	http.DefaultTransport = tt
	t.Cleanup(func() { http.DefaultTransport = old })
	return tt
}

// connectionCounter is a loopback listener that counts the connections made to it (an environment proxy or an
// identity endpoint the provider must ignore).
type connectionCounter struct {
	ln net.Listener
	n  atomic.Int64
}

func newConnectionCounter(t *testing.T) *connectionCounter {
	t.Helper()
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	c := &connectionCounter{ln: ln}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			c.n.Add(1)
			_ = conn.Close()
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return c
}

func (c *connectionCounter) addr() string { return c.ln.Addr().String() }
func (c *connectionCounter) count() int   { return int(c.n.Load()) }
