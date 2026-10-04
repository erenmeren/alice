//go:build integration

package api

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

	"alice/internal/providers"
	"alice/internal/providers/linuxssh/linuxsshtest"
	"alice/internal/providers/nginx"
	"alice/internal/testutil/pki"
)

// The Nginx side of the API stack: emulated Nginx hosts behind the fake SSH server, the nginx
// provider over them (registered in the stack's registry next to linuxssh) and the helpers the
// journeys share. Everything the journeys do goes through the HTTP API; the emulator is only the
// customer's server.

const (
	wwwCert = "/etc/nginx/ssl/www.crt"
	wwwKey  = "/etc/nginx/ssl/www.key"
	apiCert = "/etc/nginx/ssl/api.crt"
	apiKey  = "/etc/nginx/ssl/api.key"
	wwwName = "www.example.test"
	apiName = "api.example.test"
)

func wwwSite() linuxsshtest.NginxSite {
	return linuxsshtest.NginxSite{Names: []string{wwwName}, Port: 443, CertPath: wwwCert, KeyPath: wwwKey}
}

func apiSite() linuxsshtest.NginxSite {
	return linuxsshtest.NginxSite{Names: []string{apiName}, Port: 443, CertPath: apiCert, KeyPath: apiKey}
}

// nginxFixture is one emulated Nginx host serving the "old" certificate on its sites.
type nginxFixture struct {
	server *linuxsshtest.Server
	emu    *linuxsshtest.Emulator
	host   string
	port   int
	old    pki.Leaf
	// rsaOld is the certificate of the sites that serve an RSA key (nil: none); every other site
	// serves old.
	rsaOld *pki.Leaf
	rsaAt  map[string]bool // certificate paths served with rsaOld
}

// oldAt is the certificate the site with certPath served before any deployment.
func (f *nginxFixture) oldAt(certPath string) pki.Leaf {
	if f.rsaAt[certPath] {
		return *f.rsaOld
	}
	return f.old
}

// nginxFixture starts an emulated Nginx host with the given sites, authorizes Alice's platform
// key on it and makes it reachable for Alice's own TLS probe.
func (s *stack) nginxFixture(sites ...linuxsshtest.NginxSite) *nginxFixture {
	return s.nginxFixtureRSA(nil, sites...)
}

// nginxFixtureRSA is nginxFixture where the sites with a certificate path in rsaPaths serve an RSA
// certificate (a location only takes a certificate of its key type).
func (s *stack) nginxFixtureRSA(rsaPaths []string, sites ...linuxsshtest.NginxSite) *nginxFixture {
	t := s.t
	t.Helper()
	pk, err := s.inv.PlatformKey(context.Background())
	require.NoError(t, err)
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(pk.PublicKey))
	require.NoError(t, err)
	f := &nginxFixture{emu: linuxsshtest.NewEmulator()}
	f.emu.EnableNginx("1.22.1")
	f.old = s.ca.Issue(pki.Opts{CommonName: wwwName, SANs: []string{wwwName, apiName}}, s.clock.Now())
	if len(rsaPaths) > 0 {
		rsaOld := s.ca.Issue(pki.Opts{CommonName: wwwName, SANs: []string{wwwName, apiName}, KeyType: pki.RSA2048}, s.clock.Now())
		f.rsaOld, f.rsaAt = &rsaOld, map[string]bool{}
		for _, p := range rsaPaths {
			f.rsaAt[p] = true
		}
	}
	for _, site := range sites {
		old := f.oldAt(site.CertPath)
		f.emu.AddSite(site, old.FullchainPEM, old.KeyPEM)
	}
	f.server = linuxsshtest.NewServer(t, f.emu.Handler())
	f.server.Authorize(pub)
	f.host, f.port = f.server.Addr()
	s.mu.Lock()
	s.nginxSrvs = append(s.nginxSrvs, f)
	s.mu.Unlock()
	return f
}

// stackProber is Alice's own TLS probe against the emulated Nginx. Every emulated host listens
// on 127.0.0.1, so with several hosts Alice's probe cannot tell which one it would reach: it is
// then unreachable and the server-side probe (tls-probe, per host) decides (verified "local").
type stackProber struct{ s *stack }

func (p stackProber) Probe(_ context.Context, _ string, port int, sni, keyType string) (nginx.Probe, error) {
	p.s.mu.Lock()
	srvs := append([]*nginxFixture(nil), p.s.nginxSrvs...)
	p.s.mu.Unlock()
	if len(srvs) != 1 {
		return nginx.Probe{}, nginx.ErrProbeUnreachable
	}
	leaf, chain, ok := srvs[0].emu.ProbeServed("", port, sni, keyType)
	if !ok {
		return nginx.Probe{}, nginx.ErrProbeFailed
	}
	return nginx.Probe{LeafSHA256: leaf, ChainLength: chain}, nil
}

// stackNginx lets a test wrap the sessions the nginx provider opens (a process that dies after
// a call returned, a license that expires while a deployment runs).
type stackNginx struct {
	*nginx.Provider
	s *stack
}

func (p stackNginx) Open(ctx context.Context, t providers.TargetRef, c providers.CredentialSource, e providers.Env) (providers.Session, error) {
	p.s.mu.Lock()
	down := p.s.down
	p.s.mu.Unlock()
	if down {
		return nil, providers.NewError("ssh.unreachable", true, errors.New("test: the network is down"), nil)
	}
	sess, err := p.Provider.Open(ctx, t, c, e)
	if err != nil {
		return sess, err
	}
	p.s.mu.Lock()
	wrap := p.s.wrap
	p.s.mu.Unlock()
	if wrap == nil {
		return sess, nil
	}
	return wrap(t, sess), nil
}

// setDown makes every connection to an Nginx server fail as an unreachable network does.
func (s *stack) setDown(down bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.down = down
}

// setWrap makes every nginx session opened from now on pass through w (nil: none).
func (s *stack) setWrap(w func(providers.TargetRef, providers.Session) providers.Session) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.wrap = w
}

// nj is one administrator's and one operator's view of a stack with an Nginx server added,
// confirmed and discovered.
type nj struct {
	*stack
	admin, op *client
	adminAcct *account
	opAcct    *account
	f         *nginxFixture
	targetID  string
	locs      map[string]string // certificate path -> location id
}

// newNJ installs Alice, gives the administrator an email address (so deployment emails reach the
// outbox), creates an operator and adds the first Nginx server with the given sites.
func newNJ(t *testing.T, sites ...linuxsshtest.NginxSite) *nj {
	t.Helper()
	return newNJRSA(t, nil, sites...)
}

// newNJRSA is newNJ where the first server's sites with a certificate path in rsaPaths serve an RSA
// certificate.
func newNJRSA(t *testing.T, rsaPaths []string, sites ...linuxsshtest.NginxSite) *nj {
	t.Helper()
	s, admin, adminAcct := installed(t)
	s.stepUp(admin, adminAcct)
	requireStatus(t, admin.do(http.MethodPatch, "/api/v1/users/"+adminAcct.id, map[string]string{"email": "ada@example.com"}), http.StatusOK)
	operator := s.createUser(admin, adminAcct, "otto", "operator", "operator-password-2026")
	oc := s.freshClient()
	s.firstSignIn(oc, operator)
	n := &nj{stack: s, admin: admin, op: oc, adminAcct: adminAcct, opAcct: operator}
	n.f, n.targetID, n.locs = n.addNginxRSA("web-01", rsaPaths, sites...)
	return n
}

// addNginx adds another Nginx server: the emulated host, the target, the host-key confirmation
// and the first discovery. It returns the host, the target id and the discovered locations.
func (s *stack) addNginxAs(c *client, name string, sites ...linuxsshtest.NginxSite) (*nginxFixture, string, map[string]string) {
	return s.addNginxRSAAs(c, name, nil, sites...)
}

func (s *stack) addNginxRSAAs(c *client, name string, rsaPaths []string, sites ...linuxsshtest.NginxSite) (*nginxFixture, string, map[string]string) {
	t := s.t
	t.Helper()
	f := s.nginxFixtureRSA(rsaPaths, sites...)
	rec := c.do(http.MethodPost, "/api/v1/targets", map[string]any{"type": "nginx", "name": name, "host": f.host, "port": f.port, "username": "alice-svc"})
	requireStatus(t, rec, http.StatusCreated)
	targetID := decodeBody[map[string]any](t, rec)["target"].(map[string]any)["id"].(string)
	s.pinServer(c, targetID)
	return f, targetID, s.locationIDs(c, targetID)
}

func (n *nj) addNginx(name string, sites ...linuxsshtest.NginxSite) (*nginxFixture, string, map[string]string) {
	return n.addNginxAs(n.admin, name, sites...)
}

func (n *nj) addNginxRSA(name string, rsaPaths []string, sites ...linuxsshtest.NginxSite) (*nginxFixture, string, map[string]string) {
	return n.addNginxRSAAs(n.admin, name, rsaPaths, sites...)
}

// certificateLocations lists a server's certificate locations over the API.
func (s *stack) certificateLocations(c *client, targetID string, missing bool) []map[string]any {
	s.t.Helper()
	path := "/api/v1/targets/" + targetID + "/certificate-locations"
	if missing {
		path += "?missing=true"
	}
	rec := c.do(http.MethodGet, path, nil)
	requireStatus(s.t, rec, http.StatusOK)
	return decodeBody[struct {
		Items []map[string]any `json:"items"`
	}](s.t, rec).Items
}

func (s *stack) locationIDs(c *client, targetID string) map[string]string {
	s.t.Helper()
	out := map[string]string{}
	for _, l := range s.certificateLocations(c, targetID, false) {
		out[l["cert_path"].(string)] = l["id"].(string)
	}
	return out
}

// location returns the location of certPath in the server's list.
func (s *stack) location(c *client, targetID, certPath string) map[string]any {
	s.t.Helper()
	for _, l := range s.certificateLocations(c, targetID, true) {
		if l["cert_path"] == certPath {
			return l
		}
	}
	s.t.Fatalf("no location for %s", certPath)
	return nil
}

// discover runs a discovery of the server and drains the queue.
func (s *stack) discover(c *client, targetID string) {
	s.t.Helper()
	requireStatus(s.t, c.do(http.MethodPost, "/api/v1/targets/"+targetID+"/actions/discover", nil), http.StatusAccepted)
	s.runJobs()
}

// certBody is an upload of a certificate with its key as PEM.
func certBody(l pki.Leaf, label string) map[string]any {
	return map[string]any{"label": label, "certificate_pem": string(l.FullchainPEM), "private_key_pem": string(l.KeyPEM)}
}

// uploadCertificate uploads body and returns the certificate's id.
func (s *stack) uploadCertificate(c *client, body map[string]any) string {
	s.t.Helper()
	rec := c.do(http.MethodPost, "/api/v1/certificates/upload", body)
	requireStatus(s.t, rec, http.StatusCreated)
	return decodeBody[struct {
		Certificate struct {
			ID string `json:"id"`
		} `json:"certificate"`
	}](s.t, rec).Certificate.ID
}

// issue is a new certificate for the Nginx sites from the stack's CA.
func (s *stack) issue(names ...string) pki.Leaf {
	if len(names) == 0 {
		names = []string{wwwName, apiName}
	}
	return s.ca.Issue(pki.Opts{CommonName: names[0], SANs: names}, s.clock.Now())
}

// deployRef is one accepted deployment of a deploy request.
type deployRef struct {
	ID            string `json:"id"`
	JobID         string `json:"job_id"`
	LocationID    string `json:"location_id"`
	StatusURL     string `json:"status_url"`
	DeploymentURL string `json:"deployment_url"`
}

func (s *stack) requestDeploy(c *client, certID string, locationIDs ...string) *httptest.ResponseRecorder {
	return c.do(http.MethodPost, "/api/v1/certificates/"+certID+"/deploy", map[string]any{"location_ids": locationIDs})
}

// deploy requests a deployment, asserts 202 and returns the accepted deployments in order.
func (s *stack) deploy(c *client, certID string, locationIDs ...string) []deployRef {
	s.t.Helper()
	rec := s.requestDeploy(c, certID, locationIDs...)
	requireStatus(s.t, rec, http.StatusAccepted)
	got := decodeBody[struct {
		Deployments []deployRef `json:"deployments"`
	}](s.t, rec).Deployments
	require.Len(s.t, got, len(locationIDs))
	for i, d := range got {
		require.Equal(s.t, locationIDs[i], d.LocationID)
		require.Equal(s.t, "/api/v1/deployments/"+d.ID, d.DeploymentURL)
		require.Equal(s.t, "/api/v1/jobs/"+d.JobID, d.StatusURL)
	}
	return got
}

// depView is the part of a deployment the journeys assert.
type depView struct {
	ID                  string     `json:"id"`
	CertificateID       string     `json:"certificate_id"`
	LocationID          string     `json:"location_id"`
	TargetID            string     `json:"target_id"`
	CertPath            string     `json:"cert_path"`
	JobID               string     `json:"job_id"`
	JobStatus           string     `json:"job_status"`
	State               string     `json:"state"`
	Status              string     `json:"status"`
	Result              string     `json:"result"`
	Phase               string     `json:"phase"`
	Verified            string     `json:"verified"`
	FailedStep          string     `json:"failed_step"`
	HelperError         string     `json:"helper_error"`
	BackupDir           string     `json:"backup_dir"`
	NewFingerprint      string     `json:"new_fingerprint"`
	PreviousFingerprint string     `json:"previous_fingerprint"`
	RecoveryAttempts    int        `json:"recovery_attempts"`
	RecoverAfter        *time.Time `json:"recover_after"`
	Error               *struct {
		Code   string            `json:"code"`
		Reason string            `json:"reason"`
		Params map[string]string `json:"params"`
	} `json:"error"`
	VerifyFailed *struct {
		Code string `json:"code"`
	} `json:"verify_failed"`
	Steps []struct {
		Name   string            `json:"name"`
		Status string            `json:"status"`
		Params map[string]string `json:"params"`
	} `json:"steps"`
}

func (d depView) errorCode() string {
	if d.Error == nil {
		return ""
	}
	return d.Error.Code
}

func (d depView) stepList() []string {
	out := []string{}
	for _, st := range d.Steps {
		out = append(out, st.Name+":"+st.Status)
	}
	return out
}

func (s *stack) deployment(c *client, id string) depView {
	s.t.Helper()
	rec := c.do(http.MethodGet, "/api/v1/deployments/"+id, nil)
	requireStatus(s.t, rec, http.StatusOK)
	return decodeBody[depView](s.t, rec)
}

// settle plays the scheduler and the runner: the sweep (a scheduled task of the real process), the
// due jobs, then a minute on the clock, until the deployment is done. Each round reads the
// deployment over the API, which also keeps the session alive.
func (s *stack) settle(c *client, id string) depView {
	s.t.Helper()
	for range 80 {
		_, err := s.inv.SweepDeployments(context.Background())
		require.NoError(s.t, err)
		s.runJobs()
		if d := s.deployment(c, id); d.State == "done" {
			return d
		}
		s.clock.Advance(time.Minute)
	}
	s.t.Fatalf("deployment %s did not end", id)
	return depView{}
}

// emails counts the outbox rows of a template.
func (s *stack) emails(template string) int {
	s.t.Helper()
	var n int
	require.NoError(s.t, s.db.Owner.QueryRow(context.Background(),
		"SELECT count(*) FROM notifications_outbox WHERE template_key = $1", template).Scan(&n))
	return n
}

// deploymentEmails lists the deployment emails by template and count.
func (s *stack) deploymentEmails() map[string]int {
	s.t.Helper()
	rows, err := s.db.Owner.Query(context.Background(),
		"SELECT template_key, count(*) FROM notifications_outbox WHERE template_key LIKE 'deployment.%' GROUP BY 1")
	require.NoError(s.t, err)
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var k string
		var c int
		require.NoError(s.t, rows.Scan(&k, &c))
		out[k] = c
	}
	require.NoError(s.t, rows.Err())
	return out
}

// emailParam reads one param of the (only) outbox row of a template.
func (s *stack) emailParam(template, key string) string {
	s.t.Helper()
	var v string
	require.NoError(s.t, s.db.Owner.QueryRow(context.Background(),
		"SELECT params->>$2 FROM notifications_outbox WHERE template_key = $1", template, key).Scan(&v))
	return v
}

// served is the fingerprint of the leaf the emulated website serves for name.
func (f *nginxFixture) served(name string) string { return f.emu.Served(443, name) }

// requirePair asserts the files on the emulated server are a matching pair holding want, and that
// the website serves exactly it: the record, the files and the served certificate agree.
func (f *nginxFixture) requirePair(t *testing.T, certPath, keyPath, sni string, want pki.Leaf) {
	t.Helper()
	certPEM, keyPEM := f.emu.NginxFile(certPath), f.emu.NginxFile(keyPath)
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	require.NoError(t, err, "the files on the server are a matching pair, never mixed")
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	require.NoError(t, err)
	require.Equal(t, pki.Fingerprint(want.Cert), pki.Fingerprint(leaf), "the certificate file holds the expected certificate")
	require.Equal(t, pki.Fingerprint(want.Cert), f.served(sni), "the website serves the files' certificate")
}
