//go:build integration && testlicense

package backup_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

	"alice/internal/audit"
	"alice/internal/auth"
	"alice/internal/backup"
	"alice/internal/backup/dump"
	"alice/internal/inventory"
	"alice/internal/jobs"
	"alice/internal/jobs/deployjobs"
	"alice/internal/jobs/sshkeyjobs"
	"alice/internal/jobs/targetjobs"
	"alice/internal/license"
	"alice/internal/license/licensetest"
	"alice/internal/notify"
	"alice/internal/platform/clock"
	"alice/internal/platform/db"
	"alice/internal/providers"
	"alice/internal/providers/fake"
	"alice/internal/providers/linuxssh/helperproto"
	"alice/internal/rbac"
	"alice/internal/secrets"
	"alice/internal/setup"
	"alice/internal/sshkeys"
	"alice/internal/sshkeys/keymat"
	"alice/internal/testutil/pgtest"
	"alice/internal/testutil/pki"
)

// worldProvider answers Discover from the key world (each target's own files), so a scan and the key changes of a
// rotation always agree.
type worldProvider struct{ *fake.Provider }

func (p worldProvider) Open(ctx context.Context, t providers.TargetRef, c providers.CredentialSource, e providers.Env) (providers.Session, error) {
	s, err := p.Provider.Open(ctx, t, c, e)
	if err != nil {
		return nil, err
	}
	return worldSession{Session: s}, nil
}

type worldSession struct{ providers.Session }

func (s worldSession) Discover(ctx context.Context, req providers.DiscoverRequest) (providers.DiscoveryResult, error) {
	res, err := s.Session.Discover(ctx, req)
	if err != nil || !req.SSHKeys {
		return res, err
	}
	keys, err := s.ListAuthorizedKeys(ctx)
	if err != nil {
		return res, err
	}
	res.SSHKeys, res.ReadFiles = keys, nil
	for _, u := range f85Users {
		res.ReadFiles = append(res.ReadFiles, keyFile85(u))
	}
	return res, nil
}

var f85Users = []string{"deploy", "app", "root", fake.ConnectionAccount}

func keyFile85(user string) string {
	if user == "root" {
		return "/root/.ssh/authorized_keys"
	}
	return "/home/" + user + "/.ssh/authorized_keys"
}

// f85 is one Alice installation built through its services: setup, users with TOTP, targets behind fake providers,
// certificates, SSH keys, a rotation, a license, mail settings, and the backup service.
type f85 struct {
	t                         *testing.T
	ctx                       context.Context
	db                        *pgtest.DB
	clk                       *clock.Fake
	dir, keysDir, stateDir    string
	keyring                   *secrets.Keyring
	audit                     *audit.Log
	lic                       *license.Service
	queue                     *jobs.Queue
	reg                       *providers.Registry
	inv                       *inventory.Service
	keys                      *sshkeys.Service
	auth                      *auth.Service
	runner                    *jobs.Runner
	linux, nginx              *fake.Provider
	world                     *fake.KeyWorld
	ca                        *pki.CA
	admin                     inventory.Actor
	hkLinux, hkNginx          providers.HostKey
	totpSecrets               map[string]string // username → TOTP secret
	linuxTargets, nginxTarget []uuid.UUID
}

const f85Password = "correct horse battery staple, F-85"

func hostKey85(t *testing.T) providers.HostKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	k, err := ssh.NewPublicKey(pub)
	require.NoError(t, err)
	return providers.HostKey{Type: k.Type(), PublicKey: k.Marshal(), Fingerprint: ssh.FingerprintSHA256(k)}
}

func (f *f85) wire() {
	f.t.Helper()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	f.audit = audit.New(f.clk)
	f.lic = license.New(license.Config{Pool: f.db.App, Keyring: f.keyring, Audit: f.audit, Clock: f.clk, Uptime: f.clk,
		Keys: licensetest.KeySet(), StateDir: f.stateDir, Targets: inventory.Counter{}, Notifier: notify.AdminNotifier{Clock: f.clk}, Log: log})
	require.NoError(f.t, f.lic.Start(f.ctx))
	f.t.Cleanup(f.lic.Close)
	f.queue = jobs.NewQueue(jobs.QueueConfig{Pool: f.db.App, Keyring: f.keyring, Audit: f.audit, Clock: f.clk, Gate: f.lic})
	f.reg = providers.NewRegistry()
	f.reg.Register(worldProvider{Provider: f.linux})
	f.reg.Register(f.nginx)
	f.reg.Freeze()
	roots := x509.NewCertPool()
	roots.AddCert(f.ca.Root)
	f.inv = inventory.New(inventory.Config{Pool: f.db.App, Keyring: f.keyring, Audit: f.audit, Clock: f.clk, License: f.lic,
		Registry: f.reg, Jobs: f.queue, Notifier: notify.AdminNotifier{Clock: f.clk}, Log: log, Roots: roots})
	f.keys = sshkeys.New(sshkeys.Config{HelperBudget: helperproto.HelperBudget, Pool: f.db.App, Keyring: f.keyring, Audit: f.audit,
		Clock: f.clk, License: f.lic, Inventory: f.inv, Jobs: f.queue, Notifier: notify.AdminNotifier{Clock: f.clk}, Log: log})
	h := auth.NewHasher(auth.Argon2Params{MemoryKiB: 64, Time: 1, Threads: 1, SaltLen: 16, KeyLen: 32}, 4)
	f.auth = auth.NewService(auth.Config{Pool: f.db.App, Keyring: f.keyring, Audit: f.audit, Clock: f.clk, Hasher: h, RecoveryHasher: h})
	f.runner = jobs.NewRunner(jobs.RunnerConfig{Pool: f.db.App, Queue: f.queue, Gate: f.lic, Audit: f.audit, Clock: f.clk, Log: log,
		Workers: 1, WorkerID: "alice", Heartbeat: 24 * time.Hour, Jitter: func() float64 { return 0 }, Notifier: notify.AdminNotifier{Clock: f.clk}})
	targetjobs.Register(f.runner, targetjobs.Deps{Inventory: f.inv, Registry: f.reg, Clock: f.clk, Log: log})
	deployjobs.Register(f.runner, deployjobs.Deps{Inventory: f.inv, Registry: f.reg, Clock: f.clk, Log: log})
	sshkeyjobs.Register(f.runner, sshkeyjobs.Deps{Keys: f.keys, Targets: f.inv, Registry: f.reg, Clock: f.clk, Log: log, Gate: f.lic})
}

// drain evaluates the license, then runs due jobs until none is left.
func (f *f85) drain() {
	f.t.Helper()
	require.NoError(f.t, f.lic.Tick(f.ctx))
	for range 200 {
		ran, err := f.runner.RunOnce(f.ctx)
		require.NoError(f.t, err)
		if !ran {
			return
		}
	}
	f.t.Fatal("jobs did not drain")
}

func (f *f85) count(sql string, args ...any) int {
	f.t.Helper()
	var n int
	require.NoError(f.t, f.db.Owner.QueryRow(f.ctx, sql, args...).Scan(&n))
	return n
}

func newF85(t *testing.T) *f85 {
	t.Helper()
	f := &f85{t: t, ctx: context.Background(), db: pgtest.New(t), clk: clock.NewFake(time.Date(2026, 10, 5, 9, 0, 0, 0, time.UTC)),
		dir: t.TempDir(), keysDir: t.TempDir(), stateDir: t.TempDir(), world: fake.NewKeyWorld(), totpSecrets: map[string]string{},
		hkLinux: hostKey85(t), hkNginx: hostKey85(t)}
	f.world.SetClock(f.clk.Now)
	f.ca = pki.NewCA("F85", pki.ECDSA256, f.clk.Now())
	f.linux = fake.New(providers.KindLinuxSSH, providers.CapTestConnection, providers.CapDiscoverSSHKeys, providers.CapAuthorizedKeys,
		providers.CapKeyLogin)
	f.nginx = fake.New(providers.KindNginx, providers.CapTestConnection, providers.CapDiscoverSSHKeys, providers.CapAuthorizedKeys,
		providers.CapDiscoverCerts, providers.CapDeployCertificate, providers.CapVerifyDeployment)
	var err error
	f.keyring, err = secrets.LoadOrCreateMasterKey(f.ctx, f.db.App, f.keysDir, f.clk.Now())
	require.NoError(t, err)
	f.wire()
	return f
}

// setupAdmin runs the wizard's administrator and recovery-passphrase steps and returns the administrator's principal.
func (f *f85) setupAdmin() auth.Principal {
	f.t.Helper()
	h := auth.NewHasher(auth.Argon2Params{MemoryKiB: 64, Time: 1, Threads: 1, SaltLen: 16, KeyLen: 32}, 4)
	st := setup.New(setup.Config{Pool: f.db.App, Auth: f.auth, Keyring: f.keyring, Audit: f.audit, Clock: f.clk, Hasher: h, BackupKDF: fastKDF})
	code, err := st.ResetToken(f.ctx)
	require.NoError(f.t, err)
	meta := auth.Meta{RequestID: "f85"}
	token, err := st.StartSession(f.ctx, code, meta)
	require.NoError(f.t, err)
	enr, err := st.BeginAdminEnrollment(f.ctx, token, setup.AdminInput{Username: "admin1", DisplayName: "Ayşe Yılmaz",
		Email: "admin1@example.com", Password: f85Password})
	require.NoError(f.t, err)
	f.totpSecrets["admin1"] = enr.Secret
	c, err := totp.GenerateCode(enr.Secret, f.clk.Now())
	require.NoError(f.t, err)
	res, err := st.CreateAdmin(f.ctx, token, c, meta)
	require.NoError(f.t, err)
	p, err := f.auth.Authenticate(f.ctx, res.Token)
	require.NoError(f.t, err)
	require.NoError(f.t, st.SetRecoveryPassphrase(f.ctx, p, meta, passphrase, passphrase))
	f.admin = inventory.Actor{Audit: audit.Actor{Type: audit.ActorUser, ID: p.UserID, Name: p.Username}, UserID: p.UserID, Role: rbac.Admin}
	return p
}

// user creates a user and enrolls TOTP through the first sign-in.
func (f *f85) user(admin auth.Principal, name string, role rbac.Role) {
	f.t.Helper()
	meta := auth.Meta{RequestID: "f85-" + name}
	_, err := f.auth.CreateUser(f.ctx, admin, meta, auth.NewUser{Username: name, DisplayName: name, Email: name + "@example.com",
		Role: role, Password: f85Password})
	require.NoError(f.t, err)
	lr, err := f.auth.Login(f.ctx, name, f85Password, meta)
	require.NoError(f.t, err)
	require.Equal(f.t, auth.StatusMFAEnrollmentRequired, lr.Status)
	p, err := f.auth.AuthenticatePassive(f.ctx, lr.SessionToken)
	require.NoError(f.t, err)
	enr, err := f.auth.EnrollMFA(f.ctx, p, meta)
	require.NoError(f.t, err)
	c, err := totp.GenerateCode(enr.Secret, f.clk.Now())
	require.NoError(f.t, err)
	_, err = f.auth.VerifyMFA(f.ctx, p, auth.MFAInput{Code: c}, meta)
	require.NoError(f.t, err)
	f.totpSecrets[name] = enr.Secret
}

// signIn signs a user in with the password and a TOTP code computed from secret.
func (f *f85) signIn(name, secret string) auth.Principal {
	f.t.Helper()
	meta := auth.Meta{RequestID: "f85-signin"}
	lr, err := f.auth.Login(f.ctx, name, f85Password, meta)
	require.NoError(f.t, err)
	require.Equal(f.t, auth.StatusMFARequired, lr.Status)
	p, err := f.auth.AuthenticatePassive(f.ctx, lr.SessionToken)
	require.NoError(f.t, err)
	c, err := totp.GenerateCode(secret, f.clk.Now())
	require.NoError(f.t, err)
	res, err := f.auth.VerifyMFA(f.ctx, p, auth.MFAInput{Code: c}, meta)
	require.NoError(f.t, err)
	full, err := f.auth.AuthenticatePassive(f.ctx, res.Token)
	require.NoError(f.t, err)
	return full
}

func (f *f85) laptopLine() string {
	f.t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(f.t, err)
	sp, err := ssh.NewPublicKey(pub)
	require.NoError(f.t, err)
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sp))) + " someone@laptop"
}

// linuxTarget adds a Linux target whose key files the world holds (with a discovered key in deploy's file), lets the
// first test stop at the host key, confirms it, and runs the test and the first discovery.
func (f *f85) linuxTarget(name string) uuid.UUID {
	f.t.Helper()
	pk, err := f.inv.PlatformKey(f.ctx)
	require.NoError(f.t, err)
	f.linux.Configure(func(c *fake.Config) {
		c.World = f.world
		c.PresentedKey = f.hkLinux
		c.Report = providers.ConnectionReport{HostKey: f.hkLinux, HelperVersion: "1.0.0", HelperProtocol: 1}
		c.Discovery = providers.DiscoveryResult{SSHD: providers.SSHDSummary{Read: true, PubkeyAuthentication: "yes",
			PermitRootLogin: "prohibit-password", AuthorizedKeysFile: []string{".ssh/authorized_keys"}, AuthorizedKeysCommand: "none"}}
	})
	tg, _, err := f.inv.CreateTarget(f.ctx, f.admin, inventory.NewTarget{Name: name, Type: "linux", Host: name + ".example.test"})
	require.NoError(f.t, err)
	for _, u := range f85Users {
		switch u {
		case fake.ConnectionAccount:
			f.world.Put(tg.ID, u, keyFile85(u), pk.PublicKey)
		case "deploy":
			f.world.Put(tg.ID, u, keyFile85(u), f.laptopLine())
		default:
			f.world.Put(tg.ID, u, keyFile85(u))
		}
	}
	f.confirm(tg.ID)
	return tg.ID
}

func (f *f85) confirm(id uuid.UUID) {
	f.t.Helper()
	f.drain()
	recs, err := f.inv.ListHostKeys(f.ctx, id)
	require.NoError(f.t, err)
	require.Len(f.t, recs, 1)
	_, err = f.inv.ConfirmHostKey(f.ctx, f.admin, id, recs[0].ID, recs[0].Fingerprint)
	require.NoError(f.t, err)
	f.drain()
	tg, err := f.inv.GetTarget(f.ctx, id)
	require.NoError(f.t, err)
	require.Equal(f.t, inventory.StatusOK, tg.Status, "%s is connected and discovered", tg.Name)
}

var nginxFacts = &providers.NginxFacts{Found: true, ConfigValid: true, Version: "1.22.1"}

// nginxTargetWith adds an Nginx target serving leaf at /etc/nginx/ssl/www.crt.
func (f *f85) nginxTargetWith(name string, leaf pki.Leaf) uuid.UUID {
	f.t.Helper()
	pk, err := f.inv.PlatformKey(f.ctx)
	require.NoError(f.t, err)
	loc := providers.CertLocation{CertPath: "/etc/nginx/ssl/www.crt", KeyPath: "/etc/nginx/ssl/www.key", ResolvedCertPath: "/etc/nginx/ssl/www.crt",
		Supported: true, KeyExists: true, KeyMode: "0600", KeyOwner: "root", KeyGroup: "root",
		Servers: []providers.CertServer{{Names: []string{"www.example.test"}, Listens: []providers.CertListen{{Port: 443}},
			File: "/etc/nginx/sites-enabled/default", Line: 1}}}
	sum := sha256.Sum256(leaf.FullchainPEM)
	f.nginx.Configure(func(c *fake.Config) {
		c.PresentedKey = f.hkNginx
		c.Report = providers.ConnectionReport{HostKey: f.hkNginx, HelperVersion: "1.0.0", HelperProtocol: 1, Nginx: nginxFacts}
		c.Discovery = providers.DiscoveryResult{Nginx: nginxFacts,
			Certificates: []providers.DiscoveredCertificate{{Location: loc, PEMChain: leaf.FullchainPEM, FileSHA256: hex.EncodeToString(sum[:])}},
			SSHKeys: []providers.DiscoveredSSHKey{{OSUser: fake.ConnectionAccount, FilePath: keyFile85(fake.ConnectionAccount), LineNo: 1,
				PublicKey: pk.PublicKey, Fingerprint: pk.Fingerprint, KeyType: "ssh-ed25519", Bits: 256}},
			ReadFiles: []string{keyFile85(fake.ConnectionAccount)}, SSHD: providers.SSHDSummary{Read: true, AuthorizedKeysCommand: "none"}}
	})
	tg, _, err := f.inv.CreateTarget(f.ctx, f.admin, inventory.NewTarget{Name: name, Type: inventory.TypeNginx, Host: name + ".example.test"})
	require.NoError(f.t, err)
	f.confirm(tg.ID)
	return tg.ID
}

// place records the managed key in the user's file on the target and writes it into the world.
func (f *f85) place(k sshkeys.ManagedKey, target uuid.UUID, user string) {
	f.t.Helper()
	line, err := keymat.Line("", k.PublicKey, k.Comment)
	require.NoError(f.t, err)
	lines := append(f.world.Lines(target, keyFile85(user)), line)
	f.world.Put(target, user, keyFile85(user), lines...)
	require.NoError(f.t, db.InTx(f.ctx, f.db.App, func(tx pgx.Tx) error {
		_, err := f.inv.RecordKeyAddedTx(f.ctx, tx, inventory.KeyAdded{SSHKeyID: k.ID, TargetID: target, OSUser: user, FilePath: keyFile85(user),
			Comment: k.Comment, LineNo: len(lines), Actor: audit.SystemActor("test"), Verified: true})
		return err
	}))
}

func (f *f85) rotation(id uuid.UUID) sshkeys.Rotation {
	f.t.Helper()
	r, err := f.keys.Rotation(f.ctx, id)
	require.NoError(f.t, err)
	return r
}

// advanceRotation sweeps and drains a minute apart until the run reaches want (at most 120 rounds).
func (f *f85) advanceRotation(id uuid.UUID, want string, step time.Duration) sshkeys.Rotation {
	f.t.Helper()
	for range 120 {
		f.drain()
		if r := f.rotation(id); r.Status == want {
			return r
		}
		f.clk.Advance(step)
		require.NoError(f.t, f.lic.Tick(f.ctx)) // a running server evaluates at least hourly (AUD-02)
		_, err := f.keys.Sweep(f.ctx)
		require.NoError(f.t, err)
	}
	r := f.rotation(id)
	f.t.Fatalf("the rotation is %s, not %s", r.Status, want)
	return r
}

// secretHashes decrypts every envelope of the database with k and returns the SHA-256 of each plaintext by place.
func secretHashes(t *testing.T, ctx context.Context, q db.Querier, k *secrets.Keyring) map[string]string {
	t.Helper()
	out := map[string]string{}
	add := func(loc secrets.Location, env secrets.Envelope) {
		p, err := k.Open(loc, env)
		require.NoError(t, err, "%s/%s", loc.Table, loc.RowID)
		s := sha256.Sum256(p.Bytes())
		p.Zero()
		out[loc.Table+"/"+loc.RowID+"/"+loc.Column] = hex.EncodeToString(s[:])
	}
	for _, src := range []struct{ sql, table, column string }{
		{"SELECT id::text, ciphertext, nonce, wrapped_dek, key_version FROM credentials", "credentials", "ciphertext"},
		{"SELECT id::text, ciphertext, nonce, wrapped_dek, key_version FROM managed_private_keys", "managed_private_keys", "ciphertext"},
		{"SELECT user_id::text, totp_secret_ct, totp_nonce, totp_wrapped_dek, totp_key_version FROM user_mfa", "user_mfa", "totp_secret"},
		{"SELECT key, ciphertext, nonce, wrapped_dek, key_version FROM setting_secrets", "setting_secrets", "ciphertext"},
	} {
		rows, err := q.Query(ctx, src.sql)
		require.NoError(t, err)
		type row struct {
			id  string
			env secrets.Envelope
		}
		var all []row
		for rows.Next() {
			var r row
			require.NoError(t, rows.Scan(&r.id, &r.env.Ciphertext, &r.env.Nonce, &r.env.WrappedDEK, &r.env.KeyVersion))
			all = append(all, r)
		}
		require.NoError(t, rows.Err())
		rows.Close()
		require.NotEmpty(t, all, src.table)
		for _, r := range all {
			add(secrets.Location{Table: src.table, RowID: r.id, Column: src.column}, r.env)
		}
	}
	return out
}

func rowCounts(t *testing.T, ctx context.Context, q db.Querier) map[string]int64 {
	t.Helper()
	tables, err := dump.Tables(ctx, q)
	require.NoError(t, err)
	counts, err := dump.Counts(ctx, q, tables)
	require.NoError(t, err)
	return counts
}

// TestF85FullCycle is §20.6's full cycle in one process: a seeded installation is backed up, wiped (database dropped
// and recreated empty, keys and state directories deleted) and restored with the passphrase alone; then the same
// secrets decrypt, the chain continues, users sign in with their restored TOTP secrets, the Installation ID and the
// license are the same, and the in-progress rotation and a deployment run.
func TestF85FullCycle(t *testing.T) {
	f := newF85(t)
	adminP := f.setupAdmin()
	require.NoError(t, f.lic.Tick(f.ctx))
	installedID := f.lic.Snapshot().InstallationID
	payload := licensetest.Payload(installedID, f.clk.Now().Add(-time.Hour), f.clk.Now().AddDate(1, 0, 0), 100)
	_, err := f.lic.Install(f.ctx, licensetest.Sign(payload), f.admin.Audit, f.admin.UserID)
	require.NoError(t, err)
	require.NoError(t, f.lic.Tick(f.ctx))

	// Three users per role, each with TOTP.
	for _, n := range []string{"admin2", "admin3"} {
		f.user(adminP, n, rbac.Admin)
	}
	for i := 1; i <= 3; i++ {
		f.user(adminP, fmt.Sprintf("operator%d", i), rbac.Operator)
		f.user(adminP, fmt.Sprintf("auditor%d", i), rbac.Auditor)
	}

	// Ten targets with confirmed host keys: seven Linux servers (each with a discovered key) and three Nginx servers.
	_, err = f.inv.EnsurePlatformKey(f.ctx)
	require.NoError(t, err)
	for i := 1; i <= 7; i++ {
		f.linuxTargets = append(f.linuxTargets, f.linuxTarget(fmt.Sprintf("app-%02d", i)))
	}
	www := pki.Opts{CommonName: "www.example.test", SANs: []string{"www.example.test"}}
	served := f.ca.Issue(www, f.clk.Now())
	for i := 1; i <= 3; i++ {
		f.nginxTarget = append(f.nginxTarget, f.nginxTargetWith(fmt.Sprintf("web-%02d", i), served))
	}
	assert.Equal(t, 10, f.count("SELECT count(*) FROM targets"))
	assert.Equal(t, 10, f.count("SELECT count(*) FROM host_keys"))

	// Fifty certificates with private keys.
	for i := range 50 {
		leaf := f.ca.Issue(pki.Opts{CommonName: fmt.Sprintf("site-%02d.example.test", i), SANs: []string{fmt.Sprintf("site-%02d.example.test", i)}},
			f.clk.Now())
		_, _, err := f.inv.UploadCertificate(f.ctx, f.admin, inventory.UploadInput{CertificatePEM: string(leaf.FullchainPEM),
			PrivateKeyPEM: string(leaf.KeyPEM)})
		require.NoError(t, err)
	}

	// SSH keys: thirteen managed keys (one in rotation) beside the seven discovered ones.
	var managed []sshkeys.ManagedKey
	for i := range 13 {
		k, err := f.keys.Generate(f.ctx, f.admin, sshkeys.GenerateInput{Label: fmt.Sprintf("deploy key %02d", i)})
		require.NoError(t, err)
		managed = append(managed, k)
	}
	f.place(managed[0], f.linuxTargets[0], "deploy")
	f.place(managed[0], f.linuxTargets[1], "app")
	assert.GreaterOrEqual(t, f.count("SELECT count(*) FROM ssh_keys"), 20)
	p, err := f.keys.CreatePolicy(f.ctx, f.admin, sshkeys.PolicyInput{SSHKeyID: managed[0].ID, Name: "deploy key", IntervalDays: 90,
		OverlapDays: 7, NotifyBeforeHours: 24})
	require.NoError(t, err)
	pv, err := f.keys.Preview(f.ctx, f.admin, p.ID)
	require.NoError(t, err)
	run, err := f.keys.RunNow(f.ctx, f.admin, p.ID, pv.Digest)
	require.NoError(t, err)
	inOverlap := f.advanceRotation(run.ID, sshkeys.StatusOverlap, time.Minute)
	require.NotNil(t, inOverlap.OverlapUntil)

	// The SMTP password and at least 500 audit rows.
	smtp := secrets.NewPlaintext([]byte("smtp password F-85"))
	require.NoError(t, f.keyring.PutSetting(f.ctx, f.db.App, "notify.smtp.password", smtp, f.clk.Now()))
	for f.count("SELECT count(*) FROM audit_log") < 500 {
		require.NoError(t, db.InTx(f.ctx, f.db.App, func(tx pgx.Tx) error {
			_, err := f.audit.Append(f.ctx, tx, audit.Event{Actor: audit.SystemActor("test"), Action: "test.f85_filler", Result: audit.Success})
			return err
		}))
	}

	// The seeded set (§20.6).
	for role, n := range map[rbac.Role]int{rbac.Admin: 3, rbac.Operator: 3, rbac.Auditor: 3} {
		assert.Equal(t, n, f.count("SELECT count(*) FROM users u JOIN user_mfa m ON m.user_id = u.id WHERE u.role = $1 AND m.enrolled_at IS NOT NULL",
			string(role)), "%s users with TOTP", role)
	}
	assert.Equal(t, 50, f.count("SELECT count(*) FROM certificates WHERE private_key_id IS NOT NULL"))
	assert.Equal(t, 14, f.count("SELECT count(*) FROM ssh_keys WHERE managed"), "13 generated keys and the rotation's new one")
	assert.GreaterOrEqual(t, f.count("SELECT count(*) FROM ssh_keys WHERE NOT managed"), 7, "the discovered keys")
	assert.GreaterOrEqual(t, f.count("SELECT count(*) FROM audit_log"), 500)

	// What must come back.
	counts := rowCounts(t, f.ctx, f.db.Owner)
	hashes := secretHashes(t, f.ctx, f.db.Owner, f.keyring)
	var headSeq int64
	var headHash []byte
	require.NoError(t, f.db.Owner.QueryRow(f.ctx, "SELECT seq, hash FROM audit_log ORDER BY seq DESC LIMIT 1").Scan(&headSeq, &headHash))
	snap := f.lic.Snapshot()
	require.Equal(t, license.PhaseActive, snap.Eval.Phase)
	platform, err := f.inv.PlatformKey(f.ctx)
	require.NoError(t, err)

	cfg := backup.Config{Pool: f.db.App, Audit: f.audit, Notifier: notify.AdminNotifier{Clock: f.clk}, Clock: f.clk, Dir: f.dir,
		KeysDir: f.keysDir, StateDir: f.stateDir, Version: "1.0.0", Hostname: func() (string, error) { return "f85-host", nil }, Keyring: f.keyring}
	backup.SetStatfs(&cfg, func(string) (uint64, error) { return 100 << 30, nil })
	info, err := backup.New(cfg).Create(f.ctx, backup.CreateInput{Kind: backup.KindManual, Actor: audit.SystemActor("cli")})
	require.NoError(t, err)
	assert.Equal(t, counts, rowCountsWithout(t, f, "backup.created"), "the backup's own audit row came after the snapshot")

	// Wipe: the database is dropped and recreated empty, the keys and state directories are deleted.
	f.lic.Close()
	f.db.Owner.Close()
	f.db.App.Close()
	name := dbName(t, f.db.OwnerURL)
	super, err := db.Open(f.ctx, withDB(t, f.db.OwnerURL, "postgres", nil))
	require.NoError(t, err)
	defer super.Close()
	_, err = super.Exec(f.ctx, "DROP DATABASE "+pgx.Identifier{name}.Sanitize()+" WITH (FORCE)")
	require.NoError(t, err)
	_, err = super.Exec(f.ctx, "CREATE DATABASE "+pgx.Identifier{name}.Sanitize())
	require.NoError(t, err)
	require.NoError(t, os.RemoveAll(f.keysDir))
	require.NoError(t, os.RemoveAll(f.stateDir))
	require.NoError(t, os.Mkdir(f.keysDir, 0o700))
	require.NoError(t, os.Mkdir(f.stateDir, 0o700))

	f.clk.Advance(5 * time.Minute)
	rcfg := backup.Config{Clock: f.clk, Dir: f.dir, KeysDir: f.keysDir, StateDir: f.stateDir, Version: "1.0.0"}
	res, err := backup.Restore(f.ctx, rcfg, backup.RestoreInput{Path: info.Path, Passphrase: []byte(passphrase), OwnerURL: f.db.OwnerURL})
	require.NoError(t, err)
	assert.Empty(t, res.SafetyBackup, "an empty database has nothing to back up first")

	// Alice starts again on the restored installation.
	owner, err := db.Open(f.ctx, f.db.OwnerURL)
	require.NoError(t, err)
	t.Cleanup(owner.Close)
	app, err := db.Open(f.ctx, f.db.AppURL)
	require.NoError(t, err)
	t.Cleanup(app.Close)
	f.db.Owner, f.db.App = owner, app
	_, err = backup.FinishInterruptedRestore(f.ctx, f.db.App, f.keysDir, f.stateDir)
	require.NoError(t, err)
	f.keyring, err = secrets.LoadOrCreateMasterKey(f.ctx, f.db.App, f.keysDir, f.clk.Now())
	require.NoError(t, err, "the master key came back and opens the restored key check")
	f.wire()

	after := rowCounts(t, f.ctx, f.db.Owner)
	for tb, n := range counts {
		switch tb {
		case "sessions", "setup_sessions", "oidc_login_states":
			assert.Zero(t, after[tb], tb)
		case "audit_log":
			assert.Equal(t, n+1, after[tb], "one more audit row: system.restored")
		case "settings":
			assert.Equal(t, n+1, after[tb], "one more setting: backup.restore_id")
		default:
			assert.Equal(t, n, after[tb], tb)
		}
	}
	assert.Equal(t, hashes, secretHashes(t, f.ctx, f.db.Owner, f.keyring), "every secret decrypts to the same plaintext")
	rep, err := audit.Verify(f.ctx, f.db.Owner)
	require.NoError(t, err)
	assert.True(t, rep.Intact)
	var prevSeq int64
	var prevHash []byte
	require.NoError(t, f.db.Owner.QueryRow(f.ctx, "SELECT seq, hash FROM audit_log WHERE seq = $1", rep.HeadSeq-1).Scan(&prevSeq, &prevHash))
	assert.Equal(t, headSeq, prevSeq, "the head before system.restored is the recorded one")
	assert.Equal(t, headHash, prevHash)

	// A seeded Operator signs in with the password and a code from the restored TOTP secret.
	f.clk.Advance(time.Minute)
	op := f.signIn("operator2", f.totpSecrets["operator2"])
	assert.Equal(t, rbac.Operator, op.Role)

	// The Installation ID and the license are the same.
	got := f.lic.Snapshot()
	assert.Equal(t, installedID, got.InstallationID)
	assert.Equal(t, snap.Eval.Phase, got.Eval.Phase)
	require.NotNil(t, got.Eval.Current)
	assert.Equal(t, snap.Eval.Current.LicenseID, got.Eval.Current.LicenseID)
	assert.Equal(t, snap.Eval.DaysLeft, got.Eval.DaysLeft)
	assert.False(t, got.InstallationTampered)

	// The platform key's envelope opens to a private key whose public half is the recorded one.
	restored, err := f.inv.PlatformKey(f.ctx)
	require.NoError(t, err)
	assert.Equal(t, platform.PublicKey, restored.PublicKey)
	assert.Equal(t, platform.Fingerprint, ssh.FingerprintSHA256(platformSigner(t, f).PublicKey()))

	// The rotation goes on from its overlap and completes; a deployment runs against the fake provider.
	done := f.advanceRotation(run.ID, sshkeys.StatusCompleted, 24*time.Hour)
	assert.Equal(t, sshkeys.StatusCompleted, done.Status)
	assert.False(t, f.world.Has(f.linuxTargets[0], keyFile85("deploy"), managed[0].Fingerprint), "the old key was removed")
	newLeaf := f.ca.Issue(www, f.clk.Now())
	c, _, err := f.inv.UploadCertificate(f.ctx, f.admin, inventory.UploadInput{CertificatePEM: string(newLeaf.FullchainPEM),
		PrivateKeyPEM: string(newLeaf.KeyPEM)})
	require.NoError(t, err)
	locs, err := f.inv.ListLocations(f.ctx, f.nginxTarget[0], false)
	require.NoError(t, err)
	require.Len(t, locs.Items, 1)
	deps, err := f.inv.RequestDeployment(f.ctx, f.admin, inventory.DeployRequestInput{CertificateID: c.ID, LocationIDs: []uuid.UUID{locs.Items[0].ID}})
	require.NoError(t, err)
	require.Len(t, deps, 1)
	f.drain()
	var status string
	require.NoError(t, f.db.Owner.QueryRow(f.ctx, "SELECT status FROM deployments WHERE id = $1", deps[0].ID).Scan(&status))
	assert.Equal(t, "succeeded", status)
	assert.Equal(t, 1, f.nginx.Count("DeployCertificate"))
}

// rowCountsWithout is rowCounts less the audit rows of action.
func rowCountsWithout(t *testing.T, f *f85, action string) map[string]int64 {
	t.Helper()
	c := rowCounts(t, f.ctx, f.db.Owner)
	c["audit_log"] -= int64(f.count("SELECT count(*) FROM audit_log WHERE action = $1", action))
	c["settings"] -= int64(f.count("SELECT count(*) FROM settings WHERE key = 'backup.state'"))
	return c
}

// platformSigner opens the platform key's credential (its Ed25519 seed) with the restored master key.
func platformSigner(t *testing.T, f *f85) ssh.Signer {
	t.Helper()
	var id string
	var env secrets.Envelope
	require.NoError(t, f.db.Owner.QueryRow(f.ctx, "SELECT id::text, ciphertext, nonce, wrapped_dek, key_version FROM credentials WHERE purpose = 'platform_ssh'").
		Scan(&id, &env.Ciphertext, &env.Nonce, &env.WrappedDEK, &env.KeyVersion))
	p, err := f.keyring.Open(secrets.Location{Table: "credentials", RowID: id, Column: "ciphertext"}, env)
	require.NoError(t, err)
	defer p.Zero()
	require.Len(t, p.Bytes(), ed25519.SeedSize, "the platform key is stored as its Ed25519 seed")
	s, err := ssh.NewSignerFromKey(ed25519.NewKeyFromSeed(p.Bytes()))
	require.NoError(t, err)
	return s
}
