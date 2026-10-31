package windows

import (
	"context"
	"errors"
	"log/slog"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"

	"alice/internal/platform/clock"
	"alice/internal/platform/validate"
	"alice/internal/providers"
	"alice/internal/providers/linuxssh"
	"alice/internal/providers/tlspin"
	"alice/internal/providers/tlsverify"
	"alice/internal/providers/windows/winproto"
)

// Options are the provider's dependencies.
type Options struct {
	// Pool is the shared SSH connection pool (linuxssh's): its dialer holds the host-key store and the
	// target address rule, and its slots bound the connections to every target.
	Pool *linuxssh.Pool
	// AllowUnverifiedHelper lets a development build offer a setup script that cannot check
	// alice-helper.exe (the setup guide of a later task).
	AllowUnverifiedHelper bool
	// Prober is Alice's own TLS probe of a deployment's endpoints (nil = tlsverify.TLSProber{}).
	Prober tlsverify.Prober
	// RDPProber is Alice's own probe of the Remote Desktop listener, after the RDP negotiation (nil =
	// tlsverify.TLSProber{RDP: true}, W6 Ruling 15).
	RDPProber tlsverify.Prober
	// RetryWait is the wait between verification attempts (0 = 2 s); Attempts the attempts per endpoint (0 = 5).
	RetryWait time.Duration
	Attempts  int
}

// Provider is the Windows server provider (design 2026-10-21 §8, R60): OpenSSH on the server forces
// every session to alice-helper.exe, which reads the line Alice sends (Ruling 5).
type Provider struct {
	pool            *linuxssh.Pool
	caps            providers.CapabilitySet
	allowUnverified bool
	prober          tlsverify.Prober
	rdpProber       tlsverify.Prober
	retryWait       time.Duration
	attempts        int
	// The inline rollback's iis-restore is sent again while the helper answers BUSY: restoreAttempts
	// sends in all, restoreWait apart (3 and 10 s, as Nginx; tests lower the wait).
	restoreAttempts int
	restoreWait     time.Duration
}

var (
	_ providers.Provider           = (*Provider)(nil)
	_ providers.ConnectionCache    = (*Provider)(nil)
	_ providers.RollbackModel      = (*Provider)(nil)
	_ providers.Session            = (*session)(nil)
	_ providers.CertificateCleaner = (*session)(nil)
)

// guardsRollback: every helper Alice writes to checks the rollback guard itself on every restore path
// (W2 Ruling 11: the self-restore after a failed bind, iis-restore, a re-sent restore), from winproto 1
// on; a helper that could not is below WriteMinVersion and gets no write subcommand (writeReady).
const guardsRollback = true

// RollbackTraits implements providers.RollbackModel: the previous certificate stays in its store on the
// server (BackupOnTarget) and the helper may restore it by itself after a failed bind (SelfRestores);
// with guardsRollback a Required guard is satisfied (RollbackGuard.SatisfiedBy).
func (p *Provider) RollbackTraits() providers.RollbackTraits {
	return providers.RollbackTraits{Backup: providers.BackupOnTarget, SelfRestores: true}
}

// New returns the provider. It advertises what it implements: the connection test and certificate
// discovery (W1), deployment (DeployCertificate, RollbackDeployment, DeploymentStatus, FenceDeployment)
// and verification (W2, R61), and the certificate cleanup (PlanCleanup, ApplyCleanup: W3, R62).
func New(o Options) *Provider {
	p := &Provider{pool: o.Pool, caps: providers.NewCapabilitySet(providers.CapTestConnection, providers.CapDiscoverCerts,
		providers.CapDeployCertificate, providers.CapVerifyDeployment, providers.CapCleanupCertificates),
		allowUnverified: o.AllowUnverifiedHelper, prober: o.Prober, rdpProber: o.RDPProber, retryWait: o.RetryWait, attempts: o.Attempts,
		restoreAttempts: 3, restoreWait: 10 * time.Second}
	if p.prober == nil {
		p.prober = tlsverify.TLSProber{}
	}
	if p.rdpProber == nil {
		p.rdpProber = tlsverify.TLSProber{RDP: true}
	}
	if p.retryWait <= 0 {
		p.retryWait = 2 * time.Second
	}
	if p.attempts <= 0 {
		p.attempts = 5
	}
	return p
}

// Kind implements providers.Provider.
func (p *Provider) Kind() providers.Kind { return providers.KindWindows }

// DisplayNameKey implements providers.Provider.
func (p *Provider) DisplayNameKey() string { return "provider.windows.name" }

// Capabilities implements providers.Provider.
func (p *Provider) Capabilities() providers.CapabilitySet { return p.caps.Clone() }

// ConfigSchema implements providers.Provider: the Linux path's names (Ruling 1); username is the
// Windows account, a local name or DOMAIN\name.
func (p *Provider) ConfigSchema() providers.ConfigSchema {
	return providers.ConfigSchema{Fields: []providers.Field{
		{Name: "host", Type: providers.FieldHost, Required: true, Min: 1, Max: 253,
			LabelKey: "provider.windows.fields.host.label", HelpKey: "provider.windows.fields.host.help"},
		{Name: "port", Type: providers.FieldInt, Default: 22, Min: 1, Max: 65535,
			LabelKey: "provider.windows.fields.port.label", HelpKey: "provider.windows.fields.port.help"},
		{Name: "username", Type: providers.FieldString, Default: DefaultUser, Pattern: userRE.String(), Min: 1, Max: 36,
			LabelKey: "provider.windows.fields.username.label", HelpKey: "provider.windows.fields.username.help"},
		// R71 Ruling 2: under winrm the port defaults to DefaultWinRMPort and username also takes .\<SAM name> (ParseConfig).
		{Name: "transport", Type: providers.FieldEnum, Values: []string{TransportSSH, TransportWinRM}, Default: TransportSSH,
			LabelKey: "provider.windows.fields.transport.label", HelpKey: "provider.windows.fields.transport.help"},
	}}
}

// CredentialSchema implements providers.Provider: every target uses the platform key.
func (p *Provider) CredentialSchema() providers.CredentialSchema { return providers.CredentialSchema{} }

// ValidateConfig implements providers.Provider.
func (p *Provider) ValidateConfig(cfg providers.TargetConfig) []validate.FieldError {
	_, errs := ParseConfig(cfg)
	return errs
}

// ForgetTarget implements providers.ConnectionCache through the shared pool: a deleted target is
// not dialled again.
func (p *Provider) ForgetTarget(target uuid.UUID) { p.pool.ForgetTarget(target) }

// Open checks that alice-helper.exe answers with a protocol this Alice can use. Every helper call,
// this version call included, has its own fresh connection that is closed after its one command
// (design §8, W0: Windows OpenSSH hands every later session on a connection the first session's
// command), so env.FreshConnection needs nothing of its own: every call already sees the host key
// the server presents now. Under SSH the pool's dialer holds the host-key store, so env.HostKeys is
// not used; under WinRM (R71 Ruling 9) the session's tlspin.Verifier reads the pinned listener
// identity from env.HostKeys and records sightings there.
// The session keeps env.Clock (the real one when none) for the waits of a verification and of the
// inline rollback, and env.Log (none: discarded) for the verification's one warning.
func (p *Provider) Open(ctx context.Context, t providers.TargetRef, cred providers.CredentialSource, env providers.Env) (providers.Session, error) {
	cfg, errs := ParseConfig(t.Config)
	if len(errs) > 0 {
		return nil, providers.NewError("target.invalid_config", false, validate.Errors(errs), nil)
	}
	clk := env.Clock
	if clk == nil {
		clk = clock.Real{}
	}
	log := env.Log
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	s := &session{p: p, pool: p.pool, cfg: cfg, cred: cred, target: t.ID, caps: p.caps, clock: clk, log: log}
	s.run = s.sshRun
	if cfg.Transport == TransportWinRM {
		pin, err := tlspin.New(ctx, tlspin.Options{Target: t.ID, ServerName: cfg.Host, Store: env.HostKeys})
		if err != nil {
			return nil, err
		}
		s.pin, s.run = pin, s.winrmRun
	}
	v, _, err := call[winproto.VersionResponse](ctx, s, winproto.SubVersion)
	if err != nil {
		return nil, err
	}
	// MinProtocol, not Protocol: a newer helper serves an older Alice.
	if v.Protocol < winproto.MinProtocol {
		return nil, providers.NewError(ReasonHelperOutdated, false, nil, map[string]string{
			"helper_protocol": strconv.Itoa(v.Protocol), "required_protocol": strconv.Itoa(winproto.MinProtocol)})
	}
	v.Helper = cleanValue(v.Helper, 40)
	s.version = v
	return s, nil
}

// session is the scope of one Windows target. It holds no connection: each helper call dials.
type session struct {
	providers.UnsupportedSession
	p       *Provider
	pool    *linuxssh.Pool
	cfg     Config // Host is also the address of later probes
	cred    providers.CredentialSource
	target  uuid.UUID
	caps    providers.CapabilitySet
	version winproto.VersionResponse
	closed  atomic.Bool
	clock   clock.Clock
	log     *slog.Logger
	// run is the transport (R71 Ruling 10): sshRun, or winrmRun with pin, the listener's identity check.
	run func(ctx context.Context, c linuxssh.HelperCommand) (linuxssh.Result, providers.HostKey, error)
	pin *tlspin.Verifier
}

// writeReady refuses a helper older than winproto.WriteMinVersion before any write subcommand is sent
// (W2 Ruling 3): the version Open read, compared as dotted decimal; an unparsable version is below.
func (s *session) writeReady() error {
	if winproto.VersionAtLeast(s.version.Helper, winproto.WriteMinVersion) {
		return nil
	}
	return providers.NewError(ReasonHelperOutdated, false, nil, map[string]string{
		"helper_version": s.version.Helper, "required_version": winproto.WriteMinVersion})
}

var errSessionClosed = errors.New("windows: session closed")

// Close ends the session; it holds no connection, so nothing is released.
func (s *session) Close() error {
	s.closed.Store(true)
	return nil
}

// open fails once the session is closed. Every exported session method calls it first.
func (s *session) open() error {
	if s.closed.Load() {
		return providers.NewError("ssh.unreachable", false, errSessionClosed, nil)
	}
	return nil
}

// sshRun runs c on a fresh SSH connection of its own (Pool.AcquireFresh, one Run, release(false): the
// connection is closed, never kept idle) and returns the host key it was opened with. A connection
// that cannot be opened, or a context that ended before Run, is marked winrs.ErrNotSent.
func (s *session) sshRun(ctx context.Context, c linuxssh.HelperCommand) (linuxssh.Result, providers.HostKey, error) {
	conn, release, err := s.pool.AcquireFresh(ctx, s.target, s.cfg.Config, s.cred)
	if err != nil {
		return linuxssh.Result{}, providers.HostKey{}, markNotSent(err)
	}
	defer release(false)
	if err := ctx.Err(); err != nil {
		return linuxssh.Result{}, conn.HostKey(), markNotSent(providers.NewError("ssh.timeout", true, err, map[string]string{"subcommand": c.Subcommand()}))
	}
	res, err := conn.Run(ctx, c)
	return res, conn.HostKey(), err
}

// call runs one helper subcommand on a connection of its own (s.run) and decodes the answer. It
// returns the host key the connection was opened with. Errors pass through mapHelper.
func call[T any](ctx context.Context, s *session, sub string, args ...string) (T, providers.HostKey, error) {
	return callIn[T](ctx, s, sub, nil, args...)
}

// callIn is call with stdin (ccs-dump's password, W5 Ruling 11): the command's copy is wiped after the call; the
// caller clears its own buffer.
func callIn[T any](ctx context.Context, s *session, sub string, stdin []byte, args ...string) (T, providers.HostKey, error) {
	var zero T
	c, err := cmd(sub, stdin, args...)
	if err != nil {
		return zero, providers.HostKey{}, providers.NewError("internal.unexpected", false, err, map[string]string{"subcommand": sub})
	}
	defer c.WipeInput()
	res, hk, err := s.run(ctx, c)
	if err != nil {
		return zero, hk, mapHelper(err)
	}
	v, err := linuxssh.DecodeHelper[T](res, c.Subcommand())
	if err != nil {
		return zero, hk, mapHelper(err)
	}
	return v, hk, nil
}

// TestConnection reads win-facts: the operating system, the token's elevation, IIS and the machine
// stores (Ruling 19). An unelevated token fails the test with windows.not_elevated (Ruling 3), so the
// target's last error names it.
func (s *session) TestConnection(ctx context.Context) (providers.ConnectionReport, error) {
	if err := s.open(); err != nil {
		return providers.ConnectionReport{}, err
	}
	f, hk, err := call[winproto.WinFactsResponse](ctx, s, winproto.SubWinFacts)
	if err != nil {
		return providers.ConnectionReport{}, err
	}
	if !f.Elevated {
		return providers.ConnectionReport{}, providers.NewError(ReasonNotElevated, false, nil, map[string]string{"subcommand": winproto.SubWinFacts})
	}
	w, ws := facts(f)
	rep := providers.ConnectionReport{HostKey: hk, HelperVersion: s.version.Helper, HelperProtocol: s.version.Protocol,
		OS: providers.OSRelease{ID: "windows", VersionID: w.Build, PrettyName: w.Product}, Windows: w, WebServer: ws}
	if !ws.Found {
		rep.Warnings = append(rep.Warnings, providers.Warning{Code: providers.WarnWebServerNotFound, Params: map[string]string{}})
	}
	return rep, nil
}

// Bounds of the facts a connection test keeps.
const (
	maxStores      = 16
	maxFactLength  = 200
	maxStoreLength = 64
)

// facts turns win-facts into the report's facts: every string cleaned, at most maxStores stores.
func facts(f winproto.WinFactsResponse) (*providers.WindowsFacts, *providers.WebServerFacts) {
	w := &providers.WindowsFacts{Build: cleanValue(f.OSBuild, maxFactLength), Product: cleanValue(f.OSProduct, maxFactLength),
		InstallationType: cleanValue(f.InstallationType, maxFactLength), Elevated: f.Elevated, IISInstalled: f.IIS.Installed,
		IISVersion: cleanValue(f.IIS.Version, maxFactLength), Stores: []string{}, OpenSSHVersion: cleanValue(f.OpenSSHVersion, maxFactLength)}
	for _, st := range f.Stores {
		if len(w.Stores) == maxStores {
			break
		}
		if st = cleanValue(st, maxStoreLength); st != "" {
			w.Stores = append(w.Stores, st)
		}
	}
	ws := &providers.WebServerFacts{Software: "iis"}
	if f.IIS.Installed {
		ws.Version, ws.Found, ws.ConfigValid = w.IISVersion, true, true
	}
	return w, ws
}

// cleanValue makes remote text safe to store and show: invalid UTF-8 and control and format
// characters (terminal escapes, bidi marks) dropped, surrounding space trimmed, length limited in
// runes (linuxssh's rule, SC-4).
func cleanValue(v string, limit int) string {
	v = strings.ToValidUTF8(v, "")
	v = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return -1
		}
		return r
	}, v)
	v = strings.TrimSpace(v)
	if utf8.RuneCountInString(v) > limit {
		v = string([]rune(v)[:limit])
	}
	return v
}
