// Package nginx is the nginx provider (spec §6.6, §12): a linuxssh session plus certificate
// discovery, deployment, rollback and verification through alice-helper's nginx subcommands.
package nginx

import (
	"context"
	"errors"
	"sync/atomic"
	"time"

	"github.com/google/uuid"

	"alice/internal/platform/clock"
	"alice/internal/platform/validate"
	"alice/internal/providers"
	"alice/internal/providers/linuxssh"
	"alice/internal/providers/linuxssh/helperproto"
)

// Options are the provider's dependencies.
type Options struct {
	SSH       *linuxssh.Provider
	Prober    Prober        // Alice's own TLS probe; nil = TLSProber{}
	RetryWait time.Duration // between verification attempts; 0 = 2 s
	Attempts  int           // verification attempts per endpoint; 0 = 5
}

// Provider is the nginx provider.
type Provider struct {
	ssh       *linuxssh.Provider
	prober    Prober
	retryWait time.Duration
	attempts  int
	// The inline rollback's nginx-restore is sent again while the helper answers BUSY:
	// restoreAttempts sends in all, restoreWait apart (3 and 10 s).
	restoreAttempts int
	restoreWait     time.Duration
	caps            providers.CapabilitySet
}

var (
	_ providers.Provider        = (*Provider)(nil)
	_ providers.ConnectionCache = (*Provider)(nil)
	_ providers.Session         = (*session)(nil)
)

// New returns the provider. It advertises what it implements: the linuxssh capabilities, certificate
// discovery, deployment (DeployCertificate, RollbackDeployment, DeploymentStatus) and verification.
func New(o Options) *Provider {
	p := &Provider{ssh: o.SSH, prober: o.Prober, retryWait: o.RetryWait, attempts: o.Attempts,
		caps: providers.NewCapabilitySet(providers.CapTestConnection, providers.CapDiscoverSSHKeys, providers.CapAuthorizedKeys,
			providers.CapDiscoverCerts, providers.CapDeployCertificate, providers.CapVerifyDeployment)}
	if p.prober == nil {
		p.prober = TLSProber{}
	}
	p.restoreAttempts, p.restoreWait = 3, 10*time.Second
	if p.retryWait <= 0 {
		p.retryWait = 2 * time.Second
	}
	if p.attempts <= 0 {
		p.attempts = 5
	}
	return p
}

// Kind implements providers.Provider.
func (p *Provider) Kind() providers.Kind { return providers.KindNginx }

// DisplayNameKey implements providers.Provider.
func (p *Provider) DisplayNameKey() string { return "provider.nginx.name" }

// Capabilities implements providers.Provider.
func (p *Provider) Capabilities() providers.CapabilitySet { return p.caps.Clone() }

// ConfigSchema implements providers.Provider: an Nginx server is an SSH server.
func (p *Provider) ConfigSchema() providers.ConfigSchema { return p.ssh.ConfigSchema() }

// CredentialSchema implements providers.Provider.
func (p *Provider) CredentialSchema() providers.CredentialSchema { return p.ssh.CredentialSchema() }

// ValidateConfig implements providers.Provider.
func (p *Provider) ValidateConfig(cfg providers.TargetConfig) []validate.FieldError {
	return p.ssh.ValidateConfig(cfg)
}

// ForgetTarget implements providers.ConnectionCache: the pool belongs to the linuxssh provider.
func (p *Provider) ForgetTarget(target uuid.UUID) { p.ssh.ForgetTarget(target) }

// Open opens a linuxssh session (same pool, pinned host key and helper protocol check) and keeps
// its connection for the Nginx subcommands, the target's host for Alice's own TLS probes and the
// environment's clock (the real one when none is given) for the waits between verification
// attempts.
func (p *Provider) Open(ctx context.Context, t providers.TargetRef, cred providers.CredentialSource, env providers.Env) (providers.Session, error) {
	s, err := p.ssh.Open(ctx, t, cred, env)
	if err != nil {
		return nil, err
	}
	conn, ok := linuxssh.ConnOf(s)
	if !ok {
		_ = s.Close()
		return nil, providers.NewError("ssh.unreachable", true, errors.New("nginx: the linuxssh session has no connection"), nil)
	}
	cfg, _ := linuxssh.ParseConfig(t.Config) // valid: the linuxssh Open above refuses anything else
	clk := env.Clock
	if clk == nil {
		clk = clock.Real{}
	}
	return &session{Session: s, conn: conn, p: p, host: cfg.Host, clock: clk}, nil
}

// session is a linuxssh session with the certificate methods. It never keeps a helper command:
// commands are built where they are run (a deploy command carries the key on its stdin).
type session struct {
	providers.Session
	conn   *linuxssh.Conn
	p      *Provider
	host   string // the target's address, for Alice's own TLS probes
	clock  clock.Clock
	closed atomic.Bool
}

var errSessionClosed = errors.New("nginx: session closed")

// Close closes the linuxssh session, which gives its connection back to the pool.
func (s *session) Close() error {
	s.closed.Store(true)
	return s.Session.Close()
}

// open fails once the session is closed: its connection may already serve another session.
func (s *session) open() error {
	if s.closed.Load() {
		return providers.NewError("ssh.unreachable", false, errSessionClosed, nil)
	}
	return nil
}

// TestConnection is linuxssh's test plus nginx-test, which proves the nginx sudoers profile (F-14).
// A missing Nginx or an invalid configuration is a warning, not a failure.
func (s *session) TestConnection(ctx context.Context) (providers.ConnectionReport, error) {
	if err := s.open(); err != nil {
		return providers.ConnectionReport{}, err
	}
	rep, err := s.Session.TestConnection(ctx)
	if err != nil {
		return rep, err
	}
	res, err := s.conn.Run(ctx, linuxssh.CmdNginxTest())
	if err != nil {
		return rep, err
	}
	t, err := linuxssh.DecodeHelper[helperproto.NginxTestResponse](res, helperproto.SubNginxTest)
	switch {
	case isHelperCode(err, helperproto.CodeNginxNotFound):
		rep.Nginx = &providers.NginxFacts{}
		rep.Warnings = append(rep.Warnings, warning("nginx_not_found"))
		return rep, nil
	case err != nil:
		return rep, mapHelper(err, helperproto.SubNginxTest)
	}
	rep.Nginx = &providers.NginxFacts{Found: true, ConfigValid: t.Valid}
	if !t.Valid {
		rep.Nginx.ConfigError = knownOrEmpty(t.Error, configErrors)
		rep.Warnings = append(rep.Warnings, warning("nginx_config_invalid"))
	}
	return rep, nil
}

func warning(code string) providers.Warning {
	return providers.Warning{Code: code, Params: map[string]string{}}
}

// isHelperCode reports whether err is a helper answer with the given code (the reason is
// ssh.helper_refused, or ssh.file_changed for HASH_MISMATCH).
func isHelperCode(err error, code string) bool {
	var pe *providers.Error
	return errors.As(err, &pe) && pe.Params["helper_code"] == code
}

// mapHelper maps the reasons of linuxssh's DecodeHelper for the Nginx subcommands to nginx.*
// reasons; every other error is returned unchanged. sub is the helper subcommand.
func mapHelper(err error, sub string) error {
	var pe *providers.Error
	if !errors.As(err, &pe) {
		return err
	}
	code := pe.Params["helper_code"]
	switch {
	case pe.Code == "ssh.helper_missing" && pe.Params["exit_code"] == "1" && isNginxSub(sub):
		// sudo refused the command: the nginx profile is not installed.
		return providers.NewError("nginx.profile_missing", false, err, map[string]string{"subcommand": sub, "profile": "nginx"})
	case pe.Code != "ssh.helper_refused" && pe.Code != "ssh.file_changed":
		return err
	}
	switch code {
	case helperproto.CodeNginxNotFound:
		return providers.NewError("nginx.not_found", false, err, nil)
	case helperproto.CodeConfigInvalid:
		return providers.NewError("nginx.config_invalid", false, err, nil)
	case helperproto.CodeConfigChanged:
		return providers.NewError("nginx.config_changed", false, err, nil)
	case helperproto.CodeHashMismatch:
		return providers.NewError("nginx.file_changed", false, err, nil)
	case helperproto.CodeNoSpace:
		return providers.NewError("nginx.no_space", false, err, nil)
	case helperproto.CodeBusy:
		return providers.NewError("nginx.busy", true, err, nil)
	case helperproto.CodeRecoveryPending:
		// The pair's latest operation on the server was interrupted (A1 m1): the same reason as
		// Alice's own recovery check.
		return providers.NewError("deployment.recovery_pending", false, err, nil)
	case helperproto.CodeNginxNotRunning:
		return providers.NewError("nginx.not_running", false, err, nil)
	case helperproto.CodeIOError:
		if sub != helperproto.SubNginxDeploy {
			return err // a killed or timed-out nginx: the retryable ssh.helper_refused stays
		}
		// nginx-deploy's IO_ERROR has several causes the answer does not tell apart (Alice keeps the
		// code only, never the message): a folder that cannot be written, nginx killed or timed out
		// during -V/-T, the journal, backup or lock unreadable, stdin unreadable, the budget ended
		// before the first rename. Nothing was changed; a neutral, retryable reason.
		return providers.NewError("nginx.io_error", true, err, nil)
	case helperproto.CodePathNotAllowed, helperproto.CodeUnsafeFile, helperproto.CodeNotRegularFile, helperproto.CodeNotFound, helperproto.CodeTooLarge:
		return providers.NewError("nginx.location_unsupported", false, err, nil)
	case helperproto.CodeBadContent:
		return providers.NewError("certificate.invalid", false, err, nil)
	}
	return err
}

func isNginxSub(sub string) bool {
	switch sub {
	case helperproto.SubNginxDump, helperproto.SubNginxTest, helperproto.SubNginxDeploy, helperproto.SubNginxRestore, helperproto.SubNginxStatus:
		return true
	}
	return false
}
