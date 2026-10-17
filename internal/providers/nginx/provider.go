// Package nginx is the nginx provider (spec §6.6, §12): the shared web-server layer
// (internal/providers/webserver: session, test, certificate discovery) plus deployment, rollback
// and verification through alice-helper's nginx subcommands.
package nginx

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"alice/internal/platform/clock"
	"alice/internal/providers"
	"alice/internal/providers/linuxssh"
	"alice/internal/providers/linuxssh/helperproto"
	"alice/internal/providers/webserver"
)

// spec is Nginx to the shared web-server layer.
var spec = webserver.Spec{
	Kind:           providers.KindNginx,
	DisplayNameKey: "provider.nginx.name",
	Dump:           linuxssh.CmdNginxDump,
	Test:           linuxssh.CmdNginxTest,
	Subcommands: []string{helperproto.SubNginxDump, helperproto.SubNginxTest, helperproto.SubNginxDeploy, helperproto.SubNginxRestore,
		helperproto.SubNginxStatus, helperproto.SubNginxFence},
	UsualFolders: []string{"/etc/ssl/", "/etc/nginx/", "/etc/pki/", "/etc/letsencrypt/"},
}

// Options are the provider's dependencies.
type Options struct {
	SSH       *linuxssh.Provider
	Prober    Prober        // Alice's own TLS probe; nil = TLSProber{}
	RetryWait time.Duration // between verification attempts; 0 = 2 s
	Attempts  int           // verification attempts per endpoint; 0 = 5
}

// Provider is the nginx provider: the shared web-server Base (kind, schemas, validation, the
// connection pool) plus deployment and verification.
type Provider struct {
	webserver.Base
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

// New returns the provider. It advertises what it implements: the shared web-server capabilities
// (the linuxssh ones and certificate discovery), deployment (DeployCertificate, RollbackDeployment,
// DeploymentStatus), verification and the ACME HTTP-01 token publisher. It panics on a nil
// Options.SSH (webserver.NewBase).
func New(o Options) *Provider {
	p := &Provider{Base: webserver.NewBase(o.SSH, spec), prober: o.Prober, retryWait: o.RetryWait, attempts: o.Attempts,
		caps: providers.NewCapabilitySet(append(webserver.BaseCapabilities(),
			providers.CapDeployCertificate, providers.CapVerifyDeployment, providers.CapHTTP01)...)}
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

// Capabilities implements providers.Provider.
func (p *Provider) Capabilities() providers.CapabilitySet { return p.caps.Clone() }

// Open opens the shared web-server session (a linuxssh session: same pool, pinned host key and
// helper protocol check) and keeps the target's host for Alice's own TLS probes, the environment's
// clock (the real one when none is given) for the waits between verification attempts, and the
// environment's logger (none: discarded).
func (p *Provider) Open(ctx context.Context, t providers.TargetRef, cred providers.CredentialSource, env providers.Env) (providers.Session, error) {
	s, err := p.OpenSession(ctx, t, cred, env)
	if err != nil {
		return nil, err
	}
	cfg, _ := linuxssh.ParseConfig(t.Config) // valid: the linuxssh Open above refuses anything else
	clk := env.Clock
	if clk == nil {
		clk = clock.Real{}
	}
	log := env.Log
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &session{Session: s, p: p, host: cfg.Host, clock: clk, log: log}, nil
}

// session is the shared web-server session (test, discovery, Conn, Live, Close) with the
// deployment and verification methods. It never keeps a helper command: commands are built where
// they are run (a deploy command carries the key on its stdin).
type session struct {
	*webserver.Session
	p     *Provider
	host  string // the target's address, for Alice's own TLS probes
	clock clock.Clock
	log   *slog.Logger
}

// PublishHTTP01Token writes an HTTP-01 token file through the helper (linuxssh.Conn.PublishHTTP01Token: protocol 7,
// the fixed challenge directory; an older helper or sudoers file is ssh.helper_outdated_http01, ALC-SSH-0013). With
// RemoveHTTP01Token the session is the ACME HTTP-01 solver's publisher (http01.Publisher).
func (s *session) PublishHTTP01Token(ctx context.Context, token string, keyAuthorization []byte) error {
	if err := s.Live(); err != nil {
		return err
	}
	return s.Conn().PublishHTTP01Token(ctx, token, keyAuthorization)
}

// RemoveHTTP01Token removes the token file again (removed is false when there was none).
func (s *session) RemoveHTTP01Token(ctx context.Context, token string) (bool, error) {
	if err := s.Live(); err != nil {
		return false, err
	}
	return s.Conn().RemoveHTTP01Token(ctx, token)
}

// mapHelper maps the reasons of linuxssh's DecodeHelper for the Nginx subcommands to nginx.*
// reasons: first the shared web-server reasons (spec.SharedReason: nginx.profile_missing,
// nginx.not_found, nginx.config_invalid), then the deployment's own; every other error is returned
// unchanged. sub is the helper subcommand.
func mapHelper(err error, sub string) error {
	if pe := spec.SharedReason(err, sub); pe != nil {
		return pe
	}
	var pe *providers.Error
	if !errors.As(err, &pe) || (pe.Code != "ssh.helper_refused" && pe.Code != "ssh.file_changed") {
		return err
	}
	switch pe.Params["helper_code"] {
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
		// Alice's own recovery check; operation_id names it (the deploy engine restores it when Alice
		// no longer tracks it, fix round 1).
		var params map[string]string
		if op := pe.Params["operation_id"]; op != "" {
			params = map[string]string{"operation_id": op}
		}
		return providers.NewError("deployment.recovery_pending", false, err, params)
	case helperproto.CodeNginxNotRunning:
		return providers.NewError("nginx.not_running", false, err, nil)
	case helperproto.CodeFenced:
		// This operation was fenced by Alice's own recovery (AUD-05): it was never carried out.
		return providers.NewError("deployment.interrupted", false, err, nil)
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
