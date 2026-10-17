// Package webserver is the layer every web-server provider shares (spec §6.6, §12): a linuxssh
// session that tests the web server (its test subcommand proves the provider's sudoers profile),
// discovers its certificates from the helper's dump, converts the untrusted dump into locations
// and maps the shared helper answers to the provider's reasons (<kind>.not_found,
// <kind>.profile_missing, <kind>.config_invalid). A provider is a Spec plus what it adds: nginx
// embeds Base and Session and keeps deployment and verification.
package webserver

import (
	"context"
	"errors"
	"slices"
	"strconv"
	"sync/atomic"

	"github.com/google/uuid"

	"alice/internal/platform/validate"
	"alice/internal/providers"
	"alice/internal/providers/linuxssh"
	"alice/internal/providers/linuxssh/helperproto"
)

// Spec describes one web server to the shared layer.
type Spec struct {
	Kind           providers.Kind
	DisplayNameKey string
	// Dump answers helperproto.ServerDumpResponse, Test helperproto.NginxTestResponse. Test is
	// optional: without it the connection test runs Dump (a dump-only provider has no test
	// subcommand; a successful dump is a found server).
	Dump, Test func() linuxssh.HelperCommand
	// NotFoundCode is the helper code of "the software is not installed" (nginx:
	// helperproto.CodeNginxNotFound).
	NotFoundCode string
	// MinProtocol is the oldest helper protocol that has the provider's dump (at least
	// helperproto.MinProtocol): an older helper makes discovery <kind>.helper_too_old.
	MinProtocol int
	// Subcommands are every helper subcommand of the provider's sudoers profile: sudo refusing
	// one of them is <kind>.profile_missing.
	Subcommands []string
	// UsualFolders are the usual certificate folders: a resolved certificate outside them is a
	// custom location.
	UsualFolders []string
}

// Software is the web server's software name in WebServerFacts: the provider kind (spec §3.1).
func (s Spec) Software() string { return string(s.Kind) }

// SharedReason maps a shared helper answer of subcommand sub to the provider's reason: a sudo
// refusal of a profile subcommand is <kind>.profile_missing, a missing web server <kind>.not_found,
// an invalid configuration <kind>.config_invalid. nil when err is not one of them; the cause is kept.
func (s Spec) SharedReason(err error, sub string) *providers.Error {
	var pe *providers.Error
	if !errors.As(err, &pe) {
		return nil
	}
	switch {
	case pe.Code == "ssh.helper_missing" && pe.Params["exit_code"] == "1" && slices.Contains(s.Subcommands, sub):
		// sudo refused the command: the provider's profile is not installed.
		return providers.NewError(s.Kind.Reason(providers.ReasonProfileMissing), false, err,
			map[string]string{"subcommand": sub, "profile": s.Software()})
	case pe.Code != "ssh.helper_refused" && pe.Code != "ssh.file_changed":
		return nil
	}
	switch pe.Params["helper_code"] {
	case s.NotFoundCode:
		return providers.NewError(s.Kind.Reason(providers.ReasonNotFound), false, err, nil)
	case helperproto.CodeConfigInvalid:
		return providers.NewError(s.Kind.Reason(providers.ReasonConfigInvalid), false, err, nil)
	}
	return nil
}

// sharedOrSame is SharedReason when there is one, else err unchanged.
func (s Spec) sharedOrSame(err error, sub string) error {
	if pe := s.SharedReason(err, sub); pe != nil {
		return pe
	}
	return err
}

// BaseCapabilities are what every web-server provider implements through Base and Session: the
// linuxssh capabilities and certificate discovery.
func BaseCapabilities() []providers.Capability {
	return []providers.Capability{providers.CapTestConnection, providers.CapDiscoverSSHKeys, providers.CapAuthorizedKeys,
		providers.CapDiscoverCerts, providers.CapKeyLogin}
}

// Base is the shared half of a web-server provider: a web server is an SSH server, so the schemas,
// validation and connection pool are linuxssh's.
type Base struct {
	ssh  *linuxssh.Provider
	spec Spec
}

// NewBase returns the shared half for spec. It panics on a nil ssh provider or an incomplete
// spec (a programming error caught at start-up).
func NewBase(ssh *linuxssh.Provider, spec Spec) Base {
	switch {
	case ssh == nil:
		panic("webserver: NewBase without a linuxssh provider")
	case spec.Kind == "", spec.DisplayNameKey == "":
		panic("webserver: NewBase: a Spec needs Kind and DisplayNameKey")
	case spec.Dump == nil:
		panic("webserver: NewBase: a Spec needs Dump")
	case spec.NotFoundCode == "":
		panic("webserver: NewBase: a Spec needs its NotFoundCode")
	case spec.MinProtocol < helperproto.MinProtocol:
		panic("webserver: NewBase: a Spec's MinProtocol is below the helper's")
	case len(spec.Subcommands) == 0:
		panic("webserver: NewBase: a Spec needs its profile's Subcommands")
	}
	return Base{ssh: ssh, spec: spec}
}

// Kind implements providers.Provider.
func (b Base) Kind() providers.Kind { return b.spec.Kind }

// DisplayNameKey implements providers.Provider.
func (b Base) DisplayNameKey() string { return b.spec.DisplayNameKey }

// ConfigSchema implements providers.Provider: a web server is an SSH server.
func (b Base) ConfigSchema() providers.ConfigSchema { return b.ssh.ConfigSchema() }

// CredentialSchema implements providers.Provider.
func (b Base) CredentialSchema() providers.CredentialSchema { return b.ssh.CredentialSchema() }

// ValidateConfig implements providers.Provider.
func (b Base) ValidateConfig(cfg providers.TargetConfig) []validate.FieldError {
	return b.ssh.ValidateConfig(cfg)
}

// ForgetTarget implements providers.ConnectionCache: the pool belongs to the linuxssh provider.
func (b Base) ForgetTarget(target uuid.UUID) { b.ssh.ForgetTarget(target) }

// OpenSession opens a linuxssh session (same pool, pinned host key and helper protocol check) and
// keeps its connection for the web server's subcommands.
func (b Base) OpenSession(ctx context.Context, t providers.TargetRef, cred providers.CredentialSource, env providers.Env) (*Session, error) {
	s, err := b.ssh.Open(ctx, t, cred, env)
	if err != nil {
		return nil, err
	}
	conn, ok := linuxssh.ConnOf(s)
	if !ok {
		_ = s.Close()
		return nil, providers.NewError("ssh.unreachable", true, errors.New("webserver: the linuxssh session has no connection"), nil)
	}
	return &Session{Session: s, conn: conn, spec: b.spec}, nil
}

// Session is a linuxssh session with the web server's test and certificate discovery. It never
// keeps a helper command: commands are built where they are run.
type Session struct {
	providers.Session
	conn   *linuxssh.Conn
	spec   Spec
	closed atomic.Bool
}

var errSessionClosed = errors.New("webserver: session closed")

// Conn is the session's connection, for the provider's own subcommands (check Live first).
func (s *Session) Conn() *linuxssh.Conn { return s.conn }

// Live fails (ssh.unreachable) once the session is closed: its connection may already serve
// another session.
func (s *Session) Live() error {
	if s.closed.Load() {
		return providers.NewError("ssh.unreachable", false, errSessionClosed, nil)
	}
	return nil
}

// Close closes the linuxssh session, which gives its connection back to the pool.
func (s *Session) Close() error {
	s.closed.Store(true)
	return s.Session.Close()
}

// TestConnection is linuxssh's test plus the web server's test subcommand, which proves the
// provider's sudoers profile (F-14); a Spec without Test proves it with the dump. A missing web
// server, an invalid configuration and a helper too old for the provider are warnings, not
// failures.
func (s *Session) TestConnection(ctx context.Context) (providers.ConnectionReport, error) {
	if err := s.Live(); err != nil {
		return providers.ConnectionReport{}, err
	}
	rep, err := s.Session.TestConnection(ctx)
	if err != nil {
		return rep, err
	}
	if err := s.requireProtocol(ctx); err != nil {
		if isReason(err, s.spec.Kind.Reason(providers.ReasonHelperTooOld)) {
			rep.Warnings = append(rep.Warnings, warning(providers.WarnWebServerHelperTooOld))
			return rep, nil
		}
		return rep, err
	}
	if s.spec.Test == nil {
		return s.testFromDump(ctx, rep)
	}
	cmd := s.spec.Test()
	res, err := s.conn.Run(ctx, cmd)
	if err != nil {
		return rep, err
	}
	t, err := linuxssh.DecodeHelper[helperproto.NginxTestResponse](res, cmd.Subcommand())
	switch {
	case IsHelperCode(err, s.spec.NotFoundCode):
		rep.WebServer = &providers.WebServerFacts{Software: s.spec.Software()}
		rep.Warnings = append(rep.Warnings, warning(providers.WarnWebServerNotFound))
		return rep, nil
	case err != nil:
		return rep, s.spec.sharedOrSame(err, cmd.Subcommand())
	}
	rep.WebServer = &providers.WebServerFacts{Software: s.spec.Software(), Found: true, ConfigValid: t.Valid}
	if !t.Valid {
		rep.WebServer.ConfigError = knownOrEmpty(t.Error, configErrors)
		rep.Warnings = append(rep.Warnings, warning(providers.WarnWebServerConfigInvalid))
	}
	return rep, nil
}

// testFromDump is the connection test of a Spec without Test: the dump says whether the server is
// there and whether its configuration is valid.
func (s *Session) testFromDump(ctx context.Context, rep providers.ConnectionReport) (providers.ConnectionReport, error) {
	cmd := s.spec.Dump()
	out, err := s.conn.Run(ctx, cmd)
	if err != nil {
		return rep, err
	}
	d, err := linuxssh.DecodeHelper[helperproto.ServerDumpResponse](out, cmd.Subcommand())
	switch {
	case IsHelperCode(err, s.spec.NotFoundCode):
		rep.WebServer = &providers.WebServerFacts{Software: s.spec.Software()}
		rep.Warnings = append(rep.Warnings, warning(providers.WarnWebServerNotFound))
		return rep, nil
	case err != nil:
		return rep, s.spec.sharedOrSame(err, cmd.Subcommand())
	}
	facts := webServerFacts(s.spec.Software(), d)
	rep.WebServer = &facts
	if !d.ConfigValid {
		rep.Warnings = append(rep.Warnings, warning(providers.WarnWebServerConfigInvalid))
	}
	return rep, nil
}

// requireProtocol is <kind>.helper_too_old when the helper's protocol is below the Spec's
// MinProtocol (the protocol is the one stored at Open, else asked once).
func (s *Session) requireProtocol(ctx context.Context) error {
	p, err := s.conn.HelperProtocol(ctx)
	if err != nil {
		return err
	}
	if p < s.spec.MinProtocol {
		return providers.NewError(s.spec.Kind.Reason(providers.ReasonHelperTooOld), false, nil,
			map[string]string{"helper_protocol": strconv.Itoa(p), "required_protocol": strconv.Itoa(s.spec.MinProtocol)})
	}
	return nil
}

func isReason(err error, code string) bool {
	var pe *providers.Error
	return errors.As(err, &pe) && pe.Code == code
}

// Discover is linuxssh's discovery plus, when asked, the certificates of the dump (spec §12.4).
// Each half runs only when requested: a certificates-only request runs no SSH-key discovery, and
// an SSH-keys-only request runs no web-server command. A certificates-only result carries no SSH
// facts: HostKeys, SSHD, Accounts, AccountsComplete (false), UID0Users, ReadFiles and the SSH
// warnings are empty or unknown, not "none found". A caller must not overwrite stored host-key,
// sshd or account facts, or mark anything missing, from such a result. The web server missing
// fails the whole discovery (F-20: no partial data); an invalid, untrusted or unsupported
// configuration is a result that says so.
func (s *Session) Discover(ctx context.Context, req providers.DiscoverRequest) (providers.DiscoveryResult, error) {
	if err := s.Live(); err != nil {
		return providers.DiscoveryResult{}, err
	}
	if !req.Certificates {
		return s.Session.Discover(ctx, providers.DiscoverRequest{SSHKeys: req.SSHKeys})
	}
	// The web server first: when it is missing nothing else is worth reading.
	if err := s.requireProtocol(ctx); err != nil {
		return providers.DiscoveryResult{}, err
	}
	cmd := s.spec.Dump()
	out, err := s.conn.Run(ctx, cmd)
	if err != nil {
		return providers.DiscoveryResult{}, err
	}
	d, err := linuxssh.DecodeHelper[helperproto.ServerDumpResponse](out, cmd.Subcommand())
	if err != nil {
		return providers.DiscoveryResult{}, s.spec.sharedOrSame(err, cmd.Subcommand())
	}
	var res providers.DiscoveryResult
	if req.SSHKeys {
		if res, err = s.Session.Discover(ctx, providers.DiscoverRequest{SSHKeys: true}); err != nil {
			return providers.DiscoveryResult{}, err
		}
	}
	facts := webServerFacts(s.spec.Software(), d)
	res.WebServer = &facts
	if !d.ConfigValid {
		res.Warnings = append(res.Warnings, warning(providers.WarnWebServerConfigInvalid))
		warns, cut := dumpWarnings(d, nil)
		res.Warnings = append(res.Warnings, warns...)
		if cut {
			res.Warnings = append(res.Warnings, warning(providers.WarnListTruncated))
		}
		return res, nil
	}
	certs, warns := convert(d, s.spec.UsualFolders)
	res.Certificates = certs
	res.Warnings = append(res.Warnings, warns...)
	return res, nil
}

func warning(code string) providers.Warning {
	return providers.Warning{Code: code, Params: map[string]string{}}
}

// IsHelperCode reports whether err is a helper answer with the given code (the reason is
// ssh.helper_refused, or ssh.file_changed for HASH_MISMATCH).
func IsHelperCode(err error, code string) bool {
	var pe *providers.Error
	return errors.As(err, &pe) && pe.Params["helper_code"] == code
}
