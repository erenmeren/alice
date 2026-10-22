package windows

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"sync/atomic"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"

	"alice/internal/platform/validate"
	"alice/internal/providers"
	"alice/internal/providers/linuxssh"
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
}

// Provider is the Windows server provider (design 2026-10-21 §8, R60): OpenSSH on the server forces
// every session to alice-helper.exe, which reads the line Alice sends (Ruling 5).
type Provider struct {
	pool            *linuxssh.Pool
	caps            providers.CapabilitySet
	allowUnverified bool
}

var (
	_ providers.Provider        = (*Provider)(nil)
	_ providers.ConnectionCache = (*Provider)(nil)
	_ providers.Session         = (*session)(nil)
)

// New returns the provider. W1 advertises the connection test and certificate discovery only
// (Ruling 14); W2 adds deployment and verification.
func New(o Options) *Provider {
	return &Provider{pool: o.Pool, caps: providers.NewCapabilitySet(providers.CapTestConnection, providers.CapDiscoverCerts),
		allowUnverified: o.AllowUnverifiedHelper}
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
// the server presents now. The pool's dialer holds the host-key store, so env.HostKeys is not used.
func (p *Provider) Open(ctx context.Context, t providers.TargetRef, cred providers.CredentialSource, _ providers.Env) (providers.Session, error) {
	cfg, errs := ParseConfig(t.Config)
	if len(errs) > 0 {
		return nil, providers.NewError("target.invalid_config", false, validate.Errors(errs), nil)
	}
	s := &session{pool: p.pool, cfg: cfg, cred: cred, target: t.ID, caps: p.caps}
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
	pool    *linuxssh.Pool
	cfg     linuxssh.Config // Host is also the address of later probes
	cred    providers.CredentialSource
	target  uuid.UUID
	caps    providers.CapabilitySet
	version winproto.VersionResponse
	closed  atomic.Bool
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

// call runs one helper subcommand on a fresh connection of its own (Pool.AcquireFresh, one Run,
// release(false): the connection is closed, never kept idle) and decodes the answer. It returns the
// host key the connection was opened with. Errors pass through mapHelper.
func call[T any](ctx context.Context, s *session, sub string, args ...string) (T, providers.HostKey, error) {
	var zero T
	c, err := cmd(sub, args...)
	if err != nil {
		return zero, providers.HostKey{}, providers.NewError("internal.unexpected", false, err, map[string]string{"subcommand": sub})
	}
	conn, release, err := s.pool.AcquireFresh(ctx, s.target, s.cfg, s.cred)
	if err != nil {
		return zero, providers.HostKey{}, err
	}
	res, err := conn.Run(ctx, c)
	hk := conn.HostKey()
	release(false)
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
