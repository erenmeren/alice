package linuxssh

import (
	"context"
	"errors"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"

	"github.com/google/uuid"

	"alice/internal/platform/validate"
	"alice/internal/providers"
	"alice/internal/providers/linuxssh/helperproto"
)

// Options are the provider's dependencies.
type Options struct {
	Pool *Pool
	// AllowUnverifiedHelper lets a development build (version "dev") offer a setup script that
	// cannot check alice-helper because the build has no helper checksums (SetupScript).
	AllowUnverifiedHelper bool
}

// Provider is the linuxssh provider (spec §6.6, §13). It also prepares hosts (providers.SetupGuide).
type Provider struct {
	pool            *Pool
	caps            providers.CapabilitySet
	allowUnverified bool
}

var (
	_ providers.Provider        = (*Provider)(nil)
	_ providers.SetupGuide      = (*Provider)(nil)
	_ providers.ConnectionCache = (*Provider)(nil)
	_ providers.Session         = (*session)(nil)
)

// New returns the provider.
func New(o Options) *Provider {
	return &Provider{pool: o.Pool, caps: providers.NewCapabilitySet(providers.CapTestConnection, providers.CapDiscoverSSHKeys, providers.CapAuthorizedKeys, providers.CapKeyLogin),
		allowUnverified: o.AllowUnverifiedHelper}
}

// Kind implements providers.Provider.
func (p *Provider) Kind() providers.Kind { return providers.KindLinuxSSH }

// DisplayNameKey implements providers.Provider.
func (p *Provider) DisplayNameKey() string { return "provider.linuxssh.name" }

// Capabilities implements providers.Provider.
func (p *Provider) Capabilities() providers.CapabilitySet { return p.caps.Clone() }

// ConfigSchema implements providers.Provider.
func (p *Provider) ConfigSchema() providers.ConfigSchema {
	return providers.ConfigSchema{Fields: []providers.Field{
		{Name: "host", Type: providers.FieldHost, Required: true, Min: 1, Max: 253,
			LabelKey: "provider.linuxssh.fields.host.label", HelpKey: "provider.linuxssh.fields.host.help"},
		{Name: "port", Type: providers.FieldInt, Default: 22, Min: 1, Max: 65535,
			LabelKey: "provider.linuxssh.fields.port.label", HelpKey: "provider.linuxssh.fields.port.help"},
		{Name: "username", Type: providers.FieldString, Default: ServiceUser, Pattern: `^[a-z_][a-z0-9_-]{0,31}$`, Min: 1, Max: 32,
			LabelKey: "provider.linuxssh.fields.username.label", HelpKey: "provider.linuxssh.fields.username.help"},
	}}
}

// CredentialSchema implements providers.Provider: every target uses the platform key.
func (p *Provider) CredentialSchema() providers.CredentialSchema { return providers.CredentialSchema{} }

// ValidateConfig implements providers.Provider.
func (p *Provider) ValidateConfig(cfg providers.TargetConfig) []validate.FieldError {
	_, errs := ParseConfig(cfg)
	return errs
}

// SetupSnippets implements providers.SetupGuide. A profile's Script is "" when the line cannot be
// embedded in a shell script or the build cannot verify the helper (SetupScript refuses both).
func (p *Provider) SetupSnippets(authorizedKeysLine string) map[string]providers.SetupSnippet {
	out := map[string]providers.SetupSnippet{}
	for _, profile := range []string{"linux", "nginx", "apache"} {
		sudoers, _ := Sudoers(profile)
		script, _ := SetupScript(profile, authorizedKeysLine, p.allowUnverified)
		out[profile] = providers.SetupSnippet{Profile: profile, Sudoers: sudoers, Script: script}
	}
	return out
}

// ForgetTarget implements providers.ConnectionCache: a deleted target's pooled connections close.
func (p *Provider) ForgetTarget(target uuid.UUID) { p.pool.ForgetTarget(target) }

// HelperInfo implements providers.SetupGuide.
func (p *Provider) HelperInfo() (string, int) { return helperproto.HelperPath, helperproto.Protocol }

// Open connects through the pool (the pool's dialer holds the host-key store, so env.HostKeys is
// not used) and checks that alice-helper answers with a protocol this Alice can use. With
// env.FreshConnection it dials a new connection instead of reusing an idle one.
func (p *Provider) Open(ctx context.Context, t providers.TargetRef, cred providers.CredentialSource, env providers.Env) (providers.Session, error) {
	cfg, errs := ParseConfig(t.Config)
	if len(errs) > 0 {
		return nil, providers.NewError("target.invalid_config", false, validate.Errors(errs), nil)
	}
	acquire := p.pool.Acquire
	if env.FreshConnection {
		acquire = p.pool.AcquireFresh
	}
	conn, release, err := acquire(ctx, t.ID, cfg, cred)
	if err != nil {
		return nil, err
	}
	v, err := runHelper[helperproto.VersionResponse](ctx, conn, CmdVersion())
	if err != nil {
		release(conn.Healthy())
		return nil, err
	}
	// MinProtocol, not Protocol (A1): a helper that predates the HTTP-01 commands still serves every
	// other operation; PublishHTTP01Token and RemoveHTTP01Token check HTTP01MinProtocol themselves.
	if v.Protocol < helperproto.MinProtocol {
		release(true)
		return nil, providers.NewError("ssh.helper_outdated", false, nil, map[string]string{
			"helper_protocol": strconv.Itoa(v.Protocol), "required_protocol": strconv.Itoa(helperproto.MinProtocol)})
	}
	conn.helperProtocol.Store(int64(v.Protocol))
	v.Helper = cleanValue(v.Helper, 40)
	return &session{conn: conn, cfg: cfg, caps: p.caps, version: v, release: release, target: t.ID, dialer: p.pool.dialer}, nil
}

// session is one pooled connection to a linuxssh target.
type session struct {
	providers.UnsupportedSession
	conn    *Conn
	cfg     Config
	target  uuid.UUID // the target this session serves (a test login dials it afresh)
	dialer  *Dialer   // the pool's dialer: the same host-key store and address rule
	caps    providers.CapabilitySet
	version helperproto.VersionResponse
	release func(bool)
	once    sync.Once
	closed  atomic.Bool
}

var errSessionClosed = errors.New("linuxssh: session closed")

// Close returns the connection to the pool (closed when it is no longer healthy).
func (s *session) Close() error {
	s.once.Do(func() {
		s.closed.Store(true)
		s.release(s.conn.Healthy())
	})
	return nil
}

// open fails once the session is closed: its connection may already serve another session.
// Every exported session method calls it first.
func (s *session) open() error {
	if s.closed.Load() {
		return providers.NewError("ssh.unreachable", false, errSessionClosed, nil)
	}
	return nil
}

// TestConnection proves SSH, sudo and the helper work: os-release, then sshd-dump through sudo
// (spec §6.6: no "sudo -l"; a refused sudo shows as ssh.helper_missing).
func (s *session) TestConnection(ctx context.Context) (providers.ConnectionReport, error) {
	if err := s.open(); err != nil {
		return providers.ConnectionReport{}, err
	}
	osr, err := s.conn.OSRelease(ctx)
	if err != nil {
		return providers.ConnectionReport{}, err
	}
	d, err := runHelper[helperproto.SSHDDumpResponse](ctx, s.conn, CmdSSHDDump())
	if err != nil {
		return providers.ConnectionReport{}, err
	}
	rep := providers.ConnectionReport{
		HostKey: s.conn.HostKey(), HelperVersion: s.version.Helper, HelperProtocol: s.version.Protocol, OS: osr,
	}
	if d.Fallback {
		rep.Warnings = append(rep.Warnings, warn(helperproto.WarnSSHDUnreadable))
	}
	return rep, nil
}

// ListAuthorizedKeys returns the keys a full discovery finds. It belongs to the authorized_keys
// capability (list/add/remove, spec §6.1).
func (s *session) ListAuthorizedKeys(ctx context.Context) ([]providers.DiscoveredSSHKey, error) {
	if !s.caps.Has(providers.CapAuthorizedKeys) {
		return nil, providers.ErrUnsupported
	}
	if err := s.open(); err != nil {
		return nil, err
	}
	res, err := s.Discover(ctx, providers.DiscoverRequest{SSHKeys: true})
	if err != nil {
		return nil, err
	}
	return res.SSHKeys, nil
}

// ListKeys is ListAuthorizedKeys with the coverage of every candidate file, taken from what the
// helper's answer says and nothing more: a file in the discovery's ReadFiles was read completely
// (a listed file that does not exist counts: it holds nothing) unless the discovery reported a line
// of it that is neither a key, a comment nor blank (UnreadableLines), which makes it partial; a file that is not, in an answer the
// discovery marked Partial (a read failed, a bound cut it), is partial; one that is not in an answer
// that was not cut (too large, unparsable) is unread. A file the helper did not list for the account,
// or listed as unsupported, and an account the discovery skipped have no entry: unknown.
func (s *session) ListKeys(ctx context.Context) (providers.KeyListing, error) {
	if !s.caps.Has(providers.CapAuthorizedKeys) {
		return providers.KeyListing{}, providers.ErrUnsupported
	}
	if err := s.open(); err != nil {
		return providers.KeyListing{}, err
	}
	res, err := s.Discover(ctx, providers.DiscoverRequest{SSHKeys: true})
	if err != nil {
		return providers.KeyListing{}, err
	}
	l := providers.KeyListing{Keys: res.SSHKeys}
	for _, u := range res.KeyFiles {
		for _, f := range u.Files {
			st := providers.CoverageUnread
			switch {
			case slices.Contains(res.ReadFiles, f) && slices.ContainsFunc(res.UnreadableLines, func(u providers.UnreadableLine) bool { return u.FilePath == f }):
				st = providers.CoveragePartial // read, but a line was not understood: a key may be on it
			case slices.Contains(res.ReadFiles, f):
				st = providers.CoverageComplete
			case res.Partial:
				st = providers.CoveragePartial
			}
			l.Files = append(l.Files, providers.FileCoverage{OSUser: u.OSUser, FilePath: f, State: st})
		}
	}
	return l, nil
}

// ConnOf returns the connection of an open linuxssh session; the nginx provider runs its helper
// commands on it (spec §6.6: nginx is built on the linuxssh connector). A closed session has none:
// its connection may already serve another session.
func ConnOf(s providers.Session) (*Conn, bool) {
	ls, ok := s.(*session)
	if !ok || ls == nil || ls.closed.Load() {
		return nil, false
	}
	return ls.conn, true
}
