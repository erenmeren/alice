// Package haproxy is the HAProxy provider (discovery only): the shared web-server layer
// (internal/providers/webserver: session, test, certificate discovery) over alice-helper's
// haproxy-dump. It deploys nothing, verifies nothing and publishes no HTTP-01 tokens.
package haproxy

import (
	"context"

	"alice/internal/providers"
	"alice/internal/providers/linuxssh"
	"alice/internal/providers/linuxssh/helperproto"
	"alice/internal/providers/webserver"
)

// spec is HAProxy to the shared web-server layer. There is no configuration-test subcommand: the
// dump itself says whether the configuration is valid (haproxy -c).
var spec = webserver.Spec{
	Kind:           providers.KindHAProxy,
	DisplayNameKey: "provider.haproxy.name",
	Dump:           linuxssh.CmdHAProxyDump,
	Test:           nil,
	NotFoundCode:   helperproto.CodeSoftwareNotFound,
	MinProtocol:    helperproto.HAProxyMinProtocol,
	Subcommands:    []string{helperproto.SubHAProxyDump},
	UsualFolders:   []string{"/etc/ssl/", "/etc/haproxy/", "/etc/pki/", "/etc/letsencrypt/"},
}

// Options are the provider's dependencies.
type Options struct {
	SSH *linuxssh.Provider
}

// Provider is the HAProxy provider: the shared web-server Base and its capabilities.
type Provider struct {
	webserver.Base
	caps providers.CapabilitySet
}

var (
	_ providers.Provider        = (*Provider)(nil)
	_ providers.ConnectionCache = (*Provider)(nil)
)

// New returns the provider. It advertises the shared web-server capabilities only. It panics on a
// nil Options.SSH (webserver.NewBase).
func New(o Options) *Provider {
	return &Provider{Base: webserver.NewBase(o.SSH, spec), caps: providers.NewCapabilitySet(webserver.BaseCapabilities()...)}
}

// Capabilities implements providers.Provider.
func (p *Provider) Capabilities() providers.CapabilitySet { return p.caps.Clone() }

// Open opens the shared web-server session. It returns the *webserver.Session itself, never a
// typed nil.
func (p *Provider) Open(ctx context.Context, t providers.TargetRef, cred providers.CredentialSource, env providers.Env) (providers.Session, error) {
	s, err := p.OpenSession(ctx, t, cred, env)
	if err != nil {
		return nil, err
	}
	return s, nil
}
