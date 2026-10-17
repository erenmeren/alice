// Package apache is the Apache httpd provider (discovery only): the shared web-server layer
// (internal/providers/webserver: session, test, certificate discovery) over alice-helper's
// apache-dump. It deploys nothing, verifies nothing and publishes no HTTP-01 tokens.
package apache

import (
	"context"

	"alice/internal/providers"
	"alice/internal/providers/linuxssh"
	"alice/internal/providers/linuxssh/helperproto"
	"alice/internal/providers/webserver"
)

// spec is Apache to the shared web-server layer. There is no configuration-test subcommand: the
// dump itself says whether the configuration is valid.
var spec = webserver.Spec{
	Kind:           providers.KindApache,
	DisplayNameKey: "provider.apache.name",
	Dump:           linuxssh.CmdApacheDump,
	Test:           nil,
	NotFoundCode:   helperproto.CodeSoftwareNotFound,
	MinProtocol:    helperproto.ApacheMinProtocol,
	Subcommands:    []string{helperproto.SubApacheDump},
	UsualFolders:   []string{"/etc/ssl/", "/etc/apache2/", "/etc/httpd/", "/etc/pki/", "/etc/letsencrypt/"},
}

// Options are the provider's dependencies.
type Options struct {
	SSH *linuxssh.Provider
}

// Provider is the Apache provider: the shared web-server Base and its capabilities.
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
