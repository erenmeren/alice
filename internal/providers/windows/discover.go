package windows

import (
	"context"

	"alice/internal/providers"
	"alice/internal/providers/windows/winproto"
)

// Discover reads the certificate half: iis-dump on a connection of its own, converted into one
// location per http.sys SSL binding (convert). A Windows server has no SSH key inventory (§2
// non-goal), so the SSH half sends nothing: a request for it alone is an empty result (the discovery
// job always asks for it), a request for neither half is not supported.
func (s *session) Discover(ctx context.Context, req providers.DiscoverRequest) (providers.DiscoveryResult, error) {
	if err := s.open(); err != nil {
		return providers.DiscoveryResult{}, err
	}
	if !req.Certificates {
		if !req.SSHKeys {
			return providers.DiscoveryResult{}, providers.ErrUnsupported
		}
		return providers.DiscoveryResult{}, nil
	}
	d, _, err := call[winproto.IISDumpResponse](ctx, s, winproto.SubIISDump)
	if err != nil {
		return providers.DiscoveryResult{}, err
	}
	certs, warns, facts := convert(d)
	return providers.DiscoveryResult{Certificates: certs, Warnings: warns, WebServer: &facts}, nil
}
