package windows

import (
	"context"
	"slices"

	"alice/internal/providers"
	"alice/internal/providers/windows/winproto"
)

// Discover reads the certificate half: iis-dump on a connection of its own, converted into one
// location per http.sys SSL binding (convert), then the CCS files of ccs-dump on another (discoverCCS,
// W5 Ruling 18), then the Remote Desktop listener of rdp-dump on a third (discoverRDP, W6 Ruling 18), sorted
// together by cert path. A Windows server has no SSH key inventory (§2
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
	more, moreWarns, err := s.discoverCCS(ctx, d)
	if err != nil {
		return providers.DiscoveryResult{}, err
	}
	if len(more) > 0 {
		certs = append(certs, more...)
		sortByPath(certs)
	}
	rdp, rdpWarns, err := s.discoverRDP(ctx)
	if err != nil {
		return providers.DiscoveryResult{}, err
	}
	if len(rdp) > 0 {
		certs = append(certs, rdp...)
		sortByPath(certs)
	}
	for _, w := range slices.Concat(moreWarns, rdpWarns) {
		if !slices.ContainsFunc(warns, func(o providers.Warning) bool { return o.Code == w.Code }) {
			warns = append(warns, w)
		}
	}
	return providers.DiscoveryResult{Certificates: certs, Warnings: warns, WebServer: &facts}, nil
}
