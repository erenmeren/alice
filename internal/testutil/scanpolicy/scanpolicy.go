// Package scanpolicy is a test helper: a netaddr.ScanPolicy that lets discovery tests scan the
// loopback fleet the production policy always refuses (plan 2026-10-13, amendment A2: injected, no
// build tag). It is a test-only package (internal/archtest testOnlyDirs): no release binary links it.
package scanpolicy

import (
	"fmt"
	"net/netip"
	"sync"

	"alice/internal/platform/netaddr"
)

// Policy allows every valid, zone-free address except the ones in its exception prefixes, and
// records every address it was asked about.
type Policy struct {
	except []netip.Prefix

	mu      sync.Mutex
	checked []netip.Addr
}

// Permissive returns a Policy that refuses only the addresses inside except (each also matched in
// its IPv4-mapped form), so a test can prove an excluded address is never dialed.
func Permissive(except ...netip.Prefix) *Policy { return &Policy{except: except} }

// CheckScan implements netaddr.ScanPolicy. A refusal matches netaddr.ErrScanRefused.
func (p *Policy) CheckScan(a netip.Addr) error {
	p.mu.Lock()
	p.checked = append(p.checked, a)
	p.mu.Unlock()
	if !a.IsValid() || a.Zone() != "" {
		return fmt.Errorf("%w: %s", netaddr.ErrScanRefused, a)
	}
	for _, e := range p.except {
		if e.Contains(a) || e.Contains(a.Unmap()) {
			return fmt.Errorf("%w: %s (test exception)", netaddr.ErrScanRefused, a)
		}
	}
	return nil
}

// Checked returns the addresses CheckScan was asked about, in order.
func (p *Policy) Checked() []netip.Addr {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]netip.Addr(nil), p.checked...)
}

var _ netaddr.ScanPolicy = (*Policy)(nil)
