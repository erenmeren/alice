package scanpolicy_test

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/platform/netaddr"
	"alice/internal/testutil/scanpolicy"
)

func TestPermissive(t *testing.T) {
	p := scanpolicy.Permissive(netip.MustParsePrefix("127.0.0.2/32"))
	for a, want := range map[string]bool{
		"127.0.0.1": true, "::1": true, "10.0.0.1": true, "169.254.169.254": true,
		"127.0.0.2": false, "::ffff:127.0.0.2": false, "fe80::1%eth0": false,
	} {
		err := p.CheckScan(netip.MustParseAddr(a))
		if want {
			assert.NoError(t, err, a)
		} else {
			assert.ErrorIs(t, err, netaddr.ErrScanRefused, a)
		}
	}
	require.ErrorIs(t, p.CheckScan(netip.Addr{}), netaddr.ErrScanRefused)
	assert.Len(t, p.Checked(), 8)
}

// The permissive policy reaches a loopback listener through the production dial path, which the
// production policy refuses.
func TestPermissiveDialsLoopback(t *testing.T) {
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	p := scanpolicy.Permissive()
	c, err := netaddr.ScanDialContext(context.Background(), p, &net.Dialer{Timeout: 5 * time.Second}, "tcp", ln.Addr().String())
	require.NoError(t, err)
	_ = c.Close()
	assert.Equal(t, []netip.Addr{netip.MustParseAddr("127.0.0.1")}, p.Checked())
}
