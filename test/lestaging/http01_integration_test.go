//go:build integration

package lestaging

import (
	"bytes"
	"context"
	"net"
	"net/netip"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/acme/solver"
	"alice/internal/acme/solver/http01"
	"alice/internal/platform/netaddr/netaddrtest"
	"alice/internal/testutil/fakeacme"
)

// The HTTP-01 path with the real http01 solver: the harness's local listener publishes the tokens, the solver checks
// the token URL itself (pointed at the listener by the integration-only seam) and the fake CA validates over HTTP.
func TestFullRunWithHTTP01AndTheLocalListener(t *testing.T) {
	s := startFake(t, fakeacme.Options{})
	cfg := fakeConfig(t, s)
	cfg.Challenge, cfg.DNSProvider, cfg.HTTP01Listen = solver.HTTP01, "", "127.0.0.1:0"
	var out bytes.Buffer
	r, err := NewRunner(cfg, &out)
	require.NoError(t, err)
	var port int
	var checks atomic.Int64
	r.onListen = func(addr string) {
		s.SetHTTPTarget(testDomain, addr)
		_, p, err := net.SplitHostPort(addr)
		require.NoError(t, err)
		port, err = strconv.Atoi(p)
		require.NoError(t, err)
	}
	r.http01Seam = func(sol *http01.Solver) {
		http01.SetTestTarget(sol, port, netaddrtest.Resolver(func(string) []netip.Addr {
			checks.Add(1)
			return []netip.Addr{netip.MustParseAddr("127.0.0.1")}
		}))
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	rep := r.Run(ctx)
	require.True(t, rep.OK(), out.String())
	assert.Positive(t, checks.Load(), "the solver checked the token URL itself")
	assert.Contains(t, out.String(), "2 challenge(s) presented and removed")
}
