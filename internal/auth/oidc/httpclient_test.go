package oidc

import (
	"context"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Final review minor 1: the client of a token exchange or discovery is built per call, so it keeps no idle connection
// (and no reader and writer goroutine) once the answer is read: the provider's connection is closed after each call.
func TestHTTPClientKeepsNoIdleConnection(t *testing.T) {
	var mu sync.Mutex
	states := map[net.Conn]http.ConnState{}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "{}") }))
	srv.Config.ConnState = func(c net.Conn, st http.ConnState) {
		mu.Lock()
		defer mu.Unlock()
		states[c] = st
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	ca := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}))
	addr := srv.Listener.Addr().String()
	s := &Service{dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, addr)
	}}
	for range 3 {
		c, err := s.httpClient(ca)
		require.NoError(t, err)
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://example.com/", nil)
		require.NoError(t, err)
		res, err := c.Do(req)
		require.NoError(t, err)
		_, _ = io.Copy(io.Discard, res.Body)
		require.NoError(t, res.Body.Close())
	}
	assert.Eventually(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		for _, st := range states {
			if st != http.StateClosed {
				return false
			}
		}
		return len(states) == 3
	}, 5*time.Second, 10*time.Millisecond, "every connection is closed after its call")
}
