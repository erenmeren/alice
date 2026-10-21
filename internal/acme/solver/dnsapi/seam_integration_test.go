//go:build integration

package dnsapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTheIntegrationSeamMapsEveryNewClient(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) }))
	defer srv.Close()
	addr := srv.Listener.Addr().String()
	restore := MapAddressesForTest(func(hp string) string {
		if hp == "example.com:443" {
			return addr
		}
		return hp
	})
	defer restore()
	assert.Equal(t, addr, TestMappedAddr("example.com:443"))
	assert.Equal(t, "other:443", TestMappedAddr("other:443"))

	_, err := NewHTTPClient(HTTPOptions{Hosts: []string{"example.com"}})
	require.ErrorIs(t, err, ErrMapNeedsRoots, "a mapped client never uses the system roots")

	c, err := NewHTTPClient(HTTPOptions{Hosts: []string{"example.com"}, Roots: srvPool(srv)})
	require.NoError(t, err)
	req, err := http.NewRequest(http.MethodGet, "https://example.com/", nil)
	require.NoError(t, err)
	status, _, body, err := Do(context.Background(), c, req, "a.example")
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, status)
	assert.Equal(t, "ok", string(body))

	restore()
	assert.Equal(t, "example.com:443", TestMappedAddr("example.com:443"))
}
