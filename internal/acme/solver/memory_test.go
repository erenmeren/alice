package solver

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var _ Solver = (*Memory)(nil)

func TestMemoryDefaultsAndTypes(t *testing.T) {
	m := NewMemory()
	assert.Equal(t, []string{DNS01, HTTP01}, m.Types())
	ts := m.Types()
	ts[0] = "x"
	assert.Equal(t, DNS01, m.Types()[0], "Types returns a copy")
	assert.Equal(t, []string{HTTP01}, NewMemory(HTTP01).Types())
}

func TestMemoryServesHTTP01(t *testing.T) {
	m := NewMemory()
	srv := httptest.NewServer(m)
	defer srv.Close()
	ch := Challenge{Type: HTTP01, Domain: "a.test", Token: "tok", KeyAuth: "tok.thumb", HTTPPath: HTTPPathPrefix + "tok"}
	require.NoError(t, m.Present(context.Background(), ch))
	assert.Equal(t, 1, m.Live())

	get := func(path string) (int, string) {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL+path, nil)
		require.NoError(t, err)
		res, err := srv.Client().Do(req)
		require.NoError(t, err)
		defer res.Body.Close()
		b, _ := io.ReadAll(res.Body)
		return res.StatusCode, string(b)
	}
	code, body := get(HTTPPathPrefix + "tok")
	assert.Equal(t, http.StatusOK, code)
	assert.Equal(t, "tok.thumb", body)
	code, _ = get(HTTPPathPrefix + "other")
	assert.Equal(t, http.StatusNotFound, code)
	code, _ = get("/tok")
	assert.Equal(t, http.StatusNotFound, code)

	require.NoError(t, m.CleanUp(context.Background(), ch))
	code, _ = get(HTTPPathPrefix + "tok")
	assert.Equal(t, http.StatusNotFound, code)
	assert.Equal(t, []Challenge{ch}, m.Presented())
	assert.Equal(t, []Challenge{ch}, m.CleanedUp())
	assert.Zero(t, m.Live())
}

func TestMemoryHooksAndFailure(t *testing.T) {
	m := NewMemory(DNS01)
	var after []string
	m.AfterPresent = func(_ context.Context, ch Challenge) error { after = append(after, "p:"+ch.DNSValue); return nil }
	m.AfterCleanUp = func(_ context.Context, ch Challenge) error {
		after = append(after, "c:"+ch.DNSValue)
		return errors.New("x")
	}
	ch := Challenge{Type: DNS01, Domain: "a.test", Token: "t", DNSName: "_acme-challenge.a.test", DNSValue: "v"}
	require.NoError(t, m.Present(context.Background(), ch))
	require.Error(t, m.CleanUp(context.Background(), ch))
	assert.Equal(t, []string{"p:v", "c:v"}, after)

	boom := errors.New("refused")
	m.PresentErr = boom
	require.ErrorIs(t, m.Present(context.Background(), ch), boom)
	assert.Len(t, m.Presented(), 2, "a failed Present is still recorded")
	assert.Len(t, after, 2, "AfterPresent does not run when Present fails")
}
