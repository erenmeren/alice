package fakeacme

import (
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type ariDoc struct {
	SuggestedWindow struct {
		Start time.Time `json:"start"`
		End   time.Time `json:"end"`
	} `json:"suggestedWindow"`
}

func TestARI(t *testing.T) {
	s := start(t, Options{})
	c := newClient(t, s)
	register(t, c)
	der, _ := issue(t, s, c, nil, DNS01, "a.example.test")
	leaf := parseLeaf(t, der)

	var d map[string]any
	getJSON(t, s, s.DirectoryURL(), &d)
	url := d["renewalInfo"].(string) + "/" + ariID(leaf)

	var info ariDoc
	resp := getJSON(t, s, url, &info)
	assert.Equal(t, "21600", resp.Header.Get("Retry-After"))
	life := leaf.NotAfter.Sub(leaf.NotBefore)
	assert.WithinDuration(t, leaf.NotAfter.Add(-life/3), info.SuggestedWindow.Start, time.Second)
	assert.True(t, info.SuggestedWindow.End.After(info.SuggestedWindow.Start))

	// An absolute window.
	start0 := time.Now().Add(-time.Hour).Truncate(time.Second)
	require.NoError(t, s.SetARIWindow(start0, start0.Add(2*time.Hour)))
	getJSON(t, s, url, &info)
	assert.True(t, start0.Equal(info.SuggestedWindow.Start))
	assert.True(t, start0.Add(2*time.Hour).Equal(info.SuggestedWindow.End))
	require.Error(t, s.SetARIWindow(start0, start0))

	// Relative to each certificate's expiry.
	s.SetARIRelative(10*24*time.Hour, 6*time.Hour)
	getJSON(t, s, url, &info)
	assert.WithinDuration(t, leaf.NotAfter.Add(-10*24*time.Hour), info.SuggestedWindow.Start, time.Second)
	assert.Equal(t, 6*time.Hour, info.SuggestedWindow.End.Sub(info.SuggestedWindow.Start))

	// An unknown certificate.
	resp = getJSON(t, s, d["renewalInfo"].(string)+"/AAAA.BBBB", nil)
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	assert.Equal(t, 4, s.Counters()["ari"], "three answers, one refusal")
}

// An ARI GET needs no account: it is unauthenticated (RFC 9773).
func TestARIIsUnauthenticatedAndCounted(t *testing.T) {
	s := start(t, Options{})
	getJSON(t, s, s.BaseURL()+"/acme/renewal-info/x.y", nil)
	assert.Equal(t, 1, s.Counters()["ari"])
}
