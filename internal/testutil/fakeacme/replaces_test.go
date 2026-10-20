package fakeacme

import (
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/acme"
)

// newOrderWith posts a newOrder for names with the replaces field as c's account and returns the status and document.
func newOrderWith(t *testing.T, s *Server, c *acme.Client, replaces string, names ...string) (int, map[string]any) {
	t.Helper()
	ids := ""
	for i, n := range names {
		if i > 0 {
			ids += ","
		}
		ids += `{"type":"dns","value":"` + n + `"}`
	}
	payload := `{"identifiers":[` + ids + `],"replaces":"` + replaces + `"}`
	url := s.BaseURL() + "/acme/new-order"
	return rawPost(t, s, url, "application/jose+json", signedBody(t, c, url, nonceOf(t, s), payload))
}

// RFC 9773 section 5: the fake checks the replaces field (a certificate it issued, to this account, sharing a name),
// records it, and answers alreadyReplaced (409) to a second order replacing the same certificate while the first is
// not invalid.
func TestNewOrderReplaces(t *testing.T) {
	s := start(t, Options{})
	c := newClient(t, s)
	register(t, c)
	der, _ := issue(t, s, c, nil, DNS01, "a.example.test", "b.example.test")
	id := ariID(parseLeaf(t, der))

	status, doc := newOrderWith(t, s, c, id, "a.example.test")
	require.Equal(t, http.StatusCreated, status, doc)
	assert.Equal(t, id, doc["replaces"], "the order echoes the field")
	rs := s.Replacements()
	require.Len(t, rs, 1)
	assert.Equal(t, id, rs[0].CertID)
	assert.NotEmpty(t, rs[0].OrderID)

	status, doc = newOrderWith(t, s, c, id, "b.example.test")
	assert.Equal(t, http.StatusConflict, status)
	assert.Equal(t, "urn:ietf:params:acme:error:alreadyReplaced", doc["type"])
	assert.Len(t, s.Replacements(), 1, "a refused order is not recorded")

	// An order that became invalid does not count (RFC 9773 section 5): the certificate may be replaced again.
	s.mu.Lock()
	s.st.orders[rs[0].OrderID].status = "invalid"
	s.mu.Unlock()
	status, doc = newOrderWith(t, s, c, id, "b.example.test")
	assert.Equal(t, http.StatusCreated, status, doc)
	assert.Len(t, s.Replacements(), 2)

	// Refusals: garbage, a certificate the CA never issued, no shared name, another account.
	for _, bad := range []string{"nodot", "a.b.c", "!!.??", "AAAA.BBBB"} {
		status, doc = newOrderWith(t, s, c, bad, "a.example.test")
		assert.Equal(t, http.StatusBadRequest, status, bad)
		assert.Equal(t, "urn:ietf:params:acme:error:malformed", doc["type"], bad)
	}
	der2, _ := issue(t, s, c, nil, DNS01, "c.example.test")
	status, doc = newOrderWith(t, s, c, ariID(parseLeaf(t, der2)), "d.example.test")
	assert.Equal(t, http.StatusBadRequest, status)
	assert.Equal(t, "urn:ietf:params:acme:error:malformed", doc["type"])
	other := newClient(t, s)
	register(t, other)
	status, doc = newOrderWith(t, s, other, ariID(parseLeaf(t, der2)), "c.example.test")
	assert.Equal(t, http.StatusForbidden, status)
	assert.Equal(t, "urn:ietf:params:acme:error:unauthorized", doc["type"])
	assert.Len(t, s.Replacements(), 2)

	// An order without the field records nothing.
	_, err := c.AuthorizeOrder(ctx(t), idents("c.example.test"))
	require.NoError(t, err)
	assert.Len(t, s.Replacements(), 2)
}

// A window set for one certificate wins over the server-wide setting, for that certificate only.
func TestARIWindowPerCertificate(t *testing.T) {
	s := start(t, Options{})
	c := newClient(t, s)
	register(t, c)
	der1, _ := issue(t, s, c, nil, DNS01, "one.example.test")
	der2, _ := issue(t, s, c, nil, DNS01, "two.example.test")
	leaf1, leaf2 := parseLeaf(t, der1), parseLeaf(t, der2)
	var d map[string]any
	getJSON(t, s, s.DirectoryURL(), &d)
	base := d["renewalInfo"].(string) + "/"

	start0 := time.Now().Add(-time.Hour).Truncate(time.Second)
	require.NoError(t, s.SetARIWindowFor(ariID(leaf1), start0, start0.Add(30*time.Minute)))
	require.Error(t, s.SetARIWindowFor(ariID(leaf1), start0, start0))
	require.Error(t, s.SetARIWindowFor("AAAA.BBBB", start0, start0.Add(time.Hour)), "an unknown certificate")
	var info ariDoc
	getJSON(t, s, base+ariID(leaf1), &info)
	assert.True(t, start0.Equal(info.SuggestedWindow.Start))
	getJSON(t, s, base+ariID(leaf2), &info)
	life := leaf2.NotAfter.Sub(leaf2.NotBefore)
	assert.WithinDuration(t, leaf2.NotAfter.Add(-life/3), info.SuggestedWindow.Start, time.Second, "the other certificate keeps the default")

	// By serial number (the control API's way), and cleared again.
	require.NoError(t, s.SetARIWindowForSerial(leaf2.SerialNumber.Text(16), start0, start0.Add(time.Hour)))
	getJSON(t, s, base+ariID(leaf2), &info)
	assert.True(t, start0.Equal(info.SuggestedWindow.Start))
	s.ClearARIWindows()
	getJSON(t, s, base+ariID(leaf1), &info)
	assert.WithinDuration(t, leaf1.NotAfter.Add(-life/3), info.SuggestedWindow.Start, time.Second)
}
