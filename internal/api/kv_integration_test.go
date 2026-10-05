//go:build integration

package api

import (
	"net/http"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The read routes of an import are scoped to a live vault with the real inventory: a server's id, an unknown id
// and a soft-deleted vault answer 404 on both routes, and the vault itself answers 200 until it is deleted.
func TestImportReadsAreScopedToALiveVault(t *testing.T) {
	s, c, admin := installed(t)
	_ = admin
	ids := phase3Records(t, s, c)
	cert := phase4Records(t, s, c, ids["/api/v1/targets/"])["/api/v1/certificates/"]
	p5 := phase5Records(t, s, cert)
	list := func(vault string) string { return "/api/v1/targets/" + vault + "/kv/imports" }
	one := func(vault string) string { return list(vault) + "/" + p5["import"] }

	requireStatus(t, c.do(http.MethodGet, list(p5["vault"]), nil), http.StatusOK)
	requireStatus(t, c.do(http.MethodGet, one(p5["vault"]), nil), http.StatusOK)
	// Another vault's import id under this vault, a server, an unknown id.
	for _, vault := range []string{ids["/api/v1/targets/"], uuid.NewString()} {
		requireStatus(t, c.do(http.MethodGet, list(vault), nil), http.StatusNotFound)
		requireStatus(t, c.do(http.MethodGet, one(vault), nil), http.StatusNotFound)
	}
	// A deleted vault.
	_, err := s.db.Owner.Exec(t.Context(), "UPDATE targets SET deleted_at = $2 WHERE id = $1", p5["vault"], s.clock.Now())
	require.NoError(t, err)
	for _, path := range []string{list(p5["vault"]), one(p5["vault"]), "/api/v1/targets/" + p5["vault"] + "/kv/certificates"} {
		rec := c.do(http.MethodGet, path, nil)
		assert.Equal(t, http.StatusNotFound, rec.Code, path)
	}
}
