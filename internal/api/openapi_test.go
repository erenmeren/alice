package api

import (
	"bufio"
	"bytes"
	"net/http"
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"

	apispec "alice/api"
)

var pathKeyRE = regexp.MustCompile(`^  (/[^:]*):\s*$`)

func specPaths() []string {
	var paths []string
	inPaths := false
	sc := bufio.NewScanner(bytes.NewReader(apispec.YAML))
	for sc.Scan() {
		line := sc.Text()
		switch {
		case line == "paths:":
			inPaths = true
		case inPaths && len(line) > 0 && line[0] != ' ':
			inPaths = false
		case inPaths:
			if m := pathKeyRE.FindStringSubmatch(line); m != nil {
				paths = append(paths, m[1])
			}
		}
	}
	return paths
}

// Every documented GET path must be served (not fall through to the SPA or the API 404).
func TestEveryDocumentedPathIsServed(t *testing.T) {
	h := NewHandler(testDeps(t, nil))
	paths := specPaths()
	assert.ElementsMatch(t, []string{"/livez", "/healthz", "/api/v1/version", "/api/v1/i18n/locales"}, paths)
	for _, p := range paths {
		rec := do(h, http.MethodGet, p, nil)
		assert.Equal(t, http.StatusOK, rec.Code, p)
		assert.Equal(t, "application/json; charset=utf-8", rec.Header().Get("Content-Type"), p)
	}
}

// Every operation must declare x-permission; Phase 1 turns this into the RBAC route table.
func TestEveryOperationDeclaresPermission(t *testing.T) {
	ops := regexp.MustCompile(`(?m)^    (get|post|put|patch|delete):`).FindAllIndex(apispec.YAML, -1)
	perms := regexp.MustCompile(`(?m)^      x-permission: \S+`).FindAllIndex(apispec.YAML, -1)
	assert.NotEmpty(t, ops)
	assert.Equal(t, len(ops), len(perms))
}

// Every operation must fall back to the shared Error response for undeclared statuses.
func TestEveryOperationReferencesSharedError(t *testing.T) {
	ops := regexp.MustCompile(`(?m)^    (get|post|put|patch|delete):`).FindAllIndex(apispec.YAML, -1)
	defaults := regexp.MustCompile(`(?m)^        default: \{ \$ref: "#/components/responses/Error" \}$`).FindAllIndex(apispec.YAML, -1)
	assert.NotEmpty(t, ops)
	assert.Equal(t, len(ops), len(defaults))
}
