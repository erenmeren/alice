package api

import (
	"bufio"
	"bytes"
	"net/http"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	apispec "alice/api"
)

var (
	pathKeyRE   = regexp.MustCompile(`^  (/[^:]*):\s*$`)
	methodKeyRE = regexp.MustCompile(`^    (get|post|put|patch|delete):\s*$`)
)

const errorDefaultRef = `default: { $ref: "#/components/responses/Error" }`

// operation is one method block under a path in the spec's paths section.
type operation struct {
	path, method string
	lines        []string
}

// httpMethod maps a lowercase OpenAPI method key to its HTTP method
// (strings.ToUpper is forbidden repo-wide).
func httpMethod(m string) string {
	return map[string]string{
		"get": http.MethodGet, "post": http.MethodPost, "put": http.MethodPut,
		"patch": http.MethodPatch, "delete": http.MethodDelete,
	}[m]
}

func (o operation) key() string { return httpMethod(o.method) + " " + o.path }

func (o operation) has(prefix string) bool {
	for _, l := range o.lines {
		if strings.HasPrefix(strings.TrimSpace(l), prefix) {
			return true
		}
	}
	return false
}

// parseOperations reads the paths section into operation blocks: a method key
// at four spaces under a path key at two, up to the next sibling or path.
func parseOperations(yaml []byte) []operation {
	var ops []operation
	inPaths := false
	path := ""
	sc := bufio.NewScanner(bytes.NewReader(yaml))
	for sc.Scan() {
		line := sc.Text()
		if line == "paths:" {
			inPaths = true
			continue
		}
		if !inPaths {
			continue
		}
		if len(line) > 0 && line[0] != ' ' {
			break
		}
		if m := pathKeyRE.FindStringSubmatch(line); m != nil {
			path = m[1]
			continue
		}
		if m := methodKeyRE.FindStringSubmatch(line); m != nil {
			ops = append(ops, operation{path: path, method: m[1]})
			continue
		}
		if len(ops) > 0 {
			ops[len(ops)-1].lines = append(ops[len(ops)-1].lines, line)
		}
	}
	return ops
}

// missing returns the operations lacking the given line prefix.
func missing(ops []operation, prefix string) []string {
	var out []string
	for _, o := range ops {
		if !o.has(prefix) {
			out = append(out, o.key())
		}
	}
	return out
}

func specOps() []operation { return parseOperations(apispec.YAML) }

func specKeys() []string {
	var keys []string
	for _, o := range specOps() {
		keys = append(keys, o.key())
	}
	return keys
}

// The route table and the spec must list exactly the same operations.
// Excluded on purpose (not documented operations): the SPA fallback "/" and
// the "/api/" and "/test/" JSON 404 catch-alls, registered outside the table.
func TestRouteTableMatchesSpec(t *testing.T) {
	var table []string
	for _, r := range (&server{}).apiRoutes() {
		table = append(table, r.method+" "+r.pattern)
	}
	assert.NotEmpty(t, table)
	assert.ElementsMatch(t, table, specKeys())
}

// Every documented operation must be served (not fall through to the SPA or the API 404).
func TestEveryDocumentedPathIsServed(t *testing.T) {
	h := NewHandler(testDeps(t, nil))
	ops := specOps()
	assert.NotEmpty(t, ops)
	for _, o := range ops {
		rec := do(h, httpMethod(o.method), o.path, nil)
		assert.Equal(t, http.StatusOK, rec.Code, o.key())
		assert.Equal(t, "application/json; charset=utf-8", rec.Header().Get("Content-Type"), o.key())
	}
}

// Every operation must declare x-permission; Phase 1 turns this into the RBAC route table.
func TestEveryOperationDeclaresPermission(t *testing.T) {
	ops := specOps()
	assert.NotEmpty(t, ops)
	assert.Empty(t, missing(ops, "x-permission:"))
}

// Every operation must fall back to the shared Error response for undeclared statuses.
func TestEveryOperationReferencesSharedError(t *testing.T) {
	ops := specOps()
	assert.NotEmpty(t, ops)
	assert.Empty(t, missing(ops, errorDefaultRef))
}

func TestParseOperationsFlagsMissingDefault(t *testing.T) {
	snippet := `openapi: 3.1.0
paths:
  /a:
    get:
      x-permission: public
      responses:
        "200": { description: ok }
        default: { $ref: "#/components/responses/Error" }
  /b:
    get:
      x-permission: public
      responses:
        "200": { description: ok }
    post:
      x-permission: public
      responses:
        default: { $ref: "#/components/responses/Error" }
components:
  schemas:
    get:
      default: { $ref: "#/components/responses/Error" }
`
	ops := parseOperations([]byte(snippet))
	assert.Len(t, ops, 3)
	assert.Equal(t, []string{"GET /b"}, missing(ops, errorDefaultRef))
	assert.Empty(t, missing(ops, "x-permission:"))
}
