package api

import (
	"bufio"
	"bytes"
	"net/http"
	"regexp"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	apispec "alice/api"
)

var (
	pathKeyRE    = regexp.MustCompile(`^  (/[^:]*):\s*$`)
	methodKeyRE  = regexp.MustCompile(`^    (get|post|put|patch|delete):\s*$`)
	pathLevelRE  = regexp.MustCompile(`^    [^ ]`)
	pathParamRE  = regexp.MustCompile(`\{[a-z_]+\}`)
	permissionRE = regexp.MustCompile(`^\s*x-permission:\s*(\S+)\s*$`)
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

// permission returns the operation's x-permission value, or "".
func (o operation) permission() string {
	for _, l := range o.lines {
		if m := permissionRE.FindStringSubmatch(l); m != nil {
			return m[1]
		}
	}
	return ""
}

// parseOperations reads the paths section into operation blocks: a method key
// at four spaces under a path key at two, up to the next sibling or path.
// Other keys at four spaces (path-level "parameters:", "summary:", ...) end the
// current operation, so their lines are never attributed to it.
func parseOperations(yaml []byte) []operation {
	var ops []operation
	inPaths, inOp := false, false
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
			path, inOp = m[1], false
			continue
		}
		if m := methodKeyRE.FindStringSubmatch(line); m != nil {
			ops = append(ops, operation{path: path, method: m[1]})
			inOp = true
			continue
		}
		if pathLevelRE.MatchString(line) {
			inOp = false
			continue
		}
		if inOp {
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

func tableRoutes() []route { return newServer(Deps{}).apiRoutes() }

// The route table and the spec must list exactly the same operations.
// Excluded on purpose (not documented operations): the SPA fallback "/" and
// the "/api/" and "/test/" JSON 404 catch-alls, registered outside the table.
func TestRouteTableMatchesSpec(t *testing.T) {
	var table []string
	for _, r := range tableRoutes() {
		table = append(table, r.method+" "+r.pattern)
	}
	assert.NotEmpty(t, table)
	assert.ElementsMatch(t, table, specKeys())
}

// Each route's permission in the table must equal its x-permission in the spec (SEC-016).
func TestRoutePermissionsMatchSpec(t *testing.T) {
	spec := map[string]string{}
	for _, o := range specOps() {
		spec[o.key()] = o.permission()
	}
	for _, r := range tableRoutes() {
		k := r.method + " " + r.pattern
		assert.Equal(t, string(r.perm), spec[k], "x-permission of %s", k)
	}
}

// Every documented operation must be routed: an anonymous request gets a JSON
// answer (401 for protected routes, 400 for public ones without a body) and
// never the SPA or the catch-all 404.
func TestEveryDocumentedPathIsServed(t *testing.T) {
	h := NewHandler(testDeps(t, nil))
	ops := specOps()
	assert.NotEmpty(t, ops)
	for _, o := range ops {
		target := pathParamRE.ReplaceAllString(o.path, uuid.NewString())
		rec := do(h, httpMethod(o.method), target, nil)
		assert.NotEqual(t, http.StatusNotFound, rec.Code, o.key())
		assert.Equal(t, "application/json; charset=utf-8", rec.Header().Get("Content-Type"), o.key())
	}
}

// Every operation must declare x-permission.
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

// Path-level keys after an operation must not be attributed to that operation.
func TestParseOperationsIgnoresPathLevelKeys(t *testing.T) {
	snippet := `paths:
  /items/{id}:
    get:
      x-permission: read
      responses:
        "200": { description: ok }
    parameters:
      - name: id
        in: path
        x-permission: public
        default: { $ref: "#/components/responses/Error" }
    delete:
      x-permission: session
      responses:
        "204": { description: gone }
`
	ops := parseOperations([]byte(snippet))
	require.Len(t, ops, 2)
	assert.Equal(t, "read", ops[0].permission())
	assert.Equal(t, "session", ops[1].permission())
	assert.Equal(t, []string{"GET /items/{id}", "DELETE /items/{id}"}, missing(ops, errorDefaultRef),
		"the default line under parameters belongs to no operation")
}
