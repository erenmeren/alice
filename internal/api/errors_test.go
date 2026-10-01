package api

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/i18n"
	"alice/internal/platform/logging"
	"alice/locales"
)

var codeRE = regexp.MustCompile(`^ALC-[A-Z]{2,5}-\d{4}$`)

func TestEveryErrorCodeIsWellFormedUniqueAndTranslated(t *testing.T) {
	cat, err := i18n.Load(locales.FS)
	require.NoError(t, err)
	seen := map[string]bool{}
	for _, ec := range AllErrorCodes() {
		assert.Regexp(t, codeRE, ec.Code)
		assert.False(t, seen[ec.Code], "duplicate code %s", ec.Code)
		seen[ec.Code] = true
		for _, lang := range []string{"en", "tr"} {
			for _, part := range []string{"title", "cause", "action"} {
				key := "errors." + ec.Reason + "." + part
				assert.NotEqual(t, key, cat.T(lang, key, nil), "missing %s in %s", key, lang)
			}
		}
	}
}

func TestEveryErrorCodeIsDocumentedInTroubleshooting(t *testing.T) {
	doc, err := os.ReadFile("../../docs/troubleshooting.md")
	require.NoError(t, err)
	for _, ec := range AllErrorCodes() {
		assert.True(t, strings.Contains(string(doc), ec.Code), "%s missing from docs/troubleshooting.md", ec.Code)
	}
}

// Driver errors can carry column values in their message or detail (a
// password hash, a token hash). fail logs only fixed labels: the error type
// and the SQLSTATE, never the error text.
func TestFailLogsNoErrorText(t *testing.T) {
	var logs bytes.Buffer
	d := testDeps(t, nil)
	d.Log = logging.New(&logs, slog.LevelDebug)
	s := newServer(d)

	const value = "$argon2id$v=19$m=65536,t=3,p=2$c2FsdA$LEAKED-HASH"
	err := fmt.Errorf("create user: %w", &pgconn.PgError{
		Severity: "ERROR", Code: "23514",
		Message: `new row for relation "users" violates check constraint: ` + value,
		Detail:  "Failing row contains (" + value + ").",
	})
	rec := httptest.NewRecorder()
	s.fail(rec, httptest.NewRequest(http.MethodPost, "/api/v1/users", nil), err)

	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	assert.Contains(t, logs.String(), `"msg":"request failed"`)
	assert.Contains(t, logs.String(), `"sqlstate":"23514"`)
	assert.Contains(t, logs.String(), `"error_type":"*pgconn.PgError"`)
	assert.NotContains(t, logs.String(), "LEAKED-HASH")
	assert.NotContains(t, logs.String(), "argon2id")
	assert.NotContains(t, logs.String(), "create user")
	assert.NotContains(t, rec.Body.String(), "argon2id")
}

// reasonCalls are the calls whose argument at the given index is a stored failure reason: a job
// record's last_error_code or a target's status reason (jobs.Fail/Attention/Retry,
// providers.NewError, the runner's terminate/settle).
var reasonCalls = map[string]int{"Fail": 0, "Attention": 0, "Retry": 0, "NewError": 0, "terminate": 2, "settle": 2}

// unregisteredReasons map to ALC-SYS-0003 on purpose: they report a programming or packaging
// error that a person cannot act on (contract: target.invalid_config maps to ALC-SYS-0003).
var unregisteredReasons = map[string]bool{"target.invalid_config": true, "license.unclassified": true}

// storedReasons collects the literal reasons (and package string constants) passed to reasonCalls
// in the non-test sources of dir.
func storedReasons(t *testing.T, dir string) map[string]string {
	t.Helper()
	fset := token.NewFileSet()
	files, err := filepath.Glob(filepath.Join(dir, "*.go"))
	require.NoError(t, err)
	var parsed []*ast.File
	consts := map[string]string{}
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, 0)
		require.NoError(t, err)
		parsed = append(parsed, f)
		for _, decl := range f.Decls {
			gd, ok := decl.(*ast.GenDecl)
			if !ok || gd.Tok != token.CONST {
				continue
			}
			for _, spec := range gd.Specs {
				vs := spec.(*ast.ValueSpec)
				for i, n := range vs.Names {
					if i < len(vs.Values) {
						if lit, ok := vs.Values[i].(*ast.BasicLit); ok && lit.Kind == token.STRING {
							consts[n.Name], _ = strconv.Unquote(lit.Value)
						}
					}
				}
			}
		}
	}
	out := map[string]string{}
	for _, f := range parsed {
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			var name string
			switch fn := call.Fun.(type) {
			case *ast.SelectorExpr:
				name = fn.Sel.Name
			case *ast.Ident:
				name = fn.Name
			}
			idx, ok := reasonCalls[name]
			if !ok || idx >= len(call.Args) {
				return true
			}
			switch a := call.Args[idx].(type) {
			case *ast.BasicLit:
				if v, err := strconv.Unquote(a.Value); err == nil {
					out[v] = fset.Position(a.Pos()).String()
				}
			case *ast.Ident:
				if v, ok := consts[a.Name]; ok {
					out[v] = fset.Position(a.Pos()).String()
				}
			}
			return true
		})
	}
	return out
}

// TestJobResultReasonsAreRegistered is the job-result code catalog check: every reason a job
// record or a target status can carry has a registered code (and so an English and Turkish text
// and a troubleshooting section), so the UI never shows a bare reason.
func TestJobResultReasonsAreRegistered(t *testing.T) {
	seen := 0
	for _, dir := range []string{"../jobs", "../jobs/targetjobs", "../providers", "../providers/linuxssh", "../inventory"} {
		for reason, pos := range storedReasons(t, dir) {
			seen++
			if reason == "" || unregisteredReasons[reason] { // "" settles a success
				continue
			}
			registered := reason == ErrUnexpected.Reason || codeForReason(reason) != ErrUnexpected
			assert.True(t, registered, "%s: reason %q has no registered error code", pos, reason)
		}
	}
	assert.Greater(t, seen, 20, "the scan must find the reasons")
}
