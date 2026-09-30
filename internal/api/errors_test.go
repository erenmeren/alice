package api

import (
	"bytes"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
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
