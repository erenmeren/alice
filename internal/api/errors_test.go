package api

import (
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/i18n"
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
