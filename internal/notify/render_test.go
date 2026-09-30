package notify_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/i18n"
	"alice/internal/license"
	"alice/internal/notify"
	"alice/locales"
)

// Every license template exists in English and Turkish and uses only the params the
// license module sends.
func TestEveryLicenseTemplateRendersInBothLanguages(t *testing.T) {
	cat, err := i18n.Load(locales.FS)
	require.NoError(t, err)
	s := &notify.Sender{Catalog: cat}
	params := map[string]string{
		"installation_id": "ALICE-7F3K-9Q2M-XD41-B8TC", "days_left": "30", "ends_at": "2027-10-01 00:00 UTC",
		"locks_at": "2027-10-08 00:00 UTC", "customer": "Örnek Bankası A.Ş.", "license_id": "LIC-2026-000123",
		"grace_day": "3", "jump_days": "200", "system_time": "2028-04-18 09:00 UTC",
	}
	for _, tpl := range license.Templates() {
		for _, lang := range []string{"en", "tr"} {
			m := s.Render("ada@example.com", tpl, lang, params)
			assert.NotContains(t, m.Subject, "{{", "%s %s", tpl, lang)
			assert.NotContains(t, m.Body, "{{", "%s %s", tpl, lang)
			assert.NotContains(t, m.Subject, "email.", "%s %s: the key itself means a missing text", tpl, lang)
			assert.Contains(t, m.Body, "ALICE-7F3K-9Q2M-XD41-B8TC", "%s %s", tpl, lang)
		}
	}
	tr := s.Render("ada@example.com", license.TemplateLocked, "tr", params)
	assert.Contains(t, tr.Body, "Lütfen yanıtlamayın.", "the footer is in the person's language")
}

func TestRenderKeepsParamsOnOneLine(t *testing.T) {
	cat, err := i18n.Load(locales.FS)
	require.NoError(t, err)
	m := (&notify.Sender{Catalog: cat}).Render("ada@example.com", license.TemplateExpiryWarning, "en",
		map[string]string{"ends_at": "tomorrow\r\nBcc: evil@example.com"})
	assert.NotContains(t, m.Subject, "\n")
	assert.NotContains(t, m.Body, "\nBcc:")
}
