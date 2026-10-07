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

// L-28: the license note is appended (before the footer) when the license is locked; "kv" adds the data-age line.
func TestRenderAddsTheLicenseNote(t *testing.T) {
	cat, err := i18n.Load(locales.FS)
	require.NoError(t, err)
	s := &notify.Sender{Catalog: cat}
	base := map[string]string{"installation_id": "ALICE-X", "ends_at": "2027-10-01 00:00 UTC"}
	plain := s.Render("ada@example.com", license.TemplateLocked, "en", base)
	assert.NotContains(t, plain.Body, "Alice's license has expired. Renew it")
	with := map[string]string{"license_note": "true", "license_url": "https://alice.example.com/license"}
	for k, v := range base {
		with[k] = v
	}
	m := s.Render("ada@example.com", license.TemplateLocked, "en", with)
	assert.Contains(t, m.Body, "Note: Alice's license has expired. Renew it to resume automatic deployment. License page: https://alice.example.com/license")
	assert.NotContains(t, m.Body, "Key Vault data may be outdated")
	with["license_note"] = "kv"
	m = s.Render("ada@example.com", license.TemplateLocked, "tr", with)
	assert.Contains(t, m.Body, "Lisans sayfası: https://alice.example.com/license")
	assert.Contains(t, m.Body, "Key Vault verileri güncel olmayabilir")
	assert.Contains(t, m.Body, "Lütfen yanıtlamayın.", "the footer stays last")
	assert.NotContains(t, m.Body, "{{license_url}}")
}

// Review Focus 3: a hostile value never adds a header line or a paragraph, and is not expanded as a placeholder.
func TestRenderFlattensHostileParams(t *testing.T) {
	cat, err := i18n.Load(locales.FS)
	require.NoError(t, err)
	m := (&notify.Sender{Catalog: cat}).Render("ada@example.com", license.TemplateExpiryWarning, "en", map[string]string{
		"ends_at": "x\r\nBcc: evil@example.com\n\n{{installation_id}}<script>", "installation_id": "ALICE-X", "days_left": "30"})
	assert.NotContains(t, m.Subject, "\n")
	assert.NotContains(t, m.Body, "\nBcc:")
	assert.Contains(t, m.Body, "x Bcc: evil@example.com {{installation_id}}<script>", "flattened, kept as text, not expanded")
}
