package notify_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/i18n"
	"alice/internal/inventory"
	"alice/internal/notify"
	"alice/locales"
)

// The stopped canary rollout (R65, design §14): the certificate, the wave-2 websites and the rollout in both languages;
// wave 1 keeps the certificate; what to do after the renewal; no code, no URL.
func TestRolloutStoppedRendersInBothLanguages(t *testing.T) {
	cat, err := i18n.Load(locales.FS)
	require.NoError(t, err)
	s := &notify.Sender{Catalog: cat}
	params := map[string]string{"certificate_name": "www.örnek.example", "websites": "web-02 /etc/nginx/ssl/www.crt, web-03 /etc/nginx/ssl/www.crt",
		"rollout_id": "0190f5a0-0000-7000-8000-00000000abcd"}
	assert.Equal(t, []string{inventory.TemplateDeploymentRolloutStopped}, inventory.CanaryTemplates())
	for _, lang := range []string{"en", "tr"} {
		m := s.Render("ada@example.com", inventory.TemplateDeploymentRolloutStopped, lang, params)
		text := m.Subject + "\n" + m.Body
		assert.NotContains(t, text, "{{", lang)
		assert.NotContains(t, text, "email.", lang)
		assert.NotContains(t, text, "ALC-", lang)
		assert.NotContains(t, text, "http", lang)
		assert.Contains(t, m.Subject, "www.örnek.example", lang)
		assert.Contains(t, m.Body, "web-02 /etc/nginx/ssl/www.crt, web-03 /etc/nginx/ssl/www.crt", lang)
		assert.Contains(t, m.Body, "0190f5a0-0000-7000-8000-00000000abcd", lang)
	}
	en := s.Render("ada@example.com", inventory.TemplateDeploymentRolloutStopped, "en", params)
	assert.Contains(t, en.Body, "After the licence is renewed, deploy the certificate to these websites again.")
	tr := s.Render("ada@example.com", inventory.TemplateDeploymentRolloutStopped, "tr", params)
	assert.Contains(t, tr.Body, "Lisans yenilendikten sonra")
}
