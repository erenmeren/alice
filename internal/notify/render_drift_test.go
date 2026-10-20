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

// The drift e-mails (R52): the server, the file, the certificate the location should have and the one found instead in
// every text, in both languages; no code, no URL, no yes/no value; what to do; the back-off says that another tool keeps
// changing the file.
func TestDriftTemplatesRenderInBothLanguages(t *testing.T) {
	cat, err := i18n.Load(locales.FS)
	require.NoError(t, err)
	s := &notify.Sender{Catalog: cat}
	params := map[string]string{"target_name": "web-01", "cert_path": "/etc/nginx/ssl/www.crt", "certificate_name": "www.örnek.example",
		"observed_name": "eski.example"}
	require.Equal(t, []string{"location.drift_detected", "location.drift_repair_ready", "location.drift_repaired", "location.drift_flapping",
		"location.drift_repair_failing"}, inventory.DriftTemplates())
	for _, tpl := range inventory.DriftTemplates() {
		for _, lang := range []string{"en", "tr"} {
			m := s.Render("ada@example.com", tpl, lang, params)
			text := m.Subject + "\n" + m.Body
			assert.NotContains(t, text, "{{", "%s %s", tpl, lang)
			assert.NotContains(t, text, "email.", "%s %s: the key itself means a missing text", tpl, lang)
			assert.NotContains(t, text, "ALC-", "%s %s", tpl, lang)
			assert.NotContains(t, text, "http", "%s %s: no URL", tpl, lang)
			assert.Contains(t, m.Subject, "web-01", "%s %s", tpl, lang)
			assert.Contains(t, m.Subject, "/etc/nginx/ssl/www.crt", "%s %s", tpl, lang)
			assert.Contains(t, m.Body, "www.örnek.example", "%s %s", tpl, lang)
			assert.Contains(t, m.Body, "eski.example", "%s %s", tpl, lang)
			assert.NotRegexp(t, `(?i)(: |\()(yes|no|true|false|evet|hayır)(\.|\)|\n|$)`, text, "%s %s", tpl, lang)
		}
	}
	en := s.Render("ada@example.com", inventory.TemplateDriftFlapping, "en", params)
	assert.Contains(t, en.Subject, "another tool keeps changing it")
	assert.Contains(t, en.Body, "it only reports changes now")
	tr := s.Render("ada@example.com", inventory.TemplateDriftRepairReady, "tr", params)
	assert.Contains(t, tr.Body, "Onar'ı seçin")
}
