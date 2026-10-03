package notify_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/i18n"
	"alice/internal/inventory"
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

// Every inventory template exists in English and Turkish and shows the server and the
// fingerprints it is given (R37 item 14).
func TestEveryInventoryTemplateRendersInBothLanguages(t *testing.T) {
	cat, err := i18n.Load(locales.FS)
	require.NoError(t, err)
	s := &notify.Sender{Catalog: cat}
	params := map[string]string{"target_name": "web-01 (İzmir)", "old_fingerprint": "SHA256:oldOLDold", "new_fingerprint": "SHA256:newNEWnew",
		"cert_path": "/etc/nginx/ssl/www.crt", "deployment_id": "0190f5a0-0000-7000-8000-00000000abcd", "backup_dir": "/var/lib/alice-helper/backups/x"}
	for _, tpl := range inventory.Templates() {
		for _, lang := range []string{"en", "tr"} {
			m := s.Render("ada@example.com", tpl, lang, params)
			assert.NotContains(t, m.Subject, "{{", "%s %s", tpl, lang)
			assert.NotContains(t, m.Body, "{{", "%s %s", tpl, lang)
			assert.NotContains(t, m.Subject, "email.", "%s %s: the key itself means a missing text", tpl, lang)
			assert.Contains(t, m.Subject, "web-01 (İzmir)", "%s %s", tpl, lang)
			assert.Contains(t, m.Body, "web-01 (İzmir)", "%s %s", tpl, lang)
		}
		m := s.Render("ada@example.com", inventory.TemplateHostKeyChanged, "en", params)
		assert.Contains(t, m.Body, "SHA256:oldOLDold")
		assert.Contains(t, m.Body, "SHA256:newNEWnew")
	}
}

// The deployment emails (Task 15) render in English and Turkish with every param they are sent,
// keep remote-controlled text (the certificate path comes from the server's configuration) on one
// line, and say what the contract says.
func TestDeploymentTemplatesRenderInBothLanguages(t *testing.T) {
	cat, err := i18n.Load(locales.FS)
	require.NoError(t, err)
	s := &notify.Sender{Catalog: cat}
	params := map[string]string{"target_name": "web-01 (İzmir)", "cert_path": "/etc/nginx/ssl/www.crt",
		"deployment_id": "0190f5a0-0000-7000-8000-00000000abcd", "backup_dir": "/var/lib/alice-helper/backups/0190f5a0-0000-7000-8000-00000000abcd"}
	templates := []string{inventory.TemplateDeploymentFailed, inventory.TemplateDeploymentRollbackFailed, inventory.TemplateDeploymentNeedsAttention}
	for _, tpl := range templates {
		assert.Contains(t, inventory.Templates(), tpl)
		for _, lang := range []string{"en", "tr"} {
			m := s.Render("ada@example.com", tpl, lang, params)
			assert.NotContains(t, m.Subject, "{{", "%s %s", tpl, lang)
			assert.NotContains(t, m.Body, "{{", "%s %s", tpl, lang)
			assert.NotContains(t, m.Subject, "email.", "%s %s", tpl, lang)
			assert.Contains(t, m.Subject, "web-01 (İzmir)", "%s %s", tpl, lang)
			assert.Contains(t, m.Body, "/etc/nginx/ssl/www.crt", "%s %s", tpl, lang)
			assert.Contains(t, m.Body, "0190f5a0-0000-7000-8000-00000000abcd", "%s %s", tpl, lang)
			assert.NotContains(t, m.Body, "PRIVATE KEY")
		}
	}
	en := s.Render("ada@example.com", inventory.TemplateDeploymentFailed, "en", params)
	assert.Equal(t, "Certificate deployment failed on web-01 (İzmir)", en.Subject)
	assert.Contains(t, en.Body, "Alice could not deploy a certificate on the server web-01 (İzmir) (file /etc/nginx/ssl/www.crt). "+
		"The server keeps its previous certificate.\n\nThe deployment history in Alice shows each step, the reason and what to do. "+
		"Deployment: 0190f5a0-0000-7000-8000-00000000abcd")
	tr := s.Render("ada@example.com", inventory.TemplateDeploymentRollbackFailed, "tr", params)
	assert.Equal(t, "Elle müdahale gerekiyor: web-01 (İzmir) sunucusunda sertifika geri yüklenemedi", tr.Subject)
	assert.Contains(t, tr.Body, "Önceki dosyalar sunucuda şu klasörde: /var/lib/alice-helper/backups/0190f5a0-0000-7000-8000-00000000abcd.")
	na := s.Render("ada@example.com", inventory.TemplateDeploymentNeedsAttention, "en", params)
	assert.Equal(t, "Alice cannot finish a deployment on web-01 (İzmir)", na.Subject)
	assert.Contains(t, na.Body, "Alice tries again every 15 minutes.")
	natr := s.Render("ada@example.com", inventory.TemplateDeploymentNeedsAttention, "tr", params)
	assert.Contains(t, natr.Body, "Alice 15 dakikada bir yeniden dener.")

	hostile := map[string]string{"target_name": "web", "cert_path": "/etc/x.crt\r\nBcc: evil@example.com", "deployment_id": "d"}
	m := s.Render("ada@example.com", inventory.TemplateDeploymentFailed, "en", hostile)
	assert.NotContains(t, m.Body, "\nBcc:")
}
