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

// The renewal emails of the planner (Task 13): one text per fact, no raw reason code, no yes/no value,
// the vault and the certificate in every text, in both languages.
func TestKeyVaultRenewalTemplatesRenderInBothLanguages(t *testing.T) {
	cat, err := i18n.Load(locales.FS)
	require.NoError(t, err)
	s := &notify.Sender{Catalog: cat}
	params := map[string]string{"target_name": "Üretim kasası", "certificate_name": "web-cert", "count": "3"}
	templates := []string{inventory.TemplateKVNewVersion, inventory.TemplateKVNewVersionHeldLicense, inventory.TemplateKVNewVersionHeldChain,
		inventory.TemplateKVSkippedManual, inventory.TemplateKVSkippedDisabled, inventory.TemplateKVSkippedExpired, inventory.TemplateKVSkippedNotYetValid,
		inventory.TemplateKVSkippedOlder, inventory.TemplateKVSkippedSuperseded, inventory.TemplateKVAutoDeployStopped}
	for _, tpl := range templates {
		assert.Contains(t, inventory.Templates(), tpl)
		for _, lang := range []string{"en", "tr"} {
			m := s.Render("ada@example.com", tpl, lang, params)
			text := m.Subject + "\n" + m.Body
			assert.NotContains(t, text, "{{", "%s %s", tpl, lang)
			assert.NotContains(t, m.Subject, "email.", "%s %s", tpl, lang)
			assert.Contains(t, m.Subject, "web-cert", "%s %s", tpl, lang)
			assert.Contains(t, m.Subject, "Üretim kasası", "%s %s", tpl, lang)
			assert.NotContains(t, text, "incomplete_chain", "%s %s: no raw code", tpl, lang)
			assert.NotContains(t, text, "license_", "%s %s: no raw code", tpl, lang)
			assert.NotRegexp(t, `(?i)(: |\()(yes|no|true|false)(\.|\)|\n|$)`, text, "%s %s", tpl, lang)
			if tpl == inventory.TemplateKVAutoDeployStopped {
				assert.Contains(t, m.Body, "3", "%s %s", tpl, lang)
			}
		}
	}
	en := s.Render("ada@example.com", inventory.TemplateKVNewVersion, "en", params)
	assert.Contains(t, en.Body, "Automatic deployment is off")
	tr := s.Render("ada@example.com", inventory.TemplateKVAutoDeployStopped, "tr", params)
	assert.Contains(t, tr.Body, "3 dağıtım başarısız olduğu için")
	held := s.Render("ada@example.com", inventory.TemplateKVNewVersionHeldChain, "en", params)
	assert.Contains(t, held.Body, "An administrator can open the certificate")
}

// The import emails (Task 14): what failed or what is not known, the vault and the certificate, no raw code.
func TestKeyVaultImportTemplatesRenderInBothLanguages(t *testing.T) {
	cat, err := i18n.Load(locales.FS)
	require.NoError(t, err)
	s := &notify.Sender{Catalog: cat}
	params := map[string]string{"target_name": "Üretim kasası", "certificate_name": "web-cert"}
	for _, tpl := range []string{inventory.TemplateKVImportFailed, inventory.TemplateKVImportOutcomeUnknown} {
		assert.Contains(t, inventory.Templates(), tpl)
		for _, lang := range []string{"en", "tr"} {
			m := s.Render("ada@example.com", tpl, lang, params)
			text := m.Subject + "\n" + m.Body
			assert.NotContains(t, text, "{{", "%s %s", tpl, lang)
			assert.NotContains(t, m.Subject, "email.", "%s %s", tpl, lang)
			assert.Contains(t, m.Subject, "web-cert", "%s %s", tpl, lang)
			assert.Contains(t, m.Subject, "Üretim kasası", "%s %s", tpl, lang)
			assert.NotContains(t, text, "azure.", "%s %s: no raw code", tpl, lang)
			assert.NotContains(t, text, "kv.", "%s %s: no raw code", tpl, lang)
		}
	}
	en := s.Render("ada@example.com", inventory.TemplateKVImportOutcomeUnknown, "en", params)
	assert.Contains(t, en.Body, "Alice never sends an import twice")
	tr := s.Render("ada@example.com", inventory.TemplateKVImportFailed, "tr", params)
	assert.Contains(t, tr.Body, "Kasada hiçbir şey oluşturulmadı")
}
