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

// The stop mail gives advice that works (Deploy now), not "switch off and on"; the summary mails of a mass
// renewal render with their count in both languages.
func TestKeyVaultRenewalAdviceAndSummaries(t *testing.T) {
	cat, err := i18n.Load(locales.FS)
	require.NoError(t, err)
	s := &notify.Sender{Catalog: cat}
	params := map[string]string{"target_name": "Üretim kasası", "certificate_name": "web-cert", "count": "4"}
	for _, lang := range []string{"en", "tr"} {
		m := s.Render("ada@example.com", inventory.TemplateKVAutoDeployStopped, lang, params)
		assert.NotContains(t, m.Body, "switch automatic deployment off", lang)
		assert.NotContains(t, m.Body, "otomatik dağıtımını kapatıp", lang)
		assert.Contains(t, m.Body, map[string]string{"en": "Deploy now", "tr": "Şimdi dağıt"}[lang], lang)
		for _, tpl := range []string{inventory.TemplateKVNewVersionsMore, inventory.TemplateKVNewVersionsMoreOne, inventory.TemplateKVSkippedMore,
			inventory.TemplateKVSkippedMoreOne, inventory.TemplateKVStoppedMore, inventory.TemplateKVStoppedMoreOne} {
			m := s.Render("ada@example.com", tpl, lang, params)
			assert.NotContains(t, m.Subject+m.Body, "{{", "%s %s", tpl, lang)
			assert.NotContains(t, m.Subject, "email.", "%s %s", tpl, lang)
			assert.Contains(t, m.Subject, "Üretim kasası", "%s %s", tpl, lang)
			assert.Contains(t, m.Body, "4", "%s %s", tpl, lang)
		}
	}
	for _, lang := range []string{"en", "tr"} {
		for _, tpl := range []string{inventory.TemplateKVImportFailed, inventory.TemplateKVImportOutcomeUnknown} {
			m := s.Render("ada@example.com", tpl, lang, params)
			if lang == "tr" {
				assert.NotContains(t, m.Subject+m.Body, "aktarım", "the term is içe aktarma")
			}
		}
	}
}

// n6: the texts are true in every case they are sent in.
func TestKeyVaultMailTextsAreTrueInEveryCase(t *testing.T) {
	cat, err := i18n.Load(locales.FS)
	require.NoError(t, err)
	s := &notify.Sender{Catalog: cat}
	params := map[string]string{"target_name": "Üretim kasası", "certificate_name": "web-cert", "count": "4"}
	held := s.Render("ada@example.com", inventory.TemplateKVNewVersionHeldLicense, "en", params)
	assert.NotContains(t, held.Body, "while the license", "no claim about when the version was found")
	assert.Contains(t, held.Body, "at some point since the version appeared")
	unknown := s.Render("ada@example.com", inventory.TemplateKVImportOutcomeUnknown, "en", params)
	assert.NotContains(t, unknown.Body, "at the next check", "a deleted vault is never checked again")
	assert.Contains(t, unknown.Body, "If the vault was deleted")
	for _, tpl := range []string{inventory.TemplateKVNewVersionsMore, inventory.TemplateKVSkippedMore, inventory.TemplateKVStoppedMore} {
		tr := s.Render("ada@example.com", tpl, "tr", params)
		assert.NotContains(t, tr.Body, "sayılmıyor", tpl)
		assert.Contains(t, tr.Body, "listelenmiyor", tpl)
	}
	tr := s.Render("ada@example.com", inventory.TemplateKVImportFailed, "tr", params)
	assert.Contains(t, tr.Body, "içe aktaramadı")
}

// Wording pins: the sentence break of the held-for-the-licence mail, and the Turkish term for imports.
func TestKeyVaultMailWordingPins(t *testing.T) {
	cat, err := i18n.Load(locales.FS)
	require.NoError(t, err)
	s := &notify.Sender{Catalog: cat}
	params := map[string]string{"target_name": "Üretim kasası", "certificate_name": "web-cert"}
	held := s.Render("ada@example.com", inventory.TemplateKVNewVersionHeldLicense, "en", params)
	assert.Contains(t, held.Body, "in the Key Vault Üretim kasası. Because Alice's license")
	unknown := s.Render("ada@example.com", inventory.TemplateKVImportOutcomeUnknown, "tr", params)
	assert.Contains(t, unknown.Subject, "içe aktarılıp aktarılmadığını")
}

// The ACME renewal emails (plan 2026-10-13 Task 11): the certificate's names, the plain reason of the last failure in
// the reader's language (never the code), when the current certificate ends and what to do, in both languages; no URL.
func TestACMERenewalTemplatesRenderInBothLanguages(t *testing.T) {
	cat, err := i18n.Load(locales.FS)
	require.NoError(t, err)
	s := &notify.Sender{Catalog: cat}
	params := map[string]string{"name": "www.örnek.example", "names": "www.örnek.example, api.example.com", "count": "3",
		"expires_at": "2026-12-01 09:00 UTC", "error_reason": "acme.ca_rate_limited"}
	require.Equal(t, []string{"acme.renewal_failed", "acme.auto_renew_stopped"}, inventory.ACMETemplates())
	for _, tpl := range inventory.ACMETemplates() {
		for _, lang := range []string{"en", "tr"} {
			m := s.Render("ada@example.com", tpl, lang, params)
			text := m.Subject + "\n" + m.Body
			assert.NotContains(t, text, "{{", "%s %s", tpl, lang)
			assert.NotContains(t, text, "email.", "%s %s: the key itself means a missing text", tpl, lang)
			assert.NotContains(t, text, "errors.", "%s %s: the reason's title, not its key", tpl, lang)
			assert.NotContains(t, text, "acme.ca_rate_limited", "%s %s: no raw code", tpl, lang)
			assert.NotContains(t, text, "ALC-", "%s %s: no raw code", tpl, lang)
			assert.NotContains(t, text, "http", "%s %s: no URL", tpl, lang)
			assert.Contains(t, m.Subject, "www.örnek.example", "%s %s", tpl, lang)
			assert.Contains(t, m.Body, "www.örnek.example, api.example.com", "%s %s", tpl, lang)
			assert.Contains(t, m.Body, "2026-12-01 09:00 UTC", "%s %s", tpl, lang)
			assert.Contains(t, m.Body, "3", "%s %s", tpl, lang)
			assert.Contains(t, m.Body, cat.T(lang, "errors.acme.ca_rate_limited.title", nil), "%s %s: the plain reason", tpl, lang)
			assert.NotRegexp(t, `(?i)(: |\()(yes|no|true|false)(\.|\)|\n|$)`, text, "%s %s", tpl, lang)
		}
	}
	en := s.Render("ada@example.com", inventory.TemplateACMERenewalFailed, "en", params)
	assert.Equal(t, "Alice could not renew the certificate for www.örnek.example", en.Subject)
	assert.Contains(t, en.Body, "Reason of the last attempt: The authority is limiting requests.")
	assert.Contains(t, en.Body, "open Issued certificates in Alice")
	assert.Contains(t, en.Body, "choose Order now", "the button that orders at once")
	assert.NotContains(t, en.Body, "Renew now", "Renew now only re-arms a stopped certificate")
	trFailed := s.Render("ada@example.com", inventory.TemplateACMERenewalFailed, "tr", params)
	assert.Contains(t, trFailed.Body, "Şimdi iste")
	assert.NotContains(t, trFailed.Body, "Şimdi yenile")
	tr := s.Render("ada@example.com", inventory.TemplateACMEAutoRenewStopped, "tr", params)
	assert.Equal(t, "Otomatik yenileme durdu: www.örnek.example sertifikası", tr.Subject)
	assert.Contains(t, tr.Body, "Şimdi yenile")
	assert.Contains(t, tr.Body, "Şimdi iste", "a stopped certificate is renewed at once with Order now")
	assert.Contains(t, tr.Body, "Lütfen yanıtlamayın.", "the footer is in the reader's language")
}

// error_reason is rendered as the title of the code in the reader's language; an unknown or malformed code reads as the
// title of internal.unexpected, and the code itself never appears.
func TestRenderTurnsAnErrorReasonIntoItsTitle(t *testing.T) {
	cat, err := i18n.Load(locales.FS)
	require.NoError(t, err)
	s := &notify.Sender{Catalog: cat}
	for _, lang := range []string{"en", "tr"} {
		for code, want := range map[string]string{
			"license.locked":               "errors.license.locked.title",
			"acme.validation_failed_dns":   "errors.acme.validation_failed_dns.title",
			"acme.no_such_reason":          "errors.internal.unexpected.title",
			"Bcc: evil@example.com\r\nx.y": "errors.internal.unexpected.title",
			"":                             "errors.internal.unexpected.title",
		} {
			m := s.Render("ada@example.com", inventory.TemplateACMERenewalFailed, lang, map[string]string{"name": "a.example", "names": "a.example",
				"count": "3", "expires_at": "2026-12-01 09:00 UTC", "error_reason": code})
			assert.Contains(t, m.Body, cat.T(lang, want, nil), "%s %q", lang, code)
			if code != "" {
				assert.NotContains(t, m.Body, code, "%s %q", lang, code)
			}
		}
	}
}

// The ACME automatic deployment e-mails (plan 2026-10-13 Task 12): the certificate's names, for the stop the number of
// failed deployments and the plain reason of the last one (never the code), that the websites keep their certificate and
// what to do, in both languages; no URL.
func TestACMEAutoDeployTemplatesRenderInBothLanguages(t *testing.T) {
	cat, err := i18n.Load(locales.FS)
	require.NoError(t, err)
	s := &notify.Sender{Catalog: cat}
	params := map[string]string{"name": "www.örnek.example", "names": "www.örnek.example, api.example.com", "count": "3",
		"error_reason": "deployment.reload_failed"}
	require.Equal(t, []string{"acme.auto_deploy_stopped", "acme.auto_deploy_held_license", "acme.auto_deploy_held_chain"},
		inventory.ACMEDeployTemplates())
	for _, tpl := range inventory.ACMEDeployTemplates() {
		for _, lang := range []string{"en", "tr"} {
			m := s.Render("ada@example.com", tpl, lang, params)
			text := m.Subject + "\n" + m.Body
			assert.NotContains(t, text, "{{", "%s %s", tpl, lang)
			assert.NotContains(t, text, "email.", "%s %s: the key itself means a missing text", tpl, lang)
			assert.NotContains(t, text, "errors.", "%s %s", tpl, lang)
			assert.NotContains(t, text, "deployment.reload_failed", "%s %s: no raw code", tpl, lang)
			assert.NotContains(t, text, "ALC-", "%s %s", tpl, lang)
			assert.NotContains(t, text, "http", "%s %s: no URL", tpl, lang)
			assert.Contains(t, m.Subject, "www.örnek.example", "%s %s", tpl, lang)
			assert.Contains(t, m.Body, "www.örnek.example, api.example.com", "%s %s", tpl, lang)
			assert.NotRegexp(t, `(?i)(: |\()(yes|no|true|false)(\.|\)|\n|$)`, text, "%s %s", tpl, lang)
		}
	}
	for _, lang := range []string{"en", "tr"} {
		m := s.Render("ada@example.com", inventory.TemplateACMEAutoDeployStopped, lang, params)
		assert.Contains(t, m.Body, cat.T(lang, "errors.deployment.reload_failed.title", nil), "%s: the plain reason", lang)
		assert.Contains(t, m.Body, "3", lang)
	}
	en := s.Render("ada@example.com", inventory.TemplateACMEAutoDeployStopped, "en", params)
	assert.Equal(t, "Automatic deployment stopped: certificate for www.örnek.example", en.Subject)
	assert.Contains(t, en.Body, "the others keep their current certificate")
	assert.NotContains(t, en.Body, "was undone", "a rollback that failed is counted too: no false reassurance")
	assert.Contains(t, en.Body, "choose Deploy now")
	tr := s.Render("ada@example.com", inventory.TemplateACMEAutoDeployHeldLicense, "tr", params)
	assert.Contains(t, tr.Body, "Şimdi dağıt")
	assert.Contains(t, tr.Body, "Lütfen yanıtlamayın.")
}
