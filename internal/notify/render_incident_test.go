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

// The incident e-mails (D3, HB-08, R64): the certificate's name in the subject, the incident's id and counts in the
// body, the attention reason as the plain title of its code in the reader's language; both languages, no raw key.
func TestIncidentTemplatesRenderInBothLanguages(t *testing.T) {
	cat, err := i18n.Load(locales.FS)
	require.NoError(t, err)
	s := &notify.Sender{Catalog: cat}
	const id = "0199f0a0-0000-7000-8000-0000000000a1"
	params := map[string]string{"certificate_name": "www.example.test (İzmir)", "incident_id": id, "verified": "4", "failed": "1", "skipped": "2",
		"error_reason": "incident.deployments_failed"}
	require.Equal(t, []string{"incident.needs_attention", "incident.completed", "incident.completed_not_revocable"}, inventory.IncidentTemplates())
	for _, tpl := range inventory.IncidentTemplates() {
		for _, lang := range []string{"en", "tr"} {
			p := params
			if tpl != inventory.TemplateIncidentNeedsAttention {
				p = map[string]string{"certificate_name": params["certificate_name"], "incident_id": id, "verified": "4", "failed": "0", "skipped": "2"}
			}
			m := s.Render("ada@example.com", tpl, lang, p)
			text := m.Subject + "\n" + m.Body
			assert.NotContains(t, text, "{{", "%s %s", tpl, lang)
			assert.NotContains(t, m.Subject, "email.", "%s %s: the key itself means a missing text", tpl, lang)
			assert.NotContains(t, m.Body, "email.", "%s %s", tpl, lang)
			assert.NotContains(t, text, "errors.", "%s %s", tpl, lang)
			assert.Contains(t, m.Subject, "www.example.test (İzmir)", "%s %s", tpl, lang)
			assert.Contains(t, m.Body, id, "%s %s", tpl, lang)
			assert.Contains(t, m.Body, "4", "%s %s", tpl, lang)
			if tpl == inventory.TemplateIncidentNeedsAttention {
				assert.Contains(t, m.Body, cat.T(lang, "errors.incident.deployments_failed.title", nil), "%s %s: the plain reason", tpl, lang)
				assert.NotContains(t, text, "incident.deployments_failed", "%s %s: no raw code", tpl, lang)
			}
		}
	}
	done := s.Render("ada@example.com", inventory.TemplateIncidentCompletedNotRevocable, "en", params)
	assert.Contains(t, done.Body, "ask the authority that issued it to revoke it")
	revoked := s.Render("ada@example.com", inventory.TemplateIncidentCompleted, "en", params)
	assert.Contains(t, revoked.Body, "is revoked at its certificate authority")
}

// The revocation check e-mails (D5, R64): the certificate's name, the fingerprint, when and why the authority revoked
// or suspended it and by which answer, in both languages; the discovered one names where discovery found it.
func TestRevocationTemplatesRenderInBothLanguages(t *testing.T) {
	cat, err := i18n.Load(locales.FS)
	require.NoError(t, err)
	s := &notify.Sender{Catalog: cat}
	params := map[string]string{"certificate_name": "www.example.test (İzmir)", "fingerprint": "ab12", "revoked_at": "2026-10-20 08:00 UTC",
		"reason": "keyCompromise", "method": "OCSP", "endpoints": "10.0.0.9:443"}
	require.Equal(t, []string{"certificate.revoked_by_authority", "certificate.revoked_by_authority_discovered", "certificate.on_hold_by_authority"},
		inventory.RevocationTemplates())
	for _, tpl := range inventory.RevocationTemplates() {
		for _, lang := range []string{"en", "tr"} {
			m := s.Render("ada@example.com", tpl, lang, params)
			text := m.Subject + "\n" + m.Body
			assert.NotContains(t, text, "{{", "%s %s", tpl, lang)
			assert.NotContains(t, text, "email.", "%s %s", tpl, lang)
			assert.Contains(t, m.Subject, "www.example.test (İzmir)", "%s %s", tpl, lang)
			for _, v := range []string{"ab12", "2026-10-20 08:00 UTC", "OCSP"} {
				assert.Contains(t, m.Body, v, "%s %s", tpl, lang)
			}
			if tpl == inventory.TemplateCertificateRevokedByAuthorityDiscovered {
				assert.Contains(t, m.Body, "10.0.0.9:443", "%s %s", tpl, lang)
			}
		}
	}
	assert.Contains(t, s.Render("a@example.com", inventory.TemplateCertificateRevokedByAuthority, "en", params).Body, "Alice no longer deploys it")
	assert.NotContains(t, s.Render("a@example.com", inventory.TemplateCertificateRevokedByAuthorityDiscovered, "en", params).Body, "deploys")
}
