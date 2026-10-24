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
