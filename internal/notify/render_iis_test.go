package notify_test

import (
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/i18n"
	"alice/internal/inventory"
	"alice/internal/notify"
	"alice/locales"
)

// linuxWording is what a Windows deployment's e-mail never says (R61): Nginx and its commands, the Linux helper's
// backup folder, certificate files, systemctl, reloads; in English and Turkish.
var linuxWording = regexp.MustCompile(`(?i)nginx|/var/lib|/usr/local|alice-helper|systemctl|reload|\bfiles?\b|\bfolder|dosya|klasör|yedeğ`)

// Every deployment e-mail has a Windows text (R61) that names the binding, never a file, a backup folder or Nginx;
// where the Linux text names the backup folder the Windows one names the previous certificate (store \ thumbprint).
// The Linux texts are the same as before (TestDeploymentTemplatesRenderInBothLanguages).
func TestWindowsDeploymentTemplatesRenderInBothLanguages(t *testing.T) {
	cat, err := i18n.Load(locales.FS)
	require.NoError(t, err)
	s := &notify.Sender{Catalog: cat}
	const sha1 = "0123456789abcdef0123456789abcdef01234567"
	params := map[string]string{"target_name": "iis-01 (İzmir)", "cert_path": "http.sys/ipport/0.0.0.0:443",
		"deployment_id": "0190f5a0-0000-7000-8000-00000000abcd", "operation_id": "0190f5a0-0000-7000-8000-00000000beef",
		"previous_certificate": `MY \ ` + sha1}

	var linux []string
	for _, tpl := range inventory.Templates() {
		if strings.HasPrefix(tpl, "deployment.") {
			linux = append(linux, tpl)
		}
	}
	require.Len(t, linux, 9)
	require.Len(t, inventory.WindowsDeploymentTemplates(), len(linux))
	for _, tpl := range linux {
		win := inventory.WindowsTemplate(tpl)
		assert.Contains(t, inventory.WindowsDeploymentTemplates(), win)
		assert.NotContains(t, inventory.Templates(), win, "the Windows texts are their own keys")
		for _, lang := range []string{"en", "tr"} {
			m := s.Render("ada@example.com", win, lang, params)
			assert.NotContains(t, m.Subject, "{{", "%s %s", win, lang)
			assert.NotContains(t, m.Body, "{{", "%s %s", win, lang)
			assert.NotContains(t, m.Subject, "email.", "%s %s: the key itself means a missing text", win, lang)
			assert.Contains(t, m.Subject, "iis-01 (İzmir)", "%s %s", win, lang)
			assert.Contains(t, m.Body, "http.sys/ipport/0.0.0.0:443", "%s %s", win, lang)
			assert.Contains(t, m.Body, "0190f5a0-0000-7000-8000-00000000abcd", "%s %s", win, lang)
			assert.NotRegexp(t, linuxWording, m.Subject, "%s %s", win, lang)
			assert.NotRegexp(t, linuxWording, m.Body, "%s %s", win, lang)
		}
	}
	for _, tpl := range []string{inventory.TemplateDeploymentRollbackFailed, inventory.TemplateDeploymentOutcomeUnknown} {
		win := inventory.WindowsTemplate(tpl)
		assert.Contains(t, s.Render("ada@example.com", win, "en", params).Body, `Previous certificate: MY \ `+sha1+".", win)
		assert.Contains(t, s.Render("ada@example.com", win, "tr", params).Body, `Önceki sertifika: MY \ `+sha1+".", win)
	}
	en := s.Render("ada@example.com", inventory.WindowsTemplate(inventory.TemplateDeploymentFailed), "en", params)
	assert.Equal(t, "Certificate deployment failed on iis-01 (İzmir)", en.Subject)
	assert.Contains(t, en.Body, "Alice could not deploy a certificate on the server iis-01 (İzmir) (binding http.sys/ipport/0.0.0.0:443). "+
		"The binding keeps its previous certificate.")
	// The rollback-forbidden text never names the previous certificate as one to bind again.
	for _, lang := range []string{"en", "tr"} {
		assert.NotContains(t, s.Render("ada@example.com", inventory.WindowsTemplate(inventory.TemplateDeploymentRollbackForbidden), lang, params).Body, sha1)
	}
}
