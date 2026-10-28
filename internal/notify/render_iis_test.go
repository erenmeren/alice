package notify_test

import (
	"maps"
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

// R62 W3 Ruling 9: the report of a compromised certificate still in a Windows server's store after its incident names the
// server, the certificate, the store and the thumbprint, in English and Turkish, and no Linux wording.
func TestWindowsCompromisedInStoreRendersInBothLanguages(t *testing.T) {
	cat, err := i18n.Load(locales.FS)
	require.NoError(t, err)
	s := &notify.Sender{Catalog: cat}
	const sha1 = "0123456789abcdef0123456789abcdef01234567"
	params := map[string]string{"target_name": "iis-01 (İzmir)", "certificate_name": "www.example.test", "store": "My", "thumbprint": sha1}
	for _, lang := range []string{"en", "tr"} {
		m := s.Render("ada@example.com", inventory.TemplateWindowsCompromisedInStore, lang, params)
		assert.NotContains(t, m.Subject, "email.", lang)
		assert.NotContains(t, m.Body, "{{", lang)
		assert.Contains(t, m.Subject, "iis-01 (İzmir)", lang)
		for _, v := range params {
			assert.Contains(t, m.Body, v, lang)
		}
		assert.NotRegexp(t, linuxWording, m.Body, lang)
	}
	assert.Contains(t, s.Render("ada@example.com", inventory.TemplateWindowsCompromisedInStore, "en", params).Body, "Store: My. Thumbprint: "+sha1+".")
}

// R62 W3 Ruling 16: every drift e-mail has a Windows text, three of them for a detected drift (re-pointed, certificate
// removed from the store, key unusable), that names the binding and the certificates with R52's params, never a file,
// a folder or Nginx; the AutoCertRebind sentence is added only when windows_note is autocertrebind. The Linux texts are
// unchanged (TestDriftTemplatesRenderInBothLanguages).
func TestWindowsDriftTemplatesRenderInBothLanguages(t *testing.T) {
	cat, err := i18n.Load(locales.FS)
	require.NoError(t, err)
	s := &notify.Sender{Catalog: cat}
	params := map[string]string{"target_name": "iis-01 (İzmir)", "cert_path": "http.sys/ipport/0.0.0.0:443", "certificate_name": "www.örnek.example",
		"observed_name": "eski.example"}
	want := []string{"location.drift_detected_windows", "location.drift_detected_windows_cert_removed", "location.drift_detected_windows_key_unusable",
		"location.drift_repair_ready_windows", "location.drift_repaired_windows", "location.drift_flapping_windows", "location.drift_repair_failing_windows"}
	require.Equal(t, want, inventory.WindowsDriftTemplates())
	noteEN, noteTR := cat.T("en", "email.windows_note_autocertrebind", nil), cat.T("tr", "email.windows_note_autocertrebind", nil)
	require.NotEqual(t, "email.windows_note_autocertrebind", noteEN)
	require.NotEqual(t, "email.windows_note_autocertrebind", noteTR)
	assert.Contains(t, noteEN, "AutoCertRebind")
	assert.Contains(t, noteTR, "AutoCertRebind")
	for _, tpl := range inventory.WindowsDriftTemplates() {
		assert.NotContains(t, inventory.DriftTemplates(), tpl, "the Windows texts are their own keys")
		for _, lang := range []string{"en", "tr"} {
			note := map[string]string{"en": noteEN, "tr": noteTR}[lang]
			plain := s.Render("ada@example.com", tpl, lang, params)
			withNote := maps.Clone(params)
			withNote["windows_note"] = "autocertrebind"
			noted := s.Render("ada@example.com", tpl, lang, withNote)
			other := maps.Clone(params)
			other["windows_note"] = "something_else"
			for _, m := range []notify.Message{plain, noted} {
				text := m.Subject + "\n" + m.Body
				assert.NotContains(t, text, "{{", "%s %s", tpl, lang)
				assert.NotContains(t, text, "email.", "%s %s: the key itself means a missing text", tpl, lang)
				assert.NotContains(t, text, "ALC-", "%s %s", tpl, lang)
				assert.NotContains(t, text, "autocertrebind", "%s %s: the param's value is not rendered", tpl, lang)
				assert.Contains(t, m.Subject, "iis-01 (İzmir)", "%s %s", tpl, lang)
				assert.Contains(t, m.Body, "http.sys/ipport/0.0.0.0:443", "%s %s", tpl, lang)
				assert.Contains(t, m.Body, "www.örnek.example", "%s %s", tpl, lang)
				assert.NotRegexp(t, linuxWording, m.Subject, "%s %s", tpl, lang)
				assert.NotRegexp(t, linuxWording, m.Body, "%s %s", tpl, lang)
				assert.NotRegexp(t, `(?i)(: |\()(yes|no|true|false|evet|hayır)(\.|\)|\n|$)`, text, "%s %s", tpl, lang)
			}
			assert.NotContains(t, plain.Body, note, "%s %s: no note without the param", tpl, lang)
			assert.NotContains(t, s.Render("ada@example.com", tpl, lang, other).Body, note, "%s %s: only autocertrebind asks for it", tpl, lang)
			assert.Contains(t, noted.Body, note, "%s %s", tpl, lang)
			assert.Equal(t, plain.Subject, noted.Subject, "%s %s", tpl, lang)
			footer := cat.T(lang, "email.footer", nil)
			assert.True(t, strings.HasSuffix(noted.Body, note+"\n\n"+footer), "%s %s: the note sits before the footer", tpl, lang)
		}
	}
	// A removed certificate names the one it should have; the observed one is "-" (the binding names none).
	removed := maps.Clone(params)
	removed["observed_name"] = "-"
	en := s.Render("ada@example.com", "location.drift_detected_windows_cert_removed", "en", removed)
	assert.Contains(t, en.Body, "certificate store")
	assert.NotContains(t, en.Body, "Repair", "an unrepairable drift offers no repair")
	en = s.Render("ada@example.com", "location.drift_detected_windows_key_unusable", "en", params)
	assert.Contains(t, en.Body, "private key")
	assert.NotContains(t, en.Body, "Repair", "an unrepairable drift offers no repair")
	for _, tpl := range []string{"location.drift_detected_windows", "location.drift_repair_ready_windows"} {
		assert.Contains(t, s.Render("ada@example.com", tpl, "en", params).Body, "eski.example", tpl)
		assert.Contains(t, s.Render("ada@example.com", tpl, "en", params).Body, "Repair", tpl)
		assert.Contains(t, s.Render("ada@example.com", tpl, "tr", params).Body, "Onar'ı seçin", tpl)
	}
	assert.Contains(t, s.Render("ada@example.com", "location.drift_flapping_windows", "en", params).Subject, "another tool keeps changing it")
}

// W5-5 (R68): a CCS file's rollback_failed, outcome_unknown and restored_unverified e-mails have texts of their own that
// name the file and IIS Manager, never the Linux helper's backup folder, Nginx, systemctl or netsh; the first two name
// the previous certificate and the backup beside the file. A CCS file's other deployment e-mails are the file texts.
func TestWindowsCCSDeploymentTemplatesRenderInBothLanguages(t *testing.T) {
	cat, err := i18n.Load(locales.FS)
	require.NoError(t, err)
	s := &notify.Sender{Catalog: cat}
	params := map[string]string{"target_name": "iis-01 (İzmir)", "cert_path": `C:\CCS\www.example.test.pfx`,
		"deployment_id": "0190f5a0-0000-7000-8000-00000000abcd", "previous_certificate": "SHA-256 " + strings.Repeat("ab", 32)}
	want := []string{inventory.WindowsCCSTemplate(inventory.TemplateDeploymentRollbackFailed),
		inventory.WindowsCCSTemplate(inventory.TemplateDeploymentOutcomeUnknown),
		inventory.WindowsCCSTemplate(inventory.TemplateDeploymentRestoredUnverified)}
	require.Equal(t, want, inventory.WindowsCCSDeploymentTemplates())
	notLinux := regexp.MustCompile(`(?i)nginx|/var/lib|/usr/local|alice-helper|systemctl|netsh|reload`)
	for _, tpl := range want {
		assert.NotContains(t, inventory.Templates(), tpl, "the CCS texts are their own keys")
		assert.NotContains(t, inventory.WindowsDeploymentTemplates(), tpl)
		for _, lang := range []string{"en", "tr"} {
			m := s.Render("ada@example.com", tpl, lang, params)
			text := m.Subject + "\n" + m.Body
			assert.NotContains(t, text, "{{", "%s %s", tpl, lang)
			assert.NotContains(t, m.Subject, "email.", "%s %s: the key itself means a missing text", tpl, lang)
			assert.Contains(t, m.Subject, "iis-01 (İzmir)", "%s %s", tpl, lang)
			assert.Contains(t, m.Body, `C:\CCS\www.example.test.pfx`, "%s %s", tpl, lang)
			assert.Contains(t, m.Body, "0190f5a0-0000-7000-8000-00000000abcd", "%s %s", tpl, lang)
			assert.Contains(t, m.Body, "IIS", "%s %s", tpl, lang)
			assert.NotRegexp(t, notLinux, text, "%s %s", tpl, lang)
		}
	}
	for _, tpl := range want[:2] {
		for _, lang := range []string{"en", "tr"} {
			body := s.Render("ada@example.com", tpl, lang, params).Body
			assert.Contains(t, body, params["previous_certificate"], "%s %s", tpl, lang)
			assert.Contains(t, body, ".alice-<id>.bak", "%s %s", tpl, lang)
		}
	}
}

// W6 Ruling 20 (R69): the RDP listener's rollback_failed, outcome_unknown and restored_unverified e-mails have texts of
// their own that name the listener, the previous certificate, how to check it on the server and that the console or SSH
// is the way in, never a file, Nginx or netsh. The note windows_note rdp (rdp_autoenroll: also RDP autoenrolment) and
// rdp_key_acl_left (Ruling 10) are added before the footer, in English and Turkish.
func TestWindowsRDPTemplatesAndNotesRenderInBothLanguages(t *testing.T) {
	cat, err := i18n.Load(locales.FS)
	require.NoError(t, err)
	s := &notify.Sender{Catalog: cat}
	params := map[string]string{"target_name": "iis-01 (İzmir)", "cert_path": "rdp/RDP-Tcp",
		"deployment_id": "0190f5a0-0000-7000-8000-00000000abcd", "previous_certificate": `MY \ ` + strings.Repeat("ab", 20)}
	want := []string{inventory.WindowsRDPTemplate(inventory.TemplateDeploymentRollbackFailed),
		inventory.WindowsRDPTemplate(inventory.TemplateDeploymentOutcomeUnknown),
		inventory.WindowsRDPTemplate(inventory.TemplateDeploymentRestoredUnverified)}
	require.Equal(t, want, inventory.WindowsRDPDeploymentTemplates())
	notRDP := regexp.MustCompile(`(?i)nginx|/var/lib|/usr/local|alice-helper|systemctl|netsh|reload|\bfiles?\b|dosya`)
	for _, tpl := range want {
		assert.NotContains(t, inventory.Templates(), tpl, "the RDP texts are their own keys")
		for _, lang := range []string{"en", "tr"} {
			m := s.Render("ada@example.com", tpl, lang, params)
			text := m.Subject + "\n" + m.Body
			assert.NotContains(t, text, "{{", "%s %s", tpl, lang)
			assert.NotContains(t, m.Subject, "email.", "%s %s", tpl, lang)
			assert.Contains(t, m.Subject, "iis-01 (İzmir)", "%s %s", tpl, lang)
			assert.Contains(t, m.Body, "rdp/RDP-Tcp", "%s %s", tpl, lang)
			assert.Contains(t, m.Body, params["previous_certificate"], "%s %s", tpl, lang)
			assert.Contains(t, m.Body, "0190f5a0-0000-7000-8000-00000000abcd", "%s %s", tpl, lang)
			assert.Contains(t, m.Body, "Win32_TSGeneralSetting", "%s %s", tpl, lang)
			assert.Contains(t, m.Body, "SSH", "%s %s", tpl, lang)
			assert.NotRegexp(t, notRDP, text, "%s %s", tpl, lang)
		}
	}

	notes := map[string]string{"rdp": "email.windows_note_rdp", "autoenroll": "email.windows_note_rdp_autoenroll",
		"acl": "email.windows_note_rdp_key_acl_left", "granted": "email.windows_note_rdp_key_granted"}
	for _, lang := range []string{"en", "tr"} {
		text := map[string]string{}
		for k, key := range notes {
			text[k] = cat.T(lang, key, nil)
			require.NotEqual(t, key, text[k], lang)
		}
		assert.Contains(t, text["rdp"], "NETWORK SERVICE", lang)
		assert.Contains(t, text["rdp"], "RDP-Tcp", lang)
		assert.Contains(t, text["acl"], "NETWORK SERVICE", lang)
		footer := "\n\n" + cat.T(lang, "email.footer", nil)
		render := func(extra map[string]string) string {
			p := map[string]string{"target_name": "iis-01", "cert_path": "rdp/RDP-Tcp", "deployment_id": "d"}
			maps.Copy(p, extra)
			return s.Render("ada@example.com", "deployment.failed_windows", lang, p).Body
		}
		assert.NotContains(t, render(nil), text["rdp"], lang)
		assert.True(t, strings.HasSuffix(render(map[string]string{"windows_note": "rdp"}), "\n\n"+text["rdp"]+footer), lang)
		assert.True(t, strings.HasSuffix(render(map[string]string{"windows_note": "rdp_autoenroll"}),
			"\n\n"+text["rdp"]+" "+text["autoenroll"]+footer), lang)
		assert.True(t, strings.HasSuffix(render(map[string]string{"windows_note": "rdp", "rdp_key_acl_left": "true"}),
			"\n\n"+text["rdp"]+"\n\n"+text["acl"]+footer), lang)
		assert.NotContains(t, render(map[string]string{"rdp_key_acl_left": "yes"}), text["acl"], "%s: only true asks for it", lang)
		// Security review M2: the grant no restore took back; the note that it was left in place covers it.
		assert.Contains(t, text["granted"], "NETWORK SERVICE", lang)
		assert.True(t, strings.HasSuffix(render(map[string]string{"rdp_key_granted": "true"}), "\n\n"+text["granted"]+footer), lang)
		both := render(map[string]string{"rdp_key_granted": "true", "rdp_key_acl_left": "true"})
		assert.True(t, strings.HasSuffix(both, "\n\n"+text["acl"]+footer), lang)
		assert.NotContains(t, both, text["granted"], lang)
	}
	// Final review M1: the RDP manual-action texts say how to go back to the self-signed certificate.
	for _, tpl := range want[:2] {
		for _, lang := range []string{"en", "tr"} {
			assert.Contains(t, s.Render("ada@example.com", tpl, lang, params).Body, `"Remote Desktop"`, "%s %s", tpl, lang)
		}
	}
}
