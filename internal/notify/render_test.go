package notify_test

import (
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/i18n"
	"alice/internal/inventory"
	"alice/internal/license"
	"alice/internal/notify"
	"alice/internal/sshkeys"
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
		"cert_path": "/etc/nginx/ssl/www.crt", "deployment_id": "0190f5a0-0000-7000-8000-00000000abcd", "backup_dir": "/var/lib/alice-helper/backups/x",
		"operation_id":     "0190f5a0-0000-7000-8000-00000000beef",
		"certificate_name": "web-cert", "count": "37"}
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
		"deployment_id": "0190f5a0-0000-7000-8000-00000000abcd", "backup_dir": "/var/lib/alice-helper/backups/0190f5a0-0000-7000-8000-00000000abcd",
		"operation_id": "0190f5a0-0000-7000-8000-00000000beef"}
	templates := []string{inventory.TemplateDeploymentFailed, inventory.TemplateDeploymentPendingChangeRestored, inventory.TemplateDeploymentRollbackFailed, inventory.TemplateDeploymentNeedsAttention,
		inventory.TemplateDeploymentNeedsAttentionUnconfirmed, inventory.TemplateDeploymentOutcomeUnknown,
		inventory.TemplateDeploymentRestoredUnverified, inventory.TemplateDeploymentSuperseded}
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
	assert.Contains(t, na.Body, "Alice tries again every 15 minutes for about a day, then asks for manual action.")
	natr := s.Render("ada@example.com", inventory.TemplateDeploymentNeedsAttention, "tr", params)
	assert.Contains(t, natr.Body, "Alice yaklaşık bir gün boyunca 15 dakikada bir yeniden dener, sonra elle müdahale ister.")

	// The texts of each rollback_failed cause (Important 1), in both languages.
	for _, tc := range []struct{ tpl, lang, subject, body string }{
		{inventory.TemplateDeploymentNeedsAttentionUnconfirmed, "en", "Alice cannot confirm a deployment on web-01 (İzmir) yet",
			"the server did not answer as expected"},
		{inventory.TemplateDeploymentNeedsAttentionUnconfirmed, "tr", "Alice web-01 (İzmir) sunucusundaki bir dağıtımın sonucunu henüz doğrulayamıyor",
			"sunucu beklendiği gibi yanıt vermedi"},
		{inventory.TemplateDeploymentOutcomeUnknown, "en", "Alice could not confirm a certificate deployment on web-01 (İzmir)",
			"If the change reached the server, the previous files are in /var/lib/alice-helper/backups/0190f5a0-0000-7000-8000-00000000abcd."},
		{inventory.TemplateDeploymentOutcomeUnknown, "tr", "Alice web-01 (İzmir) sunucusundaki bir sertifika dağıtımının sonucunu doğrulayamadı",
			"Değişiklik sunucuya ulaştıysa önceki dosyalar şu klasördedir: /var/lib/alice-helper/backups/0190f5a0-0000-7000-8000-00000000abcd."},
		{inventory.TemplateDeploymentRestoredUnverified, "en", "The previous certificate is back on web-01 (İzmir) but Alice could not confirm the website serves it",
			"Alice put the previous files back. Alice could not confirm that the website serves the previous certificate"},
		{inventory.TemplateDeploymentRestoredUnverified, "tr", "web-01 (İzmir) sunucusunda önceki sertifika geri yüklendi ancak Alice web sitesinin onu sunduğunu doğrulayamadı",
			"Alice önceki dosyaları geri yükledi. Alice web sitesinin önceki sertifikayı sunduğunu doğrulayamadı"},
		{inventory.TemplateDeploymentSuperseded, "en", "A later operation overwrote the files of a deployment on web-01 (İzmir)",
			"a later operation has already replaced the files. Alice did not restore anything."},
		{inventory.TemplateDeploymentSuperseded, "tr", "web-01 (İzmir) sunucusunda sonraki bir işlem bir dağıtımın dosyalarının üzerine yazdı",
			"daha sonraki bir işlem dosyaları zaten değiştirdi. Alice hiçbir şeyi geri yüklemedi."},
		{inventory.TemplateDeploymentSuperseded, "en", "A later operation overwrote the files of a deployment on web-01 (İzmir)",
			"then choose Discover on the server's page in Alice."},
		{inventory.TemplateDeploymentSuperseded, "tr", "web-01 (İzmir) sunucusunda sonraki bir işlem bir dağıtımın dosyalarının üzerine yazdı",
			"sonra Alice'te sunucunun sayfasında Keşfet düğmesine tıklayın."},
	} {
		m := s.Render("ada@example.com", tc.tpl, tc.lang, params)
		assert.Equal(t, tc.subject, m.Subject, "%s %s", tc.tpl, tc.lang)
		assert.Contains(t, m.Body, tc.body, "%s %s", tc.tpl, tc.lang)
	}

	hostile := map[string]string{"target_name": "web", "cert_path": "/etc/x.crt\r\nBcc: evil@example.com", "deployment_id": "d"}
	m := s.Render("ada@example.com", inventory.TemplateDeploymentFailed, "en", hostile)
	assert.NotContains(t, m.Body, "\nBcc:")
}

// The Key Vault emails (Task 11) name the vault and what the person needs, in both languages, and
// carry no value that is not translated: no raw reason code, no yes/no.
func TestKeyVaultTemplatesRenderInBothLanguages(t *testing.T) {
	cat, err := i18n.Load(locales.FS)
	require.NoError(t, err)
	s := &notify.Sender{Catalog: cat}
	params := map[string]string{"target_name": "Üretim kasası", "certificate_name": "web-cert", "count": "37"}
	templates := []string{inventory.TemplateKVAuthFailed, inventory.TemplateKVCertificateRemoved, inventory.TemplateKVCertificateRemovedBound,
		inventory.TemplateKVCertificatesRemovedMore}
	for _, tpl := range templates {
		assert.Contains(t, inventory.Templates(), tpl)
		for _, lang := range []string{"en", "tr"} {
			m := s.Render("ada@example.com", tpl, lang, params)
			text := m.Subject + "\n" + m.Body
			assert.NotContains(t, text, "{{", "%s %s", tpl, lang)
			assert.NotContains(t, m.Subject, "email.", "%s %s", tpl, lang)
			assert.Contains(t, m.Subject, "Üretim kasası", "%s %s", tpl, lang)
			assert.Contains(t, m.Body, "Üretim kasası", "%s %s", tpl, lang)
			assert.NotContains(t, text, "azure.", "%s %s: no raw reason code", tpl, lang)
			assert.NotRegexp(t, `(?i)(: |\()(yes|no)(\.|\)|\n|$)`, text, "%s %s: no untranslated yes/no value", tpl, lang)
		}
	}
	a := s.Render("ada@example.com", inventory.TemplateKVAuthFailed, "en", params)
	assert.Contains(t, a.Body, "at most once an hour")
	free := s.Render("ada@example.com", inventory.TemplateKVCertificateRemoved, "en", params)
	assert.Contains(t, free.Body, "No website is connected")
	bound := s.Render("ada@example.com", inventory.TemplateKVCertificateRemovedBound, "tr", params)
	assert.Contains(t, bound.Subject, "web-cert")
	assert.Contains(t, bound.Body, "Alice bu web sitelerinde hiçbir şeyi değiştirmez")
	more := s.Render("ada@example.com", inventory.TemplateKVCertificatesRemovedMore, "en", params)
	assert.Contains(t, more.Body, "37 more certificates")
	// Exactly one more: the singular text, in both languages, no "1 more certificates".
	one := map[string]string{"target_name": "Üretim kasası", "count": "1"}
	for _, lang := range []string{"en", "tr"} {
		m := s.Render("ada@example.com", inventory.TemplateKVCertificatesRemovedOne, lang, one)
		assert.NotContains(t, m.Subject+m.Body, "{{", lang)
		assert.NotContains(t, m.Subject, "email.", lang)
		assert.Contains(t, m.Body, "Üretim kasası", lang)
		assert.Contains(t, m.Body, "1", lang)
	}
	oneEN := s.Render("ada@example.com", inventory.TemplateKVCertificatesRemovedOne, "en", one)
	assert.Contains(t, oneEN.Body, "1 more certificate disappeared")
	assert.NotContains(t, oneEN.Body, "certificates disappeared in the same check")
}

// rotationParams are what the sshkeys module sends with each rotation template (C10 as built: the code
// param is the run's result reason, never an ALC code).
var rotationParams = map[string]map[string]string{
	sshkeys.TemplatePreview: {"key_label": "ci-deploy (İzmir)", "fingerprint": "SHA256:oldOLDold", "planned_for": "2026-10-06 09:00 UTC",
		"change_count": "12", "skip_count": "3", "rotation_id": "0190f5a0-0000-7000-8000-00000000abcd"},
	sshkeys.TemplatePreviewAfterLicense: {"key_label": "ci-deploy (İzmir)", "fingerprint": "SHA256:oldOLDold", "change_count": "12"},
	sshkeys.TemplateOverlapStarted:      {"key_label": "ci-deploy (İzmir)", "new_fingerprint": "SHA256:newNEWnew", "overlap_until": "2026-10-13 09:00 UTC"},
	sshkeys.TemplateOverlapEnding:       {"key_label": "ci-deploy (İzmir)", "overlap_until": "2026-10-13 09:00 UTC"},
	sshkeys.TemplateCompleted:           {"key_label": "ci-deploy (İzmir)", "new_fingerprint": "SHA256:newNEWnew"},
	sshkeys.TemplateCompletedPartial:    {"key_label": "ci-deploy (İzmir)", "new_fingerprint": "SHA256:newNEWnew", "kept_count": "4"},
	sshkeys.TemplateAborted:             {"key_label": "ci-deploy (İzmir)", "code": sshkeys.ReasonVerifyFailed},
	sshkeys.TemplateNeedsAttention: {"key_label": "ci-deploy (İzmir)", "code": sshkeys.ReasonUndoFailed, "undo_failed_count": "2",
		"undo_failed_servers": "web-01, web-02", "remove_failed_count": "1", "remove_failed_servers": "db-01"},
	sshkeys.TemplatePausedLicense:  {"key_label": "ci-deploy (İzmir)"},
	sshkeys.TemplateDecisionNeeded: {"key_label": "ci-deploy (İzmir)", "count": "2", "decision_due": "2026-10-20 09:00 UTC"},
	// rotation.late_result (sshkeys.TemplateLateResult): what the server did after the run gave up on the place.
	// rotation.nothing_to_rotate (sshkeys.TemplateNothingToRotate): a scheduled plan in which every place is skipped.
	"rotation.nothing_to_rotate": {"key_label": "ci-deploy (İzmir)", "fingerprint": "SHA256:oldOLDold", "skip_count": "2",
		"skips": "web-01: sshd_unreadable; web-02: connection_files_unknown", "next_run_at": "2027-01-04 09:00 UTC"},
	"rotation.late_result": {"key_label": "ci-deploy (İzmir)", "server": "web-01 (İzmir)", "os_user": "deploy",
		"file_path": "/home/deploy/.ssh/authorized_keys", "result": "removed", "rotation_id": "0190f5a0-0000-7000-8000-00000000abcd"},
}

// Every rotation email renders in English and Turkish with the params the module sends (C10, S11, row 31): no
// placeholder is left, the subject is one line that names the key, each value the module sends appears, and no
// private key or passphrase field exists.
func TestRotationTemplatesRender(t *testing.T) {
	cat, err := i18n.Load(locales.FS)
	require.NoError(t, err)
	s := &notify.Sender{Catalog: cat}
	tpls := sshkeys.Templates()
	for tpl := range rotationParams {
		if !slices.Contains(tpls, tpl) {
			tpls = append(tpls, tpl) // a template whose texts exist before the service sends it
		}
	}
	for _, tpl := range tpls {
		params, ok := rotationParams[tpl]
		require.True(t, ok, "%s has no params in this test", tpl)
		for _, lang := range []string{"en", "tr"} {
			m := s.Render("ada@example.com", tpl, lang, params)
			assert.NotContains(t, m.Subject+m.Body, "{{", "%s %s", tpl, lang)
			assert.NotContains(t, m.Subject, "email.", "%s %s: the key itself means a missing text", tpl, lang)
			assert.NotContains(t, m.Subject, "\n", "%s %s", tpl, lang)
			assert.Contains(t, m.Subject, "ci-deploy (İzmir)", "%s %s", tpl, lang)
			for k, v := range params {
				if k == "rotation_id" {
					continue // the delivery check's link to the run (S1), not a text
				}
				assert.Contains(t, m.Body, v, "%s %s: param %s", tpl, lang, k)
			}
			assert.NotContains(t, m.Body, "PRIVATE KEY", "%s %s", tpl, lang)
		}
	}
	// The texts say what the module does (a disabled policy runs only on Run now; the renewal notice is sent before
	// Continue; a partial completion names where the old key stays; a needs-attention mail never claims a removal).
	en := func(tpl string) string { return s.Render("ada@example.com", tpl, "en", rotationParams[tpl]).Body }
	assert.Contains(t, en(sshkeys.TemplatePreview), "starts a run only when an administrator chooses Run now")
	assert.Contains(t, en(sshkeys.TemplatePreviewAfterLicense), "continues only after an administrator chooses Continue")
	assert.Contains(t, en(sshkeys.TemplateCompletedPartial), "Places where the old key stays: 4.")
	assert.Contains(t, en(sshkeys.TemplateAborted), "Reason code: rotation.verify_failed.")
	assert.Contains(t, en(sshkeys.TemplateNeedsAttention), "Alice removes the old key only where a login with the new key worked just before")
	tr := s.Render("ada@example.com", sshkeys.TemplateCompletedPartial, "tr", rotationParams[sshkeys.TemplateCompletedPartial])
	assert.Contains(t, tr.Body, "Eski anahtarın kaldığı yer sayısı: 4.")
	assert.Contains(t, tr.Body, "Lütfen yanıtlamayın.", "the footer is in the person's language")

	// The late-result mail is true whatever the server did, also when nothing was left to remove (re-review N4).
	for _, lang := range []string{"en", "tr"} {
		m := s.Render("ada@example.com", "rotation.late_result", lang, rotationParams["rotation.late_result"])
		assert.NotContains(t, m.Body, "after all", lang)
		assert.NotContains(t, m.Body, "yine de", lang)
	}
	assert.Contains(t, en("rotation.late_result"), "removed: the old key is no longer there; undone: the new key is no longer there")
	assert.Contains(t, en(sshkeys.TemplateNeedsAttention), "removing it again failed: web-01, web-02 (count: 2).")
	assert.Contains(t, en(sshkeys.TemplateNeedsAttention), "Servers where the old key stays because removing it failed: db-01 (count: 1).")

	hostile := map[string]string{"key_label": "x\r\nBcc: evil@example.com"}
	m := s.Render("ada@example.com", sshkeys.TemplatePausedLicense, "en", hostile)
	assert.NotContains(t, m.Subject, "\n")
	assert.NotContains(t, m.Body, "\nBcc:")
}
