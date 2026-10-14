package alerts

// Templates lists every email template of the alerts module (texts in locales/common, Task 14).
func Templates() []string {
	return []string{"alert.certificate_expiring", "alert.certificate_expired", "alert.kv_certificate_expiring",
		"alert.kv_certificate_expired", "alert.kv_key_expiring", "alert.kv_key_expired", "alert.kv_credential_expiring",
		"alert.kv_credential_expired", "alert.discovered_certificate_expiring", "alert.discovered_certificate_expired", "alert.more",
		"alert.more_discovered"}
}
