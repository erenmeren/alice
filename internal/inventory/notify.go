package inventory

// Email templates sent to every Administrator (R37 item 14). Texts: locales/common email.<template>.
const (
	TemplateHostKeyChanged = "target.host_key_changed" // params target_name, old_fingerprint, new_fingerprint
	TemplateAuthFailed     = "target.auth_failed"      // params target_name
)

// Templates lists the inventory's email templates (render tests).
func Templates() []string { return []string{TemplateHostKeyChanged, TemplateAuthFailed} }
