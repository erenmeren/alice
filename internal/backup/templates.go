package backup

// The e-mail templates of the backup module (C14; texts in locales/common).
const (
	TemplateFailed = "backup.failed"
	TemplateAlarm  = "backup.alarm"
	// TemplateAlarmNever is the 48-hour alarm when there was never a successful backup.
	TemplateAlarmNever = "backup.alarm_never"
)

// Templates lists every e-mail template of the backup module.
func Templates() []string { return []string{TemplateFailed, TemplateAlarm, TemplateAlarmNever} }
