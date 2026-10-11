package setup

// Wizard steps the server derives (R43 row 16). The code, language, administrator, authenticator and recovery-code
// steps belong to the browser's setup session, so the position is "" until the administrator exists.
const (
	StepPassphrase = "passphrase"
	StepHTTPS      = "https"
	StepMail       = "mail"
	StepLicense    = "license"
	StepPlatform   = "platform"
	StepDone       = "done"
)

// nextStep is the first unfinished step after the administrator: a reload resumes there.
func nextStep(st Status) string {
	switch {
	case st.Completed:
		return StepDone
	case !st.AdminExists:
		return ""
	case !st.RecoveryPassphraseSet:
		return StepPassphrase
	case !st.HTTPSChosen:
		return StepHTTPS
	case !st.MailChosen:
		return StepMail
	case !st.LicenseChosen:
		return StepLicense
	}
	return StepPlatform
}
