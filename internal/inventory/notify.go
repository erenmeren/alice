package inventory

// Email templates sent to every Administrator (R37 item 14). Texts: locales/common email.<template>.
// Every deployment template takes target_name, cert_path and deployment_id, and those that name a
// backup also backup_dir (BackupRoot/<operation id>, Alice's own value, never text from the server).
const (
	TemplateHostKeyChanged = "target.host_key_changed" // params target_name, old_fingerprint, new_fingerprint
	TemplateAuthFailed     = "target.auth_failed"      // params target_name
	// TemplateDeploymentFailed: a deployment ended and the server keeps (or has back) its previous
	// certificate (status failed or rolled_back).
	TemplateDeploymentFailed = "deployment.failed"
	// TemplateDeploymentRollbackFailed: the change failed and the automatic restore failed too
	// (status rollback_failed: the helper's restore_failed, or the restore refused because a file
	// changed); manual action, with backup_dir.
	TemplateDeploymentRollbackFailed = "deployment.rollback_failed"
	// TemplateDeploymentOutcomeUnknown: Alice stopped without knowing how the deployment ended
	// (rollback_failed with deployment.recovery_exhausted or deployment.target_deleted after a
	// send); what to check, and where the backup is if the change reached the server (backup_dir).
	TemplateDeploymentOutcomeUnknown = "deployment.outcome_unknown"
	// TemplateDeploymentRestoredUnverified: the previous files are back but the website does not
	// serve the previous certificate (rollback_failed, phase restored, failed step verify_old).
	TemplateDeploymentRestoredUnverified = "deployment.restored_unverified"
	// TemplateDeploymentSuperseded: a later operation replaced the files; nothing was restored
	// (rollback_failed with deployment.superseded).
	TemplateDeploymentSuperseded = "deployment.superseded"
	// TemplateDeploymentPendingChangeRestored: a deployment put back the files from before an
	// unfinished earlier change and then ended without writing its own certificate (rolled_back with
	// deployment.pending_change_restored); the website serves an older certificate. Params also
	// operation_id (the earlier change, a UUID of Alice's or the helper's validated form).
	TemplateDeploymentPendingChangeRestored = "deployment.pending_change_restored"
	// TemplateDeploymentNeedsAttention: Alice cannot reach the server to finish or undo a
	// deployment and keeps trying (about a day); sent once per deployment.
	TemplateDeploymentNeedsAttention = "deployment.needs_attention"
	// TemplateDeploymentNeedsAttentionUnconfirmed: as TemplateDeploymentNeedsAttention when the
	// server answered but not as expected (the cause is not a lost connection).
	TemplateDeploymentNeedsAttentionUnconfirmed = "deployment.needs_attention_unconfirmed"
	// Key Vault (Task 11): the third failed sign-in in a row of a vault (param target_name = the
	// vault's name; the reason is on the vault's page), and vault certificates that disappeared from a
	// complete listing (F-42).
	TemplateKVAuthFailed = "kv.auth_failed"
	// The removal mails come in two texts (no yes/no value to translate): TemplateKVCertificateRemoved
	// says the certificate is not connected to websites, TemplateKVCertificateRemovedBound that it is
	// and what that means; both take target_name and certificate_name. TemplateKVCertificatesRemovedMore
	// is the one summary mail when a poll removed more certificates than it mails about (params
	// target_name, count = the certificates not mailed).
	TemplateKVCertificateRemoved      = "kv.certificate_removed"
	TemplateKVCertificateRemovedBound = "kv.certificate_removed_bound"
	TemplateKVCertificatesRemovedMore = "kv.certificates_removed_more"
)

// Key Vault renewals (Task 13). The planner mails each fact once (the version's notified_at or
// skipped_notified_at) and says what happened in its own text: no raw code, no yes/no value. All take
// target_name (the vault) and certificate_name; TemplateKVAutoDeployStopped also count (the
// failed deployments). They name no version: a version ID is 32 hex digits no reader can use, and
// the certificate's page lists its versions. TemplateKVNewVersion: a version arrived and automatic deployment is off;
// the held ones: it arrived while Alice could not change anything (licence) or its chain is
// incomplete; TemplateKVSkippedManual: it arrived but misses the rule for automatic deployment; the
// other skipped ones say why a version that qualified will not be deployed.
const (
	TemplateKVNewVersion            = "kv.new_version_available"
	TemplateKVNewVersionHeldLicense = "kv.new_version_held_license"
	TemplateKVNewVersionHeldChain   = "kv.new_version_held_chain"
	TemplateKVSkippedManual         = "kv.version_skipped_manual"
	TemplateKVSkippedDisabled       = "kv.version_skipped_disabled"
	TemplateKVSkippedExpired        = "kv.version_skipped_expired"
	TemplateKVSkippedNotYetValid    = "kv.version_skipped_not_yet_valid"
	TemplateKVSkippedOlder          = "kv.version_skipped_older"
	TemplateKVSkippedSuperseded     = "kv.version_skipped_superseded"
	TemplateKVAutoDeployStopped     = "kv.auto_deploy_stopped"
)

// Templates lists the inventory's email templates (render tests).
func Templates() []string {
	return []string{TemplateHostKeyChanged, TemplateAuthFailed, TemplateDeploymentFailed, TemplateDeploymentRollbackFailed,
		TemplateDeploymentOutcomeUnknown, TemplateDeploymentRestoredUnverified, TemplateDeploymentSuperseded, TemplateDeploymentPendingChangeRestored,
		TemplateDeploymentNeedsAttention, TemplateDeploymentNeedsAttentionUnconfirmed, TemplateKVAuthFailed, TemplateKVCertificateRemoved,
		TemplateKVCertificateRemovedBound, TemplateKVCertificatesRemovedMore, TemplateKVCertificatesRemovedOne, TemplateKVNewVersion, TemplateKVNewVersionHeldLicense,
		TemplateKVNewVersionHeldChain, TemplateKVSkippedManual, TemplateKVSkippedDisabled, TemplateKVSkippedExpired, TemplateKVSkippedNotYetValid,
		TemplateKVSkippedOlder, TemplateKVSkippedSuperseded, TemplateKVAutoDeployStopped}
}
