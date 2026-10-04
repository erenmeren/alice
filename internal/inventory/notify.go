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
	// Key Vault (Task 11): the third failed sign-in in a row of a vault (params target_name = the
	// vault's name, reason = the closed reason code), and a vault certificate that disappeared from a
	// complete listing (params target_name, certificate_name, binding "yes" | "no"; F-42).
	TemplateKVAuthFailed         = "kv.auth_failed"
	TemplateKVCertificateRemoved = "kv.certificate_removed"
)

// Templates lists the inventory's email templates (render tests).
func Templates() []string {
	return []string{TemplateHostKeyChanged, TemplateAuthFailed, TemplateDeploymentFailed, TemplateDeploymentRollbackFailed,
		TemplateDeploymentOutcomeUnknown, TemplateDeploymentRestoredUnverified, TemplateDeploymentSuperseded, TemplateDeploymentPendingChangeRestored,
		TemplateDeploymentNeedsAttention, TemplateDeploymentNeedsAttentionUnconfirmed, TemplateKVAuthFailed, TemplateKVCertificateRemoved}
}
