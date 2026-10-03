package inventory

// Email templates sent to every Administrator (R37 item 14). Texts: locales/common email.<template>.
const (
	TemplateHostKeyChanged = "target.host_key_changed" // params target_name, old_fingerprint, new_fingerprint
	TemplateAuthFailed     = "target.auth_failed"      // params target_name
	// TemplateDeploymentFailed: a deployment ended and the server keeps (or has back) its previous
	// certificate (status failed or rolled_back). Params target_name, cert_path, deployment_id.
	TemplateDeploymentFailed = "deployment.failed"
	// TemplateDeploymentRollbackFailed: manual action is needed (status rollback_failed). Params
	// target_name, cert_path, deployment_id, backup_dir.
	TemplateDeploymentRollbackFailed = "deployment.rollback_failed"
	// TemplateDeploymentNeedsAttention: Alice cannot reach the server to finish or undo a
	// deployment and keeps trying; sent once per deployment. Params target_name, cert_path,
	// deployment_id.
	TemplateDeploymentNeedsAttention = "deployment.needs_attention"
)

// Templates lists the inventory's email templates (render tests).
func Templates() []string {
	return []string{TemplateHostKeyChanged, TemplateAuthFailed, TemplateDeploymentFailed, TemplateDeploymentRollbackFailed,
		TemplateDeploymentNeedsAttention}
}
