package inventory

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"alice/internal/platform/db"
	"alice/internal/providers"
)

// Email templates sent to every Administrator (R37 item 14). Texts: locales/common email.<template>.
// Every deployment template takes target_name, cert_path and deployment_id, and those that name a
// backup also backup_dir (BackupRoot/<operation id>, Alice's own value, never text from the server).
// A deployment to an http.sys binding of a Windows server is queued in its Windows text instead
// (WindowsTemplate, R61).
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
	// TemplateDeploymentRollbackForbidden (R48): the change failed and Alice did not put the previous
	// certificate back because it, or its key, is revoked or compromised (rollback_failed with
	// deployment.rollback_forbidden); the website may be broken until another certificate is deployed.
	// It never names the backup: restoring it by hand would put the compromised key back.
	TemplateDeploymentRollbackForbidden = "deployment.rollback_forbidden"
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
	// TemplateKVAutoDeployUntrusted: automatic deployment stopped for count websites whose server's service does not
	// accept the vault's keys (R49, design §5.6); sent when the websites are first marked (count, target_name,
	// certificate_name).
	TemplateKVAutoDeployUntrusted = "kv.auto_deploy_untrusted"
)

// Imports into a vault (Task 14): an import ended without a version in the vault, with a reason in the
// certificate's import history (TemplateKVImportFailed), or Alice never learned how it ended
// (TemplateKVImportOutcomeUnknown: 24 hours after the send with a complete listing, 72 hours whatever the
// listings, or the vault was deleted). Both take target_name and certificate_name.
const (
	TemplateKVImportFailed         = "kv.import_failed"
	TemplateKVImportOutcomeUnknown = "kv.import_outcome_unknown"
)

// Summary mails of a planner run that had more notices of a kind than planMailLimit for one vault (params
// target_name and count; the _one forms say "one more"): new versions (available and held), skipped
// versions, and stopped waves.
const (
	TemplateKVNewVersionsMore    = "kv.new_versions_more"
	TemplateKVNewVersionsMoreOne = "kv.new_versions_more_one"
	TemplateKVSkippedMore        = "kv.versions_skipped_more"
	TemplateKVSkippedMoreOne     = "kv.versions_skipped_more_one"
	TemplateKVStoppedMore        = "kv.auto_deploys_stopped_more"
	TemplateKVStoppedMoreOne     = "kv.auto_deploys_stopped_more_one"
)

// ACME renewals (plan 2026-10-13 Task 11; recovery, owner decision 2026-10-20): TemplateACMERenewalFailed goes once
// when an issued certificate with automatic renewal on failed to renew NotifyAfter (3) times in a row;
// TemplateACMEAutoRenewStopped when the failures stopped automatic renewal (renew.ShouldStop). While a renewal fails,
// one of the TemplateACMERenewalExpiring* e-mails goes 14, 7, 3 and 1 days before the current certificate ends (param
// days: the whole days left): _transient after an outage (Alice keeps trying by itself), _permanent after a failure
// that needs a person (Alice still tries a few times), _stopped when automatic renewal stopped.
// TemplateACMERenewalCAWait goes at once when the CA asked Alice to wait so long that less than half of the renewal
// window is left after it (R47; params days and ca_not_before: when the CA accepts orders again, "2006-01-02 15:04
// UTC"). Params: name (the certificate's first name), names (every name, comma-separated, bounded), count (the failures
// in a row), expires_at (when the current certificate ends, "2006-01-02 15:04 UTC"), error_reason (the closed code of the
// last failure: notify.Sender renders it as the plain title of the code in the reader's language, param reason) and
// acme_certificate_id (not rendered: the certificate's page shows how its last e-mail was delivered). No URL, no CA
// text.
const (
	TemplateACMERenewalFailed            = "acme.renewal_failed"
	TemplateACMEAutoRenewStopped         = "acme.auto_renew_stopped"
	TemplateACMERenewalExpiringTransient = "acme.renewal_expiring_transient"
	TemplateACMERenewalExpiringPermanent = "acme.renewal_expiring_permanent"
	TemplateACMERenewalExpiringStopped   = "acme.renewal_expiring_stopped"
	TemplateACMERenewalCAWait            = "acme.renewal_ca_wait"
)

// ACMETemplates lists the ACME renewal emails (render tests; their params differ from Templates' target_name).
func ACMETemplates() []string {
	return []string{TemplateACMERenewalFailed, TemplateACMEAutoRenewStopped, TemplateACMERenewalExpiringTransient,
		TemplateACMERenewalExpiringPermanent, TemplateACMERenewalExpiringStopped, TemplateACMERenewalCAWait}
}

// The e-mails of a key compromise incident (D3, R64 Rulings 5, 6, 11 and 13): queued in the transaction that moves the
// incident, so each move sends exactly one set, also while the licence is locked. Params: certificate_name (at most 200
// runes), incident_id, verified, failed, skipped (the places by status) and, when it needs attention, error_reason (the
// attention code: notify.Sender renders it as the plain title of the code in the reader's language, param reason). The
// recipients are those of the incident's services (incidentServices).
const (
	TemplateIncidentNeedsAttention        = "incident.needs_attention"
	TemplateIncidentCompleted             = "incident.completed"
	TemplateIncidentCompletedNotRevocable = "incident.completed_not_revocable"
)

// IncidentTemplates lists the incident e-mails (render tests; their params differ from Templates' target_name).
func IncidentTemplates() []string {
	return []string{TemplateIncidentNeedsAttention, TemplateIncidentCompleted, TemplateIncidentCompletedNotRevocable}
}

// notifyIncident queues an incident e-mail in tx (the incident's move): the certificate's name and the places by status as
// tx sees them, for the incident's services.
func (s *Service) notifyIncident(ctx context.Context, tx pgx.Tx, id uuid.UUID, template, attentionCode string) error {
	i, err := getIncident(ctx, tx, id)
	if err != nil {
		return err
	}
	svcs, err := incidentServices(ctx, tx, id)
	if err != nil {
		return err
	}
	params := map[string]string{"certificate_name": truncRunes(strings.TrimSpace(i.CertificateName), 200), "incident_id": id.String(),
		"verified": strconv.Itoa(i.Counts[IncidentLocationVerified]), "failed": strconv.Itoa(i.Counts[IncidentLocationFailed]),
		"skipped": strconv.Itoa(i.Counts[IncidentLocationSkipped])}
	if attentionCode != "" {
		params["error_reason"] = attentionCode
	}
	return s.notifier.NotifyServices(ctx, tx, svcs, template, params)
}

// Templates lists the inventory's email templates (render tests).
func Templates() []string {
	return []string{TemplateHostKeyChanged, TemplateAuthFailed, TemplateDeploymentFailed, TemplateDeploymentRollbackFailed,
		TemplateDeploymentOutcomeUnknown, TemplateDeploymentRestoredUnverified, TemplateDeploymentSuperseded, TemplateDeploymentPendingChangeRestored,
		TemplateDeploymentRollbackForbidden,
		TemplateDeploymentNeedsAttention, TemplateDeploymentNeedsAttentionUnconfirmed, TemplateKVAuthFailed, TemplateKVCertificateRemoved,
		TemplateKVCertificateRemovedBound, TemplateKVCertificatesRemovedMore, TemplateKVCertificatesRemovedOne, TemplateKVNewVersion, TemplateKVNewVersionHeldLicense,
		TemplateKVNewVersionHeldChain, TemplateKVSkippedManual, TemplateKVSkippedDisabled, TemplateKVSkippedExpired, TemplateKVSkippedNotYetValid,
		TemplateKVSkippedOlder, TemplateKVSkippedSuperseded, TemplateKVAutoDeployStopped, TemplateKVAutoDeployUntrusted, TemplateKVNewVersionsMore, TemplateKVNewVersionsMoreOne, TemplateKVSkippedMore,
		TemplateKVSkippedMoreOne, TemplateKVStoppedMore, TemplateKVStoppedMoreOne, TemplateKVImportFailed,
		TemplateKVImportOutcomeUnknown, TemplateWindowsCompromisedInStore}
}

// The services an e-mail of this package is about (R56, design §7.2): the notifier sends it to their recipients (the
// Administrators as their policies say, their owners, their extra addresses). Each is read in the e-mail's
// transaction; a row gone since names no service, and an e-mail about no service goes to the Administrators.

// notifyTarget queues an e-mail about a server or a Key Vault (target.*, kv.*) for its service.
func (s *Service) notifyTarget(ctx context.Context, tx pgx.Tx, target uuid.UUID, template string, params map[string]string) error {
	svcs, err := targetServices(ctx, tx, target)
	if err != nil {
		return err
	}
	return s.notifier.NotifyServices(ctx, tx, svcs, template, params)
}

// notifyACME queues an e-mail about an ACME certificate (acme.*) for its service.
func (s *Service) notifyACME(ctx context.Context, tx pgx.Tx, acmeCertificate uuid.UUID, template string, params map[string]string) error {
	svcs, err := acmeServices(ctx, tx, acmeCertificate)
	if err != nil {
		return err
	}
	return s.notifier.NotifyServices(ctx, tx, svcs, template, params)
}

// notifyDeployment queues an e-mail about a deployment (deployment.*) for the destination's and the certificate's
// services; a Windows deployment's in its Windows text (windowsDeploymentMail).
func (s *Service) notifyDeployment(ctx context.Context, tx pgx.Tx, deployment uuid.UUID, template string, params map[string]string) error {
	svcs, err := deploymentServices(ctx, tx, deployment)
	if err != nil {
		return err
	}
	template, params, err = windowsDeploymentMail(ctx, tx, deployment, template, params)
	if err != nil {
		return err
	}
	return s.notifier.NotifyServices(ctx, tx, svcs, template, params)
}

// windowsTemplateSuffix makes the Windows text of a deployment e-mail (WindowsTemplate).
const windowsTemplateSuffix = "_windows"

// WindowsTemplate is the Windows text of the deployment e-mail template (R61): the same facts as the Linux text, for an
// http.sys binding of a Windows server. It names the binding (param cert_path: the binding's canonical text), never a
// file, the Linux helper's backup folder or Nginx; where the Linux text names the backup folder (backup_dir:
// rollback_failed, outcome_unknown) it names the previous certificate instead (previous_certificate). The Linux texts
// and their params are unchanged.
func WindowsTemplate(template string) string { return template + windowsTemplateSuffix }

// WindowsDeploymentTemplates lists the Windows texts of the deployment e-mails (render tests).
func WindowsDeploymentTemplates() []string {
	out := make([]string, 0, len(deploymentTemplates))
	for _, t := range deploymentTemplates {
		out = append(out, WindowsTemplate(t))
	}
	return out
}

// deploymentTemplates are the deployment e-mails (deployment.*), each with a Windows text.
var deploymentTemplates = []string{TemplateDeploymentFailed, TemplateDeploymentRollbackFailed, TemplateDeploymentOutcomeUnknown,
	TemplateDeploymentRestoredUnverified, TemplateDeploymentSuperseded, TemplateDeploymentPendingChangeRestored,
	TemplateDeploymentRollbackForbidden, TemplateDeploymentNeedsAttention, TemplateDeploymentNeedsAttentionUnconfirmed}

// windowsDeploymentMail is the template and params of a deployment e-mail as queued. A deployment to anything but an
// http.sys binding keeps both as given, byte for byte. A binding's (R61) is the Windows text (WindowsTemplate) and, in
// place of backup_dir (a Linux folder; a binding has none), previous_certificate on the texts that named it: what the
// start record wrote of the certificate the binding named before the change (previousCertificate).
func windowsDeploymentMail(ctx context.Context, tx pgx.Tx, deployment uuid.UUID, template string,
	params map[string]string) (string, map[string]string, error) {
	var (
		kind providers.LocationKind
		raw  []byte
	)
	err := tx.QueryRow(ctx, "SELECT location_kind, rollback_info FROM deployments WHERE id = $1", deployment).Scan(&kind, &raw)
	if err != nil {
		return "", nil, fmt.Errorf("inventory: read the deployment's location kind: %w", err)
	}
	if kind != providers.LocationWinSSLBinding || !slices.Contains(deploymentTemplates, template) {
		return template, params, nil
	}
	out := make(map[string]string, len(params))
	for k, v := range params {
		if k != "backup_dir" {
			out[k] = v
		}
	}
	if template == TemplateDeploymentRollbackFailed || template == TemplateDeploymentOutcomeUnknown {
		var ref *providers.BackupRef
		if len(raw) > 0 {
			ref = &providers.BackupRef{}
			if json.Unmarshal(raw, ref) != nil {
				ref = nil
			}
		}
		out["previous_certificate"] = previousCertificate(ref)
	}
	return WindowsTemplate(template), out, nil
}

// previousCertificate names the certificate a Windows binding named before the change, from its start record (W2
// Ruling 17): `<store> \ <thumbprint>` as the deployment's page shows it, else the thumbprint, else "SHA-256 <hex>"
// (the DER's SHA-256, all the record keeps when a scan changed the binding meanwhile), else "-". Only values that keep
// their rule are named; the store only when it is My or WebHosting (the API's rule).
func previousCertificate(ref *providers.BackupRef) string {
	if ref == nil {
		return "-"
	}
	sha1 := backupSHA1RE.MatchString(ref.PreviousSHA1)
	switch {
	case sha1 && mailStoreRE.MatchString(ref.Store):
		return ref.Store + ` \ ` + ref.PreviousSHA1
	case sha1:
		return ref.PreviousSHA1
	case hex64RE.MatchString(ref.PreviousSHA256):
		return "SHA-256 " + ref.PreviousSHA256
	}
	return "-"
}

// notifyLocation queues an e-mail about the website of o (location.drift_*) for its server's and its certificate's
// services; a Windows binding's in its Windows text (windowsLocationMail, R62 Ruling 16).
func (s *Service) notifyLocation(ctx context.Context, tx pgx.Tx, o LocationObservation, template string, params map[string]string) error {
	svcs, err := locationServices(ctx, tx, o.LocationID)
	if err != nil {
		return err
	}
	template, params = windowsLocationMail(o, template, params)
	return s.notifier.NotifyServices(ctx, tx, svcs, template, params)
}

// targetServices is a server's or a Key Vault's service (target.*, kv.*).
func targetServices(ctx context.Context, q db.Querier, target uuid.UUID) ([]uuid.UUID, error) {
	return servicesOf(ctx, q, "SELECT service_id FROM targets WHERE id = $1", target)
}

// incidentServices are an incident's services (incident.*; R56 meets design §5.6): those fixed at its start (service_ids:
// the certificate's and every service holding an affected place) and the certificate's own.
func incidentServices(ctx context.Context, q db.Querier, incident uuid.UUID) ([]uuid.UUID, error) {
	return servicesOf(ctx, q, `SELECT c.service_id FROM certificate_incidents i JOIN certificates c ON c.id = i.certificate_id WHERE i.id = $1
UNION ALL
SELECT unnest(i.service_ids) FROM certificate_incidents i WHERE i.id = $1`, incident)
}

// acmeServices is an ACME certificate's service (acme.*).
func acmeServices(ctx context.Context, q db.Querier, acmeCertificate uuid.UUID) ([]uuid.UUID, error) {
	return servicesOf(ctx, q, "SELECT service_id FROM acme_certificates WHERE id = $1", acmeCertificate)
}

// deploymentServices is the destination server's service and the deployed certificate's owning service
// (deployment.*).
func deploymentServices(ctx context.Context, q db.Querier, deployment uuid.UUID) ([]uuid.UUID, error) {
	return servicesOf(ctx, q, `SELECT t.service_id FROM deployments d JOIN targets t ON t.id = d.target_id WHERE d.id = $1
UNION ALL
SELECT c.service_id FROM deployments d JOIN certificates c ON c.id = d.certificate_id WHERE d.id = $1`, deployment)
}

// locationServices is a website's server's service and the owning service of the certificate it holds
// (location.drift_*: as a deployment's, R52 meets R56).
func locationServices(ctx context.Context, q db.Querier, location uuid.UUID) ([]uuid.UUID, error) {
	return servicesOf(ctx, q, `SELECT t.service_id FROM certificate_locations l JOIN targets t ON t.id = l.target_id WHERE l.id = $1
UNION ALL
SELECT c.service_id FROM certificate_locations l JOIN certificates c ON c.id = l.certificate_id WHERE l.id = $1`, location)
}

// servicesOf reads the service ids a query answers, each once, in their order.
func servicesOf(ctx context.Context, q db.Querier, sql string, args ...any) ([]uuid.UUID, error) {
	rows, err := q.Query(ctx, sql, args...)
	if err != nil {
		return nil, fmt.Errorf("inventory: read the e-mail's services: %w", err)
	}
	defer rows.Close()
	var out []uuid.UUID
	for rows.Next() {
		var id *uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("inventory: read the e-mail's services: %w", err)
		}
		if id != nil && !slices.Contains(out, *id) {
			out = append(out, *id)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("inventory: read the e-mail's services: %w", err)
	}
	return out, nil
}
