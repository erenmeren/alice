package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"net/netip"
	"regexp"
	"strconv"
	"time"

	"alice/internal/auth"
	"alice/internal/inventory"
	"alice/internal/jobs"
	"alice/internal/license"
	"alice/internal/platform/validate"
	"alice/internal/providers"
	"alice/internal/setup"
)

// ErrorCode is a stable, documented API error. Codes are never reused.
type ErrorCode struct {
	Code      string
	Reason    string
	Status    int
	Retryable bool
}

var (
	ErrNotFound           = ErrorCode{Code: "ALC-SYS-0001", Reason: "system.not_found", Status: http.StatusNotFound}
	ErrUnavailable        = ErrorCode{Code: "ALC-SYS-0002", Reason: "system.unavailable", Status: http.StatusServiceUnavailable, Retryable: true}
	ErrUnexpected         = ErrorCode{Code: "ALC-SYS-0003", Reason: "internal.unexpected", Status: http.StatusInternalServerError}
	ErrBadRequest         = ErrorCode{Code: "ALC-SYS-0004", Reason: "system.bad_request", Status: http.StatusBadRequest}
	ErrRateLimited        = ErrorCode{Code: "ALC-SYS-0005", Reason: "rate.limited", Status: http.StatusTooManyRequests, Retryable: true}
	ErrValidation         = ErrorCode{Code: "ALC-SYS-0006", Reason: "validation.failed", Status: http.StatusUnprocessableEntity}
	ErrBodyTooLarge       = ErrorCode{Code: "ALC-SYS-0007", Reason: "system.body_too_large", Status: http.StatusRequestEntityTooLarge}
	ErrPreconditionFailed = ErrorCode{Code: "ALC-SYS-0008", Reason: "system.precondition_failed", Status: http.StatusPreconditionFailed}

	ErrUnauthenticated        = ErrorCode{Code: "ALC-AUTH-0001", Reason: "auth.unauthenticated", Status: http.StatusUnauthorized}
	ErrForbidden              = ErrorCode{Code: "ALC-AUTH-0002", Reason: "auth.forbidden", Status: http.StatusForbidden}
	ErrStepUpRequired         = ErrorCode{Code: "ALC-AUTH-0003", Reason: "auth.stepup_required", Status: http.StatusForbidden}
	ErrCSRF                   = ErrorCode{Code: "ALC-AUTH-0004", Reason: "auth.csrf_failed", Status: http.StatusForbidden}
	ErrInvalidCredentials     = ErrorCode{Code: "ALC-AUTH-0005", Reason: "auth.invalid_credentials", Status: http.StatusUnauthorized}
	ErrMFAInvalid             = ErrorCode{Code: "ALC-AUTH-0006", Reason: "auth.mfa_invalid", Status: http.StatusUnauthorized}
	ErrMFAAlreadyEnrolled     = ErrorCode{Code: "ALC-AUTH-0007", Reason: "auth.mfa_already_enrolled", Status: http.StatusConflict}
	ErrPasswordTooShort       = ErrorCode{Code: "ALC-AUTH-0008", Reason: "auth.password_too_short", Status: http.StatusUnprocessableEntity}
	ErrPasswordTooLong        = ErrorCode{Code: "ALC-AUTH-0009", Reason: "auth.password_too_long", Status: http.StatusUnprocessableEntity}
	ErrPasswordBreached       = ErrorCode{Code: "ALC-AUTH-0010", Reason: "auth.password_breached", Status: http.StatusUnprocessableEntity}
	ErrCurrentPasswordInvalid = ErrorCode{Code: "ALC-AUTH-0011", Reason: "auth.current_password_invalid", Status: http.StatusUnprocessableEntity}
	ErrTryAgain               = ErrorCode{Code: "ALC-AUTH-0012", Reason: "auth.try_again", Status: http.StatusServiceUnavailable, Retryable: true}

	ErrUsernameTaken        = ErrorCode{Code: "ALC-USR-0001", Reason: "user.username_taken", Status: http.StatusConflict}
	ErrLastAdmin            = ErrorCode{Code: "ALC-USR-0002", Reason: "user.last_admin", Status: http.StatusConflict}
	ErrTokenScopeNotAllowed = ErrorCode{Code: "ALC-TOK-0001", Reason: "token.scope_not_allowed", Status: http.StatusUnprocessableEntity}
	// ErrAuditBusy: another verification or export of the audit log is running in this process (AUD-06).
	ErrAuditBusy = ErrorCode{Code: "ALC-AUD-0001", Reason: "audit.busy", Status: http.StatusServiceUnavailable, Retryable: true}

	ErrSetupCodeInvalid          = ErrorCode{Code: "ALC-SET-0001", Reason: "setup.code_invalid", Status: http.StatusUnauthorized}
	ErrSetupLocked               = ErrorCode{Code: "ALC-SET-0002", Reason: "setup.locked", Status: http.StatusTooManyRequests, Retryable: true}
	ErrSetupSessionExpired       = ErrorCode{Code: "ALC-SET-0003", Reason: "setup.session_expired", Status: http.StatusUnauthorized}
	ErrSetupEnrollmentMissing    = ErrorCode{Code: "ALC-SET-0004", Reason: "setup.enrollment_missing", Status: http.StatusConflict}
	ErrPassphraseTooShort        = ErrorCode{Code: "ALC-SET-0005", Reason: "setup.passphrase_too_short", Status: http.StatusUnprocessableEntity}
	ErrPassphraseMismatch        = ErrorCode{Code: "ALC-SET-0006", Reason: "setup.passphrase_mismatch", Status: http.StatusUnprocessableEntity}
	ErrPassphraseAlreadySet      = ErrorCode{Code: "ALC-SET-0007", Reason: "setup.passphrase_already_set", Status: http.StatusConflict}
	ErrSetupIncomplete           = ErrorCode{Code: "ALC-SET-0008", Reason: "setup.incomplete", Status: http.StatusConflict}
	ErrSetupLicenseChoiceMissing = ErrorCode{Code: "ALC-SET-0009", Reason: "setup.license_choice_missing", Status: http.StatusConflict}

	ErrLicenseLocked             = ErrorCode{Code: "ALC-LIC-0001", Reason: "license.locked", Status: http.StatusForbidden}
	ErrLicenseInvalid            = ErrorCode{Code: "ALC-LIC-0002", Reason: "license.invalid", Status: http.StatusUnprocessableEntity}
	ErrLicenseWrongInstallation  = ErrorCode{Code: "ALC-LIC-0003", Reason: "license.wrong_installation", Status: http.StatusUnprocessableEntity}
	ErrLicenseUnknownKey         = ErrorCode{Code: "ALC-LIC-0004", Reason: "license.unknown_key", Status: http.StatusUnprocessableEntity}
	ErrLicenseRevokedKey         = ErrorCode{Code: "ALC-LIC-0005", Reason: "license.revoked_key", Status: http.StatusUnprocessableEntity}
	ErrLicenseUnsupportedFormat  = ErrorCode{Code: "ALC-LIC-0006", Reason: "license.unsupported_format", Status: http.StatusUnprocessableEntity}
	ErrLicenseOlderThanInstalled = ErrorCode{Code: "ALC-LIC-0007", Reason: "license.older_than_installed", Status: http.StatusConflict}
	ErrLicenseTargetLimit        = ErrorCode{Code: "ALC-LIC-0008", Reason: "license.target_limit_reached", Status: http.StatusConflict}
	// ErrLicenseUnverified: no license evaluation has succeeded for 3 hours (AUD-02); changes resume
	// after the next successful one.
	ErrLicenseUnverified = ErrorCode{Code: "ALC-LIC-0009", Reason: "license.unverified", Status: http.StatusServiceUnavailable, Retryable: true}

	// Phase 3: servers, SSH, keys and jobs (R37). The SSH and job reasons are mostly carried by job
	// records and target statuses; the API answers with them when a request fails for that reason.
	ErrTargetDuplicate    = ErrorCode{Code: "ALC-TGT-0001", Reason: "target.duplicate", Status: http.StatusConflict}
	ErrHostKeyUnconfirmed = ErrorCode{Code: "ALC-TGT-0002", Reason: "target.host_key_unconfirmed", Status: http.StatusConflict}
	ErrHostKeyStale       = ErrorCode{Code: "ALC-TGT-0003", Reason: "target.host_key_stale", Status: http.StatusConflict}
	ErrHostKeyChanged     = ErrorCode{Code: "ALC-TGT-0004", Reason: "target.host_key_changed", Status: http.StatusConflict}
	ErrHostKeyState       = ErrorCode{Code: "ALC-TGT-0005", Reason: "target.host_key_state", Status: http.StatusConflict}
	ErrTargetDisabled     = ErrorCode{Code: "ALC-TGT-0006", Reason: "target.disabled", Status: http.StatusConflict}

	ErrSSHUnreachable       = ErrorCode{Code: "ALC-SSH-0001", Reason: "ssh.unreachable", Status: http.StatusBadGateway, Retryable: true}
	ErrSSHAuthFailed        = ErrorCode{Code: "ALC-SSH-0002", Reason: "ssh.auth_failed", Status: http.StatusBadGateway}
	ErrSSHTimeout           = ErrorCode{Code: "ALC-SSH-0003", Reason: "ssh.timeout", Status: http.StatusGatewayTimeout, Retryable: true}
	ErrHelperMissing        = ErrorCode{Code: "ALC-SSH-0004", Reason: "ssh.helper_missing", Status: http.StatusBadGateway}
	ErrHelperOutdated       = ErrorCode{Code: "ALC-SSH-0005", Reason: "ssh.helper_outdated", Status: http.StatusBadGateway}
	ErrHelperRefused        = ErrorCode{Code: "ALC-SSH-0006", Reason: "ssh.helper_refused", Status: http.StatusBadGateway}
	ErrFileChanged          = ErrorCode{Code: "ALC-SSH-0007", Reason: "ssh.file_changed", Status: http.StatusConflict, Retryable: true}
	ErrKeysManagedElsewhere = ErrorCode{Code: "ALC-SSH-0008", Reason: "ssh.keys_managed_elsewhere", Status: http.StatusConflict}
	ErrOutputTooLarge       = ErrorCode{Code: "ALC-SSH-0009", Reason: "ssh.output_too_large", Status: http.StatusBadGateway}
	ErrSSHProtocol          = ErrorCode{Code: "ALC-SSH-0010", Reason: "ssh.protocol_error", Status: http.StatusBadGateway}
	ErrHelperChecksums      = ErrorCode{Code: "ALC-SSH-0011", Reason: "ssh.helper_checksums_missing", Status: http.StatusInternalServerError}
	// ErrSSHAddressNotAllowed: the server's name resolved, when Alice connected, to an address the
	// target rule refuses (AUD-25 a); not retryable.
	ErrSSHAddressNotAllowed = ErrorCode{Code: "ALC-SSH-0012", Reason: "ssh.address_not_allowed", Status: http.StatusBadGateway}

	ErrOwnKeyProtected = ErrorCode{Code: "ALC-KEY-0001", Reason: "sshkey.own_key_protected", Status: http.StatusConflict}
	ErrLastRootKey     = ErrorCode{Code: "ALC-KEY-0002", Reason: "sshkey.last_root_key", Status: http.StatusConflict}
	ErrKeyNotRemovable = ErrorCode{Code: "ALC-KEY-0003", Reason: "sshkey.not_removable", Status: http.StatusConflict}
	ErrSSHDUnreadable  = ErrorCode{Code: "ALC-KEY-0004", Reason: "sshkey.sshd_unreadable", Status: http.StatusConflict}
	ErrKeyVerifyFailed = ErrorCode{Code: "ALC-KEY-0005", Reason: "sshkey.verify_failed", Status: http.StatusBadGateway}

	ErrJobNotWaiting   = ErrorCode{Code: "ALC-JOB-0001", Reason: "job.not_waiting", Status: http.StatusConflict}
	ErrJobLeaseExpired = ErrorCode{Code: "ALC-JOB-0002", Reason: "job.lease_expired", Status: http.StatusInternalServerError, Retryable: true}
	ErrJobTampered     = ErrorCode{Code: "ALC-JOB-0003", Reason: "job.tampered", Status: http.StatusInternalServerError}
	ErrJobUnknownType  = ErrorCode{Code: "ALC-JOB-0004", Reason: "job.unknown_type", Status: http.StatusInternalServerError}
	ErrJobConflict     = ErrorCode{Code: "ALC-JOB-0005", Reason: "job.conflict", Status: http.StatusConflict}

	// Phase 4: Nginx, certificates, signing requests and deployments (R38). The nginx.* and most
	// deployment.* reasons are carried by deployment and job records; the API answers with the
	// request refusals (inventory sentinels) directly.
	ErrNginxNotFound            = ErrorCode{Code: "ALC-NGX-0001", Reason: "nginx.not_found", Status: http.StatusBadGateway}
	ErrNginxConfigInvalid       = ErrorCode{Code: "ALC-NGX-0002", Reason: "nginx.config_invalid", Status: http.StatusConflict}
	ErrNginxConfigChanged       = ErrorCode{Code: "ALC-NGX-0003", Reason: "nginx.config_changed", Status: http.StatusConflict}
	ErrNginxProfileMissing      = ErrorCode{Code: "ALC-NGX-0004", Reason: "nginx.profile_missing", Status: http.StatusBadGateway}
	ErrNginxNoSpace             = ErrorCode{Code: "ALC-NGX-0005", Reason: "nginx.no_space", Status: http.StatusBadGateway}
	ErrNginxFileChanged         = ErrorCode{Code: "ALC-NGX-0006", Reason: "nginx.file_changed", Status: http.StatusConflict}
	ErrNginxLocationUnsupported = ErrorCode{Code: "ALC-NGX-0007", Reason: "nginx.location_unsupported", Status: http.StatusConflict}
	ErrNginxBusy                = ErrorCode{Code: "ALC-NGX-0008", Reason: "nginx.busy", Status: http.StatusConflict, Retryable: true}
	// ErrNginxIOError replaces the plan's nginx.write_failed (never produced): nginx-deploy's
	// IO_ERROR, whose causes the helper's answer does not tell apart; nothing was changed.
	ErrNginxIOError = ErrorCode{Code: "ALC-NGX-0009", Reason: "nginx.io_error", Status: http.StatusBadGateway, Retryable: true}
	// ErrNginxNotRunning: nginx-deploy refused before writing anything because systemctl is missing or
	// the nginx unit is not active (a reload could not apply the files).
	ErrNginxNotRunning = ErrorCode{Code: "ALC-NGX-0010", Reason: "nginx.not_running", Status: http.StatusBadGateway}

	ErrCertInvalid            = ErrorCode{Code: "ALC-CRT-0001", Reason: "certificate.invalid", Status: http.StatusUnprocessableEntity}
	ErrCertKeyMismatch        = ErrorCode{Code: "ALC-CRT-0002", Reason: "certificate.key_mismatch", Status: http.StatusUnprocessableEntity}
	ErrCertExpired            = ErrorCode{Code: "ALC-CRT-0003", Reason: "certificate.expired", Status: http.StatusUnprocessableEntity}
	ErrCertKeyEncrypted       = ErrorCode{Code: "ALC-CRT-0004", Reason: "certificate.key_encrypted", Status: http.StatusUnprocessableEntity}
	ErrCertPFXPassword        = ErrorCode{Code: "ALC-CRT-0005", Reason: "certificate.pfx_password", Status: http.StatusUnprocessableEntity}
	ErrCertWeak               = ErrorCode{Code: "ALC-CRT-0006", Reason: "certificate.weak", Status: http.StatusUnprocessableEntity}
	ErrCertUnsupportedKey     = ErrorCode{Code: "ALC-CRT-0007", Reason: "certificate.unsupported_key", Status: http.StatusUnprocessableEntity}
	ErrCertDuplicate          = ErrorCode{Code: "ALC-CRT-0008", Reason: "certificate.duplicate", Status: http.StatusConflict}
	ErrCertNoPrivateKey       = ErrorCode{Code: "ALC-CRT-0009", Reason: "certificate.no_private_key", Status: http.StatusConflict}
	ErrCertKeyTypeMismatch    = ErrorCode{Code: "ALC-CRT-0010", Reason: "certificate.key_type_mismatch", Status: http.StatusConflict}
	ErrCertChainUnconfirmed   = ErrorCode{Code: "ALC-CRT-0011", Reason: "certificate.chain_unconfirmed", Status: http.StatusConflict}
	ErrCSRNotPending          = ErrorCode{Code: "ALC-CRT-0012", Reason: "csr.not_pending", Status: http.StatusConflict}
	ErrCSRCertificateMismatch = ErrorCode{Code: "ALC-CRT-0013", Reason: "csr.certificate_mismatch", Status: http.StatusUnprocessableEntity}
	ErrCertNotYetValid        = ErrorCode{Code: "ALC-CRT-0014", Reason: "certificate.not_yet_valid", Status: http.StatusConflict}
	ErrCertPFXBusy            = ErrorCode{Code: "ALC-CRT-0015", Reason: "certificate.pfx_busy", Status: http.StatusServiceUnavailable, Retryable: true}
	ErrCSRBusy                = ErrorCode{Code: "ALC-CRT-0016", Reason: "csr.busy", Status: http.StatusServiceUnavailable, Retryable: true}
	ErrCSRTooManyPending      = ErrorCode{Code: "ALC-CRT-0017", Reason: "csr.too_many_pending", Status: http.StatusConflict}

	ErrDeployInProgress           = ErrorCode{Code: "ALC-DEP-0001", Reason: "deployment.in_progress", Status: http.StatusConflict, Retryable: true}
	ErrDeployRecoveryPending      = ErrorCode{Code: "ALC-DEP-0002", Reason: "deployment.recovery_pending", Status: http.StatusConflict, Retryable: true}
	ErrDeployVerifyFailed         = ErrorCode{Code: "ALC-DEP-0003", Reason: "deployment.verify_failed", Status: http.StatusBadGateway}
	ErrDeployVerifyOther          = ErrorCode{Code: "ALC-DEP-0004", Reason: "deployment.verify_other", Status: http.StatusBadGateway}
	ErrDeployVerifyUnreachable    = ErrorCode{Code: "ALC-DEP-0005", Reason: "deployment.verify_unreachable", Status: http.StatusBadGateway}
	ErrDeployReloadFailed         = ErrorCode{Code: "ALC-DEP-0006", Reason: "deployment.reload_failed", Status: http.StatusBadGateway}
	ErrDeployConfigTestFailed     = ErrorCode{Code: "ALC-DEP-0007", Reason: "deployment.config_test_failed", Status: http.StatusBadGateway}
	ErrDeployRollbackFailed       = ErrorCode{Code: "ALC-DEP-0008", Reason: "deployment.rollback_failed", Status: http.StatusBadGateway}
	ErrDeployRollbackReloadFailed = ErrorCode{Code: "ALC-DEP-0009", Reason: "deployment.rollback_reload_failed", Status: http.StatusBadGateway}
	ErrDeployInterrupted          = ErrorCode{Code: "ALC-DEP-0010", Reason: "deployment.interrupted", Status: http.StatusBadGateway}
	ErrDeployTargetNotReady       = ErrorCode{Code: "ALC-DEP-0011", Reason: "deployment.target_not_ready", Status: http.StatusConflict}
	ErrDeployVerifyChain          = ErrorCode{Code: "ALC-DEP-0012", Reason: "deployment.verify_chain", Status: http.StatusBadGateway}
	ErrDeployNothingToRestore     = ErrorCode{Code: "ALC-DEP-0013", Reason: "deployment.nothing_to_restore", Status: http.StatusBadGateway}
	ErrDeploySuperseded           = ErrorCode{Code: "ALC-DEP-0014", Reason: "deployment.superseded", Status: http.StatusBadGateway}
	ErrDeployUnknownOperation     = ErrorCode{Code: "ALC-DEP-0015", Reason: "deployment.unknown_operation", Status: http.StatusBadGateway}
	ErrDeployTargetDeleted        = ErrorCode{Code: "ALC-DEP-0016", Reason: "deployment.target_deleted", Status: http.StatusConflict}
	ErrDeployRecoveryExhausted    = ErrorCode{Code: "ALC-DEP-0017", Reason: "deployment.recovery_exhausted", Status: http.StatusBadGateway}
	ErrDeployOutcomeUnknown       = ErrorCode{Code: "ALC-DEP-0018", Reason: "deployment.outcome_unknown", Status: http.StatusBadGateway}
	// ErrDeployRestoredUnverified and ErrDeployRollbackFileChanged split deployment.rollback_failed
	// by what the record says happened (refineReason): the files are back but the old certificate
	// was not confirmed, or the restore was refused because another program changed the files.
	ErrDeployRestoredUnverified  = ErrorCode{Code: "ALC-DEP-0019", Reason: "deployment.restored_unverified", Status: http.StatusBadGateway}
	ErrDeployRollbackFileChanged = ErrorCode{Code: "ALC-DEP-0020", Reason: "deployment.rollback_file_changed", Status: http.StatusBadGateway}
	ErrDeployRescanNeeded        = ErrorCode{Code: "ALC-DEP-0021", Reason: "deployment.rescan_needed", Status: http.StatusConflict}
	// ErrDeployCancelled: an Administrator discarded the deployment's waiting job before anything
	// was sent (a stored reason; no failure email).
	ErrDeployCancelled = ErrorCode{Code: "ALC-DEP-0022", Reason: "deployment.cancelled", Status: http.StatusConflict}
	// ErrDeployServerOperationPending: the server refused the deployment because an interrupted
	// operation Alice no longer tracks blocks the files, and Alice could not restore it (param
	// operation_id; nothing was written).
	ErrDeployServerOperationPending = ErrorCode{Code: "ALC-DEP-0023", Reason: "deployment.server_operation_pending", Status: http.StatusConflict}
	// ErrDeployPendingChangeRestored: Alice put back the files of an unfinished earlier change it no
	// longer tracked (param operation_id); the website serves the certificate from before that
	// change; this deployment's certificate was not written (status rolled_back).
	ErrDeployPendingChangeRestored = ErrorCode{Code: "ALC-DEP-0024", Reason: "deployment.pending_change_restored", Status: http.StatusConflict}

	// Phase 5: Azure Key Vault (R40). ALC-AKV-0001..0027 are the contract's table; 0028 and later
	// cover what the code stores or answers that the table did not name (the reasons of a deployment
	// that did not start, the vault-worded duplicate, the import refusals of the provider).
	ErrAzureAuthFailed          = ErrorCode{Code: "ALC-AKV-0001", Reason: "azure.auth_failed", Status: http.StatusBadGateway}
	ErrAzureCredentialsExpired  = ErrorCode{Code: "ALC-AKV-0002", Reason: "azure.credentials_expired", Status: http.StatusBadGateway}
	ErrAzureForbidden           = ErrorCode{Code: "ALC-AKV-0003", Reason: "azure.forbidden", Status: http.StatusBadGateway}
	ErrAzureFirewall            = ErrorCode{Code: "ALC-AKV-0004", Reason: "azure.firewall", Status: http.StatusBadGateway}
	ErrAzureVaultNotFound       = ErrorCode{Code: "ALC-AKV-0005", Reason: "azure.vault_not_found", Status: http.StatusBadGateway}
	ErrAzureUnreachable         = ErrorCode{Code: "ALC-AKV-0006", Reason: "azure.unreachable", Status: http.StatusBadGateway, Retryable: true}
	ErrAzureThrottled           = ErrorCode{Code: "ALC-AKV-0007", Reason: "azure.throttled", Status: http.StatusServiceUnavailable, Retryable: true}
	ErrAzureUnexpectedResponse  = ErrorCode{Code: "ALC-AKV-0008", Reason: "azure.unexpected_response", Status: http.StatusBadGateway, Retryable: true}
	ErrAzureClockSkew           = ErrorCode{Code: "ALC-AKV-0009", Reason: "azure.clock_skew", Status: http.StatusBadGateway}
	ErrAzureManagedIdentityGone = ErrorCode{Code: "ALC-AKV-0010", Reason: "azure.managed_identity_unavailable", Status: http.StatusBadGateway}
	// ErrAzureAddressNotAllowed is also what a region or SDK-logging variable in Alice's own
	// environment produces (the provider refuses to start a session then): its text says so.
	ErrAzureAddressNotAllowed = ErrorCode{Code: "ALC-AKV-0011", Reason: "azure.address_not_allowed", Status: http.StatusBadGateway}
	ErrAzureTLSUntrusted      = ErrorCode{Code: "ALC-AKV-0012", Reason: "azure.tls_untrusted", Status: http.StatusBadGateway}
	ErrKVNotExportable        = ErrorCode{Code: "ALC-AKV-0013", Reason: "kv.not_exportable", Status: http.StatusUnprocessableEntity}
	ErrKVVersionDisabled      = ErrorCode{Code: "ALC-AKV-0014", Reason: "kv.version_disabled", Status: http.StatusConflict}
	ErrKVCertificateNotFound  = ErrorCode{Code: "ALC-AKV-0015", Reason: "kv.certificate_not_found", Status: http.StatusConflict}
	ErrKVSecretUnreadable     = ErrorCode{Code: "ALC-AKV-0016", Reason: "kv.secret_unreadable", Status: http.StatusBadGateway}
	ErrKVSecretMismatch       = ErrorCode{Code: "ALC-AKV-0017", Reason: "kv.secret_mismatch", Status: http.StatusBadGateway}
	ErrKVLocationBound        = ErrorCode{Code: "ALC-AKV-0018", Reason: "kv.location_bound", Status: http.StatusConflict}
	ErrKVBindingExists        = ErrorCode{Code: "ALC-AKV-0019", Reason: "kv.binding_exists", Status: http.StatusConflict}
	ErrKVVaultHasBindings     = ErrorCode{Code: "ALC-AKV-0020", Reason: "kv.vault_has_bindings", Status: http.StatusConflict}
	ErrKVVersionNotDeployable = ErrorCode{Code: "ALC-AKV-0021", Reason: "kv.version_not_deployable", Status: http.StatusConflict}
	ErrKVHeldNeedsAdmin       = ErrorCode{Code: "ALC-AKV-0022", Reason: "kv.held_needs_admin", Status: http.StatusForbidden}
	ErrKVImportConfirmNeeded  = ErrorCode{Code: "ALC-AKV-0023", Reason: "kv.import_confirm_needed", Status: http.StatusConflict}
	ErrKVImportInProgress     = ErrorCode{Code: "ALC-AKV-0024", Reason: "kv.import_in_progress", Status: http.StatusConflict, Retryable: true}
	ErrKVImportRejected       = ErrorCode{Code: "ALC-AKV-0025", Reason: "kv.import_rejected", Status: http.StatusBadGateway}
	ErrKVImportOutcomeUnknown = ErrorCode{Code: "ALC-AKV-0026", Reason: "kv.import_outcome_unknown", Status: http.StatusBadGateway}
	ErrKVClientCertInvalid    = ErrorCode{Code: "ALC-AKV-0027", Reason: "kv.client_certificate_invalid", Status: http.StatusUnprocessableEntity}
	// Beyond the contract's 27 (never renumbered; R40 candidates).
	ErrKVVaultDuplicate   = ErrorCode{Code: "ALC-AKV-0028", Reason: "kv.vault_duplicate", Status: http.StatusConflict}
	ErrKVImportNameExists = ErrorCode{Code: "ALC-AKV-0029", Reason: "kv.import_name_exists", Status: http.StatusConflict}
	ErrKVImportInvalid    = ErrorCode{Code: "ALC-AKV-0030", Reason: "kv.import_invalid", Status: http.StatusUnprocessableEntity}
	ErrKVBindingGone      = ErrorCode{Code: "ALC-AKV-0031", Reason: "kv.binding_gone", Status: http.StatusConflict}
	ErrKVAutoDeployOff    = ErrorCode{Code: "ALC-AKV-0032", Reason: "kv.auto_deploy_off", Status: http.StatusConflict}
	ErrKVVaultUnavailable = ErrorCode{Code: "ALC-AKV-0033", Reason: "kv.vault_unavailable", Status: http.StatusConflict}
	ErrKVVersionHeld      = ErrorCode{Code: "ALC-AKV-0034", Reason: "kv.version_held", Status: http.StatusConflict}
	ErrKVVersionNotHeld   = ErrorCode{Code: "ALC-AKV-0035", Reason: "kv.version_not_held", Status: http.StatusConflict}
)

// AllErrorCodes lists every registered code; tests check format, uniqueness, translations and docs.
func AllErrorCodes() []ErrorCode {
	return []ErrorCode{
		ErrNotFound, ErrUnavailable, ErrUnexpected, ErrBadRequest, ErrRateLimited, ErrValidation, ErrBodyTooLarge, ErrPreconditionFailed,
		ErrUnauthenticated, ErrForbidden, ErrStepUpRequired, ErrCSRF, ErrInvalidCredentials, ErrMFAInvalid,
		ErrMFAAlreadyEnrolled, ErrPasswordTooShort, ErrPasswordTooLong, ErrPasswordBreached, ErrCurrentPasswordInvalid, ErrTryAgain,
		ErrUsernameTaken, ErrLastAdmin, ErrTokenScopeNotAllowed, ErrAuditBusy,
		ErrSetupCodeInvalid, ErrSetupLocked, ErrSetupSessionExpired, ErrSetupEnrollmentMissing,
		ErrPassphraseTooShort, ErrPassphraseMismatch, ErrPassphraseAlreadySet, ErrSetupIncomplete, ErrSetupLicenseChoiceMissing,
		ErrLicenseLocked,
		ErrLicenseInvalid, ErrLicenseWrongInstallation, ErrLicenseUnknownKey, ErrLicenseRevokedKey,
		ErrLicenseUnsupportedFormat, ErrLicenseOlderThanInstalled, ErrLicenseTargetLimit, ErrLicenseUnverified,
		ErrTargetDuplicate, ErrHostKeyUnconfirmed, ErrHostKeyStale, ErrHostKeyChanged, ErrHostKeyState, ErrTargetDisabled,
		ErrSSHUnreachable, ErrSSHAuthFailed, ErrSSHTimeout, ErrHelperMissing, ErrHelperOutdated, ErrHelperRefused,
		ErrFileChanged, ErrKeysManagedElsewhere, ErrOutputTooLarge, ErrSSHProtocol, ErrHelperChecksums, ErrSSHAddressNotAllowed,
		ErrOwnKeyProtected, ErrLastRootKey, ErrKeyNotRemovable, ErrSSHDUnreadable, ErrKeyVerifyFailed,
		ErrJobNotWaiting, ErrJobLeaseExpired, ErrJobTampered, ErrJobUnknownType, ErrJobConflict,
		ErrNginxNotFound, ErrNginxConfigInvalid, ErrNginxConfigChanged, ErrNginxProfileMissing, ErrNginxNoSpace,
		ErrNginxFileChanged, ErrNginxLocationUnsupported, ErrNginxBusy, ErrNginxIOError, ErrNginxNotRunning,
		ErrCertInvalid, ErrCertKeyMismatch, ErrCertExpired, ErrCertKeyEncrypted, ErrCertPFXPassword, ErrCertWeak,
		ErrCertUnsupportedKey, ErrCertDuplicate, ErrCertNoPrivateKey, ErrCertKeyTypeMismatch, ErrCertChainUnconfirmed,
		ErrCSRNotPending, ErrCSRCertificateMismatch, ErrCertNotYetValid, ErrCertPFXBusy, ErrCSRBusy, ErrCSRTooManyPending,
		ErrDeployInProgress, ErrDeployRecoveryPending, ErrDeployVerifyFailed, ErrDeployVerifyOther, ErrDeployVerifyUnreachable,
		ErrDeployReloadFailed, ErrDeployConfigTestFailed, ErrDeployRollbackFailed, ErrDeployRollbackReloadFailed,
		ErrDeployInterrupted, ErrDeployTargetNotReady, ErrDeployVerifyChain, ErrDeployNothingToRestore, ErrDeploySuperseded,
		ErrDeployUnknownOperation, ErrDeployTargetDeleted, ErrDeployRecoveryExhausted, ErrDeployOutcomeUnknown,
		ErrDeployRestoredUnverified, ErrDeployRollbackFileChanged, ErrDeployRescanNeeded, ErrDeployCancelled, ErrDeployServerOperationPending, ErrDeployPendingChangeRestored,
		ErrAzureAuthFailed, ErrAzureCredentialsExpired, ErrAzureForbidden, ErrAzureFirewall, ErrAzureVaultNotFound, ErrAzureUnreachable,
		ErrAzureThrottled, ErrAzureUnexpectedResponse, ErrAzureClockSkew, ErrAzureManagedIdentityGone, ErrAzureAddressNotAllowed,
		ErrAzureTLSUntrusted, ErrKVNotExportable, ErrKVVersionDisabled, ErrKVCertificateNotFound, ErrKVSecretUnreadable, ErrKVSecretMismatch,
		ErrKVLocationBound, ErrKVBindingExists, ErrKVVaultHasBindings, ErrKVVersionNotDeployable, ErrKVHeldNeedsAdmin, ErrKVImportConfirmNeeded,
		ErrKVImportInProgress, ErrKVImportRejected, ErrKVImportOutcomeUnknown, ErrKVClientCertInvalid, ErrKVVaultDuplicate,
		ErrKVImportNameExists, ErrKVImportInvalid, ErrKVBindingGone, ErrKVAutoDeployOff, ErrKVVaultUnavailable, ErrKVVersionHeld,
		ErrKVVersionNotHeld,
	}
}

// codeForReason returns the registered code of a stable reason (job records and target statuses
// store reasons). An unknown reason is ErrUnexpected, so a client always gets a documented code.
func codeForReason(reason string) ErrorCode {
	for _, ec := range AllErrorCodes() {
		if ec.Reason == reason {
			return ec
		}
	}
	return ErrUnexpected
}

// errorMap translates domain errors into API codes. Order matters only for
// errors that match each other: license.ErrUnverified matches license.ErrLocked.
var errorMap = []struct {
	err    error
	code   ErrorCode
	params map[string]string
}{
	{auth.ErrNotFound, ErrNotFound, nil},
	{auth.ErrUnauthenticated, ErrUnauthenticated, nil},
	{auth.ErrInvalidCredentials, ErrInvalidCredentials, nil},
	{auth.ErrMFAInvalid, ErrMFAInvalid, nil},
	{auth.ErrMFAAlreadyEnrolled, ErrMFAAlreadyEnrolled, nil},
	{auth.ErrPasswordTooShort, ErrPasswordTooShort, map[string]string{"min": strconv.Itoa(auth.MinPasswordLength)}},
	{auth.ErrPasswordTooLong, ErrPasswordTooLong, map[string]string{"max": strconv.Itoa(auth.MaxPasswordLength)}},
	{auth.ErrPasswordBreached, ErrPasswordBreached, nil},
	{auth.ErrCurrentPasswordInvalid, ErrCurrentPasswordInvalid, nil},
	{auth.ErrUsernameTaken, ErrUsernameTaken, nil},
	{auth.ErrLastAdmin, ErrLastAdmin, nil},
	{auth.ErrTokenScopeNotAllowed, ErrTokenScopeNotAllowed, nil},
	{setup.ErrAlreadySetUp, ErrNotFound, nil},
	{setup.ErrCodeInvalid, ErrSetupCodeInvalid, nil},
	{setup.ErrSessionInvalid, ErrSetupSessionExpired, nil},
	{setup.ErrEnrollmentMissing, ErrSetupEnrollmentMissing, nil},
	{setup.ErrPassphraseTooShort, ErrPassphraseTooShort, map[string]string{"min": strconv.Itoa(setup.MinPassphraseLength)}},
	{setup.ErrPassphraseMismatch, ErrPassphraseMismatch, nil},
	{setup.ErrPassphraseAlreadySet, ErrPassphraseAlreadySet, nil},
	{setup.ErrIncomplete, ErrSetupIncomplete, nil},
	{setup.ErrLicenseChoiceMissing, ErrSetupLicenseChoiceMissing, nil},
	{setup.ErrForbidden, ErrForbidden, nil},
	{license.ErrInvalid, ErrLicenseInvalid, nil},
	{license.ErrUnknownKey, ErrLicenseUnknownKey, nil},
	{license.ErrRevokedKey, ErrLicenseRevokedKey, nil},
	{license.ErrUnsupportedFormat, ErrLicenseUnsupportedFormat, nil},
	{license.ErrOlderThanInstalled, ErrLicenseOlderThanInstalled, nil},
	{license.ErrUnverified, ErrLicenseUnverified, nil}, // before ErrLocked, which it matches too
	{license.ErrLocked, ErrLicenseLocked, nil},
	// The typed errors (*TargetLimitError, *WrongInstallationError) are matched above with their
	// params; a bare sentinel still gets its own code instead of a 500.
	{license.ErrTargetLimit, ErrLicenseTargetLimit, nil},
	{license.ErrWrongInstallation, ErrLicenseWrongInstallation, nil},
	{license.ErrNoInstallation, ErrUnavailable, nil},
	{inventory.ErrNotFound, ErrNotFound, nil},
	{inventory.ErrNoPlatformKey, ErrUnavailable, nil},     // EnsurePlatformKey runs before serving; only a broken start reaches this
	{inventory.ErrNoSetupScript, ErrHelperChecksums, nil}, // a non-development build without the helper checksums
	{inventory.ErrDuplicateTarget, ErrTargetDuplicate, nil},
	{inventory.ErrVersionMismatch, ErrPreconditionFailed, nil},
	{inventory.ErrHostKeyUnconfirmed, ErrHostKeyUnconfirmed, nil},
	{inventory.ErrHostKeyStale, ErrHostKeyStale, nil},
	{inventory.ErrHostKeyChanged, ErrHostKeyChanged, nil},
	{inventory.ErrHostKeyState, ErrHostKeyState, nil},
	{inventory.ErrOwnKeyProtected, ErrOwnKeyProtected, nil},
	{inventory.ErrLastRootKey, ErrLastRootKey, nil},
	{inventory.ErrNotRemovable, ErrKeyNotRemovable, nil},
	{inventory.ErrKeysManagedElsewhere, ErrKeysManagedElsewhere, nil},
	{inventory.ErrSSHDUnreadable, ErrSSHDUnreadable, nil},
	{inventory.ErrJobConflict, ErrJobConflict, nil},
	{jobs.ErrNotFound, ErrNotFound, nil},
	{jobs.ErrNotWaiting, ErrJobNotWaiting, nil},
	{jobs.ErrBadCursor, ErrBadRequest, nil}, // a cursor that does not decode
	{jobs.ErrUnknownType, ErrJobUnknownType, nil},
	// Phase 4. *inventory.KeyTypeMismatchError is matched in classify with its params; the bare
	// sentinel still gets its code.
	{inventory.ErrCertificateDuplicate, ErrCertDuplicate, nil},
	{inventory.ErrCSRNotPending, ErrCSRNotPending, nil},
	{inventory.ErrLocationUnsupported, ErrNginxLocationUnsupported, nil},
	{inventory.ErrPFXBusy, ErrCertPFXBusy, nil},
	{inventory.ErrCSRBusy, ErrCSRBusy, nil},
	{inventory.ErrTooManyPendingCSRs, ErrCSRTooManyPending, nil},
	{inventory.ErrCertificateInvalid, ErrCertInvalid, nil},
	{inventory.ErrKeyMismatch, ErrCertKeyMismatch, nil},
	{inventory.ErrCertificateExpired, ErrCertExpired, nil},
	{inventory.ErrKeyEncrypted, ErrCertKeyEncrypted, nil},
	{inventory.ErrPFXPassword, ErrCertPFXPassword, nil},
	{inventory.ErrWeakCertificate, ErrCertWeak, nil},
	{inventory.ErrUnsupportedKey, ErrCertUnsupportedKey, nil},
	{inventory.ErrCSRMismatch, ErrCSRCertificateMismatch, nil},
	{inventory.ErrCertificateTooLarge, ErrBodyTooLarge, nil},
	{inventory.ErrDeploymentInProgress, ErrDeployInProgress, nil},
	{inventory.ErrRecoveryPending, ErrDeployRecoveryPending, nil},
	{inventory.ErrNoPrivateKey, ErrCertNoPrivateKey, nil},
	{inventory.ErrKeyTypeMismatch, ErrCertKeyTypeMismatch, nil},
	{inventory.ErrChainUnconfirmed, ErrCertChainUnconfirmed, nil},
	{inventory.ErrNginxConfigInvalid, ErrNginxConfigInvalid, nil},
	{inventory.ErrTargetNotReady, ErrDeployTargetNotReady, nil},
	{inventory.ErrCertificateNotYetValid, ErrCertNotYetValid, nil},
	{inventory.ErrLocationNeedsDiscovery, ErrDeployRescanNeeded, nil},
	// Phase 5. *inventory.ImportConfirmError is matched in classify with its certificate_name; the bare
	// sentinel still gets its code. ErrNotAVault and ErrNotAServer name a target of the wrong kind on
	// a route of the other: the route does not exist for it (404). ErrAdminRequired is a matter of
	// authority only (ruling S6). The engine-only ones (ErrBindingGone, ErrAutoDeployOff, ErrVersionHeld,
	// ErrImportState, ErrImportChanged, ErrCredentialNotTheTargets) have no entry on purpose.
	{inventory.ErrVaultHasBindings, ErrKVVaultHasBindings, nil},
	{inventory.ErrNotAVault, ErrNotFound, nil},
	{inventory.ErrNotAServer, ErrNotFound, nil},
	{inventory.ErrClientCertificateInvalid, ErrKVClientCertInvalid, nil},
	{inventory.ErrNotExportable, ErrKVNotExportable, nil},
	{inventory.ErrVersionNotDeployable, ErrKVVersionNotDeployable, nil},
	{inventory.ErrLocationBound, ErrKVLocationBound, nil},
	{inventory.ErrBindingExists, ErrKVBindingExists, nil},
	{inventory.ErrVersionDisabled, ErrKVVersionDisabled, nil},
	{inventory.ErrKVCertificateMissing, ErrKVCertificateNotFound, nil},
	{inventory.ErrHeldNeedsAdmin, ErrKVHeldNeedsAdmin, nil},
	{inventory.ErrAdminRequired, ErrForbidden, nil},
	{inventory.ErrVersionNotHeld, ErrKVVersionNotHeld, nil},
	{inventory.ErrSecretUnreadable, ErrKVSecretUnreadable, nil},
	{inventory.ErrSecretMismatch, ErrKVSecretMismatch, nil},
	{inventory.ErrVaultUnavailable, ErrKVVaultUnavailable, nil},
	{inventory.ErrImportConfirmNeeded, ErrKVImportConfirmNeeded, nil},
	{inventory.ErrImportInProgress, ErrKVImportInProgress, nil},
}

type errorPayload struct {
	Code       string                `json:"code"`
	Reason     string                `json:"reason"`
	MessageKey string                `json:"message_key"`
	Message    string                `json:"message"`
	RequestID  string                `json:"request_id"`
	Retryable  bool                  `json:"retryable"`
	Params     map[string]string     `json:"params,omitempty"`
	Details    []validate.FieldError `json:"details,omitempty"`
}

func (s *server) writeError(w http.ResponseWriter, r *http.Request, ec ErrorCode) {
	s.writeErrorWith(w, r, ec, nil, nil)
}

// writeErrorWith writes the error body of spec §9.3. message is the fallback
// text in the request language; clients render message_key with params.
func (s *server) writeErrorWith(w http.ResponseWriter, r *http.Request, ec ErrorCode, params map[string]string, details []validate.FieldError) {
	lang := s.deps.Catalog.Negotiate(r.Header.Get("Accept-Language"))
	key := "errors." + ec.Reason
	msg := s.deps.Catalog.T(lang, key+".title", params) + " " + s.deps.Catalog.T(lang, key+".action", params)
	writeJSON(w, ec.Status, map[string]errorPayload{"error": {
		Code:       ec.Code,
		Reason:     ec.Reason,
		MessageKey: key,
		Message:    msg,
		RequestID:  RequestID(r.Context()),
		Retryable:  ec.Retryable,
		Params:     params,
		Details:    details,
	}})
}

// fail maps a service error to its API error. Unknown errors are logged with
// the request ID and answered with a generic 500 (SEC-052).
func (s *server) fail(w http.ResponseWriter, r *http.Request, err error) {
	var verrs validate.Errors
	if errors.As(err, &verrs) {
		s.writeErrorWith(w, r, ErrValidation, nil, verrs)
		return
	}
	var locked *setup.LockedError
	if errors.As(err, &locked) {
		secs := int(locked.RetryAfter.Round(time.Second) / time.Second)
		w.Header().Set("Retry-After", strconv.Itoa(max(1, secs)))
		s.writeError(w, r, ErrSetupLocked)
		return
	}
	if errors.Is(err, auth.ErrTryAgain) {
		// The account lock was busy; nothing was verified or counted (auth.ErrTryAgain).
		w.Header().Set("Retry-After", "1")
		s.writeError(w, r, ErrTryAgain)
		return
	}
	ec, params, ok := classify(err)
	if !ok {
		s.deps.Log.Error("request failed", append([]any{"request_id", RequestID(r.Context()), "path", r.URL.Path}, errorAttrs(err)...)...)
		s.writeError(w, r, ErrUnexpected)
		return
	}
	if ec == ErrUnexpected {
		s.deps.Log.Error("request failed", append([]any{"request_id", RequestID(r.Context()), "path", r.URL.Path}, errorAttrs(err)...)...)
	}
	if ec == ErrCertPFXBusy || ec == ErrCSRBusy {
		w.Header().Set("Retry-After", "1") // a decode or key generation slot frees within seconds
	}
	var refused *inventory.LocationRefusalError
	if errors.As(err, &refused) {
		// A deployment request is all or nothing: name the location that refused it.
		params = maps.Clone(params)
		if params == nil {
			params = map[string]string{}
		}
		params["location_id"] = refused.LocationID.String()
	}
	s.writeErrorWith(w, r, ec, params, nil)
}

// classify maps a domain error to its API code and params; ok is false for an error no table
// knows (answered as ErrUnexpected by fail).
func classify(err error) (ErrorCode, map[string]string, bool) {
	var wrong *license.WrongInstallationError
	if errors.As(err, &wrong) {
		// Only the six-character ID suffixes, never file content (L-43).
		return ErrLicenseWrongInstallation, map[string]string{"expected": wrong.Expected, "got": wrong.Got}, true
	}
	var limit *license.TargetLimitError
	if errors.As(err, &limit) {
		return ErrLicenseTargetLimit, map[string]string{"used": strconv.Itoa(limit.Used), "max": strconv.Itoa(limit.Max)}, true
	}
	var keyType *inventory.KeyTypeMismatchError
	if errors.As(err, &keyType) {
		// Key type codes ("rsa", "ecdsa") from Alice's own records, never text from a server.
		return ErrCertKeyTypeMismatch, map[string]string{"expected": keyType.Expected, "actual": keyType.Actual}, true
	}
	var confirm *inventory.ImportConfirmError
	if errors.As(err, &confirm) {
		// The vault's own spelling of the name (a closed grammar, azureid.ValidObjectName), never text.
		if providerParamRules["certificate_name"].MatchString(confirm.CertificateName) {
			return ErrKVImportConfirmNeeded, map[string]string{"certificate_name": confirm.CertificateName}, true
		}
		return ErrKVImportConfirmNeeded, nil, true
	}
	var perr *providers.Error
	if errors.As(err, &perr) {
		// Only the stable reason and its allowlisted primitive params reach the client; the
		// provider's cause (remote output, driver text) is never shown nor logged as text.
		if ec := codeForReason(perr.Code); ec != ErrUnexpected {
			return ec, providerParams(perr.Params), true
		}
		if perr.Code == ErrUnexpected.Reason {
			// A provider's own "internal.unexpected" (an answer it could not use): the generic code, no params;
			// fail logs it (ec is ErrUnexpected) with the Go type only.
			return ErrUnexpected, nil, true
		}
	}
	for _, m := range errorMap {
		if errors.Is(err, m.err) {
			return m.code, m.params, true
		}
	}
	return ErrorCode{}, nil, false
}

// providerParamKeys are the provider error params a client may see: fixed labels, numbers and
// fingerprints (which are not secret). Any other key is dropped, so a provider that ever puts
// remote text or a key line into its params cannot leak it through the API; every key also has a
// value rule (providerParamRules). The Phase 4 keys are pre-flight D26's.
var providerParamKeys = map[string]bool{
	"helper_code": true, "subcommand": true, "exit_code": true, "reason": true, "field": true, "attempts": true,
	"wait": true, "fingerprint": true, "old_fingerprint": true, "new_fingerprint": true,
	"helper_protocol": true, "required_protocol": true, // ssh.helper_outdated
	"port": true, "failed_step": true, "profile": true, "phase": true, "directory": true, "backup_dir": true,
	"expected": true, "actual": true, "mode": true,
	"operation_id": true, // deployment.server_operation_pending
	// Phase 5 (Azure): the role a 403 asks for and the permission model, Entra's AADSTS number, the
	// caller's address a vault firewall refused, the vault's own error code and request id (strict
	// shapes, never Azure's text), and the certificate name an import conflicts with.
	"role": true, "model": true, "aadsts": true, "client_address": true, "azure_code": true, "azure_request_id": true,
	"certificate_name": true,
}

var (
	paramCodeRE = regexp.MustCompile(`^[a-z][a-z0-9_]{0,39}$`)
	// paramPathRE: an absolute path of the characters helper paths may hold, at most 256 bytes
	// (inventory's bound of a stored param value).
	paramPathRE       = regexp.MustCompile(`^/[A-Za-z0-9._/@:+-]{0,255}$`)
	paramPortRE       = regexp.MustCompile(`^[1-9][0-9]{0,4}$`)
	paramNumberRE     = regexp.MustCompile(`^-?[0-9]{1,6}$`)
	paramReasonRE     = regexp.MustCompile(`^[a-z][a-z0-9_]{0,39}(\.[a-z][a-z0-9_]{0,59})?$`)
	paramSubcommandRE = regexp.MustCompile(`^[a-z][a-z0-9-]{0,39}$`)
	paramHelperCodeRE = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,39}$`)
	// paramFingerprintRE: an OpenSSH SHA256 fingerprint or a certificate's hex SHA-256.
	paramFingerprintRE = regexp.MustCompile(`^(SHA256:[A-Za-z0-9+/=]{1,64}|[0-9a-f]{64})$`)
	// paramOperationRE: an operation id (a lowercase UUID, helperproto.ValidOpID).
	paramOperationRE = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	// Phase 5. paramRoleRE: the three Azure roles Alice names, in Azure's spelling. paramModelRE: the
	// vault's permission model. paramClientAddressRE only bounds the characters; providerParams also
	// requires that netip parses it. paramAADSTSRE: the number of an AADSTS code. paramAzureCodeRE:
	// azureid.ValidAzureCode. paramRequestIDRE: a GUID in any letter case (azureid.ValidRequestID).
	// paramCertNameRE: azureid.ValidObjectName.
	paramRoleRE          = regexp.MustCompile(`^Key Vault (Reader|Secrets User|Certificates Officer)$`)
	paramModelRE         = regexp.MustCompile(`^(rbac|access_policy|unknown)$`)
	paramClientAddressRE = regexp.MustCompile(`^[0-9A-Fa-f.:]{2,45}$`)
	paramAADSTSRE        = regexp.MustCompile(`^[0-9]{1,8}$`)
	paramAzureCodeRE     = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9]{0,63}$`)
	paramRequestIDRE     = regexp.MustCompile(`^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$`)
	paramCertNameRE      = regexp.MustCompile(`^[0-9A-Za-z-]{1,127}$`)
)

// providerParamRules bound every allowlisted param's value, whichever producer wrote it: a number,
// a fixed code (a step, phase, profile, key type, field, verification mode, wait), a reason code, a
// helper subcommand or code, a fingerprint, or an absolute path Alice itself chose (the backup
// folder). A value that does not fit is dropped with its key.
var providerParamRules = map[string]*regexp.Regexp{
	"helper_code": paramHelperCodeRE, "subcommand": paramSubcommandRE, "exit_code": paramNumberRE, "reason": paramReasonRE,
	"field": paramCodeRE, "attempts": paramNumberRE, "wait": paramCodeRE, "fingerprint": paramFingerprintRE,
	"old_fingerprint": paramFingerprintRE, "new_fingerprint": paramFingerprintRE, "helper_protocol": paramNumberRE,
	"required_protocol": paramNumberRE,
	"port":              paramPortRE, "failed_step": paramCodeRE, "profile": paramCodeRE, "phase": paramCodeRE, "mode": paramCodeRE,
	"expected": paramCodeRE, "actual": paramCodeRE, "directory": paramPathRE, "backup_dir": paramPathRE,
	"operation_id": paramOperationRE,
	"role":         paramRoleRE, "model": paramModelRE, "client_address": paramClientAddressRE, "aadsts": paramAADSTSRE,
	"azure_code": paramAzureCodeRE, "azure_request_id": paramRequestIDRE, "certificate_name": paramCertNameRE,
}

// validClientAddress is the second rule of client_address: the text must be an IP address.
func validClientAddress(v string) bool {
	_, err := netip.ParseAddr(v)
	return err == nil
}

// providerParams returns the allowlisted params of a provider error whose values fit their rule
// (nil when none remain).
func providerParams(in map[string]string) map[string]string {
	var out map[string]string
	for k, v := range in {
		if rule, ok := providerParamRules[k]; !ok || !providerParamKeys[k] || !rule.MatchString(v) {
			continue
		}
		if k == "client_address" && !validClientAddress(v) {
			continue
		}
		if out == nil {
			out = map[string]string{}
		}
		out[k] = v
	}
	return out
}

// errorAttrs describes err for the logs with fixed labels only: the type of
// the innermost error and, for database errors, the SQLSTATE. The error text
// is never logged, because driver messages and wrapped errors can carry column
// values such as password or token hashes (SEC-052).
func errorAttrs(err error) []any {
	inner := err
	for {
		next := errors.Unwrap(inner)
		if next == nil {
			break
		}
		inner = next
	}
	attrs := []any{"error_type", fmt.Sprintf("%T", inner)}
	var db interface{ SQLState() string }
	if errors.As(err, &db) {
		attrs = append(attrs, "sqlstate", db.SQLState())
	}
	switch {
	case errors.Is(err, context.Canceled):
		attrs = append(attrs, "cause", "canceled")
	case errors.Is(err, context.DeadlineExceeded):
		attrs = append(attrs, "cause", "deadline_exceeded")
	}
	return attrs
}

// encodeFailure is what writeJSON panics with when encoding/json refuses a value: the recoverer
// logs the value's Go type (never the value) and answers 500 ALC-SYS-0003.
type encodeFailure struct{ valueType string }

// writeJSON encodes v before anything is written, so a value encoding/json refuses (a time outside
// years 0000-9999, AUD-13) can never cut an answer short after its status line: nothing has been
// written when it panics with an encodeFailure, so the recoverer logs it and sends a complete
// 500 ALC-SYS-0003. Ingestion keeps such values out (internal/certs); this is the second line.
func writeJSON(w http.ResponseWriter, status int, v any) {
	b, err := json.Marshal(v)
	if err != nil {
		panic(encodeFailure{valueType: fmt.Sprintf("%T", v)})
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = w.Write(append(b, '\n'))
}
