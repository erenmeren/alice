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
	"strings"
	"time"

	"alice/internal/alerts/expiry"
	"alice/internal/audit/forward"
	"alice/internal/auth"
	"alice/internal/auth/ldap"
	"alice/internal/auth/oidc"
	"alice/internal/authz"
	"alice/internal/authz/services"
	"alice/internal/backup"
	"alice/internal/discovery"
	"alice/internal/discovery/discoverysvc"
	"alice/internal/inventory"
	"alice/internal/jobs"
	"alice/internal/license"
	"alice/internal/notify"
	"alice/internal/platform/tlscert"
	"alice/internal/platform/validate"
	"alice/internal/providers"
	"alice/internal/rbac"
	"alice/internal/reports"
	"alice/internal/setup"
	"alice/internal/sshkeys"
	"alice/internal/sshkeys/plan"
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
	// ErrMethodNotAllowed: HEAD on an audited export (Phase 7, Task 14 review M6).
	ErrMethodNotAllowed = ErrorCode{Code: "ALC-SYS-0009", Reason: "system.method_not_allowed", Status: http.StatusMethodNotAllowed}

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

	ErrUsernameTaken = ErrorCode{Code: "ALC-USR-0001", Reason: "user.username_taken", Status: http.StatusConflict}
	ErrLastAdmin     = ErrorCode{Code: "ALC-USR-0002", Reason: "user.last_admin", Status: http.StatusConflict}
	// ErrSSOUser: a role, password or authenticator change of a single sign-on user (Phase 7, C15; reason user.* as the
	// other USR codes, cosmetic ruling C-s4-07). It also answers auth.ErrDirectoryUser (LDAP sign-in, Task 5 decision:
	// one code for both kinds of users whose role comes from their groups; the texts name both).
	ErrSSOUser              = ErrorCode{Code: "ALC-USR-0003", Reason: "user.sso_user", Status: http.StatusConflict}
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
	// ErrHelperOutdatedHTTP01: the server's helper (or its sudoers file) predates the HTTP-01 challenge
	// commands (protocol 7). Everything else keeps working on that server (A1 of the ACME plan).
	ErrHelperOutdatedHTTP01 = ErrorCode{Code: "ALC-SSH-0013", Reason: "ssh.helper_outdated_http01", Status: http.StatusBadGateway}
	// ErrHelperOutdatedRollbackGuard (R48): the server's helper predates the rollback guard (protocol
	// 10); a deployment that needs it (an incident replacement, or one over a revoked or compromised
	// certificate) is refused before anything is sent. Params helper_protocol, required_protocol.
	ErrHelperOutdatedRollbackGuard = ErrorCode{Code: "ALC-SSH-0014", Reason: "ssh.helper_outdated_rollback_guard", Status: http.StatusBadGateway}

	ErrOwnKeyProtected = ErrorCode{Code: "ALC-KEY-0001", Reason: "sshkey.own_key_protected", Status: http.StatusConflict}
	ErrLastRootKey     = ErrorCode{Code: "ALC-KEY-0002", Reason: "sshkey.last_root_key", Status: http.StatusConflict}
	ErrKeyNotRemovable = ErrorCode{Code: "ALC-KEY-0003", Reason: "sshkey.not_removable", Status: http.StatusConflict}
	ErrSSHDUnreadable  = ErrorCode{Code: "ALC-KEY-0004", Reason: "sshkey.sshd_unreadable", Status: http.StatusConflict}
	ErrKeyVerifyFailed = ErrorCode{Code: "ALC-KEY-0005", Reason: "sshkey.verify_failed", Status: http.StatusBadGateway}
	// Phase 6: generated keys, deploys and the private key download (R41, C11). 0014 and 0015 continue the contract's
	// table for what the service built after it (review N1, ruling G14).
	ErrKeyNotManaged             = ErrorCode{Code: "ALC-KEY-0006", Reason: "sshkey.not_managed", Status: http.StatusConflict}
	ErrKeyRetired                = ErrorCode{Code: "ALC-KEY-0007", Reason: "sshkey.retired", Status: http.StatusConflict}
	ErrKeyDestroyed              = ErrorCode{Code: "ALC-KEY-0008", Reason: "sshkey.private_key_destroyed", Status: http.StatusGone}
	ErrKeyConnectionAccount      = ErrorCode{Code: "ALC-KEY-0009", Reason: "sshkey.connection_account", Status: http.StatusConflict}
	ErrKeyLoginFailed            = ErrorCode{Code: "ALC-KEY-0010", Reason: "sshkey.login_failed", Status: http.StatusBadGateway}
	ErrKeyGenerateBusy           = ErrorCode{Code: "ALC-KEY-0011", Reason: "sshkey.generate_busy", Status: http.StatusServiceUnavailable, Retryable: true}
	ErrKeyAddUndoFailed          = ErrorCode{Code: "ALC-KEY-0012", Reason: "sshkey.add_undo_failed", Status: http.StatusBadGateway}
	ErrKeyNotAKeyFile            = ErrorCode{Code: "ALC-KEY-0013", Reason: "sshkey.not_a_key_file", Status: http.StatusConflict}
	ErrKeyConnectionFilesUnknown = ErrorCode{Code: "ALC-KEY-0014", Reason: "sshkey.connection_files_unknown", Status: http.StatusConflict}
	// ErrKeyClockBehind: the clock is behind a time Alice already recorded (a download on a clock stepped back);
	// nothing was handed out, counted or audited; retryable once the clock has caught up.
	ErrKeyClockBehind = ErrorCode{Code: "ALC-KEY-0015", Reason: "sshkey.clock_behind", Status: http.StatusServiceUnavailable, Retryable: true}
	// ErrKeyAddUncertain: a deploy's add was sent and its answer lost, and the line is not in the file (yet); the job
	// waits until the add can no longer arrive, then starts over (S3). A job reason, retried by the job itself.
	ErrKeyAddUncertain = ErrorCode{Code: "ALC-KEY-0016", Reason: "sshkey.add_uncertain", Status: http.StatusBadGateway, Retryable: true}
	// ErrKeyConnectionAccountFile: a place of a rotation is the connection account's or one of its files (the planner's
	// skip connection_account_file, refused again at send time).
	ErrKeyConnectionAccountFile = ErrorCode{Code: "ALC-KEY-0017", Reason: "sshkey.connection_account_file", Status: http.StatusConflict}
	// ErrKeyInRotation: a deploy of the new key of an unfinished rotation (its undo would remove the deployed line).
	ErrKeyInRotation = ErrorCode{Code: "ALC-KEY-0018", Reason: "sshkey.in_rotation", Status: http.StatusConflict}
	// ErrNotifyQueueFailed: Alice could not queue an email (the renewal notice a paused rotation waits for); retried at
	// every background check.
	ErrNotifyQueueFailed = ErrorCode{Code: "ALC-NTF-0001", Reason: "notify.queue_failed", Status: http.StatusServiceUnavailable, Retryable: true}
	// Phase 7 (C15): the mail settings and the test e-mail. No text of the mail server reaches an answer (F-63); an
	// untrusted certificate carries its fingerprint, subject and expiry (F-62).
	ErrSMTPNotConfigured  = ErrorCode{Code: "ALC-NTF-0002", Reason: "notify.smtp_not_configured", Status: http.StatusConflict}
	ErrSMTPConnect        = ErrorCode{Code: "ALC-NTF-0003", Reason: "notify.smtp_connect", Status: http.StatusBadGateway, Retryable: true}
	ErrSMTPTLS            = ErrorCode{Code: "ALC-NTF-0004", Reason: "notify.smtp_tls", Status: http.StatusBadGateway}
	ErrSMTPUntrusted      = ErrorCode{Code: "ALC-NTF-0005", Reason: "notify.smtp_untrusted", Status: http.StatusBadGateway}
	ErrSMTPAuth           = ErrorCode{Code: "ALC-NTF-0006", Reason: "notify.smtp_auth", Status: http.StatusBadGateway}
	ErrSMTPRejected       = ErrorCode{Code: "ALC-NTF-0007", Reason: "notify.smtp_rejected", Status: http.StatusBadGateway}
	ErrSMTPCertNotSeen    = ErrorCode{Code: "ALC-NTF-0008", Reason: "notify.certificate_not_seen", Status: http.StatusConflict}
	ErrSMTPAddressRefused = ErrorCode{Code: "ALC-NTF-0009", Reason: "notify.smtp_address_refused", Status: http.StatusConflict}

	// Phase 7 (C15): exports and saved views. ALC-RPT-0004 is the one-export-at-a-time refusal (reports.ErrExportBusy,
	// S-10), in the 409 busy style of ALC-NGX-0008.
	ErrExportTooLarge = ErrorCode{Code: "ALC-RPT-0001", Reason: "export.too_large", Status: http.StatusConflict}
	ErrViewLimit      = ErrorCode{Code: "ALC-RPT-0002", Reason: "views.limit_reached", Status: http.StatusConflict}
	ErrViewNameTaken  = ErrorCode{Code: "ALC-RPT-0003", Reason: "views.name_taken", Status: http.StatusConflict}
	ErrExportBusy     = ErrorCode{Code: "ALC-RPT-0004", Reason: "export.busy", Status: http.StatusConflict, Retryable: true}

	// Phase 7 (C15): single sign-on. 0006..0015 are the closed reasons of a refused sign-in or step-up (*oidc.LoginError);
	// the callback carries them to the sign-in page as sso_error, the other routes answer them.
	ErrSSODiscoveryFailed      = ErrorCode{Code: "ALC-SSO-0001", Reason: "sso.discovery_failed", Status: http.StatusBadGateway, Retryable: true}
	ErrSSOAdminMappingDisabled = ErrorCode{Code: "ALC-SSO-0002", Reason: "sso.admin_mapping_disabled", Status: http.StatusConflict}
	ErrSSOAdminMappingsExist   = ErrorCode{Code: "ALC-SSO-0003", Reason: "sso.admin_mappings_exist", Status: http.StatusConflict}
	ErrSSOPublicURLMissing     = ErrorCode{Code: "ALC-SSO-0004", Reason: "sso.public_url_missing", Status: http.StatusConflict}
	ErrSSOProviderInUse        = ErrorCode{Code: "ALC-SSO-0005", Reason: "sso.provider_in_use", Status: http.StatusConflict}
	ErrSSONoAccess             = ErrorCode{Code: "ALC-SSO-0006", Reason: "sso.no_access", Status: http.StatusForbidden}
	ErrSSOGroupsOverage        = ErrorCode{Code: "ALC-SSO-0007", Reason: "sso.groups_overage", Status: http.StatusForbidden}
	ErrSSOEmailInUse           = ErrorCode{Code: "ALC-SSO-0008", Reason: "sso.email_in_use", Status: http.StatusForbidden}
	ErrSSOIdPUnreachable       = ErrorCode{Code: "ALC-SSO-0009", Reason: "sso.idp_unreachable", Status: http.StatusBadGateway, Retryable: true}
	ErrSSOLoginInvalid         = ErrorCode{Code: "ALC-SSO-0010", Reason: "sso.login_invalid", Status: http.StatusUnauthorized}
	ErrSSOLoginExpired         = ErrorCode{Code: "ALC-SSO-0011", Reason: "sso.login_expired", Status: http.StatusUnauthorized}
	ErrSSOUserDisabled         = ErrorCode{Code: "ALC-SSO-0012", Reason: "sso.user_disabled", Status: http.StatusForbidden}
	ErrSSOProviderDisabled     = ErrorCode{Code: "ALC-SSO-0013", Reason: "sso.provider_disabled", Status: http.StatusForbidden}
	ErrSSOStepUpOtherUser      = ErrorCode{Code: "ALC-SSO-0014", Reason: "sso.stepup_other_user", Status: http.StatusForbidden}
	ErrSSOIdPError             = ErrorCode{Code: "ALC-SSO-0015", Reason: "sso.idp_error", Status: http.StatusUnauthorized}
	ErrSSONotSSOUser           = ErrorCode{Code: "ALC-SSO-0016", Reason: "sso.not_sso_user", Status: http.StatusConflict}

	// Directory (LDAP and Active Directory) sign-in. 0001 is the one answer of every refused directory sign-in that could
	// tell something about a user (unknown name, wrong password, no mapped group, a disabled or locked user, an e-mail
	// in use, several entries, an unusable name): same status, same body; the audit row carries the reason. 0002 is a
	// directory that is unreachable, misconfigured or switched off: it says nothing about users. A group mapped to
	// Administrator while "SSO users may be Admin" is off is ALC-SSO-0002 (the same switch).
	ErrLDAPSignInRefused        = ErrorCode{Code: "ALC-LDAP-0001", Reason: "ldap.signin_refused", Status: http.StatusUnauthorized}
	ErrLDAPDirectoryUnavailable = ErrorCode{Code: "ALC-LDAP-0002", Reason: "ldap.directory_unavailable", Status: http.StatusServiceUnavailable, Retryable: true}
	ErrLDAPDirectoryInUse       = ErrorCode{Code: "ALC-LDAP-0003", Reason: "ldap.directory_in_use", Status: http.StatusConflict}
	ErrLDAPConnectionTestFailed = ErrorCode{Code: "ALC-LDAP-0004", Reason: "ldap.connection_test_failed", Status: http.StatusUnprocessableEntity}
	ErrLDAPTooManyDirectories   = ErrorCode{Code: "ALC-LDAP-0005", Reason: "ldap.too_many_directories", Status: http.StatusConflict}
	ErrLDAPSignInTestFailed     = ErrorCode{Code: "ALC-LDAP-0006", Reason: "ldap.signin_test_failed", Status: http.StatusUnprocessableEntity}
	ErrLDAPEnrolmentRequired    = ErrorCode{Code: "ALC-LDAP-0007", Reason: "ldap.enrolment_required", Status: http.StatusConflict}
	ErrLDAPNotDirectoryUser     = ErrorCode{Code: "ALC-LDAP-0008", Reason: "ldap.not_directory_user", Status: http.StatusConflict}
	ErrLDAPUserNotDirectory     = ErrorCode{Code: "ALC-LDAP-0009", Reason: "ldap.user_not_directory", Status: http.StatusConflict}

	// Phase 6: rotation policies and runs (R41, C11). The run results (rotations.result_code) and the location
	// errors (rotation_locations.error_code) are stored reasons; the API also answers the request refusals with them.
	// 0017 and later continue the contract's table (S1, S12, the service's own refusals).
	ErrRotPolicyExists      = ErrorCode{Code: "ALC-ROT-0001", Reason: "rotation.policy_exists", Status: http.StatusConflict}
	ErrRotInProgress        = ErrorCode{Code: "ALC-ROT-0002", Reason: "rotation.in_progress", Status: http.StatusConflict}
	ErrRotPlanChanged       = ErrorCode{Code: "ALC-ROT-0003", Reason: "rotation.plan_changed", Status: http.StatusConflict}
	ErrRotNothingToRotate   = ErrorCode{Code: "ALC-ROT-0004", Reason: "rotation.nothing_to_rotate", Status: http.StatusConflict}
	ErrRotNotWaiting        = ErrorCode{Code: "ALC-ROT-0005", Reason: "rotation.not_waiting", Status: http.StatusConflict}
	ErrRotAddFailed         = ErrorCode{Code: "ALC-ROT-0006", Reason: "rotation.add_failed", Status: http.StatusBadGateway}
	ErrRotVerifyFailed      = ErrorCode{Code: "ALC-ROT-0007", Reason: "rotation.verify_failed", Status: http.StatusBadGateway}
	ErrRotUndoFailed        = ErrorCode{Code: "ALC-ROT-0008", Reason: "rotation.undo_failed", Status: http.StatusBadGateway}
	ErrRotRemoveIncomplete  = ErrorCode{Code: "ALC-ROT-0009", Reason: "rotation.remove_incomplete", Status: http.StatusBadGateway}
	ErrRotDecisionTimeout   = ErrorCode{Code: "ALC-ROT-0010", Reason: "rotation.decision_timeout", Status: http.StatusConflict}
	ErrRotPausedLicense     = ErrorCode{Code: "ALC-ROT-0011", Reason: "rotation.paused_license", Status: http.StatusConflict}
	ErrRotCancelledLicense  = ErrorCode{Code: "ALC-ROT-0012", Reason: "rotation.cancelled_license", Status: http.StatusConflict}
	ErrRotStopped           = ErrorCode{Code: "ALC-ROT-0013", Reason: "rotation.stopped", Status: http.StatusConflict}
	ErrRotPolicyOff         = ErrorCode{Code: "ALC-ROT-0014", Reason: "rotation.policy_off", Status: http.StatusConflict}
	ErrRotNewKeyFailed      = ErrorCode{Code: "ALC-ROT-0015", Reason: "rotation.new_key_failed", Status: http.StatusBadGateway}
	ErrRotRetriesExhausted  = ErrorCode{Code: "ALC-ROT-0016", Reason: "rotation.retries_exhausted", Status: http.StatusBadGateway}
	ErrRotNoticeUndelivered = ErrorCode{Code: "ALC-ROT-0017", Reason: "rotation.notice_undelivered", Status: http.StatusConflict}
	ErrRotOldKeyGone        = ErrorCode{Code: "ALC-ROT-0018", Reason: "rotation.old_key_gone", Status: http.StatusConflict}
	ErrRotPlanTooLarge      = ErrorCode{Code: "ALC-ROT-0019", Reason: "rotation.plan_too_large", Status: http.StatusConflict}
	ErrRotStartFailed       = ErrorCode{Code: "ALC-ROT-0020", Reason: "rotation.start_failed", Status: http.StatusConflict}
	// ErrRotNoticePending: Continue before the renewal email of the pause was queued (S6; the next sweep queues it).
	ErrRotNoticePending = ErrorCode{Code: "ALC-ROT-0021", Reason: "rotation.notice_pending", Status: http.StatusConflict, Retryable: true}
	// ErrRotLateResult: a place's definite answer arrived after the sweep had given up on it (the attention mail's code).
	ErrRotLateResult = ErrorCode{Code: "ALC-ROT-0022", Reason: "rotation.late_result", Status: http.StatusConflict}
	// ErrRotGuardRefused: the database refused every write of a place (a store bug or a state no rule expected); the
	// place ends failed with it.
	ErrRotGuardRefused = ErrorCode{Code: "ALC-ROT-0023", Reason: "rotation.guard_refused", Status: http.StatusConflict}
	// ErrRotSkippedAtSend: a planner skip reason found when the change was about to be sent (the place's skip_reason).
	ErrRotSkippedAtSend = ErrorCode{Code: "ALC-ROT-0024", Reason: "rotation.skipped_at_send", Status: http.StatusConflict}
	// ErrRotListingIncomplete: a place ended because Alice could never read its key file completely.
	ErrRotListingIncomplete = ErrorCode{Code: "ALC-ROT-0025", Reason: "rotation.listing_incomplete", Status: http.StatusConflict}

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

	// Apache httpd (discovery only). Its helper-too-old reason exists only here: Nginx predates protocol 8.
	ErrApacheNotFound       = ErrorCode{Code: "ALC-APC-0001", Reason: "apache.not_found", Status: http.StatusBadGateway}
	ErrApacheConfigInvalid  = ErrorCode{Code: "ALC-APC-0002", Reason: "apache.config_invalid", Status: http.StatusConflict}
	ErrApacheProfileMissing = ErrorCode{Code: "ALC-APC-0003", Reason: "apache.profile_missing", Status: http.StatusBadGateway}
	ErrApacheHelperTooOld   = ErrorCode{Code: "ALC-APC-0004", Reason: "apache.helper_too_old", Status: http.StatusBadGateway}

	// HAProxy (discovery only). Its helper-too-old reason: haproxy-dump arrived with protocol 9.
	ErrHAProxyNotFound       = ErrorCode{Code: "ALC-HAP-0001", Reason: "haproxy.not_found", Status: http.StatusBadGateway}
	ErrHAProxyConfigInvalid  = ErrorCode{Code: "ALC-HAP-0002", Reason: "haproxy.config_invalid", Status: http.StatusConflict}
	ErrHAProxyProfileMissing = ErrorCode{Code: "ALC-HAP-0003", Reason: "haproxy.profile_missing", Status: http.StatusBadGateway}
	ErrHAProxyHelperTooOld   = ErrorCode{Code: "ALC-HAP-0004", Reason: "haproxy.helper_too_old", Status: http.StatusBadGateway}

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
	// Revocation and key compromise (migration 00021): a revoked or compromised certificate is never deployed again; also
	// a deployment's result when the mark came after the request.
	ErrCertRevoked     = ErrorCode{Code: "ALC-CRT-0018", Reason: "certificate.revoked", Status: http.StatusConflict}
	ErrCertCompromised = ErrorCode{Code: "ALC-CRT-0019", Reason: "certificate.compromised", Status: http.StatusConflict}

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
	// ErrDeployRollbackForbidden (R48): the change failed and Alice did not put the previous files back
	// because they hold a revoked or compromised certificate or key; the files are as the failed
	// change left them (status rollback_failed; the website may be broken until another certificate is
	// deployed).
	ErrDeployRollbackForbidden = ErrorCode{Code: "ALC-DEP-0025", Reason: "deployment.rollback_forbidden", Status: http.StatusBadGateway}
	// ErrDeployVerifyUntrusted (R51): the website serves the new certificate, but its chain does not verify against the
	// known trust anchor (param trust_error says why: unknown_authority, wrong_intermediate, incomplete_chain,
	// chain_order, expired, not_yet_valid, invalid_chain; param port); the change was rolled back.
	ErrDeployVerifyUntrusted = ErrorCode{Code: "ALC-DEP-0026", Reason: "deployment.verify_untrusted", Status: http.StatusBadGateway}
	// Certificate drift (R52): a queued automatic repair that no longer holds when its job runs (the location no longer
	// desires the certificate, or is no longer in mode auto; stored reasons, nothing was sent), and the refusals of the
	// repair mode and the one-action repair (the location follows no binding, or is not drifted).
	ErrDeployDriftRepairSuperseded = ErrorCode{Code: "ALC-DEP-0027", Reason: "deployment.drift_repair_superseded", Status: http.StatusConflict}
	ErrDeployDriftRepairOff        = ErrorCode{Code: "ALC-DEP-0028", Reason: "deployment.drift_repair_off", Status: http.StatusConflict}
	ErrDeployDriftNotBound         = ErrorCode{Code: "ALC-DEP-0029", Reason: "deployment.drift_not_bound", Status: http.StatusConflict}
	ErrDeployNotDrifted            = ErrorCode{Code: "ALC-DEP-0030", Reason: "deployment.not_drifted", Status: http.StatusConflict}

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
	// The refusals of an automatic deployment that is no longer the right one (the planner's fix round 1).
	ErrKVVersionSuperseded = ErrorCode{Code: "ALC-AKV-0036", Reason: "kv.version_superseded", Status: http.StatusConflict}
	ErrKVWaveStopped       = ErrorCode{Code: "ALC-AKV-0037", Reason: "kv.wave_stopped", Status: http.StatusConflict}
	// A queued import that was never sent: its vault was removed, or its job ended before it sent anything (imports fix round).
	ErrKVImportVaultDeleted = ErrorCode{Code: "ALC-AKV-0038", Reason: "kv.import_vault_deleted", Status: http.StatusConflict}
	ErrKVImportCancelled    = ErrorCode{Code: "ALC-AKV-0039", Reason: "kv.import_cancelled", Status: http.StatusConflict}
	// The import job found that the person who asked is no longer an Administrator (the job stores auth.forbidden;
	// importJSON shows this code for it).
	ErrKVImportAdminRequired = ErrorCode{Code: "ALC-AKV-0040", Reason: "kv.import_admin_required", Status: http.StatusForbidden}
	// The vault's sealed sign-in credential cannot be opened with this master key (secrets.ErrDecrypt); a deployment
	// ends with it before anything is read from the vault (final fix wave).
	ErrKVCredentialUnreadable = ErrorCode{Code: "ALC-AKV-0041", Reason: "kv.credential_unreadable", Status: http.StatusConflict}

	// Phase 8 (contract C12): backups, the HTTPS certificate upload, audit forwarding and the wizard's passphrase
	// strength rule (P1-08).
	ErrBackupRunning            = ErrorCode{Code: "ALC-BAK-0001", Reason: "backup.running", Status: http.StatusConflict, Retryable: true}
	ErrBackupNotConfigured      = ErrorCode{Code: "ALC-BAK-0002", Reason: "backup.not_configured", Status: http.StatusConflict}
	ErrBackupNotFound           = ErrorCode{Code: "ALC-BAK-0003", Reason: "backup.not_found", Status: http.StatusNotFound}
	ErrBackupWriteFailed        = ErrorCode{Code: "ALC-BAK-0004", Reason: "backup.write_failed", Status: http.StatusInternalServerError, Retryable: true}
	ErrTLSKeyMismatch           = ErrorCode{Code: "ALC-TLS-0001", Reason: "tls.key_mismatch", Status: http.StatusUnprocessableEntity}
	ErrTLSNotValidNow           = ErrorCode{Code: "ALC-TLS-0002", Reason: "tls.not_valid_now", Status: http.StatusUnprocessableEntity}
	ErrTLSWeakKey               = ErrorCode{Code: "ALC-TLS-0003", Reason: "tls.weak_key", Status: http.StatusUnprocessableEntity}
	ErrTLSPFXPassword           = ErrorCode{Code: "ALC-TLS-0004", Reason: "tls.pfx_password", Status: http.StatusUnprocessableEntity}
	ErrTLSUnreadable            = ErrorCode{Code: "ALC-TLS-0005", Reason: "tls.unreadable", Status: http.StatusUnprocessableEntity}
	ErrForwardingAddressRefused = ErrorCode{Code: "ALC-AUD-0002", Reason: "audit.forwarding_address_refused", Status: http.StatusUnprocessableEntity}
	ErrForwardingUnreachable    = ErrorCode{Code: "ALC-AUD-0003", Reason: "audit.forwarding_unreachable", Status: http.StatusBadGateway, Retryable: true}
	ErrForwardingUntrusted      = ErrorCode{Code: "ALC-AUD-0004", Reason: "audit.forwarding_untrusted", Status: http.StatusBadGateway}
	ErrPassphraseTooWeak        = ErrorCode{Code: "ALC-SET-0010", Reason: "setup.passphrase_too_weak", Status: http.StatusUnprocessableEntity}

	// ACME certificate issuance and renewal (area ACM).
	ErrACMProviderUnreachable  = ErrorCode{Code: "ALC-ACM-0001", Reason: "acme.provider_unreachable", Status: http.StatusBadGateway, Retryable: true}
	ErrACMDirectoryInvalid     = ErrorCode{Code: "ALC-ACM-0002", Reason: "acme.directory_invalid", Status: http.StatusBadGateway}
	ErrACMTermsNotAccepted     = ErrorCode{Code: "ALC-ACM-0003", Reason: "acme.terms_not_accepted", Status: http.StatusUnprocessableEntity}
	ErrACMAccountRejected      = ErrorCode{Code: "ALC-ACM-0004", Reason: "acme.account_rejected", Status: http.StatusUnprocessableEntity}
	ErrACMCaRateLimited        = ErrorCode{Code: "ALC-ACM-0005", Reason: "acme.ca_rate_limited", Status: http.StatusServiceUnavailable, Retryable: true}
	ErrACMValidationFailedDns  = ErrorCode{Code: "ALC-ACM-0006", Reason: "acme.validation_failed_dns", Status: http.StatusUnprocessableEntity}
	ErrACMValidationFailedHttp = ErrorCode{Code: "ALC-ACM-0007", Reason: "acme.validation_failed_http", Status: http.StatusUnprocessableEntity}
	ErrACMHookRefused          = ErrorCode{Code: "ALC-ACM-0008", Reason: "acme.hook_refused", Status: http.StatusBadGateway}
	ErrACMIdentifierRefused    = ErrorCode{Code: "ALC-ACM-0009", Reason: "acme.identifier_refused", Status: http.StatusUnprocessableEntity}
	ErrACMNotIssuedInTime      = ErrorCode{Code: "ALC-ACM-0010", Reason: "acme.not_issued_in_time", Status: http.StatusGatewayTimeout, Retryable: true}
	ErrACMKeyPolicyNotAllowed  = ErrorCode{Code: "ALC-ACM-0011", Reason: "acme.key_policy_not_allowed", Status: http.StatusUnprocessableEntity}
	ErrACMProviderInUse        = ErrorCode{Code: "ALC-ACM-0012", Reason: "acme.provider_in_use", Status: http.StatusConflict}
	ErrACMTlsTrustFailed       = ErrorCode{Code: "ALC-ACM-0013", Reason: "acme.tls_trust_failed", Status: http.StatusBadGateway}
	ErrACMRolloverUnsupported  = ErrorCode{Code: "ALC-ACM-0014", Reason: "acme.rollover_unsupported", Status: http.StatusUnprocessableEntity}
	ErrACMNameNotAllowed       = ErrorCode{Code: "ALC-ACM-0015", Reason: "acme.name_not_allowed", Status: http.StatusUnprocessableEntity}
	ErrACMOrderRunning         = ErrorCode{Code: "ALC-ACM-0016", Reason: "acme.order_running", Status: http.StatusConflict, Retryable: true}
	ErrACMChallengeUnavailable = ErrorCode{Code: "ALC-ACM-0017", Reason: "acme.challenge_unavailable", Status: http.StatusUnprocessableEntity}
	ErrACMKeyTypeLocked        = ErrorCode{Code: "ALC-ACM-0018", Reason: "acme.key_type_locked", Status: http.StatusConflict}
	// Providers, accounts and hooks (Task 9).
	ErrACMHookInUse                  = ErrorCode{Code: "ALC-ACM-0019", Reason: "acme.hook_in_use", Status: http.StatusConflict}
	ErrACMNameTaken                  = ErrorCode{Code: "ALC-ACM-0020", Reason: "acme.name_taken", Status: http.StatusConflict}
	ErrACMAccountExists              = ErrorCode{Code: "ALC-ACM-0021", Reason: "acme.account_exists", Status: http.StatusConflict}
	ErrACMDirectoryChangeUnconfirmed = ErrorCode{Code: "ALC-ACM-0022", Reason: "acme.directory_change_unconfirmed", Status: http.StatusConflict}
	ErrACMAccountState               = ErrorCode{Code: "ALC-ACM-0023", Reason: "acme.account_state", Status: http.StatusConflict}
	ErrACMRolloverPending            = ErrorCode{Code: "ALC-ACM-0024", Reason: "acme.rollover_pending", Status: http.StatusConflict, Retryable: true}
	ErrACMSecretUnreadable           = ErrorCode{Code: "ALC-ACM-0025", Reason: "acme.secret_unreadable", Status: http.StatusConflict}
	// An order a crash (or a lost worker) interrupted and that could not be finished from the authority (Task 10): the
	// order's error code; nothing was stored, its key is deleted.
	ErrACMOrderAbandoned = ErrorCode{Code: "ALC-ACM-0026", Reason: "acme.order_abandoned", Status: http.StatusConflict, Retryable: true}
	// Bindings and Deploy now (Task 12): no issued certificate yet, a location that follows another certificate, a
	// location Deploy now named that is not bound.
	ErrACMNotIssued        = ErrorCode{Code: "ALC-ACM-0027", Reason: "acme.not_issued", Status: http.StatusConflict}
	ErrACMLocationBound    = ErrorCode{Code: "ALC-ACM-0028", Reason: "acme.location_bound", Status: http.StatusConflict}
	ErrACMLocationNotBound = ErrorCode{Code: "ALC-ACM-0029", Reason: "acme.location_not_bound", Status: http.StatusUnprocessableEntity}
	// A queued automatic deployment of an ACME certificate whose request no longer held when its job ran (Task 12, fix
	// round 1): a deployment's result, nothing was sent.
	ErrACMBindingGone           = ErrorCode{Code: "ALC-ACM-0030", Reason: "acme.binding_gone", Status: http.StatusConflict}
	ErrACMAutoDeployOff         = ErrorCode{Code: "ALC-ACM-0031", Reason: "acme.auto_deploy_off", Status: http.StatusConflict}
	ErrACMCertificateSuperseded = ErrorCode{Code: "ALC-ACM-0032", Reason: "acme.certificate_superseded", Status: http.StatusConflict}
	ErrACMDeployStopped         = ErrorCode{Code: "ALC-ACM-0033", Reason: "acme.deploy_stopped", Status: http.StatusConflict}
	ErrACMDeployHeld            = ErrorCode{Code: "ALC-ACM-0034", Reason: "acme.deploy_held", Status: http.StatusConflict}
	// Deploy now without named websites (Task 13 fix round 1): none is bound, or more than one request takes.
	ErrACMNoBindings      = ErrorCode{Code: "ALC-ACM-0035", Reason: "acme.no_bindings", Status: http.StatusConflict}
	ErrACMTooManyBindings = ErrorCode{Code: "ALC-ACM-0036", Reason: "acme.too_many_bindings", Status: http.StatusUnprocessableEntity}
	// Revocation (RFC 8555 section 7.6; 2026-10-20): the named certificate is not a version of this ACME certificate; the CA
	// offers no revocation; the CA (or Alice) refuses the reason; the CA refuses this account for this certificate.
	ErrACMNotThisCertificate  = ErrorCode{Code: "ALC-ACM-0037", Reason: "acme.not_this_certificate", Status: http.StatusUnprocessableEntity}
	ErrACMRevokeUnsupported   = ErrorCode{Code: "ALC-ACM-0038", Reason: "acme.revoke_unsupported", Status: http.StatusUnprocessableEntity}
	ErrACMRevokeReasonRefused = ErrorCode{Code: "ALC-ACM-0039", Reason: "acme.revoke_reason_refused", Status: http.StatusUnprocessableEntity}
	ErrACMRevokeUnauthorized  = ErrorCode{Code: "ALC-ACM-0040", Reason: "acme.revoke_unauthorized", Status: http.StatusUnprocessableEntity}
	// RFC 9773 alreadyReplaced (R50): another order at the authority replaces the certificate already; an order's code only
	// (a renewal takes that order over or orders once more without replaces first). Transient: that order ends there.
	ErrACMAlreadyReplaced = ErrorCode{Code: "ALC-ACM-0041", Reason: "acme.already_replaced", Status: http.StatusConflict, Retryable: true}

	// Key-compromise incidents (area INC, 2026-10-20). 0001-0004 answer a request; 0005-0013 are the codes an incident
	// records on itself (attention_code) or on a location (error_code), never an answer.
	ErrINCOpen                  = ErrorCode{Code: "ALC-INC-0001", Reason: "incident.open", Status: http.StatusConflict}
	ErrINCState                 = ErrorCode{Code: "ALC-INC-0002", Reason: "incident.state", Status: http.StatusConflict}
	ErrINCReplacementInvalid    = ErrorCode{Code: "ALC-INC-0003", Reason: "incident.replacement_invalid", Status: http.StatusUnprocessableEntity}
	ErrINCNotRevocable          = ErrorCode{Code: "ALC-INC-0004", Reason: "incident.not_revocable", Status: http.StatusConflict}
	ErrINCOtherCertificate      = ErrorCode{Code: "ALC-INC-0005", Reason: "incident.other_certificate", Status: http.StatusConflict}
	ErrINCNotDeployable         = ErrorCode{Code: "ALC-INC-0006", Reason: "incident.not_deployable", Status: http.StatusConflict}
	ErrINCFollowsKeyVault       = ErrorCode{Code: "ALC-INC-0007", Reason: "incident.follows_key_vault", Status: http.StatusConflict}
	ErrINCFollowsOtherACME      = ErrorCode{Code: "ALC-INC-0008", Reason: "incident.follows_other_acme", Status: http.StatusConflict}
	ErrINCLocationBusy          = ErrorCode{Code: "ALC-INC-0009", Reason: "incident.location_busy", Status: http.StatusConflict}
	ErrINCDeploymentsFailed     = ErrorCode{Code: "ALC-INC-0010", Reason: "incident.deployments_failed", Status: http.StatusConflict}
	ErrINCDeploymentsUnverified = ErrorCode{Code: "ALC-INC-0011", Reason: "incident.deployments_unverified", Status: http.StatusConflict}
	ErrINCKeyReused             = ErrorCode{Code: "ALC-INC-0012", Reason: "incident.key_reused", Status: http.StatusConflict}
	ErrINCReplacementUnusable   = ErrorCode{Code: "ALC-INC-0013", Reason: "incident.replacement_unusable", Status: http.StatusConflict}

	// Network certificate discovery (area DSC). A scope's entries are refused at save time (0001-0003, 0009-0011); a
	// scan start meets 0004, 0007 and 0013 (the scope is switched off: Task 9 ruling); 0005, 0006 and 0012 are the end of a
	// scan (discovery_scans.error_code holds the reason). An export that finds another running answers ALC-RPT-0004
	// (export.busy), not a code of its own.
	ErrDSCScopeTooLarge   = ErrorCode{Code: "ALC-DSC-0001", Reason: "discovery.scope_too_large", Status: http.StatusUnprocessableEntity}
	ErrDSCEntryNotAllowed = ErrorCode{Code: "ALC-DSC-0002", Reason: "discovery.entry_not_allowed", Status: http.StatusUnprocessableEntity}
	ErrDSCEntryInvalid    = ErrorCode{Code: "ALC-DSC-0003", Reason: "discovery.entry_invalid", Status: http.StatusUnprocessableEntity}
	ErrDSCScanRunning     = ErrorCode{Code: "ALC-DSC-0004", Reason: "discovery.scan_running", Status: http.StatusConflict, Retryable: true}
	ErrDSCScanCancelled   = ErrorCode{Code: "ALC-DSC-0005", Reason: "discovery.scan_cancelled", Status: http.StatusConflict}
	ErrDSCScanTimedOut    = ErrorCode{Code: "ALC-DSC-0006", Reason: "discovery.scan_timed_out", Status: http.StatusGatewayTimeout}
	ErrDSCTooManyScans    = ErrorCode{Code: "ALC-DSC-0007", Reason: "discovery.too_many_scans", Status: http.StatusConflict, Retryable: true}
	ErrDSCScopeNotFound   = ErrorCode{Code: "ALC-DSC-0008", Reason: "discovery.scope_not_found", Status: http.StatusNotFound}
	ErrDSCScheduleInvalid = ErrorCode{Code: "ALC-DSC-0009", Reason: "discovery.schedule_invalid", Status: http.StatusUnprocessableEntity}
	ErrDSCNameUnresolved  = ErrorCode{Code: "ALC-DSC-0010", Reason: "discovery.name_unresolved", Status: http.StatusUnprocessableEntity}
	ErrDSCNameTaken       = ErrorCode{Code: "ALC-DSC-0011", Reason: "discovery.name_taken", Status: http.StatusConflict}
	ErrDSCScanInterrupted = ErrorCode{Code: "ALC-DSC-0012", Reason: "discovery.scan_interrupted", Status: http.StatusConflict}
	ErrDSCScopeDisabled   = ErrorCode{Code: "ALC-DSC-0013", Reason: "discovery.scope_disabled", Status: http.StatusConflict}

	// Services and environments (area SVC, R49, design §8.3). The numbers the design reserves for the later phases
	// (0005, 0006, 0008-0015: scoped callers and service policy) are not registered until a phase produces them.
	// ErrSVCUntrusted is also the closed reason of a deployment, a Key Vault import or an SSH key deploy refused at its
	// first send, and of a binding marked by the automatic deployment planners, for a trust removed meanwhile.
	ErrSVCNotFound         = ErrorCode{Code: "ALC-SVC-0001", Reason: "service.not_found", Status: http.StatusNotFound}
	ErrSVCNameTaken        = ErrorCode{Code: "ALC-SVC-0002", Reason: "service.name_taken", Status: http.StatusConflict}
	ErrSVCNotEmpty         = ErrorCode{Code: "ALC-SVC-0003", Reason: "service.not_empty", Status: http.StatusConflict}
	ErrSVCDefaultProtected = ErrorCode{Code: "ALC-SVC-0004", Reason: "service.default_protected", Status: http.StatusConflict}
	ErrSVCUntrusted        = ErrorCode{Code: "ALC-SVC-0007", Reason: "service.untrusted", Status: http.StatusConflict}
	ErrSVCEnvironmentInUse = ErrorCode{Code: "ALC-SVC-0016", Reason: "environment.in_use", Status: http.StatusConflict}
	ErrSVCEnvironmentTaken = ErrorCode{Code: "ALC-SVC-0017", Reason: "environment.key_taken", Status: http.StatusConflict}
	// ErrSVCTrustExists: the next free number (the design names no code for a trust made twice).
	ErrSVCTrustExists = ErrorCode{Code: "ALC-SVC-0018", Reason: "service.trust_exists", Status: http.StatusConflict}

	// Scoped callers (R49 Phase 2, design §4.4, §5.6, §5.10). ErrSVCRequired: a create by a caller who may create in
	// several services (or none) names no service_id; ErrSVCNotAllowed: the named service is outside the caller's
	// reach; ErrSVCSpansServices: a cross-service action reaches a service the caller holds no right on (params.count,
	// never a name).
	ErrSVCRequired      = ErrorCode{Code: "ALC-SVC-0005", Reason: "service.required", Status: http.StatusUnprocessableEntity}
	ErrSVCNotAllowed    = ErrorCode{Code: "ALC-SVC-0006", Reason: "service.not_allowed", Status: http.StatusForbidden}
	ErrSVCSpansServices = ErrorCode{Code: "ALC-SVC-0012", Reason: "service.spans_services", Status: http.StatusForbidden}

	// Role bindings (area ACC, R49 Phase 2, design §8.3): the same role on the same service or environment twice, and
	// more bindings for one person than the bound allows.
	ErrACCBindingDuplicate = ErrorCode{Code: "ALC-ACC-0001", Reason: "binding.duplicate", Status: http.StatusConflict}
	ErrACCBindingLimit     = ErrorCode{Code: "ALC-ACC-0005", Reason: "binding.limit", Status: http.StatusUnprocessableEntity}
	// ErrBreakGlassGlobalRole: removing the global role of the break-glass account (R53; the next USR number).
	ErrBreakGlassGlobalRole = ErrorCode{Code: "ALC-USR-0004", Reason: "user.break_glass_global_role", Status: http.StatusConflict}
)

// AllErrorCodes lists every registered code; tests check format, uniqueness, translations and docs.
func AllErrorCodes() []ErrorCode {
	return []ErrorCode{
		ErrNotFound, ErrUnavailable, ErrUnexpected, ErrBadRequest, ErrRateLimited, ErrValidation, ErrBodyTooLarge, ErrPreconditionFailed, ErrMethodNotAllowed,
		ErrUnauthenticated, ErrForbidden, ErrStepUpRequired, ErrCSRF, ErrInvalidCredentials, ErrMFAInvalid,
		ErrMFAAlreadyEnrolled, ErrPasswordTooShort, ErrPasswordTooLong, ErrPasswordBreached, ErrCurrentPasswordInvalid, ErrTryAgain,
		ErrUsernameTaken, ErrLastAdmin, ErrSSOUser, ErrTokenScopeNotAllowed, ErrAuditBusy,
		ErrSetupCodeInvalid, ErrSetupLocked, ErrSetupSessionExpired, ErrSetupEnrollmentMissing,
		ErrPassphraseTooShort, ErrPassphraseMismatch, ErrPassphraseAlreadySet, ErrSetupIncomplete, ErrSetupLicenseChoiceMissing,
		ErrLicenseLocked,
		ErrLicenseInvalid, ErrLicenseWrongInstallation, ErrLicenseUnknownKey, ErrLicenseRevokedKey,
		ErrLicenseUnsupportedFormat, ErrLicenseOlderThanInstalled, ErrLicenseTargetLimit, ErrLicenseUnverified,
		ErrTargetDuplicate, ErrHostKeyUnconfirmed, ErrHostKeyStale, ErrHostKeyChanged, ErrHostKeyState, ErrTargetDisabled,
		ErrSSHUnreachable, ErrSSHAuthFailed, ErrSSHTimeout, ErrHelperMissing, ErrHelperOutdated, ErrHelperRefused,
		ErrFileChanged, ErrKeysManagedElsewhere, ErrOutputTooLarge, ErrSSHProtocol, ErrHelperChecksums, ErrSSHAddressNotAllowed, ErrHelperOutdatedHTTP01,
		ErrHelperOutdatedRollbackGuard,
		ErrOwnKeyProtected, ErrLastRootKey, ErrKeyNotRemovable, ErrSSHDUnreadable, ErrKeyVerifyFailed,
		ErrKeyNotManaged, ErrKeyRetired, ErrKeyDestroyed, ErrKeyConnectionAccount, ErrKeyLoginFailed, ErrKeyGenerateBusy,
		ErrKeyAddUndoFailed, ErrKeyNotAKeyFile, ErrKeyConnectionFilesUnknown, ErrKeyClockBehind, ErrKeyAddUncertain,
		ErrKeyConnectionAccountFile, ErrKeyInRotation, ErrNotifyQueueFailed,
		ErrSMTPNotConfigured, ErrSMTPConnect, ErrSMTPTLS, ErrSMTPUntrusted, ErrSMTPAuth, ErrSMTPRejected, ErrSMTPCertNotSeen,
		ErrSMTPAddressRefused, ErrExportTooLarge, ErrViewLimit, ErrViewNameTaken, ErrExportBusy,
		ErrSSODiscoveryFailed, ErrSSOAdminMappingDisabled, ErrSSOAdminMappingsExist, ErrSSOPublicURLMissing, ErrSSOProviderInUse,
		ErrSSONoAccess, ErrSSOGroupsOverage, ErrSSOEmailInUse, ErrSSOIdPUnreachable, ErrSSOLoginInvalid, ErrSSOLoginExpired,
		ErrSSOUserDisabled, ErrSSOProviderDisabled, ErrSSOStepUpOtherUser, ErrSSOIdPError, ErrSSONotSSOUser,
		ErrLDAPSignInRefused, ErrLDAPDirectoryUnavailable, ErrLDAPDirectoryInUse, ErrLDAPConnectionTestFailed,
		ErrLDAPTooManyDirectories, ErrLDAPSignInTestFailed, ErrLDAPEnrolmentRequired, ErrLDAPNotDirectoryUser, ErrLDAPUserNotDirectory,
		ErrRotPolicyExists, ErrRotInProgress, ErrRotPlanChanged, ErrRotNothingToRotate, ErrRotNotWaiting, ErrRotAddFailed,
		ErrRotVerifyFailed, ErrRotUndoFailed, ErrRotRemoveIncomplete, ErrRotDecisionTimeout, ErrRotPausedLicense,
		ErrRotCancelledLicense, ErrRotStopped, ErrRotPolicyOff, ErrRotNewKeyFailed, ErrRotRetriesExhausted,
		ErrRotNoticeUndelivered, ErrRotOldKeyGone, ErrRotPlanTooLarge, ErrRotStartFailed, ErrRotNoticePending, ErrRotLateResult,
		ErrRotGuardRefused, ErrRotSkippedAtSend, ErrRotListingIncomplete,
		ErrJobNotWaiting, ErrJobLeaseExpired, ErrJobTampered, ErrJobUnknownType, ErrJobConflict,
		ErrNginxNotFound, ErrNginxConfigInvalid, ErrNginxConfigChanged, ErrNginxProfileMissing, ErrNginxNoSpace,
		ErrNginxFileChanged, ErrNginxLocationUnsupported, ErrNginxBusy, ErrNginxIOError, ErrNginxNotRunning,
		ErrApacheNotFound, ErrApacheConfigInvalid, ErrApacheProfileMissing, ErrApacheHelperTooOld,
		ErrHAProxyNotFound, ErrHAProxyConfigInvalid, ErrHAProxyProfileMissing, ErrHAProxyHelperTooOld,
		ErrCertInvalid, ErrCertKeyMismatch, ErrCertExpired, ErrCertKeyEncrypted, ErrCertPFXPassword, ErrCertWeak,
		ErrCertUnsupportedKey, ErrCertDuplicate, ErrCertNoPrivateKey, ErrCertKeyTypeMismatch, ErrCertChainUnconfirmed,
		ErrCSRNotPending, ErrCSRCertificateMismatch, ErrCertNotYetValid, ErrCertPFXBusy, ErrCSRBusy, ErrCSRTooManyPending,
		ErrCertRevoked, ErrCertCompromised,
		ErrDeployInProgress, ErrDeployRecoveryPending, ErrDeployVerifyFailed, ErrDeployVerifyOther, ErrDeployVerifyUnreachable,
		ErrDeployReloadFailed, ErrDeployConfigTestFailed, ErrDeployRollbackFailed, ErrDeployRollbackReloadFailed,
		ErrDeployInterrupted, ErrDeployTargetNotReady, ErrDeployVerifyChain, ErrDeployNothingToRestore, ErrDeploySuperseded,
		ErrDeployUnknownOperation, ErrDeployTargetDeleted, ErrDeployRecoveryExhausted, ErrDeployOutcomeUnknown,
		ErrDeployRestoredUnverified, ErrDeployRollbackFileChanged, ErrDeployRescanNeeded, ErrDeployCancelled, ErrDeployServerOperationPending, ErrDeployPendingChangeRestored,
		ErrDeployRollbackForbidden, ErrDeployVerifyUntrusted, ErrDeployDriftRepairSuperseded, ErrDeployDriftRepairOff, ErrDeployDriftNotBound,
		ErrDeployNotDrifted,
		ErrAzureAuthFailed, ErrAzureCredentialsExpired, ErrAzureForbidden, ErrAzureFirewall, ErrAzureVaultNotFound, ErrAzureUnreachable,
		ErrAzureThrottled, ErrAzureUnexpectedResponse, ErrAzureClockSkew, ErrAzureManagedIdentityGone, ErrAzureAddressNotAllowed,
		ErrAzureTLSUntrusted, ErrKVNotExportable, ErrKVVersionDisabled, ErrKVCertificateNotFound, ErrKVSecretUnreadable, ErrKVSecretMismatch,
		ErrKVLocationBound, ErrKVBindingExists, ErrKVVaultHasBindings, ErrKVVersionNotDeployable, ErrKVHeldNeedsAdmin, ErrKVImportConfirmNeeded,
		ErrKVImportInProgress, ErrKVImportRejected, ErrKVImportOutcomeUnknown, ErrKVClientCertInvalid, ErrKVVaultDuplicate,
		ErrKVImportNameExists, ErrKVImportInvalid, ErrKVBindingGone, ErrKVAutoDeployOff, ErrKVVaultUnavailable, ErrKVVersionHeld,
		ErrKVVersionNotHeld, ErrKVVersionSuperseded, ErrKVWaveStopped, ErrKVImportVaultDeleted, ErrKVImportCancelled, ErrKVImportAdminRequired,
		ErrKVCredentialUnreadable,
		ErrBackupRunning, ErrBackupNotConfigured, ErrBackupNotFound, ErrBackupWriteFailed,
		ErrTLSKeyMismatch, ErrTLSNotValidNow, ErrTLSWeakKey, ErrTLSPFXPassword, ErrTLSUnreadable,
		ErrForwardingAddressRefused, ErrForwardingUnreachable, ErrForwardingUntrusted, ErrPassphraseTooWeak,
		ErrACMProviderUnreachable, ErrACMDirectoryInvalid, ErrACMTermsNotAccepted, ErrACMAccountRejected, ErrACMCaRateLimited, ErrACMValidationFailedDns,
		ErrACMValidationFailedHttp, ErrACMHookRefused, ErrACMIdentifierRefused, ErrACMNotIssuedInTime, ErrACMKeyPolicyNotAllowed, ErrACMProviderInUse,
		ErrACMTlsTrustFailed, ErrACMRolloverUnsupported, ErrACMNameNotAllowed, ErrACMOrderRunning, ErrACMChallengeUnavailable, ErrACMKeyTypeLocked,
		ErrACMHookInUse, ErrACMNameTaken, ErrACMAccountExists, ErrACMDirectoryChangeUnconfirmed, ErrACMAccountState, ErrACMRolloverPending,
		ErrACMSecretUnreadable, ErrACMOrderAbandoned, ErrACMNotIssued, ErrACMLocationBound, ErrACMLocationNotBound,
		ErrACMBindingGone, ErrACMAutoDeployOff, ErrACMCertificateSuperseded, ErrACMDeployStopped, ErrACMDeployHeld,
		ErrACMNoBindings, ErrACMTooManyBindings, ErrACMNotThisCertificate, ErrACMRevokeUnsupported, ErrACMRevokeReasonRefused,
		ErrACMRevokeUnauthorized, ErrACMAlreadyReplaced,
		ErrINCOpen, ErrINCState, ErrINCReplacementInvalid, ErrINCNotRevocable, ErrINCOtherCertificate, ErrINCNotDeployable,
		ErrINCFollowsKeyVault, ErrINCFollowsOtherACME, ErrINCLocationBusy, ErrINCDeploymentsFailed, ErrINCDeploymentsUnverified,
		ErrINCKeyReused, ErrINCReplacementUnusable,
		ErrDSCScopeTooLarge, ErrDSCEntryNotAllowed, ErrDSCEntryInvalid, ErrDSCScanRunning, ErrDSCScanCancelled, ErrDSCScanTimedOut,
		ErrDSCTooManyScans, ErrDSCScopeNotFound, ErrDSCScheduleInvalid, ErrDSCNameUnresolved, ErrDSCNameTaken, ErrDSCScanInterrupted,
		ErrDSCScopeDisabled,
		ErrSVCNotFound, ErrSVCNameTaken, ErrSVCNotEmpty, ErrSVCDefaultProtected, ErrSVCUntrusted, ErrSVCEnvironmentInUse,
		ErrSVCEnvironmentTaken, ErrSVCTrustExists, ErrSVCRequired, ErrSVCNotAllowed, ErrSVCSpansServices,
		ErrACCBindingDuplicate, ErrACCBindingLimit, ErrBreakGlassGlobalRole,
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
	// Services (R49). A deployment, binding, import or SSH key deploy across services without a trust: an
	// *authz.UntrustedError (the services are named by fail).
	{authz.ErrUntrusted, ErrSVCUntrusted, nil},
	{services.ErrNotFound, ErrSVCNotFound, nil},
	{services.ErrEnvironmentNotFound, ErrNotFound, nil},
	{services.ErrTrustNotFound, ErrNotFound, nil},
	{services.ErrNameTaken, ErrSVCNameTaken, nil},
	{services.ErrDefaultProtected, ErrSVCDefaultProtected, nil},
	{services.ErrEnvironmentInUse, ErrSVCEnvironmentInUse, nil},
	{services.ErrEnvironmentKeyTaken, ErrSVCEnvironmentTaken, nil},
	{services.ErrTrustExists, ErrSVCTrustExists, nil},
	{services.ErrBindingNotFound, ErrNotFound, nil},
	{services.ErrUserNotFound, ErrNotFound, nil},
	{services.ErrBindingDuplicate, ErrACCBindingDuplicate, nil},
	{services.ErrBindingLimit, ErrACCBindingLimit, map[string]string{"max": strconv.Itoa(services.MaxBindingsPerSubject)}},
	{auth.ErrBreakGlassGlobalRole, ErrBreakGlassGlobalRole, nil},
	{services.ErrVersionMismatch, ErrPreconditionFailed, nil},
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
	{inventory.ErrTargetDisabled, ErrTargetDisabled, nil}, // a key change on a disabled server (Phase 6, Task 6)
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
	{inventory.ErrCertificateRevoked, ErrCertRevoked, nil},
	{inventory.ErrCertificateCompromised, ErrCertCompromised, nil},
	{inventory.ErrNotACMEVersion, ErrACMNotThisCertificate, nil},
	{inventory.ErrIncidentOpen, ErrINCOpen, nil},
	{inventory.ErrIncidentState, ErrINCState, nil},
	{inventory.ErrIncidentReplacement, ErrINCReplacementInvalid, nil},
	{inventory.ErrIncidentNotRevocable, ErrINCNotRevocable, nil},
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
	// Certificate drift (R52).
	{inventory.ErrDriftRepairSuperseded, ErrDeployDriftRepairSuperseded, nil},
	{inventory.ErrDriftRepairOff, ErrDeployDriftRepairOff, nil},
	{inventory.ErrDriftNotBound, ErrDeployDriftNotBound, nil},
	{inventory.ErrDriftNotDrifted, ErrDeployNotDrifted, nil},
	// Phase 5. *inventory.ImportConfirmError is matched in classify with its certificate_name; the bare
	// sentinel still gets its code. ErrNotAVault and ErrNotAServer name a target of the wrong kind on
	// a route of the other: the route does not exist for it (404). ErrAdminRequired is a matter of
	// authority only (ruling S6). The engine-only ones (ErrBindingGone, ErrAutoDeployOff, ErrVersionHeld,
	// ErrVersionSuperseded, ErrWaveStopped, ErrImportState, ErrImportChanged) have no entry on purpose.
	// ErrCredentialNotTheTargets is different: ReplaceVaultCredentials can return it (the database trigger Z1006
	// refuses a credential that is not the target's), but only when Alice's own code is wrong. It has no entry
	// ON PURPOSE: it answers the internal error ALC-SYS-0003 and fail logs its type, because a person cannot
	// act on it.
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
	{inventory.ErrVaultCredentialUnreadable, ErrKVCredentialUnreadable, nil},
	{inventory.ErrVaultUnavailable, ErrKVVaultUnavailable, nil},
	{inventory.ErrImportConfirmNeeded, ErrKVImportConfirmNeeded, nil},
	{inventory.ErrImportInProgress, ErrKVImportInProgress, nil},
	// ACME providers, accounts and hooks (Task 9). A CA exchange's failure is an *inventory.ACMEError (classify).
	{inventory.ErrACMEProviderInUse, ErrACMProviderInUse, nil},
	{inventory.ErrACMEHookInUse, ErrACMHookInUse, nil},
	{inventory.ErrACMENameTaken, ErrACMNameTaken, nil},
	{inventory.ErrACMEDirectoryChange, ErrACMDirectoryChangeUnconfirmed, nil},
	{inventory.ErrACMESecretUnreadable, ErrACMSecretUnreadable, nil},
	{inventory.ErrACMEAccountExists, ErrACMAccountExists, nil},
	{inventory.ErrACMEAccountState, ErrACMAccountState, nil},
	{inventory.ErrACMERolloverPending, ErrACMRolloverPending, nil},
	// Another account operation of the provider holds its lock: the same "not settled yet, try again" answer.
	{inventory.ErrACMEProviderBusy, ErrACMRolloverPending, nil},
	// ACME certificates and orders (Task 10).
	{inventory.ErrACMENameNotAllowed, ErrACMNameNotAllowed, nil},
	{inventory.ErrACMEOrderRunning, ErrACMOrderRunning, nil},
	// The CA asked to wait (R47): it comes inside an *inventory.ACMEError (with the time left: Retry-After); bare, the same code.
	{inventory.ErrACMECAWait, ErrACMCaRateLimited, nil},
	{inventory.ErrACMEChallengeUnavailable, ErrACMChallengeUnavailable, nil},
	{inventory.ErrACMEKeyTypeLocked, ErrACMKeyTypeLocked, nil},
	// ACME bindings and Deploy now (Task 12).
	{inventory.ErrACMENotIssued, ErrACMNotIssued, nil},
	{inventory.ErrACMELocationBound, ErrACMLocationBound, nil},
	{inventory.ErrACMELocationNotBound, ErrACMLocationNotBound, nil},
	{inventory.ErrACMEBindingGone, ErrACMBindingGone, nil},
	{inventory.ErrACMEAutoDeployOff, ErrACMAutoDeployOff, nil},
	{inventory.ErrACMESuperseded, ErrACMCertificateSuperseded, nil},
	{inventory.ErrACMEDeployStopped, ErrACMDeployStopped, nil},
	{inventory.ErrACMEDeployHeld, ErrACMDeployHeld, nil},
	{inventory.ErrACMENoBindings, ErrACMNoBindings, nil},
	{inventory.ErrACMETooManyBindings, ErrACMTooManyBindings, nil}, // the texts name the limit (inventory.MaxDeployLocations, 20)
	// The inventory repeats the session check inside its transaction (a hold or a switch-on can appear after the
	// API looked): what it refuses is a session without a fresh step-up.
	{inventory.ErrHeldNeedsStepUp, ErrStepUpRequired, nil},
	{inventory.ErrAutoDeployNeedsStepUp, ErrStepUpRequired, nil},
	// Phase 6 (C11). sshkeys.ErrNotFound, ErrVersionMismatch and ErrOwnKeyProtected are the inventory's sentinels
	// (matched above). The store's ErrNotYourTurn and ErrPaused reach only the job handlers; a request that met one
	// is answered ALC-SYS-0003. *sshkeys.GuardRefusal (the database refused a rotation step: a store bug) has no
	// entry on purpose: it is answered ALC-SYS-0003 and fail logs its SQLSTATE and constraint name only. The planner's errors are mapped by the service; they are listed for a path that
	// returns one unmapped.
	{sshkeys.ErrNotManaged, ErrKeyNotManaged, nil},
	{sshkeys.ErrRetired, ErrKeyRetired, nil},
	{sshkeys.ErrDestroyed, ErrKeyDestroyed, nil},
	{sshkeys.ErrConnectionAccount, ErrKeyConnectionAccount, nil},
	{sshkeys.ErrConnectionFilesUnknown, ErrKeyConnectionFilesUnknown, nil},
	{sshkeys.ErrNotAKeyFile, ErrKeyNotAKeyFile, nil},
	{sshkeys.ErrGenerateBusy, ErrKeyGenerateBusy, nil},
	{sshkeys.ErrClockBehind, ErrKeyClockBehind, nil},
	{sshkeys.ErrPolicyExists, ErrRotPolicyExists, nil},
	{sshkeys.ErrRotationInProgress, ErrRotInProgress, nil},
	{sshkeys.ErrPlanChanged, ErrRotPlanChanged, nil},
	{sshkeys.ErrNothingToRotate, ErrRotNothingToRotate, nil},
	{sshkeys.ErrNotWaiting, ErrRotNotWaiting, nil},
	{sshkeys.ErrNoticePending, ErrRotNoticePending, nil},
	{sshkeys.ErrInRotation, ErrKeyInRotation, nil},
	{sshkeys.ErrPlanTooLarge, ErrRotPlanTooLarge, nil},
	{sshkeys.ErrBadCursor, ErrBadRequest, nil}, // a cursor that does not decode
	{plan.ErrOwnKey, ErrOwnKeyProtected, nil},
	{plan.ErrNotManaged, ErrKeyNotManaged, nil},
	{plan.ErrRetired, ErrKeyRetired, nil},
	{plan.ErrNothingToRotate, ErrRotNothingToRotate, nil},
	{plan.ErrNewKeyType, ErrValidation, nil},
	// Phase 7 (C15). An untrusted certificate (a *notify.CertError, or the bare sentinel) is also a TLS failure: it is
	// matched first. A stale settings version is the precondition answer of every If-Match.
	{auth.ErrSSOUser, ErrSSOUser, nil},
	{auth.ErrNotDirectoryUser, ErrLDAPUserNotDirectory, nil},
	{notify.ErrNotConfigured, ErrSMTPNotConfigured, nil},
	{notify.ErrSMTPUntrusted, ErrSMTPUntrusted, nil},
	{notify.ErrSMTPConnect, ErrSMTPConnect, nil},
	{notify.ErrSMTPTLS, ErrSMTPTLS, nil},
	{notify.ErrSMTPAuth, ErrSMTPAuth, nil},
	{notify.ErrSMTPRejected, ErrSMTPRejected, nil},
	{notify.ErrCertNotSeen, ErrSMTPCertNotSeen, nil},
	{notify.ErrAddressRefused, ErrSMTPAddressRefused, nil},
	{notify.ErrVersion, ErrPreconditionFailed, nil},
	{reports.ErrTooLarge, ErrExportTooLarge, map[string]string{"max": strconv.Itoa(reports.MaxExportRows)}},
	{reports.ErrViewLimit, ErrViewLimit, map[string]string{"max": strconv.Itoa(reports.MaxViewsPerUser)}},
	{reports.ErrViewName, ErrViewNameTaken, nil},
	{reports.ErrExportBusy, ErrExportBusy, nil},
	{reports.ErrNotFound, ErrNotFound, nil},
	// Single sign-on (C15). *oidc.DiscoveryError and *oidc.LoginError are matched in classify. The auth sentinels of a
	// sign-in reach the API only as a LoginError; they are mapped here too so that none can become a 500.
	// auth.ErrOIDCIdentityInvalid means Alice passed an identity it cannot store: answered as a refused sign-in.
	{oidc.ErrAdminMappingDisabled, ErrSSOAdminMappingDisabled, nil},
	{oidc.ErrAdminMappingsExist, ErrSSOAdminMappingsExist, nil},
	{oidc.ErrPublicURLMissing, ErrSSOPublicURLMissing, nil},
	{oidc.ErrProviderInUse, ErrSSOProviderInUse, nil},
	{oidc.ErrNotFound, ErrNotFound, nil},
	{oidc.ErrVersion, ErrPreconditionFailed, nil},
	{auth.ErrNotSSOUser, ErrSSONotSSOUser, nil},
	{auth.ErrOIDCEmailInUse, ErrSSOEmailInUse, nil},
	{auth.ErrOIDCUserDisabled, ErrSSOUserDisabled, nil},
	{auth.ErrOIDCOtherUser, ErrSSOStepUpOtherUser, nil},
	{auth.ErrOIDCIdentityInvalid, ErrSSOLoginInvalid, nil},
	// Directory sign-in (Task 5). *ldap.LoginError is matched in classify. ldap.ErrTooMany of a group mapping is a field
	// error (failLDAP); here it is the directory limit. The auth sentinels of a directory sign-in are answered by the
	// sign-in handlers with the generic refusal after RefuseLDAP; they are mapped here too so that none can become a 500.
	{auth.ErrDirectoryUser, ErrSSOUser, nil},
	{ldap.ErrAdminMappingDisabled, ErrSSOAdminMappingDisabled, nil},
	{ldap.ErrDirectoryInUse, ErrLDAPDirectoryInUse, nil},
	{ldap.ErrTooMany, ErrLDAPTooManyDirectories, map[string]string{"max": strconv.Itoa(ldap.MaxDirectories)}},
	{ldap.ErrNotFound, ErrNotFound, nil},
	{ldap.ErrVersion, ErrPreconditionFailed, nil},
	{ldap.ErrNoConnectionTest, ErrLDAPConnectionTestFailed, nil},
	{auth.ErrLDAPEnrolmentRequired, ErrLDAPEnrolmentRequired, nil},
	{auth.ErrLDAPEmailInUse, ErrLDAPSignInRefused, nil},
	{auth.ErrLDAPUserDisabled, ErrLDAPSignInRefused, nil},
	{auth.ErrLDAPUserLocked, ErrLDAPSignInRefused, nil},
	{auth.ErrLDAPOtherUser, ErrLDAPSignInRefused, nil},
	{auth.ErrLDAPIdentityInvalid, ErrLDAPSignInRefused, nil},
	// Phase 8 (C12).
	{backup.ErrRunning, ErrBackupRunning, nil},
	{backup.ErrNotConfigured, ErrBackupNotConfigured, nil},
	{backup.ErrNotFound, ErrBackupNotFound, nil},
	{backup.ErrWrite, ErrBackupWriteFailed, nil},
	{backup.ErrVersion, ErrPreconditionFailed, nil},
	{tlscert.ErrKeyMismatch, ErrTLSKeyMismatch, nil},
	{tlscert.ErrNotValidNow, ErrTLSNotValidNow, nil},
	{tlscert.ErrWeakKey, ErrTLSWeakKey, nil},
	{tlscert.ErrPFXPassword, ErrTLSPFXPassword, nil},
	{tlscert.ErrUnreadable, ErrTLSUnreadable, nil},
	{forward.ErrAddressRefused, ErrForwardingAddressRefused, nil},
	{forward.ErrUnreachable, ErrForwardingUnreachable, nil},
	{forward.ErrUntrusted, ErrForwardingUntrusted, nil},
	{forward.ErrVersion, ErrPreconditionFailed, nil},
	{setup.ErrPassphraseTooWeak, ErrPassphraseTooWeak, nil},
	// Network discovery (Task 9). A *discovery.Error and a *discoverysvc.NameUnresolvedError are matched in classify with
	// their field and index; discovery.ErrFilterNeedsNow is Alice's own mistake and has no entry (ALC-SYS-0003).
	{discovery.ErrScanRunning, ErrDSCScanRunning, nil},
	{discovery.ErrScopeNotFound, ErrDSCScopeNotFound, nil},
	{discoverysvc.ErrTooManyScans, ErrDSCTooManyScans, nil},
	{discoverysvc.ErrNameTaken, ErrDSCNameTaken, nil},
	{discoverysvc.ErrScopeDisabled, ErrDSCScopeDisabled, nil},
	{discoverysvc.ErrNotFound, ErrNotFound, nil},
	{discoverysvc.ErrVersion, ErrPreconditionFailed, nil},
	// The save-time look-ups did not finish in the request's budget: a slow name server, not a missing name (ALC-DSC-0010).
	{discoverysvc.ErrLookupBudget, ErrUnavailable, nil},
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
	if errors.Is(err, expiry.ErrThresholds) {
		// C15: the thresholds rule as the form's field error.
		s.writeErrorWith(w, r, ErrValidation, nil, []validate.FieldError{{Field: "thresholds_days", Code: validate.OutOfRange,
			Params: map[string]string{"min": "1", "max": strconv.Itoa(expiry.MaxThresholdDays)}}})
		return
	}
	if errors.Is(err, plan.ErrNewKeyType) {
		// The planner's refusal of the policy's new key type: the form marks the field (review M13).
		s.writeErrorWith(w, r, ErrValidation, nil, []validate.FieldError{{Field: "new_key_type", Code: validate.OneOf,
			Params: map[string]string{"values": newKeyTypeValues()}}})
		return
	}
	ec, params, ok := classify(err)
	if !ok {
		attrs := append([]any{"request_id", RequestID(r.Context()), "path", r.URL.Path}, errorAttrs(err)...)
		var guard *sshkeys.GuardRefusal
		if errors.As(err, &guard) {
			// A rotation step the database refused: the code and the constraint's name are fixed labels; the
			// guard's message can name row values and is never logged here nor answered.
			attrs = append(attrs, "guard_sqlstate", guard.Code, "guard_constraint", guard.Constraint)
		}
		s.deps.Log.Error("request failed", attrs...)
		s.writeError(w, r, ErrUnexpected)
		return
	}
	if ec == ErrUnexpected {
		s.deps.Log.Error("request failed", append([]any{"request_id", RequestID(r.Context()), "path", r.URL.Path}, errorAttrs(err)...)...)
	}
	if ec == ErrStepUpRequired && rbac.Decide(rbac.CredentialsManage, principalFrom(r.Context()).Subject(s.deps.Clock.Now())) == rbac.DenyForbidden {
		// The inventory's strict refusal (a hold or a switch-on that appeared after the handler's check) reached a
		// caller that cannot step up, an API token: it gets the documented ALC-AUTH-0002, as at the handler.
		ec = ErrForbidden
	}
	switch ec {
	case ErrCertPFXBusy, ErrCSRBusy, ErrKeyGenerateBusy:
		w.Header().Set("Retry-After", "1") // a decode or key generation slot frees within seconds
	case ErrKeyClockBehind:
		w.Header().Set("Retry-After", "60") // the clock must pass the time Alice recorded last
	case ErrRotNoticePending:
		w.Header().Set("Retry-After", "60") // the sweep runs every minute
	case ErrExportBusy:
		w.Header().Set("Retry-After", "5") // the user's other export holds the slot until its last row is written
	case ErrDSCScanRunning, ErrDSCTooManyScans:
		w.Header().Set("Retry-After", "30") // a scan ends within its 60-minute cap; most end within minutes
	}
	if errors.Is(err, discoverysvc.ErrLookupBudget) {
		w.Header().Set("Retry-After", "30") // the name server was slow; the look-ups of the next save start afresh
	}
	if after := acmeRetryAfter(err, ec); after != "" {
		w.Header().Set("Retry-After", after)
	}
	if names := s.untrustedParams(r, err); names != nil {
		params = names // the two services of a cross-service refusal (R49)
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

// acmeRetryAfter is the Retry-After of an ACME refusal in whole seconds ("" for none): the CA's own Retry-After of a
// rate limit (*inventory.ACMEError, bounded at seven days by the client, Task 9 M7 and R47; also the time left of a wait
// the CA asked for, refused before the CA is contacted), a minute for a rate limit that named
// none, and two seconds while another account operation of the provider holds its lock (it gives up after about two).
func acmeRetryAfter(err error, ec ErrorCode) string {
	var acmeErr *inventory.ACMEError
	switch {
	case errors.As(err, &acmeErr) && acmeErr.RetryAfter > 0:
		secs := int((acmeErr.RetryAfter + time.Second - 1) / time.Second)
		return strconv.Itoa(max(1, secs))
	case ec == ErrACMCaRateLimited:
		return "60"
	case errors.Is(err, inventory.ErrACMEProviderBusy):
		return "2"
	}
	return ""
}

// classify maps a domain error to its API code and params; ok is false for an error no table
// knows (answered as ErrUnexpected by fail).
func classify(err error) (ErrorCode, map[string]string, bool) {
	var notEmpty *services.NotEmptyError
	if errors.As(err, &notEmpty) {
		// How many resources of each kind the service still owns (it is deleted when it owns none).
		c := notEmpty.Counts
		return ErrSVCNotEmpty, map[string]string{"count": strconv.Itoa(c.Total()), "servers": strconv.Itoa(c.Servers),
			"key_vaults": strconv.Itoa(c.KeyVaults), "certificates": strconv.Itoa(c.Certificates), "signing_requests": strconv.Itoa(c.SigningRequests),
			"acme_certificates": strconv.Itoa(c.ACMECertificates), "ssh_keys": strconv.Itoa(c.SSHKeys),
			"discovery_scopes": strconv.Itoa(c.DiscoveryScopes)}, true
	}
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
		// bound / auto_deploy_follows tell the dialog that a connection names the certificate and that the connection has
		// automatic deployment on, so a new version may be deployed by itself (not that it will be: the planner's rules
		// still apply). Booleans as "true"/"false": params are strings.
		params := map[string]string{"auto_deploy_follows": strconv.FormatBool(confirm.AutoDeploy), "bound": strconv.FormatBool(confirm.Bound)}
		if providerParamRules["certificate_name"].MatchString(confirm.CertificateName) {
			params["certificate_name"] = confirm.CertificateName
		}
		return ErrKVImportConfirmNeeded, params, true
	}
	var acmeErr *inventory.ACMEError
	if errors.As(err, &acmeErr) {
		// One of the registered ALC-ACM reasons (inventory maps every CA failure to one); never the CA's text.
		if ec := codeForReason(acmeErr.Reason); ec != ErrUnexpected && strings.HasPrefix(ec.Code, "ALC-ACM-") {
			return ec, nil, true
		}
		return ErrACMDirectoryInvalid, nil, true
	}
	if ec, params, ok := discoveryCode(err); ok {
		return ec, params, true
	}
	var disc *oidc.DiscoveryError
	if errors.As(err, &disc) {
		// The cause is one of Alice's closed labels (connect, tls, status, document, issuer_mismatch, not_https, jwks).
		if !paramCodeRE.MatchString(disc.Cause) {
			return ErrSSODiscoveryFailed, nil, true
		}
		return ErrSSODiscoveryFailed, map[string]string{"cause": disc.Cause}, true
	}
	var login *oidc.LoginError
	if errors.As(err, &login) {
		return loginErrorCode(login), nil, true
	}
	var ldapErr *ldap.LoginError
	if errors.As(err, &ldapErr) {
		return ldapLoginCode(ldapErr), nil, true
	}
	var perr *providers.Error
	if errors.As(err, &perr) {
		// Only the stable reason and its allowlisted primitive params reach the client; the
		// provider's cause (remote output, driver text) is never shown nor logged as text.
		if ec := codeForReason(perr.Code); ec != ErrUnexpected {
			return ec, completeParams(ec.Reason, providerParams(perr.Params)), true
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

// discoveryCode maps a scope validator refusal (*discovery.Error: ALC-DSC-0001/0002/0003/0009) and an unresolved host
// name (ALC-DSC-0010) with the field and the element's index as params. The element's value is never a param: it is
// the Administrator's own input, and the answer must never confirm what a name resolved to.
func discoveryCode(err error) (ErrorCode, map[string]string, bool) {
	var nu *discoverysvc.NameUnresolvedError
	if errors.As(err, &nu) {
		return ErrDSCNameUnresolved, map[string]string{"field": "entries", "index": strconv.Itoa(nu.Index)}, true
	}
	var de *discovery.Error
	if !errors.As(err, &de) {
		return ErrorCode{}, nil, false
	}
	var ec ErrorCode
	switch {
	case errors.Is(de.Kind, discovery.ErrTooLarge):
		ec = ErrDSCScopeTooLarge
	case errors.Is(de.Kind, discovery.ErrNotAllowed):
		ec = ErrDSCEntryNotAllowed
	case errors.Is(de.Kind, discovery.ErrInvalid):
		ec = ErrDSCEntryInvalid
	case errors.Is(de.Kind, discovery.ErrSchedule):
		ec = ErrDSCScheduleInvalid
	default:
		return ErrUnexpected, nil, true
	}
	params := map[string]string{}
	if paramCodeRE.MatchString(de.Field) {
		params["field"] = de.Field
	}
	if de.Index >= 0 {
		params["index"] = strconv.Itoa(de.Index)
	}
	return ec, params, true
}

// ldapLoginCode is the answer to a refused directory sign-in: ALC-LDAP-0002 for a directory that is unreachable,
// misconfigured or switched off (nothing about the person), the generic ALC-LDAP-0001 for every other reason.
func ldapLoginCode(e *ldap.LoginError) ErrorCode {
	switch e.Reason {
	case ldap.ReasonUnreachable, ldap.ReasonMisconfigured, ldap.ReasonDisabled:
		return ErrLDAPDirectoryUnavailable
	}
	return ErrLDAPSignInRefused
}

// loginErrorCode is the code of a refused sign-in or step-up: one of ALC-SSO-0006..0015, ALC-SSO-0010 for a reason
// that is not one of them.
func loginErrorCode(e *oidc.LoginError) ErrorCode {
	switch ec := codeForReason("sso." + e.Reason); ec {
	case ErrSSONoAccess, ErrSSOGroupsOverage, ErrSSOEmailInUse, ErrSSOIdPUnreachable, ErrSSOLoginInvalid, ErrSSOLoginExpired,
		ErrSSOUserDisabled, ErrSSOProviderDisabled, ErrSSOStepUpOtherUser, ErrSSOIdPError:
		return ec
	}
	return ErrSSOLoginInvalid
}

// providerParamKeys are the provider error params a client may see: fixed labels, numbers and
// fingerprints (which are not secret). Any other key is dropped, so a provider that ever puts
// remote text or a key line into its params cannot leak it through the API; every key also has a
// value rule (providerParamRules). The Phase 4 keys are pre-flight D26's.
var providerParamKeys = map[string]bool{
	"helper_code": true, "subcommand": true, "exit_code": true, "reason": true, "field": true, "attempts": true,
	"wait": true, "fingerprint": true, "old_fingerprint": true, "new_fingerprint": true,
	"helper_protocol": true, "required_protocol": true, // ssh.helper_outdated, ssh.helper_outdated_http01
	"port": true, "failed_step": true, "profile": true, "phase": true, "directory": true, "backup_dir": true,
	"expected": true, "actual": true, "mode": true,
	"operation_id": true, // deployment.server_operation_pending
	"trust_error":  true, // deployment.verify_untrusted (R51)
	// Phase 5 (Azure): the role a 403 asks for and the permission model, Entra's AADSTS number, the
	// caller's address a vault firewall refused, the vault's own error code and request id (strict
	// shapes, never Azure's text), and the certificate name an import conflicts with.
	"role": true, "model": true, "aadsts": true, "client_address": true, "azure_code": true, "azure_request_id": true,
	"certificate_name": true,
	// auto_deploy_follows and bound: "true" or "false" (the import confirmation: a connection names the certificate).
	"auto_deploy_follows": true, "bound": true,
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
	paramBoolRE          = regexp.MustCompile(`^(true|false)$`)
	// paramTrustErrorRE: providers.TrustErrors (R51; a test compares them).
	paramTrustErrorRE = regexp.MustCompile(`^(unknown_authority|wrong_intermediate|incomplete_chain|chain_order|name_mismatch|expired|not_yet_valid|invalid_chain)$`)
	// paramTrustRE: a trust status of a verify step (R51).
	paramTrustRE = regexp.MustCompile(`^(trusted|untrusted|unchecked)$`)
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
	"operation_id": paramOperationRE, "trust_error": paramTrustErrorRE,
	"role": paramRoleRE, "model": paramModelRE, "client_address": paramClientAddressRE, "aadsts": paramAADSTSRE,
	"azure_code": paramAzureCodeRE, "azure_request_id": paramRequestIDRE, "certificate_name": paramCertNameRE,
	"auto_deploy_follows": paramBoolRE, "bound": paramBoolRE,
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
