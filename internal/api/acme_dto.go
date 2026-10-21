package api

import (
	"slices"
	"time"

	"alice/internal/acme/renew"
	"alice/internal/inventory"
)

// The ACME views (plan 2026-10-13 Task 13). None carries a secret: the EAB HMAC key, the account key and the DNS hook
// secret are write-only (eab_configured, secret_configured); a CA bundle holds public certificates only.

type acmeProviderDTO struct {
	ID              string           `json:"id"`
	Name            string           `json:"name"`
	DirectoryURL    string           `json:"directory_url"`
	Preset          string           `json:"preset"`
	CABundlePEM     string           `json:"ca_bundle_pem"`
	EABKID          string           `json:"eab_kid"`
	EABConfigured   bool             `json:"eab_configured"`
	AllowedSuffixes []string         `json:"allowed_suffixes"`
	ActiveAccountID *string          `json:"active_account_id"`
	PendingRollover bool             `json:"pending_rollover"`
	CreatedAt       time.Time        `json:"created_at"`
	UpdatedAt       time.Time        `json:"updated_at"`
	Accounts        []acmeAccountDTO `json:"accounts,omitempty"` // the provider's own page only
}

func acmeProviderJSON(p inventory.ACMEProvider) acmeProviderDTO {
	return acmeProviderDTO{ID: p.ID.String(), Name: p.Name, DirectoryURL: p.DirectoryURL, Preset: p.Preset, CABundlePEM: p.CABundlePEM,
		EABKID: p.EABKID, EABConfigured: p.EABConfigured, AllowedSuffixes: nonNil(p.AllowedSuffixes), ActiveAccountID: idPtr(p.ActiveAccountID),
		PendingRollover: p.PendingRollover, CreatedAt: p.CreatedAt.UTC(), UpdatedAt: p.UpdatedAt.UTC()}
}

// acmePreviewDTO is what a CA's directory says before registration (POST /acme/providers/{id}/preview).
type acmePreviewDTO struct {
	TermsOfServiceURL       string `json:"terms_of_service_url"`
	TermsURLUnsafe          bool   `json:"terms_url_unsafe"`
	ExternalAccountRequired bool   `json:"external_account_required"`
	KeyChangeSupported      bool   `json:"key_change_supported"`
	RenewalInfoSupported    bool   `json:"renewal_info_supported"`
	Website                 string `json:"website"`
}

type acmeAccountDTO struct {
	ID              string     `json:"id"`
	ProviderID      string     `json:"provider_id"`
	ContactEmail    string     `json:"contact_email"`
	AccountURL      string     `json:"account_url"`
	TermsURL        string     `json:"tos_url"`
	TermsAcceptedAt *time.Time `json:"tos_accepted_at"`
	State           string     `json:"state"`
	CreatedAt       time.Time  `json:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at"`
}

func acmeAccountJSON(a inventory.ACMEAccount) acmeAccountDTO {
	return acmeAccountDTO{ID: a.ID.String(), ProviderID: a.ProviderID.String(), ContactEmail: a.ContactEmail, AccountURL: a.AccountURL,
		TermsURL: a.TermsURL, TermsAcceptedAt: utcPtr(a.TermsAcceptedAt), State: a.State, CreatedAt: a.CreatedAt.UTC(), UpdatedAt: a.UpdatedAt.UTC()}
}

type acmeHookDTO struct {
	ID                     string    `json:"id"`
	Name                   string    `json:"name"`
	URL                    string    `json:"url"`
	CABundlePEM            string    `json:"ca_bundle_pem"`
	SecretConfigured       bool      `json:"secret_configured"`
	AllowedSuffixes        []string  `json:"allowed_suffixes"`
	PropagationWaitSeconds int       `json:"propagation_wait_seconds"`
	PollTimeoutSeconds     int       `json:"poll_timeout_seconds"`
	CreatedAt              time.Time `json:"created_at"`
	UpdatedAt              time.Time `json:"updated_at"`
}

func acmeHookJSON(h inventory.ACMEHook) acmeHookDTO {
	return acmeHookDTO{ID: h.ID.String(), Name: h.Name, URL: h.URL, CABundlePEM: h.CABundlePEM, SecretConfigured: h.SecretConfigured,
		AllowedSuffixes: nonNil(h.AllowedSuffixes), PropagationWaitSeconds: h.PropagationWaitSeconds, PollTimeoutSeconds: h.PollTimeoutSeconds,
		CreatedAt: h.CreatedAt.UTC(), UpdatedAt: h.UpdatedAt.UTC()}
}

type acmeCurrentDTO struct {
	ID            string    `json:"id"`
	Fingerprint   string    `json:"fingerprint_sha256"`
	NotBefore     time.Time `json:"not_before"`
	NotAfter      time.Time `json:"not_after"`
	ChainComplete bool      `json:"chain_complete"`
	// Revocation and key compromise of the current certificate (2026-10-20).
	RevokedAt        *time.Time `json:"revoked_at"`
	RevocationReason string     `json:"revocation_reason"`
	Compromised      bool       `json:"compromised"`
}

type acmeWindowDTO struct {
	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
}

// acmeStoppedRenewalFailures is the stopped_reason of a certificate whose automatic renewal stopped after repeated
// failures (state stopped, Task 11); a successful order (also one of the recovery after an outage, recovering) or an
// Administrator's Check again and resume (re-arm) starts it again.
const acmeStoppedRenewalFailures = "renewal_failures"

type acmeCertificateDTO struct {
	ID              string   `json:"id"`
	ProviderID      string   `json:"provider_id"`
	AccountID       string   `json:"account_id"`
	Names           []string `json:"names"`
	KeyType         string   `json:"key_type"`
	Challenge       string   `json:"challenge"`
	HookID          *string  `json:"hook_id"`
	HTTPTargetID    *string  `json:"http_target_id"`
	RenewBeforeDays int      `json:"renew_before_days"`
	AutoRenew       bool     `json:"auto_renew"`
	AutoDeploy      bool     `json:"auto_deploy"`
	State           string   `json:"state"`
	StoppedReason   string   `json:"stopped_reason"`
	Failures        int      `json:"failures"`
	// LastFailureClass is transient or permanent ('' without a failure); PermanentFailures counts the permanent ones;
	// Recovering: stopped after an outage and still ordered again by itself (until the certificate expires).
	LastFailureClass  string `json:"last_failure_class"`
	PermanentFailures int    `json:"permanent_failures"`
	Recovering        bool   `json:"recovering"`
	// NextAttemptAt is the later of Alice's own backoff and the CA's wait; CANotBefore the CA's wait while it runs (R47),
	// CAWaitCritical when it leaves less than half of the renewal window.
	NextAttemptAt    *time.Time        `json:"next_attempt_at"`
	CANotBefore      *time.Time        `json:"ca_not_before"`
	CAWaitCritical   bool              `json:"ca_wait_critical"`
	LastAttemptAt    *time.Time        `json:"last_attempt_at"`
	LastError        *errorRefDTO      `json:"last_error"`
	RunningOrderID   *string           `json:"running_order_id"`
	Current          *acmeCurrentDTO   `json:"current"`
	ARIWindow        *acmeWindowDTO    `json:"ari_window"`
	DeployHeldReason string            `json:"deploy_held_reason"`
	DeployStopped    bool              `json:"deploy_stopped"`
	BindingsCount    int               `json:"bindings_count"`
	Bindings         *[]acmeBindingDTO `json:"bindings,omitempty"` // the certificate's own page only
	// RenewAt is when the planner renews the current certificate: the time chosen at random in the CA's window
	// (RenewAtSource ca_window, R50) or the local rule (local); null and '' before the first certificate.
	RenewAt       *time.Time `json:"renew_at"`
	RenewAtSource string     `json:"renew_at_source"`
	// LastNotice is how the newest renewal e-mail of the certificate was delivered (the certificate's own page only;
	// absent when none was queued).
	LastNotice *acmeNoticeDTO `json:"last_notice,omitempty"`
	CreatedAt  time.Time      `json:"created_at"`
	UpdatedAt  time.Time      `json:"updated_at"`
	// Service is the owning service (R49, design §8.2).
	Service *serviceRefDTO `json:"service,omitempty"`
	// AllowedActions are the permissions the caller holds on the row's owning service (R49 Phase 2, design §8.2).
	AllowedActions []string `json:"allowed_actions,omitempty"`
}

// acmeHoldReasons are the values of deploy_held_reason; anything else is shown as no hold (the openapi enum).
var acmeHoldReasons = []string{"", inventory.ACMEHoldLicense, inventory.ACMEHoldChainIncomplete}

// acmeCertificateJSON is the view of c at now (recovering ends when the current certificate expires).
func acmeCertificateJSON(c inventory.ACMECertificate, now time.Time, refs serviceRefs) acmeCertificateDTO {
	d := acmeCertificateDTO{ID: c.ID.String(), ProviderID: c.ProviderID.String(), AccountID: c.AccountID.String(), Names: nonNil(c.Names),
		KeyType: c.KeyType, Challenge: c.Challenge, HookID: idPtr(c.HookID), HTTPTargetID: idPtr(c.HTTPTargetID), RenewBeforeDays: c.RenewBeforeDays,
		AutoRenew: c.AutoRenew, AutoDeploy: c.AutoDeploy, State: c.State, Failures: c.Failures, NextAttemptAt: utcPtr(c.NextAttemptAt),
		LastAttemptAt: utcPtr(c.LastAttemptAt), LastError: errorRef(c.LastErrorCode, nil), RunningOrderID: idPtr(c.RunningOrderID),
		DeployHeldReason: c.DeployHeldReason, DeployStopped: c.DeployStopped, BindingsCount: c.Bindings, CreatedAt: c.CreatedAt.UTC(),
		UpdatedAt: c.UpdatedAt.UTC(), Service: refs.of(c.ServiceID), AllowedActions: refs.actions(c.ServiceID)}
	if c.State == inventory.ACMEStateStopped {
		d.StoppedReason = acmeStoppedRenewalFailures
	}
	if slices.Contains(acmeFailureClasses, c.LastFailureClass) {
		d.LastFailureClass, d.PermanentFailures = c.LastFailureClass, c.PermanentFailures
	}
	d.Recovering = c.State == inventory.ACMEStateStopped && c.AutoRenew && c.LastFailureClass == renew.ClassTransient && c.Current != nil &&
		now.Before(c.Current.NotAfter)
	if c.CANotBefore != nil && now.Before(*c.CANotBefore) {
		d.CANotBefore = utcPtr(c.CANotBefore)
		if d.NextAttemptAt == nil || d.NextAttemptAt.Before(*d.CANotBefore) {
			d.NextAttemptAt = d.CANotBefore
		}
		d.CAWaitCritical = c.Current != nil && renew.CAWaitCritical(c.Current.NotBefore, c.Current.NotAfter, c.RenewBeforeDays, *c.CANotBefore)
	}
	if c.Current != nil {
		d.Current = &acmeCurrentDTO{ID: c.Current.ID.String(), Fingerprint: c.Current.Fingerprint, NotBefore: c.Current.NotBefore.UTC(),
			NotAfter: c.Current.NotAfter.UTC(), ChainComplete: c.Current.ChainComplete, RevokedAt: utcPtr(c.Current.RevokedAt),
			RevocationReason: c.Current.RevocationReason, Compromised: c.Current.Compromised}
	}
	var window *renew.Window
	if c.ARIWindowStart != nil && c.ARIWindowEnd != nil {
		d.ARIWindow = &acmeWindowDTO{Start: c.ARIWindowStart.UTC(), End: c.ARIWindowEnd.UTC()}
		window = &renew.Window{Start: *c.ARIWindowStart, End: *c.ARIWindowEnd}
	}
	if c.Current != nil {
		at, fromCA := renew.RenewalTime(c.ARIRenewAt, window, c.Current.NotBefore, c.Current.NotAfter, c.RenewBeforeDays)
		at = at.UTC()
		d.RenewAt, d.RenewAtSource = &at, acmeRenewLocal
		if fromCA {
			d.RenewAtSource = acmeRenewCAWindow
		}
	}
	if !slices.Contains(acmeHoldReasons, d.DeployHeldReason) {
		d.DeployHeldReason = ""
	}
	return d
}

// The values of renew_at_source: the time chosen in the CA's suggested window (ARI, R50) or the local rule.
const (
	acmeRenewCAWindow = "ca_window"
	acmeRenewLocal    = "local"
)

// acmeFailureClasses are the values of last_failure_class; anything else is shown as none (the openapi enum).
var acmeFailureClasses = []string{"", renew.ClassTransient, renew.ClassPermanent}

// acmeNoticeDTO is the delivery of the newest renewal e-mail of a certificate: one copy per recipient, counted by
// outcome; last_failure_code is the mail error of a copy that was not sent (smtp.*, as on the notifications banner).
type acmeNoticeDTO struct {
	Template        string     `json:"template"`
	QueuedAt        time.Time  `json:"queued_at"`
	Recipients      int        `json:"recipients"`
	Sent            int        `json:"sent"`
	Pending         int        `json:"pending"`
	Failed          int        `json:"failed"`
	Skipped         int        `json:"skipped"`
	SentAt          *time.Time `json:"sent_at"`
	LastFailureCode string     `json:"last_failure_code"`
}

func acmeNoticeJSON(n *inventory.ACMENoticeDelivery) *acmeNoticeDTO {
	if n == nil {
		return nil
	}
	return &acmeNoticeDTO{Template: n.Template, QueuedAt: n.QueuedAt.UTC(), Recipients: n.Recipients, Sent: n.Sent, Pending: n.Pending,
		Failed: n.Failed, Skipped: n.Skipped, SentAt: utcPtr(n.SentAt), LastFailureCode: n.LastErrorCode}
}

type acmeBindingDTO struct {
	ACMECertificateID   string       `json:"acme_certificate_id"`
	LocationID          string       `json:"location_id"`
	TargetID            string       `json:"target_id"`
	TargetName          string       `json:"target_name"`
	CertPath            string       `json:"cert_path"`
	AutoDeploy          bool         `json:"auto_deploy"`
	State               string       `json:"state"`
	AttentionAt         *time.Time   `json:"attention_at"`
	Attention           *errorRefDTO `json:"attention"`
	ServedCertificateID *string      `json:"served_certificate_id"`
	CreatedAt           time.Time    `json:"created_at"`
	// Observation (R52): the location's observation model and health.
	Observation *locationObservationDTO `json:"observation"`
}

// acmeBindingStates are the values of a binding's state; anything else is shown as pending (the openapi enum). Since
// R52 current means "got the current certificate and no newer observation disagrees"; drifted is new.
var acmeBindingStates = []string{inventory.ACMEBindingCurrent, inventory.ACMEBindingPending, inventory.ACMEBindingAttention,
	inventory.ACMEBindingDrifted}

func acmeBindingJSON(b inventory.ACMEBinding) acmeBindingDTO {
	d := acmeBindingDTO{ACMECertificateID: b.ACMECertificateID.String(), LocationID: b.LocationID.String(), TargetID: b.TargetID.String(),
		TargetName: b.TargetName, CertPath: b.CertPath, AutoDeploy: b.AutoDeploy, State: b.State, AttentionAt: utcPtr(b.AttentionAt),
		Attention: errorRef(b.AttentionCode, nil), ServedCertificateID: idPtr(b.ServedCertificateID), CreatedAt: b.CreatedAt.UTC(),
		Observation: observationJSON(b.Observation)}
	if !slices.Contains(acmeBindingStates, d.State) {
		d.State = inventory.ACMEBindingPending
	}
	return d
}

type acmeOrderDTO struct {
	ID                string       `json:"id"`
	ACMECertificateID string       `json:"acme_certificate_id"`
	Kind              string       `json:"kind"`
	State             string       `json:"state"`
	Trigger           string       `json:"trigger"`
	StartedAt         time.Time    `json:"started_at"`
	FinishedAt        *time.Time   `json:"finished_at"`
	Error             *errorRefDTO `json:"error"`
	CertificateID     *string      `json:"certificate_id"`
	RequestedBy       *string      `json:"requested_by"`
	Presented         int          `json:"presented"`
	CleanupAt         *time.Time   `json:"cleanup_at"`
	CleanupError      *errorRefDTO `json:"cleanup_error"`
	// The issued certificate's revocation and compromise marks (2026-10-20).
	RevokedAt        *time.Time `json:"revoked_at"`
	RevocationReason string     `json:"revocation_reason"`
	Compromised      bool       `json:"compromised"`
	// Replaces is the RFC 9773 identifier of the certificate an issue order renews ('' for a first order or a test run);
	// ReplacesOutcome what became of it (inventory.ACMEReplacesOutcomes; R50).
	Replaces        string `json:"replaces"`
	ReplacesOutcome string `json:"replaces_outcome"`
}

func acmeOrderJSON(o inventory.ACMEOrder) acmeOrderDTO {
	d := acmeOrderDTO{ID: o.ID.String(), ACMECertificateID: o.ACMECertificateID.String(), Kind: o.Kind, State: o.State, Trigger: o.Trigger,
		StartedAt: o.StartedAt.UTC(), FinishedAt: utcPtr(o.FinishedAt), Error: errorRef(o.ErrorCode, nil), CertificateID: idPtr(o.CertificateID),
		RequestedBy: idPtr(o.RequestedBy), Presented: o.Presented, CleanupAt: utcPtr(o.CleanupAt), CleanupError: errorRef(o.CleanupErrorCode, nil),
		RevokedAt: utcPtr(o.RevokedAt), RevocationReason: o.RevocationReason, Compromised: o.Compromised, Replaces: o.Replaces}
	if slices.Contains(inventory.ACMEReplacesOutcomes(), o.ReplacesOutcome) {
		d.ReplacesOutcome = o.ReplacesOutcome
	}
	return d
}
