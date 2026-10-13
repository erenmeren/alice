package api

import (
	"slices"
	"time"

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
}

type acmeWindowDTO struct {
	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
}

// acmeStoppedRenewalFailures is the stopped_reason of a certificate whose automatic renewal stopped after repeated
// failures (state stopped, Task 11); only a successful order or an Administrator's re-arm starts it again.
const acmeStoppedRenewalFailures = "renewal_failures"

type acmeCertificateDTO struct {
	ID               string            `json:"id"`
	ProviderID       string            `json:"provider_id"`
	AccountID        string            `json:"account_id"`
	Names            []string          `json:"names"`
	KeyType          string            `json:"key_type"`
	Challenge        string            `json:"challenge"`
	HookID           *string           `json:"hook_id"`
	HTTPTargetID     *string           `json:"http_target_id"`
	RenewBeforeDays  int               `json:"renew_before_days"`
	AutoRenew        bool              `json:"auto_renew"`
	AutoDeploy       bool              `json:"auto_deploy"`
	State            string            `json:"state"`
	StoppedReason    string            `json:"stopped_reason"`
	Failures         int               `json:"failures"`
	NextAttemptAt    *time.Time        `json:"next_attempt_at"`
	LastAttemptAt    *time.Time        `json:"last_attempt_at"`
	LastError        *errorRefDTO      `json:"last_error"`
	RunningOrderID   *string           `json:"running_order_id"`
	Current          *acmeCurrentDTO   `json:"current"`
	ARIWindow        *acmeWindowDTO    `json:"ari_window"`
	DeployHeldReason string            `json:"deploy_held_reason"`
	DeployStopped    bool              `json:"deploy_stopped"`
	BindingsCount    int               `json:"bindings_count"`
	Bindings         *[]acmeBindingDTO `json:"bindings,omitempty"` // the certificate's own page only
	CreatedAt        time.Time         `json:"created_at"`
	UpdatedAt        time.Time         `json:"updated_at"`
}

// acmeHoldReasons are the values of deploy_held_reason; anything else is shown as no hold (the openapi enum).
var acmeHoldReasons = []string{"", inventory.ACMEHoldLicense, inventory.ACMEHoldChainIncomplete}

func acmeCertificateJSON(c inventory.ACMECertificate) acmeCertificateDTO {
	d := acmeCertificateDTO{ID: c.ID.String(), ProviderID: c.ProviderID.String(), AccountID: c.AccountID.String(), Names: nonNil(c.Names),
		KeyType: c.KeyType, Challenge: c.Challenge, HookID: idPtr(c.HookID), HTTPTargetID: idPtr(c.HTTPTargetID), RenewBeforeDays: c.RenewBeforeDays,
		AutoRenew: c.AutoRenew, AutoDeploy: c.AutoDeploy, State: c.State, Failures: c.Failures, NextAttemptAt: utcPtr(c.NextAttemptAt),
		LastAttemptAt: utcPtr(c.LastAttemptAt), LastError: errorRef(c.LastErrorCode, nil), RunningOrderID: idPtr(c.RunningOrderID),
		DeployHeldReason: c.DeployHeldReason, DeployStopped: c.DeployStopped, BindingsCount: c.Bindings, CreatedAt: c.CreatedAt.UTC(),
		UpdatedAt: c.UpdatedAt.UTC()}
	if c.State == inventory.ACMEStateStopped {
		d.StoppedReason = acmeStoppedRenewalFailures
	}
	if c.Current != nil {
		d.Current = &acmeCurrentDTO{ID: c.Current.ID.String(), Fingerprint: c.Current.Fingerprint, NotBefore: c.Current.NotBefore.UTC(),
			NotAfter: c.Current.NotAfter.UTC(), ChainComplete: c.Current.ChainComplete}
	}
	if c.ARIWindowStart != nil && c.ARIWindowEnd != nil {
		d.ARIWindow = &acmeWindowDTO{Start: c.ARIWindowStart.UTC(), End: c.ARIWindowEnd.UTC()}
	}
	if !slices.Contains(acmeHoldReasons, d.DeployHeldReason) {
		d.DeployHeldReason = ""
	}
	return d
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
}

// acmeBindingStates are the values of a binding's state; anything else is shown as pending (the openapi enum).
var acmeBindingStates = []string{inventory.ACMEBindingCurrent, inventory.ACMEBindingPending, inventory.ACMEBindingAttention}

func acmeBindingJSON(b inventory.ACMEBinding) acmeBindingDTO {
	d := acmeBindingDTO{ACMECertificateID: b.ACMECertificateID.String(), LocationID: b.LocationID.String(), TargetID: b.TargetID.String(),
		TargetName: b.TargetName, CertPath: b.CertPath, AutoDeploy: b.AutoDeploy, State: b.State, AttentionAt: utcPtr(b.AttentionAt),
		Attention: errorRef(b.AttentionCode, nil), ServedCertificateID: idPtr(b.ServedCertificateID), CreatedAt: b.CreatedAt.UTC()}
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
}

func acmeOrderJSON(o inventory.ACMEOrder) acmeOrderDTO {
	return acmeOrderDTO{ID: o.ID.String(), ACMECertificateID: o.ACMECertificateID.String(), Kind: o.Kind, State: o.State, Trigger: o.Trigger,
		StartedAt: o.StartedAt.UTC(), FinishedAt: utcPtr(o.FinishedAt), Error: errorRef(o.ErrorCode, nil), CertificateID: idPtr(o.CertificateID),
		RequestedBy: idPtr(o.RequestedBy), Presented: o.Presented, CleanupAt: utcPtr(o.CleanupAt), CleanupError: errorRef(o.CleanupErrorCode, nil)}
}
