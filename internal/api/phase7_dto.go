package api

import (
	"time"

	"github.com/google/uuid"

	"alice/internal/alerts"
	"alice/internal/alerts/expiry"
	"alice/internal/notify"
	"alice/internal/platform/settings"
	"alice/internal/reports"
)

// The Phase 7 answers (C13). Times are UTC RFC 3339, lists are never null, the sections a role may not see are null.
// web/src/api/phase7.ts compiles against these names.

type certificateCountsDTO struct {
	Monitored  int `json:"monitored"`
	Expired    int `json:"expired"`
	Within7    int `json:"within_7"`
	Within30   int `json:"within_30"`
	Within60   int `json:"within_60"`
	KVExpired  int `json:"kv_expired"`
	KVWithin30 int `json:"kv_within_30"`
}

type failedDeploymentDTO struct {
	ID              uuid.UUID `json:"id"`
	CertificateName string    `json:"certificate_name"`
	TargetID        uuid.UUID `json:"target_id"`
	TargetName      string    `json:"target_name"`
	Status          string    `json:"status"`
	ErrorCode       string    `json:"error_code"`
	At              time.Time `json:"at"`
}

type deploymentsDTO struct {
	Failed7d int                   `json:"failed_7d"`
	Recent   []failedDeploymentDTO `json:"recent"`
}

type targetsSummaryDTO struct {
	Total    int            `json:"total"`
	ByStatus map[string]int `json:"by_status"`
}

type licenseSummaryDTO struct {
	Expired  bool       `json:"expired"`
	Phase    string     `json:"phase"`
	EndsAt   *time.Time `json:"ends_at"`
	DaysLeft *int       `json:"days_left"`
}

type upcomingRotationDTO struct {
	PolicyID  uuid.UUID `json:"policy_id"`
	SSHKeyID  uuid.UUID `json:"ssh_key_id"`
	KeyLabel  string    `json:"key_label"`
	NextRunAt time.Time `json:"next_run_at"`
}

type dashboardRotationDTO struct {
	Upcoming       []upcomingRotationDTO `json:"upcoming"`
	Running        int                   `json:"running"`
	NeedsAttention int                   `json:"needs_attention"`
}

type auditHeadDTO struct {
	HeadSeq   int64     `json:"head_seq"`
	HeadHash  string    `json:"head_hash"`
	CheckedAt time.Time `json:"checked_at"`
	Intact    bool      `json:"intact"`
}

// deliveryDTO is the state behind the "E-mails could not be sent" banner. failed_24h counts sends that gave up
// recently (queued within the last 48 hours); it is not an exact 24-hour figure (Task 7).
type deliveryDTO struct {
	Failing             bool       `json:"failing"`
	ConsecutiveFailures int        `json:"consecutive_failures"`
	LastFailureAt       *time.Time `json:"last_failure_at"`
	LastFailureCode     string     `json:"last_failure_code"`
	LastSuccessAt       *time.Time `json:"last_success_at"`
	Pending             int        `json:"pending"`
	Failed24h           int        `json:"failed_24h"`
}

type dashboardSummaryDTO struct {
	GeneratedAt   time.Time            `json:"generated_at"`
	Certificates  certificateCountsDTO `json:"certificates"`
	Deployments   deploymentsDTO       `json:"deployments"`
	Targets       targetsSummaryDTO    `json:"targets"`
	License       licenseSummaryDTO    `json:"license"`
	Rotation      dashboardRotationDTO `json:"rotation"`
	Notifications *deliveryDTO         `json:"notifications"`
	Audit         *auditHeadDTO        `json:"audit"`
	Attention     int                  `json:"attention"`
}

func summaryJSON(s reports.Summary) dashboardSummaryDTO {
	c := s.Certificates
	out := dashboardSummaryDTO{
		GeneratedAt: s.GeneratedAt.UTC(),
		Certificates: certificateCountsDTO{Monitored: c.Monitored, Expired: c.Expired, Within7: c.Within7, Within30: c.Within30,
			Within60: c.Within60, KVExpired: c.KVExpired, KVWithin30: c.KVWithin30},
		Deployments: deploymentsDTO{Failed7d: s.Deployments.Failed7d, Recent: make([]failedDeploymentDTO, 0, len(s.Deployments.Recent))},
		Targets:     targetsSummaryDTO{Total: s.Targets.Total, ByStatus: map[string]int{}},
		License:     licenseSummaryDTO{Expired: s.License.Expired, Phase: s.License.Phase, EndsAt: utcPtr(s.License.EndsAt), DaysLeft: s.License.DaysLeft},
		Rotation: dashboardRotationDTO{Upcoming: make([]upcomingRotationDTO, 0, len(s.Rotation.Upcoming)), Running: s.Rotation.Running,
			NeedsAttention: s.Rotation.NeedsAttention},
		Attention: s.Attention,
	}
	for _, d := range s.Deployments.Recent {
		out.Deployments.Recent = append(out.Deployments.Recent, failedDeploymentDTO{ID: d.ID, CertificateName: d.CertificateName,
			TargetID: d.TargetID, TargetName: d.TargetName, Status: d.Status, ErrorCode: d.ErrorCode, At: d.At.UTC()})
	}
	for k, n := range s.Targets.ByStatus {
		out.Targets.ByStatus[k] = n
	}
	for _, u := range s.Rotation.Upcoming {
		out.Rotation.Upcoming = append(out.Rotation.Upcoming, upcomingRotationDTO{PolicyID: u.PolicyID, SSHKeyID: u.SSHKeyID,
			KeyLabel: u.KeyLabel, NextRunAt: u.NextRunAt.UTC()})
	}
	if s.Notifications != nil {
		d := deliveryJSON(*s.Notifications)
		out.Notifications = &d
	}
	if s.Audit != nil {
		out.Audit = &auditHeadDTO{HeadSeq: s.Audit.HeadSeq, HeadHash: s.Audit.HeadHash, CheckedAt: s.Audit.CheckedAt.UTC(), Intact: s.Audit.Intact}
	}
	return out
}

func deliveryJSON(d notify.Delivery) deliveryDTO {
	return deliveryDTO{Failing: d.Failing(), ConsecutiveFailures: d.ConsecutiveFailures, LastFailureAt: utcPtr(d.LastFailureAt),
		LastFailureCode: d.LastFailureCode, LastSuccessAt: utcPtr(d.LastSuccessAt), Pending: d.Pending, Failed24h: d.Failed24h}
}

// expiringItemDTO is one monitored thing that expires; vault_id is null for certificates.
type expiringItemDTO struct {
	Kind        string      `json:"kind"`
	ObjectID    uuid.UUID   `json:"object_id"`
	Name        string      `json:"name"`
	ExpiresAt   time.Time   `json:"expires_at"`
	DaysLeft    int         `json:"days_left"`
	Expired     bool        `json:"expired"`
	Fingerprint string      `json:"fingerprint"`
	Websites    []string    `json:"websites"`
	Servers     []string    `json:"servers"`
	TargetIDs   []uuid.UUID `json:"target_ids"`
	Vault       string      `json:"vault"`
	VaultID     *uuid.UUID  `json:"vault_id"`
}

// expiringItemJSON derives days_left (whole days, 0 once expired; expiry.DaysLeft) and expired (expires_at <= now, as
// the list's expired filter) at now.
func expiringItemJSON(it alerts.Item, now time.Time) expiringItemDTO {
	out := expiringItemDTO{Kind: string(it.Kind), ObjectID: it.ObjectID, Name: it.Name, ExpiresAt: it.ExpiresAt.UTC(),
		DaysLeft: expiry.DaysLeft(it.ExpiresAt, now), Expired: !it.ExpiresAt.After(now), Fingerprint: it.Fingerprint,
		Websites: nonNil(it.Websites), Servers: nonNil(it.Servers), TargetIDs: nonNil(it.TargetIDs), Vault: it.Vault}
	if it.VaultID != uuid.Nil {
		id := it.VaultID
		out.VaultID = &id
	}
	return out
}

type conditionDTO struct {
	Kind      string    `json:"kind"`
	ObjectID  string    `json:"object_id"`
	Name      string    `json:"name"`
	Since     time.Time `json:"since"`
	ErrorCode string    `json:"error_code"`
}

func conditionJSON(c reports.Condition) conditionDTO {
	return conditionDTO{Kind: c.Kind, ObjectID: c.ObjectID, Name: c.Name, Since: c.Since.UTC(), ErrorCode: c.ErrorCode}
}

type viewDTO struct {
	ID        uuid.UUID         `json:"id"`
	Page      string            `json:"page"`
	Name      string            `json:"name"`
	Query     map[string]string `json:"query"`
	CreatedAt time.Time         `json:"created_at"`
}

func viewJSON(v reports.View) viewDTO {
	q := v.Query
	if q == nil {
		q = map[string]string{}
	}
	return viewDTO{ID: v.ID, Page: v.Page, Name: v.Name, Query: q, CreatedAt: v.CreatedAt.UTC()}
}

type trustedCertificateDTO struct {
	Fingerprint string    `json:"fingerprint"`
	Subject     string    `json:"subject"`
	NotAfter    time.Time `json:"not_after"`
	TrustedBy   string    `json:"trusted_by"`
	TrustedAt   time.Time `json:"trusted_at"`
}

// smtpDTO is the mail settings. There is no password field: has_password says whether one is stored (S-08).
type smtpDTO struct {
	Configured  bool                   `json:"configured"`
	Host        string                 `json:"host"`
	Port        int                    `json:"port"`
	TLSMode     string                 `json:"tls_mode"`
	From        string                 `json:"from"`
	Username    string                 `json:"username"`
	HasPassword bool                   `json:"has_password"`
	CAPEM       string                 `json:"ca_pem"`
	Trusted     *trustedCertificateDTO `json:"trusted_certificate"`
	Version     int                    `json:"version"`
	UpdatedAt   *time.Time             `json:"updated_at"`
}

func smtpJSON(st notify.SMTPSettings, configured bool) smtpDTO {
	out := smtpDTO{Configured: configured, Host: st.Host, Port: st.Port, TLSMode: st.TLSMode, From: st.From, Username: st.Username,
		HasPassword: st.HasPassword, CAPEM: st.CAPEM, Version: st.Version}
	if !st.UpdatedAt.IsZero() {
		at := st.UpdatedAt.UTC()
		out.UpdatedAt = &at
	}
	if t := st.Trusted; t != nil {
		out.Trusted = &trustedCertificateDTO{Fingerprint: t.Fingerprint, Subject: t.Subject, NotAfter: t.NotAfter.UTC(), TrustedBy: t.TrustedBy,
			TrustedAt: t.TrustedAt.UTC()}
	}
	return out
}

type addressDTO struct {
	Email  string `json:"email"`
	Locale string `json:"locale"`
}

type recipientsDTO struct {
	Administrators bool         `json:"administrators"`
	Addresses      []addressDTO `json:"addresses"`
	Version        int          `json:"version"`
}

func recipientsJSON(r notify.Recipients) recipientsDTO {
	out := recipientsDTO{Administrators: r.Administrators, Addresses: make([]addressDTO, 0, len(r.Addresses)), Version: r.Version}
	for _, a := range r.Addresses {
		out.Addresses = append(out.Addresses, addressDTO(a))
	}
	return out
}

type thresholdsDTO struct {
	Days    []int `json:"thresholds_days"`
	Version int   `json:"version"`
}

func thresholdsJSON(t alerts.ThresholdSettings) thresholdsDTO {
	return thresholdsDTO{Days: nonNil(t.Days), Version: t.Version}
}

type generalDTO struct {
	PublicURL               string `json:"public_url"`
	RetiredKeyRetentionDays int    `json:"retired_key_retention_days"`
	Version                 int    `json:"version"`
}

func generalJSON(g settings.General) generalDTO {
	return generalDTO{PublicURL: g.PublicURL, RetiredKeyRetentionDays: g.RetiredKeyRetentionDays, Version: g.Version}
}
