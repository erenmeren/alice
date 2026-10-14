package api

import (
	"net/netip"
	"time"

	"github.com/google/uuid"

	"alice/internal/alerts/expiry"
	"alice/internal/discovery"
	"alice/internal/discovery/discoverysvc"
	"alice/internal/platform/netaddr"
)

// The network discovery views (plan 2026-10-13-network-discovery, Task 9). Discovery stores public certificates only:
// nothing here is a secret. An address appears only as a scope's own entry, an Administrator's setting or an endpoint's
// own address; an error never names one.

type discoveryScopeDTO struct {
	ID              string            `json:"id"`
	Name            string            `json:"name"`
	Entries         []string          `json:"entries"`
	Ports           []int             `json:"ports"`
	SNINames        []string          `json:"sni_names"`
	Exclusions      []string          `json:"exclusions"`
	Enabled         bool              `json:"enabled"`
	ScheduleHours   int               `json:"schedule_hours"`
	WindowStart     string            `json:"window_start"`
	WindowEnd       string            `json:"window_end"`
	WindowTZ        string            `json:"window_tz"`
	AlertOnExpiry   bool              `json:"alert_on_expiry"`
	RatePerSec      int               `json:"rate_per_sec"`
	Concurrency     int               `json:"concurrency"`
	Version         int               `json:"version"`
	CreatedBy       *string           `json:"created_by"`
	CreatedAt       time.Time         `json:"created_at"`
	UpdatedAt       time.Time         `json:"updated_at"`
	LastScheduledAt *time.Time        `json:"last_scheduled_at"`
	ActiveScanID    *string           `json:"active_scan_id"`
	LastScan        *discoveryScanDTO `json:"last_scan"`
}

func nullID(id uuid.NullUUID) *string {
	if !id.Valid {
		return nil
	}
	s := id.UUID.String()
	return &s
}

func discoveryScopeJSON(v discoverysvc.ScopeView) discoveryScopeDTO {
	sc := v.Scope
	d := discoveryScopeDTO{ID: v.ID.String(), Name: sc.Name, Entries: nonNil(sc.Entries), Ports: nonNil(sc.Ports), SNINames: nonNil(sc.SNINames),
		Exclusions: nonNil(sc.Exclusions), Enabled: sc.Enabled, ScheduleHours: sc.Schedule.Hours, WindowStart: sc.Schedule.WindowStart,
		WindowEnd: sc.Schedule.WindowEnd, WindowTZ: sc.Schedule.TimeZone, AlertOnExpiry: sc.AlertOnExpiry, RatePerSec: sc.RatePerSec,
		Concurrency: sc.Concurrency, Version: v.Version, CreatedBy: nullID(v.CreatedBy), CreatedAt: v.CreatedAt.UTC(), UpdatedAt: v.UpdatedAt.UTC(),
		LastScheduledAt: utcPtr(v.LastScheduledAt), ActiveScanID: nullID(v.ActiveScanID)}
	if v.LastScan != nil {
		s := discoveryScanJSON(*v.LastScan)
		d.LastScan = &s
	}
	return d
}

// discoveryScanDTO is a scan. error_code is the ALC code of the reason it ended without finishing (null when it did not),
// error_reason that reason (discovery.* or license.*).
type discoveryScanDTO struct {
	ID                string     `json:"id"`
	ScopeID           string     `json:"scope_id"`
	ScopeName         string     `json:"scope_name"`
	Trigger           string     `json:"trigger"`
	State             string     `json:"state"`
	CancelRequested   bool       `json:"cancel_requested"`
	EndpointsTotal    int        `json:"endpoints_total"`
	EndpointsAnswered int        `json:"endpoints_answered"`
	EndpointsFailed   int        `json:"endpoints_failed"`
	EndpointsExcluded int        `json:"endpoints_excluded"`
	CertificatesNew   int        `json:"certificates_new"`
	CertChurn         int        `json:"cert_churn"`
	RequestedBy       *string    `json:"requested_by"`
	QueuedAt          time.Time  `json:"queued_at"`
	StartedAt         *time.Time `json:"started_at"`
	FinishedAt        *time.Time `json:"finished_at"`
	ErrorCode         *string    `json:"error_code"`
	ErrorReason       *string    `json:"error_reason"`
}

func discoveryScanJSON(v discoverysvc.ScanView) discoveryScanDTO {
	d := discoveryScanDTO{ID: v.ID.String(), ScopeID: v.ScopeID.String(), ScopeName: v.ScopeName, Trigger: v.Trigger, State: v.State,
		CancelRequested: v.CancelRequested, EndpointsTotal: v.EndpointsTotal, EndpointsAnswered: v.EndpointsAnswered, EndpointsFailed: v.EndpointsFailed,
		EndpointsExcluded: v.EndpointsExcluded, CertificatesNew: v.CertificatesNew, CertChurn: v.CertChurn, RequestedBy: nullID(v.RequestedBy),
		QueuedAt: v.QueuedAt.UTC(), StartedAt: utcPtr(v.StartedAt), FinishedAt: utcPtr(v.FinishedAt)}
	if v.ErrorCode != "" {
		code, reason := codeForReason(v.ErrorCode).Code, v.ErrorCode
		d.ErrorCode, d.ErrorReason = &code, &reason
	}
	return d
}

// discoveryCertificateDTO is a discovered leaf. status: unmanaged (Alice has no record of this exact certificate),
// managed (Alice has it on a live location of a live server), known (Alice has it, on no live location).
type discoveryCertificateDTO struct {
	Fingerprint          string                  `json:"fingerprint_sha256"`
	SubjectCN            string                  `json:"subject_cn"`
	SANs                 []string                `json:"sans"`
	IssuerCN             string                  `json:"issuer_cn"`
	NotBefore            time.Time               `json:"not_before"`
	NotAfter             time.Time               `json:"not_after"`
	DaysLeft             int                     `json:"days_left"`
	Expired              bool                    `json:"expired"`
	KeyAlgorithm         string                  `json:"key_algorithm"`
	SelfSigned           bool                    `json:"self_signed"`
	Status               string                  `json:"status"`
	ManagedCertificateID *string                 `json:"managed_certificate_id"`
	EndpointCount        int                     `json:"endpoint_count"`
	SeenOnCount          int                     `json:"seen_on_count"`
	FirstSeen            time.Time               `json:"first_seen"`
	LastSeen             time.Time               `json:"last_seen"`
	Endpoints            *[]discoveryEndpointDTO `json:"endpoints,omitempty"` // the detail only
	MoreEndpoints        *bool                   `json:"more_endpoints,omitempty"`
}

func discoveryCertificateJSON(c discovery.CertificateRow, now time.Time) discoveryCertificateDTO {
	return discoveryCertificateDTO{Fingerprint: c.Fingerprint, SubjectCN: c.SubjectCN, SANs: nonNil(c.SANs), IssuerCN: c.IssuerCN,
		NotBefore: c.NotBefore.UTC(), NotAfter: c.NotAfter.UTC(), DaysLeft: expiry.DaysLeft(c.NotAfter, now), Expired: c.NotAfter.Before(now),
		KeyAlgorithm: c.KeyAlgorithm, SelfSigned: c.SelfSigned, Status: c.Status, ManagedCertificateID: nullID(c.ManagedID),
		EndpointCount: c.Endpoints, SeenOnCount: c.SeenOn, FirstSeen: c.FirstSeen.UTC(), LastSeen: c.LastSeen.UTC()}
}

type discoveryTargetDTO struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// discoveryEndpointDTO is an endpoint (address, port, SNI name sent, "" for none) with the live server it belongs to
// (target: null when no server has its address or host name). last_error_code is a closed set (refused, timeout,
// no_tls, reset, chain_too_large, policy, malformed); a Go error text is never stored or answered.
type discoveryEndpointDTO struct {
	ID          string  `json:"id"`
	ScopeID     string  `json:"scope_id"`
	Address     string  `json:"address"`
	Port        int     `json:"port"`
	SNI         string  `json:"sni"`
	Host        string  `json:"host"`
	Fingerprint *string `json:"fingerprint_sha256"`
	// PreviousFingerprints are the leaves it presented before, newest first (at most 5): its rotations.
	PreviousFingerprints []string            `json:"previous_fingerprints"`
	ChainLength          int                 `json:"chain_length"`
	TLSVersion           string              `json:"tls_version"`
	Cipher               string              `json:"cipher"`
	State                string              `json:"state"`
	LastErrorCode        string              `json:"last_error_code"`
	MissedScans          int                 `json:"missed_scans"`
	FirstSeen            time.Time           `json:"first_seen"`
	LastSeen             *time.Time          `json:"last_seen"`
	LastScannedAt        time.Time           `json:"last_scanned_at"`
	GoneSince            *time.Time          `json:"gone_since"`
	Target               *discoveryTargetDTO `json:"target"`
}

func discoveryEndpointJSON(e discovery.EndpointRow) discoveryEndpointDTO {
	d := discoveryEndpointDTO{ID: e.ID.String(), ScopeID: e.ScopeID.String(), Address: e.Address.String(), Port: e.Port, SNI: e.SNI, Host: e.Host,
		PreviousFingerprints: nonNil(e.PreviousFingerprints),
		ChainLength:          e.ChainLen, TLSVersion: e.TLSVersion, Cipher: e.Cipher, State: e.State, LastErrorCode: e.LastErrorCode, MissedScans: e.MissedScans,
		FirstSeen: e.FirstSeen.UTC(), LastSeen: utcPtr(e.LastSeen), LastScannedAt: e.LastScannedAt.UTC(), GoneSince: utcPtr(e.GoneSince)}
	if e.Fingerprint != "" {
		fp := e.Fingerprint
		d.Fingerprint = &fp
	}
	if e.TargetID.Valid {
		d.Target = &discoveryTargetDTO{ID: e.TargetID.UUID.String(), Name: e.TargetName}
	}
	return d
}

func prefixStrings(ps []netip.Prefix) []string {
	out := make([]string, 0, len(ps))
	for _, p := range ps {
		out = append(out, p.String())
	}
	return out
}

// discoveryPreviewDTO is the size of a scope as typed (no name resolved, nothing dialed): addresses of the address and
// range entries, those of them the exclusions remove, host names (each counted as one address), ports, SNI names, the
// endpoints of one scan, and the built-in exclusions the ranges overlap (never scanned).
type discoveryPreviewDTO struct {
	Addresses         int      `json:"addresses"`
	ExcludedAddresses int      `json:"excluded_addresses"`
	Hostnames         int      `json:"hostnames"`
	Ports             int      `json:"ports"`
	SNINames          int      `json:"sni_names"`
	Endpoints         int      `json:"endpoints"`
	BuiltinExclusions []string `json:"builtin_exclusions"`
}

func discoveryPreviewJSON(p discovery.Preview) discoveryPreviewDTO {
	return discoveryPreviewDTO{Addresses: p.Addresses, ExcludedAddresses: p.ExcludedAddresses, Hostnames: p.Hostnames, Ports: p.Ports,
		SNINames: p.SNINames, Endpoints: p.Endpoints, BuiltinExclusions: prefixStrings(p.BuiltinExclusions)}
}

// discoverySettingsDTO is the settings; scanning_enabled is false while no allowed scan network is set (nothing may be
// scanned then). builtin_exclusions are the ranges Alice never scans whatever the settings say.
type discoverySettingsDTO struct {
	AllowedNetworks   []string `json:"allowed_networks"`
	GlobalExclusions  []string `json:"global_exclusions"`
	RetentionDays     int      `json:"retention_days"`
	ScanningEnabled   bool     `json:"scanning_enabled"`
	BuiltinExclusions []string `json:"builtin_exclusions"`
}

func discoverySettingsJSON(v discoverysvc.SettingsView) discoverySettingsDTO {
	return discoverySettingsDTO{AllowedNetworks: nonNil(v.AllowedNetworks), GlobalExclusions: nonNil(v.GlobalExclusions), RetentionDays: v.RetentionDays,
		ScanningEnabled: v.ScanningEnabled, BuiltinExclusions: prefixStrings(netaddr.ScanBuiltins())}
}

type discoverySummaryDTO struct {
	UnmanagedTotal       int        `json:"unmanaged_total"`
	UnmanagedExpiring30d int        `json:"unmanaged_expiring_30d"`
	Scopes               int        `json:"scopes"`
	LastScanAt           *time.Time `json:"last_scan_at"`
}

func discoverySummaryJSON(s discoverysvc.Summary) discoverySummaryDTO {
	return discoverySummaryDTO{UnmanagedTotal: s.UnmanagedTotal, UnmanagedExpiring30d: s.UnmanagedExpiring30d, Scopes: s.Scopes,
		LastScanAt: utcPtr(s.LastScanAt)}
}
