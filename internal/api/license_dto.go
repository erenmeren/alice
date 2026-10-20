package api

import (
	"time"

	"alice/internal/license"
)

type bannerDTO struct {
	Kind     string            `json:"kind"`
	Severity string            `json:"severity"`
	Params   map[string]string `json:"params"`
}

type licenseStatusDTO struct {
	Expired bool        `json:"expired"`
	Phase   *string     `json:"phase,omitempty"` // Administrators and Auditors only (L-15)
	Banners []bannerDTO `json:"banners"`
}

func bannersJSON(bs []license.Banner) []bannerDTO {
	out := make([]bannerDTO, 0, len(bs))
	for _, b := range bs {
		out = append(out, bannerDTO{Kind: b.Kind, Severity: string(b.Severity), Params: b.Params})
	}
	return out
}

type licenseInfoDTO struct {
	LicenseID  string    `json:"license_id"`
	Customer   string    `json:"customer"`
	IssuedAt   time.Time `json:"issued_at"`
	ValidFrom  time.Time `json:"valid_from"`
	ValidUntil time.Time `json:"valid_until"`
	MaxTargets int       `json:"max_targets"`
	Features   []string  `json:"features"`
	Replaces   string    `json:"replaces"`
	KeyID      string    `json:"key_id"`
}

func licenseInfoJSON(p *license.Payload, keyID string) *licenseInfoDTO {
	if p == nil {
		return nil
	}
	features := p.Features
	if features == nil {
		features = []string{}
	}
	return &licenseInfoDTO{
		LicenseID: p.LicenseID, Customer: p.Customer, IssuedAt: p.IssuedAt.UTC(), ValidFrom: p.ValidFrom.UTC(),
		ValidUntil: p.ValidUntil.UTC(), MaxTargets: p.MaxTargets, Features: features, Replaces: p.Replaces, KeyID: keyID,
	}
}

type licenseFileDTO struct {
	Status     string          `json:"status"`
	UploadedAt time.Time       `json:"uploaded_at"`
	License    *licenseInfoDTO `json:"license"`
}

type licenseHistoryDTO struct {
	At        time.Time `json:"at"`
	Event     string    `json:"event"`
	LicenseID string    `json:"license_id"`
	FromState string    `json:"from_state"`
	ToState   string    `json:"to_state"`
	Notice    *string   `json:"notice"`
}

type licenseDetailDTO struct {
	InstallationID string          `json:"installation_id"`
	InstalledAt    time.Time       `json:"installed_at"`
	Phase          string          `json:"phase"`
	EffectiveTime  time.Time       `json:"effective_time"`
	Current        *licenseInfoDTO `json:"current"`
	Pending        *licenseInfoDTO `json:"pending"`
	MaxTargets     int             `json:"max_targets"`
	TargetsUsed    int             `json:"targets_used"`
	EndsAt         time.Time       `json:"ends_at"`
	LocksAt        time.Time       `json:"locks_at"`
	DaysLeft       int             `json:"days_left"`
	GraceDay       int             `json:"grace_day"`
	// ContinuityEndsAt is the end of the continuity window of a licensed lock (null for the evaluation: it has
	// none); ContinuityDaysLeft the whole days left in it while locked inside it (owner decision 2026-10-20).
	ContinuityEndsAt   *time.Time          `json:"continuity_ends_at"`
	ContinuityDaysLeft int                 `json:"continuity_days_left"`
	Tampered           bool                `json:"tampered"`
	Files              []licenseFileDTO    `json:"files"`
	History            []licenseHistoryDTO `json:"history"`
}

func licenseDetailJSON(d license.Detail) licenseDetailDTO {
	s := d.Snapshot
	e := s.Eval
	var currentKey, pendingKey string
	for _, f := range d.Files {
		switch {
		case f.Payload != nil && f.Seq == e.CurrentSeq:
			currentKey = f.KeyID
		case f.Payload != nil && f.Seq == e.PendingSeq:
			pendingKey = f.KeyID
		}
	}
	out := licenseDetailDTO{
		InstallationID: s.InstallationID, InstalledAt: s.InstalledAt.UTC(), Phase: string(e.Phase),
		EffectiveTime: s.Reading.Effective.UTC(), Current: licenseInfoJSON(e.Current, currentKey),
		Pending: licenseInfoJSON(e.Pending, pendingKey), MaxTargets: e.MaxTargets, TargetsUsed: s.Targets,
		EndsAt: e.EndsAt.UTC(), LocksAt: e.LocksAt.UTC(), DaysLeft: e.DaysLeft, GraceDay: e.GraceDay, Tampered: s.Tampered,
		Files: make([]licenseFileDTO, 0, len(d.Files)), History: make([]licenseHistoryDTO, 0, len(d.History)),
		ContinuityDaysLeft: e.ContinuityDaysLeft,
	}
	if !e.ContinuityEndsAt.IsZero() {
		at := e.ContinuityEndsAt.UTC()
		out.ContinuityEndsAt = &at
	}
	for _, f := range d.Files {
		out.Files = append(out.Files, licenseFileDTO{Status: f.Status, UploadedAt: f.UploadedAt.UTC(), License: licenseInfoJSON(f.Payload, f.KeyID)})
	}
	for _, h := range d.History {
		var notice *string
		if h.Notice != "" {
			n := h.Notice
			notice = &n
		}
		out.History = append(out.History, licenseHistoryDTO{At: h.At.UTC(), Event: h.Event, LicenseID: h.LicenseID,
			FromState: h.FromState, ToState: h.ToState, Notice: notice})
	}
	return out
}

type uploadResultDTO struct {
	License        licenseInfoDTO `json:"license"`
	Pending        bool           `json:"pending"`
	AlreadyExpired bool           `json:"already_expired"`
	Correction     bool           `json:"correction"`
	Duplicate      bool           `json:"duplicate"`
	Phase          string         `json:"phase"`
}

func uploadResultJSON(r license.UploadResult) uploadResultDTO {
	return uploadResultDTO{License: *licenseInfoJSON(&r.Payload, r.KeyID), Pending: r.Pending, AlreadyExpired: r.AlreadyExpired,
		Correction: r.Correction, Duplicate: r.Duplicate, Phase: string(r.Phase)}
}
