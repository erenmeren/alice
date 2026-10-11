package api

import (
	"time"

	"alice/internal/audit/forward"
	"alice/internal/backup"
	"alice/internal/platform/tlscert"
)

// Phase 8 DTOs (contract C12). Times are RFC 3339 UTC; a time that never happened is null.

// backupDTO is one backup file. code is set only when check is "unreadable" ("permission_denied" or "io").
type backupDTO struct {
	Name         string    `json:"name"`
	Kind         string    `json:"kind"`
	Size         int64     `json:"size"`
	CreatedAt    time.Time `json:"created_at"`
	AliceVersion string    `json:"alice_version"`
	Check        string    `json:"check"`
	Code         string    `json:"code"`
}

func backupJSON(b backup.Info) backupDTO {
	return backupDTO{Name: b.Name, Kind: string(b.Kind), Size: b.Size, CreatedAt: b.CreatedAt.UTC(), AliceVersion: b.AliceVersion,
		Check: b.Check, Code: b.Code}
}

// backupStatusDTO is the state the dashboard shows: the last success, its age in whole hours, whether the latest
// attempt failed, the 48-hour alarm and whether backups are set up (a recovery passphrase exists).
type backupStatusDTO struct {
	LastSuccessAt   *time.Time `json:"last_success_at"`
	LastSuccessName string     `json:"last_success_name"`
	AgeHours        *int64     `json:"age_hours"`
	Failing         bool       `json:"failing"`
	Alarm           bool       `json:"alarm"`
	Configured      bool       `json:"configured"`
}

// backupStateDTO is backupStatusDTO plus the free space of the backups directory (the Backups tab, S-21).
type backupStateDTO struct {
	backupStatusDTO
	FreeBytes uint64 `json:"free_bytes"`
}

func backupStatusJSON(st backup.State, configured bool, now time.Time) backupStatusDTO {
	out := backupStatusDTO{LastSuccessName: st.LastSuccessName, Failing: st.Failing(), Alarm: st.Alarm(now), Configured: configured}
	if !st.LastSuccessAt.IsZero() {
		at := st.LastSuccessAt.UTC()
		age := int64(now.Sub(at) / time.Hour)
		out.LastSuccessAt, out.AgeHours = &at, &age
	}
	return out
}

// backupScheduleDTO is the daily schedule with the next scheduled instant and its optimistic version.
type backupScheduleDTO struct {
	Time      string     `json:"time"`
	Zone      string     `json:"zone"`
	Retention int        `json:"retention"`
	NextAt    *time.Time `json:"next_at"`
	Version   int        `json:"version"`
}

func backupScheduleJSON(sch backup.Schedule, now time.Time) backupScheduleDTO {
	out := backupScheduleDTO{Time: sch.Time, Zone: sch.Zone, Retention: sch.Retention, Version: sch.Version}
	if next, ok := nextScheduled(now, sch); ok {
		out.NextAt = &next
	}
	return out
}

// nextScheduled is the first instant after now whose wall clock in the schedule's zone is its time of day (the
// scheduler catches a missed one up at its next check). False when the stored schedule does not parse.
func nextScheduled(now time.Time, sch backup.Schedule) (time.Time, bool) {
	h, m, err := backup.ParseTimeOfDay(sch.Time)
	if err != nil || sch.Zone == "" || sch.Zone == "Local" {
		return time.Time{}, false
	}
	loc, err := time.LoadLocation(sch.Zone)
	if err != nil {
		return time.Time{}, false
	}
	local := now.In(loc)
	for d := 0; d <= 2; d++ {
		at := time.Date(local.Year(), local.Month(), local.Day()+d, h, m, 0, 0, loc)
		if at.After(now) {
			return at.UTC(), true
		}
	}
	return time.Time{}, false
}

// httpsInfoDTO describes the certificate the listener serves (never its key).
type httpsInfoDTO struct {
	Subject           string    `json:"subject"`
	DNSNames          []string  `json:"dns_names"`
	IPAddresses       []string  `json:"ip_addresses"`
	NotBefore         time.Time `json:"not_before"`
	NotAfter          time.Time `json:"not_after"`
	FingerprintSHA256 string    `json:"fingerprint_sha256"`
	Temporary         bool      `json:"temporary"`
	Warnings          []string  `json:"warnings"`
}

func httpsInfoJSON(i tlscert.Info) httpsInfoDTO {
	return httpsInfoDTO{Subject: i.Subject, DNSNames: nonNil(i.DNSNames), IPAddresses: nonNil(i.IPs), NotBefore: i.NotBefore.UTC(),
		NotAfter: i.NotAfter.UTC(), FingerprintSHA256: i.FingerprintSHA256, Temporary: i.Temporary, Warnings: nonNil(i.Warnings)}
}

// forwardingDTO is the audit forwarding setting and its progress; the CA bundle is write-only (ca_set).
type forwardingDTO struct {
	Enabled       bool       `json:"enabled"`
	Host          string     `json:"host"`
	Port          int        `json:"port"`
	Transport     string     `json:"transport"`
	CASet         bool       `json:"ca_set"`
	Backlog       int64      `json:"backlog"`
	CursorSeq     int64      `json:"cursor_seq"`
	LastSentAt    *time.Time `json:"last_sent_at"`
	LastErrorCode string     `json:"last_error_code"`
	LastErrorAt   *time.Time `json:"last_error_at"`
	Version       int        `json:"version"`
}

func forwardingJSON(s forward.Settings, st forward.State) forwardingDTO {
	return forwardingDTO{Enabled: s.Enabled, Host: s.Host, Port: s.Port, Transport: string(s.Transport), CASet: s.CASet,
		Backlog: st.Backlog, CursorSeq: st.CursorSeq, LastSentAt: optionalTime(st.LastSentAt), LastErrorCode: st.LastErrorCode,
		LastErrorAt: optionalTime(st.LastErrorAt), Version: s.Version}
}

func optionalTime(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	u := t.UTC()
	return &u
}

// publicSetupStatusDTO is what an anonymous caller learns once setup is complete (S-18, R43 row 47).
type publicSetupStatusDTO struct {
	Completed     bool   `json:"completed"`
	DefaultLocale string `json:"default_locale"`
}

// checklistItemDTO is one line of the dashboard's "Finish setting up" (R43 row 18).
type checklistItemDTO struct {
	Item     string `json:"item"`
	Done     bool   `json:"done"`
	Required bool   `json:"required"`
}
