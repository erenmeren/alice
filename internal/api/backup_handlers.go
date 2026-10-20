package api

import (
	"context"
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"time"

	"alice/internal/audit"
	"alice/internal/backup"
	"alice/internal/license"
	"alice/internal/platform/clock"
	"alice/internal/rbac"
)

// backupRoutes are the backups (C12, Phase 8): the list with the state and schedule, a backup made now, the audited
// download, and the schedule setting. The backups are backup.manage (an Administrator's browser session with step-up,
// never an API token: a backup holds every secret, encrypted); the schedule is settings.manage like Alice's other
// settings. Everything works in lock (platform administration, ClassAlways).
func (s *server) backupRoutes() []route {
	return []route{
		{method: http.MethodGet, pattern: "/api/v1/backups", scope: scopePlatform, perm: rbac.BackupManage, handler: s.listBackups},
		{method: http.MethodPost, pattern: "/api/v1/backups", scope: scopePlatform, perm: rbac.BackupManage, limit: limitBackupNow, lic: license.ClassAlways,
			handler: s.createBackup},
		{method: http.MethodGet, pattern: "/api/v1/backups/{name}/download", scope: scopePlatform, perm: rbac.BackupManage, limit: limitDownload, getOnly: true,
			handler: s.downloadBackup},
		{method: http.MethodGet, pattern: "/api/v1/settings/backups", scope: scopePlatform, perm: rbac.SettingsManage, handler: s.getBackupSchedule},
		{method: http.MethodPut, pattern: "/api/v1/settings/backups", scope: scopePlatform, perm: rbac.SettingsManage, lic: license.ClassAlways,
			handler: s.putBackupSchedule},
	}
}

// backupResponseTimeout bounds the answer of a backup made now and of a download: a backup can be large, so making it,
// hashing it (Open) and sending it take longer than the server's write timeout.
const backupResponseTimeout = time.Hour

// extendResponseDeadline gives a backup route its own write deadline. It is set first, before the slow step: the
// server's deadline counts from the request.
func extendResponseDeadline(w http.ResponseWriter) {
	_ = http.NewResponseController(w).SetWriteDeadline(clock.Real{}.Now().Add(backupResponseTimeout))
}

// backupsConfigured reports whether backups are set up: the recovery passphrase exists (R4).
func (s *server) backupsConfigured(ctx context.Context) (bool, error) {
	st, err := s.deps.Setup.Status(ctx)
	if err != nil {
		return false, err
	}
	return st.RecoveryPassphraseSet, nil
}

func (s *server) listBackups(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	list, err := s.deps.Backup.List(ctx)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	st, err := s.deps.Backup.State(ctx)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	sch, err := s.deps.Backup.Schedule(ctx)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	free, err := s.deps.Backup.FreeBytes()
	if err != nil {
		s.fail(w, r, err)
		return
	}
	configured, err := s.backupsConfigured(ctx)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	now := s.deps.Clock.Now()
	items := make([]backupDTO, 0, len(list))
	for _, b := range list {
		items = append(items, backupJSON(b))
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"items":    items,
		"state":    backupStateDTO{backupStatusDTO: backupStatusJSON(st, configured, now), FreeBytes: free},
		"schedule": backupScheduleJSON(sch, now),
	})
}

// createBackup makes a manual backup now. It runs to its end even when the browser goes away: a backup that stopped
// halfway would only leave a failure behind.
func (s *server) createBackup(w http.ResponseWriter, r *http.Request) {
	extendResponseDeadline(w)
	if !s.decodeExactOptional(w, r, &struct{}{}, maxActionBody) {
		return
	}
	actor := principalFrom(r.Context()).Actor(s.meta(r))
	info, err := s.deps.Backup.Create(context.WithoutCancel(r.Context()), backup.CreateInput{Kind: backup.KindManual, Actor: actor})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, backupJSON(info))
}

// downloadBackup sends one backup file. The name must be one Alice gives or accepts (C7); anything else is
// ALC-BAK-0003 before the file system is touched, and the service opens nothing outside the backups directory. The
// download is audited (backup.downloaded) and committed before the first byte; there are no range requests.
func (s *server) downloadBackup(w http.ResponseWriter, r *http.Request) {
	name, ok := pathBackupName(r)
	if !ok {
		s.writeError(w, r, ErrBackupNotFound)
		return
	}
	extendResponseDeadline(w)
	// Open hashes the whole file first, which can outlast the connection (a proxy's read timeout on a multi-GB
	// backup): it and the audit row run to their end without the request's cancel, as createBackup does, so the
	// download is not refused halfway with its row lost.
	ctx := context.WithoutCancel(r.Context())
	f, info, err := s.deps.Backup.Open(ctx, name)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	defer func() { _ = f.Close() }()
	if err := s.deps.Audit.Write(ctx, audit.Event{Actor: principalFrom(r.Context()).Actor(s.meta(r)), Action: "backup.downloaded",
		ObjectType: "backup", ObjectID: info.Name, Result: audit.Success, Details: map[string]string{"name": info.Name}}); err != nil {
		s.fail(w, r, err)
		return
	}
	h := w.Header()
	h.Set("Content-Type", "application/octet-stream")
	h.Set("Content-Disposition", attachment(info.Name))
	h.Set("Cache-Control", "no-store")
	h.Set("Accept-Ranges", "none")
	if fi, err := f.Stat(); err == nil {
		h.Set("Content-Length", strconv.FormatInt(fi.Size(), 10))
	}
	w.WriteHeader(http.StatusOK)
	if _, err := io.Copy(w, f); err != nil {
		s.deps.Log.Warn("a backup download stopped before its end", "event", "backup.download_incomplete", "request_id", RequestID(r.Context()))
	}
}

// pathBackupName reads the {name} of a backup route: a name of C7 (a standard name, or one --out accepts), else false.
func pathBackupName(r *http.Request) (string, bool) {
	name := r.PathValue("name")
	return name, backup.ValidName(name)
}

// attachment is the Content-Disposition of a download: attachment; filename="<name>" for a plain name, the RFC 2231
// form for a name with a quote, a backslash or a character outside printable ASCII.
func attachment(name string) string {
	if !strings.ContainsFunc(name, func(c rune) bool { return c < 0x20 || c > 0x7e || c == '"' || c == '\\' }) {
		return `attachment; filename="` + name + `"`
	}
	return mime.FormatMediaType("attachment", map[string]string{"filename": name})
}

func (s *server) getBackupSchedule(w http.ResponseWriter, r *http.Request) {
	sch, err := s.deps.Backup.Schedule(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	w.Header().Set("ETag", etag(sch.Version))
	writeJSON(w, http.StatusOK, backupScheduleJSON(sch, s.deps.Clock.Now()))
}

// putBackupSchedule stores the daily time, its zone and the number of automatic backups kept; the service validates
// them (422 on time, zone, retention) and audits backup.settings_changed.
func (s *server) putBackupSchedule(w http.ResponseWriter, r *http.Request) {
	version, ok := s.settingsChange(w, r)
	if !ok {
		return
	}
	var req struct {
		Time      string `json:"time"`
		Zone      string `json:"zone"`
		Retention int    `json:"retention"`
	}
	if !s.decodeExact(w, r, &req, maxSettingsBody, "time", "zone", "retention") {
		return
	}
	sch, err := s.deps.Backup.SaveSchedule(r.Context(), principalFrom(r.Context()).Actor(s.meta(r)), version,
		backup.Schedule{Time: req.Time, Zone: req.Zone, Retention: req.Retention})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	w.Header().Set("ETag", etag(sch.Version))
	writeJSON(w, http.StatusOK, backupScheduleJSON(sch, s.deps.Clock.Now()))
}
