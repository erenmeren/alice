package reports

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"

	"alice/internal/alerts"
	"alice/internal/audit"
	"alice/internal/jobs"
	"alice/internal/notify"
	"alice/internal/platform/validate"
	"alice/internal/rbac"
)

// Viewer is who asks; the role decides which parts of the summary are filled.
type Viewer struct {
	UserID uuid.UUID
	Role   rbac.Role
}

// Summary is the dashboard's data. The certificate counts are cumulative windows with the list filter's semantics
// (Expired: not_after <= now; Within7: not_after < now+7d, expired ones included), so each equals the rows its link opens.
// KVExpired and KVWithin30 count Key Vault keys and client secrets only.
type Summary struct {
	GeneratedAt   time.Time
	Certificates  alerts.Counts
	Deployments   DeploymentSummary
	Targets       TargetSummary
	License       LicenseSummary
	Rotation      RotationSummary
	Notifications *notify.Delivery // Administrators only
	Audit         *AuditHead       // Administrators and Auditors only
	Attention     int              // len(Attention(...)) for the same viewer
}

// DeploymentSummary counts the failed deployments of FailedWindow.
type DeploymentSummary struct {
	Failed7d int
	Recent   []FailedDeployment // at most 5, newest first
}

// FailedDeployment is one deployment that did not end well.
type FailedDeployment struct {
	ID              uuid.UUID
	CertificateName string
	TargetID        uuid.UUID
	TargetName      string
	Status          string // failed | rolled_back | rollback_failed | needs_attention
	ErrorCode       string
	At              time.Time // coalesce(finished_at, created_at)
}

// TargetSummary counts live targets by status.
type TargetSummary struct {
	Total    int
	ByStatus map[string]int // every known status is present, also with 0
}

// LicenseSummary is the license line; the detail is for Administrators and Auditors.
type LicenseSummary struct {
	Expired  bool
	Phase    string     // "" for Operators
	EndsAt   *time.Time // nil for Operators
	DaysLeft *int       // nil for Operators
}

// RotationSummary is the SSH key rotation widget.
type RotationSummary struct {
	Upcoming       []UpcomingRotation // at most 5, soonest first, enabled policies due within RotationWindow
	Running        int                // runs not finished (status not completed, aborted, cancelled, needs_attention)
	NeedsAttention int                // runs whose status is needs_attention
}

// UpcomingRotation is one policy due soon.
type UpcomingRotation struct {
	PolicyID  uuid.UUID
	SSHKeyID  uuid.UUID
	KeyLabel  string
	NextRunAt time.Time
}

// AuditHead is the last verified audit chain head.
type AuditHead struct {
	HeadSeq   int64
	HeadHash  string    // hex
	CheckedAt time.Time // the checkpoint's time
	Intact    bool      // false when the last broken verification is newer than the last intact one
}

var knownTargetStatuses = []string{"pending_host_key", "checking", "ok", "unreachable", "host_key_changed", "auth_failed", "disabled",
	"degraded"}

const failedStatuses = `('failed', 'rolled_back', 'rollback_failed', 'needs_attention')`

// Summary reads the dashboard for the viewer.
func (s *Service) Summary(ctx context.Context, v Viewer) (Summary, error) {
	now := s.clock.Now().UTC()
	out := Summary{GeneratedAt: now}
	var err error
	if out.Certificates, err = s.certificateCounts(ctx, now); err != nil {
		return Summary{}, err
	}
	if out.Deployments.Failed7d, err = s.countFailedDeployments(ctx, now); err != nil {
		return Summary{}, err
	}
	if out.Deployments.Recent, err = s.failedDeployments(ctx, now, 5); err != nil {
		return Summary{}, err
	}
	if out.Targets, err = s.targetSummary(ctx); err != nil {
		return Summary{}, err
	}
	ev := s.license.Snapshot().Eval
	out.License.Expired = ev.Expired()
	if seesAudit(v.Role) {
		ends, days := ev.EndsAt.UTC(), ev.DaysLeft
		out.License.Phase, out.License.EndsAt, out.License.DaysLeft = string(ev.Phase), &ends, &days
	}
	if out.Rotation, err = s.rotationSummary(ctx, now); err != nil {
		return Summary{}, err
	}
	if v.Role == rbac.Admin {
		d, err := s.delivery.Delivery(ctx)
		if err != nil {
			return Summary{}, fmt.Errorf("reports: read the e-mail delivery state: %w", err)
		}
		out.Notifications = &d
	}
	if seesAudit(v.Role) {
		if out.Audit, err = s.auditHead(ctx); err != nil {
			return Summary{}, err
		}
	}
	att, err := s.Attention(ctx, v)
	if err != nil {
		return Summary{}, err
	}
	out.Attention = len(att)
	return out, nil
}

// countsSQL counts over the same population and with the same predicates as inventory.ListCertificates without a target
// filter (every certificate row; expired is not_after <= now, a window of n days is not_after < now + n days, expired
// ones included), so each count equals the rows its dashboard link opens. The Key Vault line counts Key Vault keys and
// client secrets, which the certificate list does not hold (Key Vault certificates are certificates).
const countsSQL = `
WITH kv AS (
    SELECT k.expires FROM kv_keys k JOIN targets t ON t.id = k.target_id AND t.deleted_at IS NULL
    WHERE k.missing_since IS NULL AND k.enabled AND k.expires IS NOT NULL
    UNION ALL
    SELECT (cr.public_info->>'secret_expires_on')::timestamptz FROM targets t JOIN credentials cr ON cr.id = t.credential_id
    WHERE t.type = 'azure_key_vault' AND t.deleted_at IS NULL AND cr.public_info ? 'secret_expires_on'
)
SELECT c.expired, c.d7, c.d30, c.d60, k.expired, k.d30
FROM (SELECT count(*) FILTER (WHERE not_after <= $1::timestamptz) AS expired,
             count(*) FILTER (WHERE not_after < $2::timestamptz) AS d7,
             count(*) FILTER (WHERE not_after < $3::timestamptz) AS d30,
             count(*) FILTER (WHERE not_after < $4::timestamptz) AS d60 FROM certificates) c,
     (SELECT count(*) FILTER (WHERE expires <= $1::timestamptz) AS expired,
             count(*) FILTER (WHERE expires < $3::timestamptz) AS d30 FROM kv) k`

// certificateCounts fills the cumulative windows in one statement. Monitored (certificates in use) is the alerts
// package's one definition.
func (s *Service) certificateCounts(ctx context.Context, now time.Time) (alerts.Counts, error) {
	base, err := s.alerts.Counts(ctx)
	if err != nil {
		return alerts.Counts{}, fmt.Errorf("reports: %w", err)
	}
	c := alerts.Counts{Monitored: base.Monitored}
	day := 24 * time.Hour
	err = s.pool.QueryRow(ctx, countsSQL, now, now.Add(7*day), now.Add(30*day), now.Add(60*day)).
		Scan(&c.Expired, &c.Within7, &c.Within30, &c.Within60, &c.KVExpired, &c.KVWithin30)
	if err != nil {
		return alerts.Counts{}, fmt.Errorf("reports: count the certificates: %w", err)
	}
	return c, nil
}

func (s *Service) countFailedDeployments(ctx context.Context, now time.Time) (int, error) {
	var n int
	err := s.pool.QueryRow(ctx, `SELECT count(*) FROM deployments WHERE status IN `+failedStatuses+`
AND (status = 'needs_attention' OR coalesce(finished_at, created_at) >= $1)`, now.Add(-FailedWindow)).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("reports: count the failed deployments: %w", err)
	}
	return n, nil
}

// failedDeployments lists the failed deployments of FailedWindow, newest first; limit 0 lists all.
func (s *Service) failedDeployments(ctx context.Context, now time.Time, limit int) ([]FailedDeployment, error) {
	rows, err := s.pool.Query(ctx, `SELECT d.id, coalesce(nullif(c.subject_cn, ''), nullif(c.label, ''), left(c.fingerprint_sha256, 16)),
t.id, t.name::text, d.status, d.error_code, coalesce(d.finished_at, d.created_at)
FROM deployments d JOIN certificates c ON c.id = d.certificate_id JOIN targets t ON t.id = d.target_id
WHERE d.status IN `+failedStatuses+` AND (d.status = 'needs_attention' OR coalesce(d.finished_at, d.created_at) >= $1)
ORDER BY coalesce(d.finished_at, d.created_at) DESC, d.id DESC LIMIT NULLIF($2::int, 0)`, now.Add(-FailedWindow), limit)
	if err != nil {
		return nil, fmt.Errorf("reports: read the failed deployments: %w", err)
	}
	defer rows.Close()
	var out []FailedDeployment
	for rows.Next() {
		var f FailedDeployment
		if err := rows.Scan(&f.ID, &f.CertificateName, &f.TargetID, &f.TargetName, &f.Status, &f.ErrorCode, &f.At); err != nil {
			return nil, fmt.Errorf("reports: read the failed deployments: %w", err)
		}
		f.At = f.At.UTC()
		out = append(out, f)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("reports: read the failed deployments: %w", err)
	}
	return out, nil
}

func (s *Service) targetSummary(ctx context.Context) (TargetSummary, error) {
	ts := TargetSummary{ByStatus: map[string]int{}}
	for _, st := range knownTargetStatuses {
		ts.ByStatus[st] = 0
	}
	rows, err := s.pool.Query(ctx, `SELECT status, count(*) FROM targets WHERE deleted_at IS NULL GROUP BY status`)
	if err != nil {
		return TargetSummary{}, fmt.Errorf("reports: count the targets: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var st string
		var n int
		if err := rows.Scan(&st, &n); err != nil {
			return TargetSummary{}, fmt.Errorf("reports: count the targets: %w", err)
		}
		ts.ByStatus[st] = n
		ts.Total += n
	}
	if err := rows.Err(); err != nil {
		return TargetSummary{}, fmt.Errorf("reports: count the targets: %w", err)
	}
	return ts, nil
}

func (s *Service) rotationSummary(ctx context.Context, now time.Time) (RotationSummary, error) {
	var rs RotationSummary
	rows, err := s.pool.Query(ctx, `SELECT p.id, p.ssh_key_id, k.label, p.next_run_at FROM rotation_policies p
JOIN ssh_keys k ON k.id = p.ssh_key_id
WHERE p.enabled AND p.deleted_at IS NULL AND p.next_run_at <= $1 ORDER BY p.next_run_at, p.id LIMIT 5`, now.Add(RotationWindow))
	if err != nil {
		return RotationSummary{}, fmt.Errorf("reports: read the upcoming rotations: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var u UpcomingRotation
		if err := rows.Scan(&u.PolicyID, &u.SSHKeyID, &u.KeyLabel, &u.NextRunAt); err != nil {
			return RotationSummary{}, fmt.Errorf("reports: read the upcoming rotations: %w", err)
		}
		u.NextRunAt = u.NextRunAt.UTC()
		rs.Upcoming = append(rs.Upcoming, u)
	}
	if err := rows.Err(); err != nil {
		return RotationSummary{}, fmt.Errorf("reports: read the upcoming rotations: %w", err)
	}
	rows.Close()
	err = s.pool.QueryRow(ctx, `SELECT count(*) FILTER (WHERE status NOT IN ('completed', 'aborted', 'cancelled', 'needs_attention')),
count(*) FILTER (WHERE status = 'needs_attention') FROM rotations`).Scan(&rs.Running, &rs.NeedsAttention)
	if err != nil {
		return RotationSummary{}, fmt.Errorf("reports: count the rotations: %w", err)
	}
	return rs, nil
}

// auditHead is nil before the first verification stored a checkpoint.
func (s *Service) auditHead(ctx context.Context) (*AuditHead, error) {
	cp, ok, err := audit.LastCheckpoint(ctx, s.pool)
	if err != nil {
		return nil, fmt.Errorf("reports: %w", err)
	}
	if !ok {
		return nil, nil //nolint:nilnil // no checkpoint yet is a normal state, the field is optional
	}
	st, err := jobs.ReadAuditVerifyState(ctx, s.pool)
	if err != nil {
		return nil, fmt.Errorf("reports: %w", err)
	}
	return &AuditHead{HeadSeq: cp.Seq, HeadHash: cp.Hash, CheckedAt: cp.At, Intact: !auditBroken(st)}, nil
}

// Expiring lists the monitored items that expire within days (1..365), soonest first, expired ones included.
func (s *Service) Expiring(ctx context.Context, days, limit int) ([]alerts.Item, error) {
	var v validate.Errors
	if days < 1 || days > 365 {
		v.Add("days", validate.OutOfRange, map[string]string{"min": "1", "max": "365"})
	}
	if limit < 1 || limit > 200 {
		v.Add("limit", validate.OutOfRange, map[string]string{"min": "1", "max": "200"})
	}
	if err := v.Err(); err != nil {
		return nil, err
	}
	items, err := s.alerts.Items(ctx, alerts.Kinds(), s.clock.Now().UTC().Add(time.Duration(days)*24*time.Hour), limit)
	if err != nil {
		return nil, fmt.Errorf("reports: %w", err)
	}
	return items, nil
}
