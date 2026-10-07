package reports

import (
	"context"
	"fmt"
	"sort"
	"time"

	"alice/internal/jobs"
	"alice/internal/rbac"
)

// Condition kinds.
const (
	CondHostKeyChanged       = "host_key_changed"
	CondAuthFailed           = "auth_failed"
	CondDeploymentFailed     = "deployment_failed"
	CondAuditBroken          = "audit_broken"
	CondNotificationsFailing = "notifications_failing"
)

// Condition is one thing that needs a person's attention.
type Condition struct {
	Kind      string // host_key_changed | auth_failed | deployment_failed | audit_broken | notifications_failing
	ObjectID  string // target, deployment or "" for audit_broken / notifications_failing
	Name      string // target name, certificate name or ""
	Since     time.Time
	ErrorCode string
}

func seesAudit(r rbac.Role) bool { return r == rbac.Admin || r == rbac.Auditor }

// Attention lists the conditions the viewer should look at, newest first. Everyone sees targets that need action and
// failed deployments; Administrators and Auditors also see a broken audit chain; Administrators also see failing
// e-mail delivery.
func (s *Service) Attention(ctx context.Context, v Viewer) ([]Condition, error) {
	now := s.clock.Now().UTC()
	var out []Condition
	rows, err := s.pool.Query(ctx, `SELECT status, id::text, name::text, updated_at, last_error_code FROM targets
WHERE deleted_at IS NULL AND status IN ('host_key_changed', 'auth_failed')`)
	if err != nil {
		return nil, fmt.Errorf("reports: read the targets needing action: %w", err)
	}
	for rows.Next() {
		var c Condition
		if err := rows.Scan(&c.Kind, &c.ObjectID, &c.Name, &c.Since, &c.ErrorCode); err != nil {
			rows.Close()
			return nil, fmt.Errorf("reports: read the targets needing action: %w", err)
		}
		c.Since = c.Since.UTC()
		out = append(out, c)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("reports: read the targets needing action: %w", err)
	}
	failed, err := s.failedDeployments(ctx, now, 0)
	if err != nil {
		return nil, err
	}
	for _, d := range failed {
		out = append(out, Condition{Kind: CondDeploymentFailed, ObjectID: d.ID.String(), Name: d.CertificateName, Since: d.At,
			ErrorCode: d.ErrorCode})
	}
	if seesAudit(v.Role) {
		st, err := jobs.ReadAuditVerifyState(ctx, s.pool)
		if err != nil {
			return nil, fmt.Errorf("reports: %w", err)
		}
		if auditBroken(st) {
			out = append(out, Condition{Kind: CondAuditBroken, Since: st.LastBrokenAt.UTC()})
		}
	}
	if v.Role == rbac.Admin {
		d, err := s.delivery.Delivery(ctx)
		if err != nil {
			return nil, fmt.Errorf("reports: read the e-mail delivery state: %w", err)
		}
		if d.Failing() {
			c := Condition{Kind: CondNotificationsFailing, ErrorCode: d.LastFailureCode}
			if d.LastFailureAt != nil {
				c.Since = d.LastFailureAt.UTC()
			}
			out = append(out, c)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Since.After(out[j].Since) })
	return out, nil
}

func auditBroken(st jobs.AuditVerifyState) bool { return st.LastBrokenAt.After(st.LastIntactAt) }
