package services

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"alice/internal/authz"
	"alice/internal/platform/db"
	"alice/internal/platform/validate"
)

// Trust is "Target accepts certificates and SSH keys owned by Source" (design §5.6): directed, made by an
// Administrator with services.trust on both services, removed with it on either.
type Trust struct {
	ID            uuid.UUID
	Source        authz.ServiceRef
	Target        authz.ServiceRef
	CreatedBy     *uuid.UUID
	CreatedByName string
	CreatedAt     time.Time
}

const trustSelect = `SELECT st.id, st.created_by, coalesce(u.display_name, ''), st.created_at,
    s1.id, s1.name::text, e1.id, coalesce(e1.key, ''), coalesce(e1.name, ''),
    s2.id, s2.name::text, e2.id, coalesce(e2.key, ''), coalesce(e2.name, '')
FROM service_trusts st
JOIN services s1 ON s1.id = st.source_service_id LEFT JOIN environments e1 ON e1.id = s1.environment_id
JOIN services s2 ON s2.id = st.target_service_id LEFT JOIN environments e2 ON e2.id = s2.environment_id
LEFT JOIN users u ON u.id = st.created_by`

func scanTrust(r pgx.CollectableRow) (Trust, error) {
	var (
		t              Trust
		env1, env2     *uuid.UUID
		k1, n1, k2, n2 string
	)
	err := r.Scan(&t.ID, &t.CreatedBy, &t.CreatedByName, &t.CreatedAt, &t.Source.ID, &t.Source.Name, &env1, &k1, &n1,
		&t.Target.ID, &t.Target.Name, &env2, &k2, &n2)
	if env1 != nil {
		t.Source.Environment = &authz.EnvironmentRef{ID: *env1, Key: k1, Name: n1}
	}
	if env2 != nil {
		t.Target.Environment = &authz.EnvironmentRef{ID: *env2, Key: k2, Name: n2}
	}
	return t, err
}

// Trusts lists the trusts, all of them or those with service on either side, by source and target name.
func (s *Store) Trusts(ctx context.Context, service *uuid.UUID) ([]Trust, error) {
	rows, err := s.pool.Query(ctx, trustSelect+` WHERE $1::uuid IS NULL OR st.source_service_id = $1 OR st.target_service_id = $1
ORDER BY lower(s1.name::text), lower(s2.name::text), st.id`, service)
	if err != nil {
		return nil, fmt.Errorf("services: list the trusts: %w", err)
	}
	return pgx.CollectRows(rows, scanTrust)
}

// TrustByID reads one trust. ErrTrustNotFound.
func (s *Store) TrustByID(ctx context.Context, id uuid.UUID) (Trust, error) {
	return getTrust(ctx, s.pool, id)
}

func getTrust(ctx context.Context, q db.Querier, id uuid.UUID) (Trust, error) {
	rows, err := q.Query(ctx, trustSelect+" WHERE st.id = $1", id)
	if err != nil {
		return Trust{}, fmt.Errorf("services: read the trust: %w", err)
	}
	t, err := pgx.CollectExactlyOneRow(rows, scanTrust)
	if errors.Is(err, pgx.ErrNoRows) {
		return Trust{}, ErrTrustNotFound
	}
	if err != nil {
		return Trust{}, fmt.Errorf("services: read the trust: %w", err)
	}
	return t, nil
}

// CreateTrust records that target accepts certificates and SSH keys of source (at most MaxTrustsPerService on either
// side); audit service.trust_added. A deployment from source to target is allowed from then on. ErrTrustExists.
func (s *Store) CreateTrust(ctx context.Context, a Actor, source, target uuid.UUID) (Trust, error) {
	var v validate.Errors
	if source == uuid.Nil {
		v.Add("source_service_id", validate.Required, nil)
	}
	if target == uuid.Nil {
		v.Add("target_service_id", validate.Required, nil)
	}
	if source != uuid.Nil && source == target {
		v.Add("target_service_id", validate.Pattern, nil)
	}
	if err := v.Err(); err != nil {
		return Trust{}, err
	}
	id := uuid.Must(uuid.NewV7())
	err := db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		// Both services, in id order (two creations of opposite trusts never wait on each other in turn).
		first, second := source, target
		if second.String() < first.String() {
			first, second = second, first
		}
		for _, sv := range []uuid.UUID{first, second} {
			var one int
			err := tx.QueryRow(ctx, "SELECT 1 FROM services WHERE id = $1 FOR UPDATE", sv).Scan(&one)
			if errors.Is(err, pgx.ErrNoRows) {
				field := "source_service_id"
				if sv == target {
					field = "target_service_id"
				}
				return validate.Errors{{Field: field, Code: validate.Required}}
			}
			if err != nil {
				return fmt.Errorf("services: lock the service: %w", err)
			}
		}
		for _, sv := range []uuid.UUID{source, target} {
			var n int
			if err := tx.QueryRow(ctx, "SELECT count(*) FROM service_trusts WHERE source_service_id = $1 OR target_service_id = $1", sv).Scan(&n); err != nil {
				return fmt.Errorf("services: count the trusts: %w", err)
			}
			if n >= MaxTrustsPerService {
				return validate.Errors{{Field: "target_service_id", Code: validate.OutOfRange,
					Params: map[string]string{"min": "0", "max": strconv.Itoa(MaxTrustsPerService)}}}
			}
		}
		_, err := tx.Exec(ctx, `INSERT INTO service_trusts (id, source_service_id, target_service_id, created_by, created_at) VALUES ($1, $2, $3, $4, $5)`,
			id, source, target, a.createdBy(), s.clock.Now().UTC())
		if uniqueViolation(err, "service_trusts_source_service_id_target_service_id_key") {
			return ErrTrustExists
		}
		if err != nil {
			return fmt.Errorf("services: store the trust: %w", err)
		}
		return s.appendAudit(ctx, tx, a, "service.trust_added", "service_trust", id, map[string]string{
			"source_service_id": source.String(), "target_service_id": target.String()})
	})
	if err != nil {
		return Trust{}, err
	}
	return s.TrustByID(ctx, id)
}

// DeleteTrust removes a trust; audit service.trust_removed. Deployments already made stay; the next deployment from
// the source to the target (a person's, the engine's first send, the automatic deployment plans) is refused.
// ErrTrustNotFound.
func (s *Store) DeleteTrust(ctx context.Context, a Actor, id uuid.UUID) error {
	return db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		t, err := getTrust(ctx, tx, id)
		if err != nil {
			return err
		}
		tag, err := tx.Exec(ctx, "DELETE FROM service_trusts WHERE id = $1", id)
		if err != nil {
			return fmt.Errorf("services: delete the trust: %w", err)
		}
		if tag.RowsAffected() == 0 {
			return ErrTrustNotFound
		}
		return s.appendAudit(ctx, tx, a, "service.trust_removed", "service_trust", id, map[string]string{
			"source_service_id": t.Source.ID.String(), "target_service_id": t.Target.ID.String()})
	})
}
