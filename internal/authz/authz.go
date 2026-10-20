// Package authz holds the value types of scoped access and service ownership (R49, design
// docs/superpowers/specs/2026-10-21-scoped-rbac-and-service-ownership-design.md) and the two checks other modules run
// inside their own transactions: which service a new resource goes to, and whether one service accepts the keys of
// another (a trust, design §5.6 (c)). The services, environments, trusts and assignment themselves live in
// authz/services; inventory, sshkeys and discovery import only this package.
package authz

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"alice/internal/platform/db"
	"alice/internal/platform/validate"
)

// ServiceRef is how a row shows the service that owns it: the service's id, name and environment (nil for none).
type ServiceRef struct {
	ID          uuid.UUID
	Name        string
	Environment *EnvironmentRef
}

// EnvironmentRef names an environment: its id, its key (production, staging, ...) and its stored name.
type EnvironmentRef struct {
	ID   uuid.UUID
	Key  string
	Name string
}

// ErrUntrusted is the refusal of an action that would place a certificate's private key or an SSH key of one service
// on a server or into a Key Vault of another service that does not accept it (no trust, design §5.6 (c)). The error
// returned is an *UntrustedError naming both services.
var ErrUntrusted = errors.New("authz: the destination service does not accept certificates and keys of the source service")

// UntrustedError names the two services of a refused cross-service action: Source owns the key, Target owns the
// server or the Key Vault.
type UntrustedError struct {
	Source, Target uuid.UUID
}

func (e *UntrustedError) Error() string {
	return fmt.Sprintf("%s (source %s, destination %s)", ErrUntrusted, e.Source, e.Target)
}

// Is makes errors.Is(err, ErrUntrusted) true.
func (e *UntrustedError) Is(target error) bool { return target == ErrUntrusted }

// ResolveService is the service a new resource goes to (design §4.4): the one named (it must exist; it is key-share
// locked so it cannot be deleted before the caller's transaction commits) or, for uuid.Nil, the Default service. An
// unknown service is a validation error on the field "service_id" (422), as an unknown reference elsewhere.
func ResolveService(ctx context.Context, q db.Querier, id uuid.UUID) (uuid.UUID, error) {
	var out uuid.UUID
	var err error
	if id == uuid.Nil {
		err = q.QueryRow(ctx, "SELECT id FROM services WHERE is_default FOR KEY SHARE").Scan(&out)
	} else {
		err = q.QueryRow(ctx, "SELECT id FROM services WHERE id = $1 FOR KEY SHARE", id).Scan(&out)
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, validate.Errors{{Field: "service_id", Code: validate.Required}}
	}
	if err != nil {
		return uuid.Nil, fmt.Errorf("authz: read the service: %w", err)
	}
	return out, nil
}

// CheckTrust is design §5.6 (c): a key owned by source may be placed on a server or into a Key Vault of target when
// both are the same service or target accepts source (a service_trusts row). The trust row is key-share locked, so
// removing it waits for the caller's transaction (a deployment queued under a trust is queued before the trust goes;
// the engine's first send checks it again). A missing trust is an *UntrustedError.
func CheckTrust(ctx context.Context, q db.Querier, source, target uuid.UUID) error {
	if source == target {
		return nil
	}
	var one int
	err := q.QueryRow(ctx, `SELECT 1 FROM service_trusts WHERE source_service_id = $1 AND target_service_id = $2 FOR KEY SHARE`,
		source, target).Scan(&one)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return &UntrustedError{Source: source, Target: target}
	case err != nil:
		return fmt.Errorf("authz: read the trust: %w", err)
	}
	return nil
}
