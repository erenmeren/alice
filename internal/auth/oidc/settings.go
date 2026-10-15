package oidc

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/jackc/pgx/v5"

	"alice/internal/audit"
	"alice/internal/platform/db"
	"alice/internal/platform/settings"
)

// switchValue is the stored "SSO users may be Admin" setting (AllowAdminKey); absent means off, version 0.
type switchValue struct {
	Allow   bool `json:"allow"`
	Version int  `json:"version"`
}

// Settings returns the "SSO users may be Admin" switch.
func (s *Service) Settings(ctx context.Context) (SSOSettings, error) {
	var v switchValue
	if _, err := settings.Get(ctx, s.pool, AllowAdminKey, &v); err != nil {
		return SSOSettings{}, err
	}
	return SSOSettings{AllowAdminRole: v.Allow, Version: v.Version}, nil
}

// lockSwitch creates the switch row when it is missing and locks it FOR UPDATE (S-5): an Admin mapping and the
// switch-off are serialized, and sign-ins (auth reads the row FOR SHARE) wait for a switch-off to commit.
func (s *Service) lockSwitch(ctx context.Context, tx pgx.Tx) (switchValue, error) {
	if _, err := tx.Exec(ctx, `INSERT INTO settings (key, value, updated_at) VALUES ($1, '{"allow": false, "version": 0}', $2)
ON CONFLICT (key) DO NOTHING`, AllowAdminKey, s.clock.Now().UTC()); err != nil {
		return switchValue{}, fmt.Errorf("oidc: create the Admin switch: %w", err)
	}
	var raw []byte
	if err := tx.QueryRow(ctx, "SELECT value FROM settings WHERE key = $1 FOR UPDATE", AllowAdminKey).Scan(&raw); err != nil {
		return switchValue{}, fmt.Errorf("oidc: lock the Admin switch: %w", err)
	}
	var v switchValue
	if err := json.Unmarshal(raw, &v); err != nil {
		return switchValue{}, fmt.Errorf("oidc: read the Admin switch: %w", err)
	}
	return v, nil
}

// SaveSettings sets "SSO users may be Admin" at the given version. Switching it off is refused while a group of an
// identity provider or of a directory (internal/auth/ldap, which shares the switch) is mapped to Administrator, and
// demotes every SSO Administrator to Auditor and ends their sessions in the same transaction (O-13, R42 row 24).
func (s *Service) SaveSettings(ctx context.Context, a audit.Actor, version int, allowAdmin bool) (SSOSettings, error) {
	var out SSOSettings
	err := db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		cur, err := s.lockSwitch(ctx, tx)
		if err != nil {
			return err
		}
		if cur.Version != version {
			return ErrVersion
		}
		action, details := "sso.admin_role_allowed", map[string]string{}
		if !allowAdmin {
			var exist bool
			if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM oidc_group_mappings WHERE role = 'admin')
OR EXISTS (SELECT 1 FROM ldap_group_mappings WHERE role = 'admin')`).Scan(&exist); err != nil {
				return fmt.Errorf("oidc: read the group mappings: %w", err)
			}
			if exist {
				return ErrAdminMappingsExist
			}
			demoted, ended, err := s.auth.DemoteSSOAdmins(ctx, tx, a)
			if err != nil {
				return err
			}
			action = "sso.admin_role_disallowed"
			details["demoted_count"], details["ended_count"] = strconv.Itoa(demoted), strconv.Itoa(ended)
		}
		next := switchValue{Allow: allowAdmin, Version: version + 1}
		if err := settings.Set(ctx, tx, AllowAdminKey, next, s.clock.Now()); err != nil {
			return err
		}
		out = SSOSettings{AllowAdminRole: next.Allow, Version: next.Version}
		_, err = s.audit.Append(ctx, tx, audit.Event{Actor: a, Action: action, ObjectType: "setting", ObjectID: AllowAdminKey,
			Result: audit.Success, Details: details})
		return err
	})
	if err != nil {
		return SSOSettings{}, err
	}
	return out, nil
}
