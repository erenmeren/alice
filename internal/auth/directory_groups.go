package auth

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"alice/internal/audit"
	"alice/internal/platform/validate"
)

// ErrNoAccess: an SSO or directory user none of whose groups is mapped to a global role, and whom no role binding
// reaches, neither their own nor one of a directory group they are in (design §6.1, R54). The sign-in or step-up is
// refused with the reason no_access, as before scoped access when no group was mapped.
var ErrNoAccess = errors.New("auth: no group of the user is mapped to a role and no role binding reaches the user")

// Bounds of the groups Alice keeps per user (user_directory_groups, migration 00026; design §6.1).
const (
	// MaxDirectoryGroups is how many of a user's groups are kept: the first ones in the order the provider or the
	// directory returned them. The rest are dropped (fewer rights, never more) and the sign-in is audited
	// user.groups_truncated.
	MaxDirectoryGroups = 1000
	// maxGroupValueRunes is the longest group value kept (the column's CHECK); a longer one is dropped like an extra one.
	maxGroupValueRunes = 1024
)

// keptGroups are the group values Alice stores for a sign-in: the first MaxDirectoryGroups distinct values that the
// column can hold (not empty, at most maxGroupValueRunes, storable text), in the order received; dropped counts the
// values left out for the bound or the length (a repeat or an empty value is not counted).
func keptGroups(groups []string) (kept []string, dropped int) {
	seen := map[string]bool{}
	kept = []string{}
	for _, g := range groups {
		if g == "" || seen[g] {
			continue
		}
		seen[g] = true
		if len(kept) >= MaxDirectoryGroups || utf8.RuneCountInString(g) > maxGroupValueRunes || !validate.StorableText(g) {
			dropped++
			continue
		}
		kept = append(kept, g)
	}
	return kept, dropped
}

// directorySubject names whose groups a sign-in brings: the source ("oidc" or "ldap") and the provider or directory.
type directorySubject struct {
	source string
	from   uuid.UUID // the OIDC provider or the LDAP directory
}

// hasScopedAccess reports whether a role binding reaches a signing-in SSO or directory user without a mapped global
// role (design §6.1): one of the user's own (userID; uuid.Nil for a user not provisioned yet), or one of a directory
// group of the user's own provider or directory whose value is among groups (the values this sign-in keeps).
func hasScopedAccess(ctx context.Context, tx pgx.Tx, userID uuid.UUID, d directorySubject, groups []string) (bool, error) {
	var ok bool
	err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM role_bindings WHERE $1::uuid IS NOT NULL AND user_id = $1)
    OR EXISTS (SELECT 1 FROM directory_groups g JOIN role_bindings rb ON rb.directory_group_id = g.id
               WHERE g.source = $2 AND g.value = ANY($4)
                 AND ((g.source = 'oidc' AND g.oidc_provider_id = $3) OR (g.source = 'ldap' AND g.ldap_directory_id = $3)))`,
		nilIfZero(userID), d.source, d.from, groups).Scan(&ok)
	if err != nil {
		return false, fmt.Errorf("read the user's role bindings: %w", err)
	}
	return ok, nil
}

// nilIfZero is a uuid parameter that is NULL for uuid.Nil.
func nilIfZero(id uuid.UUID) any {
	if id == uuid.Nil {
		return nil
	}
	return id
}

// syncDirectoryGroups rewrites the groups Alice keeps for a user (user_directory_groups) inside the sign-in's or the
// step-up's transaction, which holds the user's row lock: the bindings of directory groups reach the user by them
// until the next sign-in or step-up (design §6.1).
func syncDirectoryGroups(ctx context.Context, tx pgx.Tx, userID uuid.UUID, groups []string, now time.Time) error {
	if _, err := tx.Exec(ctx, "DELETE FROM user_directory_groups WHERE user_id = $1", userID); err != nil {
		return fmt.Errorf("store the user's groups: %w", err)
	}
	if len(groups) == 0 {
		return nil
	}
	if _, err := tx.Exec(ctx, `INSERT INTO user_directory_groups (user_id, value, seen_at) SELECT $1, v, $3 FROM unnest($2::text[]) AS v`,
		userID, groups, now); err != nil {
		return fmt.Errorf("store the user's groups: %w", err)
	}
	return nil
}

// groupsTruncated is the audit row of a sign-in or step-up whose groups were cut to MaxDirectoryGroups (or had values
// too long to keep): how many were dropped and how many kept. The user holds fewer rights by them, never more.
func groupsTruncated(actor audit.Actor, userID uuid.UUID, method string, kept, dropped int) audit.Event {
	return audit.Event{Actor: actor, Action: "user.groups_truncated", ObjectType: "user", ObjectID: userID.String(), Result: audit.Success,
		Details: map[string]string{"method": method, "groups_kept": strconv.Itoa(kept), "groups_dropped": strconv.Itoa(dropped)}}
}
