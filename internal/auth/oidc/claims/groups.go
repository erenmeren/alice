package claims

import (
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"alice/internal/rbac"
)

// MaxGroups bounds the groups claim; MaxGroupRunes a mapping's group value.
const (
	MaxGroups     = 1000
	MaxGroupRunes = 256
)

// Errors of Groups and ValidateMapping.
var (
	ErrOverage         = errors.New("claims: the identity provider left the groups out (too many groups)")
	ErrGroupsMalformed = errors.New("claims: the groups claim is not a list of names")
	ErrGroupEmpty      = errors.New("claims: a group mapping needs a group value")
	ErrGroupTooLong    = errors.New("claims: the group value is too long")
	ErrGroupCharacters = errors.New("claims: the group value has white space at its ends or invisible characters")
	ErrRole            = errors.New("claims: the role is not admin, operator or auditor")
	ErrAdminNotAllowed = errors.New("claims: groups cannot be mapped to Administrator while SSO users may not be Admin")
)

// Groups returns the values of the groups claim: a list of strings, or one string (AD FS sends a single group so).
// An Entra overage answer (the claim named in _claim_names, or hasgroups) is ErrOverage, never "no groups".
func Groups(c Claims, claim string) ([]string, error) {
	if v, ok := c.raw["_claim_names"]; ok {
		var names map[string]json.RawMessage
		if json.Unmarshal(v, &names) == nil {
			if _, over := names[claim]; over {
				return nil, ErrOverage
			}
		}
	}
	if v, ok := c.raw["hasgroups"]; ok && strings.TrimSpace(string(v)) == "true" {
		return nil, ErrOverage
	}
	v, ok := c.raw[claim]
	if !ok || isNull(v) {
		return nil, nil
	}
	var one string
	if json.Unmarshal(v, &one) == nil {
		return []string{one}, nil
	}
	var many []string
	if err := json.Unmarshal(v, &many); err != nil || len(many) > MaxGroups {
		return nil, ErrGroupsMalformed
	}
	return many, nil
}

// Mapping maps one group value to a role.
type Mapping struct {
	Group string
	Role  rbac.Role
}

func rank(r rbac.Role) int {
	switch r {
	case rbac.Admin:
		return 3
	case rbac.Operator:
		return 2
	case rbac.Auditor:
		return 1
	default:
		return 0
	}
}

// ResolveRole is the highest role mapped to any of the groups (exact, case-sensitive match). Administrator is
// capped at Operator unless adminAllowed (SEC-014). ok is false when no group is mapped: no default role (O-06).
func ResolveRole(groups []string, mappings []Mapping, adminAllowed bool) (rbac.Role, bool) {
	var best rbac.Role
	for _, m := range mappings {
		if rank(m.Role) > rank(best) && slices.Contains(groups, m.Group) {
			best = m.Role
		}
	}
	if best == "" {
		return "", false
	}
	if best == rbac.Admin && !adminAllowed {
		best = rbac.Operator
	}
	return best, true
}

// ValidateMapping refuses an empty or invisible-character group value, an unknown role, and Administrator while the
// switch is off (O-13).
func ValidateMapping(m Mapping, adminAllowed bool) error {
	switch {
	case strings.TrimSpace(m.Group) == "":
		return ErrGroupEmpty
	case !utf8.ValidString(m.Group) || m.Group != strings.TrimSpace(m.Group) || strings.IndexFunc(m.Group, invisible) >= 0:
		return ErrGroupCharacters
	case utf8.RuneCountInString(m.Group) > MaxGroupRunes:
		return ErrGroupTooLong
	case rank(m.Role) == 0:
		return ErrRole
	case m.Role == rbac.Admin && !adminAllowed:
		return ErrAdminNotAllowed
	}
	return nil
}

func invisible(r rune) bool {
	return unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == utf8.RuneError
}
