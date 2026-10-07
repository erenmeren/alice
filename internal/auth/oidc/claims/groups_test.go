package claims

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/rbac"
)

func TestGroupsReadsListsAndSingleStrings(t *testing.T) {
	c, err := Parse(payload(t, func(m map[string]any) { m["groups"] = []string{"ops", "/alice/admins"} }))
	require.NoError(t, err)
	g, err := Groups(c, "groups")
	require.NoError(t, err)
	assert.Equal(t, []string{"ops", "/alice/admins"}, g)

	c, err = Parse(payload(t, func(m map[string]any) { m["group"] = "ADFS-Operators" })) // AD FS sends one group as a string
	require.NoError(t, err)
	g, err = Groups(c, "group")
	require.NoError(t, err)
	assert.Equal(t, []string{"ADFS-Operators"}, g)

	c, err = Parse(payload(t, nil))
	require.NoError(t, err)
	g, err = Groups(c, "groups")
	require.NoError(t, err)
	assert.Empty(t, g, "no claim: no groups")

	c, err = Parse(payload(t, func(m map[string]any) { m["groups"] = nil }))
	require.NoError(t, err)
	g, err = Groups(c, "groups")
	require.NoError(t, err)
	assert.Empty(t, g)
}

// Review Focus 1, O-07: an Entra overage answer is detected and never read as "no groups".
func TestGroupsDetectsOverage(t *testing.T) {
	c, err := Parse(payload(t, func(m map[string]any) {
		m["_claim_names"] = map[string]any{"groups": "src1"}
		m["_claim_sources"] = map[string]any{"src1": map[string]any{"endpoint": "https://graph.microsoft.com/v1.0/users/x/getMemberObjects"}}
	}))
	require.NoError(t, err)
	_, err = Groups(c, "groups")
	assert.ErrorIs(t, err, ErrOverage)

	c, err = Parse(payload(t, func(m map[string]any) { m["hasgroups"] = true }))
	require.NoError(t, err)
	_, err = Groups(c, "groups")
	assert.ErrorIs(t, err, ErrOverage)

	c, err = Parse(payload(t, func(m map[string]any) { m["_claim_names"] = map[string]any{"roles": "src1"} }))
	require.NoError(t, err)
	_, err = Groups(c, "groups")
	assert.NoError(t, err, "an overage of another claim does not matter")
}

func TestGroupsRefusesMalformedValues(t *testing.T) {
	big := make([]string, MaxGroups+1)
	for i := range big {
		big[i] = "g"
	}
	for _, v := range []any{42, []any{"a", 1}, map[string]any{"a": "b"}, big} {
		c, err := Parse(payload(t, func(m map[string]any) { m["groups"] = v }))
		require.NoError(t, err)
		_, err = Groups(c, "groups")
		assert.ErrorIs(t, err, ErrGroupsMalformed)
	}
}

func TestResolveRoleCapsAdmin(t *testing.T) {
	maps := []Mapping{{"ops", rbac.Operator}, {"audit", rbac.Auditor}, {"admins", rbac.Admin}}
	cases := []struct {
		groups []string
		allow  bool
		want   rbac.Role
		ok     bool
	}{
		{[]string{"audit"}, false, rbac.Auditor, true},
		{[]string{"audit", "ops"}, false, rbac.Operator, true},
		{[]string{"admins"}, true, rbac.Admin, true},
		{[]string{"admins", "audit"}, false, rbac.Operator, true}, // SEC-014: capped at Operator
		{[]string{"Ops"}, false, "", false},                       // exact, case-sensitive match
		{[]string{"unmapped"}, true, "", false},                   // O-06: no default role
		{nil, true, "", false},
	}
	for _, c := range cases {
		got, ok := ResolveRole(c.groups, maps, c.allow)
		assert.Equal(t, c.ok, ok, "%v", c.groups)
		assert.Equal(t, c.want, got, "%v", c.groups)
	}
}

// O-13: no "all users" mapping, no Admin while the switch is off.
func TestValidateMapping(t *testing.T) {
	long := make([]rune, MaxGroupRunes+1)
	for i := range long {
		long[i] = 'ğ'
	}
	cases := []struct {
		m     Mapping
		allow bool
		want  error
	}{
		{Mapping{"ops", rbac.Operator}, false, nil},
		{Mapping{"admins", rbac.Admin}, true, nil},
		{Mapping{"admins", rbac.Admin}, false, ErrAdminNotAllowed},
		{Mapping{"", rbac.Auditor}, true, ErrGroupEmpty},
		{Mapping{"   ", rbac.Auditor}, true, ErrGroupEmpty},
		{Mapping{" ops", rbac.Auditor}, true, ErrGroupCharacters},
		{Mapping{"ops\n", rbac.Auditor}, true, ErrGroupCharacters},
		{Mapping{"o\u202eps", rbac.Auditor}, true, ErrGroupCharacters},
		{Mapping{"o\x00ps", rbac.Auditor}, true, ErrGroupCharacters},
		{Mapping{string([]byte{0xff}), rbac.Auditor}, true, ErrGroupCharacters},
		{Mapping{string(long), rbac.Auditor}, true, ErrGroupTooLong},
		{Mapping{"ops", rbac.Role("owner")}, true, ErrRole},
		{Mapping{"ops", ""}, true, ErrRole},
	}
	for _, c := range cases {
		err := ValidateMapping(c.m, c.allow)
		if c.want == nil {
			assert.NoError(t, err, "%q", c.m.Group)
		} else {
			assert.ErrorIs(t, err, c.want, "%q", c.m.Group)
		}
	}
}
