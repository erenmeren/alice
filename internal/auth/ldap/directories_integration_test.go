//go:build integration

package ldap_test

import (
	"bytes"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/audit"
	"alice/internal/auth"
	"alice/internal/auth/ldap"
	"alice/internal/auth/oidc"
	"alice/internal/platform/validate"
	"alice/internal/rbac"
	"alice/internal/secrets"
	"alice/internal/testutil/fakeldap"
)

func fieldNames(t *testing.T, err error) []string {
	t.Helper()
	var v validate.Errors
	require.True(t, errors.As(err, &v), "%v", err)
	var out []string
	for _, f := range v {
		out = append(out, f.Field)
	}
	return out
}

func TestCreateDirectoryDefaultsAndReads(t *testing.T) {
	x := newHarness(t)
	d := x.dir
	assert.True(t, d.Enabled)
	assert.True(t, d.MFARequired, "MFA is on by default")
	assert.True(t, d.BindPasswordSet)
	assert.Equal(t, 1, d.Version)
	assert.Equal(t, 1, x.count(t, `SELECT count(*) FROM audit_log WHERE action = 'ldap.directory_created' AND details->>'bind_set' = 'true'`))

	in := x.input("Second", false)
	in.GroupFilter = ""
	off, err := x.svc.CreateDirectory(x.ctx, x.admin, in)
	require.NoError(t, err)
	assert.False(t, off.Enabled, "created switched off unless enabled")
	assert.Equal(t, ldap.DefaultGroupFilter, off.GroupFilter)
	in = x.input("Third", false)
	in.MFARequired = ptr(false)
	third, err := x.svc.CreateDirectory(x.ctx, x.admin, in)
	require.NoError(t, err)
	assert.False(t, third.MFARequired)

	got, err := x.svc.Directory(x.ctx, d.ID)
	require.NoError(t, err)
	assert.Equal(t, d, got)
	all, err := x.svc.Directories(x.ctx)
	require.NoError(t, err)
	require.Len(t, all, 3)
	assert.Equal(t, []string{"Corp LDAP", "Second", "Third"}, []string{all[0].Name, all[1].Name, all[2].Name})
	public, err := x.svc.PublicDirectories(x.ctx)
	require.NoError(t, err)
	assert.Equal(t, []ldap.PublicDirectory{{ID: d.ID, Name: "Corp LDAP"}}, public, "only enabled directories")
	_, err = x.svc.Directory(x.ctx, [16]byte{1})
	assert.ErrorIs(t, err, ldap.ErrNotFound)

	_, err = x.svc.CreateDirectory(x.ctx, x.admin, x.input("Fourth", false))
	assert.ErrorIs(t, err, ldap.ErrTooMany)
}

func TestDirectoryNameIsUniqueCaseInsensitively(t *testing.T) {
	x := newHarness(t)
	_, err := x.svc.CreateDirectory(x.ctx, x.admin, x.input("CORP ldap", false))
	assert.Equal(t, []string{"name"}, fieldNames(t, err))
	other := x.create(t, "Other", false)
	_, err = x.svc.UpdateDirectory(x.ctx, x.admin, other.ID, other.Version, ldap.DirectoryPatch{Name: ptr("corp LDAP")})
	assert.Equal(t, []string{"name"}, fieldNames(t, err))
}

func TestCreateDirectoryValidation(t *testing.T) {
	x := newHarness(t)
	in := x.input("", false)
	in.Addresses = []string{"ldaps://x:0"}
	in.UserFilter = "(uid={login})(cn=*)"
	in.GroupFilter = "(objectClass=group)"
	in.BindPassword = secrets.Plaintext{}
	in.CAPEM = "nope"
	_, err := x.svc.CreateDirectory(x.ctx, x.admin, in)
	assert.Equal(t, []string{"name", "addresses", "user_filter", "bind_password", "group_filter", "ca_pem"}, fieldNames(t, err))
	assert.Equal(t, 1, x.count(t, "SELECT count(*) FROM ldap_directories"))
}

// The service account password is only an envelope; no row, audit record or setting holds it.
func TestBindPasswordIsAnEnvelope(t *testing.T) {
	x := newHarness(t)
	var dump string
	require.NoError(t, x.d.Owner.QueryRow(x.ctx, `SELECT (SELECT string_agg(t::text, ' ') FROM ldap_directories t) ||
(SELECT coalesce(string_agg(details::text, ' '), '') FROM audit_log) || (SELECT coalesce(string_agg(value::text, ' '), '') FROM settings)`).Scan(&dump))
	assert.NotContains(t, dump, x.srv.ServicePassword())
	var ct []byte
	require.NoError(t, x.d.Owner.QueryRow(x.ctx, `SELECT ciphertext FROM setting_secrets WHERE key = $1`,
		"ldap.directory."+x.dir.ID.String()+".bind_password").Scan(&ct))
	assert.False(t, bytes.Contains(ct, []byte(x.srv.ServicePassword())))
	p, ok, err := x.kr.GetSetting(x.ctx, x.d.App, "ldap.directory."+x.dir.ID.String()+".bind_password")
	require.NoError(t, err)
	require.True(t, ok)
	assert.Equal(t, x.srv.ServicePassword(), string(p.Bytes()))
}

func TestUpdateDirectoryVersionsAndPassword(t *testing.T) {
	x := newHarness(t)
	d := x.update(t, ldap.DirectoryPatch{Name: ptr("Renamed"), MFARequired: ptr(false), BindPassword: secretPtr("new-bind-pw")})
	assert.Equal(t, [3]any{"Renamed", false, 2}, [3]any{d.Name, d.MFARequired, d.Version})
	assert.Equal(t, 1, x.count(t, `SELECT count(*) FROM audit_log WHERE action = 'ldap.directory_changed' AND details->>'bind_replaced' = 'true'`))
	_, err := x.svc.UpdateDirectory(x.ctx, x.admin, d.ID, 1, ldap.DirectoryPatch{Name: ptr("Stale")})
	assert.ErrorIs(t, err, ldap.ErrVersion)
	_, err = x.svc.UpdateDirectory(x.ctx, x.admin, [16]byte{9}, 1, ldap.DirectoryPatch{})
	assert.ErrorIs(t, err, ldap.ErrNotFound)
	_, err = x.svc.UpdateDirectory(x.ctx, x.admin, d.ID, d.Version, ldap.DirectoryPatch{UserBaseDN: ptr("not a dn")})
	assert.Equal(t, []string{"user_base_dn"}, fieldNames(t, err))
	// Other fields keep the stored password.
	d = x.update(t, ldap.DirectoryPatch{UserBaseDN: ptr(fakeldap.BaseDN), MFARequired: ptr(true)})
	assert.Equal(t, 3, d.Version)
	assert.True(t, d.BindPasswordSet)
}

// The stored password is never sent to another server or account: a new address, bind DN or unique id attribute
// needs it again (a 422 on bind_password before anything is stored or dialled).
func TestChangesThatNeedTheBindPasswordAgain(t *testing.T) {
	x := newHarness(t)
	for name, p := range map[string]ldap.DirectoryPatch{
		"address added":    {Addresses: &[]string{x.srv.Address, "ldaps://evil.example.test"}},
		"address replaced": {Addresses: &[]string{"ldaps://evil.example.test"}},
		"bind dn":          {BindDN: ptr("cn=other," + fakeldap.ServicesDN)},
		"unique id":        {UniqueIDAttribute: ptr("uid")},
		"ca changed":       {CAPEM: ptr(string(x.srv.CAPEM) + "\n")},
		"ca cleared":       {CAPEM: ptr("")},
		"given but empty":  {BindPassword: &secrets.Plaintext{}},
	} {
		_, err := x.svc.UpdateDirectory(x.ctx, x.admin, x.dir.ID, x.dir.Version, p)
		var v validate.Errors
		require.True(t, errors.As(err, &v), "%s: %v", name, err)
		assert.Equal(t, validate.FieldError{Field: "bind_password", Code: validate.Required}, v[0], name)
	}
	got, err := x.svc.Directory(x.ctx, x.dir.ID)
	require.NoError(t, err)
	assert.Equal(t, x.dir, got, "nothing changed")
	assert.Zero(t, x.dials.Load())
	// Removing an address sends nothing anywhere new: no password needed.
	x.update(t, ldap.DirectoryPatch{Addresses: &[]string{x.srv.Address, "ldaps://dc2.example.test"}, BindPassword: secretPtr(x.srv.ServicePassword())})
	d := x.update(t, ldap.DirectoryPatch{Addresses: &[]string{x.srv.Address}})
	assert.Equal(t, []string{x.srv.Address}, d.Addresses)
	d = x.update(t, ldap.DirectoryPatch{UniqueIDAttribute: ptr("entryUUID"), BindDN: ptr(fakeldap.ServiceDN)})
	assert.Equal(t, 4, d.Version, "unchanged values need no password")
}

func TestDirectoryInUse(t *testing.T) {
	x := newHarness(t)
	x.seedUser(t, x.dir.ID)
	assert.ErrorIs(t, x.svc.DeleteDirectory(x.ctx, x.admin, x.dir.ID, x.dir.Version), ldap.ErrDirectoryInUse)
	// Only the unique id attribute is frozen while the directory has users: its users are matched by its value.
	_, err := x.svc.UpdateDirectory(x.ctx, x.admin, x.dir.ID, x.dir.Version, ldap.DirectoryPatch{UniqueIDAttribute: ptr("uid"),
		BindPassword: secretPtr("pw")})
	assert.ErrorIs(t, err, ldap.ErrDirectoryInUse)

	// Addresses: adding one needs the password and is audited with the count; removing and reordering need nothing.
	_, err = x.svc.UpdateDirectory(x.ctx, x.admin, x.dir.ID, x.dir.Version, ldap.DirectoryPatch{
		Addresses: &[]string{x.srv.Address, "ldaps://dc2.example.test", "ldaps://dc3.example.test"}})
	assert.Equal(t, []string{"bind_password"}, fieldNames(t, err), "a new address needs the password again")
	d := x.update(t, ldap.DirectoryPatch{Addresses: &[]string{x.srv.Address, "ldaps://dc2.example.test", "ldaps://dc3.example.test"},
		BindPassword: secretPtr(x.srv.ServicePassword())})
	assert.Len(t, d.Addresses, 3)
	var added string
	require.NoError(t, x.d.Owner.QueryRow(x.ctx, `SELECT details->>'addresses_added_count' FROM audit_log
WHERE action = 'ldap.directory_changed' ORDER BY seq DESC LIMIT 1`).Scan(&added))
	assert.Equal(t, "2", added)
	d = x.update(t, ldap.DirectoryPatch{Addresses: &[]string{"ldaps://dc3.example.test", x.srv.Address}})
	assert.Equal(t, []string{"ldaps://dc3.example.test", x.srv.Address}, d.Addresses, "removed and reordered without the password")
	assert.Equal(t, 0, x.count(t, `SELECT count(*) FROM audit_log WHERE action = 'ldap.directory_changed' AND seq = (SELECT max(seq) FROM audit_log)
AND details ? 'addresses_added_count'`))

	d = x.update(t, ldap.DirectoryPatch{Enabled: ptr(false), Name: ptr("Old LDAP"), BindDN: ptr(fakeldap.ServiceDN)})
	assert.False(t, d.Enabled, "switch it off instead")
	public, err := x.svc.PublicDirectories(x.ctx)
	require.NoError(t, err)
	assert.Empty(t, public)
}

// A first sign-in that inserts its user while a unique id attribute change waits for the directory's row lock is seen,
// and the change is refused.
func TestUniqueIDChangeRefusedOnceAUserArrives(t *testing.T) {
	x := newHarness(t)
	tx, err := x.d.Owner.Begin(x.ctx)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback(x.ctx) }()
	_, err = tx.Exec(x.ctx, `INSERT INTO users (id, username, display_name, auth_source, role, role_source, ldap_directory_id,
ldap_unique_id, ldap_login, created_at, updated_at) VALUES ($1, 'late', 'Late', 'ldap', 'auditor', 'ldap_mapping', $2, 'abcd', 'late', now(), now())`,
		uuid.New(), x.dir.ID)
	require.NoError(t, err)
	done := make(chan error, 1)
	go func() {
		_, err := x.svc.UpdateDirectory(x.ctx, x.admin, x.dir.ID, x.dir.Version, ldap.DirectoryPatch{
			UniqueIDAttribute: ptr("uid"), BindPassword: secretPtr("pw")})
		done <- err
	}()
	require.Eventually(t, func() bool { return x.count(t, `SELECT count(*) FROM pg_locks WHERE NOT granted`) > 0 },
		10*time.Second, 10*time.Millisecond, "the change waits on the directory's row")
	require.NoError(t, tx.Commit(x.ctx))
	assert.ErrorIs(t, <-done, ldap.ErrDirectoryInUse)
}

func TestDeleteDirectory(t *testing.T) {
	x := newHarness(t)
	_, err := x.svc.CreateMapping(x.ctx, x.admin, x.dir.ID, "alice-ops", rbac.Operator)
	require.NoError(t, err)
	assert.ErrorIs(t, x.svc.DeleteDirectory(x.ctx, x.admin, x.dir.ID, x.dir.Version+1), ldap.ErrVersion)
	require.NoError(t, x.svc.DeleteDirectory(x.ctx, x.admin, x.dir.ID, x.dir.Version))
	assert.ErrorIs(t, x.svc.DeleteDirectory(x.ctx, x.admin, x.dir.ID, x.dir.Version), ldap.ErrNotFound)
	assert.Zero(t, x.count(t, `SELECT count(*) FROM setting_secrets WHERE key = $1`, "ldap.directory."+x.dir.ID.String()+".bind_password"))
	assert.Zero(t, x.count(t, `SELECT count(*) FROM ldap_group_mappings`), "mappings go with the directory")
	assert.Equal(t, 1, x.count(t, `SELECT count(*) FROM audit_log WHERE action = 'ldap.directory_deleted' AND details->>'name' = 'Corp LDAP'`))
}

// At most MaxDirectories, counted under a lock: concurrent creations cannot overshoot.
func TestCreateDirectoryLimitUnderConcurrency(t *testing.T) {
	x := newHarness(t)
	const n = 6
	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := range n {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, errs[i] = x.svc.CreateDirectory(x.ctx, x.admin, x.input("Parallel "+string(rune('A'+i)), false))
		}(i)
	}
	wg.Wait()
	ok, tooMany := 0, 0
	for _, err := range errs {
		switch {
		case err == nil:
			ok++
		case errors.Is(err, ldap.ErrTooMany):
			tooMany++
		default:
			t.Errorf("unexpected: %v", err)
		}
	}
	assert.Equal(t, [2]int{ldap.MaxDirectories - 1, n - ldap.MaxDirectories + 1}, [2]int{ok, tooMany})
	assert.Equal(t, ldap.MaxDirectories, x.count(t, "SELECT count(*) FROM ldap_directories"))
}

// allowAdmin stores the "SSO users may be Admin" switch as the oidc package does.
func (x *harness) allowAdmin(t *testing.T, allow bool) {
	t.Helper()
	_, err := x.d.Owner.Exec(x.ctx, `INSERT INTO settings (key, value, updated_at) VALUES ($1, jsonb_build_object('allow', $2::boolean, 'version', 1), now())
ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value`, auth.SSOAllowAdminKey, allow)
	require.NoError(t, err)
}

func TestAdminMappingRefusedWhileOff(t *testing.T) {
	x := newHarness(t)
	_, err := x.svc.CreateMapping(x.ctx, x.admin, x.dir.ID, "admins", rbac.Admin)
	assert.ErrorIs(t, err, ldap.ErrAdminMappingDisabled)
	assert.Equal(t, 1, x.count(t, `SELECT count(*) FROM audit_log WHERE action = 'ldap.mapping.denied' AND details->>'reason' = 'admin_disabled'
AND result = 'denied'`))
	x.allowAdmin(t, true)
	m, err := x.svc.CreateMapping(x.ctx, x.admin, x.dir.ID, "admins", rbac.Admin)
	require.NoError(t, err)
	assert.Equal(t, 1, x.count(t, `SELECT count(*) FROM audit_log WHERE action = 'ldap.mapping_created' AND details->>'role' = 'admin'`))
	role, ok, err := x.svc.ResolveRole(x.ctx, x.dir.ID, []string{"admins", "other"})
	require.NoError(t, err)
	assert.Equal(t, [2]any{rbac.Admin, true}, [2]any{role, ok})

	// The switch cannot go off while a directory group is mapped to Administrator (the oidc service owns the switch).
	kr, err := secrets.NewKeyring(1, bytes.Repeat([]byte{7}, 32))
	require.NoError(t, err)
	h := auth.NewHasher(auth.Argon2Params{MemoryKiB: 64, Time: 1, Threads: 1, SaltLen: 16, KeyLen: 32}, 4)
	a := auth.NewService(auth.Config{Pool: x.d.App, Keyring: kr, Audit: audit.New(x.clk), Clock: x.clk, Hasher: h, RecoveryHasher: h})
	sso := oidc.New(oidc.Config{Pool: x.d.App, Keyring: kr, Audit: audit.New(x.clk), Clock: x.clk, Auth: a})
	_, err = sso.SaveSettings(x.ctx, x.admin, 1, false)
	assert.ErrorIs(t, err, oidc.ErrAdminMappingsExist)
	require.NoError(t, x.svc.DeleteMapping(x.ctx, x.admin, m.ID))
	_, err = sso.SaveSettings(x.ctx, x.admin, 1, false)
	require.NoError(t, err)
	// Off again: a stored Admin mapping would be capped at Operator (claims.ResolveRole).
	_, err = x.d.Owner.Exec(x.ctx, `INSERT INTO ldap_group_mappings (id, directory_id, group_value, role, created_at)
VALUES ($1, $2, 'legacy-admins', 'admin', now())`, uuid.New(), x.dir.ID)
	require.NoError(t, err)
	role, ok, err = x.svc.ResolveRole(x.ctx, x.dir.ID, []string{"legacy-admins"})
	require.NoError(t, err)
	assert.Equal(t, [2]any{rbac.Operator, true}, [2]any{role, ok})
	_, ok, err = x.svc.ResolveRole(x.ctx, x.dir.ID, []string{"unmapped"})
	require.NoError(t, err)
	assert.False(t, ok, "no mapped group, no role")
}

func TestMappings(t *testing.T) {
	x := newHarness(t)
	dn := "cn=" + strings.Repeat("g", 1021)
	_, err := x.svc.CreateMapping(x.ctx, x.admin, x.dir.ID, dn, rbac.Auditor)
	require.NoError(t, err, "a group DN of 1024 characters")
	_, err = x.svc.CreateMapping(x.ctx, x.admin, x.dir.ID, dn+"g", rbac.Auditor)
	assert.Equal(t, []string{"group"}, fieldNames(t, err))
	ops, err := x.svc.CreateMapping(x.ctx, x.admin, x.dir.ID, fakeldap.OpsDN, rbac.Operator)
	require.NoError(t, err)
	_, err = x.svc.CreateMapping(x.ctx, x.admin, x.dir.ID, fakeldap.OpsDN, rbac.Auditor)
	var v validate.Errors
	require.True(t, errors.As(err, &v))
	assert.Equal(t, validate.FieldError{Field: "group", Code: validate.Duplicate}, v[0])
	_, err = x.svc.CreateMapping(x.ctx, x.admin, x.dir.ID, fakeldap.OpsDN+" ", rbac.Auditor)
	assert.Equal(t, []string{"group"}, fieldNames(t, err), "white space at the ends")
	_, err = x.svc.CreateMapping(x.ctx, x.admin, x.dir.ID, "ops", rbac.Role("root"))
	assert.Equal(t, []string{"role"}, fieldNames(t, err))
	_, err = x.svc.CreateMapping(x.ctx, x.admin, [16]byte{3}, "ops", rbac.Operator)
	assert.ErrorIs(t, err, ldap.ErrNotFound)
	ms, err := x.svc.Mappings(x.ctx, x.dir.ID)
	require.NoError(t, err)
	require.Len(t, ms, 2)
	assert.Equal(t, [2]string{fakeldap.OpsDN, dn}, [2]string{ms[0].Group, ms[1].Group}, "by group value")
	assert.Equal(t, ops, ms[0])
	require.NoError(t, x.svc.DeleteMapping(x.ctx, x.admin, ops.ID))
	assert.ErrorIs(t, x.svc.DeleteMapping(x.ctx, x.admin, ops.ID), ldap.ErrNotFound)
	assert.Equal(t, 1, x.count(t, `SELECT count(*) FROM audit_log WHERE action = 'ldap.mapping_deleted' AND details->>'group' = $1`, fakeldap.OpsDN))
	for i := 1; i < ldap.MaxMappings; i++ {
		_, err := x.d.Owner.Exec(x.ctx, `INSERT INTO ldap_group_mappings (id, directory_id, group_value, role, created_at)
VALUES ($1, $2, $3, 'auditor', now())`, uuid.New(), x.dir.ID, "bulk-"+uuid.NewString())
		require.NoError(t, err)
	}
	_, err = x.svc.CreateMapping(x.ctx, x.admin, x.dir.ID, "one-too-many", rbac.Auditor)
	assert.ErrorIs(t, err, ldap.ErrTooMany)
}

// The mapping create takes the switch row FOR UPDATE, so it serializes with a switch-off.
func TestMappingCreateWaitsForTheSwitch(t *testing.T) {
	x := newHarness(t)
	x.allowAdmin(t, true)
	tx, err := x.d.Owner.Begin(x.ctx)
	require.NoError(t, err)
	_, err = tx.Exec(x.ctx, `SELECT 1 FROM settings WHERE key = $1 FOR UPDATE`, ldap.AllowAdminKey)
	require.NoError(t, err)
	done := make(chan error, 1)
	go func() {
		_, err := x.svc.CreateMapping(x.ctx, x.admin, x.dir.ID, "admins", rbac.Admin)
		done <- err
	}()
	select {
	case err := <-done:
		t.Fatalf("CreateMapping did not wait for the setting row: %v", err)
	case <-time.After(300 * time.Millisecond):
	}
	_, err = tx.Exec(x.ctx, `UPDATE settings SET value = '{"allow": false, "version": 2}' WHERE key = $1`, ldap.AllowAdminKey)
	require.NoError(t, err)
	require.NoError(t, tx.Commit(x.ctx))
	assert.ErrorIs(t, <-done, ldap.ErrAdminMappingDisabled)
}

// Switching a directory off ends its users' sessions and API tokens in the same transaction (audited with
// signed_out_count and one user.sessions_ended per user, by the Administrator); other changes, and switching it on
// again, end nothing.
func TestSwitchingADirectoryOffEndsItsUsersAccess(t *testing.T) {
	x := newHarness(t)
	signIn := func(uniqueID, login string) {
		_, err := x.auth.SignInLDAP(x.ctx, auth.LDAPIdentity{DirectoryID: x.dir.ID, UniqueID: uniqueID, Login: login}, rbac.Operator, false, auth.Meta{})
		require.NoError(t, err)
	}
	signIn("a1", "ada")
	signIn("a1", "ada")
	signIn("b2", "berk")
	live := func() int {
		return x.count(t, `SELECT count(*) FROM sessions s JOIN users u ON u.id = s.user_id WHERE u.ldap_directory_id = $1 AND s.revoked_at IS NULL`, x.dir.ID)
	}
	require.Equal(t, 3, live())
	lastChange := func(key string) string {
		var v *string
		require.NoError(t, x.d.Owner.QueryRow(x.ctx, `SELECT details->>$1 FROM audit_log WHERE action = 'ldap.directory_changed'
ORDER BY seq DESC LIMIT 1`, key).Scan(&v))
		if v == nil {
			return "-"
		}
		return *v
	}

	x.update(t, ldap.DirectoryPatch{Name: ptr("Corp LDAP (renamed)")})
	assert.Equal(t, 3, live(), "another change ends nothing")
	assert.Equal(t, "-", lastChange("signed_out_count"))

	x.update(t, ldap.DirectoryPatch{Enabled: ptr(false)})
	assert.Zero(t, live())
	assert.Equal(t, "2", lastChange("signed_out_count"))
	assert.Equal(t, 2, x.count(t, `SELECT count(*) FROM audit_log WHERE action = 'user.sessions_ended' AND actor_name = 'ada-admin'
AND details->>'reason' = 'provider_disabled'`))

	x.update(t, ldap.DirectoryPatch{Name: ptr("Corp LDAP")})
	assert.Equal(t, "-", lastChange("signed_out_count"), "already off: nothing to end")
	x.update(t, ldap.DirectoryPatch{Enabled: ptr(true)})
	assert.Equal(t, "-", lastChange("signed_out_count"))
	assert.Equal(t, 2, x.count(t, `SELECT count(*) FROM audit_log WHERE action = 'user.sessions_ended'`))
}
