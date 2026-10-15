//go:build integration

package migrations_test

import (
	"context"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/testutil/pgtest"
	"alice/migrations"
)

// ldapDownRefused is the SQLSTATE of 00015's Down guard.
const ldapDownRefused = "Z1021"

// ldapDirectory is a valid directory row; a test changes one field to see the CHECK refuse it.
type ldapDirectory struct {
	name, userBaseDN, userFilter, loginAttr, uniqueAttr, displayAttr, emailAttr string
	bindDN, groupBaseDN, groupFilter, groupNameAttr, caPEM                      string
	addresses                                                                   []string
}

func validLDAPDirectory(name string) ldapDirectory {
	return ldapDirectory{
		name: name, addresses: []string{"ldaps://dc1.corp.example.com:636", "ldaps://dc2.corp.example.com"},
		userBaseDN: "ou=people,dc=corp,dc=example,dc=com", userFilter: "(&(objectClass=person)(uid={login}))",
		loginAttr: "uid", uniqueAttr: "entryUUID", displayAttr: "cn", emailAttr: "mail",
		bindDN: "cn=alice,ou=services,dc=corp,dc=example,dc=com", groupBaseDN: "ou=groups,dc=corp,dc=example,dc=com",
		groupFilter: "(member={dn})", groupNameAttr: "cn",
	}
}

func insertLDAPDirectory(t *testing.T, d *pgtest.DB, dir ldapDirectory) (uuid.UUID, error) {
	t.Helper()
	id := uuid.Must(uuid.NewV7())
	return id, exec(t, d.App, `INSERT INTO ldap_directories (id, name, addresses, user_base_dn, user_filter, login_attribute,
unique_id_attribute, display_name_attribute, email_attribute, bind_dn, group_base_dn, group_filter, group_name_attribute, ca_pem,
created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, now(), now())`,
		id, dir.name, dir.addresses, dir.userBaseDN, dir.userFilter, dir.loginAttr, dir.uniqueAttr, dir.displayAttr, dir.emailAttr,
		dir.bindDN, dir.groupBaseDN, dir.groupFilter, dir.groupNameAttr, dir.caPEM)
}

func seedLDAPDirectory(t *testing.T, d *pgtest.DB, name string) uuid.UUID {
	t.Helper()
	id, err := insertLDAPDirectory(t, d, validLDAPDirectory(name))
	require.NoError(t, err)
	return id
}

// insertLDAPUser inserts a directory user with the given fields (nil for NULL).
func insertLDAPUser(t *testing.T, d *pgtest.DB, name string, directory, uniqueID, password any, breakGlass bool, roleSource string) error {
	t.Helper()
	return exec(t, d.App, `INSERT INTO users (id, username, display_name, auth_source, password_hash, role, role_source, is_break_glass,
ldap_directory_id, ldap_unique_id, created_at, updated_at)
VALUES ($1, $2::text, $2::text, 'ldap', $3, 'operator', $4, $5, $6, $7, now(), now())`,
		uuid.New(), name, password, roleSource, breakGlass, directory, uniqueID)
}

func TestLDAPDirectoryDefaultsAndName(t *testing.T) {
	d := pgtest.New(t)
	id := seedLDAPDirectory(t, d, "Corp AD")
	var (
		mfa, enabled bool
		version      int
		caPEM        string
	)
	require.NoError(t, d.App.QueryRow(context.Background(),
		`SELECT mfa_required, enabled, version, ca_pem FROM ldap_directories WHERE id = $1`, id).Scan(&mfa, &enabled, &version, &caPEM))
	assert.True(t, mfa, "Alice's own TOTP is asked for by default")
	assert.False(t, enabled, "a new directory does not allow sign-in")
	assert.Equal(t, 1, version)
	assert.Empty(t, caPEM)

	_, err := insertLDAPDirectory(t, d, validLDAPDirectory("CORP ad"))
	assert.Equal(t, "23505", sqlState(err), "names are unique ignoring case")
	_, err = insertLDAPDirectory(t, d, validLDAPDirectory(strings.Repeat("ç", 60)))
	require.NoError(t, err, "60 characters")
	for _, bad := range []string{"", strings.Repeat("ç", 61)} {
		_, err := insertLDAPDirectory(t, d, validLDAPDirectory(bad))
		assert.Equal(t, "23514", sqlState(err), "name %q", bad)
	}
	assert.Equal(t, "23514", sqlState(exec(t, d.App, `UPDATE ldap_directories SET version = 0 WHERE id = $1`, id)))
}

func TestLDAPDirectoryAddressesAreLDAPSOnly(t *testing.T) {
	d := pgtest.New(t)
	ok := func(addrs ...string) error {
		dir := validLDAPDirectory("dir-" + uuid.NewString()[:8])
		dir.addresses = addrs
		_, err := insertLDAPDirectory(t, d, dir)
		return err
	}
	require.NoError(t, ok("ldaps://dc1.corp.example.com"))
	require.NoError(t, ok("ldaps://10.0.0.5:636", "ldaps://[fd00::5]:636", "ldaps://dc3"))
	for _, bad := range [][]string{
		{},
		{"ldap://dc1.corp.example.com"},
		{"ldaps://dc1.corp.example.com/dc=corp"},
		{"ldaps://dc1.corp.example.com/"},
		{"ldaps://dc1.corp.example.com?x"},
		{"ldaps://dc1.corp.example.com#x"},
		{"ldaps://dc1 .corp.example.com"},
		{"ldaps://dc1.corp.example.com\n"},
		{"ldaps://"},
		{"LDAPS://dc1.corp.example.com"},
		{"starttls://dc1"},
		{"ldaps://a", "ldaps://b", "ldaps://c", "ldaps://d"},
		{"ldaps://a", "ldap://b"},
		{"ldaps://user@dc1"},
	} {
		assert.Equal(t, "23514", sqlState(ok(bad...)), "%q", bad)
	}
	// A NULL element and a two-dimensional array are not address lists either.
	dir := validLDAPDirectory("nulls")
	_, err := insertLDAPDirectory(t, d, dir)
	require.NoError(t, err)
	assert.Equal(t, "23514", sqlState(exec(t, d.App, `UPDATE ldap_directories SET addresses = ARRAY['ldaps://a', NULL] WHERE name = 'nulls'`)))
	assert.Equal(t, "23514", sqlState(exec(t, d.App, `UPDATE ldap_directories SET addresses = ARRAY[['ldaps://a'], ['ldaps://b']] WHERE name = 'nulls'`)))
	assert.Equal(t, "23502", sqlState(exec(t, d.App, `UPDATE ldap_directories SET addresses = NULL WHERE name = 'nulls'`)))
}

func TestLDAPDirectoryFilterPlaceholders(t *testing.T) {
	d := pgtest.New(t)
	try := func(userFilter, groupFilter string) error {
		dir := validLDAPDirectory("dir-" + uuid.NewString()[:8])
		dir.userFilter, dir.groupFilter = userFilter, groupFilter
		_, err := insertLDAPDirectory(t, d, dir)
		return err
	}
	require.NoError(t, try("(sAMAccountName={login})", "(member:1.2.840.113556.1.4.1941:={dn})"))
	require.NoError(t, try("(&(objectClass=user)(sAMAccountName={login}))", "(|(member={dn})(memberUid={login}))"))
	require.NoError(t, try("(uid={login})", "(memberUid={login})"))
	for _, bad := range []string{
		"(uid=ada)",                    // no {login}
		"(uid={LOGIN})",                // the placeholder is lower-case
		"(|(uid={login})(cn={login}))", // twice
		"(uid={login})(cn={dn})",       // {dn} is not a user filter placeholder
		"(uid={login}{)",               // a stray brace
		"(uid={login})}",
		"uid={login}", // a filter is parenthesised
		"",
		"(uid={login}\n)",
	} {
		assert.Equal(t, "23514", sqlState(try(bad, "(member={dn})")), "user filter %q", bad)
	}
	for _, bad := range []string{
		"(member={user})",            // unknown placeholder
		"(member={dn})(x={uid})",     // one unknown among known ones
		"(member={dn}",               // not parenthesised
		"(objectClass=groupOfNames)", // no placeholder: every group for every user
		"(member={dn)",
		"(member=dn})",
		"",
	} {
		assert.Equal(t, "23514", sqlState(try("(uid={login})", bad)), "group filter %q", bad)
	}
}

func TestLDAPDirectoryAttributesAndDNs(t *testing.T) {
	d := pgtest.New(t)
	try := func(change func(*ldapDirectory)) error {
		dir := validLDAPDirectory("dir-" + uuid.NewString()[:8])
		change(&dir)
		_, err := insertLDAPDirectory(t, d, dir)
		return err
	}
	require.NoError(t, try(func(x *ldapDirectory) {
		x.loginAttr, x.uniqueAttr, x.displayAttr, x.emailAttr, x.groupNameAttr = "sAMAccountName", "objectGUID", "", "", ""
	}), "display name, e-mail and group name attributes are optional")
	require.NoError(t, try(func(x *ldapDirectory) { x.uniqueAttr = "1.3.6.1.1.16.4" }), "an OID is an attribute descriptor")
	require.NoError(t, try(func(x *ldapDirectory) { x.caPEM = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n" }))
	for what, change := range map[string]func(*ldapDirectory){
		"empty login attribute":     func(x *ldapDirectory) { x.loginAttr = "" },
		"empty unique id attribute": func(x *ldapDirectory) { x.uniqueAttr = "" },
		"attribute with a space":    func(x *ldapDirectory) { x.loginAttr = "s AM" },
		"attribute with a filter":   func(x *ldapDirectory) { x.displayAttr = "cn)(uid=*" },
		"attribute starting digit":  func(x *ldapDirectory) { x.emailAttr = "1mail" },
		"attribute option":          func(x *ldapDirectory) { x.uniqueAttr = "objectGUID;binary" },
		"empty user base DN":        func(x *ldapDirectory) { x.userBaseDN = "" },
		"empty bind DN":             func(x *ldapDirectory) { x.bindDN = "" },
		"empty group base DN":       func(x *ldapDirectory) { x.groupBaseDN = "" },
		"control in a DN":           func(x *ldapDirectory) { x.bindDN = "cn=alice\n,dc=corp" },
		"oversized DN":              func(x *ldapDirectory) { x.userBaseDN = "dc=" + strings.Repeat("a", 1022) },
		"oversized CA":              func(x *ldapDirectory) { x.caPEM = strings.Repeat("A", 65537) },
	} {
		assert.Equal(t, "23514", sqlState(try(change)), what)
	}
	require.NoError(t, try(func(x *ldapDirectory) { x.userBaseDN = "dc=" + strings.Repeat("a", 1021) }), "1024 characters")
}

func TestLDAPGroupMappings(t *testing.T) {
	d := pgtest.New(t)
	dir := seedLDAPDirectory(t, d, "Corp AD")
	put := func(group, role string) error {
		return exec(t, d.App, `INSERT INTO ldap_group_mappings (id, directory_id, group_value, role, created_at)
VALUES ($1, $2, $3, $4, now())`, uuid.New(), dir, group, role)
	}
	require.NoError(t, put("CN=Alice Ops,OU=Groups,DC=corp,DC=example,DC=com", "operator"))
	require.NoError(t, put("alice-auditors", "auditor"))
	assert.Equal(t, "23505", sqlState(put("alice-auditors", "admin")), "one role per group and directory")
	require.NoError(t, put("Alice-Auditors", "admin"), "group values are exact, case-sensitive")
	for _, bad := range []string{"", " ops", "ops ", "o\tps", "o\nps", "x\x7f"} {
		assert.Equal(t, "23514", sqlState(put(bad, "auditor")), "%q", bad)
	}
	assert.Equal(t, "23514", sqlState(put(strings.Repeat("ç", 1025), "auditor")))
	require.NoError(t, put(strings.Repeat("ç", 1024), "auditor"), "1024 characters: a group DN, as long as the DN columns")
	assert.Equal(t, "23514", sqlState(put("x", "owner")))

	other := seedLDAPDirectory(t, d, "Other")
	require.NoError(t, exec(t, d.App, `INSERT INTO ldap_group_mappings (id, directory_id, group_value, role, created_at)
VALUES ($1, $2, 'alice-auditors', 'auditor', now())`, uuid.New(), other), "the same group in another directory")

	require.NoError(t, exec(t, d.App, `DELETE FROM ldap_directories WHERE id = $1`, dir), "mappings go with their directory")
	var n int
	require.NoError(t, d.App.QueryRow(context.Background(), `SELECT count(*) FROM ldap_group_mappings WHERE directory_id = $1`, dir).Scan(&n))
	assert.Zero(t, n)
	require.NoError(t, d.App.QueryRow(context.Background(), `SELECT count(*) FROM ldap_group_mappings`).Scan(&n))
	assert.Equal(t, 1, n, "the other directory's mapping stays")
}

func TestLDAPUsersAreNeverLocal(t *testing.T) {
	d := pgtest.New(t)
	dir := seedLDAPDirectory(t, d, "Corp AD")
	local := seedUser(t, d, "ada", "ada@example.com")

	require.NoError(t, insertLDAPUser(t, d, "ada-ldap", dir, "0a1b2c3d", nil, false, "ldap_mapping"))
	assert.Equal(t, "23514", sqlState(insertLDAPUser(t, d, "pw", dir, "0a01", "$argon2id$x", false, "ldap_mapping")), "no password")
	assert.Equal(t, "23514", sqlState(insertLDAPUser(t, d, "bg", dir, "0a02", nil, true, "ldap_mapping")), "never break-glass")
	assert.Equal(t, "23514", sqlState(insertLDAPUser(t, d, "manual", dir, "0a03", nil, false, "manual")), "role from the mapping")
	assert.Equal(t, "23514", sqlState(insertLDAPUser(t, d, "oidcmap", dir, "0a04", nil, false, "oidc_mapping")), "the LDAP mapping")
	assert.Equal(t, "23514", sqlState(insertLDAPUser(t, d, "noid", dir, nil, nil, false, "ldap_mapping")), "the unique id is needed")
	assert.Equal(t, "23514", sqlState(insertLDAPUser(t, d, "nodir", nil, "0a05", nil, false, "ldap_mapping")), "the directory is needed")
	assert.Equal(t, "23503", sqlState(insertLDAPUser(t, d, "ghost", uuid.New(), "0a06", nil, false, "ldap_mapping")), "a real directory")

	// The unique id is the lower-case hex of the attribute bytes, 2 to 254 characters.
	for _, bad := range []string{"", "0", "0A1B", "xyz0", "0a1", "0a 1b", strings.Repeat("a", 256)} {
		assert.Equal(t, "23514", sqlState(insertLDAPUser(t, d, "bad-"+uuid.NewString()[:8], dir, bad, nil, false, "ldap_mapping")), "%q", bad)
	}
	require.NoError(t, insertLDAPUser(t, d, "longest", dir, strings.Repeat("f", 254), nil, false, "ldap_mapping"))

	// A local user can carry no directory identity, and an OIDC column is no LDAP identity.
	assert.Equal(t, "23514", sqlState(exec(t, d.App, `UPDATE users SET ldap_directory_id = $2 WHERE id = $1`, local, dir)),
		"a local user has no directory")
	assert.Equal(t, "23514", sqlState(exec(t, d.App, `UPDATE users SET ldap_directory_id = $2, ldap_unique_id = 'ab' WHERE id = $1`, local, dir)))
	assert.Equal(t, "23514", sqlState(exec(t, d.App, `UPDATE users SET auth_source = 'ldap' WHERE id = $1`, local)),
		"a local user cannot be turned into a directory user")
	p := seedProvider(t, d, "Corp IdP")
	assert.Equal(t, "23514", sqlState(exec(t, d.App, `INSERT INTO users (id, username, display_name, auth_source, role, role_source,
oidc_provider_id, oidc_issuer, oidc_subject, ldap_directory_id, ldap_unique_id, created_at, updated_at)
VALUES ($1, 'both', 'both', 'oidc', 'auditor', 'oidc_mapping', $2, 'https://idp.example.com/realms/corp', 's', $3, 'ab', now(), now())`,
		uuid.New(), p, dir)), "an SSO user has no directory identity")
	assert.Equal(t, "23514", sqlState(exec(t, d.App, `INSERT INTO users (id, username, display_name, auth_source, role, role_source,
oidc_provider_id, oidc_issuer, oidc_subject, created_at, updated_at)
VALUES ($1, 'mixed', 'mixed', 'ldap', 'auditor', 'ldap_mapping', $2, 'https://idp.example.com/realms/corp', 's', now(), now())`,
		uuid.New(), p)), "a directory user has no SSO identity")
	assert.Equal(t, "23514", sqlState(exec(t, d.App, `INSERT INTO users (id, username, display_name, auth_source, password_hash, role, created_at, updated_at)
VALUES ($1, 'kerberos', 'kerberos', 'kerberos', 'x', 'auditor', now(), now())`, uuid.New())), "the auth sources stay a closed list")

	assert.Equal(t, "23503", sqlState(exec(t, d.App, `DELETE FROM ldap_directories WHERE id = $1`, dir)), "a directory with users stays")
}

func TestOneUserPerDirectoryIdentity(t *testing.T) {
	d := pgtest.New(t)
	a := seedLDAPDirectory(t, d, "Directory A")
	b := seedLDAPDirectory(t, d, "Directory B")
	require.NoError(t, insertLDAPUser(t, d, "via-a", a, "c0ffee", nil, false, "ldap_mapping"))
	require.NoError(t, insertLDAPUser(t, d, "via-b", b, "c0ffee", nil, false, "ldap_mapping"),
		"the same unique id in another directory is another user")
	assert.Equal(t, "23505", sqlState(insertLDAPUser(t, d, "again-a", a, "c0ffee", nil, false, "ldap_mapping")),
		"one user per (directory, unique id)")
	var idx string
	require.NoError(t, d.Owner.QueryRow(context.Background(),
		`SELECT indexdef FROM pg_indexes WHERE indexname = 'users_ldap_identity_unique'`).Scan(&idx))
	assert.Contains(t, idx, "WHERE (ldap_directory_id IS NOT NULL)")
}

func TestSettingSecretsTakeTheDirectoryBindPassword(t *testing.T) {
	d := pgtest.New(t)
	put := func(key string) error {
		return exec(t, d.App, `INSERT INTO setting_secrets (key, ciphertext, nonce, wrapped_dek, key_version, updated_at)
VALUES ($1, '\x01', decode(repeat('00', 12), 'hex'), '\x02', 1, now())`, key)
	}
	id := uuid.NewString()
	require.NoError(t, put("ldap.directory."+id+".bind_password"))
	require.NoError(t, put("notify.smtp.password"), "the earlier keys stay")
	require.NoError(t, put("backup.sender"))
	require.NoError(t, put("sso.provider."+id+".client_secret"))
	for _, bad := range []string{
		"ldap.directory.x.bind_password",
		"ldap.directory." + id + ".password",
		"ldap.directory." + id + ".bind_password.x",
		"ldap.directory." + id,
		"ldap.directory.." + id + ".bind_password",
		"LDAP.directory." + id + ".bind_password",
		"ldap.directory." + "AAAAAAAA-0000-0000-0000-000000000000" + ".bind_password",
		"ldap.provider." + id + ".bind_password",
		"ldap_directory_" + id + "_bind_password",
		"sso.provider." + id + ".bind_password",
	} {
		assert.Equal(t, "23514", sqlState(put(bad)), bad)
	}
}

// The checks 00014 leaves on users and setting_secrets, as pg_get_constraintdef prints them; 00015's Down restores them.
var pre00015Checks = map[string]string{
	"users_auth_source_check":   `CHECK ((auth_source = ANY (ARRAY['local'::text, 'oidc'::text])))`,
	"users_role_source_check":   `CHECK ((role_source = ANY (ARRAY['manual'::text, 'oidc_mapping'::text])))`,
	"setting_secrets_key_check": `CHECK ((key ~ '^(notify\.smtp\.password|backup\.sender|sso\.provider\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\.client_secret)$'::text))`,
}

func constraintDefs(t *testing.T, d *pgtest.DB) map[string]string {
	t.Helper()
	rows, err := d.Owner.Query(context.Background(), `SELECT conname, pg_get_constraintdef(oid) FROM pg_constraint
WHERE conrelid IN ('public.users'::regclass, 'public.setting_secrets'::regclass)`)
	require.NoError(t, err)
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var n, def string
		require.NoError(t, rows.Scan(&n, &def))
		out[n] = def
	}
	require.NoError(t, rows.Err())
	return out
}

func TestMigration00015DownRefusesDirectoryDataAndIsCleanWithout(t *testing.T) {
	d := pgtest.New(t)
	ctx := context.Background()
	p, err := goose.NewProvider(goose.DialectPostgres, stdlib.OpenDBFromPool(d.Owner), migrations.FS)
	require.NoError(t, err)
	version, err := p.GetDBVersion(ctx)
	require.NoError(t, err)
	require.Equal(t, int64(15), version)
	assert.Empty(t, grantProblems(t, d), "the new tables are granted to alice_app")

	// Each kind of directory data alone blocks the Down: a directory, a directory user (with its directory), a bind password.
	downRefused := func(what string) {
		t.Helper()
		_, err := p.DownTo(ctx, 14)
		require.Error(t, err, what)
		assert.Contains(t, err.Error(), ldapDownRefused, what)
		v, err := p.GetDBVersion(ctx)
		require.NoError(t, err)
		assert.Equal(t, int64(15), v, "nothing changed: %s", what)
		assert.True(t, tableExists(t, d, "ldap_directories"), what)
	}
	dir := seedLDAPDirectory(t, d, "Corp AD")
	downRefused("a directory")
	require.NoError(t, insertLDAPUser(t, d, "ada-ldap", dir, "ab", nil, false, "ldap_mapping"))
	downRefused("a directory user")
	require.NoError(t, exec(t, d.Owner, `DELETE FROM users`))
	require.NoError(t, exec(t, d.Owner, `DELETE FROM ldap_directories`))
	require.NoError(t, exec(t, d.App, `INSERT INTO setting_secrets (key, ciphertext, nonce, wrapped_dek, key_version, updated_at)
VALUES ($1, '\x01', decode(repeat('00', 12), 'hex'), '\x02', 1, now())`, "ldap.directory."+uuid.NewString()+".bind_password"))
	downRefused("a bind password")
	require.NoError(t, exec(t, d.Owner, `DELETE FROM setting_secrets`))

	// Unrelated data does not block it.
	seedUser(t, d, "ada", "")
	_, err = p.DownTo(ctx, 14)
	require.NoError(t, err, "no directory data: the Down runs")
	version, err = p.GetDBVersion(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(14), version)
	for _, tbl := range []string{"ldap_directories", "ldap_group_mappings"} {
		assert.False(t, tableExists(t, d, tbl), tbl)
	}
	var n int
	require.NoError(t, d.Owner.QueryRow(ctx, `SELECT count(*) FROM information_schema.columns
WHERE table_name = 'users' AND column_name LIKE 'ldap\_%'`).Scan(&n))
	assert.Zero(t, n, "the Down drops the users columns")
	require.NoError(t, d.Owner.QueryRow(ctx, `SELECT count(*) FROM pg_constraint WHERE conname LIKE 'users\_ldap%'`).Scan(&n))
	assert.Zero(t, n)
	require.NoError(t, d.Owner.QueryRow(ctx, `SELECT count(*) FROM pg_indexes WHERE indexname LIKE '%ldap%'`).Scan(&n))
	assert.Zero(t, n)
	require.NoError(t, d.Owner.QueryRow(ctx, `SELECT count(*) FROM pg_proc WHERE proname LIKE 'ldap\_%'`).Scan(&n))
	assert.Zero(t, n, "the Down drops the helper functions")
	defs := constraintDefs(t, d)
	for name, want := range pre00015Checks {
		assert.Equal(t, want, defs[name], "the Down restores %s", name)
	}
	assert.Empty(t, grantProblems(t, d), "the Down leaves 00014's grants as they were")

	_, err = p.Up(ctx)
	require.NoError(t, err, "and migrates up again")
	assert.Empty(t, grantProblems(t, d))
	seedLDAPDirectory(t, d, "Again")
}
