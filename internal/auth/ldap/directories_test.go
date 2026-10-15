package ldap

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/platform/validate"
	"alice/internal/rbac"
	"alice/internal/testutil/pki"
)

func TestSplitAddress(t *testing.T) {
	good := map[string][2]any{
		"ldaps://ldap.example.com":           {"ldap.example.com", 636},
		"ldaps://ldap.example.com:636":       {"ldap.example.com", 636},
		"ldaps://DC01.Corp.Example.com:3269": {"DC01.Corp.Example.com", 3269},
		"ldaps://10.0.0.1:65535":             {"10.0.0.1", 65535},
		"ldaps://[::1]:636":                  {"::1", 636},
		"ldaps://[2001:db8::1]":              {"2001:db8::1", 636},
		"ldaps://localhost:1":                {"localhost", 1},
		"ldaps://a-b.c9":                     {"a-b.c9", 636},
	}
	for in, want := range good {
		host, port, ok := splitAddress(in)
		assert.True(t, ok, in)
		assert.Equal(t, want, [2]any{host, port}, in)
	}
	for _, in := range []string{
		"", "ldaps://", "LDAPS://ldap.example.com", "Ldaps://ldap.example.com", "ldap://ldap.example.com", "ldaps:/x",
		"ldaps://:636", "ldaps://x:", "ldaps://x:0", "ldaps://x:65536", "ldaps://x:0636", "ldaps://x:+1", "ldaps://x:1a",
		"ldaps://x:123456", "ldaps://::1", "ldaps://::1:636", "ldaps://[::1", "ldaps://[::1]x", "ldaps://[::1]:",
		"ldaps://[fe80::1%25eth0]", "ldaps://[fe80::1%eth0]", "ldaps://[::ffff:10.0.0.1]", "ldaps://[10.0.0.1]",
		"ldaps://[]", "ldaps://x/y", "ldaps://x/", "ldaps://u@x", "ldaps://x?y", "ldaps://x#y", "ldaps://-x", "ldaps://x-",
		"ldaps://x..y", "ldaps://.x", "ldaps://x.", "ldaps://1.2.3.999", "ldaps://x y", "ldaps://x\n", "ldaps://x\x00",
		"ldaps://x_y", "ldaps://çiğdem.example", "ldaps://x:636:1", "ldaps://" + strings.Repeat("a", 64) + ".example",
		"ldaps://" + strings.Repeat("a.", 124) + "aa", "ldaps://x\\y", "ldaps://%78",
	} {
		_, _, ok := splitAddress(in)
		assert.False(t, ok, "%q", in)
	}
}

// validDirectory is a directory every check accepts; the tests change one field at a time.
func validDirectory() Directory {
	return Directory{Name: "Corp", Addresses: []string{"ldaps://dc1.corp.example:636", "ldaps://dc2.corp.example"},
		UserBaseDN: "OU=People,DC=corp,DC=example", UserFilter: "(&(objectClass=user)(sAMAccountName={login}))",
		LoginAttribute: "sAMAccountName", UniqueIDAttribute: "objectGUID", DisplayNameAttribute: "displayName", EmailAttribute: "mail",
		BindDN: "CN=alice-svc,OU=Services,DC=corp,DC=example", GroupBaseDN: "DC=corp,DC=example", GroupFilter: ADGroupFilter,
		GroupNameAttribute: ""}
}

func fieldsOf(err error) []string {
	var v validate.Errors
	if !errors.As(err, &v) {
		return nil
	}
	var out []string
	for _, f := range v {
		out = append(out, f.Field+":"+f.Code)
	}
	return out
}

func TestValidateDirectory(t *testing.T) {
	ok := fields{d: validDirectory(), bind: []byte("pw"), bindNeeded: true}
	require.NoError(t, ok.validate())
	ca := string(pki.NewCA("v", pki.ECDSA256, time.Now()).RootPEM)
	for name, c := range map[string]struct {
		change func(f *fields)
		want   []string
	}{
		"ca":             {func(f *fields) { f.d.CAPEM = ca }, nil},
		"oid attributes": {func(f *fields) { f.d.UniqueIDAttribute, f.d.EmailAttribute = "1.3.6.1.1.16.4", "" }, nil},
		"generic": {func(f *fields) {
			f.d.UserFilter, f.d.GroupFilter = "(uid={login})", "(|(member={dn})(memberUid={login}))"
		}, nil},
		"login in group":  {func(f *fields) { f.d.GroupFilter = "(memberUid={login})" }, nil},
		"no name":         {func(f *fields) { f.d.Name = " " }, []string{"name:" + validate.Required}},
		"long name":       {func(f *fields) { f.d.Name = strings.Repeat("ş", 61) }, []string{"name:" + validate.TooLong}},
		"name control":    {func(f *fields) { f.d.Name = "a\u200bb" }, []string{"name:" + validate.Pattern}},
		"no addresses":    {func(f *fields) { f.d.Addresses = nil }, []string{"addresses:" + validate.OutOfRange}},
		"four addresses":  {func(f *fields) { f.d.Addresses = []string{"ldaps://a", "ldaps://b", "ldaps://c", "ldaps://d"} }, []string{"addresses:" + validate.OutOfRange}},
		"upper scheme":    {func(f *fields) { f.d.Addresses = []string{"LDAPS://dc1.corp.example"} }, []string{"addresses:" + validate.Pattern}},
		"plain ldap":      {func(f *fields) { f.d.Addresses = []string{"ldap://dc1.corp.example"} }, []string{"addresses:" + validate.Pattern}},
		"bad port":        {func(f *fields) { f.d.Addresses = []string{"ldaps://dc1.corp.example:99999"} }, []string{"addresses:" + validate.Pattern}},
		"duplicate":       {func(f *fields) { f.d.Addresses = []string{"ldaps://a", "ldaps://a"} }, []string{"addresses:" + validate.Duplicate}},
		"no base":         {func(f *fields) { f.d.UserBaseDN = "" }, []string{"user_base_dn:" + validate.Required}},
		"bad base":        {func(f *fields) { f.d.UserBaseDN = "not a dn" }, []string{"user_base_dn:" + validate.Pattern}},
		"base space":      {func(f *fields) { f.d.UserBaseDN = " dc=x" }, []string{"user_base_dn:" + validate.Pattern}},
		"base control":    {func(f *fields) { f.d.UserBaseDN = "dc=x\n" }, []string{"user_base_dn:" + validate.Pattern}},
		"long base":       {func(f *fields) { f.d.UserBaseDN = "dc=" + strings.Repeat("x", 1022) }, []string{"user_base_dn:" + validate.TooLong}},
		"base 1024":       {func(f *fields) { f.d.UserBaseDN = "dc=" + strings.Repeat("x", 1021) }, nil},
		"no user filter":  {func(f *fields) { f.d.UserFilter = "" }, []string{"user_filter:" + validate.Required}},
		"long filter":     {func(f *fields) { f.d.UserFilter = "(uid={login})" + strings.Repeat(" ", 1020) }, []string{"user_filter:" + validate.TooLong}},
		"no login":        {func(f *fields) { f.d.UserFilter = "(uid=ada)" }, []string{"user_filter:" + validate.Pattern}},
		"login twice":     {func(f *fields) { f.d.UserFilter = "(|(uid={login})(mail={login}))" }, []string{"user_filter:" + validate.Pattern}},
		"dn in user":      {func(f *fields) { f.d.UserFilter = "(&(uid={login})(member={dn}))" }, []string{"user_filter:" + validate.Pattern}},
		"unbalanced":      {func(f *fields) { f.d.UserFilter = "(uid={login}" }, []string{"user_filter:" + validate.Pattern}},
		"two filters":     {func(f *fields) { f.d.UserFilter = "(uid={login})(objectClass=*)" }, []string{"user_filter:" + validate.Pattern}},
		"closed early":    {func(f *fields) { f.d.UserFilter = "(uid={login}))(|(cn=*)" }, []string{"user_filter:" + validate.Pattern}},
		"bare":            {func(f *fields) { f.d.UserFilter = "uid={login}" }, []string{"user_filter:" + validate.Pattern}},
		"placeholder key": {func(f *fields) { f.d.UserFilter = "({login}=x)" }, []string{"user_filter:" + validate.Pattern}},
		"upper login":     {func(f *fields) { f.d.UserFilter = "(uid={LOGIN})" }, []string{"user_filter:" + validate.Pattern}},
		"other brace":     {func(f *fields) { f.d.UserFilter = "(&(uid={login})(cn={x}))" }, []string{"user_filter:" + validate.Pattern}},
		"bad escape":      {func(f *fields) { f.d.UserFilter = `(&(uid={login})(cn=\zz))` }, []string{"user_filter:" + validate.Pattern}},
		"empty and":       {func(f *fields) { f.d.UserFilter = "(&(uid={login})(&))" }, []string{"user_filter:" + validate.Pattern}},
		"filter control":  {func(f *fields) { f.d.UserFilter = "(uid={login})\x00" }, []string{"user_filter:" + validate.Pattern}},
		"tab":             {func(f *fields) { f.d.UserFilter = "(&\t(uid={login}))" }, []string{"user_filter:" + validate.Pattern}},
		"double star":     {func(f *fields) { f.d.UserFilter = "(&(uid={login})(cn=**))" }, []string{"user_filter:" + validate.Pattern}},
		"no login attr":   {func(f *fields) { f.d.LoginAttribute = "" }, []string{"login_attribute:" + validate.Required}},
		"bad login attr":  {func(f *fields) { f.d.LoginAttribute = "uid;binary" }, []string{"login_attribute:" + validate.Pattern}},
		"no unique":       {func(f *fields) { f.d.UniqueIDAttribute = "" }, []string{"unique_id_attribute:" + validate.Required}},
		"bad display":     {func(f *fields) { f.d.DisplayNameAttribute = "display name" }, []string{"display_name_attribute:" + validate.Pattern}},
		"bad email":       {func(f *fields) { f.d.EmailAttribute = "-mail" }, []string{"email_attribute:" + validate.Pattern}},
		"no bind dn":      {func(f *fields) { f.d.BindDN = "" }, []string{"bind_dn:" + validate.Required}},
		"no password":     {func(f *fields) { f.bind = nil }, []string{"bind_password:" + validate.Required}},
		"long password":   {func(f *fields) { f.bind = make([]byte, 1025) }, []string{"bind_password:" + validate.TooLong}},
		"no group base":   {func(f *fields) { f.d.GroupBaseDN = "" }, []string{"group_base_dn:" + validate.Required}},
		"no placeholder":  {func(f *fields) { f.d.GroupFilter = "(objectClass=group)" }, []string{"group_filter:" + validate.Pattern}},
		"group broken":    {func(f *fields) { f.d.GroupFilter = "(member={dn}" }, []string{"group_filter:" + validate.Pattern}},
		"group injection": {func(f *fields) { f.d.GroupFilter = "(member={dn})(objectClass=*)" }, []string{"group_filter:" + validate.Pattern}},
		"bad group attr":  {func(f *fields) { f.d.GroupNameAttribute = "c n" }, []string{"group_name_attribute:" + validate.Pattern}},
		"bad ca":          {func(f *fields) { f.d.CAPEM = "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n" }, []string{"ca_pem:" + validate.Pattern}},
		"order": {func(f *fields) { f.d.Name, f.d.Addresses, f.bind, f.d.CAPEM = "", nil, nil, "x" }, []string{"name:" + validate.Required,
			"addresses:" + validate.OutOfRange, "bind_password:" + validate.Required, "ca_pem:" + validate.Pattern}},
	} {
		f := ok
		f.d.Addresses = append([]string(nil), ok.d.Addresses...)
		c.change(&f)
		assert.Equal(t, c.want, fieldsOf(f.validate()), name)
	}
	// An update without a password keeps the stored one; a given empty one is refused.
	keep := fields{d: validDirectory()}
	assert.NoError(t, keep.validate())
	keep.bindGiven = true
	assert.Equal(t, []string{"bind_password:" + validate.Required}, fieldsOf(keep.validate()))
}

func TestValidateMapping(t *testing.T) {
	dn := "CN=Alice Ops,OU=Groups,DC=corp,DC=example"
	assert.NoError(t, validateMapping(dn, rbac.Operator, false))
	assert.NoError(t, validateMapping(strings.Repeat("g", MaxGroupRunes), rbac.Auditor, false), "a DN up to 1024 characters")
	assert.NoError(t, validateMapping("admins", rbac.Admin, true))
	assert.ErrorIs(t, validateMapping("admins", rbac.Admin, false), ErrAdminMappingDisabled)
	for in, want := range map[string]string{
		"":                        "group:" + validate.Required,
		"  ":                      "group:" + validate.Required,
		" ops":                    "group:" + validate.Pattern,
		"o\u200bps":               "group:" + validate.Pattern,
		"o\nps":                   "group:" + validate.Pattern,
		"\xff":                    "group:" + validate.Pattern,
		strings.Repeat("g", 1025): "group:" + validate.TooLong,
		strings.Repeat("ş", 1025): "group:" + validate.TooLong,
	} {
		assert.Equal(t, []string{want}, fieldsOf(validateMapping(in, rbac.Operator, true)), "%q", in)
	}
	assert.Equal(t, []string{"role:" + validate.OneOf}, fieldsOf(validateMapping("ops", rbac.Role("root"), true)))
}

func TestAddedAddress(t *testing.T) {
	assert.False(t, addedAddress([]string{"ldaps://a", "ldaps://b"}, []string{"ldaps://b", "ldaps://a"}))
	assert.False(t, addedAddress([]string{"ldaps://a", "ldaps://b"}, []string{"ldaps://b"}))
	assert.True(t, addedAddress([]string{"ldaps://a"}, []string{"ldaps://a", "ldaps://c"}))
}
