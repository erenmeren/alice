package ldapx

import (
	"fmt"
	"strings"
	"testing"

	ber "github.com/go-asn1-ber/asn1-ber"
	ldap "github.com/go-ldap/ldap/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// shape is the structure of a compiled filter without its values: the tags of every node, the attribute names and
// the number of children. Two filters with the same shape differ only in assertion values.
func shape(p *ber.Packet) string {
	var b strings.Builder
	var walk func(p *ber.Packet)
	walk = func(p *ber.Packet) {
		fmt.Fprintf(&b, "(%d", p.Tag)
		switch int(p.Tag) {
		case ldap.FilterAnd, ldap.FilterOr, ldap.FilterNot:
			for _, c := range p.Children {
				walk(c)
			}
		case ldap.FilterPresent:
			fmt.Fprintf(&b, " %s", p.Data.String())
		case ldap.FilterSubstrings:
			fmt.Fprintf(&b, " %s", p.Children[0].Data.String())
			for _, c := range p.Children[1].Children {
				fmt.Fprintf(&b, " s%d", c.Tag)
			}
		case ldap.FilterExtensibleMatch:
			for _, c := range p.Children {
				if c.Tag != ldap.MatchingRuleAssertionMatchValue {
					fmt.Fprintf(&b, " e%d=%v", c.Tag, c.Value)
				}
			}
		default:
			fmt.Fprintf(&b, " %s", p.Children[0].Data.String())
		}
		b.WriteString(")")
	}
	walk(p)
	return b.String()
}

func topConditions(p *ber.Packet) int {
	switch int(p.Tag) {
	case ldap.FilterAnd, ldap.FilterOr:
		return len(p.Children)
	}
	return 1
}

var templates = []string{
	"(uid={login})",
	"(sAMAccountName={login})",
	"(&(objectClass=person)(uid={login}))",
	"(&(objectCategory=person)(objectClass=user)(|(sAMAccountName={login})(userPrincipalName={login})))",
	"(member={dn})",
	"(member:1.2.840.113556.1.4.1941:={dn})",
	"(&(objectClass=groupOfNames)(|(member={dn})(memberUid={login})))",
	"(cn={login}*)",
	"(cn=*{login}*)",
	"(!(uid={login}))",
	"(uid:dn:={login})",
	"(:dn:2.5.13.5:={login})",
	"(uid~={login})",
	"(uidNumber>={login})",
}

var hostile = []string{"ada", "*", "*)(uid=*))(|(uid=*", "admin)(&", "x)(objectClass=*", "\x00", "a\xffb", "�",
	"\\", "\\2a", "(", ")", "))))))", "((((", "{login}", "{dn}", "cn=admin,dc=example,dc=com", "|", "&", "!", "=", ":=", "Çiğdem",
	strings.Repeat("*)(", 300)}

// Review Focus: no value can change the structure of a filter. Each expansion compiles with go-ldap and has the same
// shape (and the same number of top-level conditions) as the expansion with a harmless value.
func TestExpandFilterValuesNeverChangeTheStructure(t *testing.T) {
	for _, tmpl := range templates {
		base, err := ExpandFilter(tmpl, map[string]string{"login": "x", "dn": "x"})
		require.NoError(t, err, tmpl)
		bp, err := ldap.CompileFilter(base)
		require.NoError(t, err, base)
		for _, v := range hostile {
			for _, w := range []string{"x", v} {
				got, err := ExpandFilter(tmpl, map[string]string{"login": v, "dn": w})
				require.NoError(t, err, "%s %q", tmpl, v)
				p, err := ldap.CompileFilter(got)
				require.NoError(t, err, "%s %q -> %q", tmpl, v, got)
				assert.Equal(t, topConditions(bp), topConditions(p), "%s %q", tmpl, v)
				assert.Equal(t, shape(bp), shape(p), "%s %q -> %q", tmpl, v, got)
			}
		}
	}
}

func TestExpandFilterEscapesEveryValue(t *testing.T) {
	got, err := ExpandFilter("(&(uid={login})(member={dn}))", map[string]string{"login": "*)(uid=*", "dn": "cn=a\\,b,dc=x"})
	require.NoError(t, err)
	assert.Equal(t, `(&(uid=\2a\29\28uid=\2a)(member=cn=a\5c,b,dc=x))`, got)
	got, err = ExpandFilter("(|(uid={login})(mail={login}))", map[string]string{"login": "a*"})
	require.NoError(t, err)
	assert.Equal(t, `(|(uid=a\2a)(mail=a\2a))`, got)
	got, err = ExpandFilter("(objectClass=*)", nil)
	require.NoError(t, err)
	assert.Equal(t, "(objectClass=*)", got)
}

// Only {login} and {dn} are known; a known placeholder without a value is refused as well.
func TestExpandFilterRefusesUnknownPlaceholders(t *testing.T) {
	for _, tmpl := range []string{"(uid={user})", "(uid={LOGIN})", "(uid={ login })", "(uid={})", "(uid={login)", "(uid=login})",
		"(uid={{login}})", "(uid={login}{dn", "(uid={password})"} {
		_, err := ExpandFilter(tmpl, map[string]string{"login": "a", "dn": "b"})
		assert.ErrorIs(t, err, ErrFilterTemplate, tmpl)
	}
	_, err := ExpandFilter("(member={dn})", map[string]string{"login": "a"})
	assert.ErrorIs(t, err, ErrFilterTemplate, "a placeholder without a value")
	_, err = ExpandFilter("(uid={login})", map[string]string{"login": "a", "password": "p"})
	assert.ErrorIs(t, err, ErrFilterTemplate, "an unknown value name")
}

// The template must be one balanced RFC 4515 filter; a placeholder may only stand where an assertion value stands.
func TestExpandFilterRefusesInvalidTemplates(t *testing.T) {
	bad := []string{
		"", "uid={login}", "(uid={login}", "uid={login})", "((uid={login})", "(uid={login}))", "(uid={login})(cn=x)",
		"(&)", "(|)", "(!)", "(&(uid={login})", "(!(a=b)(c=d))", "()", "(=x)", "(uid)", "(uid=a(b)", "(uid=a\\zz)",
		"(uid=a\\4)", "(uid=a\\)", "(ui d=x)", "(1uid=x)", "(uid~=*)", "(uid>=a*)", "(uid:=a*)", "(:=x)", "(:DN:2.5.13.5:=x)", "(uid:dn)",
		"(uid:1.2.:=x)", "(uid:x y:=x)", "({login}=x)", "(uid:{login}:=x)", "(uid;{login}=x)", "(uid=\x00)",
		"(uid=\xff)", "(uid=x) ", " (uid=x)", "(uid=x\n)", "(uid=x�)", "(uid=\x01)", "(uid;=x)", "(-uid=x)", "(&(a=b)(c))", "(~=x)", "(01=x)", "(1.=x)", "(uid=)" + ")",
		strings.Repeat("(!", 100) + "(a=b)" + strings.Repeat(")", 100),
		"(uid=" + strings.Repeat("a", maxTemplate) + ")",
	}
	for _, tmpl := range bad {
		_, err := ExpandFilter(tmpl, map[string]string{"login": "a", "dn": "b"})
		assert.ErrorIs(t, err, ErrFilterTemplate, "%q", tmpl)
	}
	good := []string{"(uid=)", "(uid=*)", "(uid=a*b*c)", "(uid=**)", "(cn;lang-de=x)", "(2.5.4.3=x)", "(uid=\\2a)",
		"(uid:dn:=x)", "(uid:caseExactMatch:=x)", "(:caseExactMatch:=x)", "(:dn:2.5.13.5:=x)", "(uid:dn:dn:=x)", "(uid:Dn:=x)", "(uid=Çiğdem)", "(&(a=b)(c=d)(e=f))",
		"(!(&(a=b)(|(c=d)(!(e=*)))))", "(uid<=x)", "(uid=x=y)", "(uid=a:=b)", "(uid=\\2A)", "(0.1.20=x)"}
	for _, tmpl := range good {
		got, err := ExpandFilter(tmpl, nil)
		require.NoError(t, err, "%q", tmpl)
		assert.Equal(t, tmpl, got)
		_, err = ldap.CompileFilter(got)
		assert.NoError(t, err, "%q compiles with go-ldap", tmpl)
	}
}

// Review finding: an empty value next to "*" would turn (cn={login}*) into the presence filter (cn=*), so an empty
// value is refused for every placeholder.
func TestExpandFilterRefusesEmptyValues(t *testing.T) {
	for _, tmpl := range []string{"(cn={login}*)", "(cn=*{login}*)", "(uid={login})"} {
		_, err := ExpandFilter(tmpl, map[string]string{"login": ""})
		assert.ErrorIs(t, err, ErrFilterValue, tmpl)
	}
	_, err := ExpandFilter("(member={dn})", map[string]string{"dn": ""})
	assert.ErrorIs(t, err, ErrFilterValue)
}

func TestExpandFilterErrorNamesNoValue(t *testing.T) {
	_, err := ExpandFilter("(uid={login}", map[string]string{"login": "s3cr3t-value"})
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "s3cr3t-value")
}
