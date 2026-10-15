package ldapx

import (
	"regexp"
	"strings"
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
)

var usernameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9._@-]{1,63}$`)

// FuzzEscapeFilter: the escaped value contains no unescaped special byte, is valid UTF-8, and go-ldap compiles it
// to one equality condition holding the original bytes.
func FuzzEscapeFilter(f *testing.F) {
	for _, s := range []string{"", "ada", "*)(uid=*))(|(uid=*", "\x00", "a\xffb", "�", "\\2a", "Çiğdem"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		e := EscapeFilter(s)
		if i, bad := unescapedFilterSpecial(e); bad {
			t.Fatalf("EscapeFilter(%q) = %q: unescaped special at %d", s, e, i)
		}
		p, err := ldap.CompileFilter("(cn=" + e + ")")
		if err != nil {
			t.Fatalf("EscapeFilter(%q) = %q does not compile: %v", s, e, err)
		}
		if int(p.Tag) != ldap.FilterEqualityMatch || len(p.Children) != 2 || p.Children[1].Data.String() != s {
			t.Fatalf("EscapeFilter(%q) = %q changed the condition", s, e)
		}
	})
}

// FuzzEscapeDN: go-ldap parses the escaped value back into one attribute of one RDN holding the original value.
func FuzzEscapeDN(f *testing.F) {
	for _, s := range []string{"", "Smith, John", " lead", "trail ", "#x", "a\x00b", "cn=x,dc=evil", `\`, "a\xffb", "\\ "} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		e := EscapeDN(s)
		dn, err := ldap.ParseDN("cn=" + e + ",dc=example")
		if err != nil {
			t.Fatalf("EscapeDN(%q) = %q does not parse: %v", s, e, err)
		}
		if len(dn.RDNs) != 2 || len(dn.RDNs[0].Attributes) != 1 || dn.RDNs[0].Attributes[0].Value != s {
			t.Fatalf("EscapeDN(%q) = %q changed the DN: %+v", s, e, dn.RDNs)
		}
	})
}

// FuzzUsername: the result is always a valid Alice user name, either derived or the fallback.
func FuzzUsername(f *testing.F) {
	for _, s := range []string{"", "ÇİĞDEM", "Şeref Üstün", "@@@", "a", "..x..", strings.Repeat("ab.", 40)} {
		f.Add(s, guid)
	}
	f.Add("x", "")
	f.Fuzz(func(t *testing.T, login, uid string) {
		u := Username(login, uid)
		if !usernameRE.MatchString(u) {
			t.Fatalf("Username(%q, %q) = %q", login, uid, u)
		}
	})
}

// FuzzExpandFilter: never panics; an accepted template expands to a filter go-ldap compiles, with the same shape
// as the expansion with harmless values.
func FuzzExpandFilter(f *testing.F) {
	for _, tmpl := range templates {
		f.Add(tmpl, "*)(uid=*))(|(uid=*", "cn=x,dc=y")
	}
	f.Add("(uid={login}", "a", "b")
	f.Add("(&(a=b)(|(c=d)))", "", "")
	f.Fuzz(func(t *testing.T, tmpl, login, dn string) {
		got, err := ExpandFilter(tmpl, map[string]string{"login": login, "dn": dn})
		if err != nil {
			return
		}
		p, err := ldap.CompileFilter(got)
		if err != nil {
			t.Fatalf("ExpandFilter(%q) = %q does not compile: %v", tmpl, got, err)
		}
		base, err := ExpandFilter(tmpl, map[string]string{"login": "x", "dn": "x"})
		if err != nil {
			t.Fatalf("template %q refused with harmless values: %v", tmpl, err)
		}
		bp, err := ldap.CompileFilter(base)
		if err != nil {
			t.Fatalf("ExpandFilter(%q) = %q does not compile: %v", tmpl, base, err)
		}
		if shape(p) != shape(bp) {
			t.Fatalf("ExpandFilter(%q) with %q, %q changed the shape: %s vs %s", tmpl, login, dn, shape(p), shape(bp))
		}
	})
}
