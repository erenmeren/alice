//go:build integration

package fakeldap

import (
	"os"
	"testing"

	"github.com/go-ldap/ldap/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMain(m *testing.M) {
	code := m.Run()
	Stop()
	os.Exit(code)
}

func TestTreeAndServiceAccount(t *testing.T) {
	s := Start(t)
	assert.Same(t, s, Start(t), "one directory per process")
	assert.Equal(t, "ldaps://"+s.Endpoint(), s.Address)
	l, err := ldap.DialURL(s.Address, ldap.DialWithTLSConfig(s.TLSConfig()))
	require.NoError(t, err)
	defer l.Close()
	require.NoError(t, l.Bind(ServiceDN, s.ServicePassword()))
	res, err := l.Search(ldap.NewSearchRequest(PeopleDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 10, false,
		"(uid=dup)", []string{"uid"}, nil))
	require.NoError(t, err)
	assert.Len(t, res.Entries, 2, "the service account reads the tree; dup is ambiguous")
	res, err = l.Search(ldap.NewSearchRequest(Ada.DN, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 10, false,
		"(objectClass=*)", []string{"memberOf"}, nil))
	require.NoError(t, err)
	assert.Equal(t, []string{OpsDN}, res.Entries[0].GetAttributeValues("memberOf"), "memberOf follows groupOfNames")
	require.NoError(t, l.Bind(Cigdem.DN, Cigdem.Password), "a Turkish-named user binds")
	assert.Len(t, s.EntryUUID(t, Ada.DN), 36)
	s.Add(t, "cn=extra,"+GroupsDN, map[string][]string{"objectClass": {"groupOfNames"}, "cn": {"extra"}, "member": {Grace.DN}})
	s.Add(t, "cn=extra,"+GroupsDN, map[string][]string{"objectClass": {"groupOfNames"}, "cn": {"extra"}, "member": {Grace.DN}})
}
