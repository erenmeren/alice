//go:build integration

package ldap_test

import (
	"context"
	"encoding/hex"
	"net"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/auth/ldap"
	"alice/internal/secrets"
	"alice/internal/testutil/fakeldap"
	"alice/internal/testutil/pki"
)

func TestVerifyHappyPath(t *testing.T) {
	x := newHarness(t)
	id, d, err := x.svc.Verify(x.ctx, x.dir.ID, "ada", secrets.NewPlaintext([]byte(fakeldap.Ada.Password)))
	require.NoError(t, err)
	assert.Equal(t, x.dir.ID, d.ID)
	assert.Equal(t, ldap.Identity{UniqueID: hex.EncodeToString([]byte(x.srv.EntryUUID(t, fakeldap.Ada.DN))), Login: "ada",
		DisplayName: "Ada Lovelace", Email: "ada@example.test", Groups: []string{"alice-ops"}}, id)
	assert.Len(t, id.UniqueID, 72, "the hex of the 36-character entryUUID")

	// The Turkish-named user: the login as the directory holds it; nested groups are not followed (generic LDAP).
	id, err = x.verify(fakeldap.Cigdem.Login, fakeldap.Cigdem.Password)
	require.NoError(t, err)
	assert.Equal(t, "çiğdem", id.Login)
	assert.Equal(t, "Çiğdem Öztürk", id.DisplayName)
	assert.Equal(t, []string{"alice-auditors"}, id.Groups, "alice-ops holds alice-auditors, which is not followed")

	id, err = x.verify("grace", fakeldap.Grace.Password)
	require.NoError(t, err)
	assert.Empty(t, id.Groups, "a user in no group")
	assert.NotNil(t, id.Groups)
}

func TestVerifyZeroesThePassword(t *testing.T) {
	x := newHarness(t)
	p := secrets.NewPlaintext([]byte(fakeldap.Ada.Password))
	_, _, err := x.svc.Verify(x.ctx, x.dir.ID, "ada", p)
	require.NoError(t, err)
	assert.Equal(t, make([]byte, len(fakeldap.Ada.Password)), p.Bytes())
}

func TestEmptyPasswordNeverReachesTheDirectory(t *testing.T) {
	x := newHarness(t)
	for _, p := range []secrets.Plaintext{{}, secrets.NewPlaintext(nil), secrets.NewPlaintext([]byte{})} {
		_, _, err := x.svc.Verify(x.ctx, x.dir.ID, "ada", p)
		assert.Equal(t, [2]string{ldap.ReasonBadCredentials, ldap.DetailPassword}, reasonOf(err))
		_, err = x.svc.TestSignIn(x.ctx, x.admin, x.dir.ID, "ada", p)
		assert.Equal(t, [2]string{ldap.ReasonBadCredentials, ldap.DetailPassword}, reasonOf(err))
	}
	assert.Zero(t, x.dials.Load(), "no connection was opened")
	// Positive control: the recording dial does count.
	_, err := x.verify("ada", fakeldap.Ada.Password)
	require.NoError(t, err)
	assert.Equal(t, int64(2), x.dials.Load(), "the user lookup and the group search")
}

func TestInvalidLoginNameRefused(t *testing.T) {
	x := newHarness(t)
	for _, login := range []string{"", " ada", "ada ", "a\x00da", "a\nda", "a\u200bda", "a\u00adda", "\u202eada",
		strings.Repeat("a", 257)} {
		_, err := x.verify(login, fakeldap.Ada.Password)
		assert.Equal(t, [2]string{ldap.ReasonLoginInvalid, ldap.DetailLoginName}, reasonOf(err), "%q", login)
	}
	// A name without a letter or digit passes the name rule but no filter is built from it: the answer of an unknown
	// user (ldapx.ErrFilterValue), still without traffic.
	for _, login := range []string{"*", "-", "***", "*)(", ")(|"} {
		_, err := x.verify(login, fakeldap.Ada.Password)
		assert.Equal(t, [2]string{ldap.ReasonBadCredentials, ldap.DetailLoginName}, reasonOf(err), "%q", login)
	}
	assert.Zero(t, x.dials.Load())
}

func TestWrongPasswordAndUnknownUserLookTheSame(t *testing.T) {
	x := newHarness(t)
	timed := func(login, password string) (string, time.Duration) {
		start := time.Now()
		_, err := x.verify(login, password)
		return reasonOf(err)[0], time.Since(start)
	}
	var wrong, unknown time.Duration
	for range 5 {
		r1, d1 := timed("ada", "not-her-password")
		r2, d2 := timed("nobody-here", "not-her-password")
		assert.Equal(t, ldap.ReasonBadCredentials, r1)
		assert.Equal(t, r1, r2, "the same reason, so the same visible answer")
		wrong, unknown = wrong+d1, unknown+d2
	}
	// A loose bound: an unknown user skips the user bind, one round trip on the same connection.
	assert.Less(t, (wrong - unknown).Abs(), 2*time.Second, "wrong %v, unknown %v", wrong, unknown)
}

func TestAmbiguousUserRefused(t *testing.T) {
	x := newHarness(t)
	_, err := x.verify("dup", fakeldap.Dup.Password)
	assert.Equal(t, [2]string{ldap.ReasonAmbiguousUser, ldap.DetailUserSearch}, reasonOf(err), "two entries share the login")
}

// The server's size limit: a filter that matches every person returns two entries and "size limit exceeded".
func TestResponseSizeLimit(t *testing.T) {
	x := newHarness(t)
	x.update(t, ldap.DirectoryPatch{UserFilter: ptr("(|(uid={login})(objectClass=inetOrgPerson))")})
	_, err := x.verify("ada", fakeldap.Ada.Password)
	assert.Equal(t, [2]string{ldap.ReasonAmbiguousUser, ldap.DetailUserSearch}, reasonOf(err))
}

func TestFilterInjectionDoesNotMatchOtherUsers(t *testing.T) {
	x := newHarness(t)
	for _, login := range []string{"ada)(uid=*", "ada)(|(uid=*", "ad*", "*ada", "a*a", `ada\2a`, "ada)", "(uid=ada)",
		"*)(uid=ada", "ada\\", "x)(objectClass=*"} {
		before := x.dials.Load()
		_, err := x.verify(login, fakeldap.Ada.Password)
		assert.Equal(t, [2]string{ldap.ReasonBadCredentials, ldap.DetailNotFound}, reasonOf(err), "%q", login)
		assert.Equal(t, before+1, x.dials.Load(), "%q was searched for (escaped) and found nobody", login)
	}
	// Escaping is per value: the template's own wildcard still works.
	x.update(t, ldap.DirectoryPatch{UserFilter: ptr("(&(objectClass=inetOrgPerson)(mail={login}@example.test))")})
	_, err := x.verify("ada", fakeldap.Ada.Password)
	require.NoError(t, err)
	_, err = x.verify("*", fakeldap.Ada.Password)
	assert.Equal(t, [2]string{ldap.ReasonBadCredentials, ldap.DetailLoginName}, reasonOf(err))
}

func TestGroupSearchTemplateWithDNAndNested(t *testing.T) {
	x := newHarness(t)
	groups := func(login, password string) []string {
		t.Helper()
		id, err := x.verify(login, password)
		require.NoError(t, err)
		return id.Groups
	}
	// The DN of the group entry when no name attribute is set.
	x.update(t, ldap.DirectoryPatch{GroupNameAttribute: ptr("")})
	assert.Equal(t, []string{fakeldap.OpsDN}, groups("ada", fakeldap.Ada.Password))
	// {login}: the login as the directory holds it.
	x.update(t, ldap.DirectoryPatch{GroupNameAttribute: ptr("cn"), GroupFilter: ptr("(&(objectClass=posixGroup)(memberUid={login}))")})
	assert.Equal(t, []string{"alice-posix"}, groups("ada", fakeldap.Ada.Password))
	// Both placeholders.
	x.update(t, ldap.DirectoryPatch{GroupFilter: ptr("(|(member={dn})(memberUid={login}))")})
	assert.ElementsMatch(t, []string{"alice-ops", "alice-posix"}, groups("ada", fakeldap.Ada.Password))
	// Nested groups: generic LDAP follows none; a second search level is the administrator's filter. OpenLDAP does not
	// implement Active Directory's LDAP_MATCHING_RULE_IN_CHAIN: the AD template finds nothing here (not verifiable
	// without AD).
	assert.Equal(t, []string{"alice-auditors"}, groups(fakeldap.Cigdem.Login, fakeldap.Cigdem.Password))
	x.update(t, ldap.DirectoryPatch{GroupFilter: ptr(ldap.ADGroupFilter)})
	id, err := x.verify(fakeldap.Cigdem.Login, fakeldap.Cigdem.Password)
	require.NoError(t, err)
	assert.Empty(t, id.Groups, "OpenLDAP evaluates the unknown matching rule as Undefined: no group")
	// memberOf (the overlay) in a user filter: only members of alice-ops may sign in.
	x.update(t, ldap.DirectoryPatch{GroupFilter: ptr(fakeldap.GroupFilter),
		UserFilter: ptr("(&(uid={login})(memberOf=" + fakeldap.OpsDN + "))")})
	assert.Equal(t, []string{"alice-ops"}, groups("ada", fakeldap.Ada.Password))
	_, err = x.verify("grace", fakeldap.Grace.Password)
	assert.Equal(t, ldap.ReasonBadCredentials, reasonOf(err)[0])
}

func TestTLSWrongAuthorityIsRefused(t *testing.T) {
	x := newHarness(t)
	other := string(pki.NewCA("other", pki.RSA2048, time.Now()).RootPEM)
	x.update(t, ldap.DirectoryPatch{CAPEM: &other})
	_, err := x.verify("ada", fakeldap.Ada.Password)
	assert.Equal(t, [2]string{ldap.ReasonMisconfigured, ldap.DetailTLS}, reasonOf(err))
	x.update(t, ldap.DirectoryPatch{CAPEM: ptr("")})
	_, err = x.verify("ada", fakeldap.Ada.Password)
	assert.Equal(t, [2]string{ldap.ReasonMisconfigured, ldap.DetailTLS}, reasonOf(err), "the system roots do not trust the test CA")
}

func TestTLSWrongHostNameIsRefused(t *testing.T) {
	x := newHarness(t)
	port := strconv.Itoa(x.srv.Port)
	// The certificate names ldap.example.test: the redirected name passes, another name does not.
	x.redirect.Store("ldap.example.test:" + port)
	x.update(t, ldap.DirectoryPatch{Addresses: &[]string{"ldaps://ldap.example.test:" + port}, BindPassword: secretPtr(x.srv.ServicePassword())})
	_, err := x.verify("ada", fakeldap.Ada.Password)
	require.NoError(t, err, "positive control")
	x.redirect.Store("wrong.example.test:" + port)
	x.update(t, ldap.DirectoryPatch{Addresses: &[]string{"ldaps://wrong.example.test:" + port}, BindPassword: secretPtr(x.srv.ServicePassword())})
	_, err = x.verify("ada", fakeldap.Ada.Password)
	assert.Equal(t, [2]string{ldap.ReasonMisconfigured, ldap.DetailTLS}, reasonOf(err))
}

func TestPlainLDAPAddressIsRejectedByTheDatabaseAndTheService(t *testing.T) {
	x := newHarness(t)
	for _, addr := range []string{"ldap://" + x.srv.Endpoint(), "LDAPS://" + x.srv.Endpoint(), "Ldaps://" + x.srv.Endpoint()} {
		in := x.input("Plain "+addr[:5], false)
		in.Addresses = []string{addr}
		_, err := x.svc.CreateDirectory(x.ctx, x.admin, in)
		assert.Equal(t, []string{"addresses"}, fieldNames(t, err), addr)
		_, err = x.svc.UpdateDirectory(x.ctx, x.admin, x.dir.ID, x.dir.Version, ldap.DirectoryPatch{Addresses: &[]string{addr},
			BindPassword: secretPtr("x")})
		assert.Equal(t, []string{"addresses"}, fieldNames(t, err), addr)
		_, err = x.d.Owner.Exec(x.ctx, "UPDATE ldap_directories SET addresses = $2 WHERE id = $1", x.dir.ID, []string{addr})
		assert.ErrorContains(t, err, "ldap_directories_addresses_check", "the database refuses %s too", addr)
	}
	assert.Zero(t, x.dials.Load())
}

// The dial is the injected one (netaddr by default): the configured address reaches it, and a dial that refuses an
// address stops the sign-in before anything is sent.
func TestDialIsTheInjectedOne(t *testing.T) {
	x := newHarness(t)
	_, err := x.verify("ada", fakeldap.Ada.Password)
	require.NoError(t, err)
	assert.Equal(t, int64(2), x.dials.Load())
	x.update(t, ldap.DirectoryPatch{Addresses: &[]string{"ldaps://169.254.169.254:636"}, BindPassword: secretPtr(x.srv.ServicePassword())})
	_, err = x.verify("ada", fakeldap.Ada.Password)
	assert.Equal(t, [2]string{ldap.ReasonMisconfigured, ldap.DetailConnect}, reasonOf(err), "netaddr refuses the metadata address")
	assert.Equal(t, int64(3), x.dials.Load())
}

func TestReferralsAreNotFollowed(t *testing.T) {
	x := newHarness(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()
	var hits atomic.Int64
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			hits.Add(1)
			_ = c.Close()
		}
	}()
	x.srv.Add(t, "ou=elsewhere,"+fakeldap.PeopleDN, map[string][]string{"objectClass": {"referral", "extensibleObject"},
		"ou": {"elsewhere"}, "ref": {"ldap://" + ln.Addr().String() + "/ou=people,dc=elsewhere,dc=test"}})
	id, err := x.verify("ada", fakeldap.Ada.Password)
	require.NoError(t, err, "the search reference is ignored")
	assert.Equal(t, "ada", id.Login)
	_, err = x.verify("someone-elsewhere", "pw")
	assert.Equal(t, ldap.ReasonBadCredentials, reasonOf(err)[0])
	// A base DN under the referral: the server answers with a referral result, which is not followed.
	x.update(t, ldap.DirectoryPatch{UserBaseDN: ptr("ou=x,ou=elsewhere," + fakeldap.PeopleDN)})
	_, err = x.verify("ada", fakeldap.Ada.Password)
	assert.Equal(t, [2]string{ldap.ReasonMisconfigured, ldap.DetailUserSearch}, reasonOf(err))
	assert.Zero(t, hits.Load(), "nobody dialled the referred server")
}

func TestServiceAccountFailureIsMisconfiguredNotBadCredentials(t *testing.T) {
	x := newHarness(t)
	x.update(t, ldap.DirectoryPatch{BindPassword: secretPtr("not-the-service-password")})
	for range 3 {
		_, err := x.verify("ada", fakeldap.Ada.Password)
		assert.Equal(t, [2]string{ldap.ReasonMisconfigured, ldap.DetailServiceBind}, reasonOf(err))
	}
	assert.Equal(t, 1, strings.Count(x.logs.String(), "refused its service account"), "logged once: %s", x.logs.String())
	x.update(t, ldap.DirectoryPatch{BindDN: ptr("cn=nobody," + fakeldap.ServicesDN), BindPassword: secretPtr(x.srv.ServicePassword())})
	_, err := x.verify("ada", fakeldap.Ada.Password)
	assert.Equal(t, [2]string{ldap.ReasonMisconfigured, ldap.DetailServiceBind}, reasonOf(err))
	assert.NotContains(t, x.logs.String(), "not-the-service-password")
}

func TestVerifyRefusesADisabledOrMissingDirectory(t *testing.T) {
	x := newHarness(t)
	x.update(t, ldap.DirectoryPatch{Enabled: ptr(false)})
	_, err := x.verify("ada", fakeldap.Ada.Password)
	assert.Equal(t, ldap.ReasonDisabled, reasonOf(err)[0])
	_, _, err = x.svc.Verify(x.ctx, [16]byte{1}, "ada", secrets.NewPlaintext([]byte("p")))
	assert.ErrorIs(t, err, ldap.ErrNotFound)
	assert.Zero(t, x.dials.Load())
	// A directory whose password row is gone is misconfigured, before any traffic.
	x.update(t, ldap.DirectoryPatch{Enabled: ptr(true)})
	_, err = x.d.Owner.Exec(x.ctx, "DELETE FROM setting_secrets WHERE key LIKE 'ldap.directory.%'")
	require.NoError(t, err)
	_, err = x.verify("ada", fakeldap.Ada.Password)
	assert.Equal(t, [2]string{ldap.ReasonMisconfigured, ldap.DetailNoSecret}, reasonOf(err))
	assert.Zero(t, x.dials.Load())
}

func TestUnreachableDirectory(t *testing.T) {
	x := newHarness(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	dead := ln.Addr().String()
	require.NoError(t, ln.Close())
	x.update(t, ldap.DirectoryPatch{Addresses: &[]string{"ldaps://" + dead}, BindPassword: secretPtr(x.srv.ServicePassword())})
	_, err = x.verify("ada", fakeldap.Ada.Password)
	assert.Equal(t, [2]string{ldap.ReasonUnreachable, ldap.DetailConnect}, reasonOf(err))
	// The dead address first, the server second: the next one is tried.
	x.update(t, ldap.DirectoryPatch{Addresses: &[]string{"ldaps://" + dead, x.srv.Address}, BindPassword: secretPtr(x.srv.ServicePassword())})
	_, err = x.verify("ada", fakeldap.Ada.Password)
	require.NoError(t, err)
	// The caller's context bounds Verify.
	ctx, cancel := context.WithCancel(x.ctx)
	cancel()
	_, _, err = x.svc.Verify(ctx, x.dir.ID, "ada", secrets.NewPlaintext([]byte(fakeldap.Ada.Password)))
	assert.Error(t, err)
}
