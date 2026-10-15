//go:build integration

package ldap_test

import (
	"context"
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/auth/ldap"
	"alice/internal/rbac"
	"alice/internal/secrets"
	"alice/internal/testutil/fakeldap"
)

func TestTestConnectionAudited(t *testing.T) {
	x := newHarness(t)
	require.NoError(t, x.svc.TestConnection(x.ctx, x.admin, x.dir.ID))
	assert.Equal(t, 1, x.count(t, `SELECT count(*) FROM audit_log WHERE action = 'ldap.directory_tested' AND result = 'success'
AND details->>'result' = 'ok' AND details->>'directory_id' = $1`, x.dir.ID.String()))

	// A directory that is switched off can be tested.
	x.update(t, ldap.DirectoryPatch{Enabled: ptr(false), UserBaseDN: ptr("ou=missing," + fakeldap.BaseDN)})
	err := x.svc.TestConnection(x.ctx, x.admin, x.dir.ID)
	assert.Equal(t, [2]string{ldap.ReasonMisconfigured, ldap.DetailUserSearch}, reasonOf(err))
	x.update(t, ldap.DirectoryPatch{UserBaseDN: ptr(fakeldap.PeopleDN), BindPassword: secretPtr("wrong")})
	err = x.svc.TestConnection(x.ctx, x.admin, x.dir.ID)
	assert.Equal(t, [2]string{ldap.ReasonMisconfigured, ldap.DetailServiceBind}, reasonOf(err))
	assert.Equal(t, 1, x.count(t, `SELECT count(*) FROM audit_log WHERE action = 'ldap.directory_tested' AND result = 'failure'
AND details->>'reason' = 'directory_misconfigured' AND details->>'detail' = 'service_bind'`))
	assert.Equal(t, 3, x.count(t, `SELECT count(*) FROM audit_log WHERE action = 'ldap.directory_tested'`))
	assert.ErrorIs(t, x.svc.TestConnection(x.ctx, x.admin, uuid.New()), ldap.ErrNotFound)

	// A client without connection tests (a test double) says so.
	stub := ldap.New(ldap.Config{Pool: x.d.App, Keyring: x.kr, Clock: x.clk, NewClient: func() ldap.Client { return stubClient{} }})
	assert.ErrorIs(t, stub.TestConnection(x.ctx, x.admin, x.dir.ID), ldap.ErrNoConnectionTest)
}

func TestTestSignInShowsGroupsAndRole(t *testing.T) {
	x := newHarness(t)
	_, err := x.svc.CreateMapping(x.ctx, x.admin, x.dir.ID, "alice-ops", rbac.Operator)
	require.NoError(t, err)
	_, err = x.svc.CreateMapping(x.ctx, x.admin, x.dir.ID, "alice-auditors", rbac.Auditor)
	require.NoError(t, err)
	users := x.count(t, "SELECT count(*) FROM users")
	x.update(t, ldap.DirectoryPatch{Enabled: ptr(false)}) // a switched-off directory can be tested before it is offered
	p := secrets.NewPlaintext([]byte(fakeldap.Ada.Password))
	res, err := x.svc.TestSignIn(x.ctx, x.admin, x.dir.ID, "ada", p)
	require.NoError(t, err)
	assert.Equal(t, rbac.Operator, res.Role)
	assert.Equal(t, []string{"alice-ops"}, res.Identity.Groups)
	assert.Equal(t, "Ada Lovelace", res.Identity.DisplayName)
	assert.Equal(t, make([]byte, len(fakeldap.Ada.Password)), p.Bytes(), "the password was cleared")
	assert.Equal(t, 1, x.count(t, `SELECT count(*) FROM audit_log WHERE action = 'ldap.signin_tested' AND result = 'success'
AND details->>'role' = 'operator' AND details->>'login' = 'ada' AND details->>'group_count' = '1'`))

	res, err = x.svc.TestSignIn(x.ctx, x.admin, x.dir.ID, "grace", secrets.NewPlaintext([]byte(fakeldap.Grace.Password)))
	require.NoError(t, err)
	assert.Equal(t, rbac.Role(""), res.Role, "no mapped group: no role")
	assert.Equal(t, 1, x.count(t, `SELECT count(*) FROM audit_log WHERE action = 'ldap.signin_tested' AND details->>'role' = 'none'
AND details->>'reason' = 'no_access'`))

	_, err = x.svc.TestSignIn(x.ctx, x.admin, x.dir.ID, "ada", secrets.NewPlaintext([]byte("wrong")))
	assert.Equal(t, ldap.ReasonBadCredentials, reasonOf(err)[0])
	_, err = x.svc.TestSignIn(x.ctx, x.admin, x.dir.ID, " ada", secrets.NewPlaintext([]byte("wrong")))
	assert.Equal(t, ldap.ReasonLoginInvalid, reasonOf(err)[0])
	assert.Equal(t, 2, x.count(t, `SELECT count(*) FROM audit_log WHERE action = 'ldap.signin_tested' AND result = 'failure'`))
	assert.Equal(t, 1, x.count(t, `SELECT count(*) FROM audit_log WHERE action = 'ldap.signin_tested' AND details->>'reason' = 'login_invalid'
AND NOT details ? 'login'`), "a refused name is not recorded")
	_, err = x.svc.TestSignIn(x.ctx, x.admin, uuid.New(), "ada", secrets.NewPlaintext([]byte("p")))
	assert.ErrorIs(t, err, ldap.ErrNotFound)
	assert.Equal(t, users, x.count(t, "SELECT count(*) FROM users"), "nothing is stored")
}

// Review focus: the service account password and the user's password appear in no audit record, error or log line,
// whatever the path.
func TestPasswordNeverInAuditOrErrors(t *testing.T) {
	x := newHarness(t)
	canary := "Zq7-canary-" + uuid.NewString()
	bindCanary := "Bq7-bind-canary-" + uuid.NewString()
	var errs []string
	note := func(err error) {
		if err != nil {
			errs = append(errs, err.Error(), fmt.Sprintf("%+v", err), fmt.Sprintf("%#v", err))
		}
	}
	attempt := func(login string) {
		_, _, err := x.svc.Verify(x.ctx, x.dir.ID, login, secrets.NewPlaintext([]byte(canary)))
		note(err)
		_, err = x.svc.TestSignIn(x.ctx, x.admin, x.dir.ID, login, secrets.NewPlaintext([]byte(canary)))
		note(err)
	}
	for _, login := range []string{"ada", "nobody", "dup", " bad", "*", "ada)(uid=*"} {
		attempt(login)
	}
	_, err := x.svc.TestSignIn(x.ctx, x.admin, x.dir.ID, "ada", secrets.NewPlaintext([]byte(fakeldap.Ada.Password)))
	require.NoError(t, err)

	// The service account password is the canary now: the bind fails with it.
	x.update(t, ldap.DirectoryPatch{BindPassword: secretPtr(bindCanary)})
	attempt("ada")
	note(x.svc.TestConnection(x.ctx, x.admin, x.dir.ID))
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	dead := ln.Addr().String()
	require.NoError(t, ln.Close())
	x.update(t, ldap.DirectoryPatch{Addresses: &[]string{"ldaps://" + dead}, BindPassword: secretPtr(bindCanary)})
	attempt("ada")
	note(x.svc.TestConnection(x.ctx, x.admin, x.dir.ID))
	x.update(t, ldap.DirectoryPatch{Addresses: &[]string{x.srv.Address}, CAPEM: ptr(""), BindPassword: secretPtr(bindCanary)})
	attempt("ada")
	x.update(t, ldap.DirectoryPatch{Enabled: ptr(false)})
	attempt("ada")
	ctx, cancel := context.WithCancel(x.ctx)
	cancel()
	_, _, err = x.svc.Verify(ctx, x.dir.ID, "ada", secrets.NewPlaintext([]byte(canary)))
	note(err)

	require.NotEmpty(t, errs)
	var dump string
	require.NoError(t, x.d.Owner.QueryRow(x.ctx, `SELECT coalesce(string_agg(action || ' ' || details::text, ' '), '') FROM audit_log`).Scan(&dump))
	require.Contains(t, dump, "ldap.signin_tested", "the audit rows were written")
	for _, secret := range []string{canary, bindCanary, fakeldap.Ada.Password, x.srv.ServicePassword()} {
		assert.NotContains(t, dump, secret)
		assert.NotContains(t, x.logs.String(), secret)
		for _, e := range errs {
			assert.NotContains(t, e, secret)
		}
	}
	assert.True(t, strings.Contains(dump, "bad_credentials") && strings.Contains(dump, "directory_unreachable") &&
		strings.Contains(dump, "directory_misconfigured") && strings.Contains(dump, "ambiguous_user") &&
		strings.Contains(dump, "login_invalid"), "every path ran: %s", dump)
}

// stubClient is a test double of the network client (the seam later tasks use).
type stubClient struct{}

func (stubClient) Authenticate(context.Context, ldap.Directory, secrets.Plaintext, string, secrets.Plaintext) (ldap.Entry, error) {
	return ldap.Entry{DN: "uid=stub", Attrs: map[string][][]byte{"entryUUID": {[]byte("stub-id")}, "uid": {[]byte("stub")}}}, nil
}

func (stubClient) Groups(context.Context, ldap.Directory, secrets.Plaintext, ldap.Entry, string) ([]string, error) {
	return []string{"stub-group"}, nil
}

func TestClientSeam(t *testing.T) {
	x := newHarness(t)
	svc := ldap.New(ldap.Config{Pool: x.d.App, Keyring: x.kr, Clock: x.clk, NewClient: func() ldap.Client { return stubClient{} }})
	id, _, err := svc.Verify(x.ctx, x.dir.ID, "anyone", secrets.NewPlaintext([]byte("p")))
	require.NoError(t, err)
	assert.Equal(t, ldap.Identity{UniqueID: "737475622d6964", Login: "stub", Groups: []string{"stub-group"}}, id)
	assert.Zero(t, x.dials.Load())
}
