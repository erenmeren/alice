package azurekv

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/providers"
	"alice/internal/testutil/fakekv"
)

func TestAccessCheckWithEveryRole(t *testing.T) {
	w := newWorld(t, fakekv.Options{})
	rep, err := w.check()
	require.NoError(t, err)
	require.NotNil(t, rep.Azure)
	assert.Equal(t, w.s.ObjectID(), rep.Azure.ObjectID, "the oid of the token, shown as 'Alice signs in to Azure as'")
	assert.Equal(t, w.s.TenantID(), rep.Azure.TenantID)
	assert.Equal(t, []providers.AzureCheck{
		{Name: providers.AzureCheckSignIn, Result: providers.AzureResultOK},
		{Name: providers.AzureCheckListCertificates, Result: providers.AzureResultOK},
		{Name: providers.AzureCheckListKeys, Result: providers.AzureResultOK},
		{Name: providers.AzureCheckListSecrets, Result: providers.AzureResultOK},
		{Name: providers.AzureCheckReadSecret, Result: providers.AzureResultNotChecked},
		{Name: providers.AzureCheckImport, Result: providers.AzureResultNotChecked},
	}, rep.Azure.Checks)
	assert.Equal(t, "unknown", rep.Azure.PermissionModel, "no 403 was seen: the model is not known")
	assert.Equal(t, w.clk.Now(), rep.Azure.CheckedAt, "the injected clock")
}

func TestAccessCheckReadsOnePagePerList(t *testing.T) {
	w := newWorld(t, fakekv.Options{})
	w.s.AddBulkCertificates("bulk", 60) // three pages of certificates, and as many secrets and keys
	_, err := w.check()
	require.NoError(t, err)
	listings := map[string]int{}
	for _, r := range w.vaultRequests() {
		if r.HadAuth {
			listings[r.Path]++
		}
	}
	assert.Equal(t, map[string]int{"/certificates": 1, "/keys": 1, "/secrets": 1}, listings, "the first page of each list only")
}

func TestAccessCheckReportsMissingRolesAndTheModel(t *testing.T) {
	forbidden := func(name, role string) providers.AzureCheck {
		return providers.AzureCheck{Name: name, Result: providers.AzureResultForbidden, Reason: codeForbidden, Role: role}
	}
	ok := func(name string) providers.AzureCheck {
		return providers.AzureCheck{Name: name, Result: providers.AzureResultOK}
	}
	notChecked := []providers.AzureCheck{
		{Name: providers.AzureCheckReadSecret, Result: providers.AzureResultNotChecked},
		{Name: providers.AzureCheckImport, Result: providers.AzureResultNotChecked},
	}
	signIn := ok(providers.AzureCheckSignIn)
	cases := []struct {
		name  string
		opts  fakekv.Options
		setup func(s *fakekv.Server)
		model string
		rows  []providers.AzureCheck
	}{
		{"keys list revoked on an RBAC vault", fakekv.Options{}, func(s *fakekv.Server) { s.RevokeRole("keys/list") }, "rbac",
			[]providers.AzureCheck{signIn, ok(providers.AzureCheckListCertificates), forbidden(providers.AzureCheckListKeys, providers.RoleKeyVaultReader),
				ok(providers.AzureCheckListSecrets)}},
		{"keys list revoked on an access-policy vault", fakekv.Options{Model: "access_policy"}, func(s *fakekv.Server) { s.RevokeRole("keys/list") }, "access_policy",
			[]providers.AzureCheck{signIn, ok(providers.AzureCheckListCertificates), forbidden(providers.AzureCheckListKeys, providers.RoleKeyVaultReader),
				ok(providers.AzureCheckListSecrets)}},
		{"all three lists forbidden", fakekv.Options{}, func(s *fakekv.Server) { s.SetRoles() }, "rbac",
			[]providers.AzureCheck{signIn, forbidden(providers.AzureCheckListCertificates, providers.RoleKeyVaultReader),
				forbidden(providers.AzureCheckListKeys, providers.RoleKeyVaultReader), forbidden(providers.AzureCheckListSecrets, providers.RoleKeyVaultReader)}},
		{"only the secrets role", fakekv.Options{}, func(s *fakekv.Server) { s.SetRoles(fakekv.RoleSecretsUser) }, "rbac",
			[]providers.AzureCheck{signIn, forbidden(providers.AzureCheckListCertificates, providers.RoleKeyVaultReader),
				forbidden(providers.AzureCheckListKeys, providers.RoleKeyVaultReader), ok(providers.AzureCheckListSecrets)}},
		{"firewall", fakekv.Options{}, func(s *fakekv.Server) { s.Firewall("203.0.113.7") }, "unknown",
			[]providers.AzureCheck{signIn,
				{Name: providers.AzureCheckListCertificates, Result: providers.AzureResultForbidden, Reason: codeFirewall},
				{Name: providers.AzureCheckListKeys, Result: providers.AzureResultForbidden, Reason: codeFirewall},
				{Name: providers.AzureCheckListSecrets, Result: providers.AzureResultForbidden, Reason: codeFirewall}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w := newWorld(t, c.opts)
			c.setup(w.s)
			rep, err := w.check()
			require.NoError(t, err, "the vault is reachable: monitoring continues, the checklist says what is missing")
			require.NotNil(t, rep.Azure)
			assert.Equal(t, c.model, rep.Azure.PermissionModel)
			assert.Equal(t, append(c.rows, notChecked...), rep.Azure.Checks)
		})
	}

	t.Run("a failing secrets list is a failed row, not an error", func(t *testing.T) {
		w := newWorld(t, fakekv.Options{})
		w.s.FailAll("/secrets", fakekv.Fault{Status: 500})
		rep, err := w.check()
		require.NoError(t, err)
		assert.Equal(t, providers.AzureCheck{Name: providers.AzureCheckListSecrets, Result: providers.AzureResultFailed, Reason: codeUnreachable}, rep.Azure.Checks[3])
	})
}

func TestAccessCheckRefusesWhatIsNotTheVault(t *testing.T) {
	nxdomain := &net.DNSError{Err: "no such host", Name: testVaultHost, IsNotFound: true}
	refused := &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("connection refused")}
	t.Run("wrong secret: the sign-in error, no report", func(t *testing.T) {
		s := fakekv.Start(t, fakekv.Options{})
		id := secretIdentity(s)
		id.ClientSecret = providers.NewSecret([]byte(fakekv.NewClientSecret()))
		clk := nearNow()
		sess := openSession(t, testProvider(s), &idSource{id: id}, clk)
		var rep providers.ConnectionReport
		err := drive(clk, func() (e error) { rep, e = sess.TestConnection(context.Background()); return e })
		assert.Equal(t, codeAuthFailed, asProviderError(t, err).Code)
		assert.Nil(t, rep.Azure)
	})
	t.Run("unknown vault (F-43): azure.vault_not_found is an error", func(t *testing.T) {
		w := newWorld(t, fakekv.Options{}, dialFailingTune(testVaultHost, nxdomain))
		rep, err := w.check()
		assert.Equal(t, codeVaultNotFound, asProviderError(t, err).Code)
		assert.Nil(t, rep.Azure)
	})
	t.Run("vault unreachable: azure.unreachable is an error", func(t *testing.T) {
		w := newWorld(t, fakekv.Options{}, dialFailingTune(testVaultHost, refused))
		_, err := w.check()
		assert.Equal(t, codeUnreachable, asProviderError(t, err).Code)
	})
	t.Run("the first list answering 500 is an error too", func(t *testing.T) {
		w := newWorld(t, fakekv.Options{})
		w.s.FailAll("/certificates", fakekv.Fault{Status: 503})
		_, err := w.check()
		assert.Equal(t, codeUnreachable, asProviderError(t, err).Code)
	})
	t.Run("a cancelled context sends nothing and wraps the context error", func(t *testing.T) {
		w := newWorld(t, fakekv.Options{})
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, err := w.sess.TestConnection(ctx)
		assert.ErrorIs(t, err, context.Canceled)
		assert.Empty(t, w.s.Requests())
	})
}

// TestTokenClaimsAreOnlyDisplayed: the oid and tid are read for display and kept only when they are
// GUIDs (ruling S13); the token itself is never part of the report.
func TestTokenClaimsAreOnlyDisplayed(t *testing.T) {
	const (
		oid = "0A1B2C3D-4E5F-4A6B-8C7D-9E0F1A2B3C4D"
		tid = "11111111-2222-4333-8444-555555555555"
	)
	cases := []struct {
		name, oid, tid, wantOID, wantTID string
	}{
		{"guids, upper case folded", oid, tid, "0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d", tid},
		{"not guids", "<script>alert(1)</script>", "tenant", "", ""},
		{"empty", "", "", "", ""},
		{"braces and urn forms", "{" + oid + "}", "urn:uuid:" + tid, "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w := newWorld(t, fakekv.Options{})
			w.s.SetTokenClaims(c.oid, c.tid)
			rep, err := w.check()
			require.NoError(t, err)
			assert.Equal(t, c.wantOID, rep.Azure.ObjectID)
			assert.Equal(t, c.wantTID, rep.Azure.TenantID)
		})
	}
}

func TestClaimsOfUndecodableTokens(t *testing.T) {
	good := func(payload string) string { return "h." + payload + ".s" }
	enc := func(s string) string { return base64RawURL([]byte(s)) }
	cases := map[string]string{
		"not a jwt":            "opaque",
		"two segments":         "a.b",
		"payload not base64":   "a.%%%.c",
		"payload not json":     good(enc("{not json")),
		"payload is an array":  good(enc("[1,2]")),
		"claims of other type": good(enc(`{"oid":7,"tid":["x"]}`)),
		"huge token":           "a." + string(make([]byte, maxTokenForClaims+1)) + ".c",
	}
	for name, tok := range cases {
		t.Run(name, func(t *testing.T) {
			oid, tid := claimsOf(tok)
			assert.Empty(t, oid)
			assert.Empty(t, tid)
		})
	}
	oid, tid := claimsOf(good(enc(`{"oid":"0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d","tid":"11111111-2222-4333-8444-555555555555","x":1}`)))
	assert.Equal(t, "0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d", oid)
	assert.Equal(t, "11111111-2222-4333-8444-555555555555", tid)
}

// A token that fails to decode never fails the access check.
func TestAccessCheckSurvivesAnOpaqueToken(t *testing.T) {
	api := &stubAPI{token: func() (azcore.AccessToken, error) { return azcore.AccessToken{Token: "opaque"}, nil }}
	sess, _ := stubSession(api)
	rep, err := sess.TestConnection(context.Background())
	require.NoError(t, err)
	assert.Empty(t, rep.Azure.ObjectID)
	assert.Empty(t, rep.Azure.TenantID)
	assert.Equal(t, []string{"token", "list_certificates", "list_keys", "list_secrets"}, api.calls)
}

func TestSessionOperationsHonourACancelledContext(t *testing.T) {
	api := &stubAPI{}
	sess, _ := stubSession(api)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := sess.Discover(ctx, providers.DiscoverRequest{Certificates: true})
	assert.ErrorIs(t, err, context.Canceled)
	_, err = sess.TestConnection(ctx)
	assert.ErrorIs(t, err, context.Canceled)
	assert.Empty(t, api.calls, "nothing was asked of the vault")
}
