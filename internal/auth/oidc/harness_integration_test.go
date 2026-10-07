//go:build integration

package oidc_test

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"alice/internal/audit"
	"alice/internal/auth"
	"alice/internal/auth/oidc"
	"alice/internal/platform/clock"
	"alice/internal/platform/settings"
	"alice/internal/rbac"
	"alice/internal/secrets"
	"alice/internal/testutil/fakeidp"
	"alice/internal/testutil/pgtest"
)

func TestMain(m *testing.M) { os.Exit(pgtest.Main(m)) }

var meta = auth.Meta{IP: netip.MustParseAddr("192.0.2.10"), UserAgent: "test", RequestID: "req-1"}

type harness struct {
	ctx   context.Context
	d     *pgtest.DB
	clk   *clock.Fake
	idp   *fakeidp.Server
	auth  *auth.Service
	svc   *oidc.Service
	admin audit.Actor
	prov  oidc.Provider
}

const publicURL = "https://alice.example.test"

func newHarness(t *testing.T) *harness {
	t.Helper()
	d := pgtest.New(t)
	clk := clock.NewFake(time.Date(2026, 10, 7, 9, 0, 0, 0, time.UTC))
	idp := fakeidp.Start(t, fakeidp.Options{Now: clk.Now})
	kr, err := secrets.NewKeyring(1, bytes.Repeat([]byte{7}, 32))
	require.NoError(t, err)
	h := auth.NewHasher(auth.Argon2Params{MemoryKiB: 64, Time: 1, Threads: 1, SaltLen: 16, KeyLen: 32}, 4)
	a := auth.NewService(auth.Config{Pool: d.App, Keyring: kr, Audit: audit.New(clk), Clock: clk, Hasher: h, RecoveryHasher: h})
	svc := oidc.New(oidc.Config{Pool: d.App, Keyring: kr, Audit: audit.New(clk), Clock: clk, Auth: a})
	require.NoError(t, settings.Set(context.Background(), d.App, settings.GeneralKey,
		settings.General{PublicURL: publicURL, RetiredKeyRetentionDays: 30, Version: 1}, clk.Now()))
	// D-s3-04: created_by references users, so the acting Administrator exists.
	adminID := uuid.New()
	_, err = d.Owner.Exec(context.Background(), `INSERT INTO users (id, username, display_name, password_hash, role, created_at, updated_at)
VALUES ($1, 'ada-admin', 'Ada', '$argon2id$x', 'admin', now(), now())`, adminID)
	require.NoError(t, err)
	x := &harness{ctx: context.Background(), d: d, clk: clk, idp: idp, auth: a, svc: svc,
		admin: audit.Actor{Type: audit.ActorUser, ID: adminID, Name: "ada-admin"}}
	x.prov = x.createProvider(t, true)
	idp.RegisterRedirect(x.prov.RedirectURI)
	return x
}

func (x *harness) createProvider(t *testing.T, enabled bool) oidc.Provider {
	t.Helper()
	p, err := x.svc.CreateProvider(x.ctx, x.admin, oidc.ProviderInput{Name: "Corp IdP", IssuerURL: x.idp.Issuer(),
		ClientID: x.idp.ClientID(), ClientSecret: secrets.NewPlaintext([]byte(x.idp.ClientSecret())), CAPEM: string(x.idp.CAPEM()),
		Enabled: enabled})
	require.NoError(t, err)
	return p
}

func (x *harness) mapGroup(t *testing.T, group string, role rbac.Role) {
	t.Helper()
	_, err := x.svc.CreateMapping(x.ctx, x.admin, x.prov.ID, group, role)
	require.NoError(t, err)
}

// login runs the browser's round trip: Begin, the IdP's authorize step, Complete with the callback's query.
func (x *harness) login(t *testing.T, next string) (oidc.Completion, error) {
	t.Helper()
	b, err := x.svc.Begin(x.ctx, oidc.BeginInput{ProviderID: x.prov.ID, Next: next})
	require.NoError(t, err)
	cb, err := x.idp.Authorize(b.AuthorizeURL)
	require.NoError(t, err)
	u, err := url.Parse(cb)
	require.NoError(t, err)
	return x.svc.Complete(x.ctx, x.prov.ID, u.Query(), b.Binding, meta)
}

func (x *harness) count(t *testing.T, sql string, args ...any) int {
	t.Helper()
	var n int
	require.NoError(t, x.d.Owner.QueryRow(x.ctx, sql, args...).Scan(&n))
	return n
}

func reasonOf(err error) string {
	var le *oidc.LoginError
	if errors.As(err, &le) {
		return le.Reason
	}
	return ""
}
