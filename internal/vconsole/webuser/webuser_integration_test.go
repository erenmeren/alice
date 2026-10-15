//go:build integration

package webuser_test

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/vconsole/vpgtest"
	"alice/internal/vconsole/webuser"
)

func TestMain(m *testing.M) { os.Exit(vpgtest.Main(m)) }

var now = time.Date(2026, 10, 15, 9, 0, 0, 0, time.UTC)

func TestEnrollmentCodeWorksOnce(t *testing.T) {
	d := vpgtest.New(t)
	ctx := context.Background()
	owner, web := d.As(t, "vendor_owner", "t_wu_owner1"), d.As(t, "vendor_web", "t_wu_web1")
	id, err := webuser.AddUser(ctx, owner, "ayse")
	require.NoError(t, err)
	code, err := webuser.NewEnrollment(ctx, owner, id, now, time.Hour)
	require.NoError(t, err)
	assert.Len(t, code, 43)

	u, err := webuser.LookupEnrollment(ctx, web, code, now)
	require.NoError(t, err)
	assert.Equal(t, id, u.ID)
	assert.Equal(t, "ayse", u.Name)
	require.NoError(t, webuser.ConsumeEnrollment(ctx, web, code, now))
	assert.ErrorIs(t, webuser.ConsumeEnrollment(ctx, web, code, now), webuser.ErrBadCode)
	_, err = webuser.LookupEnrollment(ctx, web, code, now)
	assert.ErrorIs(t, err, webuser.ErrBadCode)
}

func TestEnrollmentCodeExpires(t *testing.T) {
	d := vpgtest.New(t)
	ctx := context.Background()
	owner, web := d.As(t, "vendor_owner", "t_wu_owner2"), d.As(t, "vendor_web", "t_wu_web2")
	id, err := webuser.AddUser(ctx, owner, "ayse")
	require.NoError(t, err)
	code, err := webuser.NewEnrollment(ctx, owner, id, now, time.Minute)
	require.NoError(t, err)
	_, err = webuser.LookupEnrollment(ctx, web, code, now.Add(2*time.Minute))
	assert.ErrorIs(t, err, webuser.ErrBadCode)
	assert.ErrorIs(t, webuser.ConsumeEnrollment(ctx, web, code, now.Add(2*time.Minute)), webuser.ErrBadCode)
}

func TestWrongCodeIsRefused(t *testing.T) {
	d := vpgtest.New(t)
	ctx := context.Background()
	web := d.As(t, "vendor_web", "t_wu_web3")
	_, err := webuser.LookupEnrollment(ctx, web, "not-a-code", now)
	require.ErrorIs(t, err, webuser.ErrBadCode)
	assert.NotContains(t, strings.ToLower(err.Error()), "sql")
	assert.ErrorIs(t, webuser.ConsumeEnrollment(ctx, web, "not-a-code", now), webuser.ErrBadCode)
}

func TestDisabledUserCannotEnrollOrKeepASession(t *testing.T) {
	d := vpgtest.New(t)
	ctx := context.Background()
	owner, web := d.As(t, "vendor_owner", "t_wu_owner4"), d.As(t, "vendor_web", "t_wu_web4")
	id, err := webuser.AddUser(ctx, owner, "ayse")
	require.NoError(t, err)
	tok, err := webuser.NewSession(ctx, web, id, now)
	require.NoError(t, err)
	code, err := webuser.NewEnrollment(ctx, owner, id, now, time.Hour)
	require.NoError(t, err)
	_, err = webuser.Session(ctx, web, tok, now.Add(time.Minute))
	require.NoError(t, err)

	require.NoError(t, webuser.SetDisabled(ctx, owner, "ayse", true, now))
	_, err = webuser.Session(ctx, web, tok, now.Add(2*time.Minute))
	assert.ErrorIs(t, err, webuser.ErrNoSession)
	_, err = webuser.LookupEnrollment(ctx, web, code, now)
	assert.ErrorIs(t, err, webuser.ErrBadCode)
	assert.ErrorIs(t, webuser.ConsumeEnrollment(ctx, web, code, now), webuser.ErrBadCode)

	// Enabling again does not bring the deleted session back.
	require.NoError(t, webuser.SetDisabled(ctx, owner, "ayse", false, now))
	_, err = webuser.Session(ctx, web, tok, now.Add(3*time.Minute))
	assert.ErrorIs(t, err, webuser.ErrNoSession)
	assert.ErrorIs(t, webuser.SetDisabled(ctx, owner, "nobody", true, now), webuser.ErrNotFound)
}

func TestSessionIdleAndAbsoluteLimits(t *testing.T) {
	d := vpgtest.New(t)
	ctx := context.Background()
	owner, web := d.As(t, "vendor_owner", "t_wu_owner5"), d.As(t, "vendor_web", "t_wu_web5")
	id, err := webuser.AddUser(ctx, owner, "ayse")
	require.NoError(t, err)

	// Idle: ok just inside, moves last_seen, fails once idle too long.
	tok, err := webuser.NewSession(ctx, web, id, now)
	require.NoError(t, err)
	at := now.Add(29 * time.Minute)
	u, err := webuser.Session(ctx, web, tok, at)
	require.NoError(t, err)
	assert.Equal(t, "ayse", u.Name)
	var seen time.Time
	require.NoError(t, d.Owner.QueryRow(ctx, `SELECT last_seen FROM web_sessions`).Scan(&seen))
	assert.True(t, seen.Equal(at))
	_, err = webuser.Session(ctx, web, tok, at.Add(31*time.Minute))
	assert.ErrorIs(t, err, webuser.ErrNoSession)

	// Idle boundary: exactly SessionIdle is out, one second less is in.
	tok, err = webuser.NewSession(ctx, web, id, now)
	require.NoError(t, err)
	_, err = webuser.Session(ctx, web, tok, now.Add(webuser.SessionIdle))
	assert.ErrorIs(t, err, webuser.ErrNoSession)
	tok, err = webuser.NewSession(ctx, web, id, now)
	require.NoError(t, err)
	_, err = webuser.Session(ctx, web, tok, now.Add(webuser.SessionIdle-time.Second))
	assert.NoError(t, err)

	// Absolute: touched every 20 minutes, still dies at SessionAbsolute.
	tok, err = webuser.NewSession(ctx, web, id, now)
	require.NoError(t, err)
	for off := 20 * time.Minute; off < webuser.SessionAbsolute; off += 20 * time.Minute {
		_, err = webuser.Session(ctx, web, tok, now.Add(off))
		require.NoError(t, err, off)
	}
	_, err = webuser.Session(ctx, web, tok, now.Add(webuser.SessionAbsolute-time.Minute))
	require.NoError(t, err)
	_, err = webuser.Session(ctx, web, tok, now.Add(webuser.SessionAbsolute))
	assert.ErrorIs(t, err, webuser.ErrNoSession)
}

func TestForgedAndUnknownSessionTokens(t *testing.T) {
	d := vpgtest.New(t)
	ctx := context.Background()
	owner, web := d.As(t, "vendor_owner", "t_wu_owner6"), d.As(t, "vendor_web", "t_wu_web6")
	id, err := webuser.AddUser(ctx, owner, "ayse")
	require.NoError(t, err)
	tok, err := webuser.NewSession(ctx, web, id, now)
	require.NoError(t, err)
	flipped := "A" + tok[1:]
	if tok[0] == 'A' {
		flipped = "B" + tok[1:]
	}
	for _, bad := range []string{"", "random-token", flipped} {
		_, err := webuser.Session(ctx, web, bad, now)
		assert.ErrorIs(t, err, webuser.ErrNoSession, bad)
	}
	_, err = webuser.Session(ctx, web, tok, now)
	assert.NoError(t, err)
}

func TestEndSession(t *testing.T) {
	d := vpgtest.New(t)
	ctx := context.Background()
	owner, web := d.As(t, "vendor_owner", "t_wu_owner7"), d.As(t, "vendor_web", "t_wu_web7")
	id, err := webuser.AddUser(ctx, owner, "ayse")
	require.NoError(t, err)
	tok, err := webuser.NewSession(ctx, web, id, now)
	require.NoError(t, err)
	require.NoError(t, webuser.EndSession(ctx, web, tok))
	_, err = webuser.Session(ctx, web, tok, now)
	assert.ErrorIs(t, err, webuser.ErrNoSession)
}

func TestCredentialsRoundTrip(t *testing.T) {
	d := vpgtest.New(t)
	ctx := context.Background()
	owner, web := d.As(t, "vendor_owner", "t_wu_owner8"), d.As(t, "vendor_web", "t_wu_web8")
	id, err := webuser.AddUser(ctx, owner, "ayse")
	require.NoError(t, err)
	cid := []byte{1, 2, 3, 4}
	require.NoError(t, webuser.AddCredential(ctx, web, id, cid, []byte(`{"n":1}`)))
	creds, err := webuser.Credentials(ctx, web, id)
	require.NoError(t, err)
	require.Len(t, creds, 1)
	assert.Equal(t, cid, creds[0].ID)
	assert.JSONEq(t, `{"n":1}`, string(creds[0].JSON))

	require.NoError(t, webuser.UpdateCredential(ctx, web, cid, []byte(`{"n":2}`), now))
	creds, err = webuser.Credentials(ctx, web, id)
	require.NoError(t, err)
	assert.JSONEq(t, `{"n":2}`, string(creds[0].JSON))
	var used *time.Time
	require.NoError(t, d.Owner.QueryRow(ctx, `SELECT last_used_at FROM web_credentials`).Scan(&used))
	require.NotNil(t, used)
	assert.True(t, used.Equal(now))

	u, err := webuser.UserByCredential(ctx, web, cid)
	require.NoError(t, err)
	assert.Equal(t, id, u.ID)
	_, err = webuser.UserByCredential(ctx, web, []byte{9})
	assert.ErrorIs(t, err, webuser.ErrNotFound)

	assert.Error(t, webuser.AddCredential(ctx, web, id, cid, []byte(`{}`)))
	assert.ErrorIs(t, webuser.UpdateCredential(ctx, web, []byte{9}, []byte(`{}`), now), webuser.ErrNotFound)
}

func TestAddUserNameRules(t *testing.T) {
	d := vpgtest.New(t)
	ctx := context.Background()
	owner := d.As(t, "vendor_owner", "t_wu_owner9")
	for _, bad := range []string{"a b", "", strings.Repeat("a", 65)} {
		_, err := webuser.AddUser(ctx, owner, bad)
		assert.Error(t, err, bad)
	}
	_, err := webuser.AddUser(ctx, owner, "Ayse")
	require.NoError(t, err)
	_, err = webuser.AddUser(ctx, owner, "ayse")
	assert.ErrorIs(t, err, webuser.ErrDuplicateUser)

	u, err := webuser.GetUserByName(ctx, owner, "AYSE")
	require.NoError(t, err)
	assert.Equal(t, "Ayse", u.Name)
	u2, err := webuser.GetUserByID(ctx, owner, u.ID)
	require.NoError(t, err)
	assert.Equal(t, u, u2)
	list, err := webuser.ListUsers(ctx, owner)
	require.NoError(t, err)
	assert.Equal(t, []webuser.User{u}, list)
	_, err = webuser.GetUserByName(ctx, owner, "nobody")
	assert.ErrorIs(t, err, webuser.ErrNotFound)
}

func TestSalesLoginCannotCreateUsers(t *testing.T) {
	d := vpgtest.New(t)
	sales := d.As(t, "vendor_sales", "t_wu_sales10")
	_, err := webuser.AddUser(context.Background(), sales, "mallory")
	assert.Error(t, err)
}
