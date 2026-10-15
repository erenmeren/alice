//go:build integration

package web

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/license"
	"alice/internal/vconsole/webuser"
)

var noteSeq atomic.Int64

// seedNote inserts a notification through the migration pool (the only writer besides the notifier
// and the issuance trigger), created age ago, and returns its id. target is "" unless audience is user.
func (e *testEnv) seedNote(audience, target, severity, title, body, subject string, age time.Duration) int64 {
	e.t.Helper()
	var tgt any
	if target != "" {
		tgt = target
	}
	var id int64
	require.NoError(e.t, e.d.Owner.QueryRow(context.Background(), `INSERT INTO notifications
		(kind, severity, title, body, audience, target_user, subject, dedupe_key, created_at)
		VALUES ('test', $1, $2, $3, $4, $5, $6, $7, now() - $8::interval) RETURNING id`,
		severity, title, body, audience, tgt, subject, fmt.Sprintf("test:%d", noteSeq.Add(1)),
		fmt.Sprintf("%d seconds", int(age.Seconds()))).Scan(&id))
	return id
}

func (e *testEnv) userID(name string) int64 {
	e.t.Helper()
	u, err := webuser.GetUserByName(context.Background(), e.owner, name)
	require.NoError(e.t, err)
	return u.ID
}

// readsOf counts the read rows a user has.
func (e *testEnv) readsOf(name string) int {
	e.t.Helper()
	var n int
	require.NoError(e.t, e.d.Owner.QueryRow(context.Background(),
		`SELECT count(*) FROM notification_reads r JOIN web_users u ON u.id = r.user_id WHERE u.name = $1`, name).Scan(&n))
	return n
}

func (e *testEnv) page(path string, c *http.Cookie) string {
	e.t.Helper()
	w := e.do(http.MethodGet, path, "", c)
	require.Equal(e.t, http.StatusOK, w.Code, path)
	return w.Body.String()
}

func (e *testEnv) post(path string, c *http.Cookie) *httptest.ResponseRecorder {
	e.t.Helper()
	return e.form(path, url.Values{}, c)
}

func TestOwnerSeesOwnerNotificationsSalesDoesNot(t *testing.T) {
	e := newEnv(t, "https://licenses.example.test")
	boss := e.signInRole("boss", webuser.RoleOwner)
	ayse := e.signIn("ayse")
	e.signIn("mehmet")
	e.seedNote("owner", "", "info", "License issued: Owner Only Ltd", "Customer: Owner Only Ltd", "LIC-OWN-1", time.Minute)
	e.seedNote("sales", "", "warning", "Note for every seller", "", "", 2*time.Minute)
	e.seedNote("user", "ayse", "warning", "Reminder for ayse", "", "request:5", 3*time.Minute)
	e.seedNote("user", "mehmet", "alert", "Reminder for mehmet", "", "", 4*time.Minute)

	b := e.page("/notifications", boss)
	assert.Contains(t, b, "License issued: Owner Only Ltd")
	assert.Contains(t, b, "Note for every seller")
	assert.NotContains(t, b, "Reminder for ayse")
	assert.NotContains(t, b, "Reminder for mehmet")
	assert.Contains(t, b, "Notifications (2)")

	a := e.page("/notifications", ayse)
	assert.NotContains(t, a, "Owner Only")
	assert.Contains(t, a, "Note for every seller")
	assert.Contains(t, a, "Reminder for ayse")
	assert.NotContains(t, a, "Reminder for mehmet")
	assert.Contains(t, a, "Notifications (2)")
	assert.NotContains(t, e.page("/", ayse), "Owner Only")

	// Severity is a text badge, the time is UTC, the subject links where it belongs.
	assert.Contains(t, b, `>info<`)
	assert.Contains(t, b, `>warning<`)
	assert.Contains(t, b, " UTC")
	assert.Contains(t, b, `href="/licenses"`)
	assert.Contains(t, a, `href="/requests/5"`)
	assert.Contains(t, b, "<details>")
}

func TestBellShowsTheUnreadCountAndItDropsAfterMarkRead(t *testing.T) {
	e := newEnv(t, "https://licenses.example.test")
	ayse := e.signIn("ayse")

	home := e.page("/", ayse)
	assert.Contains(t, home, `href="/notifications"`)
	assert.Contains(t, home, ">Notifications</a>", "no count when nothing is unread")
	assert.NotContains(t, home, "Notifications (")

	e.seedNote("sales", "", "info", "First note", "", "", 4*time.Hour)
	e.seedNote("sales", "", "info", "Second note", "", "", 3*time.Hour)
	e.seedNote("sales", "", "info", "Third note", "", "", 2*time.Hour)
	newest := e.seedNote("sales", "", "info", "Fourth note", "", "", time.Hour)
	for _, p := range []string{"/", "/customers", "/licenses", "/requests/new", "/notifications"} {
		assert.Contains(t, e.page(p, ayse), "Notifications (4)", p)
	}
	// The home page shows the three newest unread.
	home = e.page("/", ayse)
	for _, title := range []string{"Second note", "Third note", "Fourth note"} {
		assert.Contains(t, home, title)
	}
	assert.NotContains(t, home, "First note")

	w := e.post(fmt.Sprintf("/notifications/%d/read", newest), ayse)
	assert.Equal(t, http.StatusSeeOther, w.Code)
	assert.Equal(t, "/notifications", w.Header().Get("Location"))
	assert.Contains(t, e.page("/", ayse), "Notifications (3)")
	home = e.page("/", ayse)
	assert.Contains(t, home, "First note")
	assert.NotContains(t, home, "Fourth note")

	// Marking again changes nothing.
	assert.Equal(t, http.StatusSeeOther, e.post(fmt.Sprintf("/notifications/%d/read", newest), ayse).Code)
	assert.Contains(t, e.page("/", ayse), "Notifications (3)")

	unread := e.page("/notifications?unread=1", ayse)
	assert.NotContains(t, unread, "Fourth note")
	assert.Contains(t, unread, "First note")
	all := e.page("/notifications", ayse)
	assert.Contains(t, all, "Fourth note")
	assert.Equal(t, 3, strings.Count(all, `class="unread"`))
	assert.Equal(t, 1, strings.Count(all, `class="read"`))

	w = e.post("/notifications/read-all", ayse)
	assert.Equal(t, http.StatusSeeOther, w.Code)
	assert.Equal(t, "/notifications", w.Header().Get("Location"))
	home = e.page("/", ayse)
	assert.NotContains(t, home, "Notifications (")
	assert.NotContains(t, home, "First note")
	assert.Contains(t, e.page("/notifications?unread=1", ayse), "No notifications")
}

func TestMarkReadOfAnInvisibleNotificationLooksLikeAnyOther(t *testing.T) {
	e := newEnv(t, "https://licenses.example.test")
	boss := e.signInRole("boss", webuser.RoleOwner)
	ayse := e.signIn("ayse")
	e.signIn("mehmet")
	visible := e.seedNote("sales", "", "info", "Visible", "", "", time.Minute)
	ownerOnly := e.seedNote("owner", "", "info", "Owner only", "", "", time.Minute)
	mehmets := e.seedNote("user", "mehmet", "info", "Mehmet only", "", "", time.Minute)
	unknown := ownerOnly + 100000

	first := e.post(fmt.Sprintf("/notifications/%d/read", visible), ayse)
	for _, id := range []int64{ownerOnly, mehmets, unknown, visible} {
		w := e.post(fmt.Sprintf("/notifications/%d/read", id), ayse)
		assert.Equal(t, first.Code, w.Code, id)
		assert.Equal(t, http.StatusSeeOther, w.Code, id)
		assert.Equal(t, first.Header().Get("Location"), w.Header().Get("Location"), id)
		assert.Equal(t, first.Body.String(), w.Body.String(), id)
	}
	assert.Equal(t, 1, e.readsOf("ayse"), "only the visible one was marked")
	assert.Zero(t, e.readsOf("boss"))
	assert.Zero(t, e.readsOf("mehmet"))
	assert.Contains(t, e.page("/", boss), "Notifications (2)")

	for _, bad := range []string{"abc", "0", "-1", "1.5", "99999999999999999999999"} {
		assert.Equal(t, http.StatusNotFound, e.post("/notifications/"+bad+"/read", ayse).Code, bad)
	}
}

func TestReadAllOnlyAffectsOwnState(t *testing.T) {
	e := newEnv(t, "https://licenses.example.test")
	boss := e.signInRole("boss", webuser.RoleOwner)
	ayse := e.signIn("ayse")
	mehmet := e.signIn("mehmet")
	e.seedNote("sales", "", "info", "S1", "", "", time.Minute)
	e.seedNote("sales", "", "info", "S2", "", "", time.Minute)
	ownerNote := e.seedNote("owner", "", "info", "O1", "", "", time.Minute)
	e.seedNote("user", "ayse", "info", "U1", "", "", time.Minute)

	assert.Equal(t, http.StatusSeeOther, e.post("/notifications/read-all", ayse).Code)
	assert.NotContains(t, e.page("/", ayse), "Notifications (")
	assert.Contains(t, e.page("/", mehmet), "Notifications (2)")
	assert.Contains(t, e.page("/", boss), "Notifications (3)")
	assert.Equal(t, 3, e.readsOf("ayse"))
	var n int
	require.NoError(t, e.d.Owner.QueryRow(context.Background(),
		`SELECT count(*) FROM notification_reads WHERE notification_id = $1`, ownerNote).Scan(&n))
	assert.Zero(t, n)

	assert.Equal(t, http.StatusSeeOther, e.post("/notifications/read-all", boss).Code)
	assert.NotContains(t, e.page("/", boss), "Notifications (")
	assert.Contains(t, e.page("/", mehmet), "Notifications (2)")
}

func TestNotificationTextIsEscaped(t *testing.T) {
	e := newEnv(t, "https://licenses.example.test")
	ayse := e.signIn("ayse")
	// The title CHECK refuses C0/C1 controls and U+2028/2029 but not bidi controls, so both carry them.
	title := "<script>alert(1)</script> \"q\" & \u202Eevil\u2066x"
	body := "<script>alert(2)</script>\nsecond line \u202Egnp.exe\u200F\u2067"
	e.seedNote("sales", "", "alert", title, body, "<b>subj</b>", time.Minute)

	for _, p := range []string{"/notifications", "/"} {
		page := e.page(p, ayse)
		assert.Contains(t, page, "&lt;script&gt;alert(1)&lt;/script&gt;", p)
		assert.NotContains(t, page, "<script>alert", p)
		assert.NotContains(t, page, "<b>subj", p)
		for _, r := range []string{"\u202E", "\u2066", "\u2067", "\u200F"} {
			assert.NotContains(t, page, r, "%s: %U", p, []rune(r)[0])
		}
	}
	page := e.page("/notifications", ayse)
	assert.Contains(t, page, "&lt;script&gt;alert(2)&lt;/script&gt;")
	assert.Contains(t, page, "second line")
	assert.Contains(t, page, "&lt;b&gt;subj&lt;/b&gt;")
	assert.Contains(t, page, ">alert<")
	assert.NotContains(t, page, " style=")
}

func TestNotificationsPageRequiresLogin(t *testing.T) {
	e := newEnv(t, "https://licenses.example.test")
	e.signIn("ayse")
	id := e.seedNote("sales", "", "info", "Secret title", "", "", time.Minute)
	w := e.do(http.MethodGet, "/notifications", "")
	assert.Equal(t, http.StatusSeeOther, w.Code)
	assert.Equal(t, "/login", w.Header().Get("Location"))
	assert.NotContains(t, w.Body.String(), "Secret title")
	for _, p := range []string{fmt.Sprintf("/notifications/%d/read", id), "/notifications/read-all", "/notifications/abc/read"} {
		w := e.form(p, url.Values{}, &http.Cookie{Name: e.srv.cfg.CookieName, Value: "forged"})
		assert.Equal(t, http.StatusSeeOther, w.Code, p)
		assert.Equal(t, "/login", w.Header().Get("Location"), p)
	}
	assert.Zero(t, e.countRows("notification_reads"))
	assert.NotContains(t, e.page("/login", nil), "Notifications")
}

func TestCrossSitePostToReadIsRefused(t *testing.T) {
	e := newEnv(t, "https://licenses.example.test")
	ayse := e.signIn("ayse")
	id := e.seedNote("sales", "", "info", "Note", "", "", time.Minute)
	for _, p := range []string{fmt.Sprintf("/notifications/%d/read", id), "/notifications/read-all"} {
		r := httptest.NewRequest(http.MethodPost, e.origin+p, strings.NewReader(""))
		r.Host = e.host
		r.Header.Set("Sec-Fetch-Site", "cross-site")
		r.Header.Set("Origin", "https://evil.example.test")
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.AddCookie(ayse)
		w := httptest.NewRecorder()
		e.h.ServeHTTP(w, r)
		assert.Equal(t, http.StatusForbidden, w.Code, p)
	}
	assert.Zero(t, e.countRows("notification_reads"))
	assert.Contains(t, e.page("/", ayse), "Notifications (1)")
}

func TestNoCountDoesNotBreakThePage(t *testing.T) {
	e := newEnv(t, "https://licenses.example.test")
	ayse := e.signIn("ayse")
	e.seedNote("sales", "", "info", "Still listed", "", "", time.Minute)
	assert.Contains(t, e.page("/", ayse), "Notifications (1)")

	_, err := e.d.Owner.Exec(context.Background(), `REVOKE EXECUTE ON FUNCTION web_unread_count(bigint) FROM vendor_web`)
	require.NoError(t, err)
	for _, p := range []string{"/", "/customers", "/licenses", "/notifications"} {
		page := e.page(p, ayse)
		assert.Contains(t, page, ">Notifications</a>", p)
		assert.NotContains(t, page, "Notifications (", p)
	}
	assert.Contains(t, e.page("/notifications", ayse), "Still listed")
}

func TestOwnerCanUseTheSalesPages(t *testing.T) {
	e := newEnv(t, "https://licenses.example.test")
	boss := e.signInRole("boss", webuser.RoleOwner)
	cid := e.addCustomer(boss, "Owner Customer Ltd")
	loc := e.addRequest(boss, cid, license.NewInstallationID())
	e.seedLicense(cid, "LIC-BOSS-1", time.Now().Add(20*24*time.Hour), []byte("file"))
	for _, p := range []string{"/", "/customers", "/requests/new", loc, "/licenses", "/notifications"} {
		assert.Contains(t, e.page(p, boss), "boss", p)
	}
	w := e.do(http.MethodGet, "/licenses/LIC-BOSS-1/download", "", boss)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, http.StatusSeeOther, e.post(loc+"/cancel", boss).Code)
}

func TestDisabledUserSeesNothing(t *testing.T) {
	e := newEnv(t, "https://licenses.example.test")
	ctx := context.Background()
	ayse := e.signIn("ayse")
	e.seedNote("sales", "", "info", "For everyone", "", "", time.Minute)
	id := e.userID("ayse")

	// Called the way the service calls them: inside a transaction with vendor.actor set.
	counts := func() (listed, unread int64) {
		tx, err := e.web.Begin(ctx)
		require.NoError(t, err)
		defer func() { _ = tx.Rollback(ctx) }()
		_, err = tx.Exec(ctx, `SELECT set_config('vendor.actor', 'ayse', true)`)
		require.NoError(t, err)
		require.NoError(t, tx.QueryRow(ctx, `SELECT count(*) FROM web_notifications($1, 100, false)`, id).Scan(&listed))
		require.NoError(t, tx.QueryRow(ctx, `SELECT web_unread_count($1)`, id).Scan(&unread))
		var marked bool
		require.NoError(t, tx.QueryRow(ctx, `SELECT web_mark_read($1, (SELECT max(id) FROM web_notifications($1, 1, false)))`, id).Scan(&marked))
		return listed, unread
	}
	l, u := counts()
	assert.Equal(t, int64(1), l)
	assert.Equal(t, int64(1), u)

	require.NoError(t, pgx.BeginFunc(ctx, e.owner, func(tx pgx.Tx) error {
		return webuser.SetDisabled(ctx, tx, "ayse", true, e.clk.Now())
	}))
	w := e.do(http.MethodGet, "/notifications", "", ayse)
	assert.Equal(t, http.StatusSeeOther, w.Code)
	assert.Equal(t, "/login", w.Header().Get("Location"))
	assert.Equal(t, http.StatusSeeOther, e.post("/notifications/read-all", ayse).Code)
	assert.Zero(t, e.readsOf("ayse"))

	l, u = counts()
	assert.Zero(t, l)
	assert.Zero(t, u)
}
