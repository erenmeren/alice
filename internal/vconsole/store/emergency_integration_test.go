//go:build integration

package store_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/license"
	"alice/internal/vconsole/audit"
	"alice/internal/vconsole/store"
	"alice/internal/vconsole/vpgtest"
)

const day = 24 * time.Hour

type seeded struct {
	id          string
	from, until time.Time
	targets     int
	features    []string
	emergency   bool
	revoked     bool
}

// seedFor inserts a signed request and its license for inst as the database owner.
func seedFor(t *testing.T, d *vpgtest.DB, cid int64, inst string, s seeded) {
	t.Helper()
	ctx := context.Background()
	if s.features == nil {
		s.features = []string{}
	}
	var reqID int64
	if s.emergency {
		require.NoError(t, d.Owner.QueryRow(ctx, `INSERT INTO license_requests (customer_id, installation, targets, features,
			status, kind, months, days, reason, extends) VALUES ($1, $2, $3, $4, 'signed', 'emergency', NULL, 14, 'seeded', 'LIC-SEED')
			RETURNING id`, cid, inst, s.targets, s.features).Scan(&reqID))
	} else {
		require.NoError(t, d.Owner.QueryRow(ctx, `INSERT INTO license_requests (customer_id, installation, targets, features, status)
			VALUES ($1, $2, $3, $4, 'signed') RETURNING id`, cid, inst, s.targets, s.features).Scan(&reqID))
	}
	_, err := d.Owner.Exec(ctx, `INSERT INTO licenses (license_id, request_id, customer_id, installation, key_id, issued_at,
		valid_from, valid_until, targets, file, file_sha256, revoked_at)
		VALUES ($1, $2, $3, $4, 'key1', $5, $5, $6, $7, 'bytes', 'sha', CASE WHEN $8 THEN $5::timestamptz END)`,
		s.id, reqID, cid, inst, s.from, s.until, s.targets, s.revoked)
	require.NoError(t, err)
}

func emergencySetup(t *testing.T, login string) (*vpgtest.DB, int64, string) {
	t.Helper()
	d := vpgtest.New(t)
	sales := d.As(t, "vendor_sales", login)
	cid, err := store.AddCustomer(context.Background(), sales, store.NewCustomer{Name: "Lapsed Ltd"})
	require.NoError(t, err)
	inst := license.NewInstallationID()
	seedFor(t, d, cid, inst, seeded{id: "L-OLD", from: now.Add(-800 * day), until: now.Add(-400 * day), targets: 5,
		features: []string{"a"}})
	seedFor(t, d, cid, inst, seeded{id: "L-LATE", from: now.Add(-368 * day), until: now.Add(-3 * day), targets: 9,
		features: []string{"audit", "sso"}})
	seedFor(t, d, cid, inst, seeded{id: "L-REV", from: now.Add(-10 * day), until: now.Add(300 * day), targets: 50,
		revoked: true})
	return d, cid, inst
}

func TestEmergencyRequestCarriesOverTheInstallationsLatestLicense(t *testing.T) {
	d, cid, inst := emergencySetup(t, "t_em_carry")
	ctx := context.Background()
	sales := d.Connect(t, "t_em_carry")

	basis, err := store.GetEmergencyBasis(ctx, sales, "L-OLD")
	require.NoError(t, err)
	assert.Equal(t, "L-LATE", basis.LicenseID, "the latest license that is not revoked, whichever row was opened")
	assert.Equal(t, 9, basis.Targets)
	assert.Equal(t, []string{"audit", "sso"}, basis.Features)
	assert.Equal(t, "Lapsed Ltd", basis.Customer)

	id, err := store.AddEmergencyRequest(ctx, sales, store.NewEmergency{LicenseID: "L-OLD", Reason: "Renewal PO is delayed"}, now)
	require.NoError(t, err)
	r, err := store.GetRequest(ctx, sales, id)
	require.NoError(t, err)
	assert.Equal(t, store.KindEmergency, r.Kind)
	assert.Equal(t, store.DefaultEmergencyDays, r.Days)
	assert.Equal(t, "Renewal PO is delayed", r.Reason)
	assert.Equal(t, "L-LATE", r.Extends)
	assert.Equal(t, cid, r.CustomerID)
	assert.Equal(t, inst, r.Installation)
	assert.Equal(t, 9, r.Targets)
	assert.Equal(t, []string{"audit", "sso"}, r.Features)
	assert.Zero(t, r.Months)
	assert.Empty(t, r.From)
	assert.Empty(t, r.Replaces)
	assert.Equal(t, "open", r.Status)

	var details []byte
	require.NoError(t, d.Owner.QueryRow(ctx, `SELECT details FROM audit WHERE action = 'request.add' AND subject = $1::bigint::text`,
		r.ID).Scan(&details))
	var got map[string]any
	require.NoError(t, json.Unmarshal(details, &got))
	assert.Equal(t, "emergency", got["kind"])
	assert.EqualValues(t, 14, got["days"])
	assert.Equal(t, "Renewal PO is delayed", got["reason"])
	assert.Equal(t, "L-LATE", got["extends"])
	require.NoError(t, audit.Check(ctx, d.Owner))

	// A normal request still reads as one.
	nid, err := store.AddRequest(ctx, sales, store.NewRequest{CustomerID: cid, Installation: inst, Targets: 3}, now)
	require.NoError(t, err)
	n, err := store.GetRequest(ctx, sales, nid)
	require.NoError(t, err)
	assert.Equal(t, store.KindLicense, n.Kind)
	assert.Zero(t, n.Days)
	assert.Equal(t, 12, n.Months)
}

func TestEmergencyRequestRefusals(t *testing.T) {
	d, _, _ := emergencySetup(t, "t_em_refuse")
	ctx := context.Background()
	sales := d.Connect(t, "t_em_refuse")
	before := func() int {
		var n int
		require.NoError(t, d.Owner.QueryRow(ctx, `SELECT count(*) FROM license_requests`).Scan(&n))
		return n
	}
	start := before()
	for name, e := range map[string]store.NewEmergency{
		"31 days":         {LicenseID: "L-LATE", Days: 31, Reason: "x"},
		"negative days":   {LicenseID: "L-LATE", Days: -1, Reason: "x"},
		"no reason":       {LicenseID: "L-LATE", Days: 14, Reason: "  "},
		"two-line reason": {LicenseID: "L-LATE", Days: 14, Reason: "a\nb"},
		"overlong reason": {LicenseID: "L-LATE", Days: 14, Reason: strings.Repeat("r", 201)},
	} {
		_, err := store.AddEmergencyRequest(ctx, sales, e, now)
		var invalid *store.InvalidError
		assert.ErrorAs(t, err, &invalid, name)
	}
	_, err := store.AddEmergencyRequest(ctx, sales, store.NewEmergency{LicenseID: "L-NONE", Days: 14, Reason: "x"}, now)
	assert.ErrorIs(t, err, store.ErrNotFound)
	_, err = store.AddEmergencyRequest(ctx, sales, store.NewEmergency{LicenseID: "L-REV", Days: 14, Reason: "x"}, now)
	assert.ErrorIs(t, err, store.ErrNotFound, "a revoked license is not extended (also by its own ID)")
	assert.Equal(t, start, before(), "nothing stored")

	// The database refuses the shapes the Go code never writes.
	_, err = d.Owner.Exec(ctx, `INSERT INTO license_requests (customer_id, installation, targets, kind, months, days, reason, extends)
		SELECT customer_id, installation, targets, 'emergency', 12, 14, 'x', 'L-LATE' FROM licenses WHERE license_id = 'L-LATE'`)
	assert.Error(t, err, "an extension has no months")
	_, err = d.Owner.Exec(ctx, `INSERT INTO license_requests (customer_id, installation, targets, kind, months, days, reason, extends)
		SELECT customer_id, installation, targets, 'emergency', NULL, 31, 'x', 'L-LATE' FROM licenses WHERE license_id = 'L-LATE'`)
	assert.Error(t, err, "at most 30 days")
	_, err = d.Owner.Exec(ctx, `INSERT INTO license_requests (customer_id, installation, targets, kind, months, days, reason, extends)
		SELECT customer_id, installation, targets, 'emergency', NULL, 14, ' ', 'L-LATE' FROM licenses WHERE license_id = 'L-LATE'`)
	assert.Error(t, err, "a reason is required")
}

// An extension that would end no later than a license already valid on its start day adds nothing
// and, being the later start, would hide that license in Alice; it is refused.
func TestEmergencyRequestRefusedWhileALicenseCoversIt(t *testing.T) {
	d := vpgtest.New(t)
	ctx := context.Background()
	sales := d.As(t, "vendor_sales", "t_em_cover")
	cid, err := store.AddCustomer(ctx, sales, store.NewCustomer{Name: "Running Ltd"})
	require.NoError(t, err)
	inst := license.NewInstallationID()
	seedFor(t, d, cid, inst, seeded{id: "L-RUN", from: now.Add(-300 * day), until: now.Add(40 * day), targets: 3})

	_, err = store.AddEmergencyRequest(ctx, sales, store.NewEmergency{LicenseID: "L-RUN", Days: 30, Reason: "x"}, now)
	assert.ErrorIs(t, err, store.ErrExtensionNotNeeded)
	var invalid *store.InvalidError
	assert.ErrorAs(t, err, &invalid, "shown to the person")

	// Ending within the extension: allowed (an extension may be issued just before the lapse).
	inst2 := license.NewInstallationID()
	seedFor(t, d, cid, inst2, seeded{id: "L-SOON", from: now.Add(-300 * day), until: now.Add(5 * day), targets: 3})
	_, err = store.AddEmergencyRequest(ctx, sales, store.NewEmergency{LicenseID: "L-SOON", Days: 14, Reason: "x"}, now)
	assert.NoError(t, err)
}

// A license that starts before a running extension and does not replace it would leave the
// extension in force in Alice until it ends (the later start wins); it is refused, with the fix.
func TestRequestStartingBeforeAnExtensionMustReplaceIt(t *testing.T) {
	d, cid, inst := emergencySetup(t, "t_em_before")
	ctx := context.Background()
	sales := d.Connect(t, "t_em_before")
	start := now.Truncate(day)
	seedFor(t, d, cid, inst, seeded{id: "L-EXT", from: start, until: start.Add(14 * day), targets: 9, emergency: true})

	backdated := store.NewRequest{CustomerID: cid, Installation: inst, Targets: 9, From: now.Add(-3 * day).Format("2006-01-02"),
		Months: 12, Replaces: "L-LATE"}
	_, err := store.AddRequest(ctx, sales, backdated, now)
	assert.ErrorIs(t, err, store.ErrStartsBeforeExtension)
	var invalid *store.InvalidError
	require.ErrorAs(t, err, &invalid)
	assert.Contains(t, invalid.Error(), "L-EXT")

	backdated.Replaces = "L-EXT"
	_, err = store.AddRequest(ctx, sales, backdated, now)
	assert.NoError(t, err, "replacing the extension")

	_, err = store.AddRequest(ctx, sales, store.NewRequest{CustomerID: cid, Installation: inst, Targets: 9}, now)
	assert.NoError(t, err, "starting today")
	_, err = store.AddRequest(ctx, sales, store.NewRequest{CustomerID: cid, Installation: inst, Targets: 9,
		From: start.Add(14 * day).Format("2006-01-02")}, now)
	assert.NoError(t, err, "starting where the extension ends")
	_, err = store.AddRequest(ctx, sales, store.NewRequest{CustomerID: cid, Installation: license.NewInstallationID(),
		Targets: 9, From: now.Add(-3 * day).Format("2006-01-02"), Replaces: "L-LATE"}, now)
	assert.NoError(t, err, "another installation is not affected")
}

func TestListLicensesMarksExtensionsAndTheLatest(t *testing.T) {
	d, cid, inst := emergencySetup(t, "t_em_list")
	ctx := context.Background()
	sales := d.Connect(t, "t_em_list")
	start := now.Truncate(day)
	seedFor(t, d, cid, inst, seeded{id: "L-EXT", from: start, until: start.Add(14 * day), targets: 9, emergency: true})

	rows, err := store.ListLicenses(ctx, sales, now, 0, false)
	require.NoError(t, err)
	got := map[string]store.LicenseRow{}
	for _, r := range rows {
		got[r.LicenseID] = r
	}
	assert.True(t, got["L-EXT"].Emergency)
	assert.False(t, got["L-LATE"].Emergency)
	assert.True(t, got["L-EXT"].Latest, "the latest license of the installation that is not revoked")
	assert.False(t, got["L-LATE"].Latest)
	assert.False(t, got["L-REV"].Latest, "a revoked license is never the latest")
}
