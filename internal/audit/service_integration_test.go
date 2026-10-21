//go:build integration

package audit_test

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/audit"
	"alice/internal/platform/clock"
	"alice/internal/platform/db"
	"alice/internal/testutil/pgtest"
)

// seedJob inserts a job as the owner, with service as its owning service (uuid.Nil for none).
func seedJob(t *testing.T, d *pgtest.DB, service uuid.UUID) uuid.UUID {
	t.Helper()
	id := uuid.New()
	var sv *uuid.UUID
	if service != uuid.Nil {
		sv = &service
	}
	_, err := d.Owner.Exec(context.Background(), `INSERT INTO jobs (id, type, class, kind, payload_mac, status, run_at, max_attempts,
service_id, created_at) VALUES ($1, 'test', 'always', 'system', decode(repeat('00', 32), 'hex'), 'queued', now(), 1, $2, now())`, id, sv)
	require.NoError(t, err)
	return id
}

func appendOne(t *testing.T, d *pgtest.DB, l *audit.Log, e audit.Event) (audit.Entry, error) {
	t.Helper()
	var en audit.Entry
	err := db.InTx(context.Background(), d.App, func(tx pgx.Tx) error {
		var err error
		en, err = l.Append(context.Background(), tx, e)
		return err
	})
	return en, err
}

// Design §5.8: every audit row about a resource carries details.service_id, the owning service at that time.
func TestAppendNamesTheOwningService(t *testing.T) {
	d := pgtest.New(t)
	ctx := context.Background()
	l := audit.New(clock.NewFake(start))
	service := uuid.New()
	_, err := d.Owner.Exec(ctx, `INSERT INTO services (id, name, created_at, updated_at) VALUES ($1, 'payments', now(), now())`, service)
	require.NoError(t, err)
	owned := seedJob(t, d, service)
	platform := seedJob(t, d, uuid.Nil)

	cases := []struct {
		name    string
		event   audit.Event
		service string // "" = no service_id
	}{
		{"an owned object names its service", audit.Event{ObjectType: "job", ObjectID: owned.String()}, service.String()},
		{"an object without a service names none", audit.Event{ObjectType: "job", ObjectID: platform.String()}, ""},
		{"an object that is gone names none", audit.Event{ObjectType: "job", ObjectID: uuid.NewString()}, ""},
		{"an id that is not a row id names none", audit.Event{ObjectType: "job", ObjectID: "nightly"}, ""},
		{"the nil id names none", audit.Event{ObjectType: "job", ObjectID: uuid.Nil.String()}, ""},
		{"a type without services names none", audit.Event{ObjectType: "user", ObjectID: owned.String()}, ""},
		{"an event's own service_id wins", audit.Event{ObjectType: "job", ObjectID: owned.String(),
			Details: map[string]string{"service_id": "named-by-caller"}}, "named-by-caller"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := c.event
			e.Actor, e.Action, e.Result = userActor(), "test.event", audit.Success
			if e.Details == nil {
				e.Details = map[string]string{"k": "v"}
			}
			before := len(e.Details)
			en, err := appendOne(t, d, l, e)
			require.NoError(t, err)
			assert.Len(t, e.Details, before, "the caller's details map is never changed in place")
			got, named := en.Details["service_id"]
			if c.service == "" {
				assert.False(t, named, "%v", en.Details)
				return
			}
			assert.Equal(t, c.service, got)
		})
	}

	items, _, err := audit.List(ctx, d.App, audit.Filter{})
	require.NoError(t, err)
	require.Len(t, items, len(cases))
	assert.Equal(t, service.String(), items[len(items)-1].Details["service_id"], "the stored row carries the service")
	assert.Equal(t, "v", items[len(items)-1].Details["k"])
	rep, err := audit.Verify(ctx, d.App)
	require.NoError(t, err)
	assert.True(t, rep.Intact, "%+v", rep)
}

// A failure to read the owning service fails the append; no row is written without it.
func TestAppendFailsWhenTheServiceCannotBeRead(t *testing.T) {
	d := pgtest.New(t)
	ctx := context.Background()
	l := audit.New(clock.NewFake(start))
	job := seedJob(t, d, uuid.Nil)
	_, err := d.Owner.Exec(ctx, `REVOKE SELECT ON jobs FROM alice_app`)
	require.NoError(t, err)

	_, err = appendOne(t, d, l, audit.Event{Actor: userActor(), Action: "test.event", ObjectType: "job", ObjectID: job.String(),
		Result: audit.Success})
	require.Error(t, err)
	assert.ErrorContains(t, err, "audit: read the object's service")

	items, _, err := audit.List(ctx, d.App, audit.Filter{})
	require.NoError(t, err)
	assert.Empty(t, items)
}
