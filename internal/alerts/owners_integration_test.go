//go:build integration

package alerts_test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/alerts"
	"alice/internal/audit"
	"alice/internal/notify"
	"alice/internal/platform/clock"
	"alice/internal/testutil/pgtest"
)

// seedService adds a service with the empty policy (version 1), as the services module makes one.
func seedService(t *testing.T, d *pgtest.DB, name string) uuid.UUID {
	t.Helper()
	id := uuid.New()
	_, err := d.Owner.Exec(context.Background(), `INSERT INTO services (id, name, created_at, updated_at) VALUES ($1, $2, now(), now())`, id, name)
	require.NoError(t, err)
	_, err = d.Owner.Exec(context.Background(), `INSERT INTO service_policies (service_id, version, body, created_at) VALUES ($1, 1, '{"schema":1}', now())`, id)
	require.NoError(t, err)
	return id
}

func seedPerson(t *testing.T, d *pgtest.DB, username, role, email string) uuid.UUID {
	t.Helper()
	id := uuid.New()
	var r any
	if role != "" {
		r = role
	}
	_, err := d.Owner.Exec(context.Background(), `INSERT INTO users (id, username, display_name, email, password_hash, role, locale, created_at, updated_at)
VALUES ($1, $2, $5, $3, '$argon2id$x', $4, 'en', now(), now())`, id, username, email, r, username)
	require.NoError(t, err)
	return id
}

func seedOwner(t *testing.T, d *pgtest.DB, service, user uuid.UUID) {
	t.Helper()
	_, err := d.Owner.Exec(context.Background(), `INSERT INTO service_owners (id, service_id, user_id, created_at) VALUES (gen_random_uuid(), $1, $2, now())`,
		service, user)
	require.NoError(t, err)
}

// inService moves a server and a certificate into a service.
func inService(t *testing.T, d *pgtest.DB, service, target, cert uuid.UUID) {
	t.Helper()
	_, err := d.Owner.Exec(context.Background(), `UPDATE targets SET service_id = $1 WHERE id = $2`, service, target)
	require.NoError(t, err)
	_, err = d.Owner.Exec(context.Background(), `UPDATE certificates SET service_id = $1 WHERE id = $2`, service, cert)
	require.NoError(t, err)
}

// outbox is every queued e-mail as "address template count name" ("-" for a missing parameter), in queue order.
func outbox(t *testing.T, d *pgtest.DB) []string {
	t.Helper()
	rows, err := d.Owner.Query(context.Background(), `SELECT to_address || ' ' || template_key || ' ' || coalesce(params->>'count', '-')
    || ' ' || coalesce(params->>'name', '-') FROM notifications_outbox ORDER BY id`)
	require.NoError(t, err)
	out, err := pgx.CollectRows(rows, pgx.RowTo[string])
	require.NoError(t, err)
	return out
}

func mailsTo(all []string, address string) []string {
	var out []string
	for _, m := range all {
		if rest, ok := strings.CutPrefix(m, address+" "); ok {
			out = append(out, rest)
		}
	}
	return out
}

func minutes(i int) time.Duration { return time.Duration(i) * time.Minute }

// SR-23 (R56, design §7.2): the owner of service A gets A's expiry notice and not B's; the Administrators get both. A
// certificate of A on a server of B reaches the owners of both.
func TestOwnersGetTheirServicesNotices(t *testing.T) {
	d := pgtest.New(t)
	ctx := context.Background()
	clk := clock.NewFake(t0)
	s := alerts.New(alerts.Config{Pool: d.App, Audit: audit.New(clk), Clock: clk, License: lic{}, Notifier: notify.ServiceNotifier{Clock: clk}})
	a, b := seedService(t, d, "Alpha"), seedService(t, d, "Bravo")
	seedPerson(t, d, "ada", "admin", "ada@example.com")
	seedOwner(t, d, a, seedPerson(t, d, "olga", "", "olga@example.com"))
	seedOwner(t, d, b, seedPerson(t, d, "bert", "operator", "bert@example.com"))
	webA, webB := seedTarget(t, d, "web-a", "nginx", nil), seedTarget(t, d, "web-b", "nginx", nil)
	inService(t, d, a, webA, seedCert(t, d, "a.example.com", t0.Add(6*day), []uuid.UUID{webA}))
	inService(t, d, b, webB, seedCert(t, d, "b.example.com", t0.Add(5*day), []uuid.UUID{webB}))
	shared := seedCert(t, d, "shared.example.com", t0.Add(4*day), []uuid.UUID{webB})
	_, err := d.Owner.Exec(ctx, `UPDATE certificates SET service_id = $1 WHERE id = $2`, a, shared)
	require.NoError(t, err)

	_, err = s.Scan(ctx)
	require.NoError(t, err)
	got := outbox(t, d)
	assert.ElementsMatch(t, []string{"alert.certificate_expiring - a.example.com", "alert.certificate_expiring - shared.example.com"},
		mailsTo(got, "olga@example.com"), "A's owner: A's certificate and A's certificate on B's server")
	assert.ElementsMatch(t, []string{"alert.certificate_expiring - b.example.com", "alert.certificate_expiring - shared.example.com"},
		mailsTo(got, "bert@example.com"), "B's owner: B's certificate and the one on B's server")
	assert.Len(t, mailsTo(got, "ada@example.com"), 3, "the Administrators: every notice")
}

// SR-23 (R56, design §7.2): the "and N more" summary is built per recipient. Over the cap, the Administrators' summary
// counts every suppressed notice, A's owner's only A's, B's owner's only B's; an owner none of whose notices was
// suppressed gets no summary.
func TestDigestIsBuiltPerRecipient(t *testing.T) {
	d := pgtest.New(t)
	ctx := context.Background()
	clk := clock.NewFake(t0)
	s := alerts.New(alerts.Config{Pool: d.App, Audit: audit.New(clk), Clock: clk, License: lic{}, Notifier: notify.ServiceNotifier{Clock: clk}})
	a, b, c := seedService(t, d, "Alpha"), seedService(t, d, "Bravo"), seedService(t, d, "Charlie")
	seedPerson(t, d, "ada", "admin", "ada@example.com")
	seedOwner(t, d, a, seedPerson(t, d, "olga", "", "olga@example.com"))
	seedOwner(t, d, b, seedPerson(t, d, "bert", "", "bert@example.com"))
	seedOwner(t, d, c, seedPerson(t, d, "carl", "", "carl@example.com"))
	webs := map[uuid.UUID]uuid.UUID{}
	for svc, name := range map[uuid.UUID]string{a: "web-a", b: "web-b", c: "web-c"} {
		webs[svc] = seedTarget(t, d, name, "nginx", nil)
	}
	// C's certificates expire first: they are the notices sent one by one; A's 3 and B's 2 are over the cap.
	for i := range alerts.MaxEmailsPerScan {
		inService(t, d, c, webs[c], seedCert(t, d, fmt.Sprintf("c%02d.example.com", i), t0.Add(day+minutes(i)), []uuid.UUID{webs[c]}))
	}
	for i := range 3 {
		inService(t, d, a, webs[a], seedCert(t, d, fmt.Sprintf("a%d.example.com", i), t0.Add(5*day+minutes(i)), []uuid.UUID{webs[a]}))
	}
	for i := range 2 {
		inService(t, d, b, webs[b], seedCert(t, d, fmt.Sprintf("b%d.example.com", i), t0.Add(6*day+minutes(i)), []uuid.UUID{webs[b]}))
	}
	res, err := s.Scan(ctx)
	require.NoError(t, err)
	require.Equal(t, 5, res.Suppressed[alerts.KindCertificate])
	got := outbox(t, d)
	assert.Equal(t, []string{"alert.more 3 -"}, mailsTo(got, "olga@example.com"), "A's owner: a summary of A's three")
	assert.Equal(t, []string{"alert.more 2 -"}, mailsTo(got, "bert@example.com"), "B's owner: a summary of B's two")
	assert.Len(t, mailsTo(got, "carl@example.com"), alerts.MaxEmailsPerScan, "C's owner: C's notices, no summary")
	ada := mailsTo(got, "ada@example.com")
	assert.Len(t, ada, alerts.MaxEmailsPerScan+1)
	assert.Contains(t, ada, "alert.more 5 -", "the Administrators' summary counts every suppressed notice")
}
