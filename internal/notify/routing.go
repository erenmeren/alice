package notify

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"alice/internal/authz"
	"alice/internal/platform/clock"
)

// ServiceNotifier queues the e-mails of services (R56, design §7.2): an e-mail about something a service owns goes to
// the Administrators (when a policy of one of its services keeps them, the default), to the owners of each of its
// services (people, and the members of owner groups seen at their last sign-in) and to each service's own extra
// addresses, every mailbox once, each in its own language. The platform e-mails (license, backup, lockout, audit, a
// job's tampering, the test e-mail) stay AdminNotifier's: NotifyAdmins here is the same, and a service e-mail with no
// service (a job without one) is a platform e-mail. An installation with only the Default service, no owners and the
// default policy queues exactly what AdminNotifier queues.
type ServiceNotifier struct{ Clock clock.Clock }

// NotifyAdmins queues template for the Administrator recipients only (AdminNotifier.NotifyAdmins).
func (n ServiceNotifier) NotifyAdmins(ctx context.Context, tx pgx.Tx, template string, params map[string]string) error {
	return AdminNotifier(n).NotifyAdmins(ctx, tx, template, params)
}

// NotifyServices queues template for the recipients of services (design §7.2), inside tx. No service (nil or empty)
// is a platform e-mail: the Administrator recipients. An unknown service (deleted since) has the default policy and
// no owners. When the services name nobody at all (every policy leaves the Administrators out and no owner or address
// receives it), the Administrator recipients get it: an e-mail about a resource is never dropped for want of a
// recipient.
func (n ServiceNotifier) NotifyServices(ctx context.Context, tx pgx.Tx, services []uuid.UUID, template string, params map[string]string) error {
	raw, err := encodeParams(template, params)
	if err != nil {
		return err
	}
	rt, err := loadRouting(ctx, tx, services)
	if err != nil {
		return err
	}
	return insertRows(ctx, tx, n.Clock, rt.recipients(services), template, raw)
}

// NotifyDigest queues a summary e-mail ("and N more") built per recipient (design §7.2): items are the services of
// each summarized item, every recipient of at least one item gets one e-mail whose params are params(the number of
// its items). The Administrator recipients, kept by every service's policy, count every item.
func (n ServiceNotifier) NotifyDigest(ctx context.Context, tx pgx.Tx, template string, items [][]uuid.UUID, params func(count int) map[string]string) error {
	if !templatePattern.MatchString(template) {
		return fmt.Errorf("notify: %q is not a template name", template)
	}
	var all []uuid.UUID
	for _, s := range items {
		all = append(all, s...)
	}
	rt, err := loadRouting(ctx, tx, all)
	if err != nil {
		return err
	}
	var (
		order  []recipient
		counts []int // counts[i]: the items of order[i]
	)
	for _, s := range items {
		for _, r := range rt.recipients(s) {
			i := slices.IndexFunc(order, func(o recipient) bool { return sameMailbox(o.email, r.email) })
			if i < 0 {
				order, counts = append(order, r), append(counts, 0)
				i = len(order) - 1
			}
			counts[i]++
		}
	}
	for i, r := range order {
		raw, err := encodeParams(template, params(counts[i]))
		if err != nil {
			return err
		}
		if err := insertRows(ctx, tx, n.Clock, []recipient{r}, template, raw); err != nil {
			return err
		}
	}
	return nil
}

// serviceRoute is who a service's e-mails reach besides the Administrators: whether its policy keeps them, its owners
// and its policy's extra addresses.
type serviceRoute struct {
	administrators bool
	owners         []recipient
	addresses      []recipient
}

// routing is the recipients of a set of services, read once in the e-mail's transaction.
type routing struct {
	admins   []recipient
	services map[uuid.UUID]serviceRoute
}

// loadRouting reads the Administrator recipients and, for every service named, its policy's notifications and its
// owners' addresses.
func loadRouting(ctx context.Context, tx pgx.Tx, services []uuid.UUID) (routing, error) {
	admins, err := recipientsFor(ctx, tx)
	if err != nil {
		return routing{}, err
	}
	rt := routing{admins: admins, services: map[uuid.UUID]serviceRoute{}}
	ids := distinct(services)
	if len(ids) == 0 {
		return rt, nil
	}
	for _, id := range ids {
		rt.services[id] = serviceRoute{administrators: true}
	}
	rows, err := tx.Query(ctx, `SELECT s.id, p.body FROM services s
JOIN service_policies p ON p.service_id = s.id AND p.version = s.policy_version WHERE s.id = ANY($1)`, ids)
	if err != nil {
		return routing{}, fmt.Errorf("notify: read the services' policies: %w", err)
	}
	type policyRow struct {
		id   uuid.UUID
		body []byte
	}
	policies, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (policyRow, error) {
		var p policyRow
		err := r.Scan(&p.id, &p.body)
		return p, err
	})
	if err != nil {
		return routing{}, fmt.Errorf("notify: read the services' policies: %w", err)
	}
	for _, p := range policies {
		// A stored policy this Alice cannot read keeps the Administrators and adds nobody: fewer recipients than the
		// policy may say, never none.
		pol, err := authz.ParsePolicy(p.body, "")
		if err != nil || pol.Notifications == nil {
			continue
		}
		sr := rt.services[p.id]
		if pol.Notifications.Administrators != nil {
			sr.administrators = *pol.Notifications.Administrators
		}
		for _, ad := range pol.Notifications.Addresses {
			sr.addresses = append(sr.addresses, recipient{email: ad.Email, locale: ad.Locale})
		}
		rt.services[p.id] = sr
	}
	// The owners: enabled people with an address, and the enabled people of an owner group's provider or directory
	// who were in the group at their last sign-in or step-up (user_directory_groups), each once per service.
	rows, err = tx.Query(ctx, `SELECT DISTINCT o.service_id, u.username, u.email::text, u.locale
FROM service_owners o
LEFT JOIN directory_groups g ON g.id = o.directory_group_id
JOIN users u ON (u.id = o.user_id)
    OR (g.id IS NOT NULL AND ((g.source = 'oidc' AND u.oidc_provider_id = g.oidc_provider_id)
                           OR (g.source = 'ldap' AND u.ldap_directory_id = g.ldap_directory_id))
        AND EXISTS (SELECT 1 FROM user_directory_groups ug WHERE ug.user_id = u.id AND ug.value = g.value))
WHERE o.service_id = ANY($1) AND u.disabled_at IS NULL AND u.email <> '' AND u.auth_source <> 'automation'
ORDER BY o.service_id, u.username`, ids)
	if err != nil {
		return routing{}, fmt.Errorf("notify: read the services' owners: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var (
			id       uuid.UUID
			username string
			r        recipient
		)
		if err := rows.Scan(&id, &username, &r.email, &r.locale); err != nil {
			return routing{}, fmt.Errorf("notify: read the services' owners: %w", err)
		}
		sr := rt.services[id]
		sr.owners = append(sr.owners, r)
		rt.services[id] = sr
	}
	if err := rows.Err(); err != nil {
		return routing{}, fmt.Errorf("notify: read the services' owners: %w", err)
	}
	return rt, nil
}

// recipients is who an e-mail about services goes to, in the order of design §7.2: the Administrator recipients
// when some service's policy keeps them, then every service's owners, then every service's extra addresses; the first
// form of a mailbox wins (its language too).
func (rt routing) recipients(services []uuid.UUID) []recipient {
	ids := distinct(services)
	if len(ids) == 0 {
		return rt.admins
	}
	var out []recipient
	add := func(list []recipient) {
		for _, r := range list {
			if !slices.ContainsFunc(out, func(o recipient) bool { return sameMailbox(o.email, r.email) }) {
				out = append(out, r)
			}
		}
	}
	for _, id := range ids {
		if sr, ok := rt.services[id]; !ok || sr.administrators {
			add(rt.admins)
			break
		}
	}
	for _, id := range ids {
		add(rt.services[id].owners)
	}
	for _, id := range ids {
		add(rt.services[id].addresses)
	}
	if len(out) == 0 {
		return rt.admins
	}
	return out
}

// distinct is services without uuid.Nil and repeats, in their first order.
func distinct(services []uuid.UUID) []uuid.UUID {
	var out []uuid.UUID
	for _, id := range services {
		if id != uuid.Nil && !slices.Contains(out, id) {
			out = append(out, id)
		}
	}
	return out
}

func encodeParams(template string, params map[string]string) ([]byte, error) {
	if !templatePattern.MatchString(template) {
		return nil, fmt.Errorf("notify: %q is not a template name", template)
	}
	if params == nil {
		params = map[string]string{}
	}
	return json.Marshal(params)
}

// insertRows queues one outbox row per recipient.
func insertRows(ctx context.Context, tx pgx.Tx, clk clock.Clock, rcpts []recipient, template string, raw []byte) error {
	now := clk.Now().UTC()
	for _, r := range rcpts {
		if _, err := tx.Exec(ctx, `INSERT INTO notifications_outbox
(id, kind, to_address, template_key, params, locale, status, attempts, next_attempt_at, created_at)
VALUES ($1, 'email', $2, $3, $4, $5, 'pending', 0, $6, $6)`, uuid.Must(uuid.NewV7()), r.email, template, raw, r.locale, now); err != nil {
			return fmt.Errorf("notify: queue email: %w", err)
		}
	}
	return nil
}
