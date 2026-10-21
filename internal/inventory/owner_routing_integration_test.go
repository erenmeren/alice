//go:build integration

package inventory_test

import (
	"sort"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/inventory"
	"alice/internal/rbac"
)

// Service owners and notification routing (R56, design §7.2): the inventory's e-mails go to the recipients of the
// services they are about. SR-25.

// owner makes a person with an address the owner of service.
func (h *harness) owner(service uuid.UUID, name, email string) {
	h.t.Helper()
	p := h.user(name, rbac.Operator, email)
	_, err := h.db.Owner.Exec(h.ctx, `INSERT INTO service_owners (id, service_id, user_id, created_at) VALUES ($1, $2, $3, now())`,
		uuid.Must(uuid.NewV7()), service, p.UserID)
	require.NoError(h.t, err)
}

// recipients is every address an e-mail of template went to, sorted.
func (h *harness) recipients(template string) []string {
	h.t.Helper()
	rows, err := h.db.Owner.Query(h.ctx, "SELECT to_address FROM notifications_outbox WHERE template_key = $1", template)
	require.NoError(h.t, err)
	got, err := pgx.CollectRows(rows, pgx.RowTo[string])
	require.NoError(h.t, err)
	sort.Strings(got)
	return got
}

func (h *harness) clearOutbox() {
	h.t.Helper()
	_, err := h.db.Owner.Exec(h.ctx, "DELETE FROM notifications_outbox")
	require.NoError(h.t, err)
}

// SR-25: the owner of A gets the authentication e-mail of A's server, not of B's; the Administrators get both.
func TestServerEmailsGoToTheServicesOwners(t *testing.T) {
	h := newHarness(t)
	admin := h.user("ada", rbac.Admin, "ada@example.com")
	a, b := h.newService("Alpha"), h.newService("Bravo")
	h.owner(a, "olga", "olga@example.com")
	h.owner(b, "berk", "berk@example.com")
	ta, tb := h.add(admin, "web-a", "web-a.example.com"), h.add(admin, "web-b", "web-b.example.com")
	h.moveTo("targets", ta.ID, a)
	h.moveTo("targets", tb.ID, b)

	require.NoError(t, h.svc.RecordConnectionFailure(h.ctx, ta.ID, "ssh.auth_failed"))
	assert.Equal(t, []string{"ada@example.com", "olga@example.com"}, h.recipients(inventory.TemplateAuthFailed))
	h.clearOutbox()
	require.NoError(t, h.svc.RecordConnectionFailure(h.ctx, tb.ID, "ssh.auth_failed"))
	assert.Equal(t, []string{"ada@example.com", "berk@example.com"}, h.recipients(inventory.TemplateAuthFailed))
}

// SR-25: a deployment's e-mail reaches the owners of the certificate's service and of the destination server's
// service; a deployment inside the certificate's service does not reach the other service's owner.
func TestDeploymentEmailsGoToBothServicesOwners(t *testing.T) {
	f := newDeployFixture(t)
	h := f.h
	def, pay := h.defaultService(), h.newService("Payments")
	h.moveTo("targets", f.target2, pay)
	h.trust(def, pay)
	h.owner(def, "cem", "cem@example.com")
	h.owner(pay, "pia", "pia@example.com")

	across := f.request(f.admin, f.cert.ID, f.loc2)
	require.NoError(t, h.svc.FinishDeployment(h.ctx, across, inventory.DeploymentFinish{Status: inventory.DeployStatusFailed,
		ErrorCode: "nginx.config_invalid"}))
	assert.Equal(t, []string{"ada@example.com", "cem@example.com", "pia@example.com"}, h.recipients(inventory.TemplateDeploymentFailed))

	h.clearOutbox()
	inside := f.request(f.admin, f.cert.ID, f.loc1)
	require.NoError(t, h.svc.FinishDeployment(h.ctx, inside, inventory.DeploymentFinish{Status: inventory.DeployStatusFailed,
		ErrorCode: "nginx.config_invalid"}))
	assert.Equal(t, []string{"ada@example.com", "cem@example.com"}, h.recipients(inventory.TemplateDeploymentFailed))
}
