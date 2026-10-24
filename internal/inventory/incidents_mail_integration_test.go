//go:build integration

package inventory_test

import (
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/inventory"
	"alice/internal/license"
	"alice/internal/testutil/fakeacme"
	"alice/internal/testutil/pki"
)

// Incident e-mails (D3, HB-08 and HB-10, R64 Rulings 5, 6, 11 and 13): one set per move into needs_attention and one on
// completion, queued in the move's transaction, to the incident's services' recipients (the owner and the Administrators),
// also while the licence is locked; none on close.

// incidentMailParams are the params of every e-mail of template, oldest first.
func (h *harness) incidentMailParams(template string) []map[string]string {
	h.t.Helper()
	rows, err := h.db.Owner.Query(h.ctx, "SELECT params FROM notifications_outbox WHERE template_key = $1 ORDER BY created_at, id", template)
	require.NoError(h.t, err)
	defer rows.Close()
	var out []map[string]string
	for rows.Next() {
		var p map[string]string
		require.NoError(h.t, rows.Scan(&p))
		out = append(out, p)
	}
	require.NoError(h.t, rows.Err())
	return out
}

// endRunning ends every running deployment of the incident's places with status (verified remote when it succeeded).
func (w *acmeDeployWorld) endRunning(id uuid.UUID, status string) int {
	w.h.t.Helper()
	n := 0
	for _, l := range w.incident(id).Locations {
		if l.Status == inventory.IncidentLocationDeploying && l.DeploymentID != nil {
			verified := ""
			if status == inventory.DeployStatusSucceeded {
				verified = "remote"
			}
			w.endDeployment(*l.DeploymentID, status, verified, "")
			n++
		}
	}
	return n
}

// uploadedIncident starts an incident of the deploy fixture's old certificate (uploaded, not revocable by Alice) with
// the fixture's new certificate as its replacement, and an owner of the certificate's service with an address.
func uploadedIncident(t *testing.T, licensed bool) (*acmeDeployWorld, uuid.UUID) {
	t.Helper()
	f := newDeployFixture(t)
	h := f.h
	if licensed {
		h.installLicense("LIC-INCIDENT-MAIL", 5, 365)
	}
	require.NoError(t, h.lic.Tick(h.ctx))
	h.owner(h.defaultService(), "olga", "olga@example.com")
	w := &acmeDeployWorld{deployFixture: f}
	_, _, err := h.svc.UploadCertificate(h.ctx, f.admin, pemUpload(f.old))
	require.NoError(t, err)
	old := f.certByFingerprint(t, pki.Fingerprint(f.old.Cert))
	i, err := h.svc.StartIncident(h.ctx, f.admin, old.ID, inventory.IncidentInput{})
	require.NoError(t, err)
	_, err = h.svc.ChooseIncidentReplacement(h.ctx, f.admin, i.ID, f.cert.ID)
	require.NoError(t, err)
	w.advance()
	return w, i.ID
}

func TestIncidentNeedsAttentionMailedOncePerEntry(t *testing.T) {
	w, id := uploadedIncident(t, true)
	h := w.h
	require.Positive(t, w.endRunning(id, inventory.DeployStatusFailed))
	assert.Zero(t, h.emails(inventory.TemplateIncidentNeedsAttention), "nothing before the move")
	w.advance()
	i := w.incident(id)
	require.Equal(t, inventory.IncidentNeedsAttention, i.State)
	assert.Equal(t, []string{"ada@example.com", "olga@example.com"}, h.recipients(inventory.TemplateIncidentNeedsAttention),
		"the owner and the Administrators (policy default)")
	p := h.incidentMailParams(inventory.TemplateIncidentNeedsAttention)[0]
	assert.Equal(t, id.String(), p["incident_id"])
	assert.Equal(t, inventory.IncidentCodeDeploymentsFailed, p["error_reason"])
	assert.Equal(t, "www.example.test", p["certificate_name"])
	assert.NotEqual(t, "0", p["failed"])

	w.advance()
	w.advance()
	assert.Equal(t, 2, h.emails(inventory.TemplateIncidentNeedsAttention), "advancing again adds nothing")

	_, err := h.svc.RetryIncident(h.ctx, w.admin, id)
	require.NoError(t, err)
	w.advance()
	require.Positive(t, w.endRunning(id, inventory.DeployStatusFailed))
	w.advance()
	require.Equal(t, inventory.IncidentNeedsAttention, w.incident(id).State)
	assert.Equal(t, 4, h.emails(inventory.TemplateIncidentNeedsAttention), "a retry that fails again is new news: a second set")
	assert.Zero(t, h.emails(inventory.TemplateIncidentCompleted)+h.emails(inventory.TemplateIncidentCompletedNotRevocable))
}

func TestIncidentNeedsAttentionMailedOnRevocationFailure(t *testing.T) {
	t.Run("a refusal of the CA", func(t *testing.T) {
		w := newACMEDeployWorld(t)
		require.NoError(t, w.h.lic.Tick(w.h.ctx))
		_, cur := w.issued("www.example.test")
		require.NoError(t, w.fake.Advertise("revokeCert", "off"))
		i, err := w.h.svc.StartIncident(w.h.ctx, w.admin, cur, inventory.IncidentInput{RevokeMode: inventory.IncidentRevokeNow})
		require.NoError(t, err)
		w.advance()
		i = w.incident(i.ID)
		require.Equal(t, inventory.IncidentNeedsAttention, i.State)
		require.Equal(t, inventory.IncidentRevocationFailed, i.Revocation)
		mails := w.h.incidentMailParams(inventory.TemplateIncidentNeedsAttention)
		require.Len(t, mails, 1, "one Administrator, one e-mail")
		assert.Equal(t, i.AttentionCode, mails[0]["error_reason"])
		w.advance()
		assert.Equal(t, 1, w.h.emails(inventory.TemplateIncidentNeedsAttention))
	})
	t.Run("a CA outage before the last attempt", func(t *testing.T) {
		w := newACMEDeployWorld(t)
		require.NoError(t, w.h.lic.Tick(w.h.ctx))
		_, cur := w.issued("www.example.test")
		require.NoError(t, w.fake.AddFault(fakeacme.Fault{Endpoint: "revoke-cert", Kind: fakeacme.FaultServerInternal, Times: 3}))
		i, err := w.h.svc.StartIncident(w.h.ctx, w.admin, cur, inventory.IncidentInput{RevokeMode: inventory.IncidentRevokeNow})
		require.NoError(t, err)
		for range 3 {
			w.advance()
			w.h.clock.Advance(time.Hour)
		}
		i = w.incident(i.ID)
		assert.Equal(t, 3, i.RevokeAttempts)
		assert.Equal(t, inventory.IncidentRevocationPending, i.Revocation)
		assert.Zero(t, w.h.emails(inventory.TemplateIncidentNeedsAttention), "a retried outage sends nothing")
	})
}

// driveACMEIncident runs an ACME incident of the world to its end: the replacement ordered, its deployments verified.
func (w *acmeDeployWorld) driveACMEIncident(id uuid.UUID) inventory.Incident {
	w.h.t.Helper()
	i := w.incident(id)
	if i.OrderID != nil && i.OrderState == "running" {
		w.complete(*i.OrderID)
	}
	for range 6 {
		w.advance()
		w.endRunning(id, inventory.DeployStatusSucceeded)
		if i = w.incident(id); i.FinishedAt != nil {
			break
		}
	}
	return i
}

func TestIncidentCompletedMailedOnce(t *testing.T) {
	t.Run("an ACME incident", func(t *testing.T) {
		w := newACMEDeployWorld(t)
		require.NoError(t, w.h.lic.Tick(w.h.ctx))
		_, cur := w.issued("www.example.test")
		w.serves(w.loc1, cur)
		i, err := w.h.svc.StartIncident(w.h.ctx, w.admin, cur, inventory.IncidentInput{})
		require.NoError(t, err)
		i = w.driveACMEIncident(i.ID)
		require.Equal(t, inventory.IncidentCompleted, i.State)
		mails := w.h.incidentMailParams(inventory.TemplateIncidentCompleted)
		require.Len(t, mails, 1)
		assert.Equal(t, i.ID.String(), mails[0]["incident_id"])
		assert.Equal(t, "1", mails[0]["verified"])
		assert.Zero(t, w.h.emails(inventory.TemplateIncidentCompletedNotRevocable))
		w.advance()
		assert.Equal(t, 1, w.h.emails(inventory.TemplateIncidentCompleted))
	})
	t.Run("an uploaded certificate with a chosen replacement, and a closed incident", func(t *testing.T) {
		f := newDeployFixture(t)
		h := f.h
		h.installLicense("LIC-INCIDENT-DONE", 5, 365)
		require.NoError(t, h.lic.Tick(h.ctx))
		w := &acmeDeployWorld{deployFixture: f}
		_, _, err := h.svc.UploadCertificate(h.ctx, f.admin, pemUpload(f.old))
		require.NoError(t, err)
		old := f.certByFingerprint(t, pki.Fingerprint(f.old.Cert))
		i, err := h.svc.StartIncident(h.ctx, f.admin, old.ID, inventory.IncidentInput{})
		require.NoError(t, err)
		_, err = h.svc.ChooseIncidentReplacement(h.ctx, f.admin, i.ID, f.cert.ID)
		require.NoError(t, err)
		for range 4 {
			w.advance()
			w.endRunning(i.ID, inventory.DeployStatusSucceeded)
		}
		i = w.incident(i.ID)
		require.Equal(t, inventory.IncidentCompleted, i.State, "%v", locationStatus(i))
		assert.Equal(t, []string{"ada@example.com"}, h.recipients(inventory.TemplateIncidentCompletedNotRevocable))
		assert.Zero(t, h.emails(inventory.TemplateIncidentCompleted))

		closed, err := h.svc.StartIncident(h.ctx, f.admin, f.rsaCert.ID, inventory.IncidentInput{})
		require.NoError(t, err)
		_, err = h.svc.CloseIncident(h.ctx, f.admin, closed.ID)
		require.NoError(t, err)
		w.advance()
		assert.Equal(t, 1, h.emails(inventory.TemplateIncidentCompletedNotRevocable), "closing sends nothing")
		assert.Zero(t, h.emails(inventory.TemplateIncidentNeedsAttention))
	})
}

// Two engines advance the same incident at the moment it completes: the conditional move lets one of them through, and
// only that one queues the e-mail.
func TestIncidentMoveRaceMailsOnce(t *testing.T) {
	w := newACMEDeployWorld(t)
	require.NoError(t, w.h.lic.Tick(w.h.ctx))
	_, cur := w.issued("www.example.test")
	w.serves(w.loc1, cur)
	i, err := w.h.svc.StartIncident(w.h.ctx, w.admin, cur, inventory.IncidentInput{})
	require.NoError(t, err)
	w.complete(*w.incident(i.ID).OrderID)
	for range 4 {
		w.advance()
		if w.endRunning(i.ID, inventory.DeployStatusSucceeded) > 0 {
			break
		}
	}
	var wg sync.WaitGroup
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = w.h.svc.AdvanceIncident(w.h.ctx, i.ID)
		}()
	}
	wg.Wait()
	w.advance()
	require.Equal(t, inventory.IncidentCompleted, w.incident(i.ID).State)
	assert.Equal(t, 1, w.h.emails(inventory.TemplateIncidentCompleted), "exactly one set (one Administrator)")
}

// The licence locks while a deployment of the incident runs; it fails: the incident needs attention and its e-mail is
// queued in lock (R64 Ruling 13).
func TestIncidentMailsInLock(t *testing.T) {
	w, id := uploadedIncident(t, false)
	h := w.h
	h.clock.Advance(31 * 24 * time.Hour)
	require.NoError(t, h.lic.Tick(h.ctx))
	require.Error(t, h.lic.Allow(license.ClassChange), "the gate refuses changes")
	require.Positive(t, w.endRunning(id, inventory.DeployStatusFailed), "the deployments that were running when the licence locked")
	w.advance()
	require.Equal(t, inventory.IncidentNeedsAttention, w.incident(id).State)
	assert.Equal(t, []string{"ada@example.com", "olga@example.com"}, h.recipients(inventory.TemplateIncidentNeedsAttention))
}
