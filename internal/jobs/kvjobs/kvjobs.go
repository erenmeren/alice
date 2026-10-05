// Package kvjobs holds the job handlers of Azure Key Vault targets (spec §8.2, §11) and the two
// periodic tasks that drive them: kv.test_connection (the access check), kv.poll (one poll of a
// vault: discover through the provider, store through inventory), kv.import (one import into a
// vault) and, as periodic tasks, kv.schedule (queue the polls that are due) and kv.auto_deploy
// (plan the deployments of renewed versions).
//
// Handlers hold no state between jobs. Every provider call runs under a context with a deadline (the
// job's, bounded by the provider's own budget plus a margin: the provider's budget is the real limit,
// the deadline here only keeps a provider that forgot it from holding a worker for ever). A failure
// of the vault is recorded on the vault (RecordKVFailure) by the access check and the poll, never by
// an import: an import is a person's action and says nothing new about the vault's health, and its
// attempts must not stretch the poll back-off. The text of an error is never stored, logged or
// returned: only closed reasons, allowlisted params and the Go type of a failure the code did not
// expect.
package kvjobs

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"

	"alice/internal/audit"
	"alice/internal/inventory"
	"alice/internal/jobs"
	"alice/internal/platform/clock"
	"alice/internal/providers"
)

// Inventory is the part of *inventory.Service the handlers use.
type Inventory interface {
	TargetRef(ctx context.Context, id uuid.UUID) (providers.TargetRef, inventory.Target, error)
	VaultCredentials(id uuid.UUID) inventory.VaultCredentialSource
	RecordKVConnection(ctx context.Context, id uuid.UUID, rep providers.ConnectionReport) error
	RecordAccessCheckRead(ctx context.Context, vaultID uuid.UUID, certificateName, version string, result audit.Result, reason string) error
	RecordKVFailure(ctx context.Context, id uuid.UUID, cause error) error
	AcquireKVPoll(ctx context.Context) (func(), error)
	KVPollRequest(ctx context.Context, id uuid.UUID) (providers.DiscoverRequest, error)
	ReconcileKV(ctx context.Context, id uuid.UUID, res providers.DiscoveryResult) (inventory.KVSummary, error)
	KVCertificate(ctx context.Context, vault, id uuid.UUID) (inventory.KVCertificateDetail, error)
	Import(ctx context.Context, vault, id uuid.UUID) (inventory.KVImport, error)
	ImportMaterial(ctx context.Context, id uuid.UUID) (inventory.ImportMaterial, error)
	MarkImportSent(ctx context.Context, id uuid.UUID) error
	FinishImport(ctx context.Context, id uuid.UUID, res providers.ImportResult, cause error) (inventory.KVImport, error)
	FailQueuedImport(ctx context.Context, id uuid.UUID, code string) (inventory.KVImport, error)
}

var _ Inventory = (*inventory.Service)(nil)

// Deps are the handlers' dependencies.
type Deps struct {
	Inventory Inventory
	Registry  *providers.Registry
	Clock     clock.Clock
	Log       *slog.Logger
}

// Deadlines of the provider calls. The provider's own budget is the limit that matters (the access
// check 45 s, a poll 11 minutes, a secret read one minute, an import's send about 105 s); these only
// bound a provider that does not honour it. A poll's deadline is longer than the provider's budget so
// the provider ends the poll itself, as throttled, and inventory counts the cycle.
const (
	openTimeout   = time.Minute
	testTimeout   = 90 * time.Second
	secretTimeout = 90 * time.Second
	pollTimeout   = 12 * time.Minute
	importTimeout = 4 * time.Minute
	// recordTimeout bounds the write of an outcome that is recorded on a context detached from the
	// job's: a lease lost, or a shutdown, during a send must not erase what the send did.
	recordTimeout = 15 * time.Second
)

// Register registers the three handlers; it panics on a missing dependency, so a build that forgot
// one never starts.
func Register(r *jobs.Runner, d Deps) {
	if r == nil || d.Inventory == nil || d.Registry == nil || d.Clock == nil {
		panic("kvjobs: Register needs a runner, Deps.Inventory, Deps.Registry and Deps.Clock")
	}
	h := newHandlers(d)
	r.Handle(jobs.KVTestConnection, h.testConnection)
	r.Handle(jobs.KVPoll, h.poll)
	r.Handle(jobs.KVImport, h.importToKV)
}

type handlers struct{ d Deps }

func newHandlers(d Deps) *handlers {
	if d.Log == nil {
		d.Log = slog.New(slog.DiscardHandler)
	}
	return &handlers{d: d}
}

// resolve checks that id is a live, enabled vault and that this build has the Key Vault provider. The
// failures are the job's, none is recorded on the vault: a deleted or disabled vault is dropped, a
// server's id or a build without the provider is not the vault's fault.
func (h *handlers) resolve(ctx context.Context, id uuid.UUID) (providers.Provider, providers.TargetRef, error) {
	ref, t, err := h.d.Inventory.TargetRef(ctx, id)
	switch {
	case errors.Is(err, inventory.ErrNotFound):
		return nil, ref, jobs.Fail(reasonNotFound, nil, err)
	case err != nil:
		return nil, ref, jobs.Retry(reasonUnexpected, nil, err)
	case t.Type != inventory.TypeAzureKeyVault:
		return nil, ref, jobs.Fail(reasonUnexpected, nil, inventory.ErrNotAVault)
	case t.Status == inventory.StatusDisabled:
		return nil, ref, jobs.Fail(reasonDisabled, nil, nil)
	}
	p, ok := h.d.Registry.Get(providers.KindAzureKV)
	if !ok {
		return nil, ref, jobs.Fail(reasonUnexpected, nil, errors.New("kvjobs: no Key Vault provider in this build"))
	}
	return p, ref, nil
}

// openSession opens the vault's session (the credential is read by the provider through the vault's
// own source and zeroed by it). A failure is returned as the provider's classified error; record
// says whether it is also written on the vault.
func (h *handlers) openSession(ctx context.Context, p providers.Provider, ref providers.TargetRef, record bool) (providers.Session, error) {
	octx, cancel := context.WithTimeout(ctx, openTimeout)
	defer cancel()
	sess, err := p.Open(octx, ref, h.d.Inventory.VaultCredentials(ref.ID), providers.Env{Clock: h.d.Clock, Log: h.d.Log})
	if err != nil {
		return nil, h.providerFailure(ctx, ref.ID, err, record)
	}
	return sess, nil
}

// providerFailure turns an error of a provider call into the job's failure. When the job's own context
// has ended (a shutdown, a lost lease) the vault is not blamed and the run is handed back; otherwise the
// failure is recorded on the vault (record) with its closed code and classified as the provider says. A
// failure that is not a provider error (the provider's own deadline missed, a bug) is an unreachable
// vault from the point of view of the vault's status and carries no text.
func (h *handlers) providerFailure(ctx context.Context, id uuid.UUID, err error, record bool) error {
	if ctx.Err() != nil {
		return jobs.Retry(reasonLeaseExpired, nil, ctx.Err())
	}
	var pe *providers.Error
	if !errors.As(err, &pe) {
		pe = providers.NewError(reasonUnreachable, true, err, nil)
		err = pe
	}
	if record {
		if rerr := h.d.Inventory.RecordKVFailure(context.WithoutCancel(ctx), id, pe); rerr != nil {
			h.d.Log.Error("could not record a vault failure", "target_id", id.String(), "error_type", fmt.Sprintf("%T", rerr))
		}
	}
	return jobs.FromProvider(err)
}

func (h *handlers) close(s providers.Session) {
	if err := s.Close(); err != nil {
		h.d.Log.Warn("closing a provider session failed", "error_type", fmt.Sprintf("%T", err))
	}
}

// Reasons of this package (closed codes; the rest are the provider's and inventory's).
const (
	reasonNotFound     = "system.not_found"
	reasonDisabled     = "target.disabled"
	reasonUnexpected   = "internal.unexpected"
	reasonLeaseExpired = "job.lease_expired"
	reasonUnreachable  = "azure.unreachable"
	reasonForbidden    = "azure.forbidden"
	reasonFirewall     = "azure.firewall"
	// reasonNotDeployable: the certificate has no current version Alice has read, or it is not
	// exportable (the access check of the secrets role needs one to read).
	reasonNotDeployable  = "kv.version_not_deployable"
	reasonCertNotFound   = "kv.certificate_not_found"
	reasonUnexpectedResp = "azure.unexpected_response"
)
