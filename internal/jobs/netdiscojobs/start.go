package netdiscojobs

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"alice/internal/discovery"
	"alice/internal/jobs"
)

// Scan triggers (discovery_scans.trigger).
const (
	TriggerManual   = "manual"
	TriggerSchedule = "schedule"
)

// StartRequest asks for a scan of one scope. A manual scan names the person (RequestedBy, Role) who started it; a
// scheduled one names nobody.
type StartRequest struct {
	ScopeID     uuid.UUID
	Trigger     string
	RequestedBy uuid.UUID
	Role        string
	Now         time.Time
}

// StartTx queues a scan of a live scope in tx: the discovery_scans row (queued) and its netdisco.scan job (payload: the
// scan id only; dedupe key jobs.NetdiscoScanDedupeKey: one live scan job per scope) are written together, so they
// commit or roll back together. This is the only way a scan is queued (the API's start route, the schedule): a scan row
// without a job would be ended by the orphan sweep. discovery.ErrScanRunning (ALC-DSC-0004) when the scope has a scan
// queued or running, discovery.ErrScopeNotFound (ALC-DSC-0008) when it is deleted or unknown; after any error the
// caller rolls tx back (it may be aborted).
func StartTx(ctx context.Context, tx pgx.Tx, q Enqueuer, r StartRequest) (scanID, jobID uuid.UUID, err error) {
	kind := jobs.KindScheduled
	var by *uuid.UUID
	switch r.Trigger {
	case TriggerSchedule:
	case TriggerManual:
		kind = jobs.KindUser
		if r.RequestedBy != uuid.Nil {
			by = &r.RequestedBy
		}
	default:
		return uuid.Nil, uuid.Nil, fmt.Errorf("netdiscojobs: unknown scan trigger %q", r.Trigger)
	}
	scanID, err = discovery.CreateScanTx(ctx, tx, r.ScopeID, r.Trigger, by, r.Now)
	if err != nil {
		return uuid.Nil, uuid.Nil, err
	}
	var service uuid.UUID // the scope's (R49)
	if err := tx.QueryRow(ctx, "SELECT service_id FROM discovery_scopes WHERE id = $1", r.ScopeID).Scan(&service); err != nil {
		return uuid.Nil, uuid.Nil, fmt.Errorf("netdiscojobs: read the scope's service: %w", err)
	}
	spec := jobs.Spec{Type: jobs.NetdiscoScan, Kind: kind, Payload: map[string]string{PayloadScanID: scanID.String()},
		DedupeKey: jobs.NetdiscoScanDedupeKey(r.ScopeID), ServiceID: service}
	if by != nil {
		spec.CreatedBy, spec.CreatedByRole = *by, r.Role
	}
	jobID, dup, err := q.Add(ctx, tx, spec)
	switch {
	case err != nil:
		return uuid.Nil, uuid.Nil, err
	case dup:
		// A live job already holds the scope's key: its scan is still in flight, whatever its row says.
		return uuid.Nil, uuid.Nil, discovery.ErrScanRunning
	}
	return scanID, jobID, nil
}
