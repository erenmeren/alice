//go:build integration

package sshkeys_test

import (
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/providers"
	"alice/internal/sshkeys"
)

// Task 13 review: AllowedActions offers exactly what the decision accepts, for every decision in
// every licence state: running, locked (not paused yet), paused before the renewal notice, and
// renotified. While paused only Abort is offered and accepted.
func TestAllowedActionsMatchTheDecisions(t *testing.T) {
	states := []string{"running", "locked", "paused", "renotified"}
	for _, kind := range []string{"overlap", "verifying"} {
		for _, state := range states {
			for _, action := range []string{sshkeys.ActionContinue, sshkeys.ActionFinishNow, sshkeys.ActionKeepOld, sshkeys.ActionAbort} {
				t.Run(kind+"/"+state+"/"+action, func(t *testing.T) {
					e := newEnv(t)
					srv := e.server("web-01")
					k := e.deployed("ci", srv, "deploy")
					outcomes := map[string]providers.KeyLoginOutcome{"deploy": providers.KeyLoginAccepted}
					if kind == "verifying" {
						e.addLocation(k.ID, srv, "root")
						outcomes["root"] = providers.KeyLoginUnprovable
					}
					r, ids := e.runToDecisionWith(k, outcomes)
					switch state {
					case "locked":
						e.gate.lock()
					case "paused", "renotified":
						if kind == "overlap" {
							e.clock.Advance(7 * 24 * time.Hour)
						}
						e.gate.lock()
						require.NoError(t, e.svc.Advance(e.ctx, r.ID))
						require.True(t, e.run(r.ID).PausedLicense)
						e.gate.unlock()
						if state == "renotified" {
							_, err := e.svc.Sweep(e.ctx)
							require.NoError(t, err)
							require.NotNil(t, e.run(r.ID).RenotifiedAt)
						}
					}
					got := e.run(r.ID)
					offered := slices.Contains(sshkeys.AllowedActions(got, state != "locked"), action)
					var err error
					switch action {
					case sshkeys.ActionContinue:
						err = e.svc.Continue(e.ctx, e.admin, r.ID)
					case sshkeys.ActionFinishNow:
						err = e.svc.FinishNow(e.ctx, e.admin, r.ID)
					case sshkeys.ActionKeepOld:
						loc := ids["root"]
						if loc == uuid.Nil {
							loc = ids["deploy"]
						}
						err = e.svc.KeepOld(e.ctx, e.admin, r.ID, []uuid.UUID{loc})
					case sshkeys.ActionAbort:
						err = e.svc.Abort(e.ctx, e.admin, r.ID)
					}
					assert.Equal(t, offered, err == nil, "offered %v, call: %v", offered, err)
					if got.PausedLicense {
						assert.Equal(t, action == sshkeys.ActionAbort || (action == sshkeys.ActionContinue && state == "renotified"), offered,
							"paused: only Abort (and Continue once renotified)")
					}
					if state == "locked" {
						assert.Equal(t, action == sshkeys.ActionAbort, offered, "in lock only Abort")
					}
				})
			}
		}
	}
}

// Task 13 review: the run list reads counts, not locations.
func TestRotationSummaries(t *testing.T) {
	e := newEnv(t)
	web1, web2 := e.server("web-01"), e.server("web-02")
	k := e.deployed("ci", web1, "deploy")
	e.addLocation(k.ID, web2, "deploy")
	e.setTargetStatus(web2, "unreachable")
	p := e.policy(k.ID, 90, 7, 24)
	first := e.runNow(p)
	require.NoError(t, e.svc.Abort(e.ctx, e.admin, first.ID))
	e.clock.Advance(time.Minute)
	second := e.runNow(p)
	for _, l := range second.Locations {
		if l.State == "planned" {
			e.drive(l.ID, providers.KeyLoginAccepted)
		}
	}
	list, next, err := e.svc.RotationSummaries(e.ctx, sshkeys.RotationFilter{PolicyID: p.ID, Limit: 1})
	require.NoError(t, err)
	require.Len(t, list, 1)
	assert.Equal(t, second.ID, list[0].ID)
	assert.Equal(t, sshkeys.LocationCounts{Total: 2, Verified: 1, Skipped: 1}, list[0].Counts)
	require.NotEmpty(t, next)
	list, next, err = e.svc.RotationSummaries(e.ctx, sshkeys.RotationFilter{KeyID: k.ID, Cursor: next})
	require.NoError(t, err)
	require.Len(t, list, 1)
	assert.Equal(t, first.ID, list[0].ID)
	assert.Equal(t, "aborted", list[0].Status)
	assert.Empty(t, next)
	_, _, err = e.svc.RotationSummaries(e.ctx, sshkeys.RotationFilter{Cursor: "!"})
	assert.ErrorIs(t, err, sshkeys.ErrBadCursor)
	list, _, err = e.svc.RotationSummaries(e.ctx, sshkeys.RotationFilter{KeyID: uuid.New()})
	require.NoError(t, err)
	assert.Empty(t, list)
}
