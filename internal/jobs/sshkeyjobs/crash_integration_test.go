//go:build integration

package sshkeyjobs_test

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/providers/fake"
)

// loginsWith counts the world's test logins that offered the key.
func (e *env) loginsWith(fp string) int {
	n := 0
	for _, ev := range e.events("VerifyKeyLogin") {
		if ev.Fingerprint == fp {
			n++
		}
	}
	return n
}

// F-67: Alice is killed between "add new key" and "verify". On restart the runner verifies the new key,
// the old key remains, and the run resumes from the last recorded step; nothing is removed by the
// recovery without a passing verification. S4: the line proved by the login alone is recorded.
func TestF67KillBetweenAddAndVerify(t *testing.T) {
	e := newEnv(t)
	web := e.server("web-01")
	k := e.generate("ci")
	e.place(k, web, "deploy")
	kill := newKiller("session:after:AddAuthorizedKey")
	e.setKiller(kill)
	r := e.runNow(e.policy(k.ID, 1))
	e.drainDying()
	require.Equal(t, "session:after:AddAuthorizedKey", kill.firedAt())
	loc := e.run(r.ID).Locations[0]
	assert.Equal(t, "adding", loc.State, "the add was recorded as sent, its outcome not yet")
	assert.True(t, e.world.Has(web, keyFile("deploy"), k.Fingerprint))
	assert.True(t, e.world.Has(web, keyFile("deploy"), r.NewFingerprint), "the line was written before the kill")
	e.setKiller(nil)
	e.restart()
	e.drain()
	r = e.run(r.ID)
	assert.Equal(t, "overlap", r.Status, "the run resumed and verified")
	assert.Equal(t, 1, e.countEvents("AddAuthorizedKey"), "the recovery verified instead of adding again")
	assert.Equal(t, 1, e.loginsWith(r.NewFingerprint))
	assert.True(t, e.world.Has(web, keyFile("deploy"), k.Fingerprint), "the old key remains")
	assert.Zero(t, e.removalsOf(k.Fingerprint))
	assert.Equal(t, 1, e.audits("job.recovered"))
	loc = e.run(r.ID).Locations[0]
	assert.Equal(t, "verified", loc.State)
	require.NotNil(t, loc.NewLocationID, "I5 (S4): the line confirmed by the login is a location of the new key")
	assert.Equal(t, 1, e.count("SELECT count(*) FROM audit_log WHERE action = 'sshkey.added' AND details->>'ssh_key_id' = $1",
		r.NewKeyID.String()), "S4: the change Alice made is audited")
}

// killPoints are every point the engine records or calls: before and after each store method and after
// each provider call.
var killPoints = []string{
	"before:LocationWork", "after:LocationWork",
	"before:BeginAdd", "after:BeginAdd", "session:after:AddAuthorizedKey", "before:FinishAdd", "after:FinishAdd",
	"session:after:VerifyKeyLogin", "before:RecordVerify", "after:RecordVerify", "before:Advance", "after:Advance",
	"before:RecordReverify", "after:RecordReverify", "before:BeginRemove", "after:BeginRemove",
	"session:after:RemoveAuthorizedKey", "before:FinishRemove", "after:FinishRemove",
	"before:BeginUndo", "after:BeginUndo", "session:after:ListKeys", "before:FinishUndo", "after:FinishUndo",
}

// undoNeededFor makes db-01's login refused for the undo points, so those points are reached.
func undoNeededFor(point string) func(fake.FaultPoint, *scenario) fake.Fault {
	if !strings.Contains(point, "Undo") && point != "session:after:ListKeys" {
		return nil
	}
	return func(p fake.FaultPoint, s *scenario) fake.Fault {
		if p.Method == "VerifyKeyLogin" && p.Target == s.db {
			return fake.FaultRefuse
		}
		return fake.FaultNone
	}
}

// Every point the engine records or calls: Alice is killed there once, restarts, and the system settles
// with every invariant holding.
func TestKillAtEveryRecordedPoint(t *testing.T) {
	for _, point := range killPoints {
		t.Run(point, func(t *testing.T) {
			t.Parallel()
			s := runScenario(t, schedule{v: twoLocs, renewAfter: time.Hour, step: time.Hour, killAt: point, fault: undoNeededFor(point)})
			s.assertInvariants(t)
			assert.Equal(t, 1, s.e.audits("job.recovered"), "the kill at %s happened and the job was recovered", point)
		})
	}
}
