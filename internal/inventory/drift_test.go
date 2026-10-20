package inventory

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"

	"alice/internal/providers"
)

// R52 item 2: the health of a bound location comes from its observations; a past success alone never makes it in sync
// once a newer observation disagrees.
func TestLocationHealth(t *testing.T) {
	now := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	at := func(d time.Duration) *time.Time { v := now.Add(-d); return &v }
	c1, c2 := strings.Repeat("1", 64), strings.Repeat("2", 64)
	base := func() healthInput {
		return healthInput{desired: c2, deployedAt: at(10 * time.Hour), now: now, staleAfter: now.Add(-DriftStaleAfter)}
	}
	for name, tc := range map[string]struct {
		in   func(h *healthInput)
		want string
	}{
		"nothing desired":                                     {func(h *healthInput) { h.desired = "" }, HealthUnmanaged},
		"a deployment runs":                                   {func(h *healthInput) { h.active = true }, HealthPending},
		"never reached":                                       {func(h *healthInput) { h.deployedAt = nil; h.fileFP, h.fileAt = c1, at(time.Hour) }, HealthPending},
		"deployed, nothing observed since":                    {func(*healthInput) {}, HealthInSync},
		"deployed long ago, nothing observed since":           {func(h *healthInput) { h.deployedAt = at(48 * time.Hour) }, HealthStale},
		"the website serves the desired one":                  {func(h *healthInput) { h.tlsFP, h.tlsAt = c2, at(time.Minute) }, HealthInSync},
		"the website serves another one after the deployment": {func(h *healthInput) { h.tlsFP, h.tlsAt = c1, at(time.Minute) }, HealthDrifted},
		"the website served another one before the deployment": {func(h *healthInput) { h.tlsFP, h.tlsAt = c1, at(11*time.Hour) },
			HealthInSync},
		"the file holds another one, changed outside Alice": {func(h *healthInput) {
			h.fileFP, h.fileAt, h.changedOutside = c1, at(time.Minute), at(time.Minute)
		}, HealthDrifted},
		"the file holds another one, not judged a change outside Alice": {func(h *healthInput) {
			h.fileFP, h.fileAt = c1, at(time.Minute)
		}, HealthInSync},
		"seen in sync before, never deployed, now another one served": {func(h *healthInput) {
			h.deployedAt, h.inSyncFP, h.tlsFP, h.tlsAt = nil, c2, c1, at(time.Minute)
		}, HealthDrifted},
		"the last probe failed": {func(h *healthInput) {
			h.tlsFP, h.tlsAt, h.attemptAt, h.attemptFailed = c2, at(7*time.Hour), at(time.Minute), true
		}, HealthUnreachable},
		"a failed probe before the deployment": {func(h *healthInput) {
			h.attemptAt, h.attemptFailed = at(11*time.Hour), true
		}, HealthInSync},
		"drift wins over a failed later probe": {func(h *healthInput) {
			h.tlsFP, h.tlsAt, h.attemptAt, h.attemptFailed = c1, at(2*time.Hour), at(time.Minute), true
		}, HealthDrifted},
		"a fresh agreeing file after an old deployment": {func(h *healthInput) {
			h.deployedAt, h.fileFP, h.fileAt = at(72*time.Hour), c2, at(time.Hour)
		}, HealthInSync},
	} {
		t.Run(name, func(t *testing.T) {
			in := base()
			tc.in(&in)
			assert.Equal(t, tc.want, locationHealth(in))
		})
	}
}

// What one verification of the desired certificate says about the website (R52 item 1): where it was probed from, what
// it served, its trust; a probe that reached nothing is a failure with its closed reason.
func TestDriftResultOf(t *testing.T) {
	now := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	loc := uuid.New()
	desired, other := strings.Repeat("a", 64), strings.Repeat("b", 64)
	req := providers.VerifyRequest{Fingerprint: desired}
	for name, tc := range map[string]struct {
		vr   providers.VerifyResult
		err  error
		want DriftResult
	}{
		"served and trusted from Alice": {providers.VerifyResult{OK: true, Mode: "remote", Served: desired, Level: providers.LevelTrusted,
			Trust: providers.Trust{Status: providers.TrustTrusted}}, nil,
			DriftResult{Reached: true, Served: desired, Probe: DriftProbeAlice, Level: providers.LevelTrusted, Trust: providers.TrustTrusted}},
		"another leaf from the server itself": {providers.VerifyResult{Mode: "local", Served: other, Reason: "deployment.verify_other",
			Failure: providers.VerifyFailureCertificate}, nil, DriftResult{Reached: true, Served: other, Probe: DriftProbeHelper}},
		"served but untrusted": {providers.VerifyResult{Mode: "remote", Served: desired, Failure: providers.VerifyFailureTrust,
			Trust: providers.Trust{Status: providers.TrustUntrusted, Error: providers.TrustErrWrongIntermediate}}, nil,
			DriftResult{Reached: true, Served: desired, Probe: DriftProbeAlice, Trust: providers.TrustUntrusted,
				TrustError: providers.TrustErrWrongIntermediate}},
		"unreachable": {providers.VerifyResult{Reason: "deployment.verify_unreachable", Failure: providers.VerifyFailureNetwork}, nil,
			DriftResult{Error: "deployment.verify_unreachable"}},
		"skipped":        {providers.VerifyResult{OK: true, Mode: "skipped"}, nil, DriftResult{Skipped: true}},
		"the SSH failed": {providers.VerifyResult{}, providers.NewError("ssh.timeout", true, errors.New("x"), nil), DriftResult{Error: "ssh.timeout"}},
		"anything else":  {providers.VerifyResult{}, errors.New("boom"), DriftResult{Error: "internal.unexpected"}},
	} {
		t.Run(name, func(t *testing.T) {
			want := tc.want
			want.LocationID, want.At = loc, now
			assert.Equal(t, want, DriftResultOf(loc, req, tc.vr, tc.err, now))
		})
	}
}

func TestDriftSpreadStaysInsideATenthOfTheInterval(t *testing.T) {
	for range 100 {
		d := driftSpread(uuid.New())
		assert.GreaterOrEqual(t, d, time.Duration(0))
		assert.Less(t, d, DriftObserveInterval/10)
	}
}
