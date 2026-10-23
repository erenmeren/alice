package inventory

import (
	"errors"
	"maps"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"

	"alice/internal/providers"
)

// R52 item 2: the health of a bound location comes from its observations; a past success alone never makes it in sync
// once a newer observation disagrees. R62 Review Focus 5: this table is R52's, unchanged; fileBroken (a Windows
// binding's own rule) is false in every row, so a file's health is decided as before.
func TestLinuxDriftUnchanged(t *testing.T) {
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

// R62 Ruling 14: a Windows binding whose certificate or key broke after the deployment (the scan judged it a change
// outside Alice) disagrees even when it still names the desired certificate; one that broke before the deployment does
// not, and a broken binding never judged a change outside Alice is decided as R52 decides.
func TestLocationHealthBrokenFile(t *testing.T) {
	now := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	at := func(d time.Duration) *time.Time { v := now.Add(-d); return &v }
	c2 := strings.Repeat("2", 64)
	base := func() healthInput {
		return healthInput{desired: c2, deployedAt: at(10 * time.Hour), now: now, staleAfter: now.Add(-DriftStaleAfter)}
	}
	for name, tc := range map[string]struct {
		in   func(h *healthInput)
		want string
	}{
		"broken after the deployment, the desired certificate": {func(h *healthInput) {
			h.fileFP, h.fileAt, h.changedOutside, h.fileBroken = c2, at(time.Minute), at(time.Minute), true
		}, HealthDrifted},
		"broken after the deployment, no certificate": {func(h *healthInput) {
			h.fileFP, h.fileAt, h.changedOutside, h.fileBroken = "", at(time.Minute), at(time.Minute), true
		}, HealthDrifted},
		"broken before the deployment": {func(h *healthInput) {
			h.fileFP, h.fileAt, h.changedOutside, h.fileBroken = c2, at(11*time.Hour), at(11*time.Hour), true
		}, HealthInSync},
		"scanned after the deployment, judged broken before it": {func(h *healthInput) {
			h.fileFP, h.fileAt, h.changedOutside, h.fileBroken = c2, at(time.Minute), at(11*time.Hour), true
		}, HealthInSync},
		"broken, never judged a change outside Alice": {func(h *healthInput) {
			h.fileFP, h.fileAt, h.fileBroken = c2, at(time.Minute), true
		}, HealthInSync},
		"not broken, the desired certificate, judged changed": {func(h *healthInput) {
			h.fileFP, h.fileAt, h.changedOutside = c2, at(time.Minute), at(time.Minute)
		}, HealthInSync},
		"a deployment runs": {func(h *healthInput) {
			h.fileFP, h.fileAt, h.changedOutside, h.fileBroken, h.active = c2, at(time.Minute), at(time.Minute), true, true
		}, HealthPending},
	} {
		t.Run(name, func(t *testing.T) {
			in := base()
			tc.in(&in)
			assert.Equal(t, tc.want, locationHealth(in))
		})
	}
}

// R62 Ruling 15: the drift cause of a Windows binding is derived from its problems; every other kind has none.
func TestDriftCauseOf(t *testing.T) {
	win := providers.LocationWinSSLBinding
	for name, tc := range map[string]struct {
		kind               providers.LocationKind
		health             string
		problem, keyProblm string
		want               string
	}{
		"re-pointed":                  {win, HealthDrifted, "", "", DriftCauseRepointed},
		"certificate removed":         {win, HealthDrifted, "cert_missing", "", DriftCauseCertRemoved},
		"key missing":                 {win, HealthDrifted, "", "key_missing", DriftCauseKeyUnusable},
		"key inaccessible":            {win, HealthDrifted, "", "key_inaccessible", DriftCauseKeyUnusable},
		"certificate and key missing": {win, HealthDrifted, "cert_missing", "key_missing", DriftCauseCertRemoved},
		"not drifted":                 {win, HealthInSync, "cert_missing", "", ""},
		"a file":                      {providers.LocationServerFile, HealthDrifted, "missing", "", ""},
		"a file without a kind":       {"", HealthDrifted, "", "", ""},
	} {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, tc.want, driftCause(tc.kind, tc.health, tc.problem, tc.keyProblm))
		})
	}
	assert.True(t, bindingBroken(win, "cert_missing", ""))
	assert.True(t, bindingBroken(win, "", "key_inaccessible"))
	assert.True(t, bindingBroken(win, "", "key_missing"))
	assert.False(t, bindingBroken(win, "", ""))
	assert.False(t, bindingBroken(win, "not_a_certificate", ""), "not a certificate removed from the store")
	assert.False(t, bindingBroken(providers.LocationServerFile, "missing", "key_missing"), "only a Windows binding")
	assert.False(t, bindingBroken("", "cert_missing", ""))
}

// R62 Ruling 16: a Windows binding's drift e-mail is the Windows text of its cause (a prepared repair that cannot be
// made reads as the detected text of its cause), with windows_note when AutoCertRebind is on; a file's is unchanged,
// byte for byte, and so is a template that is not a drift e-mail.
func TestWindowsLocationMail(t *testing.T) {
	params := map[string]string{"target_name": "t", "cert_path": "p", "certificate_name": "c", "observed_name": "o"}
	win := func(cause string, acr bool) LocationObservation {
		return LocationObservation{kind: providers.LocationWinSSLBinding, Cause: cause, AutoCertRebind: acr}
	}
	for _, tc := range []struct {
		o        LocationObservation
		template string
		want     string
		note     bool
	}{
		{win(DriftCauseRepointed, false), TemplateDriftDetected, TemplateDriftDetectedWindows, false},
		{win(DriftCauseCertRemoved, true), TemplateDriftDetected, TemplateDriftDetectedWindowsCertRemoved, true},
		{win(DriftCauseKeyUnusable, false), TemplateDriftDetected, TemplateDriftDetectedWindowsKeyUnusable, false},
		{win(DriftCauseRepointed, true), TemplateDriftRepairReady, TemplateDriftRepairReadyWindows, true},
		{win(DriftCauseCertRemoved, false), TemplateDriftRepairReady, TemplateDriftDetectedWindowsCertRemoved, false},
		{win(DriftCauseKeyUnusable, false), TemplateDriftRepairReady, TemplateDriftDetectedWindowsKeyUnusable, false},
		{win("", false), TemplateDriftRepaired, TemplateDriftRepairedWindows, false},
		{win(DriftCauseRepointed, false), TemplateDriftFlapping, TemplateDriftFlappingWindows, false},
		{win(DriftCauseRepointed, false), TemplateDriftRepairFailing, TemplateDriftRepairFailingWindows, false},
	} {
		got, p := windowsLocationMail(tc.o, tc.template, params)
		assert.Equal(t, tc.want, got, tc.template+" "+tc.o.Cause)
		assert.Contains(t, WindowsDriftTemplates(), got)
		want := maps.Clone(params)
		if tc.note {
			want["windows_note"] = "autocertrebind"
		}
		assert.Equal(t, want, p, tc.template+" "+tc.o.Cause)
	}
	assert.Equal(t, map[string]string{"target_name": "t", "cert_path": "p", "certificate_name": "c", "observed_name": "o"}, params,
		"the caller's params are not changed")
	for _, kind := range []providers.LocationKind{"", providers.LocationServerFile} {
		for _, tpl := range DriftTemplates() {
			got, p := windowsLocationMail(LocationObservation{kind: kind, AutoCertRebind: true}, tpl, params)
			assert.Equal(t, tpl, got)
			assert.Equal(t, params, p)
		}
	}
	got, p := windowsLocationMail(win(DriftCauseRepointed, true), TemplateDeploymentFailed, params)
	assert.Equal(t, TemplateDeploymentFailed, got, "not a drift e-mail")
	assert.Equal(t, params, p)
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
