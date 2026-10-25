package inventory

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/authz"
	"alice/internal/providers"
)

func canaryPolicy(t *testing.T, doc string) authz.Policy {
	t.Helper()
	p, err := authz.ParsePolicy([]byte(doc), "")
	require.NoError(t, err)
	return p
}

// CAN-16 (design §6, §15): whether a request becomes a rollout.
func TestCanaryDecision(t *testing.T) {
	now := time.Date(2026, 10, 25, 9, 0, 0, 0, time.UTC)
	on := canaryPolicy(t, `{"schema":1,"canary":{"enabled":true,"hold":"1h"}}`)
	off := canaryPolicy(t, `{"schema":1,"canary":{"enabled":false,"hold":"1h"}}`)
	a, b, c := uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7())
	dests := []uuid.UUID{c, a, b}
	hold := time.Hour
	for _, tc := range []struct {
		name             string
		p                authz.Policy
		dests            []uuid.UUID
		current          map[uuid.UUID]time.Time
		override, exempt bool
		skip             string
		waves            bool
	}{
		{name: "no policy", p: authz.EmptyPolicy(), dests: dests, skip: CanarySkipDisabled},
		{name: "disabled", p: off, dests: dests, skip: CanarySkipDisabled},
		{name: "one destination", p: on, dests: dests[:1], skip: CanarySkipSingle},
		{name: "override", p: on, dests: dests, override: true, skip: CanarySkipOverride},
		{name: "incident replacement", p: on, dests: dests, exempt: true, override: true, skip: CanarySkipExempt},
		{name: "a current certificate ends within hold + 24 h", p: on, dests: dests,
			current: map[uuid.UUID]time.Time{b: now.Add(hold + 23*time.Hour), a: now.Add(90 * 24 * time.Hour)}, skip: CanarySkipExpiry},
		{name: "after hold + 24 h", p: on, dests: dests, current: map[uuid.UUID]time.Time{b: now.Add(hold + 25*time.Hour)}, waves: true},
		{name: "unknown current certificates", p: on, dests: dests, waves: true},
	} {
		s, w1, w2, skip := canaryDecision(tc.p, tc.dests, tc.current, now, tc.override, tc.exempt)
		assert.Equal(t, tc.skip, skip, tc.name)
		if tc.p.CanaryEnabled() {
			assert.Equal(t, hold, s.Hold, tc.name)
		}
		if !tc.waves {
			assert.Nil(t, w1, tc.name)
			assert.Nil(t, w2, tc.name)
			continue
		}
		want1, want2 := authz.CanaryWaves(tc.dests, s)
		assert.Equal(t, want1, w1, tc.name)
		assert.Equal(t, want2, w2, tc.name)
		assert.Equal(t, []uuid.UUID{a}, w1, tc.name)
	}
}

// The expiry guard names the earliest current certificate and its location.
func TestCanaryEarliestExpiry(t *testing.T) {
	now := time.Date(2026, 10, 25, 9, 0, 0, 0, time.UTC)
	a, b := uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7())
	loc, at, ok := earliestExpiry([]uuid.UUID{a, b}, map[uuid.UUID]time.Time{a: now.Add(48 * time.Hour), b: now.Add(time.Hour)})
	require.True(t, ok)
	assert.Equal(t, b, loc)
	assert.Equal(t, now.Add(time.Hour), at)
	_, _, ok = earliestExpiry([]uuid.UUID{a}, nil)
	assert.False(t, ok)
}

// Review Focus 2, design §9.3: the address is the location's verification address, else its server's host, never the
// policy's host; the port and the server name follow the table's precedence.
func TestCanaryCheckSpecPrecedence(t *testing.T) {
	loc := providers.CertLocation{Servers: []providers.CertServer{{Names: []string{"_", "*.shop.example"}, Listens: []providers.CertListen{{Port: 8443}}}}}
	m := Material{Fingerprint: "ab", SANs: []string{"san.example"}, Location: loc}
	st := authz.CanarySettings{Timeout: 3 * time.Second, Check: &authz.CanaryCheck{Path: "/h", ExpectStatus: []int{204}}}

	spec := canaryCheckSpec(st, m, "web-01.internal", "")
	assert.Equal(t, CanaryCheckSpec{Address: "web-01.internal", Port: 8443, ServerName: "alice-check.shop.example", Path: "/h",
		ExpectStatus: []int{204}, Timeout: 3 * time.Second, ExpectLeafSHA256: "ab"}, *spec)

	spec = canaryCheckSpec(st, m, "web-01.internal", "10.9.9.9")
	assert.Equal(t, "10.9.9.9", spec.Address, "the verification address wins over the host")

	m.Verify = providers.VerifyOptions{Port: 9443, SNI: "probe.example"}
	spec = canaryCheckSpec(st, m, "web-01.internal", "")
	assert.Equal(t, 9443, spec.Port)
	assert.Equal(t, "probe.example", spec.ServerName)

	st.Check = &authz.CanaryCheck{Path: "/h", Host: "metadata.example", Port: 10443}
	spec = canaryCheckSpec(st, m, "web-01.internal", "")
	assert.Equal(t, 10443, spec.Port)
	assert.Equal(t, "metadata.example", spec.ServerName)
	assert.Equal(t, "web-01.internal", spec.Address, "the policy's host is never dialed")

	assert.Equal(t, 443, firstListenPort(nil))
	assert.Equal(t, "san.example", sniFor([]string{"_", "~re", ".x..y", "10.0.0.1"}, []string{"SAN.example"}))
	assert.Equal(t, "", sniFor(nil, []string{"*"}))
	assert.Equal(t, "x.example", sniFor([]string{".x.example"}, nil))
}
