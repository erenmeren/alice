package authz_test

import (
	"bytes"
	"encoding/json"
	"math/rand/v2"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/authz"
	"alice/internal/platform/validate"
)

// CAN-01: defaults, normalization and the stored form of the canary key.
func TestParseCanaryDefaultsAndNormalization(t *testing.T) {
	p := parse(t, `{"schema":1,"canary":{"enabled":true}}`)
	require.True(t, p.CanaryEnabled())
	s, ok := p.CanarySettings()
	require.True(t, ok)
	assert.Equal(t, 1, s.Count)
	assert.Zero(t, s.Percent)
	assert.Empty(t, s.First)
	assert.Equal(t, 10*time.Minute, s.Hold)
	assert.Equal(t, 30*time.Second, s.Interval)
	assert.Equal(t, 5*time.Second, s.Timeout)
	assert.Equal(t, 2, s.Failures)
	assert.Nil(t, s.Check)
	assert.True(t, s.OverrideAllowed)
	assert.JSONEq(t, `{"schema":1,"canary":{"enabled":true}}`, string(p.Document()))

	p = parse(t, `{"schema":1,"canary":{"enabled":true,"hold":"120s","interval":"90s","failures":3,"subset":{"percent":20},
"check":{"path":"/healthz?x=1","host":"App.Example.com","port":8443,"expect_status":[200,204],"timeout":"3s"},"override":"forbidden"}}`)
	assert.JSONEq(t, `{"schema":1,"canary":{"enabled":true,"subset":{"percent":20},"hold":"2m","interval":"90s","failures":3,
"check":{"path":"/healthz?x=1","host":"app.example.com","port":8443,"expect_status":[200,204],"timeout":"3s"},"override":"forbidden"}}`,
		string(p.Document()))
	s, ok = p.CanarySettings()
	require.True(t, ok)
	assert.Equal(t, 0, s.Count)
	assert.Equal(t, 20, s.Percent)
	assert.Equal(t, 2*time.Minute, s.Hold)
	assert.Equal(t, 90*time.Second, s.Interval)
	assert.Equal(t, 3*time.Second, s.Timeout)
	assert.Equal(t, 3, s.Failures)
	assert.False(t, s.OverrideAllowed)
	require.NotNil(t, s.Check)
	assert.Equal(t, "/healthz?x=1", s.Check.Path)
	assert.Equal(t, "app.example.com", s.Check.Host)
	assert.Equal(t, 8443, s.Check.Port)
	assert.Equal(t, []int{200, 204}, s.Check.ExpectStatus)

	// Explicit defaults are not stored (absent means default), so equal policies have equal documents.
	p = parse(t, `{"schema":1,"canary":{"enabled":true,"subset":{"count":1},"hold":"10m","interval":"30s","failures":2,
"check":{"path":"/","host":"","port":0,"expect_status":[200],"timeout":"5s"},"override":"allowed","first":[]}}`)
	assert.JSONEq(t, `{"schema":1,"canary":{"enabled":true,"check":{"path":"/"}}}`, string(p.Document()))
	s, _ = p.CanarySettings()
	assert.Equal(t, []int{200}, s.Check.ExpectStatus, "the settings carry the default statuses")
	assert.Equal(t, "5s", s.Check.Timeout, "the settings carry the default timeout")

	// Switched off with only defaults: the key disappears; switched off with settings: they are kept without effect.
	assert.JSONEq(t, `{"schema":1}`, string(parse(t, `{"schema":1,"canary":{"enabled":false}}`).Document()))
	assert.JSONEq(t, `{"schema":1}`, string(parse(t, `{"schema":1,"canary":{"enabled":false,"hold":"10m"}}`).Document()))
	off := parse(t, `{"schema":1,"canary":{"enabled":false,"hold":"1h"}}`)
	assert.JSONEq(t, `{"schema":1,"canary":{"enabled":false,"hold":"1h"}}`, string(off.Document()))
	assert.False(t, off.CanaryEnabled())
	_, ok = off.CanarySettings()
	assert.False(t, ok)
	_, ok = authz.EmptyPolicy().CanarySettings()
	assert.False(t, ok)

	// first keeps its order.
	a, b, c := uuid.New(), uuid.New(), uuid.New()
	p = parse(t, `{"schema":1,"canary":{"enabled":true,"first":["`+c.String()+`","`+a.String()+`","`+b.String()+`"]}}`)
	s, _ = p.CanarySettings()
	assert.Equal(t, []uuid.UUID{c, a, b}, s.First)

	// Units: the largest whole unit.
	for in, want := range map[string]string{"60s": "1m", "3600s": "1h", "90m": "90m", "120m": "2h", "24h": "24h", "1440m": "24h"} {
		p = parse(t, `{"schema":1,"canary":{"enabled":true,"hold":"`+in+`"}}`)
		assert.Equal(t, want, p.Canary.Hold, in)
	}
}

// CAN-02: every bound of spec §5.1, each refusal on its own field.
func TestParseCanaryRefuses(t *testing.T) {
	const ok = "ok"
	ids := make([]string, 21)
	for i := range ids {
		ids[i] = `"` + uuid.NewString() + `"`
	}
	dup := uuid.NewString()
	codes := func(n int) string {
		var out []string
		for i := range n {
			out = append(out, strconv.Itoa(200+i))
		}
		return strings.Join(out, ",")
	}
	cases := []struct {
		canary, field, code string
	}{
		{`"subset":{"count":1,"percent":10}`, "body.canary.subset", validate.OneOf},
		{`"subset":{}`, "body.canary.subset", validate.OneOf},
		{`"subset":{"count":0}`, "body.canary.subset.count", validate.OutOfRange},
		{`"subset":{"count":11}`, "body.canary.subset.count", validate.OutOfRange},
		{`"subset":{"percent":0}`, "body.canary.subset.percent", validate.OutOfRange},
		{`"subset":{"percent":51}`, "body.canary.subset.percent", validate.OutOfRange},
		{`"first":[` + strings.Join(ids, ",") + `]`, "body.canary.first", validate.TooLong},
		{`"first":["` + dup + `","` + dup + `"]`, "body.canary.first.1", validate.Duplicate},
		{`"first":["00000000-0000-0000-0000-000000000000"]`, "body.canary.first.0", validate.Required},
		{`"hold":"30s"`, "body.canary.hold", validate.OutOfRange},
		{`"hold":"25h"`, "body.canary.hold", validate.OutOfRange},
		{`"hold":"1h30m"`, "body.canary.hold", validate.Pattern},
		{`"hold":"1.5h"`, "body.canary.hold", validate.Pattern},
		{`"hold":"10"`, "body.canary.hold", validate.Pattern},
		{`"interval":"10s"`, "body.canary.interval", validate.OutOfRange},
		{`"interval":"11m","hold":"1h"`, "body.canary.interval", validate.OutOfRange},
		{`"interval":"5m","hold":"2m"`, "body.canary.interval", validate.OutOfRange},
		{`"interval":"1m","hold":"1m"`, "body.canary.interval", ok},
		{`"failures":0`, "body.canary.failures", validate.OutOfRange},
		{`"failures":11`, "body.canary.failures", validate.OutOfRange},
		{`"check":{}`, "body.canary.check.path", validate.Required},
		{`"check":{"path":"healthz"}`, "body.canary.check.path", validate.Pattern},
		{`"check":{"path":"/a#b"}`, "body.canary.check.path", validate.Pattern},
		{`"check":{"path":"/a b"}`, "body.canary.check.path", validate.Pattern},
		{`"check":{"path":"/a\u0001b"}`, "body.canary.check.path", validate.Pattern},
		{`"check":{"path":"/aé"}`, "body.canary.check.path", validate.Pattern},
		{`"check":{"path":"/a%zz"}`, "body.canary.check.path", validate.Pattern},
		{`"check":{"path":"/a%2"}`, "body.canary.check.path", validate.Pattern},
		{`"check":{"path":"/` + strings.Repeat("a", 512) + `"}`, "body.canary.check.path", validate.TooLong},
		{`"check":{"path":"/","host":"*.example.com"}`, "body.canary.check.host", validate.Pattern},
		{`"check":{"path":"/","host":"10.0.0.1"}`, "body.canary.check.host", validate.Pattern},
		{`"check":{"path":"/","host":"[::1]"}`, "body.canary.check.host", validate.Pattern},
		{`"check":{"path":"/","host":"::1"}`, "body.canary.check.host", validate.Pattern},
		{`"check":{"path":"/","host":"a..b"}`, "body.canary.check.host", validate.Pattern},
		{`"check":{"path":"/","host":"` + strings.Repeat("a.", 126) + `ab"}`, "body.canary.check.host", validate.Pattern},
		{`"check":{"path":"/","port":70000}`, "body.canary.check.port", validate.OutOfRange},
		{`"check":{"path":"/","port":-1}`, "body.canary.check.port", validate.OutOfRange},
		{`"check":{"path":"/","expect_status":[]}`, "body.canary.check.expect_status", validate.TooShort},
		{`"check":{"path":"/","expect_status":[99]}`, "body.canary.check.expect_status.0", validate.OutOfRange},
		{`"check":{"path":"/","expect_status":[200,600]}`, "body.canary.check.expect_status.1", validate.OutOfRange},
		{`"check":{"path":"/","expect_status":[` + codes(11) + `]}`, "body.canary.check.expect_status", validate.TooLong},
		{`"check":{"path":"/","expect_status":[200,200]}`, "body.canary.check.expect_status.1", validate.Duplicate},
		{`"check":{"path":"/","timeout":"0s"}`, "body.canary.check.timeout", validate.Pattern},
		{`"check":{"path":"/","timeout":"11s"}`, "body.canary.check.timeout", validate.OutOfRange},
		{`"interval":"15s","check":{"path":"/","timeout":"10s"}`, "body.canary.check.timeout", ok},
		{`"interval":"15s","hold":"1m","check":{"path":"/","timeout":"15s"}`, "body.canary.check.timeout", validate.OutOfRange},
		{`"override":"maybe"`, "body.canary.override", validate.OneOf},
	}
	for _, tc := range cases {
		doc := `{"schema":1,"canary":{"enabled":true,` + tc.canary + `}}`
		_, err := authz.ParsePolicy([]byte(doc), "body.")
		if tc.code == ok {
			assert.NoError(t, err, doc)
			continue
		}
		assert.Equal(t, map[string]string{tc.field: tc.code}, fieldCodes(t, err), doc)
	}
	// A 253-byte host is accepted; the bound is on the name.
	host := strings.Repeat("a.", 125) + "abc"
	require.Len(t, host, 253)
	_, err := authz.ParsePolicy([]byte(`{"schema":1,"canary":{"enabled":true,"check":{"path":"/","host":"`+host+`"}}}`), "body.")
	assert.NoError(t, err)
	// A 512-byte path is accepted.
	_, err = authz.ParsePolicy([]byte(`{"schema":1,"canary":{"enabled":true,"check":{"path":"/`+strings.Repeat("a", 511)+`"}}}`), "body.")
	assert.NoError(t, err)
	// RFC 3986 path and query characters.
	_, err = authz.ParsePolicy([]byte(`{"schema":1,"canary":{"enabled":true,"check":{"path":"/a-b._~!$&'()*+,;=:@/%2Fx?q=1&r=/?"}}}`), "body.")
	assert.NoError(t, err)

	for _, doc := range []string{
		`{"schema":1,"canary":{"enabled":true,"check":{"path":"/","url":"https://x"}}}`,
		`{"schema":1,"canary":{"enabled":true,"subset":{"count":1,"x":1}}}`,
		`{"schema":1,"canary":{"enabled":"yes"}}`,
		`{"schema":1,"canary":{"enabled":true,"hold":600}}`,
	} {
		_, err := authz.ParsePolicy([]byte(doc), "body.")
		assert.ErrorIs(t, err, authz.ErrPolicyMalformed, doc)
	}
}

func idAt(b byte) uuid.UUID {
	var u uuid.UUID
	u[0] = b
	u[15] = 1
	return u
}

// CAN-03: the waves of spec §7.
func TestCanaryWaves(t *testing.T) {
	d := make([]uuid.UUID, 21)
	for i := range d {
		d[i] = idAt(byte(i + 1))
	}
	count := func(n int) authz.CanarySettings { return authz.CanarySettings{Count: n} }
	percent := func(n int) authz.CanarySettings { return authz.CanarySettings{Percent: n} }

	w1, w2 := authz.CanaryWaves(d[1:2], count(1))
	assert.Nil(t, w1)
	assert.Nil(t, w2)
	w1, w2 = authz.CanaryWaves(nil, count(1))
	assert.Nil(t, w1)
	assert.Nil(t, w2)

	for _, tc := range []struct {
		name string
		n    int
		s    authz.CanarySettings
		k    int
	}{
		{name: "n=2 count 1", n: 2, s: count(1), k: 1},
		{name: "n=2 count 10 (wave 2 never empty)", n: 2, s: count(10), k: 1},
		{name: "n=20 percent 10", n: 20, s: percent(10), k: 2},
		{name: "n=3 percent 1", n: 3, s: percent(1), k: 1},
		{name: "n=5 percent 50 (ceil)", n: 5, s: percent(50), k: 3},
		{name: "n=2 percent 50", n: 2, s: percent(50), k: 1},
		{name: "n=20 count 10", n: 20, s: count(10), k: 10},
		{name: "zero settings are count 1", n: 4, s: authz.CanarySettings{}, k: 1},
	} {
		dests := slices.Clone(d[1 : tc.n+1])
		w1, w2 := authz.CanaryWaves(dests, tc.s)
		assert.Len(t, w1, tc.k, tc.name)
		assert.Len(t, w2, tc.n-tc.k, tc.name)
		assert.Equal(t, d[1:tc.k+1], w1, tc.name)
		assert.Equal(t, d[tc.k+1:tc.n+1], w2, tc.name)
	}

	// first: the destinations it names in its order, a stale id ignored; then the rest by UUID byte order.
	stale := uuid.New()
	dests := []uuid.UUID{d[5], d[1], d[4], d[3], d[2]}
	s := authz.CanarySettings{Count: 2, First: []uuid.UUID{d[4], stale, d[2]}}
	w1, w2 = authz.CanaryWaves(dests, s)
	assert.Equal(t, []uuid.UUID{d[4], d[2]}, w1)
	assert.Equal(t, []uuid.UUID{d[1], d[3], d[5]}, w2)
	s.Count = 1
	w1, w2 = authz.CanaryWaves(dests, s)
	assert.Equal(t, []uuid.UUID{d[4]}, w1)
	assert.Equal(t, []uuid.UUID{d[2], d[1], d[3], d[5]}, w2, "first ids past the subset lead wave 2")

	// Stable: any order of the same destinations gives the same waves, and the input is not changed.
	r := rand.New(rand.NewPCG(1, 2))
	base := slices.Clone(d[1:12])
	set := authz.CanarySettings{Percent: 30, First: []uuid.UUID{d[9]}}
	want1, want2 := authz.CanaryWaves(base, set)
	assert.Equal(t, []uuid.UUID{d[9], d[1], d[2], d[3]}, want1, "ceil(11 x 30 %) = 4")
	for range 20 {
		sh := slices.Clone(base)
		r.Shuffle(len(sh), func(i, j int) { sh[i], sh[j] = sh[j], sh[i] })
		before := slices.Clone(sh)
		g1, g2 := authz.CanaryWaves(sh, set)
		assert.Equal(t, want1, g1)
		assert.Equal(t, want2, g2)
		assert.Equal(t, before, sh)
	}
	assert.True(t, slices.IsSortedFunc(want2, func(a, b uuid.UUID) int { return bytes.Compare(a[:], b[:]) }))
}

// The snapshot a rollout stores reads back equal and is readable (durations as the policy writes them).
func TestCanarySettingsJSON(t *testing.T) {
	p := parse(t, `{"schema":1,"canary":{"enabled":true,"hold":"2h","subset":{"percent":10},"first":["`+idAt(3).String()+`"],
"check":{"path":"/h","host":"a.example.com","port":444,"expect_status":[200,301]},"override":"forbidden"}}`)
	s, ok := p.CanarySettings()
	require.True(t, ok)
	b, err := json.Marshal(s)
	require.NoError(t, err)
	assert.JSONEq(t, `{"count":0,"percent":10,"first":["`+idAt(3).String()+`"],"hold":"2h","interval":"30s","failures":2,
"check":{"path":"/h","host":"a.example.com","port":444,"expect_status":[200,301],"timeout":"5s"},"timeout":"5s","override_allowed":false}`, string(b))
	var back authz.CanarySettings
	require.NoError(t, json.Unmarshal(b, &back))
	assert.Equal(t, s, back)

	d, _ := authz.EmptyPolicy().CanarySettings()
	b, err = json.Marshal(d)
	require.NoError(t, err)
	assert.JSONEq(t, `{"count":0,"percent":0,"first":[],"hold":"0s","interval":"0s","failures":0,"check":null,"timeout":"0s","override_allowed":false}`, string(b))

	assert.Error(t, json.Unmarshal([]byte(`{"hold":"1h30m"}`), &back))
	assert.Error(t, json.Unmarshal([]byte(`{"interval":"x"}`), &back))
	assert.Error(t, json.Unmarshal([]byte(`{"timeout":"x"}`), &back))
	assert.Error(t, json.Unmarshal([]byte(`[]`), &back))
}

// Final review C2 (R65): wave 1 never holds more than MaxCanaryWave1 websites (the rollout table's CHECK), whatever the
// percentage of a large request.
func TestCanaryWavesCapWaveOne(t *testing.T) {
	ids := func(n int) []uuid.UUID {
		out := make([]uuid.UUID, n)
		for i := range out {
			out[i] = uuid.New()
		}
		return out
	}
	half := authz.CanarySettings{Percent: 50}
	w1, w2 := authz.CanaryWaves(ids(38), half)
	assert.Len(t, w1, 19, "the ceiling of 50 % of 38 is 19: at the limit")
	assert.Len(t, w2, 19)
	w1, w2 = authz.CanaryWaves(ids(39), half)
	assert.Len(t, w1, authz.MaxCanaryWave1, "20 would be over the limit")
	assert.Len(t, w2, 20)
	w1, w2 = authz.CanaryWaves(ids(200), authz.CanarySettings{Percent: 10})
	assert.Len(t, w1, authz.MaxCanaryWave1)
	assert.Len(t, w2, 181)
	assert.Equal(t, 19, authz.MaxCanaryWave1)
}
