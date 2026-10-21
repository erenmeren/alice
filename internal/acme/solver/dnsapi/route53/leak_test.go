package route53

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/secrets"
	"alice/internal/testutil/fakeroute53"
)

const canary = "CANARY-r53-answer-text-7f3a"

// The secret access key, the role's secret and session token and every signature stay out of every error text (all
// verbs), every print of the configuration, the provider and the solver, and the fake's request log; AWS's answer
// text (a canary in every error body) never reaches an error.
func TestNoSecretOrAnswerTextLeaks(t *testing.T) {
	f := startFake(t, fakeroute53.Options{RoleARN: testRole, ExternalID: testExternalID})
	cfg := fakeConfig(f)
	withRole(&cfg)
	p, err := New(cfg)
	require.NoError(t, err)
	s := newSolver(t, p)
	require.NoError(t, s.Present(ctx30(t), chal("example.test", "value-1")))

	var errs []error
	errBody := func(code string) string {
		return `<ErrorResponse><Error><Type>Sender</Type><Code>` + code + `</Code><Message>` + canary + `</Message></Error></ErrorResponse>`
	}
	faults := []struct {
		op string
		f  fakeroute53.Fault
	}{
		{fakeroute53.OpList, fakeroute53.Fault{Status: 403, Body: errBody("AccessDenied")}},
		{fakeroute53.OpList, fakeroute53.Fault{Status: 400, Body: errBody("Throttling")}},
		{fakeroute53.OpChange, fakeroute53.Fault{Status: 400, Body: `<InvalidChangeBatch><Messages><Message>` + canary + `</Message></Messages></InvalidChangeBatch>`}},
		{fakeroute53.OpChange, fakeroute53.Fault{Status: 500, Body: canary}},
		{fakeroute53.OpChange, fakeroute53.Fault{Body: canary}},
		{fakeroute53.OpList, fakeroute53.Fault{Status: 404, Body: errBody("NoSuchHostedZone")}},
	}
	for i, fl := range faults {
		f.FailNext(fl.op, fl.f)
		errs = append(errs, s.Present(ctx30(t), chal("example.test", fmt.Sprintf("value-x%d", i))))
	}
	f.FailNext(fakeroute53.OpGetChange, fakeroute53.Fault{Status: 500, Body: canary})
	errs = append(errs, s.Present(ctx30(t), chal("example.test", "value-gc")))

	// STS failures, on a fresh provider.
	for _, fl := range []fakeroute53.Fault{{Status: 403, Body: errBody("AccessDenied")}, {Status: 200, Body: canary}, {Status: 503, Body: canary}} {
		q, err := New(cfg)
		require.NoError(t, err)
		f.FailNext(fakeroute53.OpAssumeRole, fl)
		_, err = q.FindZone(ctx30(t), "_acme-challenge.example.test")
		errs = append(errs, err)
	}
	// The wrong secret: the fake refuses the signature.
	bad := cfg
	bad.SecretAccessKey = secrets.NewPlaintext([]byte("wrong-secret-0123456789"))
	q, err := New(bad)
	require.NoError(t, err)
	_, err = q.FindZone(ctx30(t), "_acme-challenge.example.test")
	errs = append(errs, err)

	var text strings.Builder
	for _, e := range errs {
		require.Error(t, e)
		fmt.Fprintf(&text, "%v|%+v|%#v|%s|%q\n", e, e, e, e, e)
	}
	for _, v := range []any{cfg, &cfg, p, s, f.Requests()} {
		fmt.Fprintf(&text, "%v|%+v|%#v|%s\n", v, v, v, v)
	}
	out := text.String()

	needles := []string{f.SecretAccessKey(), canary}
	for _, c := range f.IssuedCredentials() {
		needles = append(needles, c.SecretAccessKey, c.SessionToken)
	}
	require.NotEmpty(t, f.LastSignature())
	needles = append(needles, f.LastSignature())
	require.GreaterOrEqual(t, len(needles), 5)
	for _, n := range needles {
		require.NotEmpty(t, n)
		assert.NotContains(t, out, n)
	}
	assert.Contains(t, out, "route53.Provider{AccessKeyID: "+f.AccessKeyID()+", Role: set}")
	assert.Contains(t, out, "route53.Config{AccessKeyID: "+f.AccessKeyID()+", Role: set}")
	assert.Contains(t, out, "dnsapi.Solver{kind: route53}")
}

func TestPrintsOfAnInvalidKeyID(t *testing.T) {
	c := Config{AccessKeyID: "not a key\nid", RoleARN: ""}
	assert.Equal(t, "route53.Config{AccessKeyID: invalid, Role: none}", fmt.Sprintf("%#v", c))
	assert.Equal(t, "route53.Config{AccessKeyID: invalid, Role: none}", c.GoString())
}
