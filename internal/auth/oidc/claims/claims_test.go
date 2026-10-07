package claims

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var now = time.Date(2026, 10, 7, 9, 0, 0, 0, time.UTC)

const (
	iss    = "https://login.example.com/tenant/v2.0"
	client = "alice"
	nonce  = "n-0123456789abcdefghijklmnopqrstuvwxyzABCDE"
)

func payload(t *testing.T, edit func(m map[string]any)) []byte {
	t.Helper()
	m := map[string]any{"iss": iss, "aud": client, "sub": "user-1", "nonce": nonce,
		"exp": now.Add(5 * time.Minute).Unix(), "iat": now.Unix(), "email": "ada@example.com",
		"name": "Ada Yılmaz", "preferred_username": "Ada.Yilmaz@Example.com"}
	if edit != nil {
		edit(m)
	}
	b, err := json.Marshal(m)
	require.NoError(t, err)
	return b
}

func expect() Expect { return Expect{Issuer: iss, ClientID: client, Nonce: nonce, Now: now} }

func reasonOf(err error) Reason {
	var e *Error
	if errors.As(err, &e) {
		return e.Reason
	}
	return ""
}

func TestParseReadsStandardClaims(t *testing.T) {
	c, err := Parse(payload(t, func(m map[string]any) {
		m["aud"] = []string{client, "other"}
		m["azp"] = client
		m["nbf"] = now.Add(-time.Minute).Unix()
		m["auth_time"] = now.Add(-2 * time.Minute).Unix()
		m["upn"] = "ada@corp.example.com"
	}))
	require.NoError(t, err)
	assert.Equal(t, iss, c.Issuer)
	assert.Equal(t, []string{client, "other"}, c.Audience)
	assert.Equal(t, client, c.AuthorizedParty)
	assert.Equal(t, "user-1", c.Subject)
	assert.Equal(t, now.Add(5*time.Minute), c.Expiry)
	assert.Equal(t, now, c.IssuedAt)
	assert.Equal(t, now.Add(-time.Minute), c.NotBefore)
	assert.Equal(t, now.Add(-2*time.Minute), c.AuthTime)
	assert.Equal(t, "ada@example.com", c.Email)
	assert.Equal(t, "Ada Yılmaz", c.Name)
	assert.Equal(t, "ada@corp.example.com", c.UPN)
	c, err = Parse([]byte(`{"iss":"x","aud":"alice","sub":"s","exp":1790000000.9,"iat":1790000000}`))
	require.NoError(t, err)
	assert.Equal(t, []string{"alice"}, c.Audience)
	assert.Equal(t, time.Unix(1790000000, 0).UTC(), c.Expiry, "fractions are cut")
	assert.True(t, c.NotBefore.IsZero())
}

func TestParseRefusesMalformedPayloads(t *testing.T) {
	for _, raw := range []string{``, `null`, `[]`, `"x"`, `{"iss":1}`, `{"aud":{"a":1}}`, `{"aud":[1]}`, `{"exp":"soon"}`,
		`{"exp":1e300}`, `{"sub":["a"]}`, `{"iat":-1e20}`, `{"iss":"a"`} {
		_, err := Parse([]byte(raw))
		assert.Equal(t, ReasonMalformed, reasonOf(err), raw)
	}
}

func TestValidateAcceptsAGoodToken(t *testing.T) {
	c, err := Parse(payload(t, nil))
	require.NoError(t, err)
	assert.NoError(t, Validate(c, expect()))
}

// Review Focus 1, O-02 and O-03: every claim the provider could get wrong is refused with its own reason.
func TestValidateRefusesEachClaim(t *testing.T) {
	cases := []struct {
		name string
		edit func(m map[string]any)
		want Reason
	}{
		{"wrong issuer", func(m map[string]any) { m["iss"] = iss + "/" }, ReasonIssuer},
		{"issuer differs in case", func(m map[string]any) { m["iss"] = "https://LOGIN.example.com/tenant/v2.0" }, ReasonIssuer},
		{"wrong audience", func(m map[string]any) { m["aud"] = "someone-else" }, ReasonAudience},
		{"several audiences without azp", func(m map[string]any) { m["aud"] = []string{client, "x"} }, ReasonAzp},
		{"azp of another client", func(m map[string]any) { m["azp"] = "x" }, ReasonAzp},
		{"no subject", func(m map[string]any) { delete(m, "sub") }, ReasonSubject},
		{"subject too long", func(m map[string]any) { m["sub"] = string(make([]byte, 256)) }, ReasonSubject},
		{"expired beyond the leeway", func(m map[string]any) { m["exp"] = now.Add(-61 * time.Second).Unix() }, ReasonExpired},
		{"no expiry", func(m map[string]any) { delete(m, "exp") }, ReasonExpired},
		{"issued in the future beyond the leeway", func(m map[string]any) { m["iat"] = now.Add(61 * time.Second).Unix() }, ReasonIssuedAt},
		{"no issued-at", func(m map[string]any) { delete(m, "iat") }, ReasonIssuedAt},
		{"not yet valid beyond the leeway", func(m map[string]any) { m["nbf"] = now.Add(61 * time.Second).Unix() }, ReasonNotBefore},
		{"wrong nonce", func(m map[string]any) { m["nonce"] = nonce + "x" }, ReasonNonce},
		{"no nonce", func(m map[string]any) { delete(m, "nonce") }, ReasonNonce},
	}
	for _, c := range cases {
		cl, err := Parse(payload(t, c.edit))
		require.NoError(t, err, c.name)
		assert.Equal(t, c.want, reasonOf(Validate(cl, expect())), c.name)
	}
	cl, err := Parse(payload(t, nil))
	require.NoError(t, err)
	e := expect()
	e.Nonce = ""
	assert.Equal(t, ReasonNonce, reasonOf(Validate(cl, e)), "an empty expected nonce never matches")
}

func TestValidateLeewayEdges(t *testing.T) {
	ok := []func(m map[string]any){
		func(m map[string]any) { m["exp"] = now.Add(-59 * time.Second).Unix() },
		func(m map[string]any) { m["iat"] = now.Add(60 * time.Second).Unix() },
		func(m map[string]any) { m["nbf"] = now.Add(60 * time.Second).Unix() },
		func(m map[string]any) { m["aud"] = []string{client, "x"}; m["azp"] = client },
	}
	for i, edit := range ok {
		c, err := Parse(payload(t, edit))
		require.NoError(t, err)
		assert.NoError(t, Validate(c, expect()), "case %d", i)
	}
}

func TestValidateStepUpNeedsAFreshAuthTime(t *testing.T) {
	e := expect()
	e.MaxAuthAge = 5 * time.Minute
	for _, c := range []struct {
		authTime any
		ok       bool
	}{
		{now.Add(-4 * time.Minute).Unix(), true},
		{now.Add(-6 * time.Minute).Unix(), true}, // 5 minutes + 60 s leeway
		{now.Add(-6*time.Minute - 2*time.Second).Unix(), false},
		{now.Add(2 * time.Minute).Unix(), false}, // in the future
		{nil, false},
	} {
		cl, err := Parse(payload(t, func(m map[string]any) {
			if c.authTime == nil {
				delete(m, "auth_time")
			} else {
				m["auth_time"] = c.authTime
			}
		}))
		require.NoError(t, err)
		err = Validate(cl, e)
		if c.ok {
			assert.NoError(t, err, "%v", c.authTime)
		} else {
			assert.Equal(t, ReasonAuthTime, reasonOf(err), "%v", c.authTime)
		}
	}
}

func TestErrorTextNamesOnlyTheReason(t *testing.T) {
	err := Validate(Claims{Issuer: "x"}, expect())
	assert.Equal(t, "claims: the ID token was refused (issuer)", err.Error())
}
