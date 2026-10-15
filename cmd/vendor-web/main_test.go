package main

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
)

const goodDB = "postgres://web:s3cretpw@127.0.0.1:5432/vendor?sslmode=disable"

func runWith(env map[string]string, args ...string) (int, string) {
	var out, errOut bytes.Buffer
	old := serve
	serve = func(config) int { panic("a configuration error must not start the server") }
	defer func() { serve = old }()
	code := run(args, func(k string) string { return env[k] }, &out, &errOut)
	return code, errOut.String() + out.String()
}

func TestConfigurationErrorsExitTwoWithoutLeakingThePassword(t *testing.T) {
	good := map[string]string{"VENDOR_WEB_DATABASE_URL": goodDB, "VENDOR_WEB_ORIGIN": "https://licenses.example.com"}
	with := func(k, v string) map[string]string {
		m := map[string]string{}
		for a, b := range good {
			m[a] = b
		}
		if v == "" {
			delete(m, k)
		} else {
			m[k] = v
		}
		return m
	}
	for name, c := range map[string]struct {
		env  map[string]string
		args []string
		want string
	}{
		"no database url":  {with("VENDOR_WEB_DATABASE_URL", ""), nil, "VENDOR_WEB_DATABASE_URL"},
		"no origin":        {with("VENDOR_WEB_ORIGIN", ""), nil, "VENDOR_WEB_ORIGIN"},
		"http origin":      {with("VENDOR_WEB_ORIGIN", "http://licenses.example.com"), nil, "localhost"},
		"rpid mismatch":    {with("VENDOR_WEB_RPID", "other.example.com"), nil, "RP ID"},
		"only cert":        {good, []string{"--tls-cert", "c.pem"}, "--tls-key"},
		"only key":         {good, []string{"--tls-key", "k.pem"}, "--tls-cert"},
		"insecure db":      {with("VENDOR_WEB_DATABASE_URL", "postgres://web:s3cretpw@db.example.com/vendor?sslmode=disable"), nil, "verify-full"},
		"unknown flag":     {good, []string{"--nope"}, "nope"},
		"stray argument":   {good, []string{"extra"}, "extra"},
		"unparsable dburl": {with("VENDOR_WEB_DATABASE_URL", "postgres://web:s3cretpw@db.example.com:xx/vendor"), nil, "VENDOR_WEB_DATABASE_URL"},
	} {
		code, msg := runWith(c.env, c.args...)
		assert.Equal(t, 2, code, name)
		assert.Contains(t, msg, c.want, name)
		assert.NotContains(t, msg, "s3cretpw", name)
	}
}

func TestTheRPIDDefaultsToTheOriginHost(t *testing.T) {
	var got config
	old := serve
	serve = func(c config) int { got = c; return 0 }
	defer func() { serve = old }()
	var out, errOut bytes.Buffer
	env := map[string]string{"VENDOR_WEB_DATABASE_URL": goodDB, "VENDOR_WEB_ORIGIN": "https://licenses.example.com:8443"}
	code := run([]string{"--listen", "127.0.0.1:0"}, func(k string) string { return env[k] }, &out, &errOut)
	assert.Equal(t, 0, code, errOut.String())
	assert.Equal(t, "licenses.example.com", got.rpid)
	assert.Equal(t, "127.0.0.1:0", got.listen)
}
