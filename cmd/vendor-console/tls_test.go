package main

import (
	"bytes"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"alice/internal/platform/clock"
)

func TestCheckTLS(t *testing.T) {
	for url, ok := range map[string]bool{
		"postgres://u:p@db.example.com/vendor?sslmode=verify-full": true,
		"postgres://u:p@db.example.com/vendor":                     false, // default is prefer: no verification, plaintext fallback
		"postgres://u:p@db.example.com/vendor?sslmode=prefer":      false,
		"postgres://u:p@db.example.com/vendor?sslmode=require":     false, // encrypted but not verified
		"postgres://u:p@db.example.com/vendor?sslmode=verify-ca":   false, // no host name check
		"postgres://u:p@db.example.com/vendor?sslmode=disable":     false,
		"postgres://u:p@localhost/vendor?sslmode=disable":          true, // loopback needs no TLS
		"postgres://u:p@127.0.0.1:5432/vendor":                     true,
		"postgres://u:p@[::1]:5432/vendor?sslmode=disable":         true,
	} {
		err := checkTLS(url)
		if ok {
			assert.NoError(t, err, url)
		} else {
			assert.Error(t, err, url)
			if err != nil {
				assert.Contains(t, err.Error(), "verify-full", url)
				assert.NotContains(t, err.Error(), "u:p", "the URL is never echoed")
			}
		}
	}
	assert.Error(t, checkTLS("not a url ://"))
}

func TestAnUnreachableDatabaseEndsWithAMessage(t *testing.T) {
	old := connectTimeout
	connectTimeout = time.Second
	defer func() { connectTimeout = old }()
	var out, errOut bytes.Buffer
	getenv := func(string) string { return "postgres://u:p@127.0.0.1:1/vendor?sslmode=disable" }
	start := time.Now()
	code := run([]string{"request", "list"}, getenv, &out, &errOut, nil, clock.Real{})
	assert.Equal(t, 1, code)
	assert.Contains(t, errOut.String(), "within")
	assert.NotContains(t, errOut.String(), "u:p")
	assert.Less(t, time.Since(start), 10*time.Second)
}
