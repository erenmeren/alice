package main

import (
	"bytes"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"alice/internal/platform/clock"
)

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
