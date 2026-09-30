package main

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"alice/internal/platform/db"
)

func env(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

func TestVersionCommand(t *testing.T) {
	var out, errOut bytes.Buffer
	code := run([]string{"version"}, env(nil), &out, &errOut)
	assert.Equal(t, 0, code)
	assert.Contains(t, out.String(), "alice dev")
}

func TestUnknownCommand(t *testing.T) {
	var out, errOut bytes.Buffer
	code := run([]string{"frobnicate"}, env(nil), &out, &errOut)
	assert.Equal(t, 2, code)
	assert.Contains(t, errOut.String(), "unknown command")
	assert.Contains(t, errOut.String(), "serve")
}

func TestMigrateNeedsDatabaseURL(t *testing.T) {
	var out, errOut bytes.Buffer
	code := run([]string{"migrate"}, env(nil), &out, &errOut)
	assert.Equal(t, 1, code)
	assert.Contains(t, errOut.String(), "ALICE_DATABASE_URL")
}

func TestHealthcheck(t *testing.T) {
	ok := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ok.Close()
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer bad.Close()

	var out, errOut bytes.Buffer
	assert.Equal(t, 0, run([]string{"healthcheck"}, env(map[string]string{"ALICE_HEALTH_ADDR": strings.TrimPrefix(ok.URL, "http://")}), &out, &errOut))
	assert.Equal(t, 1, run([]string{"healthcheck"}, env(map[string]string{"ALICE_HEALTH_ADDR": strings.TrimPrefix(bad.URL, "http://")}), &out, &errOut))
	assert.Equal(t, 1, run([]string{"healthcheck"}, env(map[string]string{"ALICE_HEALTH_ADDR": "127.0.0.1:1"}), &out, &errOut))
}

func TestDBStartupErrorMentionsWaitOnlyForUnreachable(t *testing.T) {
	err := dbStartupError(fmt.Errorf("x: %w", db.ErrUnreachable), time.Minute)
	assert.Contains(t, err.Error(), "database not ready after 1m0s")
	assert.ErrorIs(t, err, db.ErrUnreachable)

	auth := fmt.Errorf("the database server at postgres:5432 rejected the user name or password; check the database URL: %w", db.ErrAuthFailed)
	err = dbStartupError(auth, time.Minute)
	assert.Equal(t, auth, err, "a rejected password is final and reported unchanged")
}
