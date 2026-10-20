//go:build integration

package main

import (
	"context"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/license"
	"alice/internal/platform/clock"
	"alice/internal/vconsole/store"
)

// An emergency extension asked for on the web is shown and signed on the YubiKey path like any
// request, named as what it is.
func TestIssueOpenPGPEmergencyExtension(t *testing.T) {
	cj := newCardJourney(t, nil)
	ctx := context.Background()
	now := time.Now().UTC()
	var cust int64
	require.NoError(t, cj.d.Owner.QueryRow(ctx, `SELECT id FROM customers WHERE name = 'Acme Ltd'`).Scan(&cust))
	// A license of the card journey's installation that lapsed three days ago.
	var reqID int64
	require.NoError(t, cj.d.Owner.QueryRow(ctx, `INSERT INTO license_requests (customer_id, installation, targets, features, status)
		VALUES ($1, $2, 8, '{gamma}', 'signed') RETURNING id`, cust, cj.installation).Scan(&reqID))
	_, err := cj.d.Owner.Exec(ctx, `INSERT INTO licenses (license_id, request_id, customer_id, installation, key_id, issued_at,
		valid_from, valid_until, targets, file, file_sha256) VALUES ('LIC-2025-000099', $1, $2, $3, 'vk-2026-01', $4, $4, $5, 8, 'x', 'sha')`,
		reqID, cust, cj.installation, now.Add(-368*24*time.Hour), now.Add(-3*24*time.Hour))
	require.NoError(t, err)
	id, err := store.AddEmergencyRequest(ctx, cj.d.Owner, store.NewEmergency{LicenseID: "LIC-2025-000099", Days: 10,
		Reason: "PO delayed"}, now)
	require.NoError(t, err)
	emID := strconv.FormatInt(id, 10)

	out, e, code := cj.do(clock.Real{}, "request", "show", emID)
	require.Equal(t, 0, code, e)
	for _, want := range []string{"kind          EMERGENCY EXTENSION", "days          10", "targets       8", "features      gamma",
		"reason        PO delayed", "carries over  LIC-2025-000099", "from          (the day it is signed)"} {
		assert.Contains(t, out, want)
	}
	hash := regexp.MustCompile(`hash ([0-9a-f]{64})`).FindStringSubmatch(out)[1]
	list, _, _ := cj.do(clock.Real{}, "request", "list", "--status", "open")
	assert.Contains(t, list, emID+"  open  Acme Ltd  8  "+cj.installation+"  EMERGENCY EXTENSION 10 days")

	args := append([]string{}, cj.issueBaseArgs...)
	for i, a := range args {
		switch a {
		case "--request":
			args[i+1] = emID
		case "--hash":
			args[i+1] = hash
		}
	}
	s := runSession(cj.getenv, strings.NewReader("y\n"), goodPIN, args...)
	require.Equal(t, 0, s.code, s.errOut)
	assert.Contains(t, s.errOut, "The YubiKey will sign this EMERGENCY EXTENSION.")
	assert.Contains(t, s.errOut, "days             10")
	assert.Contains(t, s.errOut, "Touch the YubiKey now...", "the normal card path: PIN and touch")

	raw, err := os.ReadFile(cj.licenseOut)
	require.NoError(t, err)
	f, err := license.ParseFile(raw)
	require.NoError(t, err)
	assert.Equal(t, 10*24*time.Hour, f.Payload.ValidUntil.Sub(f.Payload.ValidFrom))
	assert.Equal(t, 8, f.Payload.MaxTargets)
	assert.Equal(t, cj.installation, f.Payload.InstallationID)
}
