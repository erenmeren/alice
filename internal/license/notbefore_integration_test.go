//go:build integration

package license_test

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/license"
)

// insertDiscoveredCertificate stores a certificate found on a server whose notBefore is notBefore, as
// discovery would (only the columns the table requires).
func (e *env) insertDiscoveredCertificate(notBefore time.Time) {
	e.t.Helper()
	random := func() string {
		b := make([]byte, 32)
		_, _ = rand.Read(b)
		s := sha256.Sum256(b)
		return hex.EncodeToString(s[:])
	}
	now := e.clk.Now()
	_, err := e.db.Owner.Exec(e.ctx, `INSERT INTO certificates (id, fingerprint_sha256, subject_cn, not_before, not_after,
		key_algorithm, public_key_sha256, pem_chain, source, first_seen_at, last_seen_at, created_at)
		VALUES ($1, $2, 'future.example', $3, $4, 'ecdsa', $5, 'pem', 'discovered', $6, $6, $6)`,
		uuid.New(), random(), notBefore, notBefore.Add(90*day), random(), now)
	require.NoError(e.t, err)
}

// L-56, L-57 (R28): a certificate's notBefore is no evidence of time. A discovered certificate that starts
// 10 days after the license ends while the clock reads 30 days before that end (L-56), or 3 years ahead
// (L-57, a hostile target), changes neither the license state nor the effective time, before or after a
// restart, and raises no clock event. R28's optional "system clock appears to be behind" warning from
// certificate evidence is not built (ruling G-2 of docs/superpowers/rulings/phase-8.md): the clock_behind
// banner comes only from the time record (TestRollbackIsWarnedOncePerDay).
func TestL56L57CertificateNotBeforeNeverAffectsTheLicense(t *testing.T) {
	e := newEnv(t)
	start := e.clk.Now()
	ends := start.Add(30 * day) // E; the clock reads E-30d
	_, err := e.upload(e.payload("LIC-A", start, ends, 10))
	require.NoError(t, err)
	at := start.Add(time.Hour)
	e.tickAt(at)
	before := e.svc.Snapshot()
	stateBefore := e.state()
	require.False(t, before.Eval.Locked())

	e.insertDiscoveredCertificate(ends.Add(10 * day))      // L-56
	e.insertDiscoveredCertificate(at.Add(3 * 365 * day))   // L-57
	e.insertDiscoveredCertificate(at.Add(100 * 365 * day)) // malformed: a century ahead
	require.Equal(t, 3, e.countWhere("certificates", "source = 'discovered' AND not_before > first_seen_at"))
	for _, restart := range []bool{false, true} {
		if restart {
			e.restart()
		}
		e.tickAt(at)
		after := e.svc.Snapshot()
		assert.Equal(t, before.Eval.Phase, after.Eval.Phase, "restart=%v", restart)
		assert.NotEqual(t, license.PhaseLocked, after.Eval.Phase)
		assert.True(t, before.Eval.EndsAt.Equal(after.Eval.EndsAt))
		assert.True(t, before.Eval.LocksAt.Equal(after.Eval.LocksAt))
		assert.Equal(t, before.Eval.DaysLeft, after.Eval.DaysLeft)
		assert.Equal(t, 30, after.Eval.DaysLeft, "computed from the clock")
		assert.True(t, before.Reading.Effective.Equal(after.Reading.Effective), "the effective time is the clock's")
		assert.True(t, after.Reading.Effective.Equal(at))
		assert.False(t, after.Reading.Behind)
		assert.Nil(t, after.Reading.Jump)
		assert.Equal(t, kinds(before.Banners(true)), kinds(after.Banners(true)))
		assert.Equal(t, stateBefore, e.state())
	}
	assert.Zero(t, e.auditCount("clock.rollback_detected"))
	assert.Zero(t, e.auditCount("clock.forward_jump"))
	assert.Zero(t, e.countWhere("license_history", "event = 'clock_anomaly' OR notice LIKE 'clock_behind:%'"))
}
