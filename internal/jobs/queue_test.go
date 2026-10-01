package jobs

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/inventory"
	"alice/internal/license"
	"alice/internal/providers"
	"alice/internal/secrets"
)

func TestPayloadMACLabelIsTheSecretsLabel(t *testing.T) {
	assert.Equal(t, secrets.LabelJob, payloadMACLabel, "the job MAC key is the J-1 sub-key")
}

func TestPayloadMACCoversEveryField(t *testing.T) {
	key := bytes.Repeat([]byte{3}, 32)
	id, target, by := uuid.New(), uuid.New(), uuid.New()
	payload := canonicalPayload(map[string]string{"location_id": "a"})
	mac := func(key []byte, id uuid.UUID, typ, kind string, target uuid.UUID, payload []byte, by uuid.UUID, role string, maxAttempts int) []byte {
		return payloadMAC(key, id, typ, kind, target, payload, by, role, maxAttempts)
	}
	base := mac(key, id, "sshkey.remove", "user", target, payload, by, "operator", 3)
	require.Len(t, base, 32)
	assert.Equal(t, base, mac(key, id, "sshkey.remove", "user", target, payload, by, "operator", 3), "deterministic")
	for name, other := range map[string][]byte{
		"key":          mac(bytes.Repeat([]byte{4}, 32), id, "sshkey.remove", "user", target, payload, by, "operator", 3),
		"id":           mac(key, uuid.New(), "sshkey.remove", "user", target, payload, by, "operator", 3),
		"type":         mac(key, id, "target.discover", "user", target, payload, by, "operator", 3),
		"kind":         mac(key, id, "sshkey.remove", "system", target, payload, by, "operator", 3),
		"target":       mac(key, id, "sshkey.remove", "user", uuid.New(), payload, by, "operator", 3),
		"no target":    mac(key, id, "sshkey.remove", "user", uuid.Nil, payload, by, "operator", 3),
		"payload":      mac(key, id, "sshkey.remove", "user", target, canonicalPayload(map[string]string{"location_id": "b"}), by, "operator", 3),
		"created by":   mac(key, id, "sshkey.remove", "user", target, payload, uuid.Nil, "operator", 3),
		"role":         mac(key, id, "sshkey.remove", "user", target, payload, by, "admin", 3),
		"max attempts": mac(key, id, "sshkey.remove", "user", target, payload, by, "operator", 30),
		"field shift":  mac(key, id, "sshkey.remove", "useroperator", target, payload, by, "", 3),
	} {
		assert.NotEqual(t, base, other, name)
	}
}

func TestCanonicalPayloadIsOrderIndependentAndNeverNull(t *testing.T) {
	assert.Equal(t, `{}`, string(canonicalPayload(nil)))
	a := canonicalPayload(map[string]string{"b": "2", "a": "1"})
	assert.Equal(t, `{"a":"1","b":"2"}`, string(a))
}

func TestBackoff(t *testing.T) {
	for _, tc := range []struct {
		attempt int
		jitter  float64
		want    time.Duration
	}{
		{0, 0, 30 * time.Second},
		{1, 0, 30 * time.Second},
		{2, 0, time.Minute},
		{3, 0, 2 * time.Minute},
		{6, 0, 16 * time.Minute},
		{7, 0, 30 * time.Minute},
		{40, 0, 30 * time.Minute},
		{1, 0.2, 36 * time.Second},
		{1, -0.2, 24 * time.Second},
		{1, 5, 36 * time.Second}, // jitter is clamped to ±20 %
	} {
		assert.Equal(t, tc.want, Backoff(tc.attempt, tc.jitter), "attempt %d jitter %v", tc.attempt, tc.jitter)
	}
}

func TestFromProvider(t *testing.T) {
	var f *Failure
	err := FromProvider(providers.NewError("ssh.unreachable", true, errors.New("dial tcp: refused"), map[string]string{"host": "web-01"}))
	require.ErrorAs(t, err, &f)
	assert.Equal(t, Retryable, f.Class)
	assert.Equal(t, "ssh.unreachable", f.Reason)
	assert.Equal(t, map[string]string{"host": "web-01"}, f.Params)

	err = FromProvider(providers.NewError("ssh.auth_failed", false, nil, nil))
	require.ErrorAs(t, err, &f)
	assert.Equal(t, Permanent, f.Class)
	assert.Equal(t, "ssh.auth_failed", f.Reason)

	same := Fail("sshkey.own_key_protected", nil, nil)
	assert.Same(t, same, FromProvider(same), "a classified failure passes through")

	err = FromProvider(errors.New("boom"))
	require.ErrorAs(t, err, &f)
	assert.Equal(t, Retryable, f.Class)
	assert.Equal(t, "internal.unexpected", f.Reason)
	assert.NoError(t, FromProvider(nil))
}

func TestFailureMessageHidesTheCause(t *testing.T) {
	err := Retry("ssh.timeout", nil, errors.New("CANARY-secret-detail"))
	assert.Equal(t, "jobs: ssh.timeout", err.Error())
	assert.NotContains(t, err.Error(), "CANARY")
	assert.ErrorContains(t, errors.Unwrap(err), "CANARY", "the cause stays reachable for errors.Is/As")
}

func TestMaxAttemptsFor(t *testing.T) {
	assert.Equal(t, 1, MaxAttemptsFor(TargetTestConnection))
	assert.Equal(t, 5, MaxAttemptsFor(TargetDiscover))
	assert.Equal(t, 3, MaxAttemptsFor(SSHKeyRemove))
}

func TestPhase3JobTypesDeclareTheirLicenseClass(t *testing.T) {
	assert.Equal(t, Type{Name: inventory.JobTestConnection, Class: license.ClassReadOnly}, TargetTestConnection)
	assert.Equal(t, Type{Name: inventory.JobDiscover, Class: license.ClassReadOnly}, TargetDiscover)
	assert.Equal(t, Type{Name: inventory.JobSSHKeyRemove, Class: license.ClassChange}, SSHKeyRemove)
}

func TestHandleRefusesUnregisteredAndDuplicateHandlers(t *testing.T) {
	r := NewRunner(RunnerConfig{})
	h := func(_ context.Context, _ Job, _ StepRecorder) (map[string]any, error) { return nil, nil }
	assert.Panics(t, func() { r.Handle(Type{Name: "never.registered", Class: license.ClassAlways}, h) })
	assert.Panics(t, func() { r.Handle(Type{Name: TargetDiscover.Name, Class: license.ClassAlways}, h) }, "class must match the registry")
	r.Handle(TargetDiscover, h)
	assert.Panics(t, func() { r.Handle(TargetDiscover, h) })
}

func TestNewRunnerDefaults(t *testing.T) {
	r := NewRunner(RunnerConfig{})
	assert.Equal(t, 8, r.cfg.Workers)
	assert.Equal(t, 45*time.Second, r.cfg.Lease)
	assert.Equal(t, 15*time.Second, r.cfg.Heartbeat)
	assert.Equal(t, time.Second, r.cfg.Poll)
	assert.Equal(t, time.Minute, r.cfg.ReapEvery)
	assert.Equal(t, time.Minute, r.cfg.ShutdownGrace)
	assert.NotEmpty(t, r.cfg.WorkerID)
	for range 100 {
		j := r.cfg.Jitter()
		assert.True(t, j >= -0.2 && j <= 0.2, "jitter %v", j)
	}
}
