package sshkeyjobs

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/inventory"
	"alice/internal/jobs"
	"alice/internal/platform/clock"
	"alice/internal/providers"
	"alice/internal/sshkeys"
)

// stubKeys and stubTargets satisfy the interfaces; Register only checks that they are there.
type stubKeys struct{ Keys }

type stubTargets struct{ Targets }

func fullDeps() Deps {
	return Deps{Keys: stubKeys{}, Targets: stubTargets{}, Registry: providers.NewRegistry(), Clock: clock.Real{}}
}

func TestRegisterPanicsWithoutDependencies(t *testing.T) {
	for name, drop := range map[string]func(*Deps){
		"Keys":     func(d *Deps) { d.Keys = nil },
		"Targets":  func(d *Deps) { d.Targets = nil },
		"Registry": func(d *Deps) { d.Registry = nil },
		"Clock":    func(d *Deps) { d.Clock = nil },
	} {
		t.Run(name, func(t *testing.T) {
			d := fullDeps()
			drop(&d)
			assert.Panics(t, func() { Register(jobs.NewRunner(jobs.RunnerConfig{}), d) })
		})
	}
	r := jobs.NewRunner(jobs.RunnerConfig{})
	assert.NotPanics(t, func() { Register(r, fullDeps()) }, "a log is optional")
	assert.True(t, r.Handles(jobs.SSHKeyAdd))
}

func TestClassifyAddFailure(t *testing.T) {
	timeout := providers.NewError("ssh.timeout", true, nil, nil)
	changed := providers.NewError("ssh.file_changed", true, nil, map[string]string{"attempts": "3"})
	refused := providers.NewError("ssh.helper_refused", false, nil, nil)
	for _, c := range []struct {
		name     string
		wrote    bool
		res      providers.AuthKeyResult
		err      error
		definite bool
	}{
		{"no write started", false, providers.AuthKeyResult{}, timeout, true},
		{"refused before writing", false, providers.AuthKeyResult{}, refused, true},
		{"write started, the file changed under it (CAS)", true, providers.AuthKeyResult{}, changed, true},
		{"write started, then a timeout", true, providers.AuthKeyResult{}, timeout, false},
		{"a change reported with the error", false, providers.AuthKeyResult{Changed: true}, timeout, false},
		{"write started, then an unclassified error", true, providers.AuthKeyResult{}, errors.New("boom"), false},
	} {
		assert.Equal(t, c.definite, definiteNoChange(c.wrote, c.res, c.err), c.name)
	}
}

func TestReasonOfIsAlwaysClosed(t *testing.T) {
	assert.Equal(t, "ssh.unreachable", reasonOf(providers.NewError("ssh.unreachable", true, nil, nil)))
	assert.Equal(t, "sshkey.login_failed", reasonOf(jobs.Fail("sshkey.login_failed", nil, nil)))
	assert.Equal(t, "internal.unexpected", reasonOf(errors.New("CANARY free text")))
	assert.Equal(t, "internal.unexpected", reasonOf(nil))
}

func TestDeployRefusalReasons(t *testing.T) {
	for err, want := range map[error]string{
		sshkeys.ErrNotManaged:             "sshkey.not_managed",
		sshkeys.ErrRetired:                "sshkey.retired",
		sshkeys.ErrDestroyed:              "sshkey.private_key_destroyed",
		sshkeys.ErrConnectionAccount:      "sshkey.connection_account",
		sshkeys.ErrConnectionFilesUnknown: "sshkey.connection_files_unknown",
		sshkeys.ErrNotAKeyFile:            "sshkey.not_a_key_file",
		inventory.ErrNotFound:             "system.not_found",
		inventory.ErrNotAServer:           "system.not_found",
		inventory.ErrHostKeyUnconfirmed:   "target.host_key_unconfirmed",
		inventory.ErrHostKeyChanged:       "target.host_key_changed",
		inventory.ErrTargetDisabled:       "target.disabled",
		inventory.ErrKeysManagedElsewhere: "ssh.keys_managed_elsewhere",
		inventory.ErrSSHDUnreadable:       "sshkey.sshd_unreadable",
		sshkeys.ErrInRotation:             "sshkey.in_rotation",
	} {
		var f *jobs.Failure
		require.ErrorAs(t, deployRefusal(err), &f)
		assert.Equal(t, want, f.Reason)
		assert.Equal(t, jobs.Permanent, f.Class, want)
	}
	var f *jobs.Failure
	require.ErrorAs(t, deployRefusal(providers.NewError("ssh.helper_refused", false, nil, map[string]string{"field": "options"})), &f)
	assert.Equal(t, "ssh.helper_refused", f.Reason)
	assert.Equal(t, jobs.Permanent, f.Class)
	require.ErrorAs(t, deployRefusal(errors.New("database down")), &f)
	assert.Equal(t, jobs.Retryable, f.Class, "a database failure before anything was sent is retried")
	require.ErrorAs(t, deployRefusal(context.Canceled), &f)
	assert.Equal(t, jobs.Retryable, f.Class)
}

func TestPayloadDeployKeepsOnlyParsedFields(t *testing.T) {
	key, target := uuid.New(), uuid.New()
	d, ok := payloadDeploy(jobs.Job{TargetID: target, Payload: map[string]string{"ssh_key_id": key.String(), "os_user": "deploy",
		"file_path": "/home/deploy/.ssh/authorized_keys"}})
	require.True(t, ok)
	assert.Equal(t, sshkeys.DeployJob{KeyID: key, TargetID: target, OSUser: "deploy", FilePath: "/home/deploy/.ssh/authorized_keys"}, d)
	_, ok = payloadDeploy(jobs.Job{Payload: map[string]string{"ssh_key_id": "nope"}})
	assert.False(t, ok, "nothing is audited for a key that cannot be named")
}

func TestPresentNote(t *testing.T) {
	assert.Empty(t, presentNote(providers.KeyLoginAccepted, nil, ""))
	assert.Equal(t, "login_without_key", presentNote(providers.KeyLoginUnprovable, nil, ""))
	assert.Equal(t, "from_option", presentNote(providers.KeyLoginRefused, nil, `from="10.0.0.0/8"`))
	assert.Equal(t, "login_refused", presentNote(providers.KeyLoginRefused, nil, ""))
	assert.Equal(t, "login_unavailable", presentNote("", errors.New("down"), ""))
}

func TestErrType(t *testing.T) {
	assert.Equal(t, "*errors.errorString", errType(errors.New("x")))
}

func TestFailureClassesOfOpen(t *testing.T) {
	assert.True(t, internalFailure(jobs.Retry("internal.unexpected", nil, errors.New("db"))), "the database: retried, never recorded")
	assert.False(t, internalFailure(jobs.FromProvider(providers.NewError("ssh.unreachable", true, nil, nil))), "the server's failure")
	assert.False(t, internalFailure(jobs.Fail("target.host_key_changed", nil, nil)))
	assert.True(t, transient(providers.NewError("ssh.unreachable", true, nil, nil)))
	assert.False(t, transient(jobs.Fail("target.host_key_changed", nil, nil)))
}

// The store's refusals end a location job without a record, saying why; a lost claim and a duplicate
// operation id are failures (the latter permanent: a store bug, never retried).
func TestStoreStopAnswers(t *testing.T) {
	r := &locJob{h: &handlers{d: Deps{Log: slog.New(slog.DiscardHandler)}}}
	for err, want := range map[error]string{
		sshkeys.ErrNotYourTurn: "not_your_turn", sshkeys.ErrPaused: "paused", sshkeys.ErrOwnKeyProtected: "own_key_protected",
		fmt.Errorf("wrapped: %w", sshkeys.ErrNotYourTurn): "not_your_turn",
	} {
		res, ferr := r.storeStop(err)
		require.NoError(t, ferr)
		assert.Equal(t, want, res["stopped"])
	}
	var f *jobs.Failure
	_, err := r.storeStop(inventory.ErrClaimLost)
	require.ErrorAs(t, err, &f)
	assert.Equal(t, jobs.Retryable, f.Class)
	_, err = r.storeStop(fmt.Errorf("x: %w", &pgconn.PgError{Code: "23505", ConstraintName: "rotation_op_ids_pkey"}))
	require.ErrorAs(t, err, &f)
	assert.Equal(t, jobs.Permanent, f.Class, "a duplicate operation id is never retried")
	_, err = r.storeStop(errors.New("database down"))
	require.ErrorAs(t, err, &f)
	assert.Equal(t, jobs.Retryable, f.Class)
}
