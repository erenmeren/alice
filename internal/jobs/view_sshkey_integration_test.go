//go:build integration

package jobs

import (
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A job names the SSH key or the rotation it works on (payload ssh_key_id, rotation_id: sshkey.add and rotation.location
// jobs): Get and List carry them as IDs; a job without one, or with a value that is not a UUID, names none (F5).
func TestViewNamesItsSSHKeyAndRotation(t *testing.T) {
	e := newQEnv(t)
	target := insertTarget(t, e.d)
	key, run := uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7())
	withKey := e.enqueue(t, Spec{Type: testQueueJob, TargetID: target, Payload: map[string]string{"ssh_key_id": key.String()}})
	withRun := e.enqueue(t, Spec{Type: testQueueJob, Payload: map[string]string{"rotation_id": run.String()}, DedupeKey: "run"})
	bad := e.enqueue(t, Spec{Type: testQueueJob, Payload: map[string]string{"ssh_key_id": "not-a-uuid", "rotation_id": "<b>"}, DedupeKey: "bad"})

	v, err := e.q.Get(e.ctx, withKey)
	require.NoError(t, err)
	assert.Equal(t, key, v.SSHKeyID)
	assert.Equal(t, uuid.Nil, v.RotationID)
	v, err = e.q.Get(e.ctx, withRun)
	require.NoError(t, err)
	assert.Equal(t, run, v.RotationID)
	assert.Equal(t, uuid.Nil, v.SSHKeyID)
	v, err = e.q.Get(e.ctx, bad)
	require.NoError(t, err)
	assert.Equal(t, uuid.Nil, v.SSHKeyID)
	assert.Equal(t, uuid.Nil, v.RotationID)

	list, _, err := e.q.List(e.ctx, ListFilter{})
	require.NoError(t, err)
	got := map[uuid.UUID]View{}
	for _, v := range list {
		got[v.ID] = v
	}
	assert.Equal(t, key, got[withKey].SSHKeyID)
	assert.Equal(t, run, got[withRun].RotationID)
	assert.Equal(t, uuid.Nil, got[bad].SSHKeyID)
}
