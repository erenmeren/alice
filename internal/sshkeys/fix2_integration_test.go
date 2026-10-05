//go:build integration

package sshkeys_test

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/providers"
	"alice/internal/sshkeys"
)

// Task 7 review N1, N4: a connection account whose key files are not known completely, or that the
// scan lists more than once, refuses deploys with its own reason (scan the server again), not as
// "the connection account".
func TestDeployRefusedWhenTheConnectionFilesAreNotKnown(t *testing.T) {
	e := newEnv(t)
	k := e.generate("ci")
	deploy := providers.UserKeyFiles{OSUser: "deploy", Files: []string{"/home/deploy/.ssh/authorized_keys"}, Complete: true}
	svc := providers.UserKeyFiles{OSUser: "alice-svc", Files: []string{"/home/alice-svc/.ssh/authorized_keys"}, Complete: true}
	for name, files := range map[string][]providers.UserKeyFiles{
		"none":       {deploy},
		"incomplete": {deploy, {OSUser: "alice-svc", Files: svc.Files}},
		"twice":      {deploy, svc, {OSUser: "alice-svc", Files: []string{"/etc/ssh/other"}, Complete: true}},
	} {
		srv := e.serverWith("web-"+name, files)
		_, err := e.svc.RequestDeploy(e.ctx, e.operator, sshkeys.DeployInput{KeyID: k.ID, TargetID: srv, OSUser: "deploy",
			FilePath: "/home/deploy/.ssh/authorized_keys"})
		assert.ErrorIs(t, err, sshkeys.ErrConnectionFilesUnknown, name)
		assert.NotErrorIs(t, err, sshkeys.ErrConnectionAccount, name)
		assert.Equal(t, "connection_files_unknown", e.lastAuditDetail("sshkey.deploy.denied", "reason"), name)
	}
	assert.Equal(t, "sshkey.connection_files_unknown", sshkeys.ReasonConnectionFilesUnknown)
}

// Task 7 review N3: two instances of the hourly task write the live-after-destruction row once.
func TestLiveAfterDestructionIsWrittenOnceByConcurrentRuns(t *testing.T) {
	e := newEnv(t)
	k := e.generate("ci")
	e.retireAt(k.ID, e.clock.Now())
	e.clock.Advance(30 * 24 * time.Hour)
	n, err := e.svc.DestroyRetiredKeys(e.ctx)
	require.NoError(t, err)
	require.Equal(t, 1, n)
	e.liveLocation(k)
	// A second instance runs completely between the first one's read and its write.
	inside := false
	sshkeys.OnLiveFound(t, func() {
		if inside {
			return
		}
		inside = true
		_, err := e.svc.DestroyRetiredKeys(e.ctx)
		assert.NoError(t, err)
	})
	_, err = e.svc.DestroyRetiredKeys(e.ctx)
	require.NoError(t, err)
	var wg sync.WaitGroup
	for range 3 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := e.svc.DestroyRetiredKeys(e.ctx)
			assert.NoError(t, err)
		}()
	}
	wg.Wait()
	assert.Equal(t, 1, e.audits("sshkey.live_after_destruction"))
}

// G14: a download on a clock stepped back behind the last download answers a closed, retryable
// error; nothing is counted or audited and no file leaves.
func TestDownloadOnAClockSteppedBack(t *testing.T) {
	e := newEnv(t)
	k := e.generate("ci")
	dl, err := e.svc.DownloadPrivateKey(e.ctx, e.admin, sshkeys.DownloadInput{KeyID: k.ID, Reason: "the first download"})
	require.NoError(t, err)
	dl.Body.Zero()
	var built []byte
	sshkeys.OnHold(t, func(kind string, b []byte) {
		if kind == "file" {
			built = b
		}
	})
	e.clock.Set(start.Add(-time.Hour))
	_, err = e.svc.DownloadPrivateKey(e.ctx, e.admin, sshkeys.DownloadInput{KeyID: k.ID, Reason: "with the clock behind"})
	assert.ErrorIs(t, err, sshkeys.ErrClockBehind)
	assert.Equal(t, make([]byte, len(built)), built, "the built file is zeroed")
	assert.Equal(t, 1, e.audits("sshkey.private_key_downloaded"))
	got, err := e.svc.ManagedKey(e.ctx, k.ID)
	require.NoError(t, err)
	assert.Equal(t, 1, got.DownloadCount)
}
