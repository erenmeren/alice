//go:build integration

package sshkeys_test

import (
	"errors"
	"maps"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

	"alice/internal/audit"
	"alice/internal/inventory"
	"alice/internal/license"
	"alice/internal/platform/validate"
	"alice/internal/providers"
	"alice/internal/sshkeys"
)

func TestDeployRequestQueuesTheJob(t *testing.T) {
	e := newEnv(t)
	srv := e.server("web-01")
	k := e.generate("ci")
	id, err := e.svc.RequestDeploy(e.ctx, e.operator, sshkeys.DeployInput{KeyID: k.ID, TargetID: srv, OSUser: "deploy",
		FilePath: "/home/deploy/.ssh/authorized_keys", From: "10.0.0.0/8", Restrict: true})
	require.NoError(t, err)
	j := e.job(id)
	assert.Equal(t, "sshkey.add", j.Type)
	assert.Equal(t, srv, j.TargetID)
	assert.Equal(t, map[string]string{"ssh_key_id": k.ID.String(), "os_user": "deploy",
		"file_path": "/home/deploy/.ssh/authorized_keys", "options": `from="10.0.0.0/8",restrict`}, j.Payload)
	assert.Equal(t, 1, e.audits("sshkey.deploy_requested"))
	assert.Equal(t, id.String(), e.lastAuditDetail("sshkey.deploy_requested", "job_id"))
	assert.Equal(t, k.Fingerprint, e.lastAuditDetail("sshkey.deploy_requested", "fingerprint"))
	var kind, dedupe string
	require.NoError(t, e.db.Owner.QueryRow(e.ctx, "SELECT kind, dedupe_key FROM jobs WHERE id = $1", id).Scan(&kind, &dedupe))
	assert.Equal(t, "user", kind)
	assert.Regexp(t, `^sshkey\.add:`+k.ID.String()+`:`+srv.String()+`:[0-9a-f]{16}$`, dedupe)
	again, err := e.svc.RequestDeploy(e.ctx, e.operator, sshkeys.DeployInput{KeyID: k.ID, TargetID: srv, OSUser: "deploy",
		FilePath: "/home/deploy/.ssh/authorized_keys", From: "10.0.0.0/8", Restrict: true})
	require.NoError(t, err)
	assert.Equal(t, id, again, "the same deploy while queued is the same job")
	_, err = e.svc.RequestDeploy(e.ctx, e.operator, sshkeys.DeployInput{KeyID: k.ID, TargetID: srv, OSUser: "deploy",
		FilePath: "/home/deploy/.ssh/authorized_keys"})
	assert.ErrorIs(t, err, inventory.ErrJobConflict, "the same place with other options while queued")
	// Another file of the same user is another job.
	other, err := e.svc.RequestDeploy(e.ctx, e.operator, sshkeys.DeployInput{KeyID: k.ID, TargetID: srv, OSUser: "root",
		FilePath: "/root/.ssh/authorized_keys", From: " 192.0.2.1 , 2001:db8::/32 "})
	require.NoError(t, err)
	assert.NotEqual(t, id, other)
	assert.Equal(t, `from="192.0.2.1,2001:db8::/32"`, e.job(other).Payload["options"], "from= in canonical form")
}

func TestDeployRequestRefusals(t *testing.T) {
	e := newEnv(t)
	srv := e.server("web-01")
	k := e.generate("ci")
	cases := []struct {
		name   string
		in     sshkeys.DeployInput
		want   error
		denied string // audited reason, "" = not audited
	}{
		{"connection account", sshkeys.DeployInput{KeyID: k.ID, TargetID: srv, OSUser: "alice-svc", FilePath: "/home/alice-svc/.ssh/authorized_keys"},
			sshkeys.ErrConnectionAccount, "connection_account"},
		{"not a key file", sshkeys.DeployInput{KeyID: k.ID, TargetID: srv, OSUser: "deploy", FilePath: "/etc/shadow"}, sshkeys.ErrNotAKeyFile, ""},
		{"another user's file", sshkeys.DeployInput{KeyID: k.ID, TargetID: srv, OSUser: "deploy", FilePath: "/root/.ssh/authorized_keys"},
			sshkeys.ErrNotAKeyFile, ""},
		{"unknown user", sshkeys.DeployInput{KeyID: k.ID, TargetID: srv, OSUser: "nobody", FilePath: "/home/nobody/.ssh/authorized_keys"},
			sshkeys.ErrNotAKeyFile, ""},
		{"discovered key", sshkeys.DeployInput{KeyID: e.discoveredKey(), TargetID: srv, OSUser: "deploy", FilePath: "/home/deploy/.ssh/authorized_keys"},
			sshkeys.ErrNotManaged, ""},
		{"platform key", sshkeys.DeployInput{KeyID: e.platformKeyRow(), TargetID: srv, OSUser: "deploy", FilePath: "/home/deploy/.ssh/authorized_keys"},
			sshkeys.ErrNotManaged, "own_key"},
		{"unknown key", sshkeys.DeployInput{KeyID: uuid.New(), TargetID: srv, OSUser: "deploy", FilePath: "/home/deploy/.ssh/authorized_keys"},
			sshkeys.ErrNotFound, ""},
		{"unknown target", sshkeys.DeployInput{KeyID: k.ID, TargetID: uuid.New(), OSUser: "deploy", FilePath: "/home/deploy/.ssh/authorized_keys"},
			sshkeys.ErrNotFound, ""},
		{"bad from", sshkeys.DeployInput{KeyID: k.ID, TargetID: srv, OSUser: "deploy", FilePath: "/home/deploy/.ssh/authorized_keys", From: "*"},
			validate.Errors{}, ""},
		{"no user", sshkeys.DeployInput{KeyID: k.ID, TargetID: srv, FilePath: "/home/deploy/.ssh/authorized_keys"}, validate.Errors{}, ""},
		{"relative file", sshkeys.DeployInput{KeyID: k.ID, TargetID: srv, OSUser: "deploy", FilePath: ".ssh/authorized_keys"}, validate.Errors{}, ""},
		{"control byte", sshkeys.DeployInput{KeyID: k.ID, TargetID: srv, OSUser: "deploy\n", FilePath: "/home/deploy/.ssh/authorized_keys"},
			validate.Errors{}, ""},
	}
	for _, c := range cases {
		before := e.audits("sshkey.deploy.denied")
		_, err := e.svc.RequestDeploy(e.ctx, e.operator, c.in)
		if errors.As(c.want, new(validate.Errors)) {
			var verr validate.Errors
			assert.ErrorAs(t, err, &verr, c.name)
		} else {
			assert.ErrorIs(t, err, c.want, c.name)
		}
		if c.denied != "" {
			assert.Equal(t, before+1, e.audits("sshkey.deploy.denied"), c.name)
			assert.Equal(t, c.denied, e.lastAuditDetail("sshkey.deploy.denied", "reason"), c.name)
			assert.Equal(t, c.in.KeyID.String(), e.lastAuditDetail("sshkey.deploy.denied", "ssh_key_id"), c.name)
		} else {
			assert.Equal(t, before, e.audits("sshkey.deploy.denied"), c.name)
		}
	}
	e.setTargetStatus(srv, "host_key_changed")
	_, err := e.svc.RequestDeploy(e.ctx, e.operator, sshkeys.DeployInput{KeyID: k.ID, TargetID: srv, OSUser: "deploy",
		FilePath: "/home/deploy/.ssh/authorized_keys"})
	assert.ErrorIs(t, err, inventory.ErrHostKeyChanged)
	e.retire(k.ID)
	_, err = e.svc.RequestDeploy(e.ctx, e.operator, sshkeys.DeployInput{KeyID: k.ID, TargetID: e.server("web-02"), OSUser: "deploy",
		FilePath: "/home/deploy/.ssh/authorized_keys"})
	assert.ErrorIs(t, err, sshkeys.ErrRetired)
	e.gate.lock()
	_, err = e.svc.RequestDeploy(e.ctx, e.operator, sshkeys.DeployInput{KeyID: e.generateUnlocked("x"), TargetID: srv, OSUser: "deploy",
		FilePath: "/home/deploy/.ssh/authorized_keys"})
	assert.ErrorIs(t, err, license.ErrLocked)
	assert.Zero(t, e.count("SELECT count(*) FROM jobs WHERE type = 'sshkey.add'"))
}

// Servers whose sshd reads the keys from a program, or whose settings were not read, refuse
// deploys like removals do, audited.
func TestDeployRequestRefusesUnreadableServers(t *testing.T) {
	e := newEnv(t)
	k := e.generate("ci")
	srv := e.server("web-01")
	_, err := e.db.Owner.Exec(e.ctx, "UPDATE targets SET keys_managed_elsewhere = true WHERE id = $1", srv)
	require.NoError(t, err)
	_, err = e.svc.RequestDeploy(e.ctx, e.operator, sshkeys.DeployInput{KeyID: k.ID, TargetID: srv, OSUser: "deploy",
		FilePath: "/home/deploy/.ssh/authorized_keys"})
	assert.ErrorIs(t, err, inventory.ErrKeysManagedElsewhere)
	assert.Equal(t, "keys_managed_elsewhere", e.lastAuditDetail("sshkey.deploy.denied", "reason"))
	srv2 := e.server("web-02")
	_, err = e.db.Owner.Exec(e.ctx, "UPDATE targets SET facts = jsonb_set(facts, '{sshd,Read}', 'false') WHERE id = $1", srv2)
	require.NoError(t, err)
	_, err = e.svc.RequestDeploy(e.ctx, e.operator, sshkeys.DeployInput{KeyID: k.ID, TargetID: srv2, OSUser: "deploy",
		FilePath: "/home/deploy/.ssh/authorized_keys"})
	assert.ErrorIs(t, err, inventory.ErrSSHDUnreadable)
	assert.Equal(t, "sshd_unreadable", e.lastAuditDetail("sshkey.deploy.denied", "reason"))
	assert.Equal(t, 2, e.audits("sshkey.deploy.denied"))
	assert.Zero(t, e.count("SELECT count(*) FROM jobs WHERE type = 'sshkey.add'"))
}

// S7: a file the connection account's sshd reads (an absolute AuthorizedKeysFile shared by every
// user) is refused whatever user the request names, at the request and again when the job runs.
func TestDeployIntoAFileTheConnectionAccountReads(t *testing.T) {
	e := newEnv(t)
	shared := "/etc/ssh/authorized_keys/shared"
	srv := e.serverWith("web-01", []providers.UserKeyFiles{
		{OSUser: "bob", Files: []string{shared, "/home/bob/.ssh/authorized_keys"}, Complete: true},
		{OSUser: "alice-svc", Files: []string{"/home/alice-svc/.ssh/authorized_keys", shared}, Complete: true},
	})
	k := e.generate("ci")
	_, err := e.svc.RequestDeploy(e.ctx, e.operator, sshkeys.DeployInput{KeyID: k.ID, TargetID: srv, OSUser: "bob", FilePath: shared})
	assert.ErrorIs(t, err, sshkeys.ErrConnectionAccount)
	assert.Equal(t, "connection_account", e.lastAuditDetail("sshkey.deploy.denied", "reason"))
	id, err := e.svc.RequestDeploy(e.ctx, e.operator, sshkeys.DeployInput{KeyID: k.ID, TargetID: srv, OSUser: "bob",
		FilePath: "/home/bob/.ssh/authorized_keys"})
	require.NoError(t, err, "bob's own file")
	payload := e.job(id).Payload
	forged := maps.Clone(payload)
	forged["file_path"] = shared
	_, err = e.svc.DeployJob(e.ctx, id, srv, forged)
	assert.ErrorIs(t, err, sshkeys.ErrConnectionAccount)
	// The connection account's files change after the request: the job refuses.
	_, err = e.db.Owner.Exec(e.ctx, `UPDATE targets SET facts = jsonb_set(facts, '{key_files}',
    '[{"os_user":"bob","files":["/home/bob/.ssh/authorized_keys"],"complete":true},{"os_user":"alice-svc","files":["/home/bob/.ssh/authorized_keys"],"complete":true}]')
WHERE id = $1`, srv)
	require.NoError(t, err)
	_, err = e.svc.DeployJob(e.ctx, id, srv, payload)
	assert.ErrorIs(t, err, sshkeys.ErrConnectionAccount)
}

func TestDeployJobRereadsTheDatabase(t *testing.T) {
	e := newEnv(t)
	srv := e.server("web-01")
	k := e.generate("ci")
	id, err := e.svc.RequestDeploy(e.ctx, e.operator, sshkeys.DeployInput{KeyID: k.ID, TargetID: srv, OSUser: "deploy",
		FilePath: "/home/deploy/.ssh/authorized_keys", Restrict: true})
	require.NoError(t, err)
	j := e.job(id)
	d, err := e.svc.DeployJob(e.ctx, id, srv, j.Payload)
	require.NoError(t, err)
	assert.Equal(t, "restrict "+k.PublicKey+" "+k.Comment, d.Line)
	assert.Equal(t, sshkeys.DeployJob{KeyID: k.ID, TargetID: srv, Fingerprint: k.Fingerprint, OSUser: "deploy",
		FilePath: "/home/deploy/.ssh/authorized_keys", Options: "restrict", Comment: k.Comment, Line: d.Line, Protected: d.Protected}, d)
	pk, err := e.inv.PlatformKey(e.ctx)
	require.NoError(t, err)
	assert.Contains(t, d.Protected, pk.Fingerprint)
	forged := maps.Clone(j.Payload)
	forged["os_user"] = "alice-svc"
	_, err = e.svc.DeployJob(e.ctx, id, srv, forged)
	assert.ErrorIs(t, err, sshkeys.ErrConnectionAccount)
	forged = maps.Clone(j.Payload)
	forged["file_path"] = "/etc/shadow"
	_, err = e.svc.DeployJob(e.ctx, id, srv, forged)
	assert.ErrorIs(t, err, sshkeys.ErrNotAKeyFile)
	forged = maps.Clone(j.Payload)
	forged["ssh_key_id"] = e.platformKeyRow().String()
	_, err = e.svc.DeployJob(e.ctx, id, srv, forged)
	assert.ErrorIs(t, err, sshkeys.ErrNotManaged)
	forged["ssh_key_id"] = "not-a-uuid"
	_, err = e.svc.DeployJob(e.ctx, id, srv, forged)
	assert.Error(t, err)
	_, err = e.svc.DeployJob(e.ctx, id, uuid.New(), j.Payload)
	assert.ErrorIs(t, err, sshkeys.ErrNotFound)
	// The state changed after the request: the job refuses.
	e.setTargetStatus(srv, "pending_host_key")
	_, err = e.svc.DeployJob(e.ctx, id, srv, j.Payload)
	assert.ErrorIs(t, err, inventory.ErrHostKeyUnconfirmed)
	e.setTargetStatus(srv, "ok")
	e.retire(k.ID)
	_, err = e.svc.DeployJob(e.ctx, id, srv, j.Payload)
	assert.ErrorIs(t, err, sshkeys.ErrRetired)
}

// S7: whatever the payload carries, the line's options are from= (canonical) and restrict only.
func TestDeployJobRefusesForeignOptions(t *testing.T) {
	e := newEnv(t)
	srv := e.server("web-01")
	k := e.generate("ci")
	id, err := e.svc.RequestDeploy(e.ctx, e.operator, sshkeys.DeployInput{KeyID: k.ID, TargetID: srv, OSUser: "deploy",
		FilePath: "/home/deploy/.ssh/authorized_keys", From: "10.0.0.0/8"})
	require.NoError(t, err)
	payload := e.job(id).Payload
	for _, opts := range []string{"", "restrict", `from="10.0.0.0/8"`, `from="10.0.0.0/8",restrict`, `from="10.0.0.1,192.0.2.0/24",restrict`} {
		p := maps.Clone(payload)
		p["options"] = opts
		d, err := e.svc.DeployJob(e.ctx, id, srv, p)
		require.NoError(t, err, opts)
		assert.Equal(t, opts, d.Options, opts)
	}
	for _, opts := range []string{"cert-authority", `command="/bin/sh"`, `restrict,from="10.0.0.0/8"`, `from="10.0.0.0/8",command="x"`,
		`from="*"`, `from="10.0.0.1/8"`, `from="10.0.0.0/8 "`, `from=" 10.0.0.0/8"`, `from="10.0.0.0/8",restrict,restrict`,
		`no-pty`, `RESTRICT`, `from="10.0.0.0/8",`, `,restrict`, `environment="A=b"`, `from="10.0.0.0/8"` + "\n" + `command="x"`} {
		p := maps.Clone(payload)
		p["options"] = opts
		_, err := e.svc.DeployJob(e.ctx, id, srv, p)
		var perr *providers.Error
		require.True(t, errors.As(err, &perr), "%q: %v", opts, err)
		assert.Equal(t, "ssh.helper_refused", perr.Code, opts)
		assert.Equal(t, map[string]string{"field": "options"}, perr.Params, opts)
	}
	delete(payload, "options")
	_, err = e.svc.DeployJob(e.ctx, id, srv, payload)
	assert.Error(t, err, "an absent option field is not an empty one")
}

func TestFinishDeployRecordsTheLocation(t *testing.T) {
	e := newEnv(t)
	srv := e.server("web-01")
	k := e.generate("ci")
	d := sshkeys.DeployJob{KeyID: k.ID, TargetID: srv, Fingerprint: k.Fingerprint, OSUser: "deploy", FilePath: "/home/deploy/.ssh/authorized_keys",
		Comment: k.Comment}
	actor := audit.Actor{Type: audit.ActorSystem, Name: "jobs", RequestID: uuid.NewString()}
	require.NoError(t, e.svc.FinishDeploy(e.ctx, actor, d, sshkeys.DeployOutcome{Result: sshkeys.DeployVerified, LineNo: 3}))
	assert.Equal(t, 1, e.count("SELECT count(*) FROM ssh_key_locations WHERE ssh_key_id = $1 AND line_no = 3", k.ID))
	assert.Equal(t, "true", e.lastAuditDetail("sshkey.added", "verified"))
	assert.Equal(t, actor.RequestID, e.lastAuditDetail("sshkey.added", "job_id"))
	require.NoError(t, e.svc.FinishDeploy(e.ctx, actor, d, sshkeys.DeployOutcome{Result: sshkeys.DeployUnverified, LineNo: 3, Note: "from_option"}))
	assert.Equal(t, "false", e.lastAuditDetail("sshkey.added", "verified"))
	require.NoError(t, e.svc.FinishDeploy(e.ctx, actor, d, sshkeys.DeployOutcome{Result: sshkeys.DeployAlreadyPresent, LineNo: 3}))
	assert.Equal(t, 3, e.audits("sshkey.added"))
	assert.Equal(t, 1, e.count("SELECT count(*) FROM ssh_key_locations WHERE ssh_key_id = $1", k.ID))
	for _, out := range []sshkeys.DeployOutcome{
		{Result: sshkeys.DeployUndone, Reason: "sshkey.login_failed"},
		{Result: sshkeys.DeployFailed, Reason: "ssh.unreachable"},
		{Result: sshkeys.DeployUndoFailed, Reason: "sshkey.add_undo_failed"},
	} {
		require.NoError(t, e.svc.FinishDeploy(e.ctx, actor, d, out))
		assert.Equal(t, out.Reason, e.lastAuditDetail("sshkey.add_failed", "reason"))
		assert.Equal(t, actor.RequestID, e.lastAuditDetail("sshkey.add_failed", "job_id"))
		assert.Equal(t, srv.String(), e.lastAuditDetail("sshkey.add_failed", "target_id"))
	}
	// A reason that is not a closed code is not stored as given.
	require.NoError(t, e.svc.FinishDeploy(e.ctx, actor, d, sshkeys.DeployOutcome{Result: sshkeys.DeployFailed, Reason: "-----BEGIN x"}))
	assert.Equal(t, "internal.unexpected", e.lastAuditDetail("sshkey.add_failed", "reason"))
	assert.Equal(t, 4, e.audits("sshkey.add_failed"))
	assert.Error(t, e.svc.FinishDeploy(e.ctx, actor, d, sshkeys.DeployOutcome{Result: "maybe"}))
	assert.Equal(t, 1, e.count("SELECT count(*) FROM ssh_key_locations WHERE ssh_key_id = $1", k.ID), "failures record no location")
}

func TestKeySignerSignsAndZeroes(t *testing.T) {
	e := newEnv(t)
	k := e.generate("ci")
	var seen [][]byte
	sshkeys.OnOpenedKey(t, func(b []byte) { seen = append(seen, b) }) // export_test.go hook, called with the opened plaintext
	s, release, err := e.svc.KeySigner(k.ID).SSHSigner(e.ctx)
	require.NoError(t, err)
	assert.Equal(t, k.Fingerprint, ssh.FingerprintSHA256(s.PublicKey()))
	sig, err := s.Sign(nil, []byte("data"))
	require.NoError(t, err)
	require.NoError(t, s.PublicKey().Verify([]byte("data"), sig))
	require.Len(t, seen, 1)
	assert.NotEmpty(t, seen[0])
	release()
	assert.Equal(t, make([]byte, len(seen[0])), seen[0], "the opened key is zeroed")
	// The signer's own copy is released: an Ed25519 signer signs no more after release.
	sig, err = s.Sign(nil, []byte("data"))
	if err == nil {
		assert.Error(t, s.PublicKey().Verify([]byte("data"), sig))
	}
	_, _, err = e.svc.KeySigner(e.discoveredKey()).SSHSigner(e.ctx)
	assert.ErrorIs(t, err, sshkeys.ErrNotManaged)
	_, _, err = e.svc.KeySigner(uuid.New()).SSHSigner(e.ctx)
	assert.ErrorIs(t, err, sshkeys.ErrNotFound)
	e.destroy(k.ID)
	_, _, err = e.svc.KeySigner(k.ID).SSHSigner(e.ctx)
	assert.ErrorIs(t, err, sshkeys.ErrDestroyed)
}

func TestProtectedFingerprints(t *testing.T) {
	e := newEnv(t)
	pk, err := e.inv.PlatformKey(e.ctx)
	require.NoError(t, err)
	got, err := e.svc.ProtectedFingerprints(e.ctx)
	require.NoError(t, err)
	assert.Equal(t, []string{pk.Fingerprint}, got)
}
