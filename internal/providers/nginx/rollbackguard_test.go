package nginx

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/providers"
	"alice/internal/providers/linuxssh"
	"alice/internal/providers/linuxssh/helperproto"
	"alice/internal/testutil/pki"
)

// The rollback guard on the provider's side (R48): the lists go to a helper of protocol 10 with the deployment and
// with every restore; the inline rollback after a failed verification reads the guard again; an older helper never
// gets a deployment that needs the guard, and never a restore the guard forbids.

// spkiOf is the SHA-256 of the leaf's re-encoded SubjectPublicKeyInfo (internal/certs' public key hash).
func spkiOf(t *testing.T, l pki.Leaf) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(l.Cert.PublicKey)
	require.NoError(t, err)
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}

// oldKeyCompromised is the guard of the fixture site's pair once its key is compromised.
func (e *env) oldKeyCompromised(t *testing.T) providers.RollbackGuard {
	return providers.RollbackGuard{ForbiddenSPKI: []string{spkiOf(t, e.leaf)}, TargetForbidden: true, Required: true}
}

// assertNotOld checks that the files on the server are not the old (compromised) pair: the key is the new one.
func (e *env) assertNotOld(t *testing.T, nw pki.Leaf) {
	t.Helper()
	assert.NotEqual(t, string(e.leaf.KeyPEM), string(e.emu.NginxFile(wwwKey)), "the compromised key is never put back")
	assert.Equal(t, string(nw.KeyPEM), string(e.emu.NginxFile(wwwKey)))
	assert.Equal(t, string(nw.FullchainPEM), string(e.emu.NginxFile(wwwCert)))
}

func (e *env) newLeaf() pki.Leaf {
	return e.ca.Issue(pki.Opts{CommonName: "www.example.test", SANs: []string{"www.example.test"}}, e.now)
}

// The acceptance test of the provider path: the new pair is committed, the website does not serve it, and the old key
// was marked compromised while the deployment ran (only the inline rollback's own read knows): nothing is put back.
func TestInlineRollbackNeverRestoresACompromisedKey(t *testing.T) {
	e := newEnv(t)
	nw := e.newLeaf()
	e.emu.NoopReload(true)
	req := e.req(t, nw)
	reads := 0
	req.RecheckGuard = func(context.Context) (providers.RollbackGuard, error) {
		reads++
		return e.oldKeyCompromised(t), nil
	}
	log := &steps{}
	out, err := e.open(t).DeployCertificate(context.Background(), req, log)
	require.NoError(t, err)
	require.NoError(t, providers.CheckDeployReturn(out, err))
	assert.Equal(t, 1, reads, "read again right before the rollback")
	assert.Equal(t, providers.DeployRollbackFailed, out.Result)
	assert.Equal(t, providers.PhaseRestoreForbidden, out.Phase, "the helper refused and recorded it")
	assert.Equal(t, providers.StepNameRestore, out.FailedStep)
	assert.Equal(t, providers.StepNameVerify, out.CauseStep)
	assert.Equal(t, providers.DeployErrForbidden, out.Error)
	assert.Equal(t, providers.ReasonRollbackForbidden, out.Reason)
	assert.NotContains(t, out.Params, "backup_dir")
	assert.Contains(t, log.list(), "restore:failed")
	assert.Equal(t, helperproto.PhaseRestoreForbidden, e.emu.NginxPhase(e.op.String()))
	e.assertNotOld(t, nw)
	st, err := e.open(t).DeploymentStatus(context.Background(), e.op)
	require.NoError(t, err)
	assert.Equal(t, providers.PhaseRestoreForbidden, st.Phase)
}

// The acceptance test of the helper path: the old key was compromised before the deployment; the helper's own rollback
// after a failed reload (and after a failed nginx -t) checks the lists it got with the deployment and puts nothing back.
func TestHelpersOwnRollbackNeverRestoresACompromisedKey(t *testing.T) {
	for name, fail := range map[string]func(e *env){
		"reload":      func(e *env) { e.emu.FailReload(1) },
		"config test": func(e *env) { e.emu.FailConfigTest(1) },
	} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			nw := e.newLeaf()
			fail(e)
			req := e.req(t, nw)
			req.Guard = e.oldKeyCompromised(t)
			out, err := e.open(t).DeployCertificate(context.Background(), req, nil)
			require.NoError(t, err)
			require.NoError(t, providers.CheckDeployReturn(out, err))
			assert.Equal(t, providers.DeployRollbackFailed, out.Result)
			assert.Equal(t, providers.PhaseRestoreForbidden, out.Phase)
			assert.Equal(t, providers.ReasonRollbackForbidden, out.Reason)
			assert.Contains(t, []string{providers.StepNameReload, providers.StepNameConfigTest}, out.CauseStep)
			e.assertNotOld(t, nw)
			stdins := e.emu.DeployStdins()
			require.Len(t, stdins, 1)
			var in helperproto.NginxDeployInput
			require.NoError(t, json.Unmarshal(stdins[0], &in))
			assert.Equal(t, req.Guard.ForbiddenSPKI, in.ForbiddenSPKI, "the lists travel with the deployment")
			assert.Empty(t, in.ForbiddenLeaf)
		})
	}
}

// Without anything forbidden nothing changes: no lists in the input, the inline rollback restores as before.
func TestGuardWithNothingForbiddenRollsBackAsBefore(t *testing.T) {
	e := newEnv(t)
	nw := e.newLeaf()
	e.emu.NoopReload(true)
	req := e.req(t, nw)
	req.RecheckGuard = func(context.Context) (providers.RollbackGuard, error) { return providers.RollbackGuard{}, nil }
	out, err := e.open(t).DeployCertificate(context.Background(), req, nil)
	require.NoError(t, err)
	assert.Equal(t, providers.DeployRolledBack, out.Result)
	assert.Equal(t, string(e.leaf.KeyPEM), string(e.emu.NginxFile(wwwKey)), "the old pair is back")
	stdins := e.emu.DeployStdins()
	require.Len(t, stdins, 1)
	assert.NotContains(t, string(stdins[0]), "forbidden", "the input of an older protocol")
}

// A backup the lists do not name is restored, the lists checked by the helper.
func TestInlineRollbackWithListsRestoresAnAllowedBackup(t *testing.T) {
	e := newEnv(t)
	nw := e.newLeaf()
	e.emu.NoopReload(true)
	other := e.newLeaf()
	req := e.req(t, nw)
	req.Guard = providers.RollbackGuard{ForbiddenSPKI: []string{spkiOf(t, other)}, ForbiddenLeaf: []string{pki.Fingerprint(other.Cert)}}
	out, err := e.open(t).DeployCertificate(context.Background(), req, nil)
	require.NoError(t, err)
	assert.Equal(t, providers.DeployRolledBack, out.Result)
	assert.Equal(t, string(e.leaf.KeyPEM), string(e.emu.NginxFile(wwwKey)))
}

// The guard cannot be read again: nothing is restored, the outcome is uncertain with the verification's reason (the
// engine's recovery reads the guard and the journal).
func TestInlineRollbackWithoutTheGuardIsUncertain(t *testing.T) {
	e := newEnv(t)
	nw := e.newLeaf()
	e.emu.NoopReload(true)
	req := e.req(t, nw)
	req.RecheckGuard = func(context.Context) (providers.RollbackGuard, error) {
		return providers.RollbackGuard{}, errors.New("database down")
	}
	out, err := e.open(t).DeployCertificate(context.Background(), req, nil)
	require.Error(t, err)
	assert.Equal(t, providers.DeployUncertain, out.Result)
	assert.Equal(t, "deployment.verify_failed", out.Reason)
	assert.Equal(t, providers.StepNameVerify, out.Params["failed_step"])
	assert.Equal(t, helperproto.PhaseCommitted, e.emu.NginxPhase(e.op.String()), "no restore was sent")
}

// An older helper: a deployment that needs the guard is refused before anything is sent; one that does not gets the
// input it understands (no lists); a restore the guard forbids is never sent to it.
func TestOlderHelperAndTheGuard(t *testing.T) {
	t.Run("required: refused before the send", func(t *testing.T) {
		e := newEnv(t)
		e.emu.SetProtocol(9)
		nw := e.newLeaf()
		req := e.req(t, nw)
		req.Guard = e.oldKeyCompromised(t)
		out, err := e.open(t).DeployCertificate(context.Background(), req, nil)
		require.Error(t, err)
		require.NoError(t, providers.CheckDeployReturn(out, err))
		assert.Equal(t, providers.DeployNoChange, out.Result)
		assert.Equal(t, linuxssh.ReasonRollbackGuardOutdated, out.Reason)
		assert.Equal(t, map[string]string{"helper_protocol": "9", "required_protocol": "10"}, out.Params)
		assert.ErrorIs(t, err, linuxssh.ErrRollbackGuardOutdated)
		assert.Empty(t, e.emu.DeployStdins(), "nothing was sent")
		assert.Equal(t, string(e.leaf.KeyPEM), string(e.emu.NginxFile(wwwKey)))
	})
	t.Run("not required: the input without lists", func(t *testing.T) {
		e := newEnv(t)
		e.emu.SetProtocol(9)
		nw := e.newLeaf()
		req := e.req(t, nw)
		req.Guard = providers.RollbackGuard{ForbiddenLeaf: []string{strings.Repeat("d", 64)}}
		out, err := e.open(t).DeployCertificate(context.Background(), req, nil)
		require.NoError(t, err)
		assert.Equal(t, providers.DeployCommitted, out.Result)
		require.Len(t, e.emu.DeployStdins(), 1)
		assert.NotContains(t, string(e.emu.DeployStdins()[0]), "forbidden")
	})
	t.Run("the inline rollback is forbidden: nothing is sent", func(t *testing.T) {
		e := newEnv(t)
		e.emu.SetProtocol(9)
		e.emu.NoopReload(true)
		nw := e.newLeaf()
		req := e.req(t, nw)
		req.RecheckGuard = func(context.Context) (providers.RollbackGuard, error) { return e.oldKeyCompromised(t), nil }
		out, err := e.open(t).DeployCertificate(context.Background(), req, nil)
		require.NoError(t, err)
		require.NoError(t, providers.CheckDeployReturn(out, err))
		assert.Equal(t, providers.DeployRollbackFailed, out.Result)
		assert.Empty(t, out.Phase, "nothing was sent")
		assert.Equal(t, providers.ReasonRollbackForbidden, out.Reason)
		assert.Equal(t, helperproto.PhaseCommitted, e.emu.NginxPhase(e.op.String()))
		e.assertNotOld(t, nw)
	})
}

// RollbackDeployment (the engine's recovery) under the guard: the helper refuses a forbidden backup (and answers the
// same again); an older helper gets nothing; an unknown backup is not restored by an older helper while anything is
// forbidden.
func TestRollbackDeploymentUnderTheGuard(t *testing.T) {
	commit := func(t *testing.T, e *env) pki.Leaf {
		t.Helper()
		nw := e.newLeaf()
		_, err := e.open(t).DeployCertificate(context.Background(), e.req(t, nw), nil)
		require.NoError(t, err)
		return nw
	}
	rb := func(t *testing.T, e *env, g providers.RollbackGuard) providers.RollbackRequest {
		return providers.RollbackRequest{OperationID: e.op, Location: e.location(t), OldFingerprint: pki.Fingerprint(e.leaf.Cert), KeyType: "ecdsa",
			Guard: g}
	}
	t.Run("helper refuses", func(t *testing.T) {
		e := newEnv(t)
		nw := commit(t, e)
		for range 2 {
			out, err := e.open(t).RollbackDeployment(context.Background(), rb(t, e, e.oldKeyCompromised(t)), nil)
			require.NoError(t, err)
			require.NoError(t, providers.CheckRollbackReturn(out, err))
			assert.Equal(t, providers.DeployRollbackFailed, out.Result)
			assert.Equal(t, providers.PhaseRestoreForbidden, out.Phase)
			assert.Equal(t, providers.ReasonRollbackForbidden, out.Reason)
			e.assertNotOld(t, nw)
		}
	})
	t.Run("older helper: nothing sent", func(t *testing.T) {
		e := newEnv(t)
		e.emu.SetProtocol(9)
		nw := commit(t, e)
		reloads := e.emu.Reloads()
		out, err := e.open(t).RollbackDeployment(context.Background(), rb(t, e, e.oldKeyCompromised(t)), nil)
		require.NoError(t, err)
		require.NoError(t, providers.CheckRollbackReturn(out, err))
		assert.Equal(t, providers.DeployRollbackFailed, out.Result)
		assert.Empty(t, out.Phase)
		assert.Equal(t, providers.DeployErrForbidden, out.Error)
		assert.Equal(t, reloads, e.emu.Reloads())
		e.assertNotOld(t, nw)
	})
	t.Run("older helper: unknown backup while a key is compromised", func(t *testing.T) {
		e := newEnv(t)
		e.emu.SetProtocol(9)
		nw := commit(t, e)
		g := providers.RollbackGuard{ForbiddenSPKI: []string{strings.Repeat("e", 64)}, TargetUnknown: true}
		out, err := e.open(t).RollbackDeployment(context.Background(), rb(t, e, g), nil)
		require.NoError(t, err)
		assert.Equal(t, providers.DeployRollbackFailed, out.Result)
		assert.Equal(t, providers.ReasonRollbackForbidden, out.Reason)
		e.assertNotOld(t, nw)
	})
	t.Run("older helper: an allowed backup is restored", func(t *testing.T) {
		e := newEnv(t)
		e.emu.SetProtocol(9)
		commit(t, e)
		g := providers.RollbackGuard{ForbiddenSPKI: []string{strings.Repeat("e", 64)}}
		out, err := e.open(t).RollbackDeployment(context.Background(), rb(t, e, g), nil)
		require.NoError(t, err)
		assert.Equal(t, providers.DeployRolledBack, out.Result)
		assert.Equal(t, string(e.leaf.KeyPEM), string(e.emu.NginxFile(wwwKey)))
	})
	t.Run("lists the helper does not take", func(t *testing.T) {
		e := newEnv(t)
		commit(t, e)
		g := providers.RollbackGuard{ForbiddenSPKI: []string{"NOT-HEX"}}
		out, err := e.open(t).RollbackDeployment(context.Background(), rb(t, e, g), nil)
		require.Error(t, err)
		assert.Equal(t, providers.DeployNoChange, out.Result)
		assert.Equal(t, reasonUnexpected, out.Reason)
	})
}

// A deployment whose guard lists are not what the helper takes is the caller's error: refused before anything is sent,
// the site's pair untouched.
func TestDeployWithListsTheHelperDoesNotTake(t *testing.T) {
	e := newEnv(t)
	req := e.req(t, e.newLeaf())
	req.Guard = providers.RollbackGuard{ForbiddenLeaf: []string{"NOT-HEX"}, Required: true}
	out, err := e.open(t).DeployCertificate(context.Background(), req, nil)
	require.Error(t, err)
	require.NoError(t, providers.CheckDeployReturn(out, err))
	assert.Equal(t, providers.DeployNoChange, out.Result)
	assert.Equal(t, reasonUnexpected, out.Reason)
	assert.Empty(t, e.emu.DeployStdins(), "nothing was sent")
	assert.Equal(t, string(e.leaf.KeyPEM), string(e.emu.NginxFile(wwwKey)))
}

func TestDeployInputCarriesTheLists(t *testing.T) {
	spki, leaf := []string{strings.Repeat("a", 64), strings.Repeat("b", 64)}, []string{strings.Repeat("c", 64)}
	b, ok := deployInput([]byte("CERT"), []byte("KEY"), spki, leaf)
	require.True(t, ok)
	var in helperproto.NginxDeployInput
	require.NoError(t, json.Unmarshal(b, &in))
	assert.Equal(t, spki, in.ForbiddenSPKI)
	assert.Equal(t, leaf, in.ForbiddenLeaf)
	assert.Equal(t, cap(b), len(b), "one allocation of the final size")
	b, ok = deployInput([]byte("CERT"), []byte("KEY"), nil, leaf)
	require.True(t, ok)
	assert.NotContains(t, string(b), "forbidden_spki_sha256")
	var r helperproto.NginxRestoreInput
	require.NoError(t, json.Unmarshal(restoreInput(providers.RollbackGuard{ForbiddenLeaf: leaf}), &r))
	assert.Equal(t, []string{}, r.ForbiddenSPKI, "both members, as the helper requires")
	assert.Equal(t, leaf, r.ForbiddenLeaf)
}
