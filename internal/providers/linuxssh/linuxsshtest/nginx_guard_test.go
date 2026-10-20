package linuxsshtest

import (
	"crypto/x509"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/providers/linuxssh/helperproto"
	"alice/internal/testutil/pki"
)

func emuSPKIOf(t *testing.T, l pki.Leaf) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(l.Cert.PublicKey)
	require.NoError(t, err)
	return hexSum(der)
}

func guardedIn(cert, key []byte, spki, leaf []string) []byte {
	b, _ := json.Marshal(helperproto.NginxDeployInput{CertPEM: string(cert), KeyPEM: string(key), ForbiddenSPKI: spki, ForbiddenLeaf: leaf})
	return b
}

func restoreIn(spki, leaf []string) []byte {
	b, _ := json.Marshal(helperproto.NginxRestoreInput{ForbiddenSPKI: append([]string{}, spki...), ForbiddenLeaf: append([]string{}, leaf...)})
	return b
}

func (w *world) restoreWith(op string, stdin []byte) Response {
	return w.run(line(true, helperproto.SubNginxRestore, "--op", op), stdin)
}

func (w *world) deployWith(op string, in []byte) Response {
	return w.run(deployLineFor(op, crt, key, w.oldSHA, in), in)
}

// The helper's TestGuardNeverRestoresACompromisedKey on the emulator: the transaction's own
// rollback, nginx-restore with the list and with an empty stdin never put the compromised key back.
func TestEmulatorGuardNeverRestoresACompromisedKey(t *testing.T) {
	for name, fail := range map[string]func(e *Emulator){"config test": func(e *Emulator) { e.FailConfigTest(1) }, "reload": func(e *Emulator) { e.FailReload(1) }} {
		t.Run(name, func(t *testing.T) {
			w := newWorld(t)
			fail(w.e)
			r := w.deployWith(emuOp, guardedIn(w.nw.FullchainPEM, w.nw.KeyPEM, []string{emuSPKIOf(t, w.old)}, nil))
			require.Equal(t, 0, r.Exit, string(r.Stdout))
			a := decode[helperproto.NginxDeployResponse](t, r)
			assert.Equal(t, helperproto.PhaseRestoreForbidden, a.Phase)
			assert.Equal(t, helperproto.StepRestore, a.FailedStep)
			assert.Equal(t, helperproto.RestoreErrForbidden, a.Error)
			assert.Equal(t, stepFailed(helperproto.StepRestore, helperproto.RestoreErrForbidden), a.Steps[len(a.Steps)-1])
			w.assertPair(t, w.nw)
			assert.Equal(t, helperproto.PhaseRestoreForbidden, w.status(emuOp).Phase)
			for _, stdin := range [][]byte{nil, restoreIn([]string{emuSPKIOf(t, w.old)}, nil)} {
				r = w.restoreWith(emuOp, stdin)
				require.Equal(t, 0, r.Exit, string(r.Stdout))
				assert.Equal(t, helperproto.PhaseRestoreForbidden, decode[helperproto.NginxRestoreResponse](t, r).Phase)
				w.assertPair(t, w.nw)
			}
		})
	}
}

// nginx-restore of a committed operation with the list on stdin; a revoked leaf; an unrelated list.
func TestEmulatorGuardRestore(t *testing.T) {
	w := newWorld(t)
	require.Equal(t, 0, w.deploy(emuOp).Exit)
	r := w.restoreWith(emuOp, restoreIn(nil, []string{hexSum(w.old.Cert.Raw)}))
	require.Equal(t, 0, r.Exit, string(r.Stdout))
	a := decode[helperproto.NginxRestoreResponse](t, r)
	assert.Equal(t, helperproto.PhaseRestoreForbidden, a.Phase)
	assert.Equal(t, []helperproto.NginxStep{stepFailed(helperproto.StepRestore, helperproto.RestoreErrForbidden)}, a.Steps)
	w.assertPair(t, w.nw)

	w = newWorld(t)
	require.Equal(t, 0, w.deploy(emuOp).Exit)
	r = w.restoreWith(emuOp, restoreIn([]string{emuSPKIOf(t, w.other)}, nil))
	require.Equal(t, 0, r.Exit, string(r.Stdout))
	assert.Equal(t, helperproto.PhaseRestored, decode[helperproto.NginxRestoreResponse](t, r).Phase)
	w.assertPair(t, w.old)

	w = newWorld(t)
	require.Equal(t, 0, w.deploy(emuOp).Exit)
	r = w.restoreWith(emuOp, []byte(`{"forbidden_spki_sha256":[]}`))
	assert.Equal(t, helperproto.ExitRefused, r.Exit)
	assert.Equal(t, helperproto.CodeInvalidArgument, codeOf(t, r))
	w.assertPair(t, w.nw)
}

// An emulator of protocol 9 is the old helper: it refuses deploy input with the lists (BAD_CONTENT,
// nothing changed) and ignores nginx-restore's stdin (it restores the forbidden pair).
func TestEmulatorGuardOldProtocol(t *testing.T) {
	w := newWorld(t)
	w.e.SetProtocol(helperproto.RollbackGuardMinProtocol - 1)
	r := w.deployWith(emuOp, guardedIn(w.nw.FullchainPEM, w.nw.KeyPEM, []string{emuSPKIOf(t, w.old)}, nil))
	assert.Equal(t, helperproto.ExitRefused, r.Exit)
	assert.Equal(t, helperproto.CodeBadContent, codeOf(t, r))
	w.assertPair(t, w.old)
	require.Equal(t, 0, w.deploy(emuOp2).Exit)
	r = w.restoreWith(emuOp2, restoreIn([]string{emuSPKIOf(t, w.old)}, nil))
	require.Equal(t, 0, r.Exit, string(r.Stdout))
	assert.Equal(t, helperproto.PhaseRestored, decode[helperproto.NginxRestoreResponse](t, r).Phase, "an old helper never checks")
	w.assertPair(t, w.old)
}
