//go:build windows

package main

// TestFidelityRDP (W6 Task 4, R69): rdp-dump, rdp-deploy, iis-status, iis-restore and every refusal of
// Task 2 a runner can produce run with winhelper's own code against the real helper's host (the runner's
// RDP-Tcp listener, its stores, a private data directory) and against the emulator configured as F19
// found the runner (RDP on, its port, security layer and NLA, the value absent, one self-signed
// certificate in Remote Desktop: the runner's own, without its key). The answers are compared field by
// field with messages dropped, and so are the journal, the listener's binding record and the import
// inventory, the value afterwards and the chain a fresh handshake is served. The helper is the
// specification: a difference means the emulator is wrong.
//
// Normalised, because it is the machine's: the key facts of the self-signed certificate's entry in a
// dump (has_key, key_provider, key_exportable, key_usable_by_system, key_problem) are copied from the
// real answer, since the model holds that certificate without its key; every other field is compared.
// The model is given the runner's port and the certificate's friendly name.
//
// Not compared here:
//   - RDP_TLS_OFF and BINDING_NOT_FOUND: not produced on a runner (SecurityLayer and the RDP-Tcp key are
//     never written);
//   - BAD_CONTENT, INVALID_ARGUMENT, TOO_LARGE and USAGE beyond one case: winhelper's shared input
//     checks decide them before any host call, so both hosts answer alike by construction (Task 2's
//     tests cover them);
//   - BUSY: it needs a second process holding the lock; TestRealStateFilesLockHolder covers the real
//     lock.
// Compared, because each host's data directory or machine decides them: UNKNOWN_OP, SUPERSEDED,
// OPERATION_EXISTS, FENCED, RECOVERY_PENDING, HASH_MISMATCH, KEY_UNUSABLE, RDP_DISABLED and a
// restore_forbidden restore.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/providers/windows/winproto"
	"alice/internal/providers/windows/wintest"
	"alice/internal/testutil/pki"
)

// rdpTwin is the real RDP fixture and an emulator configured like it.
type rdpTwin struct {
	*rdpFixture
	model *wintest.Model
}

func newRDPTwin(t *testing.T) *rdpTwin {
	t.Helper()
	f := newRDPFixture(t)
	l, err := f.h.RDPListener(f.ctx)
	require.NoError(t, err)
	require.Empty(t, l.CertSHA1, "F19: the value is absent on the runner images")
	m := wintest.NewModel()
	m.SetRDP(wintest.RDPConfig{Present: true, Enabled: l.Enabled, NLA: l.NLA, Port: l.Port, SecurityLayer: l.SecurityLayer,
		CertTemplate: l.CertTemplate})
	d := f.dump()
	der, err := base64.StdEncoding.DecodeString(asString(dumpCert(t, d)["der"]))
	require.NoError(t, err)
	m.AddCertificate(winproto.RDPStoreSelfSigned, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), nil,
		wintest.CertOptions{FriendlyName: asString(dumpCert(t, d)["friendly_name"])})
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	require.NoError(t, m.Serve(ctx, "127.0.0.1:0"))
	return &rdpTwin{rdpFixture: f, model: m}
}

// both runs one call on both hosts and requires the same exit status and answer (rdp-dump's
// self-signed entry normalised); it returns the real answer.
func (tw *rdpTwin) both(stdin []byte, args ...string) map[string]any {
	tw.t.Helper()
	ro, real := execOn(tw.t, tw.h, stdin, args)
	mo, model := execOn(tw.t, tw.model.Host(), stdin, args)
	require.NotNil(tw.t, real, "the real helper answers %v", args)
	require.NotNil(tw.t, model, "the model answers %v", args)
	if args[0] == winproto.SubRDPDump {
		rc, _ := real["certificate"].(map[string]any)
		mc, _ := model["certificate"].(map[string]any)
		if rc != nil && mc != nil && rc["store"] == winproto.RDPStoreSelfSigned {
			for _, k := range []string{"has_key", "key_provider", "key_exportable", "key_usable_by_system", "key_problem"} {
				if v, ok := rc[k]; ok {
					mc[k] = v
				} else {
					delete(mc, k)
				}
			}
		}
	}
	require.Equal(tw.t, ro.Exit, mo.Exit, "exit status of %v (real %v, model %v)", args, real, model)
	require.Equal(tw.t, real, model, "answer of %v", args)
	return real
}

// killBoth runs the call on both hosts with the helper killed at point: neither answers.
func (tw *rdpTwin) killBoth(point string, stdin []byte, args ...string) {
	tw.t.Helper()
	require.True(tw.t, testKillHook, "this test needs the test build's kill hook: go test -tags alicetest")
	tw.t.Setenv(testKillEnv, point)
	ro, real := execOn(tw.t, tw.h, stdin, args)
	tw.t.Setenv(testKillEnv, "")
	tw.model.KillAt(point)
	mo, model := execOn(tw.t, tw.model.Host(), stdin, args)
	assert.True(tw.t, ro.Killed, "the real helper was killed at %s (answer %v)", point, real)
	assert.True(tw.t, mo.Killed, "the model was killed at %s (answer %v)", point, model)
	require.Equal(tw.t, ro.Exit, mo.Exit)
}

// sameState requires the same journal of op, the same listener binding record and import inventory,
// the same value and, when want is set, the same chain served with want as its leaf.
func (tw *rdpTwin) sameState(op, want string) {
	tw.t.Helper()
	mh := tw.model.Host()
	for _, n := range []string{"bindings/" + sum256hex([]byte(winproto.RDPCanonical)) + ".json", "imports.json", "journal/" + op + ".json"} {
		assert.Equal(tw.t, stateFile(tw.t, tw.h, n), stateFile(tw.t, mh, n), "state file %s", n)
	}
	rl, err := tw.h.RDPListener(tw.ctx)
	require.NoError(tw.t, err)
	assert.Equal(tw.t, rl.CertSHA1, tw.model.RDPThumbprint(), "the listener's value")
	if want == "" {
		return
	}
	real := tw.requirePickup("fidelity", "the deployed certificate", want)
	model, _, _, err := rdpHandshake(tw.model.Endpoint(tw.port))
	require.NoError(tw.t, err, "the model's RDP listener")
	assert.Equal(tw.t, real, model, "the chain served by the listener")
}

func (tw *rdpTwin) deploy(op string, leaf pki.Leaf, expect string) map[string]any {
	tw.t.Helper()
	return tw.both(rdpDeployInput(tw.t, leaf.FullchainPEM, leaf.KeyPEM, expect), winproto.SubRDPDeploy, winproto.ArgOp, op)
}

func assertCode(t *testing.T, got map[string]any, code string) {
	t.Helper()
	assert.Equal(t, false, got["ok"], "%v", got)
	assert.Equal(t, code, got["code"], "%v", got)
}

func TestFidelityRDP(t *testing.T) {
	tw := newRDPTwin(t)
	d := tw.both(nil, winproto.SubRDPDump)
	self := asString(dumpCert(t, d)["sha256"])
	assertCode(t, tw.both(nil, winproto.SubRDPDump, "extra"), winproto.CodeUsage)

	ca := fixtureCA("alice-w6-fidelity")
	a := issue(ca, "alice-w6-fidelity-a.test")
	removeChainLater(t, a, ca)
	aSHA := sum256hex(a.Cert.Raw)

	// A wrong expectation; the deployment over the self-signed certificate and its rollback.
	assertCode(t, tw.deploy(op1, a, aSHA), winproto.CodeHashMismatch)
	assertPhase(t, tw.deploy(op1, a, self), winproto.PhaseCommitted)
	tw.sameState(op1, aSHA)
	tw.both(nil, winproto.SubRDPDump)
	assertCode(t, tw.deploy(op1, a, self), winproto.CodeOperationExists)
	tw.both(nil, winproto.SubIISStatus, winproto.ArgOp, op1)
	assertPhase(t, tw.both(restoreInput(t), winproto.SubIISRestore, winproto.ArgOp, op1), winproto.PhaseRestored)
	tw.sameState(op1, "")
	tw.requirePickup("fidelity", "the self-signed certificate after the rollback", self)
	tw.both(nil, winproto.SubRDPDump)
	tw.both(nil, winproto.SubIISStatus, winproto.ArgOp, op1)

	// The same certificate again (the copy in My is used as it is), then unchanged.
	assertPhase(t, tw.deploy(op2, a, self), winproto.PhaseCommitted)
	tw.sameState(op2, aSHA)
	assertPhase(t, tw.deploy(op3, a, aSHA), winproto.PhaseUnchanged)
	tw.sameState(op3, "")

	// A certificate in My without its key.
	b := issue(ca, "alice-w6-fidelity-b.test")
	importCertificate(t, "My", b.Cert)
	tw.model.AddCertificate("My", b.CertPEM, nil, wintest.CertOptions{})
	assertCode(t, tw.deploy(op4, b, aSHA), winproto.CodeKeyUnusable)

	// Remote Desktop turned off (fDenyTSConnections, restored as found by the fixture).
	require.NoError(t, setRaw(keyTerminalServer, valueRDPDeny, u32(1), nil))
	tw.model.SetRDP(wintest.RDPConfig{Present: true, Enabled: false, NLA: true, Port: tw.port, SecurityLayer: 2})
	tw.both(nil, winproto.SubRDPDump)
	assertCode(t, tw.deploy(op4, b, aSHA), winproto.CodeRDPDisabled)
	require.NoError(t, setRaw(keyTerminalServer, valueRDPDeny, u32(0), nil))
	l, err := tw.h.RDPListener(tw.ctx)
	require.NoError(t, err)
	tw.model.SetRDP(wintest.RDPConfig{Present: true, Enabled: l.Enabled, NLA: l.NLA, Port: l.Port, SecurityLayer: l.SecurityLayer})
	tw.requirePickup("fidelity", "the deployed certificate with RDP on again", aSHA)

	// A fenced operation.
	tw.both(nil, winproto.SubIISFence, winproto.ArgOp, op5)
	c := issue(ca, "alice-w6-fidelity-c.test")
	removeChainLater(t, c, ca)
	assertCode(t, tw.deploy(op5, c, aSHA), winproto.CodeFenced)

	// A kill after the grant: the next deployment is refused, the restore takes the grant back.
	tw.killBoth("rdp.granted", rdpDeployInput(t, c.FullchainPEM, c.KeyPEM, aSHA), winproto.SubRDPDeploy, winproto.ArgOp, op6)
	pending := tw.deploy(op7, c, aSHA)
	assertCode(t, pending, winproto.CodeRecoveryPending)
	assert.Equal(t, op6, pending["pending_op"])
	tw.both(nil, winproto.SubIISStatus, winproto.ArgOp, op6)
	assertPhase(t, tw.both(restoreInput(t), winproto.SubIISRestore, winproto.ArgOp, op6), winproto.PhaseRestored)
	tw.sameState(op6, aSHA)
	readable, err := tw.h.RDPKeyRead(tw.ctx, "MY", thumbprint(c.Cert))
	require.NoError(t, err)
	assert.False(t, readable, "the restore took the grant on the killed operation's key back")
	assert.Equal(t, readable, tw.model.KeyReadableByNetworkService("MY", thumbprint(c.Cert)))

	// An unknown operation; a restored one again; an older committed one after newer ones.
	const unknownOp = "a8888888-8888-4888-8888-888888888888"
	assertCode(t, tw.both(restoreInput(t), winproto.SubIISRestore, winproto.ArgOp, unknownOp), winproto.CodeUnknownOp)
	assert.Equal(t, winproto.PhaseNone, tw.both(nil, winproto.SubIISStatus, winproto.ArgOp, unknownOp)["phase"])
	tw.both(restoreInput(t), winproto.SubIISRestore, winproto.ArgOp, op1)
	assertCode(t, tw.both(restoreInput(t), winproto.SubIISRestore, winproto.ArgOp, op2), winproto.CodeSuperseded)
	tw.sameState(op2, "")

	// A deployment that forbids the leaf it replaces: its restore is forbidden and changes nothing.
	forbid, err := json.Marshal(winproto.RDPDeployInput{ExpectSHA256: aSHA, ChainPEM: string(c.FullchainPEM), KeyPEM: string(c.KeyPEM),
		ForbiddenSPKI: []string{}, ForbiddenLeaf: []string{aSHA}})
	require.NoError(t, err)
	assertPhase(t, tw.both(forbid, winproto.SubRDPDeploy, winproto.ArgOp, op7), winproto.PhaseCommitted)
	tw.sameState(op7, sum256hex(c.Cert.Raw))
	got := tw.both(restoreInput(t, aSHA), winproto.SubIISRestore, winproto.ArgOp, op7)
	assert.Equal(t, winproto.PhaseRestoreForbidden, got["phase"], "%v", got)
	tw.sameState(op7, sum256hex(c.Cert.Raw))
	tw.both(nil, winproto.SubRDPDump)
}
