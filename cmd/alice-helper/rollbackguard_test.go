//go:build linux

package main

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/providers/linuxssh/helperproto"
	"alice/internal/testutil/pki"
)

// The rollback guard (protocol 10, R48): a restore never puts back a backup whose leaf or public key
// Alice listed as forbidden (a revoked certificate, a compromised key).

func spkiOf(t *testing.T, c *x509.Certificate) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(c.PublicKey)
	require.NoError(t, err)
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}

func leafOf(c *x509.Certificate) string {
	sum := sha256.Sum256(c.Raw)
	return hex.EncodeToString(sum[:])
}

// guardedInput is nginx-deploy's stdin with the forbidden lists.
func guardedInput(certPEM, keyPEM []byte, spki, leaf []string) string {
	b, _ := json.Marshal(helperproto.NginxDeployInput{CertPEM: string(certPEM), KeyPEM: string(keyPEM), ForbiddenSPKI: spki, ForbiddenLeaf: leaf})
	return string(b)
}

func restoreInput(spki, leaf []string) string {
	if spki == nil {
		spki = []string{}
	}
	if leaf == nil {
		leaf = []string{}
	}
	b, _ := json.Marshal(helperproto.NginxRestoreInput{ForbiddenSPKI: spki, ForbiddenLeaf: leaf})
	return string(b)
}

// restoreWith runs nginx-restore of op with stdin.
func (w *deployWorld) restoreWith(op, stdin string) (int, map[string]any) {
	w.f.s.stdin = strings.NewReader(stdin)
	return w.f.run("nginx-restore", "--op", op)
}

// assertNotOld: neither file holds the old (forbidden) content after a refused rollback; the pair is
// the new one the operation wrote.
func (w *deployWorld) assertNotOld(t *testing.T) {
	t.Helper()
	assert.NotEqual(t, string(w.leaf.KeyPEM), w.f.read("/etc/nginx/ssl/www.key"), "the compromised key is never put back")
	assert.NotEqual(t, string(w.leaf.FullchainPEM), w.f.read("/etc/nginx/ssl/www.crt"))
	w.assertPair(t, true)
}

// The acceptance test of the helper path: the old pair's key is compromised; the new pair fails at
// nginx -t, or at the reload; the helper's own rollback, nginx-restore with the list and
// nginx-restore with an empty stdin (the journal's list) never put the old key back.
func TestGuardNeverRestoresACompromisedKey(t *testing.T) {
	for _, tc := range []struct {
		name    string
		fail    func(w *deployWorld)
		cause   string
		reloads int
	}{
		{"config test fails", func(w *deployWorld) { w.testFail = 1 }, helperproto.StepConfigTest, 0},
		{"reload fails", func(w *deployWorld) { w.reloadFail = 1 }, helperproto.StepReload, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := newDeployWorld(t)
			tc.fail(w)
			in := guardedInput(w.newLeaf.FullchainPEM, w.newLeaf.KeyPEM, []string{spkiOf(t, w.leaf.Cert)}, nil)
			code, m := w.deploy(opA, in, w.oldSHA())
			require.Equal(t, 0, code, "%v", m)
			assert.Equal(t, helperproto.PhaseRestoreForbidden, m["phase"])
			assert.Equal(t, helperproto.StepRestore, m["failed_step"])
			assert.Equal(t, tc.cause, m["cause_step"])
			assert.Equal(t, helperproto.RestoreErrForbidden, m["error"])
			steps := stepsOf(m)
			assert.Equal(t, []string{tc.cause + ":failed", "restore:failed"}, steps[len(steps)-2:])
			assert.Equal(t, tc.reloads, w.reloads, "no rollback reload")
			w.assertNotOld(t)
			w.assertNoLeftovers(t)

			_, st := w.f.run("nginx-status", "--op", opA)
			assert.Equal(t, helperproto.PhaseRestoreForbidden, st["phase"])
			assert.Equal(t, helperproto.RestoreErrForbidden, st["error"])

			for _, stdin := range []string{"", restoreInput([]string{spkiOf(t, w.leaf.Cert)}, nil), restoreInput(nil, nil)} {
				code, r := w.restoreWith(opA, stdin)
				require.Equal(t, 0, code, "%v", r)
				assert.Equal(t, helperproto.PhaseRestoreForbidden, r["phase"], "answered as recorded")
				assert.Empty(t, stepsOf(r))
				w.assertNotOld(t)
			}
			assert.Equal(t, tc.reloads, w.reloads)
			assert.Contains(t, w.f.read(helperproto.BackupRoot+"/"+opA+"/journal.json"), spkiOf(t, w.leaf.Cert), "the journal keeps the list")
		})
	}
}

// A revoked leaf (its fingerprint listed) is refused like a compromised key.
func TestGuardRefusesAListedLeaf(t *testing.T) {
	w := newDeployWorld(t)
	w.testFail = 1
	in := guardedInput(w.newLeaf.FullchainPEM, w.newLeaf.KeyPEM, nil, []string{leafOf(w.leaf.Cert)})
	code, m := w.deploy(opA, in, w.oldSHA())
	require.Equal(t, 0, code, "%v", m)
	assert.Equal(t, helperproto.PhaseRestoreForbidden, m["phase"])
	w.assertNotOld(t)
}

// Lists that name other material change nothing: the rollback restores as before (and so does a
// deployment without lists, as an older Alice sends it: TestDeployRollsBackWhenConfigTestFails).
func TestGuardRestoresWhatIsNotListed(t *testing.T) {
	w := newDeployWorld(t)
	w.testFail = 1
	other := pki.NewCA("Other", pki.ECDSA256, testNow).Issue(pki.Opts{CommonName: "other.example.test"}, testNow)
	in := guardedInput(w.newLeaf.FullchainPEM, w.newLeaf.KeyPEM, []string{spkiOf(t, other.Cert)}, []string{leafOf(other.Cert)})
	code, m := w.deploy(opA, in, w.oldSHA())
	require.Equal(t, 0, code, "%v", m)
	assert.Equal(t, helperproto.PhaseRestored, m["phase"])
	w.assertPair(t, false)
}

// nginx-restore of a committed operation: the list on stdin (Alice reads it again before every
// rollback) is enough, also when the deployment carried none.
func TestGuardRestoreOfACommittedOperation(t *testing.T) {
	w := newDeployWorld(t)
	code, _ := w.deploy(opA, w.newInput(), w.oldSHA())
	require.Equal(t, 0, code)
	code, r := w.restoreWith(opA, restoreInput([]string{spkiOf(t, w.leaf.Cert)}, nil))
	require.Equal(t, 0, code, "%v", r)
	assert.Equal(t, helperproto.PhaseRestoreForbidden, r["phase"])
	assert.Equal(t, helperproto.StepRestore, r["failed_step"])
	assert.Equal(t, "", r["cause_step"])
	assert.Equal(t, []string{"restore:failed"}, stepsOf(r))
	w.assertNotOld(t)
	assert.Equal(t, 1, w.reloads, "the deployment's reload only")

	// The refused operation does not block the pair: the next deployment runs (no RECOVERY_PENDING).
	next := pki.NewCA("Next", pki.ECDSA256, testNow).Issue(pki.Opts{CommonName: "www.example.test"}, testNow)
	code, m := w.deploy(opB, input(next.FullchainPEM, next.KeyPEM), hexOf(string(w.newLeaf.FullchainPEM)))
	require.Equal(t, 0, code, "%v", m)
	assert.Equal(t, helperproto.PhaseCommitted, m["phase"])
}

// The re-sent interrupted operation (journal writing): the restore it starts checks the journal's
// list and the new input's.
func TestGuardReSentInterruptedOperation(t *testing.T) {
	for _, first := range []bool{true, false} {
		t.Run(fmt.Sprintf("list in the first send %v", first), func(t *testing.T) {
			w := newDeployWorld(t)
			list := []string{spkiOf(t, w.leaf.Cert)}
			w.f.s.afterDeployStep = func(step string) error {
				if step == helperproto.StepWriteCert {
					return errKilled
				}
				return nil
			}
			in := w.newInput()
			if first {
				in = guardedInput(w.newLeaf.FullchainPEM, w.newLeaf.KeyPEM, list, nil)
			}
			code, _ := w.deploy(opA, in, w.oldSHA())
			require.Equal(t, helperproto.ExitFailed, code)
			w.revive()
			code, m := w.deploy(opA, guardedInput(w.newLeaf.FullchainPEM, w.newLeaf.KeyPEM, list, nil), w.oldSHA())
			require.Equal(t, 0, code, "%v", m)
			assert.Equal(t, helperproto.PhaseRestoreForbidden, m["phase"])
			w.assertNotOld(t)
		})
	}
}

// An interrupted operation (killed after the key's rename) restored by nginx-restore with the list:
// the mixed pair is left as it is, the old key never comes back.
func TestGuardRestoreOfAnInterruptedOperation(t *testing.T) {
	w := newDeployWorld(t)
	w.f.s.afterDeployStep = func(step string) error {
		if step == helperproto.StepWriteKey {
			return errKilled
		}
		return nil
	}
	code, _ := w.deploy(opA, w.newInput(), w.oldSHA())
	require.Equal(t, helperproto.ExitFailed, code)
	w.revive()
	code, r := w.restoreWith(opA, restoreInput([]string{spkiOf(t, w.leaf.Cert)}, nil))
	require.Equal(t, 0, code, "%v", r)
	assert.Equal(t, helperproto.PhaseRestoreForbidden, r["phase"])
	assert.Equal(t, string(w.newLeaf.KeyPEM), w.f.read("/etc/nginx/ssl/www.key"), "the new key stays")
}

// nginx-restore's stdin must be the guard exactly: anything else is refused before anything changes.
func TestGuardRestoreInputRefusals(t *testing.T) {
	w := newDeployWorld(t)
	code, _ := w.deploy(opA, w.newInput(), w.oldSHA())
	require.Equal(t, 0, code)
	h := strings.Repeat("a", 64)
	many := make([]string, helperproto.MaxForbidden+1)
	for i := range many {
		many[i] = fmt.Sprintf("%064x", i)
	}
	for name, bad := range map[string]string{
		"not json":       "nope",
		"no leaf member": `{"forbidden_spki_sha256":[]}`,
		"unknown member": `{"forbidden_spki_sha256":[],"forbidden_leaf_sha256":[],"x":1}`,
		"short hash":     `{"forbidden_spki_sha256":["ab"],"forbidden_leaf_sha256":[]}`,
		"upper case":     `{"forbidden_spki_sha256":["` + strings.Repeat("A", 64) + `"],"forbidden_leaf_sha256":[]}`,
		"twice":          `{"forbidden_spki_sha256":["` + h + `","` + h + `"],"forbidden_leaf_sha256":[]}`,
		"absent":         `{"forbidden_spki_sha256":["absent"],"forbidden_leaf_sha256":[]}`,
		"too many":       restoreInput(many, nil),
		"trailing":       restoreInput(nil, nil) + "{}",
		"too large":      strings.Repeat(" ", helperproto.MaxRestoreInput+1),
	} {
		code, r := w.restoreWith(opA, bad)
		assert.Equal(t, helperproto.ExitRefused, code, name)
		assert.Equal(t, helperproto.CodeInvalidArgument, r["code"], name)
		w.assertPair(t, true)
	}
	assert.Equal(t, 1, w.reloads)
}

// A backup the guard cannot read (with a list) is not restored: what it holds cannot be shown safe.
func TestGuardBackupCheck(t *testing.T) {
	w := newDeployWorld(t)
	other := pki.NewCA("Other", pki.ECDSA256, testNow).Issue(pki.Opts{CommonName: "other.example.test"}, testNow)
	oldSPKI, oldLeaf := spkiOf(t, w.leaf.Cert), leafOf(w.leaf.Cert)
	g := guard{SPKI: []string{oldSPKI}}
	assert.True(t, g.forbids(w.leaf.FullchainPEM, w.leaf.KeyPEM))
	assert.True(t, guard{Leaf: []string{oldLeaf}}.forbids(w.leaf.FullchainPEM, w.leaf.KeyPEM))
	assert.True(t, g.forbids(other.FullchainPEM, w.leaf.KeyPEM), "the key file alone holds the compromised key")
	assert.True(t, g.forbids(w.leaf.FullchainPEM, other.KeyPEM), "the certificate names the compromised key")
	assert.False(t, g.forbids(other.FullchainPEM, other.KeyPEM))
	assert.True(t, g.forbids([]byte("not a certificate"), other.KeyPEM), "unreadable: refused")
	assert.True(t, g.forbids(other.FullchainPEM, []byte("not a key")), "unreadable: refused")
	assert.False(t, guard{}.forbids([]byte("x"), []byte("y")), "no list: nothing is checked")
	rsa := pki.NewCA("RSA", pki.RSA2048, testNow).Issue(pki.Opts{CommonName: "rsa.example.test", KeyType: pki.RSA2048}, testNow)
	assert.True(t, guard{SPKI: []string{spkiOf(t, rsa.Cert)}}.forbids(other.FullchainPEM, rsa.KeyPEM), "PKCS #8 RSA")
}

func TestParseDeployInputGuard(t *testing.T) {
	h1, h2 := strings.Repeat("a", 64), strings.Repeat("b", 64)
	in, err := parseDeployInput([]byte(`{"forbidden_leaf_sha256":["` + h2 + `"],"cert_pem":"c","forbidden_spki_sha256":[ "` + h1 + `" , "` + h2 + `" ],"key_pem":"k"}`))
	require.NoError(t, err)
	assert.Equal(t, "c", string(in.cert))
	assert.Equal(t, "k", string(in.key))
	assert.Equal(t, []string{h1, h2}, in.guard.SPKI)
	assert.Equal(t, []string{h2}, in.guard.Leaf)
	in, err = parseDeployInput([]byte(`{"cert_pem":"c","key_pem":"k","forbidden_spki_sha256":[],"forbidden_leaf_sha256":[]}`))
	require.NoError(t, err)
	assert.Empty(t, in.guard.SPKI)
	for _, bad := range []string{
		`{"cert_pem":"c","key_pem":"k","forbidden_spki_sha256":["` + h1 + `"],"forbidden_spki_sha256":[]}`,
		`{"cert_pem":"c","key_pem":"k","forbidden_spki_sha256":["ab"]}`,
		`{"cert_pem":"c","key_pem":"k","forbidden_spki_sha256":["` + h1 + `","` + h1 + `"]}`,
		`{"cert_pem":"c","key_pem":"k","forbidden_spki_sha256":"` + h1 + `"}`,
		`{"cert_pem":"c","key_pem":"k","forbidden_spki_sha256":[` + h1 + `]}`,
		`{"cert_pem":"c","key_pem":"k","forbidden_spki_sha256":["` + h1 + `",]}`,
		`{"cert_pem":"c","key_pem":"k","forbidden_spki_sha256":["` + h1 + `"`,
		`{"cert_pem":"c","key_pem":"k","forbidden_other":[]}`,
		`{"cert_pem":"c","forbidden_spki_sha256":[]}`,
	} {
		_, err := parseDeployInput([]byte(bad))
		assert.Error(t, err, bad)
	}
	many := make([]string, helperproto.MaxForbidden+1)
	for i := range many {
		many[i] = fmt.Sprintf("%064x", i)
	}
	_, err = parseDeployInput([]byte(guardedInput([]byte("c"), []byte("k"), many, nil)))
	assert.Error(t, err)
}

// A refused restore is final, like a restored one: the sweep removes it (and its backup) after
// NginxBackupKeep, never before.
func TestGuardSweepRemovesARefusedRestore(t *testing.T) {
	w := newDeployWorld(t)
	w.testFail = 1
	code, m := w.deploy(opA, guardedInput(w.newLeaf.FullchainPEM, w.newLeaf.KeyPEM, []string{spkiOf(t, w.leaf.Cert)}, nil), w.oldSHA())
	require.Equal(t, 0, code, "%v", m)
	require.Equal(t, helperproto.PhaseRestoreForbidden, m["phase"])
	for _, tc := range []struct {
		age  time.Duration
		kept bool
	}{{6 * 24 * time.Hour, true}, {8 * 24 * time.Hour, false}} {
		at := testNow.Add(-tc.age)
		require.NoError(t, os.Chtimes(w.opPath(opA), at, at))
		w.f.s.sweepBackups()
		if tc.kept {
			assert.DirExists(t, w.opPath(opA))
		} else {
			assert.NoDirExists(t, w.opPath(opA))
		}
	}
	w.assertNotOld(t)
}

// An invalid list is BAD_CONTENT before anything changed.
func TestDeployRefusesAnInvalidGuard(t *testing.T) {
	w := newDeployWorld(t)
	code, m := w.deploy(opA, guardedInput(w.newLeaf.FullchainPEM, w.newLeaf.KeyPEM, []string{"absent"}, nil), w.oldSHA())
	assert.Equal(t, helperproto.ExitRefused, code)
	assert.Equal(t, helperproto.CodeBadContent, m["code"])
	w.assertPair(t, false)
	assert.NoDirExists(t, w.opPath(opA))
}
