//go:build linux

package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"alice/internal/providers/linuxssh/helperproto"
	"alice/internal/testutil/pki"
)

const (
	opA = "0190f5a0-0000-7000-8000-0000000000d1"
	opB = "0190f5a0-0000-7000-8000-0000000000d2"
)

type deployWorld struct {
	*nginxWorld
	newLeaf    pki.Leaf
	reloads    int
	reloadFail int // fail the next n reloads
	testFail   int // fail the next n "nginx -t" (after nginx -T passed)
	chowns     []chownCall
}

func newDeployWorld(t *testing.T) *deployWorld {
	w := &deployWorld{nginxWorld: newNginxWorld(t)}
	ca := pki.NewCA("Deploy Test", pki.ECDSA256, testNow)
	w.newLeaf = ca.Issue(pki.Opts{CommonName: "www.example.test"}, testNow)
	inner := w.f.s.runNginx
	w.f.s.runNginx = func(ctx context.Context, args ...string) ([]byte, []byte, error) {
		if args[0] == "-t" && w.testFail > 0 {
			w.testFail--
			return nil, []byte("SSL_CTX_use_PrivateKey failed (key values mismatch)"), errors.New("exit status 1")
		}
		return inner(ctx, args...)
	}
	w.f.s.runSystemctl = func(_ context.Context, args ...string) error {
		if args[0] == "reload" {
			w.reloads++
			if w.reloadFail > 0 {
				w.reloadFail--
				return errors.New("exit status 1")
			}
		}
		return nil
	}
	w.f.s.chown = func(f *os.File, uid, gid int) error {
		w.chowns = append(w.chowns, chownCall{name: f.Name(), uid: uid, gid: gid})
		return nil
	}
	return w
}

// input is the stdin of nginx-deploy for the new pair (or any other content).
func input(certPEM, keyPEM []byte) string {
	b, _ := json.Marshal(helperproto.NginxDeployInput{CertPEM: string(certPEM), KeyPEM: string(keyPEM)})
	return string(b)
}

func (w *deployWorld) newInput() string { return input(w.newLeaf.FullchainPEM, w.newLeaf.KeyPEM) }

func (w *deployWorld) deploy(op string, in string, expect string) (int, map[string]any) {
	return w.f.runWith(in, "nginx-deploy", "--op", op, "--cert", "/etc/nginx/ssl/www.crt", "--key", "/etc/nginx/ssl/www.key",
		"--expect-cert-sha256", expect, "--content-sha256", hexOf(in))
}

func (w *deployWorld) oldSHA() string { return hexOf(string(w.leaf.FullchainPEM)) }

// The pair on disk is always one of the two consistent pairs.
func (w *deployWorld) assertPair(t *testing.T, newPair bool) {
	t.Helper()
	cert, key := w.f.read("/etc/nginx/ssl/www.crt"), w.f.read("/etc/nginx/ssl/www.key")
	if newPair {
		assert.Equal(t, string(w.newLeaf.FullchainPEM), cert)
		assert.Equal(t, string(w.newLeaf.KeyPEM), key)
		return
	}
	assert.Equal(t, string(w.leaf.FullchainPEM), cert)
	assert.Equal(t, string(w.leaf.KeyPEM), key)
}

// assertEachFile: each file holds its old or its new content (a mixed pair is possible).
func (w *deployWorld) assertEachFile(t *testing.T) {
	t.Helper()
	assert.Contains(t, []string{string(w.leaf.FullchainPEM), string(w.newLeaf.FullchainPEM)}, w.f.read("/etc/nginx/ssl/www.crt"))
	assert.Contains(t, []string{string(w.leaf.KeyPEM), string(w.newLeaf.KeyPEM)}, w.f.read("/etc/nginx/ssl/www.key"))
}

// assertNoLeftovers: the certificate directory holds only the pair (no staged file).
func (w *deployWorld) assertNoLeftovers(t *testing.T) {
	t.Helper()
	entries, err := os.ReadDir(w.f.host("/etc/nginx/ssl"))
	require.NoError(t, err)
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	assert.Equal(t, []string{"www.crt", "www.key"}, names)
}

func (w *deployWorld) opPath(op string) string { return w.f.host(helperproto.BackupRoot + "/" + op) }

// killAt makes the helper die at the n-th point (0-based) of the next runs.
func (w *deployWorld) killAt(n int) {
	calls := 0
	w.f.s.afterDeployStep = func(string) error {
		calls++
		if calls == n+1 {
			return errKilled
		}
		return nil
	}
}

func (w *deployWorld) revive() {
	w.f.s.afterDeployStep, w.f.s.killed = nil, false
	w.testFail, w.reloadFail = 0, 0
}

func stepsOf(m map[string]any) []string {
	var steps []string
	for _, s := range m["steps"].([]any) {
		sm := s.(map[string]any)
		steps = append(steps, sm["name"].(string)+":"+sm["status"].(string))
	}
	return steps
}

func TestDeployCommits(t *testing.T) {
	w := newDeployWorld(t)
	code, m := w.deploy(opA, w.newInput(), w.oldSHA())
	require.Equal(t, 0, code, "%v", m)
	assert.Equal(t, helperproto.PhaseCommitted, m["phase"])
	assert.Equal(t, helperproto.BackupRoot+"/"+opA, m["backup_dir"])
	assert.Equal(t, []string{"backup:ok", "write_key:ok", "write_cert:ok", "config_test:ok", "reload:ok"}, stepsOf(m))
	w.assertPair(t, true)
	assert.Equal(t, 1, w.reloads)
	assert.Equal(t, string(w.leaf.KeyPEM), w.f.read(helperproto.BackupRoot+"/"+opA+"/key.bak"), "the old key is backed up root-only")
	assert.Equal(t, string(w.leaf.FullchainPEM), w.f.read(helperproto.BackupRoot+"/"+opA+"/cert.bak"))
	for _, p := range []string{"key.bak", "cert.bak", "journal.json"} {
		st, err := os.Stat(w.opPath(opA) + "/" + p)
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0o600), st.Mode().Perm(), p)
	}
	st, err := os.Stat(w.opPath(opA))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o700), st.Mode().Perm())
	ks, err := os.Stat(w.f.host("/etc/nginx/ssl/www.key"))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), ks.Mode().Perm())
	cs, err := os.Stat(w.f.host("/etc/nginx/ssl/www.crt"))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o644), cs.Mode().Perm())
	w.assertNoLeftovers(t)
	assert.Contains(t, w.f.loggedLines(), "nginx-deploy /etc/nginx/ssl/www.crt")
	assert.Equal(t, []string{"-V", "-T", "-t"}, w.calls, "nginx -V and -T under the lock, then nginx -t")
}

// Requirement 9: no private key material, old or new, in an answer, the journal or the log.
func TestDeployNeverRevealsKeyMaterial(t *testing.T) {
	w := newDeployWorld(t)
	var outputs []string
	code, _ := w.deploy(opA, w.newInput(), w.oldSHA())
	require.Equal(t, 0, code)
	outputs = append(outputs, w.f.out.String())
	for _, args := range [][]string{{"nginx-status", "--op", opA}, {"nginx-restore", "--op", opA}, {"nginx-status", "--op", opA}} {
		_, _ = w.f.run(args...)
		outputs = append(outputs, w.f.out.String())
	}
	_, _ = w.deploy(opB, input(w.newLeaf.FullchainPEM, w.leaf.KeyPEM), w.oldSHA()) // a refusal (wrong key)
	outputs = append(outputs, w.f.out.String(), w.f.read(helperproto.BackupRoot+"/"+opA+"/journal.json"), strings.Join(w.f.loggedLines(), "\n"))
	for _, out := range outputs {
		assert.NotContains(t, out, privateKeyMarker)
		for _, k := range [][]byte{w.leaf.KeyPEM, w.newLeaf.KeyPEM} {
			assert.NotContains(t, out, string(k[40:80]))
		}
	}
}

// F-13, S10 and Review Focus 1: a 0644 key becomes 0600; a 0640 key (ssl-cert group) stays 0640;
// a certificate never gets wider than 0644.
func TestDeployModes(t *testing.T) {
	for _, tc := range []struct{ before, after os.FileMode }{{0o644, 0o600}, {0o640, 0o640}, {0o600, 0o600}, {0o400, 0o600}, {0o440, 0o600},
		{0o604, 0o600}, {0o660, 0o600}, {0o777, 0o600}} {
		w := newDeployWorld(t)
		require.NoError(t, os.Chmod(w.f.host("/etc/nginx/ssl/www.key"), tc.before))
		code, m := w.deploy(opA, w.newInput(), w.oldSHA())
		require.Equal(t, 0, code, "%v", m)
		st, err := os.Stat(w.f.host("/etc/nginx/ssl/www.key"))
		require.NoError(t, err)
		assert.Equal(t, tc.after, st.Mode().Perm(), "key from %o", tc.before)
		code, m = w.f.run("nginx-restore", "--op", opA)
		require.Equal(t, 0, code, "%v", m)
		st, err = os.Stat(w.f.host("/etc/nginx/ssl/www.key"))
		require.NoError(t, err)
		assert.Equal(t, tc.before, st.Mode().Perm(), "nginx-restore puts the exact old mode back")
	}
	for _, tc := range []struct{ before, after os.FileMode }{{0o644, 0o644}, {0o600, 0o600}, {0o664, 0o644}, {0o755, 0o644}, {0o444, 0o444}} {
		w := newDeployWorld(t)
		require.NoError(t, os.Chmod(w.f.host("/etc/nginx/ssl/www.crt"), tc.before))
		code, m := w.deploy(opA, w.newInput(), w.oldSHA())
		require.Equal(t, 0, code, "%v", m)
		st, err := os.Stat(w.f.host("/etc/nginx/ssl/www.crt"))
		require.NoError(t, err)
		assert.Equal(t, tc.after, st.Mode().Perm(), "certificate from %o", tc.before)
	}
	assert.Equal(t, uint32(0o640), keyMode(0o4640|0o1000), "special bits never count")
	assert.Equal(t, uint32(0o600), keyMode(0o6644))
	assert.Equal(t, uint32(0o644), certMode(0o6777))
}

func TestDeployKeepsOwnerAndGroup(t *testing.T) {
	w := newDeployWorld(t)
	code, _ := w.deploy(opA, w.newInput(), w.oldSHA())
	require.Equal(t, 0, code)
	require.Len(t, w.chowns, 2, "key then certificate")
	st, err := os.Stat(w.f.host(helperproto.BackupRoot + "/" + opA + "/key.bak"))
	require.NoError(t, err)
	uid, gid := owner(st)
	assert.Equal(t, uid, w.chowns[0].uid)
	assert.Equal(t, gid, w.chowns[0].gid)
	assert.Equal(t, stagedName(opA, kindKey), w.chowns[0].name)
	assert.Equal(t, stagedName(opA, kindCert), w.chowns[1].name)
}

// Review Focus 1: the write lands on the link's target; the link stays a link.
func TestDeployWritesThroughTheLinkTarget(t *testing.T) {
	w := newDeployWorld(t)
	w.f.mkdir("/etc/nginx/archive", 0o755)
	require.NoError(t, os.Rename(w.f.host("/etc/nginx/ssl/www.crt"), w.f.host("/etc/nginx/archive/www3.crt")))
	require.NoError(t, os.Symlink("../archive/www3.crt", w.f.host("/etc/nginx/ssl/www.crt")))
	code, m := w.deploy(opA, w.newInput(), w.oldSHA())
	require.Equal(t, 0, code, "%v", m)
	target, err := os.Readlink(w.f.host("/etc/nginx/ssl/www.crt"))
	require.NoError(t, err)
	assert.Equal(t, "../archive/www3.crt", target)
	assert.Equal(t, string(w.newLeaf.FullchainPEM), w.f.read("/etc/nginx/archive/www3.crt"))
	code, _ = w.f.run("nginx-restore", "--op", opA)
	require.Equal(t, 0, code)
	assert.Equal(t, string(w.leaf.FullchainPEM), w.f.read("/etc/nginx/archive/www3.crt"))
}

func TestDeployIsIdempotentPerOperation(t *testing.T) {
	w := newDeployWorld(t)
	in := w.newInput()
	code, _ := w.deploy(opA, in, w.oldSHA())
	require.Equal(t, 0, code)
	code, m := w.deploy(opA, in, w.oldSHA())
	require.Equal(t, 0, code, "the journal answers a repeated operation")
	assert.Equal(t, helperproto.PhaseCommitted, m["phase"])
	assert.Equal(t, 1, w.reloads, "nothing is done twice")
	// A replay of the operation id with another request is refused, and changes nothing.
	code, m = w.deploy(opA, input(w.leaf.FullchainPEM, w.leaf.KeyPEM), hexOf(string(w.newLeaf.FullchainPEM)))
	assert.Equal(t, helperproto.ExitRefused, code)
	assert.Equal(t, helperproto.CodeInvalidArgument, m["code"])
	w.assertPair(t, true)
}

// §12.9 "Same cert already deployed": no write, no reload.
func TestDeployUnchangedWhenTheFilesAlreadyMatch(t *testing.T) {
	w := newDeployWorld(t)
	code, m := w.deploy(opA, input(w.leaf.FullchainPEM, w.leaf.KeyPEM), w.oldSHA())
	require.Equal(t, 0, code, "%v", m)
	assert.Equal(t, helperproto.PhaseUnchanged, m["phase"])
	assert.Equal(t, 0, w.reloads)
	_, st := w.f.run("nginx-status", "--op", opA)
	assert.Equal(t, helperproto.PhaseUnchanged, st["phase"])
	code, r := w.f.run("nginx-restore", "--op", opA)
	require.Equal(t, 0, code)
	assert.Equal(t, helperproto.PhaseUnchanged, r["phase"])
	assert.Equal(t, 0, w.reloads)
}

// The key and certificate forms Nginx loads are accepted; the key must belong to the leaf.
func TestDeployAcceptsKeyForms(t *testing.T) {
	ca := pki.NewCA("Forms", pki.ECDSA256, testNow)
	rsaLeaf := ca.Issue(pki.Opts{CommonName: "www.example.test", KeyType: pki.RSA2048}, testNow)
	ecLeaf := ca.Issue(pki.Opts{CommonName: "www.example.test"}, testNow)
	edLeaf := ca.Issue(pki.Opts{CommonName: "www.example.test", KeyType: pki.Ed25519}, testNow)
	for name, tc := range map[string]struct {
		leaf pki.Leaf
		key  []byte
	}{
		"RSA PKCS #1":    {rsaLeaf, pki.KeyPEMPKCS1(rsaLeaf.Key.(*rsa.PrivateKey))},
		"RSA PKCS #8":    {rsaLeaf, rsaLeaf.KeyPEM},
		"ECDSA SEC 1":    {ecLeaf, pki.KeyPEMSEC1(ecLeaf.Key.(*ecdsa.PrivateKey))},
		"Ed25519 PKCS 8": {edLeaf, edLeaf.KeyPEM},
	} {
		t.Run(name, func(t *testing.T) {
			w := newDeployWorld(t)
			code, m := w.deploy(opA, input(tc.leaf.FullchainPEM, tc.key), w.oldSHA())
			require.Equal(t, 0, code, "%v", m)
			assert.Equal(t, string(tc.key), w.f.read("/etc/nginx/ssl/www.key"))
		})
	}
}

// Every refusal changes nothing: no backup directory, no file, no reload (F-02, F-10, F-11,
// F-12, A-13, CAS, content checks).
func TestDeployRefusesBeforeChangingAnything(t *testing.T) {
	type tc struct {
		name  string
		setup func(w *deployWorld) (in string, args []string)
		exit  int
		code  string
	}
	std := func(w *deployWorld, in string) []string {
		return []string{"--op", opA, "--cert", "/etc/nginx/ssl/www.crt", "--key", "/etc/nginx/ssl/www.key",
			"--expect-cert-sha256", w.oldSHA(), "--content-sha256", hexOf(in)}
	}
	good := func(w *deployWorld) string { return w.newInput() }
	content := func(f func(w *deployWorld) string) func(w *deployWorld) (string, []string) {
		return func(w *deployWorld) (string, []string) {
			in := f(w)
			return in, std(w, in)
		}
	}
	other := pki.NewCA("Other", pki.ECDSA256, testNow).Issue(pki.Opts{CommonName: "www.example.test"}, testNow)
	for _, c := range []tc{
		{"content mismatch", func(w *deployWorld) (string, []string) {
			in := good(w)
			a := std(w, in)
			a[9] = strings.Repeat("0", 64)
			return in, a
		}, helperproto.ExitPrecondition, helperproto.CodeContentMismatch},
		{"truncated stdin", func(w *deployWorld) (string, []string) {
			in := good(w)
			return in[:len(in)/2], std(w, in)
		}, helperproto.ExitPrecondition, helperproto.CodeContentMismatch},
		{"stdin over the limit", content(func(*deployWorld) string { return strings.Repeat(" ", helperproto.MaxDeployInput+1) }),
			helperproto.ExitRefused, helperproto.CodeTooLarge},
		{"certificate over the file limit", content(func(w *deployWorld) string {
			return input(append(append([]byte{}, w.newLeaf.FullchainPEM...), strings.Repeat("\n", helperproto.MaxCertFileSize)...), w.newLeaf.KeyPEM)
		}), helperproto.ExitRefused, helperproto.CodeTooLarge},
		{"key in the certificate", content(func(w *deployWorld) string { return input(w.newLeaf.KeyPEM, w.newLeaf.KeyPEM) }),
			helperproto.ExitRefused, helperproto.CodeBadContent},
		{"certificate in the key", content(func(w *deployWorld) string { return input(w.newLeaf.FullchainPEM, w.newLeaf.FullchainPEM) }),
			helperproto.ExitRefused, helperproto.CodeBadContent},
		{"a key after the certificates", content(func(w *deployWorld) string {
			return input(append(append([]byte{}, w.newLeaf.FullchainPEM...), w.newLeaf.KeyPEM...), w.newLeaf.KeyPEM)
		}), helperproto.ExitRefused, helperproto.CodeBadContent},
		{"two keys", content(func(w *deployWorld) string {
			return input(w.newLeaf.FullchainPEM, append(append([]byte{}, w.newLeaf.KeyPEM...), w.leaf.KeyPEM...))
		}), helperproto.ExitRefused, helperproto.CodeBadContent},
		{"the key of another certificate", content(func(w *deployWorld) string { return input(w.newLeaf.FullchainPEM, other.KeyPEM) }),
			helperproto.ExitRefused, helperproto.CodeBadContent},
		{"the key of the intermediate's leaf only", content(func(w *deployWorld) string {
			return input(append(append([]byte{}, other.CertPEM...), w.newLeaf.FullchainPEM...), w.newLeaf.KeyPEM)
		}), helperproto.ExitRefused, helperproto.CodeBadContent},
		{"an encrypted key", content(func(w *deployWorld) string { return input(w.newLeaf.FullchainPEM, pki.EncryptedKeyPEM(w.newLeaf)) }),
			helperproto.ExitRefused, helperproto.CodeBadContent},
		{"text before the certificate", content(func(w *deployWorld) string {
			return input(append([]byte("include /etc/shadow;\n"), w.newLeaf.FullchainPEM...), w.newLeaf.KeyPEM)
		}), helperproto.ExitRefused, helperproto.CodeBadContent},
		{"text after the key", content(func(w *deployWorld) string {
			return input(w.newLeaf.FullchainPEM, append(append([]byte{}, w.newLeaf.KeyPEM...), "x"...))
		}), helperproto.ExitRefused, helperproto.CodeBadContent},
		{"a block that is not a certificate", content(func(w *deployWorld) string {
			return input([]byte("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"), w.newLeaf.KeyPEM)
		}), helperproto.ExitRefused, helperproto.CodeBadContent},
		{"a malformed block before a good one", content(func(w *deployWorld) string {
			return input(append([]byte("-----BEGIN CERTIFICATE-----\n!!\n"), w.newLeaf.FullchainPEM...), w.newLeaf.KeyPEM)
		}), helperproto.ExitRefused, helperproto.CodeBadContent},
		{"unknown JSON field", content(func(*deployWorld) string { return `{"cert_pem":"x","key_pem":"y","extra":1}` }),
			helperproto.ExitRefused, helperproto.CodeBadContent},
		{"a member twice", content(func(w *deployWorld) string {
			k, _ := json.Marshal(string(w.newLeaf.KeyPEM))
			return strings.TrimSuffix(w.newInput(), "}") + `,"key_pem":` + string(k) + "}"
		}), helperproto.ExitRefused, helperproto.CodeBadContent},
		{"text after the JSON", content(func(w *deployWorld) string { return w.newInput() + "{}" }),
			helperproto.ExitRefused, helperproto.CodeBadContent},
		{"configuration already broken (F-02)", func(w *deployWorld) (string, []string) {
			w.tFails = "unexpected \"}\""
			in := good(w)
			return in, std(w, in)
		}, helperproto.ExitPrecondition, helperproto.CodeConfigInvalid},
		{"nginx missing", func(w *deployWorld) (string, []string) {
			w.missing = true
			in := good(w)
			return in, std(w, in)
		}, helperproto.ExitPrecondition, helperproto.CodeNginxNotFound},
		{"pair not in the configuration", func(w *deployWorld) (string, []string) {
			in := good(w)
			a := std(w, in)
			a[3], a[5] = "/etc/nginx/ssl/www.key", "/etc/nginx/ssl/www.crt"
			return in, a
		}, helperproto.ExitPrecondition, helperproto.CodeConfigChanged},
		{"a pair that only a writable file names (S1)", func(w *deployWorld) (string, []string) {
			require.NoError(t, os.Chmod(w.f.host("/etc/nginx/conf.d/www.conf"), 0o666))
			in := good(w)
			return in, std(w, in)
		}, helperproto.ExitPrecondition, helperproto.CodeConfigChanged},
		{"a combined certificate and key file", func(w *deployWorld) (string, []string) {
			in := good(w)
			a := std(w, in)
			a[3], a[5] = "/etc/nginx/ssl/both.pem", "/etc/nginx/ssl/both.pem"
			return in, a
		}, helperproto.ExitRefused, helperproto.CodeInvalidArgument},
		{"file changed since discovery", func(w *deployWorld) (string, []string) {
			in := good(w)
			a := std(w, in)
			a[7] = strings.Repeat("a", 64)
			return in, a
		}, helperproto.ExitPrecondition, helperproto.CodeHashMismatch},
		{"no free space (F-10; F-11: the backup directory is checked the same way)", func(w *deployWorld) (string, []string) {
			w.f.s.statfs = func(int) (int64, error) { return 1 << 20, nil }
			in := good(w)
			return in, std(w, in)
		}, helperproto.ExitPrecondition, helperproto.CodeNoSpace},
		{"user-writable directory", func(w *deployWorld) (string, []string) {
			require.NoError(t, os.Chmod(w.f.host("/etc/nginx/ssl"), 0o777))
			in := good(w)
			return in, std(w, in)
		}, helperproto.ExitRefused, helperproto.CodePathNotAllowed},
		{"hard link", func(w *deployWorld) (string, []string) {
			require.NoError(t, os.Link(w.f.host("/etc/nginx/ssl/www.key"), w.f.host("/etc/nginx/key-copy.key")))
			in := good(w)
			return in, std(w, in)
		}, helperproto.ExitRefused, helperproto.CodeUnsafeFile},
		{"key file missing", func(w *deployWorld) (string, []string) {
			require.NoError(t, os.Rename(w.f.host("/etc/nginx/ssl/www.key"), w.f.host("/etc/nginx/www.key.away")))
			in := good(w)
			return in, std(w, in)
		}, helperproto.ExitPrecondition, helperproto.CodeNotFound},
		{"key file on FUSE", func(w *deployWorld) (string, []string) {
			w.magicAt("/etc/nginx/ssl/www.key", unix.FUSE_SUPER_MAGIC)
			in := good(w)
			return in, std(w, in)
		}, helperproto.ExitRefused, helperproto.CodePathNotAllowed},
		{"same path twice", func(w *deployWorld) (string, []string) {
			in := good(w)
			a := std(w, in)
			a[5] = a[3]
			return in, a
		}, helperproto.ExitRefused, helperproto.CodeInvalidArgument},
	} {
		t.Run(c.name, func(t *testing.T) {
			w := newDeployWorld(t)
			in, args := c.setup(w)
			code, m := w.f.runWith(in, append([]string{"nginx-deploy"}, args...)...)
			assert.Equal(t, c.exit, code, "%v", m)
			assert.Equal(t, c.code, m["code"])
			_ = os.Chmod(w.f.host("/etc/nginx/ssl"), 0o755)
			if c.name == "key file missing" {
				require.NoError(t, os.Rename(w.f.host("/etc/nginx/www.key.away"), w.f.host("/etc/nginx/ssl/www.key")))
			}
			w.assertPair(t, false)
			w.assertNoLeftovers(t)
			assert.Equal(t, 0, w.reloads)
			_, err := os.Stat(w.opPath(opA))
			assert.True(t, errors.Is(err, os.ErrNotExist), "no backup directory")
			assert.NotContains(t, w.calls, "-t")
		})
	}
}

// Attack: the key path of a supported pair is a root link into a directory a user can write, or
// to /etc/shadow. Neither is ever written.
func TestAttackKeyOutsideRootControl(t *testing.T) {
	w := newDeployWorld(t)
	w.f.mkdir("/srv", 0o755)
	w.f.mkdir("/srv/keys", 0o777)
	w.f.write("/srv/keys/www.key", string(w.leaf.KeyPEM), 0o600)
	require.NoError(t, os.Remove(w.f.host("/etc/nginx/ssl/www.key")))
	w.f.symlink("/srv/keys/www.key", "/etc/nginx/ssl/www.key")
	code, m := w.deploy(opA, w.newInput(), w.oldSHA())
	assert.Equal(t, helperproto.ExitRefused, code)
	assert.Equal(t, helperproto.CodePathNotAllowed, m["code"])
	assert.Equal(t, string(w.leaf.KeyPEM), w.f.read("/srv/keys/www.key"))
	entries, err := os.ReadDir(w.f.host("/srv/keys"))
	require.NoError(t, err)
	assert.Len(t, entries, 1, "no staged file in the user's directory")

	w = newDeployWorld(t)
	w.f.write("/etc/shadow", "root:$6$secret-hash:19000:0:99999:7:::\n", 0o600)
	require.NoError(t, os.Remove(w.f.host("/etc/nginx/ssl/www.key")))
	w.f.symlink("/etc/shadow", "/etc/nginx/ssl/www.key")
	code, m = w.deploy(opA, w.newInput(), w.oldSHA())
	assert.Equal(t, helperproto.ExitRefused, code)
	assert.Equal(t, helperproto.CodePathNotAllowed, m["code"])
	assert.Equal(t, "root:$6$secret-hash:19000:0:99999:7:::\n", w.f.read("/etc/shadow"))
}

// F-01 at helper level: nginx -t fails after the write; both files come back.
func TestDeployRollsBackWhenConfigTestFails(t *testing.T) {
	w := newDeployWorld(t)
	w.testFail = 1
	code, m := w.deploy(opA, w.newInput(), w.oldSHA())
	require.Equal(t, 0, code, "%v", m)
	assert.Equal(t, helperproto.PhaseRestored, m["phase"])
	assert.Equal(t, helperproto.StepConfigTest, m["failed_step"])
	assert.Equal(t, helperproto.ConfigErrKeyMismatch, m["error"])
	assert.Equal(t, []string{"backup:ok", "write_key:ok", "write_cert:ok", "config_test:failed", "restore:ok", "rollback_config_test:ok",
		"rollback_reload:ok"}, stepsOf(m))
	w.assertPair(t, false)
	w.assertNoLeftovers(t)
	assert.Equal(t, 1, w.reloads, "the rollback reload")
}

// A timed-out or killed nginx -t is a failure (never committed), but not "configuration invalid".
func TestDeployKilledConfigTestIsNotAConfigurationError(t *testing.T) {
	w := newDeployWorld(t)
	inner := w.f.s.runNginx
	killed := false
	w.f.s.runNginx = func(ctx context.Context, args ...string) ([]byte, []byte, error) {
		if args[0] == "-t" && !killed {
			killed = true
			return nil, []byte("nginx: [emerg] whatever"), fmt.Errorf("%w: signal: killed", errProgramKilled)
		}
		return inner(ctx, args...)
	}
	code, m := w.deploy(opA, w.newInput(), w.oldSHA())
	require.Equal(t, 0, code, "%v", m)
	assert.Equal(t, helperproto.PhaseRestored, m["phase"])
	assert.Equal(t, helperproto.StepConfigTest, m["failed_step"])
	assert.Equal(t, "", m["error"])
	w.assertPair(t, false)
}

// F-03 and F-04.
func TestDeployReloadFailures(t *testing.T) {
	w := newDeployWorld(t)
	w.reloadFail = 1
	_, m := w.deploy(opA, w.newInput(), w.oldSHA())
	assert.Equal(t, helperproto.PhaseRestored, m["phase"])
	assert.Equal(t, helperproto.StepReload, m["failed_step"])
	w.assertPair(t, false)

	w = newDeployWorld(t)
	w.reloadFail = 2
	_, m = w.deploy(opA, w.newInput(), w.oldSHA())
	assert.Equal(t, helperproto.PhaseRestoreFailed, m["phase"])
	assert.Equal(t, helperproto.StepRollbackReload, m["failed_step"])
	w.assertPair(t, false) // "Files are back in place but Nginx did not reload"
	_, st := w.f.run("nginx-status", "--op", opA)
	assert.Equal(t, helperproto.PhaseRestoreFailed, st["phase"])
	code, r := w.f.run("nginx-restore", "--op", opA)
	require.Equal(t, 0, code, "%v", r)
	assert.Equal(t, helperproto.PhaseRestored, r["phase"], "a failed rollback reload is retried by nginx-restore")
	assert.Equal(t, []string{"restore:ok", "rollback_config_test:ok", "rollback_reload:ok"}, stepsOf(r))
}

// Review Focus 3, F-66 on the server side: the helper dies after each step; status and restore
// always end with a consistent pair.
func TestDeployKilledAtEveryStepRecovers(t *testing.T) {
	for _, tc := range []struct {
		step     string
		phase    string // nginx-status after the kill
		newPair  bool   // the pair on disk before the restore
		restored string // nginx-restore's phase
	}{
		{helperproto.StepBackup, helperproto.PhasePrepared, false, helperproto.PhasePrepared},
		{helperproto.StepWriteKey, helperproto.PhaseWriting, false, helperproto.PhaseRestored},
		{helperproto.StepWriteCert, helperproto.PhaseWriting, true, helperproto.PhaseRestored},
		{helperproto.StepConfigTest, helperproto.PhaseWriting, true, helperproto.PhaseRestored},
		{helperproto.StepReload, helperproto.PhaseWriting, true, helperproto.PhaseRestored},
	} {
		t.Run(tc.step, func(t *testing.T) {
			w := newDeployWorld(t)
			w.f.s.afterDeployStep = func(step string) error {
				if step == tc.step {
					return errKilled
				}
				return nil
			}
			code, _ := w.deploy(opA, w.newInput(), w.oldSHA())
			require.Equal(t, helperproto.ExitFailed, code)
			w.revive()
			_, st := w.f.run("nginx-status", "--op", opA)
			assert.Equal(t, tc.phase, st["phase"])
			assert.Equal(t, false, st["active"])
			if tc.step == helperproto.StepWriteKey {
				// Killed after the key's rename: the key is new, the certificate old — the one moment a
				// mixed pair exists on disk, and exactly what nginx-restore repairs.
				assert.Equal(t, string(w.newLeaf.KeyPEM), w.f.read("/etc/nginx/ssl/www.key"))
				assert.Equal(t, string(w.leaf.FullchainPEM), w.f.read("/etc/nginx/ssl/www.crt"))
			} else {
				w.assertPair(t, tc.newPair)
			}
			code, r := w.f.run("nginx-restore", "--op", opA)
			require.Equal(t, 0, code, "%v", r)
			assert.Equal(t, tc.restored, r["phase"])
			w.assertPair(t, false)
		})
	}
}

// crashScenarios are the paths through nginx-deploy the crash matrices kill at every point of.
var crashScenarios = []struct {
	name  string
	setup func(w *deployWorld)
}{
	{"commit", func(*deployWorld) {}},
	{"config test fails", func(w *deployWorld) { w.testFail = 1 }},
	{"reload fails", func(w *deployWorld) { w.reloadFail = 1 }},
	{"rollback reload fails", func(w *deployWorld) { w.reloadFail = 2 }},
}

// deployPoints records every point of one nginx-deploy run of a scenario.
func deployPoints(t *testing.T, setup func(w *deployWorld)) []string {
	w := newDeployWorld(t)
	setup(w)
	var points []string
	w.f.s.afterDeployStep = func(p string) error {
		points = append(points, p)
		return nil
	}
	_, _ = w.deploy(opA, w.newInput(), w.oldSHA())
	require.NotEmpty(t, points)
	return points
}

// checkRecovery is what Alice's recovery does after an uncertain outcome: nginx-status, then
// nginx-restore. The status never contradicts the disk, and the restore always ends with the old
// pair, no staged file and a final phase.
func (w *deployWorld) checkRecovery(t *testing.T) {
	t.Helper()
	code, st := w.f.run("nginx-status", "--op", opA)
	require.Equal(t, 0, code, "%v", st)
	assert.Equal(t, false, st["active"])
	phase := st["phase"].(string)
	switch phase {
	case helperproto.PhaseNone, helperproto.PhasePrepared, helperproto.PhaseRestored:
		w.assertPair(t, false)
	case helperproto.PhaseCommitted:
		w.assertPair(t, true)
	default:
		w.assertEachFile(t)
	}
	code, r := w.f.run("nginx-restore", "--op", opA)
	if phase == helperproto.PhaseNone {
		assert.Equal(t, helperproto.ExitPrecondition, code)
		assert.Equal(t, helperproto.CodeUnknownOp, r["code"])
	} else {
		require.Equal(t, 0, code, "%s: %v", phase, r)
		assert.Contains(t, []any{helperproto.PhasePrepared, helperproto.PhaseRestored}, r["phase"], phase)
	}
	w.assertPair(t, false)
	w.assertNoLeftovers(t)
	_, st = w.f.run("nginx-status", "--op", opA)
	assert.Contains(t, []any{helperproto.PhaseNone, helperproto.PhasePrepared, helperproto.PhaseRestored}, st["phase"])
}

// Requirement 3: the helper is killed at every point of every path of nginx-deploy (each journal
// write before and after its rename, each backup, each staged file before and after its content,
// each rename, each step, each point of the rollback); nginx-status and nginx-restore always end
// with the complete old pair and nothing left behind.
func TestDeployCrashMatrix(t *testing.T) {
	for _, sc := range crashScenarios {
		points := deployPoints(t, sc.setup)
		for i, p := range points {
			t.Run(fmt.Sprintf("%s/%02d %s", sc.name, i, p), func(t *testing.T) {
				w := newDeployWorld(t)
				sc.setup(w)
				w.killAt(i)
				code, m := w.deploy(opA, w.newInput(), w.oldSHA())
				require.Equal(t, helperproto.ExitFailed, code, "%v", m)
				w.revive()
				w.checkRecovery(t)
			})
		}
	}
}

// The same kills, then Alice sends the same deployment again: an interrupted operation is rolled
// back and answered, an operation that replaced nothing runs again; the answer always matches the
// pair on disk.
func TestDeployCrashThenTheSameDeploymentAgain(t *testing.T) {
	for _, sc := range crashScenarios {
		points := deployPoints(t, sc.setup)
		for i, p := range points {
			t.Run(fmt.Sprintf("%s/%02d %s", sc.name, i, p), func(t *testing.T) {
				w := newDeployWorld(t)
				sc.setup(w)
				w.killAt(i)
				code, _ := w.deploy(opA, w.newInput(), w.oldSHA())
				require.Equal(t, helperproto.ExitFailed, code)
				w.revive()
				code, m := w.deploy(opA, w.newInput(), w.oldSHA())
				require.Equal(t, 0, code, "%v", m)
				switch m["phase"] {
				case helperproto.PhaseCommitted:
					w.assertPair(t, true)
				case helperproto.PhaseRestored, helperproto.PhaseRestoreFailed:
					w.assertPair(t, false)
				default:
					t.Fatalf("unexpected phase %v", m["phase"])
				}
				w.assertNoLeftovers(t)
			})
		}
	}
}

// The helper is killed at every point of nginx-restore after a commit; a second nginx-restore
// always ends with the old pair.
func TestRestoreCrashMatrix(t *testing.T) {
	var points []string
	{
		w := newDeployWorld(t)
		code, _ := w.deploy(opA, w.newInput(), w.oldSHA())
		require.Equal(t, 0, code)
		w.f.s.afterDeployStep = func(p string) error {
			points = append(points, p)
			return nil
		}
		code, _ = w.f.run("nginx-restore", "--op", opA)
		require.Equal(t, 0, code)
	}
	require.NotEmpty(t, points)
	for i, p := range points {
		t.Run(fmt.Sprintf("%02d %s", i, p), func(t *testing.T) {
			w := newDeployWorld(t)
			code, _ := w.deploy(opA, w.newInput(), w.oldSHA())
			require.Equal(t, 0, code)
			w.killAt(i)
			code, _ = w.f.run("nginx-restore", "--op", opA)
			require.Equal(t, helperproto.ExitFailed, code)
			w.revive()
			_, st := w.f.run("nginx-status", "--op", opA)
			assert.Contains(t, []any{helperproto.PhaseCommitted, helperproto.PhaseRestoring, helperproto.PhaseRestored}, st["phase"])
			if st["phase"] == helperproto.PhaseCommitted {
				w.assertPair(t, true)
			} else {
				w.assertEachFile(t)
			}
			code, r := w.f.run("nginx-restore", "--op", opA)
			require.Equal(t, 0, code, "%v", r)
			assert.Equal(t, helperproto.PhaseRestored, r["phase"])
			w.assertPair(t, false)
			w.assertNoLeftovers(t)
		})
	}
}

// S2: the staged key file is created root-only (0600, the helper's user, empty) before any content
// is written, under the operation's deterministic name; a leftover of a dead helper is removed.
func TestDeployStagedKeyIsRootOnlyBeforeItsContent(t *testing.T) {
	w := newDeployWorld(t)
	checked := false
	w.f.s.afterDeployStep = func(p string) error {
		if p == "stage "+stagedName(opA, kindKey) {
			checked = true
			var st unix.Stat_t
			require.NoError(t, unix.Stat(w.f.host("/etc/nginx/ssl/"+stagedName(opA, kindKey)), &st))
			assert.Equal(t, uint32(0o600), st.Mode&0o777)
			assert.Equal(t, uint32(os.Geteuid()), st.Uid) //nolint:gosec // G115: a uid fits
			assert.Zero(t, st.Size)
		}
		return nil
	}
	w.f.write("/etc/nginx/ssl/"+stagedName(opA, kindKey), "left by a dead helper", 0o644)
	code, m := w.deploy(opA, w.newInput(), w.oldSHA())
	require.Equal(t, 0, code, "%v", m)
	assert.True(t, checked)
	w.assertNoLeftovers(t)
}

func TestRestoreAfterACommitAndItsRefusals(t *testing.T) {
	w := newDeployWorld(t)
	code, _ := w.deploy(opA, w.newInput(), w.oldSHA())
	require.Equal(t, 0, code)
	code, r := w.f.run("nginx-restore", "--op", opA)
	require.Equal(t, 0, code, "%v", r)
	assert.Equal(t, helperproto.PhaseRestored, r["phase"])
	assert.Equal(t, []string{"restore:ok", "rollback_config_test:ok", "rollback_reload:ok"}, stepsOf(r))
	w.assertPair(t, false)
	code, r = w.f.run("nginx-restore", "--op", opA)
	require.Equal(t, 0, code, "idempotent")
	assert.Equal(t, helperproto.PhaseRestored, r["phase"])
	assert.Equal(t, 2, w.reloads, "the second restore did nothing")

	w = newDeployWorld(t)
	code, _ = w.deploy(opA, w.newInput(), w.oldSHA())
	require.Equal(t, 0, code)
	w.f.write("/etc/nginx/ssl/www.crt", "someone else's certificate", 0o644)
	code, r = w.f.run("nginx-restore", "--op", opA)
	assert.Equal(t, helperproto.ExitPrecondition, code)
	assert.Equal(t, helperproto.CodeHashMismatch, r["code"])
	assert.Equal(t, "someone else's certificate", w.f.read("/etc/nginx/ssl/www.crt"), "never clobbered")
	assert.Equal(t, string(w.newLeaf.KeyPEM), w.f.read("/etc/nginx/ssl/www.key"), "and the key is not restored alone")
	_, st := w.f.run("nginx-status", "--op", opA)
	assert.Equal(t, helperproto.PhaseRestoreFailed, st["phase"])

	code, r = w.f.run("nginx-restore", "--op", "0190f5a0-0000-7000-8000-0000000000ee")
	assert.Equal(t, helperproto.ExitPrecondition, code)
	assert.Equal(t, helperproto.CodeUnknownOp, r["code"])
	_, st = w.f.run("nginx-status", "--op", "0190f5a0-0000-7000-8000-0000000000ee")
	assert.Equal(t, helperproto.PhaseNone, st["phase"])
	assert.Equal(t, false, st["active"])
}

// Attack: an old operation is restored after a newer deployment replaced the pair again. The newer
// pair is never clobbered, not even half of it (the newer deployment reused the key).
func TestAttackRestoreOverANewerDeployment(t *testing.T) {
	w := newDeployWorld(t)
	code, _ := w.deploy(opA, w.newInput(), w.oldSHA())
	require.Equal(t, 0, code)
	third := pki.NewCA("Third", pki.ECDSA256, testNow).Issue(pki.Opts{CommonName: "www.example.test", Key: w.newLeaf.Key}, testNow)
	code, m := w.f.runWith(input(third.FullchainPEM, w.newLeaf.KeyPEM), "nginx-deploy", "--op", opB, "--cert", "/etc/nginx/ssl/www.crt",
		"--key", "/etc/nginx/ssl/www.key", "--expect-cert-sha256", hexOf(string(w.newLeaf.FullchainPEM)),
		"--content-sha256", hexOf(input(third.FullchainPEM, w.newLeaf.KeyPEM)))
	require.Equal(t, 0, code, "%v", m)
	code, r := w.f.run("nginx-restore", "--op", opA)
	assert.Equal(t, helperproto.ExitPrecondition, code)
	assert.Equal(t, helperproto.CodeSuperseded, r["code"], "fix round 1: refused before the files are even compared")
	assert.Equal(t, string(third.FullchainPEM), w.f.read("/etc/nginx/ssl/www.crt"))
	assert.Equal(t, string(w.newLeaf.KeyPEM), w.f.read("/etc/nginx/ssl/www.key"), "the shared key stays")
}

// The key or the certificate changes (as root could) between the read and the rename.
func TestDeployCompareAndSwapBeforeEachRename(t *testing.T) {
	w := newDeployWorld(t)
	w.f.s.beforeRename = func() error {
		w.f.write("/etc/nginx/ssl/www.key", "edited in place", 0o600)
		return nil
	}
	code, m := w.deploy(opA, w.newInput(), w.oldSHA())
	assert.Equal(t, helperproto.ExitPrecondition, code, "%v", m)
	assert.Equal(t, helperproto.CodeHashMismatch, m["code"])
	assert.Equal(t, "edited in place", w.f.read("/etc/nginx/ssl/www.key"))
	assert.Equal(t, string(w.leaf.FullchainPEM), w.f.read("/etc/nginx/ssl/www.crt"))
	w.assertNoLeftovers(t)
	_, st := w.f.run("nginx-status", "--op", opA)
	assert.Equal(t, helperproto.PhaseNone, st["phase"], "nothing was replaced: a refusal leaves no operation behind")
	assert.Equal(t, 0, w.reloads)

	// After the key's rename the certificate changes: the deployment fails; nothing of someone else's
	// is clobbered and the outcome is recorded.
	w = newDeployWorld(t)
	n := 0
	w.f.s.beforeRename = func() error {
		if n++; n == 2 {
			w.f.write("/etc/nginx/ssl/www.crt", "edited in place", 0o644)
		}
		return nil
	}
	code, m = w.deploy(opA, w.newInput(), w.oldSHA())
	require.Equal(t, 0, code, "%v", m)
	assert.Equal(t, helperproto.PhaseRestoreFailed, m["phase"])
	assert.Equal(t, helperproto.StepWriteCert, m["failed_step"])
	assert.Equal(t, helperproto.RestoreErrFileChanged, m["error"])
	assert.Equal(t, "edited in place", w.f.read("/etc/nginx/ssl/www.crt"))
}

// The helper's budget ends before the first rename: nothing is replaced and the answer is a
// refusal (Alice then knows nothing changed).
func TestDeployDeadlineBeforeTheFirstRename(t *testing.T) {
	w := newDeployWorld(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	w.f.s.beforeRename = func() error {
		cancel()
		return nil
	}
	in := w.newInput()
	w.f.s.stdin = strings.NewReader(in)
	_, err := cmdNginxDeploy(ctx, w.f.s, []string{"--op", opA, "--cert", "/etc/nginx/ssl/www.crt", "--key", "/etc/nginx/ssl/www.key",
		"--expect-cert-sha256", w.oldSHA(), "--content-sha256", hexOf(in)})
	var he *helperError
	require.ErrorAs(t, err, &he)
	assert.Equal(t, helperproto.CodeIOError, he.code)
	w.assertPair(t, false)
	w.assertNoLeftovers(t)
	assert.Equal(t, 0, w.reloads)
}

// S6 and Review Focus 2: a held lock answers BUSY within the budget before stdin is read; status
// reports it as active.
func TestDeployAnswersBusyWhenTheLockIsHeld(t *testing.T) {
	w := newDeployWorld(t)
	old := lockWait
	lockWait = 100 * time.Millisecond
	defer func() { lockWait = old }()
	lock, err := w.f.s.nginxLock(context.Background())
	require.NoError(t, err)
	in := w.newInput()
	stdin := strings.NewReader(in)
	w.f.s.stdin = stdin
	code, m := w.f.run("nginx-deploy", "--op", opA, "--cert", "/etc/nginx/ssl/www.crt", "--key", "/etc/nginx/ssl/www.key",
		"--expect-cert-sha256", w.oldSHA(), "--content-sha256", hexOf(in))
	assert.Equal(t, helperproto.ExitFailed, code)
	assert.Equal(t, helperproto.CodeBusy, m["code"])
	assert.Equal(t, len(in), stdin.Len(), "stdin is read only under the lock")
	_, st := w.f.run("nginx-status", "--op", opA)
	assert.Equal(t, true, st["active"])
	code, m = w.f.run("nginx-restore", "--op", opA)
	assert.Equal(t, helperproto.ExitFailed, code)
	assert.Equal(t, helperproto.CodeBusy, m["code"])
	require.NoError(t, lock.Close())
	_, st = w.f.run("nginx-status", "--op", opA)
	assert.Equal(t, false, st["active"])
	w.assertPair(t, false)
}

// A caller that never closes stdin cannot hold the Nginx lock past the helper's budget.
func TestDeployStdinThatNeverEndsReleasesTheLock(t *testing.T) {
	w := newDeployWorld(t)
	r, wr, err := os.Pipe()
	require.NoError(t, err)
	defer func() { _ = r.Close(); _ = wr.Close() }()
	w.f.s.stdin = r
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	_, err = cmdNginxDeploy(ctx, w.f.s, []string{"--op", opA, "--cert", "/etc/nginx/ssl/www.crt", "--key", "/etc/nginx/ssl/www.key",
		"--expect-cert-sha256", w.oldSHA(), "--content-sha256", w.oldSHA()})
	var he *helperError
	require.ErrorAs(t, err, &he)
	assert.Equal(t, helperproto.CodeIOError, he.code)
	assert.False(t, w.f.s.nginxLockHeld())

	_, err = readInput(context.Background(), iotestErrReader{}, 10)
	assert.Error(t, err)
}

type iotestErrReader struct{}

func (iotestErrReader) Read([]byte) (int, error) { return 0, errors.New("broken pipe") }

// Review Focus 2: the directory is replaced by a link to a root-only directory right before the
// rename. The write still lands in the directory the helper opened, never in /root.
func TestAttackDirectorySwappedBeforeTheRename(t *testing.T) {
	w := newDeployWorld(t)
	w.f.mkdir("/root/.ssh", 0o700)
	w.f.write("/root/.ssh/www.crt", "root's file", 0o600)
	swapped := false
	w.f.s.beforeRename = func() error {
		if !swapped {
			swapped = true
			require.NoError(t, os.Rename(w.f.host("/etc/nginx/ssl"), w.f.host("/etc/nginx/ssl.old")))
			require.NoError(t, os.Symlink("/root/.ssh", w.f.host("/etc/nginx/ssl")))
		}
		return nil
	}
	_, _ = w.deploy(opA, w.newInput(), w.oldSHA())
	assert.Equal(t, "root's file", w.f.read("/root/.ssh/www.crt"))
	_, err := os.Stat(w.f.host("/root/.ssh/www.key"))
	assert.True(t, errors.Is(err, os.ErrNotExist), "nothing was written into /root")
	// A restore follows the path again: it now leads elsewhere, so nothing is touched there either.
	_, _ = w.f.run("nginx-restore", "--op", opA)
	assert.Equal(t, "root's file", w.f.read("/root/.ssh/www.crt"))
	_, err = os.Stat(w.f.host("/root/.ssh/www.key"))
	assert.True(t, errors.Is(err, os.ErrNotExist))
}

func TestStatusReportsTheJournal(t *testing.T) {
	w := newDeployWorld(t)
	code, st := w.f.run("nginx-status", "--op", opA)
	require.Equal(t, 0, code)
	assert.Equal(t, map[string]any{"ok": true, "phase": helperproto.PhaseNone, "active": false, "new_cert_sha256": "",
		"current_cert_sha256": "", "backup_dir": helperproto.BackupRoot + "/" + opA, "failed_step": "", "cause_step": "", "error": ""}, st)
	code, _ = w.deploy(opA, w.newInput(), w.oldSHA())
	require.Equal(t, 0, code)
	_, st = w.f.run("nginx-status", "--op", opA)
	assert.Equal(t, helperproto.PhaseCommitted, st["phase"])
	assert.Equal(t, hexOf(string(w.newLeaf.FullchainPEM)), st["new_cert_sha256"])
	assert.Equal(t, hexOf(string(w.newLeaf.FullchainPEM)), st["current_cert_sha256"])
	_, _ = w.f.run("nginx-restore", "--op", opA)
	_, st = w.f.run("nginx-status", "--op", opA)
	assert.Equal(t, helperproto.PhaseRestored, st["phase"])
	assert.Equal(t, w.oldSHA(), st["current_cert_sha256"])
	assert.Equal(t, []string{"nginx-deploy /etc/nginx/ssl/www.crt", "nginx-restore " + helperproto.BackupRoot + "/" + opA}, w.f.loggedLines(),
		"nginx-status is not logged")
}

// Attack: nginx-restore called again and again on an operation it refuses (or whose rollback
// reload keeps failing) never makes the journal unreadable or larger than its limit.
func TestRepeatedRestoresKeepTheJournalReadable(t *testing.T) {
	w := newDeployWorld(t)
	code, _ := w.deploy(opA, w.newInput(), w.oldSHA())
	require.Equal(t, 0, code)
	w.f.write("/etc/nginx/ssl/www.crt", "someone else's certificate", 0o644)
	for i := 0; i < 200; i++ {
		code, r := w.f.run("nginx-restore", "--op", opA)
		require.Equal(t, helperproto.ExitPrecondition, code, "%d %v", i, r)
	}
	w.f.write("/etc/nginx/ssl/www.crt", string(w.newLeaf.FullchainPEM), 0o644)
	for i := 0; i < 100; i++ {
		w.reloadFail = 1
		code, r := w.f.run("nginx-restore", "--op", opA)
		require.Equal(t, 0, code, "%d %v", i, r)
		assert.Equal(t, helperproto.PhaseRestoreFailed, r["phase"])
		assert.Equal(t, []string{"restore:ok", "rollback_config_test:ok", "rollback_reload:failed"}, stepsOf(r))
	}
	code, st := w.f.run("nginx-status", "--op", opA)
	require.Equal(t, 0, code, "%v", st)
	code, r := w.f.run("nginx-restore", "--op", opA)
	require.Equal(t, 0, code, "%v", r)
	assert.Equal(t, helperproto.PhaseRestored, r["phase"])
	var j journal
	require.NoError(t, json.Unmarshal([]byte(w.f.read(helperproto.BackupRoot+"/"+opA+"/journal.json")), &j))
	assert.LessOrEqual(t, len(j.Steps), maxSteps)
	assert.Equal(t, helperproto.StepBackup, j.Steps[0].Name, "the deployment's own steps are kept")
}

// A journal that cannot be read is never guessed at.
func TestUnreadableJournal(t *testing.T) {
	w := newDeployWorld(t)
	code, _ := w.deploy(opA, w.newInput(), w.oldSHA())
	require.Equal(t, 0, code)
	for _, bad := range []string{"{", `{"op":"` + opB + `","phase":"committed"}`, `{"phase":"bogus"}`, strings.Repeat(" ", journalLimit+1)} {
		require.NoError(t, os.WriteFile(w.opPath(opA)+"/journal.json", []byte(bad), 0o600))
		for _, args := range [][]string{{"nginx-status", "--op", opA}, {"nginx-restore", "--op", opA}} {
			code, m := w.f.run(args...)
			assert.Equal(t, helperproto.ExitFailed, code, "%v %q", args, bad)
			assert.Equal(t, helperproto.CodeIOError, m["code"])
		}
		code, m := w.deploy(opA, w.newInput(), hexOf(string(w.newLeaf.FullchainPEM)))
		assert.Equal(t, helperproto.ExitFailed, code)
		assert.Equal(t, helperproto.CodeIOError, m["code"])
		w.assertPair(t, true)
	}
}

func TestSweepKeepsNginxBackups(t *testing.T) {
	eightDays, fortyDays := testNow.Add(-8*24*time.Hour), testNow.Add(-40*24*time.Hour)
	age := func(w *deployWorld, at time.Time) {
		require.NoError(t, os.Chtimes(w.opPath(opA), at, at))
	}
	w := newDeployWorld(t)
	code, _ := w.deploy(opA, w.newInput(), w.oldSHA())
	require.Equal(t, 0, code)
	age(w, testNow.Add(-6*24*time.Hour))
	w.f.s.sweepBackups()
	assert.DirExists(t, w.opPath(opA), "kept 7 days")
	w.f.write("/etc/nginx/ssl/"+stagedName(opA, kindKey), "a staged key a dead helper left", 0o600)
	age(w, eightDays)
	lock, err := w.f.s.nginxLock(context.Background())
	require.NoError(t, err)
	w.f.s.sweepBackups()
	assert.DirExists(t, w.opPath(opA), "never while another helper holds the Nginx lock")
	require.NoError(t, lock.Close())
	w.f.s.sweepBackups()
	assert.NoDirExists(t, w.opPath(opA), "a committed operation is kept 7 days")
	w.assertNoLeftovers(t)

	w = newDeployWorld(t)
	w.reloadFail = 2
	_, _ = w.deploy(opA, w.newInput(), w.oldSHA())
	age(w, eightDays)
	w.f.s.sweepBackups()
	assert.DirExists(t, w.opPath(opA), "a failed restore keeps its backup for the 30-day cap")
	age(w, fortyDays)
	w.f.s.sweepBackups()
	assert.NoDirExists(t, w.opPath(opA))

	// S3: an interrupted operation is never swept, whatever its age.
	for _, kill := range []string{helperproto.StepWriteKey, helperproto.StepRestore} {
		w = newDeployWorld(t)
		if kill == helperproto.StepRestore {
			w.testFail = 1
		}
		w.f.s.afterDeployStep = func(p string) error {
			if p == kill {
				return errKilled
			}
			return nil
		}
		_, _ = w.deploy(opA, w.newInput(), w.oldSHA())
		w.revive()
		age(w, fortyDays)
		w.f.s.sweepBackups()
		assert.DirExists(t, w.opPath(opA), kill)
		_, st := w.f.run("nginx-status", "--op", opA)
		assert.Contains(t, []any{helperproto.PhaseWriting, helperproto.PhaseRestoring}, st["phase"])
		code, r := w.f.run("nginx-restore", "--op", opA)
		require.Equal(t, 0, code, "%v", r)
		w.assertPair(t, false)
	}

	// A directory without a journal (authorized_keys backups, or a deployment killed before its
	// first journal) keeps the 30-day rule.
	w = newDeployWorld(t)
	w.f.mkdir(helperproto.BackupRoot+"/"+opA, 0o700)
	age(w, eightDays)
	w.f.s.sweepBackups()
	assert.DirExists(t, w.opPath(opA))
	age(w, fortyDays)
	w.f.s.sweepBackups()
	assert.NoDirExists(t, w.opPath(opA))
}

// S3 for cleanup --op: an interrupted Nginx operation keeps its backups until it is restored.
func TestCleanupKeepsInterruptedNginxOperations(t *testing.T) {
	w := newDeployWorld(t)
	w.f.s.afterDeployStep = func(p string) error {
		if p == "staged "+stagedName(opA, kindKey) {
			return errKilled
		}
		return nil
	}
	_, _ = w.deploy(opA, w.newInput(), w.oldSHA())
	w.revive()
	code, m := w.f.run("cleanup", "--op", opA)
	assert.Equal(t, helperproto.ExitFailed, code)
	assert.Equal(t, helperproto.CodeBusy, m["code"])
	assert.DirExists(t, w.opPath(opA))
	code, _ = w.f.run("nginx-restore", "--op", opA)
	require.Equal(t, 0, code)
	code, m = w.f.run("cleanup", "--op", opA)
	require.Equal(t, 0, code, "%v", m)
	assert.NoDirExists(t, w.opPath(opA))
	w.assertNoLeftovers(t)
}

// A caller that loops deployments cannot fill the disk with backups.
func TestDeployBoundsTheBackupsKept(t *testing.T) {
	old := maxNginxOps
	maxNginxOps = 1
	defer func() { maxNginxOps = old }()
	w := newDeployWorld(t)
	code, _ := w.deploy(opA, w.newInput(), w.oldSHA())
	require.Equal(t, 0, code)
	in := input(w.leaf.FullchainPEM, w.leaf.KeyPEM)
	code, m := w.f.runWith(in, "nginx-deploy", "--op", opB, "--cert", "/etc/nginx/ssl/www.crt", "--key", "/etc/nginx/ssl/www.key",
		"--expect-cert-sha256", hexOf(string(w.newLeaf.FullchainPEM)), "--content-sha256", hexOf(in))
	assert.Equal(t, helperproto.ExitPrecondition, code)
	assert.Equal(t, helperproto.CodeNoSpace, m["code"])
	w.assertPair(t, true)
	assert.NoDirExists(t, w.opPath(opB))
	// An unchanged deployment records a journal too, so it counts the same.
	in = w.newInput()
	code, m = w.f.runWith(in, "nginx-deploy", "--op", opB, "--cert", "/etc/nginx/ssl/www.crt", "--key", "/etc/nginx/ssl/www.key",
		"--expect-cert-sha256", hexOf(string(w.newLeaf.FullchainPEM)), "--content-sha256", hexOf(in))
	assert.Equal(t, helperproto.ExitPrecondition, code, "%v", m)
	assert.NoDirExists(t, w.opPath(opB))
}

// Requirement 10, S5: exact argument vectors; nothing runs, reads stdin or is logged otherwise.
func TestNginxWriteArguments(t *testing.T) {
	w := newDeployWorld(t)
	sha := strings.Repeat("a", 64)
	good := []string{"--op", opA, "--cert", "/etc/nginx/ssl/www.crt", "--key", "/etc/nginx/ssl/www.key", "--expect-cert-sha256", sha, "--content-sha256", sha}
	usage := [][]string{
		{}, {"--cert", "/etc/nginx/ssl/www.crt", "--op", opA},
		good[:9], append(slices.Clone(good), "--force"), append(slices.Clone(good), ""),
		{"--cert", "/etc/nginx/ssl/www.crt", "--op", opA, "--key", "/etc/nginx/ssl/www.key", "--expect-cert-sha256", sha, "--content-sha256", sha},
		{"--op", opA, "--key", "/etc/nginx/ssl/www.key", "--cert", "/etc/nginx/ssl/www.crt", "--expect-cert-sha256", sha, "--content-sha256", sha},
		{"--op", opA, "--cert", "/etc/nginx/ssl/www.crt", "--key", "/etc/nginx/ssl/www.key", "--content-sha256", sha, "--expect-cert-sha256", sha},
		{"--op=" + opA, "--cert", "/etc/nginx/ssl/www.crt", "--key", "/etc/nginx/ssl/www.key", "--expect-cert-sha256", sha, "--content-sha256", sha, "x"},
		{"--op", opA, "--op", opA, "--key", "/etc/nginx/ssl/www.key", "--expect-cert-sha256", sha, "--content-sha256", sha},
	}
	for _, args := range usage {
		code, m := w.f.run(append([]string{"nginx-deploy"}, args...)...)
		assert.Equal(t, helperproto.ExitRefused, code, "%v", args)
		assert.Equal(t, helperproto.CodeUsage, m["code"], "%v", args)
	}
	invalid := func(i int, v string) []string {
		a := slices.Clone(good)
		a[i] = v
		return a
	}
	for _, args := range [][]string{
		invalid(1, "../../etc"), invalid(1, "0190F5A0-0000-7000-8000-0000000000D1"), invalid(3, "rel.crt"), invalid(3, "/etc/nginx/ssl/../ssl/www.crt"),
		invalid(5, "/etc/nginx//ssl/www.key"), invalid(3, "/etc/nginx/ssl/a b.crt"), invalid(7, "absent"), invalid(7, strings.Repeat("A", 64)),
		invalid(9, "absent"), invalid(9, "abc"), invalid(5, "/etc/nginx/ssl/www.crt"), invalid(3, "/"),
	} {
		code, m := w.f.run(append([]string{"nginx-deploy"}, args...)...)
		assert.Equal(t, helperproto.ExitRefused, code, "%v", args)
		assert.Equal(t, helperproto.CodeInvalidArgument, m["code"], "%v", args)
	}
	for _, sub := range []string{"nginx-restore", "nginx-status"} {
		for _, args := range [][]string{{}, {"--op"}, {opA}, {"--op", opA, "x"}, {"--op=" + opA}, {"-op", opA}, {"--op", opA, "--op", opA}} {
			code, m := w.f.run(append([]string{sub}, args...)...)
			assert.Equal(t, helperproto.ExitRefused, code, "%s %v", sub, args)
			assert.Equal(t, helperproto.CodeUsage, m["code"], "%s %v", sub, args)
		}
		for _, op := range []string{"x", "../" + opA[3:], "0190F5A0-0000-7000-8000-0000000000D1", opA + "0"} {
			code, m := w.f.run(sub, "--op", op)
			assert.Equal(t, helperproto.ExitRefused, code, sub)
			assert.Equal(t, helperproto.CodeInvalidArgument, m["code"], "%s %s", sub, op)
		}
	}
	assert.Empty(t, w.calls, "nginx never ran")
	assert.Empty(t, w.f.loggedLines())
	assert.Equal(t, 0, w.reloads)
}

// The helper survives SIGHUP and SIGPIPE (a dropped connection) once keepRunning ran.
func TestKeepRunningSurvivesHangupAndPipe(t *testing.T) {
	keepRunning()
	defer signal.Reset(syscall.SIGHUP, syscall.SIGPIPE)
	require.NoError(t, syscall.Kill(os.Getpid(), syscall.SIGHUP))
	require.NoError(t, syscall.Kill(os.Getpid(), syscall.SIGPIPE))
	time.Sleep(50 * time.Millisecond)
	r, wr, err := os.Pipe()
	require.NoError(t, err)
	require.NoError(t, r.Close())
	_, err = wr.Write([]byte("x"))
	assert.ErrorIs(t, err, syscall.EPIPE)
	_ = wr.Close()
}

func TestParseDeployInput(t *testing.T) {
	in, err := parseDeployInput([]byte(` { "key_pem" : "k\nA\/\"\\\t\r\b\f" , "cert_pem":"c" } ` + "\n"))
	require.NoError(t, err)
	assert.Equal(t, "c", string(in.cert))
	assert.Equal(t, "k\nA/\"\\\t\r\b\f", string(in.key))
	for _, bad := range []string{"", "{}", `{"cert_pem":"c"}`, `{"cert_pem":"c","cert_pem":"d"}`, `{"cert_pem":"c","key_pem":"k"`,
		`{"cert_pem":"c","key_pem":"k"}x`, `{"cert_pem":1,"key_pem":"k"}`, `{"cert_pem":"c` + "\n" + `","key_pem":"k"}`,
		`{"cert_pem":"\ud800","key_pem":"k"}`, `{"cert_pem":"\u00zz","key_pem":"k"}`, `{"cert_pem":"\x","key_pem":"k"}`,
		`{"cert_pem":"c";"key_pem":"k"}`, `{"cert_pem":"c","key_pem":"k\`, `{"cert_pem":"c","key_pem":"\u12`,
		`{"Cert_pem":"c","key_pem":"k"}`, `["c","k"]`} {
		_, err := parseDeployInput([]byte(bad))
		assert.Error(t, err, bad)
	}
}

// Root only: owners are really set, and a user-owned directory on the path is refused.
func TestDeployAsRootSetsOwnersAndRefusesUserDirectories(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root (chown)")
	}
	w := newDeployWorld(t)
	w.f.s.rootUID = 0
	w.f.s.chown = func(f *os.File, uid, gid int) error { return f.Chown(uid, gid) }
	require.NoError(t, os.Chown(w.f.host("/etc/nginx/ssl/www.key"), 0, 4321))
	require.NoError(t, os.Chmod(w.f.host("/etc/nginx/ssl/www.key"), 0o640))
	require.NoError(t, os.Chown(w.f.host("/etc/nginx/ssl/www.crt"), 1000, 1000))
	code, m := w.deploy(opA, w.newInput(), w.oldSHA())
	require.Equal(t, 0, code, "%v", m)
	st, err := os.Stat(w.f.host("/etc/nginx/ssl/www.key"))
	require.NoError(t, err)
	uid, gid := owner(st)
	assert.Equal(t, 0, uid)
	assert.Equal(t, 4321, gid)
	assert.Equal(t, os.FileMode(0o640), st.Mode().Perm())
	st, err = os.Stat(w.f.host("/etc/nginx/ssl/www.crt"))
	require.NoError(t, err)
	uid, gid = owner(st)
	assert.Equal(t, []int{1000, 1000}, []int{uid, gid})
	for _, p := range []string{"", "/key.bak", "/cert.bak", "/journal.json"} {
		st, err := os.Stat(w.opPath(opA) + p)
		require.NoError(t, err)
		uid, gid := owner(st)
		assert.Equal(t, []int{0, 0}, []int{uid, gid}, p)
	}
	code, _ = w.f.run("nginx-restore", "--op", opA)
	require.Equal(t, 0, code)
	st, err = os.Stat(w.f.host("/etc/nginx/ssl/www.key"))
	require.NoError(t, err)
	_, gid = owner(st)
	assert.Equal(t, 4321, gid)

	w = newDeployWorld(t)
	w.f.s.rootUID = 0
	require.NoError(t, os.Chown(w.f.host("/etc/nginx/ssl"), 1000, 1000))
	code, m = w.deploy(opA, w.newInput(), w.oldSHA())
	assert.Equal(t, helperproto.ExitRefused, code)
	assert.Equal(t, helperproto.CodePathNotAllowed, m["code"])
	w.assertPair(t, false)
}

// guardNginx puts a real /usr/sbin/nginx file (mode) under the fixture root and makes the fake
// nginx answer only when trustedProgram passes it, as productionSys's runner does. before runs
// ahead of each check (a test changes the binary mid-transaction there).
func (w *deployWorld) guardNginx(mode os.FileMode, before func(args []string)) {
	w.f.mkdir("/usr", 0o755)
	w.f.mkdir("/usr/sbin", 0o755)
	w.f.write(nginxPath, "#!/bin/sh\n", mode)
	inner := w.f.s.runNginx
	w.f.s.runNginx = func(ctx context.Context, args ...string) ([]byte, []byte, error) {
		if before != nil {
			before(args)
		}
		if err := w.f.s.trustedProgram(nginxPath); err != nil {
			return nil, nil, err
		}
		return inner(ctx, args...)
	}
}

// configTest's mapping: an untrusted nginx says nothing about the configuration (class "") and
// fails the step.
func TestConfigTestUntrustedProgram(t *testing.T) {
	w := newDeployWorld(t)
	w.f.s.runNginx = func(context.Context, ...string) ([]byte, []byte, error) {
		return nil, []byte("SSL_CTX_use_PrivateKey failed (key values mismatch)"), &programError{path: nginxPath}
	}
	class, err := w.f.s.configTest(context.Background())
	assert.Equal(t, "", class)
	assert.ErrorIs(t, err, errProgramUntrusted)
}

// C7: an nginx binary that a user other than root can change refuses a deployment up front
// (nginxConfig: CONFIG_INVALID), with nothing written, no backup and no reload.
func TestDeployUntrustedNginxChangesNothing(t *testing.T) {
	w := newDeployWorld(t)
	w.guardNginx(0o775, nil)
	code, m := w.deploy(opA, w.newInput(), w.oldSHA())
	assert.Equal(t, helperproto.ExitPrecondition, code, "%v", m)
	assert.Equal(t, helperproto.CodeConfigInvalid, m["code"])
	w.assertPair(t, false)
	w.assertNoLeftovers(t)
	assert.Equal(t, 0, w.reloads)
	_, err := os.Stat(w.opPath(opA))
	assert.True(t, errors.Is(err, os.ErrNotExist), "no backup directory")
	assert.Empty(t, w.calls, "nginx never ran")
}

// C7: a binary that becomes untrusted after nginx -T (only root can do that: its directory is
// root's) fails config_test with class "", and the rollback's nginx -t fails the same way: the
// files are back, nothing is reloaded, and the operation ends restore_failed.
func TestDeployUntrustedNginxAtConfigTestEndsRestoreFailed(t *testing.T) {
	w := newDeployWorld(t)
	w.guardNginx(0o755, func(args []string) {
		if args[0] == "-t" {
			require.NoError(t, os.Chmod(w.f.host(nginxPath), 0o775))
		}
	})
	code, m := w.deploy(opA, w.newInput(), w.oldSHA())
	require.Equal(t, 0, code, "%v", m)
	assert.Equal(t, helperproto.PhaseRestoreFailed, m["phase"])
	assert.Equal(t, helperproto.StepRollbackConfigTest, m["failed_step"])
	assert.Equal(t, "", m["error"])
	assert.Equal(t, []string{"backup:ok", "write_key:ok", "write_cert:ok", "config_test:failed", "restore:ok", "rollback_config_test:failed"}, stepsOf(m))
	w.assertPair(t, false)
	w.assertNoLeftovers(t)
	assert.Equal(t, 0, w.reloads)
}

// C7: nginx-restore of a committed operation on a host whose nginx has since become untrusted:
// the files are back, nginx is not reloaded, and the answer is restore_failed at
// rollback_config_test.
func TestRestoreUntrustedNginxEndsRestoreFailed(t *testing.T) {
	w := newDeployWorld(t)
	w.guardNginx(0o755, nil)
	code, m := w.deploy(opA, w.newInput(), w.oldSHA())
	require.Equal(t, 0, code, "%v", m)
	require.Equal(t, helperproto.PhaseCommitted, m["phase"])
	require.Equal(t, 1, w.reloads)

	require.NoError(t, os.Chmod(w.f.host(nginxPath), 0o775))
	code, r := w.f.run("nginx-restore", "--op", opA)
	require.Equal(t, 0, code, "%v", r)
	assert.Equal(t, helperproto.PhaseRestoreFailed, r["phase"])
	assert.Equal(t, helperproto.StepRollbackConfigTest, r["failed_step"])
	assert.Equal(t, "", r["error"])
	assert.Equal(t, []string{"restore:ok", "rollback_config_test:failed"}, stepsOf(r))
	w.assertPair(t, false)
	w.assertNoLeftovers(t)
	assert.Equal(t, 1, w.reloads, "no reload after the refused nginx -t")
}
