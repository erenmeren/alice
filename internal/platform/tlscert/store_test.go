package tlscert_test

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/platform/tlscert"
	"alice/internal/testutil/pki"
)

// fakeNow is a settable clock for the store.
type fakeNow struct {
	mu sync.Mutex
	t  time.Time
}

func (f *fakeNow) now() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.t
}

func (f *fakeNow) set(t time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.t = t
}

var hosts = []string{"alice.example.com", "127.0.0.1"}

func newStore(t *testing.T, dir string, clk *fakeNow) *tlscert.Store {
	t.Helper()
	s, err := tlscert.NewStore(dir, hosts, clk.now)
	require.NoError(t, err)
	return s
}

func customer(t *testing.T, notAfter time.Time) (pki.Leaf, tlscert.Upload) {
	t.Helper()
	ca := pki.NewCA("Customer", pki.ECDSA256, t0)
	l := ca.Issue(pki.Opts{CommonName: "alice.example.com", SANs: []string{"alice.example.com"}, NotAfter: notAfter}, t0)
	return l, tlscert.Upload{CertPEM: l.FullchainPEM, KeyPEM: l.KeyPEM}
}

func dirNames(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	slices.Sort(names)
	return names
}

func served(t *testing.T, s *tlscert.Store) []byte {
	t.Helper()
	c, err := s.GetCertificate(&tls.ClientHelloInfo{})
	require.NoError(t, err)
	return c.Certificate[0]
}

func mode(t *testing.T, p string) os.FileMode {
	t.Helper()
	st, err := os.Stat(p)
	require.NoError(t, err)
	return st.Mode().Perm()
}

func TestStoreStartsWithTheTemporaryCertificate(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "keys")
	s := newStore(t, dir, &fakeNow{t: t0})
	info := s.Info()
	assert.True(t, info.Temporary)
	assert.Equal(t, []string{"alice.example.com"}, info.DNSNames)
	assert.Equal(t, []string{"127.0.0.1"}, info.IPs)
	assert.Equal(t, t0.Add(90*24*time.Hour), info.NotAfter)
	assert.Empty(t, s.Recovered())
	assert.Equal(t, []string{"tls.crt", "tls.key"}, dirNames(t, dir))
	assert.Equal(t, info.FingerprintSHA256, fingerprintDER(served(t, s)))
}

func TestStoreLoadsACustomerCertificateAtStart(t *testing.T) {
	dir := t.TempDir()
	l, _ := customer(t, t0.AddDate(1, 0, 0))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "tls.crt"), l.FullchainPEM, 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "tls.key"), l.KeyPEM, 0o400))
	s := newStore(t, dir, &fakeNow{t: t0})
	assert.False(t, s.Info().Temporary)
	assert.Equal(t, pki.Fingerprint(l.Cert), s.Info().FingerprintSHA256)
	assert.Equal(t, l.Cert.Raw, served(t, s))
	assert.Equal(t, []string{"chain_incomplete"}, s.Info().Warnings, "the test CA is not a system root")
	assert.Nil(t, newStore(t, t.TempDir(), &fakeNow{t: t0}).Info().Warnings, "the temporary certificate has none")
}

func TestInstallHotReloads(t *testing.T) {
	dir := t.TempDir()
	s := newStore(t, dir, &fakeNow{t: t0})
	l, u := customer(t, t0.AddDate(1, 0, 0))

	ln, err := tls.Listen("tcp", "127.0.0.1:0", tlscert.ServerConfigFor(s))
	require.NoError(t, err)
	defer func() { _ = ln.Close() }()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				_ = c.(*tls.Conn).Handshake()
				_ = c.Close()
			}()
		}
	}()
	handshake := func() ([]byte, error) {
		d := tls.Dialer{Config: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}}
		c, err := d.DialContext(context.Background(), "tcp", ln.Addr().String())
		if err != nil {
			return nil, err
		}
		defer func() { _ = c.Close() }()
		return c.(*tls.Conn).ConnectionState().PeerCertificates[0].Raw, nil
	}

	var stop atomic.Bool
	var failures, done atomic.Int64
	var wg sync.WaitGroup
	for range 50 {
		wg.Go(func() {
			for !stop.Load() {
				if _, err := handshake(); err != nil {
					failures.Add(1)
				}
				done.Add(1)
			}
		})
	}
	require.Eventually(t, func() bool { return done.Load() > 100 }, 10*time.Second, time.Millisecond)
	info, err := s.Install(u)
	require.NoError(t, err)
	time.Sleep(50 * time.Millisecond)
	stop.Store(true)
	wg.Wait()
	assert.Zero(t, failures.Load(), "no handshake failed")

	assert.False(t, info.Temporary)
	assert.Equal(t, pki.Fingerprint(l.Cert), info.FingerprintSHA256)
	assert.Equal(t, info, s.Info())
	assert.Equal(t, []string{"chain_incomplete"}, info.Warnings)
	for range 5 {
		got, err := handshake()
		require.NoError(t, err)
		assert.Equal(t, l.Cert.Raw, got, "every new handshake presents the uploaded leaf")
	}
	assert.Equal(t, os.FileMode(0o400), mode(t, filepath.Join(dir, "tls.key")))
	assert.Equal(t, os.FileMode(0o644), mode(t, filepath.Join(dir, "tls.crt")))
	assert.Equal(t, []string{"tls.crt", "tls.key"}, dirNames(t, dir), "no temporary file remains")
	onDisk, err := tls.LoadX509KeyPair(filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key"))
	require.NoError(t, err)
	assert.Equal(t, l.Cert.Raw, onDisk.Certificate[0])
	assert.Len(t, onDisk.Certificate, 2, "the chain is stored leaf first")
}

func TestInstallRefusesAnInvalidUploadAndChangesNothing(t *testing.T) {
	dir := t.TempDir()
	s := newStore(t, dir, &fakeNow{t: t0})
	before := s.Info()
	_, err := s.Install(tlscert.Upload{CertPEM: []byte("junk")})
	require.ErrorIs(t, err, tlscert.ErrUnreadable)
	assert.Equal(t, before, s.Info())
	assert.Equal(t, []string{"tls.crt", "tls.key"}, dirNames(t, dir))
}

func TestInstallIsAtomicOnDisk(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	dir := t.TempDir()
	s := newStore(t, dir, &fakeNow{t: t0})
	oldCrt, err := os.ReadFile(filepath.Join(dir, "tls.crt"))
	require.NoError(t, err)
	oldKey, err := os.ReadFile(filepath.Join(dir, "tls.key"))
	require.NoError(t, err)
	before := s.Info()
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	tlscert.SetInstallHook(s, func(stage string) error {
		if stage == tlscert.StageKeyWritten {
			return os.Chmod(dir, 0o500) // the certificate write fails
		}
		return nil
	})
	_, u := customer(t, t0.AddDate(1, 0, 0))
	_, err = s.Install(u)
	require.Error(t, err)
	require.NoError(t, os.Chmod(dir, 0o700))

	gotCrt, err := os.ReadFile(filepath.Join(dir, "tls.crt"))
	require.NoError(t, err)
	gotKey, err := os.ReadFile(filepath.Join(dir, "tls.key"))
	require.NoError(t, err)
	assert.Equal(t, oldCrt, gotCrt)
	assert.Equal(t, oldKey, gotKey)
	assert.Equal(t, before, s.Info(), "the old pair stays in force in memory")

	// The leftovers of the failed attempt are cleared by the next start, which serves the old pair.
	s2 := newStore(t, dir, &fakeNow{t: t0})
	assert.Equal(t, before.FingerprintSHA256, s2.Info().FingerprintSHA256)
	assert.Empty(t, s2.Recovered())
	assert.Equal(t, []string{"tls.crt", "tls.key"}, dirNames(t, dir))
}

var errCrash = errors.New("simulated crash")

func crashBetweenRenames(t *testing.T, dir string) (before tlscert.Info, uploaded pki.Leaf) {
	t.Helper()
	s := newStore(t, dir, &fakeNow{t: t0})
	before = s.Info()
	tlscert.SetInstallHook(s, func(stage string) error {
		if stage == tlscert.StageBetweenRenames {
			return errCrash
		}
		return nil
	})
	l, u := customer(t, t0.AddDate(1, 0, 0))
	_, err := s.Install(u)
	require.ErrorIs(t, err, errCrash)
	return before, l
}

func TestStoreRecoversAnInterruptedInstall(t *testing.T) {
	t.Run("finishes the rename", func(t *testing.T) {
		dir := t.TempDir()
		_, l := crashBetweenRenames(t, dir)
		s := newStore(t, dir, &fakeNow{t: t0})
		assert.Equal(t, "finished", s.Recovered())
		assert.Equal(t, pki.Fingerprint(l.Cert), s.Info().FingerprintSHA256)
		assert.Equal(t, l.Cert.Raw, served(t, s))
		assert.Equal(t, []string{"tls.crt", "tls.key"}, dirNames(t, dir))
		assert.Equal(t, os.FileMode(0o400), mode(t, filepath.Join(dir, "tls.key")))
	})
	t.Run("restores the previous pair when the new certificate is damaged", func(t *testing.T) {
		dir := t.TempDir()
		before, _ := crashBetweenRenames(t, dir)
		require.NoError(t, os.WriteFile(filepath.Join(dir, "tls.crt.new"), []byte("damaged"), 0o644))
		s := newStore(t, dir, &fakeNow{t: t0})
		assert.Equal(t, "restored_previous", s.Recovered())
		assert.Equal(t, before.FingerprintSHA256, s.Info().FingerprintSHA256)
		assert.True(t, s.Info().Temporary)
		assert.Equal(t, []string{"tls.crt", "tls.key"}, dirNames(t, dir))
	})
	t.Run("refuses when neither pair is complete", func(t *testing.T) {
		dir := t.TempDir()
		crashBetweenRenames(t, dir)
		require.NoError(t, os.WriteFile(filepath.Join(dir, "tls.crt.new"), []byte("damaged"), 0o644))
		require.NoError(t, os.Remove(filepath.Join(dir, "tls.crt.prev")))
		key, err := os.ReadFile(filepath.Join(dir, "tls.key"))
		require.NoError(t, err)
		_, err = tlscert.NewStore(dir, hosts, (&fakeNow{t: t0}).now)
		require.Error(t, err)
		after, err := os.ReadFile(filepath.Join(dir, "tls.key"))
		require.NoError(t, err)
		assert.Equal(t, key, after, "the uploaded key is kept for the operator")
	})
	t.Run("never writes a temporary certificate over a foreign key", func(t *testing.T) {
		dir := t.TempDir()
		l, _ := customer(t, t0.AddDate(1, 0, 0))
		other, _ := customer(t, t0.AddDate(1, 0, 0))
		require.NoError(t, os.WriteFile(filepath.Join(dir, "tls.key"), l.KeyPEM, 0o400))
		require.NoError(t, os.WriteFile(filepath.Join(dir, "tls.crt"), other.FullchainPEM, 0o644))
		_, err := tlscert.NewStore(dir, hosts, (&fakeNow{t: t0}).now)
		require.Error(t, err)
		key, err := os.ReadFile(filepath.Join(dir, "tls.key"))
		require.NoError(t, err)
		assert.Equal(t, l.KeyPEM, key, "the customer's key is untouched")

		require.NoError(t, os.Remove(filepath.Join(dir, "tls.crt")))
		_, err = tlscert.NewStore(dir, hosts, (&fakeNow{t: t0}).now)
		require.Error(t, err, "a key without its certificate is not replaced either")
		key, err = os.ReadFile(filepath.Join(dir, "tls.key"))
		require.NoError(t, err)
		assert.Equal(t, l.KeyPEM, key)
	})
	t.Run("a crash before the first rename keeps the old pair", func(t *testing.T) {
		dir := t.TempDir()
		s := newStore(t, dir, &fakeNow{t: t0})
		before := s.Info()
		tlscert.SetInstallHook(s, func(stage string) error {
			if stage == tlscert.StageFilesWritten {
				return errCrash
			}
			return nil
		})
		_, u := customer(t, t0.AddDate(1, 0, 0))
		_, err := s.Install(u)
		require.ErrorIs(t, err, errCrash)
		s2 := newStore(t, dir, &fakeNow{t: t0})
		assert.Empty(t, s2.Recovered())
		assert.Equal(t, before.FingerprintSHA256, s2.Info().FingerprintSHA256)
		assert.Equal(t, []string{"tls.crt", "tls.key"}, dirNames(t, dir))
	})
}

func TestInstallAndRenewDoNotRace(t *testing.T) {
	for i := range 100 {
		dir := t.TempDir()
		clk := &fakeNow{t: t0}
		s := newStore(t, dir, clk)
		clk.set(t0.Add(85 * 24 * time.Hour)) // five days left: the temporary certificate is due
		l, u := customer(t, t0.AddDate(1, 0, 0))
		var wg sync.WaitGroup
		wg.Go(func() {
			_, err := s.Install(u)
			assert.NoError(t, err)
		})
		wg.Go(func() {
			_, err := s.Renew()
			assert.NoError(t, err)
		})
		wg.Wait()
		require.Equal(t, l.Cert.Raw, served(t, s), "iteration %d: the customer leaf survives in memory", i)
		onDisk, err := tls.LoadX509KeyPair(filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key"))
		require.NoError(t, err)
		require.Equal(t, l.Cert.Raw, onDisk.Certificate[0], "iteration %d: and on disk", i)
	}
}

// A Renew that starts while an Install holds the lock waits for it and then sees the customer pair.
func TestRenewDuringAnInstallSeesTheCustomerPair(t *testing.T) {
	dir := t.TempDir()
	clk := &fakeNow{t: t0}
	s := newStore(t, dir, clk)
	clk.set(t0.Add(85 * 24 * time.Hour))
	l, u := customer(t, t0.AddDate(1, 0, 0))
	var wg sync.WaitGroup
	var renewed bool
	tlscert.SetInstallHook(s, func(stage string) error {
		if stage == tlscert.StageFilesWritten {
			wg.Go(func() {
				var err error
				renewed, err = s.Renew()
				assert.NoError(t, err)
			})
			time.Sleep(50 * time.Millisecond) // Renew is now waiting (or would have read the old files)
		}
		return nil
	})
	_, err := s.Install(u)
	require.NoError(t, err)
	wg.Wait()
	assert.False(t, renewed)
	assert.Equal(t, l.Cert.Raw, served(t, s))
	onDisk, err := tls.LoadX509KeyPair(filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key"))
	require.NoError(t, err)
	assert.Equal(t, l.Cert.Raw, onDisk.Certificate[0])
}

func TestRenewOnlyTheTemporary(t *testing.T) {
	t.Run("a customer certificate near its end is never touched", func(t *testing.T) {
		dir := t.TempDir()
		l, u := customer(t, t0.AddDate(0, 0, 30))
		clk := &fakeNow{t: t0}
		s := newStore(t, dir, clk)
		_, err := s.Install(u)
		require.NoError(t, err)
		clk.set(t0.AddDate(0, 0, 27)) // three days left
		renewed, err := s.Renew()
		require.NoError(t, err)
		assert.False(t, renewed)
		assert.Equal(t, l.Cert.Raw, served(t, s))
	})
	t.Run("the temporary certificate six days from its end is renewed and served", func(t *testing.T) {
		dir := t.TempDir()
		clk := &fakeNow{t: t0}
		s := newStore(t, dir, clk)
		old := served(t, s)
		clk.set(t0.Add(84 * 24 * time.Hour))
		renewed, err := s.Renew()
		require.NoError(t, err)
		assert.True(t, renewed)
		assert.NotEqual(t, old, served(t, s))
		assert.True(t, s.Info().Temporary)
		assert.Equal(t, clk.now().Add(90*24*time.Hour), s.Info().NotAfter)
		assert.Equal(t, []string{"tls.crt", "tls.key"}, dirNames(t, dir))
		assert.Equal(t, os.FileMode(0o400), mode(t, filepath.Join(dir, "tls.key")))
		onDisk, err := tls.LoadX509KeyPair(filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key"))
		require.NoError(t, err)
		assert.Equal(t, served(t, s), onDisk.Certificate[0])
	})
	t.Run("one thirty days from its end is not", func(t *testing.T) {
		clk := &fakeNow{t: t0}
		s := newStore(t, t.TempDir(), clk)
		old := served(t, s)
		clk.set(t0.Add(60 * 24 * time.Hour))
		renewed, err := s.Renew()
		require.NoError(t, err)
		assert.False(t, renewed)
		assert.Equal(t, old, served(t, s))
	})
	t.Run("a temporary certificate due at start is renewed by NewStore", func(t *testing.T) {
		dir := t.TempDir()
		_, err := tlscert.EnsureSelfSigned(dir, hosts, t0)
		require.NoError(t, err)
		s := newStore(t, dir, &fakeNow{t: t0.Add(88 * 24 * time.Hour)})
		assert.Equal(t, t0.Add(178*24*time.Hour), s.Info().NotAfter)
	})
}

func fingerprintDER(der []byte) string {
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}
