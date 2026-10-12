package tlscert

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"sync/atomic"
	"time"
)

// File names in the key directory. An Install writes the .new pair, renames the key then the certificate into
// place, and keeps hard links to the replaced pair as .prev until it finished (S-13).
const (
	crtName = "tls.crt"
	keyName = "tls.key"
	newExt  = ".new"
	prevExt = ".prev"
)

// What NewStore repaired (Recovered).
const (
	RecoveredFinished         = "finished"
	RecoveredRestoredPrevious = "restored_previous"
)

// Install stages a test hook can stop at.
const (
	stageKeyWritten     = "key_written"     // tls.key.new is written, tls.crt.new not yet
	stageFilesWritten   = "files_written"   // both .new files are written, nothing renamed
	stageBetweenRenames = "between_renames" // tls.key is the new key, tls.crt still the old certificate
)

// current is the served pair and its description.
type current struct {
	cert *tls.Certificate
	info Info
}

// Store serves the HTTPS certificate of the key directory and replaces it without a restart: the listener's
// GetCertificate reads an atomic pointer, so every handshake after a swap presents the new pair. One mutex
// serialises Install and Renew (S-13), and Renew re-reads the files under it.
type Store struct {
	dir       string
	hosts     []string
	clk       func() time.Time
	cur       atomic.Pointer[current]
	mu        sync.Mutex
	recovered string
	hook      func(stage string) error // tests: a non-nil error stops Install there, as a crash would
}

// NewStore repairs an interrupted Install, creates Alice's temporary certificate when the directory holds none,
// renews it when it is due, and loads the pair. It never writes a temporary certificate over a key that is not
// the temporary one: a directory whose pair does not match and cannot be repaired is an error.
func NewStore(dir string, hosts []string, clk func() time.Time) (*Store, error) {
	s := &Store{dir: dir, hosts: slices.Clone(hosts), clk: clk}
	if err := s.repair(); err != nil {
		return nil, err
	}
	if _, err := EnsureSelfSigned(dir, hosts, clk()); err != nil { // creates a missing pair, or refuses a broken one
		return nil, err
	}
	c, err := s.load()
	if err != nil {
		return nil, err
	}
	s.cur.Store(c)
	if _, err := s.Renew(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Store) path(name string) string { return filepath.Join(s.dir, name) }

// Recovered reports what NewStore repaired: "", "finished" or "restored_previous".
func (s *Store) Recovered() string { return s.recovered }

// GetCertificate serves the current pair (tls.Config.GetCertificate).
func (s *Store) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return s.cur.Load().cert, nil
}

// Info describes the current pair.
func (s *Store) Info() Info { return s.cur.Load().info }

// ServerConfigFor is ServerConfig with the store's GetCertificate instead of a fixed certificate.
func ServerConfigFor(s *Store) *tls.Config {
	c := ServerConfig(tls.Certificate{})
	c.Certificates = nil
	c.GetCertificate = s.GetCertificate
	return c
}

// Install validates u and replaces the pair on disk and in memory. A failure leaves the old pair in force.
func (s *Store) Install(u Upload) (Info, error) {
	u.Hosts = append(slices.Clone(s.hosts), u.Hosts...)
	c, info, _, err := ParseUpload(u, s.clk())
	if err != nil {
		return Info{}, err
	}
	certPEM, keyPEM, err := encodePair(c)
	if err != nil {
		return Info{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.replace(certPEM, keyPEM); err != nil {
		return Info{}, err
	}
	s.cur.Store(&current{cert: &c, info: info})
	return info, nil
}

// Renew replaces Alice's temporary certificate when it is within seven days of its end (the tls.renew task). It
// reads the files under the lock, so a certificate an Install just wrote is never replaced; a customer
// certificate is never touched.
func (s *Store) Renew() (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, err := s.load()
	if err != nil {
		return false, err
	}
	now := s.clk()
	if !c.info.Temporary || now.Before(c.info.NotAfter.Add(-renewBefore)) {
		s.cur.Store(c)
		return false, nil
	}
	certPEM, keyPEM, err := generateTemporary(s.hosts, now)
	if err != nil {
		return false, err
	}
	if err := s.replace(certPEM, keyPEM); err != nil {
		return false, err
	}
	next, err := s.load()
	if err != nil {
		return false, err
	}
	s.cur.Store(next)
	return true, nil
}

// load reads the live pair.
func (s *Store) load() (*current, error) {
	c, keyPEM, err := loadPair(s.path(crtName), s.path(keyName))
	if err != nil {
		return nil, fmt.Errorf("the HTTPS certificate in %s could not be loaded: %w", s.dir, err)
	}
	info := infoOf(c.Leaf)
	info.Temporary = isTemporary(c.Leaf, keyPEM)
	if !info.Temporary {
		chain := make([]*x509.Certificate, 0, len(c.Certificate))
		for _, der := range c.Certificate {
			x, err := x509.ParseCertificate(der)
			if err != nil {
				return nil, fmt.Errorf("the HTTPS certificate in %s is not valid: %w", s.dir, err)
			}
			chain = append(chain, x)
		}
		info.Warnings = warnings(chain, s.hosts, s.clk())
	}
	return &current{cert: &c, info: info}, nil
}

// replace writes a new pair with the .prev/.new protocol. Callers hold s.mu.
func (s *Store) replace(certPEM, keyPEM []byte) error {
	return replacePair(s.dir, certPEM, keyPEM, s.hook)
}

// replacePair writes a new pair into dir with the .prev/.new protocol (S-13): both .new files are written and
// synced, hard links keep the live pair as .prev, then the key and the certificate are renamed into place and the
// leftovers removed. repair finishes or undoes a pair that stopped between the renames. When dir holds no live pair
// (the first creation) there is nothing to keep as .prev. hook (tests) stops it at a stage without cleanup, as a
// crash would. Callers run repair first: leftovers of an earlier interrupted replacement are removed here.
func replacePair(dir string, certPEM, keyPEM []byte, hook func(stage string) error) (err error) {
	crt, key := filepath.Join(dir, crtName), filepath.Join(dir, keyName)
	at := func(stage string) error {
		if hook == nil {
			return nil
		}
		if err := hook(stage); err != nil {
			return errors.Join(errHookStop, err)
		}
		return nil
	}
	removeLeftovers(dir)
	defer func() {
		if err != nil && !errors.Is(err, errHookStop) {
			removeLeftovers(dir)
		}
	}()
	hadPair := exists(crt) || exists(key)
	if hadPair {
		if err := os.Link(crt, crt+prevExt); err != nil {
			return fmt.Errorf("keep the previous certificate: %w", err)
		}
		if err := os.Link(key, key+prevExt); err != nil {
			return fmt.Errorf("keep the previous key: %w", err)
		}
	}
	if err := writeNew(key+newExt, keyPEM, 0o400); err != nil {
		return err
	}
	if err := at(stageKeyWritten); err != nil {
		return err
	}
	if err := writeNew(crt+newExt, certPEM, 0o644); err != nil {
		return err
	}
	if err := at(stageFilesWritten); err != nil {
		return err
	}
	if err := os.Rename(key+newExt, key); err != nil {
		return fmt.Errorf("install the key: %w", err)
	}
	if err := at(stageBetweenRenames); err != nil {
		return err
	}
	if err := os.Rename(crt+newExt, crt); err != nil {
		// Put the previous key back so the pair on disk matches again; without one, remove the lone new key.
		undo := os.Remove(key)
		if hadPair {
			undo = os.Rename(key+prevExt, key)
		}
		return errors.Join(fmt.Errorf("install the certificate: %w", err), undo)
	}
	if err := syncDir(dir); err != nil {
		return err
	}
	removeLeftovers(dir)
	return syncDir(dir)
}

// errHookStop marks an error returned by the test hook: Install stops there and cleans nothing up, like a crash.
var errHookStop = errors.New("tlscert: stopped by a test hook")

func (s *Store) removeLeftovers() { removeLeftovers(s.dir) }

func removeLeftovers(dir string) {
	for _, n := range []string{crtName + newExt, keyName + newExt, crtName + prevExt, keyName + prevExt} {
		_ = os.Remove(filepath.Join(dir, n))
	}
}

// repair finishes or undoes an Install that stopped between its two renames (S-13). An Install that stopped
// before the first rename left the live pair intact: its leftovers are removed.
func (s *Store) repair() error {
	crt, key := s.path(crtName), s.path(keyName)
	if !exists(crt+newExt) && !exists(crt+prevExt) && !exists(key+newExt) && !exists(key+prevExt) {
		return nil
	}
	if !exists(key+newExt) && exists(crt+newExt) { // the key was renamed, the certificate not
		switch {
		case pairMatches(crt+newExt, key):
			if err := os.Rename(crt+newExt, crt); err != nil {
				return fmt.Errorf("finish the interrupted certificate installation: %w", err)
			}
			s.recovered = RecoveredFinished
		case pairMatches(crt+prevExt, key+prevExt):
			if err := os.Rename(key+prevExt, key); err != nil {
				return fmt.Errorf("restore the previous key: %w", err)
			}
			if err := os.Rename(crt+prevExt, crt); err != nil {
				return fmt.Errorf("restore the previous certificate: %w", err)
			}
			s.recovered = RecoveredRestoredPrevious
		case pairMatches(crt, key):
			// The certificate rename failed and the previous key was put back before a stop: the live pair
			// is whole and only the leftovers below remain (review minor 9).
		default:
			return fmt.Errorf("the HTTPS certificate in %s was being replaced and neither the new nor the previous pair is complete", s.dir)
		}
	}
	if !exists(crt) && !exists(key) {
		// The first creation of the temporary pair stopped before its key was renamed: nothing is live, the
		// leftovers go and EnsureSelfSigned creates the pair again.
		s.removeLeftovers()
		return syncDir(s.dir)
	}
	if !pairMatches(crt, key) {
		return fmt.Errorf("the HTTPS certificate and key in %s do not match", s.dir)
	}
	s.removeLeftovers()
	return syncDir(s.dir)
}

func pairMatches(crt, key string) bool {
	_, err := tls.LoadX509KeyPair(crt, key)
	return err == nil
}

// encodePair renders a parsed pair as the chain PEM and a PKCS #8 key PEM.
func encodePair(c tls.Certificate) (certPEM, keyPEM []byte, err error) {
	for _, der := range c.Certificate {
		certPEM = append(certPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	der, err := x509.MarshalPKCS8PrivateKey(c.PrivateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("encode key: %w", err)
	}
	return certPEM, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// writeNew creates path exclusively with mode, writes data and syncs it.
func writeNew(path string, data []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode) //nolint:gosec // G304: a fixed name in the key directory
	if err != nil {
		return fmt.Errorf("write %s: %w", filepath.Base(path), err)
	}
	err = f.Chmod(mode) // the umask must not change it
	if err == nil {
		_, err = f.Write(data)
	}
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return fmt.Errorf("write %s: %w", filepath.Base(path), err)
	}
	return nil
}

func syncDir(dir string) error {
	d, err := os.Open(dir) //nolint:gosec // G304: the key directory
	if err != nil {
		return fmt.Errorf("sync the key directory: %w", err)
	}
	err = d.Sync()
	if cerr := d.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return fmt.Errorf("sync the key directory: %w", err)
	}
	return nil
}
