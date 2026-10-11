package tlscert

import (
	"crypto/x509"
	"testing"
	"time"
)

// GenerateForTest exposes certificate generation with a custom organization to tests.
func GenerateForTest(t *testing.T, org string, notBefore, notAfter time.Time) (certPEM, keyPEM []byte) {
	t.Helper()
	c, k, err := generate(org, []string{"localhost"}, notBefore, notAfter)
	if err != nil {
		t.Fatal(err)
	}
	return c, k
}

// Install stages for SetInstallHook.
const (
	StageKeyWritten     = stageKeyWritten
	StageFilesWritten   = stageFilesWritten
	StageBetweenRenames = stageBetweenRenames
)

// SetInstallHook calls f at each Install stage; a non-nil error stops Install there without any cleanup, as a
// crash would.
func SetInstallHook(s *Store, f func(stage string) error) { s.hook = f }

// SetSystemRootsForTest makes the given certificates the only system roots until restore is called.
func SetSystemRootsForTest(roots ...*x509.Certificate) (restore func()) {
	saved := systemRoots
	systemRoots = func() (*x509.CertPool, error) {
		p := x509.NewCertPool()
		for _, r := range roots {
			p.AddCert(r)
		}
		return p, nil
	}
	return func() { systemRoots = saved }
}
