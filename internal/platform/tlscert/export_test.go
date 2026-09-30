package tlscert

import (
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
