package pemca

import (
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"alice/internal/testutil/pki"
)

func TestValid(t *testing.T) {
	ca := pki.NewCA("pemca", pki.ECDSA256, time.Now())
	root := string(ca.RootPEM)
	key := "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"
	broken := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("not der")}))
	for name, c := range map[string]struct {
		in string
		ok bool
	}{
		"empty":         {"", true},
		"one":           {root, true},
		"two":           {root + string(ca.IntermediatePEM), true},
		"trailing ws":   {root + "\n\n", true},
		"max certs":     {strings.Repeat(root, MaxCerts), true},
		"too many":      {strings.Repeat(root, MaxCerts+1), false},
		"too large":     {root + strings.Repeat(" ", MaxBytes), false},
		"not pem":       {"not pem", false},
		"key":           {key, false},
		"cert then key": {root + key, false},
		"text after":    {root + "junk", false},
		"bad der":       {broken, false},
	} {
		assert.Equal(t, c.ok, Valid(c.in), name)
	}
}

func TestPool(t *testing.T) {
	ca := pki.NewCA("pemca", pki.ECDSA256, time.Now())
	p, ok := Pool(string(ca.RootPEM))
	assert.True(t, ok)
	_, err := ca.Intermediate.Verify(x509.VerifyOptions{Roots: p})
	assert.NoError(t, err, "the bundle is trusted")
	_, ok = Pool("")
	assert.True(t, ok)
	_, ok = Pool("not pem")
	assert.False(t, ok)
}
