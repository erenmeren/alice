package store

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRequireTLSVerification(t *testing.T) {
	for url, ok := range map[string]bool{
		"postgres://u:p@db.example.com/vendor?sslmode=verify-full": true,
		"postgres://u:p@db.example.com/vendor":                     false, // default is prefer: no verification, plaintext fallback
		"postgres://u:p@db.example.com/vendor?sslmode=prefer":      false,
		"postgres://u:p@db.example.com/vendor?sslmode=require":     false, // encrypted but not verified
		"postgres://u:p@db.example.com/vendor?sslmode=verify-ca":   false, // no host name check
		"postgres://u:p@db.example.com/vendor?sslmode=disable":     false,
		"postgres://u:p@localhost/vendor?sslmode=disable":          true, // loopback needs no TLS
		"postgres://u:p@127.0.0.1:5432/vendor":                     true,
		"postgres://u:p@[::1]:5432/vendor?sslmode=disable":         true,
	} {
		err := RequireTLSVerification(url, "SOME_ENV")
		if ok {
			assert.NoError(t, err, url)
		} else {
			assert.Error(t, err, url)
			if err != nil {
				assert.Contains(t, err.Error(), "verify-full", url)
				assert.Contains(t, err.Error(), "SOME_ENV", url)
				assert.NotContains(t, err.Error(), "u:p", "the URL is never echoed")
			}
		}
	}
	assert.Error(t, RequireTLSVerification("not a url ://", "SOME_ENV"))
}
