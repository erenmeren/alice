package route53

import (
	"time"

	"alice/internal/secrets"
	"alice/internal/testutil/fakeroute53"
)

// The package's test seams: the unexported address mapping of Config (every test reaches the in-process fake
// through it, with the fake's CA as BaseRoots) and the provider's clock.

// fakeConfig is a Config that reaches f with its long-term key.
func fakeConfig(f *fakeroute53.Server) Config {
	return Config{
		AccessKeyID:     f.AccessKeyID(),
		SecretAccessKey: secrets.NewPlaintext([]byte(f.SecretAccessKey())),
		BaseRoots:       f.CAPool(),
		mapAddr:         f.MapAddr,
	}
}

// withMapAddr sets the address mapping of c.
func withMapAddr(c Config, f func(string) string) Config {
	c.mapAddr = f
	return c
}

// setNow replaces the provider's clock.
func (p *Provider) setNow(now func() time.Time) { p.now = now }
