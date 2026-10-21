package azuredns

// WithMapAddr returns c with the package's address mapping set: every connection (the Resource Manager, the login
// host and the managed identity's metadata endpoint) goes through f, which must map the fake's names.
func WithMapAddr(c Config, f func(string) string) Config {
	c.mapAddr = f
	return c
}
