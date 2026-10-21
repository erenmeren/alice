package cloudflare

// WithMapAddr sets the unexported address mapping of cfg (the package's own tests reach the in-process fake).
func WithMapAddr(cfg Config, f func(string) string) Config {
	cfg.mapAddr = f
	return cfg
}
