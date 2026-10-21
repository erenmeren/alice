// Package lestaging is the Let's Encrypt staging acceptance harness (docs/dev/le-staging-acceptance.md): it runs
// Alice's real ACME code paths end to end against a real certificate authority's staging service and prints a PASS
// or FAIL line per step. It is driven by ALICE_LE_* environment variables and runs only through the lestaging build
// tag (make le-staging); without the variables it skips. The untagged tests drive the same code against the fake
// ACME CA (internal/testutil/fakeacme), so the harness itself is covered by make test and make coverage.
//
// What runs is Alice's own code: internal/acme (directory, account, order, finalize, chain download, renewal
// information, replaces, revocation), the guarded transport, internal/acme/keygen and the real solvers
// (internal/acme/solver/http01 with a local publisher, internal/acme/solver/dns01 against your DNS hook). Only the
// HTTP-01 publisher (a local listener or a webroot instead of a server's alice-helper), the "manual" DNS provider and
// the persistence (a state directory instead of the database) belong to the harness.
//
// It never contacts the production Let's Encrypt service unless ALICE_LE_ALLOW_PRODUCTION=yes is set as well.
package lestaging

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"alice/internal/acme"
	"alice/internal/acme/keygen"
	"alice/internal/acme/solver"
)

// StagingDirectory is the Let's Encrypt staging ACME directory, the default.
const StagingDirectory = "https://acme-staging-v02.api.letsencrypt.org/directory"

// productionHosts are the hosts of the production Let's Encrypt ACME service (ACME v1 is retired), refused without
// ALICE_LE_ALLOW_PRODUCTION.
var productionHosts = []string{"acme-v02.api.letsencrypt.org"}

// StagingRootURLs are the self-signed roots of the Let's Encrypt staging hierarchy, fetched at run time (Let's
// Encrypt asks not to pin them: https://letsencrypt.org/docs/staging-environment/). Pretend Pear X1 (RSA), Bogus
// Broccoli X2 (ECDSA) and the generation Y roots Yearning Yucca YE and Yonder Yam YR.
var StagingRootURLs = []string{
	"https://letsencrypt.org/certs/staging/letsencrypt-stg-root-x1.pem",
	"https://letsencrypt.org/certs/staging/letsencrypt-stg-root-x2.pem",
	"https://letsencrypt.org/certs/staging/gen-y/root-ye.pem",
	"https://letsencrypt.org/certs/staging/gen-y/root-yr.pem",
}

// The environment variables. Every name the harness reads is listed here (and in the runbook).
const (
	EnvDomain          = "ALICE_LE_DOMAIN"
	EnvAcceptTOS       = "ALICE_LE_ACCEPT_TOS"
	EnvChallenge       = "ALICE_LE_CHALLENGE"
	EnvWildcard        = "ALICE_LE_WILDCARD"
	EnvEmail           = "ALICE_LE_EMAIL"
	EnvDirectory       = "ALICE_LE_DIRECTORY"
	EnvAllowProduction = "ALICE_LE_ALLOW_PRODUCTION"
	EnvStateDir        = "ALICE_LE_STATE_DIR"
	EnvRootsFile       = "ALICE_LE_ROOTS_FILE"
	EnvCAFile          = "ALICE_LE_CA_FILE"
	EnvKeyType         = "ALICE_LE_KEY_TYPE"
	EnvDeactivate      = "ALICE_LE_DEACTIVATE"
	EnvHTTP01Listen    = "ALICE_LE_HTTP01_LISTEN"
	EnvHTTP01Webroot   = "ALICE_LE_HTTP01_WEBROOT"
	EnvDNSProvider     = "ALICE_LE_DNS_PROVIDER"
	EnvDNSHookURL      = "ALICE_LE_DNS_HOOK_URL"
	EnvDNSHookSecret   = "ALICE_LE_DNS_HOOK_SECRET" //nolint:gosec // the name of a variable, not a credential
	EnvDNSHookCAFile   = "ALICE_LE_DNS_HOOK_CA_FILE"
	EnvDNSWait         = "ALICE_LE_DNS_WAIT"
	EnvDNSPollTimeout  = "ALICE_LE_DNS_POLL_TIMEOUT"
	EnvDNSManualWait   = "ALICE_LE_DNS_MANUAL_TIMEOUT"
	EnvDNSResolver     = "ALICE_LE_DNS_RESOLVER"
)

// DefaultHTTP01Listen is where the local HTTP-01 publisher listens when no webroot is given.
const DefaultHTTP01Listen = ":80"

// DefaultManualTimeout is how long the manual DNS provider waits for a TXT record to become visible.
const DefaultManualTimeout = 10 * time.Minute

// Config is one run of the harness.
type Config struct {
	// DirectoryURL is the CA's ACME directory (default StagingDirectory).
	DirectoryURL string
	// Domain is the name ordered; Wildcard adds "*." + Domain (DNS-01 only).
	Domain   string
	Wildcard bool
	// Challenge is solver.HTTP01 or solver.DNS01.
	Challenge string
	// Email is the account contact ("" for none).
	Email string
	// AcceptTOS is the person's agreement to the CA's terms of service.
	AcceptTOS bool
	// StateDir keeps the account key and URL, the certificates still to revoke and the CA's earliest retry time
	// between runs.
	StateDir string
	// RootsPEM are the roots the issued chains must lead to; nil fetches StagingRootURLs at run time.
	RootsPEM []byte
	// ExpectStaging requires the issuing CA's name to carry "(STAGING)" (true for the staging directory).
	ExpectStaging bool
	// CABundlePEM is added to the system roots for the CA's own HTTPS (empty for Let's Encrypt).
	CABundlePEM string
	// KeyType is the certificate key policy (default ECDSA P-256).
	KeyType keygen.KeyPolicy
	// Deactivate deactivates the account at the end and forgets its key.
	Deactivate bool
	// HTTP01Listen and HTTP01Webroot choose the HTTP-01 publisher (a webroot wins).
	HTTP01Listen, HTTP01Webroot string
	// DNSProvider names the DNS-01 provider (RegisterDNSProvider); Getenv is handed to it for its own variables.
	DNSProvider string
	Getenv      func(string) string
	// CallTimeout and OrderTimeout are the ACME client's budgets (0: the client's defaults).
	CallTimeout, OrderTimeout time.Duration
}

// Names are the names ordered: the domain, and its wildcard when asked for.
func (c Config) Names() []string {
	n := []string{c.Domain}
	if c.Wildcard {
		n = append(n, "*."+c.Domain)
	}
	return n
}

// SkipError says the harness was not configured: a required variable is missing. A run that is not configured is
// skipped, never failed, so CI never runs the harness by accident.
type SkipError struct{ Missing []string }

func (e *SkipError) Error() string {
	return "Let's Encrypt staging acceptance not configured: set " + strings.Join(e.Missing, ", ") +
		" (docs/dev/le-staging-acceptance.md)"
}

// ErrProduction refuses the production Let's Encrypt service without the explicit flag.
var ErrProduction = errors.New("lestaging: the directory is the production Let's Encrypt service; " +
	"set " + EnvAllowProduction + "=yes to really order publicly trusted certificates")

// FromEnv reads the configuration. A missing required variable is a *SkipError; a variable with a wrong value is an
// error (the person meant to run the harness).
func FromEnv(getenv func(string) string) (Config, error) {
	get := func(k string) string { return strings.TrimSpace(getenv(k)) }
	cfg := Config{Getenv: getenv, DirectoryURL: StagingDirectory, Domain: strings.TrimSuffix(get(EnvDomain), "."),
		Email: get(EnvEmail), HTTP01Listen: get(EnvHTTP01Listen), HTTP01Webroot: get(EnvHTTP01Webroot)}
	var missing []string
	if cfg.Domain == "" {
		missing = append(missing, EnvDomain)
	}
	if !yes(get(EnvAcceptTOS)) {
		missing = append(missing, EnvAcceptTOS+"=yes (after reading the CA's terms of service)")
	}
	cfg.Challenge = get(EnvChallenge)
	if cfg.Challenge == "" {
		cfg.Challenge = solver.HTTP01
	}
	cfg.DNSProvider = get(EnvDNSProvider)
	if cfg.Challenge == solver.DNS01 && cfg.DNSProvider == "" {
		if get(EnvDNSHookURL) != "" {
			cfg.DNSProvider = "hook"
		} else {
			missing = append(missing, EnvDNSProvider+" (or "+EnvDNSHookURL+")")
		}
	}
	if len(missing) > 0 {
		return Config{}, &SkipError{Missing: missing}
	}
	cfg.AcceptTOS = true

	if d := get(EnvDirectory); d != "" {
		cfg.DirectoryURL = d
	}
	if err := checkDirectory(cfg.DirectoryURL, yes(get(EnvAllowProduction))); err != nil {
		return Config{}, err
	}
	cfg.ExpectStaging = cfg.DirectoryURL == StagingDirectory
	if _, err := acme.NormalizeNames(cfg.Names()); err != nil || strings.HasPrefix(cfg.Domain, "*.") {
		return Config{}, fmt.Errorf("lestaging: %s is not a DNS name Alice can order (give the base name; %s=yes adds the wildcard)", EnvDomain, EnvWildcard)
	}
	switch cfg.Challenge {
	case solver.HTTP01, solver.DNS01:
	default:
		return Config{}, fmt.Errorf("lestaging: %s must be %s or %s", EnvChallenge, solver.HTTP01, solver.DNS01)
	}
	cfg.Wildcard = yes(get(EnvWildcard))
	if cfg.Wildcard && cfg.Challenge != solver.DNS01 {
		return Config{}, fmt.Errorf("lestaging: a wildcard needs %s=%s", EnvChallenge, solver.DNS01)
	}
	if cfg.Challenge == solver.DNS01 {
		if _, ok := dnsProvider(cfg.DNSProvider); !ok {
			return Config{}, fmt.Errorf("lestaging: unknown %s %q (known: %s)", EnvDNSProvider, cfg.DNSProvider, strings.Join(DNSProviders(), ", "))
		}
	} else if cfg.HTTP01Webroot == "" && cfg.HTTP01Listen == "" {
		cfg.HTTP01Listen = DefaultHTTP01Listen
	}
	cfg.KeyType = keygen.Default
	if k := get(EnvKeyType); k != "" {
		p, err := keygen.ParseKeyPolicy(k)
		if err != nil {
			return Config{}, fmt.Errorf("lestaging: %s must be one of %v", EnvKeyType, keygen.Policies())
		}
		cfg.KeyType = p
	}
	cfg.Deactivate = yes(get(EnvDeactivate))
	var err error
	if cfg.StateDir, err = stateDir(get(EnvStateDir), cfg.DirectoryURL); err != nil {
		return Config{}, err
	}
	if f := get(EnvRootsFile); f != "" {
		if cfg.RootsPEM, err = os.ReadFile(f); err != nil { //nolint:gosec // a file the person named
			return Config{}, fmt.Errorf("lestaging: %s: %w", EnvRootsFile, err)
		}
	} else if !cfg.ExpectStaging && !productionDirectory(cfg.DirectoryURL) {
		return Config{}, fmt.Errorf("lestaging: a directory other than Let's Encrypt's needs %s (its roots, PEM)", EnvRootsFile)
	}
	if f := get(EnvCAFile); f != "" {
		b, err := os.ReadFile(f) //nolint:gosec // a file the person named
		if err != nil {
			return Config{}, fmt.Errorf("lestaging: %s: %w", EnvCAFile, err)
		}
		cfg.CABundlePEM = string(b)
	}
	if cfg.Challenge == solver.DNS01 && cfg.DNSProvider == "manual" {
		wait, err := durationEnv(getenv, EnvDNSManualWait, DefaultManualTimeout)
		if err != nil {
			return Config{}, err
		}
		// A person adds the record: each Present may take the whole wait, beyond the client's default budget.
		cfg.CallTimeout = wait + 2*time.Minute
		cfg.OrderTimeout = time.Duration(len(cfg.Names()))*cfg.CallTimeout + 10*time.Minute
	}
	return cfg, nil
}

// checkDirectory accepts an https directory and refuses production Let's Encrypt unless allowed.
func checkDirectory(raw string, allowProduction bool) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
		return fmt.Errorf("lestaging: %s must be an https URL", EnvDirectory)
	}
	if productionDirectory(raw) && !allowProduction {
		return ErrProduction
	}
	return nil
}

func productionDirectory(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	h := strings.TrimSuffix(asciiLower(u.Hostname()), ".")
	return slices.Contains(productionHosts, h)
}

// stateDir is the directory of this CA's state: dir (default the user cache directory) / the directory's host.
func stateDir(dir, directoryURL string) (string, error) {
	if dir == "" {
		c, err := os.UserCacheDir()
		if err != nil {
			return "", fmt.Errorf("lestaging: no cache directory; set %s", EnvStateDir)
		}
		dir = filepath.Join(c, "alice-le-staging")
	}
	u, err := url.Parse(directoryURL)
	if err != nil {
		return "", err
	}
	host := strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '.' || r == '-' {
			return r
		}
		return '_'
	}, asciiLower(u.Host))
	return filepath.Join(dir, host), nil
}

func durationEnv(getenv func(string) string, key string, def time.Duration) (time.Duration, error) {
	v := strings.TrimSpace(getenv(key))
	if v == "" {
		return def, nil
	}
	if n, err := strconv.Atoi(v); err == nil && n >= 0 {
		return time.Duration(n) * time.Second, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil || d < 0 {
		return 0, fmt.Errorf("lestaging: %s must be a number of seconds or a duration such as 90s", key)
	}
	return d, nil
}

func yes(v string) bool {
	switch asciiLower(v) {
	case "1", "yes", "true", "on":
		return true
	}
	return false
}

func asciiLower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 'a' - 'A'
		}
	}
	return string(b)
}
