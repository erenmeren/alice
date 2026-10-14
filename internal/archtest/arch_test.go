package archtest

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// Allowed internal imports per package. A key or entry ending in "/..." covers
// the package and everything below it; other entries are exact. A package may
// always import packages inside its own rule subtree.
var rules = map[string][]string{
	"alice/internal/platform/...":  {},
	"alice/internal/version/...":   {},
	"alice/internal/webui/...":     {},
	"alice/internal/archtest/...":  {},
	"alice/internal/i18n/...":      {platform},
	"alice/internal/rbac/...":      {platform},
	"alice/internal/secrets/...":   {platform},
	"alice/internal/audit/...":     {platform},
	"alice/internal/license/...":   {platform, "alice/internal/secrets/...", "alice/internal/audit/..."},
	"alice/internal/notify/...":    {platform, "alice/internal/i18n/...", "alice/internal/secrets/...", "alice/internal/audit/..."},
	"alice/internal/auth/...":      {platform, "alice/internal/rbac/...", "alice/internal/secrets/...", "alice/internal/audit/...", "alice/internal/notify/..."},
	"alice/internal/certs/...":     {platform, "alice/internal/secrets/..."},
	"alice/internal/providers":     {platform, "alice/internal/secrets/..."},
	"alice/internal/providers/...": {platform, "alice/internal/providers", "alice/internal/providers/linuxssh/..."},
	// The test world of the linuxssh provider runs the real nginx configuration parser, so that an
	// emulated nginx-dump parses configuration text the way the helper does.
	"alice/internal/providers/linuxssh/linuxsshtest": {platform, "alice/internal/providers/linuxssh/...", "alice/internal/providers/nginx/nginxconf"},
	// The inventory drives the ACME client for the account operations (Task 9) and reads the dns01 limits and builds
	// a hook's dns01 configuration; the client and solvers never import it back.
	"alice/internal/inventory/...": {platform, "alice/internal/secrets/...", "alice/internal/audit/...", "alice/internal/license/...", "alice/internal/rbac/...", "alice/internal/providers", "alice/internal/certs/...", "alice/internal/acme/keygen",
		"alice/internal/acme", "alice/internal/acme/transport", "alice/internal/acme/solver", "alice/internal/acme/solver/dns01", "alice/internal/acme/renew"},
	"alice/internal/jobs/...": {platform, "alice/internal/audit/...", "alice/internal/license/...", "alice/internal/inventory/...", "alice/internal/providers", "alice/internal/notify/...", "alice/internal/sshkeys/..."},
	// The ACME jobs drive an order: the client, the solver contract and both solvers (an HTTP-01 publisher is the target
	// session of the provider registry, reached through the providers interface), the key and CSR, and the inventory.
	"alice/internal/jobs/acmejobs": {platform, "alice/internal/audit/...", "alice/internal/license/...", "alice/internal/inventory/...",
		"alice/internal/providers", "alice/internal/jobs", "alice/internal/acme", "alice/internal/acme/solver", "alice/internal/acme/solver/dns01",
		"alice/internal/acme/solver/http01", "alice/internal/acme/keygen", "alice/internal/secrets"},
	// The network discovery jobs run the scanner (the scan handler, the schedule and the retention tasks) and queue a scan
	// with its job in one transaction: the scanner package and the job queue, never the probe or the inventory. The audit
	// log takes the discovery.scan.finished row where a scan ends.
	"alice/internal/jobs/netdiscojobs": {platform, "alice/internal/license/...", "alice/internal/jobs", "alice/internal/discovery",
		"alice/internal/audit"},
	"alice/internal/setup/...": {platform, "alice/internal/auth/...", "alice/internal/secrets/...", "alice/internal/audit/...", "alice/internal/rbac/...", "alice/internal/notify/..."},
	"alice/internal/api/...": {platform, "alice/internal/i18n/...", "alice/internal/version/...", "alice/internal/rbac/...",
		"alice/internal/secrets/...", "alice/internal/audit/...", "alice/internal/license/...", "alice/internal/notify/...",
		"alice/internal/auth/...", "alice/internal/setup/...", "alice/internal/inventory/...", "alice/internal/jobs/...", "alice/internal/providers", "alice/internal/sshkeys/...",
		"alice/internal/alerts/...", "alice/internal/reports/...", "alice/internal/backup/...",
		// Network discovery (Task 9): the scope model and its errors, and the discovery service; never the probe.
		"alice/internal/discovery", "alice/internal/discovery/discoverysvc"},
	// SSH key lifecycle (Phase 6). keymat and plan are pure: exact keys win over the subtree rule.
	"alice/internal/sshkeys/...": {platform, "alice/internal/secrets/...", "alice/internal/audit/...", "alice/internal/license/...",
		"alice/internal/rbac/...", "alice/internal/providers", "alice/internal/inventory/..."},
	"alice/internal/sshkeys/keymat": {platform, "alice/internal/secrets/..."},
	"alice/internal/sshkeys/plan":   {platform, "alice/internal/sshkeys/keymat"},
	// Phase 7 (R42 row 1): the alert module, the read-only reports module and the pure packages.
	"alice/internal/alerts/...":    {platform, "alice/internal/audit/...", "alice/internal/license/...", "alice/internal/notify/..."},
	"alice/internal/alerts/expiry": {platform},
	"alice/internal/reports/...": {platform, "alice/internal/audit/...", "alice/internal/license/...", "alice/internal/inventory/...",
		"alice/internal/notify/...", "alice/internal/alerts/...", "alice/internal/jobs/...", "alice/internal/rbac/..."},
	"alice/internal/auth/oidc/claims": {platform, "alice/internal/rbac/..."},
	// ACME (plan 2026-10-13): the guarded outbound transport knows the platform and nothing else.
	"alice/internal/acme/transport": {"alice/internal/platform/netaddr"},
	// The ACME client wraps golang.org/x/crypto/acme: the transport, the solver contract and the platform, never
	// the API or the inventory (they call it, not the other way round). The solver contract knows the platform only.
	"alice/internal/acme":        {platform, "alice/internal/acme/transport", "alice/internal/acme/solver"},
	"alice/internal/acme/solver": {platform},
	// The DNS-01 hook solver implements the solver contract, goes out through the guarded transport, reports its
	// failures as the client's *acme.Error and holds the hook secret as a secrets.Plaintext. No database.
	"alice/internal/acme/solver/dns01": {platform, "alice/internal/acme", "alice/internal/acme/transport", "alice/internal/acme/solver", "alice/internal/secrets"},
	// The HTTP-01 solver publishes through a Publisher interface of its own (the linuxssh connection satisfies it;
	// the provider is never imported) and fetches the token URL through netaddr. No database, no secret.
	"alice/internal/acme/solver/http01": {platform, "alice/internal/acme", "alice/internal/acme/solver"},
	// Key generation and signing requests of ACME orders are pure: the key DER is a secrets.Plaintext; no database,
	// file, network or clock. The inventory seals what it generates (the only Alice package that imports it).
	"alice/internal/acme/keygen": {"alice/internal/secrets"},
	// The renewal decision (Task 11) is pure: times in, a decision out; the inventory applies it.
	"alice/internal/acme/renew": {},
	// Phase 8: the backup container is pure (io.Reader/io.Writer only, no file, socket or database); the dump
	// knows no other Alice module; the backup module runs the dump, the container and the restore; the audit
	// forwarder reads the audit log and nothing else.
	"alice/internal/backup/format": {"alice/internal/secrets"},
	"alice/internal/backup/dump":   {platform},
	"alice/internal/backup/...": {platform, "alice/internal/audit/...", "alice/internal/secrets/...", "alice/internal/notify/...",
		"alice/internal/license/...", "alice/migrations"},
	"alice/internal/audit/forward": {platform, "alice/internal/audit"},
	// Test helpers (build tag integration) start PostgreSQL and apply the embedded migrations.
	"alice/internal/testutil/...": {platform, "alice/migrations"},
	// The fake ACME CA is a stand-alone RFC 8555 server: it imports the clock and no other package of Alice, so
	// it cannot drift towards the code it tests (golang.org/x/crypto/acme is outside the module's rules).
	"alice/internal/testutil/fakeacme": {"alice/internal/platform/clock"},
	// The fake TLS fleet of the network discovery tests (plan 2026-10-13-network-discovery) builds its certificates
	// with the test PKI, reads the real clock and imports nothing else of Alice: it cannot drift towards the
	// discovery code it tests.
	"alice/internal/testutil/fakefleet": {"alice/internal/testutil/pki", "alice/internal/platform/clock"},
	// Network certificate discovery (plan 2026-10-13-network-discovery): the scope model, its expansion and the
	// scanner know the platform (netaddr's scan policy above all) and the license gate (the scanner asks it before every
	// batch, amendment A5); the probe knows the platform only.
	"alice/internal/discovery/...":      {platform, "alice/internal/license/..."},
	"alice/internal/discovery/tlsprobe": {platform},
	// The discovery service behind the API (Task 9): scopes, settings, scans (queued with their job and audit row in one
	// transaction through netdiscojobs.StartTx) and the read side; never the probe, the inventory or the providers.
	"alice/internal/discovery/discoverysvc": {platform, "alice/internal/license/...", "alice/internal/audit", "alice/internal/jobs",
		"alice/internal/discovery", "alice/internal/jobs/netdiscojobs"},
}

const platform = "alice/internal/platform/..."

// denied lists imports that are forbidden even though a broader allow entry
// covers them. Providers are pure adapters and have no database access (§5.4 rule 2).
var denied = map[string][]string{
	"alice/internal/certs/...":                       {"alice/internal/platform/db/..."},
	"alice/internal/providers":                       {"alice/internal/platform/db/..."},
	"alice/internal/providers/...":                   {"alice/internal/platform/db/..."},
	"alice/internal/providers/linuxssh/linuxsshtest": {"alice/internal/platform/db/..."},
	"alice/internal/sshkeys/keymat":                  {"alice/internal/platform/db/..."},
	"alice/internal/sshkeys/plan":                    {"alice/internal/platform/db/..."},
	"alice/internal/alerts/expiry":                   {"alice/internal/platform/db/..."},
	"alice/internal/auth/oidc/claims":                {"alice/internal/platform/db/..."},
	"alice/internal/platform/csvx":                   {"alice/internal/platform/db/..."},
	"alice/internal/backup/format":                   {platform, "alice/internal/platform/db/..."},
	"alice/internal/acme":                            {"alice/internal/platform/db/..."},
	"alice/internal/acme/solver":                     {"alice/internal/platform/db/..."},
	"alice/internal/acme/solver/dns01":               {"alice/internal/platform/db/..."},
	"alice/internal/acme/solver/http01":              {"alice/internal/platform/db/..."},
	"alice/internal/acme/keygen":                     {"alice/internal/platform/db/..."},
	"alice/internal/acme/renew":                      {"alice/internal/platform/db/..."},
}

// deniedStd lists standard-library imports the pure packages must not use: no file, process, socket,
// database or syscall access. keymat uses net/netip (address parsing), which does no I/O and is not
// listed; every other net package is.
var deniedStd = map[string][]string{
	"alice/internal/sshkeys/keymat": pureDenied,
	"alice/internal/sshkeys/plan":   pureDenied,
	// Phase 7: claims parses URLs, which does no I/O, so net/url is not denied for it.
	"alice/internal/alerts/expiry":    pureDenied,
	"alice/internal/platform/csvx":    pureDenied,
	"alice/internal/auth/oidc/claims": pureDeniedURL,
	// Phase 8: the backup container works on io.Reader and io.Writer only.
	"alice/internal/backup/format": pureDenied,
	// ACME (plan 2026-10-13): key generation and signing requests.
	"alice/internal/acme/keygen": pureDenied,
	"alice/internal/acme/renew":  pureDenied,
}

var pureDenied = []string{"os/...", "net", "net/http/...", "net/rpc/...", "net/smtp", "net/textproto", "net/url", "net/mail",
	"database/...", "syscall/...", "io/ioutil", "io/fs", "plugin", "unsafe", "runtime/...", "internal/..."}

// pureDeniedURL is pureDenied without net/url.
var pureDeniedURL = []string{"os/...", "net", "net/http/...", "net/rpc/...", "net/smtp", "net/textproto", "net/mail",
	"database/...", "syscall/...", "io/ioutil", "io/fs", "plugin", "unsafe", "runtime/...", "internal/..."}

// allowed decides whether package pkg may import imp. It is a pure function so
// the rules can be tested with positive and negative cases.
func allowed(pkg, imp string) error {
	if !strings.HasPrefix(imp, "alice/") {
		for _, d := range deniedStd[pkg] {
			if covers(d, imp) {
				return fmt.Errorf("%s must not import %s (pure package)", pkg, imp)
			}
		}
		return nil // standard library and third-party packages are not governed here
	}
	if strings.HasPrefix(pkg, "alice/cmd/") {
		return nil // the composition root may import everything
	}
	key, ok := ruleFor(pkg)
	if !ok {
		return fmt.Errorf("%s has no import rule; add it to internal/archtest", pkg)
	}
	for _, d := range denied[key] {
		if covers(d, imp) {
			return fmt.Errorf("%s must not import %s (denied by rule %q)", pkg, imp, key)
		}
	}
	// A package may import its own subpackages. Provider implementations are
	// siblings, so for them "own" means their own subtree, not the whole rule subtree.
	if key == "alice/internal/providers/..." {
		if imp == pkg || strings.HasPrefix(imp, pkg+"/") {
			return nil
		}
	} else if covers(key, imp) {
		return nil
	}
	for _, a := range rules[key] {
		if covers(a, imp) {
			return nil
		}
	}
	return fmt.Errorf("%s must not import %s (rule %q)", pkg, imp, key)
}

func covers(pattern, pkg string) bool {
	if base, ok := strings.CutSuffix(pattern, "/..."); ok {
		return pkg == base || strings.HasPrefix(pkg, base+"/")
	}
	return pkg == pattern
}

// ruleFor returns the most specific rule key: exact keys win, then the longest subtree.
func ruleFor(pkg string) (string, bool) {
	if _, ok := rules[pkg]; ok {
		return pkg, true
	}
	best := ""
	for k := range rules {
		if covers(k, pkg) && len(k) > len(best) {
			best = k
		}
	}
	return best, best != ""
}

type goPackage struct {
	ImportPath string
	Imports    []string
}

func TestImportRules(t *testing.T) {
	root := moduleRoot(t)
	cmd := exec.Command("go", "list", "-json", "./internal/...")
	cmd.Dir = root
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	require.NoError(t, err, stderr.String())

	dec := json.NewDecoder(bytes.NewReader(out))
	for {
		var p goPackage
		if err := dec.Decode(&p); errors.Is(err, io.EOF) {
			break
		} else {
			require.NoError(t, err)
		}
		for _, imp := range p.Imports {
			if err := allowed(p.ImportPath, imp); err != nil {
				t.Error(err)
			}
		}
	}
}

func TestAllowed(t *testing.T) {
	const (
		nginx   = "alice/internal/providers/nginx"
		azurekv = "alice/internal/providers/azurekv"

		linuxsshtest = "alice/internal/providers/linuxssh/linuxsshtest"
	)
	tests := []struct {
		name, pkg, imp string
		ok             bool
	}{
		{"provider sibling denied", nginx, azurekv, false},
		{"azurekv to azureid allowed", azurekv, "alice/internal/platform/azureid", true},
		{"azurekv to platform/netaddr allowed", azurekv, "alice/internal/platform/netaddr", true},
		{"azurekv to the interface package allowed", azurekv, "alice/internal/providers", true},
		{"azurekv to certs denied", azurekv, "alice/internal/certs", false},
		{"azurekv to secrets denied", azurekv, "alice/internal/secrets", false},
		{"azurekv to the nginx provider denied", azurekv, nginx, false},
		{"azurekv to platform/db denied", azurekv, "alice/internal/platform/db", false},
		{"fakekv to the interface package denied", "alice/internal/testutil/fakekv", "alice/internal/providers", false},
		{"fakekv to azureid allowed", "alice/internal/testutil/fakekv", "alice/internal/platform/azureid", true},
		{"fakeacme to the acme package denied", "alice/internal/testutil/fakeacme", "alice/internal/acme", false},
		{"fakeacme to the clock allowed", "alice/internal/testutil/fakeacme", "alice/internal/platform/clock", true},
		{"fakeacme to netaddr denied", "alice/internal/testutil/fakeacme", "alice/internal/platform/netaddr", false},
		{"fakeacme to the interface package denied", "alice/internal/testutil/fakeacme", "alice/internal/providers", false},
		{"fakefleet to the test PKI allowed", "alice/internal/testutil/fakefleet", "alice/internal/testutil/pki", true},
		{"fakefleet to netaddr denied", "alice/internal/testutil/fakefleet", "alice/internal/platform/netaddr", false},
		{"fakefleet to the scan policy helper denied", "alice/internal/testutil/fakefleet", "alice/internal/testutil/scanpolicy", false},
		{"fakefleet to the clock allowed", "alice/internal/testutil/fakefleet", "alice/internal/platform/clock", true},
		{"discovery to the license gate allowed", "alice/internal/discovery", "alice/internal/license", true},
		{"discovery to the inventory denied", "alice/internal/discovery", "alice/internal/inventory", false},
		{"discovery to the jobs denied", "alice/internal/discovery", "alice/internal/jobs", false},
		{"tlsprobe to the license gate denied", "alice/internal/discovery/tlsprobe", "alice/internal/license", false},
		{"azureid to anything of Alice denied", "alice/internal/platform/azureid", "alice/internal/providers", false},
		{"provider to platform/db denied", nginx, "alice/internal/platform/db", false},
		{"provider interface pkg to platform/db denied", "alice/internal/providers", "alice/internal/platform/db", false},
		{"provider to platform/clock allowed", nginx, "alice/internal/platform/clock", true},
		{"provider to interface package allowed", nginx, "alice/internal/providers", true},
		{"provider to linuxssh allowed", nginx, "alice/internal/providers/linuxssh", true},
		{"provider to own subpackage allowed", nginx, nginx + "/internal", true},
		{"nginxconf to helperproto allowed", nginx + "/nginxconf", "alice/internal/providers/linuxssh/helperproto", true},
		{"linuxsshtest to nginxconf allowed", linuxsshtest, "alice/internal/providers/nginx/nginxconf", true},
		{"linuxsshtest to the nginx provider denied", linuxsshtest, nginx, false},
		{"linuxsshtest to platform/db denied", linuxsshtest, "alice/internal/platform/db", false},
		{"nginxconf to platform/db denied", nginx + "/nginxconf", "alice/internal/platform/db", false},
		{"platform to i18n denied", "alice/internal/platform/clock", "alice/internal/i18n", false},
		{"platform to platform allowed", "alice/internal/platform/db", "alice/internal/platform/clock", true},
		{"api to provider impl denied", "alice/internal/api", nginx, false},
		{"api to provider interface allowed", "alice/internal/api", "alice/internal/providers", true},
		{"api to platform/db allowed", "alice/internal/api", "alice/internal/platform/db", true},
		{"cmd to provider impl allowed", "alice/cmd/alice", nginx, true},
		{"third-party import ignored", nginx, "github.com/x/y", true},
		{"unknown package rejected", "alice/internal/mystery", "alice/internal/version", false},
		{"setup to auth allowed", "alice/internal/setup", "alice/internal/auth", true},
		{"setup to api denied", "alice/internal/setup", "alice/internal/api", false},
		{"api to setup allowed", "alice/internal/api", "alice/internal/setup", true},
		{"auth to setup denied", "alice/internal/auth", "alice/internal/setup", false},
		{"testutil to migrations allowed", "alice/internal/testutil/pgtest", "alice/migrations", true},
		{"certs to secrets allowed", "alice/internal/certs", "alice/internal/secrets", true},
		{"certs to platform/db denied", "alice/internal/certs", "alice/internal/platform/db", false},
		{"testutil to auth denied", "alice/internal/testutil/pgtest", "alice/internal/auth", false},
		{"sshkeys to inventory allowed", "alice/internal/sshkeys", "alice/internal/inventory", true},
		{"sshkeys to jobs denied", "alice/internal/sshkeys", "alice/internal/jobs", false},
		{"sshkeys to notify denied", "alice/internal/sshkeys", "alice/internal/notify", false},
		{"sshkeys to api denied", "alice/internal/sshkeys", "alice/internal/api", false},
		{"plan to keymat allowed", "alice/internal/sshkeys/plan", "alice/internal/sshkeys/keymat", true},
		{"keymat to platform/db denied", "alice/internal/sshkeys/keymat", "alice/internal/platform/db", false},
		{"plan to platform/db denied", "alice/internal/sshkeys/plan", "alice/internal/platform/db", false},
		{"sshkeyjobs to sshkeys allowed", "alice/internal/jobs/sshkeyjobs", "alice/internal/sshkeys", true},
		{"api to sshkeys allowed", "alice/internal/api", "alice/internal/sshkeys", true},
		{"inventory to sshkeys denied", "alice/internal/inventory", "alice/internal/sshkeys", false},
		{"keymat to inventory denied", "alice/internal/sshkeys/keymat", "alice/internal/inventory", false},
		{"plan to secrets denied", "alice/internal/sshkeys/plan", "alice/internal/secrets", false},
		{"plan to os denied", "alice/internal/sshkeys/plan", "os", false},
		{"plan to os/exec denied", "alice/internal/sshkeys/plan", "os/exec", false},
		{"plan to syscall denied", "alice/internal/sshkeys/plan", "syscall", false},
		{"plan to net denied", "alice/internal/sshkeys/plan", "net", false},
		{"plan to net/http denied", "alice/internal/sshkeys/plan", "net/http", false},
		{"plan to database/sql denied", "alice/internal/sshkeys/plan", "database/sql", false},
		{"keymat to os denied", "alice/internal/sshkeys/keymat", "os", false},
		{"keymat to net/netip allowed", "alice/internal/sshkeys/keymat", "net/netip", true},
		{"keymat to net/http denied", "alice/internal/sshkeys/keymat", "net/http", false},
		{"keymat to database/sql/driver denied", "alice/internal/sshkeys/keymat", "database/sql/driver", false},
		{"keymat to io allowed", "alice/internal/sshkeys/keymat", "io", true},
		{"plan to time allowed", "alice/internal/sshkeys/plan", "time", true},
		{"alerts to notify allowed", "alice/internal/alerts", "alice/internal/notify", true},
		{"alerts to inventory denied", "alice/internal/alerts", "alice/internal/inventory", false},
		{"alerts to reports denied", "alice/internal/alerts", "alice/internal/reports", false},
		{"expiry to platform/db denied", "alice/internal/alerts/expiry", "alice/internal/platform/db", false},
		{"expiry to alerts denied", "alice/internal/alerts/expiry", "alice/internal/alerts", false},
		{"expiry to os denied", "alice/internal/alerts/expiry", "os", false},
		{"reports to alerts allowed", "alice/internal/reports", "alice/internal/alerts", true},
		{"reports to jobs allowed", "alice/internal/reports", "alice/internal/jobs", true},
		{"reports to auth denied", "alice/internal/reports", "alice/internal/auth", false},
		{"reports to api denied", "alice/internal/reports", "alice/internal/api", false},
		{"claims to rbac allowed", "alice/internal/auth/oidc/claims", "alice/internal/rbac", true},
		{"claims to net/url allowed", "alice/internal/auth/oidc/claims", "net/url", true},
		{"claims to net/http denied", "alice/internal/auth/oidc/claims", "net/http", false},
		{"claims to secrets denied", "alice/internal/auth/oidc/claims", "alice/internal/secrets", false},
		{"oidc to auth allowed", "alice/internal/auth/oidc", "alice/internal/auth", true},
		{"oidc to inventory denied", "alice/internal/auth/oidc", "alice/internal/inventory", false},
		{"acme transport to platform allowed", "alice/internal/acme/transport", "alice/internal/platform/netaddr", true},
		{"acme transport to secrets denied", "alice/internal/acme/transport", "alice/internal/secrets", false},
		{"acme transport to platform/db denied", "alice/internal/acme/transport", "alice/internal/platform/db", false},
		{"acme to transport allowed", "alice/internal/acme", "alice/internal/acme/transport", true},
		{"dns01 to solver contract allowed", "alice/internal/acme/solver/dns01", "alice/internal/acme/solver", true},
		{"dns01 to transport allowed", "alice/internal/acme/solver/dns01", "alice/internal/acme/transport", true},
		{"dns01 to acme client allowed", "alice/internal/acme/solver/dns01", "alice/internal/acme", true},
		{"dns01 to secrets allowed", "alice/internal/acme/solver/dns01", "alice/internal/secrets", true},
		{"dns01 to platform/db denied", "alice/internal/acme/solver/dns01", "alice/internal/platform/db", false},
		{"dns01 to inventory denied", "alice/internal/acme/solver/dns01", "alice/internal/inventory", false},
		{"dns01 to fakeacme denied", "alice/internal/acme/solver/dns01", "alice/internal/testutil/fakeacme", false},
		{"solver contract to dns01 denied", "alice/internal/acme/solver", "alice/internal/acme/solver/dns01", false},
		{"acme to dns01 denied", "alice/internal/acme", "alice/internal/acme/solver/dns01", false},
		{"http01 to solver contract allowed", "alice/internal/acme/solver/http01", "alice/internal/acme/solver", true},
		{"http01 to acme client allowed", "alice/internal/acme/solver/http01", "alice/internal/acme", true},
		{"http01 to netaddr allowed", "alice/internal/acme/solver/http01", "alice/internal/platform/netaddr", true},
		{"http01 to linuxssh denied", "alice/internal/acme/solver/http01", "alice/internal/providers/linuxssh", false},
		{"http01 to providers denied", "alice/internal/acme/solver/http01", "alice/internal/providers", false},
		{"http01 to secrets denied", "alice/internal/acme/solver/http01", "alice/internal/secrets", false},
		{"http01 to platform/db denied", "alice/internal/acme/solver/http01", "alice/internal/platform/db", false},
		{"acme to http01 denied", "alice/internal/acme", "alice/internal/acme/solver/http01", false},
		{"renew to time allowed", "alice/internal/acme/renew", "time", true},
		{"renew to platform denied", "alice/internal/acme/renew", "alice/internal/platform/clock", false},
		{"renew to platform/db denied", "alice/internal/acme/renew", "alice/internal/platform/db", false},
		{"renew to acme denied", "alice/internal/acme/renew", "alice/internal/acme", false},
		{"renew to net/http denied", "alice/internal/acme/renew", "net/http", false},
		{"inventory to renew allowed", "alice/internal/inventory", "alice/internal/acme/renew", true},
		{"acme to solver allowed", "alice/internal/acme", "alice/internal/acme/solver", true},
		{"acme to netaddr allowed", "alice/internal/acme", "alice/internal/platform/netaddr", true},
		{"keygen to secrets allowed", "alice/internal/acme/keygen", "alice/internal/secrets", true},
		{"keygen to platform denied", "alice/internal/acme/keygen", "alice/internal/platform/clock", false},
		{"keygen to platform/db denied", "alice/internal/acme/keygen", "alice/internal/platform/db", false},
		{"keygen to acme client denied", "alice/internal/acme/keygen", "alice/internal/acme", false},
		{"keygen to os denied", "alice/internal/acme/keygen", "os", false},
		{"keygen to net/http denied", "alice/internal/acme/keygen", "net/http", false},
		{"inventory to keygen allowed", "alice/internal/inventory", "alice/internal/acme/keygen", true},
		{"inventory to acme client allowed", "alice/internal/inventory", "alice/internal/acme", true},
		{"inventory to acme transport allowed", "alice/internal/inventory", "alice/internal/acme/transport", true},
		{"inventory to dns01 allowed", "alice/internal/inventory", "alice/internal/acme/solver/dns01", true},
		{"inventory to http01 denied", "alice/internal/inventory", "alice/internal/acme/solver/http01", false},
		{"inventory to the solver contract allowed", "alice/internal/inventory", "alice/internal/acme/solver", true},
		{"acmejobs to http01 allowed", "alice/internal/jobs/acmejobs", "alice/internal/acme/solver/http01", true},
		{"acmejobs to dns01 allowed", "alice/internal/jobs/acmejobs", "alice/internal/acme/solver/dns01", true},
		{"acmejobs to linuxssh denied", "alice/internal/jobs/acmejobs", "alice/internal/providers/linuxssh", false},
		{"acmejobs to transport denied", "alice/internal/jobs/acmejobs", "alice/internal/acme/transport", false},
		{"acmejobs to fakeacme denied", "alice/internal/jobs/acmejobs", "alice/internal/testutil/fakeacme", false},
		{"kvjobs to acme denied", "alice/internal/jobs/kvjobs", "alice/internal/acme", false},
		{"netdiscojobs to discovery allowed", "alice/internal/jobs/netdiscojobs", "alice/internal/discovery", true},
		{"netdiscojobs to jobs allowed", "alice/internal/jobs/netdiscojobs", "alice/internal/jobs", true},
		{"netdiscojobs to tlsprobe denied", "alice/internal/jobs/netdiscojobs", "alice/internal/discovery/tlsprobe", false},
		{"netdiscojobs to inventory denied", "alice/internal/jobs/netdiscojobs", "alice/internal/inventory", false},
		{"netdiscojobs to providers denied", "alice/internal/jobs/netdiscojobs", "alice/internal/providers", false},
		{"netdiscojobs to audit allowed", "alice/internal/jobs/netdiscojobs", "alice/internal/audit", true},
		{"discoverysvc to netdiscojobs allowed", "alice/internal/discovery/discoverysvc", "alice/internal/jobs/netdiscojobs", true},
		{"discoverysvc to discovery allowed", "alice/internal/discovery/discoverysvc", "alice/internal/discovery", true},
		{"discoverysvc to audit allowed", "alice/internal/discovery/discoverysvc", "alice/internal/audit", true},
		{"discoverysvc to tlsprobe denied", "alice/internal/discovery/discoverysvc", "alice/internal/discovery/tlsprobe", false},
		{"discoverysvc to inventory denied", "alice/internal/discovery/discoverysvc", "alice/internal/inventory", false},
		{"discoverysvc to api denied", "alice/internal/discovery/discoverysvc", "alice/internal/api", false},
		{"api to discovery allowed", "alice/internal/api", "alice/internal/discovery", true},
		{"api to discoverysvc allowed", "alice/internal/api", "alice/internal/discovery/discoverysvc", true},
		{"api to tlsprobe denied", "alice/internal/api", "alice/internal/discovery/tlsprobe", false},
		{"inventory to fakeacme denied", "alice/internal/inventory", "alice/internal/testutil/fakeacme", false},
		{"acme to clock allowed", "alice/internal/acme", "alice/internal/platform/clock", true},
		{"acme to api denied", "alice/internal/acme", "alice/internal/api", false},
		{"acme to inventory denied", "alice/internal/acme", "alice/internal/inventory", false},
		{"acme to secrets denied", "alice/internal/acme", "alice/internal/secrets", false},
		{"acme to platform/db denied", "alice/internal/acme", "alice/internal/platform/db", false},
		{"acme to fakeacme denied", "alice/internal/acme", "alice/internal/testutil/fakeacme", false},
		{"solver to platform allowed", "alice/internal/acme/solver", "alice/internal/platform/netaddr", true},
		{"solver to acme denied", "alice/internal/acme/solver", "alice/internal/acme", false},
		{"solver to transport denied", "alice/internal/acme/solver", "alice/internal/acme/transport", false},
		{"solver to api denied", "alice/internal/acme/solver", "alice/internal/api", false},
		{"solver to inventory denied", "alice/internal/acme/solver", "alice/internal/inventory", false},
		{"csvx to os denied", "alice/internal/platform/csvx", "os", false},
		{"notify to audit allowed", "alice/internal/notify", "alice/internal/audit", true},
		{"notify to inventory denied", "alice/internal/notify", "alice/internal/inventory", false},
		{"api to reports allowed", "alice/internal/api", "alice/internal/reports", true},
		{"format to secrets allowed", "alice/internal/backup/format", "alice/internal/secrets", true},
		{"format to platform/db denied", "alice/internal/backup/format", "alice/internal/platform/db", false},
		{"format to platform/clock denied", "alice/internal/backup/format", "alice/internal/platform/clock", false},
		{"format to audit denied", "alice/internal/backup/format", "alice/internal/audit", false},
		{"format to os denied", "alice/internal/backup/format", "os", false},
		{"format to net denied", "alice/internal/backup/format", "net", false},
		{"format to crypto/hkdf allowed", "alice/internal/backup/format", "crypto/hkdf", true},
		{"dump to platform/db allowed", "alice/internal/backup/dump", "alice/internal/platform/db", true},
		{"dump to audit denied", "alice/internal/backup/dump", "alice/internal/audit", false},
		{"dump to secrets denied", "alice/internal/backup/dump", "alice/internal/secrets", false},
		{"backup to migrations allowed", "alice/internal/backup", "alice/migrations", true},
		{"backup to format allowed", "alice/internal/backup", "alice/internal/backup/format", true},
		{"backup to notify allowed", "alice/internal/backup", "alice/internal/notify", true},
		{"backup to inventory denied", "alice/internal/backup", "alice/internal/inventory", false},
		{"backup to api denied", "alice/internal/backup", "alice/internal/api", false},
		{"forward to audit allowed", "alice/internal/audit/forward", "alice/internal/audit", true},
		{"forward to platform/netaddr allowed", "alice/internal/audit/forward", "alice/internal/platform/netaddr", true},
		{"forward to notify denied", "alice/internal/audit/forward", "alice/internal/notify", false},
		{"forward to secrets denied", "alice/internal/audit/forward", "alice/internal/secrets", false},
		{"api to backup allowed", "alice/internal/api", "alice/internal/backup", true},
		{"api to format allowed", "alice/internal/api", "alice/internal/backup/format", true},
		{"setup to notify allowed", "alice/internal/setup", "alice/internal/notify", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := allowed(tc.pkg, tc.imp)
			if tc.ok {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}
		})
	}
}

func TestRuleMatching(t *testing.T) {
	k, _ := ruleFor("alice/internal/providers")
	require.Equal(t, "alice/internal/providers", k)
	k, _ = ruleFor("alice/internal/providers/nginx")
	require.Equal(t, "alice/internal/providers/...", k)
	k, _ = ruleFor("alice/internal/platform/db")
	require.Equal(t, "alice/internal/platform/...", k)
	_, ok := ruleFor("alice/internal/platformx")
	require.False(t, ok)
}

func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	require.NoError(t, err)
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		require.NotEqual(t, parent, dir, "go.mod not found")
		dir = parent
	}
}
