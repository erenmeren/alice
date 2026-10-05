//go:build integration

package azurekv

import (
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"

	"alice/internal/platform/azureid"
	"alice/internal/platform/netaddr"
)

// This file is the only way a harness points the provider at a test listener. It exists in builds
// with the integration tag only (never in a release or e2e binary: the e2e stack needs no mapping,
// Docker's DNS answers the Azure host names with the fake service); archtest keeps every caller
// outside the non-test code of the repository.
//
// The mapping changes where a connection goes and nothing else: requests are still addressed to
// login.microsoftonline.com and <name>.vault.azure.net, the host allow-list, the TLS server name
// and every other guard stay as they are, so the TLS handshake verifies those names against the
// roots the harness gives (the fake's CA). A mapping is refused unless the roots are given: a
// mapped dial must never combine with the system roots. The fixed addresses must be loopback (the
// fake runs in the test process); the CALLER must pass the fake's own pool from RootCAs: a function that
// returns the system pool cannot be told apart from the fake's, so only a nil function and a nil pool
// are refused here.

// ErrFixedAddresses is the cause of a refused FixedAddresses.
var ErrFixedAddresses = errors.New("azurekv: invalid fixed listener address")

// ErrFixedAddressesNeedRoots is the cause of WithFixedAddresses refusing Options without RootCAs.
var ErrFixedAddressesNeedRoots = errors.New("azurekv: fixed listener addresses need RootCAs (a mapped dial never uses the system roots)")

// FixedAddresses are the listeners the Azure endpoints are mapped to, as "ip:port" strings (an IP
// literal, never a name). Login is the Entra login host on :443 and Vault every vault host on :443
// (the session's own host only is allowed by its transport); IMDS is the managed identity's metadata
// endpoint (optional). Each must be a loopback address (and so one the connection rule allows).
type FixedAddresses struct {
	Login, Vault, IMDS string
}

// WithFixedAddresses returns o with its connections mapped to the fixed addresses. It refuses
// Options without RootCAs, and wraps RootCAs so a function that answers no pool fails the session
// as untrusted instead of falling back to the system roots.
func WithFixedAddresses(o Options, a FixedAddresses) (Options, error) {
	if o.RootCAs == nil {
		return Options{}, ErrFixedAddressesNeedRoots
	}
	login, err := fixedAddr("login", a.Login, true)
	if err != nil {
		return Options{}, err
	}
	vault, err := fixedAddr("vault", a.Vault, true)
	if err != nil {
		return Options{}, err
	}
	imds, err := fixedAddr("imds", a.IMDS, false)
	if err != nil {
		return Options{}, err
	}
	inner := o.RootCAs
	o.RootCAs = func() (*x509.CertPool, error) {
		pool, err := inner()
		if err != nil {
			return nil, err
		}
		if pool == nil {
			return nil, ErrFixedAddressesNeedRoots
		}
		return pool, nil
	}
	o.dialAddr = func(addr string) string {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return addr
		}
		host = foldASCII(host)
		switch {
		case port == "443" && host == azureid.AuthorityHost:
			return login
		case port == "443" && strings.HasSuffix(host, ".vault.azure.net"):
			return vault
		case imds != "" && port == "80" && host == "169.254.169.254":
			return imds
		}
		return addr
	}
	return o, nil
}

func fixedAddr(what, s string, required bool) (string, error) {
	if s == "" {
		if required {
			return "", fmt.Errorf("%w: no %s address", ErrFixedAddresses, what)
		}
		return "", nil
	}
	ap, err := netip.ParseAddrPort(s)
	if err != nil || ap.Port() == 0 || !ap.Addr().IsLoopback() || !netaddr.Allowed(ap.Addr()) {
		return "", fmt.Errorf("%w: %s must be a loopback IP address and a port", ErrFixedAddresses, what)
	}
	return ap.String(), nil
}
