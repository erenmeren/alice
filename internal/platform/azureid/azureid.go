// Package azureid holds the Azure identifiers Alice accepts (spec §11.1, SEC-062, §25.4 A-14):
// one rule for what an administrator types (inventory) and what the azurekv provider connects to.
// Public cloud only (R40 rows 5-6).
//
// Every validator is a closed grammar over ASCII. A function that accepts a value returns it in
// one normal form built from the validated parts only, and a function that refuses returns the
// zero value, so nothing a caller could turn into a request to another host ever leaves this
// package.
package azureid

import (
	"crypto/sha1" //nolint:gosec // G505: x5t is SHA-1 by Azure's definition; Alice compares it, never trusts it
	"encoding/hex"
	"errors"
	"regexp"
	"strings"
)

// Fixed endpoints of the Azure public cloud (R40 rows 4, 5, 8).
const (
	AuthorityHost = "login.microsoftonline.com"        // the only Entra ID host Alice signs in at
	AuthorityURL  = "https://" + AuthorityHost + "/"   // cloud.Configuration.ActiveDirectoryAuthorityHost
	VaultSuffix   = ".vault.azure.net"                 // every vault Alice accepts
	VaultScope    = "https://vault.azure.net/.default" // the data-plane token scope
	IMDSAddr      = "169.254.169.254:80"               // the managed-identity endpoint of an Azure VM (R40 row 4)
)

// ErrVault: the text is not a vault address of the public cloud.
var ErrVault = errors.New("azureid: not a Key Vault address of the Azure public cloud")

var (
	// vaultNameRE is Azure's vault-name rule without its length: a letter first, then letters,
	// digits and single hyphens, a letter or digit last (so no "--" and no final "-"). The length
	// (3 to 24) is checked beside it.
	vaultNameRE = regexp.MustCompile(`^[a-z](-?[a-z0-9])+$`)
	guidRE      = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	objectRE    = regexp.MustCompile(`^[0-9A-Za-z-]{1,127}$`)
	versionRE   = regexp.MustCompile(`^[0-9a-f]{32}$`)
	thumbRE     = regexp.MustCompile(`^[0-9a-f]{40}$`)
	codeRE      = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9]{0,63}$`)
)

// Vault is a normalised vault address.
type Vault struct {
	Name string // "contoso-prod"
	Host string // "contoso-prod.vault.azure.net"
	URL  string // "https://contoso-prod.vault.azure.net"
}

// foldASCII lowercases ASCII letters only (strings.ToLower is banned: Turkish İ/ı, Kelvin sign).
func foldASCII(s string) string {
	b := []byte(s)
	for i, c := range b {
		if 'A' <= c && c <= 'Z' {
			b[i] = c + ('a' - 'A')
		}
	}
	return string(b)
}

// trimASCII removes surrounding space, tab, CR and LF (what a pasted value carries), and no other
// character: Unicode spaces stay and fail the grammar.
func trimASCII(s string) string { return strings.Trim(s, " \t\r\n") }

// ParseVault accepts "name", "name.vault.azure.net" or "https://name.vault.azure.net", with one
// optional final "/" and any ASCII letter case, and nothing else: no other scheme, port, path,
// query, user, fragment, trailing dot or DNS suffix. The name follows Azure's rule: 3-24
// characters, a letter first, letters, digits and single hyphens, a letter or digit last. The
// result is built from the validated name alone.
func ParseVault(raw string) (Vault, error) {
	s := foldASCII(trimASCII(raw))
	scheme := strings.HasPrefix(s, "https://")
	s = strings.TrimSuffix(strings.TrimPrefix(s, "https://"), "/")
	name, suffixed := strings.CutSuffix(s, VaultSuffix)
	if (scheme && !suffixed) || len(name) < 3 || len(name) > 24 || !vaultNameRE.MatchString(name) {
		return Vault{}, ErrVault
	}
	host := name + VaultSuffix
	return Vault{Name: name, Host: host, URL: "https://" + host}, nil
}

// NormalizeGUID returns a GUID (tenant, client or object ID) in lower case without surrounding
// space: 8-4-4-4-12 hexadecimal digits with hyphens, no braces, no urn prefix, no bare 32 digits.
// A refusal returns "".
func NormalizeGUID(raw string) (string, bool) {
	s := foldASCII(trimASCII(raw))
	if !guidRE.MatchString(s) {
		return "", false
	}
	return s, true
}

// ValidObjectName reports a certificate, key or secret name Key Vault allows: 1 to 127 ASCII
// letters, digits and hyphens.
func ValidObjectName(s string) bool { return objectRE.MatchString(s) }

// ValidVersion reports a Key Vault version ID (32 lower-case hex digits).
func ValidVersion(s string) bool { return versionRE.MatchString(s) }

// ValidThumbprint reports an x5t as Alice stores it: 40 lower-case hex digits. It does not fold
// case; NormalizeThumbprint does, for text a person typed or the Azure portal showed.
func ValidThumbprint(s string) bool { return thumbRE.MatchString(s) }

// NormalizeThumbprint trims ASCII space, folds ASCII to lower case and returns the stored form of
// a thumbprint; a refusal returns "".
func NormalizeThumbprint(raw string) (string, bool) {
	s := foldASCII(trimASCII(raw))
	if !thumbRE.MatchString(s) {
		return "", false
	}
	return s, true
}

// Thumbprint encodes a decoded x5t (SHA-1, 20 bytes) as hex.
func Thumbprint(x5t []byte) (string, bool) {
	if len(x5t) != sha1.Size {
		return "", false
	}
	return hex.EncodeToString(x5t), true
}

// ThumbprintOf is the x5t of a DER certificate, as hex.
func ThumbprintOf(der []byte) string {
	sum := sha1.Sum(der) //nolint:gosec // G401: x5t is SHA-1 by definition; compared with Azure's value only
	return hex.EncodeToString(sum[:])
}

// ValidRequestID reports an x-ms-request-id as Azure sent it: a GUID in any letter case, with no
// surrounding space.
func ValidRequestID(s string) bool { return guidRE.MatchString(foldASCII(s)) }

// ValidAzureCode reports an Azure error or inner error code Alice may keep (R40 row 26).
func ValidAzureCode(s string) bool { return codeRE.MatchString(s) }
