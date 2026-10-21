package dnsapi

import (
	"strings"

	"alice/internal/acme/solver"
)

// InZone reports whether the normalized name fqdn is zone itself or below it on a label boundary.
func InZone(fqdn, zone string) bool {
	return zone != "" && (fqdn == zone || strings.HasSuffix(fqdn, "."+zone))
}

// Candidates lists the zone names that could hold fqdn, longest first: fqdn itself, then each parent, down to the
// last two labels (a zone of one label, a top-level domain, is never a candidate). A provider that looks zones up
// by name tries them in this order and takes the first it manages.
func Candidates(fqdn string) []string {
	labels := strings.Split(fqdn, ".")
	var out []string
	for i := 0; i+2 <= len(labels); i++ {
		out = append(out, strings.Join(labels[i:], "."))
	}
	return out
}

// Longest returns the zone of zones that holds fqdn with the longest name, and false when none does. Zone names are
// compared in normal form (NormalizeZoneName); a zone whose name is not a valid DNS name is ignored.
func Longest(fqdn string, zones []Zone) (Zone, bool) {
	var best Zone
	found := false
	for _, z := range zones {
		n, ok := NormalizeZoneName(z.Name)
		if !ok || !InZone(fqdn, n) || (found && len(n) <= len(best.Name)) {
			continue
		}
		best, found = Zone{Name: n, ID: z.ID}, true
	}
	return best, found
}

// NormalizeZoneName is the normal form of a zone name a provider answered: ASCII lower case without a trailing dot,
// a valid DNS name of at least two labels (optionally the challenge label followed by such a name).
func NormalizeZoneName(raw string) (string, bool) {
	n := strings.TrimSuffix(solver.ASCIILower(raw), ".")
	if strings.HasPrefix(n, "*") || !strings.Contains(n, ".") {
		return "", false
	}
	// A zone of its own for the challenge label ("_acme-challenge.example.com", a common delegation) is the one
	// underscore name Alice accepts; any other zone name must be a host name.
	rest, challenge := strings.CutPrefix(n, solver.ChallengeLabel)
	d, ok := solver.NormalizeDomain(rest)
	if !ok || d != rest || (challenge && !strings.Contains(rest, ".")) {
		return "", false
	}
	return n, true
}

// RelativeName is fqdn without the zone's name ("@" for the apex), the form Azure DNS names a record set by.
func RelativeName(fqdn, zone string) string {
	if fqdn == zone {
		return "@"
	}
	return strings.TrimSuffix(fqdn, "."+zone)
}
