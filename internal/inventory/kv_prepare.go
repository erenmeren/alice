package inventory

import (
	"encoding/pem"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"time"
	"unicode/utf8"

	"alice/internal/certs"
	"alice/internal/platform/azureid"
	"alice/internal/providers"
)

// The bounds of one poll's result (the provider's own, R40 row 15): inventory re-checks what it
// stores and refuses a larger result before writing anything.
const (
	maxKVCertificates = 5000
	maxKVKeys         = 5000
	maxKVSecrets      = 10000
	maxKVVersions     = 100 // listed versions of one certificate
	maxKVIssuer       = 127
	maxKVContentType  = 255
	maxKVCER          = 64 << 10
)

// WarnKVVersionConflict is the closed warning of a poll in which Azure reported a version ID that
// Alice already knows with another thumbprint (params object, count). The stored row is kept.
const WarnKVVersionConflict = "kv_version_conflict"

// WarnKVListingEmpty is the closed warning of a poll whose certificate listing was empty although
// the vault has stored certificates: nothing was marked missing yet (no params).
const WarnKVListingEmpty = "kv_listing_empty"

// Kinds of a vault listing (providers.KVInventory.Truncated, KVListFailure.Object).
const (
	kvCertificates = "certificates"
	kvVersions     = "versions"
	kvKeys         = "keys"
	kvSecrets      = "secrets"
	kvWhole        = "vault" // KVPollFailure.Object of a poll that failed as a whole
)

var (
	kvKinds       = []string{kvCertificates, kvVersions, kvKeys, kvSecrets}
	aadstsRE      = regexp.MustCompile(`^[0-9]{1,10}$`)
	certKeyTypes  = []string{"", "rsa", "ecdsa", "other"}
	certContent   = []string{"", "pkcs12", "pem", "other"}
	vaultKeyTypes = []string{"", "rsa", "ec", "oct", "other"}
	vaultCurves   = []string{"", "P-256", "P-256K", "P-384", "P-521", "other"}
	vaultRoles    = []string{providers.RoleKeyVaultReader, providers.RoleKeyVaultSecretsUser, providers.RoleKeyVaultCertificatesOfficer}
)

// kvVersion is one listed version of a certificate, ready to store.
type kvVersion struct {
	version, thumb              string
	enabled                     bool
	notBefore, expires, created *time.Time
}

// kvDetails are the current version's details with its leaf already parsed (outside any
// transaction).
type kvDetails struct {
	version, thumb string
	updated        *time.Time
	leaf           certs.Parsed
	complete       bool
	exportable     *bool
	keyType        string
	keySize        int
	contentType    string
	issuer         string
	autoRenew      bool
	attrs          kvVersion   // the current version's attributes (its own entry, else the listing's)
	history        []kvVersion // the other listed versions
}

type kvCert struct {
	name, fold, thumb                    string
	enabled                              bool
	notBefore, expires, created, updated *time.Time
	details                              *kvDetails
}

type kvKeyItem struct {
	name, fold                           string
	enabled, managed                     bool
	notBefore, expires, created, updated *time.Time
	hasDetails                           bool
	version, keyType, curve, problem     string
	hsm                                  bool
	size                                 int
}

type kvSecretItem struct {
	name, fold, contentType              string
	enabled, managed                     bool
	notBefore, expires, created, updated *time.Time
}

// preparedKV is a poll's result after validation: every value fits what the database stores, the
// items that could not be stored are counted, and what the listing proves is decided.
type preparedKV struct {
	certs   []kvCert
	keys    []kvKeyItem
	secrets []kvSecretItem

	certsAnswered   bool // the certificate listing did not fail (last_success_at)
	certsComplete   bool // ... and was neither cut nor missing an item: absent certificates are missing
	keysAsked       bool
	secretsAsked    bool
	keysComplete    bool
	secretsComplete bool

	failures       []KVPollFailure
	throttled      bool
	truncated      []string
	detailsPending int
	unreadable     map[string]int // kind -> items Alice could not use
}

func (p *preparedKV) drop(kind string) {
	p.unreadable[kind]++
	if kind != kvVersions && !slices.Contains(p.truncated, kind) {
		p.truncated = append(p.truncated, kind)
	}
}

// warnings are the closed warnings of the poll (kv_item_unreadable, merged by object).
func (p *preparedKV) warnings() []providers.Warning {
	var out []providers.Warning
	for _, k := range kvKinds {
		if n := p.unreadable[k]; n > 0 {
			out = append(out, providers.Warning{Code: providers.WarnKVItemUnreadable,
				Params: map[string]string{"object": k, "count": strconv.Itoa(n)}})
		}
	}
	return out
}

// kvTime keeps a time the database stores (years 1 to 9999) as UTC; anything else is dropped.
func kvTime(t *time.Time) *time.Time {
	if t == nil || t.Year() < 1 || t.Year() > 9999 {
		return nil
	}
	u := t.UTC()
	return &u
}

// validKVText accepts text the database stores as it is: valid UTF-8, no control characters, at
// most max characters (the rule of the provider's own check).
func validKVText(s string, max int) bool {
	if !utf8.ValidString(s) || utf8.RuneCountInString(s) > max {
		return false
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

func kvClosed(s string, allowed []string) string {
	if slices.Contains(allowed, s) {
		return s
	}
	return "other"
}

// sanitizeKVFailure keeps a provider error as a closed reason and the allowlisted params only
// (ruling S4: no Azure text is stored).
func sanitizeKVFailure(object string, e *providers.Error) KVPollFailure {
	if !slices.Contains([]string{kvCertificates, kvKeys, kvSecrets, kvWhole}, object) {
		object = kvWhole
	}
	f := KVPollFailure{Object: object, Reason: reasonInternal}
	if e == nil {
		return f
	}
	if reasonRE.MatchString(e.Code) {
		f.Reason = e.Code
	}
	if r := e.Params["role"]; slices.Contains(vaultRoles, r) {
		f.Role = r
	}
	if a, err := netip.ParseAddr(e.Params["client_address"]); err == nil && a.Zone() == "" {
		f.ClientAddress = a.String()
	}
	if id := e.Params["azure_request_id"]; azureid.ValidRequestID(id) {
		f.RequestID = foldASCII(id)
	}
	if c := e.Params["azure_code"]; azureid.ValidAzureCode(c) {
		f.AzureCode = c
	}
	if c := e.Params["aadsts"]; aadstsRE.MatchString(c) {
		f.Aadsts = c
	}
	return f
}

// errKVResult is the refusal of a result Alice cannot store as a whole.
func errKVResult() error { return providers.NewError(reasonInternal, false, nil, nil) }

// prepareKV validates a poll's result. A result without a vault half or above the bounds is
// refused as a whole (internal.unexpected); an item that cannot be stored is dropped and its kind
// is cut, so nothing of that kind is marked missing. Leaf certificates are parsed here.
func (s *Service) prepareKV(res providers.DiscoveryResult, now time.Time) (*preparedKV, error) {
	kv := res.KV
	if kv == nil || len(kv.Certificates) > maxKVCertificates || len(kv.Keys) > maxKVKeys || len(kv.Secrets) > maxKVSecrets {
		return nil, errKVResult()
	}
	p := &preparedKV{unreadable: map[string]int{}, detailsPending: max(kv.DetailsPending, 0)}
	failed := map[string]bool{}
	for _, f := range kv.Failures {
		sf := sanitizeKVFailure(f.Object, f.Err)
		if sf.Object == kvWhole {
			continue // a whole-vault failure is an error of the call, not a row
		}
		failed[sf.Object] = true
		if sf.Reason == "azure.throttled" {
			p.throttled = true
		}
		p.failures = append(p.failures, sf)
	}
	order := map[string]int{kvCertificates: 0, kvKeys: 1, kvSecrets: 2}
	slices.SortStableFunc(p.failures, func(a, b KVPollFailure) int { return order[a.Object] - order[b.Object] })
	for _, k := range kv.Truncated {
		if slices.Contains(kvKinds, k) && !slices.Contains(p.truncated, k) {
			p.truncated = append(p.truncated, k)
		}
	}
	for _, w := range res.Warnings { // the provider's count of items it dropped, merged with ours
		if w.Code != providers.WarnKVItemUnreadable || !slices.Contains(kvKinds, w.Params["object"]) {
			continue
		}
		if n, err := strconv.Atoi(w.Params["count"]); err == nil && n > 0 && n <= 1_000_000 {
			p.unreadable[w.Params["object"]] += n
		}
	}

	seen := map[string]bool{}
	for _, c := range kv.Certificates {
		fold := foldASCII(c.Name)
		if !azureid.ValidObjectName(c.Name) || !azureid.ValidThumbprint(c.Thumbprint) || seen[fold] {
			p.drop(kvCertificates)
			continue
		}
		seen[fold] = true
		item := kvCert{name: c.Name, fold: fold, thumb: c.Thumbprint, enabled: c.Enabled,
			notBefore: kvTime(c.NotBefore), expires: kvTime(c.Expires), created: kvTime(c.Created), updated: kvTime(c.Updated)}
		if c.Details != nil {
			if d, ok := s.prepareDetails(p, c, item, now); ok {
				item.details = d
			} else {
				p.unreadable[kvCertificates]++ // listed, its details wait
			}
		}
		p.certs = append(p.certs, item)
	}
	slices.SortFunc(p.certs, func(a, b kvCert) int { return compareStrings(a.fold, b.fold) })

	seen = map[string]bool{}
	for _, k := range kv.Keys {
		fold := foldASCII(k.Name)
		if !azureid.ValidObjectName(k.Name) || seen[fold] {
			p.drop(kvKeys)
			continue
		}
		seen[fold] = true
		item := kvKeyItem{name: k.Name, fold: fold, enabled: k.Enabled, managed: k.Managed,
			notBefore: kvTime(k.NotBefore), expires: kvTime(k.Expires), created: kvTime(k.Created), updated: kvTime(k.Updated)}
		switch {
		case k.Details != nil:
			item.hasDetails = true
			if azureid.ValidVersion(k.Details.Version) {
				item.version = k.Details.Version
			}
			item.keyType, item.hsm, item.curve = kvClosed(k.Details.KeyType, vaultKeyTypes), k.Details.HSM, kvClosed(k.Details.Curve, vaultCurves)
			if k.Details.KeyType == "" {
				item.keyType = ""
			}
			if k.Details.Curve == "" {
				item.curve = ""
			}
			if k.Details.Size >= 0 && k.Details.Size <= 16384 {
				item.size = k.Details.Size
			}
		case k.DetailsProblem != "":
			item.problem = k.DetailsProblem
			if item.problem != "forbidden" {
				item.problem = "failed"
			}
		}
		p.keys = append(p.keys, item)
	}
	slices.SortFunc(p.keys, func(a, b kvKeyItem) int { return compareStrings(a.fold, b.fold) })

	seen = map[string]bool{}
	for _, sc := range kv.Secrets {
		fold := foldASCII(sc.Name)
		if !azureid.ValidObjectName(sc.Name) || seen[fold] {
			p.drop(kvSecrets)
			continue
		}
		seen[fold] = true
		item := kvSecretItem{name: sc.Name, fold: fold, enabled: sc.Enabled, managed: sc.Managed,
			notBefore: kvTime(sc.NotBefore), expires: kvTime(sc.Expires), created: kvTime(sc.Created), updated: kvTime(sc.Updated)}
		if validKVText(sc.ContentType, maxKVContentType) {
			item.contentType = sc.ContentType
		}
		p.secrets = append(p.secrets, item)
	}
	slices.SortFunc(p.secrets, func(a, b kvSecretItem) int { return compareStrings(a.fold, b.fold) })

	cut := func(kind string) bool { return slices.Contains(p.truncated, kind) }
	p.certsAnswered = !failed[kvCertificates]
	p.certsComplete = p.certsAnswered && !cut(kvCertificates)
	p.keysAsked = kv.KeysListed || failed[kvKeys] || cut(kvKeys) || len(kv.Keys) > 0
	p.secretsAsked = kv.SecretsListed || failed[kvSecrets] || cut(kvSecrets) || len(kv.Secrets) > 0
	p.keysComplete = kv.KeysListed && !failed[kvKeys] && !cut(kvKeys)
	p.secretsComplete = kv.SecretsListed && !failed[kvSecrets] && !cut(kvSecrets)
	slices.Sort(p.truncated)
	return p, nil
}

func compareStrings(a, b string) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

// prepareDetails validates and parses the details of a certificate's current version. false: they
// cannot be stored (a version or thumbprint of the wrong shape, a leaf that is not the thumbprint's
// certificate); the certificate is still listed.
func (s *Service) prepareDetails(p *preparedKV, c providers.KVCertificate, item kvCert, now time.Time) (*kvDetails, bool) {
	d := c.Details
	if !azureid.ValidVersion(d.Version) || !azureid.ValidThumbprint(d.Thumbprint) ||
		len(d.CER) == 0 || len(d.CER) > maxKVCER || azureid.ThumbprintOf(d.CER) != d.Thumbprint {
		return nil, false
	}
	leaf, err := certs.ParseChainPEM(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: d.CER}))
	if err != nil {
		return nil, false
	}
	out := &kvDetails{version: d.Version, thumb: d.Thumbprint, updated: kvTime(d.Updated), leaf: leaf,
		complete: certs.ChainComplete(leaf, s.roots, now), exportable: d.Exportable,
		keyType: kvClosed(d.KeyType, certKeyTypes), contentType: kvClosed(d.ContentType, certContent), autoRenew: d.AutoRenew}
	if d.KeyType == "" {
		out.keyType = ""
	}
	if d.ContentType == "" {
		out.contentType = ""
	}
	if d.KeySize >= 0 && d.KeySize <= 16384 {
		out.keySize = d.KeySize
	}
	if validKVText(d.IssuerName, maxKVIssuer) {
		out.issuer = d.IssuerName
	}
	out.attrs = kvVersion{version: d.Version, thumb: d.Thumbprint, enabled: item.enabled,
		notBefore: item.notBefore, expires: item.expires, created: item.created}
	seen := map[string]bool{d.Version: true}
	for _, v := range c.Versions {
		if !azureid.ValidVersion(v.Version) || !azureid.ValidThumbprint(v.Thumbprint) {
			p.unreadable[kvVersions]++
			continue
		}
		kvv := kvVersion{version: v.Version, thumb: v.Thumbprint, enabled: v.Enabled,
			notBefore: kvTime(v.NotBefore), expires: kvTime(v.Expires), created: kvTime(v.Created)}
		if v.Version == d.Version {
			if v.Thumbprint == d.Thumbprint { // the current version's own entry knows its attributes best
				out.attrs = kvv
			}
			continue
		}
		if seen[v.Version] {
			continue
		}
		if len(out.history) >= maxKVVersions-1 {
			p.unreadable[kvVersions]++
			continue
		}
		seen[v.Version] = true
		out.history = append(out.history, kvv)
	}
	return out, true
}
