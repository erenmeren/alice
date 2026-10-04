package azurekv

import (
	"context"
	"errors"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azcertificates"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"

	"alice/internal/platform/azureid"
	"alice/internal/providers"
)

// The bounds of one poll. They are variables only so that tests can lower them.
var (
	maxKVCertificates = MaxKVCertificates
	maxKVKeys         = MaxKVKeys
	maxKVSecrets      = MaxKVSecrets
	maxKVDetails      = MaxKVDetails
	maxKVKeyDetails   = MaxKVKeyDetails
	maxKVVersions     = MaxKVVersions
	maxKVVersionRead  = MaxKVVersionRead // versions read per certificate before the listing is cut (D28)
	pollBudget        = PollBudget
)

const (
	kindCertificates = "certificates"
	kindVersions     = "versions"
	kindKeys         = "keys"
	kindSecrets      = "secrets"

	maxCER = 64 << 10 // a leaf larger than this is not a certificate Alice stores
)

// wholeVaultCodes are failures that say Alice cannot talk to this vault at all (or as this
// identity): the poll ends with the error instead of repeating it for every list.
var wholeVaultCodes = map[string]bool{
	codeAuthFailed: true, codeCredentialsExpired: true, codeClockSkew: true, codeManagedIdentityGone: true,
	codeVaultNotFound: true, codeAddressNotAllowed: true, codeTLSUntrusted: true,
}

// parseObjectID reads "https://<vault>/<kind>/<name>[/<version>]": only the path is used, and the
// name must pass azureid.ValidObjectName. (The SDK's ID.Name dereferences nil on a malformed id.)
func parseObjectID(raw, kind string) (name, version string, ok bool) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", "", false
	}
	segs := strings.Split(strings.Trim(u.EscapedPath(), "/"), "/")
	if len(segs) < 2 || len(segs) > 3 || segs[0] != kind || !azureid.ValidObjectName(segs[1]) {
		return "", "", false
	}
	if len(segs) == 3 {
		version = segs[2]
	}
	return segs[1], version, true
}

// okTime keeps a time the database can store (years 1 to 9999) as UTC; anything else is dropped.
func okTime(t *time.Time) *time.Time {
	if t == nil || t.Year() < 1 || t.Year() > 9999 {
		return nil
	}
	u := t.UTC()
	return &u
}

// validText accepts text the database stores: valid UTF-8 without control characters (NUL
// included) and at most max characters.
func validText(s string, max int) bool {
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

func enabledOf(b *bool) bool { return b == nil || *b }

func keySize(n int) int {
	if n < 0 || n > 16384 {
		return 0
	}
	return n
}

func idStr[T ~string](id *T) string {
	if id == nil {
		return ""
	}
	return string(*id)
}

type discovery struct {
	s       *session
	ctx     context.Context
	parent  context.Context
	start   time.Time
	inv     *providers.KVInventory
	dropped map[string]int
	cut     map[string]bool
	failed  map[string]bool
}

// over reports that the poll's budget is used up: on the injected clock, or (with the real clock)
// because the poll's own deadline ended a call.
func (d *discovery) over() bool {
	return d.s.clock.Now().Sub(d.start) >= pollBudget || (d.ctx.Err() != nil && d.parent.Err() == nil)
}

func (d *discovery) truncate(kind string) {
	if !d.cut[kind] {
		d.cut[kind] = true
		d.inv.Truncated = append(d.inv.Truncated, kind)
	}
}

func (d *discovery) drop(kind string) { d.dropped[kind]++ }

// dropItem records a listed item that cannot be stored: the list is incomplete, so nothing of its
// kind may be marked missing.
func (d *discovery) dropItem(kind string) {
	d.drop(kind)
	d.truncate(kind)
}

// failList records a failed list; the others are still read. It returns an error only when the
// poll must end: the caller's context, or a failure of the whole vault.
func (d *discovery) failList(kind string, err error) error {
	if d.parent.Err() != nil {
		return ctxError(d.parent.Err())
	}
	pe := toProviderError(err)
	if wholeVaultCodes[pe.Code] {
		return pe
	}
	d.failed[kind] = true
	d.inv.Failures = append(d.inv.Failures, providers.KVListFailure{Object: kind, Err: pe})
	return nil
}

// listErr sorts the error of a listing: nil to go on with what was read (a bound, or the poll's own
// deadline, ended it), a fatal error, or ok=false when the list failed and is to be discarded.
func (d *discovery) listErr(kind string, err error) (ok bool, fatal error) {
	switch {
	case err == nil || errors.Is(err, errStopListing):
		return true, nil
	case d.parent.Err() != nil:
		return false, ctxError(d.parent.Err())
	case d.ctx.Err() != nil:
		d.truncate(kind)
		return true, nil
	}
	return false, d.failList(kind, err)
}

func (s *session) Discover(ctx context.Context, req providers.DiscoverRequest) (providers.DiscoveryResult, error) {
	if err := ctx.Err(); err != nil {
		return providers.DiscoveryResult{}, ctxError(err)
	}
	if !req.Certificates && !req.KVKeys && !req.KVSecrets {
		return providers.DiscoveryResult{}, nil // a Key Vault has no SSH keys
	}
	pctx, cancel := context.WithTimeout(ctx, pollBudget)
	defer cancel()
	d := &discovery{s: s, ctx: pctx, parent: ctx, start: s.clock.Now(), inv: &providers.KVInventory{},
		dropped: map[string]int{}, cut: map[string]bool{}, failed: map[string]bool{}}

	steps := []struct {
		kind string
		want bool
		run  func(providers.DiscoverRequest) error
	}{
		{kindCertificates, req.Certificates, d.certificates},
		{kindKeys, req.KVKeys, d.keys},
		{kindSecrets, req.KVSecrets, d.secrets},
	}
	for i, st := range steps {
		if !st.want {
			continue
		}
		if d.over() { // the remaining lists are not read
			for _, rest := range steps[i:] {
				if rest.want {
					d.truncate(rest.kind)
				}
			}
			break
		}
		if err := st.run(req); err != nil {
			return providers.DiscoveryResult{}, err
		}
	}
	if err := ctx.Err(); err != nil {
		return providers.DiscoveryResult{}, ctxError(err)
	}
	d.inv.KeysListed = req.KVKeys && !d.cut[kindKeys] && !d.failed[kindKeys] && d.dropped[kindKeys] == 0
	d.inv.SecretsListed = req.KVSecrets && !d.cut[kindSecrets] && !d.failed[kindSecrets] && d.dropped[kindSecrets] == 0
	var warnings []providers.Warning
	for _, kind := range []string{kindCertificates, kindVersions, kindKeys, kindSecrets} {
		if n := d.dropped[kind]; n > 0 {
			warnings = append(warnings, providers.Warning{Code: providers.WarnKVItemUnreadable, Params: map[string]string{"object": kind, "count": strconv.Itoa(n)}})
		}
	}
	return providers.DiscoveryResult{KV: d.inv, Warnings: warnings}, nil
}

func foldKeys[V any](m map[string]V) map[string]V {
	out := make(map[string]V, len(m))
	for k, v := range m {
		out[foldASCII(k)] = v
	}
	return out
}

type certItem struct {
	name, thumb string
	p           *azcertificates.CertificateProperties
}

func (d *discovery) certificates(req providers.DiscoverRequest) error {
	var items []*azcertificates.CertificateProperties
	err := d.s.api.ListCertificates(d.ctx, func(page []*azcertificates.CertificateProperties) error {
		if d.over() {
			d.truncate(kindCertificates)
			return errStopListing
		}
		for _, it := range page {
			if len(items) >= maxKVCertificates {
				d.truncate(kindCertificates)
				return errStopListing
			}
			items = append(items, it)
		}
		return nil
	})
	if ok, fatal := d.listErr(kindCertificates, err); !ok || fatal != nil {
		return fatal
	}
	var entries []certItem
	seen := map[string]bool{}
	for _, it := range items {
		if it == nil {
			d.dropItem(kindCertificates)
			continue
		}
		name, _, ok := parseObjectID(idStr(it.ID), kindCertificates)
		thumb, tok := azureid.Thumbprint(it.X509Thumbprint)
		if !ok || !tok {
			d.dropItem(kindCertificates)
			continue
		}
		if seen[foldASCII(name)] {
			return d.failList(kindCertificates, perr(codeUnexpected, true, providers.ErrUnexpectedAnswer, nil))
		}
		seen[foldASCII(name)] = true
		entries = append(entries, certItem{name, thumb, it})
	}

	known := foldKeys(req.KVKnown)
	read := 0
	var out []providers.KVCertificate
	for _, e := range entries {
		c := providers.KVCertificate{Name: e.name, Thumbprint: e.thumb, Enabled: true}
		var updated *time.Time
		if a := e.p.Attributes; a != nil {
			c.Enabled = enabledOf(a.Enabled)
			c.NotBefore, c.Expires, c.Created, c.Updated = okTime(a.NotBefore), okTime(a.Expires), okTime(a.Created), okTime(a.Updated)
			updated = c.Updated
		}
		k, isKnown := known[foldASCII(e.name)]
		if !isKnown || k.Thumbprint != e.thumb || updated == nil || !k.Updated.Equal(*updated) {
			if read >= maxKVDetails || d.over() {
				d.inv.DetailsPending++
			} else {
				read++
				det, versions, gone, err := d.certificateDetails(e.name, k.Version, isKnown)
				if err != nil {
					ok, fatal := d.listErr(kindCertificates, err)
					if fatal != nil || !ok {
						return fatal
					}
					d.inv.DetailsPending++ // the poll's own deadline: the details wait
				}
				if gone {
					continue
				}
				c.Details, c.Versions = det, versions
			}
		}
		out = append(out, c)
	}
	d.inv.Certificates = out
	return nil
}

// certificateDetails reads the latest version of a certificate, and its versions when the current
// version is not the one Alice knows. gone: the certificate was deleted since the listing.
func (d *discovery) certificateDetails(name, knownVersion string, isKnown bool) (det *providers.KVCertificateDetails, versions []providers.KVCertificateVersion, gone bool, err error) {
	b, err := d.s.api.GetCertificate(d.ctx, name, "")
	if err != nil {
		if toProviderError(err).Code == codeCertificateNotFound {
			return nil, nil, true, nil
		}
		return nil, nil, false, err
	}
	det, cur, ok := certDetails(name, b)
	if !ok {
		d.drop(kindCertificates)
		return nil, nil, false, nil
	}
	if isKnown && knownVersion == det.Version {
		return det, nil, false, nil
	}
	versions, err = d.certificateVersions(name, cur)
	if err != nil {
		if toProviderError(err).Code == codeCertificateNotFound {
			return nil, nil, true, nil
		}
		return nil, nil, false, err
	}
	return det, versions, false, nil
}

func policyKeyType(t string) string {
	switch t {
	case "":
		return ""
	case "RSA", "RSA-HSM":
		return "rsa"
	case "EC", "EC-HSM":
		return "ecdsa"
	}
	return "other"
}

// certDetails maps a certificate bundle; ok is false when it cannot be stored (no leaf, a leaf that
// is not the one x5t names, a version that is not 32 hex).
func certDetails(name string, b azcertificates.Certificate) (*providers.KVCertificateDetails, providers.KVCertificateVersion, bool) {
	var none providers.KVCertificateVersion
	n, ver, ok := parseObjectID(idStr(b.ID), kindCertificates)
	thumb, tok := azureid.Thumbprint(b.X509Thumbprint)
	if !ok || !tok || !azureid.ValidVersion(ver) || foldASCII(n) != foldASCII(name) ||
		len(b.CER) == 0 || len(b.CER) > maxCER || azureid.ThumbprintOf(b.CER) != thumb {
		return nil, none, false
	}
	det := &providers.KVCertificateDetails{Version: ver, Thumbprint: thumb, CER: slices.Clone(b.CER)}
	cur := providers.KVCertificateVersion{Version: ver, Thumbprint: thumb, Enabled: true}
	if a := b.Attributes; a != nil {
		det.Updated = okTime(a.Updated)
		cur.Enabled = enabledOf(a.Enabled)
		cur.NotBefore, cur.Expires, cur.Created = okTime(a.NotBefore), okTime(a.Expires), okTime(a.Created)
	}
	ct := b.ContentType
	if p := b.Policy; p != nil {
		if kp := p.KeyProperties; kp != nil {
			det.Exportable = kp.Exportable
			if kp.KeyType != nil {
				det.KeyType = policyKeyType(string(*kp.KeyType))
			}
			if kp.KeySize != nil {
				det.KeySize = keySize(int(*kp.KeySize))
			}
		}
		if sp := p.SecretProperties; sp != nil && sp.ContentType != nil {
			ct = sp.ContentType
		}
		if ip := p.IssuerParameters; ip != nil && ip.Name != nil && validText(*ip.Name, 127) {
			det.IssuerName = *ip.Name
		}
		for _, la := range p.LifetimeActions {
			if la != nil && la.Action != nil && la.Action.ActionType != nil && *la.Action.ActionType == azcertificates.CertificatePolicyActionAutoRenew {
				det.AutoRenew = true
			}
		}
	}
	if ct != nil {
		switch *ct {
		case "application/x-pkcs12":
			det.ContentType = "pkcs12"
		case "application/x-pem-file":
			det.ContentType = "pem"
		default:
			det.ContentType = "other"
		}
	}
	return det, cur, true
}

// certificateVersions reads the versions of a certificate (every page up to maxKVVersionRead: the
// listing has no order and no page size, D28), and returns the newest maxKVVersions by creation
// time, always including the current version.
func (d *discovery) certificateVersions(name string, current providers.KVCertificateVersion) ([]providers.KVCertificateVersion, error) {
	all := map[string]providers.KVCertificateVersion{current.Version: current}
	read := 0
	err := d.s.api.ListCertificateVersions(d.ctx, name, func(page []*azcertificates.CertificateProperties) error {
		if d.over() {
			d.truncate(kindVersions)
			return errStopListing
		}
		for _, it := range page {
			if read >= maxKVVersionRead {
				d.truncate(kindVersions)
				return errStopListing
			}
			read++
			if it == nil {
				d.dropItem(kindVersions)
				continue
			}
			_, ver, ok := parseObjectID(idStr(it.ID), kindCertificates)
			thumb, tok := azureid.Thumbprint(it.X509Thumbprint)
			if !ok || !tok || !azureid.ValidVersion(ver) {
				d.dropItem(kindVersions)
				continue
			}
			if ver == current.Version {
				continue
			}
			v := providers.KVCertificateVersion{Version: ver, Thumbprint: thumb, Enabled: true}
			if a := it.Attributes; a != nil {
				v.Enabled = enabledOf(a.Enabled)
				v.NotBefore, v.Expires, v.Created = okTime(a.NotBefore), okTime(a.Expires), okTime(a.Created)
			}
			all[ver] = v
		}
		return nil
	})
	if err != nil && !errors.Is(err, errStopListing) {
		if d.parent.Err() == nil && d.ctx.Err() != nil {
			d.truncate(kindVersions)
		} else {
			return nil, err
		}
	}
	list := make([]providers.KVCertificateVersion, 0, len(all))
	for _, v := range all {
		list = append(list, v)
	}
	newestFirst := func(a, b providers.KVCertificateVersion) int {
		switch {
		case a.Created != nil && b.Created == nil:
			return -1
		case a.Created == nil && b.Created != nil:
			return 1
		case a.Created != nil && !a.Created.Equal(*b.Created):
			return b.Created.Compare(*a.Created)
		}
		return strings.Compare(b.Version, a.Version)
	}
	slices.SortFunc(list, newestFirst)
	if len(list) > maxKVVersions {
		d.truncate(kindVersions)
		list = list[:maxKVVersions]
		if !slices.ContainsFunc(list, func(v providers.KVCertificateVersion) bool { return v.Version == current.Version }) {
			list[len(list)-1] = current
			slices.SortFunc(list, newestFirst)
		}
	}
	return list, nil
}

func (d *discovery) keys(req providers.DiscoverRequest) error {
	var items []*azkeys.KeyProperties
	err := d.s.api.ListKeys(d.ctx, func(page []*azkeys.KeyProperties) error {
		if d.over() {
			d.truncate(kindKeys)
			return errStopListing
		}
		for _, it := range page {
			if len(items) >= maxKVKeys {
				d.truncate(kindKeys)
				return errStopListing
			}
			items = append(items, it)
		}
		return nil
	})
	if ok, fatal := d.listErr(kindKeys, err); !ok || fatal != nil {
		return fatal
	}
	known := foldKeys(req.KVKnownKeys)
	seen := map[string]bool{}
	read := 0
	var out []providers.KVKey
	for _, it := range items {
		if it == nil {
			d.dropItem(kindKeys)
			continue
		}
		name, _, ok := parseObjectID(idStr(it.KID), kindKeys)
		if !ok {
			d.dropItem(kindKeys)
			continue
		}
		if seen[foldASCII(name)] {
			return d.failList(kindKeys, perr(codeUnexpected, true, providers.ErrUnexpectedAnswer, nil))
		}
		seen[foldASCII(name)] = true
		k := providers.KVKey{Name: name, Enabled: true, Managed: it.Managed != nil && *it.Managed}
		if a := it.Attributes; a != nil {
			k.Enabled = enabledOf(a.Enabled)
			k.NotBefore, k.Expires, k.Created, k.Updated = okTime(a.NotBefore), okTime(a.Expires), okTime(a.Created), okTime(a.Updated)
		}
		kn, isKnown := known[foldASCII(name)]
		if !k.Managed && (!isKnown || k.Updated == nil || !kn.Equal(*k.Updated)) && read < maxKVKeyDetails && !d.over() {
			read++
			b, err := d.s.api.GetKey(d.ctx, name)
			switch {
			case err == nil:
				k.Details = keyDetails(b)
			case d.parent.Err() != nil:
				return ctxError(d.parent.Err())
			default:
				pe := toProviderError(err)
				if wholeVaultCodes[pe.Code] {
					return pe
				}
				k.DetailsProblem = "failed"
				if pe.Code == codeForbidden {
					k.DetailsProblem = "forbidden"
				}
			}
		}
		out = append(out, k)
	}
	d.inv.Keys = out
	return nil
}

func keyDetails(b azkeys.KeyBundle) *providers.KVKeyDetails {
	det := &providers.KVKeyDetails{}
	j := b.Key
	if j == nil {
		return det
	}
	if _, ver, ok := parseObjectID(idStr(j.KID), kindKeys); ok && azureid.ValidVersion(ver) {
		det.Version = ver
	}
	if j.Kty != nil {
		kty := string(*j.Kty)
		det.HSM = strings.HasSuffix(kty, "-HSM")
		switch strings.TrimSuffix(kty, "-HSM") {
		case "RSA":
			det.KeyType = "rsa"
			det.Size = keySize(len(j.N) * 8)
		case "EC":
			det.KeyType = "ec"
		case "oct":
			det.KeyType = "oct"
		default:
			det.KeyType = "other"
		}
	}
	if j.Crv != nil {
		switch c := string(*j.Crv); c {
		case "P-256", "P-256K", "P-384", "P-521":
			det.Curve = c
		default:
			det.Curve = "other"
		}
	}
	return det
}

func (d *discovery) secrets(providers.DiscoverRequest) error {
	var items []*azsecrets.SecretProperties
	err := d.s.api.ListSecrets(d.ctx, func(page []*azsecrets.SecretProperties) error {
		if d.over() {
			d.truncate(kindSecrets)
			return errStopListing
		}
		for _, it := range page {
			if len(items) >= maxKVSecrets {
				d.truncate(kindSecrets)
				return errStopListing
			}
			items = append(items, it)
		}
		return nil
	})
	if ok, fatal := d.listErr(kindSecrets, err); !ok || fatal != nil {
		return fatal
	}
	seen := map[string]bool{}
	var out []providers.KVSecret
	for _, it := range items {
		if it == nil {
			d.dropItem(kindSecrets)
			continue
		}
		name, _, ok := parseObjectID(idStr(it.ID), kindSecrets)
		if !ok {
			d.dropItem(kindSecrets)
			continue
		}
		if seen[foldASCII(name)] {
			return d.failList(kindSecrets, perr(codeUnexpected, true, providers.ErrUnexpectedAnswer, nil))
		}
		seen[foldASCII(name)] = true
		s := providers.KVSecret{Name: name, Enabled: true, Managed: it.Managed != nil && *it.Managed}
		if it.ContentType != nil && validText(*it.ContentType, 255) {
			s.ContentType = *it.ContentType
		}
		if a := it.Attributes; a != nil {
			s.Enabled = enabledOf(a.Enabled)
			s.NotBefore, s.Expires, s.Created, s.Updated = okTime(a.NotBefore), okTime(a.Expires), okTime(a.Created), okTime(a.Updated)
		}
		out = append(out, s)
	}
	d.inv.Secrets = out
	return nil
}
