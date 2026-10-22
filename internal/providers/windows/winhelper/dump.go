package winhelper

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/netip"
	"sort"
	"strings"

	"alice/internal/providers/windows/winproto"
)

// expiredStores are the stores whose expired certificates the dump counts (design §6.2).
var expiredStores = []string{"My", "WebHosting"}

// cmdIISDump answers "iis-dump": no arguments; the elevation gate ran before.
func cmdIISDump(ctx context.Context, h Host, args []string) (any, error) {
	if len(args) != 0 {
		return nil, refused(winproto.CodeUsage, "iis-dump takes no arguments")
	}
	d, err := BuildDump(ctx, h)
	if err != nil {
		return nil, err
	}
	return d, nil
}

// cleanIISFacts makes the host's IIS facts safe to send.
func cleanIISFacts(f winproto.IISFacts) winproto.IISFacts {
	return winproto.IISFacts{Installed: f.Installed, Version: cleanValue(f.Version, winproto.MaxText),
		SharedConfig: f.SharedConfig, CCSEnabled: f.CCSEnabled, CCSPath: cleanValue(f.CCSPath, winproto.MaxText),
		AutoCertRebind: f.AutoCertRebind}
}

// BuildDump assembles the iis-dump answer from the host's readings, in the order of design §6.2: IIS
// facts, http.sys bindings, the certificate of every distinct (store, SHA-1) once, the IIS sites, the
// warning facts. Records the host sent that are malformed are dropped, lists are cut at the bounds of
// Ruling 20, and either sets Truncated and the warning list_truncated. When IIS is installed and
// appcmd fails, so does the dump (Ruling 12). The error is a *helperError ready for the reply.
func BuildDump(ctx context.Context, h Host) (winproto.IISDumpResponse, error) {
	d := winproto.IISDumpResponse{OK: true, Bindings: []winproto.SSLBinding{}, Certificates: []winproto.StoreCertificate{},
		Sites: []winproto.Site{}, ExpiredInStore: map[string]int{}, Warnings: []string{}}
	stop := func() error {
		if ctx.Err() != nil {
			return failed(winproto.CodeIOError, "the call took too long")
		}
		return nil
	}

	iis, err := h.IISFacts(ctx)
	installed := true
	switch {
	case err == nil:
		d.IIS = cleanIISFacts(iis)
	case errors.Is(err, ErrIISNotInstalled):
		installed = false
	default:
		return d, failed(winproto.CodeIOError, "IIS could not be read")
	}
	if err := stop(); err != nil {
		return d, err
	}

	raw, err := h.SSLBindings(ctx)
	if err != nil {
		return d, failed(winproto.CodeIOError, "the http.sys bindings could not be read")
	}
	truncated := false
	for _, b := range raw {
		cb, ok := cleanBinding(b)
		if !ok {
			truncated = true
			continue
		}
		if len(d.Bindings) == winproto.MaxBindings {
			truncated = true
			break
		}
		d.Bindings = append(d.Bindings, cb)
	}

	// Each distinct certificate once. The bindings are cut at MaxBindings (= MaxCertificates), so the
	// certificate list needs no cut of its own. Store names compare with ASCII case folding (http.sys
	// answers MY and My for one store, W0 F2); the certificate is read and listed under the spelling of
	// the first binding that names it, in the order of the bindings list.
	type key struct{ store, sha1 string }
	type entry struct{ store, folded, sha1 string }
	seen := map[key]bool{}
	var keys []entry
	for _, b := range d.Bindings {
		folded := asciiLower(b.Store)
		if k := (key{folded, b.CertSHA1}); b.CertSHA1 != "" && !seen[k] {
			seen[k] = true
			keys = append(keys, entry{b.Store, folded, b.CertSHA1})
		}
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].folded != keys[j].folded {
			return keys[i].folded < keys[j].folded
		}
		return keys[i].sha1 < keys[j].sha1
	})
	for _, k := range keys {
		if err := stop(); err != nil {
			return d, err
		}
		c, found, err := h.Certificate(ctx, k.store, k.sha1)
		if err != nil {
			return d, failed(winproto.CodeStoreError, "a certificate could not be read")
		}
		if !found {
			continue
		}
		cc, ok := cleanCertificate(c, k.store, k.sha1)
		if !ok {
			truncated = true
			continue
		}
		d.Certificates = append(d.Certificates, cc)
	}

	if installed {
		if err := stop(); err != nil {
			return d, err
		}
		xml, err := h.AppcmdSites(ctx)
		if err != nil {
			return d, failed(winproto.CodeIOError, "appcmd failed")
		}
		sites, cut, err := parseSites(xml)
		if err != nil {
			return d, failed(winproto.CodeIOError, "the appcmd output could not be read")
		}
		d.Sites = sites
		truncated = truncated || cut
	}

	expired := false
	for _, s := range expiredStores {
		if err := stop(); err != nil {
			return d, err
		}
		n, err := h.ExpiredInStore(ctx, s)
		if err != nil || n < 0 {
			continue // a count that cannot be read is left out, not a failed dump
		}
		d.ExpiredInStore[s] = n
		expired = expired || n > 0
	}

	for _, w := range []struct {
		on   bool
		code string
	}{
		{d.IIS.SharedConfig, winproto.WarnSharedConfig},
		{d.IIS.AutoCertRebind, winproto.WarnAutoCertRebind},
		{d.IIS.CCSEnabled, winproto.WarnCCSEnabled},
		{expired, winproto.WarnExpiredInStore},
		{truncated, winproto.WarnListTruncated},
	} {
		if w.on {
			d.Warnings = append(d.Warnings, w.code)
		}
	}
	d.Truncated = truncated

	b, err := json.Marshal(d)
	if err != nil {
		return d, failed(winproto.CodeIOError, "the answer could not be encoded")
	}
	if len(b) > winproto.DumpOutput {
		return d, failed(winproto.CodeOutputTooLarge, "the answer is too large")
	}
	return d, nil
}

// cleanBinding validates and normalises one http.sys record from the host; false drops it. Nothing
// the host sent reaches Alice raw.
func cleanBinding(b winproto.SSLBinding) (winproto.SSLBinding, bool) {
	appID, ok := winproto.CanonicalAppID(b.AppID)
	if !ok || b.Port < 1 || b.Port > 65535 {
		return b, false
	}
	out := winproto.SSLBinding{Type: b.Type, Port: b.Port, AppID: appID, Flags: b.Flags,
		CertCheckMode: b.CertCheckMode, RevocationFreshnessTime: b.RevocationFreshnessTime,
		URLRetrievalTimeout: b.URLRetrievalTimeout,
		CTLIdentifier:       cleanValue(b.CTLIdentifier, winproto.MaxText), CTLStore: cleanValue(b.CTLStore, winproto.MaxText)}
	switch b.Type {
	case winproto.BindingIPPort, winproto.BindingCCS:
		// A ccs entry has ip 0.0.0.0, an empty hash and an empty store on a real host (W0).
		ip, err := netip.ParseAddr(b.IP)
		if err != nil {
			return b, false
		}
		out.IP = ip.String()
	case winproto.BindingHostnamePort:
		out.Host = cleanValue(b.Host, winproto.MaxText)
		if out.Host == "" {
			return b, false
		}
	default:
		return b, false
	}
	if b.Type == winproto.BindingCCS {
		// Whatever hash and store a ccs entry carries, it has no certificate of its own to read.
		return out, true
	}
	sha := strings.ToLower(b.CertSHA1) //nolint:forbidigo // hex digits, ASCII only
	if !winproto.ValidSHA1(sha) || (b.Store != "" && !winproto.ValidStore(b.Store)) {
		return b, false
	}
	store := b.Store
	if store == "" {
		store = defaultStore // http.sys returns a NULL store name for MY
	}
	out.CertSHA1, out.Store = sha, store
	return out, true
}

// defaultStore is the store http.sys means by a NULL store name (W0 F2).
const defaultStore = "MY"

// asciiLower folds ASCII upper case letters and leaves every other byte alone.
func asciiLower(s string) string {
	return strings.Map(func(r rune) rune {
		if r >= 'A' && r <= 'Z' {
			return r + 'a' - 'A'
		}
		return r
	}, s)
}

// cleanCertificate validates one certificate read from a store; false drops it (the binding stays).
func cleanCertificate(c winproto.StoreCertificate, store, sha1 string) (winproto.StoreCertificate, bool) {
	if c.KeyProblem != "" && c.KeyProblem != "key_missing" && c.KeyProblem != "key_inaccessible" {
		return c, false
	}
	if !validDER(c.DER) || len(c.Chain) > winproto.MaxChainCerts {
		return c, false
	}
	chain := make([]string, 0, len(c.Chain))
	for _, x := range c.Chain {
		if !validDER(x) {
			return c, false
		}
		chain = append(chain, x)
	}
	return winproto.StoreCertificate{Store: store, SHA1: sha1, SHA256: cleanValue(c.SHA256, 64), DER: c.DER, Chain: chain,
		FriendlyName: cleanValue(c.FriendlyName, winproto.MaxText), NotAfter: cleanValue(c.NotAfter, winproto.MaxText),
		HasKey: c.HasKey, KeyProvider: cleanValue(c.KeyProvider, winproto.MaxText), KeyExportable: c.KeyExportable,
		KeyUsableBySystem: c.KeyUsableBySystem, KeyProblem: c.KeyProblem}, true
}

// validDER reports whether s is standard base64 of one to MaxCertDER bytes.
func validDER(s string) bool {
	if s == "" || len(s) > base64.StdEncoding.EncodedLen(winproto.MaxCertDER) {
		return false
	}
	raw, err := base64.StdEncoding.DecodeString(s)
	return err == nil && len(raw) <= winproto.MaxCertDER
}
