package winhelper

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/netip"
	"slices"
	"sort"
	"strings"
	"time"

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
		DroppedCertificates: []winproto.CertificateRef{}, Sites: []winproto.Site{}, ExpiredInStore: map[string]int{},
		Warnings: []string{}}
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
		if errors.Is(err, ErrStore) {
			return d, failed(winproto.CodeStoreError, "a certificate store could not be opened")
		}
		if err != nil {
			// One certificate that cannot be read no longer fails the dump (W2 Ruling 19): it is named as
			// dropped, so Alice reads the binding's leaf as unreadable, not as absent.
			truncated = true
			d.DroppedCertificates = append(d.DroppedCertificates, winproto.CertificateRef{Store: k.store, SHA1: k.sha1})
			continue
		}
		if !found {
			continue
		}
		cc, ok := cleanCertificate(c, k.store, k.sha1)
		if !ok {
			// Held by the store but not sent: named, so Alice does not read it as absent (bounded by the bindings).
			truncated = true
			d.DroppedCertificates = append(d.DroppedCertificates, winproto.CertificateRef{Store: k.store, SHA1: k.sha1})
			continue
		}
		d.Certificates = append(d.Certificates, cc)
	}
	markAliceImported(h, d.Certificates)

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

// markAliceImported sets AliceImported on each certificate rule 1 holds for (W3 Rulings 5 and 19),
// best effort: a host that cannot change the machine, or an import inventory that cannot be read,
// marks none; journals that cannot be listed or read are left out. The dump never fails for it.
func markAliceImported(h Host, certs []winproto.StoreCertificate) {
	wh, ok := h.(WriteHost)
	if !ok || len(certs) == 0 {
		return
	}
	imports, err := readImports(wh)
	if err != nil {
		return
	}
	var journals []journal
	listed := false
	for i := range certs {
		if aliceImported(wh, certs[i], imports, nil) {
			certs[i].AliceImported = true
			continue
		}
		if !listed {
			listed = true
			files, _ := readJournals(wh) // best effort
			for _, f := range files {
				if f.OK {
					journals = append(journals, f.J)
				}
			}
		}
		certs[i].AliceImported = aliceImported(wh, certs[i], importsFile{}, journals)
	}
}

// aliceImported is rule 1 (W3 Ruling 5): the certificate counts as Alice's when (a) the import
// inventory lists it (its store, ASCII case folded, and SHA-1), or (b) a journal written by a 0.3.0
// helper names it as new_sha1 in its store with the "existed" record false and an import that was
// Alice's (alice_imported: ImportPFX did not meet a copy); and in both cases the store copy's friendly
// name is Alice's form ending in that entry's operation. A W2 journal (no "existed" record) never
// counts. The host is not read: everything rule 1 needs is passed.
func aliceImported(_ WriteHost, c winproto.StoreCertificate, imports importsFile, journals []journal) bool {
	store := asciiLower(c.Store)
	for _, e := range imports.Imports {
		if e.SHA1 == c.SHA1 && asciiLower(e.Store) == store && aliceFriendlyName(c.FriendlyName, e.Op) {
			return true
		}
	}
	for _, j := range journals {
		if j.Existed != nil && !*j.Existed && j.AliceImported && j.NewSHA1 == c.SHA1 && asciiLower(j.Store) == store &&
			aliceFriendlyName(c.FriendlyName, j.Op) {
			return true
		}
	}
	return false
}

// aliceFriendlyName reports a friendly name of the form friendlyName gives an import of operation op:
// "Alice <name> <yyyy-mm-dd> <op8>", the name not empty and the date a date.
func aliceFriendlyName(name, op string) bool {
	if len(op) < 8 {
		return false
	}
	rest, ok := strings.CutPrefix(name, "Alice ")
	if !ok {
		return false
	}
	if rest, ok = strings.CutSuffix(rest, " "+op[:8]); !ok || len(rest) < len(" 2006-01-02")+1 {
		return false
	}
	date := rest[len(rest)-len("2006-01-02"):]
	subject, ok := strings.CutSuffix(rest[:len(rest)-len(date)], " ")
	if _, err := time.Parse("2006-01-02", date); err != nil || !ok || strings.TrimSpace(subject) == "" {
		return false
	}
	return true
}

// cleanBinding validates and normalises one http.sys record from the host; false drops it. Nothing
// the host sent reaches Alice raw.
func cleanBinding(b winproto.SSLBinding) (winproto.SSLBinding, bool) {
	appID, ok := winproto.CanonicalAppID(b.AppID)
	if !ok || b.Port < 1 || b.Port > 65535 || !winproto.ValidExtended(b.Extended) {
		return b, false
	}
	out := winproto.SSLBinding{Type: b.Type, Port: b.Port, AppID: appID, Flags: b.Flags,
		CertCheckMode: b.CertCheckMode, RevocationFreshnessTime: b.RevocationFreshnessTime,
		URLRetrievalTimeout: b.URLRetrievalTimeout,
		CTLIdentifier:       cleanValue(b.CTLIdentifier, winproto.MaxText), CTLStore: cleanValue(b.CTLStore, winproto.MaxText)}
	if len(b.Extended) > 0 {
		out.Extended = slices.Clone(b.Extended) // the extended parameters as read (F9), checked above
	}
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
