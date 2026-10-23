package windows

import (
	"cmp"
	"crypto/sha1" //nolint:gosec // G505: Windows names certificates by their SHA-1 thumbprint
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"alice/internal/platform/validate"
	"alice/internal/providers"
	"alice/internal/providers/windows/winproto"
)

// Unsupported reasons and problems of a Windows location (design §5, Rulings 8 and 9).
const (
	UnsupportedCCS        = "win_ccs"               // a Centralized Certificate Store binding (until W5)
	UnsupportedForeignApp = "win_foreign_app"       // an http.sys binding no IIS site binding uses
	UnsupportedStore      = "win_store_unsupported" // a store other than My and WebHosting

	ProblemCertMissing     = "cert_missing"     // the binding names a certificate its store does not hold, or an IIS binding has no entry
	ProblemKeyMissing      = "key_missing"      // the store holds the certificate without its key
	ProblemKeyInaccessible = "key_inaccessible" // SYSTEM (http.sys) cannot use the key

	// ApplicationIISUnused is the details "application" of an entry with IIS's application id that no IIS site
	// binding uses (reason win_foreign_app): it is IIS's own leftover, not another application's (final review M2).
	ApplicationIISUnused = "iis_unused"
)

// Bounds on what a remote server can make Alice carry (the webserver package's values).
const (
	maxServersPerLocation = 500
	maxMembershipsPerDump = 20000
	maxNameLength         = 253
	maxVersionLength      = 64
	maxDumpWarnings       = 32
	maxLocations          = winproto.MaxBindings // entries, and again IIS bindings without an entry
)

// Flags of HTTP_SERVICE_CONFIG_SSL_PARAM that make a binding warn win_ctl: client certificate mapping
// through the directory service and client certificate negotiation (Alice does not model them).
const (
	flagUseDSMapper         = 0x1
	flagNegotiateClientCert = 0x2
)

var warningCodeRE = regexp.MustCompile(`^[a-z][a-z_]{0,39}$`)

// siteKey is an IIS binding as http.sys looks it up: ip is "*" or a canonical address.
type siteKey struct {
	ip   string
	port int
	host string // ASCII folded, "" for none
	sni  bool   // sslFlags 0x1
	ccs  bool   // sslFlags 0x2
}

// foldASCII folds ASCII upper case letters only (Windows compares host and store names so).
func foldASCII(s string) string {
	return strings.Map(func(r rune) rune {
		if r >= 'A' && r <= 'Z' {
			return r + 'a' - 'A'
		}
		return r
	}, s)
}

// hostName is a host name folded to ASCII lower case, or false when it is not one: 1 to 253 letters,
// digits, '.', '-', '_' and '*' (a wildcard host header). A path, a port, white space and control or
// format characters are refused, so the canonical text can never read as another location's.
func hostName(h string) (string, bool) {
	h = foldASCII(h)
	if h == "" || !utf8.ValidString(h) || utf8.RuneCountInString(h) > maxNameLength {
		return "", false
	}
	for _, r := range h {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) && !strings.ContainsRune(".-_*", r) {
			return "", false
		}
	}
	return h, true
}

// address is an IP in netip's canonical form, an IPv4-mapped IPv6 address unmapped; a zone is
// refused.
func address(s string) (netip.Addr, bool) {
	ip, err := netip.ParseAddr(s)
	if err != nil || ip.Zone() != "" {
		return netip.Addr{}, false
	}
	return ip.Unmap(), true
}

// canonical is an http.sys entry's identity (Ruling 6): its canonical text and its locator; false when
// the entry cannot be one (a type, address, host, port or application id outside the rules).
func canonical(b winproto.SSLBinding) (text string, loc providers.Locator, ok bool) {
	appID, ok := winproto.CanonicalAppID(b.AppID)
	if !ok || b.Port < 1 || b.Port > 65535 {
		return "", nil, false
	}
	port := strconv.Itoa(b.Port)
	switch b.Type {
	case winproto.BindingHostnamePort:
		host, ok := hostName(b.Host)
		if !ok {
			return "", nil, false
		}
		return "http.sys/hostnameport/" + host + ":" + port, providers.Locator{"type": b.Type, "host": host, "port": b.Port, "app_id": appID}, true
	case winproto.BindingIPPort:
		ip, ok := address(b.IP)
		if !ok {
			return "", nil, false
		}
		return "http.sys/ipport/" + netip.AddrPortFrom(ip, uint16(b.Port)).String(), //nolint:gosec // G115: 1..65535
			providers.Locator{"type": b.Type, "ip": ip.String(), "port": b.Port, "app_id": appID}, true
	case winproto.BindingCCS:
		return "http.sys/ccs/" + port, providers.Locator{"type": b.Type, "port": b.Port, "app_id": appID}, true
	}
	return "", nil, false
}

// parseSiteBinding reads an IIS bindingInformation "ip:port:host" ("[addr]:port:host" for IPv6) with
// its sslFlags. False for anything IIS would not write: no port, a bad address or host, SNI without a
// host name.
func parseSiteBinding(info string, sslFlags int) (siteKey, bool) {
	var ipText, rest string
	if strings.HasPrefix(info, "[") {
		end := strings.Index(info, "]:")
		if end < 0 {
			return siteKey{}, false
		}
		ipText, rest = info[1:end], info[end+2:]
	} else {
		var found bool
		if ipText, rest, found = strings.Cut(info, ":"); !found {
			return siteKey{}, false
		}
	}
	portText, host, found := strings.Cut(rest, ":")
	if !found {
		return siteKey{}, false
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return siteKey{}, false
	}
	k := siteKey{ip: "*", port: port, sni: sslFlags&0x1 != 0, ccs: sslFlags&0x2 != 0}
	if ipText != "*" && ipText != "" {
		ip, ok := address(ipText)
		if !ok {
			return siteKey{}, false
		}
		k.ip = ip.String()
	}
	if host != "" {
		if k.host, found = hostName(host); !found {
			return siteKey{}, false
		}
	}
	if k.sni && k.host == "" {
		return siteKey{}, false
	}
	return k, true
}

// wanted is the http.sys entry an IIS binding would be bound to (what IIS Manager writes when a
// certificate is chosen): ccs, hostnameport, or ipport on its address (0.0.0.0 for "*").
func (k siteKey) wanted() winproto.SSLBinding {
	switch {
	case k.ccs:
		return winproto.SSLBinding{Type: winproto.BindingCCS, Port: k.port, AppID: winproto.AppIDIIS}
	case k.sni:
		return winproto.SSLBinding{Type: winproto.BindingHostnamePort, Host: k.host, Port: k.port, AppID: winproto.AppIDIIS}
	case k.ip == "*":
		return winproto.SSLBinding{Type: winproto.BindingIPPort, IP: "0.0.0.0", Port: k.port, AppID: winproto.AppIDIIS}
	}
	return winproto.SSLBinding{Type: winproto.BindingIPPort, IP: k.ip, Port: k.port, AppID: winproto.AppIDIIS}
}

// matches are the canonical texts of the entries an IIS binding uses, in http.sys's lookup order
// (Ruling 7): ccs:<port> for CCS, hostnameport for SNI; else "*" uses 0.0.0.0:<port> and [::]:<port>,
// a specific address its own entry, else [::]:<port> (an IPv6 address), else 0.0.0.0:<port>.
func (k siteKey) matches(has func(string) bool) []string {
	port := ":" + strconv.Itoa(k.port)
	v4, v6 := "http.sys/ipport/0.0.0.0"+port, "http.sys/ipport/[::]"+port
	var cands []string
	switch {
	case k.ccs:
		cands = []string{"http.sys/ccs/" + strconv.Itoa(k.port)}
	case k.sni:
		cands = []string{"http.sys/hostnameport/" + k.host + port}
	case k.ip == "*":
		return slices.DeleteFunc([]string{v4, v6}, func(s string) bool { return !has(s) })
	default:
		ip := netip.MustParseAddr(k.ip)                                                        // parseSiteBinding kept a valid address
		cands = []string{"http.sys/ipport/" + netip.AddrPortFrom(ip, uint16(k.port)).String()} //nolint:gosec // G115: 1..65535
		if ip.Is6() {
			cands = append(cands, v6)
		}
		cands = append(cands, v4)
	}
	for _, c := range cands {
		if has(c) {
			return []string{c}
		}
	}
	return nil
}

// server is an IIS binding as a location's server, with what it is sorted by.
type server struct {
	cs         providers.CertServer
	site, info string
}

// location is an http.sys entry (or the entry an IIS binding lacks) while the sites are folded in.
type location struct {
	text    string
	locator providers.Locator
	entry   *winproto.SSLBinding // nil: an IIS binding without an entry
	servers []server
	cut     bool
}

func (l *location) add(s server) {
	if slices.ContainsFunc(l.servers, func(o server) bool { return sameServer(o.cs, s.cs) }) {
		return
	}
	if len(l.servers) >= maxServersPerLocation {
		l.cut = true
		return
	}
	l.servers = append(l.servers, s)
}

func sameServer(a, b providers.CertServer) bool {
	return a.Section == b.Section && slices.Equal(a.Names, b.Names) && slices.Equal(a.Listens, b.Listens)
}

type certKey struct{ store, sha1 string }

// convert turns an iis-dump answer into locations (design §5, §6.2): one per http.sys entry, plus one
// per entry an IIS https binding lacks (cert_missing), each with the IIS bindings that use it (Ruling
// 7), supported by Ruling 8, its problems by Ruling 9, sorted by canonical text. An entry or IIS
// binding Alice cannot read is left out, and the result then says locations were dropped, as for a
// dump the helper cut, so inventory marks nothing missing (Ruling 20).
func convert(d winproto.IISDumpResponse) (certs []providers.DiscoveredCertificate, warns []providers.Warning, facts providers.WebServerFacts) {
	facts = providers.WebServerFacts{Software: "iis", Version: cleanValue(d.IIS.Version, maxVersionLength), Found: d.IIS.Installed, ConfigValid: true}
	stored := map[certKey]winproto.StoreCertificate{}
	for _, c := range d.Certificates {
		k := certKey{foldASCII(c.Store), c.SHA1}
		if _, dup := stored[k]; !dup && winproto.ValidSHA1(c.SHA1) {
			stored[k] = c
		}
	}
	// The certificates the store holds that the helper did not send (its bounds): not cert_missing (M3).
	unread := map[certKey]bool{}
	for _, c := range d.DroppedCertificates {
		if len(unread) >= winproto.MaxCertificates {
			break
		}
		unread[certKey{foldASCII(c.Store), foldASCII(c.SHA1)}] = true
	}

	dropped := d.Truncated
	// What W2 Ruling 18 must know of a cut: the helper's own cut (truncated, list_truncated: any list may
	// lack entries), an entry Alice could not read (an IIS binding may want it), a site binding Alice could
	// not read or no longer counted (it may use an entry).
	helperCut := d.Truncated || slices.Contains(d.Warnings, winproto.WarnListTruncated)
	entriesCut, sitesCut := helperCut, helperCut
	locs := map[string]*location{}
	entries := 0
	for i := range d.Bindings {
		b := d.Bindings[i]
		text, loc, ok := canonical(b)
		if !ok || locs[text] != nil || entries >= winproto.MaxBindings {
			dropped = true
			entriesCut = entriesCut || locs[text] == nil
			continue
		}
		entries++
		locs[text] = &location{text: text, locator: loc, entry: &b}
	}
	has := func(text string) bool { l := locs[text]; return l != nil && l.entry != nil }

	missing, memberships := 0, 0
	for _, site := range d.Sites {
		name := cleanValue(site.Name, maxNameLength)
		for _, sb := range site.Bindings {
			if !strings.EqualFold(sb.Protocol, "https") {
				continue
			}
			k, ok := parseSiteBinding(sb.Information, sb.SSLFlags)
			if !ok || memberships >= maxMembershipsPerDump {
				dropped, sitesCut = true, true
				continue
			}
			memberships++
			texts := k.matches(has)
			if len(texts) == 0 {
				w := k.wanted()
				text, loc, _ := canonical(w) // parseSiteBinding's values always make an entry
				if locs[text] == nil {
					if missing >= maxLocations {
						dropped = true
						continue
					}
					missing++
					locs[text] = &location{text: text, locator: loc}
				}
				texts = []string{text}
			}
			cs := providers.CertServer{Names: []string{}, Listens: []providers.CertListen{{Addr: k.ip, Port: k.port}}, Section: name}
			if k.host != "" {
				cs.Names = []string{k.host}
			}
			for _, t := range texts {
				locs[t].add(server{cs: cs, site: name, info: sb.Information})
			}
		}
	}

	// W2 Ruling 18: a cut dump proves no verdict that rests on what may be missing: an entry no listed
	// site uses (win_foreign_app) when the sites were cut, a certificate the listed certificates lack
	// (cert_missing) when the helper cut its lists, an IIS binding without a listed entry (cert_missing)
	// when the entries were cut. Such a location is left out (locations_dropped), so inventory keeps its
	// stored row untouched instead of relabelling it. leaf_unreadable (dropped_certificates) is proven.
	incomplete := dropped || helperCut
	certs = make([]providers.DiscoveredCertificate, 0, len(locs))
	for _, l := range locs {
		dc := finish(l, stored, unread)
		switch dl := dc.Location; {
		case sitesCut && dl.Unsupported == UnsupportedForeignApp,
			helperCut && l.entry != nil && dl.Problem == ProblemCertMissing,
			entriesCut && l.entry == nil:
			continue
		}
		certs = append(certs, dc)
	}
	slices.SortFunc(certs, func(a, b providers.DiscoveredCertificate) int {
		return cmp.Compare(a.Location.CertPath, b.Location.CertPath)
	})

	warns, cut := dumpWarnings(d)
	if !d.IIS.Installed {
		warns = append(warns, warning(providers.WarnWebServerNotFound))
	}
	if incomplete {
		warns = append(warns, warning(providers.WarnListTruncated), warning(providers.WarnLocationsDropped))
	} else if cut {
		warns = append(warns, warning(providers.WarnListTruncated))
	}
	return certs, warns, facts
}

func warning(code string) providers.Warning {
	return providers.Warning{Code: code, Params: map[string]string{}}
}

// supportedStore: My and WebHosting, compared without case (W0 F2), and only a name of the protocol's
// vocabulary.
func supportedStore(s string) bool {
	return winproto.ValidStore(s) && (strings.EqualFold(s, "My") || strings.EqualFold(s, "WebHosting"))
}

// finish decides a location's support, problems, certificate and details.
func finish(l *location, stored map[certKey]winproto.StoreCertificate, unread map[certKey]bool) providers.DiscoveredCertificate {
	slices.SortFunc(l.servers, func(a, b server) int {
		return cmp.Or(cmp.Compare(a.site, b.site), cmp.Compare(a.info, b.info))
	})
	loc := providers.CertLocation{Kind: providers.LocationWinSSLBinding, Locator: l.locator, CertPath: l.text, Servers: make([]providers.CertServer, 0, len(l.servers))}
	for _, s := range l.servers {
		loc.Servers = append(loc.Servers, s.cs)
	}
	appID, _ := l.locator["app_id"].(string)
	loc.Details = map[string]any{"app_id": appID, "application": winproto.KnownApps[appID]}
	dc := providers.DiscoveredCertificate{}
	var reason string
	var dropped bool
	switch e := l.entry; {
	case e == nil:
		// An IIS https binding without an entry (Ruling 9); a CCS one stays win_ccs.
		loc.Problem = ProblemCertMissing
		if l.locator["type"] == winproto.BindingCCS {
			reason = UnsupportedCCS
		}
	case e.Type == winproto.BindingCCS:
		reason = UnsupportedCCS
		entryDetails(loc.Details, *e)
	default:
		store := e.Store
		if store == "" {
			store = "MY" // a NULL store name is MY (W0 F2)
		}
		switch {
		case len(l.servers) == 0:
			reason = UnsupportedForeignApp
			if appID == winproto.AppIDIIS {
				loc.Details["application"] = ApplicationIISUnused
			}
		case !supportedStore(store):
			reason = UnsupportedStore
		}
		entryDetails(loc.Details, *e)
		loc.Details["store"] = cleanValue(store, maxStoreLength)
		sha := strings.ToLower(e.CertSHA1) //nolint:forbidigo // hex digits
		if winproto.ValidSHA1(sha) {
			loc.Details["cert_sha1"] = sha
		}
		k := certKey{foldASCII(store), sha}
		c, ok := stored[k]
		if !ok {
			loc.Problem = ProblemCertMissing
			if unread[k] {
				// The store holds it, the helper did not send it (over its bounds): it cannot be read, it is not gone.
				loc.Problem = providers.CertProblemLeafUnreadable
			}
			break
		}
		certDetails(loc.Details, c)
		dc.PEMChain, dc.FileSHA256, dropped, loc.Problem = certificateChain(c, sha)
		loc.KeyProblem = keyProblem(c)
	}
	if e := l.entry; e != nil && (e.CTLIdentifier != "" || e.CTLStore != "" || e.Flags&(flagUseDSMapper|flagNegotiateClientCert) != 0) {
		loc.Warnings = append(loc.Warnings, winproto.WarnCTL)
	}
	if dropped {
		loc.Warnings = append(loc.Warnings, providers.WarnCertificateBlockDropped)
	}
	if l.cut {
		loc.Warnings = append(loc.Warnings, providers.WarnListTruncated)
	}
	if reason == "" && (loc.Problem != "" || loc.KeyProblem != "") {
		reason = providers.UnsupportedFile
	}
	loc.Unsupported, loc.Supported = reason, reason == ""
	if loc.Problem != "" {
		dc.PEMChain, dc.FileSHA256 = nil, ""
	}
	dc.Location = loc
	return dc
}

// entryDetails are the http.sys settings of an entry that W2 must preserve and the UI shows.
func entryDetails(d map[string]any, e winproto.SSLBinding) {
	d["flags"] = e.Flags
	d["cert_check_mode"] = e.CertCheckMode
	d["ctl_identifier"] = cleanValue(e.CTLIdentifier, winproto.MaxText)
	d["ctl_store"] = cleanValue(e.CTLStore, winproto.MaxText)
}

// certDetails are the facts of the certificate and its key (design §5: instead of the Unix key facts).
func certDetails(d map[string]any, c winproto.StoreCertificate) {
	d["friendly_name"] = cleanValue(c.FriendlyName, winproto.MaxText)
	d["key_provider"] = cleanValue(c.KeyProvider, winproto.MaxText)
	d["key_exportable"] = c.KeyExportable
	if c.KeyUsableBySystem != nil {
		d["key_usable_by_system"] = *c.KeyUsableBySystem
	} else {
		d["key_usable_by_system"] = nil
	}
	d["alice_imported"] = c.AliceImported // R62 Ruling 19: the bindings panel's "Imported by Alice"
}

// keyProblem is the key's problem: the helper's (a value outside the set is unknown), key_missing
// for a certificate without a key.
func keyProblem(c winproto.StoreCertificate) string {
	switch {
	case c.KeyProblem == ProblemKeyMissing || c.KeyProblem == ProblemKeyInaccessible:
		return c.KeyProblem
	case c.KeyProblem != "":
		return providers.CertProblemUnknown
	case !c.HasKey:
		return ProblemKeyMissing
	}
	return ""
}

// certificateChain re-encodes the certificate the binding names and the chain Windows built for it
// (the remote is not trusted: every certificate is parsed again). The leaf must decode, parse, have
// validity dates Alice can store and carry the binding's thumbprint, else the location is
// not_a_certificate; a chain certificate that does not is dropped (dropped is true). The token is the
// SHA-256 of the leaf's DER (the compare-and-swap value of a W2 deployment).
func certificateChain(c winproto.StoreCertificate, sha string) (chain []byte, sum string, dropped bool, problem string) {
	if len(c.Chain) > winproto.MaxChainCerts {
		return nil, "", false, providers.CertProblemTooLarge
	}
	leaf, ok := parseDER(c.DER)
	if !ok || thumbprint(leaf) != sha {
		return nil, "", false, providers.CertProblemNotACertificate
	}
	chain = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf})
	for _, x := range c.Chain {
		der, ok := parseDER(x)
		if !ok {
			dropped = true
			continue
		}
		chain = append(chain, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	s := sha256.Sum256(leaf)
	return chain, hex.EncodeToString(s[:]), dropped, ""
}

// parseDER decodes standard base64 of at most MaxCertDER bytes that parses as a certificate with
// storable validity dates.
func parseDER(s string) ([]byte, bool) {
	if len(s) > base64.StdEncoding.EncodedLen(winproto.MaxCertDER) {
		return nil, false
	}
	der, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, false
	}
	c, err := x509.ParseCertificate(der)
	if err != nil || !validate.CertificateTimes(c.NotBefore, c.NotAfter) {
		return nil, false
	}
	return der, true
}

func thumbprint(der []byte) string {
	s := sha1.Sum(der) //nolint:gosec // G401: a thumbprint is an identifier, not a security hash
	return hex.EncodeToString(s[:])
}

// dumpWarnings are the dump's server-level warnings, each once and only with a code of the fixed
// format, at most maxDumpWarnings (more set cut). win_expired_in_store carries the count of expired
// certificates in the stores; list_truncated is the caller's.
func dumpWarnings(d winproto.IISDumpResponse) (out []providers.Warning, cut bool) {
	seen := map[string]bool{}
	for _, w := range d.Warnings {
		switch {
		case !warningCodeRE.MatchString(w) || seen[w] || w == winproto.WarnListTruncated:
			continue
		case len(seen) >= maxDumpWarnings:
			cut = true
			continue
		}
		seen[w] = true
		wn := warning(w)
		if w == winproto.WarnExpiredInStore {
			n := 0
			for _, c := range d.ExpiredInStore {
				n += min(max(c, 0), 1<<20)
			}
			wn.Params["count"] = strconv.Itoa(n)
		}
		out = append(out, wn)
	}
	return out, cut
}
