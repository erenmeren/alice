//go:build windows

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// The IIS site "spike" the workflow creates with appcmd: https *:8443: (non-SNI, http.sys ipport 0.0.0.0:8443) and
// https *:8444:sni.spike.test with sslFlags=1 (SNI, http.sys hostnameport sni.spike.test:8444).
var (
	ipKey  = Binding{Type: "ipport", IP: "0.0.0.0", Port: 8443}
	sniKey = Binding{Type: "hostnameport", Host: "sni.spike.test", Port: 8444}
)

const errAlreadyExists = syscall.Errno(183) // ERROR_ALREADY_EXISTS

func appHostPath() string {
	return filepath.Join(os.Getenv("windir"), `system32\inetsrv\config\applicationHost.config`)
}

func fileSHA256(p string) string {
	b, err := os.ReadFile(p) //nolint:gosec // spike
	if err != nil {
		return "error: " + err.Error()
	}
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// ensure creates a binding, or re-points it when it exists.
func ensure(key Binding, hash string, b Binding) error {
	b.Type, b.IP, b.Host, b.Port, b.Hash = key.Type, key.IP, key.Host, key.Port, hash
	err := setBinding(b)
	if errors.Is(err, errAlreadyExists) {
		_, _, err = repoint(key, hash, "")
	}
	return err
}

func iisBinding() Binding { return Binding{Store: "MY", AppID: iisAppID} }

func probeIP() Probe  { return probe("127.0.0.1:8443", "ip.spike.test") }
func probeSNI() Probe { return probe("127.0.0.1:8444", "sni.spike.test") }

// cmdF1: IIS keeps the certificate only in http.sys; re-pointing there is picked up without a restart and without
// an applicationHost.config change, and survives an IIS restart.
func cmdF1(a, b string) map[string]any {
	out := map[string]any{"cert_a": a, "cert_b": b}
	out["apphost_sha256_start"] = fileSHA256(appHostPath())
	for _, k := range []Binding{ipKey, sniKey} {
		if err := ensure(k, a, iisBinding()); err != nil {
			out["set_error_"+k.Type] = errString(err)
		}
	}
	h1 := fileSHA256(appHostPath())
	out["apphost_sha256_after_set"] = h1
	out["probe_ip_a"], out["probe_sni_a"] = probeIP(), probeSNI()

	for _, k := range []Binding{ipKey, sniKey} {
		before, after, err := repoint(k, b, "")
		out["repoint_"+k.Type] = map[string]any{"before": before, "after": after, "error": errString(err),
			"other_fields_diff": sameExceptHash(before, after)}
	}
	pIP, pSNI := probeIP(), probeSNI()
	out["probe_ip_b_no_restart"], out["probe_sni_b_no_restart"] = pIP, pSNI
	h2 := fileSHA256(appHostPath())
	out["apphost_sha256_after_repoint"] = h2

	out["iisreset"] = run("iisreset", "/restart")
	time.Sleep(3 * time.Second)
	rIP, rSNI := probeIP(), probeSNI()
	out["probe_ip_after_iisreset"], out["probe_sni_after_iisreset"] = rIP, rSNI
	h3 := fileSHA256(appHostPath())
	out["apphost_sha256_after_iisreset"] = h3
	if cfg, err := os.ReadFile(appHostPath()); err == nil { //nolint:gosec // spike
		out["apphost_mentions_certificateHash"] = strings.Contains(string(cfg), "certificateHash")
		out["apphost_mentions_thumbprint_a"] = strings.Contains(strings.ToLower(string(cfg)), a)
	}
	out["netsh_after"] = netshText()
	out["verdict_confirmed"] = pIP.Leaf == b && pSNI.Leaf == b && h1 == h2 && h2 == h3 &&
		rIP.Leaf == b && rSNI.Leaf == b
	return out
}

// cmdF2: HttpUpdateServiceConfiguration changes only the hash of an ipport and a hostnameport entry in one call.
func cmdF2(a, b string) map[string]any {
	out := map[string]any{}
	ip := Binding{Type: "ipport", IP: "0.0.0.0", Port: 9443}
	sni := Binding{Type: "hostnameport", Host: "f2.spike.test", Port: 9444}
	// Non-default values in every field the design must preserve.
	tmpl := Binding{Store: "MY", AppID: "{11111111-2222-3333-4444-555555555555}", CertCheckMode: 1,
		RevocationFreshnessTime: 600, RevocationURLRetrievalTimeout: 7000, CtlIdentifier: "SpikeCtl",
		CtlStoreName: "Root", Flags: 0x2 | 0x40} // NEGOTIATE_CLIENT_CERT | DISABLE_TLS13
	for _, k := range []Binding{ip, sni} {
		res := map[string]any{}
		e := tmpl
		e.Type, e.IP, e.Host, e.Port, e.Hash = k.Type, k.IP, k.Host, k.Port, a
		if err := setBinding(e); err != nil {
			res["set_with_ctl_error"] = errString(err)
			e.CtlIdentifier, e.CtlStoreName = "", ""
			if err := setBinding(e); err != nil {
				res["set_error"] = errString(err)
			}
		}
		res["set_again_error"] = errString(setBinding(e)) // expect ERROR_ALREADY_EXISTS
		before, after, err := repoint(k, b, "")
		res["update"] = map[string]any{"before": before, "after": after, "error": errString(err),
			"hash_changed": after.Hash == b, "other_fields_diff": sameExceptHash(before, after)}

		// What does an update with only the key, hash and app id do: replace or merge?
		partial := Binding{Type: k.Type, IP: k.IP, Host: k.Host, Port: k.Port, Hash: a, AppID: before.AppID}
		perr := updateBinding(partial)
		pAfter, _ := getBinding(k)
		res["partial_update"] = map[string]any{"error": errString(perr), "after": pAfter,
			"fields_reset": sameExceptHash(after, pAfter)}
		// Restore the full entry.
		full := after
		res["restore_error"] = errString(updateBinding(full))

		// Update to a hash that is in no store: does http.sys check the certificate at update time?
		bogus := full
		bogus.Hash = strings.Repeat("ab", 20)
		berr := updateBinding(bogus)
		bAfter, _ := getBinding(k)
		res["update_unknown_hash"] = map[string]any{"error": errString(berr), "after_hash": bAfter.Hash}
		_ = updateBinding(full)

		// Update of a record that does not exist (BINDING_NOT_FOUND).
		missing := full
		missing.Port = 9449
		res["update_missing_error"] = errString(updateBinding(missing))
		out[k.Type] = res
	}

	// A CCS record, to see its shape.
	ccs := Binding{Type: "ccs", Port: 9445, AppID: iisAppID}
	out["ccs_set_error"] = errString(setBinding(ccs))
	out["enumeration"] = enumerateAll()
	g, err := getBinding(Binding{Type: "ccs", Port: 9445})
	out["ccs_get"] = map[string]any{"entry": g, "error": errString(err)}
	text := netshText()
	out["netsh"] = text
	out["netsh_vs_api"] = compareNetsh(text)
	out["ccs_delete_error"] = errString(deleteBinding(ccs))
	for _, k := range []Binding{ip, sni} {
		out["delete_error_"+k.Type] = errString(deleteBinding(k))
	}

	// No moment without a certificate: handshakes in a loop on the IIS port while the entry flips A<->B, first with
	// one update call per flip, then with delete+set (the fallback the design wants to avoid).
	out["flip_update"] = flipTest(a, b, func(h string) error { _, _, err := repoint(ipKey, h, ""); return err })
	out["flip_delete_set"] = flipTest(a, b, func(h string) error {
		cur, err := getBinding(ipKey)
		if err != nil {
			return err
		}
		if err := deleteBinding(ipKey); err != nil {
			return err
		}
		cur.Hash = h
		return setBinding(cur)
	})
	_, _, _ = repoint(ipKey, b, "")
	return out
}

func flipTest(a, b string, flip func(string) error) map[string]any {
	var ok, bad atomic.Int64
	var mu sync.Mutex
	var errs []string
	stop := make(chan struct{})
	var wg sync.WaitGroup
	for w := 0; w < 4; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				p := probeOnce("127.0.0.1:8443", "ip.spike.test")
				if p.OK {
					ok.Add(1)
				} else {
					bad.Add(1)
					mu.Lock()
					if len(errs) < 5 {
						errs = append(errs, p.Error)
					}
					mu.Unlock()
				}
			}
		}()
	}
	var flipErrs []string
	start := time.Now()
	for i := 0; i < 40; i++ {
		h := a
		if i%2 == 1 {
			h = b
		}
		if err := flip(h); err != nil && len(flipErrs) < 5 {
			flipErrs = append(flipErrs, errString(err))
		}
		time.Sleep(50 * time.Millisecond)
	}
	close(stop)
	wg.Wait()
	return map[string]any{"flips": 40, "seconds": time.Since(start).Seconds(), "handshakes_ok": ok.Load(),
		"handshakes_failed": bad.Load(), "handshake_errors": errs, "flip_errors": flipErrs}
}

// compareNetsh checks that every record the API enumerates appears in netsh's text with its hash.
func compareNetsh(text string) map[string]any {
	lower := strings.ToLower(text)
	var missing []string
	n := 0
	for _, id := range []uint32{configSSLCertInfo, configSslSniCertInfo, configSslCcsCertInfo} {
		list, _ := enumerate(id)
		for _, b := range list {
			n++
			addr := b.Key()
			_, v, _ := strings.Cut(addr, "=")
			if !strings.Contains(lower, strings.ToLower(v)) || (b.Hash != "" && !strings.Contains(lower, b.Hash)) {
				missing = append(missing, addr)
			}
		}
	}
	return map[string]any{"api_records": n, "netsh_mentions": strings.Count(lower, "certificate hash") +
		strings.Count(lower, "central certificate store"), "missing_in_netsh": missing}
}

// f4Variant imports one certificate with one method, binds it and proves http.sys serves it.
type f4Variant struct {
	name   string
	ec     bool
	method string // pfx-file, go-pfx-pbes2, go-pfx-keybag, ncrypt-pkcs8
	flags  uint32
}

func cmdF4(pfxPath, password, restore string) map[string]any {
	out := map[string]any{}
	exported, err := os.ReadFile(pfxPath) //nolint:gosec // spike
	if err != nil {
		out["pfx_read_error"] = err.Error()
	}
	const machineCNG = 0x20 | 0x200 // CRYPT_MACHINE_KEYSET | PKCS12_ALWAYS_CNG_KSP
	variants := []f4Variant{
		{"exported-pfx machine+always_cng", false, "pfx-file", machineCNG},
		{"exported-pfx machine only", false, "pfx-file", 0x20},
		{"go-pfx-pbes2 rsa machine+always_cng", false, "go-pfx-pbes2", machineCNG},
		{"go-pfx-pbes2 rsa machine+prefer_cng", false, "go-pfx-pbes2", 0x20 | pkcs12PreferCngKsp},
		{"go-pfx-keybag rsa machine+always_cng", false, "go-pfx-keybag", machineCNG},
		{"go-pfx-pbes2 ecdsa machine+always_cng", true, "go-pfx-pbes2", machineCNG},
		{"ncrypt-pkcs8 rsa", false, "ncrypt-pkcs8", 0},
		{"ncrypt-pkcs8 ecdsa", true, "ncrypt-pkcs8", 0},
		{"go-pfx-pbes2 rsa machine+always_cng+no_persist", false, "go-pfx-pbes2", machineCNG | 0x8000},
	}
	var results []map[string]any
	for i, v := range variants {
		res := map[string]any{"variant": v.name, "flags": fmt.Sprintf("0x%x", v.flags)}
		friendly := fmt.Sprintf("Alice f4.spike.test %s op%d", time.Now().Format("2006-01-02"), i)
		var thumbs []string
		var err error
		switch v.method {
		case "pfx-file":
			if exported == nil {
				err = errors.New("no exported PFX")
				break
			}
			thumbs, err = importPFX(exported, password, v.flags, "My", friendly)
		case "go-pfx-pbes2", "go-pfx-keybag":
			leaf := issue("f4.spike.test", []string{"f4.spike.test"}, false, v.ec, nil)
			pw := hex.EncodeToString(randBytes(16))
			var pfx []byte
			pfx, err = buildPFX(leaf.der, leaf.pkcs8(), pw, v.method == "go-pfx-pbes2")
			if err == nil {
				res["pfx_bytes"] = len(pfx)
				thumbs, err = importPFX(pfx, pw, v.flags, "My", friendly)
			}
			clear(pfx)
		case "ncrypt-pkcs8":
			leaf := issue("f4.spike.test", []string{"f4.spike.test"}, false, v.ec, nil)
			var t string
			t, err = importPKCS8(leaf.pkcs8(), leaf.der, fmt.Sprintf("alice-spike-f4-%d-%d", i, time.Now().UnixNano()),
				"My", friendly)
			if t != "" {
				thumbs = []string{t}
			}
		}
		if err != nil {
			res["import_error"] = errString(err)
			results = append(results, res)
			continue
		}
		thumb := thumbs[0]
		res["thumbprint"] = thumb
		res["facts"] = storeFacts("My", thumb)
		_, after, err := repoint(ipKey, thumb, "")
		res["bind_error"] = errString(err)
		res["bound_hash"] = after.Hash
		p := probeIP()
		res["probe"] = p
		res["served"] = p.Leaf == thumb
		if p.Leaf != thumb {
			// The fallback F4 would record: grant SYSTEM read on the key, rebind, probe again.
			sddl, gerr := grantSystemRead(thumb, "My")
			res["grant_system_read"] = map[string]any{"sddl": sddl, "error": errString(gerr)}
			_, _, _ = repoint(ipKey, restore, "")
			_, _, _ = repoint(ipKey, thumb, "")
			p2 := probeIP()
			res["probe_after_grant"] = p2
			res["served_after_grant"] = p2.Leaf == thumb
		}
		_, _, _ = repoint(ipKey, restore, "")
		res["cleanup"] = deleteCert("My", thumb, true)
		results = append(results, res)
	}
	out["variants"] = results
	return out
}

func storeFacts(store, thumb string) any {
	h, err := openStore(store, true)
	if err != nil {
		return errString(err)
	}
	defer closeStore(h)
	ctx, err := findByHash(h, thumb)
	if err != nil {
		return errString(err)
	}
	defer freeCtx(ctx)
	return certFacts(store, ctx)
}

// importLeaf puts a generated leaf and its key into LocalMachine\My: ncrypt-pkcs8, else a Go-built PFX.
func importLeaf(l issued, name string) (string, string, error) {
	t, err := importPKCS8(l.pkcs8(), l.der, name, "My", "")
	if err == nil {
		return t, "ncrypt-pkcs8", nil
	}
	pw := hex.EncodeToString(randBytes(16))
	pfx, perr := buildPFX(l.der, l.pkcs8(), pw, true)
	if perr != nil {
		return "", "", fmt.Errorf("%v; pfx: %v", err, perr)
	}
	ts, perr := importPFX(pfx, pw, 0x20|0x200, "My", "")
	if perr != nil {
		return "", "", fmt.Errorf("ncrypt: %v; pfx: %v", err, perr)
	}
	return ts[0], "go-pfx-pbes2", nil
}

func chainSummary(p Probe) []string {
	var s []string
	for _, c := range p.Chain {
		s = append(s, c.Subject)
	}
	return s
}

// cmdF5: schannel sends the chain Windows builds from CA and does not send the root.
func cmdF5(restore string) map[string]any {
	out := map[string]any{}
	step := func(name string, p Probe) {
		out[name] = map[string]any{"ok": p.OK, "error": p.Error, "chain_len": p.ChainLen, "chain": chainSummary(p)}
	}
	var cleanup []func()
	defer func() {
		_, _, _ = repoint(ipKey, restore, "")
		for i := len(cleanup) - 1; i >= 0; i-- {
			cleanup[i]()
		}
	}()
	addCA := func(store string, c issued) {
		t, err := addEncoded(store, c.der)
		if err != nil {
			out["add_error_"+c.cert.Subject.CommonName] = errString(err)
			return
		}
		cleanup = append(cleanup, func() { deleteCert(store, t, false) })
	}
	bindLeaf := func(l issued, name string) string {
		t, method, err := importLeaf(l, name)
		if err != nil {
			out["leaf_import_error_"+name] = errString(err)
			return ""
		}
		out["leaf_import_method"] = method
		cleanup = append(cleanup, func() { deleteCert("My", t, true) })
		if _, _, err := repoint(ipKey, t, ""); err != nil {
			out["bind_error_"+name] = errString(err)
		}
		return t
	}
	rebind := func(t string) {
		_, _, _ = repoint(ipKey, restore, "")
		_, _, _ = repoint(ipKey, t, "")
	}

	// 1. root in Root, intermediate in CA, leaf in My.
	root := issue("Spike Root 1", nil, true, true, nil)
	inter := issue("Spike Intermediate 1", nil, true, true, &root)
	leaf := issue("f5a.spike.test", []string{"f5a.spike.test"}, false, false, &inter)
	addCA("Root", root)
	interThumb := thumbOf(inter.der)
	addCA("CA", inter)
	t1 := bindLeaf(leaf, fmt.Sprintf("alice-spike-f5a-%d", time.Now().UnixNano()))
	out["machine_chain_1"] = machineChain("My", t1)
	step("served_1_root_and_intermediate_present", probeIP())
	// Intermediate removed from CA: right away, then after a rebind.
	out["remove_intermediate"] = deleteCert("CA", interThumb, false)
	step("served_1_intermediate_removed_no_rebind", probeIP())
	rebind(t1)
	step("served_1_intermediate_removed_after_rebind", probeIP())
	out["machine_chain_1_after_removal"] = machineChain("My", t1)

	// 2. root in Root, intermediate nowhere at bind time; then added to CA.
	root2 := issue("Spike Root 2", nil, true, true, nil)
	inter2 := issue("Spike Intermediate 2", nil, true, true, &root2)
	leaf2 := issue("f5b.spike.test", []string{"f5b.spike.test"}, false, false, &inter2)
	addCA("Root", root2)
	t2 := bindLeaf(leaf2, fmt.Sprintf("alice-spike-f5b-%d", time.Now().UnixNano()))
	step("served_2_intermediate_absent", probeIP())
	addCA("CA", inter2)
	step("served_2_intermediate_added_no_rebind", probeIP())
	// Does an update that names the same hash refresh schannel's cached chain?
	_, _, err := repoint(ipKey, t2, "")
	out["same_hash_update_error"] = errString(err)
	step("served_2_intermediate_added_after_same_hash_update", probeIP())
	rebind(t2)
	step("served_2_intermediate_added_after_rebind", probeIP())

	// 3. intermediate in CA, root in no store (a private CA not trusted by the server itself).
	root3 := issue("Spike Root 3", nil, true, true, nil)
	inter3 := issue("Spike Intermediate 3", nil, true, true, &root3)
	leaf3 := issue("f5c.spike.test", []string{"f5c.spike.test"}, false, false, &inter3)
	addCA("CA", inter3)
	t3 := bindLeaf(leaf3, fmt.Sprintf("alice-spike-f5c-%d", time.Now().UnixNano()))
	out["machine_chain_3"] = machineChain("My", t3)
	step("served_3_root_untrusted", probeIP())
	return out
}

// appcmd's XML: <appcmd><SITE SITE.NAME=".." SITE.ID=".." bindings=".." state=".."><site ...><bindings><binding
// protocol=".." bindingInformation=".." sslFlags=".."/></bindings></site></SITE></appcmd>.
type appcmdXML struct {
	Sites []struct {
		Name     string `xml:"SITE.NAME,attr"`
		ID       string `xml:"SITE.ID,attr"`
		Bindings string `xml:"bindings,attr"`
		State    string `xml:"state,attr"`
		Site     struct {
			Bindings []struct {
				Protocol string `xml:"protocol,attr"`
				Info     string `xml:"bindingInformation,attr"`
				SSLFlags string `xml:"sslFlags,attr"`
			} `xml:"bindings>binding"`
		} `xml:"site"`
	} `xml:"SITE"`
}

func cmdF6() map[string]any {
	appcmd := filepath.Join(os.Getenv("windir"), `system32\inetsrv\appcmd.exe`)
	out := map[string]any{"appcmd": appcmd}
	if _, err := os.Stat(appcmd); err != nil {
		out["appcmd_missing"] = err.Error()
		return out
	}
	r := run(appcmd, "list", "site", "/config", "/xml")
	raw, _ := r["output"].(string)
	out["list_site_config_xml"] = map[string]any{"exit_code": r["exit_code"], "seconds": r["seconds"],
		"head": head(raw, 1500)}
	full, _ := execOutput(appcmd, "list", "site", "/config", "/xml")
	out["bytes"] = len(full)
	var doc appcmdXML
	if err := xml.Unmarshal(full, &doc); err != nil {
		out["parse_error"] = err.Error()
	}
	var sites []map[string]any
	for _, s := range doc.Sites {
		var bs []string
		for _, b := range s.Site.Bindings {
			bs = append(bs, fmt.Sprintf("%s %s sslFlags=%s", b.Protocol, b.Info, b.SSLFlags))
		}
		sites = append(sites, map[string]any{"name": s.Name, "id": s.ID, "state": s.State, "bindings_attr": s.Bindings,
			"bindings": bs})
	}
	out["sites"] = sites
	r2 := run(appcmd, "list", "site", "/name:does-not-exist", "/xml")
	out["unknown_site"] = map[string]any{"exit_code": r2["exit_code"], "output": r2["output"]}
	return out
}

func head(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
