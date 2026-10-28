//go:build windows

package main

// The machine half of the Remote Desktop listener (W6, R69): the RDP-Tcp listener's effective settings
// (Ruling 5), its one value SSLCertificateSHA1Hash (Ruling 9 step 7), the certificates of a machine
// store (Remote Desktop's self-signed one, Ruling 4) and NETWORK SERVICE's read access to the private
// key of a certificate in My (Ruling 10). Every registry path, value name and SID is a constant of this
// file; no argument names one (WN-24).
//
//	https://learn.microsoft.com/en-us/windows-hardware/customize/desktop/unattend/microsoft-windows-terminalservices-rdp-winstationextensions-securitylayer
//	https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptsetproperty
//	https://learn.microsoft.com/en-us/windows/win32/secauthz/ace-strings

import (
	"context"
	"crypto/sha1" //nolint:gosec // G505: the store's thumbprint is SHA-1; it names a certificate, it secures nothing
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"alice/internal/providers/windows/winhelper"
	"alice/internal/providers/windows/winproto"
)

// The listener's registry keys and values (Ruling 5). The policy key's values win over the listener's.
const (
	keyRDPTcp         = `SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp`
	keyTerminalServer = `SYSTEM\CurrentControlSet\Control\Terminal Server`
	keyRDPPolicy      = `SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services`
	valueRDPHash      = "SSLCertificateSHA1Hash"
	valueRDPDeny      = "fDenyTSConnections"
	valueRDPPort      = "PortNumber"
	valueRDPLayer     = "SecurityLayer"
	valueRDPNLA       = "UserAuthentication"
	valueRDPTemplate  = "CertTemplateName"

	// The documented defaults of a value that is absent: RDP off, port 3389, the TLS security layer
	// (2, as F19 found it on both runner images) and NLA required.
	rdpDefaultDeny  = 1
	rdpDefaultPort  = 3389
	rdpDefaultLayer = 2
	rdpDefaultNLA   = 1
)

// rdpGrantMask is the mask of Ruling 10's one ACE (F21 measures it); a revoke removes only an
// access-allowed NETWORK SERVICE ACE of exactly this mask.
const rdpGrantMask = windows.GENERIC_READ

// aclRevision is ACL_REVISION, the lowest revision of an ACL of access-allowed and denied ACEs.
const aclRevision byte = 2

var (
	procNCryptSetProperty = modncrypt.NewProc("NCryptSetProperty")

	errRDPStore  = errors.New("only a certificate in My is given to the Remote Desktop listener")
	errNoCert    = errors.New("the store holds no such certificate")
	errKeyACL    = errors.New("the key's security descriptor could not be read or written")
	errNoKeyDACL = errors.New("the key's security descriptor has no DACL")
)

// RDPListener reads RDP-Tcp's settings as Windows applies them (Ruling 5). Present is false when the
// RDP-Tcp key does not exist; a value of the wrong type or size is an error.
func (host) RDPListener(ctx context.Context) (winhelper.RDPListener, error) {
	if err := ctx.Err(); err != nil {
		return winhelper.RDPListener{}, err
	}
	k, err := openKey(keyRDPTcp)
	if errors.Is(err, registry.ErrNotExist) {
		return winhelper.RDPListener{}, nil
	}
	if err != nil {
		return winhelper.RDPListener{}, err
	}
	defer func() { _ = k.Close() }()
	l := winhelper.RDPListener{Present: true}
	port, _, err := dword(k, valueRDPPort, rdpDefaultPort)
	if err != nil {
		return winhelper.RDPListener{}, err
	}
	layer, _, err := dword(k, valueRDPLayer, rdpDefaultLayer)
	if err != nil {
		return winhelper.RDPListener{}, err
	}
	nla, _, err := dword(k, valueRDPNLA, rdpDefaultNLA)
	if err != nil {
		return winhelper.RDPListener{}, err
	}
	if l.CertSHA1, err = binarySHA1(k, valueRDPHash); err != nil {
		return winhelper.RDPListener{}, err
	}
	deny := rdpDefaultDeny
	switch ts, err := openKey(keyTerminalServer); {
	case errors.Is(err, registry.ErrNotExist):
	case err != nil:
		return winhelper.RDPListener{}, err
	default:
		deny, _, err = dword(ts, valueRDPDeny, rdpDefaultDeny)
		_ = ts.Close()
		if err != nil {
			return winhelper.RDPListener{}, err
		}
	}
	switch p, err := openKey(keyRDPPolicy); {
	case errors.Is(err, registry.ErrNotExist):
	case err != nil:
		return winhelper.RDPListener{}, err
	default:
		err = applyRDPPolicy(p, &deny, &layer, &nla, &l.CertTemplate)
		_ = p.Close()
		if err != nil {
			return winhelper.RDPListener{}, err
		}
	}
	l.Enabled, l.NLA, l.Port, l.SecurityLayer = deny == 0, nla != 0, port, layer
	return l, nil
}

// applyRDPPolicy lets each value the policy key sets replace the listener's own.
func applyRDPPolicy(p registry.Key, deny, layer, nla *int, template *string) error {
	for _, v := range []struct {
		name string
		to   *int
	}{{valueRDPDeny, deny}, {valueRDPLayer, layer}, {valueRDPNLA, nla}} {
		n, found, err := dword(p, v.name, 0)
		if err != nil {
			return err
		}
		if found {
			*v.to = n
		}
	}
	s, _, err := p.GetStringValue(valueRDPTemplate)
	if err != nil && !errors.Is(err, registry.ErrNotExist) {
		return err
	}
	*template = strings.TrimSpace(s)
	return nil
}

// dword reads a REG_DWORD; found is false (and the value def) when it is absent. Any other type is an
// error.
func dword(k registry.Key, name string, def int) (int, bool, error) {
	v, typ, err := k.GetIntegerValue(name)
	if errors.Is(err, registry.ErrNotExist) {
		return def, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	if typ != registry.DWORD {
		return 0, false, errBadValue
	}
	return int(v), true, nil //nolint:gosec // G115: a DWORD fits an int on the 64-bit builds
}

// binarySHA1 reads a REG_BINARY of 20 bytes as lower-case hex, "" when it is absent.
func binarySHA1(k registry.Key, name string) (string, error) {
	v, _, err := k.GetBinaryValue(name)
	if errors.Is(err, registry.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	if len(v) != sha1.Size {
		return "", errBadValue
	}
	return hex.EncodeToString(v), nil
}

// SetRDPCertificate writes SSLCertificateSHA1Hash as the 20 bytes of sha1Hex, or deletes it for "" (a
// value already absent is no error). The key is opened with SET_VALUE only.
func (host) SetRDPCertificate(ctx context.Context, sha1Hex string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	var hash []byte
	if sha1Hex != "" {
		b, err := hex.DecodeString(sha1Hex)
		if err != nil || len(b) != sha1.Size {
			return errBadValue
		}
		hash = b
	}
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, keyRDPTcp, registry.SET_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return err
	}
	defer func() { _ = k.Close() }()
	if hash == nil {
		if err := k.DeleteValue(valueRDPHash); err != nil && !errors.Is(err, registry.ErrNotExist) {
			return err
		}
		return nil
	}
	return k.SetBinaryValue(valueRDPHash, hash)
}

// StoreCertificates lists at most limit certificates of a machine store with the facts certificate()
// reads (none when the store does not exist), in the store's order.
func (h host) StoreCertificates(ctx context.Context, store string, limit int) ([]winproto.StoreCertificate, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	out := []winproto.StoreCertificate{}
	if limit <= 0 {
		return out, nil
	}
	st, found, err := openExistingStore(store)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", winhelper.ErrStore, err)
	}
	if !found {
		return out, nil
	}
	var thumbs []string
	var prev *windows.CertContext
	for len(thumbs) < limit {
		// CertEnumCertificatesInStore frees prev, also when it returns nil.
		c, err := windows.CertEnumCertificatesInStore(st, prev)
		prev = nil
		if c == nil {
			if !hresult(err, codeCryptNotFound, codeNoMoreFiles) {
				_ = windows.CertCloseStore(st, 0)
				return nil, errStore
			}
			break
		}
		prev = c
		der := contextDER(c)
		if len(der) == 0 {
			continue
		}
		sum := sha1.Sum(der) //nolint:gosec // G401: the thumbprint, see the import
		thumbs = append(thumbs, hex.EncodeToString(sum[:]))
	}
	if prev != nil {
		_ = windows.CertFreeCertificateContext(prev) // the loop stopped at limit: the last context is still held
	}
	_ = windows.CertCloseStore(st, 0)
	for _, s := range thumbs {
		c, found, err := certificate(store, s, h.now())
		if err != nil {
			return nil, err
		}
		if found {
			out = append(out, c)
		}
	}
	return out, nil
}

// RDPKeyRead reports whether NETWORK SERVICE or Everyone holds an access-allowed ACE with the read bits
// on the key of the certificate in My (Ruling 10). Any other store is refused.
func (host) RDPKeyRead(ctx context.Context, store, sha1Hex string) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	var readable bool
	err := withRDPKey(store, sha1Hex, func(key windows.Handle) error {
		sd, keep, err := keyDACL(key)
		if err != nil {
			return err
		}
		defer runtime.KeepAlive(keep)
		readable, err = networkServiceCanRead(sd)
		return err
	})
	return readable, err
}

// SetRDPKeyRead appends Ruling 10's one ACE (grant) or removes the non-inherited access-allowed
// NETWORK SERVICE ACEs of exactly rdpGrantMask (revoke) on the key of the certificate in My; the other
// ACEs, their order and the descriptor's control bits stay. A revoke that finds nothing writes nothing.
func (host) SetRDPKeyRead(ctx context.Context, store, sha1Hex string, grant bool) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	ns, err := windows.CreateWellKnownSid(windows.WinNetworkServiceSid)
	if err != nil {
		return err
	}
	return withRDPKey(store, sha1Hex, func(key windows.Handle) error {
		if grant {
			ace, err := explicitACE(windows.GRANT_ACCESS, rdpGrantMask, ns)
			if err != nil {
				return err
			}
			return editKeyDACL(key, nil, ace)
		}
		return editKeyDACL(key, func(a *windows.ACCESS_ALLOWED_ACE, sid *windows.SID) bool {
			return a.Header.AceType == windows.ACCESS_ALLOWED_ACE_TYPE && a.Header.AceFlags&windows.INHERITED_ACE == 0 &&
				uint32(a.Mask) == rdpGrantMask && windows.EqualSid(sid, ns)
		}, nil)
	})
}

// withRDPKey opens the CNG key of the certificate with this SHA-1 in LocalMachine\My and calls f with
// it. Another store is refused before anything is opened (Ruling 6, WN-24).
func withRDPKey(store, sha1Hex string, f func(windows.Handle) error) error {
	if !strings.EqualFold(store, "MY") {
		return errRDPStore
	}
	return withStoreKey("MY", sha1Hex, f)
}

// withStoreKey opens the CNG key of a machine store's certificate and calls f with it (the store is
// the caller's constant: My here, and Remote Desktop in a measurement of the tests).
func withStoreKey(store, sha1Hex string, f func(windows.Handle) error) error {
	hash, err := hex.DecodeString(sha1Hex)
	if err != nil || len(hash) != sha1.Size {
		return errBadValue
	}
	st, err := openStore(store)
	if err != nil {
		return fmt.Errorf("%w: %w", winhelper.ErrStore, err)
	}
	defer func() { _ = windows.CertCloseStore(st, 0) }()
	blob := windows.CryptHashBlob{Size: sha1.Size, Data: &hash[0]}
	// unsafe: the hash blob is CertFindCertificateInStore's pvFindPara, alive for the call.
	c, err := windows.CertFindCertificateInStore(st, encodingAny, 0, windows.CERT_FIND_SHA1_HASH, unsafe.Pointer(&blob), nil)
	runtime.KeepAlive(hash)
	if c == nil {
		if hresult(err, codeCryptNotFound) {
			return errNoCert
		}
		return errStore
	}
	defer func() { _ = windows.CertFreeCertificateContext(c) }()
	key, free, err := acquireKey(c)
	if err != nil {
		return fmt.Errorf("%w: %w", winhelper.ErrKeyUnusable, err)
	}
	if free {
		defer func() { _, _, _ = procNCryptFreeObject.Call(uintptr(key)) }()
	}
	return f(key)
}

// keyDACL reads a key's security descriptor with its DACL only (self-relative); keep holds the
// buffer the descriptor lives in.
func keyDACL(key windows.Handle) (*windows.SECURITY_DESCRIPTOR, []uint64, error) {
	buf, n, ok := ncryptProperty(key, ncryptSecurityDescrProp, daclSecurityInformation)
	if !ok || uintptr(n) < unsafe.Sizeof(windows.SECURITY_DESCRIPTOR{}) {
		return nil, nil, errKeyACL
	}
	// unsafe: buf holds the self-relative descriptor NCryptGetProperty wrote.
	sd := (*windows.SECURITY_DESCRIPTOR)(unsafe.Pointer(&buf[0]))
	if !sd.IsValid() || sd.Length() > n {
		return nil, nil, errKeyACL
	}
	return sd, buf, nil
}

// networkServiceCanRead reports an access-allowed ACE that applies to the key itself, names NETWORK
// SERVICE or Everyone and holds GENERIC_READ or GENERIC_ALL. A NULL DACL grants everyone.
func networkServiceCanRead(sd *windows.SECURITY_DESCRIPTOR) (bool, error) {
	dacl, _, err := sd.DACL()
	if err != nil {
		return false, errNoKeyDACL
	}
	if dacl == nil {
		return true, nil
	}
	ns, err := windows.CreateWellKnownSid(windows.WinNetworkServiceSid)
	if err != nil {
		return false, err
	}
	world, err := windows.CreateWellKnownSid(windows.WinWorldSid)
	if err != nil {
		return false, err
	}
	readable := false
	err = eachACE(dacl, func(a *windows.ACCESS_ALLOWED_ACE, sid *windows.SID, _ []byte) {
		if a.Header.AceType == windows.ACCESS_ALLOWED_ACE_TYPE && a.Header.AceFlags&windows.INHERIT_ONLY_ACE == 0 &&
			uint32(a.Mask)&(rdpGrantMask|windows.GENERIC_ALL) != 0 && (windows.EqualSid(sid, ns) || windows.EqualSid(sid, world)) {
			readable = true
		}
	})
	return readable, err
}

// eachACE calls f with every ACE of an ACL: the ACE, its SID (nil for a type whose layout is not
// ACCESS_ALLOWED_ACE's) and its bytes.
func eachACE(dacl *windows.ACL, f func(a *windows.ACCESS_ALLOWED_ACE, sid *windows.SID, raw []byte)) error {
	if dacl.AceCount > maxACEs {
		return errKeyACL
	}
	for i := range uint32(dacl.AceCount) {
		var a *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &a); err != nil || a == nil || a.Header.AceSize < 8 {
			return errKeyACL
		}
		var sid *windows.SID
		switch a.Header.AceType {
		case windows.ACCESS_ALLOWED_ACE_TYPE, windows.ACCESS_DENIED_ACE_TYPE:
			// unsafe: these ACEs' SID starts at SidStart, inside the ACE.
			sid = (*windows.SID)(unsafe.Pointer(&a.SidStart))
		}
		// unsafe: the ACE's AceSize bytes lie inside the ACL.
		f(a, sid, unsafe.Slice((*byte)(unsafe.Pointer(a)), a.Header.AceSize))
	}
	return nil
}

// explicitACE builds one ACE with no inheritance flags for a SID (windows.ACLFromEntries of one entry,
// no ACL merged) and returns its bytes. The ACE is spliced into the key's DACL by editKeyDACL rather
// than merged by SetEntriesInAcl, which would fold it into (or change) an ACE the trustee already has.
func explicitACE(mode windows.ACCESS_MODE, mask uint32, sid *windows.SID) ([]byte, error) {
	acl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{{
		AccessPermissions: windows.ACCESS_MASK(mask), AccessMode: mode, Inheritance: windows.NO_INHERITANCE,
		Trustee: windows.TRUSTEE{TrusteeForm: windows.TRUSTEE_IS_SID, TrusteeType: windows.TRUSTEE_IS_WELL_KNOWN_GROUP,
			TrusteeValue: windows.TrusteeValueFromSID(sid)},
	}}, nil)
	if err != nil {
		return nil, err
	}
	var out []byte
	err = eachACE(acl, func(_ *windows.ACCESS_ALLOWED_ACE, _ *windows.SID, raw []byte) { out = append(out, raw...) })
	runtime.KeepAlive(acl)
	if err != nil || acl.AceCount != 1 {
		return nil, errKeyACL
	}
	return out, nil
}

// editKeyDACL rewrites a key's DACL: the ACEs drop selects are left out, add (one ACE's bytes) is
// appended after the rest. Nothing is written when nothing changes. The descriptor keeps its control
// bits (a protected DACL stays protected) through ToAbsolute.
func editKeyDACL(key windows.Handle, drop func(*windows.ACCESS_ALLOWED_ACE, *windows.SID) bool, add []byte) error {
	sd, keep, err := keyDACL(key)
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		return errNoKeyDACL // a missing or NULL DACL is never rewritten
	}
	// unsafe: the ACL header's first byte is its revision.
	revision := *(*byte)(unsafe.Pointer(dacl))
	var aces []byte
	count, dropped := 0, false
	err = eachACE(dacl, func(a *windows.ACCESS_ALLOWED_ACE, sid *windows.SID, raw []byte) {
		if drop != nil && sid != nil && drop(a, sid) {
			dropped = true
			return
		}
		aces = append(aces, raw...)
		count++
	})
	if err != nil {
		return err
	}
	if add != nil {
		aces = append(aces, add...)
		count++
	}
	if !dropped && add == nil {
		runtime.KeepAlive(keep)
		return nil
	}
	size := 8 + len(aces)
	if size > 0xffff || count > maxACEs {
		return errKeyACL
	}
	buf := make([]uint64, (size+7)/8) // DWORD-aligned, as an ACL must be
	// unsafe: a byte view of buf, which outlives every use of the ACL below.
	b := unsafe.Slice((*byte)(unsafe.Pointer(&buf[0])), size)
	b[0] = max(revision, aclRevision)
	binary.LittleEndian.PutUint16(b[2:], uint16(size))  //nolint:gosec // G115: size <= 0xffff
	binary.LittleEndian.PutUint16(b[4:], uint16(count)) //nolint:gosec // G115: count <= maxACEs
	copy(b[8:], aces)
	abs, err := sd.ToAbsolute()
	runtime.KeepAlive(keep)
	if err != nil {
		return errKeyACL
	}
	// unsafe: buf is the new ACL; abs and its self-relative copy are used while buf is alive.
	if err := abs.SetDACL((*windows.ACL)(unsafe.Pointer(&buf[0])), true, false); err != nil {
		return errKeyACL
	}
	rel, err := abs.ToSelfRelative()
	runtime.KeepAlive(buf)
	if err != nil {
		return errKeyACL
	}
	return setKeySecurity(key, rel)
}

// setKeySecurity writes a self-relative descriptor's DACL to a key (NCRYPT_SECURITY_DESCR_PROPERTY with
// DACL_SECURITY_INFORMATION).
func setKeySecurity(key windows.Handle, sd *windows.SECURITY_DESCRIPTOR) error {
	if procNCryptSetProperty.Find() != nil {
		return errKeyACL
	}
	name, err := windows.UTF16PtrFromString(ncryptSecurityDescrProp)
	if err != nil {
		return errKeyACL
	}
	// unsafe: name and sd are alive for the call; the result is a SECURITY_STATUS, 0 on success.
	r, _, _ := procNCryptSetProperty.Call(uintptr(key), uintptr(unsafe.Pointer(name)), uintptr(unsafe.Pointer(sd)),
		uintptr(sd.Length()), daclSecurityInformation)
	runtime.KeepAlive(sd)
	if r != 0 {
		return fmt.Errorf("%w: 0x%08x", errKeyACL, uint32(r)) //nolint:gosec // G115: a status
	}
	return nil
}
