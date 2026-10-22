//go:build windows

package main

// Machine certificate stores and the CNG facts of a certificate's private key (design 2026-10-21 §6.2
// step 2). x/sys binds the store and chain calls; the property reads, CryptAcquireCertificatePrivateKey
// (x/sys declares its 4-byte BOOL out-parameter as *bool, W0) and ncrypt.dll are bound here.
//
//	https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certgetcertificatecontextproperty
//	https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptacquirecertificateprivatekey
//	https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/ns-wincrypt-crypt_key_prov_info
//	https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptgetproperty
//	https://learn.microsoft.com/en-us/windows/win32/seccng/key-storage-property-identifiers

import (
	"bytes"
	"crypto/sha1" //nolint:gosec // G505: the store's thumbprint is SHA-1; it names a certificate, it secures nothing
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"runtime"
	"syscall"
	"time"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"

	"alice/internal/providers/windows/winproto"
)

var (
	modcrypt32                            = windows.NewLazySystemDLL("crypt32.dll")
	procCertGetCertificateContextProperty = modcrypt32.NewProc("CertGetCertificateContextProperty")
	procCryptAcquireCertificatePrivateKey = modcrypt32.NewProc("CryptAcquireCertificatePrivateKey")
	modncrypt                             = windows.NewLazySystemDLL("ncrypt.dll")
	procNCryptGetProperty                 = modncrypt.NewProc("NCryptGetProperty")
	procNCryptFreeObject                  = modncrypt.NewProc("NCryptFreeObject")
)

const (
	encodingAny = windows.X509_ASN_ENCODING | windows.PKCS_7_ASN_ENCODING

	certKeyProvInfoPropID  = 2  // CERT_KEY_PROV_INFO_PROP_ID
	certFriendlyNamePropID = 11 // CERT_FRIENDLY_NAME_PROP_ID

	// hcceLocalMachine is HCCE_LOCAL_MACHINE, the machine chain engine.
	hcceLocalMachine = windows.Handle(1)
	// certChainCacheOnlyURLRetrieval is CERT_CHAIN_CACHE_ONLY_URL_RETRIEVAL: the chain is built from the
	// machine's stores and caches, never fetched over the network within the helper's budget.
	certChainCacheOnlyURLRetrieval = 0x80000000

	ncryptExportPolicyProperty = "Export Policy"  // NCRYPT_EXPORT_POLICY_PROPERTY
	ncryptSecurityDescrProp    = "Security Descr" // NCRYPT_SECURITY_DESCR_PROPERTY
	ncryptAllowExportFlags     = 0x1 | 0x2        // NCRYPT_ALLOW_EXPORT_FLAG | NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG
	daclSecurityInformation    = 0x4              // DACL_SECURITY_INFORMATION

	// fileReadData is FILE_READ_DATA: CNG key files take file rights (W0 read 0xd01f01ff for SYSTEM).
	fileReadData = 0x1
	keyReadMask  = windows.GENERIC_READ | windows.GENERIC_ALL | fileReadData

	maxPropertyBytes = 64 << 10 // a property or security descriptor larger than this is not read
	maxACEs          = 1024
	maxStoreEnum     = 100000 // certificates a store count visits at most
)

var (
	errStore     = errors.New("a certificate store call failed")
	errNoKeyInfo = errors.New("the certificate has no key provider information")
)

// hresult reports whether err is the Win32 or HRESULT code.
func hresult(err error, codes ...uint32) bool {
	var en syscall.Errno
	if !errors.As(err, &en) {
		return false
	}
	for _, c := range codes {
		if uint32(en) == c {
			return true
		}
	}
	return false
}

const (
	codeFileNotFound   = uint32(windows.ERROR_FILE_NOT_FOUND)
	codeHRFileNotFound = 0x80070002
	codeCryptNotFound  = uint32(windows.CRYPT_E_NOT_FOUND)
	codeNoMoreFiles    = uint32(windows.ERROR_NO_MORE_FILES)
	codeNoKeyProperty  = uint32(windows.CRYPT_E_NO_KEY_PROPERTY)
	codeBadKeyset      = uint32(windows.NTE_BAD_KEYSET)
	codeNoKey          = uint32(windows.NTE_NO_KEY)
	codeNteNotFound    = uint32(windows.NTE_NOT_FOUND)
	codeAccessDenied   = uint32(windows.ERROR_ACCESS_DENIED)
	codeHRAccessDenied = uint32(windows.E_ACCESSDENIED)
	codeNtePerm        = uint32(windows.NTE_PERM)
)

// openExistingStore opens a machine store; found is false when the store does not exist.
func openExistingStore(name string) (h windows.Handle, found bool, err error) {
	h, err = openStore(name)
	if err != nil {
		if hresult(err, codeFileNotFound, codeHRFileNotFound) {
			return 0, false, nil
		}
		return 0, false, err
	}
	return h, true, nil
}

// certificate reads the certificate with this SHA-1 from the machine store: its DER and SHA-256, the
// friendly name, the expiry, the chain the machine builds for it and the facts of its private key.
// found is false when the store or the certificate does not exist.
func certificate(store, sha1Hex string, now time.Time) (winproto.StoreCertificate, bool, error) {
	hash, err := hex.DecodeString(sha1Hex)
	if err != nil || len(hash) != sha1.Size {
		return winproto.StoreCertificate{}, false, errBadValue
	}
	h, found, err := openExistingStore(store)
	if err != nil || !found {
		return winproto.StoreCertificate{}, false, err
	}
	defer func() { _ = windows.CertCloseStore(h, 0) }()
	blob := windows.CryptHashBlob{Size: sha1.Size, Data: &hash[0]}
	// unsafe: the hash blob is CertFindCertificateInStore's pvFindPara, alive for the call.
	ctx, err := windows.CertFindCertificateInStore(h, encodingAny, 0, windows.CERT_FIND_SHA1_HASH, unsafe.Pointer(&blob), nil)
	runtime.KeepAlive(hash)
	if ctx == nil {
		if hresult(err, codeCryptNotFound) {
			return winproto.StoreCertificate{}, false, nil
		}
		return winproto.StoreCertificate{}, false, errStore
	}
	defer func() { _ = windows.CertFreeCertificateContext(ctx) }()

	der := contextDER(ctx)
	if len(der) == 0 || ctx.CertInfo == nil {
		return winproto.StoreCertificate{}, false, errBadValue
	}
	if sum := sha1.Sum(der); !bytes.Equal(sum[:], hash) { //nolint:gosec // G401: the thumbprint, see the import
		return winproto.StoreCertificate{}, false, errBadValue
	}
	sum := sha256.Sum256(der)
	friendly, err := friendlyName(ctx)
	if err != nil {
		return winproto.StoreCertificate{}, false, err
	}
	chain, err := machineChain(ctx, now)
	if err != nil {
		return winproto.StoreCertificate{}, false, err
	}
	c := winproto.StoreCertificate{Store: store, SHA1: sha1Hex, SHA256: hex.EncodeToString(sum[:]),
		DER: base64.StdEncoding.EncodeToString(der), Chain: chain, FriendlyName: friendly,
		NotAfter: filetime(ctx.CertInfo.NotAfter).Format(time.RFC3339)}
	if err := keyFacts(ctx, &c); err != nil {
		return winproto.StoreCertificate{}, false, err
	}
	return c, true, nil
}

// contextDER copies a certificate context's encoded certificate.
func contextDER(ctx *windows.CertContext) []byte {
	if ctx.EncodedCert == nil || ctx.Length == 0 || ctx.Length > winproto.MaxCertDER {
		return nil
	}
	// unsafe: EncodedCert points to Length bytes owned by the context, copied before it is freed.
	return bytes.Clone(unsafe.Slice(ctx.EncodedCert, ctx.Length))
}

// filetime converts a FILETIME to UTC.
func filetime(ft windows.Filetime) time.Time { return time.Unix(0, ft.Nanoseconds()).UTC() }

// contextProperty reads one property of a certificate context; found is false when it is not set.
// The buffer is a []uint64, so a structure at its start is aligned.
func contextProperty(ctx *windows.CertContext, id uint32) (buf []uint64, n uint32, found bool, err error) {
	if err := procCertGetCertificateContextProperty.Find(); err != nil {
		return nil, 0, false, errStore
	}
	// unsafe: ctx and &n are alive for the call (LazyProc.Call keeps them).
	r, _, e := procCertGetCertificateContextProperty.Call(uintptr(unsafe.Pointer(ctx)), uintptr(id), 0,
		uintptr(unsafe.Pointer(&n)))
	if r == 0 {
		if hresult(e, codeCryptNotFound) {
			return nil, 0, false, nil
		}
		return nil, 0, false, errStore
	}
	if n == 0 || n > maxPropertyBytes {
		return nil, 0, false, errBadValue
	}
	buf = make([]uint64, (n+7)/8)
	// unsafe: buf holds n bytes and is alive for the call.
	r, _, _ = procCertGetCertificateContextProperty.Call(uintptr(unsafe.Pointer(ctx)), uintptr(id),
		uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&n)))
	if r == 0 || n == 0 || int(n) > len(buf)*8 {
		return nil, 0, false, errStore
	}
	return buf, n, true, nil
}

// utf16Units reads a NUL-terminated UTF-16 string from the first n bytes of buf.
func utf16Units(buf []uint64, n uint32) string {
	// unsafe: a uint16 view of buf's own first n bytes.
	u := unsafe.Slice((*uint16)(unsafe.Pointer(&buf[0])), n/2)
	if i := indexZero(u); i >= 0 {
		u = u[:i]
	}
	return string(utf16.Decode(u))
}

// friendlyName is CERT_FRIENDLY_NAME_PROP_ID, "" when it is not set.
func friendlyName(ctx *windows.CertContext) (string, error) {
	buf, n, found, err := contextProperty(ctx, certFriendlyNamePropID)
	if err != nil || !found {
		return "", err
	}
	return utf16Units(buf, n), nil
}

// machineChain is the chain the machine chain engine builds for the certificate: the elements of the
// first simple chain after the leaf, without a self-signed last element (design §6.2; schannel serves
// the same chain, W0 F5). At most MaxChainCerts+1 are returned, so winhelper sees an overlong chain.
func machineChain(ctx *windows.CertContext, now time.Time) ([]string, error) {
	para := windows.CertChainPara{Size: uint32(unsafe.Sizeof(windows.CertChainPara{}))}
	at := windows.NsecToFiletime(now.UnixNano())
	var chain *windows.CertChainContext
	if err := windows.CertGetCertificateChain(hcceLocalMachine, ctx, &at, 0, &para, certChainCacheOnlyURLRetrieval, 0,
		&chain); err != nil || chain == nil {
		return nil, errStore
	}
	defer windows.CertFreeCertificateChain(chain)
	out := []string{}
	if chain.ChainCount == 0 || chain.Chains == nil {
		return out, nil
	}
	// unsafe: Chains points to ChainCount simple chains and Elements to NumElements elements, owned by
	// the chain context until it is freed; only the first chain is read.
	simple := *chain.Chains
	if simple == nil || simple.Elements == nil {
		return out, nil
	}
	elements := unsafe.Slice(simple.Elements, simple.NumElements)
	for i := 1; i < len(elements) && len(out) <= winproto.MaxChainCerts; i++ {
		el := elements[i]
		if el == nil || el.CertContext == nil {
			return nil, errStore
		}
		if i == len(elements)-1 && el.TrustStatus.InfoStatus&windows.CERT_TRUST_IS_SELF_SIGNED != 0 {
			break // the root
		}
		der := contextDER(el.CertContext)
		if der == nil {
			return nil, errBadValue
		}
		out = append(out, base64.StdEncoding.EncodeToString(der))
	}
	return out, nil
}

// cryptKeyProvInfo is CRYPT_KEY_PROV_INFO (pointer fields as uintptr; only the provider name is read).
type cryptKeyProvInfo struct {
	ContainerName uintptr
	ProvName      uintptr
	ProvType      uint32
	Flags         uint32
	ProvParamN    uint32
	ProvParam     uintptr
	KeySpec       uint32
}

// keyProvider reads the key provider name of CERT_KEY_PROV_INFO_PROP_ID; errNoKeyInfo when the
// certificate has none (no private key associated).
func keyProvider(ctx *windows.CertContext) (string, error) {
	buf, n, found, err := contextProperty(ctx, certKeyProvInfoPropID)
	if err != nil {
		return "", err
	}
	if !found {
		return "", errNoKeyInfo
	}
	if uintptr(n) < unsafe.Sizeof(cryptKeyProvInfo{}) {
		return "", errBadValue
	}
	// unsafe: buf holds the property's CRYPT_KEY_PROV_INFO at its start (aligned); its strings point
	// into the same n bytes and are read as offsets from it, never as Go pointers.
	info := (*cryptKeyProvInfo)(unsafe.Pointer(&buf[0]))
	rec := unsafe.Slice((*byte)(unsafe.Pointer(&buf[0])), n)
	name, ok := stringAt(rec, info.ProvName)
	if !ok {
		return "", errBadValue
	}
	return name, nil
}

// keyFacts fills the key facts of c: has_key, the provider, exportability and whether SYSTEM (which
// http.sys uses the key as) may read it. A key that does not exist is key_missing; a key whose DACL
// grants SYSTEM no read access is key_inaccessible; what cannot be decided stays nil (never guessed).
func keyFacts(ctx *windows.CertContext, c *winproto.StoreCertificate) error {
	provider, err := keyProvider(ctx)
	if errors.Is(err, errNoKeyInfo) {
		c.KeyProblem = "key_missing"
		return nil
	}
	if err != nil {
		return err
	}
	c.KeyProvider = provider
	if err := procCryptAcquireCertificatePrivateKey.Find(); err != nil {
		return errStore
	}
	var key windows.Handle
	var spec, callerFree uint32 // callerFree is the API's 4-byte BOOL
	// unsafe: ctx and the three out-parameters are alive for the call.
	r, _, e := procCryptAcquireCertificatePrivateKey.Call(uintptr(unsafe.Pointer(ctx)),
		windows.CRYPT_ACQUIRE_SILENT_FLAG|windows.CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG|windows.CRYPT_ACQUIRE_CACHE_FLAG, 0,
		uintptr(unsafe.Pointer(&key)), uintptr(unsafe.Pointer(&spec)), uintptr(unsafe.Pointer(&callerFree)))
	if r == 0 {
		switch {
		case hresult(e, codeNoKeyProperty, codeBadKeyset, codeNoKey, codeNteNotFound, codeFileNotFound, codeHRFileNotFound):
			c.KeyProblem = "key_missing" // the certificate names a key that is not there
		case hresult(e, codeAccessDenied, codeHRAccessDenied, codeNtePerm):
			c.HasKey = true // there is a key the elevated helper may not open; SYSTEM's access is unknown
		default:
			c.HasKey = true // e.g. a legacy CSP key CNG does not open: the facts stay unknown
		}
		return nil
	}
	if callerFree != 0 {
		defer func() { _, _, _ = procNCryptFreeObject.Call(uintptr(key)) }()
	}
	c.HasKey = true
	if policy, ok := keyExportPolicy(key); ok {
		c.KeyExportable = policy&ncryptAllowExportFlags != 0
	}
	c.KeyUsableBySystem = systemCanRead(key)
	if c.KeyUsableBySystem != nil && !*c.KeyUsableBySystem {
		c.KeyProblem = "key_inaccessible"
	}
	return nil
}

// ncryptProperty reads one property of a CNG object into an aligned buffer.
func ncryptProperty(h windows.Handle, name string, flags uint32) ([]uint64, uint32, bool) {
	if procNCryptGetProperty.Find() != nil || procNCryptFreeObject.Find() != nil {
		return nil, 0, false
	}
	p, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return nil, 0, false
	}
	var n uint32
	// unsafe: p and &n are alive for the call; the result is a SECURITY_STATUS, 0 on success.
	r, _, _ := procNCryptGetProperty.Call(uintptr(h), uintptr(unsafe.Pointer(p)), 0, 0, uintptr(unsafe.Pointer(&n)),
		uintptr(flags))
	if r != 0 || n == 0 || n > maxPropertyBytes {
		return nil, 0, false
	}
	buf := make([]uint64, (n+7)/8)
	size := n
	// unsafe: buf holds size bytes and is alive for the call.
	r, _, _ = procNCryptGetProperty.Call(uintptr(h), uintptr(unsafe.Pointer(p)), uintptr(unsafe.Pointer(&buf[0])),
		uintptr(size), uintptr(unsafe.Pointer(&n)), uintptr(flags))
	if r != 0 || n == 0 || n > size {
		return nil, 0, false
	}
	return buf, n, true
}

// keyExportPolicy is NCRYPT_EXPORT_POLICY_PROPERTY (a DWORD).
func keyExportPolicy(key windows.Handle) (uint32, bool) {
	buf, n, ok := ncryptProperty(key, ncryptExportPolicyProperty, 0)
	if !ok || n < 4 {
		return 0, false
	}
	// unsafe: a byte view of the first 4 of the n bytes buf holds.
	return binary.LittleEndian.Uint32(unsafe.Slice((*byte)(unsafe.Pointer(&buf[0])), 4)), true
}

// systemCanRead decides from the key's DACL (NCRYPT_SECURITY_DESCR_PROPERTY) whether LocalSystem may
// read the key: the first ACE that applies to the key itself, names a SID in SYSTEM's token (SYSTEM,
// Administrators, Everyone, Authenticated Users) and covers read access decides; an allow grants, a
// deny refuses; no such ACE refuses; a NULL DACL grants. nil when the descriptor cannot be read.
func systemCanRead(key windows.Handle) *bool {
	yes, no := true, false
	buf, n, ok := ncryptProperty(key, ncryptSecurityDescrProp, daclSecurityInformation)
	if !ok || uintptr(n) < unsafe.Sizeof(windows.SECURITY_DESCRIPTOR{}) {
		return nil
	}
	// unsafe: buf holds the self-relative descriptor NCryptGetProperty wrote; the ACL and ACEs it points
	// to lie inside it and are read through the Windows calls.
	sd := (*windows.SECURITY_DESCRIPTOR)(unsafe.Pointer(&buf[0]))
	if !sd.IsValid() {
		return nil
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return nil
	}
	if dacl == nil {
		return &yes // a NULL DACL grants everyone every access
	}
	sids := make([]*windows.SID, 0, 4)
	for _, w := range []windows.WELL_KNOWN_SID_TYPE{windows.WinLocalSystemSid, windows.WinBuiltinAdministratorsSid,
		windows.WinWorldSid, windows.WinAuthenticatedUserSid} {
		s, err := windows.CreateWellKnownSid(w)
		if err != nil {
			return nil
		}
		sids = append(sids, s)
	}
	for i := 0; i < int(dacl.AceCount) && i < maxACEs; i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, uint32(i), &ace); err != nil || ace == nil { //nolint:gosec // G115: i < maxACEs
			return nil
		}
		if ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 || uint32(ace.Mask)&keyReadMask == 0 {
			continue
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE && ace.Header.AceType != windows.ACCESS_DENIED_ACE_TYPE {
			continue // object and callback ACEs have another layout
		}
		// unsafe: an allowed or denied ACE's SID starts at SidStart, inside the ACE.
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		applies := false
		for _, s := range sids {
			applies = applies || windows.EqualSid(sid, s)
		}
		if !applies {
			continue
		}
		if ace.Header.AceType == windows.ACCESS_ALLOWED_ACE_TYPE {
			return &yes
		}
		return &no
	}
	runtime.KeepAlive(buf)
	return &no
}

// expiredInStore counts the certificates of a machine store whose NotAfter is before now (0 for a
// store that does not exist), visiting at most maxStoreEnum certificates.
func expiredInStore(store string, now time.Time) (int, error) {
	h, found, err := openExistingStore(store)
	if err != nil || !found {
		return 0, err
	}
	defer func() { _ = windows.CertCloseStore(h, 0) }()
	count := 0
	var prev *windows.CertContext
	for range maxStoreEnum {
		// CertEnumCertificatesInStore frees prev.
		ctx, err := windows.CertEnumCertificatesInStore(h, prev)
		if ctx == nil {
			if hresult(err, codeCryptNotFound, codeNoMoreFiles) {
				return count, nil
			}
			return 0, errStore
		}
		prev = ctx
		if ctx.CertInfo != nil && filetime(ctx.CertInfo.NotAfter).Before(now) {
			count++
		}
	}
	_ = windows.CertFreeCertificateContext(prev)
	return count, nil
}
