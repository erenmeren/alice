//go:build windows

package main

// Certificate store and CNG key helpers. golang.org/x/sys/windows binds most of crypt32; the property calls and
// ncrypt.dll are bound here. Sources:
//
//	https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certgetcertificatecontextproperty
//	https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certsetcertificatecontextproperty
//	https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/ns-wincrypt-crypt_key_prov_info
//	https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-pfximportcertstore
//	https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptimportkey
//	https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptgetproperty
//	https://learn.microsoft.com/en-us/windows/win32/seccng/key-storage-property-identifiers

import (
	"crypto/sha1" //nolint:gosec // the store's thumbprint is SHA-1
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modcrypt32                             = windows.NewLazySystemDLL("crypt32.dll")
	procCertGetCertificateContextProperty  = modcrypt32.NewProc("CertGetCertificateContextProperty")
	procCertSetCertificateContextProperty  = modcrypt32.NewProc("CertSetCertificateContextProperty")
	procCertAddEncodedCertificateToStore   = modcrypt32.NewProc("CertAddEncodedCertificateToStore")
	procCryptAcquireCertificatePrivateKey  = modcrypt32.NewProc("CryptAcquireCertificatePrivateKey")
	modncrypt                              = windows.NewLazySystemDLL("ncrypt.dll")
	procNCryptOpenStorageProvider          = modncrypt.NewProc("NCryptOpenStorageProvider")
	procNCryptImportKey                    = modncrypt.NewProc("NCryptImportKey")
	procNCryptOpenKey                      = modncrypt.NewProc("NCryptOpenKey")
	procNCryptSetProperty                  = modncrypt.NewProc("NCryptSetProperty")
	procNCryptGetProperty                  = modncrypt.NewProc("NCryptGetProperty")
	procNCryptFinalizeKey                  = modncrypt.NewProc("NCryptFinalizeKey")
	procNCryptExportKey                    = modncrypt.NewProc("NCryptExportKey")
	procNCryptDeleteKey                    = modncrypt.NewProc("NCryptDeleteKey")
	procNCryptFreeObject                   = modncrypt.NewProc("NCryptFreeObject")
)

const (
	encodingAny = windows.X509_ASN_ENCODING | windows.PKCS_7_ASN_ENCODING

	certKeyProvInfoPropID  = 2  // CERT_KEY_PROV_INFO_PROP_ID
	certFriendlyNamePropID = 11 // CERT_FRIENDLY_NAME_PROP_ID

	// PFXImportCertStore flags (wincrypt.h)
	pkcs12PreferCngKsp = 0x00000100

	// ncrypt.h
	msKSP                   = "Microsoft Software Key Storage Provider"
	ncryptMachineKeyFlag    = 0x00000020
	ncryptOverwriteKeyFlag  = 0x00000080
	ncryptDoNotFinalizeFlag = 0x00000400
	ncryptSilentFlag        = 0x00000040
	ncryptPersistFlag       = 0x80000000
	ncryptbufferPkcsKeyName = 45 // NCRYPTBUFFER_PKCS_KEY_NAME
	pkcs8BlobType           = "PKCS8_PRIVATEKEY"
	ncryptExportPolicyProp  = "Export Policy"
	ncryptSecurityDescrProp = "Security Descr"
	ncryptUniqueNameProp    = "Unique Name"
	ncryptAlgorithmGroup    = "Algorithm Group"

	daclSecurityInformation  = 0x4
	ownerSecurityInformation = 0x1
)

// cryptKeyProvInfo is CRYPT_KEY_PROV_INFO (48 bytes on amd64).
type cryptKeyProvInfo struct {
	ContainerName *uint16
	ProvName      *uint16
	ProvType      uint32
	Flags         uint32
	ProvParamN    uint32
	ProvParam     uintptr
	KeySpec       uint32
}

// ncryptBuffer is NCryptBuffer (BCryptBuffer) and ncryptBufferDesc is NCryptBufferDesc.
type ncryptBuffer struct {
	CbBuffer   uint32
	BufferType uint32
	PvBuffer   unsafe.Pointer
}

type ncryptBufferDesc struct {
	Version  uint32
	CBuffers uint32
	PBuffers *ncryptBuffer
}

// ncryptCall calls an ncrypt function; they return SECURITY_STATUS (an HRESULT, 0 on success).
func ncryptCall(p *windows.LazyProc, args ...uintptr) error {
	if err := p.Find(); err != nil {
		return err
	}
	r, _, _ := p.Call(args...)
	if r != 0 {
		return fmt.Errorf("%s: 0x%08x (%s)", p.Name, uint32(r), syscall.Errno(r).Error())
	}
	return nil
}

func lpcwstr(s string) uintptr {
	p, _ := windows.UTF16PtrFromString(s)
	return uintptr(unsafe.Pointer(p))
}

func openStore(name string, readonly bool) (windows.Handle, error) {
	flags := uint32(windows.CERT_SYSTEM_STORE_LOCAL_MACHINE | windows.CERT_STORE_OPEN_EXISTING_FLAG)
	if readonly {
		flags |= windows.CERT_STORE_READONLY_FLAG
	}
	p, _ := windows.UTF16PtrFromString(name)
	h, err := windows.CertOpenStore(windows.CERT_STORE_PROV_SYSTEM, 0, 0, flags, uintptr(unsafe.Pointer(p)))
	if err != nil {
		return 0, fmt.Errorf("CertOpenStore(LocalMachine\\%s, readonly=%v): %w", name, readonly, err)
	}
	return h, nil
}

func closeStore(h windows.Handle)       { _ = windows.CertCloseStore(h, 0) }
func freeCtx(ctx *windows.CertContext) { _ = windows.CertFreeCertificateContext(ctx) }

func findByHash(store windows.Handle, thumb string) (*windows.CertContext, error) {
	h, err := hex.DecodeString(strings.ToLower(thumb))
	if err != nil || len(h) == 0 {
		return nil, fmt.Errorf("bad thumbprint %q", thumb)
	}
	blob := windows.CryptHashBlob{Size: uint32(len(h)), Data: &h[0]}
	ctx, err := windows.CertFindCertificateInStore(store, encodingAny, 0, windows.CERT_FIND_SHA1_HASH,
		unsafe.Pointer(&blob), nil)
	runtime.KeepAlive(h)
	if err != nil {
		return nil, fmt.Errorf("certificate %s not found: %w", thumb, err)
	}
	return ctx, nil
}

func certDER(ctx *windows.CertContext) []byte {
	return append([]byte(nil), unsafe.Slice(ctx.EncodedCert, ctx.Length)...)
}

func thumbOf(der []byte) string {
	s := sha1.Sum(der) //nolint:gosec // thumbprint
	return hex.EncodeToString(s[:])
}

func sha256Of(der []byte) string {
	s := sha256.Sum256(der)
	return hex.EncodeToString(s[:])
}

func getProp(ctx *windows.CertContext, id uint32) ([]byte, error) {
	var n uint32
	r, _, e := procCertGetCertificateContextProperty.Call(uintptr(unsafe.Pointer(ctx)), uintptr(id), 0,
		uintptr(unsafe.Pointer(&n)))
	if r == 0 {
		return nil, e
	}
	buf := make([]uint64, (n+7)/8+1)
	r, _, e = procCertGetCertificateContextProperty.Call(uintptr(unsafe.Pointer(ctx)), uintptr(id),
		uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&n)))
	if r == 0 {
		return nil, e
	}
	return unsafe.Slice((*byte)(unsafe.Pointer(&buf[0])), len(buf)*8), nil
}

func setProp(ctx *windows.CertContext, id uint32, data unsafe.Pointer) error {
	r, _, e := procCertSetCertificateContextProperty.Call(uintptr(unsafe.Pointer(ctx)), uintptr(id), 0,
		uintptr(data))
	if r == 0 {
		return e
	}
	return nil
}

func setFriendlyName(ctx *windows.CertContext, name string) error {
	u, _ := windows.UTF16FromString(name)
	blob := windows.CryptDataBlob{Size: uint32(len(u) * 2), Data: (*byte)(unsafe.Pointer(&u[0]))}
	err := setProp(ctx, certFriendlyNamePropID, unsafe.Pointer(&blob))
	runtime.KeepAlive(u)
	return err
}

func friendlyName(ctx *windows.CertContext) string {
	b, err := getProp(ctx, certFriendlyNamePropID)
	if err != nil {
		return ""
	}
	return windows.UTF16PtrToString((*uint16)(unsafe.Pointer(&b[0])))
}

// KeyFacts is what §6.2 step 2 wants to know about a certificate's private key.
type KeyFacts struct {
	HasKeyProvInfo   bool     `json:"has_key_prov_info"`
	Container        string   `json:"container,omitempty"`
	Provider         string   `json:"provider,omitempty"`
	ProvType         uint32   `json:"prov_type"`
	ProvFlags        uint32   `json:"prov_flags"`
	MachineKeyset    bool     `json:"machine_keyset"`
	KeySpec          uint32   `json:"key_spec"`
	AcquireError     string   `json:"acquire_error,omitempty"`
	IsNCrypt         bool     `json:"is_ncrypt"`
	UniqueName       string   `json:"unique_name,omitempty"`
	AlgorithmGroup   string   `json:"algorithm_group,omitempty"`
	ExportPolicy     *uint32  `json:"export_policy,omitempty"`
	ExportPolicyErr  string   `json:"export_policy_error,omitempty"`
	Exportable       bool     `json:"exportable"`
	ExportAttempt    string   `json:"export_attempt,omitempty"`
	SDDL             string   `json:"sddl,omitempty"`
	SDDLError        string   `json:"sddl_error,omitempty"`
	SystemCanRead    bool     `json:"system_can_read"`
	ACEs             []string `json:"aces,omitempty"`
}

// acquireKey opens the certificate's private key as an NCRYPT_KEY_HANDLE (CNG only). Bound here rather than
// through x/sys, whose binding declares pfCallerFreeProvOrNCryptKey as *bool while the API writes a 4-byte BOOL.
func acquireKey(ctx *windows.CertContext) (windows.Handle, bool, error) {
	var h windows.Handle
	var spec, free uint32
	r, _, e := procCryptAcquireCertificatePrivateKey.Call(uintptr(unsafe.Pointer(ctx)),
		windows.CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG|windows.CRYPT_ACQUIRE_SILENT_FLAG, 0,
		uintptr(unsafe.Pointer(&h)), uintptr(unsafe.Pointer(&spec)), uintptr(unsafe.Pointer(&free)))
	if r == 0 {
		return 0, false, fmt.Errorf("CryptAcquireCertificatePrivateKey: %w", e)
	}
	return h, free != 0, nil
}

func ncryptGetBytes(h windows.Handle, prop string, flags uint32) ([]byte, error) {
	var n uint32
	if err := ncryptCall(procNCryptGetProperty, uintptr(h), lpcwstr(prop), 0, 0, uintptr(unsafe.Pointer(&n)),
		uintptr(flags)); err != nil {
		return nil, err
	}
	buf := make([]uint64, (n+7)/8+1)
	if err := ncryptCall(procNCryptGetProperty, uintptr(h), lpcwstr(prop), uintptr(unsafe.Pointer(&buf[0])),
		uintptr(n), uintptr(unsafe.Pointer(&n)), uintptr(flags)); err != nil {
		return nil, err
	}
	return unsafe.Slice((*byte)(unsafe.Pointer(&buf[0])), n), nil
}

func ncryptGetString(h windows.Handle, prop string) string {
	b, err := ncryptGetBytes(h, prop, 0)
	if err != nil || len(b) < 2 {
		return ""
	}
	return windows.UTF16PtrToString((*uint16)(unsafe.Pointer(&b[0])))
}

func keyFacts(ctx *windows.CertContext) KeyFacts {
	var f KeyFacts
	if b, err := getProp(ctx, certKeyProvInfoPropID); err == nil {
		pi := (*cryptKeyProvInfo)(unsafe.Pointer(&b[0]))
		f.HasKeyProvInfo = true
		f.Container = goString(pi.ContainerName)
		f.Provider = goString(pi.ProvName)
		f.ProvType = pi.ProvType
		f.ProvFlags = pi.Flags
		f.MachineKeyset = pi.Flags&windows.CRYPT_MACHINE_KEYSET != 0
		f.KeySpec = pi.KeySpec
	}
	h, free, err := acquireKey(ctx)
	if err != nil {
		f.AcquireError = errString(err)
		return f
	}
	if free {
		defer procNCryptFreeObject.Call(uintptr(h)) //nolint:errcheck // spike
	}
	f.IsNCrypt = true
	f.UniqueName = ncryptGetString(h, ncryptUniqueNameProp)
	f.AlgorithmGroup = ncryptGetString(h, ncryptAlgorithmGroup)
	if b, err := ncryptGetBytes(h, ncryptExportPolicyProp, 0); err == nil && len(b) >= 4 {
		v := *(*uint32)(unsafe.Pointer(&b[0]))
		f.ExportPolicy = &v
		f.Exportable = v&0x3 != 0 // NCRYPT_ALLOW_EXPORT_FLAG | NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG
	} else if err != nil {
		f.ExportPolicyErr = errString(err)
	}
	// Try a plaintext PKCS #8 export: a non-exportable key must refuse it.
	var n uint32
	if err := ncryptCall(procNCryptExportKey, uintptr(h), 0, lpcwstr(pkcs8BlobType), 0, 0, 0,
		uintptr(unsafe.Pointer(&n)), 0); err != nil {
		f.ExportAttempt = "refused: " + errString(err)
	} else {
		f.ExportAttempt = fmt.Sprintf("allowed (%d bytes)", n)
	}
	if b, err := ncryptGetBytes(h, ncryptSecurityDescrProp, daclSecurityInformation|ownerSecurityInformation); err == nil {
		sd := (*windows.SECURITY_DESCRIPTOR)(unsafe.Pointer(&b[0]))
		f.SDDL = sd.String()
		f.SystemCanRead = strings.Contains(f.SDDL, ";;;SY)")
		for _, part := range strings.Split(f.SDDL, "(")[1:] {
			f.ACEs = append(f.ACEs, "("+part)
		}
	} else {
		f.SDDLError = errString(err)
	}
	return f
}

// CertFacts describes one certificate in a store.
type CertFacts struct {
	Store        string   `json:"store"`
	Thumbprint   string   `json:"thumbprint"`
	SHA256       string   `json:"sha256"`
	Subject      string   `json:"subject,omitempty"`
	FriendlyName string   `json:"friendly_name,omitempty"`
	Key          KeyFacts `json:"key"`
}

func certFacts(store string, ctx *windows.CertContext) CertFacts {
	der := certDER(ctx)
	cf := CertFacts{Store: store, Thumbprint: thumbOf(der), SHA256: sha256Of(der), FriendlyName: friendlyName(ctx)}
	if c, err := parseCert(der); err == nil {
		cf.Subject = c.Subject.String()
	}
	cf.Key = keyFacts(ctx)
	return cf
}

// addEncoded adds a DER certificate (no key) to a LocalMachine store, never replacing one (§6.3 step 5).
func addEncoded(store string, der []byte) (string, error) {
	h, err := openStore(store, false)
	if err != nil {
		return "", err
	}
	defer windows.CertCloseStore(h, 0) //nolint:errcheck // spike
	r, _, e := procCertAddEncodedCertificateToStore.Call(uintptr(h), encodingAny, uintptr(unsafe.Pointer(&der[0])),
		uintptr(len(der)), windows.CERT_STORE_ADD_USE_EXISTING, 0)
	runtime.KeepAlive(der)
	if r == 0 {
		return "", fmt.Errorf("CertAddEncodedCertificateToStore(%s): %w", store, e)
	}
	return thumbOf(der), nil
}

// deleteCert removes a certificate from a LocalMachine store; with key it also deletes the CNG key (§6.7).
func deleteCert(store, thumb string, withKey bool) map[string]any {
	out := map[string]any{"store": store, "thumbprint": thumb}
	h, err := openStore(store, false)
	if err != nil {
		out["error"] = errString(err)
		return out
	}
	defer windows.CertCloseStore(h, 0) //nolint:errcheck // spike
	ctx, err := findByHash(h, thumb)
	if err != nil {
		out["error"] = errString(err)
		return out
	}
	if withKey {
		kf := keyFacts(ctx)
		out["unique_name"] = kf.UniqueName
		if k, free, err := acquireKey(ctx); err == nil {
			if err := ncryptCall(procNCryptDeleteKey, uintptr(k), 0); err != nil {
				out["key_delete_error"] = errString(err)
				if free {
					procNCryptFreeObject.Call(uintptr(k)) //nolint:errcheck // spike
				}
			} else {
				out["key_deleted"] = true
			}
		} else {
			out["key_acquire_error"] = errString(err)
		}
		if kf.Container != "" {
			out["key_open_after_delete"] = keyOpenable(kf.Container)
		}
	}
	// CertDeleteCertificateFromStore frees the context.
	if err := windows.CertDeleteCertificateFromStore(ctx); err != nil {
		out["error"] = errString(err)
	} else {
		out["deleted"] = true
	}
	return out
}

// keyOpenable reports whether a machine key of the software KSP still opens by name.
func keyOpenable(name string) string {
	var prov, key windows.Handle
	if err := ncryptCall(procNCryptOpenStorageProvider, uintptr(unsafe.Pointer(&prov)), lpcwstr(msKSP), 0); err != nil {
		return "provider: " + errString(err)
	}
	defer procNCryptFreeObject.Call(uintptr(prov)) //nolint:errcheck // spike
	if err := ncryptCall(procNCryptOpenKey, uintptr(prov), uintptr(unsafe.Pointer(&key)), lpcwstr(name), 0,
		ncryptMachineKeyFlag|ncryptSilentFlag); err != nil {
		return "not openable: " + errString(err)
	}
	procNCryptFreeObject.Call(uintptr(key)) //nolint:errcheck // spike
	return "still openable"
}

// importPFX imports a PKCS #12 blob with PFXImportCertStore and adds every certificate with a key to
// LocalMachine\<store>. It returns the thumbprints of those certificates.
func importPFX(pfx []byte, password string, flags uint32, store, friendly string) ([]string, error) {
	pw, _ := windows.UTF16PtrFromString(password)
	blob := windows.CryptDataBlob{Size: uint32(len(pfx)), Data: &pfx[0]}
	tmp, err := windows.PFXImportCertStore(&blob, pw, flags)
	runtime.KeepAlive(pfx)
	if err != nil {
		return nil, fmt.Errorf("PFXImportCertStore(flags=0x%x): %w", flags, err)
	}
	defer windows.CertCloseStore(tmp, 0) //nolint:errcheck // spike
	dst, err := openStore(store, false)
	if err != nil {
		return nil, err
	}
	defer windows.CertCloseStore(dst, 0) //nolint:errcheck // spike
	var thumbs []string
	var prev *windows.CertContext
	for {
		ctx, err := windows.CertEnumCertificatesInStore(tmp, prev)
		if err != nil {
			break
		}
		prev = ctx
		if _, err := getProp(ctx, certKeyProvInfoPropID); err != nil {
			continue // a chain certificate without a key
		}
		var stored *windows.CertContext
		if err := windows.CertAddCertificateContextToStore(dst, ctx, windows.CERT_STORE_ADD_REPLACE_EXISTING,
			&stored); err != nil {
			return thumbs, fmt.Errorf("CertAddCertificateContextToStore: %w", err)
		}
		if friendly != "" {
			if err := setFriendlyName(stored, friendly); err != nil {
				return thumbs, fmt.Errorf("friendly name: %w", err)
			}
		}
		thumbs = append(thumbs, thumbOf(certDER(stored)))
		windows.CertFreeCertificateContext(stored) //nolint:errcheck // spike
	}
	if len(thumbs) == 0 {
		return nil, errors.New("the PFX held no certificate with a key")
	}
	return thumbs, nil
}

// importPKCS8 is the PFX-free route: NCryptImportKey of a PKCS #8 blob as a named, persisted machine key of the
// software KSP with export policy 0, then the certificate added to the store with CERT_KEY_PROV_INFO_PROP_ID
// pointing at that key (the pattern .NET uses for persisted CNG keys).
func importPKCS8(pkcs8, der []byte, keyName, store, friendly string) (string, error) {
	var prov, key windows.Handle
	if err := ncryptCall(procNCryptOpenStorageProvider, uintptr(unsafe.Pointer(&prov)), lpcwstr(msKSP), 0); err != nil {
		return "", err
	}
	defer procNCryptFreeObject.Call(uintptr(prov)) //nolint:errcheck // spike
	nameU, _ := windows.UTF16FromString(keyName)
	buf := ncryptBuffer{CbBuffer: uint32(len(nameU) * 2), BufferType: ncryptbufferPkcsKeyName,
		PvBuffer: unsafe.Pointer(&nameU[0])}
	desc := ncryptBufferDesc{Version: 0, CBuffers: 1, PBuffers: &buf}
	if err := ncryptCall(procNCryptImportKey, uintptr(prov), 0, lpcwstr(pkcs8BlobType), uintptr(unsafe.Pointer(&desc)),
		uintptr(unsafe.Pointer(&key)), uintptr(unsafe.Pointer(&pkcs8[0])), uintptr(len(pkcs8)),
		ncryptMachineKeyFlag|ncryptDoNotFinalizeFlag|ncryptOverwriteKeyFlag|ncryptSilentFlag); err != nil {
		return "", err
	}
	runtime.KeepAlive(nameU)
	runtime.KeepAlive(pkcs8)
	defer procNCryptFreeObject.Call(uintptr(key)) //nolint:errcheck // spike
	var policy uint32 // not exportable
	if err := ncryptCall(procNCryptSetProperty, uintptr(key), lpcwstr(ncryptExportPolicyProp),
		uintptr(unsafe.Pointer(&policy)), 4, ncryptPersistFlag|ncryptSilentFlag); err != nil {
		return "", err
	}
	if err := ncryptCall(procNCryptFinalizeKey, uintptr(key), ncryptSilentFlag); err != nil {
		return "", err
	}
	dst, err := openStore(store, false)
	if err != nil {
		return "", err
	}
	defer windows.CertCloseStore(dst, 0) //nolint:errcheck // spike
	ctx, err := windows.CertCreateCertificateContext(encodingAny, &der[0], uint32(len(der)))
	if err != nil {
		return "", err
	}
	defer windows.CertFreeCertificateContext(ctx) //nolint:errcheck // spike
	var stored *windows.CertContext
	if err := windows.CertAddCertificateContextToStore(dst, ctx, windows.CERT_STORE_ADD_REPLACE_EXISTING,
		&stored); err != nil {
		return "", err
	}
	defer windows.CertFreeCertificateContext(stored) //nolint:errcheck // spike
	provU, _ := windows.UTF16PtrFromString(msKSP)
	nameP, _ := windows.UTF16PtrFromString(keyName)
	pi := cryptKeyProvInfo{ContainerName: nameP, ProvName: provU, ProvType: 0, Flags: windows.CRYPT_MACHINE_KEYSET,
		KeySpec: 0}
	if err := setProp(stored, certKeyProvInfoPropID, unsafe.Pointer(&pi)); err != nil {
		return "", fmt.Errorf("CERT_KEY_PROV_INFO_PROP_ID: %w", err)
	}
	runtime.KeepAlive(provU)
	runtime.KeepAlive(nameP)
	if friendly != "" {
		if err := setFriendlyName(stored, friendly); err != nil {
			return "", err
		}
	}
	return thumbOf(der), nil
}

// grantSystemRead adds (A;;GR;;;SY) to the key's DACL: the fallback F4 would record if http.sys needed it.
func grantSystemRead(thumb, store string) (string, error) {
	h, err := openStore(store, true)
	if err != nil {
		return "", err
	}
	defer windows.CertCloseStore(h, 0) //nolint:errcheck // spike
	ctx, err := findByHash(h, thumb)
	if err != nil {
		return "", err
	}
	defer windows.CertFreeCertificateContext(ctx) //nolint:errcheck // spike
	k, free, err := acquireKey(ctx)
	if err != nil {
		return "", err
	}
	if free {
		defer procNCryptFreeObject.Call(uintptr(k)) //nolint:errcheck // spike
	}
	b, err := ncryptGetBytes(k, ncryptSecurityDescrProp, daclSecurityInformation)
	if err != nil {
		return "", err
	}
	sddl := (*windows.SECURITY_DESCRIPTOR)(unsafe.Pointer(&b[0])).String() + "(A;;GR;;;SY)"
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return "", err
	}
	if err := ncryptCall(procNCryptSetProperty, uintptr(k), lpcwstr(ncryptSecurityDescrProp),
		uintptr(unsafe.Pointer(sd)), uintptr(sd.Length()), daclSecurityInformation|ncryptSilentFlag); err != nil {
		return "", err
	}
	return sddl, nil
}

// machineChain builds the chain Windows builds for a certificate in the machine context (§6.2 step 2), with
// CertGetCertificateChain and HCCE_LOCAL_MACHINE.
func machineChain(store, thumb string) map[string]any {
	out := map[string]any{}
	h, err := openStore(store, true)
	if err != nil {
		out["error"] = errString(err)
		return out
	}
	defer windows.CertCloseStore(h, 0) //nolint:errcheck // spike
	ctx, err := findByHash(h, thumb)
	if err != nil {
		out["error"] = errString(err)
		return out
	}
	defer windows.CertFreeCertificateContext(ctx) //nolint:errcheck // spike
	para := windows.CertChainPara{}
	para.Size = uint32(unsafe.Sizeof(para))
	var chain *windows.CertChainContext
	const hcceLocalMachine = windows.Handle(1)
	if err := windows.CertGetCertificateChain(hcceLocalMachine, ctx, nil, 0, &para, 0, 0, &chain); err != nil {
		out["error"] = errString(err)
		return out
	}
	defer windows.CertFreeCertificateChain(chain)
	out["trust_error_status"] = fmt.Sprintf("0x%x", chain.TrustStatus.ErrorStatus)
	out["chain_count"] = chain.ChainCount
	if chain.ChainCount > 0 {
		simple := unsafe.Slice(chain.Chains, chain.ChainCount)[0]
		var subjects []string
		for _, el := range unsafe.Slice(simple.Elements, simple.NumElements) {
			if c, err := parseCert(certDER(el.CertContext)); err == nil {
				subjects = append(subjects, c.Subject.CommonName)
			}
		}
		out["elements"] = simple.NumElements
		out["subjects"] = subjects
	}
	return out
}
