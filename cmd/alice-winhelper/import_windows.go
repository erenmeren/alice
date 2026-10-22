//go:build windows

package main

// The certificate imports of iis-deploy (W2 Ruling 9, design §6.3 steps 5 and 6, F10):
//
//	https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-pfximportcertstore
//	https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certaddcertificatecontexttostore
//	https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certsetcertificatecontextproperty
//	https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptdeletekey
//
// PFXImportCertStore imports the PFX into a memory store and persists its key as a machine key of the
// software KSP (CRYPT_MACHINE_KEYSET | PKCS12_ALWAYS_CNG_KSP, never CRYPT_EXPORTABLE, never
// PKCS12_NO_PERSIST_KEY: W0 F4); the leaf, with its CERT_KEY_PROV_INFO_PROP_ID naming that key, is then
// added to the target store with CERT_STORE_ADD_NEW (never replacing someone else's copy). F10 (Task 9)
// confirms that the stored copy keeps the key link, so http.sys binds it without 1312.

import (
	"context"
	"crypto/sha1" //nolint:gosec // G505: the store's thumbprint is SHA-1; it names a certificate, it secures nothing
	"encoding/hex"
	"errors"
	"fmt"
	"runtime"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"

	"alice/internal/providers/windows/winhelper"
)

var (
	procCertSetCertificateContextProperty = modcrypt32.NewProc("CertSetCertificateContextProperty")
	procNCryptDeleteKey                   = modncrypt.NewProc("NCryptDeleteKey")
)

// importFlags are PFXImportCertStore's flags (W0 F4).
const importFlags = windows.CRYPT_MACHINE_KEYSET | windows.PKCS12_ALWAYS_CNG_KSP

const codeCryptExists = uint32(windows.CRYPT_E_EXISTS)

var errImport = errors.New("the certificate could not be imported")

// openWritableStore opens an existing local machine system store for writing; a failure wraps
// winhelper.ErrStore.
func openWritableStore(name string) (windows.Handle, error) {
	p, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return 0, fmt.Errorf("%w: %w", winhelper.ErrStore, errBadValue)
	}
	// unsafe: the store name is the provider's pvPara, alive until the call returns.
	h, err := windows.CertOpenStore(windows.CERT_STORE_PROV_SYSTEM_W, 0, 0,
		windows.CERT_SYSTEM_STORE_LOCAL_MACHINE|windows.CERT_STORE_OPEN_EXISTING_FLAG, uintptr(unsafe.Pointer(p)))
	runtime.KeepAlive(p)
	if err != nil {
		return 0, fmt.Errorf("%w: %w", winhelper.ErrStore, err)
	}
	return h, nil
}

// AddIntermediate adds a public certificate to LocalMachine\CA, never replacing one (CERT_STORE_ADD_NEW);
// added is false when it was there.
func (host) AddIntermediate(ctx context.Context, der []byte) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if len(der) == 0 {
		return false, errBadValue
	}
	c, err := windows.CertCreateCertificateContext(encodingAny, &der[0], uint32(len(der))) //nolint:gosec // G115: bounded by winproto.MaxCertDER
	if err != nil || c == nil {
		return false, errBadValue
	}
	defer func() { _ = windows.CertFreeCertificateContext(c) }()
	st, err := openWritableStore("CA")
	if err != nil {
		return false, err
	}
	defer func() { _ = windows.CertCloseStore(st, 0) }()
	err = windows.CertAddCertificateContextToStore(st, c, windows.CERT_STORE_ADD_NEW, nil)
	if hresult(err, codeCryptExists) {
		return false, nil
	}
	if err != nil {
		return false, errStore
	}
	return true, nil
}

// ImportPFX imports a PFX of one leaf with its key into a machine store and returns the leaf's SHA-1.
// When the store already holds that certificate, the existing copy is reported (its SHA-1, nil) and left
// as it is: not renamed, its key untouched, and the key this import persisted deleted again. A stored
// copy that cannot reach its key is removed with that key (winhelper.ErrKeyUnusable). The UTF-16 copy
// of the password is cleared here; the caller clears pfx and password.
func (host) ImportPFX(ctx context.Context, store string, pfx, password []byte, friendlyName string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if len(pfx) == 0 || len(password) == 0 {
		return "", errBadValue
	}
	pw := make([]uint16, len(password)+1)
	defer clear(pw)
	for i, c := range password {
		if c == 0 || c >= 0x80 {
			return "", errBadValue // BuildPFX's passwords are printable ASCII
		}
		pw[i] = uint16(c)
	}
	blob := windows.CryptDataBlob{Size: uint32(len(pfx)), Data: &pfx[0]} //nolint:gosec // G115: bounded by winproto.MaxDeployInput
	tmp, err := windows.PFXImportCertStore(&blob, &pw[0], importFlags)
	clear(pw)
	runtime.KeepAlive(pfx)
	if err != nil {
		return "", errImport
	}
	defer func() { _ = windows.CertCloseStore(tmp, 0) }()
	leaf, err := keyedCertificate(tmp)
	if err != nil {
		return "", err
	}
	defer func() { _ = windows.CertFreeCertificateContext(leaf) }()
	// From here the import has persisted a key: it is deleted again unless a stored copy uses it.
	keep := false
	defer func() {
		if !keep {
			deleteKey(leaf)
		}
	}()
	der := contextDER(leaf)
	if der == nil {
		return "", errBadValue
	}
	sum := sha1.Sum(der) //nolint:gosec // G401: the thumbprint, see the import
	thumb := hex.EncodeToString(sum[:])
	if friendlyName != "" {
		if err := setFriendlyName(leaf, friendlyName); err != nil {
			return "", err
		}
	}
	dst, err := openWritableStore(store)
	if err != nil {
		return "", err
	}
	defer func() { _ = windows.CertCloseStore(dst, 0) }()
	var stored *windows.CertContext
	err = windows.CertAddCertificateContextToStore(dst, leaf, windows.CERT_STORE_ADD_NEW, &stored)
	if hresult(err, codeCryptExists) {
		return thumb, nil // the existing copy (W2 Ruling 9: used as is, not Alice-imported)
	}
	if err != nil || stored == nil {
		return "", errImport
	}
	defer func() { _ = windows.CertFreeCertificateContext(stored) }()
	if !keyReachable(stored) {
		// CertDeleteCertificateFromStore frees the context it is given: a duplicate, so the deferred
		// free above stays valid.
		_ = windows.CertDeleteCertificateFromStore(windows.CertDuplicateCertificateContext(stored))
		return "", winhelper.ErrKeyUnusable
	}
	keep = true
	return thumb, nil
}

// keyedCertificate returns (a duplicate of) the one certificate of a PFX store that has a key; a store
// with none or several is not a PFX BuildPFX wrote.
func keyedCertificate(st windows.Handle) (*windows.CertContext, error) {
	var found, prev *windows.CertContext
	keyed := 0
	for range maxStoreEnum {
		// CertEnumCertificatesInStore frees prev, also when it returns nil.
		c, err := windows.CertEnumCertificatesInStore(st, prev)
		prev = c
		if c == nil {
			if !hresult(err, codeCryptNotFound, codeNoMoreFiles) {
				keyed = -1
			}
			break
		}
		if _, _, ok, err := contextProperty(c, certKeyProvInfoPropID); err == nil && ok {
			keyed++
			if found == nil {
				found = windows.CertDuplicateCertificateContext(c)
			}
		}
	}
	if prev != nil {
		_ = windows.CertFreeCertificateContext(prev)
	}
	if keyed != 1 {
		if found != nil {
			_ = windows.CertFreeCertificateContext(found)
		}
		return nil, errImport
	}
	return found, nil
}

// setFriendlyName sets CERT_FRIENDLY_NAME_PROP_ID.
func setFriendlyName(c *windows.CertContext, name string) error {
	if procCertSetCertificateContextProperty.Find() != nil {
		return errStore
	}
	u := append(utf16.Encode([]rune(name)), 0)
	blob := windows.CryptDataBlob{Size: uint32(2 * len(u)), Data: (*byte)(unsafe.Pointer(&u[0]))} //nolint:gosec // G115: a short name
	// unsafe: the blob and the string it names are alive for the call.
	r, _, _ := procCertSetCertificateContextProperty.Call(uintptr(unsafe.Pointer(c)), certFriendlyNamePropID, 0,
		uintptr(unsafe.Pointer(&blob)))
	runtime.KeepAlive(u)
	if r == 0 {
		return errStore
	}
	return nil
}

// acquireKey opens a certificate's CNG key (no cache, so the caller owns the handle when free is set).
// Bound here because x/sys declares the 4-byte BOOL out-parameter as *bool (W0).
func acquireKey(c *windows.CertContext) (key windows.Handle, free bool, err error) {
	if procCryptAcquireCertificatePrivateKey.Find() != nil {
		return 0, false, errStore
	}
	var spec, callerFree uint32
	// unsafe: c and the out-parameters are alive for the call.
	r, _, e := procCryptAcquireCertificatePrivateKey.Call(uintptr(unsafe.Pointer(c)),
		windows.CRYPT_ACQUIRE_SILENT_FLAG|windows.CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG, 0,
		uintptr(unsafe.Pointer(&key)), uintptr(unsafe.Pointer(&spec)), uintptr(unsafe.Pointer(&callerFree)))
	if r == 0 {
		return 0, false, e
	}
	return key, callerFree != 0, nil
}

// keyReachable reports whether a certificate context reaches its private key.
func keyReachable(c *windows.CertContext) bool {
	key, free, err := acquireKey(c)
	if err != nil {
		return false
	}
	if free {
		_, _, _ = procNCryptFreeObject.Call(uintptr(key))
	}
	return true
}

// deleteKey deletes the persisted key a certificate context names (NCryptDeleteKey frees the handle);
// best effort: a key that cannot be deleted stays an unused machine key.
func deleteKey(c *windows.CertContext) {
	key, free, err := acquireKey(c)
	if err != nil || !free {
		return // a handle the provider owns is never deleted through
	}
	if procNCryptDeleteKey.Find() != nil {
		_, _, _ = procNCryptFreeObject.Call(uintptr(key))
		return
	}
	if r, _, _ := procNCryptDeleteKey.Call(uintptr(key), 0); r != 0 {
		_, _, _ = procNCryptFreeObject.Call(uintptr(key))
	}
}
