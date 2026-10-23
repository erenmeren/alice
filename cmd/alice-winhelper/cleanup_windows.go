//go:build windows

package main

// The machine half of iis-cleanup (W3 Rulings 6 and 10, F11 and F12): removing a certificate Alice
// imported with its CNG key, and the certificates the RDP and WinRM listeners name.
//
//	https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certfindcertificateinstore
//	https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptacquirecertificateprivatekey
//	https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptdeletekey
//	https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certdeletecertificatefromstore
//
// The listeners' certificates are registry values the helper only reads (W3 Ruling 22: no test writes
// them either): the RDP listener's SSLCertificateSHA1Hash (REG_BINARY, absent while RDP uses its
// self-signed certificate) and each WinRM HTTPS listener's certThumbprint (REG_SZ).

import (
	"bytes"
	"context"
	"crypto/sha1" //nolint:gosec // G505: the store's thumbprint is SHA-1; it names a certificate, it secures nothing
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"runtime"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"alice/internal/providers/windows/winhelper"
)

// Registry locations of the listeners' certificates (F12).
const (
	keyRDPTcp        = `SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp`
	valueRDPHash     = "SSLCertificateSHA1Hash"
	keyWinRMListener = `SOFTWARE\Microsoft\Windows\CurrentVersion\WSMAN\Listener`
	winRMHTTPSSuffix = "+HTTPS"
	valueWinRMThumb  = "certThumbprint"
	// maxListeners bounds the WinRM listener keys read; more is an error (the cleanup then removes
	// nothing).
	maxListeners = 1024
)

var errKeyDelete = errors.New("the certificate's key could not be deleted")

// RemoveCertificate removes the certificate with this SHA-1 from a machine store: its CNG key first
// (CryptAcquireCertificatePrivateKey, then NCryptDeleteKey, F11), then the certificate
// (CertDeleteCertificateFromStore of a duplicated context). removed is false when the store or the
// certificate does not exist. A certificate without a key, or whose key is gone (a kill between the
// two steps), is removed alone. A key that exists but cannot be opened or deleted leaves the
// certificate in place (an error): removing it would leave an orphan key no listing finds (W3 Ruling
// 10).
func (host) RemoveCertificate(ctx context.Context, store, sha1Hex string) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	hash, err := hex.DecodeString(sha1Hex)
	if err != nil || len(hash) != sha1.Size {
		return false, errBadValue
	}
	p, err := windows.UTF16PtrFromString(store)
	if err != nil {
		return false, errBadValue
	}
	// unsafe: the store name is the provider's pvPara, alive until the call returns.
	st, err := windows.CertOpenStore(windows.CERT_STORE_PROV_SYSTEM_W, 0, 0,
		windows.CERT_SYSTEM_STORE_LOCAL_MACHINE|windows.CERT_STORE_OPEN_EXISTING_FLAG, uintptr(unsafe.Pointer(p)))
	runtime.KeepAlive(p)
	if err != nil {
		if hresult(err, codeFileNotFound, codeHRFileNotFound) {
			return false, nil // no such store: it holds no such certificate
		}
		return false, fmt.Errorf("%w: %w", winhelper.ErrStore, err)
	}
	defer func() { _ = windows.CertCloseStore(st, 0) }()
	blob := windows.CryptHashBlob{Size: sha1.Size, Data: &hash[0]}
	// unsafe: the hash blob is CertFindCertificateInStore's pvFindPara, alive for the call.
	c, err := windows.CertFindCertificateInStore(st, encodingAny, 0, windows.CERT_FIND_SHA1_HASH, unsafe.Pointer(&blob), nil)
	runtime.KeepAlive(hash)
	if c == nil {
		if hresult(err, codeCryptNotFound) {
			return false, nil
		}
		return false, errStore
	}
	defer func() { _ = windows.CertFreeCertificateContext(c) }()
	der := contextDER(c)
	if sum := sha1.Sum(der); len(der) == 0 || !bytes.Equal(sum[:], hash) { //nolint:gosec // G401: the thumbprint, see the import
		return false, errBadValue
	}
	if err := deleteCertificateKey(c); err != nil {
		return false, err
	}
	// CertDeleteCertificateFromStore frees the context it is given, also on failure: a duplicate, so
	// the deferred free above stays valid.
	if err := windows.CertDeleteCertificateFromStore(windows.CertDuplicateCertificateContext(c)); err != nil {
		return false, errStore
	}
	return true, nil
}

// deleteCertificateKey deletes the persisted CNG key a certificate context names; nil when it names
// none or the key is already gone. NCryptDeleteKey frees the handle when it succeeds.
func deleteCertificateKey(c *windows.CertContext) error {
	if procNCryptDeleteKey.Find() != nil {
		return errKeyDelete
	}
	key, free, err := acquireKey(c)
	if err != nil {
		if hresult(err, codeNoKeyProperty, codeBadKeyset, codeNoKey, codeNteNotFound, codeFileNotFound, codeHRFileNotFound) {
			return nil // no key, or a key that is no longer there
		}
		return errKeyDelete
	}
	if !free {
		return errKeyDelete // a handle the certificate context owns is never deleted through
	}
	if r, _, _ := procNCryptDeleteKey.Call(uintptr(key), ncryptSilentFlag); r != 0 {
		_, _, _ = procNCryptFreeObject.Call(uintptr(key))
		return errKeyDelete
	}
	return nil
}

// ProtectedThumbprints reads the RDP listener's and every WinRM HTTPS listener's certificate (F12,
// W3 Ruling 6) as lower-case SHA-1 hex. A key or value that does not exist names no certificate; one
// that exists but cannot be read, or holds no SHA-1, is an error (the cleanup then removes nothing).
func (host) ProtectedThumbprints(ctx context.Context) (winhelper.Protected, error) {
	if err := ctx.Err(); err != nil {
		return winhelper.Protected{}, err
	}
	var p winhelper.Protected
	rdp, err := rdpThumbprint()
	if err != nil {
		return winhelper.Protected{}, err
	}
	if rdp != "" {
		p.RDP = []string{rdp}
	}
	if p.WinRM, err = winRMThumbprints(); err != nil {
		return winhelper.Protected{}, err
	}
	return p, nil
}

// rdpThumbprint is RDP-Tcp's SSLCertificateSHA1Hash, "" when the key or the value is absent.
func rdpThumbprint() (string, error) {
	k, err := openKey(keyRDPTcp)
	if errors.Is(err, registry.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	defer func() { _ = k.Close() }()
	v, _, err := k.GetBinaryValue(valueRDPHash)
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

// winRMThumbprints is the certThumbprint of every WinRM listener key ending in +HTTPS, folded to
// lower case; none when the Listener key is absent or a listener has no such value.
func winRMThumbprints() ([]string, error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, keyWinRMListener, registry.ENUMERATE_SUB_KEYS|registry.WOW64_64KEY)
	if errors.Is(err, registry.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer func() { _ = k.Close() }()
	names, err := k.ReadSubKeyNames(maxListeners + 1)
	if err != nil && !errors.Is(err, io.EOF) { // io.EOF: fewer keys than asked for
		return nil, err
	}
	if len(names) > maxListeners {
		return nil, errBadValue
	}
	var out []string
	for _, name := range names {
		if len(name) < len(winRMHTTPSSuffix) || !strings.EqualFold(name[len(name)-len(winRMHTTPSSuffix):], winRMHTTPSSuffix) {
			continue
		}
		t, err := winRMListenerThumbprint(keyWinRMListener + `\` + name)
		if err != nil {
			return nil, err
		}
		if t != "" {
			out = append(out, t)
		}
	}
	return out, nil
}

// winRMListenerThumbprint reads one listener's certThumbprint: "" when the key (removed since the
// listing) or the value is absent; spaces are dropped (a thumbprint pasted from the certificate
// dialog has them) and anything but 40 hex digits is an error.
func winRMListenerThumbprint(path string) (string, error) {
	k, err := openKey(path)
	if errors.Is(err, registry.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	defer func() { _ = k.Close() }()
	v, _, err := k.GetStringValue(valueWinRMThumb)
	if errors.Is(err, registry.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	t := strings.ReplaceAll(strings.TrimSpace(v), " ", "")
	if t == "" {
		return "", nil
	}
	b, err := hex.DecodeString(t)
	if err != nil || len(b) != sha1.Size {
		return "", errBadValue
	}
	return hex.EncodeToString(b), nil
}
