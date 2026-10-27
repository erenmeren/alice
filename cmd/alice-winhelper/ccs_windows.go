//go:build windows

package main

// The Centralized Certificate Store half of the real host (W5, R68): the folder IIS's
// CentralCertProvider names, its *.pfx files, PFX reading without a persisted key, and the atomic write
// with a backup.
//
//	https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-findfirstfilew
//	https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew
//	https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-replacefilew
//	https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-pfxverifypassword
//	https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-pfximportcertstore
//
// Every folder is one the helper read (CCSConfig or a valid journal) and every name one it derived or
// listed (winhelper); this file checks both again before it joins them (ValidCCSPath, a plain name, the
// temporary and backup patterns), opens files with FILE_FLAG_OPEN_REPARSE_POINT and never follows a
// reparse point: a folder that is one is winhelper.ErrCCSFolderUnsupported, a file
// winhelper.ErrCCSFileUnsupported.

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"io"
	"os"
	"regexp"
	"runtime"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"alice/internal/providers/windows/winhelper"
	"alice/internal/providers/windows/winproto"
)

var (
	modkernel32           = windows.NewLazySystemDLL("kernel32.dll")
	procReplaceFileW      = modkernel32.NewProc("ReplaceFileW")
	procPFXIsPFXBlob      = modcrypt32.NewProc("PFXIsPFXBlob")
	procPFXVerifyPassword = modcrypt32.NewProc("PFXVerifyPassword")
)

const (
	// replaceFileWriteThrough is REPLACEFILE_WRITE_THROUGH (Ruling 14 step 6). The temporary file was
	// written through and flushed already, so the data is on disk whatever ReplaceFileW does with it.
	replaceFileWriteThrough = 0x1

	// The certificate properties that tie a certificate of a PFX store to its key:
	// CERT_KEY_PROV_INFO_PROP_ID, CERT_KEY_CONTEXT_PROP_ID, CERT_NCRYPT_KEY_HANDLE_PROP_ID and
	// CERT_HCRYPTPROV_OR_NCRYPT_KEY_HANDLE_PROP_ID (PKCS12_NO_PERSIST_KEY sets a handle, not a
	// container name).
	certKeyContextPropID      = 5
	certNCryptKeyHandlePropID = 78
	certKeyHandlePropID       = 79
)

var (
	// ccsTempRE and ccsBackupRE are the only names RemoveCCS removes and the only temporary and backup
	// names the writes take: winhelper's ccsTempName and ccsBackupName.
	ccsTempRE   = regexp.MustCompile(`^\.alice-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\.tmp$`)
	ccsBackupRE = regexp.MustCompile(`^[^\\/:]+\.pfx\.alice-[0-9a-f]{8}\.bak$`)
)

// CCSConfig reads the CentralCertProvider key at every call (centralCertStore, also win-facts').
func (host) CCSConfig(ctx context.Context) (bool, string, error) {
	if err := ctx.Err(); err != nil {
		return false, "", err
	}
	return centralCertStore()
}

// ccsDir is a CCS folder as the helper opens it: a supported local path with one trailing backslash
// trimmed, except a drive's root ("C:" alone names the drive's current directory).
func ccsDir(folder string) (string, error) {
	if !winproto.ValidCCSPath(folder) {
		return "", errBadValue
	}
	if len(folder) > 3 {
		folder = strings.TrimSuffix(folder, `\`)
	}
	return folder, nil
}

// ccsFilePath joins a plain name (no separator, no ":" of an alternate data stream, not a dot
// segment) to a CCS folder.
func ccsFilePath(folder, name string) (string, error) {
	dir, err := ccsDir(folder)
	if err != nil || name == "" || name == "." || name == ".." || strings.ContainsAny(name, `\/:`) {
		return "", errBadValue
	}
	if strings.HasSuffix(dir, `\`) {
		return dir + name, nil
	}
	return dir + `\` + name, nil
}

// pfxName reports a name ending in ".pfx", the extension in any ASCII case (b|0x20 is 'p' only for
// 'P' and 'p').
func pfxName(n string) bool {
	if len(n) < 4 {
		return false
	}
	s := n[len(n)-4:]
	return s[0] == '.' && s[1]|0x20 == 'p' && s[2]|0x20 == 'f' && s[3]|0x20 == 'x'
}

// notFound reports a file or folder that does not exist.
func notFound(err error) bool {
	return errors.Is(err, windows.ERROR_FILE_NOT_FOUND) || errors.Is(err, windows.ERROR_PATH_NOT_FOUND)
}

// ListCCS lists the regular *.pfx files of folder (FindFirstFile of <folder>\*.pfx). The pattern also
// matches a long name through its 8.3 short name ("a.pfxold" is "A~1.PFX"), so each long name is
// checked again. A folder that does not exist lists nothing (ruling W5-3, as the emulator); one that is
// a reparse point is winhelper.ErrCCSFolderUnsupported (W5 Ruling 3).
func (host) ListCCS(ctx context.Context, folder string) ([]winhelper.CCSEntry, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	dir, err := ccsDir(folder)
	if err != nil {
		return nil, err
	}
	p, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		return nil, errBadValue
	}
	attrs, err := windows.GetFileAttributes(p)
	switch {
	case notFound(err):
		return []winhelper.CCSEntry{}, nil
	case err != nil:
		return nil, err
	case attrs&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0:
		return nil, winhelper.ErrCCSFolderUnsupported
	case attrs&windows.FILE_ATTRIBUTE_DIRECTORY == 0:
		return nil, errBadValue
	}
	pattern, err := ccsFilePath(folder, "*.pfx")
	if err != nil {
		return nil, err
	}
	pp, err := windows.UTF16PtrFromString(pattern)
	if err != nil {
		return nil, errBadValue
	}
	var fd windows.Win32finddata
	fh, err := windows.FindFirstFile(pp, &fd)
	if notFound(err) {
		return []winhelper.CCSEntry{}, nil // no match, or the folder went meanwhile
	}
	if err != nil {
		return nil, err
	}
	defer func() { _ = windows.FindClose(fh) }()
	const skip = windows.FILE_ATTRIBUTE_DIRECTORY | windows.FILE_ATTRIBUTE_REPARSE_POINT | windows.FILE_ATTRIBUTE_DEVICE
	out := []winhelper.CCSEntry{}
	for n := 0; ; n++ {
		if n >= maxListedState {
			return nil, errBadValue
		}
		name := windows.UTF16ToString(fd.FileName[:])
		if fd.FileAttributes&skip == 0 && pfxName(name) {
			out = append(out, winhelper.CCSEntry{Name: name, Size: int64(fd.FileSizeHigh)<<32 | int64(fd.FileSizeLow),
				ModTime: filetime(fd.LastWriteTime)})
		}
		err := windows.FindNextFile(fh, &fd)
		if errors.Is(err, windows.ERROR_NO_MORE_FILES) {
			return out, nil
		}
		if err != nil {
			return nil, err
		}
	}
}

// ReadCCS reads at most limit+1 bytes of folder\name, opened with FILE_FLAG_OPEN_REPARSE_POINT (and
// FILE_FLAG_BACKUP_SEMANTICS, so a directory opens to be refused rather than failing as a denial):
// a reparse point, a directory or anything but a disk file is winhelper.ErrCCSFileUnsupported. Every
// share mode: IIS may read the file at the same time.
func (host) ReadCCS(ctx context.Context, folder, name string, limit int) ([]byte, bool, error) {
	if err := ctx.Err(); err != nil {
		return nil, false, err
	}
	path, err := ccsFilePath(folder, name)
	if err != nil || limit < 0 {
		return nil, false, errBadValue
	}
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, false, errBadValue
	}
	fh, err := windows.CreateFile(p, windows.GENERIC_READ,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING,
		windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if notFound(err) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	f := os.NewFile(uintptr(fh), path)
	defer func() { _ = f.Close() }()
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(fh, &info); err != nil {
		return nil, false, err
	}
	if info.FileAttributes&(windows.FILE_ATTRIBUTE_REPARSE_POINT|windows.FILE_ATTRIBUTE_DIRECTORY|windows.FILE_ATTRIBUTE_DEVICE) != 0 {
		return nil, false, winhelper.ErrCCSFileUnsupported
	}
	if t, err := windows.GetFileType(fh); err != nil || t != windows.FILE_TYPE_DISK {
		return nil, false, winhelper.ErrCCSFileUnsupported
	}
	data, err := io.ReadAll(io.LimitReader(f, int64(limit)+1))
	if err != nil {
		return nil, false, err
	}
	return data, true, nil
}

// OpenPFX reads a PFX's certificates under password into a memory store with PKCS12_NO_PERSIST_KEY,
// so no key file is written (F16): the leaf is the one certificate that has a key, the others follow
// in chain order (pfxChainOrder). PFXIsPFXBlob tells a PFX; PFXVerifyPassword's "no" is confirmed by
// the import (the import is the judge: a MAC Windows cannot verify must not read as a wrong password
// when the import opens the file). The problem is always one of winproto.CCSProblem*; err is a failure
// of the host. The UTF-16 copy of the password is cleared here; the caller clears password.
func (host) OpenPFX(data, password []byte) ([]byte, [][]byte, string, error) {
	if len(data) == 0 {
		return nil, nil, winproto.CCSProblemNotPFX, nil
	}
	if len(data) > winproto.MaxCCSFile {
		return nil, nil, "", errBadValue
	}
	if procPFXIsPFXBlob.Find() != nil || procPFXVerifyPassword.Find() != nil {
		return nil, nil, "", errStore
	}
	pw := make([]uint16, len(password)+1)
	defer clear(pw)
	for i, c := range password {
		if c == 0 || c >= 0x80 {
			return nil, nil, "", errBadValue // ValidCCSPassword: printable ASCII
		}
		pw[i] = uint16(c)
	}
	blob := windows.CryptDataBlob{Size: uint32(len(data)), Data: &data[0]} //nolint:gosec // G115: at most MaxCCSFile
	// unsafe: the blob, the bytes it names and the password are alive for the calls (KeepAlive below).
	if r, _, _ := procPFXIsPFXBlob.Call(uintptr(unsafe.Pointer(&blob))); r == 0 {
		runtime.KeepAlive(data)
		return nil, nil, winproto.CCSProblemNotPFX, nil
	}
	verified, _, _ := procPFXVerifyPassword.Call(uintptr(unsafe.Pointer(&blob)), uintptr(unsafe.Pointer(&pw[0])), 0)
	st, err := windows.PFXImportCertStore(&blob, &pw[0], windows.PKCS12_NO_PERSIST_KEY)
	clear(pw)
	runtime.KeepAlive(data)
	if err != nil {
		if verified == 0 || errors.Is(err, windows.ERROR_INVALID_PASSWORD) {
			return nil, nil, winproto.CCSProblemPasswordMismatch, nil
		}
		return nil, nil, winproto.CCSProblemNotPFX, nil
	}
	defer func() { _ = windows.CertCloseStore(st, 0) }()
	return pfxCertificates(st)
}

// pfxCertificates splits a PFX memory store into the one keyed certificate and the others: none keyed
// is CCSProblemNoKey, several CCSProblemNotPFX (as the emulator's reader: one key bag only).
func pfxCertificates(st windows.Handle) ([]byte, [][]byte, string, error) {
	var leaf []byte
	var others [][]byte
	keyed := 0
	var prev *windows.CertContext
	for range maxStoreEnum {
		// CertEnumCertificatesInStore frees prev, also when it returns nil.
		c, err := windows.CertEnumCertificatesInStore(st, prev)
		prev = c
		if c == nil {
			if !hresult(err, codeCryptNotFound, codeNoMoreFiles) {
				return nil, nil, "", errStore
			}
			break
		}
		der := contextDER(c)
		if der == nil {
			_ = windows.CertFreeCertificateContext(c)
			return nil, nil, winproto.CCSProblemNotPFX, nil // past MaxCertDER
		}
		if hasKey(c) {
			keyed++
			leaf = der
		} else {
			others = append(others, der)
		}
	}
	if prev != nil {
		_ = windows.CertFreeCertificateContext(prev)
	}
	switch {
	case keyed == 0:
		return nil, nil, winproto.CCSProblemNoKey, nil
	case keyed > 1:
		return nil, nil, winproto.CCSProblemNotPFX, nil
	}
	return leaf, pfxChainOrder(leaf, others), "", nil
}

// hasKey reports whether a certificate of a PFX store carries a key: one of the key properties, or a
// key CryptAcquireCertificatePrivateKey reaches. Which property PKCS12_NO_PERSIST_KEY sets is not
// documented (F16 records the answer), so a property that cannot be read is only not this one.
func hasKey(c *windows.CertContext) bool {
	for _, id := range []uint32{certKeyProvInfoPropID, certKeyContextPropID, certNCryptKeyHandlePropID, certKeyHandlePropID} {
		if _, _, found, err := contextProperty(c, id); err == nil && found {
			return true
		}
	}
	return keyReachable(c)
}

// pfxChainOrder orders the certificates beside the leaf as a chain: the issuer of the leaf, then its
// issuer, up to a self-signed one; the rest follow in the store's order. A memory store's enumeration
// order is not documented, and BuildPFX (and every common exporter) writes a chain in this order, so
// this is the file's order for them (the emulator reads the file's order).
func pfxChainOrder(leaf []byte, others [][]byte) [][]byte {
	parsed := make([]*x509.Certificate, len(others))
	for i, der := range others {
		parsed[i], _ = x509.ParseCertificate(der) // nil when it does not parse: kept in store order
	}
	out := make([][]byte, 0, len(others))
	used := make([]bool, len(others))
	cur, err := x509.ParseCertificate(leaf)
	for err == nil && cur != nil && !bytes.Equal(cur.RawSubject, cur.RawIssuer) {
		var next *x509.Certificate
		for i, der := range others {
			if c := parsed[i]; !used[i] && c != nil && bytes.Equal(c.RawSubject, cur.RawIssuer) {
				used[i], next = true, c
				out = append(out, der)
				break
			}
		}
		cur = next
	}
	for i, der := range others {
		if !used[i] {
			out = append(out, der)
		}
	}
	return out
}

// WriteCCSTemp creates folder\tmpName (CREATE_NEW: an existing name, a link included, fails) with
// FILE_FLAG_WRITE_THROUGH, writes data and flushes it. The new file inherits the folder's ACL.
func (host) WriteCCSTemp(ctx context.Context, folder, tmpName string, data []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !ccsTempRE.MatchString(tmpName) {
		return errBadValue
	}
	path, err := ccsFilePath(folder, tmpName)
	if err != nil {
		return err
	}
	return writeFlushed(path, data, windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_WRITE_THROUGH|windows.FILE_FLAG_OPEN_REPARSE_POINT)
}

// Retries of ReplaceFileW while a reader (IIS, a scanner) holds the file without FILE_SHARE_DELETE:
// each of these errors leaves both files under their own names (ReplaceFileW's documentation).
var replaceRetry = []windows.Errno{windows.ERROR_SHARING_VIOLATION, windows.ERROR_ACCESS_DENIED, windows.ERROR_UNABLE_TO_REMOVE_REPLACED}

// ReplaceCCS is ReplaceFileW(folder\name, folder\tmpName, folder\backupName, REPLACEFILE_WRITE_THROUGH):
// the file keeps its ACL and attributes, its old bytes become the backup (replacing one of that name),
// and the temporary file is gone (F15).
func (host) ReplaceCCS(ctx context.Context, folder, name, tmpName, backupName string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !pfxName(name) || !ccsTempRE.MatchString(tmpName) || !ccsBackupRE.MatchString(backupName) {
		return errBadValue
	}
	if procReplaceFileW.Find() != nil {
		return errBadValue
	}
	var ptrs [3]*uint16
	for i, n := range []string{name, tmpName, backupName} {
		path, err := ccsFilePath(folder, n)
		if err != nil {
			return err
		}
		if ptrs[i], err = windows.UTF16PtrFromString(path); err != nil {
			return errBadValue
		}
	}
	var err error
	for i := range moveTries {
		// unsafe: the three NUL-terminated paths are alive for the call (KeepAlive below).
		r, _, e := procReplaceFileW.Call(uintptr(unsafe.Pointer(ptrs[0])), uintptr(unsafe.Pointer(ptrs[1])),
			uintptr(unsafe.Pointer(ptrs[2])), replaceFileWriteThrough, 0, 0)
		runtime.KeepAlive(ptrs)
		if r != 0 {
			return nil
		}
		err = e
		retry := false
		for _, code := range replaceRetry {
			retry = retry || errors.Is(e, code)
		}
		if !retry {
			return err
		}
		if i < moveTries-1 {
			time.Sleep(moveWait)
		}
	}
	return err
}

// RestoreCCS moves folder\backupName over folder\name (MoveFileEx MOVEFILE_REPLACE_EXISTING |
// MOVEFILE_WRITE_THROUGH, replaceFile's retries). A backup that is a reparse point or not a regular
// file is never moved into the file's place.
func (host) RestoreCCS(ctx context.Context, folder, backupName, name string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !pfxName(name) || !ccsBackupRE.MatchString(backupName) {
		return errBadValue
	}
	from, err := ccsFilePath(folder, backupName)
	if err != nil {
		return err
	}
	to, err := ccsFilePath(folder, name)
	if err != nil {
		return err
	}
	pf, err := windows.UTF16PtrFromString(from)
	if err != nil {
		return errBadValue
	}
	pt, err := windows.UTF16PtrFromString(to)
	if err != nil {
		return errBadValue
	}
	attrs, err := windows.GetFileAttributes(pf)
	if err != nil {
		return err
	}
	if attrs&(windows.FILE_ATTRIBUTE_REPARSE_POINT|windows.FILE_ATTRIBUTE_DIRECTORY|windows.FILE_ATTRIBUTE_DEVICE) != 0 {
		return winhelper.ErrCCSFileUnsupported
	}
	return replaceFile(pf, pt)
}

// RemoveCCS deletes folder\name when the name is a temporary file or a backup of the helper's
// (ccsTempRE, ccsBackupRE) and it is a regular file: DeleteFile, which removes a link itself and never
// what it points to, but a link is refused anyway, as RemoveState refuses one. One that is absent, or
// whose folder does not exist, is nil.
func (host) RemoveCCS(ctx context.Context, folder, name string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !ccsTempRE.MatchString(name) && !ccsBackupRE.MatchString(name) {
		return errBadValue
	}
	path, err := ccsFilePath(folder, name)
	if err != nil {
		return err
	}
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return errBadValue
	}
	attrs, err := windows.GetFileAttributes(p)
	if notFound(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if attrs&(windows.FILE_ATTRIBUTE_DIRECTORY|windows.FILE_ATTRIBUTE_REPARSE_POINT|windows.FILE_ATTRIBUTE_DEVICE) != 0 {
		return winhelper.ErrCCSFileUnsupported
	}
	if err := windows.DeleteFile(p); err != nil && !notFound(err) {
		return err
	}
	return nil
}
